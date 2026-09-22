"""以固定三角色 ``spawn`` 进程和 localhost TCP 执行安全控制器。"""

from __future__ import annotations

import multiprocessing as mp
import os
import secrets
import socket
from dataclasses import dataclass
from multiprocessing.context import SpawnContext
from multiprocessing.process import BaseProcess
from typing import Any, Literal, Self

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext, PrimeModulusEvidence, PrimeModulusVerification
from secure_control.protocol import (
    ControllerRangeContract,
    ControllerRangeVerification,
    ControllerScaleLedger,
)
from secure_control.protocol.coordinator import Protocol3Orchestrator
from secure_control.protocol.messages import (
    P2TruncationPayload,
    ProductMaskPayload,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
    ResourceMetadata,
    StepResourcePlan,
    TruncationMaskPayload,
)

from ._inputs import normalize_step_input
from ._localhost_workers import localhost_client_worker, localhost_role_worker
from .localhost_codec import (
    HelloPayload,
    ReadyPayload,
    RemoteErrorPayload,
    WireEnvelope,
)
from .localhost_transport import (
    LocalhostTimeouts,
    LocalhostTransportConfig,
    LocalhostTransportDisconnected,
    LocalhostTransportError,
    LocalhostTransportProtocolError,
    LocalhostTransportTimeout,
    accept_loopback,
    create_listener,
    deadline_after,
    receive_envelope,
    send_envelope,
)

Array = np.ndarray[Any, Any]
Role = Literal["Client", "P1", "P2"]
_DEFAULT_TRANSPORT = LocalhostTransportConfig()


class LocalhostExecutionError(RuntimeError):
    """localhost 安全执行的公共异常基类。"""


class LocalhostTimeoutError(LocalhostExecutionError, TimeoutError):
    """启动、单步或关闭阶段超过有界 timeout。"""


class LocalhostProtocolError(LocalhostExecutionError):
    """framing、schema、方向、顺序或协议 identity 不匹配。"""


class LocalhostPeerError(LocalhostExecutionError):
    """远端角色报告受限错误或提前断开。"""


class LocalhostStateError(LocalhostExecutionError):
    """runtime 已关闭或失败 session 不可继续。"""


@dataclass(frozen=True, slots=True)
class LocalhostRoleInfo:
    """一个 localhost 协议角色的 PID 与公开状态。"""

    role: Role
    pid: int
    status: Literal["ready", "closed", "failed"]


@dataclass(frozen=True, slots=True)
class LocalhostTopology:
    """公开 loopback 地址和固定 Client/P1/P2 角色摘要。"""

    host: Literal["127.0.0.1"]
    port: int
    roles: tuple[LocalhostRoleInfo, LocalhostRoleInfo, LocalhostRoleInfo]


@dataclass(slots=True)
class _LocalhostSession:
    context: SpawnContext
    processes: dict[Role, BaseProcess]
    controls: dict[Role, socket.socket]
    session_id: str
    scale_ledger: ControllerScaleLedger
    range_verification: ControllerRangeVerification
    modulus_verification: PrimeModulusVerification
    pids: dict[Role, int]
    max_frame_bytes: int
    sequences: dict[Role, int]
    closed: bool = False
    failed: bool = False

    def request(
        self,
        role: Role,
        operation: str,
        timeout: float,
        *,
        round_id: str | None = None,
        step: int | None = None,
        resource_id: str | None = None,
        payload: object = None,
    ) -> object:
        deadline = deadline_after(timeout)
        request = self._send_at_deadline(
            role,
            operation,
            deadline,
            round_id=round_id,
            step=step,
            resource_id=resource_id,
            payload=payload,
        )
        return self._receive_at_deadline(role, request, deadline)

    def send(
        self,
        role: Role,
        operation: str,
        timeout: float,
        *,
        round_id: str | None = None,
        step: int | None = None,
        resource_id: str | None = None,
        payload: object = None,
    ) -> WireEnvelope:
        return self._send_at_deadline(
            role,
            operation,
            deadline_after(timeout),
            round_id=round_id,
            step=step,
            resource_id=resource_id,
            payload=payload,
        )

    def _send_at_deadline(
        self,
        role: Role,
        operation: str,
        deadline: float,
        *,
        round_id: str | None = None,
        step: int | None = None,
        resource_id: str | None = None,
        payload: object = None,
    ) -> WireEnvelope:
        sequence = self.sequences[role]
        self.sequences[role] += 1
        kind: Literal["request", "shutdown"] = "shutdown" if operation == "shutdown" else "request"
        request = WireEnvelope(
            1,
            kind,
            "Supervisor",
            role,
            sequence,
            operation,
            self.session_id,
            round_id,
            step,
            resource_id,
            payload,  # type: ignore[arg-type]
        )
        try:
            send_envelope(
                self.controls[role],
                request,
                deadline=deadline,
                limit=self.max_frame_bytes,
            )
        except Exception as error:
            self.failed = True
            raise _execution_error(error, f"向 {role}.{operation} 发送请求失败") from error
        return request

    def receive(self, role: Role, request: WireEnvelope, timeout: float) -> object:
        return self._receive_at_deadline(role, request, deadline_after(timeout))

    def _receive_at_deadline(
        self,
        role: Role,
        request: WireEnvelope,
        deadline: float,
    ) -> object:
        try:
            response = receive_envelope(
                self.controls[role],
                deadline=deadline,
                limit=self.max_frame_bytes,
            )
        except Exception as error:
            self.failed = True
            raise _execution_error(error, f"等待 {role}.{request.operation} 响应失败") from error
        if (
            response.sender,
            response.recipient,
            response.sequence,
            response.operation,
            response.session_id,
            response.round_id,
            response.step,
            response.resource_id,
        ) != (
            role,
            "Supervisor",
            request.sequence,
            request.operation,
            request.session_id,
            request.round_id,
            request.step,
            request.resource_id,
        ):
            self.failed = True
            raise LocalhostProtocolError(f"{role} 返回了错配的 localhost 响应。")
        if response.kind == "error" and isinstance(response.payload, RemoteErrorPayload):
            self.failed = True
            raise LocalhostPeerError(
                f"{role}.{request.operation} 失败："
                f"{response.payload.error_type}: {response.payload.message}"
            )
        if response.kind != "reply":
            self.failed = True
            raise LocalhostProtocolError(f"{role} 未返回 reply 或受限 error。")
        return response.payload


class _SocketProtocol3Endpoint:
    """把统一 Protocol 3 endpoint 调用映射为一条 localhost typed command。"""

    def __init__(
        self,
        session: _LocalhostSession,
        party: Literal[0, 1],
        plan: StepResourcePlan,
        timeout: float,
    ) -> None:
        self._session = session
        self._party = party
        self._role: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
        self._plan = plan
        self._timeout = timeout

    @property
    def party(self) -> int:
        return self._party

    @property
    def session_id(self) -> str:
        return self._session.session_id

    @property
    def plan(self) -> StepResourcePlan:
        return self._plan

    def begin(self) -> None:
        self._session.request(
            self._role,
            "begin",
            self._timeout,
            round_id=self._plan.round_id,
            step=self._plan.step,
        )

    def mask_product(self, metadata: ResourceMetadata) -> ProductMaskPayload:
        result = self._request(Protocol3EndpointCommand("mask_product", metadata=metadata))
        if not isinstance(result, ProductMaskPayload):
            raise LocalhostProtocolError(f"{self._role} 返回了非法乘法遮蔽消息。")
        return result

    def finish_product(self, metadata: ResourceMetadata, peer: ProductMaskPayload) -> None:
        self._request(
            Protocol3EndpointCommand("finish_product", metadata=metadata, product_mask=peer)
        )

    def complete_product(self, metadata: ResourceMetadata) -> None:
        self._request(Protocol3EndpointCommand("complete_product", metadata=metadata))

    def finish_products(self) -> None:
        self._request(Protocol3EndpointCommand("finish_products"))

    def mask_truncation(self, metadata: ResourceMetadata) -> TruncationMaskPayload:
        result = self._request(Protocol3EndpointCommand("mask_truncation", metadata=metadata))
        if not isinstance(result, TruncationMaskPayload):
            raise LocalhostProtocolError(f"{self._role} 返回了非法截断遮蔽消息。")
        return result

    def p2_truncation_message(
        self, metadata: ResourceMetadata, peer: TruncationMaskPayload
    ) -> P2TruncationPayload:
        result = self._request(
            Protocol3EndpointCommand(
                "p2_truncation_message", metadata=metadata, truncation_mask=peer
            )
        )
        if not isinstance(result, P2TruncationPayload):
            raise LocalhostProtocolError("P2 返回了非法截断消息。")
        return result

    def finish_truncation_p1(
        self,
        metadata: ResourceMetadata,
        peer: TruncationMaskPayload,
        message: P2TruncationPayload,
    ) -> None:
        self._request(
            Protocol3EndpointCommand(
                "finish_truncation_p1",
                metadata=metadata,
                truncation_mask=peer,
                p2_truncation=message,
            )
        )

    def finish_truncation_p2(self, metadata: ResourceMetadata) -> None:
        self._request(Protocol3EndpointCommand("finish_truncation_p2", metadata=metadata))

    def complete_truncation(self, metadata: ResourceMetadata) -> None:
        self._request(Protocol3EndpointCommand("complete_truncation", metadata=metadata))

    def stage_output(self) -> Protocol3StageReceipt:
        result = self._request(Protocol3EndpointCommand("stage_output"))
        if not isinstance(result, Protocol3StageReceipt):
            raise LocalhostProtocolError(f"{self._role} 返回了非法暂存回执。")
        return result

    def commit(self) -> None:
        self._request(Protocol3EndpointCommand("commit"))

    def _request(self, command: Protocol3EndpointCommand) -> object:
        resource_id = command.metadata.resource_id if command.metadata is not None else None
        return self._session.request(
            self._role,
            "endpoint",
            self._timeout,
            round_id=self._plan.round_id,
            step=self._plan.step,
            resource_id=resource_id,
            payload=command,
        )


class LocalhostSecureStateSpaceRuntime:
    """经 localhost TCP 运行 Client/P1/P2，保持通用 ``step(v)`` contract。"""

    def __init__(
        self,
        spec: ControllerSpec,
        fixed_point: FixedPointContext,
        range_contract: ControllerRangeContract,
        *,
        security_parameter: int,
        modulus_evidence: PrimeModulusEvidence | None = None,
        test_seed: int | None = None,
        transport: LocalhostTransportConfig = _DEFAULT_TRANSPORT,
    ) -> None:
        """绑定唯一 loopback listener，并启动三个不同的 ``spawn`` 角色进程。"""
        if not isinstance(spec, ControllerSpec):
            raise TypeError("spec 必须是 ControllerSpec。")
        if not isinstance(fixed_point, FixedPointContext):
            raise TypeError("fixed_point 必须是 FixedPointContext。")
        if not isinstance(range_contract, ControllerRangeContract):
            raise TypeError("range_contract 必须是 ControllerRangeContract。")
        if modulus_evidence is not None and not isinstance(modulus_evidence, PrimeModulusEvidence):
            raise TypeError("modulus_evidence 必须是 PrimeModulusEvidence 或 None。")
        if test_seed is not None and (
            isinstance(test_seed, bool) or not isinstance(test_seed, int)
        ):
            raise TypeError("test_seed 必须是整数或 None。")
        if not isinstance(transport, LocalhostTransportConfig):
            raise TypeError("transport 必须是 LocalhostTransportConfig。")
        self._spec = spec
        self._fixed_point = fixed_point
        self._range_contract = range_contract
        self._security_parameter = security_parameter
        self._modulus_evidence = modulus_evidence
        self._test_seed = test_seed
        self._transport = transport
        self._step_index = 0
        self._product_count = 0
        self._truncation_count = 0
        self._permanently_closed = False
        try:
            self._listener = create_listener(transport.host, transport.port)
        except OSError as error:
            raise LocalhostExecutionError("绑定 localhost control port 失败。") from error
        address = self._listener.getsockname()
        self._address = (str(address[0]), int(address[1]))
        try:
            self._session = self._start_session()
        except Exception:
            self._listener.close()
            raise

    @property
    def spec(self) -> ControllerSpec:
        """返回当前通用状态空间控制器规格。"""
        return self._spec

    @property
    def scale_ledger(self) -> ControllerScaleLedger:
        """返回 Client 离线验证后的公开尺度账本。"""
        return self._session.scale_ledger

    @property
    def range_verification(self) -> ControllerRangeVerification:
        """返回 Client 分享 controller 前的公开范围验证摘要。"""
        return self._session.range_verification

    @property
    def modulus_verification(self) -> PrimeModulusVerification:
        """返回 Client 对公开模数完成的验证摘要。"""
        return self._session.modulus_verification

    @property
    def topology(self) -> LocalhostTopology:
        """返回 loopback bind 和三个角色的 PID/状态，不公开 socket 或 nonce。"""
        status: Literal["ready", "closed", "failed"]
        status = "failed" if self._session.failed else "closed" if self._session.closed else "ready"
        return LocalhostTopology(
            "127.0.0.1",
            self._address[1],
            tuple(
                LocalhostRoleInfo(role, self._session.pids[role], status)
                for role in ("Client", "P1", "P2")
            ),  # type: ignore[arg-type]
        )

    @property
    def resource_counts(self) -> dict[str, int]:
        """返回成功提交步骤累计消费的逻辑资源数。"""
        return {
            "products_consumed": self._product_count,
            "truncations_consumed": self._truncation_count,
        }

    def step(self, v: Array | float) -> np.ndarray:
        """事务式执行一轮；任何 wire/peer/commit 不确定性都会关闭当前 session。"""
        self._ensure_open()
        input_vector = normalize_step_input(v, self._spec.input_dimension)
        session = self._session
        timeout = self._transport.timeouts.step
        try:
            plan = session.request(
                "Client",
                "prepare",
                timeout,
                step=self._step_index,
                payload=input_vector,
            )
            if not isinstance(plan, StepResourcePlan):
                raise LocalhostProtocolError("Client 返回了非法资源计划。")
            first = _SocketProtocol3Endpoint(session, 0, plan, timeout)
            second = _SocketProtocol3Endpoint(session, 1, plan, timeout)
            first.begin()
            second.begin()
            orchestrator = Protocol3Orchestrator()
            receipts = orchestrator.stage(first, second, plan)
            output = session.request(
                "Client",
                "reconstruct",
                timeout,
                round_id=plan.round_id,
                step=self._step_index,
            )
            orchestrator.commit(first, second)
            result = np.array(output, dtype=float, copy=True)
            if result.shape != (self._spec.output_dimension,) or not np.isfinite(result).all():
                raise LocalhostProtocolError("Client 返回的控制输出 shape 或有限性不合法。")
            self._product_count += receipts[0].products
            self._truncation_count += receipts[0].truncations
            self._step_index += 1
            return result
        except Exception:
            session.failed = True
            self._stop_session(session)
            raise

    def reset(self) -> None:
        """复用 control listener；replacement trio 完整 ready 后才替换旧 session。"""
        if self._permanently_closed:
            raise LocalhostStateError("localhost 运行时已经关闭。")
        replacement = self._start_session()
        previous = self._session
        self._session = replacement
        self._step_index = 0
        self._product_count = 0
        self._truncation_count = 0
        self._stop_session(previous)

    def close(self) -> None:
        """幂等、有界地关闭全部连接、子进程和 control listener。"""
        if self._permanently_closed:
            return
        self._permanently_closed = True
        self._stop_session(self._session)
        self._listener.close()

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._permanently_closed:
            raise LocalhostStateError("localhost 运行时已经关闭。")
        if self._session.failed:
            raise LocalhostStateError("localhost session 已失败，必须关闭或 reset。")

    def _start_session(self) -> _LocalhostSession:
        context = mp.get_context("spawn")
        nonce = secrets.token_hex(32)
        data_listeners: dict[Literal["P1", "P2"], socket.socket] = {}
        processes: dict[Role, BaseProcess] = {}
        controls: dict[Role, socket.socket] = {}
        startup_timeout = self._transport.timeouts.startup
        try:
            data_listeners = {
                "P1": create_listener("127.0.0.1", 0, backlog=1),
                "P2": create_listener("127.0.0.1", 0, backlog=1),
            }
            party_addresses = tuple(
                (
                    str(data_listeners[role].getsockname()[0]),
                    int(data_listeners[role].getsockname()[1]),
                )
                for role in ("P1", "P2")
            )
            processes = {
                "Client": context.Process(
                    name="secure-control-localhost-Client",
                    target=localhost_client_worker,
                    args=(
                        self._address,
                        party_addresses,
                        nonce,
                        self._spec,
                        self._fixed_point,
                        self._range_contract,
                        self._security_parameter,
                        self._modulus_evidence,
                        self._test_seed,
                        self._transport.max_frame_bytes,
                        startup_timeout,
                        self._transport.timeouts.step,
                        self._transport.timeouts.shutdown,
                    ),
                ),
                "P1": context.Process(
                    name="secure-control-localhost-P1",
                    target=localhost_role_worker,
                    args=(
                        0,
                        self._address,
                        data_listeners["P1"],
                        nonce,
                        self._fixed_point,
                        self._range_contract,
                        self._security_parameter,
                        self._modulus_evidence,
                        self._transport.max_frame_bytes,
                        startup_timeout,
                        self._transport.timeouts.step,
                        self._transport.timeouts.shutdown,
                    ),
                ),
                "P2": context.Process(
                    name="secure-control-localhost-P2",
                    target=localhost_role_worker,
                    args=(
                        1,
                        self._address,
                        data_listeners["P2"],
                        nonce,
                        self._fixed_point,
                        self._range_contract,
                        self._security_parameter,
                        self._modulus_evidence,
                        self._transport.max_frame_bytes,
                        startup_timeout,
                        self._transport.timeouts.step,
                        self._transport.timeouts.shutdown,
                    ),
                ),
            }
            for process in processes.values():
                process.start()
            for listener in data_listeners.values():
                listener.close()
            startup_deadline = deadline_after(startup_timeout)
            while len(controls) < 3:
                connection = accept_loopback(self._listener, deadline=startup_deadline)
                try:
                    hello = receive_envelope(
                        connection,
                        deadline=startup_deadline,
                        limit=self._transport.max_frame_bytes,
                    )
                    role = _validate_supervisor_hello(hello, nonce, processes, controls)
                    controls[role] = connection
                except Exception:
                    connection.close()
                    raise
            ready = {
                role: self._receive_ready(
                    controls[role], role, startup_deadline, self._transport.max_frame_bytes
                )
                for role in ("Client", "P1", "P2")
            }
            session_ids = {message.session_id for message in ready.values()}
            if len(session_ids) != 1 or None in session_ids:
                raise LocalhostProtocolError("三个角色未绑定同一 controller session。")
            pids: dict[Role, int] = {
                role: ready[role].payload.pid  # type: ignore[union-attr]
                for role in ("Client", "P1", "P2")
            }
            if len(set(pids.values())) != 3 or os.getpid() in pids.values():
                raise LocalhostProtocolError("Client/P1/P2 必须是不同且非父进程的 PID。")
            client_payload = ready["Client"].payload
            if (
                not isinstance(client_payload, ReadyPayload)
                or client_payload.scale_ledger is None
                or client_payload.range_verification is None
                or client_payload.modulus_verification is None
            ):
                raise LocalhostProtocolError("Client ready 缺少公开验证摘要。")
            return _LocalhostSession(
                context,
                processes,
                controls,
                ready["Client"].session_id or "",
                client_payload.scale_ledger,
                client_payload.range_verification,
                client_payload.modulus_verification,
                pids,
                self._transport.max_frame_bytes,
                {"Client": 2, "P1": 2, "P2": 2},
            )
        except Exception as error:
            for connection in controls.values():
                connection.close()
            for listener in data_listeners.values():
                try:
                    listener.close()
                except OSError:
                    pass
            for process in processes.values():
                if process.pid is None:
                    continue
                if process.is_alive():
                    process.terminate()
                process.join(self._transport.timeouts.shutdown)
            if isinstance(error, LocalhostExecutionError):
                raise
            raise _execution_error(error, "localhost session 启动失败") from error

    @staticmethod
    def _receive_ready(
        connection: socket.socket,
        role: Role,
        deadline: float,
        limit: int,
    ) -> WireEnvelope:
        try:
            message = receive_envelope(connection, deadline=deadline, limit=limit)
        except Exception as error:
            raise _execution_error(error, f"等待 {role} ready 失败") from error
        if message.kind == "error" and isinstance(message.payload, RemoteErrorPayload):
            raise LocalhostPeerError(
                f"{role} 启动失败：{message.payload.error_type}: {message.payload.message}"
            )
        if (
            message.kind != "ready"
            or message.sender != role
            or message.recipient != "Supervisor"
            or message.sequence != 1
            or message.operation != "ready"
            or not isinstance(message.payload, ReadyPayload)
        ):
            raise LocalhostProtocolError(f"{role} ready 响应不合法。")
        if role != "Client" and any(
            value is not None
            for value in (
                message.payload.scale_ledger,
                message.payload.range_verification,
                message.payload.modulus_verification,
            )
        ):
            raise LocalhostProtocolError("P1/P2 ready 不得携带 Client 验证摘要。")
        return message

    def _stop_session(self, session: _LocalhostSession) -> None:
        if session.closed:
            return
        session.closed = True
        timeout = self._transport.timeouts.shutdown
        if not session.failed:
            pending: list[tuple[Role, WireEnvelope]] = []
            for role in ("Client", "P1", "P2"):
                try:
                    pending.append((role, session.send(role, "shutdown", timeout)))
                except LocalhostExecutionError:
                    session.failed = True
                    break
            if not session.failed:
                for role, request in pending:
                    try:
                        session.receive(role, request, timeout)
                    except LocalhostExecutionError:
                        session.failed = True
                        break
        for process in session.processes.values():
            if session.failed and process.is_alive():
                process.terminate()
            process.join(timeout)
            if process.is_alive():
                process.terminate()
                process.join(timeout)
        for connection in session.controls.values():
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def _validate_supervisor_hello(
    message: WireEnvelope,
    nonce: str,
    processes: dict[Role, BaseProcess],
    controls: dict[Role, socket.socket],
) -> Role:
    if (
        message.kind != "hello"
        or message.recipient != "Supervisor"
        or message.sequence != 0
        or message.operation != "hello"
        or message.session_id is not None
        or message.sender not in {"Client", "P1", "P2"}
        or not isinstance(message.payload, HelloPayload)
        or message.payload.nonce != nonce
    ):
        raise LocalhostProtocolError("control hello 的角色、方向或 nonce 不匹配。")
    role: Role = message.sender  # type: ignore[assignment]
    if role in controls or processes[role].pid != message.payload.pid:
        raise LocalhostProtocolError("control hello 的角色重复或 PID 不匹配。")
    return role


def _execution_error(error: BaseException, context: str) -> LocalhostExecutionError:
    if isinstance(error, LocalhostExecutionError):
        return error
    if isinstance(error, LocalhostTransportTimeout):
        return LocalhostTimeoutError(f"{context}：超时。")
    if isinstance(error, (LocalhostTransportProtocolError, ValueError, TypeError)):
        return LocalhostProtocolError(f"{context}：wire 协议错误。")
    if isinstance(error, (LocalhostTransportDisconnected, LocalhostTransportError, OSError)):
        return LocalhostPeerError(f"{context}：连接断开或不可用。")
    return LocalhostExecutionError(f"{context}。")


__all__ = [
    "LocalhostExecutionError",
    "LocalhostPeerError",
    "LocalhostProtocolError",
    "LocalhostRoleInfo",
    "LocalhostSecureStateSpaceRuntime",
    "LocalhostStateError",
    "LocalhostTimeoutError",
    "LocalhostTimeouts",
    "LocalhostTopology",
    "LocalhostTransportConfig",
]
