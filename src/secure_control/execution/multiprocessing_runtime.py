"""以固定 ``spawn`` 三进程拓扑执行通用安全状态空间控制器。"""

from __future__ import annotations

import multiprocessing as mp
import os
from dataclasses import dataclass
from math import isfinite
from multiprocessing.connection import Connection
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
from ._multiprocessing_workers import IpcEnvelope, client_worker, role_worker

Array = np.ndarray[Any, Any]


class ProcessExecutionError(RuntimeError):
    """多进程安全执行的公共异常基类。"""


class ProcessExecutionTimeout(ProcessExecutionError, TimeoutError):
    """等待角色进程超过有界超时时间。"""


class ProcessWorkerError(ProcessExecutionError):
    """角色进程报告内部协议失败。"""


class ProcessProtocolError(ProcessExecutionError):
    """IPC 响应版本、请求身份或操作不匹配。"""


class ProcessStateError(ProcessExecutionError):
    """运行时已关闭或在不确定提交后不可继续使用。"""


@dataclass(frozen=True, slots=True)
class ProcessTimeouts:
    """启动、单步和关闭阶段的有限秒数上限。"""

    startup: float = 10.0
    step: float = 30.0
    shutdown: float = 5.0

    def __post_init__(self) -> None:
        for name in ("startup", "step", "shutdown"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} timeout 必须是有限正数。")
            if not isfinite(float(value)) or value <= 0:
                raise ValueError(f"{name} timeout 必须是有限正数。")


_DEFAULT_TIMEOUTS = ProcessTimeouts()


@dataclass(frozen=True, slots=True)
class ProcessRoleInfo:
    """一个协议角色的进程身份与公开状态。"""

    role: Literal["Client", "P1", "P2"]
    pid: int
    status: Literal["ready", "closed", "failed"]


@dataclass(frozen=True, slots=True)
class ProcessTopology:
    """固定 spawn 拓扑的公开只读摘要。"""

    parent_pid: int
    start_method: Literal["spawn"]
    roles: tuple[ProcessRoleInfo, ProcessRoleInfo, ProcessRoleInfo]


@dataclass(slots=True)
class _ProcessSession:
    context: SpawnContext
    processes: dict[str, BaseProcess]
    controls: dict[str, Connection]
    session_id: str
    scale_ledger: ControllerScaleLedger
    range_verification: ControllerRangeVerification
    modulus_verification: PrimeModulusVerification
    pids: dict[str, int]
    request_id: int = 0
    closed: bool = False
    failed: bool = False

    def request(
        self,
        role: Literal["Client", "P1", "P2"],
        operation: str,
        timeout: float,
        *,
        round_id: str | None = None,
        step: int | None = None,
        payload: Any = None,
    ) -> Any:
        self.request_id += 1
        request = IpcEnvelope(
            1,
            self.request_id,
            role,
            operation,
            self.session_id,
            round_id,
            step,
            payload,
        )
        connection = self.controls[role]
        try:
            connection.send(request)
        except (BrokenPipeError, EOFError, OSError) as error:
            self.failed = True
            raise ProcessWorkerError(f"{role} 进程连接已断开。") from error
        return self.receive(role, request, timeout)

    def send(
        self,
        role: Literal["Client", "P1", "P2"],
        operation: str,
        *,
        round_id: str | None = None,
        step: int | None = None,
        payload: Any = None,
    ) -> IpcEnvelope:
        self.request_id += 1
        request = IpcEnvelope(
            1,
            self.request_id,
            role,
            operation,
            self.session_id,
            round_id,
            step,
            payload,
        )
        try:
            self.controls[role].send(request)
        except (BrokenPipeError, EOFError, OSError) as error:
            self.failed = True
            raise ProcessWorkerError(f"{role} 进程连接已断开。") from error
        return request

    def receive(self, role: str, request: IpcEnvelope, timeout: float) -> Any:
        connection = self.controls[role]
        if not connection.poll(timeout):
            self.failed = True
            raise ProcessExecutionTimeout(f"等待 {role}.{request.operation} 超时。")
        try:
            response = connection.recv()
        except (EOFError, OSError) as error:
            self.failed = True
            raise ProcessWorkerError(f"{role} 进程未返回完整响应。") from error
        if not isinstance(response, IpcEnvelope) or (
            response.protocol_version,
            response.request_id,
            response.role,
            response.operation,
            response.session_id,
            response.round_id,
            response.step,
        ) != (
            1,
            request.request_id,
            role,
            request.operation,
            request.session_id,
            request.round_id,
            request.step,
        ):
            self.failed = True
            raise ProcessProtocolError(f"{role} 返回了错配的 IPC 响应。")
        if response.error_type is not None:
            self.failed = True
            detail = f"{response.error_type}: {response.error_message}"
            raise ProcessWorkerError(f"{role}.{request.operation} 失败：{detail}")
        return response.payload


class _RemoteProtocol3Endpoint:
    """把统一 Protocol 3 endpoint 调用映射为单个角色的 IPC 请求。"""

    def __init__(
        self,
        session: _ProcessSession,
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
            raise ProcessProtocolError(f"{self._role} 返回了非法乘法遮蔽消息。")
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
            raise ProcessProtocolError(f"{self._role} 返回了非法截断遮蔽消息。")
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
            raise ProcessProtocolError("P2 返回了非法截断消息。")
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
            raise ProcessProtocolError(f"{self._role} 返回了非法暂存回执。")
        return result

    def commit(self) -> None:
        self._request(Protocol3EndpointCommand("commit"))

    def _request(self, command: Protocol3EndpointCommand) -> Any:
        return self._session.request(
            self._role,
            "endpoint",
            self._timeout,
            round_id=self._plan.round_id,
            step=self._plan.step,
            payload=command,
        )


class MultiprocessingSecureStateSpaceRuntime:
    """在 Client/P1/P2 三个持久 ``spawn`` 进程中执行安全控制器。"""

    def __init__(
        self,
        spec: ControllerSpec,
        fixed_point: FixedPointContext,
        range_contract: ControllerRangeContract,
        *,
        security_parameter: int,
        modulus_evidence: PrimeModulusEvidence | None = None,
        test_seed: int | None = None,
        timeouts: ProcessTimeouts = _DEFAULT_TIMEOUTS,
    ) -> None:
        """验证配置并启动固定三角色进程；导入模块本身不会创建进程。"""
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
        if not isinstance(timeouts, ProcessTimeouts):
            raise TypeError("timeouts 必须是 ProcessTimeouts。")
        self._spec = spec
        self._fixed_point = fixed_point
        self._range_contract = range_contract
        self._security_parameter = security_parameter
        self._modulus_evidence = modulus_evidence
        self._test_seed = test_seed
        self._timeouts = timeouts
        self._step_index = 0
        self._product_count = 0
        self._truncation_count = 0
        self._permanently_closed = False
        self._session = self._start_session()

    @property
    def spec(self) -> ControllerSpec:
        """返回与当前 session 绑定的不可变通用控制器规格。"""
        return self._spec

    @property
    def scale_ledger(self) -> ControllerScaleLedger:
        """返回 Client 完成离线验证后的公开尺度账本。"""
        return self._session.scale_ledger

    @property
    def modulus_verification(self) -> PrimeModulusVerification:
        """返回 Client 进程对公开模数完成的验证摘要。"""
        return self._session.modulus_verification

    @property
    def range_verification(self) -> ControllerRangeVerification:
        """返回 Client 分享 controller 前完成的公开范围验证摘要。"""
        return self._session.range_verification

    @property
    def topology(self) -> ProcessTopology:
        """返回父进程、固定启动方式及三个角色 PID/状态。"""
        status: Literal["ready", "closed", "failed"]
        status = "failed" if self._session.failed else "closed" if self._session.closed else "ready"
        return ProcessTopology(
            os.getpid(),
            "spawn",
            (
                ProcessRoleInfo("Client", self._session.pids["Client"], status),
                ProcessRoleInfo("P1", self._session.pids["P1"], status),
                ProcessRoleInfo("P2", self._session.pids["P2"], status),
            ),
        )

    @property
    def resource_counts(self) -> dict[str, int]:
        """返回成功提交步骤累计消费的逻辑资源数。"""
        return {
            "products_consumed": self._product_count,
            "truncations_consumed": self._truncation_count,
        }

    def step(self, v: Array | float) -> np.ndarray:
        """事务式执行一轮；任何超时或不确定提交都会使整个 session 失效。"""
        self._ensure_open()
        input_vector = normalize_step_input(v, self._spec.input_dimension)
        session = self._session
        try:
            plan = session.request(
                "Client",
                "prepare",
                self._timeouts.step,
                step=self._step_index,
                payload=input_vector,
            )
            if not isinstance(plan, StepResourcePlan):
                raise ProcessProtocolError("Client 返回了非法资源计划。")
            first = _RemoteProtocol3Endpoint(session, 0, plan, self._timeouts.step)
            second = _RemoteProtocol3Endpoint(session, 1, plan, self._timeouts.step)
            first.begin()
            second.begin()
            orchestrator = Protocol3Orchestrator()
            receipts = orchestrator.stage(first, second, plan)
            output = session.request(
                "Client",
                "reconstruct",
                self._timeouts.step,
                round_id=plan.round_id,
                step=self._step_index,
            )
            orchestrator.commit(first, second)
            result = np.array(output, dtype=float, copy=True)
            if result.shape != (self._spec.output_dimension,) or not np.isfinite(result).all():
                raise ProcessProtocolError("Client 返回的控制输出 shape 或有限性不合法。")
            self._product_count += receipts[0].products
            self._truncation_count += receipts[0].truncations
            self._step_index += 1
            return result
        except Exception:
            session.failed = True
            self._stop_session(session)
            raise

    def reset(self) -> None:
        """先完整建立新三进程 session，再关闭并替换旧 session。"""
        if self._permanently_closed:
            raise ProcessStateError("多进程运行时已经关闭。")
        replacement = self._start_session()
        previous = self._session
        self._session = replacement
        self._step_index = 0
        self._product_count = 0
        self._truncation_count = 0
        self._stop_session(previous)

    def close(self) -> None:
        """有界关闭所有子进程；对已关闭实例重复调用无副作用。"""
        self._permanently_closed = True
        self._stop_session(self._session)

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._permanently_closed:
            raise ProcessStateError("多进程运行时已经关闭。")
        if self._session.failed:
            raise ProcessStateError("多进程 session 已失败，必须关闭或 reset。")

    def _start_session(self) -> _ProcessSession:
        context = mp.get_context("spawn")
        controls: dict[str, Connection] = {}
        child_controls: dict[str, Connection] = {}
        for role in ("Client", "P1", "P2"):
            controls[role], child_controls[role] = context.Pipe()
        client_p1, p1_client = context.Pipe()
        client_p2, p2_client = context.Pipe()
        processes: dict[str, BaseProcess] = {
            "Client": context.Process(
                name="secure-control-Client",
                target=client_worker,
                args=(
                    child_controls["Client"],
                    client_p1,
                    client_p2,
                    self._spec,
                    self._fixed_point,
                    self._range_contract,
                    self._security_parameter,
                    self._modulus_evidence,
                    self._test_seed,
                ),
            ),
            "P1": context.Process(
                name="secure-control-P1",
                target=role_worker,
                args=(0, child_controls["P1"], p1_client),
            ),
            "P2": context.Process(
                name="secure-control-P2",
                target=role_worker,
                args=(1, child_controls["P2"], p2_client),
            ),
        }
        all_child_connections = (
            *child_controls.values(),
            client_p1,
            p1_client,
            client_p2,
            p2_client,
        )
        try:
            for process in processes.values():
                process.start()
            for connection in all_child_connections:
                connection.close()
            ready = {
                role: self._receive_ready(controls[role], role, self._timeouts.startup)
                for role in ("Client", "P1", "P2")
            }
            session_ids = {message.session_id for message in ready.values()}
            pids = {role: int(message.payload["pid"]) for role, message in ready.items()}
            if len(session_ids) != 1 or None in session_ids:
                raise ProcessProtocolError("三个角色未绑定同一 controller session。")
            if len(set(pids.values())) != 3 or os.getpid() in pids.values():
                raise ProcessProtocolError("Client/P1/P2 必须是不同且非父进程的 PID。")
            if any(processes[role].pid != pid for role, pid in pids.items()):
                raise ProcessProtocolError("角色报告的 PID 与父进程创建记录不匹配。")
            client_payload = ready["Client"].payload
            return _ProcessSession(
                context,
                processes,
                controls,
                ready["Client"].session_id or "",
                client_payload["scale_ledger"],
                client_payload["range_verification"],
                client_payload["modulus_verification"],
                pids,
            )
        except Exception:
            for connection in all_child_connections:
                try:
                    connection.close()
                except OSError:
                    pass
            for connection in controls.values():
                connection.close()
            for process in processes.values():
                if process.pid is None:
                    continue
                if process.is_alive():
                    process.terminate()
                process.join(self._timeouts.shutdown)
            raise

    @staticmethod
    def _receive_ready(connection: Connection, role: str, timeout: float) -> IpcEnvelope:
        if not connection.poll(timeout):
            raise ProcessExecutionTimeout(f"等待 {role} 启动超时。")
        try:
            message = connection.recv()
        except (EOFError, OSError) as error:
            raise ProcessWorkerError(f"{role} 启动期间退出。") from error
        if not isinstance(message, IpcEnvelope) or (
            message.protocol_version,
            message.request_id,
            message.role,
            message.operation,
        ) != (1, 0, role, "ready"):
            if isinstance(message, IpcEnvelope) and message.error_type is not None:
                raise ProcessWorkerError(
                    f"{role} 启动失败：{message.error_type}: {message.error_message}"
                )
            raise ProcessProtocolError(f"{role} 启动响应不合法。")
        return message

    def _stop_session(self, session: _ProcessSession) -> None:
        if session.closed:
            return
        session.closed = True
        if not session.failed:
            pending: list[tuple[str, IpcEnvelope]] = []
            for role in ("Client", "P1", "P2"):
                try:
                    pending.append((role, session.send(role, "shutdown")))
                except ProcessExecutionError:
                    session.failed = True
                    break
            if not session.failed:
                for role, request in pending:
                    try:
                        session.receive(role, request, self._timeouts.shutdown)
                    except ProcessExecutionError:
                        session.failed = True
                        break
        for process in session.processes.values():
            if session.failed and process.is_alive():
                process.terminate()
            process.join(self._timeouts.shutdown)
            if process.is_alive():
                process.terminate()
                process.join(self._timeouts.shutdown)
        for connection in session.controls.values():
            connection.close()
