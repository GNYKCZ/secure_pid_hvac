"""Windows ``spawn`` 角色进程的 localhost TCP 入口与薄命令分发。"""

from __future__ import annotations

import os
import random
import socket
from typing import Literal

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext, PrimeModulusEvidence, TwoPartySharing
from secure_control.protocol import P1, P2, Client, ControllerRangeContract
from secure_control.protocol.coordinator import (
    DirectProtocol3PartyEndpoint,
    LocalProtocol3PartyEndpoint,
    Protocol3Orchestrator,
    dispatch_direct_protocol3_command,
    rehydrate_offline_material,
    rehydrate_online_material,
)
from secure_control.protocol.messages import (
    ControlShareMessage,
    OnlineRound,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyOnlineRound,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
    ResourceMetadata,
    StepResourcePlan,
)

from ._localhost_peer import LocalhostProtocol3PeerPort, accept_p1_peer, connect_p2_peer
from .localhost_codec import (
    SCHEMA_VERSION,
    ClientStepResult,
    HelloPayload,
    PartyStageResult,
    ReadyPayload,
    RemoteErrorPayload,
    WireEnvelope,
)
from .localhost_transport import (
    accept_loopback,
    connect_loopback,
    deadline_after,
    receive_envelope,
    send_envelope,
)

Address = tuple[str, int]
RoleName = Literal["Client", "P1", "P2"]


class _ClientPartyEndpoint:
    """Client 私有通道上的单方 Protocol 3 endpoint；只传调度命令和回执。"""

    def __init__(
        self,
        sock: socket.socket,
        party: Literal[0, 1],
        plan: StepResourcePlan,
        sequence: int,
        limit: int,
        timeout: float,
    ) -> None:
        self._sock = sock
        self._party = party
        self._role: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
        self._plan = plan
        self.sequence = sequence
        self._limit = limit
        self._timeout = timeout
        self.share: ControlShareMessage | None = None

    @property
    def party(self) -> int:
        return self._party

    @property
    def session_id(self) -> str:
        return self._plan.session_id

    @property
    def plan(self) -> StepResourcePlan:
        return self._plan

    def mask_product(self, metadata: ResourceMetadata) -> None:
        self._command("mask_product", metadata)

    def finish_product(self, metadata: ResourceMetadata) -> None:
        self._command("finish_product", metadata)

    def complete_product(self, metadata: ResourceMetadata) -> None:
        self._command("complete_product", metadata)

    def finish_products(self) -> None:
        self._command("finish_products")

    def mask_truncation(self, metadata: ResourceMetadata) -> None:
        self._command("mask_truncation", metadata)

    def send_truncation(self, metadata: ResourceMetadata) -> None:
        self._command("send_truncation", metadata)

    def finish_truncation_p1(self, metadata: ResourceMetadata) -> None:
        self._command("finish_truncation_p1", metadata)

    def finish_truncation_p2(self, metadata: ResourceMetadata) -> None:
        self._command("finish_truncation_p2", metadata)

    def complete_truncation(self, metadata: ResourceMetadata) -> None:
        self._command("complete_truncation", metadata)

    def stage_output(self) -> Protocol3StageReceipt:
        result = self._command("stage_output")
        if not isinstance(result, PartyStageResult):
            raise TypeError("角色未返回暂存回执和单方输出份额。")
        self.share = result.share
        return result.receipt

    def commit(self) -> None:
        self._command("commit")

    def _command(self, operation: str, metadata: ResourceMetadata | None = None) -> object:
        command = Protocol3EndpointCommand(operation, metadata=metadata)
        request = WireEnvelope(
            SCHEMA_VERSION,
            "request",
            "Client",
            self._role,
            self.sequence,
            "endpoint",
            self._plan.session_id,
            self._plan.round_id,
            self._plan.step,
            metadata.resource_id if metadata is not None else None,
            command,
        )
        self.sequence += 1
        deadline = deadline_after(self._timeout)
        send_envelope(self._sock, request, deadline=deadline, limit=self._limit)
        response = receive_envelope(self._sock, deadline=deadline, limit=self._limit)
        _validate_party_reply(response, request)
        if operation != "stage_output" and response.payload is not None:
            raise ValueError("非暂存操作不得返回输出份额或其他 payload。")
        return response.payload


def _validate_party_reply(response: WireEnvelope, request: WireEnvelope) -> None:
    if (
        response.sender != request.recipient
        or response.recipient != "Client"
        or response.sequence != request.sequence
        or response.operation != request.operation
        or (response.session_id, response.round_id, response.step, response.resource_id)
        != (request.session_id, request.round_id, request.step, request.resource_id)
    ):
        raise ValueError("单方回执的方向、顺序或 round identity 不匹配。")
    if response.kind == "error" and isinstance(response.payload, RemoteErrorPayload):
        raise RuntimeError(
            f"{response.sender}.{response.operation} 失败："
            f"{response.payload.error_type}: {response.payload.message}"
        )
    if response.kind != "reply":
        raise ValueError("单方未返回 reply 或受限 error。")


def localhost_client_worker(
    control_address: Address,
    party_addresses: tuple[Address, Address],
    bootstrap_nonce: str,
    spec: ControllerSpec,
    fixed_point: FixedPointContext,
    range_contract: ControllerRangeContract,
    security_parameter: int,
    modulus_evidence: PrimeModulusEvidence | None,
    test_seed: int | None,
    max_frame_bytes: int,
    startup_timeout: float,
    step_timeout: float,
    shutdown_timeout: float,
) -> None:
    """运行唯一 Client；所有 share 只通过对应角色的私有 loopback 连接发送。"""
    control: socket.socket | None = None
    parties: tuple[socket.socket, socket.socket] | None = None
    distribution_session: str | None = None
    ready_sent = False
    try:
        startup_deadline = deadline_after(startup_timeout)
        control = connect_loopback(control_address, deadline=startup_deadline)
        _send_hello(
            control, "Client", "Supervisor", bootstrap_nonce, startup_deadline, max_frame_bytes
        )
        p1 = connect_loopback(party_addresses[0], deadline=startup_deadline)
        p2 = connect_loopback(party_addresses[1], deadline=startup_deadline)
        parties = (p1, p2)
        _send_hello(p1, "Client", "P1", bootstrap_nonce, startup_deadline, max_frame_bytes)
        _send_hello(p2, "Client", "P2", bootstrap_nonce, startup_deadline, max_frame_bytes)

        sharing = TwoPartySharing(fixed_point.modulus)
        client = Client(
            fixed_point,
            sharing,
            security_parameter=security_parameter,
            modulus_evidence=modulus_evidence,
        )
        material_rng = random.Random(test_seed) if test_seed is not None else None
        distribution = client.distribute_controller(spec, range_contract, rng=material_rng)
        distribution_session = distribution.session_id
        for party, message in enumerate((distribution.p1, distribution.p2)):
            _send_data(
                parties[party],
                WireEnvelope(
                    SCHEMA_VERSION,
                    "request",
                    "Client",
                    "P1" if party == 0 else "P2",
                    1,
                    "offline",
                    distribution.session_id,
                    None,
                    None,
                    None,
                    PartyOfflineMaterial.from_message(message),
                ),
                startup_deadline,
                max_frame_bytes,
            )
        _send_data(
            control,
            WireEnvelope(
                SCHEMA_VERSION,
                "ready",
                "Client",
                "Supervisor",
                1,
                "ready",
                distribution.session_id,
                None,
                None,
                None,
                ReadyPayload(
                    os.getpid(),
                    distribution.p1.layout.scale_ledger,
                    client.range_verification,
                    client.truncation.modulus_verification,
                ),
            ),
            startup_deadline,
            max_frame_bytes,
        )
        ready_sent = True
        expected_sequence = 2
        party_sequences = [2, 2]
        expected_step = 0
        while True:
            request = receive_envelope(
                control,
                deadline=deadline_after(24 * 60 * 60),
                limit=max_frame_bytes,
            )
            _validate_control_request(request, "Client", expected_sequence, distribution.session_id)
            expected_sequence += 1
            try:
                if request.operation == "shutdown":
                    for party, sock in enumerate(parties):
                        role_name: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
                        shutdown = WireEnvelope(
                            SCHEMA_VERSION,
                            "shutdown",
                            "Client",
                            role_name,
                            party_sequences[party],
                            "shutdown",
                            distribution.session_id,
                            None,
                            None,
                            None,
                        )
                        deadline = deadline_after(shutdown_timeout)
                        send_envelope(sock, shutdown, deadline=deadline, limit=max_frame_bytes)
                        answer = receive_envelope(sock, deadline=deadline, limit=max_frame_bytes)
                        _validate_party_reply(answer, shutdown)
                    _send_reply(control, request, None, max_frame_bytes, shutdown_timeout)
                    return
                if request.operation == "step":
                    if request.round_id is not None or request.step != expected_step:
                        raise ValueError("Client 单步请求的 round 或 step identity 不匹配。")
                    current: OnlineRound = client.prepare_online(
                        distribution,
                        request.payload,
                        step=expected_step,
                        rng=material_rng,
                    )
                    plan = current.p1_resources.plan
                    if current.p2_resources.plan != plan:
                        raise ValueError("两方在线资源计划不一致。")
                    endpoints: list[_ClientPartyEndpoint] = []
                    for party, online in enumerate(
                        (
                            PartyOnlineRound(current.p1_input, current.p1_resources),
                            PartyOnlineRound(current.p2_input, current.p2_resources),
                        )
                    ):
                        online_request = WireEnvelope(
                            SCHEMA_VERSION,
                            "request",
                            "Client",
                            "P1" if party == 0 else "P2",
                            party_sequences[party],
                            "online",
                            current.session_id,
                            current.round_id,
                            current.step,
                            None,
                            PartyOnlineMaterial.from_round(online),
                        )
                        deadline = deadline_after(step_timeout)
                        send_envelope(
                            parties[party],
                            online_request,
                            deadline=deadline,
                            limit=max_frame_bytes,
                        )
                        answer = receive_envelope(
                            parties[party], deadline=deadline, limit=max_frame_bytes
                        )
                        _validate_party_reply(answer, online_request)
                        endpoints.append(
                            _ClientPartyEndpoint(
                                parties[party],
                                party,
                                plan,
                                party_sequences[party] + 1,
                                max_frame_bytes,
                                step_timeout,
                            )
                        )
                    result = _complete_client_round(client, endpoints[0], endpoints[1], plan)
                    party_sequences = [item.sequence for item in endpoints]
                    expected_step += 1
                    _send_reply(
                        control,
                        request,
                        result,
                        max_frame_bytes,
                        step_timeout,
                    )
                    continue
                raise ValueError(f"Client 不支持操作：{request.operation}")
            except Exception as error:  # noqa: BLE001 - wire 边界必须返回受限角色错误
                _send_error(control, request, error, max_frame_bytes, step_timeout)
                return
    except Exception as error:  # noqa: BLE001 - 启动失败必须尽力通知 supervisor
        if control is not None and not ready_sent:
            _send_startup_error(
                control,
                "Client",
                distribution_session,
                error,
                max_frame_bytes,
            )
    finally:
        _close_socket(control)
        if parties is not None:
            for sock in parties:
                _close_socket(sock)


def localhost_role_worker(
    party: Literal[0, 1],
    control_address: Address,
    data_listener: socket.socket,
    peer_listener: socket.socket | None,
    peer_address: Address | None,
    bootstrap_nonce: str,
    fixed_point: FixedPointContext,
    range_contract: ControllerRangeContract,
    security_parameter: int,
    modulus_evidence: PrimeModulusEvidence | None,
    max_frame_bytes: int,
    startup_timeout: float,
    step_timeout: float,
    shutdown_timeout: float,
) -> None:
    """运行一个 Server；worker 只负责 wire 校验和 protocol-owned endpoint 分发。"""
    role_name: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
    control: socket.socket | None = None
    client_channel: socket.socket | None = None
    session_id: str | None = None
    ready_sent = False
    endpoint: LocalProtocol3PartyEndpoint | None = None
    direct_endpoint: DirectProtocol3PartyEndpoint | None = None
    peer: LocalhostProtocol3PeerPort | None = None
    try:
        startup_deadline = deadline_after(startup_timeout)
        control = connect_loopback(control_address, deadline=startup_deadline)
        _send_hello(
            control, role_name, "Supervisor", bootstrap_nonce, startup_deadline, max_frame_bytes
        )
        if party == 0:
            if peer_listener is None or peer_address is not None:
                raise ValueError("P1 peer listener 配置错误。")
            peer = accept_p1_peer(
                peer_listener, bootstrap_nonce, startup_deadline, max_frame_bytes, step_timeout
            )
            peer_listener.close()
        else:
            if peer_listener is not None or peer_address is None:
                raise ValueError("P2 peer address 配置错误。")
            peer = connect_p2_peer(
                peer_address, bootstrap_nonce, startup_deadline, max_frame_bytes, step_timeout
            )
        client_channel = accept_loopback(data_listener, deadline=startup_deadline)
        data_listener.close()
        hello = receive_envelope(client_channel, deadline=startup_deadline, limit=max_frame_bytes)
        _validate_hello(hello, "Client", role_name, bootstrap_nonce)
        offline_envelope = receive_envelope(
            client_channel, deadline=startup_deadline, limit=max_frame_bytes
        )
        if (
            offline_envelope.kind != "request"
            or offline_envelope.sender != "Client"
            or offline_envelope.recipient != role_name
            or offline_envelope.sequence != 1
            or offline_envelope.operation != "offline"
            or not isinstance(offline_envelope.payload, PartyOfflineMaterial)
        ):
            raise ValueError("Server 离线材料信封不合法。")
        material = offline_envelope.payload
        if material.recipient != party or material.session_id != offline_envelope.session_id:
            raise ValueError("Server 离线材料的角色或 session identity 不匹配。")
        offline = rehydrate_offline_material(material, range_contract)
        if party == 0:
            role: P1 | P2 = P1(offline)
        else:
            role = P2(offline)
        session_id = role.session_id
        peer.bind(session_id)
        _send_data(
            control,
            WireEnvelope(
                SCHEMA_VERSION,
                "ready",
                role_name,
                "Supervisor",
                1,
                "ready",
                role.session_id,
                None,
                None,
                None,
                ReadyPayload(os.getpid()),
            ),
            startup_deadline,
            max_frame_bytes,
        )
        ready_sent = True
        expected_sequence = 2
        expected_step = 0
        while True:
            request = receive_envelope(
                client_channel,
                deadline=deadline_after(24 * 60 * 60),
                limit=max_frame_bytes,
            )
            if (
                request.sender != "Client"
                or request.recipient != role_name
                or request.sequence != expected_sequence
                or request.session_id != role.session_id
                or request.kind != ("shutdown" if request.operation == "shutdown" else "request")
            ):
                raise ValueError("单方私有通道请求的方向、顺序或 session 不匹配。")
            expected_sequence += 1
            try:
                if request.operation == "shutdown":
                    if request.step is not None or request.round_id is not None:
                        raise ValueError("shutdown 不得携带 round identity。")
                    _send_reply(client_channel, request, None, max_frame_bytes, shutdown_timeout)
                    return
                if request.operation == "online":
                    if endpoint is not None:
                        raise RuntimeError("前一 round 尚未提交。")
                    if (
                        not isinstance(request.payload, PartyOnlineMaterial)
                        or request.step != expected_step
                        or request.round_id is None
                        or request.resource_id is not None
                    ):
                        raise ValueError("Server 在线材料信封顺序或 identity 不匹配。")
                    online = rehydrate_online_material(
                        request.payload,
                        modulus=fixed_point.modulus,
                        security_parameter=security_parameter,
                        modulus_evidence=modulus_evidence,
                    )
                    staged_shares: list[ControlShareMessage] = []
                    endpoint = LocalProtocol3PartyEndpoint(
                        role,
                        online,
                        lambda message, collected=staged_shares: _capture_stage_share(
                            message, collected
                        ),
                    )
                    direct_endpoint = DirectProtocol3PartyEndpoint(endpoint, peer)
                    if (endpoint.plan.round_id, endpoint.plan.step) != (
                        request.round_id,
                        request.step,
                    ):
                        raise ValueError("在线材料与信封的 round identity 不匹配。")
                    _send_reply(client_channel, request, None, max_frame_bytes, step_timeout)
                    continue
                if (
                    request.operation != "endpoint"
                    or direct_endpoint is None
                    or not isinstance(request.payload, Protocol3EndpointCommand)
                ):
                    raise RuntimeError("当前没有可执行的 Protocol 3 endpoint command。")
                if (request.round_id, request.step) != (
                    endpoint.plan.round_id,
                    endpoint.plan.step,
                ):
                    raise ValueError("角色请求的 round 或 step identity 不匹配。")
                result = dispatch_direct_protocol3_command(direct_endpoint, request.payload)
                if request.payload.operation == "stage_output":
                    if not isinstance(result, Protocol3StageReceipt) or len(staged_shares) != 1:
                        raise ValueError("角色暂存未产生唯一输出份额。")
                    result = PartyStageResult(result, staged_shares[0])
                if request.payload.operation == "commit":
                    endpoint = None
                    direct_endpoint = None
                    expected_step += 1
                _send_reply(client_channel, request, result, max_frame_bytes, step_timeout)
            except Exception as error:  # noqa: BLE001 - wire 边界必须返回受限角色错误
                _send_error(client_channel, request, error, max_frame_bytes, step_timeout)
                return
    except Exception as error:  # noqa: BLE001 - 启动失败必须尽力通知 supervisor
        if control is not None and not ready_sent:
            _send_startup_error(control, role_name, session_id, error, max_frame_bytes)
    finally:
        _close_socket(control)
        _close_socket(client_channel)
        _close_socket(data_listener)
        _close_socket(peer_listener)
        if peer is not None:
            peer.close()


def _send_hello(
    sock: socket.socket,
    sender: RoleName,
    recipient: Literal["Supervisor", "P1", "P2"],
    nonce: str,
    deadline: float,
    limit: int,
) -> None:
    _send_data(
        sock,
        WireEnvelope(
            SCHEMA_VERSION,
            "hello",
            sender,
            recipient,
            0,
            "hello",
            None,
            None,
            None,
            None,
            HelloPayload(nonce, os.getpid()),
        ),
        deadline,
        limit,
    )


def _validate_hello(
    message: WireEnvelope,
    sender: RoleName,
    recipient: Literal["Supervisor", "P1", "P2"],
    nonce: str,
) -> None:
    if (
        message.kind != "hello"
        or message.sender != sender
        or message.recipient != recipient
        or message.sequence != 0
        or message.operation != "hello"
        or not isinstance(message.payload, HelloPayload)
        or message.payload.nonce != nonce
    ):
        raise ValueError("localhost hello 身份或 nonce 不匹配。")


def _validate_control_request(
    message: WireEnvelope,
    role: RoleName,
    sequence: int,
    session_id: str,
) -> None:
    expected_kind = "shutdown" if message.operation == "shutdown" else "request"
    if (
        message.kind != expected_kind
        or message.sender != "Supervisor"
        or message.recipient != role
        or message.sequence != sequence
        or message.session_id != session_id
    ):
        raise ValueError("localhost control 请求的方向、顺序或 session 不匹配。")


def _send_reply(
    sock: socket.socket,
    request: WireEnvelope,
    payload: object,
    limit: int,
    timeout: float,
) -> None:
    _send_data(
        sock,
        WireEnvelope(
            SCHEMA_VERSION,
            "reply",
            request.recipient,
            request.sender,
            request.sequence,
            request.operation,
            request.session_id,
            request.round_id,
            request.step,
            request.resource_id,
            payload,  # type: ignore[arg-type]
        ),
        deadline_after(timeout),
        limit,
    )


def _send_error(
    sock: socket.socket,
    request: WireEnvelope,
    error: BaseException,
    limit: int,
    timeout: float,
) -> None:
    message = str(error)[:1024] or type(error).__name__
    _send_data(
        sock,
        WireEnvelope(
            SCHEMA_VERSION,
            "error",
            request.recipient,
            request.sender,
            request.sequence,
            request.operation,
            request.session_id,
            request.round_id,
            request.step,
            request.resource_id,
            RemoteErrorPayload(type(error).__name__, message),
        ),
        deadline_after(timeout),
        limit,
    )


def _send_startup_error(
    sock: socket.socket,
    role: RoleName,
    session_id: str | None,
    error: BaseException,
    limit: int,
) -> None:
    try:
        _send_data(
            sock,
            WireEnvelope(
                SCHEMA_VERSION,
                "error",
                role,
                "Supervisor",
                1,
                "ready",
                session_id,
                None,
                None,
                None,
                RemoteErrorPayload(
                    type(error).__name__, (str(error) or type(error).__name__)[:1024]
                ),
            ),
            deadline_after(1.0),
            limit,
        )
    except Exception:  # noqa: BLE001 - 原始异常已在主路径处理，通知失败不能覆盖它
        return


def _capture_stage_share(
    message: ControlShareMessage, collected: list[ControlShareMessage]
) -> None:
    if collected:
        raise ValueError("角色不得重复暂存控制份额。")
    collected.append(message)


def _complete_client_round(
    client: Client,
    first: _ClientPartyEndpoint,
    second: _ClientPartyEndpoint,
    plan: StepResourcePlan,
) -> ClientStepResult:
    """仅在两方暂存、重构与双提交均完成后签发父进程可见结果。"""
    orchestrator = Protocol3Orchestrator()
    receipts = orchestrator.stage(first, second, plan)
    shares = (first.share, second.share)
    if not all(isinstance(share, ControlShareMessage) for share in shares):
        raise ValueError("Client 未收到两份暂存控制份额。")
    output = client.reconstruct_control(shares[0], shares[1])
    result = np.asarray(output, dtype=float)
    if result.shape != plan.output_shape or not np.isfinite(result).all():
        raise ValueError("Client 重构输出 shape 或有限性不合法。")
    # P2 提交或回执不确定时不能返回结果；调用方必须废弃整组角色。
    orchestrator.commit(first, second)
    return ClientStepResult(
        result, plan.round_id, plan.step, receipts[0].products, receipts[0].truncations
    )


def _send_data(
    sock: socket.socket,
    message: WireEnvelope,
    deadline: float,
    limit: int,
) -> None:
    send_envelope(sock, message, deadline=deadline, limit=limit)


def _close_socket(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()
