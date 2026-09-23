"""无 Supervisor 的三主机单 session 单步生命周期与公开时延测量。"""

from __future__ import annotations

import os
import secrets
import ssl
import time
from typing import Any, Literal

import numpy as np

from secure_control.crypto import FixedPointContext, TwoPartySharing
from secure_control.protocol import P1, P2, Client, ControllerRangeContract
from secure_control.protocol.coordinator import (
    DirectProtocol3PartyEndpoint,
    LocalProtocol3PartyEndpoint,
    dispatch_direct_protocol3_command,
    rehydrate_offline_material,
    rehydrate_online_material,
)
from secure_control.protocol.messages import (
    ControlShareMessage,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyOnlineRound,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
)

from ._localhost_peer import LocalhostProtocol3PeerPort
from ._localhost_workers import (
    _capture_stage_share,
    _ClientPartyEndpoint,
    _complete_client_round,
    _validate_party_reply,
)
from .lan_config import LanConfig, Role
from .lan_transport import accept_tls, connect_tls, listener
from .localhost_codec import (
    SCHEMA_VERSION,
    LanHelloPayload,
    LanSetupPayload,
    PartyStageResult,
    RemoteErrorPayload,
    WireEnvelope,
)
from .localhost_transport import deadline_after, receive_envelope, send_envelope

_FRAME_LIMIT = 8 * 1024 * 1024


def run_client_single_step(config: LanConfig, trial: Any) -> dict[str, object]:
    """Client 独立拨号、分发、驱动一次协议、双提交并有界关闭三条 mTLS 连接。"""
    if config.role != "Client":
        raise ValueError("只有 Client 配置可启动 LAN 单步。")
    if trial.modulus_evidence is not None or trial.range_contract.closed_loop_evidence is not None:
        raise ValueError("LAN 首个冻结单步仅支持内置 64-bit 素数与有限时域范围契约。")
    client = Client(
        trial.fixed_point,
        TwoPartySharing(trial.fixed_point.modulus),
        security_parameter=trial.security_parameter,
        modulus_evidence=trial.modulus_evidence,
    )
    distribution = client.distribute_controller(trial.spec, trial.range_contract)
    session = distribution.session_id
    hello = LanHelloPayload(config.topology.digest, secrets.token_hex(32))
    stamps: dict[str, int] = {"trial_start": time.perf_counter_ns()}
    sockets: list[ssl.SSLSocket] = []
    committed = False
    try:
        for role, address in (("P1", config.topology.p1_client), ("P2", config.topology.p2_client)):
            sock = connect_tls(address, config, role, deadline_after(config.startup_timeout))
            sockets.append(sock)
            _hello(sock, "Client", role, session, hello, config.startup_timeout)
        stamps["tls_hello"] = time.perf_counter_ns()
        for party, sock in enumerate(sockets):
            _request(
                sock, "P1" if party == 0 else "P2", 1, "lan_ready", session, config.startup_timeout
            )
        stamps["peer_ready"] = time.perf_counter_ns()
        setup = LanSetupPayload(
            trial.fixed_point.modulus,
            trial.fixed_point.integer_bits,
            trial.fixed_point.fractional_bits,
            trial.security_parameter,
            trial.range_contract.state_payload_bounds,
            trial.range_contract.input_payload_bounds,
            trial.range_contract.horizon_steps,
        )
        for party, sock in enumerate(sockets):
            role: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
            _request(sock, role, 2, "lan_setup", session, config.startup_timeout, setup)
            material = distribution.p1 if party == 0 else distribution.p2
            _request(
                sock,
                role,
                3,
                "offline",
                session,
                config.startup_timeout,
                PartyOfflineMaterial.from_message(material),
            )
        stamps["offline"] = time.perf_counter_ns()
        stamps["step_start"] = time.perf_counter_ns()
        step_deadline = deadline_after(config.step_timeout)
        current = client.prepare_online(distribution, trial.controller_input, step=0)
        plan = current.p1_resources.plan
        if current.p2_resources.plan != plan:
            raise ValueError("两方在线资源计划不一致。")
        stamps["prepared"] = time.perf_counter_ns()
        endpoints: list[_ClientPartyEndpoint] = []
        for party, sock in enumerate(sockets):
            role = "P1" if party == 0 else "P2"
            online = PartyOnlineRound(
                current.p1_input if party == 0 else current.p2_input,
                current.p1_resources if party == 0 else current.p2_resources,
            )
            _request(
                sock,
                role,
                4,
                "online",
                session,
                config.step_timeout,
                PartyOnlineMaterial.from_round(online),
                plan.round_id,
                0,
                deadline=step_deadline,
            )
            endpoints.append(
                _ClientPartyEndpoint(
                    sock, party, plan, 5, _FRAME_LIMIT, config.step_timeout, step_deadline
                )
            )
        stamps["distributed"] = time.perf_counter_ns()
        result = _complete_client_round(
            client,
            endpoints[0],
            endpoints[1],
            plan,
            lambda phase: stamps.__setitem__(phase, time.perf_counter_ns()),
        )
        committed = True
        for party, sock in enumerate(sockets):
            role = "P1" if party == 0 else "P2"
            _request(
                sock,
                role,
                endpoints[party].sequence,
                "shutdown",
                session,
                config.shutdown_timeout,
                shutdown=True,
            )
        stamps["closed"] = time.perf_counter_ns()
        output = np.asarray(result.output, dtype=float)
        return {
            "status": "complete",
            "pid": os.getpid(),
            "profile_sha256": config.topology.digest,
            "raw_control": output.tolist(),
            "baseline_raw_control": np.asarray(trial.expected_raw_output, dtype=float).tolist(),
            "maximum_raw_difference": float(np.max(np.abs(output - trial.expected_raw_output))),
            "controller_config_sha256": trial.config_sha256,
            "resource_counts": {
                "products_consumed": result.products,
                "truncations_consumed": result.truncations,
            },
            "timings_ms": _timings(stamps),
            "tls_version": "TLSv1.3",
        }
    except Exception:
        # 双提交完成但关闭回执不确定时也不输出完整成功结果；不重新拨号或重放材料。
        if committed:
            raise RuntimeError("控制步已双提交，但安全会话关闭未确认。") from None
        raise
    finally:
        for sock in sockets:
            sock.close()


def run_party_single_step(config: LanConfig) -> dict[str, object]:
    """P1/P2 只监听本机固定端口，接受一轮已认证会话后退出。"""
    if config.role not in {"P1", "P2"}:
        raise ValueError("角色命令必须是 P1 或 P2。")
    role: Literal["P1", "P2"] = config.role
    party = 0 if role == "P1" else 1
    address = config.topology.p1_client if party == 0 else config.topology.p2_client
    client_listener = listener(address)
    peer_listener = None
    client_socket: ssl.SSLSocket | None = None
    peer_socket: ssl.SSLSocket | None = None
    peer_port: LocalhostProtocol3PeerPort | None = None
    try:
        if party == 0:
            peer_listener = listener(config.topology.p1_peer)
        startup_deadline = deadline_after(config.startup_timeout)
        client_socket = accept_tls(client_listener, config, "Client", startup_deadline)
        session, hello = _accept_hello(
            client_socket,
            "Client",
            role,
            config,
            startup_deadline,
        )
        if party == 0:
            assert peer_listener is not None
            peer_socket = accept_tls(peer_listener, config, "P2", startup_deadline)
            _accept_hello(
                peer_socket, "P2", "P1", config, startup_deadline, expected=(session, hello)
            )
        else:
            peer_socket = connect_tls(config.topology.p1_peer, config, "P1", startup_deadline)
            _hello(peer_socket, "P2", "P1", session, hello, config.startup_timeout)
        _party_reply(
            client_socket,
            _party_receive(client_socket, role, 1, "lan_ready", session, config.startup_timeout),
            None,
            config.startup_timeout,
        )
        setup_request = _party_receive(
            client_socket, role, 2, "lan_setup", session, config.startup_timeout
        )
        setup = setup_request.payload
        if not isinstance(setup, LanSetupPayload):
            raise TypeError("公开 LAN setup 类型不合法。")
        fixed = FixedPointContext(
            setup.modulus, integer_bits=setup.integer_bits, fractional_bits=setup.fractional_bits
        )
        range_contract = ControllerRangeContract(
            setup.state_payload_bounds,
            setup.input_payload_bounds,
            setup.horizon_steps,
        )
        _party_reply(client_socket, setup_request, None, config.startup_timeout)
        offline_request = _party_receive(
            client_socket, role, 3, "offline", session, config.startup_timeout
        )
        material = offline_request.payload
        if (
            not isinstance(material, PartyOfflineMaterial)
            or material.recipient != party
            or material.session_id != session
        ):
            raise ValueError("离线单方材料的角色不匹配。")
        offline = rehydrate_offline_material(material, range_contract)
        role_object = P1(offline) if party == 0 else P2(offline)
        _party_reply(client_socket, offline_request, None, config.startup_timeout)
        step_deadline = deadline_after(config.step_timeout)
        online_request = _party_receive(
            client_socket,
            role,
            4,
            "online",
            session,
            config.step_timeout,
            deadline=step_deadline,
        )
        if online_request.step != 0 or online_request.round_id is None:
            raise ValueError("LAN 单步只接受 step=0。")
        online_material = online_request.payload
        if not isinstance(online_material, PartyOnlineMaterial):
            raise TypeError("在线单方材料类型错误。")
        online = rehydrate_online_material(
            online_material,
            modulus=fixed.modulus,
            security_parameter=setup.security_parameter,
            modulus_evidence=None,
        )
        staged: list[ControlShareMessage] = []
        peer_port = LocalhostProtocol3PeerPort(
            peer_socket, role, _FRAME_LIMIT, config.step_timeout, step_deadline
        )
        peer_port.bind(session)
        endpoint = LocalProtocol3PartyEndpoint(
            role_object,
            online,
            lambda message: _capture_stage_share(message, staged),
        )
        if (endpoint.plan.round_id, endpoint.plan.step) != (online_request.round_id, 0):
            raise ValueError("在线材料与信封 round identity 不匹配。")
        direct = DirectProtocol3PartyEndpoint(endpoint, peer_port)
        _party_reply(
            client_socket, online_request, None, config.step_timeout, deadline=step_deadline
        )
        sequence = 5
        while True:
            command_request = receive_envelope(
                client_socket,
                deadline=step_deadline,
                limit=_FRAME_LIMIT,
            )
            _check_request(command_request, role, sequence, "endpoint", session)
            if (command_request.round_id, command_request.step) != (
                endpoint.plan.round_id,
                endpoint.plan.step,
            ) or not isinstance(command_request.payload, Protocol3EndpointCommand):
                raise ValueError("endpoint command 与当前 round 不匹配。")
            try:
                result = dispatch_direct_protocol3_command(direct, command_request.payload)
                if command_request.payload.operation == "stage_output":
                    if not isinstance(result, Protocol3StageReceipt) or len(staged) != 1:
                        raise ValueError("暂存回执与输出份额不完整。")
                    result = PartyStageResult(result, staged[0])
                _party_reply(
                    client_socket,
                    command_request,
                    result,
                    config.step_timeout,
                    deadline=step_deadline,
                )
            except Exception as error:
                _party_error(client_socket, command_request, error, config.step_timeout)
                raise
            sequence += 1
            if command_request.payload.operation == "commit":
                # 单次试验提交后只能关闭；不接受第二轮或旧资源重放。
                shutdown_request = _party_receive(
                    client_socket, role, sequence, "shutdown", session, config.shutdown_timeout
                )
                _party_reply(client_socket, shutdown_request, None, config.shutdown_timeout)
                return {
                    "status": "closed",
                    "role": role,
                    "pid": os.getpid(),
                    "profile_sha256": config.topology.digest,
                }
    finally:
        client_listener.close()
        if peer_listener is not None:
            peer_listener.close()
        if client_socket is not None:
            client_socket.close()
        if peer_port is not None:
            peer_port.close()
        elif peer_socket is not None:
            peer_socket.close()


def _hello(
    sock: ssl.SSLSocket,
    sender: Role,
    recipient: Role,
    session: str,
    hello: LanHelloPayload,
    timeout: float,
) -> None:
    envelope = WireEnvelope(
        SCHEMA_VERSION,
        "hello",
        sender,
        recipient,
        0,
        "lan_hello",
        session,
        None,
        None,
        None,
        hello,
    )
    deadline = deadline_after(timeout)
    send_envelope(sock, envelope, deadline=deadline, limit=_FRAME_LIMIT)
    response = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    if (
        response.kind,
        response.sender,
        response.recipient,
        response.sequence,
        response.operation,
        response.session_id,
        response.payload,
    ) != (
        "hello",
        recipient,
        sender,
        0,
        "lan_hello",
        session,
        hello,
    ):
        raise ValueError("LAN hello 的角色、版本、拓扑或 session 不匹配。")


def _accept_hello(
    sock: ssl.SSLSocket,
    sender: Role,
    recipient: Role,
    config: LanConfig,
    deadline: float,
    *,
    expected: tuple[str, LanHelloPayload] | None = None,
) -> tuple[str, LanHelloPayload]:
    request = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    payload = request.payload
    if (
        request.kind != "hello"
        or request.sender != sender
        or request.recipient != recipient
        or request.sequence != 0
        or request.operation != "lan_hello"
        or request.session_id is None
        or request.round_id is not None
        or request.step is not None
        or request.resource_id is not None
        or not isinstance(payload, LanHelloPayload)
        or payload.profile_sha256 != config.topology.digest
        or (expected is not None and (request.session_id, payload) != expected)
    ):
        raise ValueError("LAN hello 的身份、模式、拓扑或 session 不匹配。")
    send_envelope(
        sock,
        WireEnvelope(
            SCHEMA_VERSION,
            "hello",
            recipient,
            sender,
            0,
            "lan_hello",
            request.session_id,
            None,
            None,
            None,
            payload,
        ),
        deadline=deadline,
        limit=_FRAME_LIMIT,
    )
    return request.session_id, payload


def _request(
    sock: ssl.SSLSocket,
    role: Literal["P1", "P2"],
    sequence: int,
    operation: str,
    session: str,
    timeout: float,
    payload: object = None,
    round_id: str | None = None,
    step: int | None = None,
    *,
    shutdown: bool = False,
    deadline: float | None = None,
) -> object:
    request = WireEnvelope(
        SCHEMA_VERSION,
        "shutdown" if shutdown else "request",
        "Client",
        role,
        sequence,
        operation,
        session,
        round_id,
        step,
        None,
        payload,  # type: ignore[arg-type]
    )
    deadline = deadline_after(timeout) if deadline is None else deadline
    send_envelope(sock, request, deadline=deadline, limit=_FRAME_LIMIT)
    response = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    _validate_party_reply(response, request)
    if response.payload is not None:
        raise ValueError("LAN 准备或关闭回执不得携带私有 payload。")
    return response.payload


def _party_receive(
    sock: ssl.SSLSocket,
    role: Literal["P1", "P2"],
    sequence: int,
    operation: str,
    session: str,
    timeout: float,
    *,
    deadline: float | None = None,
) -> WireEnvelope:
    message = receive_envelope(
        sock,
        deadline=deadline_after(timeout) if deadline is None else deadline,
        limit=_FRAME_LIMIT,
    )
    _check_request(message, role, sequence, operation, session)
    if operation in {"lan_ready", "lan_setup", "offline", "shutdown"} and (
        message.round_id is not None or message.step is not None or message.resource_id is not None
    ):
        raise ValueError("LAN 准备或关闭请求不得携带 round identity。")
    return message


def _check_request(
    message: WireEnvelope,
    role: Literal["P1", "P2"],
    sequence: int,
    operation: str,
    session: str,
) -> None:
    if (
        message.kind,
        message.sender,
        message.recipient,
        message.sequence,
        message.operation,
        message.session_id,
    ) != (
        "shutdown" if operation == "shutdown" else "request",
        "Client",
        role,
        sequence,
        operation,
        session,
    ):
        raise ValueError("LAN 请求的角色、顺序、操作或 session 不匹配。")


def _party_reply(
    sock: ssl.SSLSocket,
    request: WireEnvelope,
    payload: object,
    timeout: float,
    *,
    deadline: float | None = None,
) -> None:
    send_envelope(
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
        deadline=deadline_after(timeout) if deadline is None else deadline,
        limit=_FRAME_LIMIT,
    )


def _party_error(
    sock: ssl.SSLSocket, request: WireEnvelope, error: Exception, timeout: float
) -> None:
    try:
        send_envelope(
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
                RemoteErrorPayload(type(error).__name__, "protocol failure"),
            ),
            deadline=deadline_after(timeout),
            limit=_FRAME_LIMIT,
        )
    except Exception:  # noqa: BLE001 - 通知失败不能覆盖原始协议异常
        return


def _timings(stamps: dict[str, int]) -> dict[str, float]:
    spans = {
        "tcp_tls_hello": ("trial_start", "tls_hello"),
        "peer_ready": ("tls_hello", "peer_ready"),
        "offline": ("peer_ready", "offline"),
        "online_prepare": ("step_start", "prepared"),
        "online_distribute": ("prepared", "distributed"),
        "party_compute_stage": ("distributed", "stage"),
        "reconstruct": ("stage", "reconstruct"),
        "double_commit": ("reconstruct", "commit"),
        "shutdown": ("commit", "closed"),
        "step_end_to_end": ("step_start", "commit"),
        "trial_total": ("trial_start", "closed"),
    }
    return {name: (stamps[end] - stamps[start]) / 1_000_000 for name, (start, end) in spans.items()}
