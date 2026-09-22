"""Windows ``spawn`` 角色进程的 localhost TCP 入口与薄命令分发。"""

from __future__ import annotations

import os
import random
import socket
from typing import Literal

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext, PrimeModulusEvidence, TwoPartySharing
from secure_control.protocol import P1, P2, Client, ControllerRangeContract
from secure_control.protocol.coordinator import (
    LocalProtocol3PartyEndpoint,
    dispatch_protocol3_command,
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
)

from .localhost_codec import (
    HelloPayload,
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
    current: OnlineRound | None = None
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
                    1,
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
                1,
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
        expected_sequence = 2
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
                    _send_reply(control, request, None, max_frame_bytes, shutdown_timeout)
                    return
                if request.operation == "prepare":
                    if current is not None:
                        raise RuntimeError("前一 round 尚未结束。")
                    if request.round_id is not None:
                        raise ValueError("prepare 请求不得预先指定 round identity。")
                    current = client.prepare_online(
                        distribution,
                        request.payload,
                        step=request.step if request.step is not None else -1,
                        rng=material_rng,
                    )
                    _send_reply(
                        control,
                        request,
                        current.p1_resources.plan,
                        max_frame_bytes,
                        step_timeout,
                    )
                    for party, online in enumerate(
                        (
                            PartyOnlineRound(current.p1_input, current.p1_resources),
                            PartyOnlineRound(current.p2_input, current.p2_resources),
                        )
                    ):
                        _send_data(
                            parties[party],
                            WireEnvelope(
                                1,
                                "request",
                                "Client",
                                "P1" if party == 0 else "P2",
                                2 + current.step,
                                "online",
                                current.session_id,
                                current.round_id,
                                current.step,
                                None,
                                PartyOnlineMaterial.from_round(online),
                            ),
                            deadline_after(step_timeout),
                            max_frame_bytes,
                        )
                    continue
                if request.operation == "reconstruct":
                    if current is None:
                        raise RuntimeError("没有可重构的当前 round。")
                    identity = (current.session_id, current.round_id, current.step)
                    if (request.session_id, request.round_id, request.step) != identity:
                        raise ValueError("reconstruct 请求的 round 或 step identity 不匹配。")
                    outputs = tuple(
                        _receive_control_share(
                            sock,
                            party,
                            identity,
                            current.step + 1,
                            max_frame_bytes,
                            step_timeout,
                        )
                        for party, sock in enumerate(parties)
                    )
                    output = client.reconstruct_control(outputs[0], outputs[1])
                    current = None
                    _send_reply(control, request, output, max_frame_bytes, step_timeout)
                    continue
                raise ValueError(f"Client 不支持操作：{request.operation}")
            except Exception as error:  # noqa: BLE001 - wire 边界必须返回受限角色错误
                _send_error(control, request, error, max_frame_bytes, step_timeout)
                return
    except Exception as error:  # noqa: BLE001 - 启动失败必须尽力通知 supervisor
        if control is not None:
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
    endpoint: LocalProtocol3PartyEndpoint | None = None
    try:
        startup_deadline = deadline_after(startup_timeout)
        control = connect_loopback(control_address, deadline=startup_deadline)
        _send_hello(
            control, role_name, "Supervisor", bootstrap_nonce, startup_deadline, max_frame_bytes
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
        _send_data(
            control,
            WireEnvelope(
                1,
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
        expected_sequence = 2
        while True:
            request = receive_envelope(
                control,
                deadline=deadline_after(24 * 60 * 60),
                limit=max_frame_bytes,
            )
            _validate_control_request(request, role_name, expected_sequence, role.session_id)
            expected_sequence += 1
            try:
                if request.operation == "shutdown":
                    _send_reply(control, request, None, max_frame_bytes, shutdown_timeout)
                    return
                if request.operation == "begin":
                    if endpoint is not None:
                        raise RuntimeError("前一 round 尚未提交。")
                    online_envelope = receive_envelope(
                        client_channel,
                        deadline=deadline_after(step_timeout),
                        limit=max_frame_bytes,
                    )
                    expected_data_sequence = 2 + (request.step if request.step is not None else -1)
                    if (
                        online_envelope.kind != "request"
                        or online_envelope.sender != "Client"
                        or online_envelope.recipient != role_name
                        or online_envelope.sequence != expected_data_sequence
                        or online_envelope.operation != "online"
                        or not isinstance(online_envelope.payload, PartyOnlineMaterial)
                        or (
                            online_envelope.session_id,
                            online_envelope.round_id,
                            online_envelope.step,
                        )
                        != (request.session_id, request.round_id, request.step)
                    ):
                        raise ValueError("Server 在线材料信封顺序或 identity 不匹配。")
                    online = rehydrate_online_material(
                        online_envelope.payload,
                        modulus=fixed_point.modulus,
                        security_parameter=security_parameter,
                        modulus_evidence=modulus_evidence,
                    )
                    endpoint = LocalProtocol3PartyEndpoint(
                        role,
                        online,
                        lambda message: _send_control_share(
                            client_channel,
                            role_name,
                            message,
                            max_frame_bytes,
                            step_timeout,
                        ),
                    )
                    _send_reply(control, request, None, max_frame_bytes, step_timeout)
                    continue
                if (
                    request.operation != "endpoint"
                    or endpoint is None
                    or not isinstance(request.payload, Protocol3EndpointCommand)
                ):
                    raise RuntimeError("当前没有可执行的 Protocol 3 endpoint command。")
                if (request.round_id, request.step) != (
                    endpoint.plan.round_id,
                    endpoint.plan.step,
                ):
                    raise ValueError("角色请求的 round 或 step identity 不匹配。")
                result = dispatch_protocol3_command(endpoint, request.payload)
                if request.payload.operation == "commit":
                    endpoint = None
                _send_reply(control, request, result, max_frame_bytes, step_timeout)
            except Exception as error:  # noqa: BLE001 - wire 边界必须返回受限角色错误
                _send_error(control, request, error, max_frame_bytes, step_timeout)
                return
    except Exception as error:  # noqa: BLE001 - 启动失败必须尽力通知 supervisor
        if control is not None:
            _send_startup_error(control, role_name, session_id, error, max_frame_bytes)
    finally:
        _close_socket(control)
        _close_socket(client_channel)
        _close_socket(data_listener)


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
            1,
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
            1,
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
            1,
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
                1,
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


def _send_control_share(
    sock: socket.socket,
    role: Literal["P1", "P2"],
    message: ControlShareMessage,
    limit: int,
    timeout: float,
) -> None:
    _send_data(
        sock,
        WireEnvelope(
            1,
            "request",
            role,
            "Client",
            message.step + 1,
            "control_share",
            message.session_id,
            message.round_id,
            message.step,
            None,
            message,
        ),
        deadline_after(timeout),
        limit,
    )


def _receive_control_share(
    sock: socket.socket,
    party: int,
    identity: tuple[str, str, int],
    sequence: int,
    limit: int,
    timeout: float,
) -> ControlShareMessage:
    message = receive_envelope(sock, deadline=deadline_after(timeout), limit=limit)
    role: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
    if (
        message.kind != "request"
        or message.sender != role
        or message.recipient != "Client"
        or message.sequence != sequence
        or message.operation != "control_share"
        or (message.session_id, message.round_id, message.step) != identity
        or not isinstance(message.payload, ControlShareMessage)
        or message.payload.sender != party
    ):
        raise ValueError("control share wire identity 不匹配。")
    return message.payload


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
