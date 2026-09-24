"""localhost wire codec、framing、runtime 与清理边界测试。"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import fields
from pathlib import Path

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import AdditiveShare, FixedPointContext
from secure_control.execution import (
    LocalhostExecutionError,
    LocalhostPeerError,
    LocalhostProtocolError,
    LocalhostSecureStateSpaceRuntime,
    LocalhostStateError,
    LocalhostTimeoutError,
    MultiprocessingSecureStateSpaceRuntime,
    _localhost_workers,
)
from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
from secure_control.execution.localhost_codec import (
    SCHEMA_VERSION,
    ClientStepResult,
    HelloPayload,
    LocalhostCodecError,
    PartyStageResult,
    WireEnvelope,
    decode_envelope,
    decode_wire_value,
    encode_envelope,
    encode_wire_value,
)
from secure_control.execution.localhost_runtime import _execution_error
from secure_control.execution.localhost_transport import (
    LocalhostTimeouts,
    LocalhostTransportConfig,
    LocalhostTransportDisconnected,
    LocalhostTransportProtocolError,
    LocalhostTransportTimeout,
    deadline_after,
    receive_frame,
    send_envelope,
    send_frame,
)
from secure_control.experiments.localhost_runner import run_localhost_comparison
from secure_control.protocol import ControllerRangeContract, ControllerScaleLedger
from secure_control.protocol.messages import (
    ControlShareMessage,
    P2TruncationPayload,
    ProductMaskPayload,
    Protocol3StageReceipt,
    ResourceMetadata,
    StepResourcePlan,
)
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation.engine import compare_closed_loops
from secure_control.simulation.telemetry import (
    BoundedPublisher,
    Sample,
    SessionEnded,
    SessionFault,
    SessionStarted,
    TelemetrySession,
    public_event_json,
)

_DEFAULT_TRANSPORT = LocalhostTransportConfig()


def _general_spec() -> ControllerSpec:
    return ControllerSpec(
        A=np.array([[0.5]]),
        B=np.array([[0.25]]),
        C=np.array([[1.0]]),
        D=np.array([[0.5]]),
        x0=np.array([0.5]),
    )


def _runtime(
    spec: ControllerSpec | None = None,
    *,
    seed: int = 700,
    transport: LocalhostTransportConfig = _DEFAULT_TRANSPORT,
    horizon: int = 8,
) -> LocalhostSecureStateSpaceRuntime:
    selected = _general_spec() if spec is None else spec
    return LocalhostSecureStateSpaceRuntime(
        selected,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,) * selected.state_dimension,
            input_payload_bounds=(512,) * selected.input_dimension,
            horizon_steps=horizon,
        ),
        security_parameter=8,
        test_seed=seed,
        transport=transport,
    )


def test_bigint_scalar_and_object_array_round_trip_without_fixed_width_conversion() -> None:
    scalar = AdditiveShare(-(1 << 200) + 17)
    vector = np.array([1 << 180, -(1 << 190), 0], dtype=object)

    assert decode_wire_value(encode_wire_value(scalar)) == scalar
    decoded = decode_wire_value(encode_wire_value(AdditiveShare(vector)))
    assert isinstance(decoded, AdditiveShare)
    np.testing.assert_array_equal(decoded.value, vector)
    assert np.asarray(decoded.value).dtype == object


def test_public_int64_input_array_round_trip_preserves_low_bits() -> None:
    vector = np.array([(1 << 60) - 1, -((1 << 60) - 1)], dtype=np.int64)

    decoded = decode_wire_value(encode_wire_value(vector))

    assert isinstance(decoded, np.ndarray)
    assert decoded.dtype == object
    assert tuple(int(item) for item in decoded) == tuple(int(item) for item in vector)


def test_large_legal_int64_step_matches_multiprocessing_backend() -> None:
    spec = ControllerSpec(
        A=np.empty((0, 0)),
        B=np.empty((0, 1)),
        C=np.empty((1, 0)),
        D=np.array([[0.0]]),
        x0=np.empty((0,)),
    )
    fixed_point = FixedPointContext((1 << 61) - 1, integer_bits=60, fractional_bits=1)
    range_contract = ControllerRangeContract(
        state_payload_bounds=(),
        input_payload_bounds=((1 << 59) - 2,),
        horizon_steps=1,
    )
    input_vector = np.array([(1 << 58) - 1], dtype=np.int64)
    process = MultiprocessingSecureStateSpaceRuntime(
        spec, fixed_point, range_contract, security_parameter=8, test_seed=704
    )
    localhost = LocalhostSecureStateSpaceRuntime(
        spec, fixed_point, range_contract, security_parameter=8, test_seed=704
    )
    with process, localhost:
        expected = process.step(input_vector)
        actual = localhost.step(input_vector)

    np.testing.assert_array_equal(actual, expected)


def test_wire_envelope_round_trip_preserves_version_direction_and_identity() -> None:
    message = WireEnvelope(
        SCHEMA_VERSION,
        "hello",
        "P1",
        "Supervisor",
        0,
        "hello",
        None,
        None,
        None,
        None,
        HelloPayload("nonce-value", 1234),
    )

    assert decode_envelope(encode_envelope(message)) == message


def test_schema_v3_restricts_step_result_and_stage_share_to_their_owner_channels() -> None:
    """父进程只能收到已提交的公开结果，原始输出份额只可留在 Client 私有通道。"""
    result = ClientStepResult(np.array([0.25]), "round-0", 0, 4, 1)
    public = WireEnvelope(
        SCHEMA_VERSION,
        "reply",
        "Client",
        "Supervisor",
        2,
        "step",
        "session-0",
        None,
        0,
        None,
        result,
    )
    assert isinstance(decode_envelope(encode_envelope(public)).payload, ClientStepResult)
    stage = PartyStageResult(
        Protocol3StageReceipt(0, "session-0", "round-0", 0, 4, 1),
        ControlShareMessage(0, "session-0", "round-0", 0, 16, AdditiveShare(5)),
    )
    private = WireEnvelope(
        SCHEMA_VERSION,
        "reply",
        "P1",
        "Client",
        4,
        "endpoint",
        "session-0",
        "round-0",
        0,
        None,
        stage,
    )
    assert isinstance(decode_envelope(encode_envelope(private)).payload, PartyStageResult)
    with pytest.raises(LocalhostCodecError):
        WireEnvelope(
            SCHEMA_VERSION,
            "reply",
            "P1",
            "Supervisor",
            4,
            "endpoint",
            "session-0",
            "round-0",
            0,
            None,
            stage,
        )
    with pytest.raises(LocalhostCodecError):
        WireEnvelope(
            SCHEMA_VERSION,
            "reply",
            "Client",
            "Supervisor",
            2,
            "step",
            "session-0",
            None,
            1,
            None,
            result,
        )
    with pytest.raises(ValueError):
        PartyStageResult(
            stage.receipt,
            ControlShareMessage(0, "session-0", "other-round", 0, 16, AdditiveShare(5)),
        )


def test_peer_port_exchanges_only_protocol_messages_and_parent_reply_rejects_shares() -> None:
    """P1/P2 peer port 直接传递允许的在线 payload，endpoint reply 不可携带 share。"""
    first_socket, second_socket = socket.socketpair()
    metadata = ResourceMetadata(
        "resource-0",
        "session-0",
        "round-0",
        0,
        "multiplication",
        "D",
        (0, 0),
        (1,),
        8,
        8,
        16,
    )
    first = LocalhostProtocol3PeerPort(first_socket, "P1", 1024, 1.0)
    second = LocalhostProtocol3PeerPort(second_socket, "P2", 1024, 1.0)
    first.bind(metadata.session_id)
    second.bind(metadata.session_id)
    try:
        first_payload = ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 0)
        second_payload = ProductMaskPayload(AdditiveShare(7), AdditiveShare(11), 1)
        first.send_product(metadata, first_payload)
        second.send_product(metadata, second_payload)
        assert second.receive_product(metadata) == first_payload
        assert first.receive_product(metadata) == second_payload
        truncation = P2TruncationPayload(AdditiveShare(13))
        second.send_truncation(metadata, truncation)
        assert first.receive_truncation(metadata) == truncation
        with pytest.raises(ValueError, match="只有 P2"):
            first.send_truncation(metadata, truncation)
        with pytest.raises(LocalhostCodecError):
            WireEnvelope(
                SCHEMA_VERSION,
                "reply",
                "P1",
                "Supervisor",
                9,
                "endpoint",
                metadata.session_id,
                metadata.round_id,
                metadata.step,
                metadata.resource_id,
                first_payload,
            )
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize(
    ("kind", "operation", "sender", "recipient", "payload", "accepted"),
    (
        (
            "request",
            "peer_product",
            "P1",
            "P2",
            ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 0),
            True,
        ),
        (
            "request",
            "peer_product",
            "P2",
            "P1",
            ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 1),
            True,
        ),
        (
            "request",
            "peer_product",
            "P1",
            "Supervisor",
            ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 0),
            False,
        ),
        (
            "request",
            "peer_product",
            "P1",
            "Client",
            ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 0),
            False,
        ),
        (
            "reply",
            "peer_product",
            "P1",
            "P2",
            ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 0),
            False,
        ),
        ("request", "peer_truncation", "P2", "P1", P2TruncationPayload(AdditiveShare(1)), True),
        ("request", "peer_truncation", "P1", "P2", P2TruncationPayload(AdditiveShare(1)), False),
        (
            "request",
            "peer_truncation",
            "P2",
            "Supervisor",
            P2TruncationPayload(AdditiveShare(1)),
            False,
        ),
        (
            "request",
            "peer_truncation",
            "P2",
            "Client",
            P2TruncationPayload(AdditiveShare(1)),
            False,
        ),
        ("reply", "peer_truncation", "P2", "P1", P2TruncationPayload(AdditiveShare(1)), False),
        ("request", "peer_product", "P2", "P1", P2TruncationPayload(AdditiveShare(1)), False),
        (
            "request",
            "peer_truncation",
            "P2",
            "P1",
            ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 1),
            False,
        ),
    ),
)
def test_codec_enforces_schema_v3_peer_direction_matrix(
    kind: str, operation: str, sender: str, recipient: str, payload: object, accepted: bool
) -> None:
    """schema owner 必须在解码前拒绝进入 Supervisor/Client 的在线 peer payload。"""
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "sender": sender,
        "recipient": recipient,
        "sequence": 1,
        "operation": operation,
        "session_id": "session-0",
        "round_id": "round-0",
        "step": 0,
        "resource_id": "resource-0",
        "payload": json.loads(encode_wire_value(payload)),
    }
    encoded = json.dumps(envelope, separators=(",", ":")).encode()
    if accepted:
        assert decode_envelope(encoded).payload == payload
    else:
        with pytest.raises(LocalhostCodecError):
            decode_envelope(encoded)


@pytest.mark.parametrize(
    ("sequence", "operation", "round_id", "step", "resource_id", "payload"),
    (
        (
            0,
            "peer_product",
            "round-0",
            0,
            "resource-0",
            ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 1),
        ),
        (
            2,
            "peer_product",
            "round-0",
            0,
            "resource-0",
            ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 1),
        ),
        (
            1,
            "peer_product",
            "other-round",
            0,
            "resource-0",
            ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 1),
        ),
        (
            1,
            "peer_product",
            "round-0",
            1,
            "resource-0",
            ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 1),
        ),
        (
            1,
            "peer_product",
            "round-0",
            0,
            "other-resource",
            ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 1),
        ),
        (1, "peer_truncation", "round-0", 0, "resource-0", P2TruncationPayload(AdditiveShare(7))),
    ),
)
def test_peer_port_rejects_bad_sequence_identity_and_operation(
    sequence: int, operation: str, round_id: str, step: int, resource_id: str, payload: object
) -> None:
    """peer port 的接收边界拒绝错序、错资源与错误的 Protocol 2/1 操作替换。"""
    receiver, sender = socket.socketpair()
    metadata = _peer_metadata()
    port = LocalhostProtocol3PeerPort(receiver, "P1", 1024, 1.0)
    port.bind(metadata.session_id)
    try:
        send_envelope(
            sender,
            WireEnvelope(
                SCHEMA_VERSION,
                "request",
                "P2",
                "P1",
                sequence,
                operation,
                metadata.session_id,
                round_id,
                step,
                resource_id,
                payload,  # type: ignore[arg-type]
            ),
            deadline=deadline_after(1.0),
            limit=1024,
        )
        with pytest.raises(ValueError, match="顺序、方向或 identity"):
            port.receive_product(metadata)
    finally:
        port.close()
        sender.close()


def test_peer_port_rejects_duplicate_sequence_after_a_valid_message() -> None:
    """消费过的 peer sequence 不能因 duplicate payload 被再次接受。"""
    receiver, sender = socket.socketpair()
    metadata = _peer_metadata()
    port = LocalhostProtocol3PeerPort(receiver, "P1", 1024, 1.0)
    port.bind(metadata.session_id)
    payload = ProductMaskPayload(AdditiveShare(3), AdditiveShare(5), 1)
    try:
        for _ in range(2):
            send_envelope(
                sender,
                WireEnvelope(
                    SCHEMA_VERSION,
                    "request",
                    "P2",
                    "P1",
                    1,
                    "peer_product",
                    metadata.session_id,
                    metadata.round_id,
                    metadata.step,
                    metadata.resource_id,
                    payload,
                ),
                deadline=deadline_after(1.0),
                limit=1024,
            )
        assert port.receive_product(metadata) == payload
        with pytest.raises(ValueError, match="顺序、方向或 identity"):
            port.receive_product(metadata)
    finally:
        port.close()
        sender.close()


def test_peer_port_disconnect_and_timeout_are_bounded() -> None:
    """peer 断开或静默不产生回退；调用方获得 transport 异常以触发 session fail-closed。"""
    receiver, sender = socket.socketpair()
    metadata = _peer_metadata()
    disconnected = LocalhostProtocol3PeerPort(receiver, "P1", 1024, 1.0)
    disconnected.bind(metadata.session_id)
    sender.close()
    try:
        with pytest.raises(LocalhostTransportDisconnected):
            disconnected.receive_product(metadata)
    finally:
        disconnected.close()

    receiver, sender = socket.socketpair()
    half_frame = LocalhostProtocol3PeerPort(receiver, "P1", 1024, 1.0)
    half_frame.bind(metadata.session_id)
    sender.sendall(struct.pack("!I", 16) + b"partial")
    sender.close()
    try:
        with pytest.raises(LocalhostTransportDisconnected):
            half_frame.receive_product(metadata)
    finally:
        half_frame.close()

    receiver, sender = socket.socketpair()
    timed_out = LocalhostProtocol3PeerPort(receiver, "P1", 1024, 0.02)
    timed_out.bind(metadata.session_id)
    started = time.monotonic()
    try:
        with pytest.raises(LocalhostTransportTimeout):
            timed_out.receive_product(metadata)
        assert time.monotonic() - started < 0.5
    finally:
        timed_out.close()
        sender.close()


def _peer_metadata() -> ResourceMetadata:
    """构造不依赖 controller 的最小合法 Protocol 1 resource identity。"""
    return ResourceMetadata(
        "resource-0",
        "session-0",
        "round-0",
        0,
        "multiplication",
        "D",
        (0, 0),
        (1,),
        8,
        8,
        16,
    )


@pytest.mark.parametrize(
    "payload",
    (
        b'{"schema_version":1,"schema_version":1}',
        b'{"type":"bigint","decimal":"01"}',
        b'{"type":"bigint_array","shape":[2],"values":["1"]}',
        b"\xff",
        b'{"value":NaN}',
    ),
)
def test_codec_rejects_duplicate_noncanonical_malformed_and_nonfinite_json(payload: bytes) -> None:
    decoder = (
        decode_envelope if b"schema_version" in payload or payload == b"\xff" else decode_wire_value
    )
    with pytest.raises(LocalhostCodecError):
        decoder(payload)


def test_framing_handles_fragmented_and_coalesced_tcp_bytes() -> None:
    receiver, sender = socket.socketpair()
    try:
        first = b"fragmented-payload"
        framed = struct.pack("!I", len(first)) + first
        for chunk in (framed[:1], framed[1:3], framed[3:7], framed[7:]):
            sender.sendall(chunk)
        send_frame(sender, b"second", deadline=deadline_after(1.0), limit=1024)

        assert receive_frame(receiver, deadline=deadline_after(1.0), limit=1024) == first
        assert receive_frame(receiver, deadline=deadline_after(1.0), limit=1024) == b"second"
    finally:
        receiver.close()
        sender.close()


def test_framing_rejects_empty_oversized_and_incomplete_frames_with_total_deadline() -> None:
    receiver, sender = socket.socketpair()
    try:
        sender.sendall(struct.pack("!I", 0))
        with pytest.raises(LocalhostTransportProtocolError, match="长度"):
            receive_frame(receiver, deadline=deadline_after(1.0), limit=16)

        sender.sendall(struct.pack("!I", 17))
        with pytest.raises(LocalhostTransportProtocolError, match="上限"):
            receive_frame(receiver, deadline=deadline_after(1.0), limit=16)

        sender.sendall(struct.pack("!I", 4) + b"x")
        started = time.monotonic()
        with pytest.raises(LocalhostTransportTimeout):
            receive_frame(receiver, deadline=deadline_after(0.02), limit=16)
        assert time.monotonic() - started < 0.5
    finally:
        receiver.close()
        sender.close()


@pytest.mark.parametrize(
    "kwargs",
    (
        {"host": "0.0.0.0"},
        {"host": "localhost"},
        {"port": True},
        {"port": 65536},
        {"max_frame_bytes": 0},
        {"timeouts": LocalhostTimeouts(step=1.0)},
    ),
)
def test_transport_config_accepts_only_explicit_loopback_and_bounded_values(
    kwargs: dict[str, object],
) -> None:
    if kwargs == {"timeouts": LocalhostTimeouts(step=1.0)}:
        assert LocalhostTransportConfig(**kwargs).timeouts.step == 1.0
    else:
        with pytest.raises((TypeError, ValueError)):
            LocalhostTransportConfig(**kwargs)


def test_unknown_envelope_fields_are_rejected() -> None:
    message = json.loads(
        encode_envelope(
            WireEnvelope(
                SCHEMA_VERSION,
                "hello",
                "P1",
                "Supervisor",
                0,
                "hello",
                None,
                None,
                None,
                None,
                HelloPayload("nonce", 1),
            )
        )
    )
    message["unexpected"] = True
    with pytest.raises(LocalhostCodecError, match="字段集合"):
        decode_envelope(json.dumps(message).encode())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", 1),
        ("schema_version", 2),
        ("schema_version", True),
        ("schema_version", 1.0),
        ("kind", "unknown"),
        ("sender", "External"),
        ("operation", "arbitrary"),
        ("sequence", -1),
        ("step", -1),
    ),
)
def test_envelope_rejects_unknown_version_role_operation_and_negative_identity(
    field: str, value: object
) -> None:
    message = json.loads(
        encode_envelope(
            WireEnvelope(
                SCHEMA_VERSION,
                "hello",
                "P1",
                "Supervisor",
                0,
                "hello",
                None,
                None,
                None,
                None,
                HelloPayload("nonce", 1),
            )
        )
    )
    message[field] = value
    with pytest.raises(LocalhostCodecError):
        decode_envelope(json.dumps(message).encode())


def test_localhost_runtime_uses_distinct_loopback_roles_and_matches_issue16_backend() -> None:
    spec = _general_spec()
    process = MultiprocessingSecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,), input_payload_bounds=(512,), horizon_steps=8
        ),
        security_parameter=8,
        test_seed=701,
    )
    with process, _runtime(spec, seed=701) as localhost:
        values = (0.1, -0.2, 0.05)
        expected = np.vstack([process.step(value) for value in values])
        actual = np.vstack([localhost.step(value) for value in values])
        topology = localhost.topology

        np.testing.assert_array_equal(actual, expected)
        assert topology.host == "127.0.0.1"
        assert topology.port > 0
        assert {item.role for item in topology.roles} == {"Client", "P1", "P2"}
        assert len({item.pid for item in topology.roles}) == 3
        assert os.getpid() not in {item.pid for item in topology.roles}
        assert localhost.resource_counts == process.resource_counts


def test_parent_sends_only_one_client_step_request_per_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """父进程不得重新持有资源计划或向任一 Server 发送在线调度命令。"""
    with _runtime(horizon=3) as runtime:
        session_type = type(runtime._session)
        original = session_type.request
        calls: list[tuple[str, str]] = []

        def record_request(
            self: object, role: str, operation: str, *args: object, **kwargs: object
        ) -> object:
            calls.append((role, operation))
            return original(self, role, operation, *args, **kwargs)

        monkeypatch.setattr(session_type, "request", record_request)
        assert runtime.step(0.0).shape == (1,)
        assert runtime.step(0.25).shape == (1,)
        assert calls == [("Client", "step"), ("Client", "step")]
        assert runtime.resource_counts == {"products_consumed": 8, "truncations_consumed": 2}


def test_client_rejects_duplicate_step_and_discards_the_session() -> None:
    """同一 Client 会话不能重放上一轮输入或续用其已消耗资源。"""
    runtime = _runtime(horizon=3)
    try:
        runtime.step(0.0)
        with pytest.raises(LocalhostPeerError, match="step identity") as remote_failure:
            runtime._session.request(
                "Client",
                "step",
                2.0,
                step=0,
                payload=np.array([0.0]),
            )
        assert getattr(remote_failure.value, "_public_fault_category", None) is None
        with pytest.raises(LocalhostStateError, match="已失败"):
            runtime.step(0.0)
    finally:
        runtime.close()


@pytest.mark.parametrize("failure", ("reconstruct", "p2_commit"))
def test_client_never_reports_success_for_reconstruction_or_second_commit_failure(
    failure: str,
) -> None:
    """P1 已提交但 P2 回执不确定时仍不得向父进程发布成功结果。"""
    plan = StepResourcePlan(
        "session-0",
        "round-0",
        0,
        (0,),
        (1,),
        (1,),
        ControllerScaleLedger(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (),
        (),
    )
    events: list[str] = []

    class _Endpoint:
        def __init__(self, party: int) -> None:
            self.party = party
            self.session_id = plan.session_id
            self.plan = plan
            self.share: ControlShareMessage | None = None

        def finish_products(self) -> None:
            events.append(f"p{self.party + 1}_stage")

        def stage_output(self) -> Protocol3StageReceipt:
            self.share = ControlShareMessage(
                self.party,
                plan.session_id,
                plan.round_id,
                plan.step,
                0,
                AdditiveShare(self.party + 1),
            )
            return Protocol3StageReceipt(
                self.party,
                plan.session_id,
                plan.round_id,
                plan.step,
                0,
                0,
            )

        def commit(self) -> None:
            events.append(f"p{self.party + 1}_commit")
            if failure == "p2_commit" and self.party == 1:
                raise TimeoutError("P2 提交回执丢失")

    class _Client:
        def reconstruct_control(self, first: object, second: object) -> np.ndarray:
            events.append("reconstruct")
            if failure == "reconstruct":
                raise ValueError("重构失败")
            return np.array([0.25])

    with pytest.raises((ValueError, TimeoutError)):
        _localhost_workers._complete_client_round(
            _Client(),
            _Endpoint(0),
            _Endpoint(1),
            plan,  # type: ignore[arg-type]
        )
    if failure == "reconstruct":
        assert events == ["p1_stage", "p2_stage", "reconstruct"]
    else:
        assert events == [
            "p1_stage",
            "p2_stage",
            "reconstruct",
            "p1_commit",
            "p2_commit",
        ]


@pytest.mark.parametrize("response_kind", ("wrong_payload", "timeout"))
def test_client_rejects_uncertain_party_commit_ack(response_kind: str) -> None:
    """提交回执缺失或错配时不能把本地调用视为已确认提交。"""
    plan = StepResourcePlan(
        "session-0",
        "round-0",
        0,
        (0,),
        (1,),
        (1,),
        ControllerScaleLedger(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (),
        (),
    )
    client_sock, party_sock = socket.socketpair()
    try:
        endpoint = _localhost_workers._ClientPartyEndpoint(
            client_sock,
            1,
            plan,
            3,
            4096,
            0.02,
        )
        if response_kind == "wrong_payload":
            staged = PartyStageResult(
                Protocol3StageReceipt(1, plan.session_id, plan.round_id, 0, 0, 0),
                ControlShareMessage(1, plan.session_id, plan.round_id, 0, 0, AdditiveShare(1)),
            )
            send_envelope(
                party_sock,
                WireEnvelope(
                    SCHEMA_VERSION,
                    "reply",
                    "P2",
                    "Client",
                    3,
                    "endpoint",
                    plan.session_id,
                    plan.round_id,
                    0,
                    None,
                    staged,
                ),
                deadline=deadline_after(1.0),
                limit=4096,
            )
            with pytest.raises(ValueError, match="非暂存操作"):
                endpoint.commit()
        else:
            with pytest.raises(LocalhostTransportTimeout):
                endpoint.commit()
    finally:
        client_sock.close()
        party_sock.close()


def test_vector_zero_state_and_no_truncation_match_issue16_backend() -> None:
    vector = ControllerSpec(
        A=np.array([[0.5, 0.0], [0.25, 0.5]]),
        B=np.array([[0.25, 0.0], [0.0, 0.25]]),
        C=np.array([[1.0, 0.0], [0.0, 1.0]]),
        D=np.array([[0.5, 0.0], [0.0, -0.5]]),
        x0=np.array([0.5, -0.25]),
    )
    static = ControllerSpec(
        A=np.empty((0, 0)),
        B=np.empty((0, 1)),
        C=np.empty((1, 0)),
        D=np.array([[0.75]]),
        x0=np.empty((0,)),
    )
    no_truncation = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[-1.0]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(
            state=8,
            input=8,
            output=16,
            A=0,
            B=0,
            C=8,
            D=8,
        ),
    )
    cases = (
        (vector, (np.array([0.25, -0.5]), np.array([0.0, 0.125]))),
        (static, (0.25, -0.5)),
        (no_truncation, (0.25, -0.5)),
    )
    for spec, values in cases:
        process = MultiprocessingSecureStateSpaceRuntime(
            spec,
            FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
            ControllerRangeContract(
                state_payload_bounds=(512,) * spec.state_dimension,
                input_payload_bounds=(512,) * spec.input_dimension,
                horizon_steps=8,
            ),
            security_parameter=8,
            test_seed=703,
        )
        with process, _runtime(spec, seed=703) as localhost:
            expected = np.vstack([process.step(value) for value in values])
            actual = np.vstack([localhost.step(value) for value in values])
            np.testing.assert_array_equal(actual, expected)
            assert localhost.resource_counts == process.resource_counts
        if spec is no_truncation:
            assert localhost.resource_counts["truncations_consumed"] == 0


def test_hvac_180_step_runner_matches_issue16_backend_and_cleans_up() -> None:
    summary = run_localhost_comparison(
        Path(__file__).parents[1] / "tests" / "fixtures" / "legacy_hvac" / "hvac_dual_loop.yaml",
        test_seed=905,
    )

    assert summary["host"] == "127.0.0.1"
    assert summary["port"] > 0
    assert summary["sample_count"] == 180
    assert len(set(summary["role_pids"].values())) == 3
    assert summary["maximum_control_difference"] == 0.0
    assert summary["maximum_output_difference"] == 0.0
    assert summary["resource_counts_match_issue16"] is True
    assert summary["resource_counts"] == {
        "products_consumed": 1620,
        "truncations_consumed": 0,
    }
    assert summary["cleanup"] == "closed"


def test_hvac_180_step_result_fields_match_issue16_without_semantic_drift() -> None:
    """八个仿真结果字段逐采样一致，且不改变 HVAC 的时间索引和结果契约。"""
    config = Path(__file__).parents[1] / "tests" / "fixtures" / "legacy_hvac" / "hvac_dual_loop.yaml"
    baseline = HvacScenario(
        config,
        test_seed=905,
        secure_runtime_builder=MultiprocessingSecureStateSpaceRuntime,
    ).build_plan()
    localhost = HvacScenario(
        config,
        test_seed=905,
        secure_runtime_builder=LocalhostSecureStateSpaceRuntime,
    ).build_plan()
    try:
        expected = compare_closed_loops(
            baseline.ideal,
            baseline.secure,
            baseline.sample_times,
        )
        actual = compare_closed_loops(
            localhost.ideal,
            localhost.secure,
            localhost.sample_times,
        )
        assert len(fields(actual)) == 8
        for field in fields(actual):
            np.testing.assert_array_equal(
                getattr(actual, field.name), getattr(expected, field.name)
            )
    finally:
        baseline.secure.runtime.close()
        localhost.secure.runtime.close()


def test_localhost_step_identity_mismatch_publishes_protocol_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """真实 Client 首步成功后伪造第二步回执 identity，验证运行时和公开故障边界。"""
    config = Path(__file__).parents[1] / "tests" / "fixtures" / "legacy_hvac" / "hvac_dual_loop.yaml"
    plan = HvacScenario(
        config, test_seed=905, secure_runtime_builder=LocalhostSecureStateSpaceRuntime
    ).build_plan()
    runtime = plan.secure.runtime
    assert isinstance(runtime, LocalhostSecureStateSpaceRuntime)
    delivered: list[object] = []
    ended = threading.Event()

    def consumer(event: object) -> None:
        delivered.append(event)
        if isinstance(event, SessionEnded):
            ended.set()

    publisher = BoundedPublisher(consumer)
    telemetry = TelemetrySession(publisher, session_id="public-protocol-fault")
    original_request = type(runtime._session).request

    def mismatched_second_reply(
        session: object, role: str, operation: str, timeout: float, **kwargs: object
    ) -> object:
        if role == "Client" and operation == "step" and kwargs.get("step") == 1:
            return ClientStepResult(np.array([0.0]), "injected-round", 2, 0, 0)
        return original_request(session, role, operation, timeout, **kwargs)

    monkeypatch.setattr(type(runtime._session), "request", mismatched_second_reply)
    try:
        with pytest.raises(LocalhostProtocolError, match="step 不合法"):
            compare_closed_loops(
                plan.ideal, plan.secure, plan.sample_times[:2], telemetry=telemetry
            )
        assert ended.wait(2.0)
        assert [type(event) for event in delivered] == [
            SessionStarted, Sample, SessionFault, SessionEnded
        ]
        assert delivered[1].step == 0
        assert delivered[2].step == 1
        assert delivered[2].category == "protocol"
        assert delivered[3].status == "failed"
        assert delivered[3].last_successful_step == 0
        assert "injected-round" not in "".join(public_event_json(event) for event in delivered)
        assert runtime.topology.roles[0].status == "failed"
    finally:
        publisher.close()
        runtime.close()


def test_localhost_socket_disconnect_publishes_disconnected_without_relabeling_peer_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """确认断开的控制 socket 保留原因；远端受限错误仍不冒充断线。"""
    disconnected = _execution_error(LocalhostTransportDisconnected("private-wire"), "step")
    remote_error = LocalhostPeerError("private-remote-error")
    assert type(disconnected) is LocalhostPeerError
    assert getattr(disconnected, "_public_fault_category", None) == "disconnected"
    assert getattr(remote_error, "_public_fault_category", None) is None

    config = Path(__file__).parents[1] / "tests" / "fixtures" / "legacy_hvac" / "hvac_dual_loop.yaml"
    plan = HvacScenario(
        config, test_seed=905, secure_runtime_builder=LocalhostSecureStateSpaceRuntime
    ).build_plan()
    runtime = plan.secure.runtime
    assert isinstance(runtime, LocalhostSecureStateSpaceRuntime)
    delivered: list[object] = []
    ended = threading.Event()

    def consumer(event: object) -> None:
        delivered.append(event)
        if isinstance(event, SessionEnded):
            ended.set()

    publisher = BoundedPublisher(consumer)
    telemetry = TelemetrySession(publisher, session_id="public-disconnect")
    original_plant_step = plan.secure.plant.step
    calls = 0

    def disconnect_after_first_step(control: np.ndarray) -> np.ndarray:
        nonlocal calls
        output = original_plant_step(control)
        calls += 1
        if calls == 1:
            runtime._session.controls["Client"].shutdown(socket.SHUT_RDWR)
        return output

    monkeypatch.setattr(plan.secure.plant, "step", disconnect_after_first_step)
    try:
        with pytest.raises(LocalhostPeerError) as caught:
            compare_closed_loops(
                plan.ideal, plan.secure, plan.sample_times[:2], telemetry=telemetry
            )
        assert isinstance(caught.value.__cause__, LocalhostTransportDisconnected)
        assert getattr(caught.value, "_public_fault_category", None) == "disconnected"
        assert ended.wait(2.0)
        assert [type(event) for event in delivered] == [
            SessionStarted, Sample, SessionFault, SessionEnded
        ]
        assert delivered[1].step == 0
        assert delivered[2].step == 1
        assert delivered[2].category == "disconnected"
        assert delivered[3].status == "failed"
        assert delivered[3].last_successful_step == 0
        assert [event.event_seq for event in delivered] == [0, 1, 2, 3]
        assert "private-wire" not in "".join(public_event_json(event) for event in delivered)
        assert runtime.topology.roles[0].status == "failed"
    finally:
        publisher.close()
        runtime.close()


def test_port_collision_is_reported_without_starting_children() -> None:
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    before = {process.pid for process in mp.active_children()}
    try:
        config = LocalhostTransportConfig(port=blocker.getsockname()[1])
        with pytest.raises(LocalhostExecutionError, match="绑定"):
            _runtime(transport=config)
        assert {process.pid for process in mp.active_children()} == before
    finally:
        blocker.close()


def test_reset_close_and_port_release_are_bounded_and_idempotent() -> None:
    runtime = _runtime()
    port = runtime.topology.port
    first_pids = {item.pid for item in runtime.topology.roles}
    first = runtime.step(0.0)
    runtime.reset()
    assert first_pids.isdisjoint({item.pid for item in runtime.topology.roles})
    np.testing.assert_array_equal(runtime.step(0.0), first)
    runtime.close()
    runtime.close()
    with pytest.raises(LocalhostStateError, match="已经关闭"):
        runtime.step(0.0)

    rebound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        rebound.bind(("127.0.0.1", port))
    finally:
        rebound.close()


def test_failed_replacement_reset_keeps_old_ready_session(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(horizon=3)
    old_pids = {item.pid for item in runtime.topology.roles}

    def fail_replacement() -> None:
        raise LocalhostExecutionError("replacement startup failed")

    monkeypatch.setattr(runtime, "_start_session", fail_replacement)
    try:
        with pytest.raises(LocalhostExecutionError, match="replacement"):
            runtime.reset()
        assert {item.pid for item in runtime.topology.roles} == old_pids
        assert runtime.step(0.0).shape == (1,)
    finally:
        runtime.close()


def test_disconnect_and_step_timeout_fail_closed_and_reap_every_role() -> None:
    runtime = _runtime()
    role_pids = {item.pid for item in runtime.topology.roles}
    role = runtime._session.processes["P1"]
    role.terminate()
    role.join(1.0)
    with pytest.raises(LocalhostPeerError):
        runtime.step(0.0)
    assert all(item.status == "failed" for item in runtime.topology.roles)
    assert role_pids.isdisjoint(
        {process.pid for process in mp.active_children() if process.pid is not None}
    )

    timeout_runtime = _runtime(
        transport=LocalhostTransportConfig(
            timeouts=LocalhostTimeouts(startup=10.0, step=0.02, shutdown=5.0)
        )
    )
    timeout_pids = {item.pid for item in timeout_runtime.topology.roles}
    stalled_parent, stalled_peer = socket.socketpair()
    original_client = timeout_runtime._session.controls["Client"]
    timeout_runtime._session.controls["Client"] = stalled_parent
    original_client.close()
    try:
        with pytest.raises(LocalhostTimeoutError):
            timeout_runtime.step(0.0)
    finally:
        stalled_peer.close()
    assert timeout_pids.isdisjoint(
        {process.pid for process in mp.active_children() if process.pid is not None}
    )


@pytest.mark.parametrize("party", ("P1", "P2"))
def test_party_disconnect_fails_closed_without_resource_reuse_and_reset_recovers(
    party: str,
) -> None:
    """单方中断由 Client 发现；父进程不能继续旧会话，只有新会话可恢复。"""
    runtime = _runtime(
        transport=LocalhostTransportConfig(
            timeouts=LocalhostTimeouts(startup=10.0, step=0.2, shutdown=5.0)
        )
    )
    original_pids = {item.pid for item in runtime.topology.roles}
    original_session_id = runtime._session.session_id
    lost = runtime._session.processes[party]
    lost.terminate()
    lost.join(1.0)
    try:
        with pytest.raises(LocalhostPeerError):
            runtime.step(0.0)
        assert runtime.resource_counts == {"products_consumed": 0, "truncations_consumed": 0}
        assert runtime._step_index == 0
        assert all(item.status == "failed" for item in runtime.topology.roles)
        assert original_pids.isdisjoint(
            {process.pid for process in mp.active_children() if process.pid is not None}
        )
        with pytest.raises(LocalhostStateError, match="已失败"):
            runtime.step(0.0)

        runtime.reset()
        assert original_pids.isdisjoint({item.pid for item in runtime.topology.roles})
        assert runtime._session.session_id != original_session_id
        np.testing.assert_array_equal(runtime.step(0.0), np.array([0.5]))
        assert runtime.resource_counts == {"products_consumed": 4, "truncations_consumed": 1}
    finally:
        runtime.close()


def test_partial_startup_failure_and_import_have_no_resource_side_effects() -> None:
    before = {process.pid for process in mp.active_children()}
    with pytest.raises(LocalhostPeerError, match="Client 启动失败"):
        LocalhostSecureStateSpaceRuntime(
            _general_spec(),
            FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
            ControllerRangeContract(
                state_payload_bounds=(1,), input_payload_bounds=(512,), horizon_steps=1
            ),
            security_parameter=8,
            test_seed=702,
        )
    assert {process.pid for process in mp.active_children()} == before

    script = (
        "import json, multiprocessing as mp, socket; "
        "before=len(mp.active_children()); "
        "import secure_control.execution; "
        "probe=socket.socket(); probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]; "
        "probe.close(); print(json.dumps([before,len(mp.active_children()),port>0]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(completed.stdout) == [0, 0, True]
