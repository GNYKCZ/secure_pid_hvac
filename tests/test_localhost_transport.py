"""localhost wire codec、framing、runtime 与清理边界测试。"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import AdditiveShare, FixedPointContext
from secure_control.execution import (
    LocalhostExecutionError,
    LocalhostPeerError,
    LocalhostSecureStateSpaceRuntime,
    LocalhostStateError,
    LocalhostTimeoutError,
    MultiprocessingSecureStateSpaceRuntime,
)
from secure_control.execution.localhost_codec import (
    HelloPayload,
    LocalhostCodecError,
    WireEnvelope,
    decode_envelope,
    decode_wire_value,
    encode_envelope,
    encode_wire_value,
)
from secure_control.execution.localhost_transport import (
    LocalhostTimeouts,
    LocalhostTransportConfig,
    LocalhostTransportProtocolError,
    LocalhostTransportTimeout,
    deadline_after,
    receive_frame,
    send_frame,
)
from secure_control.experiments.localhost_runner import run_localhost_comparison
from secure_control.protocol import ControllerRangeContract

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


def test_wire_envelope_round_trip_preserves_version_direction_and_identity() -> None:
    message = WireEnvelope(
        1,
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
                1,
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
        ("schema_version", 2),
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
                1,
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
        Path(__file__).parents[1] / "configs" / "hvac_dual_loop.yaml",
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
    runtime._session.controls["P1"].close()
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
