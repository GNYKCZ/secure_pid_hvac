"""spawn 多进程安全运行时的数值、拓扑与清理测试。"""

from __future__ import annotations

import multiprocessing as mp
import os
import random
from dataclasses import replace

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import FixedPointContext, TwoPartySharing
from secure_control.execution import (
    ControllerRuntime,
    MultiprocessingSecureStateSpaceRuntime,
    ProcessExecutionTimeout,
    ProcessProtocolError,
    ProcessStateError,
    ProcessTimeouts,
    ProcessWorkerError,
    SecureStateSpaceRuntime,
)
from secure_control.execution._multiprocessing_workers import IpcEnvelope
from secure_control.execution.multiprocessing_runtime import _ProcessSession
from secure_control.protocol import Client, ControllerRangeContract
from secure_control.protocol.messages import (
    PartyOnlineRound,
    StepResourcePlan,
)


def _general_spec() -> ControllerSpec:
    return ControllerSpec(
        A=np.array([[0.5]]),
        B=np.array([[0.25]]),
        C=np.array([[1.0]]),
        D=np.array([[0.5]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=8, B=8, C=8, D=8),
    )


def _runtime(spec: ControllerSpec, *, seed: int = 100) -> MultiprocessingSecureStateSpaceRuntime:
    return MultiprocessingSecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,) * spec.state_dimension,
            input_payload_bounds=(512,) * spec.input_dimension,
            horizon_steps=16,
        ),
        security_parameter=8,
        test_seed=seed,
    )


def _single(spec: ControllerSpec, *, seed: int = 100) -> SecureStateSpaceRuntime:
    return SecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,) * spec.state_dimension,
            input_payload_bounds=(512,) * spec.input_dimension,
            horizon_steps=16,
        ),
        security_parameter=8,
        test_seed=seed,
    )


def _online_plan() -> tuple[StepResourcePlan, PartyOnlineRound, PartyOnlineRound]:
    """建立含 general Trunc 的真实计划及严格分离的两份角色 payload。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(
        fixed_point,
        TwoPartySharing(fixed_point.modulus),
        security_parameter=8,
    )
    distribution = client.distribute_controller(
        _general_spec(),
        ControllerRangeContract(
            state_payload_bounds=(512,), input_payload_bounds=(512,), horizon_steps=2
        ),
        rng=random.Random(800),
    )
    online = client.prepare_online(
        distribution,
        np.array([0.0]),
        step=0,
        rng=random.Random(801),
    )
    return (
        online.p1_resources.plan,
        PartyOnlineRound(online.p1_input, online.p1_resources),
        PartyOnlineRound(online.p2_input, online.p2_resources),
    )


@pytest.mark.integration
def test_spawn_roles_are_distinct_and_general_sequence_matches_single_process() -> None:
    spec = _general_spec()
    single = _single(spec)
    with _runtime(spec) as runtime:
        inputs = (0.1, -0.2, 0.05, 0.15)
        actual = np.vstack([runtime.step(value) for value in inputs])
        expected = np.vstack([single.step(value) for value in inputs])
        topology = runtime.topology

        assert isinstance(runtime, ControllerRuntime)
        assert topology.start_method == "spawn"
        assert topology.parent_pid == os.getpid()
        assert {item.role for item in topology.roles} == {"Client", "P1", "P2"}
        assert len({item.pid for item in topology.roles}) == 3
        assert os.getpid() not in {item.pid for item in topology.roles}
        assert all(item.status == "ready" for item in topology.roles)
        assert runtime.resource_counts == {
            "products_consumed": 16,
            "truncations_consumed": 4,
        }
        np.testing.assert_array_equal(actual, expected)


@pytest.mark.integration
def test_vector_and_zero_state_controllers_match_single_process() -> None:
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
    for spec, values in (
        (vector, (np.array([0.25, -0.5]), np.array([0.0, 0.125]))),
        (static, (0.25, -0.5)),
    ):
        single = _single(spec, seed=300)
        with _runtime(spec, seed=300) as runtime:
            actual = np.vstack([runtime.step(value) for value in values])
            expected = np.vstack([single.step(value) for value in values])
        np.testing.assert_array_equal(actual, expected)


@pytest.mark.integration
def test_large_legal_online_material_does_not_block_prepare_pipe() -> None:
    dimension = 10
    spec = ControllerSpec(
        A=np.zeros((dimension, dimension)),
        B=np.zeros((dimension, dimension)),
        C=np.zeros((dimension, dimension)),
        D=np.zeros((dimension, dimension)),
        x0=np.zeros(dimension),
    )
    runtime = MultiprocessingSecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,) * dimension,
            input_payload_bounds=(512,) * dimension,
            horizon_steps=1,
        ),
        security_parameter=8,
        test_seed=301,
        timeouts=ProcessTimeouts(startup=10.0, step=15.0, shutdown=5.0),
    )

    with runtime:
        np.testing.assert_array_equal(runtime.step(np.zeros(dimension)), np.zeros(dimension))
        assert runtime.resource_counts["products_consumed"] == 400


@pytest.mark.integration
def test_integer_scale_no_truncation_reset_and_close_are_bounded() -> None:
    spec = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[-1.0]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=0, B=0, C=8, D=8),
    )
    runtime = _runtime(spec)
    old_pids = {item.pid for item in runtime.topology.roles}
    first = runtime.step(0.25)
    assert runtime.resource_counts["truncations_consumed"] == 0
    runtime.reset()
    assert old_pids.isdisjoint({item.pid for item in runtime.topology.roles})
    np.testing.assert_array_equal(runtime.step(0.25), first)
    runtime.close()
    assert all(item.status == "closed" for item in runtime.topology.roles)
    runtime.close()
    with pytest.raises(ProcessStateError, match="已经关闭"):
        runtime.step(0.0)


@pytest.mark.integration
def test_step_timeout_fails_closed_and_leaves_no_role_process_alive() -> None:
    runtime = MultiprocessingSecureStateSpaceRuntime(
        _general_spec(),
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,), input_payload_bounds=(512,), horizon_steps=2
        ),
        security_parameter=8,
        test_seed=902,
        timeouts=ProcessTimeouts(startup=10.0, step=1e-12, shutdown=5.0),
    )
    role_pids = {item.pid for item in runtime.topology.roles}

    with pytest.raises(ProcessExecutionTimeout):
        runtime.step(0.0)

    assert all(item.status == "failed" for item in runtime.topology.roles)
    assert all(connection.closed for connection in runtime._session.controls.values())
    assert role_pids.isdisjoint(
        {process.pid for process in mp.active_children() if process.pid is not None}
    )


@pytest.mark.integration
def test_worker_failure_requires_fresh_session_before_execution_can_resume() -> None:
    runtime = MultiprocessingSecureStateSpaceRuntime(
        _general_spec(),
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(512,), input_payload_bounds=(512,), horizon_steps=1
        ),
        security_parameter=8,
        test_seed=903,
    )
    first = runtime.step(0.0)
    with pytest.raises(ProcessWorkerError, match="finite horizon"):
        runtime.step(0.0)
    assert all(connection.closed for connection in runtime._session.controls.values())
    with pytest.raises(ProcessStateError, match="已失败"):
        runtime.step(0.0)

    runtime.reset()
    np.testing.assert_array_equal(runtime.step(0.0), first)
    runtime.close()


@pytest.mark.integration
def test_partial_startup_failure_reaps_every_started_role() -> None:
    before = {process.pid for process in mp.active_children()}

    with pytest.raises(ProcessWorkerError, match="Client 启动失败"):
        MultiprocessingSecureStateSpaceRuntime(
            _general_spec(),
            FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
            ControllerRangeContract(
                state_payload_bounds=(1,), input_payload_bounds=(512,), horizon_steps=1
            ),
            security_parameter=8,
            test_seed=904,
        )

    assert {process.pid for process in mp.active_children()} == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", 8),
        ("session_id", "wrong-session"),
        ("round_id", "wrong-round"),
    ],
)
def test_malformed_reply_identity_is_rejected(field: str, value: object) -> None:
    context = mp.get_context("spawn")
    receiver, sender = context.Pipe()
    request = IpcEnvelope(1, 7, "P1", "stage_output", "session", "round", 1)
    response = replace(request, **{field: value})
    session = _ProcessSession(
        context,
        {},
        {"P1": receiver},
        "session",
        None,  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        {},
    )
    try:
        sender.send(response)
        with pytest.raises(ProcessProtocolError, match="错配"):
            session.receive("P1", request, 1.0)
        assert session.failed is True
    finally:
        receiver.close()
        sender.close()


def test_party_online_payloads_never_contain_peer_shares() -> None:
    _, first, second = _online_plan()

    assert set(PartyOnlineRound.__dataclass_fields__) == {"input_message", "resources"}
    assert first.input_message.recipient == first.resources.recipient == 0
    assert second.input_message.recipient == second.resources.recipient == 1
    assert first.input_message is not second.input_message
    assert first.resources is not second.resources


@pytest.mark.integration
def test_failed_reset_preserves_previous_session(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(_general_spec(), seed=905)
    previous_pids = {item.pid for item in runtime.topology.roles}

    def fail_startup() -> None:
        raise ProcessExecutionTimeout("replacement startup failed")

    monkeypatch.setattr(runtime, "_start_session", fail_startup)
    with pytest.raises(ProcessExecutionTimeout, match="replacement"):
        runtime.reset()

    assert {item.pid for item in runtime.topology.roles} == previous_pids
    assert runtime.step(0.0).shape == (1,)
    runtime.close()
