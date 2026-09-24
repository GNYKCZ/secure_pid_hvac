"""spawn 多进程安全运行时的数值、拓扑与清理测试。"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import random
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

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
from secure_control.experiments.multiprocessing_runner import run_multiprocessing_comparison
from secure_control.protocol import Client, ControllerRangeContract
from secure_control.protocol.coordinator import Protocol3Orchestrator
from secure_control.protocol.messages import (
    PartyOnlineRound,
    Protocol3StageReceipt,
    ResourceMetadata,
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


class _RecordingEndpoint:
    """仅记录统一调度顺序的测试 endpoint，不实现任何协议数学。"""

    def __init__(self, party: int, plan: StepResourcePlan, events: list[str]) -> None:
        self.party = party
        self.session_id = plan.session_id
        self.plan = plan
        self._events = events

    def _record(self, operation: str, metadata: ResourceMetadata | None = None) -> None:
        suffix = "" if metadata is None else f":{metadata.resource_id}"
        self._events.append(f"P{self.party + 1}.{operation}{suffix}")

    def mask_product(self, metadata: ResourceMetadata) -> None:
        self._record("mask_product", metadata)

    def finish_product(self, metadata: ResourceMetadata) -> None:
        self._record("finish_product", metadata)

    def complete_product(self, metadata: ResourceMetadata) -> None:
        self._record("complete_product", metadata)

    def finish_products(self) -> None:
        self._record("finish_products")

    def mask_truncation(self, metadata: ResourceMetadata) -> None:
        self._record("mask_truncation", metadata)

    def send_truncation(self, metadata: ResourceMetadata) -> None:
        self._record("send_truncation", metadata)

    def finish_truncation_p1(self, metadata: ResourceMetadata) -> None:
        self._record("finish_truncation_p1", metadata)

    def finish_truncation_p2(self, metadata: ResourceMetadata) -> None:
        self._record("finish_truncation_p2", metadata)

    def complete_truncation(self, metadata: ResourceMetadata) -> None:
        self._record("complete_truncation", metadata)

    def stage_output(self) -> Protocol3StageReceipt:
        self._record("stage_output")
        return Protocol3StageReceipt(
            self.party,
            self.plan.session_id,
            self.plan.round_id,
            self.plan.step,
            self.plan.triple_count,
            self.plan.truncation_count,
        )

    def commit(self) -> None:
        self._record("commit")


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


def test_parent_rejects_invalid_input_without_losing_session() -> None:
    with _runtime(_general_spec()) as runtime:
        with pytest.raises(FloatingPointError, match="NaN"):
            runtime.step(float("nan"))
        assert runtime.step(0.0).shape == (1,)


def test_hvac_180_step_runner_matches_existing_secure_backend_and_cleans_up() -> None:
    summary = run_multiprocessing_comparison(
        Path(__file__).parents[1] / "tests" / "fixtures" / "legacy_hvac" / "hvac_dual_loop.yaml",
        test_seed=901,
    )

    assert summary["start_method"] == "spawn"
    assert summary["sample_count"] == 180
    assert len(set(summary["role_pids"].values())) == 3
    assert summary["maximum_control_difference"] == 0.0
    assert summary["maximum_output_difference"] == 0.0
    assert summary["resource_counts"] == {
        "products_consumed": 1620,
        "truncations_consumed": 0,
    }
    assert summary["cleanup"] == "closed"


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
    (
        ("request_id", 8),
        ("role", "P2"),
        ("operation", "commit"),
        ("session_id", "wrong-session"),
        ("round_id", "wrong-round"),
        ("step", 2),
    ),
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


def test_protocol3_orchestrator_has_one_explicit_message_order() -> None:
    plan, _, _ = _online_plan()
    events: list[str] = []
    first = _RecordingEndpoint(0, plan, events)
    second = _RecordingEndpoint(1, plan, events)
    orchestrator = Protocol3Orchestrator()

    orchestrator.stage(first, second, plan)
    orchestrator.commit(first, second)

    expected: list[str] = []
    for metadata in plan.product_resources:
        expected.extend(
            [
                f"P1.mask_product:{metadata.resource_id}",
                f"P2.mask_product:{metadata.resource_id}",
                f"P1.finish_product:{metadata.resource_id}",
                f"P2.finish_product:{metadata.resource_id}",
                f"P1.complete_product:{metadata.resource_id}",
                f"P2.complete_product:{metadata.resource_id}",
            ]
        )
    expected.extend(["P1.finish_products", "P2.finish_products"])
    for metadata in plan.state_truncation_resources:
        expected.extend(
            [
                f"P1.mask_truncation:{metadata.resource_id}",
                f"P2.mask_truncation:{metadata.resource_id}",
                    f"P2.send_truncation:{metadata.resource_id}",
                f"P1.finish_truncation_p1:{metadata.resource_id}",
                f"P2.finish_truncation_p2:{metadata.resource_id}",
                f"P1.complete_truncation:{metadata.resource_id}",
                f"P2.complete_truncation:{metadata.resource_id}",
            ]
        )
    expected.extend(["P1.stage_output", "P2.stage_output", "P1.commit", "P2.commit"])
    assert events == expected


def test_party_online_payloads_never_contain_peer_shares() -> None:
    _, first, second = _online_plan()

    assert set(PartyOnlineRound.__dataclass_fields__) == {"input_message", "resources"}
    assert first.input_message.recipient == first.resources.recipient == 0
    assert second.input_message.recipient == second.resources.recipient == 1
    assert first.input_message is not second.input_message
    assert first.resources is not second.resources


def test_importing_execution_starts_no_child_process() -> None:
    script = (
        "import json, multiprocessing as mp; "
        "before=len(mp.active_children()); "
        "import secure_control.execution; "
        "print(json.dumps([before, len(mp.active_children())]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(completed.stdout) == [0, 0]


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
