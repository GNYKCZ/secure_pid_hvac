"""spawn 多进程安全运行时的数值、拓扑与清理测试。"""

from __future__ import annotations

import multiprocessing as mp
import os
from pathlib import Path

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import (
    ControllerRuntime,
    MultiprocessingSecureStateSpaceRuntime,
    ProcessExecutionTimeout,
    ProcessStateError,
    ProcessTimeouts,
    ProcessWorkerError,
    SecureStateSpaceRuntime,
)
from secure_control.experiments.multiprocessing_runner import run_multiprocessing_comparison
from secure_control.protocol import ControllerRangeContract


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
        Path(__file__).parents[1] / "configs" / "hvac_dual_loop.yaml",
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
    with pytest.raises(ProcessStateError, match="已失败"):
        runtime.step(0.0)

    runtime.reset()
    np.testing.assert_array_equal(runtime.step(0.0), first)
    runtime.close()
