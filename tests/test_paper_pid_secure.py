"""#70 paper-inspired 安全闭环的范围、时序与三角色回归。"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from secure_control.experiments.paper_pid_fig3 import load_definition
from secure_control.scenarios.paper_pid.baseline import run_paper_pid_baseline
from secure_control.scenarios.paper_pid.secure_experiment import build_paper_pid_plan
from secure_control.simulation import compare_closed_loops

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "paper_pid_fig3_sweep.yaml"


def _plan(ell: int, *, backend: str = "single_process", bound: int = 128):
    definition, _, q, evidence = load_definition(CONFIG)
    return build_paper_pid_plan(
        fractional_bits=ell, modulus=q, modulus_evidence=evidence,
        security_parameter=80, sample_count=51, measurement_absolute_bound=bound,
        runtime_payload_headroom_bits=definition["runtime_payload_headroom_bits"],
        test_seed=70, backend=backend,
    )


@pytest.mark.parametrize("ell", [32, 40, 48, 56])
def test_secure_51_steps_match_a05_pre_step_oracle_and_consume_resources(ell: int) -> None:
    plan, runtime, collector = _plan(ell)
    result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
    baseline = run_paper_pid_baseline(
        alpha=0.2, sample_period_seconds=0.1, plant_initial_state=[100.0]*4,
        sample_count=51,
    )
    assert collector is not None
    np.testing.assert_array_equal(result.time[[0, 1, 2, 50]], [0.0, 0.1, 0.2, 5.0])
    np.testing.assert_array_equal(result.output_ideal[:, 0], baseline.rows[:, 6])
    np.testing.assert_array_equal(result.control_ideal[:, 0], baseline.rows[:, 9])
    np.testing.assert_array_equal(result.reference, np.zeros((51, 1)))
    np.testing.assert_array_equal(result.control_error, result.control_ideal-result.control_secure)
    assert result.control_ideal.shape == result.control_secure.shape == (51, 1)
    assert runtime.range_verification.proof_mode == "finite_horizon"
    assert runtime.scale_ledger.state_truncation_bits == ell
    traces = collector.traces()
    assert len(traces) == 51
    assert [trace.step for trace in traces] == list(range(51))
    assert all(trace.operations.protocol1_triples == 9 and
               trace.operations.state_truncation == 2 for trace in traces)
    final = traces[-1].resources_after
    assert (final.triples_created, final.triples_consumed, final.triples_aborted) == (459, 459, 0)
    assert (final.truncations_created, final.truncations_consumed,
            final.truncations_aborted) == (102, 102, 0)
    assert float(np.max(np.abs(result.control_error))) < 2**-10


def test_input_bound_rejected_before_next_round_and_not_consumed() -> None:
    _, runtime, collector = _plan(32)
    runtime.step(np.array([100.0]))
    assert collector is not None and len(collector.traces()) == 1
    with pytest.raises(ValueError, match="input"):
        runtime.step(np.array([129.0]))
    assert len(collector.traces()) == 1
    runtime.step(np.array([100.0]))
    assert len(collector.traces()) == 2


def test_too_small_input_bound_rejects_initial_measurement() -> None:
    _, runtime, collector = _plan(32, bound=1)
    with pytest.raises(ValueError, match="input"):
        runtime.step(np.array([100.0]))
    assert collector is not None and collector.traces() == ()


def test_paper_parameter_width_cannot_be_reused_for_dynamic_state() -> None:
    _, _, q, evidence = load_definition(CONFIG)
    with pytest.raises(ValueError, match="state_payload_bounds"):
        build_paper_pid_plan(
            fractional_bits=32, modulus=q, modulus_evidence=evidence,
            security_parameter=80, sample_count=51, measurement_absolute_bound=128,
            runtime_payload_headroom_bits=8, test_seed=70, backend="single_process",
        )


def test_localhost_three_roles_51_steps_and_actual_resource_counts() -> None:
    plan, runtime, _ = _plan(32, backend="localhost")
    try:
        pids = [item.pid for item in runtime.topology.roles]
        assert len(set(pids)) == 3
        result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
        assert result.control_secure.shape == (51, 1)
        assert runtime.resource_counts == {"products_consumed": 459,
                                           "truncations_consumed": 102}
    finally:
        runtime.close()


def test_localhost_input_failure_closes_session_without_consuming_resources() -> None:
    _, runtime, _ = _plan(32, backend="localhost", bound=1)
    try:
        with pytest.raises(Exception, match="input"):
            runtime.step(np.array([100.0]))
        assert runtime.resource_counts == {"products_consumed": 0,
                                           "truncations_consumed": 0}
        with pytest.raises(Exception, match="失败|关闭"):
            runtime.step(np.array([0.0]))
    finally:
        runtime.close()
