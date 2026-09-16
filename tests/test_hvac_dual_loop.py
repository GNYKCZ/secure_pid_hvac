"""Issue #12 HVAC 180 步明文/安全双闭环集成与公平比较测试。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pytest

from secure_control.execution import PlaintextStateSpaceRuntime, SecureStateSpaceRuntime
from secure_control.scenarios.hvac import (
    Hvac2R2CPlant,
    load_hvac_pid_design,
    load_hvac_pid_tuning_contract,
    load_hvac_scenario_contract,
    run_plaintext_hvac_baseline,
)
from secure_control.scenarios.hvac.integration import HvacScenario, run_hvac_dual_loop
from secure_control.simulation import SimulationPlan, run

CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_dual_loop.yaml"
BASELINE_PATH = Path(__file__).parents[1] / "configs" / "hvac_pid_baseline.yaml"
CONFIG_2R2C_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_dual_loop.yaml"
BASELINE_2R2C_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_pid_baseline.yaml"
PLANT_2R2C_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_plant.yaml"


@dataclass(frozen=True)
class _FixedHvacPlan:
    """让测试重跑同一组闭环实例，用于 reset 与反馈记录断言。"""

    plan: SimulationPlan

    def build_plan(self) -> SimulationPlan:
        """返回已由 HVAC 场景完成物理/编码证明的计划。"""
        return self.plan


def test_full_horizon_matches_old_ideal_baseline_and_records_applied_control() -> None:
    """锁定 10800 s 的 pre-plant 时间索引、切换点及既有明文 actuator 语义。"""
    comparison = run_hvac_dual_loop(CONFIG_PATH, test_seed=12)
    result = comparison.result
    contract = load_hvac_scenario_contract(BASELINE_PATH)
    design = load_hvac_pid_design(BASELINE_PATH, contract)
    baseline = run_plaintext_hvac_baseline(contract, design)

    assert result.time.shape == (180,)
    np.testing.assert_array_equal(result.time, np.arange(180, dtype=float) * 60.0)
    for name in (
        "reference",
        "output_ideal",
        "output_secure",
        "control_ideal",
        "control_secure",
        "control_error",
        "output_error",
    ):
        signal = getattr(result, name)
        assert signal.shape == (180, 1)
        assert np.isfinite(signal).all()
        assert not signal.flags.writeable
    np.testing.assert_array_equal(
        result.reference[[0, 59, 60, 119, 120, 179], 0], [15, 15, 20, 20, 25, 25]
    )
    np.testing.assert_array_equal(result.output_ideal, baseline.output_ideal)
    np.testing.assert_array_equal(result.control_ideal, baseline.control_ideal)
    np.testing.assert_array_equal(result.output_ideal[0], np.array([30.0]))
    np.testing.assert_array_equal(result.output_secure[0], np.array([30.0]))
    np.testing.assert_array_equal(baseline.raw_control_ideal[0], np.array([12.5]))
    np.testing.assert_array_equal(result.control_ideal[0], np.array([12.0]))
    np.testing.assert_array_equal(
        result.control_error, result.control_ideal - result.control_secure
    )
    np.testing.assert_array_equal(result.output_error, result.output_ideal - result.output_secure)


def test_hvac_certificate_bounds_and_actual_errors_are_checked() -> None:
    """物理证书先于运行构造，轨迹不得越界，最大偏差从真实八字段计算。"""
    comparison = run_hvac_dual_loop(CONFIG_PATH, test_seed=13)
    result = comparison.result
    certificate = comparison.safety_certificate
    contract = load_hvac_scenario_contract(BASELINE_PATH)

    assert certificate.horizon_steps == 180
    assert certificate.temperature_bounds_celsius == (6.0, 30.0)
    assert certificate.input_abs_bound_celsius == 19.0
    assert certificate.input_payload_bound == 19 * (1 << 20) + 1
    assert certificate.state_payload_bounds == (
        180 * 60 * certificate.input_payload_bound,
        certificate.input_payload_bound,
    )
    for name in ("output_ideal", "output_secure"):
        signal = getattr(result, name)
        assert np.all((6.0 - 1e-10 <= signal) & (signal <= 30.0 + 1e-10))
    for name in ("control_ideal", "control_secure"):
        signal = getattr(result, name)
        assert np.all(signal >= contract.model.lower_control_bound_kw)
        assert np.all(signal <= contract.model.upper_control_bound_kw)
    # 0.01 是本配置 ell=20、180 步 controller/plant 量化比较的预设回归门槛，
    # 实测值仍须另外报告，不能用该门槛替代范围证明或修改 PID gains。
    assert float(np.max(np.abs(result.control_error))) < 0.01
    assert float(np.max(np.abs(result.output_error))) < 0.01
    assert len(comparison.segment_metrics_ideal) == len(comparison.segment_metrics_secure) == 3
    assert all(
        metric.tail_mae_celsius <= 1.0
        for metric in (*comparison.segment_metrics_ideal, *comparison.segment_metrics_secure)
    )
    assert contract.metadata.output.names == ("temperature",)
    assert contract.metadata.control.units == ("kW_thermal_cooling",)


def test_build_plan_keeps_instances_and_secure_resources_isolated() -> None:
    """仅共享不可变配置值，两支 plant/adapter/runtime/log 和安全 session 都独立。"""
    scenario = HvacScenario(CONFIG_PATH, test_seed=14)
    plan = scenario.build_plan()
    assert plan.ideal.plant is not plan.secure.plant
    assert plan.ideal.adapter is not plan.secure.adapter
    assert plan.ideal.runtime is not plan.secure.runtime
    assert isinstance(plan.ideal.runtime, PlaintextStateSpaceRuntime)
    assert isinstance(plan.secure.runtime, SecureStateSpaceRuntime)
    for name in ("A", "B", "C", "D", "x0"):
        np.testing.assert_array_equal(
            getattr(plan.ideal.runtime.spec, name), getattr(plan.secure.runtime.spec, name)
        )
    assert plan.secure.runtime.scale_ledger.state_truncation_bits == 0
    assert plan.secure.runtime._range_contract.horizon_steps == 180

    result = run(_FixedHvacPlan(plan))
    assert result.output_ideal is not result.output_secure
    assert result.control_ideal is not result.control_secure
    # 本 HVAC n=2,m=1,p=1：每步 9 份独立 triple，integer A/B 无 state Trunc。
    assert plan.secure.runtime._client.multiplier.created_triples == 180 * 9
    assert plan.secure.runtime._client.multiplier.consumed_triples == 180 * 9
    assert plan.secure.runtime._client.truncation.created_masks == 0


def test_each_branch_controller_input_uses_only_its_own_plant_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """记录 adapter 实参，证明 secure v 不读取 ideal output 或 controller 内部 state。"""
    plan = HvacScenario(CONFIG_PATH, test_seed=15).build_plan()
    observed_ideal: list[np.ndarray] = []
    observed_secure: list[np.ndarray] = []
    ideal_adapter = plan.ideal.adapter
    secure_adapter = plan.secure.adapter
    original_ideal = ideal_adapter.controller_input
    original_secure = secure_adapter.controller_input

    def ideal_input(reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """仅记录明文 adapter 实际收到的本支测量。"""
        observed_ideal.append(output.copy())
        return original_ideal(reference, output)

    def secure_input(reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """仅记录安全 adapter 实际收到的本支测量。"""
        observed_secure.append(output.copy())
        return original_secure(reference, output)

    monkeypatch.setattr(ideal_adapter, "controller_input", ideal_input)
    monkeypatch.setattr(secure_adapter, "controller_input", secure_input)
    result = run(_FixedHvacPlan(plan))

    np.testing.assert_array_equal(np.vstack(observed_ideal), result.output_ideal)
    np.testing.assert_array_equal(np.vstack(observed_secure), result.output_secure)
    assert np.any(result.output_ideal != result.output_secure)


def test_seeded_rerun_and_explicit_reset_restore_both_closed_loops() -> None:
    """相同 config/测试 seed 重建或分别 reset 两支，八字段数值轨迹都可复现。"""
    first = run_hvac_dual_loop(CONFIG_PATH, test_seed=16).result
    second = run_hvac_dual_loop(CONFIG_PATH, test_seed=16).result
    for name in first.__dataclass_fields__:
        np.testing.assert_array_equal(getattr(first, name), getattr(second, name))

    plan = HvacScenario(CONFIG_PATH, test_seed=17).build_plan()
    before = run(_FixedHvacPlan(plan))
    plan.ideal.plant.reset()
    plan.secure.plant.reset()
    plan.ideal.runtime.reset()
    plan.secure.runtime.reset()
    after = run(_FixedHvacPlan(plan))
    for name in before.__dataclass_fields__:
        np.testing.assert_array_equal(getattr(before, name), getattr(after, name))


def test_2r2c_dual_loop_matches_plaintext_oracle_and_all_quality_thresholds() -> None:
    """2R2C 两支各 180 步，ideal 与调参 oracle 一致且完整指标通过。"""
    comparison = run_hvac_dual_loop(CONFIG_2R2C_PATH, test_seed=42)
    result = comparison.result
    contract = load_hvac_scenario_contract(PLANT_2R2C_PATH)
    selected, _, _ = load_hvac_pid_tuning_contract(BASELINE_2R2C_PATH, contract)
    baseline = run_plaintext_hvac_baseline(contract, selected)

    np.testing.assert_array_equal(result.time, np.arange(180) * 60.0)
    np.testing.assert_array_equal(result.reference[[59, 60, 119, 120], 0], [15, 20, 20, 25])
    np.testing.assert_array_equal(result.output_ideal, baseline.output_ideal)
    np.testing.assert_array_equal(result.control_ideal, baseline.control_ideal)
    assert comparison.comparison_metrics is not None
    assert comparison.comparison_metrics.passed
    assert comparison.comparison_metrics.max_control_error_kw < 0.01
    assert comparison.comparison_metrics.mean_control_error_kw < 0.005
    assert comparison.comparison_metrics.rms_control_error_kw < 0.005
    assert comparison.comparison_metrics.max_temperature_error_celsius < 0.01
    assert comparison.comparison_metrics.mean_temperature_error_celsius < 0.005
    assert comparison.comparison_metrics.rms_temperature_error_celsius < 0.005
    assert all(metric.passed for metric in comparison.segment_metrics_ideal)
    assert all(metric.passed for metric in comparison.segment_metrics_secure)


def test_2r2c_plan_and_certificate_cover_independent_internal_states_and_protocol_bounds() -> None:
    """二维状态只留在各 plant 内部，证书与协议 preflight 覆盖 180 步且无 Trunc。"""
    scenario = HvacScenario(CONFIG_2R2C_PATH, test_seed=43)
    certificate = scenario.safety_certificate
    plan = scenario.build_plan()

    assert isinstance(plan.ideal.plant, Hvac2R2CPlant)
    assert isinstance(plan.secure.plant, Hvac2R2CPlant)
    assert plan.ideal.plant is not plan.secure.plant
    assert plan.ideal.adapter is not plan.secure.adapter
    assert plan.ideal.runtime is not plan.secure.runtime
    assert certificate.horizon_steps == 180
    assert certificate.plant_state_names == ("air_temperature", "wall_temperature")
    assert len(certificate.plant_state_bounds_celsius) == 2
    assert certificate.controller_state_names == ("integral_error", "previous_error")
    assert len(certificate.controller_state_bounds) == 2
    assert certificate.applied_control_bounds_kw == (0.0, 12.0)
    assert certificate.state_truncation_bits == 0
    assert all(
        value <= certificate.centered_modulus_limit
        for value in certificate.maximum_state_accumulator_bounds
    )
    assert all(
        value <= certificate.centered_modulus_limit
        for value in certificate.maximum_output_accumulator_bounds
    )
    assert plan.secure.runtime._range_contract.horizon_steps == 180
    assert (
        plan.secure.runtime._range_contract.state_payload_bounds == certificate.state_payload_bounds
    )
    assert (
        plan.secure.runtime._range_contract.input_payload_bounds == certificate.input_payload_bounds
    )
    assert plan.metadata.output.names == ("air_temperature",)


def test_2r2c_secure_runtime_rejects_step_beyond_certified_horizon() -> None:
    """第 181 次 controller step 必须 fail closed，不能把有限证书扩称无限时域。"""
    plan = HvacScenario(CONFIG_2R2C_PATH, test_seed=44).build_plan()
    for _ in range(180):
        plan.secure.runtime.step(np.array([0.0]))
    with pytest.raises(ValueError, match="horizon"):
        plan.secure.runtime.step(np.array([0.0]))
