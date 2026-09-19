"""HVAC PID 到通用状态空间转换及明文闭环基线测试。"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest
import yaml

from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.scenarios.hvac import (
    HvacBranchMetrics,
    HvacGainSearchAxis,
    HvacPidDesign,
    HvacPidTuningContract,
    HvacSegmentMetric,
    HvacTuningInfeasibleError,
    evaluate_hvac_branch_metrics,
    evaluate_hvac_comparison_metrics,
    load_hvac_pid_design,
    load_hvac_pid_tuning_contract,
    load_hvac_scenario_contract,
    run_plaintext_hvac_baseline,
    tune_hvac_pid,
)
from secure_control.simulation import SimulationResult

PID_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_pid_baseline.yaml"
PLANT_2R2C_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_plant.yaml"
PID_2R2C_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_pid_baseline.yaml"


def _contract_and_design():
    """从同一个 YAML 读取场景契约和 PID，保证采样周期没有分叉来源。"""
    contract = load_hvac_scenario_contract(PID_CONFIG_PATH)
    return contract, load_hvac_pid_design(PID_CONFIG_PATH, contract)


def _pid_config_mapping() -> dict[str, Any]:
    """读取 PID YAML 副本，供无效策略配置测试使用。"""
    loaded = yaml.safe_load(PID_CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_config(tmp_path: Path, mapping: dict[str, Any]) -> Path:
    """将单个测试的变体写入临时目录，不修改正式实验配置。"""
    path = tmp_path / "hvac_pid.yaml"
    path.write_text(yaml.safe_dump(mapping, sort_keys=False), encoding="utf-8")
    return path


def test_pid_design_converts_nonzero_derivative_to_known_state_space_matrices() -> None:
    """非零 Kd 的手算矩阵可保护 PID 转换中的符号和 Ts 因子。"""
    design = HvacPidDesign(
        proportional_gain_kw_per_celsius=-1.0,
        integral_gain_kw_per_celsius_second=-0.25,
        derivative_gain_kw_second_per_celsius=-2.0,
        sample_period_seconds=4,
        initial_integral_error_celsius_seconds=3.0,
        initial_previous_error_celsius=-5.0,
        tail_window_seconds=4,
        max_tail_mae_celsius=1.0,
    )
    spec = design.to_controller_spec()

    assert np.array_equal(spec.A, np.array([[1.0, 0.0], [0.0, 0.0]]))
    assert np.array_equal(spec.B, np.array([[4.0], [1.0]]))
    assert np.array_equal(spec.C, np.array([[-0.25, 0.5]]))
    assert np.array_equal(spec.D, np.array([[-1.5]]))
    assert np.array_equal(spec.x0, np.array([3.0, -5.0]))


def test_direct_form_oracle_matches_generic_plaintext_runtime() -> None:
    """direct-form oracle 仅在测试中验证 runtime 的 update-order 与 PID 定义一致。"""
    design = HvacPidDesign(
        proportional_gain_kw_per_celsius=-1.0,
        integral_gain_kw_per_celsius_second=-0.25,
        derivative_gain_kw_second_per_celsius=-2.0,
        sample_period_seconds=4,
        initial_integral_error_celsius_seconds=3.0,
        initial_previous_error_celsius=-5.0,
        tail_window_seconds=4,
        max_tail_mae_celsius=1.0,
    )
    runtime = PlaintextStateSpaceRuntime(design.to_controller_spec())
    integral = design.initial_integral_error_celsius_seconds
    previous_error = design.initial_previous_error_celsius

    for error in (-2.0, 0.5, 3.0, -1.0):
        expected = (
            design.proportional_gain_kw_per_celsius * error
            + design.integral_gain_kw_per_celsius_second * integral
            + design.derivative_gain_kw_second_per_celsius
            * (error - previous_error)
            / design.sample_period_seconds
        )
        actual = runtime.step(np.array([error]))
        assert np.allclose(actual, np.array([expected]))

        integral += design.sample_period_seconds * error
        previous_error = error
        assert np.allclose(runtime.state, np.array([integral, previous_error]))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["scenario"]["hvac"]["controller"].__setitem__(
                "derivative_filter", "low_pass"
            ),
            "filter",
        ),
        (
            lambda value: value["scenario"]["hvac"]["controller"].__setitem__(
                "anti_windup", "back_calculation"
            ),
            "anti_windup",
        ),
        (
            lambda value: value["scenario"]["hvac"]["controller"].__setitem__(
                "proportional_gain_kw_per_celsius", 0.1
            ),
            "proportional",
        ),
    ],
)
def test_pid_config_rejects_unfrozen_strategy_or_wrong_feedback_sign(
    tmp_path: Path, mutate, message: str
) -> None:
    """滤波、anti-windup 和冷却负反馈方向不能由 YAML 静默改变。"""
    config = deepcopy(_pid_config_mapping())
    mutate(config)
    path = _write_config(tmp_path, config)
    contract = load_hvac_scenario_contract(path)

    with pytest.raises(ValueError, match=message):
        load_hvac_pid_design(path, contract)


def test_plaintext_hvac_baseline_meets_predefined_bounds_and_tracking_metrics() -> None:
    """完整 10800 s 轨迹必须有限、受 actuator 约束，并满足三个预设 MAE 门槛。"""
    contract, design = _contract_and_design()
    result = run_plaintext_hvac_baseline(contract, design)

    assert result.time.shape == (180,)
    assert (
        result.reference.shape
        == result.output_ideal.shape
        == result.control_ideal.shape
        == (180, 1)
    )
    assert np.isfinite(result.output_ideal).all()
    assert np.isfinite(result.control_ideal).all()
    assert np.all(result.control_ideal >= contract.model.lower_control_bound_kw)
    assert np.all(result.control_ideal <= contract.model.upper_control_bound_kw)
    assert len(result.segment_metrics) == 3
    assert all(
        metric.tail_mae_celsius <= design.max_tail_mae_celsius for metric in result.segment_metrics
    )

    # 首步 raw PID 输出为 12.5 kW，但场景在 plant 前裁剪为 12 kW；runtime 内没有 saturation。
    assert np.allclose(result.raw_control_ideal[0], np.array([12.5]))
    assert np.array_equal(result.control_ideal[0], np.array([12.0]))


def _known_metric_result() -> tuple[SimulationResult, Any, Any]:
    """构造不依赖闭环实现的 180 点已知数据及其场景/品质契约。"""
    contract = load_hvac_scenario_contract(PLANT_2R2C_PATH)
    _, _, quality = load_hvac_pid_tuning_contract(PID_2R2C_PATH, contract)
    time = np.arange(180, dtype=float) * 60.0
    reference = np.repeat(np.array([15.0, 20.0, 25.0]), 60).reshape(-1, 1)
    signed = np.concatenate(
        (
            np.array([2.0, -1.0, 0.6, *([0.5] * 57)]),
            np.full(60, 0.6),
            np.array([-1.0, *([0.0] * 59)]),
        )
    ).reshape(-1, 1)
    output_ideal = reference + signed
    control_ideal = np.concatenate(
        (
            np.array([0.0, 0.0, 12.0, *([3.0] * 57)]),
            np.full(60, 4.0),
            np.full(60, 12.0),
        )
    ).reshape(-1, 1)
    output_delta = np.full((180, 1), 0.002)
    output_delta[0, 0] = 0.02
    control_delta = np.where(control_ideal == 12.0, -0.001, 0.001)
    control_delta[3, 0] = 0.02
    output_secure = output_ideal + output_delta
    control_secure = control_ideal + control_delta
    result = SimulationResult(
        time,
        reference,
        output_ideal,
        output_secure,
        control_ideal,
        control_secure,
        control_ideal - control_secure,
        output_ideal - output_secure,
    )
    return result, contract, quality


def test_known_dataset_locks_all_branch_and_comparison_metric_formulas() -> None:
    """独立已知数据逐项锁定区段指标、未调节语义及两类差异统计。"""
    result, contract, quality = _known_metric_result()
    branch = evaluate_hvac_branch_metrics(
        time=result.time,
        reference=result.reference,
        air_temperature=result.output_ideal,
        applied_control=result.control_ideal,
        contract=contract,
        quality_contract=quality,
    )
    first, second, third = branch.segments
    assert (
        first.mae_celsius,
        first.tail_mae_celsius,
        first.max_abs_error_celsius,
        first.settling_time_seconds,
        first.max_signed_deviation_celsius,
        first.min_signed_deviation_celsius,
        first.saturation_fraction,
        first.max_abs_applied_control_kw,
    ) == pytest.approx((0.535, 0.5, 2.0, 180.0, 2.0, -1.0, 0.05, 12.0))
    assert second.settling_time_seconds is None
    assert (
        second.mae_celsius,
        second.tail_mae_celsius,
        second.max_abs_error_celsius,
        second.max_signed_deviation_celsius,
        second.min_signed_deviation_celsius,
        second.saturation_fraction,
        second.max_abs_applied_control_kw,
    ) == pytest.approx((0.6, 0.6, 0.6, 0.6, 0.6, 0.0, 4.0))
    assert (
        third.mae_celsius,
        third.tail_mae_celsius,
        third.max_abs_error_celsius,
        third.settling_time_seconds,
        third.max_signed_deviation_celsius,
        third.min_signed_deviation_celsius,
        third.saturation_fraction,
        third.max_abs_applied_control_kw,
    ) == pytest.approx((1 / 60, 0.0, 1.0, 60.0, 0.0, -1.0, 1.0, 12.0))
    assert first.violations == ("min_signed_deviation_celsius",)
    assert second.violations == (
        "tail_mae_celsius",
        "settling_time_seconds",
        "max_signed_deviation_celsius",
    )
    assert third.violations == ("saturation_fraction",)
    assert not branch.passed
    comparison = evaluate_hvac_comparison_metrics(result, contract, quality)
    assert comparison.max_control_error_kw == pytest.approx(0.02)
    assert comparison.mean_control_error_kw == pytest.approx((0.02 + 179 * 0.001) / 180)
    assert comparison.rms_control_error_kw == pytest.approx(
        np.sqrt((0.02**2 + 179 * 0.001**2) / 180)
    )
    assert comparison.max_temperature_error_celsius == pytest.approx(0.02)
    assert comparison.mean_temperature_error_celsius == pytest.approx((0.02 + 179 * 0.002) / 180)
    assert comparison.rms_temperature_error_celsius == pytest.approx(
        np.sqrt((0.02**2 + 179 * 0.002**2) / 180)
    )
    assert not comparison.passed


def test_comparison_metrics_rejects_error_fields_inconsistent_with_saved_trajectories() -> None:
    """冗余 error 即使伪造为零，也不能掩盖超阈值的两支轨迹差异。"""
    result, contract, quality = _known_metric_result()
    forged = SimulationResult(
        result.time,
        result.reference,
        result.output_ideal,
        result.output_secure,
        result.control_ideal,
        result.control_secure,
        np.zeros_like(result.control_error),
        np.zeros_like(result.output_error),
    )
    with pytest.raises(ValueError, match="error.*差值"):
        evaluate_hvac_comparison_metrics(forged, contract, quality)

    wrong_shape = SimpleNamespace(
        **{
            name: getattr(result, name)
            for name in result.__dataclass_fields__
            if name not in {"control_error", "output_error"}
        },
        control_error=np.zeros(180),
        output_error=result.output_error,
    )
    with pytest.raises(ValueError, match="shape"):
        evaluate_hvac_comparison_metrics(wrong_shape, contract, quality)


def test_2r2c_tuner_reproduces_frozen_unique_selection_and_audit_counts() -> None:
    """正式 exhaustive tuner 必须重现配置 gains、10179 候选和唯一 objective。"""
    contract = load_hvac_scenario_contract(PLANT_2R2C_PATH)
    selected, tuning, quality = load_hvac_pid_tuning_contract(PID_2R2C_PATH, contract)
    result = tune_hvac_pid(contract, tuning, quality)

    assert result.selected_design == selected
    assert result.evaluated_candidate_count == 10179
    assert result.feasible_candidate_count == 679
    assert result.selected_objective == pytest.approx(
        (0.0597207712547501, 1.1932930117280225, 1 / 30, 0.5, 0.0007, 0.85, -0.85, -0.0007, -0.5)
    )
    assert result.rejection_counts["segment_0:settling_time_seconds"] == 6419
    with pytest.raises(TypeError):
        result.rejection_counts["changed"] = 1  # type: ignore[index]

    baseline = run_plaintext_hvac_baseline(contract, selected)
    assert baseline.output_ideal.shape == (180, 1)
    assert [metric.tail_mae_celsius for metric in baseline.segment_metrics] == pytest.approx(
        [0.022305476494438637, 0.0597207712547501, 0.030022651226448715]
    )


def test_legacy_2r2c_loader_still_recomputes_and_rejects_tampered_result(
    tmp_path: Path,
) -> None:
    """解析步骤拆分后，旧 #42 loader 仍必须重跑 tuner 并核对冻结 result。"""
    plant = tmp_path / PLANT_2R2C_PATH.name
    plant.write_bytes(PLANT_2R2C_PATH.read_bytes())
    loaded = yaml.safe_load(PID_2R2C_PATH.read_text(encoding="utf-8"))
    loaded["tuning"]["result"]["evaluated_candidate_count"] = 10178
    baseline = tmp_path / PID_2R2C_PATH.name
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="evaluated candidate count"):
        load_hvac_pid_tuning_contract(baseline, load_hvac_scenario_contract(plant))


def test_tuner_reports_explicit_infeasible_result_without_relaxing_thresholds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全部候选失败时必须抛出诊断异常，不能调整门槛或返回次优 gains。"""
    from secure_control.scenarios.hvac import tuning as tuning_module

    contract = load_hvac_scenario_contract(PLANT_2R2C_PATH)
    _, _, quality = load_hvac_pid_tuning_contract(PID_2R2C_PATH, contract)
    search = HvacPidTuningContract(
        HvacGainSearchAxis(-1.5, -0.2, 27),
        HvacGainSearchAxis(-0.0015, -0.0001, 29),
        HvacGainSearchAxis(-6.0, 0.0, 13),
        "deterministic_exhaustive_grid_v1",
        (
            "maximum_segment_tail_mae_celsius",
            "mean_segment_mae_celsius",
            "global_saturation_fraction",
        ),
        (
            "absolute_derivative_gain",
            "absolute_integral_gain",
            "absolute_proportional_gain",
            "proportional_gain",
            "integral_gain",
            "derivative_gain",
        ),
    )
    failed_metric = HvacSegmentMetric(
        0, 3600, 15.0, 99.0, 99.0, 99.0, None, 99.0, -99.0, 1.0, 12.0, False, ("mae_celsius",)
    )
    failed_branch = HvacBranchMetrics((failed_metric,), 99.0, 1.0, 12.0, False)
    baseline = run_plaintext_hvac_baseline(
        contract, HvacPidDesign(-0.85, -0.0007, -0.5, 60, 0.0, 0.0, 600, 0.5)
    )
    monkeypatch.setattr(tuning_module, "run_plaintext_hvac_baseline", lambda *args: baseline)
    monkeypatch.setattr(
        tuning_module, "evaluate_hvac_branch_metrics", lambda **kwargs: failed_branch
    )

    with pytest.raises(HvacTuningInfeasibleError) as captured:
        tune_hvac_pid.__wrapped__(contract, search, quality)  # type: ignore[attr-defined]
    assert captured.value.evaluated_candidate_count == 10179
    assert captured.value.best_failed_design is not None
    assert captured.value.violations == ("segment_0:mae_celsius",)
