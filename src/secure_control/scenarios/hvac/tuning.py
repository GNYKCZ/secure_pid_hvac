"""2R2C HVAC 的确定性明文 PID 网格调参与配置契约。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from itertools import product
from math import isfinite
from numbers import Integral, Real
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

import numpy as np
import yaml

from .baseline import (
    HvacControlQualityContract,
    HvacSegmentQualityContract,
    evaluate_hvac_branch_metrics,
    run_plaintext_hvac_baseline,
)
from .contract import Hvac2R2CModelContract, HvacScenarioContract, load_hvac_scenario_contract
from .pid import HvacPidDesign

_ALGORITHM = "deterministic_exhaustive_grid_v1"
_OBJECTIVE_ORDER = (
    "maximum_segment_tail_mae_celsius",
    "mean_segment_mae_celsius",
    "global_saturation_fraction",
)
_TIE_BREAK_ORDER = (
    "absolute_derivative_gain",
    "absolute_integral_gain",
    "absolute_proportional_gain",
    "proportional_gain",
    "integral_gain",
    "derivative_gain",
)


@dataclass(frozen=True, slots=True)
class HvacGainSearchAxis:
    """以固定端点与点数描述一个不依赖浮点步进累计的 gain 轴。"""

    minimum: float
    maximum: float
    points: int

    def __post_init__(self) -> None:
        if isinstance(self.points, bool) or not isinstance(self.points, Integral):
            raise TypeError("gain axis points 必须是整数")
        if not isinstance(self.minimum, Real) or not isinstance(self.maximum, Real):
            raise TypeError("gain axis 端点必须是实数")
        if not isfinite(float(self.minimum)) or not isfinite(float(self.maximum)):
            raise ValueError("gain axis 端点必须有限")
        if float(self.minimum) >= float(self.maximum) or int(self.points) < 2:
            raise ValueError("gain axis 必须满足 minimum < maximum 且 points >= 2")
        object.__setattr__(self, "minimum", float(self.minimum))
        object.__setattr__(self, "maximum", float(self.maximum))
        object.__setattr__(self, "points", int(self.points))

    @property
    def candidates(self) -> tuple[float, ...]:
        """返回包含两个端点的确定性升序候选 tuple。"""
        return tuple(float(value) for value in np.linspace(self.minimum, self.maximum, self.points))


@dataclass(frozen=True, slots=True)
class HvacPidTuningContract:
    """冻结 exhaustive grid、候选顺序与唯一选择规则。"""

    proportional: HvacGainSearchAxis
    integral: HvacGainSearchAxis
    derivative: HvacGainSearchAxis
    algorithm: Literal["deterministic_exhaustive_grid_v1"]
    objective_order: tuple[str, ...]
    tie_break_order: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.algorithm != _ALGORITHM:
            raise ValueError(f"tuning algorithm 必须为 {_ALGORITHM}")
        if self.objective_order != _OBJECTIVE_ORDER:
            raise ValueError("tuning objective_order 与冻结设计不一致")
        if self.tie_break_order != _TIE_BREAK_ORDER:
            raise ValueError("tuning tie_break_order 与冻结设计不一致")
        if self.candidate_count != 10179:
            raise ValueError("冻结 tuning grid 必须恰好包含 10179 个候选")
        if self.proportional.maximum >= 0 or self.integral.maximum >= 0:
            raise ValueError("HVAC tuning 的 Kp/Ki 候选必须全部为负数")
        if self.derivative.maximum > 0:
            raise ValueError("HVAC tuning 的 Kd 候选不得为正数")

    @property
    def candidate_count(self) -> int:
        """返回三轴笛卡尔积的精确候选数量。"""
        return self.proportional.points * self.integral.points * self.derivative.points


@dataclass(frozen=True, slots=True)
class HvacPidTuningResult:
    """保存唯一 selected design 和足以审计选择过程的聚合结果。"""

    selected_design: HvacPidDesign
    evaluated_candidate_count: int
    feasible_candidate_count: int
    rejection_counts: Mapping[str, int]
    selected_objective: tuple[float, ...]

    def __post_init__(self) -> None:
        copied = {str(key): int(value) for key, value in self.rejection_counts.items()}
        if any(value < 0 for value in copied.values()):
            raise ValueError("rejection_counts 不得包含负数")
        object.__setattr__(self, "rejection_counts", MappingProxyType(copied))


class HvacTuningInfeasibleError(ValueError):
    """报告固定网格没有可行候选，并保留最佳失败候选的诊断。"""

    def __init__(
        self,
        evaluated_candidate_count: int,
        best_failed_design: HvacPidDesign | None,
        violations: tuple[str, ...],
    ) -> None:
        super().__init__("冻结 HVAC PID 网格没有满足全部品质门槛的候选")
        self.evaluated_candidate_count = evaluated_candidate_count
        self.best_failed_design = best_failed_design
        self.violations = violations


def load_hvac_pid_tuning_contract(
    path: str | Path, plant_contract: HvacScenarioContract
) -> tuple[HvacPidDesign, HvacPidTuningContract, HvacControlQualityContract]:
    """读取 2R2C PID 配置并校验 plant 引用、hash、策略与冻结调参规则。"""
    if not isinstance(plant_contract, HvacScenarioContract) or not isinstance(
        plant_contract.model, Hvac2R2CModelContract
    ):
        raise TypeError("plant_contract 必须是 2R2C HvacScenarioContract")
    config_path = Path(path)
    try:
        source = config_path.read_bytes()
        loaded = yaml.safe_load(source.decode("utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"无法读取 2R2C PID 配置：{config_path}") from error
    if not isinstance(loaded, Mapping):
        raise TypeError("2R2C PID 配置根节点必须是映射")
    scenario = _mapping(loaded, "scenario")
    if _string(scenario, "name") != "hvac":
        raise ValueError("scenario.name 必须为 hvac")
    plant_name = _string(loaded, "plant_config")
    plant_path = config_path.parent / plant_name
    try:
        plant_source = plant_path.read_bytes()
    except OSError as error:
        raise ValueError(f"无法读取引用的 2R2C plant 配置：{plant_path}") from error
    # Git 可按平台转换工作树换行；引用 hash 统一按 LF 规范化，保证跨平台配置身份稳定。
    canonical_plant_source = plant_source.replace(b"\r\n", b"\n")
    if sha256(canonical_plant_source).hexdigest() != _string(loaded, "plant_sha256"):
        raise ValueError("2R2C plant 配置 SHA-256 与冻结引用不一致")
    if load_hvac_scenario_contract(plant_path) != plant_contract:
        raise ValueError("传入 plant contract 与 PID 配置引用的 plant 不一致")

    controller = _mapping(loaded, "controller")
    _validate_controller_strategy(controller)
    tracking = _mapping(loaded, "tracking")
    selected = HvacPidDesign(
        proportional_gain_kw_per_celsius=_number(controller, "proportional_gain_kw_per_celsius"),
        integral_gain_kw_per_celsius_second=_number(
            controller, "integral_gain_kw_per_celsius_second"
        ),
        derivative_gain_kw_second_per_celsius=_number(
            controller, "derivative_gain_kw_second_per_celsius"
        ),
        sample_period_seconds=plant_contract.timing.sampling_period_seconds,
        initial_integral_error_celsius_seconds=_number(
            controller, "initial_integral_error_celsius_seconds"
        ),
        initial_previous_error_celsius=_number(controller, "initial_previous_error_celsius"),
        tail_window_seconds=_integer(tracking, "tail_window_seconds"),
        max_tail_mae_celsius=_number(tracking, "max_tail_mae_celsius"),
    )
    tuning = _parse_tuning(_mapping(loaded, "tuning"))
    quality = _parse_quality(_mapping(loaded, "quality"), plant_contract)
    report = _mapping(_mapping(loaded, "tuning"), "result")
    rerun = tune_hvac_pid(plant_contract, tuning, quality)
    if rerun.selected_design != selected:
        raise ValueError("配置 selected gains 与确定性 tuner 重跑结果不一致")
    if _integer(report, "evaluated_candidate_count") != rerun.evaluated_candidate_count:
        raise ValueError("配置 evaluated candidate count 与 tuner 重跑结果不一致")
    if _integer(report, "feasible_candidate_count") != rerun.feasible_candidate_count:
        raise ValueError("配置 feasible candidate count 与 tuner 重跑结果不一致")
    objective = report.get("selected_objective")
    if (
        not isinstance(objective, list)
        or tuple(float(item) for item in objective) != rerun.selected_objective
    ):
        raise ValueError("配置 selected objective 与 tuner 重跑结果不一致")
    rejection_report = _mapping(report, "rejection_counts")
    configured_rejections = {key: _integer(rejection_report, key) for key in rejection_report}
    normalized_rerun = {
        key.replace(":", "_", 1): value for key, value in rerun.rejection_counts.items()
    }
    if configured_rejections != normalized_rerun:
        raise ValueError("配置 rejection counts 与 tuner 重跑结果不一致")
    if config_path.read_bytes() != source or plant_path.read_bytes() != plant_source:
        raise ValueError("2R2C PID/plant 配置在解析期间发生变化")
    return selected, tuning, quality


@lru_cache(maxsize=8)
def tune_hvac_pid(
    plant_contract: HvacScenarioContract,
    tuning_contract: HvacPidTuningContract,
    quality_contract: HvacControlQualityContract,
) -> HvacPidTuningResult:
    """仅使用明文 2R2C 闭环遍历冻结网格并作字典序唯一选择。"""
    if not isinstance(plant_contract.model, Hvac2R2CModelContract):
        raise TypeError("tune_hvac_pid 只接受 2R2C plant contract")
    rejection_counts: dict[str, int] = {}
    feasible_count = 0
    selected: tuple[tuple[float, ...], HvacPidDesign] | None = None
    best_failed: tuple[int, tuple[str, ...], HvacPidDesign] | None = None
    for kp, ki, kd in product(
        tuning_contract.proportional.candidates,
        tuning_contract.integral.candidates,
        tuning_contract.derivative.candidates,
    ):
        design = HvacPidDesign(
            kp,
            ki,
            kd,
            plant_contract.timing.sampling_period_seconds,
            0.0,
            0.0,
            quality_contract.tail_window_seconds,
            max(item.max_tail_mae_celsius for item in quality_contract.segments),
        )
        try:
            baseline = run_plaintext_hvac_baseline(plant_contract, design)
            branch = evaluate_hvac_branch_metrics(
                time=baseline.time,
                reference=baseline.reference,
                air_temperature=baseline.output_ideal,
                applied_control=baseline.control_ideal,
                contract=plant_contract,
                quality_contract=quality_contract,
            )
        except FloatingPointError:
            rejection_counts["non_finite"] = rejection_counts.get("non_finite", 0) + 1
            continue
        violations = tuple(
            f"segment_{metric.start_seconds}:{violation}"
            for metric in branch.segments
            for violation in metric.violations
        )
        if violations:
            for violation in set(violations):
                rejection_counts[violation] = rejection_counts.get(violation, 0) + 1
            diagnostic = (len(violations), violations, design)
            if best_failed is None or diagnostic[:2] < best_failed[:2]:
                best_failed = diagnostic
            continue
        feasible_count += 1
        objective = (
            max(metric.tail_mae_celsius for metric in branch.segments),
            float(np.mean([metric.mae_celsius for metric in branch.segments])),
            branch.global_saturation_fraction,
            abs(kd),
            abs(ki),
            abs(kp),
            kp,
            ki,
            kd,
        )
        if selected is None or objective < selected[0]:
            selected = (objective, design)
    if selected is None:
        raise HvacTuningInfeasibleError(
            tuning_contract.candidate_count,
            None if best_failed is None else best_failed[2],
            () if best_failed is None else best_failed[1],
        )
    return HvacPidTuningResult(
        selected[1],
        tuning_contract.candidate_count,
        feasible_count,
        rejection_counts,
        selected[0],
    )


def _parse_tuning(source: Mapping[str, Any]) -> HvacPidTuningContract:
    """解析并严格冻结 exhaustive grid 与排序字段。"""
    axes = _mapping(source, "axes")
    return HvacPidTuningContract(
        _axis(_mapping(axes, "proportional")),
        _axis(_mapping(axes, "integral")),
        _axis(_mapping(axes, "derivative")),
        _string(source, "algorithm"),  # type: ignore[arg-type]
        _string_tuple(source, "objective_order"),
        _string_tuple(source, "tie_break_order"),
    )


def _parse_quality(
    source: Mapping[str, Any], contract: HvacScenarioContract
) -> HvacControlQualityContract:
    """解析按 reference 对齐的品质与安全/明文比较门槛。"""
    items = source.get("segments")
    if not isinstance(items, list):
        raise TypeError("quality.segments 必须是列表")
    segments = tuple(
        HvacSegmentQualityContract(
            _integer(_item_mapping(item, "quality.segments item"), "start_seconds"),
            _integer(_item_mapping(item, "quality.segments item"), "end_seconds"),
            _number(_item_mapping(item, "quality.segments item"), "target_temperature_celsius"),
            _number(_item_mapping(item, "quality.segments item"), "max_mae_celsius"),
            _number(_item_mapping(item, "quality.segments item"), "max_tail_mae_celsius"),
            _number(_item_mapping(item, "quality.segments item"), "max_abs_error_celsius"),
            _number(_item_mapping(item, "quality.segments item"), "max_settling_time_seconds"),
            _number(_item_mapping(item, "quality.segments item"), "max_signed_deviation_celsius"),
            _number(_item_mapping(item, "quality.segments item"), "min_signed_deviation_celsius"),
        )
        for item in items
    )
    comparison = _mapping(source, "comparison")
    quality = HvacControlQualityContract(
        _integer(source, "tail_window_seconds"),
        _number(source, "settling_band_celsius"),
        _number(source, "saturation_tolerance_kw"),
        _number(source, "max_segment_saturation_fraction"),
        _number(source, "max_segment_applied_control_kw"),
        segments,
        _number(comparison, "max_control_error_kw"),
        _number(comparison, "mean_control_error_kw"),
        _number(comparison, "rms_control_error_kw"),
        _number(comparison, "max_temperature_error_celsius"),
        _number(comparison, "mean_temperature_error_celsius"),
        _number(comparison, "rms_temperature_error_celsius"),
    )
    if quality.tail_window_seconds % contract.timing.sampling_period_seconds != 0:
        raise ValueError("quality tail window 必须能被采样周期整除")
    return quality


def _axis(source: Mapping[str, Any]) -> HvacGainSearchAxis:
    """解析一个 gain 搜索轴。"""
    return HvacGainSearchAxis(
        _number(source, "minimum"), _number(source, "maximum"), _integer(source, "points")
    )


def _validate_controller_strategy(source: Mapping[str, Any]) -> None:
    """拒绝改变 PID realization、滤波、anti-windup 或 saturation 位置。"""
    expected = {
        "kind": "positional_pid_error_derivative",
        "derivative_filter": "none",
        "anti_windup": "disabled",
        "output_saturation": "scenario_before_plant",
    }
    for key, value in expected.items():
        if _string(source, key) != value:
            raise ValueError(f"controller.{key} 必须为 {value}")


def _mapping(source: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """读取必填映射。"""
    return _item_mapping(source.get(key), key)


def _item_mapping(value: Any, name: str) -> Mapping[str, Any]:
    """验证列表中的映射项。"""
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{name} 必须是映射")
    return value


def _string(source: Mapping[str, Any], key: str) -> str:
    """读取非空字符串。"""
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} 必须是非空字符串")
    return value


def _string_tuple(source: Mapping[str, Any], key: str) -> tuple[str, ...]:
    """读取非空字符串列表并冻结为 tuple。"""
    value = source.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{key} 必须是非空字符串列表")
    return tuple(value)


def _integer(source: Mapping[str, Any], key: str) -> int:
    """读取不接受布尔值的整数。"""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise TypeError(f"{key} 必须是整数")
    return int(value)


def _number(source: Mapping[str, Any], key: str) -> float:
    """读取有限实数。"""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
        raise ValueError(f"{key} 必须是有限实数")
    return float(value)
