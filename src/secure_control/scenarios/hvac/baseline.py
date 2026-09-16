"""使用通用明文状态空间运行时的 HVAC 闭环基线。"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any

import numpy as np
from numpy.typing import NDArray

from secure_control.execution import PlaintextStateSpaceRuntime

from .adapter import HvacSignalAdapter
from .contract import HvacScenarioContract
from .pid import HvacPidDesign
from .plant import build_hvac_plant

Array = NDArray[Any]


def _readonly_trajectory(name: str, value: Array, shape: tuple[int, ...]) -> Array:
    """复制并验证保存的原始轨迹，避免调用方事后改变已计算的基线结果。"""
    trajectory = np.array(value, dtype=float, copy=True)
    if trajectory.shape != shape or not np.isfinite(trajectory).all():
        raise ValueError(f"{name} 必须是 shape 为 {shape} 的有限浮点轨迹")
    trajectory.setflags(write=False)
    return trajectory


@dataclass(frozen=True, slots=True)
class HvacSegmentMetric:
    """一个 reference 区段的完整控制品质指标与门槛判定。"""

    start_seconds: int
    end_seconds: int
    target_temperature_celsius: float
    mae_celsius: float
    tail_mae_celsius: float
    max_abs_error_celsius: float
    settling_time_seconds: float | None
    max_signed_deviation_celsius: float
    min_signed_deviation_celsius: float
    saturation_fraction: float
    max_abs_applied_control_kw: float
    passed: bool
    violations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HvacSegmentQualityContract:
    """冻结单个 reference 区段的控制品质门槛。"""

    start_seconds: int
    end_seconds: int
    target_temperature_celsius: float
    max_mae_celsius: float
    max_tail_mae_celsius: float
    max_abs_error_celsius: float
    max_settling_time_seconds: float
    max_signed_deviation_celsius: float
    min_signed_deviation_celsius: float

    def __post_init__(self) -> None:
        """拒绝空区段、非有限值和不能形成有效门槛的配置。"""
        if self.start_seconds < 0 or self.end_seconds <= self.start_seconds:
            raise ValueError("quality 区段必须满足 0 <= start < end")
        values = (
            self.target_temperature_celsius,
            self.max_mae_celsius,
            self.max_tail_mae_celsius,
            self.max_abs_error_celsius,
            self.max_settling_time_seconds,
            self.max_signed_deviation_celsius,
            self.min_signed_deviation_celsius,
        )
        if not all(isfinite(value) for value in values):
            raise ValueError("quality 区段门槛必须是有限数")
        if any(value < 0 for value in values[1:5]):
            raise ValueError("MAE、最大误差和调节时间门槛不得为负数")
        if self.min_signed_deviation_celsius > self.max_signed_deviation_celsius:
            raise ValueError("有符号偏差门槛上下界反转")


@dataclass(frozen=True, slots=True)
class HvacControlQualityContract:
    """冻结 branch 指标、执行器和安全/明文差异的验收阈值。"""

    tail_window_seconds: int
    settling_band_celsius: float
    saturation_tolerance_kw: float
    max_segment_saturation_fraction: float
    max_segment_applied_control_kw: float
    segments: tuple[HvacSegmentQualityContract, ...]
    max_control_error_kw: float
    mean_control_error_kw: float
    rms_control_error_kw: float
    max_temperature_error_celsius: float
    mean_temperature_error_celsius: float
    rms_temperature_error_celsius: float

    def __post_init__(self) -> None:
        """校验全局品质阈值、比较阈值及不可变区段集合。"""
        if (
            isinstance(self.tail_window_seconds, bool)
            or not isinstance(self.tail_window_seconds, int)
            or self.tail_window_seconds <= 0
        ):
            raise ValueError("tail_window_seconds 必须是正整数")
        nonnegative = (
            self.settling_band_celsius,
            self.saturation_tolerance_kw,
            self.max_segment_saturation_fraction,
            self.max_segment_applied_control_kw,
            self.max_control_error_kw,
            self.mean_control_error_kw,
            self.rms_control_error_kw,
            self.max_temperature_error_celsius,
            self.mean_temperature_error_celsius,
            self.rms_temperature_error_celsius,
        )
        if not all(isfinite(value) and value >= 0 for value in nonnegative):
            raise ValueError("quality 全局门槛必须是有限非负数")
        if self.settling_band_celsius == 0 or self.max_segment_applied_control_kw == 0:
            raise ValueError("settling band 和 applied control 门槛必须为正数")
        if self.max_segment_saturation_fraction > 1:
            raise ValueError("saturation fraction 门槛不得超过 1")
        if not isinstance(self.segments, tuple) or not self.segments:
            raise ValueError("quality.segments 必须是非空 tuple")


@dataclass(frozen=True, slots=True)
class HvacBranchMetrics:
    """汇总一支闭环的区段指标与全局观测值。"""

    segments: tuple[HvacSegmentMetric, ...]
    global_max_abs_error_celsius: float
    global_saturation_fraction: float
    global_max_abs_applied_control_kw: float
    passed: bool


@dataclass(frozen=True, slots=True)
class HvacComparisonMetrics:
    """汇总明文/安全两支品质与逐样本差异指标。"""

    ideal: HvacBranchMetrics
    secure: HvacBranchMetrics
    max_control_error_kw: float
    mean_control_error_kw: float
    rms_control_error_kw: float
    max_temperature_error_celsius: float
    mean_temperature_error_celsius: float
    rms_temperature_error_celsius: float
    passed: bool


@dataclass(frozen=True, slots=True)
class HvacPlaintextBaseline:
    """明文 HVAC 闭环的通用命名轨迹与场景专属 tracking 指标。"""

    time: Array
    reference: Array
    output_ideal: Array
    control_ideal: Array
    raw_control_ideal: Array
    segment_metrics: tuple[HvacSegmentMetric, ...]

    def __post_init__(self) -> None:
        sample_count = np.asarray(self.time).shape[0]
        object.__setattr__(self, "time", _readonly_trajectory("time", self.time, (sample_count,)))
        for name in ("reference", "output_ideal", "control_ideal", "raw_control_ideal"):
            object.__setattr__(
                self,
                name,
                _readonly_trajectory(name, getattr(self, name), (sample_count, 1)),
            )
        if not self.segment_metrics:
            raise ValueError("HVAC 基线必须包含 reference 区段指标")
        if any(not isfinite(metric.tail_mae_celsius) for metric in self.segment_metrics):
            raise ValueError("HVAC 区段指标必须是有限数值")


def run_plaintext_hvac_baseline(
    contract: HvacScenarioContract, design: HvacPidDesign
) -> HvacPlaintextBaseline:
    """执行 10800 s HVAC 明文闭环，并以通用轨迹字段记录未过滤结果。

    本函数故意位于场景层，不替代未来领域无关的 simulation engine。每步由 HVAC adapter
    构造 ``v``，再调用 #21 的 ``PlaintextStateSpaceRuntime.step(v)``。saturation 在 plant 前
    发生，PID 内部积分状态保持原始线性递推，因此当前配置明确为 anti-windup disabled。
    """
    if not isinstance(contract, HvacScenarioContract):
        raise TypeError("contract 必须是 HvacScenarioContract")
    if not isinstance(design, HvacPidDesign):
        raise TypeError("design 必须是 HvacPidDesign")
    if design.sample_period_seconds != contract.timing.sampling_period_seconds:
        raise ValueError("PID 采样周期必须与 HVAC 场景契约一致")

    plant = build_hvac_plant(contract)
    adapter = HvacSignalAdapter(contract)
    runtime = PlaintextStateSpaceRuntime(design.to_controller_spec())
    sample_times = contract.timing.sample_times_seconds
    sample_count = len(sample_times)
    reference = np.empty((sample_count, 1), dtype=float)
    output_ideal = np.empty((sample_count, 1), dtype=float)
    control_ideal = np.empty((sample_count, 1), dtype=float)
    raw_control_ideal = np.empty((sample_count, 1), dtype=float)

    for index, time_seconds in enumerate(sample_times):
        reference_value = adapter.reference_at(time_seconds)
        output_value = plant.output()
        controller_input = adapter.controller_input(reference_value, output_value)
        raw_control = runtime.step(controller_input)
        applied_control = adapter.apply_control(raw_control)

        reference[index] = reference_value
        output_ideal[index] = output_value
        raw_control_ideal[index] = raw_control
        control_ideal[index] = applied_control
        plant.step(applied_control)

    return HvacPlaintextBaseline(
        time=np.array(sample_times, dtype=float),
        reference=reference,
        output_ideal=output_ideal,
        control_ideal=control_ideal,
        raw_control_ideal=raw_control_ideal,
        segment_metrics=_legacy_segment_metrics(contract, design, output_ideal, control_ideal),
    )


def _legacy_segment_metrics(
    contract: HvacScenarioContract,
    design: HvacPidDesign,
    output_ideal: Array,
    control_ideal: Array,
) -> tuple[HvacSegmentMetric, ...]:
    """为旧一阶配置提供兼容指标，不引入新的验收门槛。"""
    unbounded = 1e300
    quality = HvacControlQualityContract(
        tail_window_seconds=design.tail_window_seconds,
        settling_band_celsius=unbounded,
        saturation_tolerance_kw=1e-9,
        max_segment_saturation_fraction=1.0,
        max_segment_applied_control_kw=contract.model.upper_control_bound_kw,
        segments=tuple(
            HvacSegmentQualityContract(
                segment.start_seconds,
                segment.end_seconds,
                segment.target_temperature_celsius,
                unbounded,
                design.max_tail_mae_celsius,
                unbounded,
                unbounded,
                unbounded,
                -unbounded,
            )
            for segment in contract.reference_segments
        ),
        max_control_error_kw=unbounded,
        mean_control_error_kw=unbounded,
        rms_control_error_kw=unbounded,
        max_temperature_error_celsius=unbounded,
        mean_temperature_error_celsius=unbounded,
        rms_temperature_error_celsius=unbounded,
    )
    time = np.asarray(contract.timing.sample_times_seconds, dtype=float)
    reference = np.array(
        [
            next(
                segment.target_temperature_celsius
                for segment in contract.reference_segments
                if segment.start_seconds <= value < segment.end_seconds
            )
            for value in time
        ],
        dtype=float,
    ).reshape(-1, 1)
    return evaluate_hvac_branch_metrics(
        time=time,
        reference=reference,
        air_temperature=output_ideal,
        applied_control=control_ideal,
        contract=contract,
        quality_contract=quality,
    ).segments


def evaluate_hvac_branch_metrics(
    *,
    time: Array,
    reference: Array,
    air_temperature: Array,
    applied_control: Array,
    contract: HvacScenarioContract,
    quality_contract: HvacControlQualityContract,
) -> HvacBranchMetrics:
    """按冻结公式计算一支闭环的区段与全局指标。"""
    sample_count = contract.timing.sample_count
    time_values = np.asarray(time, dtype=float)
    reference_values = np.asarray(reference, dtype=float)
    temperature_values = np.asarray(air_temperature, dtype=float)
    control_values = np.asarray(applied_control, dtype=float)
    if time_values.shape != (sample_count,):
        raise ValueError("time shape 与 HVAC sample_count 不一致")
    for name, values in (
        ("reference", reference_values),
        ("air_temperature", temperature_values),
        ("applied_control", control_values),
    ):
        if values.shape != (sample_count, 1):
            raise ValueError(f"{name} 必须是 shape ({sample_count}, 1)")
    if not all(
        np.isfinite(values).all()
        for values in (time_values, reference_values, temperature_values, control_values)
    ):
        raise FloatingPointError("HVAC 指标输入包含 NaN 或无穷大")
    expected_time = np.asarray(contract.timing.sample_times_seconds, dtype=float)
    if not np.array_equal(time_values, expected_time) or np.any(np.diff(time_values) <= 0):
        raise ValueError("time 必须与 HVAC 契约的严格递增采样网格一致")
    if len(quality_contract.segments) != len(contract.reference_segments):
        raise ValueError("quality 区段数必须与 reference 区段数一致")
    low = contract.model.lower_control_bound_kw
    high = contract.model.upper_control_bound_kw
    tolerance = quality_contract.saturation_tolerance_kw
    if np.any(control_values < low - tolerance) or np.any(control_values > high + tolerance):
        raise ValueError("applied_control 超出 HVAC actuator 范围")

    metrics: list[HvacSegmentMetric] = []
    all_errors: list[np.ndarray] = []
    for segment, threshold in zip(contract.reference_segments, quality_contract.segments):
        if (
            threshold.start_seconds != segment.start_seconds
            or threshold.end_seconds != segment.end_seconds
            or threshold.target_temperature_celsius != segment.target_temperature_celsius
        ):
            raise ValueError("quality 区段与 reference 区段不一致")
        mask = (time_values >= segment.start_seconds) & (time_values < segment.end_seconds)
        if not np.any(mask):
            raise ValueError("reference 区段没有采样点")
        expected_reference = segment.target_temperature_celsius
        if not np.all(reference_values[mask, 0] == expected_reference):
            raise ValueError("reference 轨迹与 HVAC 契约不一致")
        signed = temperature_values[mask, 0] - expected_reference
        absolute = np.abs(signed)
        all_errors.append(absolute)
        tail_mask = mask & (
            time_values >= segment.end_seconds - quality_contract.tail_window_seconds
        )
        if (
            np.count_nonzero(tail_mask) * contract.timing.sampling_period_seconds
            < quality_contract.tail_window_seconds
        ):
            raise ValueError("reference 区段的 tail window 样本不足")
        tail = np.abs(temperature_values[tail_mask, 0] - expected_reference)
        settled_index: int | None = None
        within = absolute <= quality_contract.settling_band_celsius
        for index in range(within.size):
            if bool(np.all(within[index:])):
                settled_index = index
                break
        settling_time = (
            None
            if settled_index is None
            else float(settled_index * contract.timing.sampling_period_seconds)
        )
        segment_control = control_values[mask, 0]
        saturated = (np.abs(segment_control - low) <= tolerance) | (
            np.abs(segment_control - high) <= tolerance
        )
        mae = float(np.mean(absolute))
        tail_mae = float(np.mean(tail))
        max_abs = float(np.max(absolute))
        max_signed = float(np.max(signed))
        min_signed = float(np.min(signed))
        saturation_fraction = float(np.mean(saturated))
        max_control = float(np.max(np.abs(segment_control)))
        violations: list[str] = []
        checks = (
            (mae <= threshold.max_mae_celsius, "mae_celsius"),
            (tail_mae <= threshold.max_tail_mae_celsius, "tail_mae_celsius"),
            (max_abs <= threshold.max_abs_error_celsius, "max_abs_error_celsius"),
            (
                settling_time is not None and settling_time <= threshold.max_settling_time_seconds,
                "settling_time_seconds",
            ),
            (
                max_signed <= threshold.max_signed_deviation_celsius,
                "max_signed_deviation_celsius",
            ),
            (
                min_signed >= threshold.min_signed_deviation_celsius,
                "min_signed_deviation_celsius",
            ),
            (
                saturation_fraction <= quality_contract.max_segment_saturation_fraction,
                "saturation_fraction",
            ),
            (
                max_control <= quality_contract.max_segment_applied_control_kw,
                "max_abs_applied_control_kw",
            ),
        )
        violations.extend(name for passed, name in checks if not passed)
        metrics.append(
            HvacSegmentMetric(
                segment.start_seconds,
                segment.end_seconds,
                expected_reference,
                mae,
                tail_mae,
                max_abs,
                settling_time,
                max_signed,
                min_signed,
                saturation_fraction,
                max_control,
                not violations,
                tuple(violations),
            )
        )
    global_absolute = np.concatenate(all_errors)
    all_control = control_values[:, 0]
    all_saturated = (np.abs(all_control - low) <= tolerance) | (
        np.abs(all_control - high) <= tolerance
    )
    return HvacBranchMetrics(
        tuple(metrics),
        float(np.max(global_absolute)),
        float(np.mean(all_saturated)),
        float(np.max(np.abs(all_control))),
        all(metric.passed for metric in metrics),
    )


def evaluate_hvac_comparison_metrics(
    result: Any,
    contract: HvacScenarioContract,
    quality_contract: HvacControlQualityContract,
) -> HvacComparisonMetrics:
    """从正式八字段结果计算两支品质与明文/安全差异。"""
    ideal = evaluate_hvac_branch_metrics(
        time=result.time,
        reference=result.reference,
        air_temperature=result.output_ideal,
        applied_control=result.control_ideal,
        contract=contract,
        quality_contract=quality_contract,
    )
    secure = evaluate_hvac_branch_metrics(
        time=result.time,
        reference=result.reference,
        air_temperature=result.output_secure,
        applied_control=result.control_secure,
        contract=contract,
        quality_contract=quality_contract,
    )
    control_difference = np.asarray(result.control_error, dtype=float)
    temperature_difference = np.asarray(result.output_error, dtype=float)
    if not np.isfinite(control_difference).all() or not np.isfinite(temperature_difference).all():
        raise FloatingPointError("安全/明文差异包含 NaN 或无穷大")
    control_abs = np.abs(control_difference)
    temperature_abs = np.abs(temperature_difference)
    values = (
        float(np.max(control_abs)),
        float(np.mean(control_abs)),
        float(np.sqrt(np.mean(np.square(control_difference)))),
        float(np.max(temperature_abs)),
        float(np.mean(temperature_abs)),
        float(np.sqrt(np.mean(np.square(temperature_difference)))),
    )
    limits = (
        quality_contract.max_control_error_kw,
        quality_contract.mean_control_error_kw,
        quality_contract.rms_control_error_kw,
        quality_contract.max_temperature_error_celsius,
        quality_contract.mean_temperature_error_celsius,
        quality_contract.rms_temperature_error_celsius,
    )
    return HvacComparisonMetrics(
        ideal,
        secure,
        *values,
        ideal.passed
        and secure.passed
        and all(value <= limit for value, limit in zip(values, limits)),
    )
