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
from .plant import HvacPlant

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
    """一个 reference 区段末尾固定窗口上的未过滤温度 MAE。"""

    start_seconds: int
    end_seconds: int
    target_temperature_celsius: float
    tail_mae_celsius: float


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
        if len(self.segment_metrics) != 3:
            raise ValueError("HVAC 基线必须包含三个 reference 区段的指标")
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

    plant = HvacPlant(contract)
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
        applied_control = _saturate_for_hvac_plant(raw_control, contract)

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
        segment_metrics=_segment_metrics(contract, design, output_ideal),
    )


def _saturate_for_hvac_plant(control: Array, contract: HvacScenarioContract) -> Array:
    """在场景层将线性 runtime 的原始控制量限制为 plant 的物理输入范围。"""
    if control.shape != (1,) or not np.isfinite(control).all():
        raise FloatingPointError("明文 runtime 必须返回有限的 HVAC 单通道控制量")
    model = contract.model
    return np.clip(
        control,
        model.lower_control_bound_kw,
        model.upper_control_bound_kw,
    ).astype(float, copy=False)


def _segment_metrics(
    contract: HvacScenarioContract, design: HvacPidDesign, output_ideal: Array
) -> tuple[HvacSegmentMetric, ...]:
    """从未过滤的记录温度计算每个 reference 区段尾部窗口 MAE。"""
    sample_period = contract.timing.sampling_period_seconds
    metrics: list[HvacSegmentMetric] = []
    for segment in contract.reference_segments:
        end_index = segment.end_seconds // sample_period
        tail_start = end_index - design.tail_window_samples
        temperatures = output_ideal[tail_start:end_index, 0]
        tail_mae = float(np.mean(np.abs(temperatures - segment.target_temperature_celsius)))
        metrics.append(
            HvacSegmentMetric(
                start_seconds=segment.start_seconds,
                end_seconds=segment.end_seconds,
                target_temperature_celsius=segment.target_temperature_celsius,
                tail_mae_celsius=tail_mae,
            )
        )
    return tuple(metrics)
