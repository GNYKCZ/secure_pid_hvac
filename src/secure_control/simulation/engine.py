"""只依赖通用契约的双分支离散时间仿真引擎。"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from time import perf_counter
from typing import Any

import numpy as np
from numpy.typing import NDArray

from .contracts import SimulationBranch
from .results import SimulationResult
from .telemetry import TelemetrySession

Array = NDArray[Any]


def _vector(name: str, value: Any, channels: int | None = None) -> np.ndarray:
    """拒绝广播含义不明的信号，并复制成有限的单步扁平实数向量。"""
    signal = np.asarray(value)
    if signal.ndim != 1 or signal.size == 0:
        raise ValueError(f"{name} 必须是非空的一维信号向量。")
    if channels is not None and signal.shape != (channels,):
        raise ValueError(f"{name} channel shape 必须是 ({channels},)。")
    if signal.dtype.kind not in "iuf":
        raise TypeError(f"{name} 必须包含实数。")
    if not np.isfinite(signal).all():
        raise FloatingPointError(f"{name} 包含 NaN 或无穷大。")
    return np.array(signal, dtype=float, copy=True)


def _times(sample_times: Array) -> np.ndarray:
    """冻结一个非空、有限且严格递增的单支时间网格。"""
    times = np.asarray(sample_times)
    if times.ndim != 1 or times.size == 0:
        raise ValueError("sample_times 必须是非空一维时间数组。")
    if times.dtype.kind not in "iuf":
        raise TypeError("sample_times 必须包含实数。")
    if not np.isfinite(times).all():
        raise FloatingPointError("sample_times 包含 NaN 或无穷大。")
    if any(later <= earlier for earlier, later in pairwise(times)):
        raise ValueError("sample_times 必须严格递增。")
    return np.array(times, copy=True)


def _fault_category(error: Exception, phase: str) -> str:
    """按错误所有者给出的受限类别分类，不依赖具体 runtime 实现。"""
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, ConnectionError):
        return "disconnected"
    if phase == "control" and getattr(error, "_public_fault_category", None) == "protocol":
        return "protocol"
    return "plant" if phase == "plant" else "control"


@dataclass(frozen=True, slots=True)
class BranchTrajectory:
    """仅保存一支运行成功后的 reference、更新前 output 与 applied control。"""

    reference: Array
    output: Array
    control: Array


def simulate_branch(
    branch: SimulationBranch,
    sample_times: Array,
    *,
    _on_sample: Any = None,
    _on_phase: Any = None,
) -> BranchTrajectory:
    """按 reference→pre-plant output→v→raw u→actuator→plant 顺序执行单支。

    任一 hook 或状态更新失败时直接传播异常，不返回部分轨迹；plant.step 的后输出
    只用于检查执行成功，记录仍对应时间 ``t_k`` 的更新前 output。
    """
    if not isinstance(branch, SimulationBranch):
        raise TypeError("branch 必须是 SimulationBranch。")
    times = _times(sample_times)
    metadata = branch.adapter.metadata
    reference_channels = len(metadata.reference.names)
    output_channels = len(metadata.output.names)
    control_channels = len(metadata.control.names)
    references: list[np.ndarray] = []
    outputs: list[np.ndarray] = []
    controls: list[np.ndarray] = []

    for step, time in enumerate(times):
        if _on_phase is not None:
            _on_phase(step, "control")
        reference = _vector(
            "reference", branch.adapter.reference_at(float(time)), reference_channels
        )
        output = _vector("plant output", branch.plant.output(), output_channels)
        controller_input = _vector(
            "controller input", branch.adapter.controller_input(reference, output)
        )
        round_start = perf_counter() if _on_sample is not None else 0.0
        raw_control = _vector(
            "raw control", branch.runtime.step(controller_input), control_channels
        )
        round_ms = (perf_counter() - round_start) * 1000 if _on_sample is not None else None
        plant_start = perf_counter() if _on_sample is not None else 0.0
        if _on_phase is not None:
            _on_phase(step, "plant")
        applied_control = _vector(
            "applied control", branch.adapter.apply_control(raw_control), control_channels
        )
        next_output = branch.plant.step(applied_control)
        _vector("next plant output", next_output, output_channels)
        # 只有 plant.step 完整成功后才记录；但 output 始终是本轮 pre-plant 测量。
        references.append(reference)
        outputs.append(output)
        controls.append(applied_control)
        if _on_sample is not None:
            _on_sample(
                step,
                float(time),
                reference,
                output,
                applied_control,
                round_ms,
                (perf_counter() - plant_start) * 1000,
            )

    return BranchTrajectory(np.vstack(references), np.vstack(outputs), np.vstack(controls))


def compare_closed_loops(
    ideal: SimulationBranch,
    secure: SimulationBranch,
    sample_times: Array,
    *,
    telemetry: TelemetrySession | None = None,
) -> SimulationResult:
    """先拒绝共享对象，再独立执行两支并计算逐时刻有符号误差。"""
    if not isinstance(ideal, SimulationBranch) or not isinstance(secure, SimulationBranch):
        raise TypeError("ideal/secure 必须是 SimulationBranch。")
    if (
        ideal.plant is secure.plant
        or ideal.adapter is secure.adapter
        or ideal.runtime is secure.runtime
    ):
        raise ValueError("ideal/secure 不得共享 plant、adapter 或 runtime 实例。")
    if ideal.adapter.metadata != secure.adapter.metadata:
        raise ValueError("ideal/secure 的 channel metadata 必须一致。")
    times = _times(sample_times)
    if telemetry is not None and not isinstance(telemetry, TelemetrySession):
        raise TypeError("telemetry 必须是 TelemetrySession。")
    step_in_progress: int | None = None
    phase = "control"
    if telemetry is not None:
        telemetry.start(secure.adapter.metadata)
    try:
        ideal_log = simulate_branch(ideal, times)

        def publish_sample(
            step: int,
            time: float,
            reference: np.ndarray,
            output: np.ndarray,
            control: np.ndarray,
            round_ms: float,
            plant_ms: float,
        ) -> None:
            """只从成功记录的 secure 步复制公开数值。"""
            nonlocal step_in_progress
            step_in_progress = step
            if not np.array_equal(ideal_log.reference[step], reference):
                raise ValueError("ideal/secure 的 reference 时间轨迹必须一致。")
            assert telemetry is not None
            telemetry.sample(
                step=step,
                time_s=time,
                metadata=secure.adapter.metadata,
                reference=tuple(map(float, reference)),
                output_secure=tuple(map(float, output)),
                control_secure=tuple(map(float, control)),
                output_ideal=tuple(map(float, ideal_log.output[step])),
                control_ideal=tuple(map(float, ideal_log.control[step])),
                control_error=tuple(map(float, ideal_log.control[step] - control)),
                output_error=tuple(map(float, ideal_log.output[step] - output)),
                controller_round_ms=round_ms,
                actuator_plant_ms=plant_ms,
            )

        def note_phase(step: int, current: str) -> None:
            """只记录故障所在的公开步骤和边界，不读取 runtime 内部。"""
            nonlocal step_in_progress, phase
            step_in_progress = step
            phase = current

        secure_log = simulate_branch(
            secure,
            times,
            _on_sample=publish_sample if telemetry is not None else None,
            _on_phase=note_phase if telemetry is not None else None,
        )
        phase = "control"
        if not np.array_equal(ideal_log.reference, secure_log.reference):
            raise ValueError("ideal/secure 的 reference 时间轨迹必须一致。")
        if ideal_log.output.shape != secure_log.output.shape:
            raise ValueError("ideal/secure 的 output channel shape 必须一致。")
        if ideal_log.control.shape != secure_log.control.shape:
            raise ValueError("ideal/secure 的 control channel shape 必须一致。")

        result = SimulationResult(
            time=times,
            reference=ideal_log.reference,
            output_ideal=ideal_log.output,
            output_secure=secure_log.output,
            control_ideal=ideal_log.control,
            control_secure=secure_log.control,
            control_error=ideal_log.control - secure_log.control,
            output_error=ideal_log.output - secure_log.output,
        )
        if telemetry is not None:
            telemetry.end("completed")
        return result
    except Exception as error:
        if telemetry is not None:
            # 故障类别固定，绝不复制异常字符串或原始 payload。
            telemetry.fault(step_in_progress, _fault_category(error, phase))
            telemetry.end("failed")
        raise


def run_secure_branch(
    branch: SimulationBranch, sample_times: Array, *, telemetry: TelemetrySession
) -> BranchTrajectory:
    """无 ideal 对照的 Client 运行，比较字段保持 null。"""
    if not isinstance(telemetry, TelemetrySession):
        raise TypeError("telemetry 必须是 TelemetrySession。")
    telemetry.start(branch.adapter.metadata)
    step_in_progress: int | None = None
    phase = "control"

    def note_phase(step: int, current: str) -> None:
        nonlocal step_in_progress, phase
        step_in_progress = step
        phase = current

    def publish_sample(
        step: int,
        time: float,
        reference: np.ndarray,
        output: np.ndarray,
        control: np.ndarray,
        round_ms: float,
        plant_ms: float,
    ) -> None:
        telemetry.sample(
            step=step,
            time_s=time,
            metadata=branch.adapter.metadata,
            reference=tuple(map(float, reference)),
            output_secure=tuple(map(float, output)),
            control_secure=tuple(map(float, control)),
            controller_round_ms=round_ms,
            actuator_plant_ms=plant_ms,
        )

    try:
        result = simulate_branch(
            branch, sample_times, _on_sample=publish_sample, _on_phase=note_phase
        )
        telemetry.end("completed")
        return result
    except Exception as error:
        telemetry.fault(step_in_progress, _fault_category(error, phase))
        telemetry.end("failed")
        raise
