"""只依赖通用契约的双分支离散时间仿真引擎。"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from typing import Any

import numpy as np
from numpy.typing import NDArray

from .contracts import SimulationBranch
from .results import SimulationResult

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


@dataclass(frozen=True, slots=True)
class BranchTrajectory:
    """仅保存一支运行成功后的 reference、更新前 output 与 applied control。"""

    reference: Array
    output: Array
    control: Array


def simulate_branch(branch: SimulationBranch, sample_times: Array) -> BranchTrajectory:
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

    for time in times:
        reference = _vector(
            "reference", branch.adapter.reference_at(float(time)), reference_channels
        )
        output = _vector("plant output", branch.plant.output(), output_channels)
        controller_input = _vector(
            "controller input", branch.adapter.controller_input(reference, output)
        )
        raw_control = _vector(
            "raw control", branch.runtime.step(controller_input), control_channels
        )
        applied_control = _vector(
            "applied control", branch.adapter.apply_control(raw_control), control_channels
        )
        next_output = branch.plant.step(applied_control)
        _vector("next plant output", next_output, output_channels)
        # 只有 plant.step 完整成功后才记录；但 output 始终是本轮 pre-plant 测量。
        references.append(reference)
        outputs.append(output)
        controls.append(applied_control)

    return BranchTrajectory(np.vstack(references), np.vstack(outputs), np.vstack(controls))


def compare_closed_loops(
    ideal: SimulationBranch, secure: SimulationBranch, sample_times: Array
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
    ideal_log = simulate_branch(ideal, times)
    secure_log = simulate_branch(secure, times)
    if not np.array_equal(ideal_log.reference, secure_log.reference):
        raise ValueError("ideal/secure 的 reference 时间轨迹必须一致。")
    if ideal_log.output.shape != secure_log.output.shape:
        raise ValueError("ideal/secure 的 output channel shape 必须一致。")
    if ideal_log.control.shape != secure_log.control.shape:
        raise ValueError("ideal/secure 的 control channel shape 必须一致。")

    return SimulationResult(
        time=times,
        reference=ideal_log.reference,
        output_ideal=ideal_log.output,
        output_secure=secure_log.output,
        control_ideal=ideal_log.control,
        control_secure=secure_log.control,
        control_error=ideal_log.control - secure_log.control,
        output_error=ideal_log.output - secure_log.output,
    )
