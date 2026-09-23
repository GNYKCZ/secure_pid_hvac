"""论文参数与自选四级对象组合的单支 paper-inspired 明文基线。"""

from __future__ import annotations

from dataclasses import dataclass
from numbers import Integral
from typing import Any

import numpy as np
from numpy.typing import NDArray

from secure_control.core import SchurStabilityReport, check_discrete_schur_stability
from secure_control.execution import PlaintextStateSpaceRuntime

from .pid import paper_sec_vii_controller_spec
from .plant import CascadeZohStateSpace, PaperPidCascadePlant

Array = NDArray[Any]

BASELINE_COLUMNS = (
    "k",
    "time_seconds",
    "x_p_1",
    "x_p_2",
    "x_p_3",
    "x_p_4",
    "y",
    "x_c_1",
    "x_c_2",
    "raw_u",
)


@dataclass(frozen=True, slots=True)
class PaperPidBaseline:
    """保存单支轨迹、所选离散对象和仅对此闭环有效的稳定性诊断。"""

    rows: Array
    plant_matrices: CascadeZohStateSpace
    stability: SchurStabilityReport

    def __post_init__(self) -> None:
        rows = np.array(self.rows, dtype=float, copy=True)
        if rows.ndim != 2 or rows.shape[1] != len(BASELINE_COLUMNS) or not np.isfinite(rows).all():
            raise ValueError("paper-inspired 轨迹必须是有限的十列矩阵")
        rows.setflags(write=False)
        object.__setattr__(self, "rows", rows)


def run_paper_pid_baseline(
    *,
    alpha: float,
    sample_period_seconds: float,
    plant_initial_state: Array,
    sample_count: int,
) -> PaperPidBaseline:
    """逐步记录更新前状态和测量，使用论文印刷控制器驱动自选对象。

    这里不引入 HVAC 的 reference/error 或双支仿真契约。两类状态只在这条
    场景层装配路径相遇；失败时丢弃本次局部实例和轨迹，不发布半成品。
    """
    if isinstance(sample_count, bool) or not isinstance(sample_count, Integral) or sample_count <= 0:
        raise ValueError("sample_count 必须是正整数")
    plant = PaperPidCascadePlant(alpha, sample_period_seconds, plant_initial_state)
    spec = paper_sec_vii_controller_spec()
    runtime = PlaintextStateSpaceRuntime(spec)
    m = plant.state_space
    # 论文 Eq. (3) 的完整六维闭环，仅对本项目明确选择的 plant realization 成立。
    phi = np.block(
        [
            [m.A_p + m.B_p @ spec.D @ m.C_p, m.B_p @ spec.C],
            [spec.B @ m.C_p, spec.A],
        ]
    )
    stability = check_discrete_schur_stability(phi)
    rows = np.empty((int(sample_count), len(BASELINE_COLUMNS)), dtype=float)
    for k in range(int(sample_count)):
        x_p = plant.state
        x_c = runtime.state
        y = plant.output()
        raw_u = runtime.step(y)
        plant.step(raw_u)
        row = np.array(
            (k, k * float(sample_period_seconds), *x_p, y[0], *x_c, raw_u[0]),
            dtype=float,
        )
        if not np.isfinite(row).all():
            raise FloatingPointError("paper-inspired 轨迹产生 NaN 或无穷大")
        rows[k] = row
    return PaperPidBaseline(rows, m, stability)
