"""[38] Eq. (2) 的四级串联对象；状态坐标是本项目的显式选择。"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Real
from typing import Any

import numpy as np
from numpy.typing import NDArray
from scipy.signal import cont2discrete

Array = NDArray[Any]


def _positive_finite(name: str, value: float) -> float:
    """拒绝布尔值、非实数和非正参数，避免隐式改变时间尺度。"""
    if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
        raise ValueError(f"{name} 必须是正的有限实数")
    result = float(value)
    if result <= 0.0:
        raise ValueError(f"{name} 必须是正的有限实数")
    return result


def _finite_array(name: str, value: Array, shape: tuple[int, ...]) -> Array:
    """对外部数组做严格 shape/实数检查，并保存独立的只读快照。"""
    raw = np.asarray(value)
    if raw.shape != shape:
        raise ValueError(f"{name} 必须是 shape={shape}")
    if raw.dtype.kind not in "iuf":
        raise TypeError(f"{name} 必须是实数数组")
    if not np.isfinite(raw).all():
        raise FloatingPointError(f"{name} 包含 NaN 或无穷大")
    snapshot = np.array(raw, dtype=float, copy=True)
    snapshot.setflags(write=False)
    return snapshot


@dataclass(frozen=True, slots=True)
class CascadeZohStateSpace:
    """保存自选连续串联坐标及由同一模型派生的离散 SISO 矩阵。"""

    F: Array
    G: Array
    H: Array
    J: Array
    A_p: Array
    B_p: Array
    C_p: Array
    D_p: Array

    def __post_init__(self) -> None:
        for name, shape in (
            ("F", (4, 4)),
            ("G", (4, 1)),
            ("H", (1, 4)),
            ("J", (1, 1)),
            ("A_p", (4, 4)),
            ("B_p", (4, 1)),
            ("C_p", (1, 4)),
            ("D_p", (1, 1)),
        ):
            object.__setattr__(self, name, _finite_array(name, getattr(self, name), shape))


def build_cascade_zoh_state_space(
    alpha: float, sample_period_seconds: float
) -> CascadeZohStateSpace:
    """按四个单位静态增益一阶环节串联，再以输入零阶保持精确离散化。

    ``x_i`` 是第 ``i`` 级的输出；该 realization 对零初态输入的传递函数
    正好是 [38] Eq. (2)。作者没有公布原例的状态坐标，所以这里的矩阵不能
    称为作者所用 ``A_p/B_p/C_p``。
    """
    a = _positive_finite("alpha", alpha)
    period = _positive_finite("sample_period_seconds", sample_period_seconds)
    try:
        powers = (a, a**2, a**3)
    except OverflowError as error:
        raise FloatingPointError("alpha 的幂超出有限浮点范围") from error
    if any(power == 0.0 or not isfinite(power) for power in powers):
        raise FloatingPointError("alpha 的幂超出有限浮点范围")
    rates = np.array([1.0, *(1.0 / power for power in powers)], dtype=float)
    if not np.isfinite(rates).all():
        raise FloatingPointError("串联对象速率溢出")
    F = np.diag(-rates)
    F[1, 0], F[2, 1], F[3, 2] = rates[1:]
    G = np.array([[1.0], [0.0], [0.0], [0.0]], dtype=float)
    H = np.array([[0.0, 0.0, 0.0, 1.0]], dtype=float)
    J = np.zeros((1, 1), dtype=float)
    A_p, B_p, C_p, D_p, _ = cont2discrete((F, G, H, J), period, method="zoh")
    return CascadeZohStateSpace(F, G, H, J, A_p, B_p, C_p, D_p)


class PaperPidCascadePlant:
    """在自选四级状态坐标中推进对象，不解释 PID 或安全协议。"""

    def __init__(
        self, alpha: float, sample_period_seconds: float, initial_state: Array
    ) -> None:
        """用只读模型与独立状态建立一次明文 plant 运行。"""
        self._state_space = build_cascade_zoh_state_space(alpha, sample_period_seconds)
        self._initial_state = _finite_array("initial_state", initial_state, (4,))
        self._state = self._initial_state.copy()

    @property
    def state_space(self) -> CascadeZohStateSpace:
        """返回独立矩阵快照，避免外部改写运行中的动力学。"""
        m = self._state_space
        return CascadeZohStateSpace(m.F, m.G, m.H, m.J, m.A_p, m.B_p, m.C_p, m.D_p)

    @property
    def state(self) -> Array:
        """返回当前四级输出的只读副本。"""
        snapshot = self._state.copy()
        snapshot.setflags(write=False)
        return snapshot

    def output(self) -> Array:
        """以 shape=(1,) 返回更新前对象输出 ``y(k)=C_p x_p(k)``。"""
        return np.asarray(self._state_space.C_p @ self._state, dtype=float)

    def step(self, control: Array) -> Array:
        """把 shape=(1,) 的未裁剪控制量保持一采样期后提交下一状态。"""
        u = _finite_array("control", control, (1,))
        m = self._state_space
        with np.errstate(over="raise", invalid="raise"):
            next_state = m.A_p @ self._state + m.B_p[:, 0] * u[0]
        if not np.isfinite(next_state).all():
            raise FloatingPointError("对象状态更新产生 NaN 或无穷大")
        self._state = np.array(next_state, dtype=float, copy=True)
        return self.output()

    def reset(self) -> None:
        """恢复本次配置的四维初态。"""
        self._state = self._initial_state.copy()
