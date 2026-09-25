"""Johansson 四水箱连续线性化与本项目 ZOH 离散明文 plant。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from numpy.typing import NDArray
from scipy.linalg import expm

from .contract import QuadrupleTankContract

Array = NDArray[Any]


def _finite_vector(value: Any, size: int, name: str) -> np.ndarray:
    """拒绝错误通道或非有限信号，并复制以隔离调用者的缓冲区。"""
    raw = np.asarray(value)
    if raw.shape != (size,):
        raise ValueError(f"{name} 必须是 shape=({size},)")
    if raw.dtype.kind not in "iuf":
        raise TypeError(f"{name} 必须是实数向量")
    if not np.isfinite(raw).all():
        raise FloatingPointError(f"{name} 包含 NaN 或无穷大")
    result = np.array(raw, dtype=float, copy=True)
    if not np.isfinite(result).all():
        raise FloatingPointError(f"{name} 转换后包含无穷大")
    return result


def _matrix(value: Array, shape: tuple[int, int], name: str) -> Array:
    """复制矩阵以防止外部数组修改内部模型。"""
    result = np.array(value, dtype=float, copy=True)
    if result.shape != shape or not np.isfinite(result).all():
        raise ValueError(f"{name} 必须是有限的 {shape} 矩阵")
    result.setflags(write=False)
    return result


@dataclass(frozen=True, slots=True)
class QuadrupleTankStateSpace:
    """冻结连续 F/G/C 与离散 Aₚ/Bₚ/Cₚ/Dₚ 的矩阵快照。"""

    F: Array
    G: Array
    C: Array
    A_p: Array
    B_p: Array
    C_p: Array
    D_p: Array

    def __post_init__(self) -> None:
        for name, shape in (
            ("F", (4, 4)), ("G", (4, 2)), ("C", (2, 4)),
            ("A_p", (4, 4)), ("B_p", (4, 2)),
            ("C_p", (2, 4)), ("D_p", (2, 2)),
        ):
            object.__setattr__(self, name, _matrix(getattr(self, name), shape, name))


def build_quadruple_tank_state_space(contract: QuadrupleTankContract) -> QuadrupleTankStateSpace:
    """由 Johansson 式 (2)–(3) 构造模型，以增广指数执行 0.5 s ZOH。

    x=h−h⁰ (cm)、u=v−v⁰ (V)、y=k_c(x₁,x₂) (V)；ZOH 为本项目选择。
    """
    if not isinstance(contract, QuadrupleTankContract):
        raise TypeError("contract 必须是 QuadrupleTankContract")
    area = np.asarray(contract.tank_cross_sections_cm2)
    outlet = np.asarray(contract.outlet_cross_sections_cm2)
    height = np.asarray(contract.heights_cm)
    pump = np.asarray(contract.pump_flow_coefficients_cm3_per_v_s)
    gamma = np.asarray(contract.valve_fractions)
    with np.errstate(over="raise", divide="raise", invalid="raise"):
        # Johansson 式 (3)：几何与工作点决定四个排水时间常数。
        time_constants = area / outlet * np.sqrt(2 * height / contract.gravity_cm_per_s2)
        F = np.diag(-1 / time_constants)
        F[0, 2] = area[2] / (area[0] * time_constants[2])
        F[1, 3] = area[3] / (area[1] * time_constants[3])
        G = np.array([
            [gamma[0] * pump[0] / area[0], 0],
            [0, gamma[1] * pump[1] / area[1]],
            [0, (1 - gamma[1]) * pump[1] / area[2]],
            [(1 - gamma[0]) * pump[0] / area[3], 0],
        ])
        C = np.array([
            [contract.sensor_gain_v_per_cm, 0, 0, 0],
            [0, contract.sensor_gain_v_per_cm, 0, 0],
        ])
        augmented = np.zeros((6, 6))
        augmented[:4, :4] = F
        augmented[:4, 4:] = G
        discrete = expm(augmented * contract.sample_period_seconds)
    return QuadrupleTankStateSpace(
        F, G, C, discrete[:4, :4], discrete[:4, 4:], C, np.zeros((2, 2))
    )


class QuadrupleTankPlant:
    """推进四维高度偏差状态；每个实例拥有自己的明文状态。"""

    def __init__(self, contract: QuadrupleTankContract) -> None:
        """从已验证契约生成矩阵，并复制论文初态。"""
        self._state_space = build_quadruple_tank_state_space(contract)
        self._initial_state = _finite_vector(contract.initial_state_deviation_cm, 4, "initial_state")
        self._state = self._initial_state.copy()

    @property
    def state_space(self) -> QuadrupleTankStateSpace:
        """返回独立只读矩阵副本，避免调用者篡改内部动力学。"""
        m = self._state_space
        return QuadrupleTankStateSpace(m.F, m.G, m.C, m.A_p, m.B_p, m.C_p, m.D_p)

    @property
    def state(self) -> Array:
        """返回不可共享的状态快照，单位 cm。"""
        snapshot = self._state.copy()
        snapshot.setflags(write=False)
        return snapshot

    def output(self) -> Array:
        """返回当前更新前的两路测量偏差，单位 V。"""
        return np.array(self._state_space.C_p @ self._state, copy=True)

    def step(self, control: Array) -> Array:
        """保持两路泵电压偏差一采样期，成功后才提交下一状态。"""
        u = _finite_vector(control, 2, "control")
        m = self._state_space
        with np.errstate(over="raise", invalid="raise"):
            next_state = m.A_p @ self._state + m.B_p @ u
        if not np.isfinite(next_state).all():
            raise FloatingPointError("对象状态更新产生 NaN 或无穷大")
        self._state = np.array(next_state, copy=True)
        return self.output()

    def reset(self) -> None:
        """恢复同一初态，不更换矩阵或共享其他实例状态。"""
        self._state = self._initial_state.copy()
