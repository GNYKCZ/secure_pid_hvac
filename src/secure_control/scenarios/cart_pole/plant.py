"""CTMS 单杆小车倒立摆非线性方程与固定步长 RK4 对象。"""

from __future__ import annotations

from typing import Any

import numpy as np
from numpy.typing import NDArray

from .contract import CartPoleContract

Array = NDArray[Any]

STATE_NAMES = ("p", "p_dot", "theta", "theta_dot")
STATE_UNITS = ("m", "m/s", "rad", "rad/s")
OUTPUT_NAMES = STATE_NAMES
OUTPUT_UNITS = STATE_UNITS
CONTROL_NAMES = ("applied_force",)
CONTROL_UNITS = ("N",)


class CartPolePlant:
    """每个实例独立持有四维状态；step 成功时才提交整个采样步。"""

    def __init__(self, contract: CartPoleContract) -> None:
        """使用已校验的参数快照和初态，不在源码复制物理数值。"""
        if not isinstance(contract, CartPoleContract):
            raise TypeError("contract 必须是 CartPoleContract")
        self._contract = contract
        self._initial_state = np.array(contract.initial_state, dtype=float)
        self._state = self._initial_state.copy()

    @property
    def state(self) -> Array:
        """返回不可共享、只读的 SI 状态快照。"""
        snapshot = self._state.copy()
        snapshot.setflags(write=False)
        return snapshot

    def output(self) -> Array:
        """返回当前时刻的理想全状态观测，顺序同 STATE_NAMES。"""
        return self._state.copy()

    def _checked_state(self, state: Array) -> None:
        """各 RK4 阶段都检查有限值和离散轨道界。"""
        if not np.isfinite(state).all():
            raise FloatingPointError("倒立摆状态包含 NaN 或无穷大")
        if abs(state[0]) > self._contract.track_center_limit_m:
            raise ValueError(
                f"p 超出 track_center_limit_m={self._contract.track_center_limit_m} m"
            )

    def _rhs(self, state: Array, force: float) -> Array:
        """由 CTMS 非线性双式解加速度；theta=0 是直立、正向左偏。"""
        self._checked_state(state)
        c = self._contract
        _, velocity, theta, omega = state
        m_l = c.pole_mass_kg * c.com_length_m
        j = c.pole_inertia_kg_m2 + m_l * c.com_length_m
        coupling = -m_l * np.cos(theta)
        determinant = (c.cart_mass_kg + c.pole_mass_kg) * j - coupling**2
        if not np.isfinite(determinant) or determinant <= 0:
            raise FloatingPointError("倒立摆质量矩阵行列式无效")
        cart_rhs = force - c.cart_friction_n_s_per_m * velocity - m_l * omega**2 * np.sin(theta)
        pole_rhs = m_l * c.gravity_m_per_s2 * np.sin(theta)
        p_ddot = (j * cart_rhs - coupling * pole_rhs) / determinant
        theta_ddot = ((c.cart_mass_kg + c.pole_mass_kg) * pole_rhs - coupling * cart_rhs) / determinant
        derivative = np.array([velocity, p_ddot, omega, theta_ddot])
        if not np.isfinite(derivative).all():
            raise FloatingPointError("倒立摆加速度包含 NaN 或无穷大")
        return derivative

    def step(self, control: Array) -> Array:
        """将实际力在 [t_k,t_{k+1}) 零阶保持，配置数量的 RK4 子步后原子提交。"""
        raw = np.asarray(control)
        if raw.shape != (1,):
            raise ValueError("control 必须是 shape=(1,) 的力向量 [N]")
        if raw.dtype.kind not in "iuf":
            raise TypeError("control 必须是实数力向量 [N]")
        if not np.isfinite(raw).all():
            raise FloatingPointError("control 包含 NaN 或无穷大 [N]")
        force = float(raw[0])
        if not np.isfinite(force):
            raise FloatingPointError("control 转换后不是有限力 [N]")
        if abs(force) > self._contract.max_applied_force_n:
            raise ValueError(
                f"control 超出 max_applied_force_n={self._contract.max_applied_force_n} N"
            )
        self._checked_state(self._state)
        h = self._contract.sample_period_s / self._contract.rk4_substeps
        candidate = self._state.copy()
        with np.errstate(over="raise", invalid="raise", divide="raise"):
            for _ in range(self._contract.rk4_substeps):
                k1 = self._rhs(candidate, force)
                k2 = self._rhs(candidate + 0.5 * h * k1, force)
                k3 = self._rhs(candidate + 0.5 * h * k2, force)
                k4 = self._rhs(candidate + h * k3, force)
                candidate = candidate + (h / 6.0) * (k1 + 2 * k2 + 2 * k3 + k4)
                self._checked_state(candidate)
        self._state = candidate
        return self.output()

    def reset(self) -> None:
        """恢复配置初态，不修改其他 plant 实例。"""
        self._state = self._initial_state.copy()
