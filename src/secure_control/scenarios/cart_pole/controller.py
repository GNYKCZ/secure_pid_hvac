"""倒立摆平衡配置与原点附近的离散 LQR 静态反馈设计。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from scipy.linalg import solve_discrete_are
from scipy.signal import cont2discrete

from secure_control.core import ControllerSpec, check_discrete_schur_stability

from .contract import CartPoleContract, _number, _UniqueKeyLoader


def _four(value: Any, name: str, *, positive: bool = False) -> tuple[float, ...]:
    """四维 SI/权重向量不接受广播、布尔或非有限值。"""
    if not isinstance(value, (tuple, list)) or len(value) != 4:
        raise ValueError(f"{name} 必须是四维向量")
    return tuple(_number(item, f"{name}[{i}]", positive=positive) for i, item in enumerate(value))


@dataclass(frozen=True, slots=True)
class CartPoleBalanceConfig:
    """保存本项目自选 LQR 权重、固定零目标及运行判定阈值。"""

    q_state_weights: tuple[float, float, float, float]
    r_force_weight: float
    target_state: tuple[float, float, float, float]
    safe_abs: tuple[float, float, float, float]
    stable_abs: tuple[float, float, float, float]
    hold_observations: int
    horizon_steps: int

    def __post_init__(self) -> None:
        for name, positive in (
            ("q_state_weights", True), ("target_state", False),
            ("safe_abs", True), ("stable_abs", True),
        ):
            object.__setattr__(self, name, _four(getattr(self, name), name, positive=positive))
        object.__setattr__(self, "r_force_weight", _number(
            self.r_force_weight, "r_force_weight", positive=True
        ))
        for name in ("hold_observations", "horizon_steps"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} 必须是正整数")
        if any(value != 0 for value in self.target_state):
            raise ValueError("target_state 本期必须是直立中央的零状态")
        if any(stable >= safe for stable, safe in zip(self.stable_abs, self.safe_abs, strict=True)):
            raise ValueError("stable_abs 每项必须小于 safe_abs")

    def validate_plant(self, plant: CartPoleContract) -> None:
        """工作域小车位置必须严格处于 #90 物理轨道界内。"""
        if not isinstance(plant, CartPoleContract):
            raise TypeError("plant 必须是 CartPoleContract")
        if self.safe_abs[0] >= plant.track_center_limit_m:
            raise ValueError("safe_abs[0] 必须小于 track_center_limit_m")


def load_cart_pole_balance_config(path: str | Path, plant: CartPoleContract) -> CartPoleBalanceConfig:
    """严格加载唯一平衡配置，并与 #90 轨道界交叉验证。"""
    with Path(path).open(encoding="utf-8") as stream:
        root = yaml.load(stream, Loader=_UniqueKeyLoader)
    expected = {"schema_version", "scenario", *CartPoleBalanceConfig.__dataclass_fields__}
    if not isinstance(root, Mapping) or set(root) != expected:
        raise ValueError(f"平衡配置必须且仅能包含 {sorted(expected)}")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version 必须是 1")
    if root["scenario"] != "cart_pole":
        raise ValueError("scenario 必须是 cart_pole")
    config = CartPoleBalanceConfig(**{
        name: root[name] for name in CartPoleBalanceConfig.__dataclass_fields__
    })
    config.validate_plant(plant)
    return config


def _linearized_model(plant: CartPoleContract) -> tuple[np.ndarray, np.ndarray]:
    """对 #90 直立零态非线性双式求解析 Jacobian，不近似生产 plant。"""
    mass = plant.cart_mass_kg
    pole = plant.pole_mass_kg
    length = plant.com_length_m
    inertia = plant.pole_inertia_kg_m2 + pole * length**2
    coupling = pole * length
    delta = (mass + pole) * inertia - coupling**2
    with np.errstate(over="raise", divide="raise", invalid="raise"):
        a = np.array([
            [0, 1, 0, 0],
            [0, -plant.cart_friction_n_s_per_m * inertia / delta,
             pole**2 * plant.gravity_m_per_s2 * length**2 / delta, 0],
            [0, 0, 0, 1],
            [0, -plant.cart_friction_n_s_per_m * coupling / delta,
             (mass + pole) * pole * plant.gravity_m_per_s2 * length / delta, 0],
        ], dtype=np.float64)
        b = np.array([[0], [inertia / delta], [0], [coupling / delta]], dtype=np.float64)
    if delta <= 0 or not np.isfinite(a).all() or not np.isfinite(b).all():
        raise FloatingPointError("倒立摆原点线性化矩阵无效")
    return a, b


def build_cart_pole_controller_spec(
    plant: CartPoleContract, config: CartPoleBalanceConfig
) -> ControllerSpec:
    """从 #90 参数与本期 Q/R 重算 ZOH/DARE，返回零维状态反馈规格。"""
    if not isinstance(plant, CartPoleContract) or not isinstance(config, CartPoleBalanceConfig):
        raise TypeError("plant/config 类型无效")
    config.validate_plant(plant)
    a_c, b_c = _linearized_model(plant)
    a_d, b_d, _, _, _ = cont2discrete(
        (a_c, b_c, np.eye(4), np.zeros((4, 1))), plant.sample_period_s, method="zoh"
    )
    if not np.isfinite(a_d).all() or not np.isfinite(b_d).all():
        raise FloatingPointError("ZOH 离散矩阵无效")
    controllability = np.column_stack([np.linalg.matrix_power(a_d, i) @ b_d for i in range(4)])
    if np.linalg.matrix_rank(controllability) != 4:
        raise ValueError("原点线性化离散模型不可控")
    q = np.diag(config.q_state_weights)
    r = np.array([[config.r_force_weight]])
    p = solve_discrete_are(a_d, b_d, q, r)
    if not np.isfinite(p).all():
        raise FloatingPointError("DARE 解无效")
    gain = np.linalg.solve(r + b_d.T @ p @ b_d, b_d.T @ p @ a_d)
    residual = a_d.T @ p @ a_d - p - a_d.T @ p @ b_d @ gain + q
    if not np.isfinite(gain).all() or np.linalg.norm(residual) > 1e-9 * max(1., np.linalg.norm(p)):
        raise FloatingPointError("DARE 残差或反馈增益无效")
    stability = check_discrete_schur_stability(a_d - b_d @ gain)
    if stability.status != "stable":
        raise ValueError(f"原点无饱和线性闭环未被数值确认为稳定: {stability.status}")
    # 静态全状态反馈不虚构 controller state；输入为 y−r，输出 raw 力为 −K(y−r)。
    return ControllerSpec(
        A=np.empty((0, 0), dtype=np.float64),
        B=np.empty((0, 4), dtype=np.float64),
        C=np.empty((1, 0), dtype=np.float64),
        D=np.array(-gain, dtype=np.float64),
        x0=np.empty(0, dtype=np.float64),
    )
