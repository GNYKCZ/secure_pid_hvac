"""HVAC 一阶 RC 与二阶 2R2C 冷却对象的确定性离散时间实现。"""

from __future__ import annotations

from dataclasses import dataclass
from math import exp, isfinite
from numbers import Integral
from typing import Any

import numpy as np
from numpy.typing import NDArray
from scipy.linalg import expm

from .contract import (
    Hvac2R2CModelContract,
    HvacModelContract,
    HvacPlantModelContract,
    HvacScenarioContract,
)

Array = NDArray[Any]


def _readonly_matrix(name: str, value: Array, shape: tuple[int, int]) -> Array:
    """复制并冻结有限浮点矩阵，避免外部改写已审查的热模型系数。"""
    matrix = np.array(value, dtype=float, copy=True)
    if matrix.shape != shape:
        raise ValueError(f"{name} 必须是 shape 为 {shape} 的矩阵")
    if not np.isfinite(matrix).all():
        raise FloatingPointError(f"{name} 包含 NaN 或无穷大")
    matrix.setflags(write=False)
    return matrix


@dataclass(frozen=True, slots=True)
class Hvac2R2CStateSpace:
    """保存 2R2C 连续矩阵及由同一模型 exact ZOH 得到的离散矩阵。"""

    F: Array
    G: Array
    H: Array
    A_p: Array
    B_p: Array
    E_p: Array
    C_p: Array

    def __post_init__(self) -> None:
        for name, shape in (
            ("F", (2, 2)),
            ("G", (2, 1)),
            ("H", (2, 1)),
            ("A_p", (2, 2)),
            ("B_p", (2, 1)),
            ("E_p", (2, 1)),
            ("C_p", (1, 2)),
        ):
            object.__setattr__(self, name, _readonly_matrix(name, getattr(self, name), shape))


def build_hvac_2r2c_state_space(
    model: Hvac2R2CModelContract,
    sample_period_seconds: int,
) -> Hvac2R2CStateSpace:
    """构造连续 2R2C 模型，并用增广矩阵指数执行 exact zero-order hold。

    状态顺序固定为 ``[T_air, T_wall]``，输入 ``u>0`` 表示制冷，扰动为常值
    ``T_ambient``。增广矩阵同时离散化 ``G`` 与 ``H``，避免对可能病态或奇异的
    ``F`` 求逆；所有 R/C 单位使时间常数为秒，与采样周期一致。
    """
    if not isinstance(model, Hvac2R2CModelContract):
        raise TypeError("model 必须是 Hvac2R2CModelContract")
    if isinstance(sample_period_seconds, bool) or not isinstance(sample_period_seconds, Integral):
        raise TypeError("sample_period_seconds 必须是整数秒")
    if sample_period_seconds <= 0:
        raise ValueError("sample_period_seconds 必须为正整数秒")

    resistance_air_wall = model.air_wall_thermal_resistance_celsius_per_kw
    resistance_wall_outdoor = model.wall_outdoor_thermal_resistance_celsius_per_kw
    capacitance_air = model.air_thermal_capacitance_kj_per_celsius
    capacitance_wall = model.wall_thermal_capacitance_kj_per_celsius

    # 该连续模型严格对应 Issue #41 冻结方程，不含内部热源、天气动态或其他未授权项。
    F = np.array(
        [
            [
                -1.0 / (capacitance_air * resistance_air_wall),
                1.0 / (capacitance_air * resistance_air_wall),
            ],
            [
                1.0 / (capacitance_wall * resistance_air_wall),
                -(1.0 / resistance_air_wall + 1.0 / resistance_wall_outdoor) / capacitance_wall,
            ],
        ],
        dtype=float,
    )
    G = np.array([[-model.cooling_coefficient / capacitance_air], [0.0]], dtype=float)
    H = np.array([[0.0], [1.0 / (capacitance_wall * resistance_wall_outdoor)]], dtype=float)

    augmented = np.zeros((4, 4), dtype=float)
    augmented[:2, :2] = F
    augmented[:2, 2:3] = G
    augmented[:2, 3:4] = H
    discrete = expm(augmented * int(sample_period_seconds))
    if not np.isfinite(discrete).all():
        raise FloatingPointError("2R2C exact ZOH 矩阵指数产生 NaN 或无穷大")
    return Hvac2R2CStateSpace(
        F=F,
        G=G,
        H=H,
        A_p=discrete[:2, :2],
        B_p=discrete[:2, 2:3],
        E_p=discrete[:2, 3:4],
        C_p=np.array([[1.0, 0.0]], dtype=float),
    )


class HvacPlant:
    """按 HVAC 场景契约推进一个标量温度状态。

    对当前温度 ``T(k)`` 和冷却功率 ``u(k)``，本对象采用 #2 冻结的 ZOH 递推：
    ``T(k+1) = a*T(k) + (1-a)*T_ambient - eta*R*(1-a)*u(k)``，其中
    ``a = exp(-Ts/(R*C))``。正 ``u`` 表示冷却，所以输入项带负号。

    本对象不执行 PID、饱和或闭环循环。配置范围以外的控制量会明确失败，而非静默裁剪；
    这样后续控制器可在一致的位置显式组合自己的 actuator 语义。
    """

    def __init__(self, contract: HvacScenarioContract) -> None:
        """从不可变场景契约复制 HVAC 的初温和离散模型系数。"""
        if not isinstance(contract, HvacScenarioContract):
            raise TypeError("contract 必须是 HvacScenarioContract")

        self._contract = contract
        model = contract.model
        if not isinstance(model, HvacModelContract):
            raise TypeError("HvacPlant 只接受一阶 HvacModelContract")
        # R*C 的单位为秒，与 sampling_period_seconds 相同，因此指数项无量纲。
        self._state_coefficient = exp(
            -contract.timing.sampling_period_seconds
            / (model.thermal_resistance_celsius_per_kw * model.thermal_capacitance_kj_per_celsius)
        )
        self._control_coefficient = (
            model.cooling_coefficient
            * model.thermal_resistance_celsius_per_kw
            * (1.0 - self._state_coefficient)
        )
        self._temperature_celsius = model.initial_temperature_celsius

    @property
    def temperature_celsius(self) -> float:
        """返回当前标量温度状态；修改状态只能通过 ``step`` 或 ``reset``。"""
        return self._temperature_celsius

    def output(self) -> Array:
        """以通用仿真契约要求的单通道扁平数组 ``(1,)`` 返回当前温度。"""
        return np.array([self._temperature_celsius], dtype=float)

    def reset(self) -> None:
        """将温度恢复为配置中冻结的初始温度。"""
        self._temperature_celsius = self._contract.model.initial_temperature_celsius

    def step(self, control: Array | float) -> Array:
        """用一个时间步的冷却功率推进 plant，并返回更新后的温度输出。"""
        cooling_power_kw = _coerce_control(control, self._contract.model)
        model = self._contract.model
        next_temperature = (
            self._state_coefficient * self._temperature_celsius
            + (1.0 - self._state_coefficient) * model.ambient_temperature_celsius
            - self._control_coefficient * cooling_power_kw
        )
        if not isfinite(next_temperature):
            raise FloatingPointError("HVAC 状态更新产生 NaN 或无穷大")

        # 只在全部计算成功后写入状态，避免非法输入留下半完成的 plant 状态。
        self._temperature_celsius = next_temperature
        return self.output()


class Hvac2R2CPlant:
    """推进 ``[T_air, T_wall]`` 二状态，同时只向通用边界观测 ``T_air``。"""

    def __init__(self, contract: HvacScenarioContract) -> None:
        """从 2R2C 场景契约建立 exact-ZOH 矩阵和独立的二维初始状态。"""
        if not isinstance(contract, HvacScenarioContract):
            raise TypeError("contract 必须是 HvacScenarioContract")
        model = contract.model
        if not isinstance(model, Hvac2R2CModelContract):
            raise TypeError("Hvac2R2CPlant 只接受 Hvac2R2CModelContract")
        self._contract = contract
        self._state_space = build_hvac_2r2c_state_space(
            model, contract.timing.sampling_period_seconds
        )
        self._initial_state = np.array(
            [model.initial_air_temperature_celsius, model.initial_wall_temperature_celsius],
            dtype=float,
        )
        self._initial_state.setflags(write=False)
        self._state = self._initial_state.copy()

    @property
    def state_space(self) -> Hvac2R2CStateSpace:
        """返回只含只读矩阵的连续/离散状态空间记录。"""
        return self._state_space

    @property
    def state_celsius(self) -> Array:
        """返回只读二维状态副本，外部不能反向修改 plant 内部状态。"""
        snapshot = self._state.copy()
        snapshot.setflags(write=False)
        return snapshot

    @property
    def air_temperature_celsius(self) -> float:
        """返回当前空气温度；这是默认 HVAC measurement。"""
        return float(self._state[0])

    @property
    def wall_temperature_celsius(self) -> float:
        """返回当前墙体温度；该状态只由 HVAC 场景拥有。"""
        return float(self._state[1])

    def output(self) -> Array:
        """按 ``C_p=[1,0]`` 返回 shape ``(1,)`` 的空气温度副本。"""
        return np.asarray(self._state_space.C_p @ self._state, dtype=float)

    def reset(self) -> None:
        """将空气和墙体温度一起恢复到配置冻结的初始状态。"""
        self._state = self._initial_state.copy()

    def step(self, control: Array | float) -> Array:
        """施加一个采样周期的常值制冷功率并事务式更新二维状态。"""
        model = self._contract.model
        if not isinstance(model, Hvac2R2CModelContract):
            raise TypeError("Hvac2R2CPlant 的内部 model 类型无效")
        cooling_power_kw = _coerce_control(control, model)
        matrices = self._state_space
        next_state = (
            matrices.A_p @ self._state
            + matrices.B_p[:, 0] * cooling_power_kw
            + matrices.E_p[:, 0] * model.ambient_temperature_celsius
        )
        if not np.isfinite(next_state).all():
            raise FloatingPointError("HVAC 2R2C 状态更新产生 NaN 或无穷大")

        # 只有完整二维结果通过校验后才提交，失败 step 不得留下部分状态漂移。
        self._state = np.asarray(next_state, dtype=float)
        return self.output()


def _coerce_control(control: Array | float, model: HvacPlantModelContract) -> float:
    """校验两种 HVAC plant 共用的 SISO 控制 shape、有限性和配置范围。"""
    value = np.asarray(control)
    if value.ndim == 0:
        value = value.reshape(1)
    if value.shape != (1,):
        raise ValueError("HVAC control 必须是标量或 shape 为 (1,) 的单通道数组")
    if value.dtype.kind not in "iuf":
        raise TypeError("HVAC control 必须是实数")
    cooling_power_kw = float(value[0])
    if not isfinite(cooling_power_kw):
        raise FloatingPointError("HVAC control 包含 NaN 或无穷大")
    if not model.lower_control_bound_kw <= cooling_power_kw <= model.upper_control_bound_kw:
        raise ValueError(
            "HVAC control 超出配置的冷却功率范围 "
            f"[{model.lower_control_bound_kw}, {model.upper_control_bound_kw}] kW"
        )
    return cooling_power_kw
