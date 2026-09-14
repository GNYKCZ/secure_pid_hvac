"""HVAC 一阶 RC 冷却对象的确定性离散时间实现。"""

from __future__ import annotations

from math import exp, isfinite
from typing import Any

import numpy as np
from numpy.typing import NDArray

from .contract import HvacScenarioContract

Array = NDArray[Any]


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
        cooling_power_kw = self._coerce_control(control)
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

    def _coerce_control(self, control: Array | float) -> float:
        """校验 HVAC SISO 控制输入的 shape、有限性和配置范围。"""
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

        model = self._contract.model
        if not model.lower_control_bound_kw <= cooling_power_kw <= model.upper_control_bound_kw:
            raise ValueError(
                "HVAC control 超出配置的冷却功率范围 "
                f"[{model.lower_control_bound_kw}, {model.upper_control_bound_kw}] kW"
            )
        return cooling_power_kw
