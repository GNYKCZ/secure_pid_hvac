"""HVAC reference/output 到通用 controller input 的场景专属映射。"""

from __future__ import annotations

from math import isfinite
from typing import Any

import numpy as np
from numpy.typing import NDArray

from secure_control.simulation import ScenarioMetadata

from .contract import HvacScenarioContract
from .reference import HvacStepReference

Array = NDArray[Any]


class HvacSignalAdapter:
    """组合 HVAC reference 与 ``v = r - T`` 映射，满足通用 ScenarioAdapter 结构。"""

    def __init__(self, contract: HvacScenarioContract) -> None:
        """创建无状态的 signal adapter，并复用同一不可变场景 metadata。"""
        if not isinstance(contract, HvacScenarioContract):
            raise TypeError("contract 必须是 HvacScenarioContract")
        self.metadata: ScenarioMetadata = contract.metadata
        self._contract = contract
        self._reference = HvacStepReference(contract)

    def reference_at(self, time: float) -> Array:
        """返回场景 reference；实际分段边界由 ``HvacStepReference`` 统一维护。"""
        return self._reference.reference_at(time)

    def controller_input(self, reference: Array, output: Array) -> Array:
        """将 HVAC 温度目标和测量值映射为单通道误差 ``v = r - T``。"""
        reference_temperature = self._coerce_temperature_signal(reference, "reference")
        measured_temperature = self._coerce_temperature_signal(output, "output")
        # 该减法只存在于 HVAC scenario；通用 simulation engine 不得假定任意场景都有该公式。
        return np.array([reference_temperature - measured_temperature], dtype=float)

    def apply_control(self, raw_control: Array) -> Array:
        """按 HVAC actuator 配置在 plant 前裁剪 raw control，不改变 PID 内部递推。"""
        value = np.asarray(raw_control)
        if value.shape != (1,):
            raise ValueError("HVAC raw control 必须是 shape 为 (1,) 的单通道数组")
        if value.dtype.kind not in "iuf":
            raise TypeError("HVAC raw control 必须包含实数")
        if not np.isfinite(value).all():
            raise FloatingPointError("HVAC raw control 包含 NaN 或无穷大")
        model = self._contract.model
        return np.clip(
            value.astype(float),
            model.lower_control_bound_kw,
            model.upper_control_bound_kw,
        )

    @staticmethod
    def _coerce_temperature_signal(value: Array, name: str) -> float:
        """验证通用边界传入的是一个有限的单通道温度数组。"""
        signal = np.asarray(value)
        if signal.shape != (1,):
            raise ValueError(f"HVAC {name} 必须是 shape 为 (1,) 的温度数组")
        if signal.dtype.kind not in "iuf":
            raise TypeError(f"HVAC {name} 必须包含实数")
        temperature = float(signal[0])
        if not isfinite(temperature):
            raise FloatingPointError(f"HVAC {name} 包含 NaN 或无穷大")
        return temperature
