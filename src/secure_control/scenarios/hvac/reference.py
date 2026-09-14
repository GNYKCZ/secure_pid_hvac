"""HVAC 左闭右开阶跃温度参考的场景实现。"""

from __future__ import annotations

from math import isfinite
from numbers import Real
from typing import Any

import numpy as np
from numpy.typing import NDArray

from .contract import HvacScenarioContract

Array = NDArray[Any]


class HvacStepReference:
    """根据 #2 配置的左闭右开区间返回单通道目标温度。"""

    def __init__(self, contract: HvacScenarioContract) -> None:
        """持有不可变 reference segments；reference 查询不会改变任何状态。"""
        if not isinstance(contract, HvacScenarioContract):
            raise TypeError("contract 必须是 HvacScenarioContract")
        self._contract = contract

    def reference_at(self, time_seconds: float) -> Array:
        """返回时刻 ``t`` 的目标温度数组 ``(1,)``，并显式处理 horizon 端点。"""
        time_value = self._coerce_time(time_seconds)
        horizon = self._contract.timing.horizon_seconds
        if time_value == horizon:
            # 默认日志不记录终点，但 reference API 仍把 t=horizon 定义为最后一个目标值。
            return np.array([self._contract.endpoint_reference_celsius], dtype=float)

        for segment in self._contract.reference_segments:
            if segment.start_seconds <= time_value < segment.end_seconds:
                return np.array([segment.target_temperature_celsius], dtype=float)
        raise RuntimeError("HVAC reference 区间与时间契约不一致")

    def _coerce_time(self, time_seconds: float) -> float:
        """拒绝布尔、非实数、非有限或超出 ``[0, horizon]`` 的 reference 查询。"""
        if isinstance(time_seconds, bool) or not isinstance(time_seconds, Real):
            raise TypeError("HVAC reference 时间必须是实数秒")
        time_value = float(time_seconds)
        if not isfinite(time_value):
            raise ValueError("HVAC reference 时间必须是有限实数")
        if not 0.0 <= time_value <= self._contract.timing.horizon_seconds:
            raise ValueError("HVAC reference 时间必须位于 [0, horizon_seconds]")
        return time_value
