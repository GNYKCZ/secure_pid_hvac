"""四水箱测量与泵输入映射；reference 仅为未使用的零占位。"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from secure_control.simulation import ChannelMetadata, ScenarioMetadata

from .plant import _finite_vector


class QuadrupleTankAdapter:
    """直接传递测量与电压偏差，不引入误差计算或执行器裁剪。"""

    def __init__(self) -> None:
        """标注两路信号的物理单位及零 reference 的占位性质。"""
        self.metadata = ScenarioMetadata(
            "quadruple_tank",
            ChannelMetadata(("unused_zero_1", "unused_zero_2"), ("dimensionless",) * 2),
            ChannelMetadata(("y1", "y2"), ("V_deviation",) * 2),
            ChannelMetadata(("u1", "u2"), ("V_deviation",) * 2),
        )

    def reference_at(self, time: float) -> NDArray[np.float64]:
        """返回未使用的零占位；论文没有给出目标阶跃。"""
        if not isinstance(time, (int, float, np.integer, np.floating)) or not np.isfinite(time):
            raise ValueError("time 必须是有限实数")
        return np.zeros(2, dtype=float)

    def controller_input(self, reference: NDArray, output: NDArray) -> NDArray[np.float64]:
        """检查占位通道，并将两路测量偏差直接送往未来 observer。"""
        _finite_vector(reference, 2, "reference")
        return _finite_vector(output, 2, "output")

    def apply_control(self, raw_control: NDArray) -> NDArray[np.float64]:
        """复制两路泵电压偏差，不借用 HVAC 的裁剪策略。"""
        return _finite_vector(raw_control, 2, "raw_control")
