"""倒立摆零目标观测映射及施加力裁剪。"""

from __future__ import annotations

from typing import Any

import numpy as np

from secure_control.simulation import ChannelMetadata, ScenarioMetadata

from .contract import CartPoleContract
from .controller import CartPoleBalanceConfig
from .plant import CONTROL_NAMES, CONTROL_UNITS, OUTPUT_NAMES, OUTPUT_UNITS


def _finite_vector(value: Any, size: int, name: str) -> np.ndarray:
    """拒绝错误 shape、非实数和非有限信号，并隔离调用者缓冲区。"""
    raw = np.asarray(value)
    if raw.shape != (size,):
        raise ValueError(f"{name} 必须是 shape=({size},)")
    if raw.dtype.kind not in "iuf":
        raise TypeError(f"{name} 必须是实数向量")
    if not np.isfinite(raw).all():
        raise FloatingPointError(f"{name} 包含 NaN 或无穷大")
    converted = np.array(raw, dtype=np.float64, copy=True)
    if not np.isfinite(converted).all():
        raise FloatingPointError(f"{name} 转换后不是有限实数")
    return converted


class CartPoleAdapter:
    """保持 #90 SI 通道；在场景执行器边界对 raw 力作对称限幅。"""

    def __init__(self, plant: CartPoleContract, config: CartPoleBalanceConfig) -> None:
        """目标和执行器界分别来自本期与 #90 的唯一配置来源。"""
        if not isinstance(plant, CartPoleContract) or not isinstance(config, CartPoleBalanceConfig):
            raise TypeError("plant/config 类型无效")
        config.validate_plant(plant)
        self._target = np.array(config.target_state, dtype=np.float64)
        self._max_force = plant.max_applied_force_n
        self.metadata = ScenarioMetadata(
            "cart_pole",
            ChannelMetadata(OUTPUT_NAMES, OUTPUT_UNITS),
            ChannelMetadata(OUTPUT_NAMES, OUTPUT_UNITS),
            ChannelMetadata(CONTROL_NAMES, CONTROL_UNITS),
        )

    def reference_at(self, time: float) -> np.ndarray:
        """返回与当前理想观测同顺序、同单位的固定直立中央目标。"""
        if isinstance(time, bool) or not isinstance(time, (int, float, np.integer, np.floating)):
            raise TypeError("time 必须是有限实数秒")
        if not np.isfinite(time):
            raise FloatingPointError("time 不是有限实数秒")
        return self._target.copy()

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """LQR 输入 v=y−r；#90 正角向左，D=−K 给出恢复方向。"""
        target = _finite_vector(reference, 4, "reference")
        measured = _finite_vector(output, 4, "output")
        return measured - target

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        """先验证 raw 力，再只在 actuator 边界裁到 #90 的 ±F_max。"""
        raw = _finite_vector(raw_control, 1, "raw_control")
        return np.clip(raw, -self._max_force, self._max_force)
