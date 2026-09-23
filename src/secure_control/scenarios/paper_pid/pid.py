"""论文 arXiv:2503.02176v3 §VII 的并联 PID 状态空间表示。"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Integral, Real

import numpy as np

from secure_control.core import ControllerSpec


@dataclass(frozen=True, slots=True)
class PaperPidDesign:
    """将论文 §VII 的 Kp/Ki/Kd、导数滤波参数 Nd 和采样秒数转换为通用控制器。

    输入 ``v(k)`` 是论文的 plant 输出 ``y(k)``，不是 HVAC 的参考误差。
    ``initial_state`` 使用论文矩阵的两个状态坐标，默认零初态；不在此处
    增加饱和、anti-windup 或场景专用的输入符号约定。
    """

    proportional_gain: float
    integral_gain: float
    derivative_gain: float
    derivative_filter_parameter: int
    sample_period_seconds: float
    initial_state: tuple[float, float] = (0.0, 0.0)

    def __post_init__(self) -> None:
        """在构造矩阵前拒绝布尔、非有限参数和不合法的滤波/时间值。"""
        for name in ("proportional_gain", "integral_gain", "derivative_gain"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
                raise ValueError(f"{name} 必须是有限实数")
        nd = self.derivative_filter_parameter
        if isinstance(nd, bool) or not isinstance(nd, Integral) or nd <= 0:
            raise ValueError("derivative_filter_parameter 必须是正整数")
        period = self.sample_period_seconds
        if isinstance(period, bool) or not isinstance(period, Real) or not isfinite(float(period)) or period <= 0:
            raise ValueError("sample_period_seconds 必须是正的有限秒数")
        if (
            not isinstance(self.initial_state, tuple)
            or len(self.initial_state) != 2
            or any(
                isinstance(value, bool)
                or not isinstance(value, Real)
                or not isfinite(float(value))
                for value in self.initial_state
            )
        ):
            raise ValueError("initial_state 必须是两个有限实数的元组")

    def to_controller_spec(self) -> ControllerSpec:
        """按论文 §VII 的 c1、c2、d 公式生成 A/B/C/D/x0，交给通用明文运行时。"""
        nd = self.derivative_filter_parameter
        ts = self.sample_period_seconds
        ki_ts = self.integral_gain * ts
        nd2_kd_over_ts = nd * nd * self.derivative_gain / ts
        nd_kd_over_ts = nd * self.derivative_gain / ts
        # C 的两个系数保留论文的滤波极点与积分极点贡献；D 是当前采样的直接通道。
        return ControllerSpec(
            A=np.array([[2 - nd, nd - 1], [1, 0]], dtype=float),
            B=np.array([[1], [0]], dtype=float),
            C=np.array(
                [[ki_ts - nd2_kd_over_ts, (nd - 1) * ki_ts + nd2_kd_over_ts]],
                dtype=float,
            ),
            D=np.array([[self.proportional_gain + nd_kd_over_ts]], dtype=float),
            x0=np.array(self.initial_state, dtype=float),
        )


def paper_sec_vii_controller_spec() -> ControllerSpec:
    """返回论文 §VII 印刷实例的权威矩阵，不用反推 gains 重新舍入系数。"""
    return ControllerSpec(
        A=np.array([[1.0, 0.0], [1.0, 0.0]], dtype=float),
        B=np.array([[1.0], [0.0]], dtype=float),
        C=np.array([[2.7368927, -2.96540833]], dtype=float),
        D=np.array([[-5.01071167]], dtype=float),
        x0=np.array([0.0, 0.0], dtype=float),
    )
