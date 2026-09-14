"""HVAC 位置式 PID 设计及其到通用状态空间规格的转换。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from numbers import Integral, Real
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from secure_control.core import ControllerSpec

from .contract import HvacScenarioContract


@dataclass(frozen=True, slots=True)
class HvacPidDesign:
    """HVAC 冷却场景的位置式 PID 参数、初态和已冻结的闭环策略。"""

    proportional_gain_kw_per_celsius: float
    integral_gain_kw_per_celsius_second: float
    derivative_gain_kw_second_per_celsius: float
    sample_period_seconds: int
    initial_integral_error_celsius_seconds: float
    initial_previous_error_celsius: float
    tail_window_seconds: int
    max_tail_mae_celsius: float

    def __post_init__(self) -> None:
        for name in (
            "proportional_gain_kw_per_celsius",
            "integral_gain_kw_per_celsius_second",
            "derivative_gain_kw_second_per_celsius",
            "initial_integral_error_celsius_seconds",
            "initial_previous_error_celsius",
            "max_tail_mae_celsius",
        ):
            value = getattr(self, name)
            if not isfinite(value):
                raise ValueError(f"{name} 必须是有限实数")
        if self.sample_period_seconds <= 0 or self.tail_window_seconds <= 0:
            raise ValueError("采样周期和 tracking 尾部窗口必须为正整数秒")
        if self.tail_window_seconds % self.sample_period_seconds != 0:
            raise ValueError("tracking 尾部窗口必须能被采样周期整除")
        if self.max_tail_mae_celsius <= 0:
            raise ValueError("max_tail_mae_celsius 必须为正数")
        # 当前场景以 e=r-T 和正冷却功率为约定，因此三个 gain 不得改变负反馈方向。
        if self.proportional_gain_kw_per_celsius >= 0:
            raise ValueError("HVAC 冷却 PID 的 proportional gain 必须为负数")
        if self.integral_gain_kw_per_celsius_second >= 0:
            raise ValueError("HVAC 冷却 PID 的 integral gain 必须为负数")
        if self.derivative_gain_kw_second_per_celsius > 0:
            raise ValueError("HVAC 冷却 PID 的 derivative gain 不得为正数")

    @property
    def tail_window_samples(self) -> int:
        """将已冻结的秒数窗口转换为和记录网格一致的样本数。"""
        return self.tail_window_seconds // self.sample_period_seconds

    def to_controller_spec(self) -> ControllerSpec:
        """将位置式 PID 转换为 runtime 消费的 ``A/B/C/D/x0``，不传递 gain object。

        取 controller state ``x=[I, e_previous]``，其中 ``I(k)`` 是更新前的误差积分。
        对 ``e(k)=v(k)``，PID 为 ``u=Kp*e + Ki*I + Kd*(e-e_previous)/Ts``，且更新为
        ``I(k+1)=I(k)+Ts*e(k)``、``e_previous(k+1)=e(k)``。因此输出严格使用 runtime 的
        更新前 state，和 #21 的时序一致。
        """
        derivative_over_period = (
            self.derivative_gain_kw_second_per_celsius / self.sample_period_seconds
        )
        return ControllerSpec(
            A=np.array([[1.0, 0.0], [0.0, 0.0]], dtype=float),
            B=np.array([[self.sample_period_seconds], [1.0]], dtype=float),
            C=np.array(
                [
                    [
                        self.integral_gain_kw_per_celsius_second,
                        -derivative_over_period,
                    ]
                ],
                dtype=float,
            ),
            D=np.array(
                [[self.proportional_gain_kw_per_celsius + derivative_over_period]], dtype=float
            ),
            x0=np.array(
                [
                    self.initial_integral_error_celsius_seconds,
                    self.initial_previous_error_celsius,
                ],
                dtype=float,
            ),
        )


def load_hvac_pid_design(path: str | Path, contract: HvacScenarioContract) -> HvacPidDesign:
    """从 HVAC YAML 读取 PID 和 tracking 配置，并校验其与场景采样语义一致。"""
    if not isinstance(contract, HvacScenarioContract):
        raise TypeError("contract 必须是 HvacScenarioContract")
    config_path = Path(path)
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"无法读取 HVAC PID 配置文件：{config_path}") from error
    if not isinstance(loaded, Mapping):
        raise TypeError("HVAC PID 配置根节点必须是映射")

    scenario = _mapping(loaded, "scenario")
    if _string(scenario, "name") != "hvac":
        raise ValueError("scenario.name 必须为 hvac")
    hvac = _mapping(scenario, "hvac")
    controller = _mapping(hvac, "controller")
    tracking = _mapping(hvac, "tracking")
    _validate_controller_strategy(controller)

    design = HvacPidDesign(
        proportional_gain_kw_per_celsius=_number(controller, "proportional_gain_kw_per_celsius"),
        integral_gain_kw_per_celsius_second=_number(
            controller, "integral_gain_kw_per_celsius_second"
        ),
        derivative_gain_kw_second_per_celsius=_number(
            controller, "derivative_gain_kw_second_per_celsius"
        ),
        sample_period_seconds=contract.timing.sampling_period_seconds,
        initial_integral_error_celsius_seconds=_number(
            controller, "initial_integral_error_celsius_seconds"
        ),
        initial_previous_error_celsius=_number(controller, "initial_previous_error_celsius"),
        tail_window_seconds=_integer(tracking, "tail_window_seconds"),
        max_tail_mae_celsius=_number(tracking, "max_tail_mae_celsius"),
    )
    if design.tail_window_seconds > min(
        segment.end_seconds - segment.start_seconds for segment in contract.reference_segments
    ):
        raise ValueError("tracking 尾部窗口不得超过任一 reference 区段")
    return design


def _validate_controller_strategy(controller: Mapping[str, Any]) -> None:
    """冻结 derivative、饱和和 anti-windup 策略，避免实验结果隐式改变控制语义。"""
    if _string(controller, "kind") != "positional_pid_error_derivative":
        raise ValueError("controller.kind 必须为 positional_pid_error_derivative")
    if _string(controller, "derivative_filter") != "none":
        raise ValueError("当前 HVAC PID 不使用 derivative filter")
    if _string(controller, "anti_windup") != "disabled":
        raise ValueError("当前 HVAC PID 的 anti_windup 必须为 disabled")
    if _string(controller, "output_saturation") != "scenario_before_plant":
        raise ValueError("HVAC PID saturation 必须在 scenario_before_plant 组合")


def _mapping(source: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """读取必填映射节点，避免错误配置在 PID 计算时才暴露。"""
    value = source.get(key)
    if not isinstance(value, Mapping) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{key} 必须是映射")
    return value


def _string(source: Mapping[str, Any], key: str) -> str:
    """读取非空字符串策略字段。"""
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} 必须是非空字符串")
    return value


def _integer(source: Mapping[str, Any], key: str) -> int:
    """读取不接受布尔值的正整数配置。"""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise TypeError(f"{key} 必须是整数")
    return int(value)


def _number(source: Mapping[str, Any], key: str) -> float:
    """读取有限实数，不让 YAML 字符串或 NaN 进入控制器参数。"""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
        raise ValueError(f"{key} 必须是有限实数")
    return float(value)
