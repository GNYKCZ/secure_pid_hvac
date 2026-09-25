"""四水箱物理参数与项目建模选择的独立配置契约。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from numbers import Real
from pathlib import Path
from typing import Any

import yaml


def _keys(value: Any, expected: set[str], name: str) -> Mapping[str, Any]:
    """拒绝漏项和拼错的配置键，避免静默改动物理模型。"""
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{name} 必须且仅能包含 {sorted(expected)}")
    return value


def _number(value: Any, name: str, *, positive: bool = False) -> float:
    """只接受有限实数；布尔值不属于物理量。"""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{name} 必须是有限实数")
    try:
        result = float(value)
    except OverflowError as error:
        raise ValueError(f"{name} 必须是有限实数") from error
    if not isfinite(result):
        raise ValueError(f"{name} 必须是有限实数")
    if positive and result <= 0:
        raise ValueError(f"{name} 必须为正数")
    return result


def _vector(value: Any, size: int, name: str, *, positive: bool = False) -> tuple[float, ...]:
    """固定通道数与顺序，产出不共享配置列表的不可变快照。"""
    if not isinstance(value, (tuple, list)) or len(value) != size:
        raise ValueError(f"{name} 必须有 {size} 个元素")
    return tuple(_number(item, f"{name}[{index}]", positive=positive) for index, item in enumerate(value))


@dataclass(frozen=True, slots=True)
class QuadrupleTankContract:
    """保存 Johansson P− 参数、论文工作点及显式偏差坐标/ZOH 选择。"""

    tank_cross_sections_cm2: tuple[float, ...]
    outlet_cross_sections_cm2: tuple[float, ...]
    pump_flow_coefficients_cm3_per_v_s: tuple[float, ...]
    sensor_gain_v_per_cm: float
    gravity_cm_per_s2: float
    heights_cm: tuple[float, ...]
    pump_voltages_v: tuple[float, ...]
    valve_fractions: tuple[float, ...]
    sample_period_seconds: float
    initial_state_deviation_cm: tuple[float, ...]
    state_coordinate: str
    discretization: str

    def __post_init__(self) -> None:
        for name, size in (
            ("tank_cross_sections_cm2", 4),
            ("outlet_cross_sections_cm2", 4),
            ("pump_flow_coefficients_cm3_per_v_s", 2),
            ("heights_cm", 4),
            ("pump_voltages_v", 2),
            ("valve_fractions", 2),
            ("initial_state_deviation_cm", 4),
        ):
            values = _vector(
                getattr(self, name), size, name,
                positive=name not in ("valve_fractions", "initial_state_deviation_cm"),
            )
            object.__setattr__(self, name, values)
        for name in ("sensor_gain_v_per_cm", "gravity_cm_per_s2", "sample_period_seconds"):
            object.__setattr__(self, name, _number(getattr(self, name), name, positive=True))
        if any(not 0 < fraction < 1 for fraction in self.valve_fractions):
            raise ValueError("valve_fractions 必须严格位于 (0, 1)")
        if self.state_coordinate != "height_deviation_cm" or self.discretization != "zoh":
            raise ValueError("仅支持高度偏差坐标和 ZOH 离散化")


def load_quadruple_tank_contract(path: str | Path) -> QuadrupleTankContract:
    """从 YAML 加载单一物理来源；离散矩阵由 plant 计算，不从配置读取。"""
    with Path(path).open(encoding="utf-8") as stream:
        root = _keys(
            yaml.safe_load(stream),
            {"schema_version", "scenario", "physical", "operating_point", "sample_period_seconds", "initial_state_deviation_cm", "state_coordinate", "discretization"},
            "root",
        )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version 必须是 1")
    if root["scenario"] != "quadruple_tank":
        raise ValueError("scenario 必须是 quadruple_tank")
    physical = _keys(root["physical"], {"tank_cross_sections_cm2", "outlet_cross_sections_cm2", "pump_flow_coefficients_cm3_per_v_s", "sensor_gain_v_per_cm", "gravity_cm_per_s2"}, "physical")
    point = _keys(root["operating_point"], {"heights_cm", "pump_voltages_v", "valve_fractions"}, "operating_point")
    return QuadrupleTankContract(
        **physical, **point,
        sample_period_seconds=root["sample_period_seconds"],
        initial_state_deviation_cm=root["initial_state_deviation_cm"],
        state_coordinate=root["state_coordinate"],
        discretization=root["discretization"],
    )
