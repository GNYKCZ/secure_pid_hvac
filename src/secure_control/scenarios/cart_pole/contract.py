"""倒立摆物理参数、采样和边界的严格配置契约。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from numbers import Real
from pathlib import Path
from typing import Any

import yaml


class _UniqueKeyLoader(yaml.SafeLoader):
    """拒绝重复 YAML 键，避免物理参数被后一个值静默覆盖。"""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[object, object]:
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError(f"倒立摆 YAML 包含重复配置键: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _number(value: Any, name: str, *, positive: bool = False) -> float:
    """物理量必须是有限实数，布尔值和复数没有物理含义。"""
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


@dataclass(frozen=True, slots=True)
class CartPoleContract:
    """冻结 CTMS 教学参数与本项目的离散仿真选择。"""

    cart_mass_kg: float
    pole_mass_kg: float
    com_length_m: float
    pole_inertia_kg_m2: float
    cart_friction_n_s_per_m: float
    gravity_m_per_s2: float
    sample_period_s: float
    rk4_substeps: int
    initial_state: tuple[float, float, float, float]
    track_center_limit_m: float
    max_applied_force_n: float

    def __post_init__(self) -> None:
        for name in (
            "cart_mass_kg", "pole_mass_kg", "com_length_m", "pole_inertia_kg_m2",
            "gravity_m_per_s2", "sample_period_s", "track_center_limit_m",
            "max_applied_force_n",
        ):
            object.__setattr__(self, name, _number(getattr(self, name), name, positive=True))
        friction = _number(self.cart_friction_n_s_per_m, "cart_friction_n_s_per_m")
        if friction < 0:
            raise ValueError("cart_friction_n_s_per_m 不得为负数")
        object.__setattr__(self, "cart_friction_n_s_per_m", friction)
        if type(self.rk4_substeps) is not int or self.rk4_substeps <= 0:
            raise ValueError("rk4_substeps 必须是正整数")
        if not isinstance(self.initial_state, (tuple, list)) or len(self.initial_state) != 4:
            raise ValueError("initial_state 必须是四维向量")
        state = tuple(_number(value, f"initial_state[{i}]") for i, value in enumerate(self.initial_state))
        if abs(state[0]) > self.track_center_limit_m:
            raise ValueError("initial_state[0] 超出 track_center_limit_m")
        object.__setattr__(self, "initial_state", state)


def load_cart_pole_contract(path: str | Path) -> CartPoleContract:
    """严格加载唯一 YAML 参数源，拒绝遗漏、拼错或重复字段。"""
    with Path(path).open(encoding="utf-8") as stream:
        root = yaml.load(stream, Loader=_UniqueKeyLoader)
    expected = {"schema_version", "scenario", *CartPoleContract.__dataclass_fields__}
    if not isinstance(root, Mapping) or set(root) != expected:
        raise ValueError(f"倒立摆配置必须且仅能包含 {sorted(expected)}")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version 必须是 1")
    if root["scenario"] != "cart_pole":
        raise ValueError("scenario 必须是 cart_pole")
    return CartPoleContract(**{name: root[name] for name in CartPoleContract.__dataclass_fields__})
