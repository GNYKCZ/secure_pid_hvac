"""将论文 §VII 的四水箱 observer 印刷矩阵装配为通用 ControllerSpec。"""

from __future__ import annotations

from math import isfinite
from numbers import Real
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from secure_control.core import ControllerSpec

from .contract import _keys, _UniqueKeyLoader

_SOURCE = "arxiv:2503.02176v3 §VII"


def _printed_array(value: Any, shape: tuple[int, ...], name: str) -> np.ndarray:
    """按印刷矩阵的固定 shape 加载有限实数，并拒绝布尔和字符串隐式转换。"""
    try:
        raw = np.asarray(value, dtype=object)
    except ValueError as error:
        raise ValueError(f"{name} 必须是 shape={shape} 的矩阵或向量") from error
    if raw.shape != shape:
        raise ValueError(f"{name} 必须是 shape={shape} 的矩阵或向量")
    values: list[float] = []
    for item in raw.flat:
        if isinstance(item, bool) or not isinstance(item, Real):
            raise TypeError(f"{name} 必须只含实数")
        try:
            number = float(item)
        except OverflowError as error:
            raise ValueError(f"{name} 必须只含有限实数") from error
        if not isfinite(number):
            raise ValueError(f"{name} 必须只含有限实数")
        values.append(number)
    return np.array(values, dtype=np.float64).reshape(shape)


def load_quadruple_tank_observer_spec(path: str | Path) -> ControllerSpec:
    """从单一论文印刷来源加载 A/B/C/D/x0，不在此派生或量化增益。"""
    with Path(path).open(encoding="utf-8") as stream:
        root = _keys(
            yaml.load(stream, Loader=_UniqueKeyLoader),
            {"schema_version", "scenario", "source", "controller"},
            "root",
        )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version 必须是 1")
    if root["scenario"] != "quadruple_tank" or root["source"] != _SOURCE:
        raise ValueError("scenario 或 source 与论文四水箱 observer 来源不一致")
    controller = _keys(root["controller"], {"A", "B", "C", "D", "x0"}, "controller")
    return ControllerSpec(
        A=_printed_array(controller["A"], (4, 4), "A"),
        B=_printed_array(controller["B"], (4, 2), "B"),
        C=_printed_array(controller["C"], (2, 4), "C"),
        D=_printed_array(controller["D"], (2, 2), "D"),
        x0=_printed_array(controller["x0"], (4,), "x0"),
    )
