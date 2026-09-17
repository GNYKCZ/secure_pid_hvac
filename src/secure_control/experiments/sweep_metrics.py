"""领域无关的误差统计与跨重复运行汇总。"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from typing import Any

import numpy as np
from numpy.typing import ArrayLike


@dataclass(frozen=True, slots=True)
class ErrorMetrics:
    """保存绝对误差、RMS、零计数和 binary64 正误差下限。"""

    max_abs: float
    mean_abs: float
    rms: float
    zero_count: int
    minimum_positive_abs: float | None
    sample_count: int


def compute_error_metrics(values: ArrayLike) -> ErrorMetrics:
    """对任意有限非空误差数组按全部元素计算统一指标。"""
    array = np.asarray(values, dtype=float)
    if array.size == 0 or not np.isfinite(array).all():
        raise ValueError("误差数组必须非空且只包含有限值")
    absolute = np.abs(array.reshape(-1))
    positive = absolute[absolute > 0.0]
    return ErrorMetrics(
        max_abs=float(np.max(absolute)),
        mean_abs=float(np.mean(absolute)),
        rms=sqrt(float(np.mean(np.square(absolute)))),
        zero_count=int(np.count_nonzero(absolute == 0.0)),
        minimum_positive_abs=None if positive.size == 0 else float(np.min(positive)),
        sample_count=int(absolute.size),
    )


def aggregate_error_metrics(metrics: list[ErrorMetrics]) -> dict[str, Any]:
    """按运行保留 max/mean/rms 的最小、最大和均值摘要。"""
    if not metrics:
        raise ValueError("metrics 不得为空")
    result: dict[str, Any] = {"run_count": len(metrics)}
    for name in ("max_abs", "mean_abs", "rms"):
        values = np.asarray([getattr(item, name) for item in metrics], dtype=float)
        result[name] = {
            "minimum": float(np.min(values)),
            "maximum": float(np.max(values)),
            "mean": float(np.mean(values)),
        }
    result["zero_count"] = {
        "minimum": min(item.zero_count for item in metrics),
        "maximum": max(item.zero_count for item in metrics),
    }
    positive = [item.minimum_positive_abs for item in metrics if item.minimum_positive_abs]
    result["minimum_positive_abs"] = None if not positive else min(positive)
    return result
