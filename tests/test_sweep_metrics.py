"""Issue #15 通用误差指标与跨 seed 汇总回归。"""

from __future__ import annotations

import numpy as np
import pytest

from secure_control.experiments.sweep_metrics import aggregate_error_metrics, compute_error_metrics


def test_error_metrics_report_zero_floor_and_binary64_minimum() -> None:
    """高精度扫描必须区分数学零、binary64 零与最小正误差。"""
    metrics = compute_error_metrics(np.array([0.0, -0.25, 0.5, 0.0]))
    assert metrics.max_abs == 0.5
    assert metrics.mean_abs == pytest.approx(0.1875)
    assert metrics.rms == pytest.approx(np.sqrt(0.078125))
    assert metrics.zero_count == 2
    assert metrics.minimum_positive_abs == 0.25
    assert metrics.sample_count == 4


def test_aggregate_error_metrics_preserves_seed_distribution() -> None:
    """汇总只做逐字段统计，不把多个 seed 冒充一次轨迹。"""
    summary = aggregate_error_metrics(
        [compute_error_metrics(np.array([0.0, 1.0])), compute_error_metrics(np.array([0.0, 3.0]))]
    )
    assert summary["run_count"] == 2
    assert summary["max_abs"]["minimum"] == 1.0
    assert summary["max_abs"]["maximum"] == 3.0
    assert summary["max_abs"]["mean"] == 2.0


@pytest.mark.parametrize("values", [np.array([]), np.array([np.nan]), np.array([np.inf])])
def test_error_metrics_reject_empty_or_nonfinite_values(values: np.ndarray) -> None:
    """正式摘要不接受空数组、NaN 或无穷大。"""
    with pytest.raises(ValueError):
        compute_error_metrics(values)
