"""Issue #51 增强报告的冻结设计、分钟分段与资源口径测试。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from secure_control.experiments.evidence_reporting import (
    _integer_decode_data,
    _integer_decode_figure,
    _quantitative_rows,
    _resource_timing_figure,
    load_evidence_report_profile,
)
from secure_control.experiments.reporting import ResolvedFont, load_report_profile
from secure_control.experiments.sweep import (
    PrecisionPreflightReport,
    ProtocolCostReport,
    SweepPointDefinition,
    SweepRunRecord,
    SweepRunStatus,
)
from secure_control.experiments.sweep_artifacts import VerifiedSweepData
from secure_control.experiments.sweep_metrics import ErrorMetrics

PROJECT_ROOT = Path(__file__).parents[1]
PROFILE = PROJECT_ROOT / "configs" / "hvac_2r2c_evidence_report_zh.yaml"
BASE_PROFILE = PROJECT_ROOT / "configs" / "hvac_2r2c_report_zh.yaml"


def _record(ell: int, seed: int, *, triples: int = 1620) -> SweepRunRecord:
    """构造只用于资源统计的成功点。"""
    metrics = ErrorMetrics(1.0 / ell, 0.5 / ell, 0.75 / ell, 0, 1.0 / ell, 180)
    return SweepRunRecord(
        SweepPointDefinition(ell, ell + 28, 128, (1 << 255) - 19, 120, seed),
        SweepRunStatus.SUCCESS,
        PrecisionPreflightReport(True, True, True, (), True, ()),
        metrics,
        metrics,
        {},
        ProtocolCostReport(9, triples, 0, 0, 256, 160, float(seed), "fixture"),
        f"runs/ell-{ell}-seed-{seed}/run",
        None,
        None,
    )


def test_evidence_profile_freezes_minute_segments_main_order_and_limitations() -> None:
    """增强 profile 固定三段半开分钟区间、applied Fig.3 与安全声明。"""
    profile = load_evidence_report_profile(PROFILE)
    assert profile.time_unit == "min"
    assert profile.segments_minutes == ((0, 60), (60, 120), (120, 180))
    assert profile.fig3_control_semantics == "applied"
    assert profile.deployment_security is False
    assert profile.main_order[-2:] == ("quantitative_table", "resource_and_timing")
    assert any("Protocol 2 count 为 0" in item for item in profile.limitations_zh)


def test_resource_figure_requires_exact_counts_across_all_three_seeds(tmp_path: Path) -> None:
    """跨 seed 资源不一致时不得把协议开销标为 exact。"""
    records = tuple(
        _record(ell, seed, triples=1621 if (ell, seed) == (48, 44) else 1620)
        for ell in (32, 40, 48, 56)
        for seed in (42, 43, 44)
    )
    sweep = VerifiedSweepData(
        tmp_path,
        {"fractional_bits": [32, 40, 48, 56]},
        records,
        {},
    )
    base = load_report_profile(BASE_PROFILE)
    font = ResolvedFont("fixture", tmp_path / "unused.ttf", "0" * 64, "")
    with pytest.raises(ValueError, match="跨 seed 不一致"):
        _resource_timing_figure(sweep, SimpleNamespace(resource_rows=()), base, font)


def test_quantitative_table_requires_real_primary_run_and_source_files(tmp_path: Path) -> None:
    """定量表不能脱离 verified primary run 或伪造 provenance。"""
    records = tuple(_record(ell, seed) for ell in (32, 40, 48, 56) for seed in (42, 43, 44))
    sweep = VerifiedSweepData(
        tmp_path,
        {"fractional_bits": [32, 40, 48, 56]},
        records,
        {},
    )
    profile = load_evidence_report_profile(PROFILE)
    with pytest.raises(FileNotFoundError):
        _quantitative_rows(sweep, profile)


def _integer_evidence() -> SimpleNamespace:
    """构造 180 步精确整数、真实 scale 与 k=60 单步交叉证据。"""
    scale = 96
    rows = tuple(
        {
            "step": step,
            "channel": 0,
            "secure_output_centered": (step + 1) * (1 << scale),
            "output_fractional_bits": scale,
            "raw_secure_control": float(step + 1),
            "applied_secure_control": float(min(step + 1, 50)),
        }
        for step in range(180)
    )
    selected = rows[60]
    return SimpleNamespace(
        integer_control_rows=rows,
        metadata={"scale_ledger": {"output": scale}},
        selected_step={
            "step": 60,
            "raw_control": {
                "centered": [str(selected["secure_output_centered"])],
                "residue": [str(selected["secure_output_centered"])],
                "fractional_bits": scale,
            },
            "decoded_raw_control": [selected["raw_secure_control"]],
        },
    )


def test_integer_figure_uses_verified_integers_scale_formula_and_local_window(
    tmp_path: Path,
) -> None:
    """03 图的整数、k=58..62 与 decode 公式直接来自 verified evidence。"""
    evidence = _integer_evidence()
    source_before = tuple(row["secure_output_centered"] for row in evidence.integer_control_rows)
    data = _integer_decode_data(evidence, 60)
    assert len(data["integers"]) == 180
    assert all(type(value) is int for value in data["integers"])
    assert tuple(step for step, _ in data["local_window"]) == (58, 59, 60, 61, 62)
    assert dict(data["local_window"])[60] == source_before[60]
    assert data["fractional_bits"] == 96
    assert data["selected_raw"] == source_before[60] / (1 << 96)
    assert (
        tuple(row["secure_output_centered"] for row in evidence.integer_control_rows)
        == source_before
    )

    profile = load_evidence_report_profile(PROFILE)
    base = load_report_profile(BASE_PROFILE)
    font = ResolvedFont("fixture", tmp_path / "unused.ttf", "0" * 64, "")
    figure = _integer_decode_figure(evidence, profile, base, font)
    assert len(figure.axes[0].lines[0].get_xdata()) == 180
    assert figure.axes[0].lines[0].get_marker() == "o"
    displayed = " ".join(
        [text.get_text() for axis in figure.axes for text in axis.texts]
        + [cell.get_text().get_text() for cell in figure.axes[1].tables[0].get_celld().values()]
    )
    assert str(source_before[60]) in displayed
    assert "2^96" in displayed
    assert "applied 50" in displayed


def test_resource_figure_includes_real_cumulative_and_per_step_series(tmp_path: Path) -> None:
    """09 图同时使用跨 seed exact totals 与代表点真实 lifecycle rows。"""
    records = tuple(_record(ell, seed) for ell in (32, 40, 48, 56) for seed in (42, 43, 44))
    sweep = VerifiedSweepData(
        tmp_path,
        {"fractional_bits": [32, 40, 48, 56]},
        records,
        {},
    )
    resource_rows = tuple(
        {
            "step": step,
            "triples_consumed": 9 * (step + 1),
            "triples_consumed_delta": 9,
            "truncations_consumed": 0,
            "truncations_consumed_delta": 0,
        }
        for step in range(180)
    )
    base = load_report_profile(BASE_PROFILE)
    font = ResolvedFont("fixture", tmp_path / "unused.ttf", "0" * 64, "")
    figure = _resource_timing_figure(
        sweep, SimpleNamespace(resource_rows=resource_rows), base, font
    )
    lifecycle = next(axis for axis in figure.axes if axis.get_ylabel() == "实际累计消费")
    delta = next(axis for axis in figure.axes if axis.get_ylabel() == "实际每步增量")
    assert np.array_equal(lifecycle.lines[0].get_ydata(), np.arange(9, 1621, 9))
    assert set(delta.lines[0].get_ydata()) == {9}
