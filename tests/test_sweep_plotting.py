"""Issue #15 扫描图只消费已保存 summary，不重跑场景。"""

from __future__ import annotations

import csv
from pathlib import Path

from secure_control.experiments.sweep_plotting import render_sweep_figures


def test_sweep_plotting_reads_summary_and_publishes_four_figures(tmp_path: Path) -> None:
    """跨 ell 图由工件生成，并保留所有 seed 与主 seed 标记。"""
    root = tmp_path / "sweep"
    root.mkdir()
    summary = root / "summary.csv"
    fields = [
        "ell",
        "k",
        "seed",
        "status",
        "control_max_abs",
        "control_mean_abs",
        "control_rms",
        "output_max_abs",
        "output_mean_abs",
        "output_rms",
        "wall_clock_seconds",
        "protocol1_triples_total",
        "protocol2_truncations_total",
    ]
    with summary.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        for ell in (32, 40, 48, 56):
            for seed in (42, 43, 44):
                writer.writerow(
                    {
                        "ell": ell,
                        "k": ell + 28,
                        "seed": seed,
                        "status": "success",
                        "control_max_abs": 2.0**-ell,
                        "control_mean_abs": 2.0 ** (-ell - 1),
                        "control_rms": 2.0 ** (-ell - 1),
                        "output_max_abs": 2.0 ** (-ell + 1),
                        "output_mean_abs": 2.0**-ell,
                        "output_rms": 2.0**-ell,
                        "wall_clock_seconds": 0.5,
                        "protocol1_triples_total": 1620,
                        "protocol2_truncations_total": 0,
                    }
                )
    figures = render_sweep_figures(root, primary_seed=42)
    assert len(figures) == 4
    assert {path.name for path in figures} == {
        "control_error_vs_ell.png",
        "output_error_vs_ell.png",
        "precision_summary.png",
        "timing_cost.png",
    }
    assert all(path.is_file() and path.stat().st_size > 0 for path in figures)
