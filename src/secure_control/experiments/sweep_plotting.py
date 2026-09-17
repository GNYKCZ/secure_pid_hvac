"""只消费已发布扫描摘要的无 GUI 跨精度绘图。"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
import numpy as np
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure

matplotlib.use("Agg")


def _rows(root: Path) -> list[dict[str, str]]:
    """读取成功点并拒绝缺少正式摘要。"""
    with (root / "summary.csv").open("r", encoding="utf-8", newline="") as source:
        rows = [row for row in csv.DictReader(source) if row.get("status") == "success"]
    if not rows:
        raise ValueError("summary.csv 不含成功扫描点")
    return rows


def _save(figure: Figure, path: Path) -> Path:
    """以固定 DPI 保存并关闭单张图。"""
    FigureCanvasAgg(figure)
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    figure.clear()
    return path


def _error_figure(
    rows: list[dict[str, str]], *, prefix: str, title: str, primary_seed: int
) -> Figure:
    """画出每个 seed 的 max/mean/RMS 及主 seed 轨迹。"""
    figure = Figure(figsize=(7.2, 4.5))
    axis = figure.subplots()
    for metric, marker in (("max_abs", "o"), ("mean_abs", "s"), ("rms", "^")):
        for seed in sorted({int(row["seed"]) for row in rows}):
            selected = sorted(
                (row for row in rows if int(row["seed"]) == seed),
                key=lambda row: int(row["ell"]),
            )
            axis.plot(
                [int(row["ell"]) for row in selected],
                [float(row[f"{prefix}_{metric}"]) for row in selected],
                marker=marker,
                linewidth=2.0 if seed == primary_seed else 0.8,
                alpha=1.0 if seed == primary_seed else 0.45,
                label=f"{metric}, seed={seed}",
            )
    axis.set_yscale("log")
    axis.set_xlabel("fractional bits (ell)")
    axis.set_ylabel("absolute error")
    axis.set_title(title)
    axis.grid(True, which="both", alpha=0.25)
    axis.legend(fontsize=7, ncol=2)
    return figure


def render_sweep_figures(root: str | Path, *, primary_seed: int) -> tuple[Path, ...]:
    """从 summary.csv 生成控制/输出误差、精度摘要和计时成本图。"""
    sweep_root = Path(root)
    rows = _rows(sweep_root)
    output = sweep_root / "figures"
    output.mkdir(parents=True, exist_ok=True)
    paths = [
        _save(
            _error_figure(
                rows,
                prefix="control",
                title="Control error versus fixed-point precision",
                primary_seed=primary_seed,
            ),
            output / "control_error_vs_ell.png",
        ),
        _save(
            _error_figure(
                rows,
                prefix="output",
                title="Output error versus fixed-point precision",
                primary_seed=primary_seed,
            ),
            output / "output_error_vs_ell.png",
        ),
    ]
    primary = sorted(
        (row for row in rows if int(row["seed"]) == primary_seed),
        key=lambda row: int(row["ell"]),
    )
    figure = Figure(figsize=(7.2, 4.5))
    axis = figure.subplots()
    ell = [int(row["ell"]) for row in primary]
    axis.plot(ell, [float(row["control_max_abs"]) for row in primary], "o-", label="control")
    axis.plot(ell, [float(row["output_max_abs"]) for row in primary], "s-", label="output")
    axis.plot(ell, [2.0 ** (-value) for value in ell], "--", label="2^-ell")
    axis.set_yscale("log")
    axis.set_xlabel("fractional bits (ell)")
    axis.set_ylabel("primary-seed maximum absolute error")
    axis.set_title("Precision scaling summary")
    axis.grid(True, which="both", alpha=0.25)
    axis.legend()
    paths.append(_save(figure, output / "precision_summary.png"))

    figure = Figure(figsize=(7.2, 4.5))
    axis = figure.subplots()
    grouped = {
        value: [float(row["wall_clock_seconds"]) for row in rows if int(row["ell"]) == value]
        for value in sorted({int(row["ell"]) for row in rows})
    }
    ell_values = list(grouped)
    axis.bar(ell_values, [float(np.mean(values)) for values in grouped.values()], alpha=0.65)
    axis.set_xlabel("fractional bits (ell)")
    axis.set_ylabel("mean wall-clock seconds")
    cost_axis = axis.twinx()
    for field, marker, label in (
        ("protocol1_triples_total", "o", "Protocol 1 triples"),
        ("protocol2_truncations_total", "s", "Protocol 2 truncations"),
    ):
        costs = [
            float(np.mean([float(row[field]) for row in rows if int(row["ell"]) == ell]))
            for ell in ell_values
        ]
        cost_axis.plot(ell_values, costs, marker=marker, label=label)
    cost_axis.set_ylabel("derived exact resources per run")
    cost_axis.legend(loc="upper right")
    axis.set_title("Execution timing and protocol resource counts")
    axis.grid(True, axis="y", alpha=0.25)
    paths.append(_save(figure, output / "timing_cost.png"))
    return tuple(paths)
