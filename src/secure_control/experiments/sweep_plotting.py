"""只消费已通过两阶段清单验证的正式扫描工件进行无 GUI 绘图。"""

from __future__ import annotations

from pathlib import Path

import matplotlib
import numpy as np
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure

from .sweep import SweepRunRecord, SweepRunStatus
from .sweep_artifacts import VerifiedSweepData, load_verified_sweep_data

matplotlib.use("Agg")


def _save(figure: Figure, path: Path) -> Path:
    """以固定 DPI 独占保存并关闭单张图。"""
    if path.exists():
        raise FileExistsError(f"拒绝覆盖既有 figure：{path.name}")
    FigureCanvasAgg(figure)
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    figure.clear()
    return path


def _successful(data: VerifiedSweepData) -> list[SweepRunRecord]:
    """返回已验证的成功点，并拒绝空扫描。"""
    records = [record for record in data.records if record.status is SweepRunStatus.SUCCESS]
    if not records:
        raise ValueError("已验证扫描不含成功点")
    return records


def select_primary_records(
    data: VerifiedSweepData, primary_seed: int
) -> tuple[SweepRunRecord, ...]:
    """按精度返回主 seed 的成功点，缺失任一定义精度时明确失败。"""
    records = tuple(
        sorted(
            (
                record
                for record in data.records
                if record.status is SweepRunStatus.SUCCESS and record.point.seed == primary_seed
            ),
            key=lambda record: record.point.ell,
        )
    )
    expected = tuple(data.definition["fractional_bits"])
    if tuple(record.point.ell for record in records) != expected:
        raise ValueError("主 seed 未完整覆盖 sweep definition 的全部精度")
    return records


def verified_error_series(
    data: VerifiedSweepData, *, primary_seed: int, field: str
) -> tuple[tuple[int, np.ndarray, np.ndarray], ...]:
    """从 verified runs 提取同网格误差序列，不读取孤立 CSV。"""
    if field not in ("control_error", "output_error"):
        raise ValueError("field 必须是 control_error 或 output_error")
    reference_time: np.ndarray | None = None
    series: list[tuple[int, np.ndarray, np.ndarray]] = []
    for record in select_primary_records(data, primary_seed):
        result = data.runs[record.point.point_id].result
        if reference_time is None:
            reference_time = result.time
        elif not np.array_equal(reference_time, result.time):
            raise ValueError("primary seed 的 time grids 不一致")
        series.append((record.point.ell, result.time, getattr(result, field)[:, 0]))
    return tuple(series)


def _error_figure(
    records: list[SweepRunRecord], *, name: str, title: str, primary_seed: int
) -> Figure:
    """画出每个 seed 的 max/mean/RMS，并突出主 seed。"""
    figure = Figure(figsize=(7.2, 4.5))
    axis = figure.subplots()
    for metric, marker in (("max_abs", "o"), ("mean_abs", "s"), ("rms", "^")):
        for seed in sorted({record.point.seed for record in records}):
            selected = sorted(
                (record for record in records if record.point.seed == seed),
                key=lambda record: record.point.ell,
            )
            axis.plot(
                [record.point.ell for record in selected],
                [getattr(getattr(record, name), metric) for record in selected],
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


def _time_series_figure(
    data: VerifiedSweepData, *, primary_seed: int, field: str, title: str
) -> Figure:
    """在同一时间网格上画四个 ell 的主 seed 绝对误差，零值以 mask 保留。"""
    figure = Figure(figsize=(7.2, 4.5))
    axis = figure.subplots()
    for ell, time, error in verified_error_series(data, primary_seed=primary_seed, field=field):
        values = np.abs(error)
        masked = np.ma.masked_equal(values, 0.0)
        axis.plot(time / 3600.0, masked, label=f"ell={ell}")
    axis.set_yscale("log")
    axis.set_xlabel("time (h)")
    axis.set_ylabel("absolute error")
    axis.set_title(title)
    axis.grid(True, which="both", alpha=0.25)
    axis.legend()
    return figure


def render_sweep_figures(
    root: str | Path,
    *,
    primary_seed: int,
    output_dir: str | Path | None = None,
    manifest_name: str = "manifest.json",
) -> tuple[Path, ...]:
    """验证正式闭包后生成四张汇总图和两张主 seed 跨精度时序图。"""
    data = load_verified_sweep_data(root, manifest_name=manifest_name)
    records = _successful(data)
    output = Path(output_dir) if output_dir is not None else data.root / "figures"
    output.mkdir(parents=True, exist_ok=True)
    paths = [
        _save(
            _error_figure(
                records,
                name="control_error",
                title="Control error versus fixed-point precision",
                primary_seed=primary_seed,
            ),
            output / "control_error_vs_ell.png",
        ),
        _save(
            _error_figure(
                records,
                name="output_error",
                title="Output error versus fixed-point precision",
                primary_seed=primary_seed,
            ),
            output / "output_error_vs_ell.png",
        ),
        _save(
            _time_series_figure(
                data,
                primary_seed=primary_seed,
                field="control_error",
                title="Primary-seed control error over time",
            ),
            output / "control_error_over_time_by_ell.png",
        ),
        _save(
            _time_series_figure(
                data,
                primary_seed=primary_seed,
                field="output_error",
                title="Primary-seed output error over time",
            ),
            output / "output_error_over_time_by_ell.png",
        ),
    ]
    primary = sorted(
        (record for record in records if record.point.seed == primary_seed),
        key=lambda record: record.point.ell,
    )
    figure = Figure(figsize=(7.2, 4.5))
    axis = figure.subplots()
    ell = [record.point.ell for record in primary]
    axis.plot(ell, [record.control_error.max_abs for record in primary], "o-", label="control")
    axis.plot(ell, [record.output_error.max_abs for record in primary], "s-", label="output")
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
    ell_values = sorted({record.point.ell for record in records})
    grouped = {
        ell_value: [
            record.cost.wall_clock_seconds for record in records if record.point.ell == ell_value
        ]
        for ell_value in ell_values
    }
    axis.bar(ell_values, [float(np.mean(values)) for values in grouped.values()], alpha=0.65)
    axis.set_xlabel("fractional bits (ell)")
    axis.set_ylabel("mean wall-clock seconds")
    cost_axis = axis.twinx()
    for name, marker, label in (
        ("protocol1_triples_total", "o", "Protocol 1 triples"),
        ("protocol2_truncations_total", "s", "Protocol 2 truncations"),
    ):
        values = [
            float(
                np.mean(
                    [getattr(record.cost, name) for record in records if record.point.ell == value]
                )
            )
            for value in ell_values
        ]
        cost_axis.plot(ell_values, values, marker=marker, label=label)
    cost_axis.set_ylabel("derived exact resources per run")
    cost_axis.legend(loc="upper right")
    axis.set_title("Execution timing and protocol resource counts")
    axis.grid(True, axis="y", alpha=0.25)
    paths.append(_save(figure, output / "timing_cost.png"))
    return tuple(paths)
