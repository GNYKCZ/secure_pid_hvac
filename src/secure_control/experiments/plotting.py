"""仅消费已验证 schema v1 结果的领域无关、无 GUI 绘图与批次发布。"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal

import matplotlib
import numpy as np
from matplotlib.axis import Axis
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from matplotlib.ticker import LogFormatterMathtext, ScalarFormatter

from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult

from .artifacts import SCHEMA_VERSION, ExperimentRecord, load_artifacts

ErrorScale = Literal["linear", "log"]
TimeUnit = Literal["s", "h"]
FigureFormat = Literal["png", "pdf"]
_RENDER_ID_PATTERN = re.compile(r"\A\d{8}T\d{12}Z-[0-9a-f]{12}\Z")


@dataclass(frozen=True, slots=True)
class LineStyle:
    """冻结一条曲线的颜色与线型，供展示层注入而不携带领域语义。"""

    color: str
    linestyle: str

    def __post_init__(self) -> None:
        """拒绝空样式，避免配置错误延迟到 Matplotlib。"""
        if not isinstance(self.color, str) or not self.color:
            raise ValueError("line color 不能为空。")
        if self.linestyle not in ("-", "--", "-.", ":"):
            raise ValueError("line style 无效。")


@dataclass(frozen=True, slots=True)
class FigureStyle:
    """冻结报告画布和字号；数值数组不受展示样式影响。"""

    width_inches: float
    height_inches: float
    dpi: int
    title_size: float
    label_size: float
    tick_size: float
    legend_size: float
    line_width: float
    grid_alpha: float
    marker_every: int

    def __post_init__(self) -> None:
        """画布、DPI、字号和线宽必须是有限正数。"""
        numeric = (
            self.width_inches,
            self.height_inches,
            self.title_size,
            self.label_size,
            self.tick_size,
            self.legend_size,
            self.line_width,
            self.grid_alpha,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not np.isfinite(value)
            or value <= 0
            for value in numeric
        ):
            raise ValueError("figure style 数值必须有限且为正。")
        if type(self.dpi) is not int or self.dpi <= 0:
            raise ValueError("figure DPI 必须是正整数。")
        if type(self.marker_every) is not int or self.marker_every <= 0:
            raise ValueError("marker_every 必须是正整数。")


def apply_axis_format(
    axis: Axis,
    *,
    scale: ErrorScale,
    signed: bool,
    scientific: bool = True,
) -> None:
    """只格式化刻度与零基线，不缩放、截断或改写曲线数组。"""
    if scale not in ("linear", "log"):
        raise ValueError("scale 必须是 linear 或 log。")
    if scale == "log":
        if axis.axis_name == "y":
            axis.axes.set_yscale("log")
        else:
            axis.axes.set_xscale("log")
        axis.set_major_formatter(LogFormatterMathtext())
    elif scientific:
        formatter = ScalarFormatter(useMathText=True)
        formatter.set_powerlimits((-3, 3))
        axis.set_major_formatter(formatter)
    if signed:
        axis.axes.axhline(0.0, color="#666666", linewidth=0.9, zorder=0)


@dataclass(frozen=True, slots=True)
class PlotSelection:
    """冻结通道/尺度/格式；未指定 output error 时保留由 tracking 推导的旧行为。"""

    tracking_pairs: tuple[tuple[int, int], ...]
    control_channels: tuple[int, ...]
    control_error_scale: ErrorScale = "linear"
    time_unit: TimeUnit = "s"
    format: FigureFormat = "png"
    output_error_channels: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        """拒绝自动配对、重复或歧义选择；越界和单位由 source metadata 判定。"""
        if (
            not isinstance(self.tracking_pairs, tuple)
            or not self.tracking_pairs
            or not isinstance(self.control_channels, tuple)
            or not self.control_channels
        ):
            raise ValueError("tracking_pairs/control_channels 必须是非空 tuple。")
        for pair in self.tracking_pairs:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or any(type(index) is not int or index < 0 for index in pair)
            ):
                raise ValueError("tracking 必须是非负整数 (output, reference) 配对。")
        if any(type(index) is not int or index < 0 for index in self.control_channels):
            raise ValueError("control channel 必须是非负整数。")
        if len(set(self.tracking_pairs)) != len(self.tracking_pairs) or len(
            set(self.control_channels)
        ) != len(self.control_channels):
            raise ValueError("重复的 tracking/control channel 选择无效。")
        if self.output_error_channels is not None:
            if (
                not isinstance(self.output_error_channels, tuple)
                or not self.output_error_channels
                or any(type(index) is not int or index < 0 for index in self.output_error_channels)
            ):
                raise ValueError("output error channel 必须是非空的非负整数 tuple。")
            if len(set(self.output_error_channels)) != len(self.output_error_channels):
                raise ValueError("重复的 output error channel 选择无效。")
        if self.control_error_scale not in ("linear", "log"):
            raise ValueError("control error scale 必须是 linear 或 log。")
        if self.time_unit not in ("s", "h") or self.format not in ("png", "pdf"):
            raise ValueError("time unit/figure format 无效。")


@dataclass(frozen=True, slots=True)
class PlotDisplay:
    """场景薄展示层只提供标题前缀与时间单位，不改变通用信号。"""

    time_unit: TimeUnit = "s"
    title_prefix: str = ""

    def __post_init__(self) -> None:
        """显式拒绝不受支持的时间换算，保持 schema v1 秒轴不被猜测。"""
        if self.time_unit not in ("s", "h") or not isinstance(self.title_prefix, str):
            raise ValueError("展示时间单位或标题无效。")


@dataclass(frozen=True, slots=True)
class FigureSet:
    """一次完整发布的 source/render 身份、图路径与清单路径。"""

    source_run_id: str
    render_id: str
    figure_paths: tuple[Path, ...]
    manifest_path: Path


def _channel(channels: ChannelMetadata, index: int, field: str) -> tuple[str, str]:
    """选择只能落在场景声明的通道内，不能依赖固定领域列名。"""
    if type(index) is not int or index < 0 or index >= len(channels.names):
        raise ValueError(f"{field} channel index 越界：{index}")
    return channels.names[index], channels.units[index]


def _series(
    record: ExperimentRecord, field: str, channels: ChannelMetadata, index: int
) -> np.ndarray:
    """公共 helper 也核对所选 shape/有限性；正式批次仍由 reader 先复验全 schema。"""
    if (
        not isinstance(record, ExperimentRecord)
        or not isinstance(record.result, SimulationResult)
        or not isinstance(record.metadata, ScenarioMetadata)
    ):
        raise TypeError("plotting 需要已验证的 ExperimentRecord。")
    _channel(channels, index, field)
    data = np.asarray(getattr(record.result, field))
    if (
        data.shape != (record.result.time.size, len(channels.names))
        or data.dtype.kind not in "iuf"
        or not np.isfinite(data).all()
    ):
        raise ValueError(f"{field} 与 channel metadata 的 shape/有限性不一致。")
    return data[:, index]


def _time(record: ExperimentRecord, display: PlotDisplay) -> np.ndarray:
    """小时轴只换算既有秒样本，不补造 horizon 终点。"""
    if not isinstance(display, PlotDisplay):
        raise TypeError("display 必须是 PlotDisplay。")
    return record.result.time if display.time_unit == "s" else record.result.time / 3600.0


def _axes(record: ExperimentRecord, display: PlotDisplay, title: str, ylabel: str):
    """使用独立 Agg canvas，避免 GUI 后端、LaTeX 或全局 pyplot 状态。"""
    figure = Figure(figsize=(8.2, 4.6), layout="constrained")
    FigureCanvasAgg(figure)
    axes = figure.subplots()
    prefix = display.title_prefix or record.metadata.name
    axes.set_title(f"{prefix} · {title}")
    axes.set_xlabel("Time (s)" if display.time_unit == "s" else "Time (h)")
    axes.set_ylabel(ylabel)
    axes.grid(True, alpha=0.3)
    return figure, axes


def plot_tracking(
    record: ExperimentRecord, output_index: int, reference_index: int, display: PlotDisplay
) -> Figure:
    """只在单位相同时将 reference 与更新前 ideal/secure output 共轴。"""
    reference = _series(record, "reference", record.metadata.reference, reference_index)
    ideal = _series(record, "output_ideal", record.metadata.output, output_index)
    secure = _series(record, "output_secure", record.metadata.output, output_index)
    reference_name, reference_unit = _channel(
        record.metadata.reference, reference_index, "reference"
    )
    output_name, output_unit = _channel(record.metadata.output, output_index, "output")
    if reference_unit != output_unit:
        raise ValueError("tracking reference/output 单位不一致，不能共用 y 轴。")
    figure, axes = _axes(record, display, f"Tracking · {output_name}", output_unit)
    time = _time(record, display)
    axes.plot(time, reference, color="black", linestyle="--", label=f"Reference · {reference_name}")
    axes.plot(time, ideal, color="tab:blue", label=f"Ideal · {output_name}")
    axes.plot(time, secure, color="tab:orange", linestyle=":", label=f"Secure · {output_name}")
    axes.legend()
    return figure


def plot_control(record: ExperimentRecord, control_index: int, display: PlotDisplay) -> Figure:
    """对比已保存的 applied control，而非重新推算的 raw controller 输出。"""
    ideal = _series(record, "control_ideal", record.metadata.control, control_index)
    secure = _series(record, "control_secure", record.metadata.control, control_index)
    name, unit = _channel(record.metadata.control, control_index, "control")
    figure, axes = _axes(record, display, f"Applied control · {name}", f"Applied control ({unit})")
    time = _time(record, display)
    axes.plot(time, ideal, color="tab:blue", label=f"Ideal · {name}")
    axes.plot(time, secure, color="tab:orange", linestyle=":", label=f"Secure · {name}")
    axes.legend()
    return figure


def plot_control_error(
    record: ExperimentRecord, control_index: int, *, scale: ErrorScale, display: PlotDisplay
) -> Figure:
    """linear 画有符号误差；log 仅取渲染副本绝对值并 mask 零，不造 epsilon。"""
    if scale not in ("linear", "log"):
        raise ValueError("control error scale 必须是 linear 或 log。")
    error = _series(record, "control_error", record.metadata.control, control_index)
    name, unit = _channel(record.metadata.control, control_index, "control")
    ylabel = f"Ideal - secure ({unit})" if scale == "linear" else f"|Ideal - secure| ({unit})"
    figure, axes = _axes(record, display, f"Control error · {name}", ylabel)
    time = _time(record, display)
    if scale == "linear":
        axes.plot(time, error, color="tab:red", label=f"Signed error · {name}")
        axes.axhline(0.0, color="gray", linewidth=0.8)
    else:
        # 普通 log y 轴无法表示负值或零；只改画布上的副本，原结果仍为 signed error。
        zero_count = int(np.count_nonzero(error == 0))
        rendered = np.ma.masked_where(error == 0, np.abs(error))
        axes.set_yscale("log")
        if zero_count != error.size:
            axes.plot(time, rendered, color="tab:red", label=f"|Error| · {name}")
        else:
            axes.text(
                0.5,
                0.5,
                "All errors are zero; no positive values to display",
                ha="center",
                transform=axes.transAxes,
            )
        axes.text(
            0.98,
            0.02,
            f"Masked zero samples: {zero_count}",
            ha="right",
            va="bottom",
            transform=axes.transAxes,
        )
    if axes.lines:
        axes.legend()
    return figure


def plot_output_error(record: ExperimentRecord, output_index: int, display: PlotDisplay) -> Figure:
    """保留 ideal-secure 的有符号 output error，不因场景显示名称而取绝对值。"""
    error = _series(record, "output_error", record.metadata.output, output_index)
    name, unit = _channel(record.metadata.output, output_index, "output")
    figure, axes = _axes(record, display, f"Output error · {name}", f"Ideal - secure ({unit})")
    axes.plot(_time(record, display), error, color="tab:purple", label=f"Signed error · {name}")
    axes.axhline(0.0, color="gray", linewidth=0.8)
    axes.legend()
    return figure


def _new_render_id() -> str:
    """时间用于排序，nonce 使同一 source run 可安全重绘而不覆盖旧图。"""
    return f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{secrets.token_hex(6)}"


def _digest(path: Path) -> str:
    """清单仅记录文件摘要与相对名称，不暴露本机绝对路径。"""
    return sha256(path.read_bytes()).hexdigest()


def _owned_stage(stage: Path, parent: Path, identity: int) -> bool:
    """异常时只清理本调用拥有的直属 staging，不触碰未知目录。"""
    try:
        return (
            stage.resolve().parent == parent.resolve()
            and stage.name.startswith(".incomplete-")
            and not stage.is_symlink()
            and stage.stat(follow_symlinks=False).st_ino == identity
        )
    except OSError:
        return False


def render_saved_run(
    run_dir: str | Path,
    selection: PlotSelection,
    *,
    output_root: str | Path = "results/figures",
    display: PlotDisplay | None = None,
) -> FigureSet:
    """先经正式 reader 复验，再将四类图及追溯清单同批无覆盖发布。"""
    if not isinstance(selection, PlotSelection):
        raise TypeError("selection 必须是 PlotSelection。")
    source = Path(run_dir)
    try:
        # 摘要先于 reader：reader 返回后的变化不能成为清单声称的“已验证源”。
        source_hashes = {
            name: _digest(source / name)
            for name in ("trajectory.csv", "metadata.json", "config.json")
        }
    except OSError:
        # 缺失/错误目录仍由 #13 canonical reader 给出原有异常类型与说明。
        load_artifacts(source)
        raise
    record = load_artifacts(source)
    if source_hashes != {name: _digest(source / name) for name in source_hashes}:
        raise ValueError("source run 在读取期间发生变化。")
    display = display or PlotDisplay(selection.time_unit)
    if display.time_unit != selection.time_unit:
        raise ValueError("selection 与 display 的时间单位不一致。")
    for output_index, reference_index in selection.tracking_pairs:
        _series(record, "reference", record.metadata.reference, reference_index)
        _series(record, "output_ideal", record.metadata.output, output_index)
        _series(record, "output_secure", record.metadata.output, output_index)
        if (
            record.metadata.reference.units[reference_index]
            != record.metadata.output.units[output_index]
        ):
            raise ValueError("tracking reference/output 单位不一致，不能共用 y 轴。")
    for control_index in selection.control_channels:
        for field in ("control_ideal", "control_secure", "control_error"):
            _series(record, field, record.metadata.control, control_index)
    output_indices = selection.output_error_channels
    if output_indices is None:
        output_indices = tuple(dict.fromkeys(pair[0] for pair in selection.tracking_pairs))
    for output_index in output_indices:
        _series(record, "output_error", record.metadata.output, output_index)
    parent = Path(output_root) / record.run_id
    parent.mkdir(parents=True, exist_ok=True)
    render_id = _new_render_id()
    if not _RENDER_ID_PATTERN.fullmatch(render_id):
        raise ValueError("render_id 格式无效。")
    stage = parent / f".incomplete-{render_id}"
    final = parent / render_id
    if os.path.lexists(final):
        raise FileExistsError(f"render ID 已存在：{render_id}")
    stage.mkdir(exist_ok=False)
    identity = stage.stat(follow_symlinks=False).st_ino
    entries: list[dict[str, object]] = []

    def save(
        category: str,
        filename: str,
        figure: Figure,
        channels: dict[str, object],
        *,
        zero_count: int = 0,
    ) -> None:
        """每张图写入私有 staging，并把实际图 bytes 与选择规范关联。"""
        path = stage / filename
        try:
            figure.savefig(path, dpi=300, format=selection.format)
        finally:
            figure.clear()
        entries.append(
            {
                "category": category,
                "filename": filename,
                "channels": channels,
                "time_unit": selection.time_unit,
                "control_error_scale": selection.control_error_scale
                if category == "control_error"
                else None,
                "masked_zero_samples": zero_count,
                "sha256": _digest(path),
            }
        )

    try:
        suffix = selection.format
        for output_index, reference_index in selection.tracking_pairs:
            save(
                "tracking",
                f"tracking_output-{output_index}_reference-{reference_index}.{suffix}",
                plot_tracking(record, output_index, reference_index, display),
                {
                    "output": {
                        "index": output_index,
                        "name": record.metadata.output.names[output_index],
                        "unit": record.metadata.output.units[output_index],
                    },
                    "reference": {
                        "index": reference_index,
                        "name": record.metadata.reference.names[reference_index],
                        "unit": record.metadata.reference.units[reference_index],
                    },
                },
            )
        for control_index in selection.control_channels:
            channels = {
                "control": {
                    "index": control_index,
                    "name": record.metadata.control.names[control_index],
                    "unit": record.metadata.control.units[control_index],
                }
            }
            save(
                "control",
                f"control-{control_index}.{suffix}",
                plot_control(record, control_index, display),
                channels,
            )
            save(
                "control_error",
                f"control_error-{control_index}_{selection.control_error_scale}.{suffix}",
                plot_control_error(
                    record, control_index, scale=selection.control_error_scale, display=display
                ),
                channels,
                zero_count=(
                    int(np.count_nonzero(record.result.control_error[:, control_index] == 0))
                    if selection.control_error_scale == "log"
                    else 0
                ),
            )
        for output_index in output_indices:
            save(
                "output_error",
                f"output_error-{output_index}.{suffix}",
                plot_output_error(record, output_index, display),
                {
                    "output": {
                        "index": output_index,
                        "name": record.metadata.output.names[output_index],
                        "unit": record.metadata.output.units[output_index],
                    }
                },
            )
        if source_hashes != {name: _digest(source / name) for name in source_hashes}:
            raise ValueError("source run 在绘图期间发生变化。")
        manifest = {
            "source_run_id": record.run_id,
            "source_schema_version": SCHEMA_VERSION,
            "scenario": {
                "name": record.metadata.name,
                "version": record.effective_config["scenario"]["version"],
            },
            "source_files_sha256": source_hashes,
            "render_id": render_id,
            "matplotlib_version": matplotlib.__version__,
            "figure_format": selection.format,
            "figures": entries,
        }
        (stage / "figures_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            + "\n",
            encoding="utf-8",
        )
        if os.path.lexists(final):
            raise FileExistsError(f"render ID 已存在：{render_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, parent, identity):
            shutil.rmtree(stage)
        raise
    return FigureSet(
        record.run_id,
        render_id,
        tuple(final / entry["filename"] for entry in entries),
        final / "figures_manifest.json",
    )
