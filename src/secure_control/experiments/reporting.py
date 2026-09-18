"""从已验证实验工件原子发布可复现的本地化汇报图。"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import warnings
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Literal

import matplotlib
import numpy as np
import yaml
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from matplotlib.font_manager import FontProperties, findfont
from matplotlib.ft2font import FT2Font

from .artifacts import ExperimentRecord, load_artifacts
from .plotting import FigureStyle, LineStyle, apply_axis_format
from .sweep import SweepRunRecord, SweepRunStatus
from .sweep_artifacts import VerifiedSweepData, load_verified_sweep_data
from .sweep_plotting import select_primary_records, verified_error_series

ReportPriority = Literal["P1", "P2", "P3"]
_RENDER_ID_PATTERN = re.compile(r"\A\d{8}T\d{12}Z-[0-9a-f]{12}\Z")
_SAFE_FILENAME = re.compile(r"\A[\w\u4e00-\u9fff]+\.png\Z", re.UNICODE)


@dataclass(frozen=True, slots=True)
class FontSpec:
    """声明按顺序尝试的本机字体 family。"""

    families: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReportFigureSpec:
    """冻结一张图的顺序、图义、展示文字和来源字段。"""

    sequence: int
    key: str
    filename: str
    priority: ReportPriority
    title: str
    y_label: str
    purpose_zh: str
    speaker_note_zh: str
    source_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReportProfile:
    """冻结本地化展示选择，不改变机器 metadata 与实验数据。"""

    schema_version: int
    locale: str
    primary_seed: int
    representative_ell: int
    time_unit: Literal["s", "h"]
    phase_segments_path: tuple[str, ...]
    channel_names: Mapping[str, str]
    unit_names: Mapping[str, str]
    channel_indices: Mapping[str, int]
    labels: Mapping[str, str]
    limitations_zh: tuple[str, ...]
    font: FontSpec
    style: FigureStyle
    ell_styles: Mapping[int, LineStyle]
    figures: tuple[ReportFigureSpec, ...]


@dataclass(frozen=True, slots=True)
class ResolvedFont:
    """记录实际字体 family、文件和字形预检摘要。"""

    family: str
    path: Path
    sha256: str
    checked_characters: str


@dataclass(frozen=True, slots=True)
class ReportArtifacts:
    """返回一次完整报告发布的路径。"""

    report_id: str
    output_dir: Path
    figure_paths: tuple[Path, ...]
    manifest_path: Path
    catalog_path: Path


def _mapping(value: object, name: str) -> Mapping[str, object]:
    """拒绝将非映射 YAML 节点按 truthiness 静默接受。"""
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} 必须是映射")
    return value


def load_report_profile(path: str | Path) -> ReportProfile:
    """严格读取 UTF-8 展示配置并冻结 01–12 图目录。"""
    source = Path(path)
    loaded = yaml.safe_load(source.read_text(encoding="utf-8"))
    root = _mapping(loaded, "report profile")
    required = {
        "schema_version",
        "locale",
        "primary_seed",
        "representative_ell",
        "time_unit",
        "phase_segments_path",
        "channel_names",
        "unit_names",
        "channel_indices",
        "labels",
        "limitations_zh",
        "font",
        "style",
        "ell_styles",
        "figures",
    }
    if set(root) != required or root["schema_version"] != 1:
        raise ValueError("report profile 字段或 schema_version 无效")
    if root["locale"] != "zh-CN" or root["time_unit"] not in ("s", "h"):
        raise ValueError("locale/time_unit 无效")
    font = _mapping(root["font"], "font")
    families = font.get("families")
    if (
        set(font) != {"families"}
        or not isinstance(families, list)
        or not families
        or not all(isinstance(item, str) and item for item in families)
    ):
        raise ValueError("font.families 必须是非空数组")
    style_data = _mapping(root["style"], "style")
    try:
        style = FigureStyle(**style_data)
    except TypeError as error:
        raise ValueError("style 字段无效") from error
    ell_styles_data = _mapping(root["ell_styles"], "ell_styles")
    try:
        ell_styles = {
            int(key): LineStyle(**_mapping(value, f"ell_styles.{key}"))
            for key, value in ell_styles_data.items()
        }
    except (TypeError, ValueError) as error:
        raise ValueError("ell_styles 的精度键或样式无效") from error
    if not ell_styles or any(ell <= 0 for ell in ell_styles):
        raise ValueError("ell_styles 必须使用正整数精度键")
    figures_data = root["figures"]
    if not isinstance(figures_data, list):
        raise TypeError("figures 必须是数组")
    figures_list: list[ReportFigureSpec] = []
    for raw in figures_data:
        item = dict(_mapping(raw, "figure"))
        fields = item.get("source_fields")
        if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
            raise TypeError("figure.source_fields 必须是字符串数组")
        item["source_fields"] = tuple(fields)
        figures_list.append(ReportFigureSpec(**item))
    figures = tuple(figures_list)
    expected_keys = (
        "tracking",
        "applied_control",
        "control_signed",
        "control_absolute",
        "output_signed",
        "output_absolute",
        "control_time_by_ell",
        "control_metrics_by_ell",
        "output_time_by_ell",
        "output_metrics_by_ell",
        "precision_summary",
        "timing_cost",
    )
    if tuple(item.sequence for item in figures) != tuple(range(1, 13)):
        raise ValueError("figures 必须按 01–12 完整排序")
    if tuple(item.key for item in figures) != expected_keys:
        raise ValueError("figures key 或顺序无效")
    for item in figures:
        if item.priority not in ("P1", "P2", "P3"):
            raise ValueError("figure priority 无效")
        if not _SAFE_FILENAME.fullmatch(item.filename) or not item.filename.startswith(
            f"{item.sequence:02d}_"
        ):
            raise ValueError("figure filename 必须是安全的固定中文编号 PNG 名称")
        if not item.purpose_zh or not item.speaker_note_zh or not item.source_fields:
            raise ValueError("figure 说明和来源字段不能为空")
    path_parts = root["phase_segments_path"]
    if (
        not isinstance(path_parts, list)
        or not path_parts
        or not all(isinstance(item, str) and item for item in path_parts)
    ):
        raise ValueError("phase_segments_path 无效")
    channel_names = _mapping(root["channel_names"], "channel_names")
    unit_names = _mapping(root["unit_names"], "unit_names")
    channel_indices = _mapping(root["channel_indices"], "channel_indices")
    labels = _mapping(root["labels"], "labels")
    if not all(
        isinstance(key, str) and isinstance(value, str) for key, value in channel_names.items()
    ):
        raise TypeError("channel_names 必须是字符串映射")
    if not all(
        isinstance(key, str) and isinstance(value, str) for key, value in unit_names.items()
    ):
        raise TypeError("unit_names 必须是字符串映射")
    if set(channel_indices) != {"reference", "output", "control"} or not all(
        type(value) is int and value >= 0 for value in channel_indices.values()
    ):
        raise ValueError("channel_indices 必须完整声明非负 reference/output/control 索引")
    required_labels = {
        "time_axis",
        "tracking_reference",
        "tracking_ideal",
        "tracking_secure",
        "control_ideal",
        "control_secure",
        "signed_error",
        "absolute_error",
        "zero_count",
        "all_zero",
        "ell",
        "max_abs",
        "mean_abs",
        "rms",
        "precision_axis",
        "control_max_abs",
        "output_max_abs",
        "precision_scale",
        "mean_time",
        "protocol1",
        "protocol2",
        "resource_axis",
    }
    if set(labels) != required_labels or not all(
        isinstance(value, str) and value for value in labels.values()
    ):
        raise ValueError("labels 必须完整声明正式图面文案")
    limitations = root["limitations_zh"]
    if (
        not isinstance(limitations, list)
        or not limitations
        or not all(isinstance(item, str) and item for item in limitations)
    ):
        raise TypeError("limitations_zh 必须是非空字符串数组")
    primary_seed = root["primary_seed"]
    representative_ell = root["representative_ell"]
    if type(primary_seed) is not int or type(representative_ell) is not int:
        raise TypeError("primary_seed/representative_ell 必须是整数")
    return ReportProfile(
        1,
        "zh-CN",
        primary_seed,
        representative_ell,
        root["time_unit"],
        tuple(path_parts),
        MappingProxyType(dict(channel_names)),
        MappingProxyType(dict(unit_names)),
        MappingProxyType(dict(channel_indices)),
        MappingProxyType(dict(labels)),
        tuple(limitations),
        FontSpec(tuple(families)),
        style,
        MappingProxyType(ell_styles),
        figures,
    )


def resolve_report_font(spec: FontSpec, texts: Iterable[str]) -> ResolvedFont:
    """选择实际字体并在绘制前验证本批所有中文字符具有 glyph。"""
    path: Path | None = None
    family = ""
    for candidate in spec.families:
        try:
            resolved = Path(findfont(FontProperties(family=candidate), fallback_to_default=False))
        except ValueError:
            continue
        if resolved.is_file():
            path, family = resolved, candidate
            break
    if path is None:
        raise ValueError("找不到 display profile 声明的中文字体")
    characters = "".join(
        sorted({char for text in texts for char in text if "\u4e00" <= char <= "\u9fff"})
    )
    charmap = FT2Font(str(path)).get_charmap()
    missing = "".join(char for char in characters if ord(char) not in charmap)
    if missing:
        raise ValueError(f"中文字体缺少所需 glyph：{missing}")
    return ResolvedFont(family, path, sha256(path.read_bytes()).hexdigest(), characters)


def _new_render_id() -> str:
    """生成可排序且不覆盖旧报告的渲染标识。"""
    return f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{secrets.token_hex(6)}"


def _digest(path: Path) -> str:
    """计算文件 bytes 的 SHA-256。"""
    return sha256(path.read_bytes()).hexdigest()


def _owned_stage(stage: Path, parent: Path, identity: int) -> bool:
    """异常时只清理本调用创建且未被替换的直属 staging。"""
    try:
        return (
            stage.resolve().parent == parent.resolve()
            and stage.name.startswith(".incomplete-")
            and not stage.is_symlink()
            and stage.stat(follow_symlinks=False).st_ino == identity
        )
    except OSError:
        return False


def _time(record: ExperimentRecord, unit: str) -> np.ndarray:
    """只换算已有采样点，不补造 horizon 终点。"""
    return record.result.time if unit == "s" else record.result.time / 3600.0


def _phase_boundaries(record: ExperimentRecord, profile: ReportProfile) -> tuple[float, ...]:
    """按 profile 声明路径读取阶段边界，拒绝在通用层硬编码场景键。"""
    value: object = record.effective_config
    for part in profile.phase_segments_path:
        value = _mapping(value, part).get(part)
    if not isinstance(value, list) or not value:
        raise ValueError("来源配置缺少阶段列表")
    ends: list[float] = []
    for item in value[:-1]:
        segment = _mapping(item, "phase segment")
        end = segment.get("end_seconds")
        if isinstance(end, bool) or not isinstance(end, (int, float)):
            raise TypeError("阶段 end_seconds 无效")
        ends.append(float(end) if profile.time_unit == "s" else float(end) / 3600.0)
    return tuple(ends)


def _validate_display_mappings(record: ExperimentRecord, profile: ReportProfile) -> None:
    """正式模式不允许机器通道名或单位静默回退到英文。"""
    for channels in (record.metadata.reference, record.metadata.output, record.metadata.control):
        missing_names = set(channels.names) - set(profile.channel_names)
        missing_units = set(channels.units) - set(profile.unit_names)
        if missing_names or missing_units:
            raise ValueError(f"display profile 缺少通道/单位映射：{missing_names or missing_units}")
    for kind, channels, arrays in (
        ("reference", record.metadata.reference, (record.result.reference,)),
        (
            "output",
            record.metadata.output,
            (record.result.output_ideal, record.result.output_secure, record.result.output_error),
        ),
        (
            "control",
            record.metadata.control,
            (
                record.result.control_ideal,
                record.result.control_secure,
                record.result.control_error,
            ),
        ),
    ):
        index = profile.channel_indices[kind]
        if index >= len(channels.names) or any(index >= array.shape[1] for array in arrays):
            raise ValueError(f"display profile 的 {kind} 通道索引越界")


def _display_values(record: ExperimentRecord, profile: ReportProfile) -> dict[str, object]:
    """由 profile 选择 metadata 通道，避免展示层默认猜测第一个领域通道。"""
    values: dict[str, object] = {
        "seconds_unit": profile.unit_names["seconds"],
        "time_unit": profile.time_unit,
    }
    for kind, channels in (
        ("reference", record.metadata.reference),
        ("output", record.metadata.output),
        ("control", record.metadata.control),
    ):
        index = profile.channel_indices[kind]
        values[f"{kind}_name"] = profile.channel_names[channels.names[index]]
        values[f"{kind}_unit"] = profile.unit_names[channels.units[index]]
    return values


def _format_text(template: str, values: Mapping[str, object]) -> str:
    """替换已声明占位符，同时保留 mathtext 使用的花括号。"""
    # ``str.format`` 会把 ``T_{air}`` 误认为 Python 占位符；只替换已声明的展示字段。
    pattern = re.compile("|".join(re.escape("{" + key + "}") for key in values))
    return pattern.sub(lambda match: str(values[match.group()[1:-1]]), template)


def _figure(
    spec: ReportFigureSpec,
    profile: ReportProfile,
    font: ResolvedFont,
    *,
    time_axis: bool,
    boundaries: tuple[float, ...],
    x_range: tuple[float, float],
    display_values: Mapping[str, object],
) -> tuple[Figure, object]:
    """构造统一 16:9 画布、字体、网格、边距和阶段线。"""
    figure = Figure(figsize=(profile.style.width_inches, profile.style.height_inches))
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    prop = FontProperties(fname=str(font.path))
    axis.set_title(
        _format_text(spec.title, display_values),
        fontproperties=prop,
        fontsize=profile.style.title_size,
    )
    axis.set_ylabel(
        _format_text(spec.y_label, display_values),
        fontproperties=prop,
        fontsize=profile.style.label_size,
    )
    axis.tick_params(labelsize=profile.style.tick_size)
    axis.grid(True, which="both", alpha=profile.style.grid_alpha)
    if time_axis:
        axis.set_xlabel(
            _format_text(profile.labels["time_axis"], display_values),
            fontproperties=prop,
            fontsize=profile.style.label_size,
        )
        axis.set_xlim(*x_range)
        for boundary in boundaries:
            axis.axvline(boundary, color="#999999", linestyle="--", linewidth=0.8, alpha=0.7)
    figure.subplots_adjust(left=0.11, right=0.88, top=0.88, bottom=0.22)
    return figure, axis


def _legend(axis: object, font: ResolvedFont, profile: ReportProfile, *, ncol: int = 3) -> None:
    """用固定字体把图例放在图外上方，避免遮挡关键曲线。"""
    axis.legend(
        prop=FontProperties(fname=str(font.path), size=profile.style.legend_size),
        loc="upper center",
        bbox_to_anchor=(0.5, -0.16),
        ncol=ncol,
        frameon=False,
    )


def _single_figure(
    spec: ReportFigureSpec,
    record: ExperimentRecord,
    profile: ReportProfile,
    font: ResolvedFont,
    boundaries: tuple[float, ...],
) -> Figure:
    """从同一个 ExperimentRecord 生成六类单点图。"""
    time = _time(record, profile.time_unit)
    display_values = _display_values(record, profile)
    figure, axis = _figure(
        spec,
        profile,
        font,
        time_axis=True,
        boundaries=boundaries,
        x_range=(float(time[0]), float(time[-1])),
        display_values=display_values,
    )
    width = profile.style.line_width
    if spec.key == "tracking":
        axis.plot(
            time,
            record.result.reference[:, profile.channel_indices["reference"]],
            color="#000000",
            linestyle="--",
            linewidth=width,
            label=_format_text(profile.labels["tracking_reference"], display_values),
        )
        axis.plot(
            time,
            record.result.output_ideal[:, profile.channel_indices["output"]],
            color="#0072B2",
            linewidth=width,
            label=_format_text(profile.labels["tracking_ideal"], display_values),
        )
        axis.plot(
            time,
            record.result.output_secure[:, profile.channel_indices["output"]],
            color="#D55E00",
            linestyle=":",
            linewidth=width,
            label=_format_text(profile.labels["tracking_secure"], display_values),
        )
        _legend(axis, font, profile)
    elif spec.key == "applied_control":
        axis.plot(
            time,
            record.result.control_ideal[:, profile.channel_indices["control"]],
            color="#0072B2",
            linewidth=width,
            marker="o",
            markevery=profile.style.marker_every,
            label=_format_text(profile.labels["control_ideal"], display_values),
        )
        axis.plot(
            time,
            record.result.control_secure[:, profile.channel_indices["control"]],
            color="#D55E00",
            linestyle="--",
            linewidth=width,
            marker="s",
            markevery=profile.style.marker_every,
            label=_format_text(profile.labels["control_secure"], display_values),
        )
        _legend(axis, font, profile, ncol=2)
    else:
        control = spec.key.startswith("control_")
        index = profile.channel_indices["control" if control else "output"]
        error = (
            record.result.control_error[:, index]
            if control
            else record.result.output_error[:, index]
        )
        absolute = spec.key.endswith("absolute")
        if absolute:
            values = np.ma.masked_equal(np.abs(error), 0.0)
            if values.count():
                axis.plot(
                    time,
                    values,
                    color="#CC3311",
                    linewidth=width,
                    label=_format_text(profile.labels["absolute_error"], display_values),
                )
                _legend(axis, font, profile, ncol=1)
            zero_count = int(np.count_nonzero(error == 0.0))
            axis.text(
                0.98,
                0.03,
                _format_text(profile.labels["zero_count"], {**display_values, "count": zero_count}),
                ha="right",
                transform=axis.transAxes,
                fontproperties=FontProperties(fname=str(font.path)),
            )
            if not values.count():
                axis.text(
                    0.5,
                    0.5,
                    _format_text(profile.labels["all_zero"], display_values),
                    ha="center",
                    transform=axis.transAxes,
                    fontproperties=FontProperties(fname=str(font.path)),
                )
            apply_axis_format(axis.yaxis, scale="log", signed=False)
        else:
            axis.plot(
                time,
                error,
                color="#AA3377",
                linewidth=width,
                label=_format_text(profile.labels["signed_error"], display_values),
            )
            _legend(axis, font, profile, ncol=1)
            apply_axis_format(axis.yaxis, scale="linear", signed=True)
    return figure


def _cross_figure(
    spec: ReportFigureSpec,
    data: VerifiedSweepData,
    records: tuple[SweepRunRecord, ...],
    profile: ReportProfile,
    font: ResolvedFont,
    boundaries: tuple[float, ...],
    x_range: tuple[float, float],
    display_values: Mapping[str, object],
) -> Figure:
    """生成跨精度时序、指标、精度汇总与资源附录图。"""
    is_time = spec.key.endswith("time_by_ell")
    figure, axis = _figure(
        spec,
        profile,
        font,
        time_axis=is_time,
        boundaries=boundaries,
        x_range=x_range,
        display_values=display_values,
    )
    if is_time:
        control = spec.key.startswith("control_")
        field = "control_error" if control else "output_error"
        channel_index = profile.channel_indices["control" if control else "output"]
        for ell, raw_time, error in verified_error_series(
            data,
            primary_seed=profile.primary_seed,
            field=field,
            channel_index=channel_index,
        ):
            style = profile.ell_styles[ell]
            values = np.ma.masked_equal(np.abs(error), 0.0)
            axis.plot(
                raw_time if profile.time_unit == "s" else raw_time / 3600.0,
                values,
                color=style.color,
                linestyle=style.linestyle,
                linewidth=profile.style.line_width,
                label=_format_text(profile.labels["ell"], {**display_values, "ell": ell}),
            )
        apply_axis_format(axis.yaxis, scale="log", signed=False)
        _legend(axis, font, profile, ncol=4)
        return figure
    ell = [record.point.ell for record in records]
    if spec.key.endswith("metrics_by_ell"):
        name = "control_error" if spec.key.startswith("control_") else "output_error"
        for metric, marker, label_key in (
            ("max_abs", "o", "max_abs"),
            ("mean_abs", "s", "mean_abs"),
            ("rms", "^", "rms"),
        ):
            axis.plot(
                ell,
                [getattr(getattr(record, name), metric) for record in records],
                marker=marker,
                linewidth=profile.style.line_width,
                label=_format_text(profile.labels[label_key], display_values),
            )
        axis.set_xlabel(
            _format_text(profile.labels["precision_axis"], display_values),
            fontproperties=FontProperties(fname=str(font.path)),
            fontsize=profile.style.label_size,
        )
        apply_axis_format(axis.yaxis, scale="log", signed=False)
        _legend(axis, font, profile)
    elif spec.key == "precision_summary":
        axis.plot(
            ell,
            [record.control_error.max_abs for record in records],
            "o-",
            linewidth=profile.style.line_width,
            label=_format_text(profile.labels["control_max_abs"], display_values),
        )
        axis.plot(
            ell,
            [record.output_error.max_abs for record in records],
            "s-",
            linewidth=profile.style.line_width,
            label=_format_text(profile.labels["output_max_abs"], display_values),
        )
        axis.plot(
            ell,
            [2.0**-value for value in ell],
            "--",
            label=_format_text(profile.labels["precision_scale"], display_values),
        )
        axis.set_xlabel(
            _format_text(profile.labels["precision_axis"], display_values),
            fontproperties=FontProperties(fname=str(font.path)),
            fontsize=profile.style.label_size,
        )
        apply_axis_format(axis.yaxis, scale="log", signed=False)
        _legend(axis, font, profile)
    else:
        all_success = [record for record in data.records if record.status is SweepRunStatus.SUCCESS]
        grouped = {
            value: [record for record in all_success if record.point.ell == value] for value in ell
        }
        axis.bar(
            ell,
            [
                float(np.mean([record.cost.wall_clock_seconds for record in grouped[value]]))
                for value in ell
            ],
            color="#56B4E9",
            alpha=0.7,
            label=_format_text(profile.labels["mean_time"], display_values),
        )
        axis.set_xlabel(
            _format_text(profile.labels["precision_axis"], display_values),
            fontproperties=FontProperties(fname=str(font.path)),
            fontsize=profile.style.label_size,
        )
        other = axis.twinx()
        for field, marker, label_key in (
            ("protocol1_triples_total", "o", "protocol1"),
            ("protocol2_truncations_total", "s", "protocol2"),
        ):
            other.plot(
                ell,
                [
                    float(np.mean([getattr(record.cost, field) for record in grouped[value]]))
                    for value in ell
                ],
                marker=marker,
                linewidth=profile.style.line_width,
                label=_format_text(profile.labels[label_key], display_values),
            )
        other.set_ylabel(
            _format_text(profile.labels["resource_axis"], display_values),
            fontproperties=FontProperties(fname=str(font.path)),
            fontsize=profile.style.label_size,
        )
        handles1, labels1 = axis.get_legend_handles_labels()
        handles2, labels2 = other.get_legend_handles_labels()
        axis.legend(
            handles1 + handles2,
            labels1 + labels2,
            prop=FontProperties(fname=str(font.path), size=profile.style.legend_size),
            loc="upper center",
            bbox_to_anchor=(0.5, -0.16),
            ncol=3,
            frameon=False,
        )
    axis.set_xticks(ell)
    return figure


def _save_figure(figure: Figure, path: Path, profile: ReportProfile) -> None:
    """捕获 missing-glyph warning，失败时不允许发布乱码图。"""
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            figure.savefig(path, dpi=profile.style.dpi, format="png")
        missing = [
            item
            for item in caught
            if "Glyph" in str(item.message) and "missing" in str(item.message)
        ]
        if missing:
            raise ValueError(f"绘图字体缺少 glyph：{missing[0].message}")
    finally:
        figure.clear()


def _index_markdown(
    entries: list[dict[str, object]],
    limitations_zh: tuple[str, ...],
    source_points: list[dict[str, object]] | None = None,
) -> str:
    """从 manifest 同一 entries 生成中文目录，避免两套说明漂移。"""
    lines = ["# 汇报图目录", "", "本目录全部图由已验证工件只读重渲染。", ""]
    for item in entries:
        lines.extend(
            [
                f"## {item['sequence']:02d}. {item['filename']}（{item['priority']}）",
                "",
                f"- 用途：{item['purpose_zh']}",
                f"- 汇报说明：{item['speaker_note_zh']}",
                f"- 来源字段：{', '.join(item['source_fields'])}",
                f"- 必须保留的限制：{'；'.join(item['limitations_zh'])}",
                f"- SHA-256：`{item['sha256']}`",
                "",
            ]
        )
    if source_points is not None:
        lines.extend(
            [
                "## 全部扫描点状态",
                "",
                "| point | ell | seed | status | run ID |",
                "| --- | ---: | ---: | --- | --- |",
                *(
                    f"| {item['point_id']} | {item['ell']} | {item['seed']} | "
                    f"{item['status']} | {item['run_id'] or '-'} |"
                    for item in source_points
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## 统一限制",
            "",
            "；".join(limitations_zh) + "。",
            "",
        ]
    )
    return "\n".join(lines)


def render_chinese_report(
    sweep_dir: str | Path,
    profile_path: str | Path,
    output_root: str | Path,
    *,
    manifest_name: str = "manifest.json",
) -> ReportArtifacts:
    """验证最终 sweep 后将 12 图、manifest 与目录同批原子发布。"""
    if manifest_name != "manifest.json":
        raise ValueError("正式中文 sweep 报告只能验证最终 manifest.json")
    source = Path(sweep_dir)
    profile_source = Path(profile_path)
    profile_hash = _digest(profile_source)
    source_snapshot = {
        name: _digest(source / name) for name in (manifest_name, "data_manifest.json")
    }
    data = load_verified_sweep_data(source, manifest_name=manifest_name)
    profile = load_report_profile(profile_source)
    if tuple(profile.ell_styles) != tuple(data.definition["fractional_bits"]):
        raise ValueError("ell_styles 必须按 sweep definition 完整且有序覆盖全部精度")
    records = select_primary_records(data, profile.primary_seed)
    representative = next(
        (record for record in records if record.point.ell == profile.representative_ell), None
    )
    if representative is None:
        raise ValueError("representative ell 不存在成功的 primary seed 点")
    record = data.runs[representative.point.point_id]
    _validate_display_mappings(record, profile)
    display_values = _display_values(record, profile)
    boundaries = _phase_boundaries(record, profile)
    time = _time(record, profile.time_unit)
    texts = [
        profile.locale,
        *profile.channel_names.values(),
        *profile.unit_names.values(),
        *profile.labels.values(),
    ]
    for spec in profile.figures:
        texts.extend(
            (
                _format_text(spec.title, display_values),
                _format_text(spec.y_label, display_values),
                spec.purpose_zh,
                spec.speaker_note_zh,
            )
        )
    font = resolve_report_font(profile.font, texts)
    report_id = _new_render_id()
    if not _RENDER_ID_PATTERN.fullmatch(report_id):
        raise ValueError("report_id 格式无效")
    parent = Path(output_root) / source.name
    parent.mkdir(parents=True, exist_ok=True)
    stage = parent / f".incomplete-{report_id}"
    final = parent / report_id
    if os.path.lexists(final):
        raise FileExistsError(f"report ID 已存在：{report_id}")
    stage.mkdir(exist_ok=False)
    identity = stage.stat(follow_symlinks=False).st_ino
    entries: list[dict[str, object]] = []
    try:
        for spec in profile.figures:
            if spec.sequence <= 6:
                figure = _single_figure(spec, record, profile, font, boundaries)
            else:
                figure = _cross_figure(
                    spec,
                    data,
                    records,
                    profile,
                    font,
                    boundaries,
                    (float(time[0]), float(time[-1])),
                    display_values,
                )
            path = stage / spec.filename
            _save_figure(figure, path, profile)
            limitations = ["数值来自已验证工件，未重新运行或修改实验"]
            if spec.key == "applied_control":
                limitations.append("控制量是实际 applied control，不是 raw PID output")
            if spec.key.endswith("absolute") or spec.key.endswith("time_by_ell"):
                limitations.append("对数轴精确零值仅掩码，未注入 epsilon")
            if spec.sequence >= 7:
                limitations.append("主图仅画冻结主 seed，全部 seed 和状态保留在 manifest")
            entries.append(
                {
                    "sequence": spec.sequence,
                    "priority": spec.priority,
                    "filename": spec.filename,
                    "purpose_zh": spec.purpose_zh,
                    "speaker_note_zh": spec.speaker_note_zh,
                    "source_fields": list(spec.source_fields),
                    "source_point": {
                        "ell": representative.point.ell,
                        "seed": representative.point.seed,
                    }
                    if spec.sequence <= 6
                    else {
                        "seed": profile.primary_seed,
                        "ell": list(data.definition["fractional_bits"]),
                    },
                    "source_run_id": record.run_id if spec.sequence <= 6 else None,
                    "limitations_zh": limitations,
                    "sha256": _digest(path),
                }
            )
        if source_snapshot != {name: _digest(source / name) for name in source_snapshot}:
            raise ValueError("source sweep 在报告绘制期间发生变化")
        # 再次运行 canonical reader，捕获 manifest 未变但成员在绘图期间被替换的情况。
        load_verified_sweep_data(source, manifest_name=manifest_name)
        if _digest(profile_source) != profile_hash:
            raise ValueError("display profile 在报告绘制期间发生变化")
        artifact_root = source / str(representative.artifact_path)
        source_points = [
            {
                "point_id": item.point.point_id,
                "ell": item.point.ell,
                "seed": item.point.seed,
                "status": item.status.value,
                "run_id": (
                    data.runs[item.point.point_id].run_id
                    if item.status is SweepRunStatus.SUCCESS
                    else None
                ),
            }
            for item in data.records
        ]
        manifest = {
            "schema_version": 1,
            "report_id": report_id,
            "source_sweep_id": source.name,
            "source_manifest_name": manifest_name,
            "source_manifest_sha256": source_snapshot[manifest_name],
            "source_data_manifest_sha256": source_snapshot["data_manifest.json"],
            "source_status_counts": {},
            "source_definition": {
                "fractional_bits": data.definition["fractional_bits"],
                "seeds": data.definition["seeds"],
                "primary_seed": data.definition["primary_seed"],
            },
            "source_git": record.provenance.get("git"),
            "source_points": source_points,
            "representative": {
                "point_id": representative.point.point_id,
                "run_id": record.run_id,
                "files_sha256": {
                    name: _digest(artifact_root / name)
                    for name in ("trajectory.csv", "metadata.json", "config.json")
                },
            },
            "display_profile": {
                "path": profile_source.name,
                "sha256": profile_hash,
                "locale": profile.locale,
            },
            "font": {
                "family": font.family,
                "path": str(font.path),
                "sha256": font.sha256,
                "glyph_preflight": True,
                "checked_characters": font.checked_characters,
            },
            "matplotlib_version": matplotlib.__version__,
            "layout_contract": {
                "time_unit": profile.time_unit,
                "time_range": [float(time[0]), float(time[-1])],
                "phase_boundaries": list(boundaries),
                "ell_order": list(data.definition["fractional_bits"]),
                "ell_styles": {
                    str(ell): {"color": style.color, "linestyle": style.linestyle}
                    for ell, style in profile.ell_styles.items()
                },
                "canvas_pixels": [
                    round(profile.style.width_inches * profile.style.dpi),
                    round(profile.style.height_inches * profile.style.dpi),
                ],
            },
            "figures": entries,
            "limitations": list(profile.limitations_zh),
        }
        # Counter 缺少的状态显式保留为零，不能通过 success 过滤隐藏状态维度。
        counts = Counter(item.status.value for item in data.records)
        manifest["source_status_counts"] = {
            name: counts.get(name, 0) for name in ("failed", "infeasible", "success")
        }
        (stage / "report_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (stage / "汇报图目录.md").write_text(
            _index_markdown(entries, profile.limitations_zh, source_points),
            encoding="utf-8",
            newline="\n",
        )
        if source_snapshot != {name: _digest(source / name) for name in source_snapshot}:
            raise ValueError("source sweep 在发布前发生变化")
        load_verified_sweep_data(source, manifest_name="manifest.json")
        if _digest(profile_source) != profile_hash:
            raise ValueError("display profile 在发布前发生变化")
        if os.path.lexists(final):
            raise FileExistsError(f"report ID 已存在：{report_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, parent, identity):
            shutil.rmtree(stage)
        raise
    return ReportArtifacts(
        report_id,
        final,
        tuple(final / item.filename for item in profile.figures),
        final / "report_manifest.json",
        final / "汇报图目录.md",
    )


def render_chinese_saved_run(
    run_dir: str | Path, profile_path: str | Path, output_root: str | Path
) -> ReportArtifacts:
    """从单个 canonical run 只读生成 01–06 中文图，保留旧 CLI 默认语义。"""
    source = Path(run_dir)
    profile_source = Path(profile_path)
    profile_hash = _digest(profile_source)
    snapshot = {
        name: _digest(source / name) for name in ("trajectory.csv", "metadata.json", "config.json")
    }
    record = load_artifacts(source)
    profile = load_report_profile(profile_source)
    _validate_display_mappings(record, profile)
    display_values = _display_values(record, profile)
    boundaries = _phase_boundaries(record, profile)
    texts = [
        text
        for item in profile.figures[:6]
        for text in (
            _format_text(item.title, display_values),
            _format_text(item.y_label, display_values),
            item.purpose_zh,
            item.speaker_note_zh,
        )
    ]
    font = resolve_report_font(profile.font, texts)
    report_id = _new_render_id()
    parent = Path(output_root) / record.run_id
    parent.mkdir(parents=True, exist_ok=True)
    stage, final = parent / f".incomplete-{report_id}", parent / report_id
    if os.path.lexists(final):
        raise FileExistsError(f"report ID 已存在：{report_id}")
    stage.mkdir(exist_ok=False)
    identity = stage.stat(follow_symlinks=False).st_ino
    entries: list[dict[str, object]] = []
    try:
        for spec in profile.figures[:6]:
            path = stage / spec.filename
            _save_figure(_single_figure(spec, record, profile, font, boundaries), path, profile)
            entries.append(
                {
                    "sequence": spec.sequence,
                    "priority": spec.priority,
                    "filename": spec.filename,
                    "purpose_zh": spec.purpose_zh,
                    "speaker_note_zh": spec.speaker_note_zh,
                    "source_fields": list(spec.source_fields),
                    "limitations_zh": ["数值来自已验证工件，未重新运行或修改实验"],
                    "sha256": _digest(path),
                }
            )
        if snapshot != {name: _digest(source / name) for name in snapshot}:
            raise ValueError("source run 在绘图期间发生变化")
        manifest = {
            "schema_version": 1,
            "report_id": report_id,
            "source_run_id": record.run_id,
            "source_files_sha256": snapshot,
            "display_profile_sha256": profile_hash,
            "font": {
                "family": font.family,
                "path": str(font.path),
                "sha256": font.sha256,
                "glyph_preflight": True,
            },
            "figures": entries,
        }
        (stage / "report_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (stage / "汇报图目录.md").write_text(
            _index_markdown(entries, profile.limitations_zh), encoding="utf-8", newline="\n"
        )
        if snapshot != {name: _digest(source / name) for name in snapshot}:
            raise ValueError("source run 在发布前发生变化")
        # 在 rename 前重走 canonical reader，确保源三文件没有在目录生成期间被替换。
        load_artifacts(source)
        if _digest(profile_source) != profile_hash:
            raise ValueError("display profile 在发布前发生变化")
        if os.path.lexists(final):
            raise FileExistsError(f"report ID 已存在：{report_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, parent, identity):
            shutil.rmtree(stage)
        raise
    return ReportArtifacts(
        report_id,
        final,
        tuple(final / item.filename for item in profile.figures[:6]),
        final / "report_manifest.json",
        final / "汇报图目录.md",
    )
