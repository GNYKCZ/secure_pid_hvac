"""只读组合 verified sweep 与 sanitized evidence 的中文增强报告。"""

from __future__ import annotations

import csv
import json
import os
import re
import secrets
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal

import matplotlib
import numpy as np
import yaml
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from matplotlib.font_manager import FontProperties
from matplotlib.patches import FancyBboxPatch

from secure_control.simulation import SimulationResult

from .evidence_artifacts import VerifiedEvidenceData, load_verified_evidence_artifacts
from .plotting import apply_axis_format
from .reporting import (
    ReportProfile,
    ResolvedFont,
    _cross_figure,
    _display_values,
    _phase_boundaries,
    _save_figure,
    _single_figure,
    _time,
    _validate_display_mappings,
    load_report_profile,
    resolve_report_font,
)
from .sweep import SweepRunRecord, SweepRunStatus
from .sweep_artifacts import VerifiedSweepData, load_verified_sweep_data
from .sweep_plotting import select_primary_records

_REPORT_ID_PATTERN = re.compile(r"\A\d{8}T\d{12}Z-[0-9a-f]{12}\Z")
_MAIN_ORDER = (
    "dual_path_architecture",
    "selected_secure_trace",
    "integer_decode_applied",
    "controller_state_transition",
    "tracking",
    "applied_control",
    "fig3_adapted",
    "normalized_precision",
    "quantitative_table",
    "resource_and_timing",
)
_RESULT_FIELDS = (
    "time",
    "reference",
    "output_ideal",
    "output_secure",
    "control_ideal",
    "control_secure",
    "control_error",
    "output_error",
)


@dataclass(frozen=True, slots=True)
class EvidenceReportProfile:
    """冻结增强报告来源、分钟轴、选定 step、分段与声明边界。"""

    locale: str
    source_sweep_id: str
    source_manifest_sha256: str
    source_data_manifest_sha256: str
    base_profile_path: Path
    representative_ell: int
    representative_seed: int
    selected_step: int
    time_unit: Literal["min"]
    segments_minutes: tuple[tuple[int, int], ...]
    fig3_control_semantics: Literal["applied"]
    diagnostic_rng_mode: Literal["reproducibility_only"]
    deployment_security: Literal[False]
    main_order: tuple[str, ...]
    limitations_zh: tuple[str, ...]
    source_path: Path


@dataclass(frozen=True, slots=True)
class EvidenceReportArtifacts:
    """返回一次增强报告的身份、目录、manifest 与两级中文目录。"""

    report_id: str
    output_dir: Path
    manifest_path: Path
    main_catalog_path: Path
    appendix_catalog_path: Path
    table_csv_path: Path
    table_markdown_path: Path


def load_evidence_report_profile(path: str | Path) -> EvidenceReportProfile:
    """严格读取 Issue #51 profile，并相对配置目录解析复用的 #48 profile。"""
    source = Path(path)
    loaded = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise TypeError("evidence report profile 必须是映射。")
    required = {
        "schema_version",
        "locale",
        "source_sweep_id",
        "source_manifest_sha256",
        "source_data_manifest_sha256",
        "base_profile",
        "representative_ell",
        "representative_seed",
        "selected_step",
        "time_unit",
        "segments_minutes",
        "fig3_control_semantics",
        "diagnostic_rng_mode",
        "deployment_security",
        "main_order",
        "limitations_zh",
    }
    if set(loaded) != required or loaded["schema_version"] != 1:
        raise ValueError("evidence report profile 字段或 schema_version 无效。")
    if (
        loaded["locale"] != "zh-CN"
        or loaded["time_unit"] != "min"
        or loaded["fig3_control_semantics"] != "applied"
        or loaded["diagnostic_rng_mode"] != "reproducibility_only"
        or loaded["deployment_security"] is not False
    ):
        raise ValueError("evidence report 的 locale/time/control/RNG/security 语义无效。")
    for name in ("source_manifest_sha256", "source_data_manifest_sha256"):
        if not _is_sha256(loaded[name]):
            raise ValueError(f"{name} 必须是 SHA-256。")
    source_sweep_id = loaded["source_sweep_id"]
    if (
        not isinstance(source_sweep_id, str)
        or not source_sweep_id
        or source_sweep_id in {".", ".."}
        or Path(source_sweep_id).name != source_sweep_id
        or "/" in source_sweep_id
        or "\\" in source_sweep_id
    ):
        raise ValueError("source_sweep_id 必须是安全的单级目录名。")
    integers = (
        loaded["representative_ell"],
        loaded["representative_seed"],
        loaded["selected_step"],
    )
    if any(type(value) is not int for value in integers) or integers[0] <= 0 or integers[2] < 0:
        raise ValueError("representative ell/seed/selected step 无效。")
    segments = loaded["segments_minutes"]
    if (
        not isinstance(segments, list)
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or any(type(value) is not int for value in item)
            or item[0] >= item[1]
            for item in segments
        )
        or [item[0] for item in segments] != [0, 60, 120]
        or [item[1] for item in segments] != [60, 120, 180]
    ):
        raise ValueError("segments_minutes 必须恰为三个连续半开 60 min 分段。")
    main_order = loaded["main_order"]
    limitations = loaded["limitations_zh"]
    if (
        not isinstance(main_order, list)
        or tuple(main_order) != _MAIN_ORDER
        or any(not isinstance(item, str) or not item for item in main_order)
        or not isinstance(limitations, list)
        or not limitations
        or any(not isinstance(item, str) or not item for item in limitations)
    ):
        raise ValueError("main_order 必须等于冻结主论证顺序，limitations_zh 必须非空。")
    base = loaded["base_profile"]
    if not isinstance(base, str) or Path(base).name != base:
        raise ValueError("base_profile 必须是同目录安全文件名。")
    return EvidenceReportProfile(
        locale="zh-CN",
        source_sweep_id=source_sweep_id,
        source_manifest_sha256=loaded["source_manifest_sha256"],
        source_data_manifest_sha256=loaded["source_data_manifest_sha256"],
        base_profile_path=source.parent / base,
        representative_ell=integers[0],
        representative_seed=integers[1],
        selected_step=integers[2],
        time_unit="min",
        segments_minutes=tuple((item[0], item[1]) for item in segments),
        fig3_control_semantics="applied",
        diagnostic_rng_mode="reproducibility_only",
        deployment_security=False,
        main_order=tuple(main_order),
        limitations_zh=tuple(limitations),
        source_path=source,
    )


def render_evidence_report(
    *,
    verified_sweep: VerifiedSweepData,
    verified_evidence: VerifiedEvidenceData,
    profile: EvidenceReportProfile,
    output_root: Path,
) -> EvidenceReportArtifacts:
    """从两个 verified reader 的内存结果生成报告，绝不运行 simulation/runtime。"""
    _validate_inputs(verified_sweep, verified_evidence, profile)
    base_profile = replace(load_report_profile(profile.base_profile_path), time_unit="min")
    records = select_primary_records(verified_sweep, profile.representative_seed)
    representative = next(item for item in records if item.point.ell == profile.representative_ell)
    record = verified_sweep.runs[representative.point.point_id]
    _validate_display_mappings(record, base_profile)
    display_values = _display_values(record, base_profile)
    boundaries = _phase_boundaries(record, base_profile)
    time_minutes = _time(record, "min")
    if time_minutes.size != 180 or not np.array_equal(time_minutes, np.arange(180, dtype=float)):
        raise ValueError("正式 HVAC 分钟轴必须保留 k=0..179 的全部 180 点。")
    font = resolve_report_font(
        base_profile.font,
        (
            *base_profile.labels.values(),
            *profile.limitations_zh,
            "明文与安全计算双路径",
            "单步安全执行轨迹",
            "控制器状态更新证据",
            "无量纲精度影响",
            "协议资源累计与逐步增量",
        ),
    )
    source_snapshot = _source_snapshot(verified_sweep, verified_evidence, profile)
    report_id = _new_report_id()
    parent = Path(output_root) / profile.source_sweep_id
    parent.mkdir(parents=True, exist_ok=True)
    stage, final = parent / f".incomplete-{report_id}", parent / report_id
    if os.path.lexists(final):
        raise FileExistsError(f"evidence report ID 已存在：{report_id}")
    stage.mkdir(exist_ok=False)
    identity = stage.stat(follow_symlinks=False).st_ino
    main_dir = stage / "主汇报"
    appendix_dir = stage / "附录"
    legacy_dir = appendix_dir / "Issue48十二图"
    main_dir.mkdir()
    appendix_dir.mkdir()
    legacy_dir.mkdir()
    entries: list[dict[str, object]] = []
    try:
        _render_main_figures(
            main_dir,
            entries,
            record,
            records,
            verified_sweep,
            verified_evidence,
            profile,
            base_profile,
            font,
            boundaries,
            display_values,
        )
        _render_segment_figures(
            appendix_dir,
            entries,
            record,
            verified_evidence,
            profile,
            base_profile,
            font,
        )
        _render_legacy_figures(
            legacy_dir,
            entries,
            record,
            records,
            verified_sweep,
            representative,
            base_profile,
            font,
            boundaries,
            display_values,
            time_minutes,
        )
        table_rows = _quantitative_rows(verified_sweep, profile)
        table_csv = stage / "四精度定量总表.csv"
        table_md = stage / "四精度定量总表.md"
        _write_quantitative_table(table_csv, table_md, table_rows)
        entries.extend(
            (
                _file_entry(
                    stage,
                    table_csv,
                    "table",
                    "四精度完整机器可读定量表",
                    "主汇报",
                    artifact_key="quantitative_table",
                ),
                _file_entry(
                    stage,
                    table_md,
                    "table",
                    "四精度中文定量表",
                    "主汇报",
                    artifact_key="quantitative_table",
                ),
            )
        )
        _sort_main_entries(entries, profile.main_order)
        main_catalog = stage / "主汇报目录.md"
        appendix_catalog = stage / "附录目录.md"
        main_catalog.write_text(
            _catalog("主汇报目录", entries, "主汇报", profile.limitations_zh),
            encoding="utf-8",
            newline="\n",
        )
        appendix_catalog.write_text(
            _catalog("附录目录", entries, "附录", profile.limitations_zh),
            encoding="utf-8",
            newline="\n",
        )
        entries.extend(
            (
                _file_entry(stage, main_catalog, "catalog", "主汇报顺序与讲解说明", "主汇报"),
                _file_entry(stage, appendix_catalog, "catalog", "附录顺序与讲解说明", "附录"),
            )
        )
        manifest = {
            "schema_version": 1,
            "report_id": report_id,
            "source_sweep_id": profile.source_sweep_id,
            "source_manifest_sha256": profile.source_manifest_sha256,
            "source_data_manifest_sha256": profile.source_data_manifest_sha256,
            "source_evidence": {
                "trace_id": verified_evidence.metadata["trace_id"],
                "manifest_sha256": source_snapshot["evidence_manifest"],
                "private_audit": verified_evidence.metadata["private_audit"],
            },
            "display_profile": {
                "filename": profile.source_path.name,
                "sha256": source_snapshot["evidence_profile"],
                "base_profile_filename": profile.base_profile_path.name,
                "base_profile_sha256": source_snapshot["base_profile"],
                "time_unit": "min",
            },
            "representative": {
                "ell": profile.representative_ell,
                "seed": profile.representative_seed,
                "selected_step": profile.selected_step,
                "run_id": record.run_id,
            },
            "segments": [list(item) for item in profile.segments_minutes],
            "fig3_control_semantics": "applied",
            "font": {
                "family": font.family,
                "sha256": font.sha256,
                "glyph_preflight": True,
            },
            "matplotlib_version": matplotlib.__version__,
            "artifacts": entries,
            "limitations": list(profile.limitations_zh),
        }
        (stage / "report_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        _validate_prepublish(verified_sweep, verified_evidence, profile, source_snapshot)
        if os.path.lexists(final):
            raise FileExistsError(f"evidence report ID 已存在：{report_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, parent, identity):
            shutil.rmtree(stage)
        raise
    return EvidenceReportArtifacts(
        report_id,
        final,
        final / "report_manifest.json",
        final / "主汇报目录.md",
        final / "附录目录.md",
        final / "四精度定量总表.csv",
        final / "四精度定量总表.md",
    )


def render_verified_evidence_report(
    *, sweep_dir: Path, evidence_dir: Path, profile_path: Path, output_root: Path
) -> EvidenceReportArtifacts:
    """CLI 友好的 verified reader 组合入口。"""
    return render_evidence_report(
        verified_sweep=load_verified_sweep_data(sweep_dir, manifest_name="manifest.json"),
        verified_evidence=load_verified_evidence_artifacts(evidence_dir),
        profile=load_evidence_report_profile(profile_path),
        output_root=output_root,
    )


def _validate_inputs(
    sweep: VerifiedSweepData,
    evidence: VerifiedEvidenceData,
    profile: EvidenceReportProfile,
) -> None:
    """绑定 sweep/evidence/profile lineage，并拒绝缺失 point、step 或 raw-share 泄漏。"""
    if sweep.root.name != profile.source_sweep_id:
        raise ValueError("profile source_sweep_id 与 verified sweep 不一致。")
    if _digest(sweep.root / "manifest.json") != profile.source_manifest_sha256:
        raise ValueError("profile source_manifest_sha256 与 verified sweep 不一致。")
    if _digest(sweep.root / "data_manifest.json") != profile.source_data_manifest_sha256:
        raise ValueError("profile source_data_manifest_sha256 与 verified sweep 不一致。")
    if evidence.metadata.get("source_sweep_id") != profile.source_sweep_id:
        raise ValueError("evidence lineage 与 verified sweep 不一致。")
    source_hashes = evidence.metadata.get("source_hashes")
    if not isinstance(source_hashes, dict) or (
        source_hashes.get("manifest.json"),
        source_hashes.get("data_manifest.json"),
    ) != (profile.source_manifest_sha256, profile.source_data_manifest_sha256):
        raise ValueError("evidence source hashes 与冻结 profile 不一致。")
    point = evidence.metadata.get("source_point")
    if not isinstance(point, dict) or (point.get("ell"), point.get("seed")) != (
        profile.representative_ell,
        profile.representative_seed,
    ):
        raise ValueError("evidence representative point 与 profile 不一致。")
    if evidence.metadata.get("selected_step") != profile.selected_step:
        raise ValueError("evidence selected step 与 profile 不一致。")
    if evidence.metadata.get("diagnostic_rng_mode") != profile.diagnostic_rng_mode:
        raise ValueError("evidence diagnostic RNG mode 无效。")
    if evidence.metadata.get("deployment_security") is not False:
        raise ValueError("combined diagnostic 不得声明 deployment security。")
    equivalence = evidence.metadata.get("result_equivalence")
    if equivalence != {
        "comparison": "dtype_shape_and_array_equal",
        "fields": list(_RESULT_FIELDS),
        "all_equal": True,
    }:
        raise ValueError("diagnostic reproduction 未通过八字段严格等价门禁。")
    successful = {
        (item.point.ell, item.point.seed)
        for item in sweep.records
        if item.status is SweepRunStatus.SUCCESS
    }
    if (profile.representative_ell, profile.representative_seed) not in successful:
        raise ValueError("profile representative point 不是成功点。")
    seeds = {item.point.seed for item in sweep.records if item.status is SweepRunStatus.SUCCESS}
    if seeds != {42, 43, 44}:
        raise ValueError("增强报告必须完整包含 seeds 42/43/44。")


def _render_main_figures(
    directory: Path,
    entries: list[dict[str, object]],
    record: SimulationResult,
    records: tuple[SweepRunRecord, ...],
    sweep: VerifiedSweepData,
    evidence: VerifiedEvidenceData,
    profile: EvidenceReportProfile,
    base: ReportProfile,
    font: ResolvedFont,
    boundaries: tuple[float, ...],
    display_values: Mapping[str, object],
) -> None:
    """生成主论证链：路径、单步、整数、状态、结果、Fig.3、精度与成本。"""
    figures = (
        (
            "01_明文与安全计算双路径.png",
            _dual_path_figure(base, font),
            "dual_path_architecture",
            "证明明文与安全计算使用两套独立闭环。",
        ),
        (
            "02_k60单步安全执行轨迹.png",
            _selected_trace_figure(evidence, base, font),
            "selected_secure_trace",
            "展示 k=60 的真实编码、重构、decode 与 applied 链。",
        ),
        (
            "03_整数解码与实际控制.png",
            _integer_decode_figure(evidence, profile, base, font),
            "integer_decode_applied",
            "展示完整 180 点 centered integer、局部十进制原值、真实 decode 公式与 applied control。",
        ),
        (
            "04_控制器状态更新证据.png",
            _state_transition_figure(evidence, base, font),
            "controller_state_transition",
            "证明输出读取 x_c(k)，并提交 x_c(k+1)。",
        ),
        (
            "05_温度闭环跟踪_分钟.png",
            _single_figure(base.figures[0], record, base, font, boundaries),
            "tracking",
            "展示 180 分钟温度闭环跟踪。",
        ),
        (
            "06_实际控制输入_分钟.png",
            _single_figure(base.figures[1], record, base, font, boundaries),
            "applied_control",
            "展示实际施加给 plant 的明文/安全控制。",
        ),
        (
            "07_Fig3_adapted_applied_control.png",
            _fig3_figure(sweep, records, base, font),
            "fig3_adapted",
            "按真实 k=0..179 比较四精度 applied control error。",
        ),
        (
            "08_无量纲精度影响.png",
            _normalized_precision_figure(records, base, font),
            "normalized_precision",
            "以 ell=32 为基准比较无量纲控制/温度误差。",
        ),
        (
            "09_协议资源与执行时间.png",
            _resource_timing_figure(sweep, evidence, base, font),
            "resource_and_timing",
            "区分 wall-clock mean±sample std、exact 总资源及逐步累计/增量。",
        ),
    )
    for filename, figure, key, purpose in figures:
        path = directory / filename
        _save_figure(figure, path, base)
        entries.append(_figure_entry(directory.parent, path, key, purpose, "主汇报"))

    raw_path = directory.parent / "附录" / "10_raw_control数值机制误差.png"
    _save_figure(_raw_control_error_figure(evidence, base, font), raw_path, base)
    entries.append(
        _figure_entry(
            directory.parent,
            raw_path,
            "raw_control_diagnostic",
            "只用于数值机制诊断的 |u_raw-û_raw|，不属于 Fig. 3 adapted 指标。",
            "附录",
        )
    )


def _render_segment_figures(
    directory: Path,
    entries: list[dict[str, object]],
    record: SimulationResult,
    evidence: VerifiedEvidenceData,
    profile: EvidenceReportProfile,
    base: ReportProfile,
    font: ResolvedFont,
) -> None:
    """按 [0,60)、[60,120)、[120,180) 生成无重复无遗漏四联图。"""
    rows = [row for row in evidence.integer_control_rows if row["channel"] == 0]
    for index, (start, end) in enumerate(profile.segments_minutes, start=1):
        selected = np.arange(start, end)
        if selected.size != 60:
            raise ValueError("每个正式 HVAC segment 必须恰含 60 个样本。")
        figure = Figure(
            figsize=(base.style.width_inches, base.style.height_inches), layout="constrained"
        )
        FigureCanvasAgg(figure)
        axes = figure.subplots(2, 2)
        font_prop = FontProperties(fname=str(font.path))
        time = record.result.time[selected] / 60.0
        axes[0, 0].plot(time, record.result.reference[selected, 0], label="参考温度")
        axes[0, 0].plot(time, record.result.output_ideal[selected, 0], label="明文空气温度")
        axes[0, 0].plot(
            time, record.result.output_secure[selected, 0], "--", label="安全计算空气温度"
        )
        axes[0, 1].plot(time, record.result.control_ideal[selected, 0], label="明文 applied u")
        axes[0, 1].plot(
            time, record.result.control_secure[selected, 0], "--", label="安全 applied û"
        )
        signed = np.array([rows[step]["signed_applied_error"] for step in selected])
        axes[1, 0].plot(time, signed)
        axes[1, 1].plot(time, np.abs(signed))
        for axis, title in zip(
            axes.flat,
            ("温度跟踪", "实际控制输入", "有符号控制误差", "绝对控制误差"),
            strict=True,
        ):
            axis.set_title(title, fontproperties=font_prop)
            axis.set_xlabel("时间（min）", fontproperties=font_prop)
            axis.grid(True, alpha=base.style.grid_alpha)
            axis.set_xlim(start, end)
        axes[0, 0].legend(prop=font_prop)
        axes[0, 1].legend(prop=font_prop)
        filename = f"{10 + index:02d}_分段_{start:03d}_{end:03d}min.png"
        path = directory / filename
        _save_figure(figure, path, base)
        entries.append(
            _figure_entry(
                directory.parent,
                path,
                f"segment_{start}_{end}",
                f"半开区间 [{start},{end}) min 的 60 个真实样本，无重复或遗漏。",
                "附录",
            )
        )


def _render_legacy_figures(
    directory: Path,
    entries: list[dict[str, object]],
    record: SimulationResult,
    records: tuple[SweepRunRecord, ...],
    sweep: VerifiedSweepData,
    representative: SweepRunRecord,
    base: ReportProfile,
    font: ResolvedFont,
    boundaries: tuple[float, ...],
    display_values: Mapping[str, object],
    time_minutes: np.ndarray,
) -> None:
    """完整保留 #48 的 01–12 类别，并统一用分钟轴重新渲染。"""
    for spec in base.figures:
        figure = (
            _single_figure(spec, record, base, font, boundaries)
            if spec.sequence <= 6
            else _cross_figure(
                spec,
                sweep,
                records,
                base,
                font,
                boundaries,
                (float(time_minutes[0]), float(time_minutes[-1])),
                display_values,
            )
        )
        path = directory / spec.filename
        _save_figure(figure, path, base)
        entries.append(
            _figure_entry(
                directory.parents[1],
                path,
                f"issue48_{spec.key}",
                spec.purpose_zh,
                "附录",
                note=(
                    "Issue #48 原有类别在增强报告中保留；其中旧精度汇总由主汇报无量纲图替代解释。"
                    if spec.key == "precision_summary"
                    else spec.speaker_note_zh
                ),
            )
        )


def _dual_path_figure(profile: ReportProfile, font: ResolvedFont) -> Figure:
    """绘制两套 plant/runtime 独立的路径图，不把输出汇入同一 plant。"""
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    axis.set_axis_off()
    font_prop = FontProperties(fname=str(font.path), size=9)
    paths = (
        (
            0.70,
            "明文路径",
            (
                "reference\n/ output",
                "明文 controller\n/ runtime",
                "raw u(k)",
                "actuator\n/ 明文 plant",
            ),
            "#0072B2",
        ),
        (
            0.31,
            "安全计算路径",
            (
                "reference\n/ output",
                "encode 与\nP1/P2 shares",
                "安全算术\n与 Beaver",
                "Client 重构\ncentered / decode",
                "actuator\n/ 安全 plant",
            ),
            "#D55E00",
        ),
    )
    for y, label, boxes, color in paths:
        axis.text(0.01, y, label, fontproperties=font_prop, color=color, weight="bold")
        xs = np.linspace(0.18, 0.89, len(boxes))
        width = 0.14 if len(boxes) == 5 else 0.17
        height = 0.11
        for box_index, (x, text) in enumerate(zip(xs, boxes, strict=True)):
            axis.add_patch(
                FancyBboxPatch(
                    (x - width / 2, y - height / 2),
                    width,
                    height,
                    boxstyle="round,pad=0.01",
                    facecolor="white",
                    edgecolor=color,
                    linewidth=1.3,
                )
            )
            axis.text(
                x,
                y,
                text,
                ha="center",
                va="center",
                fontproperties=font_prop,
            )
            if box_index:
                axis.annotate(
                    "",
                    xy=(x - width / 2 - 0.01, y),
                    xytext=(xs[box_index - 1] + width / 2 + 0.01, y),
                    arrowprops={"arrowstyle": "->", "color": color},
                )
    axis.text(
        0.5,
        0.06,
        "同时查看 P1/P2 share 仅是显式离线组合诊断视图，不代表部署中的任一参与方同时持有两份 share。",
        ha="center",
        fontproperties=font_prop,
    )
    axis.set_title(
        "明文与安全计算双路径",
        fontproperties=FontProperties(fname=str(font.path), size=profile.style.title_size),
    )
    return figure


def _selected_trace_figure(
    evidence: VerifiedEvidenceData, profile: ReportProfile, font: ResolvedFont
) -> Figure:
    """用 sanitized k=60 数值展示真实 secure execution stage 顺序。"""
    selected = evidence.selected_step
    input_value = selected["controller_input"]["centered"][0]
    raw = selected["raw_control"]
    decoded = selected["decoded_raw_control"][0]
    row = next(
        row
        for row in evidence.integer_control_rows
        if row["step"] == selected["step"] and row["channel"] == 0
    )

    def summarized_integer(value: object) -> str:
        """图上保留首尾与位数；完整十进制整数由 selected JSON 无损保存。"""
        text = str(value)
        return text if len(text) <= 28 else f"{text[:14]}…{text[-14:]}（{len(text)} 位）"

    stages = (
        (
            "controller input",
            f"centered={summarized_integer(input_value)}；ell={selected['controller_input']['fractional_bits']}",
        ),
        (
            "P1/P2 安全算术",
            f"资源 ID 哈希 {len(selected['resource_id_sha256'])} 个；不公开 triple 明文",
        ),
        ("Z_q 重构", f"residue={summarized_integer(raw['residue'][0])}"),
        (
            "centered integer",
            f"{summarized_integer(raw['centered'][0])}；ell={raw['fractional_bits']}",
        ),
        ("decode raw û", f"{decoded:.12g}"),
        ("actuator applied û", f"{row['applied_secure_control']:.12g}"),
    )
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    axis.set_axis_off()
    ys = np.linspace(0.82, 0.25, len(stages))
    font_prop = FontProperties(fname=str(font.path), size=10)
    for index, (name, value) in enumerate(stages):
        y = ys[index]
        axis.text(
            0.20,
            y,
            name,
            ha="right",
            va="center",
            fontproperties=font_prop,
            weight="bold",
        )
        axis.text(
            0.25,
            y,
            value,
            ha="left",
            va="center",
            fontproperties=font_prop,
            bbox={
                "boxstyle": "round,pad=0.35",
                "facecolor": "#F2F2F2",
                "edgecolor": "#333333",
            },
        )
        if index:
            axis.annotate(
                "",
                xy=(0.225, y + 0.03),
                xytext=(0.225, ys[index - 1] - 0.03),
                arrowprops={"arrowstyle": "->"},
            )
    axis.text(
        0.5,
        0.10,
        "完整整数见 selected_step_trace.json；share 重构已在本地审计通过，最终报告不含 raw shares。",
        ha="center",
        fontproperties=font_prop,
    )
    axis.set_title(
        f"k={selected['step']} 单步安全执行轨迹",
        fontproperties=FontProperties(fname=str(font.path), size=profile.style.title_size),
    )
    return figure


def _integer_decode_figure(
    evidence: VerifiedEvidenceData,
    evidence_profile: EvidenceReportProfile,
    profile: ReportProfile,
    font: ResolvedFont,
) -> Figure:
    """绘制 180 步整数证据、真实十进制窗口与 decode/applied 对应。"""
    data = _integer_decode_data(evidence, evidence_profile.selected_step)
    step = data["step"]
    integers = data["integers"]
    raw = data["raw"]
    applied = data["applied"]
    fractional_bits = data["fractional_bits"]
    exponent = max(len(str(abs(value))) - 1 for value in integers if value != 0)
    display_scale = 10**exponent
    scaled = np.array([value / display_scale for value in integers], dtype=float)
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    grid = figure.add_gridspec(2, 2, width_ratios=(1.75, 1.0))
    upper = figure.add_subplot(grid[0, 0])
    table_axis = figure.add_subplot(grid[0, 1])
    lower = figure.add_subplot(grid[1, :], sharex=upper)
    upper.plot(
        step,
        scaled,
        marker="o",
        markevery=profile.style.marker_every,
        markersize=4,
        linewidth=0.8,
        label="180 个真实 secure step",
    )
    lower.plot(step, raw, label="decode 后 raw û")
    lower.plot(step, applied, "--", label="actuator 后 applied û")
    font_prop = FontProperties(fname=str(font.path))
    upper.set_ylabel(f"centered integer / 10^{exponent}", fontproperties=font_prop)
    upper.set_xlabel("离散步 k", fontproperties=font_prop)
    upper.legend(prop=font_prop)
    upper.text(
        0.01,
        0.03,
        "仅为绘图显示缩放；底层 artifact 保存并验证精确十进制整数。",
        transform=upper.transAxes,
        fontproperties=font_prop,
    )
    local_rows = [[str(k), str(value)] for k, value in data["local_window"]]
    table_axis.set_axis_off()
    table = table_axis.table(
        cellText=local_rows,
        colLabels=("k", "真实 centered integer（十进制）"),
        cellLoc="center",
        loc="center",
        colWidths=(0.14, 0.86),
    )
    for cell in table.get_celld().values():
        cell.get_text().set_fontproperties(font_prop)
    selected_integer = dict(data["local_window"])[evidence_profile.selected_step]
    table_axis.set_title(
        f"局部整数窗口（k={evidence_profile.selected_step - 2}…{evidence_profile.selected_step + 2}）",
        fontproperties=font_prop,
    )
    table_axis.text(
        0.5,
        0.08,
        (
            f"û_raw(k) = m_centered(k) / 2^{fractional_bits}\n"
            f"k={evidence_profile.selected_step}: {selected_integer} / 2^{fractional_bits} "
            f"= {data['selected_raw']:.12g} kW → applied {data['selected_applied']:.12g} kW"
        ),
        ha="center",
        va="center",
        fontproperties=font_prop,
        transform=table_axis.transAxes,
    )
    lower.set_ylabel("制冷功率（kW）", fontproperties=font_prop)
    lower.set_xlabel("离散步 k", fontproperties=font_prop)
    lower.legend(prop=font_prop)
    for axis in (upper, lower):
        axis.grid(True, alpha=profile.style.grid_alpha)
    upper.set_title("完整 180 步 decode 前整数轨迹", fontproperties=font_prop)
    return figure


def _integer_decode_data(evidence: VerifiedEvidenceData, selected_step: int) -> dict[str, object]:
    """只从 verified integer artifact 提取并交叉核对全程/单步 decode 证据。"""
    rows = [row for row in evidence.integer_control_rows if row["channel"] == 0]
    if len(rows) != 180 or [row["step"] for row in rows] != list(range(180)):
        raise ValueError("整数执行证据必须完整覆盖 k=0..179。")
    integers = tuple(row["secure_output_centered"] for row in rows)
    if any(type(value) is not int for value in integers):
        raise TypeError("centered integer 必须直接来自整数 schema。")
    fractional_bits_values = {row["output_fractional_bits"] for row in rows}
    if len(fractional_bits_values) != 1:
        raise ValueError("完整整数轨迹的 output fractional bits 必须一致。")
    fractional_bits = fractional_bits_values.pop()
    ledger = evidence.metadata.get("scale_ledger")
    if not isinstance(ledger, Mapping) or ledger.get("output") != fractional_bits:
        raise ValueError("integer artifact 的 output scale 与真实 scale ledger 不一致。")
    selected = evidence.selected_step
    if selected.get("step") != selected_step:
        raise ValueError("整数图 selected step 与 verified trace 不一致。")
    selected_row = rows[selected_step]
    selected_raw = selected["raw_control"]
    if (
        int(selected_raw["centered"][0]) != selected_row["secure_output_centered"]
        or selected_raw["fractional_bits"] != fractional_bits
        or selected["decoded_raw_control"][0] != selected_row["raw_secure_control"]
        or selected_row["secure_output_centered"] / (1 << fractional_bits)
        != selected_row["raw_secure_control"]
    ):
        raise ValueError("02 单步与 03 全程整数/decode 证据不一致。")
    window = tuple(
        (row["step"], row["secure_output_centered"])
        for row in rows[selected_step - 2 : selected_step + 3]
    )
    if tuple(step for step, _ in window) != tuple(range(selected_step - 2, selected_step + 3)):
        raise ValueError("局部十进制整数窗口不完整。")
    return {
        "step": np.arange(180),
        "integers": integers,
        "raw": np.array([row["raw_secure_control"] for row in rows], dtype=float),
        "applied": np.array([row["applied_secure_control"] for row in rows], dtype=float),
        "fractional_bits": fractional_bits,
        "local_window": window,
        "selected_raw": selected_row["raw_secure_control"],
        "selected_applied": selected_row["applied_secure_control"],
    }


def _state_transition_figure(
    evidence: VerifiedEvidenceData, profile: ReportProfile, font: ResolvedFont
) -> Figure:
    """分尺度展示 x_c(k)、state accumulator 与 x_c(k+1) 的真实整数。"""
    state = evidence.selected_step["state_transition"]
    before = [int(value) for value in state["state_before"]["centered"]]
    accumulator = [int(value) for value in state["state_accumulator"]["centered"]]
    after = [int(value) for value in state["state_after"]["centered"]]
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axes = figure.subplots(1, 3)
    font_prop = FontProperties(fname=str(font.path))
    for axis, values, title, bits in (
        (axes[0], before, "x_c(k)", state["state_before"]["fractional_bits"]),
        (axes[1], accumulator, "A x_c(k)+B v(k)", state["state_accumulator"]["fractional_bits"]),
        (axes[2], after, "x_c(k+1)", state["state_after"]["fractional_bits"]),
    ):
        axis.bar(np.arange(len(values)), values)
        axis.set_title(f"{title}\n分数位={bits}", fontproperties=font_prop)
        axis.set_xlabel("state index", fontproperties=font_prop)
        axis.grid(True, axis="y", alpha=profile.style.grid_alpha)
    figure.suptitle(
        f"控制器状态更新证据（Trunc bits={state['truncation_bits']}，方程核查通过）",
        fontproperties=FontProperties(fname=str(font.path), size=profile.style.title_size),
    )
    return figure


def _fig3_figure(
    sweep: VerifiedSweepData,
    records: tuple[SweepRunRecord, ...],
    profile: ReportProfile,
    font: ResolvedFont,
) -> Figure:
    """直接读取 #15 applied control_error，保留 k=0..179 与精确零 mask。"""
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    for item in records:
        values = np.abs(sweep.runs[item.point.point_id].result.control_error[:, 0])
        masked = np.ma.masked_where(values == 0.0, values)
        style = profile.ell_styles[item.point.ell]
        axis.plot(
            np.arange(values.size),
            masked,
            color=style.color,
            linestyle=style.linestyle,
            label=f"ell={item.point.ell}",
        )
    apply_axis_format(axis.yaxis, scale="log", signed=False)
    font_prop = FontProperties(fname=str(font.path))
    axis.set_xlabel("离散步 k", fontproperties=font_prop)
    axis.set_ylabel("|u_applied(k) - û_applied(k)|（kW）", fontproperties=font_prop)
    axis.set_title("论文 Fig. 3 adapted：实际施加控制误差", fontproperties=font_prop)
    axis.legend(prop=font_prop)
    axis.grid(True, alpha=profile.style.grid_alpha)
    return figure


def _raw_control_error_figure(
    evidence: VerifiedEvidenceData, profile: ReportProfile, font: ResolvedFont
) -> Figure:
    """单独绘制 raw controller output 误差，避免与正式 applied 指标混称。"""
    rows = [row for row in evidence.integer_control_rows if row["channel"] == 0]
    error = np.abs(
        np.array([row["raw_plaintext_control"] - row["raw_secure_control"] for row in rows])
    )
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    axis.plot(np.arange(error.size), np.ma.masked_where(error == 0.0, error))
    apply_axis_format(axis.yaxis, scale="log", signed=False)
    font_prop = FontProperties(fname=str(font.path))
    axis.set_title("数值机制诊断：raw control 绝对误差", fontproperties=font_prop)
    axis.set_xlabel("离散步 k", fontproperties=font_prop)
    axis.set_ylabel("|u_raw - û_raw|（kW）", fontproperties=font_prop)
    axis.grid(True, alpha=profile.style.grid_alpha)
    return figure


def _normalized_precision_figure(
    records: tuple[SweepRunRecord, ...], profile: ReportProfile, font: ResolvedFont
) -> Figure:
    """只共轴绘制三个无量纲比值，基准为 ell=32 且禁止 epsilon。"""
    ordered = sorted(records, key=lambda item: item.point.ell)
    control = np.array([item.control_error.max_abs for item in ordered], dtype=float)
    output = np.array([item.output_error.max_abs for item in ordered], dtype=float)
    if control[0] == 0.0 or output[0] == 0.0:
        raise ValueError("无量纲 precision summary 的 ell=32 基准分母不得为零。")
    ell = np.array([item.point.ell for item in ordered])
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    axis.plot(ell, control / control[0], "o-", label="控制最大绝对误差比 R_u")
    axis.plot(ell, output / output[0], "s-", label="温度最大绝对误差比 R_T")
    axis.plot(ell, 2.0 ** (-(ell - ell[0])), "--", label="2^{-(ell-32)} 参考")
    apply_axis_format(axis.yaxis, scale="log", signed=False)
    font_prop = FontProperties(fname=str(font.path))
    axis.set_xlabel("定点小数位数 ell", fontproperties=font_prop)
    axis.set_ylabel("无量纲比值", fontproperties=font_prop)
    axis.set_title("无量纲精度影响", fontproperties=font_prop)
    axis.legend(prop=font_prop)
    axis.grid(True, alpha=profile.style.grid_alpha)
    return figure


def _resource_timing_figure(
    sweep: VerifiedSweepData,
    evidence: VerifiedEvidenceData,
    profile: ReportProfile,
    font: ResolvedFont,
) -> Figure:
    """同时展示三 seed timing、跨 seed exact 总量及真实逐步资源轨迹。"""
    ell_values = list(sweep.definition["fractional_bits"])
    means: list[float] = []
    stds: list[float] = []
    triples: list[int] = []
    truncations: list[int] = []
    for ell in ell_values:
        group = [
            item
            for item in sweep.records
            if item.point.ell == ell and item.status is SweepRunStatus.SUCCESS
        ]
        timings = np.array([item.cost.wall_clock_seconds for item in group], dtype=float)
        if timings.size != 3:
            raise ValueError("wall-clock 必须完整包含 seeds 42/43/44。")
        triple_values = {item.cost.protocol1_triples_total for item in group}
        trunc_values = {item.cost.protocol2_truncations_total for item in group}
        if len(triple_values) != 1 or len(trunc_values) != 1:
            raise ValueError("确定性协议资源跨 seed 不一致，不能标为 exact。")
        means.append(float(np.mean(timings)))
        stds.append(float(np.std(timings, ddof=1)))
        triples.append(triple_values.pop())
        truncations.append(trunc_values.pop())
    figure = Figure(
        figsize=(profile.style.width_inches, profile.style.height_inches), layout="constrained"
    )
    FigureCanvasAgg(figure)
    axis, lifecycle = figure.subplots(2, 1)
    axis.bar(ell_values, means, yerr=stds, capsize=5, label="wall-clock mean ± sample std")
    other = axis.twinx()
    other.plot(ell_values, triples, "o-", label="Protocol 1 exact triples")
    other.plot(ell_values, truncations, "s--", label="Protocol 2 exact truncations")
    font_prop = FontProperties(fname=str(font.path))
    axis.set_xlabel("定点小数位数 ell", fontproperties=font_prop)
    axis.set_ylabel("执行时间（s）", fontproperties=font_prop)
    other.set_ylabel("精确资源数", fontproperties=font_prop)
    axis.set_title("wall-clock 统计与确定性协议资源", fontproperties=font_prop)
    handles1, labels1 = axis.get_legend_handles_labels()
    handles2, labels2 = other.get_legend_handles_labels()
    axis.legend(handles1 + handles2, labels1 + labels2, prop=font_prop, loc="upper center")
    axis.grid(True, alpha=profile.style.grid_alpha)
    resource_rows = evidence.resource_rows
    if len(resource_rows) != 180 or [row["step"] for row in resource_rows] != list(range(180)):
        raise ValueError("资源图必须读取 180 个连续的 verified resource steps。")
    steps = np.arange(180)
    triple_cumulative = np.array([row["triples_consumed"] for row in resource_rows], dtype=int)
    triple_delta = np.array([row["triples_consumed_delta"] for row in resource_rows], dtype=int)
    trunc_cumulative = np.array([row["truncations_consumed"] for row in resource_rows], dtype=int)
    trunc_delta = np.array([row["truncations_consumed_delta"] for row in resource_rows], dtype=int)
    lifecycle.plot(steps, triple_cumulative, label="P1 triples 累计")
    lifecycle.plot(steps, trunc_cumulative, "--", label="P2 truncations 累计")
    delta_axis = lifecycle.twinx()
    delta_axis.plot(steps, triple_delta, ":", label="P1 每步增量")
    delta_axis.plot(steps, trunc_delta, "-.", label="P2 每步增量")
    lifecycle.set_xlabel("离散步 k", fontproperties=font_prop)
    lifecycle.set_ylabel("实际累计消费", fontproperties=font_prop)
    delta_axis.set_ylabel("实际每步增量", fontproperties=font_prop)
    lifecycle.set_title("代表点真实资源生命周期：累计与每步增量", fontproperties=font_prop)
    handles3, labels3 = lifecycle.get_legend_handles_labels()
    handles4, labels4 = delta_axis.get_legend_handles_labels()
    lifecycle.legend(handles3 + handles4, labels3 + labels4, prop=font_prop, loc="upper left")
    lifecycle.grid(True, alpha=profile.style.grid_alpha)
    return figure


def _quantitative_rows(
    sweep: VerifiedSweepData, profile: EvidenceReportProfile
) -> list[dict[str, object]]:
    """从同一 verified sweep 构造四精度误差、三 seed timing 与 exact 资源表。"""
    rows: list[dict[str, object]] = []
    manifest_hash = _digest(sweep.root / "manifest.json")
    for ell in sweep.definition["fractional_bits"]:
        group = [
            item
            for item in sweep.records
            if item.point.ell == ell and item.status is SweepRunStatus.SUCCESS
        ]
        primary = next(item for item in group if item.point.seed == profile.representative_seed)
        timings = [
            item.cost.wall_clock_seconds for item in sorted(group, key=lambda item: item.point.seed)
        ]
        triple_values = {item.cost.protocol1_triples_total for item in group}
        trunc_values = {item.cost.protocol2_truncations_total for item in group}
        if len(triple_values) != 1 or len(trunc_values) != 1:
            raise ValueError("四精度表不能把跨 seed 不一致资源标为 exact。")
        source = sweep.runs[primary.point.point_id]
        run_root = sweep.root / str(primary.artifact_path)
        rows.append(
            {
                "ell": ell,
                "control_max_abs_kw": primary.control_error.max_abs,
                "control_mean_abs_kw": primary.control_error.mean_abs,
                "control_rms_kw": primary.control_error.rms,
                "temperature_max_abs_degC": primary.output_error.max_abs,
                "temperature_mean_abs_degC": primary.output_error.mean_abs,
                "temperature_rms_degC": primary.output_error.rms,
                "wall_clock_seed42_s": timings[0],
                "wall_clock_seed43_s": timings[1],
                "wall_clock_seed44_s": timings[2],
                "wall_clock_mean_s": float(np.mean(timings)),
                "wall_clock_sample_std_s": float(np.std(timings, ddof=1)),
                "protocol1_triples_exact": triple_values.pop(),
                "protocol2_truncations_exact": trunc_values.pop(),
                "q": str(primary.point.q),
                "kappa": primary.point.kappa,
                "k": primary.point.k,
                "lambda": primary.point.lambda_,
                "source_run_id": source.run_id,
                "source_config_sha256": _digest(run_root / "config.json"),
                "source_manifest_sha256": manifest_hash,
            }
        )
    return rows


def _write_quantitative_table(
    csv_path: Path, markdown_path: Path, rows: list[dict[str, object]]
) -> None:
    """由同一 rows 同批写 CSV/中文 Markdown，保留完整 q 和三个 seed 原值。"""
    fields = tuple(rows[0])
    with csv_path.open("x", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# 四精度定量总表",
        "",
        "| ell | 控制 max/mean/RMS (kW) | 温度 max/mean/RMS (°C) | wall-clock mean±sample std (s) | P1 triples | P2 truncations | q / kappa / k / lambda |",
        "| ---: | --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['ell']} | {row['control_max_abs_kw']:.6e} / {row['control_mean_abs_kw']:.6e} / {row['control_rms_kw']:.6e} | "
            f"{row['temperature_max_abs_degC']:.6e} / {row['temperature_mean_abs_degC']:.6e} / {row['temperature_rms_degC']:.6e} | "
            f"{row['wall_clock_mean_s']:.6f} ± {row['wall_clock_sample_std_s']:.6f} | {row['protocol1_triples_exact']} | "
            f"{row['protocol2_truncations_exact']} | {row['q']} / {row['kappa']} / {row['k']} / {row['lambda']} |"
        )
    lines.extend(
        (
            "",
            "Protocol 2 为 0 仅说明当前整数 A/B 正式路径没有 state Trunc；不表示完整 HVAC 闭环运行验证了 Protocol 2。",
            "",
        )
    )
    markdown_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def _source_snapshot(
    sweep: VerifiedSweepData, evidence: VerifiedEvidenceData, profile: EvidenceReportProfile
) -> dict[str, str]:
    """冻结 sweep、evidence 和两个 profile 的原始 bytes 摘要。"""
    return {
        "sweep_manifest": _digest(sweep.root / "manifest.json"),
        "sweep_data_manifest": _digest(sweep.root / "data_manifest.json"),
        "evidence_manifest": _digest(evidence.root / "manifest.json"),
        "evidence_profile": _digest(profile.source_path),
        "base_profile": _digest(profile.base_profile_path),
    }


def _validate_prepublish(
    sweep: VerifiedSweepData,
    evidence: VerifiedEvidenceData,
    profile: EvidenceReportProfile,
    snapshot: dict[str, str],
) -> None:
    """紧邻 rename 重走 canonical readers 并拒绝任一来源/profile 变化。"""
    if snapshot != _source_snapshot(sweep, evidence, profile):
        raise ValueError("source sweep/evidence/profile 在报告生成期间发生变化。")
    load_verified_sweep_data(sweep.root, manifest_name="manifest.json")
    load_verified_evidence_artifacts(evidence.root)


def _figure_entry(
    root: Path, path: Path, key: str, purpose: str, section: str, *, note: str | None = None
) -> dict[str, object]:
    """为图生成统一的 manifest/catalog 记录。"""
    return {
        "kind": "figure",
        "key": key,
        "section": section,
        "path": path.relative_to(root).as_posix(),
        "purpose_zh": purpose,
        "speaker_note_zh": note or purpose,
        "sha256": _digest(path),
    }


def _file_entry(
    root: Path,
    path: Path,
    kind: str,
    purpose: str,
    section: str,
    *,
    artifact_key: str | None = None,
) -> dict[str, object]:
    """为表格或目录生成与图一致的 hash 记录。"""
    return {
        "kind": kind,
        "key": artifact_key or path.stem,
        "section": section,
        "path": path.relative_to(root).as_posix(),
        "purpose_zh": purpose,
        "speaker_note_zh": purpose,
        "sha256": _digest(path),
    }


def _sort_main_entries(entries: list[dict[str, object]], main_order: tuple[str, ...]) -> None:
    """按冻结论证顺序整理主汇报；同一表格的 CSV/Markdown 相邻。"""
    rank = {key: index for index, key in enumerate(main_order)}
    main = [entry for entry in entries if entry["section"] == "主汇报"]
    appendix = [entry for entry in entries if entry["section"] != "主汇报"]
    keys = {entry["key"] for entry in main}
    if keys != set(main_order):
        raise ValueError("实际主汇报 artifact key 与冻结 main_order 不一致。")
    main.sort(key=lambda entry: (rank[str(entry["key"])], str(entry["path"])))
    entries[:] = [*main, *appendix]


def _catalog(
    title: str, entries: list[dict[str, object]], section: str, limitations: tuple[str, ...]
) -> str:
    """由 manifest 同一 entries 生成中文目录，避免手工说明漂移。"""
    lines = [f"# {title}", "", "全部内容来自 verified artifacts 的只读重建。", ""]
    for index, item in enumerate(
        (entry for entry in entries if entry["section"] == section), start=1
    ):
        lines.extend(
            (
                f"## {index}. {item['path']}",
                "",
                f"- 用途：{item['purpose_zh']}",
                f"- 汇报说明：{item['speaker_note_zh']}",
                f"- SHA-256：`{item['sha256']}`",
                "",
            )
        )
    lines.extend(("## 必须保留的限制", "", *[f"- {item}" for item in limitations], ""))
    return "\n".join(lines)


def _new_report_id() -> str:
    """生成 UTC+nonce 报告 ID，拒绝覆盖已有报告。"""
    value = f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{secrets.token_hex(6)}"
    if not _REPORT_ID_PATTERN.fullmatch(value):
        raise ValueError("report ID 格式无效。")
    return value


def _digest(path: Path) -> str:
    """返回文件原始 bytes SHA-256。"""
    return sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    """验证小写十六进制 SHA-256。"""
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _owned_stage(stage: Path, parent: Path, identity: int) -> bool:
    """异常时只清理本调用创建的直属 staging。"""
    try:
        return (
            stage.resolve().parent == parent.resolve()
            and stage.name.startswith(".incomplete-")
            and not stage.is_symlink()
            and stage.stat(follow_symlinks=False).st_ino == identity
        )
    except OSError:
        return False
