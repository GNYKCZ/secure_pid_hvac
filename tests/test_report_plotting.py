"""Issue #48 中文汇报图只消费 verified sweep，并保持来源与目录可追溯。"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest
import yaml
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure

from secure_control.experiments.artifacts import SCHEMA_VERSION, write_artifacts
from secure_control.experiments.plotting import apply_axis_format
from secure_control.experiments.reporting import (
    FontSpec,
    _phase_boundaries,
    _single_figure,
    load_report_profile,
    render_chinese_report,
    render_chinese_saved_run,
    resolve_report_font,
)
from secure_control.experiments.sweep import (
    PrecisionPreflightReport,
    ProtocolCostReport,
    SweepRunRecord,
    SweepRunStatus,
    load_precision_sweep_definition,
)
from secure_control.experiments.sweep_artifacts import (
    build_summary_payload,
    load_verified_sweep_data,
    write_data_manifest,
    write_definition,
    write_json,
    write_manifest,
    write_range_margins,
    write_summary,
)
from secure_control.experiments.sweep_metrics import compute_error_metrics
from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult

PROJECT_ROOT = Path(__file__).parents[1]
PROFILE = PROJECT_ROOT / "configs" / "hvac_2r2c_report_zh.yaml"
DEFINITION = PROJECT_ROOT / "configs" / "hvac_2r2c_precision_sweep.yaml"


def _verified_sweep(root: Path) -> Path:
    """构造包含四个精度和完整 2R2C 展示配置的最小正式闭包。"""
    definition = load_precision_sweep_definition(DEFINITION)
    root.mkdir()
    metadata = ScenarioMetadata(
        "hvac",
        ChannelMetadata(("target_temperature",), ("degC",)),
        ChannelMetadata(("air_temperature",), ("degC",)),
        ChannelMetadata(("cooling_power",), ("kW_thermal_cooling",)),
    )
    records: list[SweepRunRecord] = []
    for point in definition.points:
        if point.seed != 42:
            status = SweepRunStatus.INFEASIBLE if point.seed == 43 else SweepRunStatus.FAILED
            record = SweepRunRecord(
                point,
                status,
                PrecisionPreflightReport(None, None, None, (), False, ("fixture",)),
                None,
                None,
                {"fixture": True},
                None,
                None,
                "fixture",
                "fixture failure",
            )
            records.append(record)
            write_json(root / "points" / point.point_id / "record.json", record)
            continue
        time = np.array([0.0, 60.0, 120.0, 180.0])
        control_error = np.array([[0.0], [2.0**-point.ell], [-(2.0**-point.ell)], [0.0]])
        output_error = control_error / 4.0
        reference = np.array([[15.0], [15.0], [20.0], [20.0]])
        result = SimulationResult(
            time=time,
            reference=reference,
            output_ideal=output_error,
            output_secure=np.zeros((4, 1)),
            control_ideal=control_error,
            control_secure=np.zeros((4, 1)),
            control_error=control_error,
            output_error=output_error,
        )
        effective = {
            "scenario": {"name": "hvac", "version": "2"},
            "hvac": {
                "reference_segments": [
                    {"start_seconds": 0, "end_seconds": 120},
                    {"start_seconds": 120, "end_seconds": 240},
                ],
                "timing": {"sampling_period_seconds": 60, "sample_count": 4},
            },
        }
        published = write_artifacts(
            result,
            metadata,
            effective,
            {"scenario_name": "hvac", "scenario_version": "2", "schema_version": SCHEMA_VERSION},
            output_root=root / "runs" / point.point_id,
        )
        record = SweepRunRecord(
            point,
            SweepRunStatus.SUCCESS,
            PrecisionPreflightReport(True, True, True, (), True, ()),
            compute_error_metrics(output_error),
            compute_error_metrics(control_error),
            {"fixture": True},
            ProtocolCostReport(9, 36, 0, 0, 256, 64, 0.01, "fixture"),
            published.run_dir.relative_to(root).as_posix(),
            None,
            None,
        )
        records.append(record)
        write_json(root / "points" / point.point_id / "record.json", record)
    frozen = tuple(records)
    write_definition(root / "definition.json", definition)
    write_summary(root / "summary.csv", frozen)
    write_range_margins(root / "range_margins.csv", frozen)
    write_json(root / "summary.json", build_summary_payload(frozen, {"fixture": True}))
    write_data_manifest(
        root / "data_manifest.json", sweep_id=root.name, definition=definition, records=frozen
    )
    write_manifest(
        root / "manifest.json", sweep_id=root.name, definition=definition, records=frozen
    )
    return root


def test_profile_freezes_twelve_chinese_figures_and_priorities() -> None:
    """展示配置固定 01–12 中文文件名，优先级不承担过滤语义。"""
    profile = load_report_profile(PROFILE)
    assert profile.locale == "zh-CN"
    assert [item.sequence for item in profile.figures] == list(range(1, 13))
    assert [item.priority for item in profile.figures].count("P1") == 6
    assert {item.priority for item in profile.figures} == {"P1", "P2", "P3"}
    assert all(item.filename.startswith(f"{item.sequence:02d}_") for item in profile.figures)


def test_scientific_formatters_never_emit_default_1e_notation() -> None:
    """线性 offset 与 log tick 均使用 mathtext 幂记法而不是默认 1e-n。"""
    figure = Figure()
    canvas = FigureCanvasAgg(figure)
    linear, logarithmic = figure.subplots(1, 2)
    linear.plot([0, 1], [1.0e-8, 2.0e-8])
    logarithmic.plot([0, 1], [1.0e-9, 1.0e-7])
    apply_axis_format(linear.yaxis, scale="linear", signed=False)
    apply_axis_format(logarithmic.yaxis, scale="log", signed=False)
    canvas.draw()
    texts = [
        linear.yaxis.get_offset_text().get_text(),
        *(tick.get_text() for tick in linear.get_yticklabels()),
        *(tick.get_text() for tick in logarithmic.get_yticklabels()),
    ]
    assert not any(re.search(r"1e[+-]?\d+", text) for text in texts)
    assert "10" in linear.yaxis.get_offset_text().get_text()
    assert any("10" in tick.get_text() for tick in logarithmic.get_yticklabels())


def test_font_resolution_fails_closed_without_declared_family() -> None:
    """正式报告不能在中文字体缺失时回退到默认字体继续发布。"""
    with pytest.raises(ValueError, match="字体"):
        resolve_report_font(FontSpec(("missing-font-for-issue-48",)), ["中文"])


def test_report_atomically_publishes_twelve_figures_and_matching_indexes(tmp_path: Path) -> None:
    """图、JSON 与 Markdown 共用 catalog，且源闭包 bytes 不变。"""
    sweep = _verified_sweep(tmp_path / "中文 sweep")
    source_before = {
        path: sha256(path.read_bytes()).hexdigest() for path in sweep.rglob("*") if path.is_file()
    }
    report = render_chinese_report(sweep, PROFILE, tmp_path / "中文 报告")
    assert len(report.figure_paths) == 12
    assert all(path.is_file() and path.stat().st_size > 0 for path in report.figure_paths)
    manifest = json.loads(report.manifest_path.read_text(encoding="utf-8"))
    assert [item["filename"] for item in manifest["figures"]] == [
        path.name for path in report.figure_paths
    ]
    assert all(item["purpose_zh"] and item["speaker_note_zh"] for item in manifest["figures"])
    index = report.catalog_path.read_text(encoding="utf-8")
    assert all(
        item["filename"] in index and item["sha256"] in index for item in manifest["figures"]
    )
    assert "全部扫描点状态" in index
    assert all(
        item["point_id"] in index and item["status"] in index for item in manifest["source_points"]
    )
    assert manifest["source_status_counts"] == {"failed": 4, "infeasible": 4, "success": 4}
    assert manifest["font"]["family"] in {"Microsoft YaHei", "SimHei"}
    source_after = {
        path: sha256(path.read_bytes()).hexdigest() for path in sweep.rglob("*") if path.is_file()
    }
    assert source_after == source_before


def test_report_rejects_existing_render_id_without_overwrite(tmp_path: Path, monkeypatch) -> None:
    """相同 render ID 的第二次发布必须拒绝且不留下 staging。"""
    sweep = _verified_sweep(tmp_path / "sweep")
    monkeypatch.setattr(
        "secure_control.experiments.reporting._new_render_id",
        lambda: "20260917T150000000000Z-123456789abc",
    )
    render_chinese_report(sweep, PROFILE, tmp_path / "reports")
    try:
        render_chinese_report(sweep, PROFILE, tmp_path / "reports")
    except FileExistsError:
        pass
    else:
        raise AssertionError("重复 report ID 未被拒绝")
    assert not list((tmp_path / "reports" / sweep.name).glob(".incomplete-*"))


def test_report_rejects_nonfinal_manifest_name_without_downgrading_reader(tmp_path: Path) -> None:
    """公开 Python 入口保留签名兼容，但正式报告不得绕过最终 manifest。"""
    sweep = _verified_sweep(tmp_path / "sweep")
    with pytest.raises(ValueError, match="最终 manifest"):
        render_chinese_report(
            sweep, PROFILE, tmp_path / "reports", manifest_name="data_manifest.json"
        )


def test_sweep_report_cli_rejects_removed_manifest_override(monkeypatch) -> None:
    """CLI 不再暴露将正式报告降级为 data manifest 的开关。"""
    from secure_control.experiments.sweep_figure_runner import main

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_figure_runner",
            "--sweep-dir",
            "unused",
            "--display-config",
            "unused",
            "--manifest-name",
            "data_manifest.json",
        ],
    )
    with pytest.raises(SystemExit) as raised:
        main()
    assert raised.value.code == 2


def test_profile_mappings_control_single_figure_text_and_selected_curves(tmp_path: Path) -> None:
    """名称、单位和通道选择必须真正驱动图面与来源数组，而非只参与校验。"""
    sweep = _verified_sweep(tmp_path / "sweep")
    data = load_verified_sweep_data(sweep)
    record = data.runs[
        next(item.point.point_id for item in data.records if item.status.value == "success")
    ]
    profile_data = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    profile_data["channel_names"]["air_temperature"] = "已配置输出"
    profile_data["unit_names"]["degC"] = "显示单位"
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(
        yaml.safe_dump(profile_data, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    profile = load_report_profile(profile_path)
    font = resolve_report_font(profile.font, ["已配置输出", "显示单位", *profile.labels.values()])
    figure = _single_figure(
        profile.figures[0], record, profile, font, _phase_boundaries(record, profile)
    )
    axis = figure.axes[0]
    assert axis.get_xlabel() == "时间（h）"
    assert axis.get_ylabel() == "已配置输出（显示单位）"
    plotted = [line for line in axis.lines if not line.get_label().startswith("_child")]
    assert [line.get_label() for line in plotted] == [
        "参考温度",
        "明文 已配置输出 $T_{air}(k)$",
        r"安全计算 已配置输出 $\hat{T}_{air}(k)$",
    ]
    np.testing.assert_array_equal(plotted[0].get_ydata(), record.result.reference[:, 0])
    np.testing.assert_array_equal(plotted[1].get_ydata(), record.result.output_ideal[:, 0])
    np.testing.assert_array_equal(plotted[2].get_ydata(), record.result.output_secure[:, 0])


@pytest.mark.parametrize(
    "target",
    ("manifest.json", "data_manifest.json", "summary.csv", "record", "trajectory"),
)
def test_report_rejects_each_tampered_verified_sweep_member(tmp_path: Path, target: str) -> None:
    """中文 renderer 自身必须拒绝 final/data manifest 及闭包成员任一篡改。"""
    sweep = _verified_sweep(tmp_path / target)
    successful = next(
        item
        for item in load_verified_sweep_data(sweep).records
        if item.status is SweepRunStatus.SUCCESS
    )
    path = {
        "manifest.json": sweep / "manifest.json",
        "data_manifest.json": sweep / "data_manifest.json",
        "summary.csv": sweep / "summary.csv",
        "record": sweep / "points" / successful.point.point_id / "record.json",
        "trajectory": sweep / str(successful.artifact_path) / "trajectory.csv",
    }[target]
    if target == "manifest.json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["files_sha256"]["data_manifest.json"] = "0" * 64
        path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        render_chinese_report(sweep, PROFILE, tmp_path / "reports")


def test_saved_run_rechecks_source_and_profile_at_atomic_commit(
    tmp_path: Path, monkeypatch
) -> None:
    """单点报告在目录和 manifest 写完后仍检测来源变化，并清理 staging。"""
    sweep = _verified_sweep(tmp_path / "sweep")
    data = load_verified_sweep_data(sweep)
    successful = next(item for item in data.records if item.status is SweepRunStatus.SUCCESS)
    source_run = sweep / str(successful.artifact_path)
    trajectory = source_run / "trajectory.csv"
    from secure_control.experiments import reporting

    original = reporting._index_markdown

    def mutate_after_old_check(*args, **kwargs):
        trajectory.write_bytes(trajectory.read_bytes() + b"\n")
        return original(*args, **kwargs)

    monkeypatch.setattr(reporting, "_index_markdown", mutate_after_old_check)
    output = tmp_path / "reports"
    with pytest.raises(ValueError, match="发布前"):
        render_chinese_saved_run(source_run, PROFILE, output)
    assert not list(output.rglob(".incomplete-*"))


def test_report_rejects_primary_seed_time_grid_mismatch(tmp_path: Path, monkeypatch) -> None:
    """报告入口必须拒绝跨精度主 seed 的不一致时间网格，不能静默对齐曲线。"""
    sweep = _verified_sweep(tmp_path / "sweep")
    data = load_verified_sweep_data(sweep)
    altered_point = next(
        item.point.point_id
        for item in data.records
        if item.status is SweepRunStatus.SUCCESS and item.point.ell == 40
    )
    altered_run = data.runs[altered_point]
    altered_result = replace(altered_run.result, time=altered_run.result.time + 1.0)
    altered_data = replace(
        data, runs={**data.runs, altered_point: replace(altered_run, result=altered_result)}
    )
    from secure_control.experiments import reporting

    monkeypatch.setattr(
        reporting, "load_verified_sweep_data", lambda *_args, **_kwargs: altered_data
    )
    with pytest.raises(ValueError, match="time grids"):
        render_chinese_report(sweep, PROFILE, tmp_path / "reports")


def test_loaded_profile_maps_are_immutable_and_ell_coverage_uses_definition(tmp_path: Path) -> None:
    """配置冻结后禁止原地漂移，ell 样式在报告入口与已验证 definition 对照。"""
    profile = load_report_profile(PROFILE)
    with pytest.raises(TypeError):
        profile.channel_names["air_temperature"] = "错误改写"
    with pytest.raises(TypeError):
        profile.ell_styles[32] = profile.ell_styles[32]
    sweep = _verified_sweep(tmp_path / "sweep")
    profile_data = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    profile_data["ell_styles"] = {"40": profile_data["ell_styles"]["40"]}
    path = tmp_path / "bad-profile.yaml"
    path.write_text(
        yaml.safe_dump(profile_data, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="ell_styles"):
        render_chinese_report(sweep, path, tmp_path / "reports")
