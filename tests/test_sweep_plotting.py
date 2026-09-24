"""Issue #15 扫描图只消费已通过清单验证的正式工件。"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

from secure_control.experiments.artifacts import SCHEMA_VERSION, write_artifacts
from secure_control.experiments.sweep import (
    PrecisionPreflightReport,
    ProtocolCostReport,
    ResolvedBaselineSource,
    ResolvedPrecisionSweepPlan,
    ReusablePrecisionSweepDefinition,
    SweepRunRecord,
    SweepRunStatus,
    load_precision_sweep_definition,
)
from secure_control.experiments.sweep_artifacts import (
    _safe_member,
    build_summary_payload,
    load_verified_sweep_data,
    write_data_manifest,
    write_definition,
    write_json,
    write_manifest,
    write_range_margins,
    write_resolved_plan,
    write_resolved_source,
    write_summary,
)
from secure_control.experiments.sweep_metrics import compute_error_metrics
from secure_control.experiments.sweep_plotting import _time_series_figure, render_sweep_figures
from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult

PROJECT_ROOT = Path(__file__).parents[1]
DEFINITION_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_precision_sweep.yaml"
V2_DEFINITION_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_precision_sweep_definition.yaml"


def _verified_sweep(root: Path) -> Path:
    """构造四个主 seed 点的最小 schema v2 正式扫描闭包。"""
    loaded = load_precision_sweep_definition(DEFINITION_PATH)
    definition = replace(loaded, seeds=(42,), primary_seed=42)
    root.mkdir()
    metadata = ScenarioMetadata(
        "fixture",
        ChannelMetadata(("reference",), ("degree_Celsius",)),
        ChannelMetadata(("output",), ("degree_Celsius",)),
        ChannelMetadata(("control",), ("watt",)),
    )
    records: list[SweepRunRecord] = []
    for point in definition.points:
        time = np.array([0.0, 1.0, 2.0])
        control_error = np.array([[0.0], [2.0**-point.ell], [2.0 ** (-point.ell + 1)]])
        output_error = control_error / 2.0
        result = SimulationResult(
            time=time,
            reference=np.zeros((3, 1)),
            output_ideal=output_error,
            output_secure=np.zeros((3, 1)),
            control_ideal=control_error,
            control_secure=np.zeros((3, 1)),
            control_error=control_error,
            output_error=output_error,
        )
        published = write_artifacts(
            result,
            metadata,
            {"scenario": {"name": "fixture", "version": "1"}},
            {
                "scenario_name": "fixture",
                "scenario_version": "1",
                "schema_version": SCHEMA_VERSION,
            },
            output_root=root / "runs" / point.point_id,
        )
        record = SweepRunRecord(
            point,
            SweepRunStatus.SUCCESS,
            PrecisionPreflightReport(True, True, True, (), True, ()),
            compute_error_metrics(output_error),
            compute_error_metrics(control_error),
            {"fixture": True},
            ProtocolCostReport(9, 1620, 0, 0, 256, 64, 0.5, "fixture"),
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
        root / "data_manifest.json",
        sweep_id=root.name,
        definition=definition,
        records=frozen,
    )
    write_manifest(
        root / "manifest.json",
        sweep_id=root.name,
        definition=definition,
        records=frozen,
    )
    return root


def test_sweep_plotting_verifies_data_and_publishes_six_figures(tmp_path: Path) -> None:
    """跨 ell 图包含四张汇总图和两张主 seed 跨精度时序图。"""
    root = _verified_sweep(tmp_path / "sweep")
    figures = render_sweep_figures(root, primary_seed=42, output_dir=tmp_path / "rendered")
    assert len(figures) == 6
    assert {path.name for path in figures} == {
        "control_error_vs_ell.png",
        "output_error_vs_ell.png",
        "control_error_over_time_by_ell.png",
        "output_error_over_time_by_ell.png",
        "precision_summary.png",
        "timing_cost.png",
    }
    assert all(path.is_file() and path.stat().st_size > 0 for path in figures)


def test_renderer_rejects_summary_with_manifest_hash_mismatch(tmp_path: Path) -> None:
    """正式 consumer 不能用被篡改的 summary 继续生成可信图。"""
    root = _verified_sweep(tmp_path / "sweep")
    with (root / "summary.csv").open("a", encoding="utf-8") as target:
        target.write("tampered\n")
    with pytest.raises(ValueError, match="manifest|SHA-256"):
        render_sweep_figures(root, primary_seed=42, output_dir=tmp_path / "rendered")


def test_renderer_rejects_tampered_trajectory(tmp_path: Path) -> None:
    """任一主 seed 轨迹被改写时，单次 reader 和 sweep renderer 都必须拒绝。"""
    root = _verified_sweep(tmp_path / "sweep")
    trajectory = next(root.glob("runs/*/*/trajectory.csv"))
    with trajectory.open("a", encoding="utf-8") as target:
        target.write("0\n")
    with pytest.raises(ValueError, match="manifest|SHA-256"):
        render_sweep_figures(root, primary_seed=42, output_dir=tmp_path / "rendered")


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_verified_reader_rejects_missing_or_extra_authoritative_file(
    tmp_path: Path, mutation: str
) -> None:
    """权威闭包既不能少文件，也不能偷偷加入未列入清单的文件。"""
    root = _verified_sweep(tmp_path / "sweep")
    if mutation == "missing":
        (root / "range_margins.csv").unlink()
    else:
        (root / "unlisted.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="缺失|额外"):
        load_verified_sweep_data(root)


def test_v2_sweep_manifest_closes_definition_resolved_source_and_plan(tmp_path: Path) -> None:
    """v2 artifact 将稳定定义和运行实例 provenance 分开保存并一起纳入清单。"""
    root = _verified_sweep(tmp_path / "sweep")
    v2 = load_precision_sweep_definition(V2_DEFINITION_PATH)
    assert isinstance(v2, ReusablePrecisionSweepDefinition)
    v2 = replace(v2, seeds=(42,), primary_seed=42)
    source = ResolvedBaselineSource(
        PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_dual_loop_25_20_15.yaml",
        "fixture_identity_v1",
        "1" * 64,
        {"wrapper": "2" * 64, "baseline": "3" * 64, "scenario": "4" * 64},
        "5" * 64,
        "6" * 64,
    )
    plan = ResolvedPrecisionSweepPlan(
        v2,
        source,
        {"schur": {"status": "stable"}, "equilibria": []},
        "7" * 64,
        True,
        v2.points,
        {"definition_schema_version": 2, "definition_source_sha256": "8" * 64},
    )
    records = load_verified_sweep_data(root).records
    (root / "manifest.json").unlink()
    (root / "data_manifest.json").unlink()
    write_definition(root / "definition.json", v2)
    write_resolved_source(root / "resolved_source.json", source)
    write_resolved_plan(root / "resolved_plan.json", plan)
    write_data_manifest(
        root / "data_manifest.json", sweep_id=root.name, definition=v2, records=records
    )
    write_manifest(root / "manifest.json", sweep_id=root.name, definition=v2, records=records)

    verified = load_verified_sweep_data(root)
    assert verified.definition["schema_version"] == 2
    assert verified.resolved_source["baseline_id"] == "1" * 64
    assert verified.resolved_plan["points"] == verified.definition["points"]
    assert str(PROJECT_ROOT) not in (root / "resolved_source.json").read_text(encoding="utf-8")

    with (root / "resolved_plan.json").open("a", encoding="utf-8") as target:
        target.write(" ")
    with pytest.raises(ValueError, match="SHA-256"):
        load_verified_sweep_data(root)


def test_verified_path_rejects_escape(tmp_path: Path) -> None:
    """manifest 和 worker 提供的相对路径均不能用父目录片段逃逸。"""
    root = tmp_path / "sweep"
    root.mkdir()
    with pytest.raises(ValueError, match="逃逸"):
        _safe_member(root, "../outside.json")


def test_verified_path_rejects_real_leaf_symlink(tmp_path: Path) -> None:
    """manifest 成员自身即使指向闭包内普通文件，也不得作为 leaf link 被接受。"""
    root = tmp_path / "sweep"
    root.mkdir()
    target = root / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    (root / "member.json").symlink_to(target)
    with pytest.raises(ValueError, match="符号链接"):
        _safe_member(root, "member.json")


def test_time_series_rejects_primary_seed_time_grid_mismatch(tmp_path: Path) -> None:
    """四个主 seed 精度点必须共享完全一致的时间网格。"""
    data = load_verified_sweep_data(_verified_sweep(tmp_path / "sweep"))
    runs = dict(data.runs)
    target = sorted(runs)[1]
    experiment = runs[target]
    altered = replace(experiment.result, time=np.array([0.0, 1.5, 2.0]))
    runs[target] = replace(experiment, result=altered)
    with pytest.raises(ValueError, match="time grids"):
        _time_series_figure(
            replace(data, runs=runs),
            primary_seed=42,
            field="control_error",
            title="test",
        )
