"""从固定已保存 scalar/vector 产物核对真实曲线、校验、零值和批次发布。"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest
from matplotlib.figure import Figure

from secure_control.experiments import plotting
from secure_control.experiments.artifacts import (
    ExperimentRecord,
    RunArtifacts,
    load_artifacts,
    write_artifacts,
)
from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult


def _published(tmp_path: Path, *, vector: bool) -> RunArtifacts:
    """沿用 #13 writer 固定一个不依赖 HVAC/仿真的完整 schema v1 fixture。"""
    reference = ChannelMetadata(
        ("setpoint", "second_target") if vector else ("setpoint",),
        ("degC", "degC") if vector else ("degC",),
    )
    output = ChannelMetadata(
        ("measurement", "second_output", "pressure") if vector else ("measurement",),
        ("degC", "degC", "kPa") if vector else ("degC",),
    )
    control = ChannelMetadata(
        ("actuator", "second_actuator") if vector else ("actuator",),
        ("kW", "kW") if vector else ("kW",),
    )
    metadata = ScenarioMetadata("toy", reference, output, control)
    reference_values = (
        np.array([[10.0, 11.0], [20.0, 12.0], [25.0, 13.0]])
        if vector
        else np.array([[10.0], [20.0], [25.0]])
    )
    ideal_output = (
        np.array([[11.0, 11.0, 100.0], [19.0, 12.0, 101.0], [26.0, 13.0, 102.0]])
        if vector
        else np.array([[11.0], [19.0], [26.0]])
    )
    secure_output = (
        np.array([[12.0, 12.0, 100.0], [18.0, 11.0, 101.0], [26.0, 13.0, 102.0]])
        if vector
        else np.array([[12.0], [18.0], [26.0]])
    )
    ideal_control = (
        np.array([[0.0, 2.0], [1.0, 2.0], [3.0, 2.0]])
        if vector
        else np.array([[0.0], [1.0], [3.0]])
    )
    secure_control = (
        np.array([[1.0, 2.0], [1.0, 2.0], [1.0, 2.0]])
        if vector
        else np.array([[1.0], [1.0], [1.0]])
    )
    result = SimulationResult(
        time=np.array([0.0, 3600.0, 7200.0]),
        reference=reference_values,
        output_ideal=ideal_output,
        output_secure=secure_output,
        control_ideal=ideal_control,
        control_secure=secure_control,
        control_error=ideal_control - secure_control,
        output_error=ideal_output - secure_output,
    )
    return write_artifacts(
        result,
        metadata,
        {"scenario": {"name": "toy", "version": "1"}, "fixture": "saved"},
        {"scenario_name": "toy", "scenario_version": "1", "schema_version": 1},
        output_root=tmp_path / "带空格 CSV 输入",
    )


@pytest.mark.parametrize("vector", [False, True])
def test_saved_scalar_vector_figures_use_actual_series_labels_units_and_seconds(
    tmp_path: Path, vector: bool
) -> None:
    """四类图逐条读取原始曲线，小时轴仅换算同一批秒样本。"""
    record = load_artifacts(_published(tmp_path, vector=vector).run_dir)
    display = plotting.PlotDisplay("h", "Research")
    output_index = 1 if vector else 0
    reference_index = 1 if vector else 0
    figures = (
        plotting.plot_tracking(record, output_index, reference_index, display),
        plotting.plot_control(record, 0, display),
        plotting.plot_control_error(record, 0, scale="linear", display=display),
        plotting.plot_output_error(record, output_index, display),
    )
    assert all(isinstance(figure, Figure) for figure in figures)
    tracking, control, control_error, output_error = (figure.axes[0] for figure in figures)
    np.testing.assert_array_equal(tracking.lines[0].get_xdata(), record.result.time / 3600.0)
    np.testing.assert_array_equal(
        tracking.lines[0].get_ydata(), record.result.reference[:, reference_index]
    )
    np.testing.assert_array_equal(
        tracking.lines[1].get_ydata(), record.result.output_ideal[:, output_index]
    )
    np.testing.assert_array_equal(
        tracking.lines[2].get_ydata(), record.result.output_secure[:, output_index]
    )
    assert record.metadata.reference.names[reference_index] in tracking.lines[0].get_label()
    assert record.metadata.output.names[output_index] in tracking.lines[1].get_label()
    assert tracking.get_ylabel() == record.metadata.output.units[output_index]
    assert tracking.get_xlabel() == "Time (h)"
    np.testing.assert_array_equal(control.lines[0].get_ydata(), record.result.control_ideal[:, 0])
    np.testing.assert_array_equal(control.lines[1].get_ydata(), record.result.control_secure[:, 0])
    assert "Applied control" in control.get_ylabel()
    assert record.metadata.control.units[0] in control.get_ylabel()
    np.testing.assert_array_equal(
        control_error.lines[0].get_ydata(), record.result.control_error[:, 0]
    )
    np.testing.assert_array_equal(
        output_error.lines[0].get_ydata(), record.result.output_error[:, output_index]
    )
    assert record.result.control_error[0, 0] < 0
    assert record.result.output_error[0, output_index] < 0
    for figure in figures:
        figure.clear()


def test_log_partial_and_all_zero_mask_only_render_copy(tmp_path: Path) -> None:
    """log 画绝对值并 mask 零；全零无人工正值，CSV/record 原值保持不变。"""
    published = _published(tmp_path, vector=True)
    record = load_artifacts(published.run_dir)
    csv_before = published.trajectory_path.read_bytes()
    signed_before = record.result.control_error.copy()
    display = plotting.PlotDisplay()
    partial = plotting.plot_control_error(record, 0, scale="log", display=display).axes[0]
    assert partial.get_yscale() == "log"
    assert "|Ideal - secure|" in partial.get_ylabel()
    rendered = partial.lines[0].get_ydata()
    np.testing.assert_array_equal(np.ma.getmaskarray(rendered), [False, True, False])
    np.testing.assert_array_equal(rendered.compressed(), [1.0, 2.0])
    assert any("Masked zero samples: 1" in text.get_text() for text in partial.texts)
    all_zero = plotting.plot_control_error(record, 1, scale="log", display=display).axes[0]
    assert all_zero.get_yscale() == "log"
    assert len(all_zero.lines) == 0
    assert any("All errors are zero" in text.get_text() for text in all_zero.texts)
    assert any("Masked zero samples: 3" in text.get_text() for text in all_zero.texts)
    np.testing.assert_array_equal(record.result.control_error, signed_before)
    assert published.trajectory_path.read_bytes() == csv_before


@pytest.mark.parametrize("vector", [False, True])
def test_render_batch_paths_manifest_hashes_and_no_simulation(
    tmp_path: Path, vector: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """reader 后直接画四类图；任何隐藏仿真/场景计划调用立即失败。"""
    published = _published(tmp_path, vector=vector)
    csv_before = published.trajectory_path.read_bytes()

    def forbidden(*args: object, **kwargs: object) -> None:
        """绘图绝不允许重新建立控制分支或运行 engine。"""
        raise AssertionError("plotting called simulation")

    monkeypatch.setattr("secure_control.simulation.runner.run", forbidden)
    monkeypatch.setattr(
        "secure_control.scenarios.hvac.integration.HvacScenario.build_plan", forbidden
    )
    pairs = ((1, 1),) if vector else ((0, 0),)
    controls = (0, 1) if vector else (0,)
    selection = plotting.PlotSelection(pairs, controls, "log", "s", "png")
    rendered = plotting.render_saved_run(
        published.run_dir, selection, output_root=tmp_path / "图片 输出"
    )
    assert rendered.source_run_id == published.run_id
    assert len(rendered.figure_paths) == (6 if vector else 4)
    assert all(
        path.is_file() and path.read_bytes().startswith(b"\x89PNG")
        for path in rendered.figure_paths
    )
    manifest = json.loads(rendered.manifest_path.read_text(encoding="utf-8"))
    assert manifest["source_run_id"] == published.run_id
    assert manifest["source_schema_version"] == 1
    assert manifest["source_files_sha256"]["trajectory.csv"] == sha256(csv_before).hexdigest()
    assert (
        manifest["source_files_sha256"]["config.json"]
        == sha256(published.config_path.read_bytes()).hexdigest()
    )
    assert (
        manifest["source_files_sha256"]["metadata.json"]
        == sha256(published.metadata_path.read_bytes()).hexdigest()
    )
    assert manifest["figure_format"] == "png"
    assert {item["category"] for item in manifest["figures"]} == {
        "tracking",
        "control",
        "control_error",
        "output_error",
    }
    assert [
        item["channels"]["output"]["index"]
        for item in manifest["figures"]
        if item["category"] == "output_error"
    ] == [1 if vector else 0]
    assert [item["filename"] for item in manifest["figures"]] == [
        path.name for path in rendered.figure_paths
    ]
    assert all(
        item["sha256"] == sha256(path.read_bytes()).hexdigest()
        for item, path in zip(manifest["figures"], rendered.figure_paths)
    )
    assert manifest["figures"][0]["channels"]["output"]["name"] == (
        "second_output" if vector else "measurement"
    )
    assert manifest["figures"][0]["channels"]["reference"]["unit"] == "degC"
    assert published.trajectory_path.read_bytes() == csv_before
    assert not list(rendered.manifest_path.parents[1].glob(".incomplete-*"))


def test_vector_output_error_selection_does_not_require_tracking_unit_match(tmp_path: Path) -> None:
    """独立请求 pressure/kPa 的 output error，不放松 tracking 的共轴单位校验。"""
    published = _published(tmp_path, vector=True)
    selection = plotting.PlotSelection(((1, 1),), (0,), output_error_channels=(1, 2))
    rendered = plotting.render_saved_run(published.run_dir, selection, output_root=tmp_path / "图")
    manifest = json.loads(rendered.manifest_path.read_text(encoding="utf-8"))
    tracking = [item for item in manifest["figures"] if item["category"] == "tracking"]
    errors = [item for item in manifest["figures"] if item["category"] == "output_error"]
    assert [item["channels"]["output"]["index"] for item in tracking] == [1]
    assert [item["channels"]["output"]["index"] for item in errors] == [1, 2]
    assert errors[1]["channels"]["output"] == {
        "index": 2,
        "name": "pressure",
        "unit": "kPa",
    }
    assert (rendered.manifest_path.parent / "output_error-2.png").is_file()


def test_source_change_after_reader_before_first_hash_cannot_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """reader 返回后的确定性损坏窗口必须拒绝，而不能为坏 CSV 签出图清单。"""
    published = _published(tmp_path, vector=False)
    original_csv_hash = sha256(published.trajectory_path.read_bytes()).hexdigest()
    real_load = plotting.load_artifacts

    def load_then_tamper(run_dir: Path) -> ExperimentRecord:
        """模拟外部操作恰在 reader 返回后、首次 source hash 前改坏 CSV。"""
        record = real_load(run_dir)
        published.trajectory_path.write_text("tampered", encoding="utf-8")
        return record

    monkeypatch.setattr(plotting, "load_artifacts", load_then_tamper)
    root = tmp_path / "变化源不发布"
    with pytest.raises(ValueError, match="source run.*变化"):
        plotting.render_saved_run(
            published.run_dir, plotting.PlotSelection(((0, 0),), (0,)), output_root=root
        )
    assert sha256(published.trajectory_path.read_bytes()).hexdigest() != original_csv_hash
    assert not root.exists()


def test_selection_and_public_helpers_reject_invalid_channel_shape_or_scale(tmp_path: Path) -> None:
    """重复、越界、单位不匹配及人工错 metadata 不生成成功图。"""
    published = _published(tmp_path, vector=True)
    record = load_artifacts(published.run_dir)
    root = tmp_path / "无效图不创建"
    with pytest.raises(ValueError, match="重复"):
        plotting.PlotSelection(((0, 0), (0, 0)), (0,))
    with pytest.raises(ValueError, match="非负"):
        plotting.PlotSelection(((0, -1),), (0,))
    with pytest.raises(ValueError, match="重复"):
        plotting.PlotSelection(((0, 0),), (0,), output_error_channels=(2, 2))
    with pytest.raises(ValueError, match="scale"):
        plotting.plot_control_error(record, 0, scale="unsupported", display=plotting.PlotDisplay())
    for selection, message in (
        (plotting.PlotSelection(((9, 0),), (0,)), "越界"),
        (plotting.PlotSelection(((2, 0),), (0,)), "单位不一致"),
        (plotting.PlotSelection(((0, 0),), (9,)), "越界"),
        (plotting.PlotSelection(((0, 0),), (0,), output_error_channels=(9,)), "越界"),
    ):
        with pytest.raises(ValueError, match=message):
            plotting.render_saved_run(published.run_dir, selection, output_root=root)
    assert not root.exists()
    wrong_metadata = ScenarioMetadata(
        "toy",
        record.metadata.reference,
        ChannelMetadata(("only",), ("degC",)),
        record.metadata.control,
    )
    invalid_record = ExperimentRecord(
        record.run_id, record.result, wrong_metadata, record.effective_config, record.provenance
    )
    with pytest.raises(ValueError, match="shape"):
        plotting.plot_output_error(invalid_record, 0, plotting.PlotDisplay())


@pytest.mark.parametrize("damage", ["schema", "missing_column", "nan", "inf", "shape"])
def test_corrupt_saved_schema_is_rejected_before_any_figure_output(
    tmp_path: Path, damage: str
) -> None:
    """缺列/非有限/版本/通道 shape 的损坏不能绕过 #13 正式 reader。"""
    published = _published(tmp_path, vector=False)
    metadata = json.loads(published.metadata_path.read_text(encoding="utf-8"))
    if damage == "schema":
        metadata["schema_version"] = 2
    elif damage == "shape":
        metadata["channel_counts"]["output"] = 2
    else:
        lines = published.trajectory_path.read_text(encoding="utf-8").splitlines()
        if damage == "missing_column":
            lines[0] = lines[0].replace("output_ideal[0],", "", 1)
        else:
            cells = lines[1].split(",")
            cells[1] = "NaN" if damage == "nan" else "Inf"
            lines[1] = ",".join(cells)
        published.trajectory_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        metadata["files_sha256"]["trajectory.csv"] = sha256(
            published.trajectory_path.read_bytes()
        ).hexdigest()
    published.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    root = tmp_path / "不能发布"
    with pytest.raises(ValueError):
        plotting.render_saved_run(
            published.run_dir, plotting.PlotSelection(((0, 0),), (0,)), output_root=root
        )
    assert not root.exists()


def test_collision_and_mid_batch_failure_preserve_user_data_and_no_partial_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同 render ID 不覆盖，第二张图中途失败仅清理本次 staging。"""
    published = _published(tmp_path, vector=False)
    root = tmp_path / "图片根"
    fixed_id = "20260916T010203123456Z-abcdef123456"
    monkeypatch.setattr(plotting, "_new_render_id", lambda: fixed_id)
    selection = plotting.PlotSelection(((0, 0),), (0,))
    first = plotting.render_saved_run(published.run_dir, selection, output_root=root)
    first_hash = sha256(first.manifest_path.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError, match="render ID 已存在"):
        plotting.render_saved_run(published.run_dir, selection, output_root=root)
    assert sha256(first.manifest_path.read_bytes()).hexdigest() == first_hash

    parent = root / published.run_id
    user_dir = parent / "user-owned"
    user_dir.mkdir()
    (user_dir / "keep.txt").write_text("保留", encoding="utf-8")
    second_id = "20260916T010204123456Z-abcdef123456"
    monkeypatch.setattr(plotting, "_new_render_id", lambda: second_id)
    original_savefig = Figure.savefig
    calls = 0

    def fail_second(figure: Figure, path: Path, *args: object, **kwargs: object) -> None:
        """模拟一张图已经写出、第二张在保存后失败。"""
        nonlocal calls
        calls += 1
        original_savefig(figure, path, *args, **kwargs)
        if calls == 2:
            raise OSError("simulated second figure failure")

    monkeypatch.setattr(Figure, "savefig", fail_second)
    with pytest.raises(OSError, match="second figure failure"):
        plotting.render_saved_run(published.run_dir, selection, output_root=root)
    assert not (parent / second_id).exists()
    assert not list(parent.glob(".incomplete-*"))
    assert (user_dir / "keep.txt").read_text(encoding="utf-8") == "保留"
    assert sha256(first.manifest_path.read_bytes()).hexdigest() == first_hash
