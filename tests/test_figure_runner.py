"""仅从已发布 run 调用薄绘图 CLI，核对 HVAC 默认与向量显式选择。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from secure_control.experiments.artifacts import RunArtifacts, write_artifacts
from secure_control.experiments.runner import run_experiment
from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult

PROJECT_ROOT = Path(__file__).parents[1]
HVAC_CONFIG = PROJECT_ROOT / "configs" / "hvac_dual_loop.yaml"


def _vector_run(tmp_path: Path) -> RunArtifacts:
    """用既有 writer 生成两组独立通道，避免 CLI 测试依赖另一测试模块。"""
    reference = ChannelMetadata(("setpoint_a", "setpoint_b"), ("unit_a", "unit_b"))
    output = ChannelMetadata(("output_a", "output_b", "pressure"), ("unit_a", "unit_b", "kPa"))
    control = ChannelMetadata(("applied_a", "applied_b"), ("power_a", "power_b"))
    metadata = ScenarioMetadata("toy", reference, output, control)
    ideal_output = np.array([[3.0, 4.0, 100.0], [4.0, 6.0, 101.0]])
    secure_output = np.array([[2.0, 4.0, 99.0], [5.0, 5.0, 102.0]])
    ideal_control = np.array([[1.0, 2.0], [2.0, 3.0]])
    secure_control = np.array([[1.0, 1.0], [2.0, 4.0]])
    result = SimulationResult(
        time=np.array([0.0, 60.0]),
        reference=np.array([[2.0, 4.0], [4.0, 5.0]]),
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
        {"scenario": {"name": "toy", "version": "1"}},
        {"scenario_name": "toy", "scenario_version": "1", "schema_version": 1},
        output_root=tmp_path / "向量 CSV",
    )


def _cli(run_dir: Path, output_root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    """复用当前 uv 进程的 Python 与本地 .venv，模拟用户的 `python -m` 调用。"""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_control.experiments.figure_runner",
            "--run-dir",
            str(run_dir),
            "--output-root",
            str(output_root),
            *extra,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_hvac_default_cli_renders_four_saved_run_figures_without_new_controller_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HVAC 默认 0→0/0、小时轴、四 PNG；绘图不进入仿真 runner。"""
    published = run_experiment(HVAC_CONFIG, test_seed=12, output_root=tmp_path / "HVAC CSV")
    output_root = tmp_path / "HVAC 图"

    def forbidden(*args: object, **kwargs: object) -> None:
        """直接 CLI 调用若尝试新的 controller run 则测试失败。"""
        raise AssertionError("figure CLI called simulation")

    monkeypatch.setattr("secure_control.simulation.runner.run", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "figure_runner",
            "--run-dir",
            str(published.run_dir),
            "--output-root",
            str(output_root),
            "--control-error-scale",
            "log",
        ],
    )
    from secure_control.experiments.figure_runner import main

    main()
    render_dirs = list((output_root / published.run_id).glob("*/figures_manifest.json"))
    assert len(render_dirs) == 1
    manifest = json.loads(render_dirs[0].read_text(encoding="utf-8"))
    assert manifest["scenario"] == {"name": "hvac", "version": "1"}
    assert len(manifest["figures"]) == 4
    assert {entry["category"] for entry in manifest["figures"]} == {
        "tracking",
        "control",
        "control_error",
        "output_error",
    }
    assert all(entry["time_unit"] == "h" for entry in manifest["figures"])
    assert manifest["figures"][0]["channels"]["output"]["name"] == "temperature"
    assert manifest["figures"][0]["channels"]["reference"]["name"] == "target_temperature"
    assert manifest["figures"][0]["channels"]["output"]["unit"] == "degC"
    assert all(
        (render_dirs[0].parent / entry["filename"]).is_file() for entry in manifest["figures"]
    )


def test_vector_cli_repeated_channel_pairs_and_pdf_output(tmp_path: Path) -> None:
    """非 HVAC 向量必须显式选择，可重复选通道并按同一批次发布 PDF。"""
    published = _vector_run(tmp_path)
    root = tmp_path / "向量 PDF 图"
    result = _cli(
        published.run_dir,
        root,
        "--tracking",
        "0:0",
        "--tracking",
        "1:1",
        "--control-channel",
        "0",
        "--control-channel",
        "1",
        "--format",
        "pdf",
        "--time-unit",
        "s",
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["source_run_id"] == published.run_id
    assert len(summary["figures"]) == 8
    assert all(Path(path).read_bytes().startswith(b"%PDF") for path in summary["figures"])
    manifest = json.loads(Path(summary["manifest"]).read_text(encoding="utf-8"))
    assert manifest["figure_format"] == "pdf"
    assert manifest["figures"][1]["channels"]["output"]["name"] == "output_b"
    assert manifest["figures"][1]["channels"]["reference"]["unit"] == "unit_b"


def test_vector_cli_selects_unmatched_output_error_channel(tmp_path: Path) -> None:
    """CLI 可画无同单位 reference 的 pressure error，tracking 仍只配合法通道。"""
    published = _vector_run(tmp_path)
    root = tmp_path / "pressure 图"
    result = _cli(
        published.run_dir,
        root,
        "--tracking",
        "0:0",
        "--control-channel",
        "0",
        "--output-error-channel",
        "2",
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    manifest = json.loads(Path(summary["manifest"]).read_text(encoding="utf-8"))
    errors = [item for item in manifest["figures"] if item["category"] == "output_error"]
    assert len(errors) == 1
    assert errors[0]["channels"]["output"] == {
        "index": 2,
        "name": "pressure",
        "unit": "kPa",
    }
    assert Path(summary["manifest"]).parent.joinpath("output_error-2.png").is_file()


@pytest.mark.parametrize(
    "extra",
    [
        (),
        ("--tracking", "bad"),
        ("--tracking", "9:0", "--control-channel", "0"),
        ("--tracking", "0:0", "--control-channel", "0", "--output-error-channel", "9"),
        (
            "--tracking",
            "0:0",
            "--control-channel",
            "0",
            "--output-error-channel",
            "2",
            "--output-error-channel",
            "2",
        ),
    ],
)
def test_cli_rejects_missing_or_invalid_vector_selection_without_figures(
    tmp_path: Path, extra: tuple[str, ...]
) -> None:
    """错误选择由参数解析/metadata 校验失败，不能留下成功图目录。"""
    published = _vector_run(tmp_path)
    root = tmp_path / "失败图根"
    failed = _cli(published.run_dir, root, *extra)
    assert failed.returncode != 0
    assert not root.exists()


def test_cli_rejects_corrupt_published_schema_without_output(tmp_path: Path) -> None:
    """thin CLI 不能绕过 reader 对不完整 source run 的拒绝。"""
    published = _vector_run(tmp_path)
    metadata = json.loads(published.metadata_path.read_text(encoding="utf-8"))
    metadata["schema_version"] = 2
    published.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    root = tmp_path / "损坏不发布"
    failed = _cli(published.run_dir, root, "--tracking", "0:0", "--control-channel", "0")
    assert failed.returncode != 0
    assert "schema version" in failed.stderr
    assert not root.exists()
