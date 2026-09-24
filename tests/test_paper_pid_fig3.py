"""#70 正式四点 reader、清单、图与来源失败关闭测试。"""

from __future__ import annotations

import json
from pathlib import Path
from shutil import copy2

import pytest
import yaml

from secure_control.experiments.paper_pid_fig3 import (
    load_definition,
    render_saved_sweep,
    run_sweep,
)

CONFIGS = Path(__file__).resolve().parents[1] / "configs"


def test_four_saved_runs_and_figure_are_derived_from_verified_reader(tmp_path: Path) -> None:
    root = run_sweep(CONFIGS / "paper_pid_fig3_sweep.yaml", output_root=tmp_path / "runs")
    manifest = render_saved_sweep(root)
    assert [item["ell"] for item in manifest["summaries"]] == [32, 40, 48, 56]
    assert all(item["below_epsilon"] for item in manifest["summaries"])
    assert manifest["summaries"][2]["below_numeric_resolution"]
    assert manifest["summaries"][3]["below_numeric_resolution"]
    assert (root / "fig3.png").stat().st_size > 1000
    assert len(manifest["runs"]) == 4
    changed = root / manifest["runs"][0]["run_id"] / "trajectory.csv"
    changed.write_bytes(changed.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="摘要"):
        render_saved_sweep(root)


def test_missing_point_or_tampered_manifest_rejected(tmp_path: Path) -> None:
    root = run_sweep(CONFIGS / "paper_pid_fig3_sweep.yaml", output_root=tmp_path / "runs")
    path = root / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["runs"].pop()
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="四个精度"):
        render_saved_sweep(root)


def test_source_drift_and_wrong_precision_fail_before_publish(tmp_path: Path) -> None:
    for name in ("paper_pid_fig3_sweep.yaml", "paper_pid_cascade_zoh.yaml",
                 "hvac_2r2c_sweep_prime.yaml"):
        copy2(CONFIGS / name, tmp_path / name)
    path = tmp_path / "paper_pid_fig3_sweep.yaml"
    definition = yaml.safe_load(path.read_text(encoding="utf-8"))
    definition["fractional_bits"] = [32, 40, 48, 58]
    path.write_text(yaml.safe_dump(definition), encoding="utf-8")
    with pytest.raises(ValueError, match="冻结"):
        run_sweep(path, output_root=tmp_path / "runs")
    assert not (tmp_path / "runs").exists()
    copy2(CONFIGS / "paper_pid_fig3_sweep.yaml", path)
    with (tmp_path / "paper_pid_cascade_zoh.yaml").open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError, match="摘要"):
        load_definition(path)
