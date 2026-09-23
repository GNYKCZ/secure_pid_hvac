"""#69 自选串联对象的单支明文入口；不复用双支 secure artifact schema。"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

import numpy as np
import yaml

from secure_control.scenarios.paper_pid.baseline import (
    BASELINE_COLUMNS,
    PaperPidBaseline,
    run_paper_pid_baseline,
)
from secure_control.scenarios.paper_pid.pid import paper_sec_vii_controller_spec


def _require_keys(name: str, value: Any, expected: set[str]) -> dict[str, Any]:
    """严格限定固定实验配置字段，避免拼写错误被静默忽略。"""
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} 字段必须恰好是 {sorted(expected)}")
    return value


def _load_config(path: Path) -> tuple[dict[str, Any], str]:
    """锁定论文参数和 paper-inspired 身份；变体需另作显式设计。"""
    raw_bytes = path.read_bytes()
    loaded = yaml.safe_load(raw_bytes.decode("utf-8"))
    config = _require_keys(
        "config",
        loaded,
        {"schema_version", "claim_level", "sources", "controller", "plant", "sample_count"},
    )
    sources = _require_keys("sources", config["sources"], {"controller", "plant", "plant_equation"})
    plant = _require_keys(
        "plant",
        config["plant"],
        {"alpha", "sample_period_seconds", "initial_state", "realization", "discretization"},
    )
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("schema_version 必须是 1")
    if config["claim_level"] != "paper-inspired":
        raise ValueError("仅允许 paper-inspired 声明等级")
    if config["controller"] != "printed_section_vii":
        raise ValueError("仅允许论文 §VII 印刷控制器")
    if (
        sources["controller"] != "https://arxiv.org/html/2503.02176v3#S7"
        or sources["plant"] != "https://doi.org/10.1016/S1474-6670(17)38238-1"
        or sources["plant_equation"] != "Eq. (2)"
    ):
        raise ValueError("来源必须对应论文 v3 §VII 与 [38] Eq. (2)")
    if (
        plant["realization"] != "four_stage_cascade_outputs"
        or plant["discretization"] != "zoh"
    ):
        raise ValueError("只支持已审查的四级串联坐标和 ZOH")
    for name, expected in (("alpha", 0.2), ("sample_period_seconds", 0.1)):
        value = plant[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != expected:
            raise ValueError(f"{name} 必须保持论文实例值 {expected}")
    if (
        not isinstance(plant["initial_state"], list)
        or len(plant["initial_state"]) != 4
        or any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or value != 100.0
            for value in plant["initial_state"]
        )
    ):
        raise ValueError("initial_state 必须是论文四个 100 的数值向量")
    if type(config["sample_count"]) is not int or config["sample_count"] != 51:
        raise ValueError("sample_count 必须是 k=0..50 对应的 51")
    return config, sha256(raw_bytes).hexdigest()


def _git_revision() -> dict[str, Any]:
    """记录源码 commit 与 dirty 状态；无可靠 Git 身份时拒绝成功发布。"""
    root = Path(__file__).resolve().parents[3]
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True, capture_output=True, text=True,
    ).stdout
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ValueError("无法验证 Git head SHA")
    return {"head_sha": head, "dirty": bool(status.strip())}


def _json_bytes(value: dict[str, Any]) -> bytes:
    """使用确定性 UTF-8 JSON，并拒绝非标准 NaN/Infinity。"""
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def _write_csv(path: Path, result: PaperPidBaseline) -> None:
    """十七位有效数字保留 binary64 轨迹的可读写回环。"""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(BASELINE_COLUMNS)
        for row in result.rows:
            writer.writerow([int(row[0]), *(format(float(value), ".17g") for value in row[1:])])


def _verify_staging(path: Path, expected: PaperPidBaseline) -> None:
    """正式发布前读回 CSV 和 sidecar，避免半写入被标为成功。"""
    trajectory = path / "trajectory.csv"
    metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
    with trajectory.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        if tuple(next(reader)) != BASELINE_COLUMNS:
            raise ValueError("轨迹列与单支 schema 不一致")
        rows = np.asarray([[float(item) for item in row] for row in reader], dtype=float)
    if rows.shape != expected.rows.shape or not np.array_equal(rows, expected.rows):
        raise ValueError("CSV 数值读回与本次轨迹不一致")
    if metadata["trajectory"]["sha256"] != sha256(trajectory.read_bytes()).hexdigest():
        raise ValueError("CSV SHA256 与 sidecar 不一致")
    if metadata["trajectory"]["sample_count"] != rows.shape[0]:
        raise ValueError("CSV 样本数与 sidecar 不一致")


def run_paper_pid_experiment(
    config_path: str | Path,
    *,
    output_root: str | Path = "results/csv/paper_pid_cascade_zoh",
) -> Path:
    """从固定配置重建 51 点明文轨迹，并原子发布独立目录。"""
    config, config_hash = _load_config(Path(config_path))
    plant = config["plant"]
    result = run_paper_pid_baseline(
        alpha=plant["alpha"],
        sample_period_seconds=plant["sample_period_seconds"],
        plant_initial_state=plant["initial_state"],
        sample_count=config["sample_count"],
    )
    git = _git_revision()
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    run_id = uuid4().hex
    final = root / run_id
    if os.path.lexists(final):
        raise FileExistsError(f"运行目录已存在：{run_id}")
    with TemporaryDirectory(prefix=".incomplete-", dir=root) as temporary:
        stage = Path(temporary)
        trajectory = stage / "trajectory.csv"
        _write_csv(trajectory, result)
        m = result.plant_matrices
        controller = paper_sec_vii_controller_spec()
        metadata = {
            "schema_version": 1,
            "success": True,
            "run_id": run_id,
            "claim_level": "paper-inspired",
            "sources": config["sources"],
            "config_sha256": config_hash,
            "git": git,
            "model": {
                "realization": plant["realization"],
                "state_coordinates": "four successive first-order stage outputs",
                "discretization": plant["discretization"],
                "alpha": plant["alpha"],
                "sample_period_seconds": plant["sample_period_seconds"],
                "plant_initial_state": plant["initial_state"],
                "controller_initial_state": controller.x0.tolist(),
                "F": m.F.tolist(), "G": m.G.tolist(), "H": m.H.tolist(), "J": m.J.tolist(),
                "A_p": m.A_p.tolist(), "B_p": m.B_p.tolist(),
                "C_p": m.C_p.tolist(), "D_p": m.D_p.tolist(),
            },
            "controller": {
                "source": "printed_section_vii",
                "A": controller.A.tolist(), "B": controller.B.tolist(),
                "C": controller.C.tolist(), "D": controller.D.tolist(),
            },
            "trajectory": {
                "columns": list(BASELINE_COLUMNS),
                "sample_count": int(result.rows.shape[0]),
                "time_index": "pre-plant and pre-controller state; k=0..50",
                "control_semantics": "raw unclipped u; input is plant y; no reference",
                "physical_units": "not specified by the cited benchmark equation",
                "sha256": sha256(trajectory.read_bytes()).hexdigest(),
            },
            "closed_loop_stability": asdict(result.stability),
            "limitation": "Self-chosen plant coordinates/ZOH, not the authors' original matrices or Fig. 3 trajectory.",
        }
        (stage / "metadata.json").write_bytes(_json_bytes(metadata))
        _verify_staging(stage, result)
        if os.path.lexists(final):
            raise FileExistsError(f"运行目录已存在：{run_id}")
        os.rename(stage, final)
    return final


def main() -> None:
    """显式运行 paper-inspired 基线，打印产物路径供读者复验。"""
    parser = argparse.ArgumentParser(description="Run paper-inspired PID plaintext baseline")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-root", default="results/csv/paper_pid_cascade_zoh")
    arguments = parser.parse_args()
    run_dir = run_paper_pid_experiment(arguments.config, output_root=arguments.output_root)
    print(json.dumps({"run_dir": str(run_dir), "claim_level": "paper-inspired"}))


if __name__ == "__main__":
    main()
