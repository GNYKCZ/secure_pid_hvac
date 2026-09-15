"""显式选择当前已实现的场景，再调用纯仿真 runner 和通用结果 writer。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path

import yaml

from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation import run

from .artifacts import SCHEMA_VERSION, RunArtifacts, write_artifacts
from .provenance import collect_provenance


class UnsupportedScenarioError(ValueError):
    """配置请求了当前实验 composition root 尚未实现的场景。"""


def select_scenario(config_path: str | Path, *, test_seed: int | None = None) -> HvacScenario:
    """只认显式 scenario.name=hvac；不使用动态 import、registry 或 fallback。"""
    path = Path(config_path)
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"无法读取实验配置：{path}") from error
    if not isinstance(loaded, Mapping):
        raise TypeError("实验配置根节点必须是映射。")
    selector = loaded.get("scenario")
    if not isinstance(selector, Mapping):
        raise TypeError("scenario 必须是映射。")
    name = selector.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("scenario.name 必须是非空字符串。")
    if name == "hvac":
        return HvacScenario(path, test_seed=test_seed)
    raise UnsupportedScenarioError(f"unsupported scenario.name: {name}")


def run_experiment(
    config_path: str | Path,
    *,
    test_seed: int | None = None,
    output_root: str | Path = "results/csv",
) -> RunArtifacts:
    """每次重建完整场景/session；仿真及场景校验成功后才发布原始产物。"""
    scenario = select_scenario(config_path, test_seed=test_seed)
    result = run(scenario)
    scenario.metrics(result)
    effective_config = scenario.effective_config_snapshot()
    provenance = collect_provenance(
        scenario_name=scenario.metadata.name,
        scenario_version=scenario.scenario_version,
        schema_version=SCHEMA_VERSION,
        test_seed=test_seed,
    )
    return write_artifacts(
        result,
        scenario.metadata,
        effective_config,
        provenance,
        output_root=output_root,
    )


def main() -> None:
    """输出成功目录摘要；失败由异常传播并以非零退出，不打印敏感材料。"""
    parser = argparse.ArgumentParser(description="Run a scenario and publish generic artifacts")
    parser.add_argument("--config", required=True, help="scenario-aware YAML configuration")
    parser.add_argument("--seed", type=int, default=None, help="test-only secure material seed")
    parser.add_argument("--output-root", default="results/csv", help="published run directory root")
    args = parser.parse_args()
    artifacts = run_experiment(args.config, test_seed=args.seed, output_root=args.output_root)
    print(json.dumps({"run_id": artifacts.run_id, "run_dir": str(artifacts.run_dir)}))


if __name__ == "__main__":
    main()
