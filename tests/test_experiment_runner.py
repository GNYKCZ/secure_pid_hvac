"""Issue #13 显式选择、HVAC 全状态重建、CLI/provenance 与场景边界回归。"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np
import pytest
import yaml

from secure_control.experiments.artifacts import load_artifacts
from secure_control.experiments.runner import (
    UnsupportedScenarioError,
    run_experiment,
    select_scenario,
)
from secure_control.scenarios.hvac import (
    evaluate_hvac_comparison_metrics,
    load_hvac_pid_baseline_resolution,
    load_hvac_pid_tuning_contract,
    load_hvac_scenario_contract,
)
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation import (
    ChannelMetadata,
    ScenarioMetadata,
    SimulationBranch,
    SimulationPlan,
)

PROJECT_ROOT = Path(__file__).parents[1]
CONFIG_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_dual_loop.yaml"
BASELINE_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_pid_baseline.yaml"
CONFIG_2R2C_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_dual_loop.yaml"
CONFIG_2R2C_MIGRATED_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_dual_loop_25_20_15.yaml"
BASELINE_2R2C_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_pid_baseline.yaml"
BASELINE_2R2C_MIGRATED_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_pid_baseline_25_20_15.yaml"
PLANT_2R2C_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_plant.yaml"
SCENARIO_2R2C_MIGRATED_PATH = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_scenario_25_20_15.yaml"


def test_selector_accepts_only_explicit_hvac_and_rejects_unimplemented_names(
    tmp_path: Path,
) -> None:
    """未来名字可写在 YAML，但本 Issue 不动态加载也不实现第二 plant。"""
    selected = select_scenario(CONFIG_PATH, test_seed=12)
    assert isinstance(selected, HvacScenario)
    assert selected.metadata.name == "hvac"
    for name in ("inverted_pendulum", "unknown"):
        config = tmp_path / f"{name}.yaml"
        config.write_text(yaml.safe_dump({"scenario": {"name": name}}), encoding="utf-8")
        with pytest.raises(UnsupportedScenarioError, match="unsupported scenario.name"):
            select_scenario(config)


@pytest.mark.parametrize(
    ("content", "error"),
    [
        ("[]", TypeError),
        ("scenario: []", TypeError),
        ("scenario: {}", ValueError),
        ("scenario:\n  name: 13", ValueError),
        ("scenario: [", ValueError),
    ],
)
def test_selector_rejects_missing_or_invalid_yaml(
    tmp_path: Path, content: str, error: type[Exception]
) -> None:
    """无效 YAML/selector 在建立运行时和正式目录前失败。"""
    config = tmp_path / "invalid.yaml"
    config.write_text(content, encoding="utf-8")
    with pytest.raises(error):
        select_scenario(config)
    with pytest.raises(ValueError, match="无法读取实验配置"):
        select_scenario(tmp_path / "missing.yaml")


def test_hvac_wrapper_validates_selector_again_at_scenario_boundary(tmp_path: Path) -> None:
    """直接调用 HVAC composition 时也不能绕过 wrapper scenario.name。"""
    loaded = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    loaded["scenario"]["name"] = "inverted_pendulum"
    config = tmp_path / "invalid-hvac.yaml"
    config.write_text(yaml.safe_dump(loaded), encoding="utf-8")
    with pytest.raises(ValueError, match="scenario.name 必须为 hvac"):
        HvacScenario(config)


def test_snapshot_of_absolute_baseline_reference_keeps_only_source_filename(
    tmp_path: Path,
) -> None:
    """可用绝对路径加载现有 baseline，但正式配置不泄露机器路径。"""
    loaded = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    loaded["baseline_config"] = str(BASELINE_PATH)
    wrapper = tmp_path / "wrapper.yaml"
    wrapper.write_text(yaml.safe_dump(loaded), encoding="utf-8")
    snapshot = HvacScenario(wrapper).effective_config_snapshot()
    assert snapshot["wrapper"]["baseline_config"] == BASELINE_PATH.name
    assert str(BASELINE_PATH) not in json.dumps(snapshot)


def test_seeded_hvac_reruns_publish_distinct_ids_but_identical_numeric_csv_and_new_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """每 run 新建两支及协议资源，同 config/测试 seed 的八字段和 CSV 完全可复现。"""
    plans: list[SimulationPlan] = []
    original_build = HvacScenario.build_plan

    def capture_plan(self: HvacScenario) -> SimulationPlan:
        """记录真实 composition 产生的对象身份，不改变仿真执行。"""
        plan = original_build(self)
        plans.append(plan)
        return plan

    monkeypatch.setattr(HvacScenario, "build_plan", capture_plan)
    root = tmp_path / "CSV 结果"
    first = run_experiment(CONFIG_PATH, test_seed=12, output_root=root)
    second = run_experiment(CONFIG_PATH, test_seed=12, output_root=root)
    assert first.run_id != second.run_id
    assert first.trajectory_path.read_bytes() == second.trajectory_path.read_bytes()
    first_record = load_artifacts(first.run_dir)
    second_record = load_artifacts(second.run_dir)
    for field in first_record.result.__dataclass_fields__:
        np.testing.assert_array_equal(
            getattr(first_record.result, field), getattr(second_record.result, field)
        )
    assert first_record.result.time.size == 180
    assert len(plans) == 2
    assert plans[0].ideal.plant is not plans[1].ideal.plant
    assert plans[0].secure.plant is not plans[1].secure.plant
    assert plans[0].ideal.runtime is not plans[1].ideal.runtime
    assert plans[0].secure.runtime is not plans[1].secure.runtime
    assert plans[0].secure.runtime._client is not plans[1].secure.runtime._client
    for plan in plans:
        assert plan.ideal.plant is not plan.secure.plant
        assert plan.ideal.runtime is not plan.secure.runtime
        assert plan.secure.runtime._client.multiplier.created_triples == 1620
        assert plan.secure.runtime._client.multiplier.consumed_triples == 1620
        assert plan.secure.runtime._client.truncation.created_masks == 0
    assert len([item for item in root.iterdir() if item.is_dir()]) == 2
    assert not list(root.glob(".incomplete-*"))


def test_effective_snapshot_and_provenance_record_actual_public_inputs(tmp_path: Path) -> None:
    """快照包含 wrapper+baseline 有效值及来源 hash，不转储本地路径或安全材料。"""
    published = run_experiment(CONFIG_PATH, test_seed=13, output_root=tmp_path / "results")
    record = load_artifacts(published.run_dir)
    config = record.effective_config
    provenance = record.provenance
    assert config["scenario"] == {"name": "hvac", "version": "1"}
    assert config["sources"]["wrapper"]["sha256"] == sha256(CONFIG_PATH.read_bytes()).hexdigest()
    assert config["sources"]["baseline"]["sha256"] == sha256(BASELINE_PATH.read_bytes()).hexdigest()
    assert config["wrapper"]["security"]["fractional_bits"] == 20
    assert config["hvac"]["timing"]["sample_count"] == 180
    assert config["hvac"]["model"]["upper_control_bound_kw"] == 12.0
    assert config["hvac"]["pid"]["integral_gain_kw_per_celsius_second"] == -0.0005
    assert config["finite_horizon_certificate"]["horizon_steps"] == 180
    assert config["modulus_verification"] == {
        "modulus": "2305843009213693951",
        "bit_length": 61,
        "method": "deterministic_miller_rabin_64_v1",
        "status": "verified",
        "source": "secure_control.crypto.primes",
        "source_version": "mr64-v1",
        "certificate_id": None,
        "certificate_sha256": None,
    }
    assert config["execution"] == {
        "secure_material_test_seed": 13,
        "secure_material_randomness": "deterministic_test",
    }
    assert provenance["scenario_name"] == "hvac"
    assert provenance["schema_version"] == 1
    assert provenance["configured_seeds"] == {"secure_material_test_seed": 13}
    assert provenance["secure_material_randomness"] == "deterministic_test"
    assert provenance["project_version"] == "0.1.0"
    assert provenance["git"]["available"] is True
    assert (
        provenance["git"]["commit"]
        == subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    assert isinstance(provenance["git"]["dirty"], bool)
    assert (
        provenance["uv_lock"]["sha256"]
        == sha256((PROJECT_ROOT / "uv.lock").read_bytes()).hexdigest()
    )
    assert "numpy" in provenance["dependency_versions"]
    assert provenance["python"]["version"] == platform.python_version()
    assert provenance["platform"]["system"] == platform.system()
    serialized = json.dumps({"config": config, "provenance": provenance})
    assert str(PROJECT_ROOT) not in serialized
    assert "private_key" not in serialized
    assert "triple_share" not in serialized


def test_2r2c_saved_run_has_three_source_hashes_and_reader_recomputes_same_metrics(
    tmp_path: Path,
) -> None:
    """正式 reader 读回同一 run 后可重算通过的指标，且快照绑定三份源配置。"""
    published = run_experiment(
        CONFIG_2R2C_PATH, test_seed=42, output_root=tmp_path / "2R2C results"
    )
    record = load_artifacts(published.run_dir)
    sources = record.effective_config["sources"]
    assert sources == {
        "wrapper": {
            "filename": CONFIG_2R2C_PATH.name,
            "sha256": sha256(CONFIG_2R2C_PATH.read_bytes()).hexdigest(),
        },
        "baseline": {
            "filename": BASELINE_2R2C_PATH.name,
            "sha256": sha256(BASELINE_2R2C_PATH.read_bytes()).hexdigest(),
        },
        "plant": {
            "filename": PLANT_2R2C_PATH.name,
            "sha256": sha256(PLANT_2R2C_PATH.read_bytes()).hexdigest(),
        },
    }
    contract = load_hvac_scenario_contract(PLANT_2R2C_PATH)
    _, _, quality = load_hvac_pid_tuning_contract(BASELINE_2R2C_PATH, contract)
    metrics = evaluate_hvac_comparison_metrics(record.result, contract, quality)
    assert metrics.passed
    assert metrics.max_control_error_kw == pytest.approx(
        np.max(np.abs(record.result.control_error))
    )
    assert metrics.max_temperature_error_celsius == pytest.approx(
        np.max(np.abs(record.result.output_error))
    )
    assert record.effective_config["hvac"]["tuning"]["evaluated_candidate_count"] == 10179
    assert record.effective_config["hvac"]["tuning"]["feasible_candidate_count"] == 679
    assert record.effective_config["finite_horizon_certificate"]["state_truncation_bits"] == 0


def test_migrated_2r2c_run_preserves_identity_and_reader_recomputes_metrics(
    tmp_path: Path,
) -> None:
    """新代表 run 沿用 schema v1，保存稳定身份并可由 canonical reader 重算指标。"""
    published = run_experiment(
        CONFIG_2R2C_MIGRATED_PATH,
        test_seed=42,
        output_root=tmp_path / "migrated 2R2C results",
    )
    record = load_artifacts(published.run_dir)
    contract = load_hvac_scenario_contract(SCENARIO_2R2C_MIGRATED_PATH)
    resolution = load_hvac_pid_baseline_resolution(BASELINE_2R2C_MIGRATED_PATH, contract)
    metrics = evaluate_hvac_comparison_metrics(record.result, contract, resolution.quality_contract)
    identity = record.effective_config["baseline_identity"]
    scenario_identity = HvacScenario(CONFIG_2R2C_MIGRATED_PATH).baseline_identity
    assert scenario_identity is not None
    assert metrics.passed
    assert identity["baseline_id"] == scenario_identity.baseline_id
    assert record.effective_config["hvac"]["pid_selection"]["pid_reused"] is True
    assert record.effective_config["hvac"]["pid_selection"]["tuning_executed"] is False
    assert record.effective_config["hvac"]["pid_selection"]["evaluated_candidate_count"] == 0


def test_default_randomness_is_recorded_without_inventing_seed(tmp_path: Path) -> None:
    """省略 seed 时仍能运行，但 metadata 不冒称逐次随机材料可复现。"""
    published = run_experiment(CONFIG_PATH, output_root=tmp_path / "results")
    record = load_artifacts(published.run_dir)
    assert record.provenance["configured_seeds"] == {}
    assert record.provenance["secure_material_randomness"] == "secure_random"
    assert record.effective_config["execution"]["secure_material_test_seed"] is None


def test_scenario_validation_failure_does_not_publish_success_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scene metrics 若失败，实验层不能越过校验去保存轨迹。"""

    def fail_metrics(self: HvacScenario, result: object) -> None:
        """模拟场景级物理边界校验失败。"""
        raise ValueError("simulated scene validation failure")

    monkeypatch.setattr(HvacScenario, "metrics", fail_metrics)
    root = tmp_path / "never-published"
    with pytest.raises(ValueError, match="scene validation failure"):
        run_experiment(CONFIG_PATH, test_seed=14, output_root=root)
    assert not root.exists()


def test_cli_runs_hvac_and_invalid_seed_exits_nonzero_with_unicode_root(tmp_path: Path) -> None:
    """正式 `python -m` 入口支持路径空格/中文，CLI 参数错误不给成功目录。"""
    root = tmp_path / "中文 输出路径"
    command = [
        sys.executable,
        "-m",
        "secure_control.experiments.runner",
        "--config",
        str(CONFIG_PATH),
        "--output-root",
        str(root),
    ]
    success = subprocess.run(
        command + ["--seed", "15"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert success.returncode == 0, success.stderr
    run_dir = Path(json.loads(success.stdout)["run_dir"])
    assert run_dir.is_dir()
    assert load_artifacts(run_dir).result.time.size == 180
    before = sorted(path.name for path in root.iterdir())
    invalid = subprocess.run(
        command + ["--seed", "bad"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert invalid.returncode != 0
    assert sorted(path.name for path in root.iterdir()) == before


def test_non_hvac_plan_fixture_uses_same_experiment_runner_and_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """仅替换显式选择结果即可运行 toy 向量计划，engine/writer 无需场景算法分支。"""
    from secure_control.experiments import runner as experiment_runner

    channels = ChannelMetadata(("first", "second"), ("unit", "unit"))
    metadata = ScenarioMetadata("toy", channels, channels, channels)

    class ToyPlant:
        """两支状态独立的最小向量 plant。"""

        def __init__(self, start: float) -> None:
            self.state = np.full(2, start)

        def output(self) -> np.ndarray:
            return self.state.copy()

        def step(self, control: np.ndarray) -> np.ndarray:
            self.state += control
            return self.output()

    class ToyAdapter:
        """toy 场景拥有自己的 v 映射和恒等 actuator。"""

        def __init__(self) -> None:
            self.metadata = metadata

        def reference_at(self, time: float) -> np.ndarray:
            return np.array([1.0, 2.0])

        def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
            return reference - output

        def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
            return raw_control.copy()

    class ToyRuntime:
        """透传向量 runtime，仅用于实验层边界 fixture。"""

        def step(self, value: np.ndarray) -> np.ndarray:
            return value.copy()

        def reset(self) -> None:
            """此 fixture 无内部状态。"""

    class ToyScenario:
        """以相同 Scenario 接口提供版本、元数据、快照与校验。"""

        scenario_version = "1"

        def __init__(self) -> None:
            self.metadata = metadata

        def build_plan(self) -> SimulationPlan:
            return SimulationPlan(
                self.metadata,
                np.array([0.0, 1.0]),
                SimulationBranch(ToyPlant(0.0), ToyAdapter(), ToyRuntime()),
                SimulationBranch(ToyPlant(0.5), ToyAdapter(), ToyRuntime()),
            )

        def metrics(self, result: object) -> None:
            """无场景指标，但保留实验层成功前校验 hook。"""

        def effective_config_snapshot(self) -> dict[str, Any]:
            return {"scenario": {"name": "toy", "version": "1"}}

    monkeypatch.setattr(experiment_runner, "select_scenario", lambda *args, **kwargs: ToyScenario())
    published = experiment_runner.run_experiment("not-read.yaml", output_root=tmp_path / "toy")
    record = load_artifacts(published.run_dir)
    assert record.metadata.name == "toy"
    assert record.result.output_ideal.shape == (2, 2)
    assert record.result.control_error.shape == (2, 2)
