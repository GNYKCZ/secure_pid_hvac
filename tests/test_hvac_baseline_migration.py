"""Issue #53 的 25→20→15 正式基线迁移、门禁与身份回归测试。"""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest
import yaml

import secure_control.scenarios.hvac.migration as migration_module
from secure_control.scenarios.hvac import (
    HvacPidSelectionRecord,
    HvacPidTuningResult,
    HvacPidValidationResult,
    build_hvac_baseline_identity,
    canonical_hvac_source_sha256,
    load_hvac_pid_baseline_resolution,
    load_hvac_scenario_contract,
    selection_record_payload,
)
from secure_control.scenarios.hvac.integration import HvacScenario, run_hvac_dual_loop

PROJECT_ROOT = Path(__file__).parents[1]
CONFIGS = PROJECT_ROOT / "configs"
WRAPPER = CONFIGS / "hvac_2r2c_dual_loop_25_20_15.yaml"
BASELINE = CONFIGS / "hvac_2r2c_pid_baseline_25_20_15.yaml"
SCENARIO = CONFIGS / "hvac_2r2c_scenario_25_20_15.yaml"
OLD_WRAPPER = CONFIGS / "hvac_2r2c_dual_loop.yaml"
OLD_BASELINE = CONFIGS / "hvac_2r2c_pid_baseline.yaml"
OLD_SCENARIO = CONFIGS / "hvac_2r2c_plant.yaml"


def _copy_migration_chain(destination: Path) -> Path:
    """复制测试所需的完整配置链，避免篡改仓库中的冻结配置。"""
    for source in (BASELINE, SCENARIO, OLD_BASELINE, OLD_SCENARIO):
        (destination / source.name).write_bytes(source.read_bytes())
    return destination / BASELINE.name


def test_new_scenario_changes_only_reference_and_preserves_historical_hashes() -> None:
    """迁移不得改写历史基线，且新 scenario 除 reference 外保持 plant 契约完全相同。"""
    assert canonical_hvac_source_sha256(OLD_WRAPPER.read_bytes()) == (
        "d16a51688df4fc2b94eeda6adeb62e2fe50c48f6a9a3c6a91d97ce87b3ac7e3f"
    )
    assert canonical_hvac_source_sha256(OLD_BASELINE.read_bytes()) == (
        "f5df82b1dc21123ed6d138006bedbdd1e1de595d8c56d1f6791f2ae9c008a44e"
    )
    assert canonical_hvac_source_sha256(OLD_SCENARIO.read_bytes()) == (
        "54d980b7b3d5ef7f9187de008a78348748f0246193fc8bdaf4ef9a3f6be33dbd"
    )

    old = yaml.safe_load(OLD_SCENARIO.read_text(encoding="utf-8"))["scenario"]["hvac"]
    new = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))["scenario"]["hvac"]
    old_reference = old.pop("reference")
    new_reference = new.pop("reference")
    assert new == old
    assert old_reference["segments"][0]["target_temperature_celsius"] == 15.0
    assert [item["target_temperature_celsius"] for item in new_reference["segments"]] == [
        25.0,
        20.0,
        15.0,
    ]
    assert new_reference["endpoint_value_celsius"] == 15.0


def test_current_pid_passes_before_tuner_and_records_zero_evaluations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """旧 PID 通过明文门禁时不得触发 10179 点网格搜索。"""
    contract = load_hvac_scenario_contract(SCENARIO)

    def unexpected_tuning(*args: object, **kwargs: object) -> None:
        """若条件式门禁错误地调用 tuner，则立即暴露回归。"""
        raise AssertionError("通过门禁后不应执行 tuner")

    monkeypatch.setattr(migration_module, "tune_hvac_pid", unexpected_tuning)
    resolution = load_hvac_pid_baseline_resolution(BASELINE, contract)
    selection = resolution.selection
    assert selection.current_validation.passed
    assert selection.pid_reused
    assert not selection.tuning_executed
    assert selection.search_space_candidate_count == 10179
    assert selection.evaluated_candidate_count == 0
    assert selection.feasible_candidate_count is None
    assert selection.old_design == selection.final_design == resolution.design


def test_failed_current_pid_gate_executes_frozen_fallback_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """门禁失败分支必须执行原冻结网格，并把实际选择过程逐字段写入声明。"""
    contract = load_hvac_scenario_contract(SCENARIO)
    original = load_hvac_pid_baseline_resolution(BASELINE, contract)
    original_validation = original.selection.current_validation
    failed_segment = replace(
        original_validation.metrics.segments[0],
        passed=False,
        violations=("mae_celsius",),
    )
    failed_metrics = replace(
        original_validation.metrics,
        segments=(failed_segment, *original_validation.metrics.segments[1:]),
        passed=False,
    )
    failed_validation = HvacPidValidationResult(
        original.selection.old_design,
        failed_metrics,
        ("segment_0:mae_celsius",),
    )
    tuned = HvacPidTuningResult(
        original.design,
        10179,
        1,
        {"segment_0:mae_celsius": 1},
        (0.1, 0.2, 0.0, 0.5, 0.0007, 0.85, -0.85, -0.0007, -0.5),
    )
    declared_record = HvacPidSelectionRecord(
        method="validate_current_then_conditionally_tune_v1",
        source_pid_filename=OLD_BASELINE.name,
        source_pid_sha256=original.selection.source_pid_sha256,
        pid_reused=False,
        old_design=original.selection.old_design,
        final_design=tuned.selected_design,
        current_validation=failed_validation,
        tuning_executed=True,
        search_space_candidate_count=10179,
        evaluated_candidate_count=10179,
        feasible_candidate_count=1,
        selected_objective=tuned.selected_objective,
        rejection_counts=tuned.rejection_counts,
        quality_contract_sha256=original.selection.quality_contract_sha256,
    )
    declared = selection_record_payload(declared_record)
    for key in ("method", "source_pid_filename", "source_pid_sha256", "quality_contract_sha256"):
        declared.pop(key)
    baseline = _copy_migration_chain(tmp_path)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    loaded["migration"]["selection"] = declared
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    calls = 0

    def fail_current(*args: object, **kwargs: object) -> HvacPidValidationResult:
        """模拟旧 PID 不满足新参考品质门槛。"""
        return failed_validation

    def run_fallback(*args: object, **kwargs: object) -> HvacPidTuningResult:
        """记录 fallback 仅被调用一次，并返回可审计的冻结结果。"""
        nonlocal calls
        calls += 1
        return tuned

    monkeypatch.setattr(migration_module, "validate_hvac_pid_design", fail_current)
    monkeypatch.setattr(migration_module, "tune_hvac_pid", run_fallback)
    resolution = load_hvac_pid_baseline_resolution(
        baseline, load_hvac_scenario_contract(tmp_path / SCENARIO.name)
    )
    assert calls == 1
    assert not resolution.selection.pid_reused
    assert resolution.selection.tuning_executed
    assert resolution.selection.evaluated_candidate_count == 10179


def test_declared_selection_tampering_fails_closed(tmp_path: Path) -> None:
    """配置中伪造 evaluated count 时必须在安全运行时创建前拒绝。"""
    baseline = _copy_migration_chain(tmp_path)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    loaded["migration"]["selection"]["evaluated_candidate_count"] = 1
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="selection 声明"):
        load_hvac_pid_baseline_resolution(
            baseline, load_hvac_scenario_contract(tmp_path / SCENARIO.name)
        )


def test_formal_dual_loop_identity_is_seed_independent_and_metrics_pass() -> None:
    """正式 180 步双闭环通过品质契约，baseline identity 不含随机 seed。"""
    first = HvacScenario(WRAPPER, test_seed=1)
    second = HvacScenario(WRAPPER, test_seed=2)
    assert first.baseline_identity is not None
    assert second.baseline_identity is not None
    assert first.baseline_identity.baseline_id == second.baseline_identity.baseline_id
    snapshot = first.effective_config_snapshot()
    identity = snapshot["baseline_identity"]
    assert identity["baseline_id"] == first.baseline_identity.baseline_id
    assert identity["start_commit"] == "a1561d0800127e35f263cf6afd0213d4d7563a3a"
    assert identity["supersedes_baseline"] == (
        "2489e5476ad316ea2d9599783e29f2d849ffcf485ca860e0db76c80312c532f9"
    )
    assert "seed" not in json.dumps(identity).lower()
    assert snapshot["hvac"]["tuning"]["executed"] is False
    assert snapshot["hvac"]["pid_selection"]["evaluated_candidate_count"] == 0

    comparison = run_hvac_dual_loop(WRAPPER, test_seed=42)
    metrics = comparison.comparison_metrics
    assert metrics is not None and metrics.passed
    np.testing.assert_array_equal(
        comparison.result.reference[[0, 59, 60, 119, 120, 179], 0],
        [25.0, 25.0, 20.0, 20.0, 15.0, 15.0],
    )
    assert metrics.max_control_error_kw <= 0.01
    assert metrics.max_temperature_error_celsius <= 0.01
    assert comparison.safety_certificate.horizon_steps == 180
    assert sha256(WRAPPER.read_bytes()).hexdigest() == snapshot["sources"]["wrapper"]["sha256"]


def test_baseline_identity_changes_with_sources_or_certificate() -> None:
    """reference/security 来源或先验证书变化时，稳定内容身份必须同步变化。"""
    contract = load_hvac_scenario_contract(SCENARIO)
    resolution = load_hvac_pid_baseline_resolution(BASELINE, contract)
    scenario = HvacScenario(WRAPPER)
    assert scenario.baseline_identity is not None
    source_hashes = {
        "wrapper": canonical_hvac_source_sha256(WRAPPER.read_bytes()),
        "baseline": canonical_hvac_source_sha256(BASELINE.read_bytes()),
        "scenario": canonical_hvac_source_sha256(SCENARIO.read_bytes()),
    }

    def rebuild(sources: dict[str, str], certificate: object = scenario.safety_certificate) -> str:
        """复用同一选择结果构造一个只改变指定 canonical material 的身份。"""
        return build_hvac_baseline_identity(
            source_hashes=sources,
            quality_contract=resolution.quality_contract,
            selection=resolution.selection,
            controller_spec=resolution.design.to_controller_spec(),
            safety_certificate=certificate,
            supersedes_baseline=resolution.supersedes_baseline,
            start_commit=resolution.start_commit,
        ).baseline_id

    for name in source_hashes:
        changed = dict(source_hashes)
        changed[name] = "0" * 64
        assert rebuild(changed) != scenario.baseline_identity.baseline_id
    changed_certificate = replace(
        scenario.safety_certificate,
        maximum_output_accumulator_bounds=(
            scenario.safety_certificate.maximum_output_accumulator_bounds[0] + 1,
        ),
    )
    assert rebuild(source_hashes, changed_certificate) != scenario.baseline_identity.baseline_id
