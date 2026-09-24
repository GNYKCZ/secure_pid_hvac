"""Issue #53/#57 的正式基线迁移、主动 redesign 与统一身份回归测试。"""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest
import yaml

import secure_control.scenarios.hvac.integration as integration_module
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
CONFIGS = PROJECT_ROOT / "tests" / "fixtures" / "legacy_hvac"
WRAPPER = CONFIGS / "hvac_2r2c_dual_loop_25_20_15.yaml"
BASELINE = CONFIGS / "hvac_2r2c_pid_baseline_25_20_15.yaml"
REDESIGN_WRAPPER = CONFIGS / "hvac_2r2c_dual_loop_25_20_15_fast_response.yaml"
REDESIGN_BASELINE = CONFIGS / "hvac_2r2c_pid_baseline_25_20_15_fast_response.yaml"
SCENARIO = CONFIGS / "hvac_2r2c_scenario_25_20_15.yaml"
OLD_WRAPPER = CONFIGS / "hvac_2r2c_dual_loop.yaml"
OLD_BASELINE = CONFIGS / "hvac_2r2c_pid_baseline.yaml"
OLD_SCENARIO = CONFIGS / "hvac_2r2c_plant.yaml"


def _copy_migration_chain(destination: Path) -> Path:
    """复制测试所需的完整配置链，避免篡改仓库中的冻结配置。"""
    for source in (WRAPPER, BASELINE, SCENARIO, OLD_WRAPPER, OLD_BASELINE, OLD_SCENARIO):
        (destination / source.name).write_bytes(source.read_bytes())
    return destination / BASELINE.name


def _copy_redesign_chain(destination: Path) -> tuple[Path, Path]:
    """复制主动 redesign 及其完整 predecessor lineage，供 fail-closed 测试使用。"""
    for source in (
        REDESIGN_WRAPPER,
        REDESIGN_BASELINE,
        WRAPPER,
        BASELINE,
        SCENARIO,
        OLD_WRAPPER,
        OLD_BASELINE,
        OLD_SCENARIO,
    ):
        (destination / source.name).write_bytes(source.read_bytes())
    return destination / REDESIGN_WRAPPER.name, destination / REDESIGN_BASELINE.name


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
    wrapper = yaml.safe_load(WRAPPER.read_text(encoding="utf-8"))
    baseline = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    assert wrapper["baseline_sha256"] == canonical_hvac_source_sha256(BASELINE.read_bytes())
    assert baseline["migration"]["source_wrapper_sha256"] == canonical_hvac_source_sha256(
        OLD_WRAPPER.read_bytes()
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


def test_migration_wrapper_rejects_preexisting_baseline_drift(tmp_path: Path) -> None:
    """wrapper 必须用冻结摘要拒绝在本次解析开始前已经漂移的 PID baseline。"""
    baseline = _copy_migration_chain(tmp_path)
    wrapper = tmp_path / WRAPPER.name
    wrapper_loaded = yaml.safe_load(wrapper.read_text(encoding="utf-8"))
    wrapper_loaded["baseline_sha256"] = canonical_hvac_source_sha256(baseline.read_bytes())
    wrapper.write_text(yaml.safe_dump(wrapper_loaded, sort_keys=False), encoding="utf-8")
    baseline.write_bytes(baseline.read_bytes() + b"\n# post-freeze drift\n")

    with pytest.raises(ValueError, match="baseline.*SHA-256"):
        HvacScenario(wrapper)


def test_migration_wrapper_rejects_legacy_baseline_replacement_before_downstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """wrapper 信任锚必须在分支判定前拒绝被整体替换的合法 legacy baseline。"""
    baseline = _copy_migration_chain(tmp_path)
    wrapper = tmp_path / WRAPPER.name
    baseline.write_bytes(OLD_BASELINE.read_bytes())

    def unexpected_downstream(*args: object, **kwargs: object) -> None:
        """哈希不匹配时不得进入调参或范围证书派生路径。"""
        raise AssertionError("baseline 摘要校验必须先于下游装配")

    monkeypatch.setattr(integration_module, "load_hvac_pid_tuning_contract", unexpected_downstream)
    monkeypatch.setattr(
        integration_module.HvacScenario, "_derive_safety_certificate", unexpected_downstream
    )

    with pytest.raises(ValueError, match="baseline.*SHA-256"):
        HvacScenario(wrapper)


def test_supersedes_baseline_must_match_recomputed_historical_chain(tmp_path: Path) -> None:
    """格式合法但并非旧三配置链真实身份的 supersedes 声明必须 fail closed。"""
    baseline = _copy_migration_chain(tmp_path)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    loaded["migration"]["supersedes_baseline"] = "0" * 64
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="supersedes_baseline"):
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
    assert first.baseline_identity.baseline_id == (
        "f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab"
    )
    assert first.baseline_identity.selection_record_sha256 == (
        "9f965a4ed4147abcc88e3e8ae2c5727886adc1b9645e877866db04b291246897"
    )
    assert first.baseline_identity.finite_horizon_certificate_sha256 == (
        "ebd7afd4b66466d29dbde897b3daad325c160ea7d4b79dbcaef48ddcaf4f794c"
    )
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


def test_explicit_redesign_builds_new_identity_and_preserves_v1_baseline() -> None:
    """source PID 已通过旧门禁时，显式 redesign 仍执行 tuner 并复用同一 identity scheme。"""
    predecessor = HvacScenario(WRAPPER)
    redesigned = HvacScenario(REDESIGN_WRAPPER)
    assert predecessor.baseline_identity is not None
    assert redesigned.baseline_identity is not None
    assert predecessor.baseline_identity.baseline_id == (
        "f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab"
    )
    assert redesigned.baseline_identity.scheme == predecessor.baseline_identity.scheme
    assert redesigned.baseline_identity.baseline_id == (
        "e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7"
    )
    assert redesigned.baseline_identity.supersedes_baseline == (
        predecessor.baseline_identity.baseline_id
    )
    snapshot = redesigned.effective_config_snapshot()
    record = snapshot["hvac"]["pid_redesign"]
    assert record["method"] == "plaintext_controller_redesign_v1"
    assert record["tuning_executed"] is True
    assert record["evaluated_candidate_count"] == 10179
    assert record["feasible_candidate_count"] == 2392
    assert record["source_validation"]["passed"] is False
    assert snapshot["hvac"]["tuning"]["selected_objective"][0] == 540.0
    assert "pid_selection" not in snapshot["hvac"]


def test_redesign_plaintext_and_secure_metrics_meet_frozen_contract() -> None:
    """最终 gains 冻结后，seed 42 双闭环仅作兼容验证且两支都满足品质门槛。"""
    comparison = run_hvac_dual_loop(REDESIGN_WRAPPER, test_seed=42)
    metrics = comparison.comparison_metrics
    assert metrics is not None and metrics.passed
    assert [item.settling_time_seconds for item in metrics.ideal.segments] == [540.0] * 3
    assert min(item.min_signed_deviation_celsius for item in metrics.ideal.segments) >= -0.3
    assert max(item.tail_mae_celsius for item in metrics.ideal.segments) <= 0.5
    assert max(item.saturation_fraction for item in metrics.ideal.segments) <= 0.15
    assert metrics.ideal.global_max_abs_applied_control_kw <= 12.0
    assert metrics.max_control_error_kw <= 0.01
    assert metrics.max_temperature_error_celsius <= 0.01
    assert comparison.safety_certificate.horizon_steps == 180


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["baseline_creation"]["source_baseline_identity"].__setitem__(
                "baseline_id", "0" * 64
            ),
            "source baseline identity",
        ),
        (
            lambda value: value["baseline_creation"]["selection"].__setitem__(
                "evaluated_candidate_count", 1
            ),
            "selection 声明",
        ),
        (
            lambda value: value["controller"].__setitem__(
                "proportional_gain_kw_per_celsius", -1.45
            ),
            "final gains",
        ),
    ],
)
def test_redesign_tampering_fails_closed(tmp_path: Path, mutate, message: str) -> None:
    """source identity、selection 或 final gains 任一伪造都不能形成 baseline。"""
    wrapper, baseline = _copy_redesign_chain(tmp_path)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    mutate(loaded)
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    wrapper_loaded = yaml.safe_load(wrapper.read_text(encoding="utf-8"))
    wrapper_loaded["baseline_sha256"] = canonical_hvac_source_sha256(baseline.read_bytes())
    wrapper.write_text(yaml.safe_dump(wrapper_loaded, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        HvacScenario(wrapper)


def test_redesign_lineage_cycle_and_toctou_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """递归 source 与调参期间 predecessor 漂移必须在 identity 发布前拒绝。"""
    wrapper, baseline = _copy_redesign_chain(tmp_path)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    loaded["baseline_creation"]["source_wrapper_config"] = wrapper.name
    loaded["baseline_creation"]["source_wrapper_sha256"] = "0" * 64
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    wrapper_loaded = yaml.safe_load(wrapper.read_text(encoding="utf-8"))
    wrapper_loaded["baseline_sha256"] = canonical_hvac_source_sha256(baseline.read_bytes())
    wrapper.write_text(yaml.safe_dump(wrapper_loaded, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="cycle"):
        HvacScenario(wrapper)

    wrapper, _ = _copy_redesign_chain(tmp_path)
    original = migration_module.tune_hvac_pid

    def mutate_predecessor(*args: object, **kwargs: object) -> HvacPidTuningResult:
        result = original(*args, **kwargs)
        scenario = tmp_path / SCENARIO.name
        scenario.write_text(
            scenario.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8"
        )
        return result

    monkeypatch.setattr(migration_module, "tune_hvac_pid", mutate_predecessor)
    with pytest.raises(ValueError, match="解析期间发生变化"):
        HvacScenario(wrapper)


@pytest.mark.parametrize("mutation_target", ["current_wrapper", "predecessor_scenario"])
def test_redesign_certificate_stage_toctou_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation_target: str
) -> None:
    """证书生成期间 current 或 predecessor 漂移时不得发布 baseline identity。"""
    wrapper, _ = _copy_redesign_chain(tmp_path)
    original = integration_module.HvacScenario._derive_safety_certificate

    def mutate_during_certificate(scenario: HvacScenario):
        certificate = original(scenario)
        if scenario._wrapper_filename == wrapper.name:
            target = wrapper if mutation_target == "current_wrapper" else tmp_path / SCENARIO.name
            target.write_text(
                target.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8"
            )
        return certificate

    monkeypatch.setattr(
        integration_module.HvacScenario,
        "_derive_safety_certificate",
        mutate_during_certificate,
    )
    with pytest.raises(ValueError, match="解析期间发生变化"):
        HvacScenario(wrapper)


def test_redesign_baseline_aba_switch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """跨 integration/loader 切换 PID 为 B 再恢复 A 时不得生成混合身份。"""
    wrapper, baseline = _copy_redesign_chain(tmp_path)
    original_source = baseline.read_bytes()
    alternate = yaml.safe_load(original_source.decode("utf-8"))
    alternate["baseline_creation"]["start_commit"] = "0" * 40
    alternate_source = yaml.safe_dump(alternate, sort_keys=False).encode("utf-8")
    original_loader = integration_module.load_hvac_pid_redesign_resolution

    def switch_baseline_during_loader(*args: object, **kwargs: object):
        baseline.write_bytes(alternate_source)
        try:
            return original_loader(*args, **kwargs)
        finally:
            baseline.write_bytes(original_source)

    monkeypatch.setattr(
        integration_module,
        "load_hvac_pid_redesign_resolution",
        switch_baseline_during_loader,
    )
    with pytest.raises(ValueError, match="解析期间发生变化"):
        HvacScenario(wrapper)


def test_redesign_predecessor_rejects_path_traversal_and_real_symlink(tmp_path: Path) -> None:
    """前驱 wrapper 必须是同目录普通文件，不能用 traversal 或 leaf link 改变 authority。"""
    wrapper, baseline = _copy_redesign_chain(tmp_path)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    loaded["baseline_creation"]["source_wrapper_config"] = "../outside.yaml"
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    wrapper_loaded = yaml.safe_load(wrapper.read_text(encoding="utf-8"))
    wrapper_loaded["baseline_sha256"] = canonical_hvac_source_sha256(baseline.read_bytes())
    wrapper.write_text(yaml.safe_dump(wrapper_loaded, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="安全文件名"):
        HvacScenario(wrapper)

    wrapper, baseline = _copy_redesign_chain(tmp_path)
    source_link = tmp_path / "source-link.yaml"
    source_link.symlink_to(tmp_path / WRAPPER.name)
    loaded = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    loaded["baseline_creation"]["source_wrapper_config"] = source_link.name
    baseline.write_text(yaml.safe_dump(loaded, sort_keys=False), encoding="utf-8")
    wrapper_loaded = yaml.safe_load(wrapper.read_text(encoding="utf-8"))
    wrapper_loaded["baseline_sha256"] = canonical_hvac_source_sha256(baseline.read_bytes())
    wrapper.write_text(yaml.safe_dump(wrapper_loaded, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="普通非链接文件"):
        HvacScenario(wrapper)
