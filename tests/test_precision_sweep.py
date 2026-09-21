"""Issue #15 扫描定义、精确范围和资源计数回归。"""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from secure_control.experiments import _sweep_worker, sweep_runner
from secure_control.experiments.sweep import (
    BaselineSourceRequest,
    PrecisionPreflightReport,
    RangeMargin,
    ResolvedBaselineSource,
    ReusablePrecisionSweepDefinition,
    SweepPointDefinition,
    SweepRunStatus,
    load_precision_sweep_definition,
    materialize_point_config,
)
from secure_control.experiments.sweep_artifacts import record_from_payload, write_json
from secure_control.experiments.sweep_runner import (
    _resolve_definition_plan,
    _run_child,
    build_preflight_report,
    derive_protocol_cost,
    resolve_hvac_baseline_source,
    resolve_precision_sweep_plan,
)
from secure_control.scenarios.hvac.integration import HvacSafetyCertificate, HvacScenario

PROJECT_ROOT = Path(__file__).parents[1]
DEFINITION_PATH = PROJECT_ROOT / "configs" / "hvac_2r2c_precision_sweep.yaml"
V2_DEFINITION_PATH = PROJECT_ROOT / "configs" / "hvac_2r2c_precision_sweep_definition.yaml"
HISTORICAL_BASELINE = PROJECT_ROOT / "configs" / "hvac_2r2c_dual_loop.yaml"
CURRENT_BASELINE = PROJECT_ROOT / "configs" / "hvac_2r2c_dual_loop_25_20_15.yaml"
REDESIGN_BASELINE = PROJECT_ROOT / "configs" / "hvac_2r2c_dual_loop_25_20_15_fast_response.yaml"
HISTORICAL_BASELINE_ID = "2489e5476ad316ea2d9599783e29f2d849ffcf485ca860e0db76c80312c532f9"
CURRENT_BASELINE_ID = "f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab"
REDESIGN_BASELINE_ID = "e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7"


def test_v2_definition_is_source_independent_and_preserves_historical_files() -> None:
    """v2 只保存稳定实验策略，历史 v1 definition/profile 的 bytes 不变。"""
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    assert isinstance(definition, ReusablePrecisionSweepDefinition)
    assert len(definition.points) == 12
    payload = yaml.safe_load(V2_DEFINITION_PATH.read_text(encoding="utf-8"))
    forbidden = {
        "source_config",
        "source_hashes",
        "stability_report_hash",
        "baseline_config",
        "baseline_id",
        "sweep_id",
        "trace_id",
        "run_id",
        "manifest_sha256",
    }
    assert forbidden.isdisjoint(payload)
    assert (
        sha256(DEFINITION_PATH.read_bytes()).hexdigest()
        == "87e20bf25c445849acf3ca15c8a7b6f9848f1fbd1b739aaab3cfd51a35a10e83"
    )
    legacy_profile = PROJECT_ROOT / "configs" / "hvac_2r2c_evidence_report_zh.yaml"
    assert (
        sha256(legacy_profile.read_bytes()).hexdigest()
        == "bf3166c51ad3f87373618d2379730dbdfe0e6c7fa8178c9cb55fa0b1032cb20e"
    )


def test_same_v2_definition_resolves_both_real_baselines() -> None:
    """两个真实 baseline 只改变 resolved provenance，不改变十二点实验矩阵。"""
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    assert isinstance(definition, ReusablePrecisionSweepDefinition)
    historical = resolve_precision_sweep_plan(
        definition,
        BaselineSourceRequest(HISTORICAL_BASELINE, HISTORICAL_BASELINE_ID),
    )
    current = resolve_precision_sweep_plan(
        definition,
        BaselineSourceRequest(CURRENT_BASELINE, CURRENT_BASELINE_ID),
    )
    assert historical.points == current.points == definition.points
    assert (historical.source.identity_scheme, historical.source.baseline_id) == (
        "hvac_historical_config_chain_v1",
        HISTORICAL_BASELINE_ID,
    )
    assert (current.source.identity_scheme, current.source.baseline_id) == (
        "hvac_baseline_identity_v1",
        CURRENT_BASELINE_ID,
    )
    assert historical.source.source_hashes != current.source.source_hashes
    assert historical.source.effective_config_sha256 != current.source.effective_config_sha256
    assert historical.stability_report_sha256 != current.stability_report_sha256
    assert historical.source.finite_horizon_certificate_sha256
    assert current.source.finite_horizon_certificate_sha256


def test_same_v2_definition_accepts_redesigned_baseline_without_runner_changes() -> None:
    """第三个兼容 baseline 只产生新 provenance，不要求 resolver 增加实例特例。"""
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    assert isinstance(definition, ReusablePrecisionSweepDefinition)
    redesigned = resolve_precision_sweep_plan(
        definition,
        BaselineSourceRequest(REDESIGN_BASELINE, REDESIGN_BASELINE_ID),
    )

    assert redesigned.points == definition.points
    assert redesigned.source.identity_scheme == "hvac_baseline_identity_v1"
    assert redesigned.source.baseline_id == REDESIGN_BASELINE_ID
    assert redesigned.source.finite_horizon_certificate_sha256 == (
        "9719cde72bf67a004cb2c995327cc8124142fef255add8f38c2226aaca7039ac"
    )
    assert redesigned.stability_report == json.loads(
        json.dumps(redesigned.stability_report, ensure_ascii=False, allow_nan=False)
    )


def test_v2_source_request_and_v1_adapter_fail_closed_before_worker() -> None:
    """缺少 v2 trust anchor、错误 ID 或 v1 override 均不能形成 execution plan。"""
    v2 = load_precision_sweep_definition(V2_DEFINITION_PATH)
    v1 = load_precision_sweep_definition(DEFINITION_PATH)
    with pytest.raises(ValueError, match="必须同时提供"):
        _resolve_definition_plan(v2, baseline_config=CURRENT_BASELINE, expected_baseline_id=None)
    with pytest.raises(ValueError, match="不允许"):
        _resolve_definition_plan(
            v1,
            baseline_config=HISTORICAL_BASELINE,
            expected_baseline_id=HISTORICAL_BASELINE_ID,
        )
    with pytest.raises(ValueError, match="expected_baseline_id"):
        resolve_precision_sweep_plan(
            v2,
            BaselineSourceRequest(CURRENT_BASELINE, HISTORICAL_BASELINE_ID),
        )


def test_v2_definition_rejects_instance_identity_fields(tmp_path: Path) -> None:
    """稳定 definition 即使收到合法外观的实例 pin 也必须按 schema 拒绝。"""
    payload = yaml.safe_load(V2_DEFINITION_PATH.read_text(encoding="utf-8"))
    payload["baseline_id"] = CURRENT_BASELINE_ID
    target = tmp_path / "definition.yaml"
    target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    (tmp_path / "hvac_2r2c_sweep_prime.yaml").write_bytes(
        (PROJECT_ROOT / "configs" / "hvac_2r2c_sweep_prime.yaml").read_bytes()
    )
    with pytest.raises(ValueError, match="字段"):
        load_precision_sweep_definition(target)


def test_source_resolution_rejects_path_traversal_without_running_scenario(
    tmp_path: Path,
) -> None:
    """source request 不得借 wrapper 的相对路径逃逸显式配置目录。"""
    wrapper = tmp_path / "wrapper.yaml"
    wrapper.write_text(
        "scenario: {name: hvac}\nbaseline_config: ../outside.yaml\nsecurity: {}\n",
        encoding="utf-8",
    )
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    with pytest.raises(ValueError, match="安全文件名"):
        resolve_precision_sweep_plan(
            definition,
            BaselineSourceRequest(wrapper, HISTORICAL_BASELINE_ID),
        )


def test_source_resolution_rejects_missing_and_real_symlink_source(tmp_path: Path) -> None:
    """显式 source 必须是存在的普通文件，不能通过链接改变 authority。"""
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    with pytest.raises(ValueError, match="存在的普通非链接文件"):
        resolve_precision_sweep_plan(
            definition,
            BaselineSourceRequest(tmp_path / "missing.yaml", HISTORICAL_BASELINE_ID),
        )

    link = tmp_path / "baseline-link.yaml"
    link.symlink_to(CURRENT_BASELINE)
    with pytest.raises(ValueError, match="存在的普通非链接文件"):
        resolve_hvac_baseline_source(
            BaselineSourceRequest(link, CURRENT_BASELINE_ID),
            definition.source_requirements,
        )


def test_source_resolution_rejects_real_symlink_source_ancestor(tmp_path: Path) -> None:
    """显式 source 的祖先目录也不能通过链接改变 path authority。"""
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    linked_configs = tmp_path / "linked-configs"
    linked_configs.symlink_to(CURRENT_BASELINE.parent, target_is_directory=True)

    with pytest.raises(ValueError, match="存在的普通非链接文件"):
        resolve_hvac_baseline_source(
            BaselineSourceRequest(linked_configs / CURRENT_BASELINE.name, CURRENT_BASELINE_ID),
            definition.source_requirements,
        )


def test_source_resolution_rejects_tampered_current_config_chain(tmp_path: Path) -> None:
    """scenario bytes 被改写时，PID→scenario trust anchor 必须先于 worker 失败。"""
    names = (
        "hvac_2r2c_dual_loop_25_20_15.yaml",
        "hvac_2r2c_pid_baseline_25_20_15.yaml",
        "hvac_2r2c_scenario_25_20_15.yaml",
    )
    for name in names:
        (tmp_path / name).write_bytes((PROJECT_ROOT / "configs" / name).read_bytes())
    scenario = tmp_path / names[-1]
    scenario.write_text(
        scenario.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    with pytest.raises(ValueError, match="SHA-256"):
        resolve_precision_sweep_plan(
            definition,
            BaselineSourceRequest(tmp_path / names[0], CURRENT_BASELINE_ID),
        )


def test_plan_rejects_stability_and_prime_policy_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resolved source 合法也不能绕过动态 stability 与固定 q 的 prime trust anchor。"""
    definition = load_precision_sweep_definition(V2_DEFINITION_PATH)
    source = ResolvedBaselineSource(
        CURRENT_BASELINE,
        "fixture",
        CURRENT_BASELINE_ID,
        {"wrapper": "1" * 64, "baseline": "2" * 64, "scenario": "3" * 64},
        "4" * 64,
        "5" * 64,
    )
    monkeypatch.setattr(sweep_runner, "resolve_hvac_baseline_source", lambda *_args: source)
    monkeypatch.setattr(
        sweep_runner,
        "stability_report_sha256",
        lambda *_args: (
            "6" * 64,
            {"schur": {"status": "unstable"}, "equilibria": []},
        ),
    )
    with pytest.raises(ValueError, match="stability"):
        resolve_precision_sweep_plan(
            definition,
            BaselineSourceRequest(CURRENT_BASELINE, CURRENT_BASELINE_ID),
        )

    monkeypatch.setattr(
        sweep_runner,
        "stability_report_sha256",
        lambda *_args: (
            "7" * 64,
            {"schur": {"status": "stable"}, "equilibria": []},
        ),
    )
    with pytest.raises(ValueError, match="prime evidence"):
        resolve_precision_sweep_plan(
            replace(definition, prime_evidence_hash="0" * 64),
            BaselineSourceRequest(CURRENT_BASELINE, CURRENT_BASELINE_ID),
        )


def test_definition_freezes_twelve_points_and_security_invariants() -> None:
    """扫描只改变 ell/k，固定 q、lambda、seed 集合与主 seed。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    assert definition.fractional_bits == (32, 40, 48, 56)
    assert definition.seeds == (42, 43, 44)
    assert definition.primary_seed == 42
    assert len(definition.points) == 12
    assert {(point.ell, point.k) for point in definition.points} == {
        (32, 60),
        (40, 68),
        (48, 76),
        (56, 84),
    }
    assert {point.lambda_ for point in definition.points} == {80}
    assert {point.q.bit_length() for point in definition.points} == {256}
    assert {point.kappa for point in definition.points} == {174}


def test_materialized_ell56_config_uses_proven_prime_and_exact_input_bound(
    tmp_path: Path,
) -> None:
    """ell=56 的输入 payload 上界按 float 精确比值计算，不丢失最后的 +1。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    point = next(item for item in definition.points if item.ell == 56 and item.seed == 42)
    path = tmp_path / "point.yaml"
    materialize_point_config(definition, point, path)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["security"]["integer_bits"] == 84
    assert loaded["security"]["fractional_bits"] == 56
    assert loaded["security"]["security_parameter"] == 80
    assert loaded["security"]["modulus"] == point.q

    scenario = HvacScenario(path, test_seed=42)
    low, high = scenario.safety_certificate.controller_input_bounds_celsius
    maximum = max(abs(low), abs(high))
    numerator, denominator = maximum.as_integer_ratio()
    expected = -(-(numerator * (1 << 56)) // denominator) + 1
    assert scenario.safety_certificate.input_payload_bound == expected


def test_protocol_cost_is_derived_from_actual_shapes_and_zero_truncation_ledger(
    tmp_path: Path,
) -> None:
    """2x1x1 PID 每步九个 triple，整数 A/B ledger 不分配 Protocol 2。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    point = definition.points[0]
    path = tmp_path / "point.yaml"
    materialize_point_config(definition, point, path)
    scenario = HvacScenario(path, test_seed=point.seed)
    plan = scenario.build_plan()
    cost = derive_protocol_cost(
        plan.secure.runtime,
        scenario.safety_certificate,
        scenario.effective_config_snapshot()["hvac"]["timing"]["sample_count"],
        1.25,
    )
    assert cost.protocol1_triples_per_step == 9
    assert cost.protocol1_triples_total == 1620
    assert cost.protocol2_truncations_per_step == 0
    assert cost.protocol2_truncations_total == 0
    assert cost.resource_count_kind == "derived_exact"
    assert cost.q_bit_length == 256
    assert cost.wall_clock_seconds == 1.25
    assert SweepRunStatus.SUCCESS.value == "success"
    assert asdict(cost)["timing_scope"] == "child_start_through_atomic_point_result"


def test_runner_publishes_success_infeasible_and_failed_points_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """单点不可行或异常不吞掉诊断，也不阻止完整批次原子发布。"""
    loaded = load_precision_sweep_definition(DEFINITION_PATH)
    definition = replace(loaded, fractional_bits=(32,), seeds=(42, 43, 44))
    stable = {"schur": {"status": "stable"}, "equilibria": [{"applicability": "applicable"}]}
    outcomes = iter(("timeout", "nonzero", "malformed"))

    def fake_child(command: list[str], **_kwargs: object) -> sweep_runner._ChildResult:
        """首点保存真实 checkpoint 后超时，其余点验证无 checkpoint 的 unknown 语义。"""
        outcome = next(outcomes)
        request_path = Path(command[-1])
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if outcome == "timeout":
            point = SweepPointDefinition(**request["point"])
            preflight = PrecisionPreflightReport(
                True,
                True,
                True,
                (RangeMargin("saved_range", 1, 10, 9, 0.1),),
                True,
                (),
            )
            write_json(
                request_path.parent / "preflight.json",
                {
                    "schema_version": 1,
                    "point": asdict(point),
                    "preflight": asdict(preflight),
                },
            )
            return sweep_runner._ChildResult(None, True, "", "")
        if outcome == "nonzero":
            return sweep_runner._ChildResult(7, False, "", "worker failed")
        return sweep_runner._ChildResult(0, False, "", "")

    monkeypatch.setattr(sweep_runner, "load_precision_sweep_definition", lambda _path: definition)
    monkeypatch.setattr(
        sweep_runner, "stability_report_sha256", lambda _plant, _pid: ("a" * 64, stable)
    )
    monkeypatch.setattr(sweep_runner, "_frozen_sources", lambda _definition, _hash: (True, {}))
    monkeypatch.setattr(sweep_runner, "_run_child", fake_child)

    artifacts = sweep_runner.run_precision_sweep(DEFINITION_PATH, output_root=tmp_path / "out")
    assert [record.status for record in artifacts.records] == [
        SweepRunStatus.FAILED,
        SweepRunStatus.FAILED,
        SweepRunStatus.FAILED,
    ]
    assert [record.failure_code for record in artifacts.records] == [
        "point_timeout",
        "worker_nonzero_exit",
        "worker_result_invalid",
    ]
    assert artifacts.records[0].preflight == PrecisionPreflightReport(
        True,
        True,
        True,
        (RangeMargin("saved_range", 1, 10, 9, 0.1),),
        True,
        (),
    )
    for record in artifacts.records[1:]:
        assert record.preflight.stability_passed is True
        assert record.preflight.prime_evidence_passed is True
        assert record.preflight.frozen_fields_passed is True
        assert record.preflight.ranges == ()
        assert record.preflight.feasible is None
        assert record.preflight.reason_codes == ("preflight_not_completed",)
    assert artifacts.manifest_path.is_file()
    assert not list((tmp_path / "out").glob(".incomplete-*"))


def test_worker_preserves_passed_preflight_when_execution_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """门禁通过后的执行异常必须保留真实布尔结论和全部 range margins。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    point = definition.points[0]

    class FailingExecutionScenario:
        """提供有效证书，但在进入执行计划时稳定失败。"""

        def __init__(self, _path: Path, *, test_seed: int) -> None:
            assert test_seed == point.seed
            self.safety_certificate = _minimal_preflight_scenario(point.q).safety_certificate

        def build_plan(self) -> None:
            """模拟 preflight 完成后的执行阶段异常。"""
            raise RuntimeError("execution failed")

    monkeypatch.setattr(_sweep_worker, "HvacScenario", FailingExecutionScenario)
    request_path = _write_worker_request(tmp_path, point)
    _sweep_worker.run_request(request_path)
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    record = record_from_payload(payload["record"])
    assert record.status is SweepRunStatus.FAILED
    assert record.failure_code == "RuntimeError"
    assert record.preflight.feasible is True
    assert record.preflight.stability_passed is True
    assert record.preflight.prime_evidence_passed is True
    assert record.preflight.frozen_fields_passed is True
    assert record.preflight.ranges
    assert (tmp_path / "preflight.json").is_file()


def test_worker_classifies_scenario_construction_rejection_as_infeasible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """场景构造尚未形成证书时应保留已知门禁，并把未知结论显式序列化。"""
    point = load_precision_sweep_definition(DEFINITION_PATH).points[0]

    def reject_scenario(_path: Path, *, test_seed: int) -> None:
        assert test_seed == point.seed
        raise ValueError("invalid point config")

    monkeypatch.setattr(_sweep_worker, "HvacScenario", reject_scenario)
    request_path = _write_worker_request(tmp_path, point)
    _sweep_worker.run_request(request_path)
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    record = record_from_payload(payload["record"])
    assert record.status is SweepRunStatus.INFEASIBLE
    assert record.failure_code == "preflight_rejected"
    assert record.preflight.stability_passed is True
    assert record.preflight.prime_evidence_passed is True
    assert record.preflight.frozen_fields_passed is True
    assert record.preflight.feasible is None
    assert record.preflight.ranges == ()
    assert record.preflight.reason_codes == ("preflight_not_completed",)


@pytest.mark.parametrize(
    ("kappa_offset", "expected_reason"),
    [(0, "kappa_not_greater_than_ell"), (-1, "kappa_not_greater_than_ell")],
)
def test_preflight_rejects_kappa_at_or_below_ell(kappa_offset: int, expected_reason: str) -> None:
    """协议参数不满足 runtime 的严格边界时必须在 preflight 判为不可行。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    base = definition.points[0]
    ell = base.kappa - kappa_offset
    point = replace(base, ell=ell, k=ell + 28)
    scenario = _minimal_preflight_scenario(definition.q)
    report = build_preflight_report(
        point,
        scenario,
        stability_passed=True,
        prime_evidence_passed=True,
        frozen_fields_passed=True,
    )
    assert not report.feasible
    assert expected_reason in report.reason_codes


def test_preflight_accepts_kappa_equal_ell_plus_one_and_rejects_derived_mismatch() -> None:
    """门禁边界与保存的派生 kappa 都必须和 runtime 公式一致。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    base = definition.points[0]
    ell = base.kappa - 1
    point = replace(base, ell=ell, k=ell + 28)
    scenario = _minimal_preflight_scenario(definition.q)
    accepted = build_preflight_report(
        point,
        scenario,
        stability_passed=True,
        prime_evidence_passed=True,
        frozen_fields_passed=True,
    )
    assert "kappa_not_greater_than_ell" not in accepted.reason_codes
    mismatch = build_preflight_report(
        replace(point, kappa=point.kappa - 1),
        scenario,
        stability_passed=True,
        prime_evidence_passed=True,
        frozen_fields_passed=True,
    )
    assert not mismatch.feasible
    assert "derived_kappa_mismatch" in mismatch.reason_codes


def test_real_child_timeout_is_bounded_and_reaped() -> None:
    """Windows/Python 3.11 下真实阻塞 child 必须在 deadline 后被终止并回收。"""
    import sys

    result = _run_child([sys.executable, "-c", "import time; time.sleep(30)"], timeout_seconds=1)
    assert result.timed_out
    assert result.returncode is None
    following = _run_child([sys.executable, "-c", "print('next')"], timeout_seconds=5)
    assert not following.timed_out
    assert following.returncode == 0
    assert following.stdout.strip() == "next"


def _minimal_preflight_scenario(q: int) -> SimpleNamespace:
    """为纯 preflight 边界测试提供不会触发其他范围拒绝的最小证书。"""
    return SimpleNamespace(
        safety_certificate=HvacSafetyCertificate(
            1,
            ("plant",),
            ((0.0, 1.0),),
            (-1.0, 1.0),
            ("state",),
            ((-1.0, 1.0),),
            (-1.0, 1.0),
            (0.0, 1.0),
            (1,),
            (1,),
            (1,),
            (1,),
            (q - 1) // 2,
            0,
        )
    )


def _write_worker_request(tmp_path: Path, point: SweepPointDefinition) -> Path:
    """写出不依赖真实场景文件内容的最小严格 worker request。"""
    (tmp_path / "config.yaml").write_text("fixture: true\n", encoding="utf-8")
    request_path = tmp_path / "request.json"
    write_json(
        request_path,
        {
            "schema_version": 1,
            "point": asdict(point),
            "config_path": "config.yaml",
            "artifact_root": "raw",
            "result_path": "result.json",
            "stability_passed": True,
            "prime_evidence_passed": True,
            "frozen_fields_passed": True,
            "resource_limits": {
                "max_protocol1_triples_per_point": 1620,
                "max_protocol2_truncations_per_point": 0,
                "max_certified_integer_bit_length": 192,
            },
        },
    )
    return request_path
