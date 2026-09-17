"""Issue #15 扫描定义、精确范围和资源计数回归。"""

from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from secure_control.experiments import sweep_runner
from secure_control.experiments.sweep import (
    SweepRunStatus,
    load_precision_sweep_definition,
    materialize_point_config,
)
from secure_control.experiments.sweep_runner import (
    _run_child,
    build_preflight_report,
    derive_protocol_cost,
)
from secure_control.scenarios.hvac.integration import HvacSafetyCertificate, HvacScenario

PROJECT_ROOT = Path(__file__).parents[1]
DEFINITION_PATH = PROJECT_ROOT / "configs" / "hvac_2r2c_precision_sweep.yaml"


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
    outcomes = iter(
        (
            sweep_runner._ChildResult(None, True, "", ""),
            sweep_runner._ChildResult(7, False, "", "worker failed"),
            sweep_runner._ChildResult(0, False, "", ""),
        )
    )
    monkeypatch.setattr(sweep_runner, "load_precision_sweep_definition", lambda _path: definition)
    monkeypatch.setattr(
        sweep_runner, "stability_report_sha256", lambda _plant, _pid: ("hash", stable)
    )
    monkeypatch.setattr(sweep_runner, "_frozen_sources", lambda _definition, _hash: (True, {}))
    monkeypatch.setattr(sweep_runner, "_run_child", lambda *_args, **_kwargs: next(outcomes))

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
    assert artifacts.manifest_path.is_file()
    assert not list((tmp_path / "out").glob(".incomplete-*"))


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
