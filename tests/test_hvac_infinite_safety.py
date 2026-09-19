"""Issue #38 HVAC 条件化无限时域安全证书回归。"""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest
import yaml

from secure_control.core import (
    RationalBox,
    RationalValue,
    invariant_certificate_sha256,
    verify_ellipsoidal_invariant,
)
from secure_control.crypto import TwoPartySharing
from secure_control.protocol import Client
from secure_control.scenarios.hvac.contract import load_hvac_scenario_contract
from secure_control.scenarios.hvac.infinite_safety import load_hvac_infinite_safety_bundle
from secure_control.scenarios.hvac.tuning import load_hvac_pid_tuning_contract

PROJECT_ROOT = Path(__file__).parents[1]
CONFIG = PROJECT_ROOT / "configs" / "hvac_2r2c_infinite_safety.yaml"


@pytest.fixture(scope="module")
def bundle():
    """只执行一次较昂贵的 256-bit 素数证据与四点精确复验。"""
    return load_hvac_infinite_safety_bundle(CONFIG)


def test_four_verified_precision_profiles_are_exactly_certified(bundle) -> None:
    """四个已扫描 ell 均使用 kappa=174、零 Trunc 和闭环证据模式。"""
    assert [profile.fractional_bits for profile in bundle.profiles] == [32, 40, 48, 56]
    assert {profile.kappa for profile in bundle.profiles} == {174}
    assert {profile.invariant_report.status for profile in bundle.profiles} == {"certified"}
    for profile in bundle.profiles:
        assert profile.range_contract.proof_mode == "closed_loop_invariant"
        assert profile.controller.scale_metadata.A == 0
        assert profile.controller.scale_metadata.B == 0
        assert profile.controller.scale_metadata.state == profile.fractional_bits
        assert profile.controller.scale_metadata.output == 2 * profile.fractional_bits
        assert profile.prime_verification.status == "verified"


def test_protocol_reverifies_evidence_before_any_share(bundle, monkeypatch) -> None:
    """证书初态被放大后，Client 在创建 controller share 之前 fail closed。"""
    profile = bundle.profiles[0]
    sharing = TwoPartySharing(profile.fixed_point.modulus)
    client = Client(
        profile.fixed_point,
        sharing,
        security_parameter=profile.security_parameter,
        modulus_evidence=profile.modulus_evidence,
    )
    client.distribute_controller(profile.controller, profile.range_contract)
    assert client.range_verification.proof_mode == "closed_loop_invariant"
    assert (
        client.range_verification.certificate_sha256 == profile.invariant_report.certificate_sha256
    )
    assert client.range_verification.state_accumulator_bounds == profile.state_accumulator_bounds
    assert client.range_verification.output_accumulator_bounds == profile.output_accumulator_bounds
    evidence = profile.range_contract.closed_loop_evidence
    assert evidence is not None
    dimension = len(evidence.problem.state_labels)
    outside = RationalBox(
        tuple(RationalValue(-10_000) for _ in range(dimension)),
        tuple(RationalValue(10_000) for _ in range(dimension)),
    )
    problem = replace(evidence.problem, initial_set=outside)
    tampered = replace(evidence, problem=problem)
    contract = replace(profile.range_contract, closed_loop_evidence=tampered)
    called = False

    def forbidden_share(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("验证失败前不得创建 share")

    monkeypatch.setattr(TwoPartySharing, "share", forbidden_share)
    singleton = RationalBox(evidence.witness.equilibrium, evidence.witness.equilibrium)
    singleton_problem = replace(evidence.problem, initial_set=singleton)
    singleton_evidence = replace(
        evidence,
        problem=singleton_problem,
        certificate_sha256=invariant_certificate_sha256(singleton_problem, evidence.witness),
    )
    singleton_contract = replace(profile.range_contract, closed_loop_evidence=singleton_evidence)
    with pytest.raises(ValueError, match="controller x0"):
        client.distribute_controller(profile.controller, singleton_contract)
    assert called is False

    with pytest.raises(ValueError, match="certificate SHA-256"):
        client.distribute_controller(profile.controller, contract)
    assert called is False


def test_default_segmented_baseline_is_explicitly_outside_claim(bundle) -> None:
    """默认 15°C 首步 raw u=12.875 kW，会饱和且不能引用局部证书。"""
    plant = load_hvac_scenario_contract(PROJECT_ROOT / "configs" / "hvac_2r2c_plant.yaml")
    design, _, _ = load_hvac_pid_tuning_contract(
        PROJECT_ROOT / "configs" / "hvac_2r2c_pid_baseline.yaml", plant
    )
    spec = design.to_controller_spec()
    first_error = 15.0 - 30.0
    first_raw = float(spec.C[0] @ spec.x0 + spec.D[0, 0] * first_error)
    assert first_raw == pytest.approx(12.875)
    assert first_raw > plant.model.upper_control_bound_kw
    assert "默认 180 步" in bundle.claim_boundary


def test_configuration_rejects_missing_infinite_reference_tail(tmp_path: Path) -> None:
    """未明确 reference 无限持续时，装配器在数学验证前拒绝。"""
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    source = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    source["fixed_assumptions"]["continues_forever"] = False
    for name in (
        "hvac_2r2c_plant.yaml",
        "hvac_2r2c_pid_baseline.yaml",
        "hvac_2r2c_precision_sweep.yaml",
        "hvac_2r2c_sweep_prime.yaml",
    ):
        (config_dir / name).write_bytes((PROJECT_ROOT / "configs" / name).read_bytes())
    path = config_dir / CONFIG.name
    path.write_text(yaml.safe_dump(source, allow_unicode=True, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="continues_forever"):
        load_hvac_infinite_safety_bundle(path)


def test_configuration_rejects_mismatched_upstream_stability_report(tmp_path: Path) -> None:
    """#37 完整报告摘要不匹配时，不得继续生成 #38 证书。"""
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    source = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    source["upstream_stability"]["report_sha256"] = "0" * 64
    for name in (
        "hvac_2r2c_plant.yaml",
        "hvac_2r2c_pid_baseline.yaml",
        "hvac_2r2c_precision_sweep.yaml",
        "hvac_2r2c_sweep_prime.yaml",
    ):
        (config_dir / name).write_bytes((PROJECT_ROOT / "configs" / name).read_bytes())
    path = config_dir / CONFIG.name
    path.write_text(yaml.safe_dump(source, allow_unicode=True, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="stability report SHA-256"):
        load_hvac_infinite_safety_bundle(path)


def test_input_encoding_bound_is_exact_half_lsb(bundle) -> None:
    """闭环 problem 的第一扰动界逐 ell 精确等于输入编码半 LSB。"""
    for profile in bundle.profiles:
        evidence = profile.range_contract.closed_loop_evidence
        assert evidence is not None
        bound = evidence.problem.disturbance_abs_bounds[0]
        assert bound.fraction == Fraction(1, 1 << (profile.fractional_bits + 1))
        assert np.isfinite(float(bound.fraction))


def test_excessive_declared_disturbance_is_rejected(bundle) -> None:
    """扰动大到超过冻结鲁棒半径时，精确闭包检查必须失败。"""
    evidence = bundle.profiles[0].range_contract.closed_loop_evidence
    assert evidence is not None
    problem = replace(
        evidence.problem,
        disturbance_abs_bounds=(RationalValue(1), evidence.problem.disturbance_abs_bounds[1]),
    )

    report = verify_ellipsoidal_invariant(problem, evidence.witness)

    assert report.status == "rejected"
    assert "robust_radius_closure" in report.reason_codes
