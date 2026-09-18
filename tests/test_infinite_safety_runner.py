"""无限时域安全报告只读组合根与原子发布测试。"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from secure_control.experiments import infinite_safety_runner
from secure_control.experiments.sweep import SweepRunStatus
from secure_control.scenarios.hvac.infinite_safety import load_hvac_infinite_safety_bundle

PROJECT_ROOT = Path(__file__).parents[1]
CONFIG = PROJECT_ROOT / "configs" / "hvac_2r2c_infinite_safety.yaml"


def test_runner_consumes_verified_reader_without_rerunning_experiment(
    tmp_path: Path, monkeypatch
) -> None:
    """组合根只消费 verified 对象，并原子写出三件套。"""
    bundle = load_hvac_infinite_safety_bundle(CONFIG)
    source_hashes = dict(bundle.source_hashes)
    records = tuple(
        SimpleNamespace(
            status=SweepRunStatus.SUCCESS,
            cost=SimpleNamespace(protocol2_truncations_total=0),
            point=SimpleNamespace(
                ell=profile.fractional_bits,
                k=profile.integer_bits,
                lambda_=profile.security_parameter,
                q=profile.fixed_point.modulus,
                kappa=profile.kappa,
                seed=seed,
            ),
        )
        for profile in bundle.profiles
        for seed in (42, 43, 44)
    )
    verified = SimpleNamespace(
        root=tmp_path / "verified-sweep",
        definition={
            "fractional_bits": [32, 40, 48, 56],
            "integer_headroom_bits": 28,
            "security_parameter": 80,
            "seeds": [42, 43, 44],
            "primary_seed": 42,
            "max_protocol2_truncations_per_point": 0,
            "source_hashes": {
                "plant": source_hashes["plant"],
                "baseline": source_hashes["pid"],
            },
        },
        records=records,
    )
    monkeypatch.setattr(
        infinite_safety_runner,
        "load_hvac_infinite_safety_bundle",
        lambda _path: bundle,
    )
    monkeypatch.setattr(
        infinite_safety_runner,
        "load_verified_sweep_data",
        lambda _path: verified,
    )

    target = infinite_safety_runner.publish_infinite_safety_report(
        CONFIG, verified.root, tmp_path / "safety"
    )

    assert {path.name for path in target.iterdir()} == {
        "certificate.json",
        "report.md",
        "manifest.json",
    }
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    certificate = json.loads((target / "certificate.json").read_text(encoding="utf-8"))
    assert manifest["complete"] is True
    assert certificate["default_180_step_baseline_covered"] is False
    assert {profile["status"] for profile in certificate["profiles"]} == {"certified"}
    assert {profile["protocol2_truncations_per_step"] for profile in certificate["profiles"]} == {0}
    assert not list((tmp_path / "safety").glob(".*.tmp-*"))

    bad_point = SimpleNamespace(**vars(records[0].point))
    bad_point.q += 2
    bad_verified = SimpleNamespace(
        root=verified.root,
        definition=verified.definition,
        records=(SimpleNamespace(**{**vars(records[0]), "point": bad_point}), *records[1:]),
    )
    monkeypatch.setattr(
        infinite_safety_runner,
        "load_verified_sweep_data",
        lambda _path: bad_verified,
    )
    with pytest.raises(ValueError, match="q/kappa"):
        infinite_safety_runner.publish_infinite_safety_report(
            CONFIG, verified.root, tmp_path / "bad-safety"
        )
