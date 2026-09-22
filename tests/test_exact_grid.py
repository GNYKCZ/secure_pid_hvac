"""Exact-grid derivation, immutable sidecar and fail-closed publication tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from secure_control.experiments.exact_grid import (
    derive_exact_grid_row,
    unquantized_binary64_error,
)
from secure_control.experiments.exact_grid_artifacts import (
    load_verified_exact_grid_artifact,
    publish_exact_grid_artifact,
)
from secure_control.experiments.sweep import SweepPointDefinition, SweepRunStatus
from secure_control.experiments.sweep_artifacts import VerifiedSweepData
from secure_control.simulation import SimulationResult


def test_issue62_expected_exact_grid_zero_and_float64_collisions() -> None:
    """The accepted k=0/26/60 deltas remain exact integers at s=96."""
    scale = 96
    ideal = 1.0
    ideal_integer = 1 << scale
    zero = derive_exact_grid_row(
        ell=48,
        seed=42,
        step=0,
        channel=0,
        output_fractional_bits=scale,
        ideal_applied_control=ideal,
        secure_grid_integer=ideal_integer,
        float64_applied_error=0.0,
    )
    collision_26 = derive_exact_grid_row(
        ell=48,
        seed=42,
        step=26,
        channel=0,
        output_fractional_bits=scale,
        ideal_applied_control=ideal,
        secure_grid_integer=ideal_integer - 1_137_144_267_292,
        float64_applied_error=0.0,
    )
    collision_60 = derive_exact_grid_row(
        ell=48,
        seed=42,
        step=60,
        channel=0,
        output_fractional_bits=scale,
        ideal_applied_control=ideal,
        secure_grid_integer=ideal_integer - 66_080_791_343_908,
        float64_applied_error=0.0,
    )
    assert (zero.signed_error_integer, zero.classification) == (0, "exact_grid_zero")
    assert (collision_26.signed_error_integer, collision_26.classification) == (
        1_137_144_267_292,
        "float64_collision",
    )
    assert (collision_60.signed_error_integer, collision_60.classification) == (
        66_080_791_343_908,
        "float64_collision",
    )


def test_grid_quantized_error_is_distinct_from_unquantized_binary64_error() -> None:
    row = derive_exact_grid_row(
        ell=2,
        seed=42,
        step=0,
        channel=0,
        output_fractional_bits=2,
        ideal_applied_control=0.1,
        secure_grid_integer=0,
        float64_applied_error=0.1,
    )
    assert row.exact_grid_error == 0
    assert (
        unquantized_binary64_error(
            ideal_applied_control=0.1,
            secure_grid_integer=0,
            output_fractional_bits=2,
        )
        != 0
    )


def _fixture_sources(tmp_path: Path) -> tuple[VerifiedSweepData, SimpleNamespace, dict[str, str]]:
    sweep_root = tmp_path / "fixture-sweep"
    sweep_root.mkdir()
    for name, content in (("manifest.json", b"final\n"), ("data_manifest.json", b"data\n")):
        (sweep_root / name).write_bytes(content)
    points = tuple(
        SweepPointDefinition(ell, ell + 48, 128, (1 << 255) - 19, 120, 42) for ell in (32, 48)
    )
    records = []
    runs = {}
    for point in points:
        artifact_path = f"runs/{point.point_id}/fixture-run-{point.ell}"
        for relative, content in (
            (f"points/{point.point_id}/record.json", b"record\n"),
            (f"{artifact_path}/config.json", b"config\n"),
            (f"{artifact_path}/metadata.json", b"metadata\n"),
            (f"{artifact_path}/trajectory.csv", b"trajectory\n"),
        ):
            path = sweep_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        result = SimulationResult(
            time=np.array([0.0, 60.0]),
            reference=np.zeros((2, 1)),
            output_ideal=np.zeros((2, 1)),
            output_secure=np.zeros((2, 1)),
            control_ideal=np.ones((2, 1)),
            control_secure=np.ones((2, 1)),
            control_error=np.zeros((2, 1)),
            output_error=np.zeros((2, 1)),
        )
        records.append(
            SimpleNamespace(
                point=point,
                status=SweepRunStatus.SUCCESS,
                artifact_path=artifact_path,
            )
        )
        runs[point.point_id] = SimpleNamespace(run_id=f"fixture-run-{point.ell}", result=result)
    sweep = VerifiedSweepData(sweep_root, {"fractional_bits": [32, 48]}, tuple(records), runs)
    record = records[1]
    point = record.point
    run = runs[point.point_id]
    evidence_root = tmp_path / "evidence" / sweep_root.name / "fixture-trace"
    evidence_root.mkdir(parents=True)
    (evidence_root / "manifest.json").write_bytes(b"evidence\n")
    source_paths = (
        "manifest.json",
        "data_manifest.json",
        f"points/{point.point_id}/record.json",
        f"{record.artifact_path}/config.json",
        f"{record.artifact_path}/metadata.json",
        f"{record.artifact_path}/trajectory.csv",
    )
    source_hashes = {
        name: hashlib.sha256((sweep_root / name).read_bytes()).hexdigest() for name in source_paths
    }
    scale = 96
    centered = (1 << scale, (1 << scale) - 1)
    rows = tuple(
        {
            "step": step,
            "channel": 0,
            "time_seconds": float(run.result.time[step]),
            "raw_plaintext_control": 1.0,
            "raw_secure_control": 1.0,
            "secure_output_centered": centered[step],
            "output_fractional_bits": scale,
            "applied_plaintext_control": 1.0,
            "applied_secure_control": 1.0,
            "signed_applied_error": 0.0,
            "absolute_applied_error": 0.0,
        }
        for step in range(2)
    )
    evidence = SimpleNamespace(
        root=evidence_root,
        metadata={
            "source_point": {
                "ell": point.ell,
                "seed": point.seed,
                "point_id": point.point_id,
                "q": point.q,
                "artifact_path": record.artifact_path,
                "run_id": run.run_id,
            },
            "source_hashes": source_hashes,
            "modulus": point.q,
            "trace_id": evidence_root.name,
        },
        integer_control_rows=rows,
    )
    expected = {name: source_hashes[name] for name in ("manifest.json", "data_manifest.json")}
    return sweep, evidence, expected


def test_sidecar_round_trip_marks_missing_precision_and_rejects_tamper(tmp_path: Path) -> None:
    sweep, evidence, expected = _fixture_sources(tmp_path)
    artifacts = publish_exact_grid_artifact(
        verified_sweep=sweep,
        evidence_by_point={(48, 42): evidence},
        primary_seed=42,
        output_root=tmp_path / "exact",
        expected_source_hashes=expected,
    )
    loaded = load_verified_exact_grid_artifact(
        artifacts.directory,
        verified_sweep=sweep,
        evidence_by_point={(48, 42): evidence},
        expected_source_hashes=expected,
    )
    assert loaded.summary["by_fractional_bits"]["32"]["status"] == "unavailable"
    assert loaded.summary["by_fractional_bits"]["48"]["float64_zero_count"] == 2
    assert [row.classification for row in loaded.rows] == [
        "exact_grid_zero",
        "float64_collision",
    ]
    with (artifacts.directory / "exact_grid_control.csv").open("a", encoding="utf-8") as target:
        target.write("tamper\n")
    with pytest.raises(ValueError, match="SHA-256"):
        load_verified_exact_grid_artifact(
            artifacts.directory,
            verified_sweep=sweep,
            evidence_by_point={(48, 42): evidence},
            expected_source_hashes=expected,
        )


def test_sidecar_fails_closed_when_actuator_is_not_identity(tmp_path: Path) -> None:
    sweep, evidence, expected = _fixture_sources(tmp_path)
    altered = [dict(row) for row in evidence.integer_control_rows]
    altered[1]["raw_secure_control"] = 2.0
    evidence.integer_control_rows = tuple(altered)
    with pytest.raises(ValueError, match="actuator"):
        publish_exact_grid_artifact(
            verified_sweep=sweep,
            evidence_by_point={(48, 42): evidence},
            primary_seed=42,
            output_root=tmp_path / "exact",
            expected_source_hashes=expected,
        )


@pytest.mark.parametrize("invalid_version", [True, 1.0])
@pytest.mark.parametrize("target", ["manifest", "summary"])
def test_sidecar_rejects_non_integer_schema_versions(
    tmp_path: Path, target: str, invalid_version: object
) -> None:
    """JSON bool/float values must not compare equal to integer schema version 1."""
    sweep, evidence, expected = _fixture_sources(tmp_path)
    artifacts = publish_exact_grid_artifact(
        verified_sweep=sweep,
        evidence_by_point={(48, 42): evidence},
        primary_seed=42,
        output_root=tmp_path / "exact",
        expected_source_hashes=expected,
    )
    manifest_path = artifacts.directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if target == "manifest":
        manifest["schema_version"] = invalid_version
    else:
        summary_path = artifacts.directory / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["schema_version"] = invalid_version
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        manifest["files_sha256"]["summary.json"] = hashlib.sha256(
            summary_path.read_bytes()
        ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ValueError, match="schema"):
        load_verified_exact_grid_artifact(
            artifacts.directory,
            verified_sweep=sweep,
            evidence_by_point={(48, 42): evidence},
            expected_source_hashes=expected,
        )
