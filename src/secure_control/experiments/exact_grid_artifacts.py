"""Immutable exact-grid sidecar publication and strict verified reader."""

from __future__ import annotations

import csv
import io
import json
import math
import os
import re
import secrets
import shutil
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from .evidence_artifacts import VerifiedEvidenceData
from .exact_grid import ExactGridControlRow, derive_exact_grid_row
from .sweep import SweepRunStatus
from .sweep_artifacts import VerifiedSweepData

EXACT_GRID_SCHEMA_VERSION = 1
_ARTIFACT_ID_PATTERN = re.compile(r"\A\d{8}T\d{12}Z-[0-9a-f]{12}\Z")
_INTEGER_PATTERN = re.compile(r"\A(?:0|-?[1-9][0-9]*)\Z")
_SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
_MAX_ROWS = 1_000_000
_MAX_INTEGER_DIGITS = 2048
_MAX_CSV_BYTES = 64 * 1024 * 1024
_MAX_JSON_BYTES = 2 * 1024 * 1024
_CSV_HEADER = (
    "ell",
    "seed",
    "step",
    "channel",
    "output_fractional_bits",
    "ideal_grid_integer",
    "secure_grid_integer",
    "signed_error_integer",
    "float64_applied_error",
    "classification",
)


@dataclass(frozen=True, slots=True)
class ExactGridArtifacts:
    """Identity and paths for one atomically published exact-grid sidecar."""

    artifact_id: str
    directory: Path
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedExactGridData:
    """Exact-grid rows and summary after closure, lineage and formula verification."""

    root: Path
    manifest: Mapping[str, Any]
    summary: Mapping[str, Any]
    rows: tuple[ExactGridControlRow, ...]


def publish_exact_grid_artifact(
    *,
    verified_sweep: VerifiedSweepData,
    evidence_by_point: Mapping[tuple[int, int], VerifiedEvidenceData],
    primary_seed: int,
    output_root: str | Path,
    expected_source_hashes: Mapping[str, str],
) -> ExactGridArtifacts:
    """Publish exact-grid rows from already verified sources; never execute a controller."""
    source_hashes = _validate_expected_source_hashes(verified_sweep, expected_source_hashes)
    rows, availability = _derive_rows(verified_sweep, evidence_by_point, primary_seed=primary_seed)
    summary = _build_summary(rows, availability, primary_seed)
    artifact_id = _new_artifact_id()
    parent = Path(output_root) / verified_sweep.root.name
    parent.mkdir(parents=True, exist_ok=True)
    stage = parent / f".incomplete-{artifact_id}"
    final = parent / artifact_id
    if os.path.lexists(final):
        raise FileExistsError(f"exact-grid artifact ID 已存在：{artifact_id}")
    stage.mkdir(exist_ok=False)
    identity = stage.stat(follow_symlinks=False).st_ino
    try:
        csv_path = stage / "exact_grid_control.csv"
        summary_path = stage / "summary.json"
        _write_bytes(csv_path, _rows_csv(rows).encode("utf-8"))
        _write_bytes(summary_path, _json_bytes(summary))
        manifest = {
            "schema_version": EXACT_GRID_SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "source_sweep_id": verified_sweep.root.name,
            "source_hashes": source_hashes,
            "primary_seed": primary_seed,
            "row_count": len(rows),
            "availability": availability,
            "files_sha256": {
                "exact_grid_control.csv": _digest(csv_path),
                "summary.json": _digest(summary_path),
            },
        }
        _write_bytes(stage / "manifest.json", _json_bytes(manifest))
        _read_exact_grid(
            stage,
            verified_sweep=verified_sweep,
            evidence_by_point=evidence_by_point,
            expected_source_hashes=expected_source_hashes,
            allow_staging=True,
        )
        if os.path.lexists(final):
            raise FileExistsError(f"exact-grid artifact ID 已存在：{artifact_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, parent, identity):
            shutil.rmtree(stage)
        raise
    return ExactGridArtifacts(artifact_id, final, _digest(final / "manifest.json"))


def load_verified_exact_grid_artifact(
    path: str | Path,
    *,
    verified_sweep: VerifiedSweepData,
    evidence_by_point: Mapping[tuple[int, int], VerifiedEvidenceData],
    expected_source_hashes: Mapping[str, str],
) -> VerifiedExactGridData:
    """Verify an exact-grid sidecar against its canonical sweep and evidence sources."""
    return _read_exact_grid(
        Path(path),
        verified_sweep=verified_sweep,
        evidence_by_point=evidence_by_point,
        expected_source_hashes=expected_source_hashes,
        allow_staging=False,
    )


def _read_exact_grid(
    root: Path,
    *,
    verified_sweep: VerifiedSweepData,
    evidence_by_point: Mapping[tuple[int, int], VerifiedEvidenceData],
    expected_source_hashes: Mapping[str, str],
    allow_staging: bool,
) -> VerifiedExactGridData:
    """Shared staging/final reader with bounded parsing and formula re-derivation."""
    if (
        not root.is_dir()
        or _is_link_or_reparse(root)
        or (root.name.startswith(".incomplete-") and not allow_staging)
    ):
        raise ValueError("只允许读取已发布的 exact-grid 目录。")
    manifest = _read_json(root / "manifest.json")
    required = {
        "schema_version",
        "artifact_id",
        "created_at_utc",
        "source_sweep_id",
        "source_hashes",
        "primary_seed",
        "row_count",
        "availability",
        "files_sha256",
    }
    artifact_id = manifest.get("artifact_id")
    schema_version = manifest.get("schema_version")
    expected_name = f".incomplete-{artifact_id}" if allow_staging else artifact_id
    if (
        set(manifest) != required
        or type(schema_version) is not int
        or schema_version != EXACT_GRID_SCHEMA_VERSION
        or not isinstance(artifact_id, str)
        or not _ARTIFACT_ID_PATTERN.fullmatch(artifact_id)
        or root.name != expected_name
        or not isinstance(manifest.get("created_at_utc"), str)
    ):
        raise ValueError("exact-grid manifest schema、状态或 artifact ID 无效。")
    if root.parent.name != manifest.get("source_sweep_id"):
        raise ValueError("exact-grid 目录位置与 source_sweep_id 不一致。")
    source_hashes = _validate_expected_source_hashes(verified_sweep, expected_source_hashes)
    if (
        manifest.get("source_sweep_id") != verified_sweep.root.name
        or manifest.get("source_hashes") != source_hashes
    ):
        raise ValueError("exact-grid manifest 与 verified sweep lineage 不一致。")
    files = manifest.get("files_sha256")
    expected_files = {"exact_grid_control.csv", "summary.json"}
    members = tuple(root.iterdir())
    if (
        not isinstance(files, dict)
        or set(files) != expected_files
        or {item.name for item in members} != expected_files | {"manifest.json"}
        or any(_is_link_or_reparse(item) or not item.is_file() for item in members)
    ):
        raise ValueError("exact-grid 文件闭包无效。")
    for name, digest in files.items():
        if not _is_sha256(digest) or _digest(root / name) != digest:
            raise ValueError(f"exact-grid SHA-256 不匹配：{name}")
    primary_seed = manifest.get("primary_seed")
    if type(primary_seed) is not int:
        raise TypeError("exact-grid primary_seed 必须是 int。")
    rows = _read_rows(root / "exact_grid_control.csv")
    expected_rows, availability = _derive_rows(
        verified_sweep, evidence_by_point, primary_seed=primary_seed
    )
    if rows != expected_rows:
        raise ValueError("exact-grid rows 无法从 verified sources 重导。")
    if manifest.get("row_count") != len(rows) or manifest.get("availability") != availability:
        raise ValueError("exact-grid manifest 行数或可用性不可重导。")
    summary = _read_json(root / "summary.json")
    summary_version = summary.get("schema_version")
    if type(summary_version) is not int or summary_version != EXACT_GRID_SCHEMA_VERSION:
        raise ValueError("exact-grid summary schema_version 无效。")
    if summary != _build_summary(rows, availability, primary_seed):
        raise ValueError("exact-grid summary 不可重导。")
    return VerifiedExactGridData(root.resolve(), manifest, summary, rows)


def _derive_rows(
    sweep: VerifiedSweepData,
    evidence_by_point: Mapping[tuple[int, int], VerifiedEvidenceData],
    *,
    primary_seed: int,
) -> tuple[tuple[ExactGridControlRow, ...], list[dict[str, Any]]]:
    """Build exact rows and explicit unavailable entries for the primary seed."""
    if type(primary_seed) is not int:
        raise TypeError("primary_seed 必须是 int。")
    records = sorted(
        (
            item
            for item in sweep.records
            if item.point.seed == primary_seed and item.status is SweepRunStatus.SUCCESS
        ),
        key=lambda item: item.point.ell,
    )
    if not records:
        raise ValueError("verified sweep 不含 primary seed 的成功点。")
    record_keys = {(item.point.ell, item.point.seed) for item in records}
    extra = set(evidence_by_point) - record_keys
    if extra:
        raise ValueError("evidence mapping 包含非 primary-seed 成功点。")
    result_rows: list[ExactGridControlRow] = []
    availability: list[dict[str, Any]] = []
    for record in records:
        key = (record.point.ell, record.point.seed)
        evidence = evidence_by_point.get(key)
        if evidence is None:
            availability.append(
                {
                    "ell": record.point.ell,
                    "seed": record.point.seed,
                    "point_id": record.point.point_id,
                    "status": "unavailable",
                    "reason": "missing_verified_evidence",
                    "source": None,
                }
            )
            continue
        rows = _derive_point_rows(sweep, record, evidence)
        result_rows.extend(rows)
        availability.append(
            {
                "ell": record.point.ell,
                "seed": record.point.seed,
                "point_id": record.point.point_id,
                "status": "available",
                "reason": None,
                "source": {
                    "run_id": evidence.metadata["source_point"]["run_id"],
                    "trajectory_sha256": evidence.metadata["source_hashes"][
                        f"{record.artifact_path}/trajectory.csv"
                    ],
                    "trace_id": evidence.metadata["trace_id"],
                    "evidence_manifest_sha256": _digest(evidence.root / "manifest.json"),
                },
            }
        )
    return tuple(result_rows), availability


def _derive_point_rows(
    sweep: VerifiedSweepData, record: Any, evidence: VerifiedEvidenceData
) -> tuple[ExactGridControlRow, ...]:
    """Validate lineage/alignment/identity and derive one point without float-decoding U."""
    point = evidence.metadata.get("source_point")
    source_hashes = evidence.metadata.get("source_hashes")
    run = sweep.runs.get(record.point.point_id)
    if run is None or not isinstance(point, dict) or not isinstance(source_hashes, dict):
        raise ValueError("exact-grid evidence 缺少 point、hash 或 verified run。")
    artifact_path = str(record.artifact_path)
    expected_point = {
        "ell": record.point.ell,
        "seed": record.point.seed,
        "point_id": record.point.point_id,
        "q": record.point.q,
        "artifact_path": artifact_path,
        "run_id": run.run_id,
    }
    if any(point.get(name) != value for name, value in expected_point.items()):
        raise ValueError("exact-grid evidence point lineage 与 sweep run 不一致。")
    expected_hash_paths = (
        "manifest.json",
        "data_manifest.json",
        f"points/{record.point.point_id}/record.json",
        f"{artifact_path}/config.json",
        f"{artifact_path}/metadata.json",
        f"{artifact_path}/trajectory.csv",
    )
    for relative in expected_hash_paths:
        path = sweep.root / relative
        if source_hashes.get(relative) != _digest(path):
            raise ValueError(f"exact-grid evidence source hash 不匹配：{relative}")
    if evidence.metadata.get("modulus") != record.point.q:
        raise ValueError("exact-grid evidence modulus 与 sweep point 不一致。")
    ideal = run.result.control_ideal
    secure = run.result.control_secure
    errors = run.result.control_error
    if ideal.shape != secure.shape or ideal.shape != errors.shape:
        raise ValueError("exact-grid control arrays shape 不一致。")
    indexed: dict[tuple[int, int], Mapping[str, Any]] = {}
    for row in evidence.integer_control_rows:
        key = (row.get("step"), row.get("channel"))
        if key in indexed:
            raise ValueError("integer_control 含重复 step/channel。")
        indexed[key] = row
    expected_keys = {
        (step, channel) for step in range(ideal.shape[0]) for channel in range(ideal.shape[1])
    }
    if set(indexed) != expected_keys:
        raise ValueError("integer_control 与 trajectory step/channel 不完整对齐。")
    derived: list[ExactGridControlRow] = []
    scale: int | None = None
    for step, channel in sorted(expected_keys):
        row = indexed[(step, channel)]
        row_scale = row.get("output_fractional_bits")
        secure_integer = row.get("secure_output_centered")
        if type(row_scale) is not int or not 0 <= row_scale <= 4096:
            raise ValueError("integer_control scale 无效。")
        if type(secure_integer) is not int or len(str(abs(secure_integer))) > _MAX_INTEGER_DIGITS:
            raise ValueError("integer_control centered integer 无效或超出资源上限。")
        scale = row_scale if scale is None else scale
        if row_scale != scale:
            raise ValueError("一个 exact-grid point 的 output scale 必须恒定。")
        ideal_value = float(ideal[step, channel])
        secure_value = float(secure[step, channel])
        error_value = float(errors[step, channel])
        if (
            row.get("time_seconds") != float(run.result.time[step])
            or row.get("applied_plaintext_control") != ideal_value
            or row.get("applied_secure_control") != secure_value
            or row.get("signed_applied_error") != error_value
            or row.get("absolute_applied_error") != abs(error_value)
        ):
            raise ValueError("integer_control 与 verified 八字段 trajectory 不一致。")
        if row.get("raw_plaintext_control") != row.get("applied_plaintext_control") or row.get(
            "raw_secure_control"
        ) != row.get("applied_secure_control"):
            raise ValueError("actuator 不是逐步恒等映射，拒绝发布 applied exact-grid。")
        derived.append(
            derive_exact_grid_row(
                ell=record.point.ell,
                seed=record.point.seed,
                step=step,
                channel=channel,
                output_fractional_bits=row_scale,
                ideal_applied_control=ideal_value,
                secure_grid_integer=secure_integer,
                float64_applied_error=error_value,
            )
        )
    return tuple(derived)


def _build_summary(
    rows: tuple[ExactGridControlRow, ...],
    availability: list[dict[str, Any]],
    primary_seed: int,
) -> dict[str, Any]:
    """Build deterministic counts while preserving historical float64-zero semantics."""
    by_ell: dict[str, Any] = {}
    for item in availability:
        ell = item["ell"]
        selected = tuple(row for row in rows if row.ell == ell)
        if item["status"] == "unavailable":
            by_ell[str(ell)] = {
                "status": "unavailable",
                "reason": item["reason"],
                "sample_count": 0,
                "float64_zero_count": None,
                "exact_grid_zero_count": None,
                "float64_collision_count": None,
                "nonzero_count": None,
                "maximum_absolute_error_integer": None,
                "minimum_positive_absolute_error_integer": None,
            }
            continue
        positive = [abs(row.signed_error_integer) for row in selected if row.signed_error_integer]
        by_ell[str(ell)] = {
            "status": "available",
            "reason": None,
            "sample_count": len(selected),
            "float64_zero_count": sum(row.float64_applied_error == 0.0 for row in selected),
            "exact_grid_zero_count": sum(
                row.classification == "exact_grid_zero" for row in selected
            ),
            "float64_collision_count": sum(
                row.classification == "float64_collision" for row in selected
            ),
            "nonzero_count": sum(row.classification == "nonzero" for row in selected),
            "maximum_absolute_error_integer": max(positive, default=0),
            "minimum_positive_absolute_error_integer": min(positive, default=None),
        }
    return {
        "schema_version": EXACT_GRID_SCHEMA_VERSION,
        "primary_seed": primary_seed,
        "metric_definitions": {
            "float64_applied_error": "stored binary64 ideal applied control minus secure applied control",
            "ideal_grid_integer": "floor(Fraction.from_float(ideal_binary64) * 2**s + 1/2)",
            "exact_grid_error": "(ideal_grid_integer - secure_grid_integer) / 2**s",
            "unquantized_binary64_error": "Fraction.from_float(ideal_binary64) - secure_grid_integer / 2**s; distinct from exact_grid_error",
        },
        "by_fractional_bits": by_ell,
    }


def _rows_csv(rows: tuple[ExactGridControlRow, ...]) -> str:
    target = io.StringIO(newline="")
    writer = csv.DictWriter(target, fieldnames=_CSV_HEADER)
    writer.writeheader()
    for row in rows:
        payload = asdict(row)
        payload["float64_applied_error"] = format(row.float64_applied_error, ".17g")
        writer.writerow(payload)
    return target.getvalue()


def _read_rows(path: Path) -> tuple[ExactGridControlRow, ...]:
    if path.stat().st_size > _MAX_CSV_BYTES:
        raise ValueError("exact-grid CSV 超出资源上限。")
    result: list[ExactGridControlRow] = []
    with path.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != _CSV_HEADER:
            raise ValueError("exact-grid CSV header 无效。")
        for payload in reader:
            if len(result) >= _MAX_ROWS:
                raise ValueError("exact-grid CSV 行数超出资源上限。")
            if set(payload) != set(_CSV_HEADER) or any(value is None for value in payload.values()):
                raise ValueError("exact-grid CSV row 列数无效。")
            integers = {
                name: _parse_integer(payload[name])
                for name in _CSV_HEADER
                if name
                not in {
                    "float64_applied_error",
                    "classification",
                }
            }
            error = float(payload["float64_applied_error"])
            classification = payload["classification"]
            if not math.isfinite(error) or classification not in {
                "exact_grid_zero",
                "float64_collision",
                "nonzero",
            }:
                raise ValueError("exact-grid float 或 classification 无效。")
            result.append(
                ExactGridControlRow(
                    **integers,
                    float64_applied_error=error,
                    classification=classification,
                )
            )
    return tuple(result)


def _validate_expected_source_hashes(
    sweep: VerifiedSweepData, expected: Mapping[str, str]
) -> dict[str, str]:
    required = {"manifest.json", "data_manifest.json"}
    if set(expected) != required or any(not _is_sha256(value) for value in expected.values()):
        raise ValueError("expected sweep source hashes 无效。")
    actual = {name: _digest(sweep.root / name) for name in sorted(required)}
    if dict(expected) != actual:
        raise ValueError("expected sweep source hashes 与 verified sweep 不一致。")
    return actual


def _parse_integer(value: object) -> int:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_INTEGER_DIGITS + 1
        or not _INTEGER_PATTERN.fullmatch(value)
    ):
        raise ValueError("exact-grid integer 文本无效或超出资源上限。")
    return int(value)


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"{path.name} 超出资源上限。")

    def reject(value: str) -> None:
        raise ValueError(f"非标准 JSON 数值：{value}")

    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=reject)
    if not isinstance(value, dict):
        raise TypeError(f"{path.name} 必须是 JSON 对象。")
    return value


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def _write_bytes(path: Path, content: bytes) -> None:
    with path.open("xb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_PATTERN.fullmatch(value))


def _new_artifact_id() -> str:
    value = f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{secrets.token_hex(6)}"
    if not _ARTIFACT_ID_PATTERN.fullmatch(value):
        raise ValueError("exact-grid artifact ID 格式无效。")
    return value


def _is_link_or_reparse(path: Path) -> bool:
    """Reject symlinks and Windows reparse points before following artifact members."""
    try:
        mode = path.lstat().st_mode
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(mode) or bool(attributes & reparse)


def _owned_stage(stage: Path, parent: Path, identity: int) -> bool:
    try:
        return (
            stage.resolve().parent == parent.resolve()
            and stage.name.startswith(".incomplete-")
            and not stage.is_symlink()
            and stage.stat(follow_symlinks=False).st_ino == identity
        )
    except OSError:
        return False
