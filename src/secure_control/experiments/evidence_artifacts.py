"""Secure execution evidence 的无损整数工件、原子发布与严格 reader。"""

from __future__ import annotations

import csv
import json
import math
import os
import re
import secrets
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np

from secure_control.execution import SecureStepTrace
from secure_control.protocol.evidence import CombinedShareStepAudit, IntegerVectorEvidence
from secure_control.simulation import SimulationResult

EVIDENCE_SCHEMA_VERSION = 1
_TRACE_ID_PATTERN = re.compile(r"\A\d{8}T\d{12}Z-[0-9a-f]{12}\Z")
_INTEGER_PATTERN = re.compile(r"\A(?:0|-?[1-9][0-9]*)\Z")
_INTEGER_HEADER = (
    "step",
    "channel",
    "time_seconds",
    "raw_plaintext_control",
    "raw_secure_control",
    "secure_output_residue",
    "secure_output_centered",
    "output_fractional_bits",
    "applied_plaintext_control",
    "applied_secure_control",
    "signed_applied_error",
    "absolute_applied_error",
)
_RESOURCE_HEADER = (
    "step",
    "triples_created",
    "triples_consumed",
    "triples_aborted",
    "truncations_created",
    "truncations_consumed",
    "truncations_aborted",
    "triples_created_delta",
    "triples_consumed_delta",
    "truncations_created_delta",
    "truncations_consumed_delta",
    "operation_A",
    "operation_B",
    "operation_C",
    "operation_D",
    "state_truncation",
)


@dataclass(frozen=True, slots=True)
class EvidenceArtifacts:
    """返回一次已发布 sanitized evidence 与可选 private audit 的身份。"""

    trace_id: str
    directory: Path
    manifest_sha256: str
    private_audit_sha256: str | None
    private_audit_path: Path | None


@dataclass(frozen=True, slots=True)
class VerifiedEvidenceData:
    """保存严格校验后的证据行、选定 step、metadata 和来源目录。"""

    root: Path
    metadata: Mapping[str, Any]
    integer_control_rows: tuple[Mapping[str, Any], ...]
    resource_rows: tuple[Mapping[str, int], ...]
    selected_step: Mapping[str, Any]


def write_evidence_artifacts(
    *,
    traces: Sequence[SecureStepTrace],
    result: SimulationResult,
    plaintext_raw_control: np.ndarray,
    metadata: Mapping[str, Any],
    output_root: str | Path,
    source_sweep_id: str,
    share_audit: CombinedShareStepAudit | None,
    prepublish_validator: Callable[[], None] | None = None,
) -> EvidenceArtifacts:
    """以 staging+验证+rename 发布 sanitized 证据，并物理隔离 private shares。"""
    _validate_path_component(source_sweep_id, "source_sweep_id")
    trace_tuple = tuple(traces)
    _validate_trace_inputs(trace_tuple, result, plaintext_raw_control, metadata)
    root = Path(output_root)
    parent = root / source_sweep_id
    private_parent = root / "private"
    parent.mkdir(parents=True, exist_ok=True)
    if share_audit is not None:
        private_parent.mkdir(parents=True, exist_ok=True)
    trace_id = _new_trace_id()
    stage = parent / f".incomplete-{trace_id}"
    final = parent / trace_id
    private_stage = private_parent / f".incomplete-{trace_id}"
    private_final = private_parent / trace_id
    if os.path.lexists(final) or os.path.lexists(private_final):
        raise FileExistsError(f"trace ID 已存在：{trace_id}")
    stage.mkdir(exist_ok=False)
    stage_identity = stage.stat(follow_symlinks=False).st_ino
    private_identity: int | None = None
    private_hash: str | None = None
    private_path: Path | None = None
    try:
        if share_audit is not None:
            private_stage.mkdir(exist_ok=False)
            private_identity = private_stage.stat(follow_symlinks=False).st_ino
            private_payload = {
                "schema_version": 1,
                "trace_id": trace_id,
                "deployment_security": False,
                "diagnostic_rng_mode": "reproducibility_only",
                "step": share_audit.step,
                "input_p1": [str(value) for value in share_audit.input_p1],
                "input_p2": [str(value) for value in share_audit.input_p2],
                "output_p1": [str(value) for value in share_audit.output_p1],
                "output_p2": [str(value) for value in share_audit.output_p2],
                "reconstruction_verified": share_audit.reconstruction_verified,
            }
            private_file = private_stage / "combined_share_step.json"
            _write_bytes(private_file, _json_bytes(private_payload))
            private_hash = _digest(private_file)

        integer_path = stage / "integer_control.csv"
        resource_path = stage / "resource_counts.csv"
        selected_path = stage / "selected_step_trace.json"
        metadata_path = stage / "metadata.json"
        _write_integer_control(integer_path, trace_tuple, result, plaintext_raw_control)
        _write_resource_counts(resource_path, trace_tuple)
        selected = next(trace for trace in trace_tuple if trace.state_transition is not None)
        if share_audit is not None and (
            share_audit.step != selected.step or share_audit.reconstruction_verified is not True
        ):
            raise ValueError("combined-share audit 必须绑定 selected step 且已通过重构核查。")
        _write_bytes(selected_path, _json_bytes(_selected_step_payload(selected)))
        metadata_payload = dict(metadata)
        metadata_payload.update(
            {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "trace_id": trace_id,
                "source_sweep_id": source_sweep_id,
                "sample_count": len(trace_tuple),
                "selected_step": selected.step,
                "private_audit": {
                    "schema_version": 1,
                    "sha256": private_hash,
                    "present_at_publication": share_audit is not None,
                    "deployment_security": False,
                    "contains_raw_share_values": share_audit is not None,
                },
            }
        )
        _write_bytes(metadata_path, _json_bytes(metadata_payload))
        files = (
            "integer_control.csv",
            "resource_counts.csv",
            "selected_step_trace.json",
            "metadata.json",
        )
        manifest = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "trace_id": trace_id,
            "success": True,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "source_sweep_id": source_sweep_id,
            "files_sha256": {name: _digest(stage / name) for name in files},
            "private_audit": {
                "schema_version": 1,
                "sha256": private_hash,
                "deployment_security": False,
                "included_in_files_sha256": False,
            },
        }
        _write_bytes(stage / "manifest.json", _json_bytes(manifest))
        _read_evidence(stage, allow_staging=True)
        if prepublish_validator is not None:
            prepublish_validator()

        if share_audit is not None:
            if os.path.lexists(private_final):
                raise FileExistsError(f"private trace ID 已存在：{trace_id}")
            os.rename(private_stage, private_final)
            private_path = private_final / "combined_share_step.json"
        if os.path.lexists(final):
            raise FileExistsError(f"trace ID 已存在：{trace_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, parent, stage_identity):
            shutil.rmtree(stage)
        if private_identity is not None and _owned_stage(
            private_stage, private_parent, private_identity
        ):
            shutil.rmtree(private_stage)
        if private_path is not None and private_final.is_dir() and not private_final.is_symlink():
            shutil.rmtree(private_final)
        raise
    manifest_path = final / "manifest.json"
    return EvidenceArtifacts(
        trace_id,
        final,
        _digest(manifest_path),
        private_hash,
        private_path,
    )


def load_verified_evidence_artifacts(path: str | Path) -> VerifiedEvidenceData:
    """读取已发布目录并验证 schema、文件闭包、hash、整数和 step/resource 不变量。"""
    return _read_evidence(Path(path), allow_staging=False)


def _read_evidence(root: Path, *, allow_staging: bool) -> VerifiedEvidenceData:
    """共享 staging/final reader；private 文件从不属于 sanitized 目录闭包。"""
    if (
        not root.is_dir()
        or root.is_symlink()
        or (root.name.startswith(".incomplete-") and not allow_staging)
    ):
        raise ValueError("只允许读取已发布的 evidence 目录。")
    manifest = _read_json(root / "manifest.json")
    if set(manifest) != {
        "schema_version",
        "trace_id",
        "success",
        "created_at_utc",
        "source_sweep_id",
        "files_sha256",
        "private_audit",
    }:
        raise ValueError("evidence manifest 字段无效。")
    trace_id = manifest.get("trace_id")
    expected_name = f".incomplete-{trace_id}" if allow_staging else trace_id
    if (
        manifest.get("schema_version") != EVIDENCE_SCHEMA_VERSION
        or manifest.get("success") is not True
        or not isinstance(trace_id, str)
        or not _TRACE_ID_PATTERN.fullmatch(trace_id)
        or root.name != expected_name
    ):
        raise ValueError("evidence manifest 状态、schema 或 trace ID 无效。")
    source_sweep_id = manifest.get("source_sweep_id")
    _validate_path_component(source_sweep_id, "source_sweep_id")
    if root.parent.name != source_sweep_id:
        raise ValueError("evidence 目录位置与 source_sweep_id 不一致。")
    if not isinstance(manifest.get("created_at_utc"), str):
        raise TypeError("evidence manifest created_at_utc 必须是字符串。")
    expected_files = {
        "integer_control.csv",
        "resource_counts.csv",
        "selected_step_trace.json",
        "metadata.json",
    }
    declared = manifest.get("files_sha256")
    if not isinstance(declared, dict) or set(declared) != expected_files:
        raise ValueError("evidence manifest 文件闭包无效。")
    actual_members = {item.name for item in root.iterdir() if item.is_file()}
    if actual_members != expected_files | {"manifest.json"}:
        raise ValueError("evidence 目录包含缺失或未声明的文件。")
    for name, digest in declared.items():
        member = _safe_member(root, name)
        if not isinstance(digest, str) or _digest(member) != digest:
            raise ValueError(f"{name} SHA-256 与 manifest 不一致。")
    private = manifest.get("private_audit")
    if not isinstance(private, dict) or set(private) != {
        "schema_version",
        "sha256",
        "deployment_security",
        "included_in_files_sha256",
    }:
        raise ValueError("private audit descriptor 无效。")
    if (
        private["schema_version"] != 1
        or private["deployment_security"] is not False
        or private["included_in_files_sha256"] is not False
        or (private["sha256"] is not None and not _is_sha256(private["sha256"]))
    ):
        raise ValueError("private audit 安全标记或摘要无效。")
    metadata = _read_json(root / "metadata.json")
    selected = _read_json(root / "selected_step_trace.json")
    if (
        metadata.get("schema_version") != EVIDENCE_SCHEMA_VERSION
        or metadata.get("trace_id") != trace_id
        or metadata.get("source_sweep_id") != manifest.get("source_sweep_id")
        or metadata.get("private_audit")
        != {
            "schema_version": 1,
            "sha256": private["sha256"],
            "present_at_publication": private["sha256"] is not None,
            "deployment_security": False,
            "contains_raw_share_values": private["sha256"] is not None,
        }
    ):
        raise ValueError("metadata 与 manifest/private audit descriptor 不一致。")
    _reject_raw_share_keys(metadata, "metadata")
    _reject_raw_share_keys(selected, "selected_step_trace")
    integer_rows = _read_integer_rows(root / "integer_control.csv")
    resource_rows = _read_resource_rows(root / "resource_counts.csv")
    sample_count = metadata.get("sample_count")
    if type(sample_count) is not int or sample_count <= 0:
        raise ValueError("metadata.sample_count 必须是正整数。")
    steps = sorted({row["step"] for row in integer_rows})
    if steps != list(range(sample_count)) or [row["step"] for row in resource_rows] != steps:
        raise ValueError("evidence step 必须从 0 连续到 sample_count-1。")
    selected_step = metadata.get("selected_step")
    if (
        type(selected_step) is not int
        or selected.get("step") != selected_step
        or selected_step not in steps
    ):
        raise ValueError("selected step 与 metadata/trajectory 不一致。")
    _validate_selected_payload(selected)
    _validate_resource_rows(resource_rows)
    resource_contract = metadata.get("resource_contract")
    if resource_contract is not None:
        _validate_resource_contract(resource_rows, resource_contract)
    return VerifiedEvidenceData(
        root,
        metadata,
        tuple(integer_rows),
        tuple(resource_rows),
        selected,
    )


def _validate_trace_inputs(
    traces: tuple[SecureStepTrace, ...],
    result: SimulationResult,
    plaintext_raw_control: np.ndarray,
    metadata: Mapping[str, Any],
) -> None:
    """在创建 staging 前拒绝缺步、shape、有限值和 selected-state 不一致。"""
    if not traces or not isinstance(result, SimulationResult):
        raise ValueError("traces/result 必须是非空合法诊断结果。")
    if tuple(trace.step for trace in traces) != tuple(range(len(traces))):
        raise ValueError("trace step 必须严格连续。")
    if len(traces) != result.time.size:
        raise ValueError("trace 数量必须等于 SimulationResult sample count。")
    raw = np.asarray(plaintext_raw_control)
    if raw.shape != result.control_ideal.shape or not np.isfinite(raw).all():
        raise ValueError("plaintext raw control shape/有限性与正式 control 不一致。")
    if sum(trace.state_transition is not None for trace in traces) != 1:
        raise ValueError("evidence 必须且只能包含一个 selected state transition。")
    if not isinstance(metadata, Mapping):
        raise TypeError("metadata 必须是映射。")


def _write_integer_control(
    path: Path,
    traces: tuple[SecureStepTrace, ...],
    result: SimulationResult,
    plaintext_raw_control: np.ndarray,
) -> None:
    """逐 step/channel 保存真实整数与 raw/applied 控制，不缩窄任意精度整数。"""
    with path.open("x", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(_INTEGER_HEADER)
        for trace in traces:
            channels = len(trace.raw_control.centered)
            if channels != result.control_secure.shape[1]:
                raise ValueError("secure raw control channel 数与 SimulationResult 不一致。")
            for channel in range(channels):
                ideal_applied = float(result.control_ideal[trace.step, channel])
                secure_applied = float(result.control_secure[trace.step, channel])
                writer.writerow(
                    (
                        trace.step,
                        channel,
                        _float_text(result.time[trace.step]),
                        _float_text(plaintext_raw_control[trace.step, channel]),
                        _float_text(trace.decoded_raw_control[channel]),
                        str(trace.raw_control.residue[channel]),
                        str(trace.raw_control.centered[channel]),
                        trace.raw_control.fractional_bits,
                        _float_text(ideal_applied),
                        _float_text(secure_applied),
                        _float_text(ideal_applied - secure_applied),
                        _float_text(abs(ideal_applied - secure_applied)),
                    )
                )
        target.flush()
        os.fsync(target.fileno())


def _write_resource_counts(path: Path, traces: tuple[SecureStepTrace, ...]) -> None:
    """保存真实累计资源与相邻快照增量，操作分解来自每步 plan。"""
    with path.open("x", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(_RESOURCE_HEADER)
        for trace in traces:
            before, after, operations = (
                trace.resources_before,
                trace.resources_after,
                trace.operations,
            )
            writer.writerow(
                (
                    trace.step,
                    after.triples_created,
                    after.triples_consumed,
                    after.triples_aborted,
                    after.truncations_created,
                    after.truncations_consumed,
                    after.truncations_aborted,
                    after.triples_created - before.triples_created,
                    after.triples_consumed - before.triples_consumed,
                    after.truncations_created - before.truncations_created,
                    after.truncations_consumed - before.truncations_consumed,
                    operations.A,
                    operations.B,
                    operations.C,
                    operations.D,
                    operations.state_truncation,
                )
            )
        target.flush()
        os.fsync(target.fileno())


def _selected_step_payload(trace: SecureStepTrace) -> dict[str, Any]:
    """生成不含 raw shares 的选定 step JSON，并保留整数十进制文本。"""
    if trace.state_transition is None:
        raise ValueError("selected step 缺少 state transition。")
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "step": trace.step,
        "session_id_sha256": trace.session_id_sha256,
        "round_id_sha256": trace.round_id_sha256,
        "controller_input": _integer_vector_payload(trace.controller_input),
        "raw_control": _integer_vector_payload(trace.raw_control),
        "decoded_raw_control": list(trace.decoded_raw_control),
        "resource_id_sha256": list(trace.resource_id_sha256),
        "resources_before": asdict(trace.resources_before),
        "resources_after": asdict(trace.resources_after),
        "operations": {
            **asdict(trace.operations),
            "protocol1_triples": trace.operations.protocol1_triples,
        },
        "state_transition": {
            "state_before": _integer_vector_payload(trace.state_transition.state_before),
            "controller_input": _integer_vector_payload(trace.state_transition.controller_input),
            "state_accumulator": _integer_vector_payload(trace.state_transition.state_accumulator),
            "state_after": _integer_vector_payload(trace.state_transition.state_after),
            "truncation_bits": trace.state_transition.truncation_bits,
            "equation_verified": trace.state_transition.equation_verified,
        },
    }


def _integer_vector_payload(value: IntegerVectorEvidence) -> dict[str, Any]:
    """用十进制字符串保存大整数，避免 JSON consumer 的 binary64 精度丢失。"""
    return {
        "residue": [str(item) for item in value.residue],
        "centered": [str(item) for item in value.centered],
        "fractional_bits": value.fractional_bits,
    }


def _read_integer_rows(path: Path) -> list[dict[str, Any]]:
    """严格解析控制 CSV；整数列保持 Python int，浮点列拒绝 NaN/Inf。"""
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != _INTEGER_HEADER:
            raise ValueError("integer_control.csv header 无效。")
        for raw in reader:
            row = {
                "step": _parse_integer(raw["step"]),
                "channel": _parse_integer(raw["channel"]),
                "time_seconds": _parse_float(raw["time_seconds"]),
                "raw_plaintext_control": _parse_float(raw["raw_plaintext_control"]),
                "raw_secure_control": _parse_float(raw["raw_secure_control"]),
                "secure_output_residue": _parse_integer(raw["secure_output_residue"]),
                "secure_output_centered": _parse_integer(raw["secure_output_centered"]),
                "output_fractional_bits": _parse_integer(raw["output_fractional_bits"]),
                "applied_plaintext_control": _parse_float(raw["applied_plaintext_control"]),
                "applied_secure_control": _parse_float(raw["applied_secure_control"]),
                "signed_applied_error": _parse_float(raw["signed_applied_error"]),
                "absolute_applied_error": _parse_float(raw["absolute_applied_error"]),
            }
            if row["step"] < 0 or row["channel"] < 0 or row["output_fractional_bits"] < 0:
                raise ValueError("integer control 索引与 scale 必须非负。")
            scale = 1 << row["output_fractional_bits"]
            if row["raw_secure_control"] != row["secure_output_centered"] / scale:
                raise ValueError("centered integer 与 decoded raw secure control 不一致。")
            if (
                row["signed_applied_error"]
                != row["applied_plaintext_control"] - row["applied_secure_control"]
            ):
                raise ValueError("signed applied error 与控制量不一致。")
            if row["absolute_applied_error"] != abs(row["signed_applied_error"]):
                raise ValueError("absolute applied error 与 signed error 不一致。")
            rows.append(row)
    if not rows:
        raise ValueError("integer_control.csv 不得为空。")
    pairs = [(row["step"], row["channel"]) for row in rows]
    if len(pairs) != len(set(pairs)) or pairs != sorted(pairs):
        raise ValueError("integer control step/channel 必须唯一且有序。")
    channels = sorted({row["channel"] for row in rows})
    if channels != list(range(len(channels))) or any(
        [row["channel"] for row in rows if row["step"] == step] != channels
        for step in sorted({row["step"] for row in rows})
    ):
        raise ValueError("每个 step 必须具有相同且从 0 连续的 control channels。")
    return rows


def _read_resource_rows(path: Path) -> list[dict[str, int]]:
    """严格解析资源 CSV，拒绝负数、重复或乱序 step。"""
    rows: list[dict[str, int]] = []
    with path.open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != _RESOURCE_HEADER:
            raise ValueError("resource_counts.csv header 无效。")
        for raw in reader:
            row = {name: _parse_integer(raw[name]) for name in _RESOURCE_HEADER}
            if any(value < 0 for value in row.values()):
                raise ValueError("resource count 不得为负数。")
            rows.append(row)
    if [row["step"] for row in rows] != list(range(len(rows))):
        raise ValueError("resource step 必须从 0 连续且有序。")
    return rows


def _validate_resource_rows(rows: list[dict[str, int]]) -> None:
    """核对累计单调、delta 与 A/B/C/D/truncation 的真实 plan 分解。"""
    previous = {
        name: 0 for name in _RESOURCE_HEADER if name.endswith(("created", "consumed", "aborted"))
    }
    for row in rows:
        for name, value in previous.items():
            if row[name] < value:
                raise ValueError("资源累计计数不得倒退。")
        if row["triples_created_delta"] != row["triples_created"] - previous["triples_created"]:
            raise ValueError("triple created delta 无效。")
        if row["triples_consumed_delta"] != row["triples_consumed"] - previous["triples_consumed"]:
            raise ValueError("triple consumed delta 无效。")
        if (
            row["truncations_created_delta"]
            != row["truncations_created"] - previous["truncations_created"]
        ):
            raise ValueError("truncation created delta 无效。")
        if (
            row["truncations_consumed_delta"]
            != row["truncations_consumed"] - previous["truncations_consumed"]
        ):
            raise ValueError("truncation consumed delta 无效。")
        if row["triples_created_delta"] != sum(row[f"operation_{term}"] for term in "ABCD"):
            raise ValueError("每步 triple delta 与 A/B/C/D operation plan 不一致。")
        if row["truncations_created_delta"] != row["state_truncation"]:
            raise ValueError("每步 truncation delta 与 operation plan 不一致。")
        if (
            row["triples_consumed_delta"] != row["triples_created_delta"]
            or row["truncations_consumed_delta"] != row["truncations_created_delta"]
            or row["triples_aborted"] != 0
            or row["truncations_aborted"] != 0
        ):
            raise ValueError("成功 evidence 的当步资源必须全部消费且不得废弃。")
        for name in previous:
            previous[name] = row[name]


def _validate_resource_contract(rows: list[dict[str, int]], value: object) -> None:
    """把 runner 声明的每步/总资源数绑定到实际 lifecycle 最终行。"""
    required = {
        "protocol1_triples_per_step",
        "protocol1_triples_total",
        "protocol2_truncations_per_step",
        "protocol2_truncations_total",
        "count_semantics",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("resource_contract schema 无效。")
    counts = (
        value["protocol1_triples_per_step"],
        value["protocol1_triples_total"],
        value["protocol2_truncations_per_step"],
        value["protocol2_truncations_total"],
    )
    if any(type(item) is not int or item < 0 for item in counts):
        raise ValueError("resource_contract count 必须是非负整数。")
    if value["count_semantics"] != "runtime_lifecycle_observed":
        raise ValueError("resource_contract count semantics 无效。")
    final = rows[-1]
    if (
        {row["triples_created_delta"] for row in rows} != {value["protocol1_triples_per_step"]}
        or {row["truncations_created_delta"] for row in rows}
        != {value["protocol2_truncations_per_step"]}
        or final["triples_consumed"] != value["protocol1_triples_total"]
        or final["truncations_consumed"] != value["protocol2_truncations_total"]
    ):
        raise ValueError("resource_contract 与实际 lifecycle 记录不一致。")


def _validate_selected_payload(value: Mapping[str, Any]) -> None:
    """验证选定 step 的 schema、哈希、无损整数文本、scale 和状态证据。"""
    required = {
        "schema_version",
        "step",
        "session_id_sha256",
        "round_id_sha256",
        "controller_input",
        "raw_control",
        "decoded_raw_control",
        "resource_id_sha256",
        "resources_before",
        "resources_after",
        "operations",
        "state_transition",
    }
    if set(value) != required or value["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise ValueError("selected step schema 无效。")
    if not _is_sha256(value["session_id_sha256"]) or not _is_sha256(value["round_id_sha256"]):
        raise ValueError("selected step identity hash 无效。")
    hashes = value["resource_id_sha256"]
    if not isinstance(hashes, list) or any(not _is_sha256(item) for item in hashes):
        raise ValueError("resource identity hash 无效。")
    controller_input = _parse_integer_vector(value["controller_input"])
    raw = _parse_integer_vector(value["raw_control"])
    decoded = value["decoded_raw_control"]
    if not isinstance(decoded, list) or len(decoded) != len(raw["centered"]):
        raise ValueError("decoded raw control shape 无效。")
    if any(
        not isinstance(item, (int, float)) or not math.isfinite(float(item)) for item in decoded
    ):
        raise ValueError("decoded raw control 必须为有限数。")
    if any(
        float(item) != centered / (1 << raw["fractional_bits"])
        for item, centered in zip(decoded, raw["centered"], strict=True)
    ):
        raise ValueError("selected centered integer 与 decoded raw control 不一致。")
    resources_before = _parse_resource_snapshot(value["resources_before"])
    resources_after = _parse_resource_snapshot(value["resources_after"])
    operations = value["operations"]
    operation_keys = {"A", "B", "C", "D", "state_truncation", "protocol1_triples"}
    if not isinstance(operations, dict) or set(operations) != operation_keys:
        raise ValueError("selected operations schema 无效。")
    if any(type(operations[name]) is not int or operations[name] < 0 for name in operation_keys):
        raise ValueError("selected operations 必须是非负整数。")
    if operations["protocol1_triples"] != sum(operations[name] for name in "ABCD"):
        raise ValueError("selected Protocol 1 分解与总数不一致。")
    if len(hashes) != operations["protocol1_triples"] + operations["state_truncation"]:
        raise ValueError("selected resource hashes 与实际操作数量不一致。")
    if (
        resources_after["triples_created"] - resources_before["triples_created"]
        != operations["protocol1_triples"]
        or resources_after["triples_consumed"] - resources_before["triples_consumed"]
        != operations["protocol1_triples"]
        or resources_after["truncations_created"] - resources_before["truncations_created"]
        != operations["state_truncation"]
        or resources_after["truncations_consumed"] - resources_before["truncations_consumed"]
        != operations["state_truncation"]
    ):
        raise ValueError("selected resource snapshot 与 operations 不一致。")
    state = value["state_transition"]
    if not isinstance(state, dict) or set(state) != {
        "state_before",
        "controller_input",
        "state_accumulator",
        "state_after",
        "truncation_bits",
        "equation_verified",
    }:
        raise ValueError("state transition schema 无效。")
    before = _parse_integer_vector(state["state_before"])
    state_input = _parse_integer_vector(state["controller_input"])
    accumulator = _parse_integer_vector(state["state_accumulator"])
    after = _parse_integer_vector(state["state_after"])
    if len(before["centered"]) != len(accumulator["centered"]) or len(before["centered"]) != len(
        after["centered"]
    ):
        raise ValueError("state transition shape 不一致。")
    if (
        type(state["truncation_bits"]) is not int
        or state["truncation_bits"] < 0
        or state["equation_verified"] is not True
    ):
        raise ValueError("state transition scale/equation evidence 无效。")
    truncation_bits = state["truncation_bits"]
    if (
        state_input != controller_input
        or before["fractional_bits"] != after["fractional_bits"]
        or accumulator["fractional_bits"] - truncation_bits != after["fractional_bits"]
    ):
        raise ValueError("state transition input/scale 不一致。")
    divisor = 1 << truncation_bits
    expected = tuple((2 * item + divisor) // (2 * divisor) for item in accumulator["centered"])
    tolerance = 0 if truncation_bits == 0 else 1
    if any(
        abs(actual - target) > tolerance
        for actual, target in zip(after["centered"], expected, strict=True)
    ):
        raise ValueError("state transition 整数方程与 Trunc 语义不一致。")


def _parse_resource_snapshot(value: object) -> dict[str, int]:
    """严格读取 selected step 的真实资源累计快照。"""
    keys = {
        "triples_created",
        "triples_consumed",
        "triples_aborted",
        "truncations_created",
        "truncations_consumed",
        "truncations_aborted",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("selected resource snapshot schema 无效。")
    if any(type(value[name]) is not int or value[name] < 0 for name in keys):
        raise ValueError("selected resource snapshot 必须是非负整数。")
    if (
        value["triples_consumed"] + value["triples_aborted"] > value["triples_created"]
        or value["truncations_consumed"] + value["truncations_aborted"]
        > value["truncations_created"]
    ):
        raise ValueError("selected resource snapshot 生命周期无效。")
    return value


def _parse_integer_vector(value: object) -> dict[str, Any]:
    """验证 JSON 中的十进制整数向量与非负分数位数。"""
    if not isinstance(value, dict) or set(value) != {"residue", "centered", "fractional_bits"}:
        raise ValueError("integer vector schema 无效。")
    residue, centered, bits = value["residue"], value["centered"], value["fractional_bits"]
    if (
        not isinstance(residue, list)
        or not isinstance(centered, list)
        or not residue
        or len(residue) != len(centered)
        or type(bits) is not int
        or bits < 0
    ):
        raise ValueError("integer vector shape/scale 无效。")
    return {
        "residue": tuple(_parse_integer(item) for item in residue),
        "centered": tuple(_parse_integer(item) for item in centered),
        "fractional_bits": bits,
    }


def _reject_raw_share_keys(value: object, path: str) -> None:
    """递归拒绝 sanitized JSON 中出现 P1/P2 share 数值字段。"""
    if isinstance(value, dict):
        forbidden = {"input_p1", "input_p2", "output_p1", "output_p2", "state_p1", "state_p2"}
        if forbidden & set(value):
            raise ValueError(f"{path} 不得包含 raw combined-share 字段。")
        for key, item in value.items():
            _reject_raw_share_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_raw_share_keys(item, f"{path}[{index}]")


def _new_trace_id() -> str:
    """生成不可覆盖的 UTC+nonce 诊断标识。"""
    return f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{secrets.token_hex(6)}"


def _float_text(value: object) -> str:
    """以 binary64 round-trip 文本保存有限值。"""
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("evidence 浮点值必须有限。")
    return format(number, ".17g")


def _parse_float(value: object) -> float:
    """读取有限 binary64 数值。"""
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("evidence CSV 含无效浮点值。") from error
    if not math.isfinite(result):
        raise ValueError("evidence CSV 含 NaN/Inf。")
    return result


def _parse_integer(value: object) -> int:
    """只接受 canonical 十进制整数文本，拒绝浮点/指数/前导零。"""
    if isinstance(value, bool):
        raise TypeError("整数文本不能是 bool。")
    text = str(value)
    if not _INTEGER_PATTERN.fullmatch(text):
        raise ValueError("整数必须使用 canonical 十进制文本。")
    return int(text)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    """生成禁止 NaN/Inf 的稳定 UTF-8 JSON。"""
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    """拒绝非对象 JSON 和非标准数值常量。"""
    loaded = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"非标准 JSON 数值：{value}")
        ),
    )
    if not isinstance(loaded, dict):
        raise TypeError(f"{path.name} 必须是 JSON 对象。")
    return loaded


def _write_bytes(path: Path, content: bytes) -> None:
    """独占写入并 fsync 单个 staging 文件。"""
    with path.open("xb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def _digest(path: Path) -> str:
    """返回文件原始 bytes 的 SHA-256。"""
    return sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    """判断值是否为 64 字符小写十六进制 SHA-256。"""
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _validate_path_component(value: object, name: str) -> None:
    """拒绝空值、绝对路径、父目录和任意目录分隔符。"""
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or Path(value).name != value
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{name} 必须是安全的单级目录名。")


def _safe_member(root: Path, name: str) -> Path:
    """拒绝绝对路径、目录逃逸和 symlink 成员。"""
    candidate = root / name
    if (
        Path(name).name != name
        or candidate.is_symlink()
        or candidate.resolve().parent != root.resolve()
    ):
        raise ValueError("evidence manifest 成员路径不安全。")
    if not candidate.is_file():
        raise FileNotFoundError(candidate)
    return candidate


def _owned_stage(stage: Path, parent: Path, identity: int) -> bool:
    """异常时只清理由本调用创建的直属 staging。"""
    try:
        return (
            stage.resolve().parent == parent.resolve()
            and stage.name.startswith(".incomplete-")
            and not stage.is_symlink()
            and stage.stat(follow_symlinks=False).st_ino == identity
        )
    except OSError:
        return False
