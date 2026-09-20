"""领域无关的扫描 JSON/CSV 工件序列化、摘要和完整性清单。"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from secure_control.experiments.artifacts import ExperimentRecord, load_artifacts

from .sweep import (
    PrecisionPreflightReport,
    PrecisionSweepDefinition,
    ProtocolCostReport,
    RangeMargin,
    ResolvedBaselineSource,
    ResolvedPrecisionSweepPlan,
    ReusablePrecisionSweepDefinition,
    SweepPointDefinition,
    SweepRunRecord,
    SweepRunStatus,
    reusable_definition_from_snapshot,
)
from .sweep_metrics import ErrorMetrics, aggregate_error_metrics

SWEEP_SCHEMA_VERSION = 2


def _is_sha256(value: object) -> bool:
    """判断值是否为小写十六进制 SHA-256。"""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class VerifiedSweepData:
    """保存经清单、摘要和单次运行 reader 共同复验的扫描数据。"""

    root: Path
    definition: dict[str, Any]
    records: tuple[SweepRunRecord, ...]
    runs: dict[str, ExperimentRecord]
    resolved_source: dict[str, Any] | None = None
    resolved_plan: dict[str, Any] | None = None


def _jsonable(value: Any) -> Any:
    """把 dataclass、枚举、Path 和 tuple 转换为标准 JSON 载荷。"""
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    if isinstance(value, Path):
        return value.name
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def write_json(path: Path, value: Any) -> None:
    """写入禁止 NaN/Infinity 的稳定 UTF-8 JSON。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_jsonable(value), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def record_payload(record: SweepRunRecord) -> dict[str, Any]:
    """返回单点正式 JSON 载荷。"""
    return _jsonable(record)


def preflight_from_payload(payload: object) -> PrecisionPreflightReport:
    """恢复 preflight checkpoint，并保留 ``null`` 表示尚未获得的结论。"""
    if not isinstance(payload, dict) or set(payload) != {
        "stability_passed",
        "prime_evidence_passed",
        "frozen_fields_passed",
        "ranges",
        "feasible",
        "reason_codes",
    }:
        raise ValueError("preflight checkpoint 字段无效")

    def optional_bool(value: object, name: str) -> bool | None:
        """拒绝用 truthiness 把畸形值或 unknown 静默改写为布尔值。"""
        if value is None or type(value) is bool:
            return value
        raise TypeError(f"{name} 必须是 bool 或 null")

    ranges = payload["ranges"]
    reasons = payload["reason_codes"]
    if not isinstance(ranges, list):
        raise TypeError("preflight.ranges 必须是数组")
    if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
        raise TypeError("preflight.reason_codes 必须是字符串数组")
    return PrecisionPreflightReport(
        optional_bool(payload["stability_passed"], "stability_passed"),
        optional_bool(payload["prime_evidence_passed"], "prime_evidence_passed"),
        optional_bool(payload["frozen_fields_passed"], "frozen_fields_passed"),
        tuple(RangeMargin(**item) for item in ranges),
        optional_bool(payload["feasible"], "feasible"),
        tuple(reasons),
    )


def record_from_payload(payload: object) -> SweepRunRecord:
    """从严格 JSON 对象恢复单点记录，拒绝额外字段和错型状态。"""
    if not isinstance(payload, dict):
        raise TypeError("point record 必须是 JSON 对象")
    expected = {
        "point",
        "status",
        "preflight",
        "output_error",
        "control_error",
        "scenario_metrics",
        "cost",
        "artifact_path",
        "failure_code",
        "failure_message",
    }
    if set(payload) != expected:
        raise ValueError("point record 字段无效")
    point_payload = payload["point"]
    preflight_payload = payload["preflight"]
    if not isinstance(point_payload, dict) or set(point_payload) != {
        "ell",
        "k",
        "lambda_",
        "q",
        "kappa",
        "seed",
    }:
        raise ValueError("point record 的 point 无效")
    preflight = preflight_from_payload(preflight_payload)

    def error_metrics(value: object) -> ErrorMetrics | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise TypeError("error metrics 必须是对象或 null")
        return ErrorMetrics(**value)

    cost_payload = payload["cost"]
    cost = None if cost_payload is None else ProtocolCostReport(**cost_payload)
    return SweepRunRecord(
        SweepPointDefinition(**point_payload),
        SweepRunStatus(payload["status"]),
        preflight,
        error_metrics(payload["output_error"]),
        error_metrics(payload["control_error"]),
        payload["scenario_metrics"],
        cost,
        payload["artifact_path"],
        payload["failure_code"],
        payload["failure_message"],
    )


_SUMMARY_FIELDS = (
    "ell",
    "k",
    "lambda",
    "q_bit_length",
    "kappa",
    "seed",
    "status",
    "control_max_abs",
    "control_mean_abs",
    "control_rms",
    "control_zero_count",
    "control_minimum_positive_abs",
    "output_max_abs",
    "output_mean_abs",
    "output_rms",
    "output_zero_count",
    "output_minimum_positive_abs",
    "wall_clock_seconds",
    "protocol1_triples_total",
    "protocol2_truncations_total",
    "max_certified_integer_bit_length",
    "artifact_path",
    "failure_code",
)


def _summary_text(records: tuple[SweepRunRecord, ...]) -> str:
    """生成可直接重导和逐字节复验的 compact CSV。"""
    target = io.StringIO(newline="")
    writer = csv.DictWriter(target, fieldnames=_SUMMARY_FIELDS)
    writer.writeheader()
    for record in records:
        control, output, cost = record.control_error, record.output_error, record.cost
        writer.writerow(
            {
                "ell": record.point.ell,
                "k": record.point.k,
                "lambda": record.point.lambda_,
                "q_bit_length": record.point.q.bit_length(),
                "kappa": record.point.kappa,
                "seed": record.point.seed,
                "status": record.status.value,
                "control_max_abs": "" if control is None else control.max_abs,
                "control_mean_abs": "" if control is None else control.mean_abs,
                "control_rms": "" if control is None else control.rms,
                "control_zero_count": "" if control is None else control.zero_count,
                "control_minimum_positive_abs": (
                    "" if control is None else control.minimum_positive_abs
                ),
                "output_max_abs": "" if output is None else output.max_abs,
                "output_mean_abs": "" if output is None else output.mean_abs,
                "output_rms": "" if output is None else output.rms,
                "output_zero_count": "" if output is None else output.zero_count,
                "output_minimum_positive_abs": (
                    "" if output is None else output.minimum_positive_abs
                ),
                "wall_clock_seconds": "" if cost is None else cost.wall_clock_seconds,
                "protocol1_triples_total": ("" if cost is None else cost.protocol1_triples_total),
                "protocol2_truncations_total": (
                    "" if cost is None else cost.protocol2_truncations_total
                ),
                "max_certified_integer_bit_length": (
                    "" if cost is None else cost.max_certified_integer_bit_length
                ),
                "artifact_path": record.artifact_path or "",
                "failure_code": record.failure_code or "",
            }
        )
    return target.getvalue()


def write_summary(path: Path, records: tuple[SweepRunRecord, ...]) -> None:
    """把全部点（含失败/不可行）写入一张稳定列顺序的 CSV。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_summary_text(records), encoding="utf-8", newline="")


def _range_margins_text(records: tuple[SweepRunRecord, ...]) -> str:
    """生成可直接重导和逐字节复验的范围余量 CSV。"""
    fields = (
        "ell",
        "seed",
        "name",
        "certified_abs_bound",
        "centered_modulus_limit",
        "remaining_margin",
        "utilization",
    )
    target = io.StringIO(newline="")
    writer = csv.DictWriter(target, fieldnames=fields)
    writer.writeheader()
    for record in records:
        for margin in record.preflight.ranges:
            writer.writerow(
                {
                    "ell": record.point.ell,
                    "seed": record.point.seed,
                    **asdict(margin),
                }
            )
    return target.getvalue()


def write_range_margins(path: Path, records: tuple[SweepRunRecord, ...]) -> None:
    """逐点逐范围保存认证界、上限、余量和使用率。"""
    path.write_text(_range_margins_text(records), encoding="utf-8", newline="")


def build_summary_payload(
    records: tuple[SweepRunRecord, ...],
    stability: dict[str, Any],
    claim_boundary: str = (
        "Adapted application precision sweep; it does not reproduce the paper's exact plant, "
        "closed-loop tuning, or Protocol 2 runtime path."
    ),
) -> dict[str, Any]:
    """构造既含完整逐点记录又含通用按精度聚合的无损摘要。"""
    by_ell: dict[str, Any] = {}
    for ell in sorted({record.point.ell for record in records}):
        selected = [
            record
            for record in records
            if record.point.ell == ell and record.status is SweepRunStatus.SUCCESS
        ]
        by_ell[str(ell)] = {
            "success_count": len(selected),
            "control_error": (
                None
                if not selected
                else aggregate_error_metrics([record.control_error for record in selected])
            ),
            "output_error": (
                None
                if not selected
                else aggregate_error_metrics([record.output_error for record in selected])
            ),
        }
    return {
        "records": [record_payload(record) for record in records],
        "by_fractional_bits": by_ell,
        "stability": stability,
        "claim_boundary": claim_boundary,
    }


def write_definition(
    path: Path, definition: PrecisionSweepDefinition | ReusablePrecisionSweepDefinition
) -> None:
    """保存不泄露绝对路径的冻结扫描定义快照。"""
    payload = _jsonable(definition)
    if isinstance(definition, PrecisionSweepDefinition):
        payload["source_config"] = definition.source_config.name
    else:
        payload.pop("definition_path", None)
        payload["schema_version"] = 2
    payload["prime_evidence_path"] = definition.prime_evidence_path.name
    payload["points"] = [_jsonable(point) for point in definition.points]
    write_json(path, payload)


def write_resolved_source(path: Path, source: ResolvedBaselineSource) -> None:
    """保存不含绝对路径的已验证 baseline 身份与来源摘要。"""
    payload = _jsonable(source)
    payload["config_path"] = source.config_path.name
    payload["schema_version"] = 1
    write_json(path, payload)


def write_resolved_plan(path: Path, plan: ResolvedPrecisionSweepPlan) -> None:
    """保存 definition+source 后的真实稳定性、点矩阵与运行 provenance。"""
    write_json(
        path,
        {
            "schema_version": 1,
            "definition_schema_version": plan.provenance.get("definition_schema_version"),
            "definition_sha256": plan.provenance.get("definition_source_sha256"),
            "baseline_identity_scheme": plan.source.identity_scheme,
            "baseline_id": plan.source.baseline_id,
            "stability_report": plan.stability_report,
            "stability_report_sha256": plan.stability_report_sha256,
            "prime_evidence_passed": plan.prime_evidence_passed,
            "points": plan.points,
            "provenance": plan.provenance,
        },
    )


def write_manifest(
    path: Path,
    *,
    sweep_id: str,
    definition: PrecisionSweepDefinition | ReusablePrecisionSweepDefinition,
    records: tuple[SweepRunRecord, ...],
) -> None:
    """对已写入的正式文件生成递归 SHA-256 最终清单。"""
    root = path.parent
    files = {
        item.relative_to(root).as_posix(): sha256(item.read_bytes()).hexdigest()
        for item in sorted(root.rglob("*"))
        if item.is_file() and item != path
    }
    write_json(
        path,
        {
            "schema_version": SWEEP_SCHEMA_VERSION,
            "manifest_kind": "final",
            "sweep_id": sweep_id,
            "scenario_id": definition.scenario_id,
            "point_count": len(records),
            "status_counts": {
                status: sum(record.status.value == status for record in records)
                for status in ("success", "infeasible", "failed")
            },
            "complete": len(records) == len(definition.points),
            "files_sha256": files,
        },
    )


def write_data_manifest(
    path: Path,
    *,
    sweep_id: str,
    definition: PrecisionSweepDefinition | ReusablePrecisionSweepDefinition,
    records: tuple[SweepRunRecord, ...],
) -> None:
    """在绘图前冻结定义、记录、摘要和原始运行的权威闭包。"""
    root = path.parent
    files = {
        item.relative_to(root).as_posix(): sha256(item.read_bytes()).hexdigest()
        for item in sorted(root.rglob("*"))
        if item.is_file()
        and item != path
        and not item.relative_to(root).parts[0] in {"figures", "standard", "work"}
        and item.name != "manifest.json"
    }
    write_json(
        path,
        {
            "schema_version": SWEEP_SCHEMA_VERSION,
            "manifest_kind": "data",
            "sweep_id": sweep_id,
            "scenario_id": definition.scenario_id,
            "point_count": len(records),
            "status_counts": {
                status: sum(record.status.value == status for record in records)
                for status in ("success", "infeasible", "failed")
            },
            "complete": len(records) == len(definition.points),
            "files_sha256": files,
        },
    )


def _safe_member(root: Path, relative: str) -> Path:
    """把清单相对路径约束在根目录内，并拒绝符号链接逃逸。"""
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("manifest 路径逃逸")
    unresolved = root / candidate
    resolved = unresolved.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("manifest 路径逃逸") from error
    if unresolved.is_symlink() or any(
        item.is_symlink() for item in unresolved.parents if item != root.parent
    ):
        raise ValueError("manifest 不允许符号链接")
    return resolved


def _read_json_object(path: Path) -> dict[str, Any]:
    """读取只含标准有限数值的 JSON 对象。"""

    def reject(value: str) -> None:
        raise ValueError(f"非标准 JSON 数值：{value}")

    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=reject)
    if not isinstance(value, dict):
        raise TypeError(f"{path.name} 必须是 JSON 对象")
    return value


def load_verified_sweep_data(
    root: str | Path, *, manifest_name: str = "manifest.json"
) -> VerifiedSweepData:
    """按两阶段清单复验扫描闭包、摘要可重导性与每个成功运行。"""
    sweep_root = Path(root).resolve()
    manifest_path = sweep_root / manifest_name
    manifest = _read_json_object(manifest_path)
    expected_kind = "data" if manifest_name == "data_manifest.json" else "final"
    if (
        manifest.get("schema_version") != SWEEP_SCHEMA_VERSION
        or manifest.get("manifest_kind") != expected_kind
        or manifest.get("complete") is not True
    ):
        raise ValueError("sweep manifest schema、类型或完成状态无效")
    hashes = manifest.get("files_sha256")
    if not isinstance(hashes, dict) or any(
        not isinstance(name, str) or not isinstance(digest, str) for name, digest in hashes.items()
    ):
        raise ValueError("manifest SHA-256 映射无效")
    excluded = {manifest_name}
    if expected_kind == "data":
        excluded |= {"manifest.json"}
    actual_files = {
        item.relative_to(sweep_root).as_posix()
        for item in sweep_root.rglob("*")
        if item.is_file()
        and item.relative_to(sweep_root).as_posix() not in excluded
        and not (
            expected_kind == "data"
            and item.relative_to(sweep_root).parts[0] in {"figures", "standard", "work"}
        )
    }
    if actual_files != set(hashes):
        raise ValueError("manifest 存在缺失或额外的权威文件")
    for relative, digest in hashes.items():
        member = _safe_member(sweep_root, relative)
        if not member.is_file() or sha256(member.read_bytes()).hexdigest() != digest:
            raise ValueError(f"manifest SHA-256 不匹配：{relative}")

    definition = _read_json_object(sweep_root / "definition.json")
    if definition.get("schema_version") == 2:
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
        if forbidden.intersection(definition):
            raise ValueError("v2 definition 包含具体 source/artifact identity")
        reusable_definition_from_snapshot(definition)
    point_payloads = definition.get("points")
    if not isinstance(point_payloads, list):
        raise TypeError("definition points 缺失")
    expected_points = {SweepPointDefinition(**item) for item in point_payloads}
    record_paths = sorted((sweep_root / "points").glob("*/record.json"))
    records = tuple(record_from_payload(_read_json_object(path)) for path in record_paths)
    if (
        len(records) != len(expected_points)
        or {record.point for record in records} != expected_points
    ):
        raise ValueError("point records 与冻结 definition 不完整或重复")
    counts = {
        status: sum(record.status.value == status for record in records)
        for status in ("success", "infeasible", "failed")
    }
    if manifest.get("point_count") != len(records) or manifest.get("status_counts") != counts:
        raise ValueError("manifest 点数或状态计数不可重导")
    summary = _read_json_object(sweep_root / "summary.json")
    if summary.get("records") != [record_payload(record) for record in records]:
        raise ValueError("summary.json 逐点记录不可重导")
    claim_boundary = summary.get("claim_boundary")
    if not isinstance(claim_boundary, str) or not claim_boundary:
        raise ValueError("summary.json claim boundary 无效")
    rebuilt = build_summary_payload(records, summary.get("stability"), claim_boundary)
    if summary != rebuilt:
        raise ValueError("summary.json 聚合不可重导")
    with (sweep_root / "summary.csv").open(encoding="utf-8", newline="") as source:
        summary_csv = source.read()
    if summary_csv != _summary_text(records):
        raise ValueError("summary.csv 不可从 point records 重导")
    with (sweep_root / "range_margins.csv").open(encoding="utf-8", newline="") as source:
        range_csv = source.read()
    if range_csv != _range_margins_text(records):
        raise ValueError("range_margins.csv 不可从 point records 重导")
    runs: dict[str, ExperimentRecord] = {}
    for record in records:
        if record.status is SweepRunStatus.SUCCESS:
            if not isinstance(record.artifact_path, str):
                raise ValueError("成功点缺少 artifact_path")
            path = _safe_member(sweep_root, record.artifact_path)
            if record.point.point_id in runs:
                raise ValueError("成功点 artifact 重复")
            runs[record.point.point_id] = load_artifacts(path)
    source_path = sweep_root / "resolved_source.json"
    plan_path = sweep_root / "resolved_plan.json"
    if source_path.is_file() != plan_path.is_file():
        raise ValueError("resolved source/plan 必须成对出现")
    resolved_source = _read_json_object(source_path) if source_path.is_file() else None
    resolved_plan = _read_json_object(plan_path) if plan_path.is_file() else None
    if definition.get("schema_version") == 2 and (resolved_source is None or resolved_plan is None):
        raise ValueError("schema v2 sweep 缺少 resolved source/plan")
    if resolved_source is not None and resolved_plan is not None:
        source_fields = {
            "schema_version",
            "config_path",
            "identity_scheme",
            "baseline_id",
            "source_hashes",
            "effective_config_sha256",
            "finite_horizon_certificate_sha256",
        }
        plan_fields = {
            "schema_version",
            "definition_schema_version",
            "definition_sha256",
            "baseline_identity_scheme",
            "baseline_id",
            "stability_report",
            "stability_report_sha256",
            "prime_evidence_passed",
            "points",
            "provenance",
        }
        config_name = resolved_source.get("config_path")
        source_hashes = resolved_source.get("source_hashes")
        digests = (
            resolved_source.get("baseline_id"),
            resolved_source.get("effective_config_sha256"),
            resolved_source.get("finite_horizon_certificate_sha256"),
            resolved_plan.get("definition_sha256"),
            resolved_plan.get("stability_report_sha256"),
        )
        if (
            set(resolved_source) != source_fields
            or set(resolved_plan) != plan_fields
            or resolved_source.get("schema_version") != 1
            or not isinstance(config_name, str)
            or Path(config_name).name != config_name
            or resolved_plan.get("schema_version") != 1
            or not isinstance(source_hashes, dict)
            or set(source_hashes) != {"wrapper", "baseline", "scenario"}
            or not all(_is_sha256(value) for value in (*digests, *source_hashes.values()))
            or resolved_plan.get("definition_schema_version")
            != (2 if definition.get("schema_version") == 2 else 1)
            or resolved_plan.get("baseline_identity_scheme")
            != resolved_source.get("identity_scheme")
            or resolved_plan.get("baseline_id") != resolved_source.get("baseline_id")
            or resolved_plan.get("points") != point_payloads
            or resolved_plan.get("prime_evidence_passed") is not True
        ):
            raise ValueError("resolved source/plan identity 或点矩阵不一致")
    return VerifiedSweepData(
        sweep_root,
        definition,
        records,
        runs,
        resolved_source,
        resolved_plan,
    )
