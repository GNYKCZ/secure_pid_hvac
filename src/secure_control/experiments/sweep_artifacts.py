"""领域无关的扫描 JSON/CSV 工件序列化、摘要和完整性清单。"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Any

from .sweep import PrecisionSweepDefinition, SweepRunRecord


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


def write_summary(path: Path, records: tuple[SweepRunRecord, ...]) -> None:
    """把全部点（含失败/不可行）写入一张稳定列顺序的 CSV。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as target:
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
                    "protocol1_triples_total": (
                        "" if cost is None else cost.protocol1_triples_total
                    ),
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


def write_definition(path: Path, definition: PrecisionSweepDefinition) -> None:
    """保存不泄露绝对路径的冻结扫描定义快照。"""
    payload = _jsonable(definition)
    payload["source_config"] = definition.source_config.name
    payload["prime_evidence_path"] = definition.prime_evidence_path.name
    payload["points"] = [_jsonable(point) for point in definition.points]
    write_json(path, payload)


def write_manifest(
    path: Path,
    *,
    sweep_id: str,
    definition: PrecisionSweepDefinition,
    records: tuple[SweepRunRecord, ...],
) -> None:
    """对已写入的正式文件生成递归 SHA-256 清单。"""
    root = path.parent
    files = {
        item.relative_to(root).as_posix(): sha256(item.read_bytes()).hexdigest()
        for item in sorted(root.rglob("*"))
        if item.is_file() and item != path
    }
    write_json(
        path,
        {
            "schema_version": 1,
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
