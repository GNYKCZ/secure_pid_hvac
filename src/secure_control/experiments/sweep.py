"""领域无关的定点精度扫描定义、点配置物化与预检数据契约。"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from .sweep_metrics import ErrorMetrics


class SweepRunStatus(str, Enum):
    """单个扫描点的最终状态。"""

    SUCCESS = "success"
    INFEASIBLE = "infeasible"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SweepPointDefinition:
    """冻结一个 ``(ell, k, lambda, q, kappa, seed)`` 扫描点。"""

    ell: int
    k: int
    lambda_: int
    q: int
    kappa: int
    seed: int

    @property
    def point_id(self) -> str:
        """返回不含机器路径的稳定点标识。"""
        return f"ell-{self.ell}-seed-{self.seed}"


@dataclass(frozen=True, slots=True)
class PrecisionSweepDefinition:
    """保存正式扫描的来源、哈希、参数网格与执行约束。"""

    scenario_id: str
    source_config: Path
    source_hashes: Mapping[str, str]
    stability_report_hash: str
    prime_evidence_path: Path
    prime_evidence_hash: str
    fractional_bits: tuple[int, ...]
    integer_headroom_bits: int
    security_parameter: int
    seeds: tuple[int, ...]
    primary_seed: int
    allowed_variable_fields: tuple[str, ...]
    timeout_seconds: int
    max_protocol1_triples_per_point: int
    max_protocol2_truncations_per_point: int
    max_certified_integer_bit_length: int
    max_artifact_bytes: int
    q: int
    modulus_evidence: Mapping[str, Any]

    @property
    def points(self) -> tuple[SweepPointDefinition, ...]:
        """按 ell 外层、seed 内层生成固定交错执行顺序。"""
        kappa = self.q.bit_length() - self.security_parameter - 2
        return tuple(
            SweepPointDefinition(
                ell,
                ell + self.integer_headroom_bits,
                self.security_parameter,
                self.q,
                kappa,
                seed,
            )
            for ell in self.fractional_bits
            for seed in self.seeds
        )


@dataclass(frozen=True, slots=True)
class RangeMargin:
    """保存一个已证明整数界到其适用上限的剩余余量。"""

    name: str
    certified_abs_bound: int
    centered_modulus_limit: int
    remaining_margin: int
    utilization: float


@dataclass(frozen=True, slots=True)
class PrecisionPreflightReport:
    """记录运行前稳定性、证据、冻结字段和全部范围门禁。"""

    stability_passed: bool
    prime_evidence_passed: bool
    frozen_fields_passed: bool
    ranges: tuple[RangeMargin, ...]
    feasible: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProtocolCostReport:
    """记录从实际 shape/ledger 精确推导的协议资源和计时口径。"""

    protocol1_triples_per_step: int
    protocol1_triples_total: int
    protocol2_truncations_per_step: int
    protocol2_truncations_total: int
    q_bit_length: int
    max_certified_integer_bit_length: int
    wall_clock_seconds: float
    timing_scope: str
    resource_count_kind: str = "derived_exact"


@dataclass(frozen=True, slots=True)
class SweepRunRecord:
    """保存一个点的状态、指标、资源成本和对应原始工件。"""

    point: SweepPointDefinition
    status: SweepRunStatus
    preflight: PrecisionPreflightReport
    output_error: ErrorMetrics | None
    control_error: ErrorMetrics | None
    scenario_metrics: Mapping[str, Any] | None
    cost: ProtocolCostReport | None
    artifact_path: str | None
    failure_code: str | None
    failure_message: str | None


@dataclass(frozen=True, slots=True)
class SweepArtifacts:
    """返回已发布扫描的标识、根目录、清单、摘要和逐点记录。"""

    sweep_id: str
    root: Path
    manifest_path: Path
    summary_path: Path
    records: tuple[SweepRunRecord, ...]


def canonical_file_sha256(path: str | Path) -> str:
    """按 UTF-8/LF 规范化文本求摘要，避免 checkout 换行差异改变定义。"""
    source = Path(path).read_bytes().replace(b"\r\n", b"\n")
    return sha256(source).hexdigest()


def _integer_sequence(value: object, name: str) -> tuple[int, ...]:
    """读取非空、无重复且不接受布尔值的正整数序列。"""
    if not isinstance(value, list) or not value:
        raise TypeError(f"{name} 必须是非空整数数组")
    result = tuple(value)
    if any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in result):
        raise ValueError(f"{name} 必须只包含正整数")
    if len(set(result)) != len(result):
        raise ValueError(f"{name} 不得包含重复值")
    return result


def load_precision_sweep_definition(path: str | Path) -> PrecisionSweepDefinition:
    """严格读取扫描定义和独立素数证据，并冻结全部十二个点。"""
    definition_path = Path(path).resolve()
    try:
        loaded = yaml.safe_load(definition_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError("无法读取 precision sweep 定义") from error
    if not isinstance(loaded, Mapping):
        raise TypeError("precision sweep 根节点必须是映射")
    required = {
        "schema_version",
        "scenario_id",
        "source_config",
        "source_hashes",
        "stability_report_hash",
        "prime_evidence_path",
        "prime_evidence_hash",
        "fractional_bits",
        "integer_headroom_bits",
        "security_parameter",
        "seeds",
        "primary_seed",
        "allowed_variable_fields",
        "timeout_seconds",
        "max_protocol1_triples_per_point",
        "max_protocol2_truncations_per_point",
        "max_certified_integer_bit_length",
        "max_artifact_bytes",
    }
    if set(loaded) != required or loaded["schema_version"] != 1:
        raise ValueError("precision sweep 字段或 schema_version 无效")
    source_config = (definition_path.parent / str(loaded["source_config"])).resolve()
    evidence_path = (definition_path.parent / str(loaded["prime_evidence_path"])).resolve()
    try:
        prime = yaml.safe_load(evidence_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError("无法读取 sweep prime 证据") from error
    if not isinstance(prime, Mapping) or set(prime) != {"modulus", "evidence"}:
        raise ValueError("sweep prime 证据字段无效")
    q = prime["modulus"]
    if isinstance(q, bool) or not isinstance(q, int) or q.bit_length() != 256:
        raise ValueError("sweep modulus 必须是 256-bit 整数")
    evidence = prime["evidence"]
    if not isinstance(evidence, Mapping):
        raise TypeError("sweep modulus evidence 必须是映射")
    fractional_bits = _integer_sequence(loaded["fractional_bits"], "fractional_bits")
    seeds = _integer_sequence(loaded["seeds"], "seeds")
    primary_seed = loaded["primary_seed"]
    if primary_seed not in seeds:
        raise ValueError("primary_seed 必须属于 seeds")
    headroom = loaded["integer_headroom_bits"]
    security_parameter = loaded["security_parameter"]
    timeout = loaded["timeout_seconds"]
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item <= 0
        for item in (headroom, security_parameter, timeout)
    ):
        raise ValueError("headroom、security parameter 和 timeout 必须是正整数")
    resource_limits = (
        loaded["max_protocol1_triples_per_point"],
        loaded["max_protocol2_truncations_per_point"],
        loaded["max_certified_integer_bit_length"],
        loaded["max_artifact_bytes"],
    )
    if any(isinstance(item, bool) or not isinstance(item, int) for item in resource_limits):
        raise TypeError("resource limits 必须是整数")
    if (
        resource_limits[0] <= 0
        or resource_limits[1] < 0
        or any(item <= 0 for item in resource_limits[2:])
    ):
        raise ValueError("resource limits 必须满足正值约束")
    hashes = loaded["source_hashes"]
    if not isinstance(hashes, Mapping) or set(hashes) != {"wrapper", "baseline", "plant"}:
        raise ValueError("source_hashes 必须冻结 wrapper/baseline/plant")
    allowed = loaded["allowed_variable_fields"]
    if not isinstance(allowed, list) or not allowed or any(not isinstance(x, str) for x in allowed):
        raise TypeError("allowed_variable_fields 必须是非空字符串数组")
    expected_allowed = (
        "security.modulus",
        "security.integer_bits",
        "security.fractional_bits",
        "security.security_parameter",
        "security.modulus_evidence",
    )
    if tuple(allowed) != expected_allowed:
        raise ValueError("allowed_variable_fields 不得扩大冻结扫描变量集合")
    return PrecisionSweepDefinition(
        scenario_id=str(loaded["scenario_id"]),
        source_config=source_config,
        source_hashes={str(key): str(value) for key, value in hashes.items()},
        stability_report_hash=str(loaded["stability_report_hash"]),
        prime_evidence_path=evidence_path,
        prime_evidence_hash=str(loaded["prime_evidence_hash"]),
        fractional_bits=fractional_bits,
        integer_headroom_bits=headroom,
        security_parameter=security_parameter,
        seeds=seeds,
        primary_seed=primary_seed,
        allowed_variable_fields=expected_allowed,
        timeout_seconds=timeout,
        max_protocol1_triples_per_point=resource_limits[0],
        max_protocol2_truncations_per_point=resource_limits[1],
        max_certified_integer_bit_length=resource_limits[2],
        max_artifact_bytes=resource_limits[3],
        q=q,
        modulus_evidence=dict(evidence),
    )


def materialize_point_config(
    definition: PrecisionSweepDefinition,
    point: SweepPointDefinition,
    output_path: str | Path,
) -> Path:
    """由唯一 wrapper 物化一个点，仅改写设计许可的 security 字段。"""
    if point not in definition.points:
        raise ValueError("point 不属于当前冻结扫描定义")
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    loaded = yaml.safe_load(definition.source_config.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("security"), dict):
        raise TypeError("source wrapper 缺少 security 映射")
    baseline = loaded.get("baseline_config")
    if not isinstance(baseline, str):
        raise TypeError("source wrapper baseline_config 无效")
    baseline_path = (definition.source_config.parent / baseline).resolve()
    loaded["baseline_config"] = Path(
        os.path.relpath(baseline_path, start=target.parent.resolve())
    ).as_posix()
    security = loaded["security"]
    security.update(
        {
            "modulus": point.q,
            "integer_bits": point.k,
            "fractional_bits": point.ell,
            "security_parameter": point.lambda_,
            "modulus_evidence": dict(definition.modulus_evidence),
        }
    )
    target.write_text(
        yaml.safe_dump(loaded, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )
    return target
