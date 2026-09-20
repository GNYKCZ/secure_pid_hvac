"""Issue #15 的 2R2C 扫描 composition root、预检、执行和原子发布。"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from typing import Any

import yaml

from secure_control.experiments.artifacts import load_artifacts
from secure_control.experiments.plotting import PlotDisplay, PlotSelection, render_saved_run
from secure_control.experiments.provenance import collect_provenance
from secure_control.scenarios.hvac.integration import HvacSafetyCertificate, HvacScenario
from secure_control.scenarios.hvac.migration import canonical_hvac_mapping_sha256
from secure_control.scenarios.hvac.stability import analyze_hvac_closed_loop_stability

from .sweep import (
    BaselineSourceRequest,
    PrecisionPreflightReport,
    PrecisionSweepDefinition,
    ProtocolCostReport,
    RangeMargin,
    ResolvedBaselineSource,
    ResolvedPrecisionSweepPlan,
    ReusablePrecisionSweepDefinition,
    SweepArtifacts,
    SweepPointDefinition,
    SweepRunRecord,
    SweepRunStatus,
    canonical_file_sha256,
    canonical_mapping_sha256,
    load_precision_sweep_definition,
    materialize_point_config,
)
from .sweep_artifacts import (
    build_summary_payload,
    load_verified_sweep_data,
    preflight_from_payload,
    record_from_payload,
    write_data_manifest,
    write_definition,
    write_json,
    write_manifest,
    write_range_margins,
    write_resolved_plan,
    write_resolved_source,
    write_summary,
)
from .sweep_plotting import render_sweep_figures


@dataclass(frozen=True, slots=True)
class _ChildResult:
    """保存一个直接子进程的有界输出、退出状态和 deadline 结果。"""

    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str
    elapsed_seconds: float = 0.0


def _bounded_text(value: str | bytes | None, limit: int = 4096) -> str:
    """把 worker 输出统一为 UTF-8 文本并保留有界尾部诊断。"""
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text[-limit:]


def _run_child(command: list[str], *, timeout_seconds: int) -> _ChildResult:
    """以 shell=False 运行一个直接子进程，deadline 后杀死并完成回收。"""
    started = perf_counter()
    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return _ChildResult(
            None,
            True,
            _bounded_text(error.stdout),
            _bounded_text(error.stderr),
            perf_counter() - started,
        )
    return _ChildResult(
        completed.returncode,
        False,
        _bounded_text(completed.stdout),
        _bounded_text(completed.stderr),
        perf_counter() - started,
    )


def _safe_source_member(parent: Path, value: object, name: str) -> Path:
    """只接受同目录普通文件名，拒绝路径逃逸、链接和 reparse source。"""
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise ValueError(f"{name} 必须是同目录安全文件名")
    member = parent / value
    if not member.is_file() or member.is_symlink():
        raise ValueError(f"{name} 必须是存在的普通非链接文件")
    return member.resolve()


def _source_paths_from_config(config_path: Path) -> tuple[Path, Path, Path]:
    """解析 wrapper、PID baseline 和 scenario，并限制配置链不能逃逸目录。"""
    requested_path = Path(config_path)
    # 必须在 canonicalize 前检查 leaf 和祖先；resolve() 会折叠链接并丢失调用者选择的 path authority。
    if (
        not requested_path.is_file()
        or requested_path.is_symlink()
        or any(parent.is_symlink() for parent in requested_path.parents)
    ):
        raise ValueError("baseline_config 必须是存在的普通非链接文件")
    wrapper_path = requested_path.resolve()
    wrapper = yaml.safe_load(wrapper_path.read_text(encoding="utf-8"))
    if not isinstance(wrapper, Mapping):
        raise TypeError("baseline wrapper 根节点必须是映射")
    baseline = _safe_source_member(
        wrapper_path.parent, wrapper.get("baseline_config"), "baseline_config"
    )
    baseline_data = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    if not isinstance(baseline_data, Mapping):
        raise TypeError("PID baseline 根节点必须是映射")
    plant = _safe_source_member(baseline.parent, baseline_data.get("plant_config"), "plant_config")
    return wrapper_path, baseline, plant


def _source_paths(definition: PrecisionSweepDefinition) -> tuple[Path, Path, Path]:
    """解析历史 v1 definition 内嵌的配置链。"""
    return _source_paths_from_config(definition.source_config)


def stability_report_sha256(plant_path: Path, pid_path: Path) -> tuple[str, dict[str, Any]]:
    """规范化来源摘要后计算跨 checkout 换行稳定的稳定性报告哈希。"""
    report = analyze_hvac_closed_loop_stability(plant_path, pid_path)
    payload = asdict(report)
    payload["plant_source_sha256"] = canonical_file_sha256(plant_path)
    payload["pid_source_sha256"] = canonical_file_sha256(pid_path)
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    # resolved_plan 经 JSON reader 恢复后，tuple 会成为 list；这里直接返回同一规范形态，
    # 避免 evidence 重放把等价的持久化载荷误判为 provenance 漂移。
    canonical_payload = json.loads(serialized)
    return sha256(serialized).hexdigest(), canonical_payload


def resolve_hvac_baseline_source(
    request: BaselineSourceRequest,
    requirements: Mapping[str, object],
) -> ResolvedBaselineSource:
    """验证显式 HVAC baseline 身份与兼容 contract，不依赖具体文件名或 ID。"""
    if not isinstance(request, BaselineSourceRequest):
        raise TypeError("source request 必须是 BaselineSourceRequest")
    if not re.fullmatch(r"[0-9a-f]{64}", request.expected_baseline_id):
        raise ValueError("expected_baseline_id 必须是小写 SHA-256")
    required_keys = {
        "scenario_name",
        "scenario_version",
        "model_kind",
        "sample_count",
        "horizon_steps",
        "controller_dimensions",
        "channel_dimensions",
        "allowed_security_override_fields",
    }
    if not isinstance(requirements, Mapping) or set(requirements) != required_keys:
        raise ValueError("source_requirements 字段无效")
    wrapper, baseline, scenario_path = _source_paths_from_config(request.config_path)
    before = {path: path.read_bytes() for path in (wrapper, baseline, scenario_path)}
    scenario = HvacScenario(wrapper)
    snapshot = scenario.effective_config_snapshot()
    source_hashes = {
        "wrapper": canonical_file_sha256(wrapper),
        "baseline": canonical_file_sha256(baseline),
        "scenario": canonical_file_sha256(scenario_path),
    }
    identity = scenario.baseline_identity
    if identity is None:
        identity_scheme = "hvac_historical_config_chain_v1"
        baseline_id = canonical_hvac_mapping_sha256(
            {"scheme": identity_scheme, "source_hashes": source_hashes}
        )
    else:
        identity_scheme = identity.scheme
        baseline_id = identity.baseline_id
        if dict(identity.source_hashes) != source_hashes:
            raise ValueError("baseline identity 的 source hashes 与实际配置链不一致")
    if baseline_id != request.expected_baseline_id:
        raise ValueError("expected_baseline_id 与实际 resolved baseline identity 不一致")

    actual_requirements = _source_requirements(scenario, snapshot)
    if actual_requirements != dict(requirements):
        raise ValueError("baseline source 与 reusable definition 的 compatibility contract 不一致")
    certificate_hash = canonical_hvac_mapping_sha256(snapshot["finite_horizon_certificate"])
    if identity is not None and identity.finite_horizon_certificate_sha256 != certificate_hash:
        raise ValueError("baseline identity 的 finite-horizon certificate 摘要不一致")
    if any(path.read_bytes() != source for path, source in before.items()):
        raise ValueError("baseline 配置链在 source resolution 期间发生变化")
    return ResolvedBaselineSource(
        wrapper,
        identity_scheme,
        baseline_id,
        source_hashes,
        canonical_mapping_sha256(snapshot),
        certificate_hash,
    )


def validate_resolved_baseline_source(source: ResolvedBaselineSource) -> None:
    """复验运行期 source bytes 未偏离 resolver 冻结的配置链。"""
    wrapper, baseline, scenario = _source_paths_from_config(source.config_path)
    actual = {
        "wrapper": canonical_file_sha256(wrapper),
        "baseline": canonical_file_sha256(baseline),
        "scenario": canonical_file_sha256(scenario),
    }
    if actual != dict(source.source_hashes):
        raise ValueError("resolved baseline source 在运行期间发生变化")


def _source_requirements(scenario: HvacScenario, snapshot: Mapping[str, Any]) -> dict[str, object]:
    """只抽取下游真正依赖的能力，避免稳定层复制 baseline 内部参数。"""
    metadata = scenario.metadata
    return {
        "scenario_name": metadata.name,
        "scenario_version": scenario.scenario_version,
        "model_kind": snapshot["hvac"]["model_semantics"]["kind"],
        "sample_count": snapshot["hvac"]["timing"]["sample_count"],
        "horizon_steps": snapshot["wrapper"]["security"]["horizon_steps"],
        "controller_dimensions": dict(
            zip(("state", "input", "output"), scenario.controller_dimensions, strict=True)
        ),
        "channel_dimensions": {
            "reference": len(metadata.reference.names),
            "output": len(metadata.output.names),
            "control": len(metadata.control.names),
        },
        "allowed_security_override_fields": [
            "security.modulus",
            "security.integer_bits",
            "security.fractional_bits",
            "security.security_parameter",
            "security.modulus_evidence",
        ],
    }


def _legacy_requirements(definition: PrecisionSweepDefinition) -> dict[str, object]:
    """把历史 v1 的隐含兼容条件显式归一化，不复制具体 source identity。"""
    scenario = HvacScenario(definition.source_config)
    requirements = _source_requirements(scenario, scenario.effective_config_snapshot())
    requirements["allowed_security_override_fields"] = list(definition.allowed_variable_fields)
    return requirements


def _adapt_legacy_definition(
    definition: PrecisionSweepDefinition,
) -> ReusablePrecisionSweepDefinition:
    """将 v1 embedded source definition 适配到同一稳定定义模型。"""
    return ReusablePrecisionSweepDefinition(
        definition_path=definition.source_config,
        scenario_id=definition.scenario_id,
        source_requirements=_legacy_requirements(definition),
        stability_policy={
            "schur_status": "stable",
            "equilibrium_applicability": "applicable",
        },
        prime_evidence_path=definition.prime_evidence_path,
        prime_evidence_hash=definition.prime_evidence_hash,
        fractional_bits=definition.fractional_bits,
        integer_headroom_bits=definition.integer_headroom_bits,
        security_parameter=definition.security_parameter,
        seeds=definition.seeds,
        primary_seed=definition.primary_seed,
        allowed_variable_fields=definition.allowed_variable_fields,
        timeout_seconds=definition.timeout_seconds,
        max_protocol1_triples_per_point=definition.max_protocol1_triples_per_point,
        max_protocol2_truncations_per_point=definition.max_protocol2_truncations_per_point,
        max_certified_integer_bit_length=definition.max_certified_integer_bit_length,
        max_artifact_bytes=definition.max_artifact_bytes,
        q=definition.q,
        modulus_evidence=definition.modulus_evidence,
    )


def resolve_precision_sweep_plan(
    definition: ReusablePrecisionSweepDefinition,
    source_request: BaselineSourceRequest,
) -> ResolvedPrecisionSweepPlan:
    """在创建正式 staging/worker 前解析来源、稳定性与 prime trust anchor。"""
    if not isinstance(definition, ReusablePrecisionSweepDefinition):
        raise TypeError("definition 必须是 ReusablePrecisionSweepDefinition")
    source = resolve_hvac_baseline_source(source_request, definition.source_requirements)
    _, baseline, plant = _source_paths_from_config(source.config_path)
    stability_hash, stability = stability_report_sha256(plant, baseline)
    policy = definition.stability_policy
    if set(policy) != {"schur_status", "equilibrium_applicability"}:
        raise ValueError("stability_policy 字段无效")
    stability_passed = stability["schur"]["status"] == policy["schur_status"] and all(
        item["applicability"] == policy["equilibrium_applicability"]
        for item in stability["equilibria"]
    )
    if not stability_passed:
        raise ValueError("baseline stability result 不满足 reusable definition policy")
    prime_passed = (
        canonical_file_sha256(definition.prime_evidence_path) == definition.prime_evidence_hash
    )
    if not prime_passed:
        raise ValueError("prime evidence SHA-256 与 reusable definition 不一致")
    provenance = collect_provenance(
        scenario_name=str(definition.source_requirements["scenario_name"]),
        scenario_version=str(definition.source_requirements["scenario_version"]),
        schema_version=2,
        test_seed=None,
    )
    plan = ResolvedPrecisionSweepPlan(
        definition,
        source,
        stability,
        stability_hash,
        True,
        definition.points,
        provenance,
    )
    # 用首个点走正式 HvacScenario parser，确保 q 与 Pocklington 证据真实可验证。
    with tempfile.TemporaryDirectory(prefix="secure-control-sweep-preflight-") as temporary:
        point_config = Path(temporary) / "point.yaml"
        materialize_point_config(plan, plan.points[0], point_config)
        HvacScenario(point_config)
    return plan


def resolve_verified_precision_sweep_plan(
    definition: ReusablePrecisionSweepDefinition,
    source_request: BaselineSourceRequest,
    resolved_source: Mapping[str, object],
    resolved_plan: Mapping[str, object],
) -> ResolvedPrecisionSweepPlan:
    """以 verified artifact 的 plan 为权威，复验显式 baseline 后供 evidence 重放。"""
    source = resolve_hvac_baseline_source(source_request, definition.source_requirements)
    expected_source = {
        "schema_version": 1,
        "identity_scheme": source.identity_scheme,
        "baseline_id": source.baseline_id,
        "source_hashes": dict(source.source_hashes),
        "effective_config_sha256": source.effective_config_sha256,
        "finite_horizon_certificate_sha256": source.finite_horizon_certificate_sha256,
    }
    stored_source = dict(resolved_source)
    stored_config = stored_source.pop("config_path", None)
    if (
        not isinstance(stored_config, str)
        or Path(stored_config).name != stored_config
        or stored_source != expected_source
    ):
        raise ValueError("显式 baseline 与 verified sweep resolved_source 不一致")
    _, baseline, plant = _source_paths_from_config(source.config_path)
    stability_hash, stability = stability_report_sha256(plant, baseline)
    if (
        resolved_plan.get("stability_report_sha256") != stability_hash
        or resolved_plan.get("stability_report") != stability
        or resolved_plan.get("baseline_id") != source.baseline_id
        or resolved_plan.get("baseline_identity_scheme") != source.identity_scheme
        or resolved_plan.get("points") != [asdict(point) for point in definition.points]
        or resolved_plan.get("prime_evidence_passed") is not True
    ):
        raise ValueError("显式 baseline 与 verified sweep resolved_plan 不一致")
    plan = ResolvedPrecisionSweepPlan(
        definition,
        source,
        stability,
        stability_hash,
        True,
        definition.points,
        dict(resolved_plan.get("provenance", {})),
    )
    with tempfile.TemporaryDirectory(prefix="secure-control-evidence-preflight-") as temporary:
        point_config = Path(temporary) / "point.yaml"
        materialize_point_config(plan, plan.points[0], point_config)
        HvacScenario(point_config)
    return plan


def _resolve_definition_plan(
    definition: PrecisionSweepDefinition | ReusablePrecisionSweepDefinition,
    *,
    baseline_config: str | Path | None,
    expected_baseline_id: str | None,
) -> ResolvedPrecisionSweepPlan:
    """将 v1 embedded pins 或 v2 explicit request 归一为同一 resolved plan。"""
    if isinstance(definition, PrecisionSweepDefinition):
        if baseline_config is not None or expected_baseline_id is not None:
            raise ValueError("schema v1 不允许同时提供 v2 source override")
        actual_hashes = {
            name: canonical_file_sha256(path)
            for name, path in zip(
                ("wrapper", "baseline", "plant"), _source_paths(definition), strict=True
            )
        }
        if actual_hashes != dict(definition.source_hashes):
            raise ValueError("schema v1 embedded source hashes 不匹配")
        expected_id = canonical_hvac_mapping_sha256(
            {
                "scheme": "hvac_historical_config_chain_v1",
                "source_hashes": {
                    "wrapper": definition.source_hashes["wrapper"],
                    "baseline": definition.source_hashes["baseline"],
                    "scenario": definition.source_hashes["plant"],
                },
            }
        )
        plan = resolve_precision_sweep_plan(
            _adapt_legacy_definition(definition),
            BaselineSourceRequest(definition.source_config, expected_id),
        )
        frozen_passed, _ = _frozen_sources(definition, plan.stability_report_sha256)
        if not frozen_passed:
            raise ValueError("schema v1 embedded source/stability/prime pins 不匹配")
        return plan
    if baseline_config is None or expected_baseline_id is None:
        raise ValueError("schema v2 必须同时提供 baseline_config 与 expected_baseline_id")
    return resolve_precision_sweep_plan(
        definition,
        BaselineSourceRequest(Path(baseline_config), expected_baseline_id),
    )


def _margin(name: str, bound: int, limit: int) -> RangeMargin:
    """构造单个非负整数界的余量与使用率。"""
    remaining = limit - bound
    return RangeMargin(name, bound, limit, remaining, bound / limit)


def build_preflight_report(
    point: SweepPointDefinition,
    scenario: HvacScenario,
    *,
    stability_passed: bool,
    prime_evidence_passed: bool,
    frozen_fields_passed: bool,
) -> PrecisionPreflightReport:
    """在安全 session 建立前核对来源、素数和全部 payload/accumulator 界。"""
    certificate = scenario.safety_certificate
    payload_limit = (1 << (point.k - 1)) - 1
    modulus_limit = certificate.centered_modulus_limit
    ranges = (
        *(
            _margin(f"input_payload[{index}]", value, payload_limit)
            for index, value in enumerate(certificate.input_payload_bounds)
        ),
        *(
            _margin(f"state_payload[{index}]", value, payload_limit)
            for index, value in enumerate(certificate.state_payload_bounds)
        ),
        *(
            _margin(f"state_accumulator[{index}]", value, modulus_limit)
            for index, value in enumerate(certificate.maximum_state_accumulator_bounds)
        ),
        *(
            _margin(f"output_accumulator[{index}]", value, modulus_limit)
            for index, value in enumerate(certificate.maximum_output_accumulator_bounds)
        ),
    )
    reasons: list[str] = []
    if not stability_passed:
        reasons.append("stability_gate_failed")
    if not frozen_fields_passed:
        reasons.append("frozen_source_mismatch")
    if not prime_evidence_passed:
        reasons.append("prime_evidence_hash_mismatch")
    derived_kappa = point.q.bit_length() - point.lambda_ - 2
    if point.kappa != derived_kappa:
        reasons.append("derived_kappa_mismatch")
    if point.kappa <= point.ell:
        reasons.append("kappa_not_greater_than_ell")
    if any(item.remaining_margin < 0 for item in ranges):
        reasons.append("certified_range_exceeded")
    return PrecisionPreflightReport(
        stability_passed,
        prime_evidence_passed,
        frozen_fields_passed,
        ranges,
        not reasons,
        tuple(reasons),
    )


def derive_protocol_cost(
    runtime: Any,
    certificate: HvacSafetyCertificate,
    horizon_steps: int,
    wall_clock_seconds: float,
) -> ProtocolCostReport:
    """从实际 controller shape 与 scale ledger 推导每步和总资源数。"""
    spec = runtime.spec
    state, input_, output = spec.state_dimension, spec.input_dimension, spec.output_dimension
    triples = state * state + state * input_ + output * state + output * input_
    truncations = state if runtime.scale_ledger.state_truncation_bits else 0
    certified = (
        *certificate.input_payload_bounds,
        *certificate.state_payload_bounds,
        *certificate.maximum_state_accumulator_bounds,
        *certificate.maximum_output_accumulator_bounds,
    )
    return ProtocolCostReport(
        triples,
        triples * horizon_steps,
        truncations,
        truncations * horizon_steps,
        runtime.modulus_verification.bit_length,
        max(value.bit_length() for value in certified),
        wall_clock_seconds,
        "child_start_through_atomic_point_result",
    )


def _incomplete_preflight(
    *,
    stability_passed: bool,
    prime_evidence_passed: bool,
    frozen_fields_passed: bool,
    reason: str = "preflight_not_completed",
) -> PrecisionPreflightReport:
    """保留父进程已知门禁，并以 ``None`` 明示尚未形成的可行性结论。"""
    return PrecisionPreflightReport(
        stability_passed,
        prime_evidence_passed,
        frozen_fields_passed,
        (),
        None,
        (reason,),
    )


def _frozen_sources(
    definition: PrecisionSweepDefinition, stability_hash: str
) -> tuple[bool, dict[str, str]]:
    """核对三份来源、稳定性报告和素数证据的规范化摘要。"""
    wrapper, baseline, plant = _source_paths(definition)
    actual = {
        "wrapper": canonical_file_sha256(wrapper),
        "baseline": canonical_file_sha256(baseline),
        "plant": canonical_file_sha256(plant),
    }
    passed = (
        actual == dict(definition.source_hashes)
        and stability_hash == definition.stability_report_hash
        and canonical_file_sha256(definition.prime_evidence_path) == definition.prime_evidence_hash
    )
    return passed, actual


def _new_sweep_id() -> str:
    """生成可排序且不依赖扫描参数的唯一发布标识。"""
    now = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{now}-{secrets.token_hex(6)}"


def _failed_record(
    point: SweepPointDefinition,
    code: str,
    message: str,
    preflight: PrecisionPreflightReport,
    cost: ProtocolCostReport | None = None,
) -> SweepRunRecord:
    """构造父进程失败记录，同时保留已获得的真实门禁与成本证据。"""
    return SweepRunRecord(
        point,
        SweepRunStatus.FAILED,
        preflight,
        None,
        None,
        None,
        cost,
        None,
        code,
        message,
    )


def _read_preflight_checkpoint(
    attempt: Path,
    point: SweepPointDefinition,
    *,
    stability_passed: bool,
    prime_evidence_passed: bool,
    frozen_fields_passed: bool,
) -> PrecisionPreflightReport:
    """恢复 worker 原子 checkpoint；缺失或畸形时明确返回 unknown，而非伪造失败。"""
    fallback = _incomplete_preflight(
        stability_passed=stability_passed,
        prime_evidence_passed=prime_evidence_passed,
        frozen_fields_passed=frozen_fields_passed,
    )
    checkpoint_path = attempt / "preflight.json"
    try:
        payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return fallback
    except (OSError, json.JSONDecodeError):
        return replace(fallback, reason_codes=("preflight_checkpoint_invalid",))
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "point",
        "preflight",
    }:
        return replace(fallback, reason_codes=("preflight_checkpoint_invalid",))
    try:
        if payload["schema_version"] != 1 or SweepPointDefinition(**payload["point"]) != point:
            raise ValueError("checkpoint identity mismatch")
        return preflight_from_payload(payload["preflight"])
    except (TypeError, ValueError):
        return replace(fallback, reason_codes=("preflight_checkpoint_invalid",))


def _attempt_member(attempt: Path, relative: str) -> Path:
    """将 worker 返回路径约束在本次 attempt，拒绝绝对路径和逃逸。"""
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("worker_result_path_escape")
    resolved = (attempt / candidate).resolve()
    try:
        resolved.relative_to(attempt.resolve())
    except ValueError as error:
        raise ValueError("worker_result_path_escape") from error
    return resolved


def _read_worker_record(attempt: Path, point: SweepPointDefinition) -> SweepRunRecord:
    """读取 worker 原子结果并复验点身份及成功运行目录。"""
    result_path = attempt / "result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "record"}:
        raise ValueError("worker_result_invalid")
    if payload["schema_version"] != 1:
        raise ValueError("worker_result_invalid")
    record = record_from_payload(payload["record"])
    if record.point != point:
        raise ValueError("worker_point_mismatch")
    if record.status is SweepRunStatus.SUCCESS:
        if not isinstance(record.artifact_path, str):
            raise ValueError("worker_artifact_missing")
        run_dir = _attempt_member(attempt, record.artifact_path)
        load_artifacts(run_dir)
        raw_root = attempt / "raw"
        published = [
            path
            for path in raw_root.iterdir()
            if path.is_dir() and not path.name.startswith(".incomplete-")
        ]
        if published != [run_dir]:
            raise ValueError("worker_artifact_count_invalid")
    return record


def _artifact_size(path: Path) -> int:
    """统计单次正式运行目录内的普通文件字节数。"""
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def run_precision_sweep(
    definition_path: str | Path,
    *,
    baseline_config: str | Path | None = None,
    expected_baseline_id: str | None = None,
    output_root: str | Path = "results/sweeps",
) -> SweepArtifacts:
    """依次预检并运行十二点，最后以同盘 rename 原子发布完整或部分结果。"""
    loaded_definition = load_precision_sweep_definition(definition_path)
    plan = _resolve_definition_plan(
        loaded_definition,
        baseline_config=baseline_config,
        expected_baseline_id=expected_baseline_id,
    )
    plan = replace(
        plan,
        provenance={
            **plan.provenance,
            "definition_schema_version": (
                1 if isinstance(loaded_definition, PrecisionSweepDefinition) else 2
            ),
            "definition_source_sha256": canonical_file_sha256(definition_path),
        },
    )
    definition = plan.definition
    stability_payload = dict(plan.stability_report)
    stability_passed = True
    frozen_passed = True
    actual_hashes = dict(plan.source.source_hashes)
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    sweep_id = _new_sweep_id()
    stage = root / f".incomplete-{sweep_id}"
    final = root / sweep_id
    stage.mkdir(exist_ok=False)
    records: list[SweepRunRecord] = []
    try:
        write_json(
            stage / "source_hashes.json",
            (
                {
                    "expected": dict(loaded_definition.source_hashes),
                    "actual": {
                        "wrapper": actual_hashes["wrapper"],
                        "baseline": actual_hashes["baseline"],
                        "plant": actual_hashes["scenario"],
                    },
                }
                if isinstance(loaded_definition, PrecisionSweepDefinition)
                else {
                    "expected_baseline_id": plan.source.baseline_id,
                    "identity_scheme": plan.source.identity_scheme,
                    "actual": actual_hashes,
                }
            ),
        )
        prime_passed = plan.prime_evidence_passed
        for point in plan.points:
            validate_resolved_baseline_source(plan.source)
            point_root = stage / "points" / point.point_id
            materialize_point_config(plan, point, point_root / "config.yaml")
            attempt = stage / "work" / point.point_id / secrets.token_hex(8)
            attempt.mkdir(parents=True, exist_ok=False)
            materialize_point_config(plan, point, attempt / "config.yaml")
            request = {
                "schema_version": 1,
                "point": asdict(point),
                "config_path": "config.yaml",
                "artifact_root": "raw",
                "result_path": "result.json",
                "stability_passed": stability_passed,
                "prime_evidence_passed": prime_passed,
                "frozen_fields_passed": frozen_passed,
                "resource_limits": {
                    "max_protocol1_triples_per_point": definition.max_protocol1_triples_per_point,
                    "max_protocol2_truncations_per_point": definition.max_protocol2_truncations_per_point,
                    "max_certified_integer_bit_length": definition.max_certified_integer_bit_length,
                },
            }
            write_json(attempt / "request.json", request)
            child = _run_child(
                [
                    sys.executable,
                    "-m",
                    "secure_control.experiments._sweep_worker",
                    "--request",
                    str(attempt / "request.json"),
                ],
                timeout_seconds=definition.timeout_seconds,
            )
            checkpoint = _read_preflight_checkpoint(
                attempt,
                point,
                stability_passed=stability_passed,
                prime_evidence_passed=prime_passed,
                frozen_fields_passed=frozen_passed,
            )
            if child.timed_out:
                record = _failed_record(
                    point,
                    "point_timeout",
                    "worker deadline exceeded",
                    checkpoint,
                )
            elif child.returncode != 0:
                record = _failed_record(
                    point,
                    "worker_nonzero_exit",
                    f"returncode={child.returncode}; stderr={child.stderr}",
                    checkpoint,
                )
            else:
                try:
                    record = _read_worker_record(attempt, point)
                    if record.cost is not None:
                        record = replace(
                            record,
                            cost=replace(
                                record.cost,
                                wall_clock_seconds=child.elapsed_seconds,
                                timing_scope="child_start_through_atomic_point_result",
                            ),
                        )
                    if record.status is SweepRunStatus.SUCCESS:
                        source = _attempt_member(attempt, record.artifact_path)
                        if _artifact_size(source) > definition.max_artifact_bytes:
                            record = _failed_record(
                                point,
                                "artifact_budget_exceeded",
                                "worker artifact exceeds configured byte budget",
                                record.preflight,
                                record.cost,
                            )
                        else:
                            destination_root = stage / "runs" / point.point_id
                            destination_root.mkdir(parents=True, exist_ok=False)
                            destination = destination_root / source.name
                            os.rename(source, destination)
                            record = replace(
                                record, artifact_path=destination.relative_to(stage).as_posix()
                            )
                except Exception as error:  # noqa: BLE001 - worker 不可信输出转稳定失败码。
                    code = (
                        str(error) if str(error).startswith("worker_") else "worker_result_invalid"
                    )
                    record = _failed_record(point, code, str(error), checkpoint)
            records.append(record)
            write_json(point_root / "record.json", record)
            shutil.rmtree(attempt.parent)
        validate_resolved_baseline_source(plan.source)
        frozen_records = tuple(records)
        write_definition(stage / "definition.json", loaded_definition)
        write_resolved_source(stage / "resolved_source.json", plan.source)
        write_resolved_plan(stage / "resolved_plan.json", plan)
        write_summary(stage / "summary.csv", frozen_records)
        write_range_margins(stage / "range_margins.csv", frozen_records)
        write_json(
            stage / "summary.json",
            build_summary_payload(
                frozen_records,
                stability_payload,
                (
                    "Adapted 2R2C HVAC precision sweep; it does not reproduce the paper's exact "
                    "plant, closed-loop tuning, or Protocol 2 runtime path."
                ),
            ),
        )
        write_data_manifest(
            stage / "data_manifest.json",
            sweep_id=sweep_id,
            definition=loaded_definition,
            records=frozen_records,
        )
        verified = load_verified_sweep_data(stage, manifest_name="data_manifest.json")
        for record in verified.records:
            if record.status is not SweepRunStatus.SUCCESS:
                continue
            standard_root = stage / "standard" / f"{record.point.ell}-{record.point.seed}"
            standard_root.mkdir(parents=True, exist_ok=False)
            render_saved_run(
                stage / record.artifact_path,
                PlotSelection(((0, 0),), (0,), "linear", "h", "png", (0,)),
                output_root=standard_root,
                display=PlotDisplay("h", f"ell={record.point.ell}, seed={record.point.seed}"),
            )
        if any(record.status is SweepRunStatus.SUCCESS for record in frozen_records):
            render_sweep_figures(
                stage,
                primary_seed=definition.primary_seed,
                manifest_name="data_manifest.json",
            )
        write_manifest(
            stage / "manifest.json",
            sweep_id=sweep_id,
            definition=loaded_definition,
            records=frozen_records,
        )
        load_verified_sweep_data(stage)
        os.rename(stage, final)
    except Exception:
        if stage.exists() and stage.resolve().parent == root:
            shutil.rmtree(stage)
        raise
    return SweepArtifacts(
        sweep_id,
        final,
        final / "manifest.json",
        final / "summary.csv",
        tuple(records),
    )


def main() -> None:
    """运行正式扫描；只要存在失败或不可行点，发布诊断后以非零退出。"""
    parser = argparse.ArgumentParser(description="Run the frozen 2R2C precision sweep")
    parser.add_argument("--definition", required=True)
    parser.add_argument("--baseline-config")
    parser.add_argument("--expected-baseline-id")
    parser.add_argument("--output-root", default="results/sweeps")
    args = parser.parse_args()
    artifacts = run_precision_sweep(
        args.definition,
        baseline_config=args.baseline_config,
        expected_baseline_id=args.expected_baseline_id,
        output_root=args.output_root,
    )
    print(
        json.dumps(
            {
                "sweep_id": artifacts.sweep_id,
                "root": str(artifacts.root),
                "statuses": [record.status.value for record in artifacts.records],
            }
        )
    )
    if any(record.status is not SweepRunStatus.SUCCESS for record in artifacts.records):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
