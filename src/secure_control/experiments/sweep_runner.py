"""Issue #15 的 2R2C 扫描 composition root、预检、执行和原子发布。"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
from dataclasses import asdict
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from typing import Any

import yaml

from secure_control.experiments.artifacts import SCHEMA_VERSION, write_artifacts
from secure_control.experiments.plotting import PlotDisplay, PlotSelection, render_saved_run
from secure_control.experiments.provenance import collect_provenance
from secure_control.scenarios.hvac.integration import HvacSafetyCertificate, HvacScenario
from secure_control.scenarios.hvac.stability import analyze_hvac_closed_loop_stability
from secure_control.simulation import compare_closed_loops

from .sweep import (
    PrecisionPreflightReport,
    PrecisionSweepDefinition,
    ProtocolCostReport,
    RangeMargin,
    SweepArtifacts,
    SweepPointDefinition,
    SweepRunRecord,
    SweepRunStatus,
    canonical_file_sha256,
    load_precision_sweep_definition,
    materialize_point_config,
)
from .sweep_artifacts import (
    write_definition,
    write_json,
    write_manifest,
    write_summary,
)
from .sweep_metrics import aggregate_error_metrics, compute_error_metrics
from .sweep_plotting import render_sweep_figures


def _source_paths(definition: PrecisionSweepDefinition) -> tuple[Path, Path, Path]:
    """解析冻结 wrapper、PID baseline 和 plant 的同仓库来源路径。"""
    wrapper = yaml.safe_load(definition.source_config.read_text(encoding="utf-8"))
    baseline = (definition.source_config.parent / wrapper["baseline_config"]).resolve()
    baseline_data = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    plant = (baseline.parent / baseline_data["plant_config"]).resolve()
    return definition.source_config, baseline, plant


def stability_report_sha256(plant_path: Path, pid_path: Path) -> tuple[str, dict[str, Any]]:
    """规范化来源摘要后计算跨 checkout 换行稳定的稳定性报告哈希。"""
    report = analyze_hvac_closed_loop_stability(plant_path, pid_path)
    payload = asdict(report)
    payload["plant_source_sha256"] = canonical_file_sha256(plant_path)
    payload["pid_source_sha256"] = canonical_file_sha256(pid_path)
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return sha256(serialized).hexdigest(), payload


def _margin(name: str, bound: int, limit: int) -> RangeMargin:
    """构造单个非负整数界的余量与使用率。"""
    remaining = limit - bound
    return RangeMargin(name, bound, limit, remaining, bound / limit)


def build_preflight_report(
    definition: PrecisionSweepDefinition,
    point: SweepPointDefinition,
    scenario: HvacScenario,
    *,
    stability_passed: bool,
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
    if canonical_file_sha256(definition.prime_evidence_path) != definition.prime_evidence_hash:
        reasons.append("prime_evidence_hash_mismatch")
    if any(item.remaining_margin < 0 for item in ranges):
        reasons.append("certified_range_exceeded")
    prime_passed = not any(reason.startswith("prime_evidence") for reason in reasons)
    return PrecisionPreflightReport(
        stability_passed,
        prime_passed,
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
        "validated_point_execution_and_artifact_write",
    )


def _failure_preflight(reason: str) -> PrecisionPreflightReport:
    """在场景预检本身拒绝配置时保留稳定不可行原因。"""
    return PrecisionPreflightReport(False, False, False, (), False, (reason,))


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


def _aggregate(records: tuple[SweepRunRecord, ...], stability: dict[str, Any]) -> dict[str, Any]:
    """按 ell 汇总三次 seed 的误差，同时保留稳定性 claim boundary。"""
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
        "by_fractional_bits": by_ell,
        "stability": stability,
        "claim_boundary": (
            "Adapted 2R2C HVAC precision sweep; it does not reproduce the paper's exact plant, "
            "closed-loop tuning, or Protocol 2 runtime path."
        ),
    }


def run_precision_sweep(
    definition_path: str | Path,
    *,
    output_root: str | Path = "results/sweeps",
) -> SweepArtifacts:
    """依次预检并运行十二点，最后以同盘 rename 原子发布完整或部分结果。"""
    definition = load_precision_sweep_definition(definition_path)
    _, baseline, plant = _source_paths(definition)
    stability_hash, stability_payload = stability_report_sha256(plant, baseline)
    stability_passed = stability_payload["schur"]["status"] == "stable" and all(
        item["applicability"] == "applicable" for item in stability_payload["equilibria"]
    )
    frozen_passed, actual_hashes = _frozen_sources(definition, stability_hash)
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
            {"expected": definition.source_hashes, "actual": actual_hashes},
        )
        for point in definition.points:
            point_root = stage / "points" / point.point_id
            config_path = materialize_point_config(definition, point, point_root / "config.yaml")
            try:
                scenario = HvacScenario(config_path, test_seed=point.seed)
                preflight = build_preflight_report(
                    definition,
                    point,
                    scenario,
                    stability_passed=stability_passed,
                    frozen_fields_passed=frozen_passed,
                )
            except Exception as error:  # noqa: BLE001 - 单点预检必须转成正式不可行记录。
                record = SweepRunRecord(
                    point,
                    SweepRunStatus.INFEASIBLE,
                    _failure_preflight(type(error).__name__),
                    None,
                    None,
                    None,
                    None,
                    None,
                    "preflight_rejected",
                    str(error),
                )
                records.append(record)
                write_json(point_root / "record.json", record)
                continue
            if not preflight.feasible:
                record = SweepRunRecord(
                    point,
                    SweepRunStatus.INFEASIBLE,
                    preflight,
                    None,
                    None,
                    None,
                    None,
                    None,
                    "preflight_infeasible",
                    ";".join(preflight.reason_codes),
                )
                records.append(record)
                write_json(point_root / "record.json", record)
                continue
            started = perf_counter()
            try:
                plan = scenario.build_plan()
                result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
                scenario_metrics = scenario.metrics_snapshot(result)
                effective_config = scenario.effective_config_snapshot()
                provenance = collect_provenance(
                    scenario_name=scenario.metadata.name,
                    scenario_version=scenario.scenario_version,
                    schema_version=SCHEMA_VERSION,
                    test_seed=point.seed,
                )
                published = write_artifacts(
                    result,
                    scenario.metadata,
                    effective_config,
                    provenance,
                    output_root=stage / "runs" / point.point_id,
                )
                elapsed = perf_counter() - started
                if elapsed > definition.timeout_seconds:
                    raise TimeoutError(
                        f"扫描点耗时 {elapsed:.3f}s 超过 {definition.timeout_seconds}s"
                    )
                # 通用 figure writer 还会追加 run/render ID；短目录避免 Windows 深工作区超长路径。
                standard_figure_root = stage / "standard" / f"{point.ell}-{point.seed}"
                standard_figure_root.mkdir(parents=True, exist_ok=False)
                render_saved_run(
                    published.run_dir,
                    PlotSelection(((0, 0),), (0,), "linear", "h", "png", (0,)),
                    output_root=standard_figure_root,
                    display=PlotDisplay("h", f"ell={point.ell}, seed={point.seed}"),
                )
                cost = derive_protocol_cost(
                    plan.secure.runtime,
                    scenario.safety_certificate,
                    len(plan.sample_times),
                    elapsed,
                )
                record = SweepRunRecord(
                    point,
                    SweepRunStatus.SUCCESS,
                    preflight,
                    compute_error_metrics(result.output_error),
                    compute_error_metrics(result.control_error),
                    scenario_metrics,
                    cost,
                    published.run_dir.relative_to(stage).as_posix(),
                    None,
                    None,
                )
            except Exception as error:  # noqa: BLE001 - 单点失败不得阻止其余扫描点发布。
                record = SweepRunRecord(
                    point,
                    SweepRunStatus.FAILED,
                    preflight,
                    None,
                    None,
                    None,
                    None,
                    None,
                    type(error).__name__,
                    str(error),
                )
            records.append(record)
            write_json(point_root / "record.json", record)
        frozen_records = tuple(records)
        write_definition(stage / "definition.json", definition)
        write_summary(stage / "summary.csv", frozen_records)
        write_json(stage / "summary.json", _aggregate(frozen_records, stability_payload))
        if any(record.status is SweepRunStatus.SUCCESS for record in frozen_records):
            render_sweep_figures(stage, primary_seed=definition.primary_seed)
        write_manifest(
            stage / "manifest.json",
            sweep_id=sweep_id,
            definition=definition,
            records=frozen_records,
        )
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
    parser.add_argument("--output-root", default="results/sweeps")
    args = parser.parse_args()
    artifacts = run_precision_sweep(args.definition, output_root=args.output_root)
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
