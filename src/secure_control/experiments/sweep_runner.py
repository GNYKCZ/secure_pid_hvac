"""Issue #15 的 2R2C 扫描 composition root、预检、执行和原子发布。"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from typing import Any

import yaml

from secure_control.experiments.artifacts import load_artifacts
from secure_control.experiments.plotting import PlotDisplay, PlotSelection, render_saved_run
from secure_control.scenarios.hvac.integration import HvacSafetyCertificate, HvacScenario
from secure_control.scenarios.hvac.stability import analyze_hvac_closed_loop_stability

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
    build_summary_payload,
    load_verified_sweep_data,
    record_from_payload,
    write_data_manifest,
    write_definition,
    write_json,
    write_manifest,
    write_range_margins,
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


def _failed_record(point: SweepPointDefinition, code: str, message: str) -> SweepRunRecord:
    """构造父进程可稳定发布的失败记录。"""
    return SweepRunRecord(
        point,
        SweepRunStatus.FAILED,
        _failure_preflight(code),
        None,
        None,
        None,
        None,
        None,
        code,
        message,
    )


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
        prime_passed = (
            canonical_file_sha256(definition.prime_evidence_path) == definition.prime_evidence_hash
        )
        for point in definition.points:
            point_root = stage / "points" / point.point_id
            materialize_point_config(definition, point, point_root / "config.yaml")
            attempt = stage / "work" / point.point_id / secrets.token_hex(8)
            attempt.mkdir(parents=True, exist_ok=False)
            materialize_point_config(definition, point, attempt / "config.yaml")
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
            if child.timed_out:
                record = _failed_record(point, "point_timeout", "worker deadline exceeded")
            elif child.returncode != 0:
                record = _failed_record(
                    point,
                    "worker_nonzero_exit",
                    f"returncode={child.returncode}; stderr={child.stderr}",
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
                    record = _failed_record(point, code, str(error))
            records.append(record)
            write_json(point_root / "record.json", record)
            shutil.rmtree(attempt.parent)
        frozen_records = tuple(records)
        write_definition(stage / "definition.json", definition)
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
            definition=definition,
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
            definition=definition,
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
