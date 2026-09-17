"""Issue #15 单点私有 worker；它不发布批次，也不创建任何子进程。"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from pathlib import Path
from time import perf_counter
from typing import Any

from secure_control.experiments.artifacts import SCHEMA_VERSION, write_artifacts
from secure_control.experiments.provenance import collect_provenance
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation import compare_closed_loops

from .sweep import SweepPointDefinition, SweepRunRecord, SweepRunStatus
from .sweep_artifacts import record_payload, write_json
from .sweep_metrics import compute_error_metrics
from .sweep_runner import build_preflight_report, derive_protocol_cost


def _private_path(root: Path, value: object) -> Path:
    """解析 request 内相对路径，并确保它不能离开本次 attempt。"""
    if not isinstance(value, str):
        raise TypeError("worker path 必须是字符串")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("worker request path escape")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("worker request path escape") from error
    return resolved


def _atomic_result(path: Path, record: SweepRunRecord) -> None:
    """先完整写临时 JSON，再以同目录 replace 提交唯一单点结果。"""
    temporary = path.with_name(f".{path.name}.tmp")
    write_json(temporary, {"schema_version": 1, "record": record_payload(record)})
    os.replace(temporary, path)


def _resource_exceeded(cost: Any, limits: dict[str, Any]) -> bool:
    """按冻结预算判断三个可在仿真前精确推导的资源量。"""
    return (
        cost.protocol1_triples_total > limits["max_protocol1_triples_per_point"]
        or cost.protocol2_truncations_total > limits["max_protocol2_truncations_per_point"]
        or cost.max_certified_integer_bit_length > limits["max_certified_integer_bit_length"]
    )


def run_request(request_path: str | Path) -> None:
    """严格执行一个 request，并只在其私有目录原子提交 result.json。"""
    request_file = Path(request_path).resolve()
    attempt = request_file.parent
    request = json.loads(request_file.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "point",
        "config_path",
        "artifact_root",
        "result_path",
        "stability_passed",
        "prime_evidence_passed",
        "frozen_fields_passed",
        "resource_limits",
    }
    if not isinstance(request, dict) or set(request) != required or request["schema_version"] != 1:
        raise ValueError("worker request schema 无效")
    point_payload = request["point"]
    limits = request["resource_limits"]
    if not isinstance(point_payload, dict) or not isinstance(limits, dict):
        raise TypeError("worker point/resource_limits 无效")
    point = SweepPointDefinition(**point_payload)
    config_path = _private_path(attempt, request["config_path"])
    artifact_root = _private_path(attempt, request["artifact_root"])
    result_path = _private_path(attempt, request["result_path"])
    started = perf_counter()
    try:
        scenario = HvacScenario(config_path, test_seed=point.seed)
        preflight = build_preflight_report(
            point,
            scenario,
            stability_passed=request["stability_passed"] is True,
            prime_evidence_passed=request["prime_evidence_passed"] is True,
            frozen_fields_passed=request["frozen_fields_passed"] is True,
        )
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
            _atomic_result(result_path, record)
            return
        plan = scenario.build_plan()
        preliminary_cost = derive_protocol_cost(
            plan.secure.runtime,
            scenario.safety_certificate,
            len(plan.sample_times),
            0.0,
        )
        if _resource_exceeded(preliminary_cost, limits):
            constrained = replace(
                preflight,
                feasible=False,
                reason_codes=(*preflight.reason_codes, "resource_budget_exceeded"),
            )
            record = SweepRunRecord(
                point,
                SweepRunStatus.INFEASIBLE,
                constrained,
                None,
                None,
                None,
                preliminary_cost,
                None,
                "resource_budget_exceeded",
                "derived point resources exceed configured budget",
            )
            _atomic_result(result_path, record)
            return
        result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
        published = write_artifacts(
            result,
            scenario.metadata,
            scenario.effective_config_snapshot(),
            collect_provenance(
                scenario_name=scenario.metadata.name,
                scenario_version=scenario.scenario_version,
                schema_version=SCHEMA_VERSION,
                test_seed=point.seed,
            ),
            output_root=artifact_root,
        )
        elapsed = perf_counter() - started
        cost = replace(preliminary_cost, wall_clock_seconds=elapsed)
        record = SweepRunRecord(
            point,
            SweepRunStatus.SUCCESS,
            preflight,
            compute_error_metrics(result.output_error),
            compute_error_metrics(result.control_error),
            scenario.metrics_snapshot(result),
            cost,
            published.run_dir.relative_to(attempt).as_posix(),
            None,
            None,
        )
    except Exception as error:  # noqa: BLE001 - 单点异常必须成为可审计失败记录。
        from .sweep_runner import _failure_preflight

        record = SweepRunRecord(
            point,
            SweepRunStatus.FAILED,
            _failure_preflight(type(error).__name__),
            None,
            None,
            None,
            None,
            None,
            type(error).__name__,
            str(error),
        )
    _atomic_result(result_path, record)


def main() -> None:
    """解析唯一 request 参数；非法 request 直接以非零退出。"""
    parser = argparse.ArgumentParser(description="Run one private precision-sweep point")
    parser.add_argument("--request", required=True)
    args = parser.parse_args()
    run_request(args.request)


if __name__ == "__main__":
    main()
