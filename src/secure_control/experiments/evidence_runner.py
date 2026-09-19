"""用冻结 sweep point 执行隔离诊断复现并发布真实 secure evidence。"""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np

from secure_control.execution import ControllerRuntime, SecureTraceCollector, SecureTracePolicy
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation import SimulationBranch, compare_closed_loops

from .evidence_artifacts import EvidenceArtifacts, write_evidence_artifacts
from .provenance import collect_provenance
from .sweep import (
    SweepRunStatus,
    load_precision_sweep_definition,
    materialize_point_config,
)
from .sweep_artifacts import load_verified_sweep_data

ISSUE51_START_COMMIT = "3dfbd05fdc63ee2ddab91c42f3999f39a13e6d48"
_RESULT_FIELDS = (
    "time",
    "reference",
    "output_ideal",
    "output_secure",
    "control_ideal",
    "control_secure",
    "control_error",
    "output_error",
)


class _RecordingRuntime:
    """透明记录通用 runtime 的 raw output，不改变 controller 输入或状态顺序。"""

    def __init__(self, runtime: ControllerRuntime) -> None:
        """绑定唯一底层 runtime；记录动作发生在其成功返回之后。"""
        if not isinstance(runtime, ControllerRuntime):
            raise TypeError("runtime 必须满足 ControllerRuntime。")
        self._runtime = runtime
        self._outputs: list[np.ndarray] = []

    def step(self, value: np.ndarray | float) -> np.ndarray:
        """委托真实 step，并复制其 raw control 返回值。"""
        output = np.asarray(self._runtime.step(value), dtype=float)
        self._outputs.append(np.array(output, copy=True))
        return np.array(output, copy=True)

    def reset(self) -> None:
        """重置底层 runtime 与本地记录，保持事务边界一致。"""
        self._runtime.reset()
        self._outputs.clear()

    def outputs(self) -> np.ndarray:
        """返回全部成功 step 的二维 raw output 副本。"""
        if not self._outputs:
            raise ValueError("尚未记录 raw control。")
        return np.vstack(self._outputs)


def run_evidence_diagnostic(
    *,
    sweep_dir: Path,
    ell: int,
    seed: int,
    selected_step: int,
    output_root: Path,
    allow_combined_share_diagnostic: bool = False,
    definition_path: Path = Path("configs/hvac_2r2c_precision_sweep.yaml"),
    start_commit: str = ISSUE51_START_COMMIT,
) -> EvidenceArtifacts:
    """复现唯一冻结点，严格比对八字段后原子发布独立 evidence。

    该函数明确属于实验 composition root：它可以组合 HVAC 场景、通用仿真与
    evidence runtime，但不会修改 source sweep，也不会把 trace 写入正式八字段 schema。
    """
    if type(ell) is not int or ell <= 0 or type(seed) is not int:
        raise ValueError("ell 必须为正整数，seed 必须为整数。")
    if type(selected_step) is not int or selected_step < 0:
        raise ValueError("selected_step 必须为非负整数。")
    if type(allow_combined_share_diagnostic) is not bool:
        raise TypeError("allow_combined_share_diagnostic 必须是 bool。")
    if not isinstance(start_commit, str) or len(start_commit) != 40:
        raise ValueError("start_commit 必须是完整 40 字符 commit SHA。")

    source = Path(sweep_dir)
    snapshot = _source_snapshot(source, ell, seed)
    verified = load_verified_sweep_data(source, manifest_name="manifest.json")
    record = next(
        (item for item in verified.records if item.point.ell == ell and item.point.seed == seed),
        None,
    )
    if (
        record is None
        or record.status is not SweepRunStatus.SUCCESS
        or record.artifact_path is None
    ):
        raise ValueError("指定 ell/seed 不存在唯一成功的 source point。")
    if selected_step >= verified.runs[record.point.point_id].result.time.size:
        raise ValueError("selected_step 超出 source run sample 范围。")

    definition = load_precision_sweep_definition(definition_path)
    point = next(
        (item for item in definition.points if item.ell == ell and item.seed == seed),
        None,
    )
    if point is None:
        raise ValueError("指定 ell/seed 不属于冻结 precision sweep definition。")
    _validate_definition(verified.definition, definition, point.q)
    source_record = verified.runs[record.point.point_id]

    with tempfile.TemporaryDirectory(prefix="secure-control-evidence-") as temporary:
        point_config = Path(temporary) / f"ell-{ell}-seed-{seed}.yaml"
        materialize_point_config(definition, point, point_config)
        point_config_sha256 = sha256(point_config.read_bytes()).hexdigest()
        collector = SecureTraceCollector()
        policy = SecureTracePolicy(
            selected_step=selected_step,
            allow_combined_share_diagnostic=allow_combined_share_diagnostic,
        )
        scenario = HvacScenario(
            point_config,
            test_seed=seed,
            trace_policy=policy,
            trace_collector=collector,
        )
        plan = scenario.build_plan()
        recorder = _RecordingRuntime(plan.ideal.runtime)
        ideal = SimulationBranch(plan.ideal.plant, plan.ideal.adapter, recorder)
        result = compare_closed_loops(ideal, plan.secure, plan.sample_times)
        scenario.metrics(result)
        plaintext_raw = recorder.outputs()
        traces = collector.traces()
        _assert_exact_result(result, source_record.result)
        _validate_runtime_evidence(traces, record.cost, selected_step)
        share_audit = collector.selected_share_audit()
        if (share_audit is not None) != allow_combined_share_diagnostic:
            raise ValueError("combined-share audit 与显式授权状态不一致。")

        def validate_source() -> None:
            """在原子发布提交点复验 source hashes 与 canonical final reader。"""
            if snapshot != _source_snapshot(source, ell, seed):
                raise ValueError("source sweep/run 在诊断期间发生变化。")
            load_verified_sweep_data(source, manifest_name="manifest.json")

        validate_source()
        ledger = plan.secure.runtime.scale_ledger
        metadata: dict[str, Any] = {
            "artifact_kind": "diagnostic_reproduction",
            "deployment_security": False,
            "diagnostic_rng_seed": seed,
            "diagnostic_rng_mode": "reproducibility_only",
            "start_commit": start_commit,
            "source_point": {
                "ell": ell,
                "seed": seed,
                "q": point.q,
                "point_id": record.point.point_id,
                "run_id": source_record.run_id,
                "artifact_path": record.artifact_path,
            },
            "source_hashes": snapshot,
            "point_config_sha256": point_config_sha256,
            "sweep_definition_sha256": sha256(Path(definition_path).read_bytes()).hexdigest(),
            "result_equivalence": {
                "comparison": "dtype_shape_and_array_equal",
                "fields": list(_RESULT_FIELDS),
                "all_equal": True,
            },
            "scale_ledger": asdict(ledger),
            "modulus": point.q,
            "resource_contract": {
                "protocol1_triples_per_step": record.cost.protocol1_triples_per_step,
                "protocol1_triples_total": record.cost.protocol1_triples_total,
                "protocol2_truncations_per_step": record.cost.protocol2_truncations_per_step,
                "protocol2_truncations_total": record.cost.protocol2_truncations_total,
                "count_semantics": "runtime_lifecycle_observed",
            },
            "time_step_semantics": {
                "selected_step": selected_step,
                "time_seconds": float(result.time[selected_step]),
                "order": [
                    "reference",
                    "pre_plant_output",
                    "controller_input",
                    "raw_control_from_state_before",
                    "controller_state_commit",
                    "actuator_mapping_or_clipping",
                    "plant_update",
                ],
                "trajectory_row_uses_pre_plant_output": True,
            },
            "diagnostic_provenance": collect_provenance(
                scenario_name=scenario.metadata.name,
                scenario_version=scenario.scenario_version,
                schema_version=1,
                test_seed=seed,
            ),
        }
        artifacts = write_evidence_artifacts(
            traces=traces,
            result=result,
            plaintext_raw_control=plaintext_raw,
            metadata=metadata,
            output_root=output_root,
            source_sweep_id=source.name,
            share_audit=share_audit,
            prepublish_validator=validate_source,
        )
    return artifacts


def _validate_definition(definition: dict[str, Any], frozen: Any, modulus: int) -> None:
    """确认仓库 definition 与已发布 sweep 的参数和来源没有漂移。"""
    expected = {
        "scenario_id": frozen.scenario_id,
        "fractional_bits": list(frozen.fractional_bits),
        "seeds": list(frozen.seeds),
        "primary_seed": frozen.primary_seed,
        "q": modulus,
        "source_hashes": dict(frozen.source_hashes),
        "stability_report_hash": frozen.stability_report_hash,
        "prime_evidence_hash": frozen.prime_evidence_hash,
    }
    for name, value in expected.items():
        if definition.get(name) != value:
            raise ValueError(f"已发布 sweep definition 的 {name} 与仓库冻结定义不一致。")


def _assert_exact_result(actual: Any, expected: Any) -> None:
    """逐字段同时锁定 dtype、shape 和 bitwise 数值，禁止自行放宽等价性。"""
    for name in _RESULT_FIELDS:
        first = np.asarray(getattr(actual, name))
        second = np.asarray(getattr(expected, name))
        if (
            first.dtype != second.dtype
            or first.shape != second.shape
            or not np.array_equal(first, second)
        ):
            raise ValueError(f"diagnostic reproduction 的 {name} 与 source run 不严格相等。")


def _validate_runtime_evidence(traces: tuple[Any, ...], cost: Any, selected_step: int) -> None:
    """核对 trace 完整性、选定状态证据及最终资源数与正式 summary。"""
    if len(traces) != 180 or tuple(item.step for item in traces) != tuple(range(180)):
        raise ValueError("正式 HVAC evidence 必须包含 180 个连续 step。")
    selected = [item for item in traces if item.state_transition is not None]
    if len(selected) != 1 or selected[0].step != selected_step:
        raise ValueError("state transition evidence 未绑定固定 selected step。")
    final = traces[-1].resources_after
    if (
        final.triples_created != cost.protocol1_triples_total
        or final.triples_consumed != cost.protocol1_triples_total
        or final.triples_aborted != 0
        or final.truncations_created != cost.protocol2_truncations_total
        or final.truncations_consumed != cost.protocol2_truncations_total
        or final.truncations_aborted != 0
    ):
        raise ValueError("runtime 真实资源累计与 source summary exact count 不一致。")
    for trace in traces:
        before, after = trace.resources_before, trace.resources_after
        if (
            after.triples_created - before.triples_created != trace.operations.protocol1_triples
            or after.triples_consumed - before.triples_consumed
            != trace.operations.protocol1_triples
            or after.truncations_created - before.truncations_created
            != trace.operations.state_truncation
            or after.truncations_consumed - before.truncations_consumed
            != trace.operations.state_truncation
        ):
            raise ValueError("每步真实资源 delta 与 StepResourcePlan 不一致。")


def _source_snapshot(sweep_dir: Path, ell: int, seed: int) -> dict[str, str]:
    """冻结 final/data manifest 与代表 run 三文件，防止诊断期间 TOCTOU。"""
    point_id = f"ell-{ell}-seed-{seed}"
    point_record = sweep_dir / "points" / point_id / "record.json"
    if not point_record.is_file():
        raise FileNotFoundError(point_record)
    point_payload = json.loads(point_record.read_text(encoding="utf-8"))
    artifact_path = point_payload.get("artifact_path")
    if not isinstance(artifact_path, str):
        raise TypeError("source point 没有成功 artifact_path。")
    run = (sweep_dir / artifact_path).resolve()
    if run.parent.parent.parent != sweep_dir.resolve() or not run.is_dir() or run.is_symlink():
        raise ValueError("source run path 不属于当前 sweep。")
    paths = {
        "manifest.json": sweep_dir / "manifest.json",
        "data_manifest.json": sweep_dir / "data_manifest.json",
        f"points/{point_id}/record.json": point_record,
        f"{artifact_path}/trajectory.csv": run / "trajectory.csv",
        f"{artifact_path}/metadata.json": run / "metadata.json",
        f"{artifact_path}/config.json": run / "config.json",
    }
    return {name: sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}


def main() -> None:
    """解析显式 combined-share 授权并输出新诊断目录，不打印任何 share。"""
    parser = argparse.ArgumentParser(description="Reproduce a frozen point with secure evidence")
    parser.add_argument("--source-sweep-id", required=True)
    parser.add_argument("--sweep-root", default="results/sweeps")
    parser.add_argument("--ell", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--trace-step", type=int, required=True)
    parser.add_argument("--output-root", default="results/diagnostics")
    parser.add_argument(
        "--definition",
        default="configs/hvac_2r2c_precision_sweep.yaml",
    )
    parser.add_argument(
        "--allow-combined-share-diagnostic",
        action="store_true",
        help="write one local short-lived combined-share audit marked deployment_security=false",
    )
    args = parser.parse_args()
    artifacts = run_evidence_diagnostic(
        sweep_dir=Path(args.sweep_root) / args.source_sweep_id,
        ell=args.ell,
        seed=args.seed,
        selected_step=args.trace_step,
        output_root=Path(args.output_root),
        allow_combined_share_diagnostic=args.allow_combined_share_diagnostic,
        definition_path=Path(args.definition),
    )
    print(
        json.dumps(
            {
                "trace_id": artifacts.trace_id,
                "directory": str(artifacts.directory),
                "manifest_sha256": artifacts.manifest_sha256,
                "private_audit_sha256": artifacts.private_audit_sha256,
                "deployment_security": False,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
