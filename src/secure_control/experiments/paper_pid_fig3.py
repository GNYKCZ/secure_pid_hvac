"""#70 四精度 paper-inspired 双闭环扫描及只读结果绘图。"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import matplotlib
import numpy as np
import yaml

from secure_control.crypto import (
    PrimeModulusEvidence,
    verify_prime_modulus,
)
from secure_control.execution import LocalhostSecureStateSpaceRuntime
from secure_control.scenarios.paper_pid.baseline import run_paper_pid_baseline
from secure_control.scenarios.paper_pid.secure_experiment import (
    SCENARIO_VERSION,
    build_paper_pid_plan,
)
from secure_control.simulation import compare_closed_loops

from .artifacts import SCHEMA_VERSION, ExperimentRecord, load_artifacts, write_artifacts
from .paper_pid_sources import load_baseline_config, parse_prime_certificate
from .provenance import collect_provenance

matplotlib.use("Agg")
from matplotlib import pyplot as plt

PRECISIONS = (32, 40, 48, 56)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_definition(path: str | Path) -> tuple[dict[str, Any], dict[str, Any], int, PrimeModulusEvidence]:
    """锁定 #69 对象、256-bit 证书及论文点；任何漂移在运行前失败。"""
    definition_path = Path(path)
    definition = yaml.safe_load(definition_path.read_text(encoding="utf-8"))
    required = {"schema_version", "claim_level", "baseline_config", "baseline_sha256",
                "prime_config", "prime_sha256", "fractional_bits",
                "paper_parameter_headroom_bits", "runtime_payload_headroom_bits",
                "security_parameter", "measurement_absolute_bound", "epsilon",
                "sample_count", "reference_channel"}
    if not isinstance(definition, dict) or set(definition) != required:
        raise ValueError("Fig.3 定义字段无效")
    fixed = {
        "schema_version": 1, "claim_level": "paper-inspired", "fractional_bits": list(PRECISIONS),
        "paper_parameter_headroom_bits": 8, "runtime_payload_headroom_bits": 14,
        "security_parameter": 80, "measurement_absolute_bound": 128,
        "epsilon": 2**-10, "sample_count": 51, "reference_channel": "unused_zero",
    }
    if any(type(definition[key]) is not type(value) or definition[key] != value
           for key, value in fixed.items()):
        raise ValueError("Fig.3 冻结参数或声明等级漂移")
    for key in ("baseline_config", "prime_config"):
        if not isinstance(definition[key], str) or Path(definition[key]).name != definition[key]:
            raise ValueError("来源必须是同目录的配置文件名")
    baseline_path = definition_path.parent / definition["baseline_config"]
    prime_path = definition_path.parent / definition["prime_config"]
    if (_digest(baseline_path) != definition["baseline_sha256"] or
            _digest(prime_path) != definition["prime_sha256"]):
        raise ValueError("paper PID 或 prime 来源摘要漂移")
    baseline, _ = load_baseline_config(baseline_path)
    prime = yaml.safe_load(prime_path.read_text(encoding="utf-8"))
    if not isinstance(prime, dict) or set(prime) != {"modulus", "evidence"}:
        raise ValueError("prime 配置无效")
    q, source = prime["modulus"], prime["evidence"]
    if type(q) is not int or q.bit_length() != 256 or not isinstance(source, dict):
        raise ValueError("必须使用已证实的 256-bit q")
    if set(source) != {"method", "source", "source_version", "certificate_id",
                       "certificate_sha256", "certificate"}:
        raise ValueError("prime evidence 字段无效")
    evidence = PrimeModulusEvidence(
        source["method"], source["source"], source["source_version"],
        source["certificate_id"], source["certificate_sha256"],
        parse_prime_certificate(source["certificate"]),
    )
    verify_prime_modulus(q, evidence)
    return definition, baseline, q, evidence


def _validate_record(record: ExperimentRecord, ell: int, definition: dict[str, Any]) -> dict[str, Any]:
    """绘图前逐点复验身份、时序、占位通道和 raw 控制误差。"""
    result = record.result
    config, provenance = record.effective_config, record.provenance
    if (record.metadata.name != "paper_pid_fig3" or
            config.get("scenario") != {"name": "paper_pid_fig3", "version": SCENARIO_VERSION} or
            config.get("fractional_bits") != ell or config.get("definition") != definition or
            config.get("reference_used") is not False or
            config.get("raw_equals_applied") is not True or
            config.get("paper_parameter_bits") != ell + definition["paper_parameter_headroom_bits"] or
            config.get("runtime_payload_bits") != ell + definition["runtime_payload_headroom_bits"] or
            config.get("range") != {"mode": "finite_horizon", "steps": definition["sample_count"],
                                    "measurement_absolute_bound": definition["measurement_absolute_bound"]} or
            provenance.get("prime_verification", {}).get("modulus") != config.get("q") or
            provenance.get("prime_verification", {}).get("status") != "verified" or
            provenance.get("kappa") != config.get("q", 0).bit_length() - definition["security_parameter"] - 2 or
            provenance.get("scale_ledger", {}).get("state_truncation_bits") != ell or
            provenance.get("claim_level") != "paper-inspired"):
        raise ValueError("Fig.3 run 身份、来源或精度不符")
    if result.time.shape != (51,) or not np.allclose(result.time, np.arange(51)*0.1,
                                                     rtol=0, atol=1e-15):
        raise ValueError("Fig.3 时间网格不符")
    if any(getattr(result, name).shape != (51, 1)
           for name in ("reference", "output_ideal", "output_secure",
                        "control_ideal", "control_secure", "control_error")):
        raise ValueError("Fig.3 必须是 51 点 SISO")
    if not np.array_equal(result.reference, np.zeros((51, 1))):
        raise ValueError("unused_zero 只能是恒零占位")
    error = np.abs(result.control_ideal[:, 0] - result.control_secure[:, 0])
    if not np.array_equal(error, np.abs(result.control_error[:, 0])):
        raise ValueError("Fig.3 误差必须由 raw u 与 uhat 重算")
    maximum = float(np.max(error))
    resolution = float(np.max(np.spacing(np.maximum(np.abs(result.control_ideal[:, 0]),
                                                  np.abs(result.control_secure[:, 0])))))
    return {"ell": ell, "run_id": record.run_id, "max_error": maximum,
            "below_epsilon": maximum < definition["epsilon"],
            "binary64_ulp_upper": resolution,
            "below_numeric_resolution": bool(np.any((error > 0) & (error <= resolution)) or
                                             np.all(error == 0))}


def _render(records: list[ExperimentRecord], definition: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    summaries = [_validate_record(record, ell, definition)
                 for ell, record in zip(PRECISIONS, records)]
    fig, ax = plt.subplots(figsize=(9, 5))
    for summary, record in zip(summaries, records):
        error = np.abs(record.result.control_error[:, 0])
        ax.plot(np.arange(51), error, marker=".", markersize=3,
                label=f"ell={summary['ell']} (max={summary['max_error']:.3g})")
    ax.axhline(definition["epsilon"], color="black", linestyle="--", label="epsilon=2^-10")
    ax.set_yscale("symlog", linthresh=1e-14)
    ax.set_xlabel("sample k (0..50); Ts=0.1 s")
    ax.set_ylabel("|raw u - reconstructed u| (paper unit unspecified)")
    ax.set_title("Paper-inspired cascade ZOH; not authors' original Fig. 3 plant")
    ax.legend()
    ax.grid(True, which="both", alpha=0.3)
    fig.text(0.01, 0.01, "Zero is shown at zero; binary64 may hide ell=48/56 differences.",
             fontsize=8)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return summaries


def render_saved_sweep(sweep_dir: str | Path) -> dict[str, Any]:
    """仅从四个成功 run 的 reader 重建图，拒绝缺点及 run/manifest 篡改。"""
    root = Path(sweep_dir)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"definition", "runs", "summaries", "figure_sha256"}:
        raise ValueError("Fig.3 清单无效")
    definition = manifest["definition"]
    if tuple(definition.get("fractional_bits", ())) != PRECISIONS or len(manifest["runs"]) != 4:
        raise ValueError("Fig.3 必须包含四个精度")
    records = []
    for ell, entry in zip(PRECISIONS, manifest["runs"]):
        if (entry.get("ell") != ell or entry.get("status") != "success" or
                not isinstance(entry.get("run_id"), str)):
            raise ValueError("Fig.3 run 顺序或精度不符")
        record = load_artifacts(root / entry["run_id"])
        if (_digest(root / entry["run_id"] / "metadata.json") != entry.get("metadata_sha256") or
                record.run_id != entry["run_id"]):
            raise ValueError("Fig.3 run 摘要不符")
        records.append(record)
    if len({record.effective_config["q"] for record in records}) != 1 or len({
        (record.provenance.get("backend"), record.provenance.get("secure_material_randomness"),
         json.dumps(record.provenance.get("configured_seeds"), sort_keys=True))
        for record in records
    }) != 1:
        raise ValueError("Fig.3 四点 q/backend/随机性模式必须一致")
    with TemporaryDirectory() as temporary:
        generated = Path(temporary) / "fig3.png"
        summaries = _render(records, definition, generated)
        if summaries != manifest["summaries"]:
            raise ValueError("Fig.3 派生指标不符")
    if _digest(root / "fig3.png") != manifest["figure_sha256"]:
        raise ValueError("Fig.3 已发布图摘要不符")
    return manifest


def run_sweep(config_path: str | Path, *, output_root: str | Path,
              test_seed: int = 70, backend: str = "single_process") -> Path:
    """逐点正式发布，四点全部成功后才发布完整图与清单。"""
    if type(test_seed) is not int:
        raise TypeError("正式诊断扫描需要整数 test_seed")
    definition, baseline_config, q, evidence = load_definition(config_path)
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise FileExistsError("Fig.3 输出目录必须为空")
    baseline = run_paper_pid_baseline(
        alpha=baseline_config["plant"]["alpha"],
        sample_period_seconds=baseline_config["plant"]["sample_period_seconds"],
        plant_initial_state=baseline_config["plant"]["initial_state"],
        sample_count=definition["sample_count"],
    )
    records = []
    entries = []
    for ell in PRECISIONS:
        plan, runtime, collector = build_paper_pid_plan(
            fractional_bits=ell, modulus=q, modulus_evidence=evidence,
            security_parameter=definition["security_parameter"],
            sample_count=definition["sample_count"],
            measurement_absolute_bound=definition["measurement_absolute_bound"],
            runtime_payload_headroom_bits=definition["runtime_payload_headroom_bits"],
            test_seed=test_seed, backend=backend,
        )
        try:
            result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
            np.testing.assert_allclose(result.output_ideal[:, 0], baseline.rows[:, 6], rtol=0, atol=1e-12)
            np.testing.assert_allclose(result.control_ideal[:, 0], baseline.rows[:, 9], rtol=0, atol=1e-12)
            if max(np.max(np.abs(result.output_ideal)), np.max(np.abs(result.output_secure))) > definition["measurement_absolute_bound"]:
                raise ValueError("plant y 超出声明的有限时域输入界")
            if runtime.scale_ledger.state_truncation_bits != ell:
                raise ValueError("Protocol 2 截断尺度与论文 ell 不符")
            if isinstance(runtime, LocalhostSecureStateSpaceRuntime):
                counts = runtime.resource_counts
                topology = runtime.topology
                role_pids = {item.role: item.pid for item in topology.roles}
            else:
                if collector is None or len(collector.traces()) != 51:
                    raise ValueError("缺少完整真实资源 trace")
                final = collector.traces()[-1].resources_after
                counts = {"products_consumed": final.triples_consumed,
                          "truncations_consumed": final.truncations_consumed}
                role_pids = None
            if counts != {"products_consumed": 459, "truncations_consumed": 102}:
                raise ValueError("实际资源消费与 Protocol 3 计划不符")
            config = {
                "scenario": {"name": "paper_pid_fig3", "version": SCENARIO_VERSION},
                "definition": definition, "fractional_bits": ell,
                "paper_parameter_bits": ell + 8,
                "runtime_payload_bits": ell + definition["runtime_payload_headroom_bits"],
                "q": q, "reference_used": False, "raw_equals_applied": True,
                "range": {"mode": "finite_horizon", "steps": 51,
                          "measurement_absolute_bound": 128},
            }
            provenance = collect_provenance(
                scenario_name="paper_pid_fig3", scenario_version=SCENARIO_VERSION,
                schema_version=SCHEMA_VERSION, test_seed=test_seed,
            )
            provenance.update({"claim_level": "paper-inspired", "backend": backend,
                               "resource_counts": counts, "role_pids": role_pids,
                               "prime_certificate_sha256": evidence.certificate_sha256,
                               "prime_verification": asdict(runtime.modulus_verification),
                               "range_verification": asdict(runtime.range_verification),
                               "scale_ledger": asdict(runtime.scale_ledger),
                               "kappa": q.bit_length() - definition["security_parameter"] - 2,
                               "security_boundary": "diagnostic seed; no deployment security claim"})
            artifact = write_artifacts(result, plan.metadata, config, provenance,
                                       output_root=root)
            record = load_artifacts(artifact.run_dir)
            records.append(record)
            entries.append({"ell": ell, "status": "success", "run_id": artifact.run_id,
                            "metadata_sha256": _digest(artifact.metadata_path)})
        finally:
            if isinstance(runtime, LocalhostSecureStateSpaceRuntime):
                runtime.close()
    try:
        with TemporaryDirectory(dir=root, prefix=".incomplete-") as temporary:
            figure = Path(temporary) / "fig3.png"
            summaries = _render(records, definition, figure)
            manifest = {"definition": definition, "runs": entries, "summaries": summaries,
                        "figure_sha256": _digest(figure)}
            (Path(temporary) / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8")
            os.replace(figure, root / "fig3.png")
            os.replace(Path(temporary) / "manifest.json", root / "manifest.json")
        render_saved_sweep(root)
    except Exception:
        # 单点目录仍可审计，但不存在可被误读为“四点完成”的图或清单。
        (root / "manifest.json").unlink(missing_ok=True)
        (root / "fig3.png").unlink(missing_ok=True)
        raise
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description="Run or verify paper-inspired Fig.3 comparison")
    parser.add_argument("--config", default="configs/paper_pid_fig3_sweep.yaml")
    parser.add_argument("--output-root", default="results/paper_pid_fig3")
    parser.add_argument("--seed", type=int, default=70)
    parser.add_argument("--backend", choices=("single_process", "localhost"), default="single_process")
    parser.add_argument("--verify-dir", help="verify saved four-run artifact without execution")
    args = parser.parse_args()
    result = (render_saved_sweep(args.verify_dir) if args.verify_dir else
              render_saved_sweep(run_sweep(args.config, output_root=args.output_root,
                                           test_seed=args.seed, backend=args.backend)))
    print(json.dumps(result["summaries"], ensure_ascii=False))


if __name__ == "__main__":
    main()
