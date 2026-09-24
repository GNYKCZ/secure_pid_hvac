"""三终端 LAN 单步诊断及 Client 场景装配的连续实验命令。"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path

import numpy as np

from secure_control.execution.lan_config import LanConfig, load_lan_config
from secure_control.execution.lan_runtime import (
    LanContinuousRuntime,
    run_client_single_step,
    run_party_single_step,
)
from secure_control.execution.lan_transport import (
    LanConnectionError,
    LanIdentityError,
    LanTimeoutError,
)
from secure_control.execution.localhost_codec import LocalhostCodecError
from secure_control.execution.localhost_transport import (
    LocalhostTransportDisconnected,
    LocalhostTransportTimeout,
)
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.scenarios.paper_pid.baseline import run_paper_pid_baseline
from secure_control.scenarios.paper_pid.secure_experiment import (
    assemble_paper_pid_plan,
    paper_pid_numeric_contract,
)
from secure_control.simulation import compare_closed_loops

from .artifacts import SCHEMA_VERSION, load_artifacts, write_artifacts
from .lan_profile import load_paper_pid_lan_profile
from .paper_pid_fig3 import SCENARIO_VERSION, load_definition
from .plotting import redraw_control_triptych, verify_control_triptych, write_control_triptych
from .provenance import collect_provenance


def _failure(role: str, code: int, category: str, error: Exception) -> int:
    print(
        json.dumps(
            {
                "status": "failed",
                "role": role,
                "pid": os.getpid(),
                "category": category,
                "error_type": type(error).__name__,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return code


def cli() -> None:
    """pyproject 命令入口：配置错误 2、连接 3、身份/协议 4、不确定/超时 5。"""
    raise SystemExit(_run())


def run_client_continuous(config: LanConfig) -> dict[str, object]:
    """先预检 Client 场景，后建立单 session 多步 LAN，并一次性发布正式图。"""
    if config.experiment_config is None:
        raise ValueError("缺少 Client experiment profile。")
    profile = load_paper_pid_lan_profile(config.experiment_config)
    spec, context, contract = paper_pid_numeric_contract(
        fractional_bits=profile.ell, parameter_bits=profile.parameter_bits,
        runtime_payload_bits=profile.runtime_payload_bits, modulus=profile.q,
        sample_count=profile.sample_count,
        measurement_absolute_bound=profile.measurement_absolute_bound,
    )
    runtime = LanContinuousRuntime(config, spec, context, contract,
                                   profile.security_parameter, profile.evidence)
    try:
        plan = assemble_paper_pid_plan(spec, runtime, profile.sample_count)
        result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
        if max(np.max(np.abs(result.output_ideal)),
               np.max(np.abs(result.output_secure))) > profile.measurement_absolute_bound:
            raise ValueError("plant y 超出声明的有限时域输入界。")
        definition, baseline_config, _, _ = load_definition(profile.definition_path)
        baseline = run_paper_pid_baseline(
            alpha=baseline_config["plant"]["alpha"],
            sample_period_seconds=baseline_config["plant"]["sample_period_seconds"],
            plant_initial_state=baseline_config["plant"]["initial_state"],
            sample_count=profile.sample_count,
        )
        np.testing.assert_allclose(result.output_ideal[:, 0], baseline.rows[:, 6],
                                   rtol=0, atol=1e-12)
        np.testing.assert_allclose(result.control_ideal[:, 0], baseline.rows[:, 9],
                                   rtol=0, atol=1e-12)
        if runtime.scale_ledger.state_truncation_bits != profile.ell:
            raise ValueError("Protocol 2 截断尺度与 profile ell 不符。")
        counts = runtime.resource_counts
        confirmed = runtime.confirmed_steps
        if len(confirmed) != profile.sample_count or any(
            item["step"] != index or item["status"] != "double_committed"
            for index, item in enumerate(confirmed)
        ):
            raise ValueError("LAN 逐步双提交确认不完整。")
        if profile.sample_count == definition["sample_count"] and counts != {
            "products_consumed": 9 * profile.sample_count,
            "truncations_consumed": 2 * profile.sample_count,
        }:
            raise ValueError("实际资源消费与逐步 Protocol 3 计划不符。")
        runtime.finish()
    finally:
        runtime.close()
    effective = {
        "scenario": {"name": "paper_pid_fig3", "version": SCENARIO_VERSION},
        "fractional_bits": profile.ell, "paper_parameter_bits": profile.parameter_bits,
        "runtime_payload_bits": profile.runtime_payload_bits,
        "security_parameter": profile.security_parameter, "q": profile.q,
        "sample_count": profile.sample_count,
        "range": {"mode": "finite_horizon", "steps": profile.sample_count,
                  "measurement_absolute_bound": profile.measurement_absolute_bound},
        "reference_used": False, "raw_equals_applied": True,
        "claim_level": profile.claim_level,
        "profile_sha256": profile.digest,
        "prime_source_sha256": profile.prime_digest,
        "frozen_definition_sha256": profile.definition_digest,
        "definition": definition,
        "baseline_plant": baseline_config["plant"],
        "controller_spec": {
            name: getattr(spec, name).tolist() for name in ("A", "B", "C", "D", "x0")
        },
    }
    provenance = collect_provenance(
        scenario_name="paper_pid_fig3", scenario_version=SCENARIO_VERSION,
        schema_version=SCHEMA_VERSION, test_seed=None,
    )
    provenance.update({
        "backend": "lan_continuous", "claim_level": profile.claim_level,
        "session_id": runtime.session_id, "client_pid": os.getpid(),
        "topology_sha256": config.topology.digest,
        "resource_counts": counts,
        "confirmed_steps": confirmed,
        "prime_verification": asdict(runtime.modulus_verification),
        "range_verification": asdict(runtime.range_verification),
        "scale_ledger": asdict(runtime.scale_ledger),
        "kappa": profile.q.bit_length() - profile.security_parameter - 2,
        "security_boundary": "local three-terminal TLS; no real three-machine validation",
    })
    artifact = write_artifacts(
        result, plan.metadata, effective, provenance, output_root=profile.output_root,
        derived_writer=lambda record, stage: write_control_triptych(
            record, stage, profile.control_channel
        ),
    )
    record = load_artifacts(artifact.run_dir)
    verify_control_triptych(record, artifact.run_dir)
    if record.run_id != artifact.run_id or record.result.time.size != profile.sample_count:
        raise ValueError("发布后的 run 身份或行数不符。")
    return {
        "status": "complete", "role": "Client", "pid": os.getpid(),
        "topology_sha256": config.topology.digest,
        "session_id": runtime.session_id, "run_id": artifact.run_id,
        "run_dir": str(artifact.run_dir), "sample_count": profile.sample_count,
        "resource_counts": counts, "tls_version": "TLSv1.3",
    }


def _run() -> int:
    parser = argparse.ArgumentParser(prog="secure-control", description="Authenticated LAN experiment")
    commands = parser.add_subparsers(dest="role", required=True)
    for role in ("p1", "p2", "client"):
        command = commands.add_parser(role)
        command.add_argument("--config", required=True, type=Path)
    redraw = commands.add_parser("redraw")
    redraw.add_argument("--run-dir", required=True, type=Path)
    redraw.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.role == "redraw":
        try:
            target = redraw_control_triptych(args.run_dir, args.output)
        except (ValueError, TypeError, OSError) as error:
            return _failure("Client", 2, "verified_redraw", error)
        print(json.dumps({"status": "complete", "figure": str(target)},
                         ensure_ascii=False, sort_keys=True))
        return 0
    role = {"p1": "P1", "p2": "P2", "client": "Client"}[args.role]
    try:
        config = load_lan_config(args.config, role)
        trial = (HvacScenario(config.controller_config).build_lan_single_step()
                 if role == "Client" and config.controller_config is not None else None)
        if role == "Client" and config.experiment_config is not None:
            load_paper_pid_lan_profile(config.experiment_config)
    except (ValueError, TypeError, OSError) as error:
        return _failure(role, 2, "configuration", error)
    try:
        result = (
            (run_client_continuous(config) if config.experiment_config is not None
             else run_client_single_step(config, trial))
            if role == "Client"
            else run_party_single_step(config)
        )
    except LanConnectionError as error:
        return _failure(role, 3, "connection", error)
    except (LanIdentityError, LocalhostCodecError, ValueError, TypeError) as error:
        return _failure(role, 4, "identity_or_protocol", error)
    except (
        LanTimeoutError,
        LocalhostTransportTimeout,
        LocalhostTransportDisconnected,
        TimeoutError,
        RuntimeError,
        OSError,
    ) as error:
        return _failure(role, 5, "uncertain_or_disconnected", error)
    except Exception as error:  # noqa: BLE001 - CLI 不把意外异常的 payload/traceback 输出到日志
        return _failure(role, 5, "uncertain_or_disconnected", error)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0
