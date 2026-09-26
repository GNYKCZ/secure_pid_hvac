"""三终端 LAN 单步诊断及 Client 场景装配的连续实验命令。"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import asdict
from pathlib import Path
from threading import Event

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
from secure_control.simulation import compare_closed_loops

from .artifacts import SCHEMA_VERSION, _write_artifacts, load_artifacts
from .lan_continuous_profile import PreparedLanExperiment, load_prepared_lan_experiment
from .plotting import redraw_control_triptych, verify_control_triptych, write_control_triptych
from .provenance import collect_provenance

_LAN_LOG = logging.getLogger("secure_control.lan")


def _enable_terminal_progress() -> None:
    """只在 CLI 启用可读进度；正式结果仍是 stdout 的单行 JSON。"""
    if not _LAN_LOG.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _LAN_LOG.addHandler(handler)
    _LAN_LOG.setLevel(logging.INFO)
    _LAN_LOG.propagate = False


def _failure(role: str, code: int, category: str, error: Exception) -> int:
    _LAN_LOG.error("%s 运行失败：%s（%s）。", role, category, type(error).__name__)
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
    experiment = load_prepared_lan_experiment(config.experiment_config)
    return _run_prepared_client(config, experiment)


def _run_prepared_client(config: LanConfig, experiment: PreparedLanExperiment,
                         *, phase: Callable[[str], None] | None = None,
                         cancelled: Event | None = None,
                         publication_guard: Callable[[], AbstractContextManager[None]]
                         | None = None) -> dict[str, object]:
    """通用会话/资源/正式发布只保留一份；交互入口仅换执行计划。"""
    def check_cancelled() -> None:
        if cancelled is not None and cancelled.is_set():
            raise RuntimeError("Client 运行已取消。")

    check_cancelled()
    if phase is not None:
        phase("connecting")
    runtime = LanContinuousRuntime(
        config, experiment.spec, experiment.context, experiment.contract,
        experiment.security_parameter, experiment.evidence,
    )
    try:
        check_cancelled()
        if phase is not None:
            phase("connected")
        plan = experiment.build_plan(runtime)
        if phase is not None:
            phase("running")
        result = (experiment.execute_plan(plan) if experiment.execute_plan is not None
                  else compare_closed_loops(plan.ideal, plan.secure, plan.sample_times))
        check_cancelled()
        if phase is not None:
            phase("verifying")
        experiment.validate_result(result)
        if runtime.scale_ledger.state_truncation_bits != experiment.expected_state_truncation_bits:
            raise ValueError("Protocol 2 截断尺度与场景契约不符。")
        spec = experiment.spec
        products_per_step = sum(getattr(spec, name).size for name in ("A", "B", "C", "D"))
        truncations_per_step = (spec.state_dimension
                                if experiment.expected_state_truncation_bits else 0)
        counts = runtime.resource_counts
        confirmed = runtime.confirmed_steps
        if len(confirmed) != experiment.sample_count or any(
            item != {"step": index, "status": "double_committed",
                     "products": products_per_step, "truncations": truncations_per_step}
            for index, item in enumerate(confirmed)
        ):
            raise ValueError("LAN 逐步双提交确认不完整。")
        if counts != {
            "products_consumed": products_per_step * experiment.sample_count,
            "truncations_consumed": truncations_per_step * experiment.sample_count,
        }:
            raise ValueError("实际资源消费与逐步 Protocol 3 计划不符。")
        experiment.recheck_sources()
        check_cancelled()
        runtime.finish()
    finally:
        runtime.close()
    provenance = collect_provenance(
        scenario_name=experiment.scenario_name,
        scenario_version=experiment.scenario_version,
        schema_version=SCHEMA_VERSION, test_seed=None,
    )
    provenance.update({
        "backend": "lan_continuous", "claim_level": experiment.claim_level,
        "session_id": runtime.session_id, "client_pid": os.getpid(),
        "topology_sha256": config.topology.digest,
        "transport": config.transport,
        "resource_counts": counts,
        "confirmed_steps": confirmed,
        "prime_verification": asdict(runtime.modulus_verification),
        "range_verification": asdict(runtime.range_verification),
        "scale_ledger": asdict(runtime.scale_ledger),
        "kappa": experiment.q.bit_length() - experiment.security_parameter - 2,
        "security_boundary": (
            "local three-terminal TLS; no real three-machine validation"
            if config.transport == "mutual_tls" else
            "unauthenticated plaintext TCP lab simulation; no authenticated LAN claim"
        ),
    })
    def derived_writer(record, stage):
        """一份正式 staging 同时收纳通用 applied 图和可选场景证据。"""
        names = write_control_triptych(record, stage, experiment.control_channel)
        if experiment.write_scenario_evidence is not None:
            names += experiment.write_scenario_evidence(record, stage)
        check_cancelled()
        return names

    check_cancelled()
    artifact = _write_artifacts(
        result, plan.metadata, experiment.effective_config, provenance,
        output_root=experiment.output_root,
        derived_writer=derived_writer,
        publication_guard=publication_guard,
    )
    record = load_artifacts(artifact.run_dir)
    verify_control_triptych(record, artifact.run_dir)
    if experiment.verify_scenario_run is not None:
        experiment.verify_scenario_run(artifact.run_dir)
    if record.run_id != artifact.run_id or record.result.time.size != experiment.sample_count:
        raise ValueError("发布后的 run 身份或行数不符。")
    return {
        "status": "complete", "role": "Client", "pid": os.getpid(),
        "topology_sha256": config.topology.digest,
        "session_id": runtime.session_id, "run_id": artifact.run_id,
        "run_dir": str(artifact.run_dir),
        "figure_path": str((artifact.run_dir / "control.png").resolve()),
        "scenario": experiment.scenario_name, "ell": experiment.ell,
        "claim_level": experiment.claim_level, "sample_count": experiment.sample_count,
        "resource_counts": counts, "transport": config.transport,
        "tls_version": "TLSv1.3" if config.transport == "mutual_tls" else None,
    }


def _run() -> int:
    parser = argparse.ArgumentParser(prog="secure-control", description="Three-role LAN experiment")
    commands = parser.add_subparsers(dest="role", required=True)
    for role in ("p1", "p2", "client"):
        command = commands.add_parser(role)
        command.add_argument("--config", required=True, type=Path)
    redraw = commands.add_parser("redraw")
    redraw.add_argument("--run-dir", required=True, type=Path)
    redraw.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _enable_terminal_progress()
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
            load_prepared_lan_experiment(config.experiment_config)
    except (ValueError, TypeError, OSError) as error:
        return _failure(role, 2, "configuration", error)
    mode = "无证书实验连接" if config.transport == "insecure_tcp" else "TLS 认证连接"
    _LAN_LOG.info("%s 配置检查通过，开始运行（%s）。", role, mode)
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
    if role == "Client":
        _LAN_LOG.info("Client 运行完成，图已保存：%s", result.get("figure_path", "单步模式无图"))
    else:
        _LAN_LOG.info("%s 运行完成，已提交 %s 步。", role, result.get("steps_committed", 1))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    cli()
