"""三终端 LAN 单步诊断及 Client 场景装配的连续实验命令。"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event
from time import perf_counter, perf_counter_ns

from secure_control.execution.cycle_timing import (
    AbsoluteCycleClock,
    CycleDeadlineExceeded,
    CycleTiming,
    check_deadline,
)
from secure_control.execution.lan_config import LanConfig, load_lan_config
from secure_control.execution.lan_runtime import (
    LanContinuousRuntime,
    LanSegmentedRuntime,
    RunControl,
    SegmentedStep,
    SegmentRecord,
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
from .lan_continuous_profile import (
    PreparedLanExperiment,
    load_prepared_lan_experiment,
    load_segmented_experiment,
)
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
    progress = getattr(error, "_public_lan_progress", None)
    report = {
        "status": "uncertain" if isinstance(progress, dict) and progress.get("uncertain")
                  else "failed",
        "role": role, "pid": os.getpid(), "category": category,
        "error_type": type(error).__name__,
    }
    if isinstance(progress, dict):
        report["progress"] = progress
    print(
        json.dumps(
            report,
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


@dataclass(frozen=True, slots=True)
class ConfirmedStep:
    """双方协议提交与场景物理推进均已确认的公开记录。"""

    protocol: SegmentedStep
    snapshot: object
    double_committed: bool = True
    physically_confirmed: bool = True


@dataclass(frozen=True, slots=True)
class CompletedSegment:
    """双方结束确认后可交给 #101 的有界公开段，接收方负责持久保存。"""

    protocol: SegmentRecord
    steps: tuple[ConfirmedStep, ...]


def run_client_segmented(config: LanConfig, *, segment_steps: int = 400,
                         control: RunControl,
                         on_step: Callable[[ConfirmedStep], None] | None = None,
                         on_segment: Callable[[CompletedSegment], None] | None = None,
                         phase: Callable[[str], None] | None = None,
                         session=None, preload_steps=0, preload_execution="fused") -> dict[str, object]:
    """运行到正常停止请求或故障；不将后端 stopped 冒充正式 artifact complete。"""
    # 队列与场景选择由装配层拥有；核心仅处理协议身份、双提交及确认前缀。
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    if config.experiment_config is None:
        raise ValueError("持续 Client 缺少 experiment profile。")
    session = InteractiveSession() if session is None else session
    if not isinstance(session, InteractiveSession) or not isinstance(control, RunControl):
        raise TypeError("持续模式需要 RunControl 和 InteractiveSession。")
    experiment = load_segmented_experiment(config.experiment_config, segment_steps, session)
    return _run_prepared_segmented(config, experiment, control=control, session=session,
                                   on_step=on_step, on_segment=on_segment, phase=phase,
                                   preload_steps=preload_steps, preload_execution=preload_execution)


def _run_prepared_segmented(config, experiment, *, control, session,
                            on_step=None, on_segment=None, on_start=None,
                            phase=None, realtime=None, material_slots=16,
                            on_cycle=None, cycle_snapshot=None,
                            before_sample=None, preload_steps=0,
                            preload_execution="fused") -> dict[str, object]:
    """唯一持续循环接收已装配场景；保存/GUI 与 headless 不重复 parse 或创建 plant。"""
    control.bind_stop(session.reject_new)
    if preload_steps and material_slots != 16:
        raise ValueError("预送窗口与显式非默认material_slots互斥")
    runtime = None
    records: list[ConfirmedStep] = []
    phase_name = "CONNECTING"
    clock = None
    attempt = None
    cycle_count = misses = 0
    last_cycle = None
    startup_gc = None

    def emit_cycle(status, failure_phase=None):
        """成功和失败尝试走同一公开出口，失败不能丢掉首步/边界样本。"""
        nonlocal attempt, cycle_count, misses, last_cycle
        if attempt is None:
            return
        lifecycle = runtime.snapshot()
        external = cycle_snapshot() if cycle_snapshot is not None else {}
        timing = CycleTiming(
            run_id=attempt["run_id"], session_id=attempt["session_id"],
            controller_epoch=attempt["controller_epoch"],
            segment_index=attempt["segment_index"], global_step=attempt["step"],
            round_id=attempt.get("round_id") or lifecycle.attempted_round_id,
            period_ns=clock.period_ns, scheduled_start_ns=attempt["scheduled"],
            actual_sample_start_ns=attempt.get("sample"), deadline_ns=attempt["deadline"],
            device_completed_ns=attempt.get("device"),
            bookkeeping_completed_ns=attempt.get("bookkeeping"),
            cycle_completed_ns=perf_counter_ns() if status == "confirmed" else None,
            status=status, failure_phase=failure_phase,
            protocol_committed_count=lifecycle.protocol_committed_count,
            physically_confirmed_count=lifecycle.physically_confirmed_count,
            durable_step_count=external.get("durable_step_count", 0),
            phase_durations_ns=attempt["durations"],
            queue_levels={**runtime.cycle_queue_levels,
                          **{k: v for k, v in external.items() if k != "durable_step_count"}},
        )
        cycle_count += 1
        misses += status in {"miss_before_apply", "miss_after_apply"}
        last_cycle = asdict(timing)
        attempt = None
        if on_cycle is not None:
            on_cycle(timing)

    def transition(deadline_ns=None):
        """段结束、源核查和段开始同属原周期；正常停止在控制计时之后确认。"""
        progress("ENDING_SEGMENT", "STOPPING" if control.stop_requested else None)
        segment = (runtime.end_segment() if deadline_ns is None
                   else runtime.end_segment(deadline_ns=deadline_ns))
        if session.cancelled.is_set():
            raise RuntimeError("Client 运行已取消。")
        progress("RECORDING_SEGMENT")
        if on_segment is not None:
            on_segment(CompletedSegment(segment, tuple(records)))
        records.clear()
        check_deadline(deadline_ns, "RECORDING_SEGMENT")
        if runtime.phase == "STOPPED":
            experiment.recheck_sources()
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            return {
                "status": "stopped", "stop_reason": (
                    "preload_exhausted" if preload_steps and runtime.confirmed_step_count == preload_steps
                    else "user_requested"),
                "role": "Client", "pid": os.getpid(), "run_id": runtime.run_id,
                "confirmed_step_count": runtime.confirmed_step_count,
                "protocol_committed_count": runtime.protocol_committed_count,
                "next_global_step": runtime.confirmed_step_count,
                **experiment.scene.terminal_summary(),
                "resource_counts": runtime.resource_counts,
                "final_segment": asdict(segment), "transport": config.transport,
                "cycle_summary": {"attempts": cycle_count, "misses": misses,
                                  "last_cycle": last_cycle},
                "material_summary": getattr(runtime, "material_summary", runtime.cycle_queue_levels),
                "startup_gc": startup_gc,
            }
        progress("CONNECTING_NEXT")
        experiment.recheck_sources()
        check_deadline(deadline_ns, "SOURCE_CHECK")
        if deadline_ns is None:
            runtime.next_segment()
        else:
            runtime.next_segment(deadline_ns=deadline_ns)
        progress("RUNNING")
        return None

    def progress(value, display=None):
        """处理实际进入该阶段后才发通知，失败出口保留同一阶段事实。"""
        nonlocal phase_name
        phase_name = value
        if phase is not None:
            phase(display if display is not None else value)

    try:
        progress("CONNECTING")
        experiment.recheck_sources()
        runtime = LanSegmentedRuntime(
            config, experiment.spec, experiment.context, experiment.contract,
            experiment.security_parameter, experiment.evidence, control=control,
            segment_capacity=(experiment.segment_capacity
                              if experiment.spec.state_dimension else None),
            preload_steps=preload_steps, preload_execution=preload_execution,
        )
        if on_start is not None:
            on_start(runtime.snapshot(), runtime.public_setup)
        dynamic_realtime = experiment.spec.state_dimension != 0 if realtime is None else realtime
        if preload_steps:
            progress("PRELOADING")
            runtime.enable_material_preload(cancelled=lambda: session.cancelled.is_set()
                                           or control.stop_requested)
        if dynamic_realtime:
            if material_slots and not preload_steps:
                runtime.enable_material_preparation(slots=material_slots)
            # 所有固定验证、建连、writer 初始化与首池填充完成后才确定唯一 t0。
            # 收集初始化暂存垃圾；运行中的自动 GC/阈值保持原样，不转移周期内的工作。
            started = perf_counter_ns()
            collected = gc.collect(2)
            startup_gc = {"duration_ns": perf_counter_ns() - started, "collected": collected}
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            # 启动期间的正常停止仍关闭零步段，不再建立不需要的控制时钟。
            if not control.stop_requested:
                clock = AbsoluteCycleClock(experiment.scene.period)
        progress("RUNNING")
        while True:
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            if control.stop_requested or runtime.segment_full:
                stopped = transition()
                if stopped is not None:
                    return stopped
                continue
            deadline_ns = None
            if clock is not None:
                scheduled, deadline_ns = clock.wait(runtime.confirmed_step_count)
                lifecycle = runtime.snapshot()
                attempt = {"scheduled": scheduled, "deadline": deadline_ns,
                           "run_id": lifecycle.run_id, "session_id": lifecycle.session_id,
                           "controller_epoch": lifecycle.controller_epoch,
                           "segment_index": lifecycle.segment_index,
                           "step": lifecycle.physically_confirmed_count, "durations": {}}
                check_deadline(deadline_ns, "SAMPLE_START")
                if session.cancelled.is_set():
                    raise RuntimeError("Client 运行已取消。")
            if before_sample is not None:
                before_sample()
            progress("INPUT")
            started = perf_counter_ns()
            if attempt is not None:
                attempt["sample"] = started
            value = experiment.scene.controller_input()
            check_deadline(deadline_ns, "INPUT")
            if attempt is not None:
                attempt["durations"]["input"] = perf_counter_ns() - started
            progress("ROUND_IN_FLIGHT")
            identity = (runtime.step(value) if deadline_ns is None
                        else runtime.step(value, deadline_ns=deadline_ns))
            if identity is None:
                attempt = None
                continue
            if attempt is not None:
                attempt["round_id"] = identity.round_id
                attempt["durations"].update(runtime.cycle_phase_ns)
            progress("AWAITING_PLANT")
            check_deadline(deadline_ns, "BEFORE_DEVICE")
            started = perf_counter_ns()
            if attempt is not None:
                attempt["device_started"] = started
            snapshot = (experiment.scene.advance(identity.global_step, identity.raw_control)
                        if deadline_ns is None else experiment.scene.advance(
                            identity.global_step, identity.raw_control, deadline_ns=deadline_ns,
                        ))
            runtime.confirm_applied(identity)
            if preload_steps and runtime.confirmed_step_count == preload_steps:
                control.request_stop()
            if attempt is not None:
                attempt["device"] = perf_counter_ns()
                attempt["durations"]["device"] = attempt["device"] - started
            record = ConfirmedStep(identity, snapshot)
            records.append(record)
            progress("RECORDING_STEP")
            started = perf_counter_ns()
            if on_step is not None:
                on_step(record)
            if attempt is not None:
                attempt["bookkeeping"] = perf_counter_ns()
                attempt["durations"]["recording"] = attempt["bookkeeping"] - started
            check_deadline(deadline_ns, "RECORDING_STEP")
            if clock is not None and runtime.segment_full and not control.stop_requested:
                started = perf_counter_ns()
                transition(deadline_ns)
                attempt["durations"]["maintenance"] = perf_counter_ns() - started
            check_deadline(deadline_ns, "CYCLE_COMPLETE")
            emit_cycle("confirmed")
            # 公开观测回调自身也受预算约束；不能靠观测出口隐藏一次超期。
            if deadline_ns is not None and perf_counter_ns() >= deadline_ns:
                misses += 1
                last_cycle["status"] = "miss_after_apply"
                last_cycle["failure_phase"] = "CYCLE_OBSERVATION"
                last_cycle["cycle_completed_ns"] = None
                raise CycleDeadlineExceeded("CYCLE_OBSERVATION")
    except Exception as error:  # noqa: BLE001 - 生命周期出口不披露协议秘密或异常载荷
        lifecycle = runtime.snapshot() if runtime is not None else None
        uncertain = lifecycle is not None and lifecycle.phase == "UNCERTAIN"
        failure_phase = getattr(error, "phase", phase_name)
        if attempt is not None:
            attempt["durations"].update(runtime.cycle_phase_ns)
            applied = "device_started" in attempt and failure_phase != "BEFORE_DEVICE_SIGNAL"
            missed = isinstance(error, CycleDeadlineExceeded)
            # 网络 timeout 只有实际超出本周期才归入 miss，仍保留 UNCERTAIN 生命周期。
            missed = missed or perf_counter_ns() >= attempt["deadline"]
            try:
                emit_cycle(("miss_after_apply" if applied else "miss_before_apply")
                           if missed else "failed", failure_phase)
            except Exception as recording_error:  # noqa: BLE001 - 只保留公开类别
                if last_cycle is not None:
                    last_cycle["recording_error"] = type(recording_error).__name__
        return {
            "status": ("cancelled" if session.cancelled.is_set() else
                       "uncertain" if uncertain else "failed"),
            "category": type(error).__name__, "failure_phase": failure_phase,
            "run_id": lifecycle.run_id if lifecycle else None,
            "segment_index": lifecycle.segment_index if lifecycle else 0,
            "session_id": lifecycle.session_id if lifecycle else None,
            "attempted_round": lifecycle.attempted_round if lifecycle else None,
            "round_id": lifecycle.attempted_round_id if lifecycle else None,
            "protocol_committed_count": lifecycle.protocol_committed_count if lifecycle else 0,
            "confirmed_step_count": lifecycle.physically_confirmed_count if lifecycle else 0,
            "resource_counts": ({"products_consumed": lifecycle.products_consumed,
                                 "truncations_consumed": lifecycle.truncations_consumed}
                                if lifecycle else {}),
            "lifecycle": asdict(lifecycle) if lifecycle else None,
            "cycle_summary": {"attempts": cycle_count, "misses": misses,
                              "last_cycle": last_cycle},
            "material_summary": getattr(runtime, "material_summary", runtime.cycle_queue_levels) if runtime is not None else {},
            "startup_gc": startup_gc,
        }
    finally:
        session.stop_accepting()
        if runtime is not None:
            runtime.close()


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
    wall_started = perf_counter()
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
        wall_elapsed_ms = (perf_counter() - wall_started) * 1000
    except Exception as error:
        if experiment.physical_completed_count is not None:
            attempted = len(runtime.confirmed_steps)
            physical = experiment.physical_completed_count()
            error._public_lan_progress = {
                "protocol_double_committed_count": attempted,
                "physically_confirmed_count": physical,
                "resource_counts": runtime.resource_counts,
                "uncertain": isinstance(error, (
                    LanTimeoutError, LocalhostTransportTimeout,
                    LocalhostTransportDisconnected, TimeoutError, ConnectionError, OSError,
                )),
            }
        raise
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
    if experiment.include_round_ledger:
        provenance["round_ledger"] = runtime.confirmed_plans
        provenance["wall_elapsed_ms"] = wall_elapsed_ms
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
    completed = {
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
    if experiment.include_round_ledger:
        completed["wall_elapsed_ms"] = wall_elapsed_ms
    return completed


def _run() -> int:
    parser = argparse.ArgumentParser(prog="secure-control", description="Three-role LAN experiment")
    commands = parser.add_subparsers(dest="role", required=True)
    for role in ("p1", "p2", "client"):
        command = commands.add_parser(role)
        command.add_argument("--config", required=True, type=Path)
    redraw = commands.add_parser("redraw")
    redraw.add_argument("--run-dir", required=True, type=Path)
    redraw.add_argument("--output", required=True, type=Path)
    benchmark = commands.add_parser("benchmark")
    benchmark.add_argument("--case", required=True, choices=("dynamic", "scalar", "continuous", "cycle"))
    benchmark.add_argument("--mode", required=True, choices=("legacy", "batch"))
    benchmark.add_argument("--steps", required=True, type=int)
    benchmark.add_argument("--delay-ms", type=float, default=0.)
    benchmark.add_argument("--segment-steps", type=int, default=8)
    benchmark.add_argument("--material-slots", type=int, choices=(0, 4, 16), default=16)
    benchmark.add_argument("--preload-steps", type=int, default=0)
    benchmark.add_argument("--preload-execution", choices=("staged", "fused"), default="fused")
    benchmark.add_argument("--role-config", type=Path)
    benchmark.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _enable_terminal_progress()
    if args.role == "benchmark":
        from .communication_benchmark import run_continuous_observation, run_local_benchmark

        try:
            if args.case in {"continuous", "cycle"}:
                if args.mode != "batch":
                    raise ValueError("实际持续观察只使用默认批量协议")
                report = run_continuous_observation(
                    steps=args.steps, delay_ms=args.delay_ms, segment_steps=args.segment_steps,
                    optimized=args.case == "cycle", material_slots=args.material_slots,
                    preload_steps=args.preload_steps, preload_execution=args.preload_execution,
                    role_config=args.role_config,
                )
            else:
                if args.preload_steps:
                    raise ValueError("预送观察仅支持cycle动态v2入口")
                report = run_local_benchmark(
                    args.case, args.mode, steps=args.steps, delay_ms=args.delay_ms,
                )
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        except (OSError, ValueError, RuntimeError) as error:
            return _failure("Client", 5, "communication_benchmark", error)
        observed_ok = report.get("status", "complete") in {"complete", "stopped"}
        display_timing = report["cycle_timing"] if args.case == "cycle" else report["timing"]
        print(json.dumps({"status": "complete" if observed_ok else "failed", "report": str(args.output),
                          "case": args.case, "mode": args.mode,
                          "p50_ms": display_timing["p50_ms"]},
                         ensure_ascii=False, sort_keys=True))
        return 0 if observed_ok else 5
    if args.role == "redraw":
        try:
            if (args.run_dir / "run.json").exists():
                from .cart_pole_segmented_evidence import (
                    FORMAT,
                    HEADER_LIMIT,
                    _read,
                    redraw_segmented_control,
                )
                if _read(args.run_dir / "run.json", HEADER_LIMIT).get("format") != FORMAT:
                    raise ValueError("未知聚合产物格式。")
                target = redraw_segmented_control(args.run_dir, args.output)
            else:
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
