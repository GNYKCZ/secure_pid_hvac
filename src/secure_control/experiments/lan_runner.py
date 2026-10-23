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
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from threading import Event
from time import perf_counter, perf_counter_ns, sleep

from secure_control.execution.cycle_timing import (
    AbsoluteCycleClock,
    CycleDeadlineExceeded,
    CycleTiming,
    StepTimingObservation,
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
from secure_control.execution.localhost_codec import (
    _COMPACT_ADVANCE_PROFILES,
    _COMPACT_PROFILE_V2,
    _COMPACT_PROFILE_V3,
    LocalhostCodecError,
)
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
    if config.wire_profile != "control-batch-v1":
        raise ValueError("compact-v2 仅支持专用动态持续 light 入口。")
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


def validate_segmented_mode(config, experiment, *, non_realtime=False,
                            recording_mode=None, preload_steps=0):
    """联网前拒绝新演示不支持的组合；旧 batch 留证与预送语义不变。"""
    dynamic = experiment.spec.state_dimension != 0
    mode = recording_mode if recording_mode is not None else "light" if dynamic else "full"
    if type(non_realtime) is not bool:
        raise ValueError("non_realtime 必须是布尔值。")
    compact = config.wire_profile in _COMPACT_ADVANCE_PROFILES
    if (non_realtime or compact) and (not dynamic or mode != "light" or preload_steps):
        raise ValueError("紧凑/矩阵协议或非实时演示仅支持动态持续 light，不能预送或保存 full。")
    return mode


def run_client_segmented(config: LanConfig, *, segment_steps: int = 400,
                         control: RunControl,
                         on_step: Callable[[ConfirmedStep], None] | None = None,
                         on_segment: Callable[[CompletedSegment], None] | None = None,
                         phase: Callable[[str], None] | None = None,
                         session=None, preload_steps=0, preload_execution="fused",
                         non_realtime=False) -> dict[str, object]:
    """运行到正常停止请求或故障；不将后端 stopped 冒充正式 artifact complete。"""
    # 队列与场景选择由装配层拥有；核心仅处理协议身份、双提交及确认前缀。
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    if config.experiment_config is None:
        raise ValueError("持续 Client 缺少 experiment profile。")
    session = InteractiveSession() if session is None else session
    if not isinstance(session, InteractiveSession) or not isinstance(control, RunControl):
        raise TypeError("持续模式需要 RunControl 和 InteractiveSession。")
    experiment = load_segmented_experiment(config.experiment_config, segment_steps, session)
    validate_segmented_mode(config, experiment, non_realtime=non_realtime, preload_steps=preload_steps)
    return _run_prepared_segmented(config, experiment, control=control, session=session,
                                   on_step=on_step, on_segment=on_segment, phase=phase,
                                   preload_steps=preload_steps, preload_execution=preload_execution,
                                   non_realtime=non_realtime)


def _wait_nonrealtime(target_ns, cancelled, control):
    """以同一实际采样目标分片休眠；5ms是请求上限，不是系统唤醒保证。"""
    started = perf_counter_ns()
    requested = max(0, target_ns - started)
    waited = False
    while True:
        if cancelled.is_set() or control.stop_requested:
            return requested if waited else 0, perf_counter_ns() - started if waited else 0, None
        remaining = target_ns - perf_counter_ns()
        if remaining <= 0:
            elapsed = perf_counter_ns() - started if waited else 0
            return requested if waited else 0, elapsed, max(0, elapsed - requested) if waited else 0
        # time.sleep走标准库节拍休眠路径；每次醒来重新核对同一目标，不忙等或追赶。
        waited = True
        sleep(min(remaining, 5_000_000) / 1e9)


def _run_prepared_segmented(config, experiment, *, control, session,
                            on_step=None, on_segment=None, on_start=None,
                            phase=None, realtime=None, material_slots=16,
                            on_cycle=None, cycle_snapshot=None,
                            before_sample=None, preload_steps=0,
                            preload_execution="fused", on_segment_ready=None,
                            _material_candidate=None, _wire_profile=None,
                            non_realtime=False, timing_observer=None) -> dict[str, object]:
    """唯一持续循环接收已装配场景；保存/GUI 与 headless 不重复 parse 或创建 plant。"""
    control.bind_stop(session.reject_new)
    wire_profile = _wire_profile if _wire_profile is not None else getattr(config, "wire_profile", "control-batch-v1")
    # 旧实验显式参数仍归原实验 owner；普通角色配置的选择才装配演示 worker。
    configured_compact = _wire_profile is None and wire_profile in _COMPACT_ADVANCE_PROFILES
    if non_realtime or configured_compact:
        validate_segmented_mode(config, experiment, non_realtime=non_realtime,
                                preload_steps=preload_steps)
        if realtime is True and non_realtime:
            raise ValueError("非实时演示不能同时启用实时截止。")
    material_candidate = "worker" if configured_compact else _material_candidate
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
    sample_count = 0
    previous_sample_ns = None
    outcome = None
    wall_started = perf_counter()
    dynamic_realtime = (experiment.spec.state_dimension != 0 if realtime is None else realtime) and not non_realtime
    observation = None
    observation_seq = 0
    observer_started = perf_counter_ns() if timing_observer is not None else None
    if timing_observer is not None:
        timing_observer.completion_clock = perf_counter_ns

    def observe_finish(status="confirmed", failure_phase=None, *, complete=True, endpoint=None):
        """独立观察不创建CycleTiming；异常只使统计不可用，原控制异常仍由外层处理。"""
        nonlocal observation, observation_seq
        if timing_observer is None or observation is None:
            return None
        data, observation = observation, None
        start = data["actual_sample_start_ns"]
        now = perf_counter_ns()
        try:
            if data.pop("runtime_called", False):
                data["phase_durations_ns"].update(runtime.cycle_phase_ns)
                if data.get("round_id") is None:
                    known = runtime.snapshot()
                    if known.attempted_round == data["global_step"]:
                        data["round_id"] = known.attempted_round_id
            data["queue_levels"] = runtime.cycle_queue_levels
            row = StepTimingObservation(**data, status=status, failure_phase=failure_phase,
                work_completed_ns=(now if endpoint is None else endpoint) if complete else None,
                terminal_elapsed_ns=now-start if not complete and start is not None else None,
                observation_ns=perf_counter_ns()-now)
            observation_seq += 1
            timing_observer.record(row)
            return row
        except Exception as error:  # noqa: BLE001 - 观察不改变协议/plant
            timing_observer.disable(error)
            return None

    def summary():
        """非实时没有周期截止证据；尝试数独立于 CycleTiming 的存在。"""
        return {"attempts": sample_count if non_realtime else cycle_count,
                "misses": None if non_realtime else misses,
                "last_cycle": None if non_realtime else last_cycle}

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
        def measured(name, action):
            started = perf_counter_ns()
            try:
                return action()
            finally:
                if attempt is not None or observation is not None:
                    key = name() if callable(name) else name
                    elapsed = perf_counter_ns() - started
                    if attempt is not None:
                        attempt["durations"]["maintenance_" + key] = elapsed
                    if observation is not None:
                        observation["phase_durations_ns"]["maintenance_" + key] = elapsed

        progress("ENDING_SEGMENT", "STOPPING" if control.stop_requested else None)
        segment = measured(lambda: getattr(runtime, "last_maintenance_operation", "end"),
                           lambda: runtime.end_segment() if deadline_ns is None
                           else runtime.end_segment(deadline_ns=deadline_ns))
        compound = getattr(runtime, "last_maintenance_operation", "end") == "advance"
        if session.cancelled.is_set():
            raise RuntimeError("Client 运行已取消。")
        progress("RECORDING_SEGMENT")
        packet = CompletedSegment(segment, tuple(records)) if on_segment is not None else None
        if on_segment is not None:
            measured("seal", lambda: on_segment(packet))
        primary = None
        released = False
        try:
            records.clear()
            check_deadline(deadline_ns, "RECORDING_SEGMENT")
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            if runtime.phase == "STOPPED":
                measured("source", experiment.recheck_sources)
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
                    "cycle_summary": summary(),
                    "material_summary": getattr(runtime, "material_summary", runtime.cycle_queue_levels),
                    "startup_gc": startup_gc,
                    "last_commit_observation": getattr(runtime, "last_commit_observation", None),
                }
            progress("CONNECTING_NEXT")
            measured("source", experiment.recheck_sources)
            check_deadline(deadline_ns, "SOURCE_CHECK")
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            if compound:
                if on_segment is not None and on_segment_ready is not None:
                    released = True
                    measured("release", lambda: on_segment_ready(packet))
                check_deadline(deadline_ns, "SEGMENT_RELEASE")
                if session.cancelled.is_set():
                    raise RuntimeError("Client 运行已取消。")
                # 网络已双确认；release/source/原截止检查后才允许本地激活。
                runtime.next_segment(deadline_ns=deadline_ns)
            else:
                measured("begin", lambda: runtime.next_segment() if deadline_ns is None
                         else runtime.next_segment(deadline_ns=deadline_ns))
            progress("RUNNING")
            return None
        except Exception as error:
            primary = error
            raise
        finally:
            if not released and on_segment is not None and on_segment_ready is not None:
                try:
                    measured("release", lambda: on_segment_ready(packet))
                except Exception as release_error:
                    if primary is None:
                        raise
                    primary._public_recording_error = type(release_error).__name__

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
            **({"wire_profile": wire_profile} if wire_profile != "control-batch-v1" else {}),
        )
        if on_start is not None:
            on_start(runtime.snapshot(), runtime.public_setup)
        if preload_steps:
            progress("PRELOADING")
            runtime.enable_material_preload(cancelled=lambda: session.cancelled.is_set()
                                           or control.stop_requested)
        if dynamic_realtime or configured_compact:
            if material_slots and not preload_steps:
                runtime.enable_material_preparation(slots=material_slots,
                    **({"_candidate": material_candidate} if material_candidate else {}))
            # 所有固定验证、建连、writer 初始化与首池填充完成后才确定唯一 t0。
            # 收集初始化暂存垃圾；运行中的自动 GC/阈值保持原样，不转移周期内的工作。
            started = perf_counter_ns()
            collected = gc.collect(2)
            startup_gc = {"duration_ns": perf_counter_ns() - started, "collected": collected}
            if material_candidate:
                runtime._begin_material_control()
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            # 启动期间的正常停止仍关闭零步段，不再建立不需要的控制时钟。
            if dynamic_realtime and not control.stop_requested:
                clock = AbsoluteCycleClock(experiment.scene.period)
        progress("RUNNING")
        if timing_observer is not None:
            timing_observer.lifecycle_ns["startup"] = perf_counter_ns()-observer_started
        while True:
            if session.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            if control.stop_requested or runtime.segment_full:
                # 非实时自动维护保持原位置，观察归刚填满的上一控制步。
                if control.stop_requested:
                    observe_finish()
                started = perf_counter_ns() if timing_observer is not None else None
                try:
                    stopped = transition()
                finally:
                    if observation is not None:
                        observation["phase_durations_ns"]["maintenance"] = perf_counter_ns()-started
                    elif timing_observer is not None and control.stop_requested:
                        timing_observer.lifecycle_ns["stop"] = perf_counter_ns()-started
                observe_finish()
                if stopped is not None:
                    outcome = stopped
                    return outcome
                continue
            deadline_ns = None
            pacing_requested = pacing_elapsed = pacing_excess = 0
            if non_realtime and previous_sample_ns is not None:
                # 只尽力保持模型节奏：从上次实际采样算剩余等待，慢轮不追赶或积压输入。
                target_ns = previous_sample_ns + round(experiment.scene.period * 1e9)
                pacing_requested, pacing_elapsed, pacing_excess = _wait_nonrealtime(
                    target_ns, session.cancelled, control)
                if session.cancelled.is_set() or control.stop_requested:
                    if timing_observer is not None:
                        timing_observer.waiting_terminal = {"status":"cancelled" if session.cancelled.is_set() else "stopped",
                            "pacing_requested_ns":pacing_requested,"pacing_elapsed_ns":pacing_elapsed,
                            "pacing_excess_ns":None,"actual_sample_start_ns":None}
                    continue
            if clock is not None:
                wait_started = perf_counter_ns() if timing_observer is not None else None
                scheduled, deadline_ns = clock.wait(runtime.confirmed_step_count)
                if timing_observer is not None:
                    pacing_requested = max(0,scheduled-wait_started)
                    pacing_elapsed = perf_counter_ns()-wait_started if pacing_requested else 0
                    pacing_excess = max(0,pacing_elapsed-pacing_requested)
                lifecycle = runtime.snapshot()
                attempt = {"scheduled": scheduled, "deadline": deadline_ns,
                           "run_id": lifecycle.run_id, "session_id": lifecycle.session_id,
                           "controller_epoch": lifecycle.controller_epoch,
                           "segment_index": lifecycle.segment_index,
                           "step": lifecycle.physically_confirmed_count, "durations": {}}
                if timing_observer is not None:
                    observation = {"attempt_seq":observation_seq,"global_step":runtime.confirmed_step_count,
                        "segment_index":lifecycle.segment_index,"actual_sample_start_ns":None,
                        "pacing_requested_ns":pacing_requested,"pacing_elapsed_ns":pacing_elapsed,
                        "pacing_excess_ns":pacing_excess,"scheduled_start_ns":scheduled,
                        "deadline_ns":deadline_ns,"phase_durations_ns":{}}
                check_deadline(deadline_ns, "SAMPLE_START")
                if session.cancelled.is_set():
                    raise RuntimeError("Client 运行已取消。")
            if timing_observer is not None and observation is None:
                observation = {"attempt_seq":observation_seq,"global_step":runtime.confirmed_step_count,
                    "segment_index":runtime.snapshot().segment_index,"actual_sample_start_ns":None,
                    "phase_durations_ns":{},"pacing_requested_ns":pacing_requested,
                    "pacing_elapsed_ns":pacing_elapsed,"pacing_excess_ns":pacing_excess}
            if before_sample is not None:
                before_sample()
            progress("INPUT")
            started = perf_counter_ns()
            if timing_observer is not None:
                observation.update(actual_sample_start_ns=started,
                    sample_interval_ns=started-previous_sample_ns if previous_sample_ns is not None else None)
            previous_sample_ns = started
            sample_count += 1
            if attempt is not None:
                attempt["sample"] = started
            value = experiment.scene.controller_input()
            if observation is not None:
                observation["phase_durations_ns"]["input"] = perf_counter_ns()-started
            check_deadline(deadline_ns, "INPUT")
            if attempt is not None:
                attempt["durations"]["input"] = perf_counter_ns() - started
            progress("ROUND_IN_FLIGHT")
            if observation is not None:
                observation["runtime_called"] = True
            identity = (runtime.step(value) if deadline_ns is None
                        else runtime.step(value, deadline_ns=deadline_ns))
            if identity is None:
                observe_finish("stopped_before_commit", complete=False)
                attempt = None
                continue
            if observation is not None:
                observation["round_id"] = identity.round_id
                observation["phase_durations_ns"].update(runtime.cycle_phase_ns)
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
            if observation is not None:
                observation["control_applied_ns"] = perf_counter_ns()
                observation["phase_durations_ns"]["device"] = observation["control_applied_ns"]-started
            if preload_steps and runtime.confirmed_step_count == preload_steps:
                control.request_stop()
            if attempt is not None:
                attempt["device"] = perf_counter_ns()
                attempt["durations"]["device"] = attempt["device"] - started
            record = ConfirmedStep(identity, snapshot) if on_step is not None or on_segment is not None else None
            if on_segment is not None:
                records.append(record)
            progress("RECORDING_STEP")
            started = perf_counter_ns()
            if on_step is not None:
                on_step(record)
            if observation is not None:
                observation["phase_durations_ns"]["recording"] = perf_counter_ns()-started
            if attempt is not None:
                attempt["bookkeeping"] = perf_counter_ns()
                attempt["durations"]["recording"] = attempt["bookkeeping"] - started
            check_deadline(deadline_ns, "RECORDING_STEP")
            if clock is not None and runtime.segment_full and not control.stop_requested:
                started = perf_counter_ns()
                try:
                    transition(deadline_ns)
                finally:
                    attempt["durations"]["maintenance"] = perf_counter_ns() - started
                    if observation is not None:
                        observation["phase_durations_ns"]["maintenance"] = attempt["durations"]["maintenance"]
            check_deadline(deadline_ns, "CYCLE_COMPLETE")
            emit_cycle("confirmed")
            # 公开观测回调自身也受预算约束；不能靠观测出口隐藏一次超期。
            if deadline_ns is not None and perf_counter_ns() >= deadline_ns:
                misses += 1
                last_cycle["status"] = "miss_after_apply"
                last_cycle["failure_phase"] = "CYCLE_OBSERVATION"
                last_cycle["cycle_completed_ns"] = None
                raise CycleDeadlineExceeded("CYCLE_OBSERVATION")
            if timing_observer is not None and not (non_realtime and runtime.segment_full and not control.stop_requested):
                final_observation = observe_finish()
                # 新汇总/显示的成本与旧回调一样受原截止保护。
                if deadline_ns is not None and perf_counter_ns() >= deadline_ns:
                    misses += 1
                    last_cycle.update(status="miss_after_apply", failure_phase="CYCLE_OBSERVATION", cycle_completed_ns=None)
                    if final_observation is not None:
                        timing_observer.correct_last(replace(final_observation,status="miss_after_apply",
                            work_completed_ns=None,failure_phase="CYCLE_OBSERVATION",
                            terminal_elapsed_ns=perf_counter_ns()-final_observation.actual_sample_start_ns))
                    raise CycleDeadlineExceeded("CYCLE_OBSERVATION")
    except Exception as error:  # noqa: BLE001 - 生命周期出口不披露协议秘密或异常载荷
        if (runtime is not None and wire_profile in _COMPACT_ADVANCE_PROFILES
                and runtime.last_maintenance_operation == "advance"
                and (runtime.phase == "CONNECTING_NEXT" or attempt is not None
                     and "maintenance_advance" in attempt["durations"]
                     or attempt is None and last_cycle is not None and "maintenance_advance" in last_cycle["phase_durations_ns"]
                     and last_cycle["global_step"] == runtime.confirmed_step_count - 1)):
            runtime.abort_segment_transition()
        lifecycle = runtime.snapshot() if runtime is not None else None
        uncertain = lifecycle is not None and lifecycle.phase == "UNCERTAIN"
        failure_phase = getattr(error, "phase", phase_name)
        observation_missed = (isinstance(error,CycleDeadlineExceeded) or observation is not None
            and observation.get("deadline_ns") is not None and perf_counter_ns() >= observation["deadline_ns"])
        observation_applied = ("device_started" in attempt and failure_phase != "BEFORE_DEVICE_SIGNAL"
                               if attempt is not None else observation is not None
                               and observation.get("control_applied_ns") is not None)
        observe_finish("cancelled" if session.cancelled.is_set() else "uncertain" if uncertain else
            "miss_after_apply" if observation_missed and observation_applied else
            "miss_before_apply" if observation_missed else "failed",
            failure_phase, complete=False)
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
        outcome = {
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
            "resource_counts": getattr(runtime, "resource_counts",
                {"products_consumed": lifecycle.products_consumed,
                 "truncations_consumed": lifecycle.truncations_consumed} if lifecycle else {}),
            "lifecycle": asdict(lifecycle) if lifecycle else None,
            "cycle_summary": summary(),
            "material_summary": getattr(runtime, "material_summary", runtime.cycle_queue_levels) if runtime is not None else {},
            "startup_gc": startup_gc,
            "last_commit_observation": getattr(runtime, "last_commit_observation", None),
            **({"last_sealed_segment": asdict(runtime.last_sealed_record)
                if runtime.last_sealed_record is not None else None,
                "known_segment_receipts": [asdict(r) for r in runtime.last_segment_receipts]}
               if runtime is not None and wire_profile in _COMPACT_ADVANCE_PROFILES else {}),
            "recording_error": getattr(error, "_public_recording_error", None),
        }
        return outcome
    finally:
        session.stop_accepting()
        if runtime is not None:
            cleanup_started = perf_counter_ns()
            try:
                runtime.close()
            except Exception as error:
                if not (non_realtime or configured_compact) or outcome is None:
                    raise
                outcome["cleanup_error_type"] = type(error).__name__
                if outcome["status"] == "stopped":
                    outcome.update(status="failed", category=type(error).__name__, failure_phase="CLEANUP")
            finally:
                if timing_observer is not None:
                    timing_observer.lifecycle_ns["cleanup"] = perf_counter_ns()-cleanup_started
        if (non_realtime or configured_compact) and outcome is not None:
            # close 后再取工人清退事实，不以构造 return 时的旧快照声称清理完成。
            material = runtime.material_summary if runtime is not None else {}
            outcome.update(transport=config.transport, wire_profile=wire_profile,
                material_source="worker" if material_candidate == "worker" else "inline",
                timing_mode=("non_realtime_demo" if non_realtime else "absolute" if dynamic_realtime else "unpaced"),
                model_period_s=experiment.scene.period,
                wall_elapsed_s=perf_counter() - wall_started, material_summary=material)
            if (material.get("cleanup_failed") or material.get("error_type")
                    or (material.get("worker") or {}).get("memory_guard_failed")) and outcome["status"] == "stopped":
                outcome.update(status="failed", category="MaterialWorkerFailure", failure_phase="CLEANUP")


def _run_prepared_client(config: LanConfig, experiment: PreparedLanExperiment,
                         *, phase: Callable[[str], None] | None = None,
                         cancelled: Event | None = None,
                         publication_guard: Callable[[], AbstractContextManager[None]]
                         | None = None) -> dict[str, object]:
    """通用会话/资源/正式发布只保留一份；交互入口仅换执行计划。"""
    if config.wire_profile != "control-batch-v1":
        raise ValueError("紧凑/矩阵协议仅支持动态持续 light。")
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
    benchmark.add_argument("--case", required=True, choices=("dynamic", "scalar", "continuous", "cycle", "full-observation"))
    benchmark.add_argument("--mode", default="batch", choices=("legacy", "batch"))
    benchmark.add_argument("--steps", type=int)
    benchmark.add_argument("--delay-ms", type=float, default=0.)
    benchmark.add_argument("--segment-steps", type=int)
    benchmark.add_argument("--material-slots", type=int, choices=(0, 4, 16), default=16)
    benchmark.add_argument("--preload-steps", type=int, default=0)
    benchmark.add_argument("--preload-execution", choices=("staged", "fused"), default="fused")
    benchmark.add_argument("--recording", choices=("light", "full"),
                           help="仅cycle：轻量控制/完整留证对照；默认full保持原观察负载")
    benchmark.add_argument("--tcp-nodelay", choices=("default", "off"), default="default")
    benchmark.add_argument("--commit-policy", choices=("default", "serial"), default="default")
    benchmark.add_argument("--diagnostic", action="store_true",
                           help="本机cycle有限CPU/GC观测，不作为正式资格")
    benchmark.add_argument("--gc-trial-policy", choices=("baseline", "startup-freeze"),
                           help="独占Client一次性限定GC对照；默认不启用")
    benchmark.add_argument("--timeout-trace", action="store_true",
                           help="显式baseline或startup-freeze一次最多200周期的有限socket超时定位")
    benchmark.add_argument("--material-candidate", choices=("thread", "worker"),
                           help="S5显式供料对照，固定1000/400/16/light；默认不启用")
    benchmark.add_argument("--worker-timeout-diagnostic", action="store_true",
                           help="S6独立worker正常GC定位，固定20/400/16/light，首次失败停，非性能资格")
    benchmark.add_argument("--worker-long-run", action="store_true",
                           help="S9显式worker长期候选，固定10000/400/16/light，首次失败停，非整体资格")
    benchmark.add_argument("--worker-wait-diagnostic", action="store_true",
                           help="S10独立worker确认链定位，固定4000/400/16/light，首次失败停，非资格")
    benchmark.add_argument("--server-gc-candidate", action="store_true",
                           help="S11独立服务端启动GC候选，固定4000/400/16/light，非长期资格")
    benchmark.add_argument("--stage-wait-diagnostic", action="store_true",
                           help="S12独立stage/首个通信错误定位，固定4000/400/16/light，非资格")
    benchmark.add_argument("--compact-history-candidate", action="store_true",
                           help="S13紧凑实验历史候选，固定4000/400/16/light，保留S12观察，非长期资格")
    benchmark.add_argument("--qpc-stage-receive-candidate", action="store_true",
                           help="S15仅实验Client stage回复按原QPC截止续收；默认关闭")
    benchmark.add_argument("--qpc-dynamic-qualification", action="store_true",
                           help="固定10000/400/16/light的本机动态资格，使用正式canonical QPC接收")
    benchmark.add_argument("--fixed-proof-cache", action="store_true",
                           help="full-observation固定精确矩阵计算的显式候选对照")
    benchmark.add_argument("--role-config", type=Path)
    benchmark.add_argument("--network-profile", choices=("N0", "N1", "N2", "N3"))
    benchmark.add_argument("--network-phase", choices=("discovery", "recheck", "qualification", "candidate"))
    benchmark.add_argument("--network-certs", type=Path)
    benchmark.add_argument("--network-ports", help="预声明的三个固定端口，逗号分隔")
    benchmark.add_argument("--network-ledger", type=Path)
    benchmark.add_argument("--network-approval", type=Path)
    benchmark.add_argument("--network-repair-note")
    benchmark.add_argument("--network-wire-profile", choices=("control-dynamic-compact-v1", _COMPACT_PROFILE_V2,
                                                            _COMPACT_PROFILE_V3, "control-dynamic-matrix-v1"))
    benchmark.add_argument("--network-authorization", help="当前 Issue 的直接用户批准登记评论 URL")
    benchmark.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _enable_terminal_progress()
    if args.role == "benchmark":
        if any(getattr(args, name) is not None for name in ("network_profile", "network_phase", "network_certs",
                "network_ports", "network_ledger", "network_approval", "network_repair_note",
                "network_wire_profile", "network_authorization")):
            from .network_benchmark import run_network_benchmark, validate_cli

            try:
                ports = validate_cli(args)
                report = run_network_benchmark(profile=args.network_profile, phase=args.network_phase,
                    certs=args.network_certs, ports=ports, ledger=args.network_ledger,
                    approval=args.network_approval, output=args.output, repair_note=args.network_repair_note,
                    **({"wire_profile": args.network_wire_profile, "authorization": args.network_authorization}
                       if args.network_wire_profile is not None else {}))
            except (OSError, ValueError, RuntimeError) as error:
                return _failure("Client", 5, "network_benchmark", error)
            print(json.dumps({"status": report["status"], "profile": args.network_profile, "phase": args.network_phase,
                "network_sample_pass": report["network_sample_pass"],
                **({"network_progress_goal_pass": report.get("network_progress_goal_pass")}
                   if (report.get("network_manifest") or {}).get("comparison_stage") else {}),
                "network_dynamic_qualification_pass": report["network_dynamic_qualification_pass"],
                "attempts": len(report.get("cycles", [])), "history_export_ns": report["network_export_ns"],
                "report": str(args.output)}, ensure_ascii=False, sort_keys=True))
            comparison = (report.get("network_manifest") or {}).get("comparison_stage")
            return 0 if (report["network_sample_pass"] and (comparison not in ("T2", "T3", "U2", "V1", "W1", "W2", "SC-B", "M128-B")
                           or report.get("network_progress_goal_pass") is True)) else 5
        if args.steps is None:
            parser.error("benchmark requires --steps outside the fixed network profiles")
        if args.segment_steps is None:
            args.segment_steps = 8
        from .communication_benchmark import (
            run_continuous_observation,
            run_full_observation,
            run_local_benchmark,
        )

        try:
            if args.qpc_dynamic_qualification and (args.case != "cycle" or args.mode != "batch" or args.fixed_proof_cache):
                raise ValueError("qpc-dynamic-qualification只支持独立cycle/batch资格。")
            if args.qpc_stage_receive_candidate and (args.case != "cycle" or args.mode != "batch" or args.fixed_proof_cache):
                raise ValueError("qpc-stage-receive-candidate只支持独立cycle/batch候选。")
            if args.compact_history_candidate and (args.case != "cycle" or args.mode != "batch" or args.fixed_proof_cache):
                raise ValueError("compact-history-candidate只支持独立cycle/batch候选。")
            if args.stage_wait_diagnostic and (args.case != "cycle" or args.mode != "batch" or args.fixed_proof_cache):
                raise ValueError("stage-wait-diagnostic只支持独立cycle/batch定位。")
            if args.server_gc_candidate and (args.case != "cycle" or args.mode != "batch" or args.fixed_proof_cache):
                raise ValueError("server-gc-candidate只支持独立cycle/batch候选。")
            if args.worker_wait_diagnostic and (args.case != "cycle" or args.mode != "batch"
                                                or args.fixed_proof_cache):
                raise ValueError("worker-wait-diagnostic只支持独立cycle/batch诊断。")
            if args.worker_long_run and (args.case != "cycle" or args.mode != "batch"
                                         or args.fixed_proof_cache):
                raise ValueError("worker-long-run只支持独立cycle/batch候选。")
            if args.worker_timeout_diagnostic and (args.case != "cycle" or args.mode != "batch"):
                raise ValueError("worker-timeout-diagnostic只支持cycle/batch。")
            if args.material_candidate is not None and (args.case != "cycle" or args.mode != "batch"):
                raise ValueError("材料候选只支持cycle/batch")
            if args.timeout_trace and (args.case != "cycle" or args.mode != "batch"):
                raise ValueError("timeout-trace只支持cycle/batch。")
            if args.gc_trial_policy is not None and (args.case != "cycle" or args.mode != "batch"):
                raise ValueError("GC限定试验只支持cycle/batch。")
            if args.recording is not None and args.case != "cycle":
                raise ValueError("--recording 只适用于cycle动态持续观察")
            if (args.tcp_nodelay != "default" or args.commit_policy != "default") and args.case != "cycle":
                raise ValueError("通信策略对照只适用于cycle。")
            if args.fixed_proof_cache and args.case != "full-observation":
                raise ValueError("固定证明对照只适用于full-observation")
            if args.case == "full-observation":
                if args.mode != "batch" or args.preload_steps or args.diagnostic:
                    raise ValueError("full-observation只观察原batch完整路线，不支持预送或cycle诊断")
                report = run_full_observation(steps=args.steps, delay_ms=args.delay_ms,
                                             segment_steps=args.segment_steps,
                                             role_config=args.role_config, fixed_proof_cache=args.fixed_proof_cache)
            elif args.case in {"continuous", "cycle"}:
                if args.mode != "batch":
                    raise ValueError("实际持续观察只使用默认批量协议")
                report = run_continuous_observation(
                    steps=args.steps, delay_ms=args.delay_ms, segment_steps=args.segment_steps,
                    optimized=args.case == "cycle", material_slots=args.material_slots,
                    preload_steps=args.preload_steps, preload_execution=args.preload_execution,
                    role_config=args.role_config,
                    diagnostic=args.diagnostic,
                    recording_mode=args.recording if args.recording is not None else "full",
                    tcp_nodelay=False if args.tcp_nodelay == "off" else None,
                    commit_policy=args.commit_policy,
                    gc_trial_policy=args.gc_trial_policy,
                    timeout_trace=args.timeout_trace,
                    material_candidate=args.material_candidate,
                    worker_timeout_diagnostic=args.worker_timeout_diagnostic,
                    worker_long_run=args.worker_long_run,
                    worker_wait_diagnostic=args.worker_wait_diagnostic,
                    server_gc_candidate=args.server_gc_candidate,
                    stage_wait_diagnostic=args.stage_wait_diagnostic,
                    compact_history_candidate=args.compact_history_candidate,
                    qpc_stage_receive_candidate=args.qpc_stage_receive_candidate,
                    qpc_dynamic_qualification=args.qpc_dynamic_qualification,
                )
            else:
                if args.preload_steps or args.diagnostic:
                    raise ValueError("预送/有限诊断仅支持cycle动态v2入口")
                report = run_local_benchmark(
                    args.case, args.mode, steps=args.steps, delay_ms=args.delay_ms,
                )
            export_started = perf_counter_ns() if (args.compact_history_candidate or args.qpc_stage_receive_candidate
                                                   or args.qpc_dynamic_qualification) else None
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
            export_ns = perf_counter_ns()-export_started if export_started is not None else None
        except (OSError, ValueError, RuntimeError) as error:
            return _failure("Client", 5, "communication_benchmark", error)
        observed_ok = report.get("status", "complete") in {"complete", "stopped"}
        display_timing = report["cycle_timing"] if args.case == "cycle" else report["timing"]
        print(json.dumps({"status": "complete" if observed_ok else "failed", "report": str(args.output),
                          "case": args.case, "mode": args.mode,
                          "p50_ms": display_timing["p50_ms"],
                          **({"history_export_ns": export_ns,
                              "history_export_scope": "after control/observer exit; JSON encoding and exclusive file write"}
                             if args.compact_history_candidate or args.qpc_stage_receive_candidate or args.qpc_dynamic_qualification else {})},
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
        if role == "Client" and config.wire_profile != "control-batch-v1":
            raise ValueError("紧凑/矩阵 Client 请使用倒立摆专用动态持续入口。")
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
            else run_party_single_step(config, wire_profile=config.wire_profile)
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
