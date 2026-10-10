"""#116/#121 本机三进程公开观察；只保存身份、计数和本机时长。"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from queue import Empty
from unittest.mock import patch

import numpy as np

from secure_control.execution.lan_config import LanConfig, LanEndpoint, LanTopology, load_lan_config
from secure_control.execution.lan_runtime import LanContinuousRuntime, run_party_single_step
from secure_control.execution.lan_scalar_runtime import LanScalarRuntime

_ROOT = Path(__file__).resolve().parents[3]


def _source_fingerprints():
    """区分同一 HEAD 上的观察补丁和优化补丁；只保存内容摘要。"""
    paths = (
        "src/secure_control/protocol/coordinator.py",
        "src/secure_control/protocol/roles.py", "src/secure_control/protocol/messages.py",
        "src/secure_control/execution/lan_runtime.py",
        "src/secure_control/execution/_localhost_workers.py",
        "src/secure_control/execution/lan_transport.py",
        "src/secure_control/experiments/communication_benchmark.py",
        "src/secure_control/experiments/lan_runner.py",
        "src/secure_control/experiments/cart_pole_segmented_evidence.py",
        "src/secure_control/execution/cycle_timing.py",
        "configs/cart_pole_observer_lan.example.yaml", "configs/cart_pole_observer.yaml",
    )
    return {name: sha256((_ROOT / name).read_bytes()).hexdigest() for name in paths}


def _process_memory():
    """读取本进程 OS 峰值 RSS/working set；不把 canonical 编码预算当成 RSS。"""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD),
                        *((name, ctypes.c_size_t) for name in (
                            "peak", "current", "peak_paged", "paged", "peak_nonpaged",
                            "nonpaged", "pagefile", "peak_pagefile"))]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        api = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        api.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
        value = Counters()
        value.cb = ctypes.sizeof(value)
        if not api.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(value), value.cb):
            return {"peak_rss_bytes": None, "scope": "unavailable"}
        return {"peak_rss_bytes": value.peak, "current_rss_bytes": value.current,
                "scope": "Client OS working set, includes libraries and observation arrays"}
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {"peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
            "scope": "Client OS peak RSS, includes libraries and observation arrays"}


def _ports() -> tuple[int, int, int]:
    sockets = [socket.socket() for _ in range(3)]
    try:
        for item in sockets:
            item.bind(("127.0.0.1", 0))
        return tuple(item.getsockname()[1] for item in sockets)
    finally:
        for item in sockets:
            item.close()


def _config(role: str, ports: tuple[int, int, int]) -> LanConfig:
    identities = {name: f"{name.lower()}.secure-control.test"
                  for name in ("Client", "P1", "P2")}
    endpoints = tuple(LanEndpoint("127.0.0.1", "127.0.0.1", port) for port in ports)
    public = {"version": 1, "identities": identities,
              **{name: asdict(endpoint) for name, endpoint in zip(
                  ("p1_client", "p2_client", "p1_peer"), endpoints, strict=True,
              )}}
    digest = sha256(json.dumps(public, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode()).hexdigest()
    topology = LanTopology(identities, *endpoints, digest)
    return LanConfig(
        role, topology, None, None, None, 30., 30., 5., None,
        _ROOT / "configs/cart_pole_observer_lan.example.yaml" if role == "Client" else None,
        30., "insecure_tcp",
    )


def _meter(role: str, ports: tuple[int, int, int], delay_ms: float, role_steps=None):
    """包住既有 framing 最外层，只数发送次数/字节，不解码或保存 payload。"""
    from secure_control.execution import lan_scalar_runtime, localhost_transport

    counts: dict[str, dict[str, int]] = {}
    activity = {name: 0. for name in (
        "send_ms", "receive_ms", "encode_ms", "decode_ms", "recovery_ms",
        "local_arithmetic_ms", "peer_exchange_ms", "plan_digest_ms", "dto_validation_ms",
    )}
    originals = {
        "send": localhost_transport._send_exact,
        "receive": localhost_transport._receive_exact,
        "encode": localhost_transport.encode_envelope,
        "decode": localhost_transport.decode_envelope,
        "scalar_encode": lan_scalar_runtime.encode_scalar_frame_v3,
        "scalar_decode": lan_scalar_runtime.decode_scalar_frame_v3,
    }

    def timed(name, original):
        def call(*args, **kwargs):
            started = time.perf_counter_ns()
            try:
                return original(*args, **kwargs)
            finally:
                activity[name] += (time.perf_counter_ns() - started) / 1e6
        return call

    def measured(sock, payload, deadline):
        started = time.perf_counter_ns()
        if delay_ms:
            time.sleep(delay_ms / 1000)
        local = sock.getsockname()[1]
        remote = sock.getpeername()[1]
        if role == "Client":
            recipient = "P1" if remote == ports[0] else "P2"
        elif role == "P1":
            recipient = "Client" if local == ports[0] else "P2"
        else:
            recipient = "Client" if local == ports[1] else "P1"
        direction = f"{role}->{recipient}"
        entry = counts.setdefault(direction, {"frames": 0, "application_bytes": 0})
        entry["frames"] += 1
        entry["application_bytes"] += len(payload)
        try:
            return originals["send"](sock, payload, deadline)
        finally:
            activity["send_ms"] += (time.perf_counter_ns() - started) / 1e6

    localhost_transport._send_exact = measured
    localhost_transport._receive_exact = timed("receive_ms", originals["receive"])
    localhost_transport.encode_envelope = timed("encode_ms", originals["encode"])
    localhost_transport.decode_envelope = timed("decode_ms", originals["decode"])
    lan_scalar_runtime.encode_scalar_frame_v3 = timed("encode_ms", originals["scalar_encode"])
    lan_scalar_runtime.decode_scalar_frame_v3 = timed("decode_ms", originals["scalar_decode"])
    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.protocol.coordinator import LocalProtocol3PartyEndpoint

    # 只在基准进程包住现有方法；不输出参数、返回值或任意秘密 payload。
    observations = ExitStack()
    from secure_control.execution import _localhost_peer, lan_runtime
    from secure_control.protocol import coordinator

    observations.enter_context(patch.object(
        _localhost_peer, "public_step_plan_sha256",
        timed("plan_digest_ms", _localhost_peer.public_step_plan_sha256),
    ))
    if hasattr(lan_runtime, "encode_wire_value"):
        observations.enter_context(patch.object(
            lan_runtime, "encode_wire_value", timed("dto_validation_ms", lan_runtime.encode_wire_value),
        ))

    recovery_name = ("_rehydrate_online_material" if hasattr(coordinator, "_rehydrate_online_material")
                     else "rehydrate_online_material")
    observations.enter_context(patch.object(
        coordinator, recovery_name, timed("recovery_ms", getattr(coordinator, recovery_name)),
    ))
    if recovery_name == "rehydrate_online_material":
        observations.enter_context(patch.object(
            lan_runtime, recovery_name, timed("recovery_ms", getattr(lan_runtime, recovery_name)),
        ))
    for owner, names, category in (
        (LocalProtocol3PartyEndpoint, (
            "mask_product", "finish_product", "complete_product", "finish_products",
            "mask_truncation", "p2_truncation_message_direct", "finish_truncation_p1_direct",
            "finish_truncation_p2", "complete_truncation", "stage_output", "commit",
        ), "local_arithmetic_ms"),
        (LocalhostProtocol3PeerPort, (
            "exchange_products", "product_complete", "send_truncations",
            "receive_truncations", "state_complete",
        ), "peer_exchange_ms"),
    ):
        for name in names:
            observations.enter_context(patch.object(owner, name, timed(category, getattr(owner, name))))
    if role_steps is not None:
        reply = lan_runtime._party_reply
        previous = dict(activity)
        previous_counts = {}

        def observed_reply(sock, request, *args, **kwargs):
            nonlocal previous, previous_counts
            value = reply(sock, request, *args, **kwargs)
            if (request.operation == "endpoint"
                    and getattr(request.payload, "operation", None) == "commit"):
                role_steps.append({"step": request.step, "round_id": request.round_id,
                                   "activity_ms": {k: activity[k] - v for k, v in previous.items()},
                                   "sent": {k: {field: v[field] - previous_counts.get(k, {}).get(field, 0)
                                                for field in v} for k, v in counts.items()}})
            if request.operation == "offline" or (request.operation == "endpoint"
                    and getattr(request.payload, "operation", None) == "commit"):
                previous = dict(activity)
                previous_counts = {k: dict(v) for k, v in counts.items()}
            return value

        observations.enter_context(patch.object(lan_runtime, "_party_reply", observed_reply))

    def restore():
        observations.close()
        localhost_transport._send_exact = originals["send"]
        localhost_transport._receive_exact = originals["receive"]
        localhost_transport.encode_envelope = originals["encode"]
        localhost_transport.decode_envelope = originals["decode"]
        lan_scalar_runtime.encode_scalar_frame_v3 = originals["scalar_encode"]
        lan_scalar_runtime.decode_scalar_frame_v3 = originals["scalar_decode"]

    return counts, activity, restore


def _party_job(
    config: LanConfig, ports: tuple[int, int, int], delay_ms: float, batch: bool, queue,
) -> None:
    role_steps = []
    counts, activity, restore = _meter(config.role, ports, delay_ms, role_steps)
    try:
        result = run_party_single_step(config, batch=batch)
        queue.put({"role": config.role, "status": result.get("status", "closed"),
                   "directions": counts, "activity_ms": activity, "steps": role_steps})
    except Exception as error:  # noqa: BLE001 - 基准仅导出公开错误类别
        queue.put({"role": config.role, "status": "failed",
                   "error_type": type(error).__name__, "directions": counts,
                   "activity_ms": activity, "steps": role_steps})
    finally:
        restore()


def _quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _party_outcomes(queue):
    outcomes = []
    for _ in range(2):
        try:
            outcomes.append(queue.get(timeout=10))
        except Empty:
            break
    for role in sorted({"P1", "P2"} - {item["role"] for item in outcomes}):
        outcomes.append({"role": role, "status": "not_reported", "directions": {},
                         "activity_ms": {}, "steps": []})
    return outcomes


def _timing(values: list[float]) -> dict[str, object]:
    samples = values
    if not samples:
        return {"warmup_steps": 0, "sample_count": 0, "samples_ms": [], "p50_ms": None}
    jitter = [abs(current - previous) for previous, current in pairwise(samples)]
    return {
        "warmup_steps": 0, "sample_count": len(samples),
        "quantile_method": "linear interpolation at (n-1)*p",
        "p50_ms": _quantile(samples, .5), "p95_ms": _quantile(samples, .95),
        "p99_ms": _quantile(samples, .99), "max_ms": max(samples),
        "jitter_definition": "absolute difference of adjacent observed step attempt times",
        "jitter_p95_ms": _quantile(jitter, .95) if jitter else None,
        "jitter_max_ms": max(jitter) if jitter else None,
        "over_20_ms": sum(value > 20 for value in samples),
        "samples_ms": samples,
    }


@contextmanager
def _observe_dynamic(marks):
    """复用内核的阶段回调和既有方法；仅保存本机时长和公开角色号。"""
    from secure_control.execution import lan_runtime
    from secure_control.execution._localhost_workers import _ClientPartyEndpoint
    from secure_control.protocol import Client

    prepare, complete = Client.prepare_online, lan_runtime._complete_client_round
    bind = Client.bind_online_input
    commit = _ClientPartyEndpoint.commit

    def measured_prepare(self, *args, **kwargs):
        started = time.perf_counter_ns()
        try:
            return prepare(self, *args, **kwargs)
        finally:
            marks["material_prepare_ms"] = (time.perf_counter_ns() - started) / 1e6
            marks["prepare_end_ns"] = time.perf_counter_ns()

    def measured_complete(client, p1, p2, plan, **kwargs):
        started = time.perf_counter_ns()
        marks["online_distribution_ms"] = (started - marks["prepare_end_ns"]) / 1e6
        stamps = {"start": started}
        original_phase = kwargs.pop("on_phase", None)
        def measured_phase(name):
            stamps[name] = time.perf_counter_ns()
            if original_phase is not None:
                original_phase(name)
        try:
            return complete(client, p1, p2, plan, **kwargs,
                            on_phase=measured_phase)
        finally:
            for label, begin, end in (("stage_ms", "start", "stage"),
                                      ("reconstruct_ms", "stage", "reconstruct")):
                if end in stamps:
                    marks[label] = (stamps[end] - stamps[begin]) / 1e6

    def measured_bind(self, *args, **kwargs):
        started = time.perf_counter_ns()
        try:
            return bind(self, *args, **kwargs)
        finally:
            marks["material_bind_ms"] = (time.perf_counter_ns() - started) / 1e6
            marks["prepare_end_ns"] = time.perf_counter_ns()

    def measured_commit(self):
        started = time.perf_counter_ns()
        try:
            return commit(self)
        finally:
            marks[f"p{self.party + 1}_commit_ms"] = (time.perf_counter_ns() - started) / 1e6

    with (patch.object(Client, "prepare_online", measured_prepare),
          patch.object(Client, "bind_online_input", measured_bind),
          patch.object(lan_runtime, "_complete_client_round", measured_complete),
          patch.object(_ClientPartyEndpoint, "commit", measured_commit)):
        yield


def run_continuous_observation(*, steps: int, delay_ms: float,
                               segment_steps: int, optimized=False, material_slots=16,
                               role_config: Path | None = None) -> dict[str, object]:
    """实际持续动态循环及原同步 writer；退出后报告观察，不发布图或更改调度。"""
    from secure_control.execution.lan_runtime import RunControl
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    from .cart_pole_segmented_evidence import _BatchWriter, _Spool
    from .lan_continuous_profile import load_segmented_experiment
    from .lan_runner import _run_prepared_segmented

    maximum = 10000 if optimized else 400
    if type(steps) is not int or not 2 <= steps <= maximum:
        raise ValueError(f"观察步数必须在2..{maximum}，首步不剔除。")
    if material_slots not in (0, 4, 16) or isinstance(material_slots, bool):
        raise ValueError("资格观察材料库存只可显式选择 0/4/16。")
    if type(segment_steps) is not int or not 1 <= segment_steps <= 1000:
        raise ValueError("段容量必须在1..1000")
    if not isinstance(delay_ms, (int, float)) or not 0 <= delay_ms <= 3:
        raise ValueError("单帧注入等待必须在0..3ms")
    ports = _ports()
    config = _config("Client", ports) if role_config is None else load_lan_config(role_config, "Client")
    if role_config is not None:
        ports = tuple(endpoint.port for endpoint in (
            config.topology.p1_client, config.topology.p2_client, config.topology.p1_peer,
        ))
    context = mp.get_context("spawn")
    queue = context.Queue()
    parties = [context.Process(target=_party_job, args=(
        _config(role, ports), ports, delay_ms, True, queue,
    )) for role in ("P1", "P2")] if role_config is None else []
    records, events, outcomes = [], [], []
    cycles = []
    marks, storage = {}, {"fsync_ms": 0., "fsync_count": 0, "checkpoint_ms": 0.,
                          "source_check_ms": 0.}
    counts, activity, restore = _meter("Client", ports, delay_ms)
    control, session = RunControl(), InteractiveSession()
    fsync, checkpoint = os.fsync, _Spool._checkpoint
    before_activity, before_storage = dict(activity), dict(storage)
    before_counts = {}
    current_phase, phase_start, started = None, time.perf_counter_ns(), time.perf_counter_ns()
    attempt = None

    def phase(name):
        nonlocal current_phase, phase_start, attempt, before_activity, before_storage, before_counts
        now = time.perf_counter_ns()
        if current_phase is not None:
            events.append({"phase": current_phase, "duration_ms": (now - phase_start) / 1e6,
                           "attempt": len(records) if attempt is not None else None})
        if name == "INPUT":
            attempt = now
            marks.clear()
            before_activity, before_storage = dict(activity), dict(storage)
            before_counts = {k: dict(v) for k, v in counts.items()}
        current_phase, phase_start = name, now

    def durable_step(record):
        nonlocal attempt
        sink.record_step(record)
        now = time.perf_counter_ns()
        records.append({"global_step": record.protocol.global_step,
                        "segment_index": record.protocol.segment_index,
                        "session_id": record.protocol.session_id,
                        "round_id": record.protocol.round_id, "status": "confirmed",
                        "duration_ms": (now - attempt) / 1e6,
                        "components_ms": {k: v for k, v in marks.items() if k.endswith("_ms")},
                        "activity": {k: activity[k] - v for k, v in before_activity.items()},
                        "sent": {k: {field: v[field] - before_counts.get(k, {}).get(field, 0)
                                     for field in v} for k, v in counts.items()},
                        "storage": {k: storage[k] - v for k, v in before_storage.items()}})
        attempt = None
        if len(records) >= steps:
            control.request_stop()

    def observed_cycle(timing):
        sent = {k: v["frames"] - before_counts.get(k, {}).get("frames", 0)
                for k, v in counts.items()}
        byte_counts = {k: v["application_bytes"] - before_counts.get(k, {}).get("application_bytes", 0)
                       for k, v in counts.items()}
        timing = replace(timing, public_frame_counts=sent, public_byte_counts=byte_counts)
        cycles.append(asdict(timing))
        if writer is not None:
            writer.record_cycle(timing)

    def measured_fsync(fd):
        start = time.perf_counter_ns()
        try:
            return fsync(fd)
        finally:
            storage["fsync_ms"] += (time.perf_counter_ns() - start) / 1e6
            storage["fsync_count"] += 1

    def measured_checkpoint(self, *args, **kwargs):
        start = time.perf_counter_ns()
        try:
            return checkpoint(self, *args, **kwargs)
        finally:
            storage["checkpoint_ms"] += (time.perf_counter_ns() - start) / 1e6

    try:
        with tempfile.TemporaryDirectory(prefix="secure-control-observation-") as folder:
            assembly_start = time.perf_counter_ns()
            prepared = load_segmented_experiment(config.experiment_config, segment_steps, session)
            recheck = prepared.recheck_sources

            def measured_sources():
                start = time.perf_counter_ns()
                try:
                    return recheck()
                finally:
                    storage["source_check_ms"] += (time.perf_counter_ns() - start) / 1e6

            prepared = replace(prepared, output_root=Path(folder), recheck_sources=measured_sources)
            transaction = _Spool(prepared, config, session, phase)
            writer = _BatchWriter(transaction) if optimized else None
            sink = writer if writer is not None else transaction
            initial_assembly_ms = (time.perf_counter_ns() - assembly_start) / 1e6
            for party in parties:
                party.start()
            with (_observe_dynamic(marks), patch.object(os, "fsync", measured_fsync),
                  patch.object(_Spool, "_checkpoint", measured_checkpoint)):
                result = _run_prepared_segmented(
                    config, prepared, control=control, session=session,
                    on_step=durable_step, on_segment=sink.record,
                    on_start=sink.begin, phase=phase, realtime=optimized,
                    material_slots=material_slots,
                    on_cycle=observed_cycle if optimized else None,
                    cycle_snapshot=writer.snapshot if writer else None,
                    before_sample=writer.check if writer else None,
                )
                active_storage = dict(storage)
                if writer is not None:
                    try:
                        writer.finish()
                    except OSError:
                        result = {**result, "status": "failed", "category": "OSError",
                                  "failure_phase": "WRITER_DRAIN"}
                if result["status"] != "stopped":
                    try:
                        transaction.fail(result)
                    except OSError:
                        result["checkpoint_error"] = "OSError"
            if attempt is not None:
                records.append({"global_step": len(records), "status": "failed",
                                "duration_ms": (time.perf_counter_ns() - attempt) / 1e6,
                                "failure_phase": result.get("failure_phase"),
                                "error_type": result.get("category"),
                                "components_ms": {k: v for k, v in marks.items() if k.endswith("_ms")},
                                "activity": {k: activity[k] - v for k, v in before_activity.items()},
                                "sent": {k: {field: v[field] - before_counts.get(k, {}).get(field, 0)
                                             for field in v} for k, v in counts.items()},
                                "storage": {k: storage[k] - v for k, v in before_storage.items()}})
            events.append({"phase": current_phase,
                           "duration_ms": (time.perf_counter_ns() - phase_start) / 1e6,
                           "attempt": None})
            outcomes = _party_outcomes(queue) if parties else []
            for party in parties:
                party.join(timeout=10)
    finally:
        restore()
        for party in parties:
            if party.is_alive():
                party.terminate()
                party.join(timeout=5)
        queue.close()
    directions = dict(counts)
    for item in outcomes:
        directions.update(item["directions"])
    cycle_timing = _timing([(row["cycle_completed_ns"] - row["scheduled_start_ns"]) / 1e6
                            for row in cycles if row["cycle_completed_ns"] is not None])
    device_timing = _timing([(row["device_completed_ns"] - row["scheduled_start_ns"]) / 1e6
                             for row in cycles if row["device_completed_ns"] is not None])
    return {
        "schema": "cycle-qualification-v1" if optimized else "continuous-observation-v1",
        "case": "cycle" if optimized else "continuous", "mode": "batch",
        "code_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=_ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=_ROOT, text=True)),
        "source_sha256": _source_fingerprints(),
        "environment": {"os": platform.platform(), "python": sys.version.split()[0],
                        "roles": "three local processes" if parties else "Client with externally started roles",
                        "transport": config.transport,
                        "cpu_count": mp.cpu_count(), "timer": "local perf_counter_ns",
                        "delay_model": "sleep before each application frame send",
                        "one_way_delay_ms": delay_ms},
        "clock_info": {name: {field: getattr(time.get_clock_info(name), field)
                              for field in ("implementation", "monotonic", "adjustable", "resolution")}
                       for name in ("monotonic", "perf_counter")},
        "configuration_reference": ("configs/cart_pole_observer_lan.example.yaml"
                                    if role_config is None else "external Client profile"),
        "configuration_sha256": {name: prepared.effective_config.get(name)
                                  for name in ("profile_sha256", "plant_source_sha256",
                                               "observer_source_sha256", "prime_source_sha256")},
        "input_policy": "fresh device two-measurement local chart at each scheduled attempt",
        "initial_state": prepared.effective_config["plant_contract"]["initial_state"],
        "numeric_profile": {"fractional_bits": prepared.context.fractional_bits,
                            "security_parameter": prepared.security_parameter,
                            "period_s": prepared.scene.period,
                            "modulus_bits": prepared.context.modulus.bit_length(),
                            "state_dimension": prepared.spec.state_dimension,
                            "input_dimension": prepared.spec.input_dimension,
                            "output_dimension": prepared.spec.output_dimension},
        "segment_capacity": segment_steps, "requested_steps": steps,
        "material_slots": material_slots if optimized else 0,
        "status": result["status"], "failed_phase": result.get("failure_phase"),
        "failure_category": result.get("category"),
        "successful_steps": sum(row["status"] == "confirmed" for row in records),
        "failed_attempts": sum(row["status"] == "failed" for row in records),
        "steps": records, "events": events, "party_outcomes": outcomes,
        "cycles": cycles, "cycle_summary": result.get("cycle_summary"),
        "cycle_timing": cycle_timing, "device_timing": device_timing,
        "startup_jitter_ms": [(row["actual_sample_start_ns"] - row["scheduled_start_ns"]) / 1e6
                              if row["actual_sample_start_ns"] is not None else None for row in cycles],
        "material_summary": result.get("material_summary"),
        "recording_summary": writer.snapshot() if writer else None,
        "stop_drain_ns": writer.drain_ns if writer else 0,
        "spool_io": dict(transaction.disk_metrics),
        "storage_active": active_storage, "storage_all": storage,
        "client_memory": _process_memory(),
        "resource_counts": result["resource_counts"], "directions_all_session": directions,
        "timing": _timing([row["duration_ms"] for row in records]),
        "timing_scope": ("timing: work attempt input through record callback (failure includes cleanup); "
                         "cycle_timing: completed scheduled-start through maintenance, before timing export; "
                         "device_timing: scheduled-start through confirmed device receipt; "
                         "unfinished attempts remain in cycles with null endpoints and miss status; "
                         "timing export is separately guarded and cycle_summary is authoritative"),
        "all_observation_ms": (time.perf_counter_ns() - started) / 1e6,
        "initial_assembly_ms": initial_assembly_ms,
        "activity_scope": "local arithmetic excludes peer calls; peer_exchange includes I/O, encoding and waits; send/receive/codec overlap; checkpoint includes its fsync",
        "byte_scope": "application payload plus 4-byte header; excludes TCP/TLS overhead",
        "qualification_pass": (optimized and steps == 10000 and result["status"] == "stopped"
                               and len(cycles) == steps
                               and result.get("cycle_summary", {}).get("misses") == 0
                               and all(row["status"] == "confirmed" and row["cycle_completed_ns"] is not None
                                       and row["cycle_completed_ns"] < row["deadline_ns"]
                                       for row in cycles)),
        "limits": ("actual sustained simulation runner; observation overhead included and guarded; "
                   "local frame delay is not Wi-Fi or real hardware evidence; no plots published; "
                   "spool I/O excludes timing sidecar and stop-time replay/plots; "
                   "memory is Client OS peak RSS/working set, not encoded-budget size; "
                   "baseline continuous mode explicitly has no absolute scheduling"),
    }


def run_local_benchmark(
    case: str, mode: str, *, steps: int, delay_ms: float,
) -> dict[str, object]:
    """同一代码头上可重复选择显式旧协议或默认批量协议。"""
    if case not in {"dynamic", "scalar"} or mode not in {"legacy", "batch"}:
        raise ValueError("基准 case/mode 无效")
    if type(steps) is not int or not 2 <= steps <= 400:
        raise ValueError("基准须含2..400个观测步骤，首步不剔除")
    if not isinstance(delay_ms, (int, float)) or not 0 <= delay_ms <= 3:
        raise ValueError("单向注入延迟必须在0..3ms")
    ports = _ports()
    context = mp.get_context("spawn")
    queue = context.Queue()
    parties = [context.Process(target=_party_job,
                               args=(_config(role, ports), ports, delay_ms,
                                     mode == "batch", queue))
               for role in ("P1", "P2")]
    for party in parties:
        party.start()
    counts, activity, restore = _meter("Client", ports, delay_ms)
    timings: list[float] = []
    per_step_activity: list[dict[str, float]] = []
    phase_samples: list[dict[str, float]] = []
    attempts = []
    outcomes = []
    numeric_profile = {}
    failure = None
    initial_setup_ms = None

    def measured_step(call):
        started = time.perf_counter_ns()
        status = "confirmed"
        try:
            return call()
        except Exception:
            status = "failed"
            raise
        finally:
            elapsed = (time.perf_counter_ns() - started) / 1e6
            timings.append(elapsed)
            attempts.append({"step": len(attempts), "status": status, "duration_ms": elapsed})
    try:
        config = _config("Client", ports)
        if case == "dynamic":
            from secure_control.execution import lan_runtime
            from secure_control.protocol import Client

            from .lan_continuous_profile import load_prepared_lan_experiment

            prepared = load_prepared_lan_experiment(config.experiment_config)
            contract = replace(prepared.contract, horizon_steps=steps)
            numeric_profile = {
                "fractional_bits": prepared.context.fractional_bits,
                "modulus_bits": prepared.context.modulus.bit_length(),
                "state_dimension": prepared.spec.state_dimension,
                "input_dimension": prepared.spec.input_dimension,
                "output_dimension": prepared.spec.output_dimension,
            }
            prepare = Client.prepare_online
            complete = lan_runtime._complete_client_round
            marks: dict[str, int] = {}

            def measured_prepare(self, *args, **kwargs):
                marks["prepare_start"] = time.perf_counter_ns()
                result = prepare(self, *args, **kwargs)
                marks["prepare_end"] = time.perf_counter_ns()
                return result

            def measured_complete(client, p1, p2, plan, *, batch, on_phase=None):
                marks["stage_start"] = time.perf_counter_ns()
                def measured_phase(name):
                    marks[name] = time.perf_counter_ns()
                    if on_phase is not None:
                        on_phase(name)
                return complete(client, p1, p2, plan, on_phase=measured_phase, batch=batch)

            with (patch.object(Client, "prepare_online", measured_prepare),
                  patch.object(lan_runtime, "_complete_client_round", measured_complete)):
                setup_start = time.perf_counter_ns()
                runtime = LanContinuousRuntime(
                    config, prepared.spec, prepared.context, contract,
                    prepared.security_parameter, prepared.evidence, batch=mode == "batch",
                )
                initial_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
                try:
                    for _ in range(steps):
                        marks.clear()
                        before = dict(activity)
                        measured_step(lambda: runtime.step(np.zeros(prepared.spec.input_dimension)))
                        per_step_activity.append({name: activity[name] - value
                                                  for name, value in before.items()})
                        phase_samples.append({
                            "material_prepare_ms": (marks["prepare_end"] -
                                                    marks["prepare_start"]) / 1e6,
                            "online_distribution_ms": (marks["stage_start"] -
                                                       marks["prepare_end"]) / 1e6,
                            "stage_ms": (marks["stage"] - marks["stage_start"]) / 1e6,
                            "reconstruct_ms": (marks["reconstruct"] - marks["stage"]) / 1e6,
                            "commit_ms": (marks["commit"] - marks["reconstruct"]) / 1e6,
                        })
                    runtime.finish()
                finally:
                    runtime.close()
        else:
            from secure_control.execution import lan_scalar_runtime
            from secure_control.experiments.lan_profile import _load_prime
            from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
            from secure_control.scenarios.cart_pole.swing_up import load_cart_pole_swing_up_config
            from secure_control.scenarios.cart_pole.swing_up_numeric import (
                certify_swing_up_arithmetic,
            )

            design = load_cart_pole_observer_design(_ROOT / "configs/cart_pole_observer.yaml")
            swing = load_cart_pole_swing_up_config(
                _ROOT / "configs/cart_pole_swing_up.yaml", design.plant, design.balance,
            )
            modulus, evidence, _ = _load_prime(
                _ROOT / "configs/shared_prime_256_pocklington.yaml"
            )
            program, certificate = certify_swing_up_arithmetic(
                design.plant, design.balance, swing, modulus=modulus,
                modulus_evidence=evidence,
            )
            numeric_profile = {
                "fractional_bits": certificate.fractional_bits,
                "modulus_bits": modulus.bit_length(),
                "multiplication_gates": 38,
            }
            prepare = lan_scalar_runtime.prepare_scalar_round
            send = lan_scalar_runtime._send
            receive = lan_scalar_runtime._receive
            marks: dict[str, int] = {}

            def measured_prepare(*args, **kwargs):
                marks["prepare_start"] = time.perf_counter_ns()
                result = prepare(*args, **kwargs)
                marks["prepare_end"] = time.perf_counter_ns()
                return result

            def measured_send(sock, frame, deadline):
                if frame.sender == "Client" and frame.recipient == "P1" and frame.operation in {
                    "compute", "commit",
                }:
                    marks[f"{frame.operation}_start"] = time.perf_counter_ns()
                return send(sock, frame, deadline)

            def measured_receive(sock, expected, deadline):
                result = receive(sock, expected, deadline)
                if expected.sender == "P2" and expected.recipient == "Client" and (
                    expected.operation in {"ready", "result", "committed"}
                ):
                    marks[f"{expected.operation}_end"] = time.perf_counter_ns()
                return result

            with (patch.object(lan_scalar_runtime, "prepare_scalar_round", measured_prepare),
                  patch.object(lan_scalar_runtime, "_send", measured_send),
                  patch.object(lan_scalar_runtime, "_receive", measured_receive)):
                setup_start = time.perf_counter_ns()
                runtime = LanScalarRuntime(
                    config, program, certificate, modulus=modulus,
                    modulus_evidence=evidence, run_id="public-communication-benchmark",
                    epoch_id="synthetic-step", start_physical_step=0,
                    batch=mode == "batch",
                )
                initial_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
                try:
                    values = {"p": .2, "v": -.4, "beta": .31, "omega": 1.7}
                    for step in range(steps):
                        marks.clear()
                        before = dict(activity)
                        measured_step(lambda current_step=step: runtime.step(values, current_step))
                        per_step_activity.append({name: activity[name] - value
                                                  for name, value in before.items()})
                        phase_samples.append({
                            "material_prepare_ms": (marks["prepare_end"] -
                                                    marks["prepare_start"]) / 1e6,
                            "online_distribution_ms": (marks["ready_end"] -
                                                       marks["prepare_end"]) / 1e6,
                            "stage_ms": (marks["result_end"] -
                                         marks["compute_start"]) / 1e6,
                            "reconstruct_ms": (marks["commit_start"] -
                                               marks["result_end"]) / 1e6,
                            "commit_ms": (marks["committed_end"] -
                                          marks["commit_start"]) / 1e6,
                        })
                    runtime.end()
                finally:
                    runtime.close()
        outcomes = _party_outcomes(queue)
        for party in parties:
            party.join(timeout=10)
        if any(party.exitcode != 0 for party in parties) or any(
            item["status"] not in {"closed", "complete"} for item in outcomes
        ):
            raise RuntimeError("角色未成功完成基准会话")
    except Exception as error:  # noqa: BLE001 - 原始失败只保留公开错误类别及已观测尝试
        failure = type(error).__name__
        if not outcomes:
            outcomes = _party_outcomes(queue)
    finally:
        restore()
        for party in parties:
            if party.is_alive():
                party.terminate()
                party.join(timeout=5)
        queue.close()
    directions = dict(counts)
    for item in outcomes:
        directions.update(item["directions"])
    overhead = {name: 5 if case == "dynamic" else 4
                for name in ("Client->P1", "Client->P2", "P1->Client", "P2->Client")}
    overhead.update({"P1->P2": 1, "P2->P1": 1})
    online_frames = {}
    for direction, fixed_frames in overhead.items():
        if failure is not None:
            break
        actual = directions[direction]["frames"] - fixed_frames
        if actual < 0 or actual % steps:
            raise RuntimeError("公开帧数不符合固定会话 setup/结束边界")
        online_frames[direction] = actual // steps
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                                  text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"],
                                         cwd=_ROOT, text=True).strip())
    return {
        "schema": "communication-benchmark-v1", "case": case, "mode": mode,
        "status": "failed" if failure else "complete", "failure_type": failure,
        "code_sha": sha, "dirty": dirty,
        "source_sha256": _source_fingerprints(),
        "command": ["secure-control", "benchmark", "--case", case, "--mode", mode,
                    "--steps", str(steps), "--delay-ms", str(delay_ms)],
        "environment": {"os": platform.platform(), "python": sys.version.split()[0],
                        "cpu_count": mp.cpu_count(), "architecture": platform.machine(),
                        "roles": "three local processes", "transport": "insecure_tcp",
                        "delay_model": "sleep before each application frame send",
                        "one_way_delay_ms": delay_ms,
                        "timer": "perf_counter_ns; Client online prepare through double commit"},
        "configuration_reference": "configs/cart_pole_observer_lan.example.yaml"
        if case == "dynamic" else "configs/cart_pole_swing_up.yaml",
        "public_topology_sha256": config.topology.digest,
        "numeric_profile": numeric_profile,
        "steps": steps, "successful_steps": sum(item["status"] == "confirmed" for item in attempts),
        "failed_steps": sum(item["status"] == "failed" for item in attempts),
        "raw_attempts": attempts, "initial_setup_ms": initial_setup_ms,
        "resources_per_step": {"products": 30 if case == "dynamic" else 38,
                               "truncations": 4 if case == "dynamic" else 38},
        "timing": _timing(timings), "directions_all_session": directions,
        "online_frames_per_step": online_frames,
        "client_request_reply_groups_per_step": (
            online_frames["Client->P1"] + online_frames["Client->P2"] if not failure else None
        ),
        "peer_frames_per_step": online_frames["P1->P2"] + online_frames["P2->P1"] if not failure else None,
        "online_frame_derivation": "whole-session directional frames minus fixed setup/end frames (Client 5 dynamic or 4 scalar per direction; peer 1 per direction), divided by steps",
        "client_phase_p50_ms": {
            name: _quantile([item[name] for item in phase_samples], .5)
            for name in (phase_samples[0] if phase_samples else {})
        },
        "client_step_activity_p50_ms": {
            name: _quantile([item[name] for item in per_step_activity], .5) if per_step_activity else None
            for name in activity
        },
        "party_activity_all_session_ms": {
            item["role"]: item["activity_ms"] for item in outcomes
        },
        "party_steps": {item["role"]: item["steps"] for item in outcomes},
        "raw_step_phases_ms": phase_samples,
        "raw_step_activity_ms": per_step_activity,
        "activity_scope": "Client activity is within step; send includes injected delay, receive includes waiting; encode/decode and wall phases overlap, stage includes remote compute and peer I/O",
        "byte_scope": "application frame payload plus 4-byte header; includes setup/end; excludes TCP/TLS overhead",
        "limits": "synthetic kernel benchmark, no plant, GUI, three-machine network or 20ms guarantee",
    }
