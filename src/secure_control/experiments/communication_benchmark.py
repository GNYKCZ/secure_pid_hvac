"""#116 本机三进程公开通信基准；只保存帧、字节与墙钟时间。"""

from __future__ import annotations

import json
import multiprocessing as mp
import platform
import socket
import subprocess
import sys
import time
from dataclasses import asdict, replace
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from unittest.mock import patch

import numpy as np

from secure_control.execution.lan_config import LanConfig, LanEndpoint, LanTopology
from secure_control.execution.lan_runtime import LanContinuousRuntime, run_party_single_step
from secure_control.execution.lan_scalar_runtime import LanScalarRuntime

_ROOT = Path(__file__).resolve().parents[3]


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


def _meter(role: str, ports: tuple[int, int, int], delay_ms: float):
    """包住既有 framing 最外层，只数发送次数/字节，不解码或保存 payload。"""
    from secure_control.execution import lan_scalar_runtime, localhost_transport

    counts: dict[str, dict[str, int]] = {}
    activity = {name: 0. for name in ("send_ms", "receive_ms", "encode_ms", "decode_ms")}
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

    def restore():
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
    counts, activity, restore = _meter(config.role, ports, delay_ms)
    try:
        result = run_party_single_step(config, batch=batch)
        queue.put({"role": config.role, "status": result.get("status", "closed"),
                   "directions": counts, "activity_ms": activity})
    except Exception as error:  # noqa: BLE001 - 基准仅导出公开错误类别
        queue.put({"role": config.role, "status": "failed",
                   "error_type": type(error).__name__, "directions": counts,
                   "activity_ms": activity})
    finally:
        restore()


def _quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _timing(values: list[float]) -> dict[str, object]:
    samples = values[1:]
    jitter = [abs(current - previous) for previous, current in pairwise(samples)]
    return {
        "warmup_steps": 1, "sample_count": len(samples),
        "quantile_method": "linear interpolation at (n-1)*p",
        "p50_ms": _quantile(samples, .5), "p95_ms": _quantile(samples, .95),
        "p99_ms": _quantile(samples, .99), "max_ms": max(samples),
        "jitter_definition": "absolute difference of adjacent successful step times",
        "jitter_p95_ms": _quantile(jitter, .95) if jitter else None,
        "jitter_max_ms": max(jitter) if jitter else None,
        "over_20_ms": sum(value > 20 for value in samples),
        "timeouts": 0, "samples_ms": samples,
    }


def run_local_benchmark(
    case: str, mode: str, *, steps: int, delay_ms: float,
) -> dict[str, object]:
    """同一代码头上可重复选择显式旧协议或默认批量协议。"""
    if case not in {"dynamic", "scalar"} or mode not in {"legacy", "batch"}:
        raise ValueError("基准 case/mode 无效")
    if type(steps) is not int or not 2 <= steps <= 400:
        raise ValueError("基准须含1个warmup和1..399个样本")
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

            def measured_complete(client, p1, p2, plan, *, batch):
                marks["stage_start"] = time.perf_counter_ns()
                return complete(client, p1, p2, plan, on_phase=lambda name: marks.__setitem__(
                    name, time.perf_counter_ns()), batch=batch)

            with (patch.object(Client, "prepare_online", measured_prepare),
                  patch.object(lan_runtime, "_complete_client_round", measured_complete)):
                runtime = LanContinuousRuntime(
                    config, prepared.spec, prepared.context, contract,
                    prepared.security_parameter, prepared.evidence, batch=mode == "batch",
                )
                try:
                    for _ in range(steps):
                        marks.clear()
                        before = dict(activity)
                        start = time.perf_counter_ns()
                        runtime.step(np.zeros(prepared.spec.input_dimension))
                        timings.append((time.perf_counter_ns() - start) / 1e6)
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
                runtime = LanScalarRuntime(
                    config, program, certificate, modulus=modulus,
                    modulus_evidence=evidence, run_id="public-communication-benchmark",
                    epoch_id="synthetic-step", start_physical_step=0,
                    batch=mode == "batch",
                )
                try:
                    values = {"p": .2, "v": -.4, "beta": .31, "omega": 1.7}
                    for step in range(steps):
                        marks.clear()
                        before = dict(activity)
                        start = time.perf_counter_ns()
                        runtime.step(values, step)
                        timings.append((time.perf_counter_ns() - start) / 1e6)
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
        outcomes = [queue.get(timeout=10) for _ in parties]
        for party in parties:
            party.join(timeout=10)
        if any(party.exitcode != 0 for party in parties) or any(
            item["status"] not in {"closed", "complete"} for item in outcomes
        ):
            raise RuntimeError("角色未成功完成基准会话")
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
        "code_sha": sha, "dirty": dirty,
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
        "steps": steps, "successful_steps": steps, "failed_steps": 0,
        "resources_per_step": {"products": 30 if case == "dynamic" else 38,
                               "truncations": 4 if case == "dynamic" else 38},
        "timing": _timing(timings), "directions_all_session": directions,
        "online_frames_per_step": online_frames,
        "client_request_reply_groups_per_step": (
            online_frames["Client->P1"] + online_frames["Client->P2"]
        ),
        "peer_frames_per_step": online_frames["P1->P2"] + online_frames["P2->P1"],
        "online_frame_derivation": "whole-session directional frames minus fixed setup/end frames (Client 5 dynamic or 4 scalar per direction; peer 1 per direction), divided by steps",
        "client_phase_p50_ms": {
            name: _quantile([item[name] for item in phase_samples[1:]], .5)
            for name in phase_samples[0]
        },
        "client_step_activity_p50_ms": {
            name: _quantile([item[name] for item in per_step_activity[1:]], .5)
            for name in activity
        },
        "party_activity_all_session_ms": {
            item["role"]: item["activity_ms"] for item in outcomes
        },
        "activity_scope": "Client activity is within step; send includes injected delay, receive includes waiting; encode/decode and wall phases overlap, stage includes remote compute and peer I/O",
        "byte_scope": "application frame payload plus 4-byte header; includes setup/end; excludes TCP/TLS overhead",
        "limits": "synthetic kernel benchmark, no plant, GUI, three-machine network or 20ms guarantee",
    }
