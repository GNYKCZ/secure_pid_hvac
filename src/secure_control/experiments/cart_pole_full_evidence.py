"""#103 完整路线 v3 证据；旧分段 v1/v2 reader 保持原入口和语义。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

import numpy as np

from secure_control.crypto.primes import verify_prime_modulus
from secure_control.execution.cycle_timing import CycleTiming
from secure_control.execution.localhost_codec import _decode_prime_evidence, _encode_prime_evidence
from secure_control.protocol.arithmetic import ScalarProgram
from secure_control.scenarios.cart_pole.adapter import (
    CartPoleAdapter,
    CartPoleObserverSimulation,
    ControlCommand,
)
from secure_control.scenarios.cart_pole.contract import CartPoleContract
from secure_control.scenarios.cart_pole.controller import CartPoleBalanceConfig
from secure_control.scenarios.cart_pole.observer import (
    CartPoleObserverConfig,
    build_cart_pole_observer_design,
)
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_full_experiment import SecureFullResult
from secure_control.scenarios.cart_pole.swing_up import (
    CartPoleSwingUpConfig,
    CausalVelocityEstimator,
    SwingUpSupervisor,
    energy_shaping_force,
)
from secure_control.scenarios.cart_pole.swing_up_experiment import SwingUpResult
from secure_control.scenarios.cart_pole.swing_up_numeric import certify_swing_up_arithmetic

from .cart_pole_segmented_evidence import _bytes, _decode, _hash, _path, _same

FORMAT = "cart_pole_full_run"
MAX_FILE = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerifiedFullRun:
    """reader 完整重放后暴露的不可变公开结果。"""

    path: Path
    manifest: dict
    report: dict
    steps: tuple[dict, ...]
    cycles: tuple[CycleTiming, ...] = ()

    def observation(self, step: int) -> dict:
        if type(step) is not int or not 0 <= step <= self.manifest["N"]:
            raise ValueError("观测索引超界")
        state = (self.report["state"][step])
        return {"step": step, "state": tuple(state),
                "phase": (self.steps[step]["phase"] if step < len(self.steps)
                          else self.report["observations"][step]["phase"]
                          if step < len(self.report["observations"]) else
                          self.steps[-1]["phase"]),
                "controller_source": (self.steps[step]["source"]
                                      if step < len(self.steps) else None)}


def write_cart_pole_full_run(result: SecureFullResult, directory: str | Path) -> Path:
    """只发布真实物理确认前缀；目标不可覆盖，半写入目录不冒充正式完成。"""
    physical = result.physical
    if physical.route != "secure_full" or len(result.steps) != physical.completed_steps:
        raise ValueError("v3 完整路线只接受相等的协议/物理确认前缀")
    epochs = list(result.epoch_events)
    sealed = [(index, close["physical_end"]) for index, epoch in enumerate(epochs)
              for close in epoch["closed_segments"]]
    if not sealed:
        raise ValueError("v3 失败运行尚无双方密封的物理前缀")
    last_epoch, sealed_end = sealed[-1]
    if sealed_end != physical.completed_steps or last_epoch + 1 != len(epochs):
        if sealed_end < 1 or sealed_end > physical.completed_steps:
            raise ValueError("v3 双方密封前缀无效")
        original = physical
        physical = replace(
            physical,
            time_s=physical.time_s[:sealed_end + 1],
            state=physical.state[:sealed_end + 1],
            output=physical.output[:sealed_end + 1],
            upright_angle_rad=physical.upright_angle_rad[:sealed_end + 1],
            raw_force=physical.raw_force[:sealed_end],
            applied_force=physical.applied_force[:sealed_end],
            disturbance_force=physical.disturbance_force[:sealed_end],
            total_force=physical.total_force[:sealed_end],
            mode_for_interval=physical.mode_for_interval[:sealed_end],
            observations=physical.observations[:sealed_end + 1],
            transitions=tuple(row for row in physical.transitions
                              if row.observation_step <= sealed_end),
            disturbance_events=tuple(row for row in physical.disturbance_events
                                     if row[0] < sealed_end),
            termination="failed", goal_met=False,
            first_stable_step=(physical.first_stable_step
                               if physical.first_stable_step is not None
                               and physical.first_stable_step <= sealed_end else None),
            measurement=physical.measurement[:sealed_end + 1],
            estimated_state=physical.estimated_state[:sealed_end + 1],
            controller_source=physical.controller_source[:sealed_end],
            observer_state_before=physical.observer_state_before[:sealed_end],
            observer_initializations=tuple(row for row in physical.observer_initializations
                                           if row[0] <= sealed_end),
        )
        epochs = epochs[:last_epoch + 1]
        unsealed = {"physical_steps_before_failure": original.completed_steps,
                    "first_unsealed_step": sealed_end,
                    "attempted_step": original.failure_interval_step,
                    "unconfirmed_protocol_step": result.unconfirmed_protocol_step}
    else:
        unsealed = None
    report = physical.to_report()
    report["resource_counts"] = {
        "beaver_triples": sum(row["products"] for row in result.steps[:sealed_end]),
        "truncations": sum(row["truncations"] for row in result.steps[:sealed_end]),
    }
    report["run_id"] = result.run_id
    report["wall_seconds"] = result.wall_seconds
    report["unconfirmed_protocol_step"] = result.unconfirmed_protocol_step
    report["unsealed_failure"] = unsealed
    if result.timing_context is not None:
        report["cycle_failure"] = result.cycle_failure
        report["finalization_failure"] = result.finalization_failure
    return _publish(report, result.steps[:sealed_end], epochs, directory,
                    modulus=result.modulus, modulus_evidence=result.modulus_evidence,
                    cycles=result.cycles if result.timing_context is not None else None,
                    timing_context=result.timing_context)


def write_cart_pole_plaintext_full_run(result: SwingUpResult, directory: str | Path) -> Path:
    """明文独立 run 也用 v3 物理逐步格式；资源恒零且不构造安全 epoch。"""
    if result.route != "plaintext_full":
        raise ValueError("需要明文完整路线")
    report = result.to_report()
    report["run_id"] = f"plaintext-full-{secrets.token_hex(16)}"
    report["unconfirmed_protocol_step"] = None
    rows = []
    for k, source in enumerate(result.controller_source):
        rows.append({
            "physical_step": k, "phase": result.mode_for_interval[k], "source": source,
            "raw_force_n": float(result.raw_force[k, 0]),
            "applied_force_n": float(result.applied_force[k, 0]),
            "disturbance_force_n": float(result.disturbance_force[k, 0]),
            "total_force_n": float(result.total_force[k, 0]),
            "physical_confirmed": True, "products": 0, "truncations": 0,
            "resource_ids": [], "epoch_id": None, "session_id": None,
            "local_step": None, "round_id": None,
        })
    return _publish(report, rows, (), directory)


def _publish(report: dict, steps, epochs, directory: str | Path, *,
             modulus: int | None = None, modulus_evidence=None,
             cycles=None, timing_context=None) -> Path:
    target = Path(directory)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    stage = Path(tempfile.mkdtemp(prefix=".cart-pole-full-", dir=target.parent))
    try:
        (stage / "physical.json").write_bytes(_bytes(report))
        with (stage / "steps.jsonl").open("xb") as stream:
            for step in steps:
                stream.write(_bytes(step))
        manifest = {
            "format": FORMAT, "format_version": 4 if cycles is not None else 3,
            "route": report["route"], "run_id": report["run_id"],
            "N": report["summary"]["completed_steps"],
            "status": ("failed_prefix" if report["termination"] == "failed" else "complete"),
            "epochs": list(epochs),
            "prime": (None if modulus is None else {
                "modulus": str(modulus), "evidence": _encode_prime_evidence(modulus_evidence),
            }),
            "resource_counts": report["resource_counts"],
            "physical_sha256": _hash(stage / "physical.json"),
            "steps_sha256": _hash(stage / "steps.jsonl"),
        }
        if cycles is not None:
            with (stage / "timing.jsonl").open("xb") as stream:
                for cycle in cycles:
                    stream.write(_bytes(asdict(cycle)))
            manifest.update({"timing_sha256": _hash(stage / "timing.jsonl"),
                             "timing_context": timing_context,
                             "timing_summary": _timing_summary(cycles),
                             "cycle_failure": report["cycle_failure"],
                             "finalization_failure": report["finalization_failure"]})
        (stage / "run.json").write_bytes(_bytes(manifest))
        open_verified_cart_pole_full_run(stage)
        if target.exists() or target.is_symlink():
            raise FileExistsError(target)
        os.rename(stage, target)
        return target
    except Exception:
        shutil.rmtree(stage)
        raise


def _finite_close(actual, expected, *, atol=1e-10) -> None:
    a = np.asarray(actual, dtype=float)
    b = np.asarray(expected, dtype=float)
    if a.shape != b.shape or not np.isfinite(a).all() or not np.isfinite(b).all() or not np.allclose(
        a, b, rtol=0, atol=atol,
    ):
        raise ValueError("v3 数值或物理重放不一致")


def _timing_summary(cycles) -> dict:
    """只派生周期事实；仿真目标和周期资格分别判断。"""
    return {"attempts": len(cycles),
            "completed_cycles": sum(c.status == "confirmed" for c in cycles),
            "misses": sum(c.status.startswith("miss_") for c in cycles),
            "failed_cycles": sum(c.status != "confirmed" for c in cycles),
            "protocol_committed_count": cycles[-1].protocol_committed_count if cycles else 0,
            "physically_confirmed_count": cycles[-1].physically_confirmed_count if cycles else 0,
            "durable_step_count": 0}


def _verified_timing(root, manifest, report, steps, period_s, horizon) -> tuple[CycleTiming, ...]:
    """v4独立严格核验全尝试时序；未密封尾部绝不加入数学/物理验证轨迹。"""
    path = _path(root, "timing.jsonl", limit=MAX_FILE)
    if _hash(path) != manifest.get("timing_sha256"):
        raise ValueError("v4 timing摘要缺失或错误")
    context = manifest.get("timing_context")
    if not isinstance(context, dict) or set(context) != {
        "mode", "code_sha", "dirty", "source_sha256", "configuration_sha256", "initial_preparation_ns",
        "t0_ns", "epoch_bindings", "replayable_steps_before_sealing",
        "finalization_duration_ns",
        "proof_cache",
    } or context["mode"] != "absolute":
        raise ValueError("v4时序来源/模式无效")
    def integer(value, name):
        if type(value) is not int or value < 0:
            raise ValueError(f"v4 {name}不是非负整数")
        return value
    def digest(value, size=64):
        return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None
    if context["code_sha"] is not None and not digest(context["code_sha"], 40):
        raise ValueError("v4 code_sha无效")
    if context["dirty"] is not None and type(context["dirty"]) is not bool:
        raise ValueError("v4 dirty标记无效")
    sources = context["source_sha256"]
    if (not isinstance(sources, dict) or not sources or len(sources) > 64
            or any(not isinstance(k, str) or ".." in k
                   or re.fullmatch(r"src/secure_control/[a-zA-Z0-9_/]+\.py", k) is None
                   or not digest(v) for k, v in sources.items())
            or not {"src/secure_control/scenarios/cart_pole/secure_full_experiment.py",
                    "src/secure_control/execution/cycle_timing.py",
                    "src/secure_control/experiments/cart_pole_full_evidence.py"} <= sources.keys()):
        raise ValueError("v4源码来源hash无效")
    config_hash = hashlib.sha256(json.dumps(report["configurations"], sort_keys=True,
                                           separators=(",", ":"), ensure_ascii=False,
                                           allow_nan=False).encode()).hexdigest()
    if context["configuration_sha256"] != config_hash:
        raise ValueError("v4配置来源hash错误")
    t0 = integer(context["t0_ns"], "t0")
    integer(context["initial_preparation_ns"], "initial_preparation_ns")
    integer(context["finalization_duration_ns"], "finalization_duration_ns")
    cache = context["proof_cache"]
    if not isinstance(cache, dict) or set(cache) != {"capacity", "byte_limit", "entries", "charged_bytes",
                                                   "hits", "misses", "evictions", "warmup_ns", "warmed_candidates"}:
        raise ValueError("v4固定计算准备摘要无效")
    for name, value in cache.items():
        integer(value, name)
    if not (1 <= cache["capacity"] <= 128 and 2048 <= cache["byte_limit"] <= 4 * 1024 * 1024
            and cache["entries"] <= cache["capacity"] and cache["charged_bytes"] <= cache["byte_limit"]
            and 1 <= cache["warmed_candidates"] <= 128):
        raise ValueError("v4固定计算缓存预算不一致")
    replayable = integer(context["replayable_steps_before_sealing"], "replayable_steps")
    if not manifest["N"] <= replayable <= horizon:
        raise ValueError("v4原物理可重放前缀与密封不一致")
    bindings = context["epoch_bindings"]
    if not isinstance(bindings, list) or not bindings or len(bindings) > horizon:
        raise ValueError("v4缺少epoch身份观察")
    previous, starts, sessions, epochs = None, [], set(), set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {
            "physical_start", "phase", "epoch_id", "session_id", "previous_session_id",
        }:
            raise ValueError("v4 epoch字段无效")
        start = integer(binding["physical_start"], "epoch_start")
        if (start >= horizon or (starts and start <= starts[-1]) or (not starts and start != 0)
                or binding["phase"] not in {"kick", "energy", "dynamic"}
                or any(not isinstance(binding[k], str) or not binding[k]
                       for k in ("epoch_id", "session_id"))
                or binding["epoch_id"] in epochs or binding["session_id"] in sessions
                or binding["previous_session_id"] != previous):
            raise ValueError("v4 epoch身份链错误")
        starts.append(start); sessions.add(binding["session_id"]); epochs.add(binding["epoch_id"])
        previous = binding["session_id"]
    for index, epoch in enumerate(manifest["epochs"]):
        if index >= len(bindings) or any(bindings[index][k] != epoch[k] for k in bindings[index]):
            raise ValueError("v4公开epoch与已密封身份冲突")
    cycles, seen_rounds = [], set()
    expected_fields = {f.name for f in fields(CycleTiming)}
    period = round(period_s * 1e9)
    with path.open("rb") as stream:
        for raw in stream:
            if len(raw) > 4096 or not raw.endswith(b"\n") or len(cycles) >= horizon:
                raise ValueError("v4周期记录超界")
            row = _decode(raw)
            if set(row) != expected_fields or raw != _bytes(row):
                raise ValueError("v4周期字段/规范编码无效")
            for name in ("format_version", "segment_index", "global_step", "period_ns", "scheduled_start_ns",
                         "deadline_ns", "protocol_committed_count", "physically_confirmed_count", "durable_step_count"):
                integer(row[name], name)
            for name in ("actual_sample_start_ns", "device_completed_ns", "bookkeeping_completed_ns", "cycle_completed_ns"):
                if row[name] is not None:
                    integer(row[name], name)
            for name in ("run_id", "session_id", "controller_epoch", "round_id", "failure_phase", "status"):
                if row[name] is not None and (not isinstance(row[name], str) or not 0 < len(row[name]) <= 256):
                    raise ValueError("v4身份/状态类型无效")
            for name in ("phase_durations_ns", "queue_levels", "public_frame_counts", "public_byte_counts"):
                mapping = row[name]
                if mapping is None and name in {"public_frame_counts", "public_byte_counts"}:
                    continue
                if not isinstance(mapping, dict) or len(mapping) > 64:
                    raise ValueError("v4公开分项类型/数量无效")
                for key, value in mapping.items():
                    if not isinstance(key, str) or not 0 < len(key) <= 80:
                        raise ValueError("v4公开分项字段越界")
                    integer(value, "公开分项")
            record = CycleTiming(**row)
            k = len(cycles)
            if (type(record.format_version) is not int or record.format_version != 1
                    or record.global_step != k or record.run_id != manifest["run_id"]
                    or record.period_ns != period or record.scheduled_start_ns != t0 + k * period
                    or record.durable_step_count != 0
                    or record.protocol_committed_count not in {k, k + 1}
                    or record.physically_confirmed_count not in {k, k + 1}
                    or record.physically_confirmed_count > record.protocol_committed_count
                    or record.status not in {"confirmed", "miss_before_apply", "miss_after_apply",
                                             "failed_before_apply", "failed_after_apply"}):
                raise ValueError("v4周期计划/计数/状态无效")
            for mapping in (record.phase_durations_ns, record.queue_levels,
                            record.public_frame_counts, record.public_byte_counts):
                if mapping is not None and (not isinstance(mapping, dict) or len(mapping) > 64
                        or any(not isinstance(key, str) or not key or len(key) > 80 for key in mapping)):
                    raise ValueError("v4公开分项越界")
            endpoints = [record.actual_sample_start_ns, record.device_completed_ns,
                         record.bookkeeping_completed_ns, record.cycle_completed_ns]
            reached = [value for value in endpoints if value is not None]
            if (reached != sorted(reached) or (reached and reached[0] < record.scheduled_start_ns)
                    or (record.actual_sample_start_ns is None and any(v is not None for v in endpoints[1:]))
                    or (record.device_completed_ns is None and record.bookkeeping_completed_ns is not None)):
                raise ValueError("v4周期端点次序错误")
            applied = record.device_completed_ns is not None
            if record.physically_confirmed_count != k + int(applied):
                raise ValueError("v4设备端点与确认数矛盾")
            if record.status == "confirmed":
                if (record.failure_phase is not None or any(v is None for v in endpoints)
                        or record.cycle_completed_ns >= record.deadline_ns
                        or record.protocol_committed_count != k + 1):
                    raise ValueError("v4未完成或迟到周期冒充完成")
            elif (record.cycle_completed_ns is not None
                  or not isinstance(record.failure_phase, str)
                  or re.fullmatch(r"[A-Z][A-Z_]*", record.failure_phase) is None
                  or record.status.endswith("after_apply") != applied):
                raise ValueError("v4失败端点/阶段/施力事实错误")
            if cycles and cycles[-1].status != "confirmed":
                raise ValueError("v4失败后继续控制")
            binding = bindings[max(i for i, start in enumerate(starts) if start <= k)]
            if record.session_id is None or record.controller_epoch is None:
                if (record.session_id is not None or record.controller_epoch is not None
                        or record.status == "confirmed" or applied or record.round_id is not None):
                    raise ValueError("v4未建立身份冒充合法控制")
            elif (record.session_id, record.controller_epoch) != (binding["session_id"], binding["epoch_id"]):
                raise ValueError("v4周期epoch错误")
            if record.round_id is not None:
                if not isinstance(record.round_id, str) or not record.round_id or record.round_id in seen_rounds:
                    raise ValueError("v4轮身份错误或重用")
                seen_rounds.add(record.round_id)
            if k < len(steps):
                expected = steps[k]
                if (not applied or record.protocol_committed_count != k + 1
                        or (record.session_id, record.controller_epoch, record.round_id)
                        != (expected["session_id"], expected["epoch_id"], expected["round_id"])):
                    raise ValueError("v4 timing与已验证物理步冲突")
                epoch = next(e for e in manifest["epochs"] if e["epoch_id"] == expected["epoch_id"])
                segment = (sum(c["physical_end"] <= k for c in epoch["closed_segments"])
                           if epoch["phase"] == "dynamic" else 0)
                if record.segment_index != segment:
                    raise ValueError("v4段索引与密封边界错误")
            cycles.append(record)
    if (not cycles or cycles[-1].physically_confirmed_count < replayable
            or _bytes(manifest.get("timing_summary")) != _bytes(_timing_summary(cycles))):
        raise ValueError("v4遗漏已确认步或周期摘要错误")
    failure = manifest.get("cycle_failure")
    if report.get("cycle_failure") != failure:
        raise ValueError("v4周期失败结论冲突")
    last = cycles[-1]
    if last.status != "confirmed":
        if not isinstance(failure, dict) or set(failure) != {
            "physical_step", "failure_phase", "status", "failure_type", "protocol_state",
            "protocol_committed_count", "physically_confirmed_count", "sealed_step_count", "durable_step_count",
        } or report["termination"] != "failed":
            raise ValueError("v4缺少失败尝试或失败结论")
        if (integer(failure["physical_step"], "failed_step") != last.global_step or failure["failure_phase"] != last.failure_phase
                or failure["status"] != last.status
                or integer(failure["protocol_committed_count"], "protocol_count") != last.protocol_committed_count
                or integer(failure["physically_confirmed_count"], "physical_count") != last.physically_confirmed_count
                or integer(failure["durable_step_count"], "durable") != 0
                or integer(failure["sealed_step_count"], "sealed") not in {0, *(c["physical_end"] for e in manifest["epochs"] for c in e["closed_segments"])}
                or failure["sealed_step_count"] > last.physically_confirmed_count
                or not isinstance(failure["failure_type"], str) or not failure["failure_type"]
                or failure["protocol_state"] not in {"not_committed", "uncertain", "double_committed"}
                or (failure["protocol_state"] == "double_committed") != (last.protocol_committed_count == last.global_step + 1)):
            raise ValueError("v4失败身份/计数不一致")
    elif failure is not None:
        raise ValueError("v4失败结论没有失败尝试")
    finalization = manifest.get("finalization_failure")
    if report.get("finalization_failure") != finalization:
        raise ValueError("v4结束失败结论冲突")
    if finalization is not None and (not isinstance(finalization, dict)
            or set(finalization) != {"phase", "failure_type"}
            or finalization["phase"] != "FINALIZATION" or report["termination"] != "failed"
            or not isinstance(finalization["failure_type"], str) or not finalization["failure_type"]):
        raise ValueError("v4结束失败事实无效")
    return tuple(cycles)


def _verified_outcome(report: dict, manifest: dict, horizon: int) -> None:
    """由已重放的观测和已确认前缀核对终止结论及派生摘要。"""
    observations = report["observations"]
    n = manifest["N"]
    entries = [row["step"] for index, row in enumerate(observations)
               if row["status"] == "stable"
               and (index == 0 or observations[index - 1]["status"] != "stable")]

    def peak(rows):
        return np.max(np.abs(np.asarray(rows, dtype=float)), axis=0).tolist() if rows else None

    expected_summary = {
        "completed_steps": n,
        "first_stable_step": entries[0] if entries else None,
        "stable_entry_steps": entries,
        "max_abs_state": peak(report["state"]),
        "max_abs_raw_force": peak(report["raw_force"]),
        "max_abs_applied_force": peak(report["applied_force"]),
        "max_abs_total_force": peak(report["total_force"]),
        "saturated_intervals": sum(raw != applied for raw, applied in zip(
            report["raw_force"], report["applied_force"], strict=True)),
        "final_stable_count": observations[-1]["stable_count"],
    }
    if _bytes(report["summary"]) != _bytes(expected_summary):
        raise ValueError("v3 派生摘要与已验证观测不一致")

    failure = report["failure"]
    if not isinstance(failure, dict) or set(failure) != {
        "observation_step", "interval_step", "reason", "detail",
    }:
        raise ValueError("v3 失败结论字段无效")
    termination = report["termination"]
    if termination not in {"observed_success", "time_limit", "stopped", "failed"}:
        raise ValueError("v3 终止状态无效")
    if type(report["goal_met"]) is not bool or report["goal_met"] != (
        termination == "observed_success"
    ):
        raise ValueError("v3 目标结论与终止状态不一致")
    if manifest["status"] != ("failed_prefix" if termination == "failed" else "complete"):
        raise ValueError("v3 manifest 状态与终止状态不一致")

    terminal = observations[-1] if len(observations) == n + 1 else None
    unsealed = report.get("unsealed_failure")
    if unsealed is not None:
        closure = (manifest["epochs"][-1]["closed_segments"][-1]
                   if manifest["route"] == "secure_full" else None)
        if (termination != "failed" or not isinstance(unsealed, dict)
                or set(unsealed) != {
                    "physical_steps_before_failure", "first_unsealed_step",
                    "attempted_step", "unconfirmed_protocol_step",
                }
                or type(unsealed["physical_steps_before_failure"]) is not int
                or not n <= unsealed["physical_steps_before_failure"] <= horizon
                or unsealed["first_unsealed_step"] != n or n >= horizon
                or unsealed["attempted_step"] != failure["interval_step"]
                or unsealed["unconfirmed_protocol_step"]
                != report["unconfirmed_protocol_step"]
                or closure is None or closure["action"] not in {"switch", "continue"}
                or closure["physical_end"] != n):
            raise ValueError("v3 未密封失败与安全确认前缀不一致")
    if termination == "failed":
        if (manifest.get("format_version") == 4
                and (manifest["cycle_failure"] is not None or manifest["finalization_failure"] is not None)
                and failure["reason"] is None):
            if any(value is not None for value in failure.values()) or report["attempted_step"] is not None:
                raise ValueError("v4 周期失败不得捏造物理失败区间")
            return  # 独立周期失败在_verified_timing严格核验；以上物理重放/摘要仍必需。
        if not isinstance(failure["reason"], str) or not failure["reason"]:
            raise ValueError("v3 失败状态缺少原因")
        if (failure["observation_step"] is not None
                and failure["interval_step"] is not None):
            raise ValueError("v3 观测失败与区间失败不能同时声明")
        if terminal is not None and terminal["phase"] == "failed":
            if (failure["observation_step"] != n
                    or failure["interval_step"] is not None
                    or failure["reason"] != terminal["failure_reason"]
                    or unsealed is not None):
                raise ValueError("v3 失败观测与结论不一致")
        elif failure["observation_step"] is not None:
            later_failure = (isinstance(unsealed, dict)
                             and type(failure["observation_step"]) is int
                             and n < failure["observation_step"]
                             == unsealed["physical_steps_before_failure"])
            if not later_failure and (terminal is not None
                                      or failure["observation_step"] != n
                                      or failure["reason"] != "measurement_invalid"):
                raise ValueError("v3 失败观测步与前缀不一致")
        elif failure["interval_step"] is not None:
            interval = failure["interval_step"]
            attempted = report["attempted_step"]
            if (type(interval) is not int or not n <= interval < horizon
                    or terminal is None or terminal["phase"] == "failed"
                    or not isinstance(attempted, dict)
                    or attempted.get("interval_step") != interval
                    or (unsealed is not None
                        and unsealed["physical_steps_before_failure"] != interval)
                    or (interval > n and (
                        not isinstance(unsealed, dict)
                        or unsealed["first_unsealed_step"] != n
                        or unsealed["physical_steps_before_failure"] != interval
                    ))):
                raise ValueError("v3 失败区间与确认前缀不一致")
        else:
            closure = (manifest["epochs"][-1]["closed_segments"][-1]
                       if manifest["route"] == "secure_full" else None)
            sealed_switch_failure = (
                failure["reason"] == "setup_or_switch"
                and terminal is not None and terminal["phase"] != "failed"
                and n < horizon and report["attempted_step"] is None
                and report["unconfirmed_protocol_step"] is None
                and report.get("unsealed_failure") is None
                and closure is not None and closure["action"] == "switch"
                and closure["physical_end"] == n
            )
            unsealed_setup_failure = (
                unsealed is not None and failure["reason"] == "setup_or_switch"
                and terminal is not None and terminal["phase"] != "failed"
                and unsealed["physical_steps_before_failure"] > n
                and report["attempted_step"] is None
            )
            if not sealed_switch_failure and not unsealed_setup_failure:
                raise ValueError("v3 失败结论没有观测、区间或已密封切换证据")
    else:
        if any(value is not None for value in failure.values()) or report["attempted_step"] is not None:
            raise ValueError("v3 非失败终止不得带失败结论")
        if termination == "stopped":
            if terminal is not None or n > horizon:
                raise ValueError("v3 停止结论与观测前缀不一致")
        else:
            expected = ("observed_success" if terminal is not None
                        and terminal["phase"] == "balance"
                        and terminal["status"] == "stable" else "time_limit")
            if terminal is None or n != horizon or termination != expected:
                raise ValueError("v3 到期结论与终点观测不一致")


def _verified_epochs(manifest: dict, steps: list[dict]) -> None:
    epochs = manifest["epochs"]
    if not isinstance(epochs, list) or not epochs or epochs[0]["physical_start"] != 0:
        raise ValueError("v3 缺少首 epoch")
    seen_sessions: set[str] = set()
    seen_epochs: set[str] = set()
    seen_rounds: set[str] = set()
    prior_end = 0
    prior_session = None
    for index, epoch in enumerate(epochs):
        start = epoch["physical_start"]
        end = epochs[index + 1]["physical_start"] if index + 1 < len(epochs) else len(steps)
        if (type(start) is not int or not prior_end == start < end <= len(steps)
                or epoch["phase"] not in {"kick", "energy", "dynamic"}
                or epoch["session_id"] in seen_sessions
                or epoch["epoch_id"] in seen_epochs
                or epoch["previous_session_id"] != prior_session
                or epoch["fractional_bits"] != (32 if epoch["phase"] == "dynamic" else 80)):
            raise ValueError("v3 epoch 链或精度无效")
        seen_sessions.add(epoch["session_id"])
        seen_epochs.add(epoch["epoch_id"])
        for local, step in enumerate(steps[start:end]):
            if (step["epoch_id"] != epoch["epoch_id"]
                    or step["session_id"] != epoch["session_id"]
                    or not isinstance(step["round_id"], str)
                    or not step["round_id"]
                    or step["source"] != {
                        "kick": "secure_public_kick", "energy": "secure_energy_gates",
                        "dynamic": "secure_dynamic_observer",
                    }[epoch["phase"]]
                    or step["local_step"] != local):
                raise ValueError("v3 步来源、epoch 或局部序号无效")
            if step["round_id"] in seen_rounds:
                raise ValueError("v3 协议轮身份重用")
            seen_rounds.add(step["round_id"])
        closures = epoch["closed_segments"]
        if not isinstance(closures, list) or not closures:
            raise ValueError("v3 epoch 缺少双方关闭回执")
        if closures[-1]["action"] != ("switch" if index + 1 < len(epochs) else "stop") and not (
            index + 1 == len(epochs) and manifest["status"] == "failed_prefix"
            and closures[-1]["action"] in {"switch", "continue"}
        ):
            raise ValueError("v3 epoch 切换动作不一致")
        if closures[-1]["physical_end"] != end:
            raise ValueError("v3 epoch 结束前缀不一致")
        closed_physical = start
        for segment_index, closure in enumerate(closures):
            if closure["action"] not in {"switch", "stop", "continue"}:
                raise ValueError("v3 关闭动作无效")
            if segment_index + 1 < len(closures) and closure["action"] != "continue":
                raise ValueError("v3 非末段只能继续同一秘密状态")
            boundary = closure["physical_end"]
            if type(boundary) is not int or not closed_physical < boundary <= end:
                raise ValueError("v3 段物理边界无效")
            if epoch["phase"] == "dynamic":
                receipts = closure["receipts"]
                segment = steps[closed_physical:boundary]
                expected = {
                    "action": closure["action"],
                    "confirmed_count": len(segment),
                    "global_start": closed_physical - start,
                    "global_end_exclusive": boundary - start,
                    "segment_index": segment_index,
                    "run_id": manifest["run_id"],
                    "last_round_id": segment[-1]["round_id"],
                }
                if ([row["role"] for row in receipts] != ["P1", "P2"]
                        or any(row["end"] != expected
                               or row["session_id"] != epoch["session_id"]
                               or row["cumulative_committed_count"] != boundary - start
                               or row["products"] != sum(item["products"]
                                                        for item in steps[start:boundary])
                               or row["truncations"] != sum(item["truncations"]
                                                           for item in steps[start:boundary])
                               for row in receipts)):
                    raise ValueError("v3 缺少独立双 party 回执")
            else:
                expected = {
                    "session_id": epoch["session_id"],
                    "epoch_id": epoch["epoch_id"],
                    "action": closure["action"],
                    "physical_end": boundary,
                    "committed_steps": end - start,
                }
                if (len(closures) != 1
                        or [item["role"] for item in closure["receipts"]] != ["P1", "P2"]
                        or any({key: value for key, value in item.items() if key != "role"}
                               != expected for item in closure["receipts"])):
                    raise ValueError("v3 scalar 缺少独立双 party 结束回执")
            closed_physical = boundary
        prior_end, prior_session = end, epoch["session_id"]


def open_verified_cart_pole_full_run(directory: str | Path) -> VerifiedFullRun:
    """有界读取、链/资源检查，再按两测量控制与 canonical 物理重放每一步。"""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("v3 产物文件集合无效")
    manifest = _decode(_path(root, "run.json", limit=MAX_FILE).read_bytes())
    version = manifest.get("format_version")
    expected_files = {"run.json", "physical.json", "steps.jsonl"}
    if version == 4:
        expected_files.add("timing.jsonl")
    if {p.name for p in root.iterdir()} != expected_files:
        raise ValueError("完整路线产物文件集合无效")
    if (manifest.get("format") != FORMAT or type(version) is not int or version not in {3, 4}
            or manifest.get("route") not in {"secure_full", "plaintext_full"}):
        raise ValueError("不是 v3 完整路线")
    if version == 4 and manifest["route"] != "secure_full":
        raise ValueError("v4只用于具有周期证据的安全完整路线")
    physical_path = _path(root, "physical.json", limit=MAX_FILE)
    steps_path = _path(root, "steps.jsonl", limit=MAX_FILE)
    if (_hash(physical_path) != manifest["physical_sha256"]
            or _hash(steps_path) != manifest["steps_sha256"]):
        raise ValueError("v3 摘要不一致")
    report = _decode(physical_path.read_bytes())
    secure = manifest["route"] == "secure_full"
    if (report["kind"] != ("cart_pole_secure_full" if secure else "cart_pole_plaintext_full")
            or report["run_id"] != manifest["run_id"]
            or report["summary"]["completed_steps"] != manifest["N"]
            or report["resource_counts"] != manifest["resource_counts"]):
        raise ValueError("v3 物理报告身份不一致")
    with steps_path.open("rb") as source:
        steps = []
        for raw in source:
            if len(raw) > 64 * 1024 or not raw.endswith(b"\n"):
                raise ValueError("v3 步记录超界")
            step = _decode(raw)
            if raw != _bytes(step):
                raise ValueError("v3 非规范步记录")
            steps.append(step)
            if len(steps) > 100_000:
                raise ValueError("v3 步数超界")
    n = manifest["N"]
    if type(n) is not int or n != len(steps) or n < 1:
        raise ValueError("v3 物理前缀长度无效")
    if (len(report["state"]) != n + 1 or len(report["output"]) != n + 1
            or len(report["time_s"]) != n + 1
            or any(len(report[name]) != n for name in (
                "raw_force", "applied_force", "disturbance_force", "total_force",
                "mode_for_interval", "controller_source",
            )) or any(len(report[name]) not in {n, n + 1} for name in (
                "measurement", "estimated_state", "observations",
            )) or len({len(report[name]) for name in (
                "measurement", "estimated_state", "observations",
            )}) != 1):
        raise ValueError("v3 N+1 观测和 N 区间长度不一致")
    if secure:
        _verified_epochs(manifest, steps)
    elif manifest["epochs"] != [] or manifest["resource_counts"] != {
        "beaver_triples": 0, "truncations": 0,
    }:
        raise ValueError("v3 明文路线不得声明安全 epoch 或资源")
    if secure:
        prime = manifest["prime"]
        if not isinstance(prime, dict) or set(prime) != {"modulus", "evidence"}:
            raise ValueError("v3 prime 元数据无效")
        modulus = int(prime["modulus"])
        evidence = _decode_prime_evidence(prime["evidence"])
        verify_prime_modulus(modulus, evidence)
    elif manifest["prime"] is not None:
        raise ValueError("v3 明文不得声明安全模数")
    config = report["configurations"]
    plant_source = CartPoleContract(**config["plant_source_contract"])
    balance = CartPoleBalanceConfig(**config["balance"])
    swing = CartPoleSwingUpConfig(**config["swing_up"])
    if secure:
        energy_program, energy_cert = certify_swing_up_arithmetic(
            plant_source, balance, swing, modulus=modulus, modulus_evidence=evidence,
        )
        kick_hash = ScalarProgram(("kick",), (), (), "kick").topology_sha256()
        for epoch in manifest["epochs"]:
            if epoch["phase"] in {"kick", "energy"} and epoch["program_sha256"] != (
                kick_hash if epoch["phase"] == "kick" else energy_program.topology_sha256()
            ):
                raise ValueError("v3 固定程序身份与参数配置不一致")
        if energy_cert.fractional_bits != 80:
            raise ValueError("v3 安全起摆证书精度不一致")
    observer = build_cart_pole_observer_design(
        plant_source, balance, CartPoleObserverConfig(**config["observer"]["observer"]),
    )
    from dataclasses import replace

    effective = replace(plant_source, initial_state=swing.initial_state)
    plant = CartPolePlant(effective)
    device = CartPoleObserverSimulation(plant, effective, swing.disturbances)
    adapter = CartPoleAdapter(effective, balance)
    supervisor = SwingUpSupervisor(
        effective, balance, swing, observer_design=observer, external_dynamic=True,
    )
    estimator = CausalVelocityEstimator(effective.sample_period_s)
    seen_resources: set[str] = set()
    dynamic_state = None
    for k, row in enumerate(steps):
        if row["physical_step"] != k or row["physical_confirmed"] is not True:
            raise ValueError("v3 物理步失序或未确认")
        _finite_close(report["state"][k], plant.state)
        _finite_close(report["output"][k], plant.output())
        _finite_close(report["time_s"][k], k * effective.sample_period_s)
        sample = device.read_measurement()
        _finite_close(report["measurement"][k], [sample.p_m, sample.theta_rad])
        estimate = estimator.observe(sample)
        _finite_close(report["estimated_state"][k], estimate)
        observed = supervisor.observe(k, estimate)
        _same(report["observations"][k], asdict(observed))
        if row["phase"] != observed.phase or observed.phase == "failed":
            raise ValueError("v3 阶段与因果监督器不一致")
        source = (("secure_dynamic_observer" if secure else "plaintext_dynamic_observer")
                  if observed.phase in {"capture", "balance"} else
                  ("secure_public_kick" if secure else "plaintext_kick")
                  if k < swing.kick_steps else
                  ("secure_energy_gates" if secure else "plaintext_energy"))
        if source != row["source"] or report["controller_source"][k] != source:
            raise ValueError("v3 安全控制来源不一致")
        if report["mode_for_interval"][k] != observed.phase:
            raise ValueError("v3 区间模式不一致")
        if source in {"secure_dynamic_observer", "plaintext_dynamic_observer"}:
            init = supervisor.latest_initialization
            if init is None:
                raise ValueError("v3 动态初始化缺失")
            if dynamic_state is None:
                dynamic_state = np.array(init.spec.x0, dtype=float)
            expected_raw = float((-observer.K @ dynamic_state)[0])
            y = np.array([sample.p_m, sample.theta_rad - init.theta_star])
            dynamic_state = observer.A @ dynamic_state + observer.L @ y
            if secure and (row["products"] <= 0 or row["truncations"] <= 0):
                raise ValueError("v3 动态资源计数无效")
            tolerance = 1e-5
        else:
            dynamic_state = None
            expected_raw = (swing.kick_direction * swing.kick_force_n
                            if source in {"secure_public_kick", "plaintext_kick"} else
                            energy_shaping_force(effective, swing, estimate))
            expected_count = 0 if source in {"secure_public_kick", "plaintext_kick"} else 38
            if not secure:
                expected_count = 0
            if (row["products"], row["truncations"]) != (expected_count, expected_count):
                raise ValueError("v3 固定门资源计数无效")
            tolerance = (float(energy_cert.bound(energy_program.output).error_abs)
                         if secure and source == "secure_energy_gates" else 1e-10)
        if not secure and (row["products"], row["truncations"], row["resource_ids"],
                           row["epoch_id"], row["session_id"]) != (0, 0, [], None, None):
            raise ValueError("v3 明文步冒充安全来源")
        expected_ids = (row["products"] + row["truncations"]
                        if source == "secure_dynamic_observer" else row["products"])
        if not isinstance(row["resource_ids"], list) or len(row["resource_ids"]) != expected_ids:
            raise ValueError("v3 资源身份数量无效")
        for identity in row["resource_ids"]:
            if not isinstance(identity, str) or not identity or identity in seen_resources:
                raise ValueError("v3 材料重用或无效")
            seen_resources.add(identity)
        _finite_close(row["raw_force_n"], expected_raw, atol=tolerance)
        _finite_close(report["raw_force"][k][0], row["raw_force_n"])
        applied = float(adapter.apply_control(np.array([row["raw_force_n"]]))[0])
        if source == "secure_dynamic_observer" and applied != row["raw_force_n"]:
            raise ValueError("v3 动态控制不允许饱和")
        _finite_close(row["applied_force_n"], applied)
        _finite_close(report["applied_force"][k][0], applied)
        receipt = device.send_control(ControlCommand(k, manifest["run_id"], k, applied))
        if receipt.disposition != "simulated_interval_completed":
            raise ValueError("v3 物理区间未完成")
        _, disturbance, total, _ = device.read_interval_forces()
        _finite_close(row["disturbance_force_n"], disturbance)
        _finite_close(row["total_force_n"], total)
        _finite_close(report["disturbance_force"][k][0], disturbance)
        _finite_close(report["total_force"][k][0], total)
        _finite_close(report["state"][k + 1], plant.state)
        _finite_close(report["output"][k + 1], plant.output())
    _finite_close(report["time_s"][n], n * effective.sample_period_s)
    if len(report["observations"]) == n + 1:
        sample = device.read_measurement()
        _finite_close(report["measurement"][n], [sample.p_m, sample.theta_rad])
        estimate = estimator.observe(sample)
        _finite_close(report["estimated_state"][n], estimate)
        _same(report["observations"][n], asdict(supervisor.observe(n, estimate)))
    _same(report["transitions"], [asdict(event) for event in supervisor.transitions])
    _same(report["observer_initializations"], [
        {"observation_step": step, "branch": branch, "theta_star_rad": theta_star,
         "x0": list(x0)}
        for step, branch, theta_star, x0 in supervisor.initializations
    ])
    if (sum(row["products"] for row in steps) != manifest["resource_counts"]["beaver_triples"]
            or sum(row["truncations"] for row in steps)
            != manifest["resource_counts"]["truncations"]):
        raise ValueError("v3 累计资源计数不一致")
    _verified_outcome(report, manifest, swing.horizon_steps)
    cycles = (_verified_timing(root, manifest, report, steps, effective.sample_period_s,
                               swing.horizon_steps) if version == 4 else ())
    return VerifiedFullRun(root, manifest, report, tuple(steps), cycles)
