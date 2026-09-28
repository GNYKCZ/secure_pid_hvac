"""#103 完整路线 v3 证据；旧分段 v1/v2 reader 保持原入口和语义。"""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import numpy as np

from secure_control.crypto.primes import verify_prime_modulus
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
    return _publish(report, result.steps[:sealed_end], epochs, directory,
                    modulus=result.modulus, modulus_evidence=result.modulus_evidence)


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
             modulus: int | None = None, modulus_evidence=None) -> Path:
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
            "format": FORMAT, "format_version": 3,
            "route": report["route"], "run_id": report["run_id"],
            "N": report["summary"]["completed_steps"],
            "status": ("complete" if report["failure"]["reason"] is None else "failed_prefix"),
            "epochs": list(epochs),
            "prime": (None if modulus is None else {
                "modulus": str(modulus), "evidence": _encode_prime_evidence(modulus_evidence),
            }),
            "resource_counts": report["resource_counts"],
            "physical_sha256": _hash(stage / "physical.json"),
            "steps_sha256": _hash(stage / "steps.jsonl"),
        }
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
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != {
        "run.json", "physical.json", "steps.jsonl",
    }:
        raise ValueError("v3 产物文件集合无效")
    manifest = _decode(_path(root, "run.json", limit=MAX_FILE).read_bytes())
    if ((manifest.get("format"), manifest.get("format_version")) != (FORMAT, 3)
            or manifest.get("route") not in {"secure_full", "plaintext_full"}):
        raise ValueError("不是 v3 完整路线")
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
    return VerifiedFullRun(root, manifest, report, tuple(steps))
