"""#103 从下垂起点经真实三进程起摆与秘密动态 observer 的完整物理路线。"""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from functools import wraps
from math import pi
from pathlib import Path
from threading import Event

import numpy as np

from secure_control.crypto.fixed_point import FixedPointContext
from secure_control.crypto.primes import PrimeModulusEvidence
from secure_control.execution.cycle_timing import (
    AbsoluteCycleClock,
    CycleDeadlineExceeded,
    CycleTiming,
    check_deadline,
)
from secure_control.execution.lan_config import LanConfig
from secure_control.execution.lan_runtime import LanSegmentedRuntime, RunControl
from secure_control.execution.lan_scalar_runtime import LanScalarRuntime
from secure_control.protocol.arithmetic import ScalarProgram, certify_scalar_program
from secure_control.protocol.roles import (
    _REACHABILITY_BASIS,
    _reachability_basis_scope,
    _warm_reachability_basis,
)

from .adapter import (
    CartPoleAdapter,
    CartPoleObserverSimulation,
    ControlCommand,
    _finite_vector,
)
from .contract import CartPoleContract, _number
from .controller import CartPoleBalanceConfig
from .observer import CartPoleObserverDesign
from .plant import CartPolePlant
from .secure_experiment import sustained_observer_numeric_contract
from .swing_up import (
    CartPoleSwingUpConfig,
    CausalVelocityEstimator,
    SwingUpSupervisor,
    _observation,
    upright_coordinates,
)
from .swing_up_experiment import SwingUpResult, _rows
from .swing_up_numeric import certify_swing_up_arithmetic


@dataclass(frozen=True, slots=True)
class SecureFullResult:
    """物理确认前缀、逐步协议来源与真实资源消耗分开保存。"""

    physical: SwingUpResult
    run_id: str
    steps: tuple[dict[str, object], ...]
    epoch_events: tuple[dict[str, object], ...]
    protocol_products: int
    protocol_truncations: int
    wall_seconds: float
    unconfirmed_protocol_step: int | None
    modulus: int
    modulus_evidence: PrimeModulusEvidence | None
    cycles: tuple[CycleTiming, ...] = ()
    cycle_failure: dict[str, object] | None = None
    timing_context: dict[str, object] | None = None
    physically_confirmed_count: int = 0
    finalization_failure: dict[str, str] | None = None
    proof_cache_summary: dict[str, object] | None = None


def _scoped_fixed_proof(function):
    """原函数拥有整个运行；只给确定性固定计算提供当前线程的有限作用域。"""
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _reachability_basis_scope(enabled=kwargs.get("realtime", False) or kwargs.get("fixed_proof_cache", False)):
            return function(*args, **kwargs)
    return wrapped


@_scoped_fixed_proof
def run_secure_full_experiment(
    plant_contract: CartPoleContract, balance: CartPoleBalanceConfig,
    config: CartPoleSwingUpConfig, observer_design: CartPoleObserverDesign,
    client: LanConfig, *, modulus: int,
    modulus_evidence: PrimeModulusEvidence | None, segment_capacity: int = 100,
    on_step: Callable[[int, tuple[float, ...], str, str, float, float], None] | None = None,
    stop_event: Event | None = None,
    realtime: bool = False,
    on_cycle: Callable[[CycleTiming], None] | None = None,
    fixed_proof_cache: bool = False,
) -> SecureFullResult:
    """Client 唯一推进 plant；P1/P2 计算 kick/能量力和非零秘密动态 state。"""
    preparation_started_ns = time.perf_counter_ns() if realtime else None
    config.validate(plant_contract, balance)
    if type(realtime) is not bool or type(fixed_proof_cache) is not bool or config.horizon_steps > 1500:
        raise ValueError("完整路线需明确realtime，且记录有界于原1500步范围")
    if client.role != "Client" or client.experiment_config is None:
        raise ValueError("secure_full 需要 Client LAN 配置")
    effective = replace(plant_contract, initial_state=config.initial_state)
    plant = CartPolePlant(effective)
    device = CartPoleObserverSimulation(plant, effective, config.disturbances)
    adapter = CartPoleAdapter(effective, balance)
    supervisor = SwingUpSupervisor(
        effective, balance, config, observer_design=observer_design,
        external_dynamic=True,
    )
    estimator = CausalVelocityEstimator(effective.sample_period_s)
    energy_program, energy_certificate = certify_swing_up_arithmetic(
        effective, balance, config, modulus=modulus,
        modulus_evidence=modulus_evidence,
    )
    kick_program = ScalarProgram(("kick",), (), (), "kick")
    kick_certificate = certify_scalar_program(
        kick_program, {"kick": Fraction.from_float(config.kick_force_n)},
        modulus=modulus, fractional_bits=80, security_parameter=80,
        modulus_evidence=modulus_evidence,
    )
    run_id = f"cart-pole-full-{secrets.token_hex(16)}"
    scalar: LanScalarRuntime | None = None
    dynamic: LanSegmentedRuntime | None = None
    dynamic_control: RunControl | None = None
    active: str | None = None
    epochs: list[dict[str, object]] = []
    protocol_rows: list[dict[str, object]] = []
    protocol_products = protocol_truncations = 0
    unconfirmed = None
    states, outputs, measurements, estimates, observations = [], [], [], [], []
    raws, applieds, disturbances, totals, modes, events, sources = [], [], [], [], [], [], []
    termination = "failed"
    failure_observation = failure_interval = reason = detail = attempted = first_stable = None
    started = time.perf_counter()
    cycles: list[CycleTiming] = []
    clock = None
    cycle_failure = None
    finalization_failure = None
    finalization_started_ns = None
    physically_confirmed_count = epoch_protocol_base = 0
    cycle_device = cycle_bookkeeping = cycle_actual = cycle_deadline = None
    cycle_segment = 0
    cycle_identity = None
    cycle_attempt_started = False
    cycle_phase = "INITIAL_SETUP"
    phase_ns: dict[str, int] = {}
    snapshots = json.dumps({
        "plant_source_contract": asdict(plant_contract), "balance": asdict(balance),
        "swing_up": asdict(config), "observer": observer_design.to_snapshot(),
        "effective_initial_state": list(effective.initial_state),
    }, allow_nan=False)

    timing_context = None
    proof_warmup_ns = proof_warmed_candidates = 0
    if realtime or fixed_proof_cache:
        warmup_started_ns = time.perf_counter_ns()
        encoded_a = np.asarray(FixedPointContext(modulus, 40, 32).encode(observer_design.A), dtype=object)
        proof_warmed_candidates = _warm_reachability_basis(encoded_a, 32)
        proof_warmup_ns = time.perf_counter_ns() - warmup_started_ns
    if realtime:
        # 启动前固定实际源码/config来源；仅公开hash，不保存本机路径或秘密材料。
        root = Path(__file__).resolve().parents[4]
        package = Path(__file__).resolve().parents[2]
        paths = (
            "scenarios/cart_pole/secure_full_experiment.py", "scenarios/cart_pole/adapter.py",
            "scenarios/cart_pole/swing_up.py", "scenarios/cart_pole/swing_up_numeric.py",
            "scenarios/cart_pole/secure_experiment.py", "execution/lan_scalar_runtime.py",
            "execution/lan_runtime.py", "execution/cycle_timing.py", "execution/lan_transport.py",
            "execution/localhost_transport.py", "protocol/arithmetic.py", "protocol/coordinator.py",
            "experiments/cart_pole_full_evidence.py",
            "protocol/roles.py", "execution/localhost_codec.py", "execution/lan_config.py",
            "crypto/primes.py", "crypto/fixed_point.py", "crypto/beaver.py", "crypto/truncation.py",
        )
        hashes = {"src/secure_control/" + p: hashlib.sha256(
            (package / p).read_bytes()).hexdigest() for p in paths}
        try:
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                           timeout=5, stderr=subprocess.DEVNULL, text=True).strip()
            dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root,
                                                timeout=5, stderr=subprocess.DEVNULL, text=True).strip())
        except (OSError, subprocess.SubprocessError):
            head = None
            dirty = None
        timing_context = {"mode": "absolute", "code_sha": head, "dirty": dirty, "source_sha256": hashes,
                          "configuration_sha256": hashlib.sha256(json.dumps(
                              json.loads(snapshots), sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode()).hexdigest()}

    def committed_count() -> int:
        runtime = dynamic if active == "dynamic" else scalar
        return epoch_protocol_base + (runtime.protocol_committed_count if runtime else 0)

    @contextmanager
    def measured(name: str):
        nonlocal cycle_phase
        cycle_phase = name
        check_deadline(cycle_deadline, name)
        mark = time.perf_counter_ns()
        try:
            yield
        finally:
            phase_ns[name] = phase_ns.get(name, 0) + time.perf_counter_ns() - mark
        check_deadline(cycle_deadline, name)

    def end_epoch(step: int, action: str, deadline_ns=None):
        """出口超期也保留刚核验的双方回执，绝不把close当作密封。"""
        if active == "dynamic":
            previous = dynamic.last_sealed_record
            try:
                record = dynamic.end_segment(switch_epoch=action == "switch", deadline_ns=deadline_ns)
            finally:
                record = dynamic.last_sealed_record
                if record is not None and record is not previous:
                    epochs[-1]["closed_segments"].append({
                        "action": action, "physical_end": step,
                        "receipts": [asdict(item) for item in record.receipts],
                    })
        else:
            previous = scalar.last_end_receipts
            try:
                receipts = scalar.end(action, deadline_ns=deadline_ns)
            finally:
                receipts = scalar.last_end_receipts
                if receipts and receipts is not previous:
                    epochs[-1]["closed_segments"].append({
                        "action": action, "physical_end": step,
                        "receipts": [asdict(item) for item in receipts],
                    })

    @contextmanager
    def cycle(step: int):
        nonlocal cycle_actual, cycle_device, cycle_bookkeeping, cycle_deadline
        nonlocal cycle_failure, termination, cycle_phase, cycle_segment, phase_ns
        nonlocal cycle_identity, cycle_attempt_started
        if not realtime or step == config.horizon_steps:
            yield None
            return
        scheduled, cycle_deadline = clock.wait(step)
        cycle_actual = cycle_device = cycle_bookkeeping = None
        phase_ns = {}
        cycle_phase = "SAMPLE"
        cycle_identity = None
        cycle_attempt_started = False
        cycle_segment = dynamic.segment_index if active == "dynamic" else 0
        failure_phase = None
        failure_type = None
        try:
            yield cycle_deadline
        except Exception as error:  # noqa: BLE001 - 任何用户回调失败都停止，公开类型而非载荷
            failure_phase = error.phase if isinstance(error, CycleDeadlineExceeded) else cycle_phase
            failure_type = type(error).__name__
            termination = "failed"
        if reason is not None and failure_phase is None:
            failure_phase = cycle_phase
            failure_type = "ControlFailure"
        def snapshot(status, failure, completed=None):
            runtime = dynamic if active == "dynamic" else scalar
            if active == "dynamic" and runtime is not None:
                identity = runtime.snapshot()
                session, epoch, round_id = identity.session_id, identity.controller_epoch, identity.attempted_round_id
                details = runtime.cycle_phase_ns
            else:
                session = runtime.session_id if runtime else None
                epoch = runtime.epoch_id if runtime else None
                round_id = runtime.last_round_id if runtime else None
                details = runtime.cycle_phase_ns if runtime else {}
            if cycle_identity is not None:
                session, epoch, round_id = cycle_identity
            elif not cycle_attempt_started:
                round_id = None
            return CycleTiming(
                run_id, session, epoch, cycle_segment, step, round_id,
                clock.period_ns, scheduled, cycle_actual, cycle_deadline,
                cycle_device, cycle_bookkeeping, completed, status, failure,
                committed_count(), physically_confirmed_count, 0,
                {**phase_ns, **{f"protocol_{k}": v for k, v in details.items()}},
            )
        # 观察者只接收未完成快照；其成本仍在当前预算内，最终事实以result.cycles为准。
        if on_cycle is not None:
            try:
                on_cycle(snapshot("observing", failure_phase))
            except Exception as error:  # noqa: BLE001 - 用户观察者失败只保留公开类型
                if failure_phase is None:
                    failure_phase, failure_type = "OBSERVATION", type(error).__name__
        if failure_phase is None:
            try:
                # 公开快照装配也在周期内；以实际完成端点检查，避免检查与取时之间跨截止。
                completed_record = snapshot("observing", None)
                completed_ns = time.perf_counter_ns()
                check_deadline(cycle_deadline, "CYCLE_EXIT", now=lambda: completed_ns)
            except CycleDeadlineExceeded:
                failure_phase, failure_type = "CYCLE_EXIT", "CycleDeadlineExceeded"
        if failure_phase is None:
            cycles.append(replace(completed_record, status="confirmed", cycle_completed_ns=completed_ns))
        else:
            late = time.perf_counter_ns() >= cycle_deadline or failure_type == "CycleDeadlineExceeded"
            status = ("miss_" if late else "failed_") + ("after_apply" if cycle_device is not None else "before_apply")
            record = snapshot(status, failure_phase)
            cycles.append(record)
            runtime = dynamic if active == "dynamic" else scalar
            known = record.protocol_committed_count > step
            uncertain = (runtime.snapshot().phase == "UNCERTAIN" if active == "dynamic" and runtime
                         else getattr(runtime, "last_step_protocol_state", "not_started") == "uncertain")
            cycle_failure = {"physical_step": step, "failure_phase": failure_phase,
                             "status": status, "failure_type": failure_type,
                             "protocol_state": "double_committed" if known else "uncertain" if uncertain else "not_committed",
                             "protocol_committed_count": record.protocol_committed_count,
                             "physically_confirmed_count": physically_confirmed_count,
                             "sealed_step_count": max((c["physical_end"] for e in epochs for c in e["closed_segments"]), default=0),
                             "durable_step_count": 0}
            termination = "failed"
        cycle_deadline = None

    def start_scalar(kind: str, step: int, previous_session: str | None, deadline_ns=None) -> None:
        nonlocal scalar, active, epoch_protocol_base
        epoch_protocol_base = step
        if kind == "kick":
            program, certificate = kick_program, kick_certificate
        else:
            program, certificate = energy_program, energy_certificate
        epoch_id = f"{kind}-{secrets.token_hex(16)}"
        scalar = LanScalarRuntime(
            client, program, certificate, modulus=modulus,
            modulus_evidence=modulus_evidence, run_id=run_id,
            epoch_id=epoch_id, start_physical_step=step,
            **({"deadline_ns": deadline_ns} if deadline_ns is not None else {}),
        )
        active = kind
        epochs.append({
            "physical_start": step, "phase": kind, "epoch_id": epoch_id,
            "session_id": scalar.session_id, "previous_session_id": previous_session,
            "program_sha256": certificate.program_sha256,
            "fractional_bits": certificate.fractional_bits,
            "closed_segments": [],
        })

    def start_dynamic(step: int, previous_session: str, deadline_ns=None) -> None:
        nonlocal dynamic, dynamic_control, active, epoch_protocol_base
        epoch_protocol_base = step
        initialization = supervisor.latest_initialization
        if initialization is None:
            raise RuntimeError("动态捕获缺少本次两测量初始化")
        with measured("DYNAMIC_PROOF"):
            fixed, contract, proof = sustained_observer_numeric_contract(
                initialization, fractional_bits=32, parameter_bits=40,
                runtime_payload_bits=46, modulus=modulus,
            )
        dynamic_control = RunControl()
        dynamic = LanSegmentedRuntime(
            client, initialization.spec, fixed, contract, 80, modulus_evidence,
            control=dynamic_control, segment_capacity=segment_capacity,
            full_run_id=run_id, previous_epoch_session=previous_session,
            **({"deadline_ns": deadline_ns} if deadline_ns is not None else {}),
        )
        active = "dynamic"
        epochs.append({
            "physical_start": step, "phase": "dynamic",
            "epoch_id": dynamic.controller_epoch,
            "session_id": dynamic._segment.session_id,
            "previous_session_id": previous_session,
            "fractional_bits": 32,
            "numeric_proof": proof,
            "observer_x0": [float(value) for value in initialization.spec.x0],
            "closed_segments": [],
        })

    try:
        sample = None if realtime else device.read_measurement()
        state = _finite_vector(plant.state, 4, "initial_state")
        output = _observation(device.read_diagnostic_truth())
        states.append(state)
        outputs.append(output)
        start_scalar("kick", 0, None)
        if realtime:
            timing_context["initial_preparation_ns"] = time.perf_counter_ns() - preparation_started_ns
            clock = AbsoluteCycleClock(effective.sample_period_s, now=time.perf_counter_ns, sleep=time.sleep)
            timing_context["t0_ns"] = clock.t0_ns
        for step in range(config.horizon_steps + 1):
            if stop_event is not None and stop_event.is_set():
                termination = "stopped"
                break
            with cycle(step):
                try:
                    if realtime:
                        cycle_actual = time.perf_counter_ns() if step < config.horizon_steps else None
                        with measured("SAMPLE"):
                            sample = device.read_measurement()
                    with measured("ESTIMATION"):
                        estimated = estimator.observe(sample)
                except (TypeError, ValueError, FloatingPointError, OverflowError) as error:
                    failure_observation, reason, detail = step, "measurement_invalid", str(error)
                    break
                with measured("SUPERVISION"):
                    observed = supervisor.observe(step, estimated)
                    measurements.append(np.array([sample.p_m, sample.theta_rad]))
                    estimates.append(estimated)
                    observations.append(observed)
                if observed.status == "stable" and first_stable is None:
                    first_stable = step
                if observed.phase == "failed":
                    failure_observation, reason = step, observed.failure_reason
                    break
                if step == config.horizon_steps:
                    termination = (
                        "observed_success" if observed.phase == "balance"
                        and observed.status == "stable" else "time_limit"
                    )
                    break
                desired = (
                    "dynamic" if observed.phase in ("capture", "balance") else
                    "kick" if step < config.kick_steps else "energy"
                )
                if desired != active:
                    cycle_phase = "EPOCH_SWITCH"
                    check_deadline(cycle_deadline, cycle_phase)
                    previous_session = (
                        dynamic._segment.session_id if active == "dynamic" else scalar.session_id
                    )
                    if active == "dynamic":
                        with measured("EPOCH_END"):
                            end_epoch(step, "switch", cycle_deadline)
                        dynamic = None
                    else:
                        with measured("EPOCH_END"):
                            end_epoch(step, "switch", cycle_deadline)
                        scalar = None
                    if desired == "dynamic":
                        with measured("DYNAMIC_SETUP"):
                            start_dynamic(step, previous_session, cycle_deadline)
                        cycle_segment = 0
                    else:
                        with measured("SCALAR_SETUP"):
                            start_scalar(desired, step, previous_session, cycle_deadline)
                        cycle_segment = 0
                pending = None
                raw = applied = disturbance = total = None
                stage = "control"
                try:
                    unconfirmed = step
                    cycle_phase = "CONTROL"
                    check_deadline(cycle_deadline, cycle_phase)
                    if active == "dynamic":
                        if dynamic.segment_full:
                            record = dynamic.end_segment()
                            epochs[-1]["closed_segments"].append({
                                "action": "continue", "physical_end": step,
                                "receipts": [asdict(item) for item in record.receipts],
                            })
                            dynamic.next_segment()
                        init = supervisor.latest_initialization
                        if init is None:
                            raise RuntimeError("动态 epoch 状态与监督器不一致")
                        local_y = np.array([sample.p_m, sample.theta_rad - init.theta_star])
                        cycle_attempt_started = True
                        pending = dynamic.step(local_y, **({"deadline_ns": cycle_deadline} if realtime else {}))
                        if pending is None:
                            raise RuntimeError("动态 epoch 停止请求阻断本步")
                        raw = float(pending.raw_control[0])
                        source = "secure_dynamic_observer"
                        row = {
                            "physical_step": step, "local_step": pending.global_step,
                            "phase": observed.phase, "source": source,
                            "epoch_id": dynamic.controller_epoch,
                            "session_id": pending.session_id, "round_id": pending.round_id,
                            "resource_ids": list(pending.resource_ids),
                            "products": pending.products, "truncations": pending.truncations,
                        }
                    else:
                        if active == "kick":
                            values = {"kick": config.kick_direction * config.kick_force_n}
                            source = "secure_public_kick"
                        else:
                            beta = (sample.theta_rad + pi) % (2 * pi) - pi
                            values = {
                                "p": float(estimated[0]), "v": float(estimated[1]),
                                "beta": beta, "omega": float(estimated[3]),
                            }
                            source = "secure_energy_gates"
                        cycle_attempt_started = True
                        pending = scalar.step(values, step, **({"deadline_ns": cycle_deadline} if realtime else {}))
                        raw = pending.output
                        row = {
                            "physical_step": step, "local_step": pending.local_step,
                            "phase": observed.phase, "source": source,
                            "epoch_id": scalar.epoch_id,
                            "session_id": scalar.session_id, "round_id": pending.round_id,
                            "resource_ids": list(pending.resource_ids),
                            "products": pending.products, "truncations": pending.truncations,
                            "program_sha256": scalar.certificate.program_sha256,
                        }
                    cycle_identity = row["session_id"], row["epoch_id"], row["round_id"]
                    protocol_products += row["products"]
                    protocol_truncations += row["truncations"]
                    raw = _number(raw, "raw_force")
                    applied = float(adapter.apply_control(np.array([raw]))[0])
                    if active == "dynamic" and applied != raw:
                        raise ValueError("saturation_outside_contract")
                    stage = "plant"
                    cycle_phase = "BEFORE_DEVICE"
                    check_deadline(cycle_deadline, cycle_phase)
                    receipt = device.send_control(ControlCommand(step, run_id, step, applied))
                    if receipt.disposition != "simulated_interval_completed":
                        raise ValueError("区间未物理确认")
                    # 设备事实先登记，随后诊断/记账失败也不能撤回实际完成的区间。
                    physically_confirmed_count += 1
                    cycle_device = time.perf_counter_ns() if realtime else None
                    unconfirmed = None
                    cycle_phase = "AFTER_DEVICE"
                    if active == "dynamic":
                        dynamic.confirm_applied(pending)
                    requested, disturbance, total, disposition = device.read_interval_forces()
                    next_sample = None if realtime else device.read_measurement()
                    next_state = _finite_vector(plant.state, 4, "next_state")
                    next_output = _observation(device.read_diagnostic_truth())
                    unconfirmed = None
                except (TypeError, ValueError, RuntimeError, FloatingPointError,
                        OverflowError, OSError, TimeoutError) as error:
                    if realtime:
                        if stage == "plant" and cycle_device is None and not isinstance(error, TimeoutError):
                            failure_interval, detail = step, type(error).__name__
                            reason = ("track_limit" if "track_center_limit_m" in str(error) else "numeric_step")
                            attempted = (step, raw, applied, disturbance, total)
                        raise
                    failure_interval, detail = step, str(error)
                    reason = (
                        "track_limit" if stage == "plant" and "track_center_limit_m" in str(error)
                        else "numeric_step" if stage == "plant" else "protocol_or_control"
                    )
                    attempted = (step, raw, applied, disturbance, total)
                    break
                row.update({
                    "raw_force_n": raw, "applied_force_n": applied,
                    "disturbance_force_n": disturbance, "total_force_n": total,
                    "physical_confirmed": True,
                })
                protocol_rows.append(row)
                raws.append(np.array([raw]))
                applieds.append(np.array([applied]))
                disturbances.append(np.array([disturbance]))
                totals.append(np.array([total]))
                modes.append(observed.phase)
                sources.append(source)
                if requested:
                    events.append((step, requested, disturbance, disposition))
                sample, state, output = next_sample, next_state, next_output
                states.append(state)
                outputs.append(output)
                if on_step is not None:
                    cycle_phase = "BOOKKEEPING"
                    on_step(step + 1, tuple(float(value) for value in state), observed.phase,
                            source, applied, disturbance)
                if realtime:
                    cycle_bookkeeping = time.perf_counter_ns()
                    check_deadline(cycle_deadline, "BOOKKEEPING")
                    if active == "dynamic" and dynamic.segment_full and step + 1 < config.horizon_steps:
                        with measured("SEGMENT_MAINTENANCE"):
                            end_epoch(step + 1, "continue", cycle_deadline)
                            dynamic.next_segment(deadline_ns=cycle_deadline)
            if cycle_failure is not None:
                break
        cycle_phase = "FINALIZATION"
        finalization_started_ns = time.perf_counter_ns() if realtime else None
        if failure_interval is None and unconfirmed is None and len(raws) == physically_confirmed_count:
            if active == "dynamic" and dynamic.phase == "RUNNING":
                dynamic_control.request_stop()
                end_epoch(len(raws), "stop")
            elif active in {"kick", "energy"} and scalar is not None:
                if not scalar._failed and not scalar._ended:
                    end_epoch(len(raws), "stop")
    except (TypeError, ValueError, RuntimeError, FloatingPointError,
            OverflowError, OSError, TimeoutError) as error:
        if realtime and cycle_phase == "FINALIZATION":
            finalization_failure = {"phase": "FINALIZATION", "failure_type": type(error).__name__}
        elif reason is None:
            reason, detail = "setup_or_switch", str(error)
        termination = "failed"
    finally:
        if scalar is not None:
            scalar.close()
        if dynamic is not None:
            dynamic.close()
    time_axis = np.arange(len(states), dtype=float) * effective.sample_period_s
    angles = np.array([upright_coordinates(row)[2] for row in outputs], dtype=float)
    physical = SwingUpResult(
        time_axis, _rows(states, 4), _rows(outputs, 4), angles,
        _rows(raws, 1), _rows(applieds, 1), _rows(disturbances, 1), _rows(totals, 1),
        tuple(modes), tuple(observations), tuple(supervisor.transitions), tuple(events),
        termination, termination == "observed_success", first_stable,
        failure_observation, failure_interval, reason, detail, attempted, snapshots,
        route="secure_full", measurement=_rows(measurements, 2),
        estimated_state=_rows(estimates, 4), controller_source=tuple(sources),
        observer_state_before=(None,) * len(sources),
        observer_initializations=tuple(supervisor.initializations),
    )
    if timing_context is not None:
        timing_context["epoch_bindings"] = [{k: epoch[k] for k in (
            "physical_start", "phase", "epoch_id", "session_id", "previous_session_id",
        )} for epoch in epochs]
        timing_context["replayable_steps_before_sealing"] = len(raws)
        timing_context["finalization_duration_ns"] = (time.perf_counter_ns() - finalization_started_ns
                                                       if finalization_started_ns is not None else 0)
    cache = _REACHABILITY_BASIS.get()
    proof_summary = ({**cache.summary(), "warmup_ns": proof_warmup_ns,
                      "warmed_candidates": proof_warmed_candidates} if cache is not None else None)
    if timing_context is not None:
        timing_context["proof_cache"] = proof_summary
    return SecureFullResult(
        physical, run_id, tuple(protocol_rows), tuple(epochs),
        protocol_products, protocol_truncations, time.perf_counter() - started,
        unconfirmed, modulus, modulus_evidence,
        tuple(cycles), cycle_failure, timing_context, physically_confirmed_count,
        finalization_failure,
        proof_summary,
    )
