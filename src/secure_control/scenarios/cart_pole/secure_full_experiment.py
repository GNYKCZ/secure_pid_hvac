"""#103 从下垂起点经真实三进程起摆与秘密动态 observer 的完整物理路线。"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from math import pi
from threading import Event

import numpy as np

from secure_control.crypto.primes import PrimeModulusEvidence
from secure_control.execution.lan_config import LanConfig
from secure_control.execution.lan_runtime import LanSegmentedRuntime, RunControl
from secure_control.execution.lan_scalar_runtime import LanScalarRuntime
from secure_control.protocol.arithmetic import ScalarProgram, certify_scalar_program

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


def run_secure_full_experiment(
    plant_contract: CartPoleContract, balance: CartPoleBalanceConfig,
    config: CartPoleSwingUpConfig, observer_design: CartPoleObserverDesign,
    client: LanConfig, *, modulus: int,
    modulus_evidence: PrimeModulusEvidence | None, segment_capacity: int = 100,
    on_step: Callable[[int, tuple[float, ...], str, str, float, float], None] | None = None,
    stop_event: Event | None = None,
) -> SecureFullResult:
    """Client 唯一推进 plant；P1/P2 计算 kick/能量力和非零秘密动态 state。"""
    config.validate(plant_contract, balance)
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
    snapshots = json.dumps({
        "plant_source_contract": asdict(plant_contract), "balance": asdict(balance),
        "swing_up": asdict(config), "observer": observer_design.to_snapshot(),
        "effective_initial_state": list(effective.initial_state),
    }, allow_nan=False)

    def start_scalar(kind: str, step: int, previous_session: str | None) -> None:
        nonlocal scalar, active
        if kind == "kick":
            program, certificate = kick_program, kick_certificate
        else:
            program, certificate = energy_program, energy_certificate
        epoch_id = f"{kind}-{secrets.token_hex(16)}"
        scalar = LanScalarRuntime(
            client, program, certificate, modulus=modulus,
            modulus_evidence=modulus_evidence, run_id=run_id,
            epoch_id=epoch_id, start_physical_step=step,
        )
        active = kind
        epochs.append({
            "physical_start": step, "phase": kind, "epoch_id": epoch_id,
            "session_id": scalar.session_id, "previous_session_id": previous_session,
            "program_sha256": certificate.program_sha256,
            "fractional_bits": certificate.fractional_bits,
            "closed_segments": [],
        })

    def start_dynamic(step: int, previous_session: str) -> None:
        nonlocal dynamic, dynamic_control, active
        initialization = supervisor.latest_initialization
        if initialization is None:
            raise RuntimeError("动态捕获缺少本次两测量初始化")
        fixed, contract, proof = sustained_observer_numeric_contract(
            initialization, fractional_bits=32, parameter_bits=40,
            runtime_payload_bits=46, modulus=modulus,
        )
        dynamic_control = RunControl()
        dynamic = LanSegmentedRuntime(
            client, initialization.spec, fixed, contract, 80, modulus_evidence,
            control=dynamic_control, segment_capacity=segment_capacity,
            full_run_id=run_id, previous_epoch_session=previous_session,
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
        sample = device.read_measurement()
        state = _finite_vector(plant.state, 4, "initial_state")
        output = _observation(device.read_diagnostic_truth())
        states.append(state)
        outputs.append(output)
        start_scalar("kick", 0, None)
        for step in range(config.horizon_steps + 1):
            if stop_event is not None and stop_event.is_set():
                termination = "stopped"
                break
            try:
                estimated = estimator.observe(sample)
            except (TypeError, ValueError, FloatingPointError, OverflowError) as error:
                failure_observation, reason, detail = step, "measurement_invalid", str(error)
                break
            measurements.append(np.array([sample.p_m, sample.theta_rad]))
            estimates.append(estimated)
            observed = supervisor.observe(step, estimated)
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
                previous_session = (
                    dynamic._segment.session_id if active == "dynamic" else scalar.session_id
                )
                if active == "dynamic":
                    record = dynamic.end_segment(switch_epoch=True)
                    epochs[-1]["closed_segments"].append({
                        "action": "switch", "physical_end": step,
                        "receipts": [asdict(item) for item in record.receipts],
                    })
                    dynamic = None
                else:
                    receipts = scalar.end("switch")
                    epochs[-1]["closed_segments"].append({
                        "action": "switch", "physical_end": step,
                        "receipts": [asdict(item) for item in receipts],
                    })
                    scalar = None
                if desired == "dynamic":
                    start_dynamic(step, previous_session)
                else:
                    start_scalar(desired, step, previous_session)
            pending = None
            raw = applied = disturbance = total = None
            stage = "control"
            try:
                unconfirmed = step
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
                    pending = dynamic.step(local_y)
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
                    pending = scalar.step(values, step)
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
                protocol_products += row["products"]
                protocol_truncations += row["truncations"]
                raw = _number(raw, "raw_force")
                applied = float(adapter.apply_control(np.array([raw]))[0])
                if active == "dynamic" and applied != raw:
                    raise ValueError("saturation_outside_contract")
                stage = "plant"
                receipt = device.send_control(ControlCommand(step, run_id, step, applied))
                if receipt.disposition != "simulated_interval_completed":
                    raise ValueError("区间未物理确认")
                requested, disturbance, total, disposition = device.read_interval_forces()
                next_sample = device.read_measurement()
                next_state = _finite_vector(plant.state, 4, "next_state")
                next_output = _observation(device.read_diagnostic_truth())
                if active == "dynamic":
                    dynamic.confirm_applied(pending)
                unconfirmed = None
            except (TypeError, ValueError, RuntimeError, FloatingPointError,
                    OverflowError, OSError, TimeoutError) as error:
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
                on_step(step + 1, tuple(float(value) for value in state), observed.phase,
                        source, applied, disturbance)
        if failure_interval is None and unconfirmed is None:
            if active == "dynamic" and dynamic.phase == "RUNNING":
                dynamic_control.request_stop()
                record = dynamic.end_segment()
                epochs[-1]["closed_segments"].append({
                    "action": "stop", "physical_end": len(raws),
                    "receipts": [asdict(item) for item in record.receipts],
                })
            elif active in {"kick", "energy"} and scalar is not None:
                receipts = scalar.end()
                epochs[-1]["closed_segments"].append({
                    "action": "stop", "physical_end": len(raws),
                    "receipts": [asdict(item) for item in receipts],
                })
    except (TypeError, ValueError, RuntimeError, FloatingPointError,
            OverflowError, OSError, TimeoutError) as error:
        if reason is None:
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
    return SecureFullResult(
        physical, run_id, tuple(protocol_rows), tuple(epochs),
        protocol_products, protocol_truncations, time.perf_counter() - started,
        unconfirmed, modulus, modulus_evidence,
    )
