"""倒立摆有限时长明文闭环记录与场景自有的观察判定。"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

from secure_control.execution import PlaintextStateSpaceRuntime

from .adapter import (
    ActuationReceipt,
    CartPoleAdapter,
    CartPoleObserverSimulation,
    ControlCommand,
    ObserverBalanceEpisode,
    ObserverDevice,
    _checked_sample,
    _disturbance_plan,
    _finite_vector,
)
from .contract import CartPoleContract
from .controller import CartPoleBalanceConfig, build_cart_pole_controller_spec
from .plant import CartPolePlant

if TYPE_CHECKING:
    from .observer import CartPoleObserverDesign


class BalanceMonitor:
    """以四维理想观测更新连续稳定计数，越工作域后保持失败状态。"""

    def __init__(self, config: CartPoleBalanceConfig) -> None:
        """判定只使用场景配置与可观测信号，不读取 plant 隐藏状态。"""
        if not isinstance(config, CartPoleBalanceConfig):
            raise TypeError("config 必须是 CartPoleBalanceConfig")
        self._target = np.array(config.target_state, dtype=np.float64)
        self._safe = np.array(config.safe_abs, dtype=np.float64)
        self._stable = np.array(config.stable_abs, dtype=np.float64)
        self._hold = config.hold_observations
        self.stable_count = 0
        self.status = "recovering"
        self.failure_reason: str | None = None

    def observe(self, output: Any) -> str:
        """在 t_k 先门禁，再以含首尾的连续观测数判定 observed stable。"""
        if self.status == "failed":
            return self.status
        raw = np.asarray(output)
        if raw.shape != (4,) or raw.dtype.kind not in "iuf":
            self.failure_reason = "invalid_observation"
        elif not np.isfinite(raw).all():
            self.failure_reason = "nonfinite_observation"
        else:
            measured = np.array(raw, dtype=np.float64, copy=True)
            if not np.isfinite(measured).all():
                self.failure_reason = "nonfinite_observation"
            else:
                error = np.abs(measured - self._target)
                if np.any(error > self._safe):
                    self.failure_reason = "outside_safe_domain"
                elif np.all(error <= self._stable):
                    self.stable_count += 1
                else:
                    self.stable_count = 0
        if self.failure_reason is not None:
            self.stable_count = 0
            self.status = "failed"
        else:
            self.status = "stable" if self.stable_count >= self._hold else "recovering"
        return self.status


@dataclass(frozen=True, slots=True)
class BalanceResult:
    """N+1 个观测与 N 个成功施加力；失败时只保留已提交前缀。"""

    time_s: np.ndarray
    state: np.ndarray
    output: np.ndarray
    reference: np.ndarray
    raw_force: np.ndarray
    applied_force: np.ndarray
    observed_status: tuple[str, ...]
    stable_count: tuple[int, ...]
    status: str
    failure_step: int | None
    failure_reason: str | None

    @property
    def completed_steps(self) -> int:
        """返回已成功推进并提交的控制区间数。"""
        return self.applied_force.shape[0]


def _rows(values: list[np.ndarray], width: int) -> np.ndarray:
    """把记录冻结为形状确定、不能从外部改写的数组。"""
    result = np.vstack(values) if values else np.empty((0, width), dtype=np.float64)
    result.setflags(write=False)
    return result


def _result(
    times: list[float], states: list[np.ndarray], outputs: list[np.ndarray],
    references: list[np.ndarray], raw_forces: list[np.ndarray], applied_forces: list[np.ndarray],
    statuses: list[str], counts: list[int], status: str,
    failure_step: int | None = None, failure_reason: str | None = None,
) -> BalanceResult:
    """在成功或失败出口都复制已完成记录，不填造未执行的时间步。"""
    time = np.array(times, dtype=np.float64)
    time.setflags(write=False)
    return BalanceResult(
        time, _rows(states, 4), _rows(outputs, 4), _rows(references, 4),
        _rows(raw_forces, 1), _rows(applied_forces, 1), tuple(statuses), tuple(counts),
        status, failure_step, failure_reason,
    )


def run_balance_experiment(
    plant_contract: CartPoleContract,
    config: CartPoleBalanceConfig,
    *,
    initial_state: tuple[float, float, float, float] | None = None,
) -> BalanceResult:
    """用既有 plant/adapter/明文 runtime 执行 N 个区间并保留 raw/applied 分账。

    通用引擎不暴露 raw 力与判定，故本场景仅为这些证据执行薄记录循环；
    每步依然遵循 reference→更新前 output→v→raw→applied→plant 顺序。
    """
    if not isinstance(plant_contract, CartPoleContract) or not isinstance(config, CartPoleBalanceConfig):
        raise TypeError("plant_contract/config 类型无效")
    config.validate_plant(plant_contract)
    contract = (
        plant_contract if initial_state is None
        else replace(plant_contract, initial_state=initial_state)
    )
    plant = CartPolePlant(contract)
    adapter = CartPoleAdapter(contract, config)
    runtime = PlaintextStateSpaceRuntime(build_cart_pole_controller_spec(contract, config))
    monitor = BalanceMonitor(config)
    times: list[float] = []
    states: list[np.ndarray] = []
    outputs: list[np.ndarray] = []
    references: list[np.ndarray] = []
    raw_forces: list[np.ndarray] = []
    applied_forces: list[np.ndarray] = []
    statuses: list[str] = []
    counts: list[int] = []

    for step in range(config.horizon_steps + 1):
        time = step * contract.sample_period_s
        try:
            reference = adapter.reference_at(time)
            output = plant.output()
            state = plant.state
        except (TypeError, ValueError, FloatingPointError, OverflowError):
            return _result(
                times, states, outputs, references, raw_forces, applied_forces,
                statuses, counts, "failed", step, "observation",
            )
        decision = monitor.observe(output)
        # 错误 shape 不能进入四维表；失败步号仍保留在结果中。
        observed = np.asarray(output)
        if observed.shape == (4,) and observed.dtype.kind in "iuf":
            times.append(time)
            states.append(np.array(state, dtype=np.float64, copy=True))
            outputs.append(np.array(output, dtype=np.float64, copy=True))
            references.append(reference)
            statuses.append(decision)
            counts.append(monitor.stable_count)
        if decision == "failed":
            return _result(
                times, states, outputs, references, raw_forces, applied_forces,
                statuses, counts, "failed", step, monitor.failure_reason,
            )
        if step == config.horizon_steps:
            final_status = "stable" if decision == "stable" else "time_limit"
            return _result(
                times, states, outputs, references, raw_forces, applied_forces,
                statuses, counts, final_status,
            )
        try:
            controller_input = adapter.controller_input(reference, output)
            raw_force = _finite_vector(runtime.step(controller_input), 1, "raw_force")
            applied_force = adapter.apply_control(raw_force)
            _finite_vector(plant.step(applied_force), 4, "next_output")
        except (TypeError, ValueError, FloatingPointError, OverflowError):
            return _result(
                times, states, outputs, references, raw_forces, applied_forces,
                statuses, counts, "failed", step, "control_or_plant_step",
            )
        # 只有完整成功推进 plant 后才提交本区间的 raw 与 applied 力。
        raw_forces.append(raw_force)
        applied_forces.append(applied_force)
    raise AssertionError("不可达：有限 horizon 的末尾必须返回结果")


@dataclass(frozen=True, slots=True)
class ObserverBalanceResult:
    """只读有限证据：估计/真值/测量/监督分账，未确认区间只在attempt中。"""

    time_s: np.ndarray
    sample_ids: tuple[int, ...]
    measurement: np.ndarray
    local_measurement: np.ndarray
    estimate: np.ndarray
    truth: np.ndarray
    local_truth: np.ndarray
    raw_force: np.ndarray
    command_force: np.ndarray
    applied_force: np.ndarray
    disturbance_force: np.ndarray
    total_force: np.ndarray
    observed_status: tuple[str, ...]
    stable_count: tuple[int, ...]
    receipts: tuple[ActuationReceipt, ...]
    disturbance_events: tuple[tuple[int, float, float, str], ...]
    termination: str
    failure_step: int | None
    failure_reason: str | None
    failure_detail: str | None
    attempted_json: str
    design_json: str
    initialization_json: str
    options_json: str

    @property
    def completed_steps(self) -> int:
        """物理完成证据来自回执，不来自已算出的下一估计。"""
        return len(self.receipts)

    @property
    def goal_met(self) -> bool:
        """终点仍连续stable才成功；历史stable不替代终态。"""
        return self.termination == "observed_success"

    def to_report(self, *, provenance: dict | None = None) -> dict:
        """从已记录行复算研究摘要，无重跑、NaN补行或安全成功认证。"""
        errors = self.local_truth - self.estimate
        entries = [self.sample_ids[i] for i, status in enumerate(self.observed_status)
                   if status == "stable" and (i == 0 or self.observed_status[i - 1] != "stable")]
        def peak(rows: np.ndarray) -> list | None:
            return np.max(np.abs(rows), axis=0).tolist() if len(rows) else None

        return {
            "kind": "cart_pole_observer_plaintext", "version": 1, "computation_mode": "plaintext",
            "design": json.loads(self.design_json), "initialization": json.loads(self.initialization_json),
            "effective_options": json.loads(self.options_json),
            "provenance": json.loads(json.dumps(provenance, allow_nan=False)) if provenance else {
                "available": False, "reason": "source_and_code_provenance_not_supplied"
            },
            "supervision_source": "ideal_simulation_truth", "time_basis": "simulation_time",
            "channels": {"measurement": ["p_m", "theta_rad"], "measurement_units": ["m", "rad"],
                         "estimate": ["p_hat", "v_hat", "alpha_hat", "omega_hat"],
                         "state_units": ["m", "m/s", "rad", "rad/s"], "force_unit": "N"},
            "time_s": self.time_s.tolist(), "sample_ids": list(self.sample_ids),
            "measurement_valid": [[True, True] for _ in self.sample_ids],
            **{name: getattr(self, name).tolist() for name in (
                "measurement", "local_measurement", "estimate", "truth", "local_truth", "raw_force",
                "command_force", "applied_force", "disturbance_force", "total_force"
            )},
            "estimation_error": errors.tolist(), "observed_status": list(self.observed_status),
            "stable_count": list(self.stable_count), "receipts": [asdict(row) for row in self.receipts],
            "disturbance_events": [dict(zip(
                ("interval_step", "requested_force_n", "actual_force_n", "disposition"), event,
                strict=True,
            )) for event in self.disturbance_events],
            "termination": self.termination, "goal_met": self.goal_met,
            "failure": {"step": self.failure_step, "reason": self.failure_reason,
                        "detail": self.failure_detail}, "attempted": json.loads(self.attempted_json),
            "summary": {"completed_steps": self.completed_steps, "observations": len(self.time_s),
                        "first_stable_step": entries[0] if entries else None,
                        "stable_entry_steps": entries, "max_abs_local_truth": peak(self.local_truth),
                        "max_abs_estimation_error": peak(errors),
                        "final_estimation_error": errors[-1].tolist() if len(errors) else None,
                        "max_abs_raw_force": peak(self.raw_force),
                        "final_stable_count": self.stable_count[-1] if self.stable_count else 0},
            "limitations": ["finite nonlinear plaintext witness, not global or indefinite stability",
                            "ideal full-state supervision is separate from two-channel controller input",
                            "unknown external force is not an observer input",
                            "simulation completion is not hardware ACK/rollback or real-time proof",
                            "plaintext estimates must not become public secret-state diagnostics"],
        }


def run_observer_balance_experiment(
    design: CartPoleObserverDesign, *,
    initial_state: tuple[float, ...] | None = None,
    disturbances: tuple[tuple[int, float], ...] = (),
    velocity_seed: tuple[float, ...] | None = None,
    device: ObserverDevice | None = None,
    truth_provider: Callable[[], np.ndarray] | None = None,
    force_evidence: Callable[[], tuple[float, float, float, str]] | None = None,
) -> ObserverBalanceResult:
    """从两测量到原runtime/actuator/plant贯通；超raw域或非完成回执即终止。

    控制器递推和物理确认不是原子事务。失败后销毁episode，数学attempt独立记录，
    不重试、不reset、不把ACK或目标力假装已执行。truth仅用于理想监督和离线误差诊断。
    """
    from .observer import CartPoleObserverDesign

    if not isinstance(design, CartPoleObserverDesign):
        raise TypeError("design 必须是 CartPoleObserverDesign")
    config, contract = design.balance, design.plant
    if velocity_seed is not None:
        velocity_seed = replace(design.config, initial_velocity_estimate=velocity_seed).initial_velocity_estimate
    events = _disturbance_plan(disturbances, config.horizon_steps)
    effective = contract if initial_state is None else replace(contract, initial_state=initial_state)
    is_simulation = device is None
    if is_simulation:
        simulation = CartPoleObserverSimulation(CartPolePlant(effective), effective, events)
        device = simulation
        truth_provider = simulation.read_diagnostic_truth
        force_evidence = simulation.read_interval_forces
    elif truth_provider is None or force_evidence is None:
        raise ValueError("替代测量/执行提供者必须另外注入真值诊断和已完成力证据")
    monitor = BalanceMonitor(config)
    actuator = CartPoleAdapter(contract, config)
    rows: dict[str, list] = {name: [] for name in (
        "measurement", "local_measurement", "estimate", "truth", "local_truth", "raw_force",
        "command_force", "applied_force", "disturbance_force", "total_force"
    )}
    sample_ids, times, statuses, counts, receipts, recorded_events = [], [], [], [], [], []
    episode = None
    initialization_json = "null"
    attempted = None
    status, reason, detail, failure_step = "failed", None, None, None
    for step in range(config.horizon_steps + 1):
        stage = "measurement"
        try:
            sample = device.read_measurement()
            _checked_sample(sample, step, contract.sample_period_s)
            if episode is None:
                initialization = design.initialize(sample, velocity_seed)
                runtime = PlaintextStateSpaceRuntime(initialization.spec)
                episode = ObserverBalanceEpisode(initialization, runtime, episode_id="finite-0")
                spec = initialization.spec
                initialization_json = json.dumps({
                    "episode_id": episode.episode_id, "branch": initialization.branch,
                    "theta_star": initialization.theta_star, "first_sample_id": sample.sample_id,
                    "first_sample_time_s": sample.time_s,
                    "velocity_seed": initialization.velocity_seed,
                    "initial_error_abs": initialization.initial_error_abs,
                    "y_abs": initialization.y_abs,
                    "spec": {name: getattr(spec, name).tolist() for name in ("A", "B", "C", "D", "x0")},
                    "state_abs_bound": initialization.state_abs_bound.tolist(),
                    "raw_abs_bound": initialization.raw_abs_bound.tolist(),
                    "linear_initial_value_assuming_zero_error": initialization.linear_initial_value,
                    "linear_domain_c": initialization.linear_domain_c,
                }, allow_nan=False)
            local_y = episode.local_measurement(sample)
            stage = "diagnostic_observation"
            truth = _finite_vector(truth_provider(), 4, "diagnostic_truth")
            local_truth = truth.copy()
            local_truth[2] -= episode.initialization.theta_star
            local_truth = _finite_vector(local_truth, 4, "local_diagnostic_truth")
            estimate = _finite_vector(runtime.state, 4, "estimate")
            decision = monitor.observe(local_truth)
            # 诊断初态约束是仿真可核查前提；绝不据真速度覆盖seed或控制输入。
            initial_error_invalid = step == 0 and np.any(
                np.abs(local_truth - estimate) > design.config.initial_error_abs
            )
            for name, value in (("measurement", [sample.p_m, sample.theta_rad]),
                                ("local_measurement", local_y), ("estimate", estimate),
                                ("truth", truth), ("local_truth", local_truth)):
                rows[name].append(np.array(value, copy=True))
            sample_ids.append(sample.sample_id)
            times.append(sample.time_s)
            statuses.append(decision)
            counts.append(monitor.stable_count)
            if decision == "failed" or initial_error_invalid:
                reason = monitor.failure_reason if decision == "failed" else "initial_error_outside_assumption"
                failure_step = step
                break
            if step == config.horizon_steps:
                status = "observed_success" if decision == "stable" else "time_limit"
                break
            stage = "runtime"
            raw = episode.step(sample)
            next_estimate = _finite_vector(runtime.state, 4, "attempted_next_estimate")
            attempted = {"interval_step": step, "raw_force_n": float(raw[0]),
                         "mathematical_next_estimate": next_estimate.tolist(),
                         "physical_interval_completed": False}
            stage = "saturation_outside_contract"
            if abs(raw[0]) > contract.max_applied_force_n:
                raise ValueError("raw超界不能限幅后继续用raw递推observer")
            command_force = actuator.apply_control(raw)
            command = ControlCommand(step, episode.episode_id, sample.sample_id, float(command_force[0]))
            stage = "actuation"
            receipt = device.send_control(command)
            if not isinstance(receipt, ActuationReceipt) or (
                receipt.command_id, receipt.episode_id, receipt.sample_id
            ) != (command.command_id, command.episode_id, command.sample_id):
                raise ValueError("invalid_actuation_receipt_identity")
            attempted["receipt"] = asdict(receipt)
            if receipt.disposition != "simulated_interval_completed":
                status = "failed" if receipt.disposition == "rejected" else "uncertain"
                reason, failure_step = f"actuation_{receipt.disposition}", step
                break
            if receipt.applied_force_n != command.target_force_n or (
                receipt.applied_source != "canonical_simulation"
            ):
                status, reason, failure_step = "uncertain", "applied_force_not_confirmed", step
                break
            attempted["physical_interval_completed"] = True
            stage = "force_evidence"
            requested, actual, total, disposition = force_evidence()
            evidence = _finite_vector([requested, actual, total], 3, "force_evidence")
            if (evidence[0] != dict(events).get(step, 0.) or evidence[1] not in (-1., 0., 1.)
                or total != receipt.applied_force_n + actual or abs(total) > contract.max_applied_force_n
                or (disposition == "accepted" and actual != requested)
                or (disposition == "rejected_total_force_limit" and (
                    actual != 0 or abs(receipt.applied_force_n + requested) <= contract.max_applied_force_n
                )) or disposition not in {"accepted", "rejected_total_force_limit"}):
                raise ValueError("invalid_completed_force_evidence")
            for name, value in (("raw_force", raw), ("command_force", command_force),
                                ("applied_force", [receipt.applied_force_n]),
                                ("disturbance_force", [actual]), ("total_force", [total])):
                rows[name].append(np.array(value, dtype=float, copy=True))
            receipts.append(receipt)
            if requested:
                recorded_events.append((step, requested, actual, disposition))
            attempted = None
        except (TypeError, ValueError, FloatingPointError, OverflowError, RuntimeError, OSError) as error:
            failure_step, reason, detail = step, stage, str(error)
            if stage == "force_evidence" or (stage == "actuation" and not is_simulation):
                status = "uncertain"
            break
    if episode is not None:
        episode.end(reason or status)
    time_rows = np.array(times, dtype=float)
    time_rows.setflags(write=False)
    return ObserverBalanceResult(
        time_rows, tuple(sample_ids), *(_rows(rows[name], width) for name, width in (
            ("measurement", 2), ("local_measurement", 2), ("estimate", 4), ("truth", 4), ("local_truth", 4),
            ("raw_force", 1), ("command_force", 1), ("applied_force", 1), ("disturbance_force", 1),
            ("total_force", 1)
        )), tuple(statuses), tuple(counts), tuple(receipts), tuple(recorded_events), status,
        failure_step, reason, detail, json.dumps(attempted, allow_nan=False),
        json.dumps(design.to_snapshot(), allow_nan=False), initialization_json,
        json.dumps({"initial_state": effective.initial_state, "disturbances": events,
                    "velocity_seed_override": velocity_seed}, allow_nan=False),
    )


def write_observer_balance_report(result: ObserverBalanceResult, path: str | Path,
                                  *, provenance: dict | None = None) -> Path:
    """独立明文研究JSON沿用有限实验能力；排他写入，失败抛出且不报告保存成功。"""
    payload = json.dumps(result.to_report(provenance=provenance), ensure_ascii=False, allow_nan=False)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        stream.write(payload + "\n")
    return target
