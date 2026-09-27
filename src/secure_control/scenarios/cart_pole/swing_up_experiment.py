"""有限明文起摆记录与研究 JSON；不生成三方正式产物或虚构 secure 分支。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import numpy as np

from .adapter import CartPoleAdapter, _finite_vector
from .contract import CartPoleContract, _number
from .controller import CartPoleBalanceConfig
from .experiment import _rows
from .plant import STATE_NAMES, STATE_UNITS, CartPolePlant
from .swing_up import (
    CartPoleSwingUpConfig,
    SwingUpObservation,
    SwingUpSupervisor,
    SwingUpTransition,
    _observation,
    upright_coordinates,
)


@dataclass(frozen=True, slots=True)
class SwingUpResult:
    """冻结真实前缀：N+1 观测、N 个已完成区间，未提交尝试单独诊断。"""

    time_s: np.ndarray
    state: np.ndarray
    output: np.ndarray
    upright_angle_rad: np.ndarray
    raw_force: np.ndarray
    applied_force: np.ndarray
    disturbance_force: np.ndarray
    total_force: np.ndarray
    mode_for_interval: tuple[str, ...]
    observations: tuple[SwingUpObservation, ...]
    transitions: tuple[SwingUpTransition, ...]
    disturbance_events: tuple[tuple[int, float, float, str], ...]
    termination: str
    goal_met: bool
    first_stable_step: int | None
    failure_observation_step: int | None
    failure_interval_step: int | None
    failure_reason: str | None
    failure_detail: str | None
    attempted_step: tuple[int, float | None, float | None, float | None, float | None] | None
    configurations_json: str

    @property
    def completed_steps(self) -> int:
        """只计入完整成功并形成合法有限观测的物理区间。"""
        return len(self.raw_force)

    def to_report(self, *, provenance: dict | None = None) -> dict:
        """原始行派生摘要；每次返回独立对象，不重跑控制或修饰失败轨迹。"""
        entries = [row.step for i, row in enumerate(self.observations)
                   if row.status == "stable" and (i == 0 or self.observations[i - 1].status != "stable")]
        peak = lambda rows: np.max(np.abs(rows), axis=0).tolist() if len(rows) else None
        return {
            "kind": "cart_pole_swing_up_plaintext", "version": 1, "computation_mode": "plaintext",
            "configurations": json.loads(self.configurations_json),
            "provenance": json.loads(json.dumps(provenance, allow_nan=False)) if provenance else {
                "available": False, "reason": "source_and_code_provenance_not_supplied",
            },
            "channels": {"state": list(STATE_NAMES), "state_units": list(STATE_UNITS),
                         "force_unit": "N", "time_unit": "s"},
            "assumptions": ["ideal full-state observation", "ZOH force and canonical RK4",
                            "finite numerical feasibility, not global stability or secure swing-up"],
            "time_s": self.time_s.tolist(), "state": self.state.tolist(),
            "output": self.output.tolist(), "upright_angle_rad": self.upright_angle_rad.tolist(),
            "raw_force": self.raw_force.tolist(), "applied_force": self.applied_force.tolist(),
            "disturbance_force": self.disturbance_force.tolist(),
            "total_force": self.total_force.tolist(), "mode_for_interval": list(self.mode_for_interval),
            "saturated": np.any(self.raw_force != self.applied_force, axis=1).tolist(),
            "observations": [asdict(row) for row in self.observations],
            "transitions": [asdict(event) for event in self.transitions],
            "disturbance_events": [dict(zip(
                ("interval_step", "requested_force_n", "actual_force_n", "disposition"),
                event, strict=True,
            )) for event in self.disturbance_events],
            "termination": self.termination, "goal_met": self.goal_met,
            "failure": {"observation_step": self.failure_observation_step,
                        "interval_step": self.failure_interval_step,
                        "reason": self.failure_reason, "detail": self.failure_detail},
            "attempted_step": None if self.attempted_step is None else dict(zip(
                ("interval_step", "raw_force_n", "applied_force_n", "disturbance_force_n",
                 "total_force_n"), self.attempted_step, strict=True,
            )),
            "summary": {"completed_steps": self.completed_steps,
                        "first_stable_step": self.first_stable_step, "stable_entry_steps": entries,
                        "max_abs_state": peak(self.state), "max_abs_raw_force": peak(self.raw_force),
                        "max_abs_applied_force": peak(self.applied_force),
                        "max_abs_total_force": peak(self.total_force),
                        "saturated_intervals": int(np.count_nonzero(self.raw_force != self.applied_force)),
                        "final_stable_count": self.observations[-1].stable_count
                        if self.observations else 0},
        }


def run_swing_up_experiment(
    plant_contract: CartPoleContract, balance: CartPoleBalanceConfig, config: CartPoleSwingUpConfig,
    *, replay_disturbances: tuple[float, ...] | None = None,
) -> SwingUpResult:
    """观测→监督→控制→一次限幅→外力→原子物理步；终点只观察，不再施力。

    replay_disturbances 是显式实际事件序列：不再次接受/拒绝请求，非法合力直接失败。
    参数错误在运行前抛出；物理/观测/数值失败返回真实可信前缀和分类诊断。
    """
    if not isinstance(config, CartPoleSwingUpConfig):
        raise TypeError("config 必须是 CartPoleSwingUpConfig")
    config.validate(plant_contract, balance)
    if replay_disturbances is not None:
        if not isinstance(replay_disturbances, tuple) or len(replay_disturbances) != config.horizon_steps:
            raise ValueError("重放事件必须是 horizon 长度的冻结元组")
        replay_disturbances = tuple(_number(d, "replay_disturbance") for d in replay_disturbances)
        if any(d not in (-1., 0., 1.) for d in replay_disturbances):
            raise ValueError("重放外力必须是实际 0/±1 N")
    effective = replace(plant_contract, initial_state=config.initial_state)
    plant = CartPolePlant(effective)
    adapter = CartPoleAdapter(effective, balance)
    supervisor = SwingUpSupervisor(effective, balance, config)
    states, outputs, observations = [], [], []
    raw_forces, applied_forces, disturbances, totals, modes, events = [], [], [], [], [], []
    scheduled = dict(config.disturbances)
    termination = "failed"
    failure_observation = failure_interval = reason = detail = attempted = first_stable = None
    snapshots = json.dumps({"plant_source_contract": asdict(plant_contract),
                            "balance": asdict(balance), "swing_up": asdict(config),
                            "effective_initial_state": list(effective.initial_state)}, allow_nan=False)
    try:
        output = _observation(plant.output())
        state = _finite_vector(plant.state, 4, "initial_state")
        states.append(state)
        outputs.append(output)
    except (TypeError, ValueError, FloatingPointError, OverflowError) as error:
        reason = "nonfinite" if isinstance(error, (FloatingPointError, OverflowError)) else "observation_invalid"
        failure_observation, detail = 0, str(error)
    else:
        for step in range(config.horizon_steps + 1):
            observed = supervisor.observe(step, output)
            observations.append(observed)
            if observed.status == "stable" and first_stable is None:
                first_stable = step
            if observed.phase == "failed":
                failure_observation, reason = step, observed.failure_reason
                break
            if step == config.horizon_steps:
                termination = ("observed_success" if observed.phase == "balance"
                               and observed.status == "stable" else "time_limit")
                break
            raw = applied = disturbance = total = None
            stage = "control"
            try:
                raw = _number(supervisor.raw_force(step, output), "raw_force")
                applied = float(adapter.apply_control(np.array([raw]))[0])
                requested = scheduled.get(step, 0.)
                disturbance = requested if replay_disturbances is None else replay_disturbances[step]
                disposition = "accepted"
                if abs(applied + disturbance) > effective.max_applied_force_n:
                    if replay_disturbances is not None:
                        stage = "replay_force"
                        raise ValueError("重放外力与控制合力超界")
                    disturbance, disposition = 0., "rejected_total_force_limit"
                total = applied + disturbance
                stage = "plant"
                next_output = _observation(plant.step(np.array([total])))
                next_state = _finite_vector(plant.state, 4, "next_state")
            except (TypeError, ValueError, FloatingPointError, OverflowError) as error:
                failure_interval, detail = step, str(error)
                if stage == "replay_force":
                    reason = "replay_force_limit"
                elif stage == "plant" and "track_center_limit_m" in str(error):
                    reason = "track_limit"
                else:
                    reason = "numeric_step" if stage == "plant" else "numeric_control"
                attempted = (step, raw, applied, disturbance, total)
                break
            # 真实有限的新观测先提交；下次速度/safe 门禁失败仍保留此已完成区间。
            raw_forces.append(np.array([raw]))
            applied_forces.append(np.array([applied]))
            disturbances.append(np.array([disturbance]))
            totals.append(np.array([total]))
            modes.append(observed.phase)
            if replay_disturbances is None and requested:
                events.append((step, requested, disturbance, disposition))
            elif replay_disturbances is not None and disturbance:
                events.append((step, disturbance, disturbance, "replayed_actual"))
            state, output = next_state, next_output
            states.append(state)
            outputs.append(output)
    # 不能形成有限新观测的异常只留最后可信前缀；不向 JSON 填 NaN 或伪造行。
    state_rows, output_rows = _rows(states, 4), _rows(outputs, 4)
    time = np.arange(len(states), dtype=np.float64) * effective.sample_period_s
    time.setflags(write=False)
    angles = np.array([upright_coordinates(row)[2] for row in output_rows], dtype=np.float64)
    angles.setflags(write=False)
    return SwingUpResult(
        time, state_rows, output_rows, angles, _rows(raw_forces, 1), _rows(applied_forces, 1),
        _rows(disturbances, 1), _rows(totals, 1), tuple(modes), tuple(observations),
        tuple(supervisor.transitions), tuple(events), termination, termination == "observed_success",
        first_stable, failure_observation, failure_interval, reason, detail, attempted, snapshots,
    )


def write_swing_up_report(result: SwingUpResult, path: str | Path,
                          *, provenance: dict | None = None) -> Path:
    """写入不覆盖已有文件的完整明文研究报告；I/O 失败明确抛出，不宣告保存成功。"""
    payload = json.dumps(result.to_report(provenance=provenance), ensure_ascii=False, allow_nan=False)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        stream.write(payload + "\n")
    return target
