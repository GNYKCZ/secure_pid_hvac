"""倒立摆有限时长明文闭环记录与场景自有的观察判定。"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import numpy as np

from secure_control.execution import PlaintextStateSpaceRuntime

from .adapter import CartPoleAdapter, _finite_vector
from .contract import CartPoleContract
from .controller import CartPoleBalanceConfig, build_cart_pole_controller_spec
from .plant import CartPolePlant


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
