"""倒立摆连续 LAN 的有限范围证明、双支装配及场景证据。"""

from __future__ import annotations

from dataclasses import dataclass
from math import inf, nextafter
from typing import TYPE_CHECKING

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.protocol import ControllerRangeContract
from secure_control.protocol.roles import (
    _bounded_input_reachability,
    _finite_horizon_encoded_trace,
)
from secure_control.simulation import SimulationBranch, SimulationPlan, SimulationResult

from .adapter import (
    CartPoleAdapter,
    CartPoleObserverSimulation,
    ControlCommand,
    MeasurementSample,
    ObserverBalanceEpisode,
    _checked_sample,
    _disturbance_plan,
    _finite_vector,
)
from .contract import CartPoleContract
from .controller import CartPoleBalanceConfig
from .experiment import BalanceMonitor
from .observer import CartPoleObserverDesign, ObserverInitialization
from .plant import CartPolePlant

if TYPE_CHECKING:
    from .interactive import InteractiveSession

SCENARIO_VERSION = "1"


def sustained_observer_numeric_contract(
    initialization: ObserverInitialization, *, fractional_bits: int,
    parameter_bits: int, runtime_payload_bits: int, modulus: int,
) -> tuple[FixedPointContext, ControllerRangeContract, dict[str, object]]:
    """Choose an exact encoded block certificate for an unbounded number of rounds."""
    spec = initialization.spec
    if (spec.state_dimension != 4 or spec.input_dimension != 2 or spec.output_dimension != 1
            or not runtime_payload_bits >= parameter_bits > fractional_bits >= 1):
        raise ValueError("observer 持续数值位宽或维度无效。")
    parameter_context = FixedPointContext(modulus, parameter_bits, fractional_bits)
    for name in ("A", "B", "C", "D", "x0"):
        parameter_context.encode(getattr(spec, name))
    context = FixedPointContext(modulus, runtime_payload_bits, fractional_bits)
    inputs = tuple(max(abs(int(context.encode(-nextafter(limit, inf)))),
                       abs(int(context.encode(nextafter(limit, inf)))))
                   for limit in initialization.y_abs)
    if any(bound > context.maximum_payload for bound in inputs):
        raise ValueError("observer 测量超过 runtime payload。")
    payloads = {name: np.asarray(context.encode(getattr(spec, name)), dtype=object)
                for name in ("A", "B", "C", "D", "x0")}
    for block in range(1, 129):
        try:
            bounds = _bounded_input_reachability(payloads, inputs, fractional_bits, block)
        except ValueError:
            continue
        if all(bound <= context.maximum_payload for bound in bounds):
            break
    else:
        raise ValueError("observer 编码矩阵无可表示的有界输入可达证书。")
    contract = ControllerRangeContract(bounds, inputs, reachability_block_steps=block)
    proof = {"algorithm": "encoded-block-power-rational-v1", "block_steps": block,
             "state_payload_bounds": list(bounds), "input_payload_bounds": list(inputs),
             "initial_payload": [int(x) for x in payloads["x0"].flat],
             "output_fractional_bits": 2 * fractional_bits}
    return context, contract, proof


def cart_pole_observer_numeric_contract(
    initialization: ObserverInitialization, horizon_steps: int, *,
    fractional_bits: int, parameter_bits: int, runtime_payload_bits: int, modulus: int,
) -> tuple[FixedPointContext, ControllerRangeContract, dict[str, object]]:
    """从已确定的两测量初态派生编码范围，交由通用 Client 精确复核。"""
    spec = initialization.spec
    if (spec.state_dimension != 4 or spec.input_dimension != 2 or spec.output_dimension != 1
            or type(horizon_steps) is not int or not 1 <= horizon_steps <= 1000
            or type(fractional_bits) is not int or type(parameter_bits) is not int
            or type(runtime_payload_bits) is not int
            or not runtime_payload_bits >= parameter_bits > fractional_bits >= 1):
        raise ValueError("observer 数值位宽、维度或有限时域无效。")
    parameters = FixedPointContext(modulus, parameter_bits, fractional_bits)
    for name in ("A", "B", "C", "D", "x0"):
        parameters.encode(getattr(spec, name))
    context = FixedPointContext(modulus, runtime_payload_bits, fractional_bits)
    input_bounds = tuple(max(abs(int(context.encode(-nextafter(limit, inf)))),
                             abs(int(context.encode(nextafter(limit, inf)))))
                         for limit in initialization.y_abs)
    if any(bound > context.maximum_payload for bound in input_bounds):
        raise ValueError("observer 两测量超过 runtime payload 位宽。")
    contract = ControllerRangeContract(
        (context.maximum_payload,) * spec.state_dimension, input_bounds,
        horizon_steps=horizon_steps,
    )
    proof = {
        "algorithm": "encoded-matrix-power-rational-v1",
        "horizon_steps": horizon_steps,
        "state_payload_bounds": list(contract.state_payload_bounds),
        "input_payload_bounds": list(input_bounds),
        "initial_payload": [int(value) for value in np.asarray(context.encode(spec.x0)).flat],
        "output_fractional_bits": 2 * fractional_bits,
        "parameter_bits": parameter_bits,
        "runtime_payload_bits": runtime_payload_bits,
        "step_bounds": list(_finite_horizon_encoded_trace(
            {name: np.asarray(context.encode(getattr(spec, name)), dtype=object)
             for name in ("A", "B", "C", "D", "x0")},
            input_bounds, fractional_bits, horizon_steps,
        )),
    }
    return context, contract, proof


def cart_pole_numeric_contract(
    spec: ControllerSpec, config: CartPoleBalanceConfig, *, fractional_bits: int,
    parameter_bits: int, runtime_payload_bits: int, modulus: int,
) -> tuple[FixedPointContext, ControllerRangeContract, dict[str, object]]:
    """按四维工作域证明静态 LQR 的编码输入及未回绕输出，限于 N≤1000。"""
    if (spec.state_dimension != 0 or spec.input_dimension != 4 or spec.output_dimension != 1
            or type(fractional_bits) is not int or type(parameter_bits) is not int
            or type(runtime_payload_bits) is not int
            or not runtime_payload_bits >= parameter_bits > fractional_bits >= 1
            or not 1 <= config.horizon_steps <= 1000):
        raise ValueError("倒立摆控制器维度、数值位宽或有限步数无效。")
    parameter_context = FixedPointContext(modulus, parameter_bits, fractional_bits)
    for name in ("A", "B", "C", "D", "x0"):
        parameter_context.encode(getattr(spec, name))
    context = FixedPointContext(modulus, runtime_payload_bits, fractional_bits)
    encoded_d = np.asarray(context.encode(spec.D), dtype=object).reshape(4)
    # 下一浮点数包络包含端点乘法的舍入；实际输入仍由 Client.prepare_online 再查一次。
    bounds = tuple(max(abs(int(context.encode(-nextafter(limit, inf)))),
                       abs(int(context.encode(nextafter(limit, inf)))))
                   for limit in config.safe_abs)
    if any(bound > context.maximum_payload for bound in bounds):
        raise ValueError("倒立摆观测工作域超过动态输入 payload 位宽。")
    output_bound = sum(abs(int(gain)) * bound
                       for gain, bound in zip(encoded_d, bounds, strict=True))
    if output_bound > (modulus - 1) // 2:
        raise ValueError("倒立摆 2ell 尺度输出可能在 Z_q 回绕。")
    contract = ControllerRangeContract((), bounds, horizon_steps=config.horizon_steps)
    proof = {
        "state_payload_bounds": [], "input_payload_bounds": list(bounds),
        "encoded_D": [int(value) for value in encoded_d],
        "output_accumulator_absolute_bound": output_bound,
        "centered_modulus_limit": (modulus - 1) // 2,
        "output_fractional_bits": 2 * fractional_bits,
    }
    return context, contract, proof


@dataclass(frozen=True, slots=True)
class CartPoleStepSnapshot:
    """一个已验证物理区间的公开不可变快照，观测与力保持原 SI 单位。"""

    t_before_s: float
    t_after_s: float
    observation_before: tuple[float, ...]
    observation_after: tuple[float, ...]
    target: tuple[float, ...]
    raw_force_n: float
    applied_force_n: float
    disturbance_force_n: float
    observed_status: str
    stable_count: int


class SustainedCartPoleExperiment:
    """整个 run 唯一的 plant/adapter/monitor，不累计全程轨迹或重复观测段界。"""

    def __init__(self, plant: CartPoleContract, balance: CartPoleBalanceConfig,
                 session: InteractiveSession) -> None:
        self.plant = CartPolePlant(plant)
        self.adapter = CartPoleAdapter(plant, balance)
        self.metadata = self.adapter.metadata
        self.monitor = BalanceMonitor(balance)
        self.session = session
        self.period = plant.sample_period_s
        self.force_limit = plant.max_applied_force_n
        self.output = _finite_vector(self.plant.output(), 4, "initial output")
        if self.monitor.observe(self.output) == "failed":
            raise ValueError("倒立摆初态离开工作域。")
        self.next_step = 0

    def controller_input(self) -> np.ndarray:
        """缓存观测已通过上一物理区间门禁，段间不重新观察/重建初态。"""
        return self.adapter.controller_input(
            self.adapter.reference_at(self.next_step * self.period), self.output,
        )

    def advance(self, global_step: int, raw: tuple[float, ...]) -> CartPoleStepSnapshot:
        """双提交之后完成执行器、外力、物理更新及工作域门禁才返回快照。"""
        if global_step != self.next_step:
            raise ValueError("物理区间不能重复或跳步。")
        force = _finite_vector(raw, 1, "raw control")
        applied = self.adapter.apply_control(force)
        disturbance = self.session.latch(global_step, float(applied[0]), self.force_limit)
        before = tuple(float(value) for value in self.output)
        following = _finite_vector(
            self.plant.step(np.array([float(applied[0]) + disturbance])), 4, "plant output",
        )
        if self.monitor.observe(following) == "failed":
            raise ValueError(f"倒立摆推进后离开工作域：{self.monitor.failure_reason}")
        snapshot = CartPoleStepSnapshot(
            global_step * self.period, (global_step + 1) * self.period,
            before, tuple(float(value) for value in following),
            tuple(float(value) for value in self.adapter.reference_at(global_step * self.period)),
            float(force[0]), float(applied[0]), disturbance,
            self.monitor.status, self.monitor.stable_count,
        )
        self.output = following
        self.next_step += 1
        return snapshot

    def terminal_summary(self) -> dict[str, object]:
        return {"terminal_time_s": self.next_step * self.period,
                "observed_status": self.monitor.status,
                "stable_count": self.monitor.stable_count}


class MonitoredCartPoleAdapter(CartPoleAdapter):
    """在分享之前门禁更新前观测，并单独保存 raw 力与判定。"""

    def __init__(self, plant: CartPoleContract, config: CartPoleBalanceConfig) -> None:
        super().__init__(plant, config)
        self.monitor = BalanceMonitor(config)
        self.observations: list[list[float]] = []
        self.statuses: list[str] = []
        self.stable_counts: list[int] = []
        self.raw_forces: list[float] = []

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """原场景 v=y−r 之前拒绝越域，确保该步不会产生 share。"""
        measured = _finite_vector(output, 4, "output")
        status = self.monitor.observe(measured)
        if status == "failed":
            raise ValueError(f"倒立摆观测离开工作域：{self.monitor.failure_reason}")
        self.observations.append(measured.tolist())
        self.statuses.append(status)
        self.stable_counts.append(self.monitor.stable_count)
        return super().controller_input(reference, measured)

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        """保存有限 raw 力，再由 #91 唯一执行器实现进行裁剪。"""
        raw = _finite_vector(raw_control, 1, "raw_control")
        applied = super().apply_control(raw)
        self.raw_forces.append(float(raw[0]))
        return applied

    def observe_terminal(self, output: np.ndarray) -> None:
        """第 N 次 plant.step 之后只观测，不再调用控制协议。"""
        measured = _finite_vector(output, 4, "terminal output")
        status = self.monitor.observe(measured)
        self.observations.append(measured.tolist())
        self.statuses.append(status)
        self.stable_counts.append(self.monitor.stable_count)
        if status != "stable":
            raise ValueError(f"倒立摆终点未稳定：{status}")


class CartPoleSecureExperiment:
    """拥有两套可变 plant/adapter；通用 runner 仅消费 plan 与验证方法。"""

    def __init__(self, plant: CartPoleContract, balance: CartPoleBalanceConfig,
                 spec: ControllerSpec) -> None:
        self.plant_contract = plant
        self.balance = balance
        self.spec = spec
        self.ideal_plant = CartPolePlant(plant)
        self.secure_plant = CartPolePlant(plant)
        self.ideal_adapter = MonitoredCartPoleAdapter(plant, balance)
        self.secure_adapter = MonitoredCartPoleAdapter(plant, balance)

    def build_plan(self, secure: object) -> SimulationPlan:
        """同一物理配置和初态，分别建 plant、adapter、runtime。"""
        return SimulationPlan(
            self.ideal_adapter.metadata,
            np.arange(self.balance.horizon_steps, dtype=np.float64)
            * self.plant_contract.sample_period_s,
            SimulationBranch(self.ideal_plant, self.ideal_adapter,
                             PlaintextStateSpaceRuntime(self.spec)),
            SimulationBranch(self.secure_plant, self.secure_adapter, secure),
        )

    def validate_result(self, result: SimulationResult) -> None:
        """N 行更新前轨迹后检查两支末端观测、完整记录和执行器口径。"""
        n = self.balance.horizon_steps
        for adapter, plant, outputs, applied in (
            (self.ideal_adapter, self.ideal_plant, result.output_ideal, result.control_ideal),
            (self.secure_adapter, self.secure_plant, result.output_secure, result.control_secure),
        ):
            if (len(adapter.observations) != n or len(adapter.raw_forces) != n
                    or len(adapter.statuses) != n or len(adapter.stable_counts) != n):
                raise ValueError("倒立摆逐步场景记录不完整。")
            np.testing.assert_allclose(adapter.observations, outputs, rtol=0, atol=0)
            np.testing.assert_allclose(
                np.clip(adapter.raw_forces, -self.plant_contract.max_applied_force_n,
                        self.plant_contract.max_applied_force_n), applied[:, 0], rtol=0, atol=0,
            )
            adapter.observe_terminal(plant.output())

    def evidence(self, run_id: str, result: SimulationResult) -> dict[str, object]:
        """N 行 raw/applied 配对与 N+1 判定属于场景，不改变八字段 schema。"""
        branches = {}
        for name, adapter in (("ideal", self.ideal_adapter), ("secure", self.secure_adapter)):
            branches[name] = {
                "observations": adapter.observations,
                "raw_force_n": adapter.raw_forces,
                "statuses": adapter.statuses,
                "stable_counts": adapter.stable_counts,
            }
        return {
            "schema_version": 1, "run_id": run_id, "sample_count": self.balance.horizon_steps,
            "sample_period_s": self.plant_contract.sample_period_s,
            "time_s": (np.arange(self.balance.horizon_steps + 1)
                       * self.plant_contract.sample_period_s).tolist(),
            "reference": [list(self.balance.target_state)
                          for _ in range(self.balance.horizon_steps + 1)],
            "state_units": list(self.ideal_adapter.metadata.output.units),
            "force_unit": "N", "raw_error": "ideal - secure",
            "raw_force_error_n": (np.asarray(self.ideal_adapter.raw_forces)
                                  - np.asarray(self.secure_adapter.raw_forces)).tolist(),
            "terminal_time_s": self.balance.horizon_steps * self.plant_contract.sample_period_s,
            "branches": branches,
        }


@dataclass(frozen=True, slots=True)
class SustainedObserverStepSnapshot:
    """Public interval facts; no observer estimate or protocol share is exposed."""

    t_before_s: float
    t_after_s: float
    measurement: tuple[float, float]
    local_measurement: tuple[float, float]
    observation_before: tuple[float, ...]
    observation_after: tuple[float, ...]
    raw_force_n: float
    applied_force_n: float
    requested_disturbance_n: float
    disturbance_force_n: float
    total_force_n: float
    force_disposition: str
    observed_status: str
    stable_count: int


class SustainedCartPoleObserverExperiment:
    """One physical plant, chart and global measurement stream across logical segments."""

    def __init__(self, design: CartPoleObserverDesign,
                 initialization: ObserverInitialization, session: InteractiveSession,
                 disturbances: tuple[tuple[int, float], ...] = ()) -> None:
        from .interactive import InteractiveSession

        if not isinstance(session, InteractiveSession):
            raise TypeError("需要交互会话。")
        self.design, self.initialization, self.session = design, initialization, session
        self._scheduled = dict(_disturbance_plan(disturbances, None))
        self.plant = CartPolePlant(design.plant)
        self.device = CartPoleObserverSimulation(self.plant, design.plant)
        self.monitor = BalanceMonitor(design.balance)
        self.metadata = CartPoleAdapter(design.plant, design.balance).metadata
        self.period = design.plant.sample_period_s
        self._step = initialization.first_sample_id
        self._sample: MeasurementSample | None = None
        self._before: np.ndarray | None = None
        self._local: np.ndarray | None = None
        self._episode_id = "sustained-observer"
        self._observe()

    def _observe(self) -> np.ndarray:
        truth = self.device.read_diagnostic_truth()
        local = truth.copy()
        local[2] -= self.initialization.theta_star
        if self.monitor.observe(local) == "failed":
            raise ValueError("倒立摆超出 observer 监督工作域。")
        return truth

    def controller_input(self) -> np.ndarray:
        if self._sample is not None:
            raise RuntimeError("上一测量尚未完成物理区间。")
        sample = self.device.read_measurement()
        _checked_sample(sample, self._step, self.period)
        local = _finite_vector(
            [sample.p_m, sample.theta_rad - self.initialization.theta_star],
            2, "measurement",
        )
        if np.any(np.abs(local) > self.initialization.y_abs):
            raise ValueError("measurement_outside_local_domain")
        self._sample, self._local = sample, local
        self._before = self.device.read_diagnostic_truth()
        return local.copy()

    def advance(self, step: int, raw_control: np.ndarray) -> SustainedObserverStepSnapshot:
        if (step != self._step or self._sample is None or self._local is None
                or self._before is None):
            raise ValueError("物理推进与全局样本不一致。")
        raw = float(_finite_vector(raw_control, 1, "raw_control")[0])
        if abs(raw) > self.design.plant.max_applied_force_n:
            raise ValueError("saturation_outside_contract")
        requested = self.session.take(step)
        if not requested:
            requested = self._scheduled.pop(step, 0.)
        self.device.request_disturbance(step, requested)
        receipt = self.device.send_control(ControlCommand(
            step, self._episode_id, self._sample.sample_id, raw,
        ))
        if (receipt.disposition != "simulated_interval_completed"
                or receipt.applied_force_n != raw
                or receipt.applied_source != "canonical_simulation"):
            raise ValueError("物理区间未确认。")
        requested, actual, total, disposition = self.device.read_interval_forces()
        after = self._observe()
        snapshot = SustainedObserverStepSnapshot(
            step * self.period, (step + 1) * self.period,
            (self._sample.p_m, self._sample.theta_rad), tuple(self._local),
            tuple(self._before), tuple(after), raw, raw, requested, actual, total,
            disposition, self.monitor.status, self.monitor.stable_count,
        )
        self._sample = self._local = self._before = None
        self._step += 1
        self.session.emit("frame", {"step": self._step, "time_s": self._step * self.period,
                                    "state": tuple(after), "status": self.monitor.status,
                                    "applied_force_n": raw,
                                    "disturbance_force_n": actual})
        return snapshot

    def terminal_summary(self) -> dict[str, object]:
        return {"terminal_time_s": self._step * self.period,
                "observed_status": self.monitor.status,
                "stable_count": self.monitor.stable_count}


class CartPoleObserverSecureExperiment:
    """#108 有限双支仿真；秘密估计只留在 P1/P2 的原 runtime。"""

    def __init__(self, design: CartPoleObserverDesign, initialization: ObserverInitialization,
                 disturbances: tuple[tuple[int, float], ...] = ()) -> None:
        if not isinstance(design, CartPoleObserverDesign):
            raise TypeError("需要已编译 observer design。")
        self.design = design
        self.initialization = initialization
        self.disturbances = _disturbance_plan(disturbances, design.balance.horizon_steps)
        self.records: dict[str, dict[str, list]] = {}
        self.secure_physical_completed = 0

    def build_plan(self, secure: object) -> SimulationPlan:
        """构造两份 plant/运行时；此 plan 由本类的两测量循环消费。"""
        plant, balance = self.design.plant, self.design.balance
        ideal = SimulationBranch(CartPolePlant(plant), CartPoleAdapter(plant, balance),
                                 PlaintextStateSpaceRuntime(self.initialization.spec))
        protected = SimulationBranch(CartPolePlant(plant), CartPoleAdapter(plant, balance), secure)
        return SimulationPlan(
            ideal.adapter.metadata,
            np.arange(balance.horizon_steps, dtype=np.float64) * plant.sample_period_s,
            ideal, protected,
        )

    def _run_branch(self, branch: SimulationBranch, name: str) -> dict[str, list]:
        """只从成功完成的仿真区间记录力；终点仅观测，不多消费一轮材料。"""
        plant, balance = self.design.plant, self.design.balance
        device = CartPoleObserverSimulation(branch.plant, plant, self.disturbances)
        episode = ObserverBalanceEpisode(self.initialization, branch.runtime,
                                         episode_id=f"finite-{name}")
        monitor = BalanceMonitor(balance)
        record: dict[str, list] = {key: [] for key in (
            "observations", "measurements", "local_measurements", "raw_force_n",
            "applied_force_n", "disturbance_force_n", "requested_disturbance_n",
            "total_force_n", "force_dispositions", "statuses", "stable_counts",
        )}
        if name == "ideal":
            record["ideal_estimates"] = []
        try:
            for step in range(balance.horizon_steps + 1):
                sample = device.read_measurement()
                local = episode.local_measurement(sample)
                truth = device.read_diagnostic_truth()
                local_truth = truth.copy()
                local_truth[2] -= self.initialization.theta_star
                status = monitor.observe(local_truth)
                if status == "failed":
                    raise ValueError(f"倒立摆 {name} 第 {step} 步超出工作域。")
                record["observations"].append(truth.tolist())
                record["measurements"].append([sample.p_m, sample.theta_rad])
                record["local_measurements"].append(local.tolist())
                record["statuses"].append(status)
                record["stable_counts"].append(monitor.stable_count)
                if name == "ideal":
                    record["ideal_estimates"].append(branch.runtime.state.tolist())
                if step == balance.horizon_steps:
                    if status != "stable":
                        raise ValueError(f"倒立摆 {name} 终点尚未稳定。")
                    break
                raw = float(episode.step(sample)[0])
                if abs(raw) > plant.max_applied_force_n:
                    raise ValueError("saturation_outside_contract")
                receipt = device.send_control(ControlCommand(
                    step, episode.episode_id, sample.sample_id, raw,
                ))
                if (receipt.disposition != "simulated_interval_completed"
                        or receipt.applied_force_n != raw
                        or receipt.applied_source != "canonical_simulation"):
                    raise ValueError("物理区间未确认；不得发布完整结果。")
                requested, actual, total, disposition = device.read_interval_forces()
                record["raw_force_n"].append(raw)
                record["applied_force_n"].append(float(receipt.applied_force_n))
                record["requested_disturbance_n"].append(requested)
                record["disturbance_force_n"].append(actual)
                record["total_force_n"].append(total)
                record["force_dispositions"].append(disposition)
                if name == "secure":
                    self.secure_physical_completed += 1
        finally:
            episode.end("finite_complete_or_failed")
        return record

    def execute_plan(self, plan: SimulationPlan) -> SimulationResult:
        """理想和安全支独立完成；只有两支完整 N 区间才生成正式结果。"""
        ideal = self._run_branch(plan.ideal, "ideal")
        secure = self._run_branch(plan.secure, "secure")
        self.records = {"ideal": ideal, "secure": secure}
        reference = np.tile(np.asarray(self.design.balance.target_state),
                            (self.design.balance.horizon_steps, 1))
        reference[:, 2] += self.initialization.theta_star
        output_ideal = np.asarray(ideal["observations"][:-1])
        output_secure = np.asarray(secure["observations"][:-1])
        control_ideal = np.asarray(ideal["applied_force_n"]).reshape(-1, 1)
        control_secure = np.asarray(secure["applied_force_n"]).reshape(-1, 1)
        return SimulationResult(
            plan.sample_times, reference, output_ideal, output_secure,
            control_ideal, control_secure, control_ideal - control_secure,
            output_ideal - output_secure,
        )

    def validate_result(self, result: SimulationResult) -> None:
        """确认执行后所有公开数组及成功终点来自同一实际轨迹。"""
        n = self.design.balance.horizon_steps
        if set(self.records) != {"ideal", "secure"} or result.time.size != n:
            raise ValueError("observer 双支记录不完整。")
        for name in ("ideal", "secure"):
            record = self.records[name]
            if (len(record["observations"]) != n + 1
                    or len(record["raw_force_n"]) != n
                    or record["statuses"][-1] != "stable"):
                raise ValueError("observer 物理前缀或终点不完整。")
            np.testing.assert_array_equal(
                getattr(result, f"output_{name}"), record["observations"][:-1]
            )
            np.testing.assert_array_equal(
                getattr(result, f"control_{name}")[:, 0], record["applied_force_n"]
            )

    def evidence(self, run_id: str, result: SimulationResult) -> dict[str, object]:
        """公开两测量、真实区间和监督结果，不复制任何秘密估计或份额。"""
        n = self.design.balance.horizon_steps
        local_truth = np.asarray(self.records["ideal"]["observations"]).copy()
        local_truth[:, 2] -= self.initialization.theta_star
        ideal_estimation_error = local_truth - np.asarray(
            self.records["ideal"]["ideal_estimates"]
        )
        raw_difference = (np.asarray(self.records["ideal"]["raw_force_n"])
                          - np.asarray(self.records["secure"]["raw_force_n"]))
        return {
            "schema_version": 3, "run_id": run_id, "sample_count": n,
            "sample_period_s": self.design.plant.sample_period_s,
            "terminal_time_s": n * self.design.plant.sample_period_s,
            "time_s": (np.arange(n + 1) * self.design.plant.sample_period_s).tolist(),
            "reference": [list(row) for row in np.vstack((
                result.reference, result.reference[-1]
            ))],
            "state_units": list(CartPoleAdapter(self.design.plant, self.design.balance)
                                .metadata.output.units),
            "force_unit": "N", "raw_error": "ideal - secure",
            "raw_force_error_n": raw_difference.tolist(),
            "metrics": {
                "ideal_estimation_error_max_abs_si": np.max(
                    np.abs(ideal_estimation_error), axis=0
                ).tolist(),
                "branch_state_difference_max_abs_si": np.max(
                    np.abs(result.output_error), axis=0
                ).tolist(),
                "raw_force_difference_max_abs_n": float(np.max(np.abs(raw_difference))),
                "secure_raw_peak_abs_n": float(np.max(np.abs(
                    self.records["secure"]["raw_force_n"]
                ))),
            },
            "events": [{"step": step, "force_n": force, "duration_steps": 1,
                        "phase": "after_controller_commit_before_plant_step"}
                       for step, force in self.disturbances],
            "branches": self.records,
        }
