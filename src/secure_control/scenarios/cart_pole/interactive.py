"""倒立摆 Client 的单步外力锁存与安全支先行的确定性对照。"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from queue import Empty, Full, Queue
from threading import Event, RLock

import numpy as np

from secure_control.simulation import SimulationPlan, SimulationResult
from secure_control.simulation.engine import simulate_branch

from .adapter import _finite_vector
from .experiment import BalanceMonitor
from .plant import CartPolePlant
from .secure_experiment import CartPoleSecureExperiment

PULSE_FORCE_N = 1.0
PULSE_PHASE = "after_controller_commit_before_plant_step"


class InteractiveSession:
    """GUI 只提交有界请求和取消标志；工作线程独占事件的实际步号。"""

    def __init__(self, *, scheduled: Mapping[int, float] | None = None,
                 notify: Callable[[str, object], None] | None = None) -> None:
        if scheduled is not None and any(
            type(step) is not int or step < 0 or type(force) not in (int, float)
            or force not in (-PULSE_FORCE_N, PULSE_FORCE_N)
            for step, force in scheduled.items()
        ):
            raise ValueError("预定脉冲必须是非负整数步的 ±1 N。")
        self._requests: Queue[float] = Queue(maxsize=8)
        self._scheduled = dict(scheduled or {})
        self.cancelled = Event()
        self._accepting = True
        # 首次 SIGINT 也可能打断持锁的请求/清理；同线程停止回调必须能设置拒绝门禁。
        self._lock = RLock()
        self.notify = notify

    def request(self, force_n: float) -> bool:
        """按钮仅排队；返回值不表示外力已经施加。"""
        if type(force_n) not in (int, float) or force_n not in (-PULSE_FORCE_N, PULSE_FORCE_N):
            raise ValueError("只接受 +1 N 或 -1 N 单区间脉冲。")
        with self._lock:
            if self.cancelled.is_set() or not self._accepting:
                self.emit("rejected", "run_not_accepting")
                return False
            try:
                self._requests.put_nowait(float(force_n))
            except Full:
                self.emit("rejected", "queue_full")
                return False
        self.emit("queued", float(force_n))
        return True

    def take(self, step: int) -> float:
        """在已提交控制量与 plant.step 之间至多消费一个请求。"""
        try:
            return self._requests.get_nowait()
        except Empty:
            return self._scheduled.pop(step, 0.0)

    def close(self) -> None:
        with self._lock:
            self.cancelled.set()
            self._accepting = False
            self._reject_pending()

    @contextmanager
    def publication_guard(self) -> Iterator[None]:
        """Serialize close with the final artifact rename only."""
        with self._lock:
            if self.cancelled.is_set():
                raise RuntimeError("Client 运行已取消。")
            yield

    def stop_accepting(self) -> None:
        """安全支最后一步后拒绝未消费的请求，回放不再接收外力。"""
        with self._lock:
            self._accepting = False
            self._reject_pending()

    def reject_new(self) -> None:
        """正常停止保留已排队请求给 in-flight 区间，不设置 cancellation。"""
        with self._lock:
            self._accepting = False

    def latch(self, step: int, applied: float, limit: float) -> float:
        """按全局区间锁存至多一项外力；合力超界拒绝外力，不额外裁剪。"""
        if self.cancelled.is_set():
            raise RuntimeError("倒立摆交互运行已取消。")
        disturbance = self.take(step)
        if abs(applied + disturbance) > limit:
            self.emit("rejected", {"step": step, "reason": "total_force_limit"})
            return 0.0
        return disturbance

    def _reject_pending(self) -> None:
        while True:
            try:
                self._requests.get_nowait()
            except Empty:
                return
            self.emit("rejected", "run_ended")

    def emit(self, kind: str, value: object) -> None:
        if self.notify is not None:
            self.notify(kind, value)


class DisturbedCartPolePlant:
    """在既有 plant 前合成物理外力；正式 control 仍是控制器 applied 力。"""

    def __init__(self, plant: CartPolePlant, scenario: CartPoleSecureExperiment,
                 *, session: InteractiveSession | None = None) -> None:
        self._plant = plant
        self._scenario = scenario
        self._session = session
        self._replay: tuple[float, ...] | None = None
        self.forces: list[float] = []
        self._display_monitor = BalanceMonitor(scenario.balance)
        self._display_monitor.observe(plant.output())

    def set_replay(self, forces: tuple[float, ...]) -> None:
        """普通支运行前冻结安全支已成功推进的外力序列。"""
        if self._session is not None or self._replay is not None or self.forces:
            raise ValueError("普通支事件序列只能设置一次。")
        self._replay = forces

    def output(self) -> np.ndarray:
        return self._plant.output()

    def step(self, control: np.ndarray) -> np.ndarray:
        applied = _finite_vector(control, 1, "controller applied force")
        step = len(self.forces)
        if self._session is not None:
            disturbance = self._session.latch(
                step, float(applied[0]), self._scenario.plant_contract.max_applied_force_n,
            )
        else:
            if self._replay is None or step >= len(self._replay):
                raise ValueError("普通支缺少冻结的外力事件。")
            disturbance = self._replay[step]
        limit = self._scenario.plant_contract.max_applied_force_n
        if abs(float(applied[0]) + disturbance) > limit:
            if self._session is None or disturbance == 0:
                raise ValueError("重放外力与控制器合力超出物理输入界。")
            self._session.emit("rejected", {"step": step, "reason": "total_force_limit"})
            disturbance = 0.0
        next_output = self._plant.step(np.array([float(applied[0]) + disturbance]))
        # plant 成功推进后才把事件归属到当前整数控制步。
        self.forces.append(disturbance)
        status = self._display_monitor.observe(next_output)
        if self._session is not None:
            self._session.emit("frame", {
                "step": step + 1,
                "time_s": (step + 1) * self._scenario.plant_contract.sample_period_s,
                "state": tuple(float(value) for value in next_output),
                "status": status,
                "applied_force_n": float(applied[0]),
                "disturbance_force_n": disturbance,
            })
        return next_output


class InteractiveCartPoleExperiment:
    """组合 #92 场景；安全支现场锁存，普通支用冻结事件重放。"""

    def __init__(self, scenario: CartPoleSecureExperiment, session: InteractiveSession) -> None:
        self.scenario = scenario
        self.session = session
        self.secure_plant = DisturbedCartPolePlant(scenario.secure_plant, scenario,
                                                   session=session)
        self.ideal_plant = DisturbedCartPolePlant(scenario.ideal_plant, scenario)
        scenario.secure_plant = self.secure_plant
        scenario.ideal_plant = self.ideal_plant

    @property
    def forces(self) -> tuple[float, ...]:
        return tuple(self.secure_plant.forces)

    def build_plan(self, runtime: object) -> SimulationPlan:
        return self.scenario.build_plan(runtime)

    def execute_plan(self, plan: SimulationPlan) -> SimulationResult:
        """沿用通用逐支引擎，避免交互事件落入 ideal-first 批处理。"""
        if (plan.secure.plant is not self.secure_plant or plan.ideal.plant is not self.ideal_plant
                or plan.secure.adapter is plan.ideal.adapter
                or plan.secure.runtime is plan.ideal.runtime):
            raise ValueError("交互双支必须拥有独立状态与指定 plant。")
        times = plan.sample_times
        secure = simulate_branch(plan.secure, times)
        self.session.stop_accepting()
        if self.session.cancelled.is_set():
            raise RuntimeError("倒立摆交互运行已取消。")
        frozen = self.forces
        if len(frozen) != times.size:
            raise ValueError("安全支事件记录不完整。")
        self.ideal_plant.set_replay(frozen)
        self.session.emit("phase", "replaying")
        ideal = simulate_branch(plan.ideal, times)
        if not np.array_equal(ideal.reference, secure.reference):
            raise ValueError("倒立摆双支参考时间轨迹不一致。")
        if ideal.output.shape != secure.output.shape or ideal.control.shape != secure.control.shape:
            raise ValueError("倒立摆双支轨迹 shape 不一致。")
        if tuple(self.ideal_plant.forces) != frozen:
            raise ValueError("倒立摆双支外力事件不一致。")
        return SimulationResult(
            time=times, reference=secure.reference,
            output_ideal=ideal.output, output_secure=secure.output,
            control_ideal=ideal.control, control_secure=secure.control,
            control_error=ideal.control - secure.control,
            output_error=ideal.output - secure.output,
        )
