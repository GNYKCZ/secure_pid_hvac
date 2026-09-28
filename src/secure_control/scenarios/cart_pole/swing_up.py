"""明文能量起摆与观测驱动阶段机；不改变旧近直立或安全计算契约。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import yaml

from secure_control.execution import PlaintextStateSpaceRuntime

from .adapter import MeasurementSample, ObserverBalanceEpisode, _checked_sample, _finite_vector
from .contract import CartPoleContract, _number, _UniqueKeyLoader, load_cart_pole_contract
from .controller import (
    CartPoleBalanceConfig,
    _four,
    build_cart_pole_controller_spec,
    load_cart_pole_balance_config,
)
from .experiment import BalanceMonitor

if TYPE_CHECKING:
    from .observer import CartPoleObserverDesign


@dataclass(frozen=True, slots=True)
class CartPoleSwingUpConfig:
    """仅保存起摆参数；轨道、力界、采样和原稳定域继续来自既有契约。"""

    initial_state: tuple[float, float, float, float]
    kick_direction: int
    kick_force_n: float
    kick_steps: int
    energy_gain_m_per_j_s: float
    cart_position_gain_per_s2: float
    cart_velocity_gain_per_s: float
    capture_enter_abs: tuple[float, float, float, float]
    capture_exit_abs: tuple[float, float, float, float]
    capture_hold_observations: int
    swing_reentry_dwell_steps: int
    capture_timeout_steps: int
    capture_max_attempts: int
    acquisition_deadline_steps: int
    max_cart_speed_m_per_s: float
    max_pole_speed_rad_per_s: float
    horizon_steps: int
    disturbances: tuple[tuple[int, float], ...]

    def __post_init__(self) -> None:
        for name in ("initial_state", "capture_enter_abs", "capture_exit_abs"):
            object.__setattr__(self, name, _four(
                getattr(self, name), name, positive=name != "initial_state"
            ))
        for name in (
            "kick_force_n", "energy_gain_m_per_j_s", "cart_position_gain_per_s2",
            "cart_velocity_gain_per_s", "max_cart_speed_m_per_s", "max_pole_speed_rad_per_s",
        ):
            object.__setattr__(self, name, _number(getattr(self, name), name, positive=True))
        if type(self.kick_direction) is not int or self.kick_direction not in (-1, 1):
            raise ValueError("kick_direction 必须是整数 ±1")
        for name in (
            "kick_steps", "capture_hold_observations", "swing_reentry_dwell_steps",
            "capture_timeout_steps", "capture_max_attempts", "acquisition_deadline_steps",
            "horizon_steps",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} 必须是正整数")
        if not self.kick_steps < self.acquisition_deadline_steps <= self.horizon_steps:
            raise ValueError("kick_steps < acquisition_deadline_steps <= horizon_steps 必须成立")
        if self.capture_hold_observations - 1 > self.capture_timeout_steps:
            raise ValueError("捕获保持不能长于捕获时限")
        if not isinstance(self.disturbances, (list, tuple)):
            raise TypeError("disturbances 必须是有序事件序列")
        events = []
        previous = -1
        for event in self.disturbances:
            if not isinstance(event, (list, tuple)) or len(event) != 2:
                raise ValueError("外力事件必须是 (step, force_n)")
            step, force = event
            if type(step) is not int or not previous < step < self.horizon_steps:
                raise ValueError("外力步号必须唯一、递增且位于 horizon 内")
            force = _number(force, "disturbance.force_n")
            if force not in (-1., 1.):
                raise ValueError("外力必须是 ±1 N 单区间事件")
            events.append((step, force))
            previous = step
        object.__setattr__(self, "disturbances", tuple(events))

    def validate(self, plant: CartPoleContract, balance: CartPoleBalanceConfig) -> None:
        """在运行前交叉核对原物理域、捕获滞回和实数时间范围。"""
        if not isinstance(plant, CartPoleContract) or not isinstance(balance, CartPoleBalanceConfig):
            raise TypeError("plant/balance 类型无效")
        balance.validate_plant(plant)
        if not all(a < b < c for a, b, c in zip(
            self.capture_enter_abs, self.capture_exit_abs, balance.safe_abs, strict=True
        )):
            raise ValueError("必须逐项满足 capture_enter_abs < capture_exit_abs < safe_abs")
        if self.kick_force_n > plant.max_applied_force_n:
            raise ValueError("kick_force_n 超过原力界")
        if abs(self.initial_state[0]) > plant.track_center_limit_m:
            raise ValueError("initial_state 超过原轨道界")
        if (abs(self.initial_state[1]) > self.max_cart_speed_m_per_s
                or abs(self.initial_state[3]) > self.max_pole_speed_rad_per_s):
            raise ValueError("initial_state 超过起摆速度包络")
        try:
            final_time = self.horizon_steps * plant.sample_period_s
        except OverflowError as error:
            raise ValueError("实验终点时间超出实数范围") from error
        if not np.isfinite(final_time):
            raise ValueError("实验终点时间不是有限秒")


def load_cart_pole_swing_up_config(
    path: str | Path, plant: CartPoleContract, balance: CartPoleBalanceConfig
) -> CartPoleSwingUpConfig:
    """严格加载独立起摆配置，引用的唯一物理/平衡来源必须与调用参数相符。"""
    path = Path(path)
    with path.open(encoding="utf-8") as stream:
        root = yaml.load(stream, Loader=_UniqueKeyLoader)
    expected = {"schema_version", "scenario", "plant_source", "balance_source",
                *CartPoleSwingUpConfig.__dataclass_fields__}
    if not isinstance(root, Mapping) or set(root) != expected:
        raise ValueError(f"起摆配置必须且仅能包含 {sorted(expected)}")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version 必须是整数 1")
    if root["scenario"] != "cart_pole":
        raise ValueError("scenario 必须是 cart_pole")
    for name in ("plant_source", "balance_source"):
        if not isinstance(root[name], str) or not root[name].strip():
            raise ValueError(f"{name} 必须是非空路径")
    referenced_plant = load_cart_pole_contract(path.parent / root["plant_source"])
    referenced_balance = load_cart_pole_balance_config(
        path.parent / root["balance_source"], referenced_plant
    )
    if referenced_plant != plant or referenced_balance != balance:
        raise ValueError("起摆引用来源与传入 plant/balance 不一致")
    fields = {name: root[name] for name in CartPoleSwingUpConfig.__dataclass_fields__}
    if not isinstance(fields["disturbances"], list):
        raise TypeError("disturbances 必须是 YAML 列表")
    events = []
    for event in fields["disturbances"]:
        if not isinstance(event, Mapping) or set(event) != {"step", "force_n"}:
            raise ValueError("外力事件必须且仅能含 step/force_n")
        events.append((event["step"], event["force_n"]))
    fields["disturbances"] = events
    config = CartPoleSwingUpConfig(**fields)
    config.validate(plant, balance)
    return config


def _observation(output) -> np.ndarray:
    """显式拒绝混合列表中的 bool，不能让 NumPy 转浮点时抹掉错误类型。"""
    if any(isinstance(item, (bool, np.bool_)) for item in np.asarray(output, dtype=object).flat):
        raise TypeError("observation 不接受 bool")
    return _finite_vector(output, 4, "observation")


def upright_coordinates(output) -> np.ndarray:
    """仅在新场景构造 z=[p,v,α,ω]；原 θ 连续，α∈[-π,π)，ω不差分。"""
    local = _observation(output)
    # 已在 chart 内的角保持原浮点值，避免加减 π 引入阈值边界的额外舍入。
    if not -np.pi <= local[2] < np.pi:
        local[2] = (local[2] + np.pi) % (2 * np.pi) - np.pi
    local.setflags(write=False)
    return local


def pole_energy(plant: CartPoleContract, output) -> float:
    """带杆惯量的支点相对能量 E=Jω²/2+mlg cosθ，不是全系统机械能。"""
    _, _, theta, omega = _observation(output)
    h = plant.pole_mass_kg * plant.com_length_m
    j = plant.pole_inertia_kg_m2 + h * plant.com_length_m
    with np.errstate(over="raise", invalid="raise"):
        energy = .5 * j * omega**2 + h * plant.gravity_m_per_s2 * np.cos(theta)
    return _number(energy, "pole_energy")


def energy_shaping_force(plant: CartPoleContract, config: CartPoleSwingUpConfig, output) -> float:
    """按原质量矩阵消元把期望加速度映射为 raw 力；无除 cosθ 奇点。"""
    position, velocity, theta, omega = _observation(output)
    h = plant.pole_mass_kg * plant.com_length_m
    j = plant.pole_inertia_kg_m2 + h * plant.com_length_m
    cosine, sine = np.cos(theta), np.sin(theta)
    with np.errstate(over="raise", invalid="raise", divide="raise"):
        error = pole_energy(plant, output) - h * plant.gravity_m_per_s2
        acceleration = (-config.energy_gain_m_per_j_s * error * omega * cosine
                        - config.cart_position_gain_per_s2 * position
                        - config.cart_velocity_gain_per_s * velocity)
        force = ((plant.cart_mass_kg + plant.pole_mass_kg - h**2 * cosine**2 / j)
                 * acceleration + plant.cart_friction_n_s_per_m * velocity
                 + h * omega**2 * sine - h**2 * plant.gravity_m_per_s2 / j * sine * cosine)
    return _number(force, "raw_force")


class CausalVelocityEstimator:
    """只缓存最近两个两编码器样本；连续角在差分前绝不折回。"""

    def __init__(self, sample_period_s: float) -> None:
        self.period = _number(sample_period_s, "sample_period_s", positive=True)
        self.next_step = 0
        self._previous: list[np.ndarray] = []

    def observe(self, sample: MeasurementSample) -> np.ndarray:
        """k=0 使用声明的零速度，k=1 后差，此后使用三点因果后差。"""
        _checked_sample(sample, self.next_step, self.period)
        y = np.array([sample.p_m, sample.theta_rad], dtype=np.float64)
        with np.errstate(over="raise", invalid="raise", divide="raise"):
            if self.next_step == 0:
                velocity = np.zeros(2)
            elif self.next_step == 1:
                velocity = (y - self._previous[-1]) / self.period
            else:
                velocity = (3 * y - 4 * self._previous[-1] + self._previous[-2]) / (2 * self.period)
        estimate = _finite_vector(
            [y[0], velocity[0], y[1], velocity[1]], 4, "estimated_state"
        )
        self._previous = [*self._previous[-1:], y]
        self.next_step += 1
        estimate.setflags(write=False)
        return estimate


@dataclass(frozen=True, slots=True)
class SwingUpObservation:
    """监督器的一次独立观测快照；计数只随整数新观测推进。"""

    step: int
    local_state: tuple[float, ...] | None
    phase: str
    status: str
    stable_count: int
    capture_attempt: int
    capture_count: int
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class SwingUpTransition:
    """在 t_k 发生的真实转换，保留触发观测而非预测或图帧。"""

    observation_step: int
    time_s: float
    from_phase: str
    to_phase: str
    trigger: str
    local_state: tuple[float, ...] | None


class SwingUpSupervisor:
    """独占起摆阶段/捕获重试；旧静态路径与新明文 observer 共用阶段判据。"""

    def __init__(self, plant: CartPoleContract, balance: CartPoleBalanceConfig,
                 config: CartPoleSwingUpConfig,
                 *, observer_design: CartPoleObserverDesign | None = None) -> None:
        """每次实验新建独立状态；不虚构能量法的线性控制器状态。"""
        config.validate(plant, balance)
        if observer_design is not None and (
            replace(observer_design.plant, initial_state=config.initial_state) != plant
            or observer_design.balance != balance
        ):
            raise ValueError("observer设计与起摆物理/平衡来源不一致")
        self.plant, self.balance, self.config = plant, balance, config
        self.observer_design = observer_design
        self.runtime = (PlaintextStateSpaceRuntime(build_cart_pole_controller_spec(plant, balance))
                        if observer_design is None else None)
        self.episode: ObserverBalanceEpisode | None = None
        self.initializations: list[tuple[int, int, float, tuple[float, ...]]] = []
        self.phase = "swing_up"
        self.next_observation_step = 0
        self.capture_attempt = self.capture_count = 0
        self.capture_started = self.reentry_step = self.acquisition_started = 0
        self.monitor: BalanceMonitor | None = None
        self.failure_reason: str | None = None
        self.transitions: list[SwingUpTransition] = []
        self.last: SwingUpObservation | None = None

    def _transition(self, phase, reason, step, local):
        self.transitions.append(SwingUpTransition(
            step, step * self.plant.sample_period_s, self.phase, phase, reason,
            None if local is None else tuple(float(v) for v in local),
        ))
        self.phase = phase

    def _fail(self, reason, step, local):
        self.failure_reason = reason
        self._end_observer(reason)
        self._transition("failed", reason, step, local)

    def _end_observer(self, reason: str) -> None:
        if self.episode is not None:
            self.episode.end(reason)
            self.episode = None
            self.runtime = None

    def _return_to_swing(self, reason: str, step: int, local: np.ndarray) -> None:
        was_balanced = self.phase == "balance"
        self._end_observer(reason)
        self._transition("swing_up", reason, step, local)
        self.capture_count = 0
        self.monitor = None
        self.reentry_step = step + self.config.swing_reentry_dwell_steps
        if was_balanced:
            self.capture_attempt = 0
            self.acquisition_started = step

    def _start_observer(self, step: int, output: np.ndarray) -> None:
        if self.observer_design is None:
            return
        sample = MeasurementSample(step, step * self.plant.sample_period_s,
                                   float(output[0]), float(output[2]))
        initialization = self.observer_design.initialize(
            sample, velocity_seed=(float(output[1]), float(output[3])))
        self.runtime = PlaintextStateSpaceRuntime(initialization.spec)
        self.episode = ObserverBalanceEpisode(
            initialization, self.runtime, episode_id=f"plaintext-capture-{step}")
        self.initializations.append((
            step, initialization.branch, initialization.theta_star,
            tuple(float(value) for value in initialization.spec.x0),
        ))

    def observe(self, step: int, output) -> SwingUpObservation:
        """先物理/速度门禁，再原 safe 门禁与捕获滞回，最后到期判定；终点可调用。"""
        if self.phase == "failed":
            raise RuntimeError("失败监督器不能继续消费观测")
        if type(step) is not int or step != self.next_observation_step:
            raise ValueError("观测步号必须从 0 连续消费一次")
        self.next_observation_step += 1
        try:
            local = upright_coordinates(output)
        except (TypeError, ValueError):
            local = None
            self._fail("observation_invalid", step, local)
        except (FloatingPointError, OverflowError):
            local = None
            self._fail("nonfinite", step, local)
        if self.phase != "failed":
            if abs(local[0]) > self.plant.track_center_limit_m:
                self._fail("track_limit", step, local)
            elif (abs(local[1]) > self.config.max_cart_speed_m_per_s
                  or abs(local[3]) > self.config.max_pole_speed_rad_per_s):
                self._fail("overspeed", step, local)
        if (self.phase == "swing_up" and step >= max(self.config.kick_steps, self.reentry_step)
                and np.all(np.abs(local) <= self.config.capture_enter_abs)
                and local[2] * local[3] <= 0):
            if self.capture_attempt >= self.config.capture_max_attempts:
                self._fail("capture_attempts_exhausted", step, local)
            else:
                self.capture_attempt += 1
                self.capture_started = step
                self.capture_count = 0
                self.monitor = BalanceMonitor(self.balance)
                try:
                    self._start_observer(step, _observation(output))
                except (TypeError, ValueError, FloatingPointError, OverflowError):
                    self._fail("observer_initialization", step, local)
                else:
                    self._transition("capture", "capture_enter", step, local)
        if self.phase in ("capture", "balance"):
            self.monitor.observe(local)
            if self.monitor.status == "failed":
                if self.observer_design is None:
                    self._fail("balance_domain_exceeded", step, local)
                else:
                    self._return_to_swing("balance_domain_exit", step, local)
            elif self.phase == "capture":
                inside_exit = np.all(np.abs(local) <= self.config.capture_exit_abs)
                self.capture_count = (self.capture_count + 1
                                      if np.all(np.abs(local) <= self.config.capture_enter_abs)
                                      else 0)
                if self.capture_count >= self.config.capture_hold_observations:
                    self._transition("balance", "capture_hold", step, local)
                elif step - self.capture_started >= self.config.capture_timeout_steps:
                    if self.observer_design is None:
                        self._fail("capture_timeout", step, local)
                    else:
                        self._return_to_swing("capture_timeout", step, local)
                elif not inside_exit:
                    self._return_to_swing("capture_aborted", step, local)
        # 同刻合法捕获保持转换优先；达到全局时限却仍未 balance 则失败。
        acquisition_age = (step if self.observer_design is None
                           else step - self.acquisition_started)
        if (self.phase not in ("balance", "failed")
                and acquisition_age >= self.config.acquisition_deadline_steps):
            self._fail("acquisition_timeout", step, local)
        status = ("failed" if self.phase == "failed" else self.monitor.status
                  if self.monitor is not None else "acquiring")
        self.last = SwingUpObservation(
            step, None if local is None else tuple(float(v) for v in local), self.phase, status,
            self.monitor.stable_count if self.monitor is not None else 0,
            self.capture_attempt, self.capture_count, self.failure_reason,
        )
        return self.last

    def raw_force(self, step: int, output) -> float:
        """只为刚消费的可继续观测计算力；报告终点不调用此方法。"""
        if (self.last is None or type(step) is not int or step != self.last.step
                or self.phase == "failed"):
            raise RuntimeError("必须先消费可继续的新观测")
        local = upright_coordinates(output)
        if tuple(local) != self.last.local_state:
            raise ValueError("力计算必须使用本次观测")
        if self.phase in ("capture", "balance"):
            if self.episode is not None:
                sample = MeasurementSample(step, step * self.plant.sample_period_s,
                                           float(output[0]), float(output[2]))
                return float(self.episode.step(sample)[0])
            return float(self.runtime.step(local - np.array(self.balance.target_state))[0])
        if step < self.config.kick_steps:
            return self.config.kick_direction * self.config.kick_force_n
        return energy_shaping_force(self.plant, self.config, output)
