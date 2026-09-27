"""倒立摆零目标观测映射及施加力裁剪。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

import numpy as np

from secure_control.simulation import ChannelMetadata, ScenarioMetadata

from .contract import CartPoleContract, _number
from .controller import CartPoleBalanceConfig
from .plant import CONTROL_NAMES, CONTROL_UNITS, OUTPUT_NAMES, OUTPUT_UNITS

if TYPE_CHECKING:
    from .observer import ObserverInitialization


def _finite_vector(value: Any, size: int, name: str) -> np.ndarray:
    """拒绝错误 shape、非实数和非有限信号，并隔离调用者缓冲区。"""
    raw = np.asarray(value)
    if raw.shape != (size,):
        raise ValueError(f"{name} 必须是 shape=({size},)")
    if raw.dtype.kind not in "iuf":
        raise TypeError(f"{name} 必须是实数向量")
    if not np.isfinite(raw).all():
        raise FloatingPointError(f"{name} 包含 NaN 或无穷大")
    converted = np.array(raw, dtype=np.float64, copy=True)
    if not np.isfinite(converted).all():
        raise FloatingPointError(f"{name} 转换后不是有限实数")
    return converted


class CartPoleAdapter:
    """保持 #90 SI 通道；在场景执行器边界对 raw 力作对称限幅。"""

    def __init__(self, plant: CartPoleContract, config: CartPoleBalanceConfig) -> None:
        """目标和执行器界分别来自本期与 #90 的唯一配置来源。"""
        if not isinstance(plant, CartPoleContract) or not isinstance(config, CartPoleBalanceConfig):
            raise TypeError("plant/config 类型无效")
        config.validate_plant(plant)
        self._target = np.array(config.target_state, dtype=np.float64)
        self._max_force = plant.max_applied_force_n
        self.metadata = ScenarioMetadata(
            "cart_pole",
            ChannelMetadata(OUTPUT_NAMES, OUTPUT_UNITS),
            ChannelMetadata(OUTPUT_NAMES, OUTPUT_UNITS),
            ChannelMetadata(CONTROL_NAMES, CONTROL_UNITS),
        )

    def reference_at(self, time: float) -> np.ndarray:
        """返回与当前理想观测同顺序、同单位的固定直立中央目标。"""
        if isinstance(time, bool) or not isinstance(time, (int, float, np.integer, np.floating)):
            raise TypeError("time 必须是有限实数秒")
        if not np.isfinite(time):
            raise FloatingPointError("time 不是有限实数秒")
        return self._target.copy()

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """LQR 输入 v=y−r；#90 正角向左，D=−K 给出恢复方向。"""
        target = _finite_vector(reference, 4, "reference")
        measured = _finite_vector(output, 4, "output")
        return measured - target

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        """先验证 raw 力，再只在 actuator 边界裁到 #90 的 ±F_max。"""
        raw = _finite_vector(raw_control, 1, "raw_control")
        return np.clip(raw, -self._max_force, self._max_force)


def _index(value: Any, name: str) -> int:
    """采样/命令身份是严格非负整数，不接受bool或1.0。"""
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} 必须是非负整数")
    return value


def _disturbance_plan(events: Any, horizon: int | None) -> tuple[tuple[int, float], ...]:
    """有限单区间±1N请求严格递增、唯一且在真实horizon内。"""
    result = []
    previous = -1
    for pair in events:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("disturbance 必须是(step,force)对")
        step, force = pair
        _index(step, "disturbance step")
        force = _number(force, "disturbance force")
        if step <= previous or (horizon is not None and step >= horizon) or force not in (-1., 1.):
            raise ValueError("disturbance 必须是horizon内严格递增的±1N")
        result.append((step, force))
        previous = step
    return tuple(result)


@dataclass(frozen=True, slots=True)
class MeasurementSample:
    """推进前的两编码器样本；theta连续，正向左，时间为声明的采样时间。"""

    sample_id: int
    time_s: float
    p_m: float
    theta_rad: float
    valid: tuple[bool, bool] = (True, True)

    def __post_init__(self) -> None:
        _index(self.sample_id, "sample_id")
        for name in ("time_s", "p_m", "theta_rad"):
            object.__setattr__(self, name, _number(getattr(self, name), name))
        if self.time_s < 0:
            raise ValueError("time_s 不得为负数")
        if not isinstance(self.valid, (tuple, list)) or len(self.valid) != 2 or any(
            type(item) is not bool for item in self.valid
        ):
            raise ValueError("valid 必须是两个bool")
        object.__setattr__(self, "valid", tuple(self.valid))


def _checked_sample(sample: MeasurementSample, expected_id: int, period: float) -> None:
    """固定周期消费者拒绝缺失/重复/乱序和无效样本；容差仅针对时间浮点表示。"""
    if not isinstance(sample, MeasurementSample):
        raise TypeError("测量必须是 MeasurementSample")
    if sample.sample_id != expected_id or not all(sample.valid):
        raise ValueError("invalid_measurement_identity_or_validity")
    expected_time = expected_id * period
    tolerance = 8 * np.finfo(float).eps * max(1., abs(expected_time))
    if not np.isfinite(expected_time) or abs(sample.time_s - expected_time) > tolerance:
        raise ValueError("invalid_measurement_time")


@dataclass(frozen=True, slots=True)
class ControlCommand:
    """关联episode和本轮测量的执行器目标；不含未知外力。"""

    command_id: int
    episode_id: str
    sample_id: int
    target_force_n: float

    def __post_init__(self) -> None:
        _index(self.command_id, "command_id")
        _index(self.sample_id, "sample_id")
        if not isinstance(self.episode_id, str) or not self.episode_id.strip():
            raise ValueError("episode_id 必须是非空字符串")
        object.__setattr__(self, "target_force_n", _number(self.target_force_n, "target_force_n"))


@dataclass(frozen=True, slots=True)
class ActuationReceipt:
    """ACK不等于执行：未知施加量保持None，仿真完成才确认整个区间。"""

    command_id: int
    episode_id: str
    sample_id: int
    disposition: str
    applied_force_n: float | None
    applied_source: str

    def __post_init__(self) -> None:
        _index(self.command_id, "command_id")
        _index(self.sample_id, "sample_id")
        if not isinstance(self.episode_id, str) or not self.episode_id.strip():
            raise ValueError("episode_id 必须是非空字符串")
        if self.disposition not in {"rejected", "accepted", "unknown", "simulated_interval_completed"}:
            raise ValueError("未知的执行回执状态")
        if not isinstance(self.applied_source, str) or not self.applied_source.strip():
            raise ValueError("applied_source 必须声明")
        if self.applied_force_n is not None:
            object.__setattr__(self, "applied_force_n", _number(self.applied_force_n, "applied_force_n"))
        if self.disposition == "simulated_interval_completed" and self.applied_force_n is None:
            raise ValueError("仿真完成必须有可确认施加量")


class ObserverDevice(Protocol):
    """有限consumer仅依赖两项被实际消费的能力，不认识设备内部plant或状态。"""

    def read_measurement(self) -> MeasurementSample:
        """读取推进前的新样本。"""
        ...

    def send_control(self, command: ControlCommand) -> ActuationReceipt:
        """执行一次关联指令并报告执行证据；禁止把ACK填成真实施加。"""
        ...


class ObserverBalanceEpisode:
    """消费固定chart两测量的薄episode；递推由注入runtime独占，不读取其秘密state。"""

    def __init__(self, initialization: ObserverInitialization, runtime: Any,
                 *, episode_id: str) -> None:
        """新episode必须显式初始化，段边界或恢复不应调用此构造器。"""
        from .observer import ObserverInitialization

        if not isinstance(initialization, ObserverInitialization):
            raise TypeError("initialization 必须是 ObserverInitialization")
        if not isinstance(episode_id, str) or not episode_id.strip():
            raise ValueError("episode_id 必须是非空字符串")
        self.initialization = initialization
        self.episode_id = episode_id
        self._runtime = runtime
        self._next_sample_id = initialization.first_sample_id
        self.active = True
        self.end_reason: str | None = None

    def local_measurement(self, sample: MeasurementSample) -> np.ndarray:
        """固定整圈零点，绝不逐轮wrap角或对wrapped角差分。"""
        _checked_sample(sample, self._next_sample_id, self.initialization.sample_period_s)
        local = _finite_vector(
            [sample.p_m, sample.theta_rad - self.initialization.theta_star], 2, "measurement"
        )
        if np.any(np.abs(local) > self.initialization.y_abs):
            raise ValueError("measurement_outside_local_domain")
        return local

    def step(self, sample: MeasurementSample) -> np.ndarray:
        """输出用更新前估计；失败终止episode，不reset、不重试已消费测量。"""
        if not self.active:
            raise RuntimeError("episode 已结束")
        try:
            force = _finite_vector(self._runtime.step(self.local_measurement(sample)), 1, "raw_force")
        except Exception:
            self.end("measurement_or_runtime_failure")
            raise
        self._next_sample_id += 1
        return force

    def end(self, reason: str) -> None:
        """退出吸收且保持首次原因；不回滚物理或控制器。"""
        if not isinstance(reason, str) or not reason:
            raise ValueError("结束原因必须是非空字符串")
        if self.active:
            self.active = False
            self.end_reason = reason


class CartPoleObserverSimulation:
    """组合canonical plant的两测量提供者；诊断是另一条显式通路。"""

    def __init__(self, plant: Any, contract: CartPoleContract,
                 disturbances: tuple[tuple[int, float], ...] = ()) -> None:
        """只在适配器内部推进仿真；未知外力不向observer提供输入。"""
        self._plant = plant
        self._contract = contract
        self._step = 0
        self._scheduled = dict(_disturbance_plan(disturbances, None))
        self._last_forces: tuple[float, float, float, str] | None = None
        self._ended = False

    def read_measurement(self) -> MeasurementSample:
        """控制路径只获得p与连续theta；不暴露四维output能力。"""
        truth = _finite_vector(self._plant.output(), 4, "simulation_output")
        return MeasurementSample(self._step, self._step * self._contract.sample_period_s,
                                 float(truth[0]), float(truth[2]))

    def read_diagnostic_truth(self) -> np.ndarray:
        """单独注入理想监督/诊断；不能用于控制初始化或创新。"""
        return _finite_vector(self._plant.output(), 4, "diagnostic_truth")

    def read_interval_forces(self) -> tuple[float, float, float, str]:
        """已完成区间的实际外力/合力证据，不是observer输入。"""
        if self._last_forces is None:
            raise ValueError("没有已完成区间")
        return self._last_forces

    def send_control(self, command: ControlCommand) -> ActuationReceipt:
        """原plant原子完成才发完成回执；失败后拒绝重发，不冒充硬件回滚。"""
        if self._ended:
            raise RuntimeError("仿真适配器已失败终止")
        if not isinstance(command, ControlCommand) or (
            command.sample_id != self._step or command.command_id != self._step
        ):
            self._ended = True
            raise ValueError("指令未关联当前样本")
        applied = command.target_force_n
        if abs(applied) > self._contract.max_applied_force_n:
            self._ended = True
            raise ValueError("saturation_outside_contract")
        requested = self._scheduled.get(self._step, 0.)
        actual = requested
        disposition = "accepted"
        if abs(applied + actual) > self._contract.max_applied_force_n:
            actual, disposition = 0., "rejected_total_force_limit"
        try:
            self._plant.step(np.array([applied + actual]))
        except Exception:
            self._ended = True
            raise
        self._last_forces = (requested, actual, applied + actual, disposition)
        self._step += 1
        return ActuationReceipt(command.command_id, command.episode_id, command.sample_id,
                                "simulated_interval_completed", applied, "canonical_simulation")
