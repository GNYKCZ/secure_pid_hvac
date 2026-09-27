"""两测量预测型观测器的唯一配置编译、线性保证域与初始化交接。"""

from __future__ import annotations

import hashlib
import json
import warnings
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from math import floor, pi
from pathlib import Path

import numpy as np
import yaml
from scipy.linalg import solve_discrete_lyapunov
from scipy.signal import place_poles

from secure_control.core import ControllerSpec, check_discrete_schur_stability

from .adapter import MeasurementSample, _checked_sample, _finite_vector
from .contract import CartPoleContract, _number, _UniqueKeyLoader, load_cart_pole_contract
from .controller import CartPoleBalanceConfig, _feedback_design, load_cart_pole_balance_config


def _vector(value: object, size: int, name: str) -> tuple[float, ...]:
    """配置不隐式转换字符串/bool、不广播；合法有限小数保持实数。"""
    if not isinstance(value, (tuple, list)) or len(value) != size:
        raise ValueError(f"{name} 必须是{size}维向量")
    return tuple(_number(item, name) for item in value)


def _frozen(value: object) -> np.ndarray:
    """派生矩阵与范围快照隔离缓冲区，不能作为第二可编辑配置。"""
    result = np.array(value, dtype=np.float64, copy=True)
    if not np.isfinite(result).all():
        raise FloatingPointError("observer 派生数据非有限")
    result.setflags(write=False)
    return result


@dataclass(frozen=True, slots=True)
class CartPoleObserverConfig:
    """仅拥有衰减率、速度种子及误差假设；物理/Q/R/阈值属于原配置。"""

    observer_decay_rates_per_s: tuple[float, ...]
    initial_velocity_estimate: tuple[float, ...]
    initial_error_abs: tuple[float, ...]

    def __post_init__(self) -> None:
        for name, size in (("observer_decay_rates_per_s", 4),
                           ("initial_velocity_estimate", 2), ("initial_error_abs", 4)):
            object.__setattr__(self, name, _vector(getattr(self, name), size, name))
        rates = self.observer_decay_rates_per_s
        if any(rate <= 0 for rate in rates) or len(set(rates)) != 4:
            raise ValueError("observer衰减率必须正且互异")
        if any(value < 0 for value in self.initial_error_abs):
            raise ValueError("initial_error_abs 必须非负")


@dataclass(frozen=True, slots=True)
class ObserverInitialization:
    """明确首测量、固定整圈、种子和前提的新episode记录；不是续段状态。"""

    spec: ControllerSpec
    branch: int
    theta_star: float
    first_sample_id: int
    sample_period_s: float
    velocity_seed: tuple[float, ...]
    initial_error_abs: tuple[float, ...]
    y_abs: tuple[float, float]
    state_abs_bound: np.ndarray
    raw_abs_bound: np.ndarray
    linear_initial_value: float
    linear_domain_c: float


@dataclass(frozen=True, slots=True)
class CartPoleObserverDesign:
    """从三个owner编译的不可变设计；下游直接initialize取得spec，无需手抄矩阵。"""

    plant: CartPoleContract
    balance: CartPoleBalanceConfig
    config: CartPoleObserverConfig
    Ac: np.ndarray
    Bc: np.ndarray
    Ap: np.ndarray
    Bp: np.ndarray
    Cp: np.ndarray
    Dp: np.ndarray
    K: np.ndarray
    L: np.ndarray
    A: np.ndarray
    Phi: np.ndarray
    P: np.ndarray
    domain_c: float
    observer_poles: np.ndarray
    source_snapshots_json: str = "[]"

    def initialize(self, first_measurement: MeasurementSample,
                   velocity_seed: tuple[float, ...] | None = None) -> ObserverInitialization:
        """只从两测量和声明种子创建x0，误差界是前提而非两个测量可证明的事实。"""
        if not isinstance(first_measurement, MeasurementSample):
            raise TypeError("first_measurement 必须是 MeasurementSample")
        _checked_sample(first_measurement, first_measurement.sample_id, self.plant.sample_period_s)
        seed = self.config.initial_velocity_estimate if velocity_seed is None else _vector(
            velocity_seed, 2, "velocity_seed"
        )
        theta = first_measurement.theta_rad
        branch = 0 if -pi <= theta < pi else floor((theta + pi) / (2 * pi))
        theta_star = 2 * pi * branch
        alpha = theta - theta_star
        y_abs = (self.balance.safe_abs[0], self.balance.safe_abs[2])
        if abs(first_measurement.p_m) > y_abs[0] or abs(alpha) > y_abs[1]:
            raise ValueError("measurement_outside_local_domain")
        x0 = _finite_vector([first_measurement.p_m, seed[0], alpha, seed[1]], 4, "x0")
        spec = ControllerSpec(self.A, self.L, -self.K, np.zeros((1, 2)), x0)
        # 精确矩阵幂绝对值界，避免把|A|^k的指数粗界误当有限实际状态。
        power = np.eye(4)
        accumulated = np.zeros(4)
        bounds = []
        with np.errstate(over="raise", invalid="raise"):
            for _ in range(self.balance.horizon_steps + 1):
                bounds.append(np.abs(power) @ np.abs(x0) + accumulated)
                accumulated += np.abs(power @ self.L) @ np.array(y_abs)
                power = power @ self.A
        h = _frozen(bounds)
        raw_bound = _frozen(h @ np.abs(self.K).T)
        s = np.concatenate((x0, x0))
        value = _number(s @ self.P @ s, "linear_initial_value")
        return ObserverInitialization(
            spec, branch, theta_star, first_measurement.sample_id, self.plant.sample_period_s,
            tuple(seed), self.config.initial_error_abs, y_abs, h, raw_bound, value, self.domain_c,
        )

    def to_snapshot(self) -> dict:
        """发布SI矩阵、谱/保证域与源快照；公开明文研究，不能照搬公开秘密估计。"""
        matrices = {name: getattr(self, name).tolist() for name in (
            "Ac", "Bc", "Ap", "Bp", "Cp", "Dp", "K", "L", "A", "Phi", "P"
        )}
        return {
            "contract_version": 1, "plant": asdict(self.plant), "balance": asdict(self.balance),
            "observer": asdict(self.config), "matrices": matrices,
            "spectral_radius": {name: float(max(abs(np.linalg.eigvals(matrix)))) for name, matrix in (
                ("controller", self.A), ("augmented", self.Phi),
                ("feedback", self.Ap - self.Bp @ self.K), ("observer", self.Ap - self.L @ self.Cp)
            )},
            "observer_poles": self.observer_poles.tolist(), "linear_domain_c": self.domain_c,
            "controllability_rank": int(np.linalg.matrix_rank(np.column_stack([
                np.linalg.matrix_power(self.Ap, j) @ self.Bp for j in range(4)
            ]))),
            "observability_rank": int(np.linalg.matrix_rank(np.vstack([
                self.Cp @ np.linalg.matrix_power(self.Ap, j) for j in range(4)
            ]))),
            "linear_domain_scope": "ideal_unforced_linear_system_only",
            "pole_placement": {"method": "YT", "rtol": 1e-10, "maxiter": 200},
            "hold_span_s": (self.balance.hold_observations - 1) * self.plant.sample_period_s,
            "horizon_time_s": self.balance.horizon_steps * self.plant.sample_period_s,
            "source_snapshots": json.loads(self.source_snapshots_json),
        }


def build_cart_pole_observer_design(plant: CartPoleContract, balance: CartPoleBalanceConfig,
                                   config: CartPoleObserverConfig) -> CartPoleObserverDesign:
    """复用canonical反馈推导；对偶极点、分离谱和Lyapunov域均检查后交付。"""
    if not isinstance(config, CartPoleObserverConfig):
        raise TypeError("config 必须是 CartPoleObserverConfig")
    ac, bc, ap, bp, gain = _feedback_design(plant, balance)
    if balance.safe_abs[2] >= pi:
        raise ValueError("observer局部直立chart的safe角域必须小于pi")
    if not np.isfinite(plant.sample_period_s * balance.horizon_steps):
        raise ValueError("horizon 时间必须有限")
    cp = np.array([[1., 0, 0, 0], [0, 0, 1., 0]])
    observability = np.vstack([cp @ np.linalg.matrix_power(ap, i) for i in range(4)])
    if np.linalg.matrix_rank(observability) != 4:
        raise ValueError("离散模型不可观")
    with np.errstate(over="raise", invalid="raise", under="ignore"):
        poles = np.exp(-np.array(config.observer_decay_rates_per_s) * plant.sample_period_s)
    if np.any(poles <= 0) or np.any(poles >= 1) or np.min(np.diff(np.sort(poles))) <= 1e-10:
        raise ValueError("observer转换后极点无效或数值重合")
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        placed = place_poles(ap.T, cp.T, poles, method="YT", rtol=1e-10, maxiter=200)
    if not np.isfinite(placed.rtol) or placed.rtol > 1e-10:
        raise ValueError("observer极点配置未收敛")
    observer_gain = placed.gain_matrix.T
    error_a = ap - observer_gain @ cp
    actual = np.linalg.eigvals(error_a)
    if np.max(np.abs(np.imag(actual))) > 1e-9 or not np.allclose(
        np.sort(actual.real), np.sort(poles), rtol=0, atol=1e-9
    ):
        raise ValueError("observer实际极点不符")
    controller_a = ap - bp @ gain - observer_gain @ cp
    phi = np.block([[ap, -bp @ gain], [observer_gain @ cp, controller_a]])
    for matrix in (error_a, phi, controller_a):
        if check_discrete_schur_stability(matrix).status != "stable":
            raise ValueError("observer/增广/controller矩阵未被数值确认为Schur稳定")
    expected = np.concatenate((np.linalg.eigvals(ap - bp @ gain), actual))
    if not np.allclose(np.sort_complex(np.linalg.eigvals(phi)), np.sort_complex(expected),
                       rtol=0, atol=1e-8):
        raise ValueError("增广闭环不满足分离谱")
    w = np.diag(1 / np.tile(np.array(balance.safe_abs), 2)**2)
    p = solve_discrete_lyapunov(phi.T, w)
    residual = phi.T @ p @ phi - p + w
    if not np.isfinite(p).all() or np.linalg.eigvalsh((p + p.T) / 2).min() <= 0 or (
        np.linalg.norm(p - p.T) > 1e-9 * np.linalg.norm(p)
        or np.linalg.norm(residual) > 1e-9 * np.linalg.norm(p)
    ):
        raise ValueError("Lyapunov正定性/残差无效")
    rows = np.vstack((np.eye(8)[:4], np.concatenate((np.zeros(4), -gain[0]))))
    limits = np.array([*balance.safe_abs, plant.max_applied_force_n])
    projections = np.sum(rows * np.linalg.solve(p, rows.T).T, axis=1)
    if np.any(projections <= 0):
        raise ValueError("保证域投影无效")
    c = _number(np.min(limits**2 / projections), "domain_c", positive=True)
    return CartPoleObserverDesign(
        plant, balance, config, *(_frozen(value) for value in (
            ac, bc, ap, bp, cp, np.zeros((2, 1)), gain, observer_gain, controller_a, phi, p
        )), c, _frozen(poles),
    )


def load_cart_pole_observer_design(path: str | Path) -> CartPoleObserverDesign:
    """三源统一加载/派生并冻结字节摘要；源文件运行期间变化不得冒充本次来源。"""
    from dataclasses import replace

    source = Path(path)
    blob = source.read_bytes()
    root = yaml.load(blob, Loader=_UniqueKeyLoader)
    expected = {"schema_version", "scenario", "plant_source", "balance_source",
                *CartPoleObserverConfig.__dataclass_fields__}
    if not isinstance(root, Mapping) or set(root) != expected:
        raise ValueError(f"observer配置必须且仅包含{sorted(expected)}")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version 必须是1")
    if root["scenario"] != "cart_pole":
        raise ValueError("scenario 必须是cart_pole")
    for name in ("plant_source", "balance_source"):
        if not isinstance(root[name], str) or not root[name].strip():
            raise ValueError(f"{name} 必须是非空路径")
    sources = {"observer": source, "plant": source.parent / root["plant_source"],
               "balance": source.parent / root["balance_source"]}
    blobs = {name: target.read_bytes() for name, target in sources.items()}
    if blobs["observer"] != blob:
        raise ValueError("observer源在加载期间改变")
    plant = load_cart_pole_contract(sources["plant"])
    balance = load_cart_pole_balance_config(sources["balance"], plant)
    config = CartPoleObserverConfig(**{
        name: root[name] for name in CartPoleObserverConfig.__dataclass_fields__
    })
    design = build_cart_pole_observer_design(plant, balance, config)
    if any(target.read_bytes() != blobs[name] for name, target in sources.items()):
        raise ValueError("来源在设计加载期间改变")
    snapshots = [{"role": name, "filename": sources[name].name,
                  "sha256": hashlib.sha256(data).hexdigest(),
                  "yaml": yaml.load(data, Loader=_UniqueKeyLoader)} for name, data in blobs.items()]
    return replace(design, source_snapshots_json=json.dumps(snapshots, allow_nan=False))
