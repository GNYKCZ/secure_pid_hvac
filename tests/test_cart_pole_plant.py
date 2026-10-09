"""倒立摆非线性对象的独立数值、信号与失败原子性验证。"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest
from scipy.integrate import solve_ivp

from secure_control.scenarios.cart_pole import (
    CONTROL_NAMES,
    CONTROL_UNITS,
    OUTPUT_NAMES,
    OUTPUT_UNITS,
    CartPolePlant,
    load_cart_pole_contract,
)
from secure_control.simulation import (
    ChannelMetadata,
    Plant,
    ScenarioMetadata,
    SimulationBranch,
    simulate_branch,
)

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "cart_pole_plant.yaml"


@pytest.fixture
def contract():
    """从唯一受版本管理的来源加载参数。"""
    return load_cart_pole_contract(CONFIG)


def _independent_rhs(_time: float, state: np.ndarray, force: float) -> list[float]:
    """独立按 CTMS 隐式双式求解，不调用生产 plant 的 RHS。"""
    _, velocity, theta, omega = state
    cart_mass, pole_mass, length, inertia, friction, gravity = .5, .2, .3, .006, .1, 9.8
    matrix = np.array([
        [cart_mass + pole_mass, -pole_mass * length * np.cos(theta)],
        [-pole_mass * length * np.cos(theta), inertia + pole_mass * length**2],
    ])
    loads = np.array([
        force - friction * velocity - pole_mass * length * omega**2 * np.sin(theta),
        pole_mass * gravity * length * np.sin(theta),
    ])
    acceleration = np.linalg.solve(matrix, loads)
    return [velocity, acceleration[0], omega, acceleration[1]]


def test_upright_equilibrium_and_force_direction(contract) -> None:
    """直立零力严格平衡；正力使小车向右、杆向左偏。"""
    plant = CartPolePlant(replace(contract, initial_state=(0, 0, 0, 0)))
    assert isinstance(plant, Plant)
    for _ in range(5):
        np.testing.assert_array_equal(plant.step(np.array([0.])), np.zeros(4))
    np.testing.assert_allclose(
        plant._rhs(np.zeros(4), 1.)[[1, 3]], [1.8181818181818181, 4.545454545454545],
        rtol=0, atol=2e-15,
    )
    np.testing.assert_allclose(
        plant._rhs(np.zeros(4), -1.)[[1, 3]], [-1.8181818181818181, -4.545454545454545],
        rtol=0, atol=2e-15,
    )
    right = plant.step(np.array([1.]))
    assert right[0] > 0 and right[2] > 0
    plant.reset()
    left = plant.step(np.array([-1.]))
    np.testing.assert_allclose(left, -right, rtol=0, atol=2e-15)
    for angle in (-.05, .05):
        angled = CartPolePlant(replace(contract, initial_state=(0, 0, angle, 0)))
        assert np.sign(angled.step(np.array([0.]))[2] - angle) == np.sign(angle)


def test_independent_dop853_single_and_multi_step_oracle(contract) -> None:
    """独立隐式式与高精度积分先核对冻结常量，再核对生产 RK4。"""
    frozen = np.array([
        [0.0002275645774823446, 0.02275090995623928, 0.08826107296399356, 0.09952729853479188],
        [0.0006382842285331395, 0.01834379910942703, 0.09057672995402018, 0.1322837298207997],
        [0.001052946466058015, 0.02314681739760755, 0.0937893514685246, 0.1892997524700963],
        [0.001837087199604073, 0.05528811767154277, 0.09884079238927035, 0.3163003090028443],
        [0.002812921252387607, 0.04235970461211236, 0.1053375787872952, 0.3340697962145806],
    ])
    independent = np.array(contract.initial_state)
    plant = CartPolePlant(contract)
    for force, expected in zip((.5, -.25, 0, .75, -.5), frozen, strict=True):
        independent = solve_ivp(
            _independent_rhs, (0, contract.sample_period_s), independent,
            args=(force,), method="DOP853", rtol=1e-13, atol=1e-15,
        ).y[:, -1]
        np.testing.assert_allclose(independent, expected, rtol=0, atol=2e-14)
        np.testing.assert_allclose(plant.step(np.array([force])), independent, rtol=0, atol=1e-8)
        np.testing.assert_allclose(plant.state, independent, rtol=0, atol=1e-8)


@pytest.mark.parametrize("bad", [1., [1., 2.], [True], [1j], [np.nan], [11.]])
def test_invalid_force_is_atomic(contract, bad) -> None:
    """错误 shape、类型、有限性及力界均不能推进状态。"""
    plant = CartPolePlant(contract)
    before = plant.state
    with pytest.raises((ValueError, TypeError, FloatingPointError)):
        plant.step(bad)
    np.testing.assert_array_equal(plant.state, before)


def test_track_stage_and_overflow_are_atomic(contract) -> None:
    """阶段越轨和角速度溢出不会提交部分子步。"""
    near_edge = CartPolePlant(replace(contract, initial_state=(.499, 1, 0, 0)))
    before = near_edge.state
    with pytest.raises(ValueError, match="track_center_limit_m"):
        near_edge.step(np.array([0.]))
    np.testing.assert_array_equal(near_edge.state, before)
    overflow = CartPolePlant(replace(contract, initial_state=(0, 0, .1, 1e200)))
    before = overflow.state
    with pytest.raises(FloatingPointError):
        overflow.step(np.array([0.]))
    np.testing.assert_array_equal(overflow.state, before)


def test_snapshot_reset_and_instance_isolation(contract) -> None:
    """输出和状态不泄漏内部缓冲区，reset 不影响其他实例。"""
    first, second = CartPolePlant(contract), CartPolePlant(contract)
    initial = first.output()
    state = first.state
    assert state.shape == (4,) and state.dtype == np.float64 and not state.flags.writeable
    first.output()[2] = 99
    np.testing.assert_array_equal(first.output(), initial)
    first.step(np.array([.5]))
    np.testing.assert_array_equal(second.output(), initial)
    first.reset()
    np.testing.assert_array_equal(first.output(), initial)


class _RecordingAdapter:
    """仅验证通用引擎时序的测试桩，不属于场景交付。"""

    metadata = ScenarioMetadata(
        "cart_pole", ChannelMetadata(("unused_zero",), ("dimensionless",)),
        ChannelMetadata(OUTPUT_NAMES, OUTPUT_UNITS),
        ChannelMetadata(CONTROL_NAMES, CONTROL_UNITS),
    )

    def reference_at(self, time: float) -> np.ndarray:
        """此测试不设计参考信号。"""
        return np.zeros(1)

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """转发当前观测。"""
        return output.copy()

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        """转发实际力，不加入限幅策略。"""
        return raw_control.copy()


class _PulseRuntime:
    """仅测试首步施力和预更新观测顺序。"""

    def __init__(self) -> None:
        self.seen: list[np.ndarray] = []

    def step(self, measurement: np.ndarray) -> np.ndarray:
        """保存收到的观测，首步返回 0.5 N。"""
        self.seen.append(measurement.copy())
        return np.array([.5 if len(self.seen) == 1 else 0.])


def test_generic_engine_records_pre_step_output(contract) -> None:
    """t_k 记录更新前状态，step 的返回是下一时刻状态。"""
    plant = CartPolePlant(contract)
    runtime = _PulseRuntime()
    times = np.arange(3) * contract.sample_period_s
    log = simulate_branch(SimulationBranch(plant, _RecordingAdapter(), runtime), times)
    expected = np.array(contract.initial_state)
    np.testing.assert_array_equal(log.output[0], expected)
    np.testing.assert_allclose(log.output, runtime.seen, rtol=0, atol=0)
    np.testing.assert_array_equal(log.control, [[.5], [0.], [0.]])
    for force, observed in zip((.5, 0.), log.output[1:], strict=True):
        expected = solve_ivp(
            _independent_rhs, (0, contract.sample_period_s), expected,
            args=(force,), method="DOP853", rtol=1e-13, atol=1e-15,
        ).y[:, -1]
        np.testing.assert_allclose(observed, expected, rtol=0, atol=1e-8)
    assert not np.array_equal(plant.output(), log.output[-1])


@pytest.mark.parametrize("theta", [np.pi, 2 * np.pi])
def test_large_angle_periodicity_and_hanging_force_direction(contract, theta):
    """大角度保留原 θ；周期平移不改变速度/非角导数及物理力方向。"""
    state = np.array([.1, -.2, theta, .3])
    plant = CartPolePlant(replace(contract, initial_state=tuple(state)))
    shifted = CartPolePlant(replace(contract, initial_state=tuple(state + [0, 0, 2 * np.pi, 0])))
    np.testing.assert_allclose(plant._rhs(state, 1), _independent_rhs(0, state, 1), rtol=0, atol=2e-14)
    np.testing.assert_allclose(shifted._rhs(shifted.state, 1), plant._rhs(state, 1), rtol=0, atol=2e-14)
    np.testing.assert_allclose(shifted.step(np.array([1.])) - [0, 0, 2 * np.pi, 0],
                               plant.step(np.array([1.])), rtol=0, atol=2e-14)
    if abs(np.cos(theta) + 1) < 1e-14:
        acceleration = plant._rhs(np.array([0., 0., theta, 0.]), 1.)
        np.testing.assert_allclose(acceleration[[1, 3]], [1.8181818181818181, -4.545454545454545], rtol=0, atol=2e-14)


@pytest.mark.parametrize("theta,omega", [(np.pi - .001, 1.), (-np.pi + .001, -1.)])
def test_step_crosses_angle_chart_boundaries_without_wrapping(contract, theta, omega):
    """真实 RK4 步跨±π及2π；角度继续累计，角速度不是 wrapped 角差分。"""
    plant = CartPolePlant(replace(contract, initial_state=(0, 0, theta, omega)))
    actual = plant.step(np.array([0.]))
    expected = solve_ivp(_independent_rhs, (0., .02), [0, 0, theta, omega], args=(0.,),
                         method="DOP853", rtol=1e-13, atol=1e-15).y[:, -1]
    np.testing.assert_allclose(actual, expected, rtol=0, atol=1e-8)
    boundary = np.pi if theta > 0 and theta < np.pi else -np.pi if theta < 0 else 2 * np.pi
    assert (actual[2] - boundary) * omega > 0 and actual[3] * omega > 0


def test_hanging_track_failure_and_interior_stage_crossing_are_atomic(contract):
    """采样末端回到轨道内也不能掩盖 RK4 中间越界；失败保持 step 前值。"""
    for initial, force in [((.499, 1, np.pi, 0), 0.), ((.49998, .05, np.pi, 0), -10.)]:
        plant = CartPolePlant(replace(contract, initial_state=initial))
        before = plant.state
        with pytest.raises(ValueError, match="track_center_limit_m"):
            plant.step(np.array([force]))
        np.testing.assert_array_equal(plant.state, before)
    solved = solve_ivp(_independent_rhs, (0., .02), [.49998, .05, np.pi, 0], args=(-10.,),
                       method="DOP853", rtol=1e-13, atol=1e-15, t_eval=np.linspace(0., .02, 101))
    assert solved.y[0, -1] < .5 and np.max(solved.y[0]) > .5
