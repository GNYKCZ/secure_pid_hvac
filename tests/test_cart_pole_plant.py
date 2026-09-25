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
    STATE_NAMES,
    STATE_UNITS,
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


def test_parameter_and_signal_contract(contract) -> None:
    """固定坐标、SI 单位、源参数和项目采样选择。"""
    assert STATE_NAMES == OUTPUT_NAMES == ("p", "p_dot", "theta", "theta_dot")
    assert STATE_UNITS == OUTPUT_UNITS == ("m", "m/s", "rad", "rad/s")
    assert CONTROL_NAMES == ("applied_force",)
    assert CONTROL_UNITS == ("N",)
    assert (contract.cart_mass_kg, contract.pole_mass_kg, contract.com_length_m) == (.5, .2, .3)
    assert (contract.pole_inertia_kg_m2, contract.cart_friction_n_s_per_m) == (.006, .1)
    assert contract.gravity_m_per_s2 == 9.8
    assert contract.sample_period_s == .02
    assert contract.rk4_substeps == 4
    assert contract.initial_state == (0, 0, 0.08726646259971647, 0)
    assert contract.track_center_limit_m == .5
    assert contract.max_applied_force_n == 10


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


@pytest.mark.parametrize("bad", [
    1., [], [1., 2.], [[1.]], np.ones(4), [True], ["1"], [1j], [np.nan], [np.inf],
    [-np.inf], [11.], [-11.],
])
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


def test_config_rejects_bad_schema_and_values(contract, tmp_path: Path) -> None:
    """配置构造与 YAML 加载同样拒绝非法参数。"""
    for field, value in (
        ("cart_mass_kg", 0), ("pole_mass_kg", -1), ("com_length_m", 0),
        ("pole_inertia_kg_m2", float("inf")), ("gravity_m_per_s2", float("nan")),
        ("sample_period_s", 0), ("track_center_limit_m", -1),
        ("max_applied_force_n", 0), ("cart_friction_n_s_per_m", -.1),
        ("rk4_substeps", 0), ("rk4_substeps", True),
        ("initial_state", (.51, 0, 0, 0)), ("initial_state", (0, 0, 0)),
        ("initial_state", (0, 0, 1j, 0)), ("cart_mass_kg", True),
    ):
        with pytest.raises((TypeError, ValueError)):
            replace(contract, **{field: value})
    source = CONFIG.read_text(encoding="utf-8")
    for altered in (
        source + "unknown: 1\n",
        source.replace("cart_mass_kg: 0.5\n", ""),
        source.replace("schema_version: 1", "schema_version: true"),
        source.replace("scenario: cart_pole", "scenario: other"),
        source.replace("cart_mass_kg: 0.5", "cart_mass_kg: 0.5\ncart_mass_kg: 0.6"),
    ):
        path = tmp_path / "invalid.yaml"
        path.write_text(altered, encoding="utf-8")
        with pytest.raises((TypeError, ValueError)):
            load_cart_pole_contract(path)


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
