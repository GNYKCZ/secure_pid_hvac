"""倒立摆离散 LQR、场景限幅/判定及独立非线性闭环基线。"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest
from scipy.integrate import solve_ivp
from scipy.linalg import expm, solve_discrete_are

from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.scenarios.cart_pole import (
    CONTROL_NAMES,
    CONTROL_UNITS,
    OUTPUT_NAMES,
    OUTPUT_UNITS,
    BalanceMonitor,
    CartPoleAdapter,
    CartPolePlant,
    build_cart_pole_controller_spec,
    load_cart_pole_balance_config,
    load_cart_pole_contract,
    run_balance_experiment,
)
from secure_control.scenarios.cart_pole.controller import _linearized_model
from secure_control.simulation import ScenarioAdapter, SimulationBranch, simulate_branch

ROOT = Path(__file__).resolve().parents[1]
PLANT_CONFIG = ROOT / "configs" / "cart_pole_plant.yaml"
BALANCE_CONFIG = ROOT / "configs" / "cart_pole_balance.yaml"
# 由 #90 CTMS 隐式方程、20 ms ZOH 与 Q/R 离线核算；oracle 不调用生产增益 builder。
ORACLE_K = np.array([
    -2.686135642062081, -3.4220210753211164,
    25.671292765180784, 4.663385720565947,
])
FIVE_DEG = 0.08726646259971647


@pytest.fixture
def setup():
    """读取两份独立的场景配置，不复制 #90 物理界。"""
    plant = load_cart_pole_contract(PLANT_CONFIG)
    return plant, load_cart_pole_balance_config(BALANCE_CONFIG, plant)


def _oracle_rhs(_time: float, state: np.ndarray, force: float) -> list[float]:
    """另写 CTMS 非线性隐式双式并求解，不调用生产 RHS 或 RK4。"""
    _, velocity, theta, omega = state
    m_cart, m_pole, length, inertia, friction, gravity = .5, .2, .3, .006, .1, 9.8
    matrix = np.array([
        [m_cart + m_pole, -m_pole * length * np.cos(theta)],
        [-m_pole * length * np.cos(theta), inertia + m_pole * length**2],
    ])
    loads = np.array([
        force - friction * velocity - m_pole * length * omega**2 * np.sin(theta),
        m_pole * gravity * length * np.sin(theta),
    ])
    p_ddot, theta_ddot = np.linalg.solve(matrix, loads)
    return [velocity, p_ddot, omega, theta_ddot]


def _independent_run(initial: tuple[float, ...], steps: int = 400):
    """固定 K、独立 DOP853 和独立阈值计数产生 N+1/N oracle。"""
    state = np.array(initial, dtype=float)
    states = [state.copy()]
    raw_forces: list[float] = []
    applied_forces: list[float] = []
    statuses: list[str] = []
    counts: list[int] = []
    count = 0
    safe = np.array([.45, .6, .20, 1.0])
    stable = np.array([.02, .03, .02, .05])
    for index in range(steps + 1):
        assert np.isfinite(state).all() and np.all(np.abs(state) <= safe)
        count = count + 1 if np.all(np.abs(state) <= stable) else 0
        statuses.append("stable" if count >= 51 else "recovering")
        counts.append(count)
        if index == steps:
            break
        raw = float(-ORACLE_K @ state)
        applied = float(np.clip(raw, -10., 10.))
        raw_forces.append(raw)
        applied_forces.append(applied)
        solved = solve_ivp(
            _oracle_rhs, (0., .02), state, args=(applied,),
            method="DOP853", rtol=1e-13, atol=1e-15,
        )
        assert solved.success
        state = solved.y[:, -1]
        states.append(state.copy())
    return np.array(states), np.array(raw_forces), np.array(applied_forces), statuses, counts


def test_strict_balance_configuration(setup, tmp_path: Path) -> None:
    """Q/R、零目标、工作域/稳定阈值、时长与物理轨道界共同校验。"""
    plant, config = setup
    assert config.q_state_weights == (10, 1, 100, 1)
    assert config.r_force_weight == 1
    assert config.target_state == (0, 0, 0, 0)
    assert config.safe_abs == (.45, .6, .20, 1.0)
    assert config.stable_abs == (.02, .03, .02, .05)
    assert (config.hold_observations, config.horizon_steps) == (51, 400)
    for name, value in (
        ("q_state_weights", (10, 1, 0, 1)),
        ("q_state_weights", (10, 1, 100)),
        ("q_state_weights", (10, 1, 100, True)),
        ("r_force_weight", np.inf),
        ("r_force_weight", -1),
        ("target_state", (0, 0, 1, 0)),
        ("safe_abs", (.45, .6, np.nan, 1)),
        ("stable_abs", (.45, .03, .02, .05)),
        ("horizon_steps", 0),
        ("hold_observations", True),
    ):
        with pytest.raises((ValueError, TypeError)):
            replace(config, **{name: value})
    outside_track = replace(config, safe_abs=(.5, .6, .2, 1.))
    with pytest.raises(ValueError, match="track_center_limit_m"):
        outside_track.validate_plant(plant)
    with pytest.raises(ValueError, match="track_center_limit_m"):
        build_cart_pole_controller_spec(plant, outside_track)
    source = BALANCE_CONFIG.read_text(encoding="utf-8")
    for altered in (
        source + "unknown: 1\n",
        source.replace("horizon_steps: 400\n", ""),
        source.replace("scenario: cart_pole", "scenario: other"),
        source.replace("schema_version: 1", "schema_version: true"),
        source.replace("r_force_weight: 1", "r_force_weight: 1\nr_force_weight: 2"),
    ):
        bad = tmp_path / "invalid.yaml"
        bad.write_text(altered, encoding="utf-8")
        with pytest.raises((ValueError, TypeError)):
            load_cart_pole_balance_config(bad, plant)


def test_linearized_zoh_dare_and_static_spec(setup) -> None:
    """解析 Jacobian、独立增广指数、DARE、冻结 K 和局部谱半径逐项核对。"""
    plant, config = setup
    a_c, b_c = _linearized_model(plant)
    np.testing.assert_allclose(a_c, [
        [0, 1, 0, 0], [0, -0.18181818181818182, 2.6727272727272737, 0],
        [0, 0, 0, 1], [0, -0.45454545454545464, 31.18181818181818, 0],
    ], rtol=0, atol=2e-14)
    np.testing.assert_allclose(b_c[:, 0], [0, 1.8181818181818181, 0, 4.545454545454545],
                               rtol=0, atol=2e-14)
    # 有限差分只核对原点 Jacobian；测试的连续 RHS 是独立隐式矩阵求解。
    zero = np.zeros(4)
    eps = 1e-6
    finite_a = np.column_stack([
        (np.array(_oracle_rhs(0, zero + np.eye(4)[i] * eps, 0))
         - np.array(_oracle_rhs(0, zero - np.eye(4)[i] * eps, 0))) / (2 * eps)
        for i in range(4)
    ])
    finite_b = (
        np.array(_oracle_rhs(0, zero, eps)) - np.array(_oracle_rhs(0, zero, -eps))
    ) / (2 * eps)
    np.testing.assert_allclose(a_c, finite_a, rtol=0, atol=1e-9)
    np.testing.assert_allclose(b_c[:, 0], finite_b, rtol=0, atol=1e-9)
    augmented = np.zeros((5, 5))
    augmented[:4, :4], augmented[:4, 4:] = a_c, b_c
    zoh = expm(augmented * .02)
    a_d, b_d = zoh[:4, :4], zoh[:4, 4:]
    np.testing.assert_allclose(b_d[:, 0], [
        .00036327690037460175, .03631377974760129,
        .000908934444103713, .09093289188930598,
    ], rtol=0, atol=2e-14)
    assert np.linalg.matrix_rank(np.column_stack([
        np.linalg.matrix_power(a_d, i) @ b_d for i in range(4)
    ])) == 4
    q, r = np.diag([10., 1., 100., 1.]), np.array([[1.]])
    p = solve_discrete_are(a_d, b_d, q, r)
    independent_k = np.linalg.solve(r + b_d.T @ p @ b_d, b_d.T @ p @ a_d)
    residual = a_d.T @ p @ a_d - p - a_d.T @ p @ b_d @ independent_k + q
    assert np.linalg.norm(residual) < 1e-9 * np.linalg.norm(p)
    np.testing.assert_allclose(independent_k[0], ORACLE_K, rtol=0, atol=2e-11)
    radius = max(abs(np.linalg.eigvals(a_d - b_d @ independent_k)))
    assert radius == pytest.approx(.975793840705157, abs=2e-12)
    spec = build_cart_pole_controller_spec(plant, config)
    assert (spec.A.shape, spec.B.shape, spec.C.shape, spec.D.shape, spec.x0.shape) == (
        (0, 0), (0, 4), (1, 0), (1, 4), (0,),
    )
    assert spec.scale_metadata is None and spec.D.dtype == np.float64
    np.testing.assert_allclose(spec.D[0], -ORACLE_K, rtol=0, atol=2e-11)
    runtime = PlaintextStateSpaceRuntime(spec)
    assert runtime.state.shape == (0,)
    np.testing.assert_allclose(runtime.step(np.array([0, 0, FIVE_DEG, 0])),
                               [-2.240242909979021], rtol=0, atol=2e-11)


def test_adapter_signal_and_saturation_boundary(setup) -> None:
    """四维目标/测量到 v 的符号及一维 raw→applied 力只在场景限幅。"""
    plant_contract, config = setup
    adapter = CartPoleAdapter(plant_contract, config)
    assert isinstance(adapter, ScenarioAdapter)
    assert adapter.metadata.reference.names == OUTPUT_NAMES
    assert adapter.metadata.output.units == OUTPUT_UNITS
    assert adapter.metadata.control.names == CONTROL_NAMES
    assert adapter.metadata.control.units == CONTROL_UNITS
    reference = adapter.reference_at(0.)
    np.testing.assert_array_equal(reference, np.zeros(4))
    reference[0] = 99
    np.testing.assert_array_equal(adapter.reference_at(.02), np.zeros(4))
    input_state = np.array([0., 0., FIVE_DEG, 0.])
    np.testing.assert_array_equal(adapter.controller_input(np.zeros(4), input_state), input_state)
    np.testing.assert_array_equal(
        adapter.controller_input(np.array([.1, 0, 0, 0]), np.array([.2, 0, 0, 0])),
        [.1, 0, 0, 0],
    )
    runtime = PlaintextStateSpaceRuntime(build_cart_pole_controller_spec(plant_contract, config))
    raw = runtime.step(adapter.controller_input(np.zeros(4), input_state))
    assert raw.shape == (1,) and raw[0] < 0
    np.testing.assert_array_equal(adapter.apply_control(raw), raw)
    large = np.array([-.4, -.5, .18, .8])
    raw_large = runtime.step(large)
    assert raw_large[0] < -10
    np.testing.assert_array_equal(adapter.apply_control(raw_large), [-10.])
    np.testing.assert_array_equal(adapter.apply_control(-raw_large), [10.])
    physical = CartPolePlant(plant_contract)
    before = physical.state
    with pytest.raises(ValueError, match="max_applied_force_n"):
        physical.step(raw_large)
    np.testing.assert_array_equal(physical.state, before)
    for bad in (0., [0.], [np.nan] * 4, [True] * 4, [1j] * 4):
        with pytest.raises((TypeError, ValueError, FloatingPointError)):
            adapter.controller_input(bad, np.zeros(4))
        with pytest.raises((TypeError, ValueError, FloatingPointError)):
            adapter.controller_input(np.zeros(4), bad)
    for bad in (0., [1, 2], [np.nan], [np.inf], [1j], [True]):
        with pytest.raises((TypeError, ValueError, FloatingPointError)):
            adapter.apply_control(bad)
    for bad in (True, np.nan, "0"):
        with pytest.raises((TypeError, ValueError, FloatingPointError)):
            adapter.reference_at(bad)


@pytest.mark.parametrize("initial", [
    (0., 0., 0., 0.),
    (0., 0., FIVE_DEG, 0.),
    (0., 0., -FIVE_DEG, 0.),
    (.1, 0., 0., 0.),
    (-.1, 0., 0., 0.),
    (.08, 0., -.05, 0.),
])
def test_declared_initial_states_match_independent_400_step_oracle(setup, initial) -> None:
    """六组预声明局部初态的全轨迹、力分账和尾端计数与 DOP853 一致。"""
    plant, config = setup
    result = run_balance_experiment(plant, config, initial_state=initial)
    expected_x, expected_raw, expected_applied, expected_status, expected_counts = (
        _independent_run(initial)
    )
    assert result.status == "stable" and result.failure_step is None
    assert result.completed_steps == 400
    assert result.time_s.shape == (401,)
    assert result.state.shape == result.output.shape == result.reference.shape == (401, 4)
    assert result.raw_force.shape == result.applied_force.shape == (400, 1)
    np.testing.assert_allclose(result.time_s, np.arange(401) * .02, rtol=0, atol=1e-14)
    np.testing.assert_array_equal(result.state, result.output)
    np.testing.assert_array_equal(result.reference, np.zeros((401, 4)))
    np.testing.assert_allclose(result.state, expected_x, rtol=0, atol=3e-8)
    np.testing.assert_allclose(result.raw_force[:, 0], expected_raw, rtol=0, atol=3e-8)
    np.testing.assert_allclose(result.applied_force[:, 0], expected_applied, rtol=0, atol=3e-8)
    assert result.observed_status == tuple(expected_status)
    assert result.stable_count == tuple(expected_counts)
    assert result.observed_status[-1] == "stable" and result.stable_count[-1] >= 51
    assert not result.state.flags.writeable
    assert not result.raw_force.flags.writeable


def test_five_degree_frozen_key_samples_and_hold_time(setup) -> None:
    """k=0/1/5/50/100/400 数值和首次持续稳定时刻来自独立求解常量。"""
    plant, config = setup
    result = run_balance_experiment(plant, config)
    expected = {
        0: [0., 0., FIVE_DEG, 0.],
        1: [-.0007658530747043172, -.07655355407376617,
            .08578493246437614, -.1481985489421732],
        5: [-.01456815855558679, -.2385699376882175,
            .06100703855928773, -.4050102011008122],
        50: [-.09336566769954814, .05340150629835261,
             -.01319630597863577, .04052572767619486],
        100: [-.02958623260100315, .0500485476414881,
              .004279295314846884, .002127516647333391],
        400: [-2.058238915441783e-05, 2.905180910186913e-05,
              1.491577421041131e-06, 3.441554654647237e-06],
    }
    for index, frozen in expected.items():
        np.testing.assert_allclose(result.state[index], frozen, rtol=0, atol=3e-8)
    assert result.raw_force[0, 0] == pytest.approx(-2.240242909979021, abs=2e-11)
    assert next(i for i, state in enumerate(result.observed_status) if state == "stable") == 172
    zero = run_balance_experiment(plant, config, initial_state=(0, 0, 0, 0))
    assert zero.observed_status[0] == "recovering"
    assert zero.observed_status[49] == "recovering"
    assert zero.observed_status[50] == "stable"
    assert zero.time_s[50] == pytest.approx(1.0)


def test_gate_failure_saturation_and_time_limit(setup) -> None:
    """越域先于控制；饱和分账、次步失稳和时限未达不伪装为成功。"""
    plant, config = setup
    outside = run_balance_experiment(plant, config, initial_state=(0, 0, .25, 0))
    assert (outside.status, outside.failure_step, outside.failure_reason) == (
        "failed", 0, "outside_safe_domain",
    )
    assert outside.completed_steps == 0 and outside.time_s.shape == (1,)
    near_track = run_balance_experiment(plant, config, initial_state=(.44, .6, -.2, -1.))
    assert (near_track.status, near_track.failure_step, near_track.failure_reason) == (
        "failed", 1, "outside_safe_domain",
    )
    assert near_track.completed_steps == 1
    assert near_track.raw_force[0, 0] > 10 and near_track.applied_force[0, 0] == 10
    assert near_track.state[1, 0] > .45
    timeout = run_balance_experiment(plant, replace(config, horizon_steps=10))
    assert timeout.status == "time_limit" and timeout.failure_step is None
    assert (timeout.time_s.shape, timeout.raw_force.shape) == ((11,), (10, 1))
    for bad in ((.51, 0, 0, 0), (0, 0, np.nan, 0), (0, 0, 0)):
        with pytest.raises((ValueError, TypeError)):
            run_balance_experiment(plant, config, initial_state=bad)  # type: ignore[arg-type]


def test_monitor_recovery_and_nonfinite_observation(setup, monkeypatch) -> None:
    """离开稳定阈值重置计数，非有限观测在 runtime 前失败。"""
    plant, config = setup
    monitor = BalanceMonitor(config)
    for _ in range(51):
        monitor.observe(np.zeros(4))
    assert monitor.status == "stable" and monitor.stable_count == 51
    assert monitor.observe([.03, 0, 0, 0]) == "recovering"
    assert monitor.stable_count == 0
    assert monitor.observe([np.nan, 0, 0, 0]) == "failed"
    assert monitor.failure_reason == "nonfinite_observation"
    monkeypatch.setattr(CartPolePlant, "output", lambda self: np.array([0., np.nan, 0., 0.]))
    failed = run_balance_experiment(plant, config)
    assert (failed.status, failed.failure_step, failed.failure_reason) == (
        "failed", 0, "nonfinite_observation",
    )
    assert failed.completed_steps == 0


def test_plant_fault_keeps_last_committed_prefix(setup, monkeypatch) -> None:
    """plant 更新失败仅保留 t0 观测，不把尝试的力提交为成功步。"""
    plant, config = setup

    def fail_step(self, control):
        raise ValueError("injected plant fault")

    monkeypatch.setattr(CartPolePlant, "step", fail_step)
    failed = run_balance_experiment(plant, config)
    assert (failed.status, failed.failure_step, failed.failure_reason) == (
        "failed", 0, "control_or_plant_step",
    )
    assert failed.time_s.shape == (1,) and failed.completed_steps == 0
    assert failed.raw_force.shape == failed.applied_force.shape == (0, 1)


def test_short_trajectory_matches_generic_engine_timing(setup) -> None:
    """专用记录循环与通用引擎在同一 pre-output→raw→applied→plant 时序对齐。"""
    plant, config = setup
    short = replace(config, horizon_steps=4)
    result = run_balance_experiment(plant, short)
    branch = SimulationBranch(
        CartPolePlant(plant), CartPoleAdapter(plant, short),
        PlaintextStateSpaceRuntime(build_cart_pole_controller_spec(plant, short)),
    )
    generic = simulate_branch(branch, np.arange(4) * plant.sample_period_s)
    np.testing.assert_allclose(generic.output, result.output[:4], rtol=0, atol=0)
    np.testing.assert_allclose(generic.reference, result.reference[:4], rtol=0, atol=0)
    np.testing.assert_allclose(generic.control, result.applied_force, rtol=0, atol=0)
    np.testing.assert_allclose(branch.plant.output(), result.state[4], rtol=0, atol=0)
