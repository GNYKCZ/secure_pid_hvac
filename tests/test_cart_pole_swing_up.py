"""#102：独立大角度数学/闭环 oracle、监督器边界及真实失败前缀。"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest
import yaml
from scipy.integrate import solve_ivp
from test_cart_pole_balance import ORACLE_K

from secure_control.scenarios.cart_pole.contract import load_cart_pole_contract
from secure_control.scenarios.cart_pole.controller import load_cart_pole_balance_config
from secure_control.scenarios.cart_pole.swing_up import (
    SwingUpSupervisor,
    energy_shaping_force,
    load_cart_pole_swing_up_config,
    pole_energy,
    upright_coordinates,
)
from secure_control.scenarios.cart_pole.swing_up_experiment import (
    run_swing_up_experiment,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/cart_pole_swing_up.yaml"


@pytest.fixture
def setup():
    """唯一来源的物理/平衡/起摆输入，每个实验重新装配可变对象。"""
    plant = load_cart_pole_contract(ROOT / "configs/cart_pole_plant.yaml")
    balance = load_cart_pole_balance_config(ROOT / "configs/cart_pole_balance.yaml", plant)
    return plant, balance, load_cart_pole_swing_up_config(CONFIG, plant, balance)


@pytest.mark.parametrize("name,value", [
    ("kick_direction", True),
    ("kick_direction", 1.),
    ("kick_direction", 0),
    ("kick_steps", True),
    ("kick_steps", 0),
    ("energy_gain_m_per_j_s", float("inf")),
    ("initial_state", [0, 0, np.pi]),
    ("disturbances", [(True, 1)]),
    ("disturbances", [(600, 2)]),
    ("disturbances", [(600, 1), (600, -1)]),
    ("disturbances", [(600, 1), (500, -1)]),
    ("disturbances", [(1500, 1)]),
    ("disturbances", [(600,)]),
])
def test_config_rejects_invalid_types_shapes_and_events(setup, name, value):
    """直接构造/replace 与 YAML 一样守住类型、shape、有限性和事件顺序。"""
    with pytest.raises((ValueError, TypeError)):
        replace(setup[2], **{name: value})


@pytest.mark.parametrize("changes", [
    {"initial_state": [.501, 0, np.pi, 0]}, {"initial_state": [0, 3.001, np.pi, 0]},
    {"initial_state": [0, 0, np.pi, 15.001]}, {"kick_force_n": 10.1},
    {"capture_enter_abs": [.4, .5, .15, .8]}, {"capture_exit_abs": [.45, .55, .18, .9]},
    {"acquisition_deadline_steps": 10}, {"horizon_steps": 599},
    {"capture_timeout_steps": 1},
])
def test_config_cross_validates_physical_capture_and_time_limits(setup, changes):
    """新配置不成为轨道/力/原 safe 的第二来源。"""
    with pytest.raises(ValueError):
        config = replace(setup[2], **changes)
        config.validate(setup[0], setup[1])


def test_yaml_exact_schema_sources_and_duplicate_keys(setup, tmp_path):
    """未知/遗漏/重复字段及引用不一致不能进入起摆运行。"""
    root = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    root["plant_source"] = str(ROOT / "configs/cart_pole_plant.yaml")
    root["balance_source"] = str(ROOT / "configs/cart_pole_balance.yaml")
    source = yaml.safe_dump(root)
    alterations = [source + "unknown: 1\n", source + "kick_direction: -1\n",
                   source.replace("schema_version: 1", "schema_version: true"),
                   source.replace("scenario: cart_pole", "scenario: other")]
    for changes in ({"disturbances": [{"step": 2, "force_n": 1, "other": 0}]},
                    {"plant_source": True}, {"disturbances": None}):
        alterations.append(yaml.safe_dump({**root, **changes}))
    missing = dict(root)
    missing.pop("kick_steps")
    alterations.append(yaml.safe_dump(missing))
    for altered in alterations:
        path = tmp_path / "bad.yaml"
        path.write_text(altered, encoding="utf-8")
        with pytest.raises((TypeError, ValueError)):
            load_cart_pole_swing_up_config(path, setup[0], setup[1])
    with pytest.raises(ValueError, match="来源"):
        load_cart_pole_swing_up_config(CONFIG, replace(setup[0], cart_mass_kg=.6), setup[1])


@pytest.mark.parametrize("theta", [-3 * np.pi, -np.pi, -.15, .18, np.pi, 2 * np.pi])
def test_local_chart_preserves_continuous_angle_and_angular_velocity(theta):
    """只改变局部角；小角边界不引入额外舍入，+π统一为−π。"""
    original = np.array([.1, .2, theta, -.3])
    local = upright_coordinates(original)
    assert -np.pi <= local[2] < np.pi and not local.flags.writeable
    np.testing.assert_array_equal(local[[0, 1, 3]], original[[0, 1, 3]])
    assert original[2] == theta
    if -np.pi <= theta < np.pi:
        assert local[2] == theta
    else:
        assert local[2] == pytest.approx((theta + np.pi) % (2 * np.pi) - np.pi, abs=1e-14)


@pytest.mark.parametrize("bad", [[0, True, 0, 0], [0, 0, 0], [0, 0, np.nan, 0], [0, 0, 1j, 0]])
def test_observation_and_math_helpers_reject_invalid_signals(setup, bad):
    """不能在观测到 raw 力的数据流中静默转换 bool、复数或非有限量。"""
    for function in (lambda: upright_coordinates(bad), lambda: pole_energy(setup[0], bad),
                     lambda: energy_shaping_force(setup[0], setup[2], bad)):
        with pytest.raises((ValueError, TypeError, FloatingPointError)):
            function()


def _accelerations(plant, state, force):
    """独立隐式质量矩阵求解，保留可变化的非零杆惯量和摩擦。"""
    _, velocity, theta, omega = state
    h = plant.pole_mass_kg * plant.com_length_m
    j = plant.pole_inertia_kg_m2 + plant.pole_mass_kg * plant.com_length_m**2
    matrix = [[plant.cart_mass_kg + plant.pole_mass_kg, -h * np.cos(theta)],
              [-h * np.cos(theta), j]]
    loads = [force - plant.cart_friction_n_s_per_m * velocity - h * omega**2 * np.sin(theta),
             h * plant.gravity_m_per_s2 * np.sin(theta)]
    return np.linalg.solve(matrix, loads)


@pytest.mark.parametrize("theta,modified", [
    (0., False), (np.pi, False), (np.pi / 2, False),
    (-np.pi / 2, False), (.9, False), (.9, True),
])
def test_energy_derivative_and_force_mapping_against_implicit_equations(setup, theta, modified):
    """独立解加速度核对能量导数与期望加速度，水平摆位无奇点。"""
    plant, _, config = setup
    if modified:
        plant = replace(plant, pole_inertia_kg_m2=.02, cart_friction_n_s_per_m=.3)
    state = np.array([.1, -.2, theta, 1.3])
    h, j = plant.pole_mass_kg * plant.com_length_m, plant.pole_inertia_kg_m2 + plant.pole_mass_kg * plant.com_length_m**2
    independent_energy = .5 * j * state[3]**2 + h * plant.gravity_m_per_s2 * np.cos(theta)
    assert pole_energy(plant, state) == pytest.approx(independent_energy, abs=1e-14)
    desired = (-8 * (independent_energy - h * plant.gravity_m_per_s2) * state[3] * np.cos(theta)
               - 16 * state[0] - 8 * state[1])
    force = energy_shaping_force(plant, config, state)
    assert np.isfinite(force)
    assert _accelerations(plant, state, force)[0] == pytest.approx(desired, abs=2e-14)
    for applied in (-1., 0., 1.):
        cart_a, pole_a = _accelerations(plant, state, applied)
        derivative = j * state[3] * pole_a - h * plant.gravity_m_per_s2 * np.sin(theta) * state[3]
        assert derivative == pytest.approx(h * np.cos(theta) * state[3] * cart_a, abs=1e-14)
    assert pole_energy(plant, [0, 0, np.pi, 0]) == pytest.approx(-h * plant.gravity_m_per_s2)


def _supervisor(setup, **changes):
    supervisor = SwingUpSupervisor(setup[0], setup[1], replace(setup[2], kick_steps=1, **changes))
    supervisor.observe(0, [0, 0, np.pi, 0])
    return supervisor


@pytest.mark.parametrize("component", range(4))
def test_capture_enter_and_exit_exact_boundaries(setup, component):
    """逐维等号在盒内；相邻浮点在盒外，不添加 guard epsilon。"""
    supervisor = _supervisor(setup)
    state = np.zeros(4)
    state[component] = setup[2].capture_enter_abs[component]
    assert supervisor.observe(1, state).phase == "capture"
    state[component] = setup[2].capture_exit_abs[component]
    assert supervisor.observe(2, state).phase == "capture"
    state[component] = np.nextafter(state[component], np.inf)
    assert supervisor.observe(3, state).phase == "swing_up"
    assert supervisor.transitions[-1].trigger == "capture_aborted"
    other = _supervisor(setup)
    state[component] = np.nextafter(setup[2].capture_enter_abs[component], np.inf)
    assert other.observe(1, state).phase == "swing_up"


@pytest.mark.parametrize("omega,captured", [(-.1, True), (0., True), (.1, False)])
def test_capture_direction_is_used_only_at_entry(setup, omega, captured):
    supervisor = _supervisor(setup)
    assert (supervisor.observe(1, [0, 0, .1, omega]).phase == "capture") == captured
    if captured:
        assert supervisor.observe(2, [0, 0, .1, .1]).phase == "capture"
        assert supervisor.observe(3, [0, 0, .1, .1]).phase == "balance"


def test_hold_reset_cooldown_and_new_monitor_on_capture_retry(setup):
    """内盒计数被中间观测清零，外盒中止至少推进5区间后才可重入。"""
    supervisor = _supervisor(setup)
    assert supervisor.observe(1, [0, 0, 0, 0]).capture_count == 1
    assert supervisor.observe(2, [.36, 0, 0, 0]).capture_count == 0
    assert supervisor.observe(3, [0, 0, 0, 0]).capture_count == 1
    old_monitor = supervisor.monitor
    assert supervisor.observe(4, [.401, 0, 0, 0]).phase == "swing_up"
    for step in range(5, 9):
        assert supervisor.observe(step, [0, 0, 0, 0]).phase == "swing_up"
    observation = supervisor.observe(9, [0, 0, 0, 0])
    assert (observation.phase, observation.capture_attempt, observation.capture_count) == ("capture", 2, 1)
    assert observation.stable_count == 1 and supervisor.monitor is not old_monitor


def test_safe_domain_failure_precedes_capture_abort_and_is_absorbing(setup):
    supervisor = _supervisor(setup)
    supervisor.observe(1, [0, 0, 0, 0])
    failed = supervisor.observe(2, [.451, 0, 0, 0])
    assert failed.phase == "failed" and failed.failure_reason == "balance_domain_exceeded"
    assert [e.trigger for e in supervisor.transitions] == ["capture_enter", "balance_domain_exceeded"]
    with pytest.raises(RuntimeError):
        supervisor.observe(3, [0, 0, 0, 0])
    with pytest.raises(RuntimeError):
        supervisor.raw_force(2, [0, 0, 0, 0])


def test_monitor_requires_51_observations_and_recovery_restarts_count(setup):
    supervisor = _supervisor(setup)
    for step in range(1, 51):
        observed = supervisor.observe(step, [0, 0, 0, 0])
        assert observed.status != "stable"
    assert supervisor.observe(51, [0, 0, 0, 0]).status == "stable"
    assert supervisor.observe(52, [.021, 0, 0, 0]).stable_count == 0
    for step in range(53, 103):
        assert supervisor.observe(step, [0, 0, 0, 0]).status == "recovering"
    assert supervisor.observe(103, [0, 0, 0, 0]).status == "stable"


def test_capture_timeout_acquisition_deadline_and_boundary_success(setup):
    supervisor = _supervisor(setup, capture_timeout_steps=3)
    supervisor.observe(1, [0, 0, 0, 0])
    for step in (2, 3):
        assert supervisor.observe(step, [.36, 0, 0, 0]).phase == "capture"
    assert supervisor.observe(4, [.36, 0, 0, 0]).failure_reason == "capture_timeout"
    supervisor = _supervisor(setup, acquisition_deadline_steps=3)
    for step in (1, 2):
        supervisor.observe(step, [0, 0, np.pi, 0])
    assert supervisor.observe(3, [0, 0, np.pi, 0]).failure_reason == "acquisition_timeout"
    supervisor = _supervisor(setup, acquisition_deadline_steps=3, capture_timeout_steps=2)
    for step in (1, 2):
        supervisor.observe(step, [0, 0, 0, 0])
    assert supervisor.observe(3, [0, 0, 0, 0]).phase == "balance"


def test_capture_attempt_budget_and_observation_sequence(setup):
    supervisor = _supervisor(setup, capture_max_attempts=1)
    supervisor.observe(1, [0, 0, 0, 0])
    with pytest.raises(ValueError):
        supervisor.observe(1, [0, 0, 0, 0])
    with pytest.raises(ValueError):
        supervisor.observe(3, [0, 0, 0, 0])
    supervisor.observe(2, [.401, 0, 0, 0])
    for step in range(3, 7):
        supervisor.observe(step, [0, 0, 0, 0])
    assert supervisor.observe(7, [0, 0, 0, 0]).failure_reason == "capture_attempts_exhausted"


@pytest.mark.parametrize("state,reason", [([.501, 0, np.pi, 0], "track_limit"),
    ([0, 3.001, np.pi, 0], "overspeed"), ([0, 0, np.pi, 15.001], "overspeed"),
    ([0, True, 0, 0], "observation_invalid"), ([0, 0, np.nan, 0], "nonfinite")])
def test_observation_physical_and_type_gates_precede_startup(setup, state, reason):
    supervisor = SwingUpSupervisor(*setup)
    assert supervisor.observe(0, state).failure_reason == reason


def _independent_closed_loop(direction, pulse=None):
    """冻结独立 K/判据/公式，在自身状态上逐区间 DOP853，不重放生产控制力。"""
    state = np.array([0., 0., np.pi, 0.])
    states, raws, applied, forces, modes, counts, statuses, transitions = [], [], [], [], [], [], [], []
    phase, capture_count, stable_count = "swing_up", 0, 0
    enter, safe, stable = np.array([.35, .5, .15, .8]), np.array([.45, .6, .2, 1.]), np.array([.02, .03, .02, .05])
    plant = load_cart_pole_contract(ROOT / "configs/cart_pole_plant.yaml")

    def rhs(_time, y, force):
        cart_a, pole_a = _accelerations(plant, y, force)
        return [y[1], cart_a, y[3], pole_a]

    for step in range(1501):
        local = state.copy()
        local[2] = (state[2] + np.pi) % (2 * np.pi) - np.pi
        assert abs(state[0]) <= .5 and abs(state[1]) <= 3 and abs(state[3]) <= 15
        if phase == "swing_up" and step >= 10 and np.all(np.abs(local) <= enter) and local[2] * local[3] <= 0:
            phase = "capture"
            transitions.append((step, "capture"))
        if phase in ("capture", "balance"):
            assert np.all(np.abs(local) <= safe)
            stable_count = stable_count + 1 if np.all(np.abs(local) <= stable) else 0
            if phase == "capture":
                capture_count = capture_count + 1 if np.all(np.abs(local) <= enter) else 0
                if capture_count >= 3:
                    phase = "balance"
                    transitions.append((step, "balance"))
        states.append(state.copy())
        modes.append(phase)
        counts.append(stable_count)
        statuses.append("stable" if stable_count >= 51 else "recovering" if phase != "swing_up" else "acquiring")
        if step == 1500:
            break
        if phase in ("capture", "balance"):
            raw = float(-ORACLE_K @ local)
        elif step < 10:
            raw = float(direction)
        else:
            position, velocity, theta, omega = state
            error = .012 * omega**2 + .588 * np.cos(theta) - .588
            desired_a = -8 * error * omega * np.cos(theta) - 16 * position - 8 * velocity
            raw = ((.7 - .15 * np.cos(theta)**2) * desired_a + .1 * velocity
                   + .06 * omega**2 * np.sin(theta) - 1.47 * np.sin(theta) * np.cos(theta))
        clipped = float(np.clip(raw, -10., 10.))
        disturbance = float(pulse[1]) if pulse is not None and step == pulse[0] else 0.
        assert abs(clipped + disturbance) <= 10
        solved = solve_ivp(rhs, (0., .02), state, args=(clipped + disturbance,),
                           method="DOP853", rtol=1e-12, atol=1e-14,
                           t_eval=np.linspace(0., .02, 21))
        assert solved.success and np.max(np.abs(solved.y[0])) < .5
        state = solved.y[:, -1]
        raws.append(raw)
        applied.append(clipped)
        forces.append(disturbance)
    return np.array(states), np.array(raws), np.array(applied), np.array(forces), modes, counts, statuses, transitions


@pytest.mark.parametrize("direction,pulse", [(1, None), (-1, (600, -1))])
@pytest.mark.stress
def test_1500_step_witness_against_independent_full_closed_loop(setup, direction, pulse):
    """两方向与预声明±1N扰动均比较完整轨迹/力/事件/计数，不用生产输出驱动 oracle。"""
    plant, balance, config = setup
    config = replace(config, kick_direction=direction, disturbances=() if pulse is None else (pulse,))
    actual = run_swing_up_experiment(plant, balance, config)
    expected = _independent_closed_loop(direction, pulse)
    assert actual.goal_met and actual.termination == "observed_success" and actual.completed_steps == 1500
    assert actual.state.shape == actual.output.shape == (1501, 4)
    assert actual.raw_force.shape == actual.applied_force.shape == actual.total_force.shape == (1500, 1)
    # 来自设计的独立积分差异及 RK4 细化证据；各 SI 分量单独给绝对容差。
    assert np.all(np.max(np.abs(actual.state - expected[0]), axis=0) <= [5e-8, 2e-7, 1e-6, 2e-6])
    np.testing.assert_allclose(actual.raw_force[:, 0], expected[1], rtol=0, atol=5e-6)
    np.testing.assert_allclose(actual.applied_force[:, 0], expected[2], rtol=0, atol=5e-6)
    np.testing.assert_array_equal(actual.disturbance_force[:, 0], expected[3])
    np.testing.assert_array_equal(actual.time_s, np.arange(1501) * .02)
    assert list(actual.mode_for_interval) == expected[4][:-1]
    assert [row.phase for row in actual.observations] == expected[4]
    assert [row.stable_count for row in actual.observations] == expected[5]
    assert [row.status for row in actual.observations] == expected[6]
    assert [(event.observation_step, event.to_phase) for event in actual.transitions] == expected[7] == [(232, "capture"), (234, "balance")]
    assert actual.first_stable_step == 370
    summary = actual.to_report()["summary"]
    assert summary["saturated_intervals"] == 7
    assert summary["max_abs_state"][0] == pytest.approx(.3824047502, abs=1e-9)
    assert summary["max_abs_raw_force"][0] == pytest.approx(17.273358921, abs=1e-8)
    assert summary["stable_entry_steps"] == ([370] if pulse is None else [370, 653])
    assert summary["final_stable_count"] == (1181 if pulse is None else 898)
    assert np.max(np.abs(actual.total_force)) <= plant.max_applied_force_n
    np.testing.assert_allclose(actual.raw_force[:10, 0], direction, rtol=0, atol=0)
    if direction < 0:
        assert actual.state[-1, 2] == pytest.approx(2 * np.pi, abs=1e-8)
    else:
        assert actual.state[-1, 2] == pytest.approx(0., abs=1e-8)


@pytest.mark.stress
def test_rk4_refinement_reduces_error_without_changing_phases(setup):
    """8 子步误差显著小于4子步，支持名义30s全轨迹容差而非任意放宽。"""
    plant, balance, config = setup
    expected = _independent_closed_loop(1)[0]
    coarse = run_swing_up_experiment(plant, balance, config)
    fine = run_swing_up_experiment(replace(plant, rk4_substeps=8), balance, config)
    coarse_error = np.max(np.abs(coarse.state - expected), axis=0)
    fine_error = np.max(np.abs(fine.state - expected), axis=0)
    assert np.all(fine_error < coarse_error / 8)
    assert [(e.observation_step, e.to_phase) for e in fine.transitions] == [(232, "capture"), (234, "balance")]
    assert fine.first_stable_step == 370


@pytest.mark.stress
def test_repeat_runs_frozen_records_and_instance_isolation(setup):
    """同机数组/事件 bitwise 重复；两实例不共享状态或可变结果缓冲区。"""
    first, second = run_swing_up_experiment(*setup), run_swing_up_experiment(*setup)
    for field in ("state", "output", "time_s", "upright_angle_rad", "raw_force", "applied_force", "disturbance_force", "total_force"):
        left, right = getattr(first, field), getattr(second, field)
        np.testing.assert_array_equal(left, right)
        assert not left.flags.writeable and not np.shares_memory(left, right)
    assert first.observations == second.observations and first.transitions == second.transitions
    report = first.to_report()
    report["state"][0][0] = 99
    assert first.state[0, 0] == 0
    assert setup[0].initial_state[2] != np.pi and setup[1].safe_abs == (.45, .6, .2, 1.)


@pytest.mark.parametrize("step,force", [(10, 1), (233, -1)])
@pytest.mark.stress
def test_predeclared_swing_and_capture_disturbances_are_honest(setup, step, force):
    """不筛选最佳事件；可成功或保留真实失败，但不得更改合力或补齐前缀。"""
    config = replace(setup[2], disturbances=((step, force),))
    actual = run_swing_up_experiment(setup[0], setup[1], config)
    assert actual.completed_steps > step
    assert actual.disturbance_events[0][:3] == (step, force, force)
    assert actual.mode_for_interval[step] == ("swing_up" if step == 10 else "capture")
    assert actual.total_force[step, 0] == actual.applied_force[step, 0] + force
    assert len(actual.state) == actual.completed_steps + 1
    assert actual.goal_met == (actual.termination == "observed_success")


@pytest.mark.stress
def test_request_rejection_and_actual_replay_do_not_clip_total_force(setup):
    """饱和区间请求被拒绝；重放冻结实际事件，非法重放合力直接失败。"""
    base = run_swing_up_experiment(*setup)
    index = int(np.flatnonzero(np.abs(base.applied_force[:, 0]) == 10)[0])
    force = float(np.sign(base.applied_force[index, 0]))
    actual = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], disturbances=((index, force),)))
    assert actual.disturbance_events == ((index, force, 0., "rejected_total_force_limit"),)
    np.testing.assert_array_equal(actual.state, base.state)
    replay = run_swing_up_experiment(*setup, replay_disturbances=tuple(actual.disturbance_force[:, 0]))
    np.testing.assert_array_equal(replay.state, actual.state)
    invalid = [0.] * 1500
    invalid[index] = force
    failed = run_swing_up_experiment(*setup, replay_disturbances=tuple(invalid))
    assert not failed.goal_met and failed.failure_reason == "replay_force_limit"
    assert failed.completed_steps == failed.failure_interval_step == index
    assert len(failed.state) == index + 1


@pytest.mark.stress
def test_track_failure_preserves_state_and_does_not_commit_attempted_force(setup):
    failed = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], initial_state=(.499, 1, np.pi, 0)))
    assert failed.failure_reason == "track_limit" and failed.failure_interval_step == 0
    assert failed.completed_steps == 0 and not failed.goal_met
    np.testing.assert_array_equal(failed.state, [[.499, 1, np.pi, 0]])
    assert failed.attempted_step == (0, 1., 1., 0., 1.)


@pytest.mark.stress
def test_postcommit_speed_failure_retains_actual_interval_and_failure_observation(setup):
    failed = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], max_cart_speed_m_per_s=.01))
    assert failed.failure_reason == "overspeed" and failed.failure_observation_step == 1
    assert failed.completed_steps == 1 and failed.failure_interval_step is None
    assert len(failed.state) == len(failed.observations) == 2
    assert failed.observations[-1].phase == "failed" and failed.applied_force[0, 0] == 1
    assert failed.state[1, 1] > .01


@pytest.mark.stress
def test_poor_gain_and_numeric_overflow_are_real_failure_results(setup):
    poor = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], energy_gain_m_per_j_s=800))
    assert not poor.goal_met and poor.failure_reason in ("track_limit", "overspeed", "acquisition_timeout")
    assert poor.completed_steps < 1500 and len(poor.state) == poor.completed_steps + 1
    assert np.any(np.abs(poor.raw_force) > 10)
    overflow = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], initial_state=(0, 0, np.pi, 1e200), max_pole_speed_rad_per_s=1e201))
    assert overflow.failure_reason == "numeric_step" and overflow.completed_steps == 0
    encoded = json.dumps(overflow.to_report(), allow_nan=False)
    assert "NaN" not in encoded and "Infinity" not in encoded


@pytest.mark.stress
def test_past_stable_is_not_terminal_success_and_endpoint_computes_no_force(setup, monkeypatch):
    import secure_control.scenarios.cart_pole.swing_up_experiment as experiment
    original = experiment.SwingUpSupervisor.raw_force
    calls = []

    def force(supervisor, step, output):
        calls.append(step)
        return original(supervisor, step, output)

    monkeypatch.setattr(experiment.SwingUpSupervisor, "raw_force", force)
    actual = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], horizon_steps=601, disturbances=((600, 1),)))
    assert actual.first_stable_step == 370 and actual.termination == "time_limit" and not actual.goal_met
    assert actual.observations[-1].status == "recovering" and calls == list(range(601))
    assert actual.completed_steps == 601 and len(actual.state) == 602


def test_capture_cannot_evade_timeout_by_aborting_at_deadline(setup):
    """到期仍未 balance 必失败，不能借同观测的外盒退出绕过本次时限。"""
    supervisor = _supervisor(setup, capture_timeout_steps=2)
    supervisor.observe(1, [0, 0, 0, 0])
    supervisor.observe(2, [.36, 0, 0, 0])
    assert supervisor.observe(3, [.401, 0, 0, 0]).failure_reason == "capture_timeout"


def test_default_100_and_600_step_deadlines_are_observation_boundaries(setup):
    """原配置的100/600步边界可复算，不靠墙钟或预设成功时刻推进。"""
    supervisor = _supervisor(setup)
    supervisor.observe(1, [0, 0, 0, 0])
    for step in range(2, 101):
        assert supervisor.observe(step, [.36, 0, 0, 0]).phase == "capture"
    assert supervisor.observe(101, [.36, 0, 0, 0]).failure_reason == "capture_timeout"
    supervisor = _supervisor(setup)
    for step in range(1, 600):
        assert supervisor.observe(step, [0, 0, np.pi, 0]).phase == "swing_up"
    assert supervisor.observe(600, [0, 0, np.pi, 0]).failure_reason == "acquisition_timeout"


@pytest.mark.parametrize("bad", [tuple([False] * 1500), tuple([np.nan] * 1500),
                                 tuple([2.] * 1500), tuple([0.] * 1499)])
@pytest.mark.stress
def test_actual_replay_sequence_is_strict(setup, bad):
    with pytest.raises((TypeError, ValueError)):
        run_swing_up_experiment(*setup, replay_disturbances=bad)


@pytest.mark.stress
def test_numeric_control_and_invalid_next_observation_never_serialize_nonfinite_rows(setup, monkeypatch):
    """异常只保留可信前缀/诊断，不向 JSON 写入未提交力或 NaN/Infinity。"""
    import secure_control.scenarios.cart_pole.swing_up_experiment as experiment
    with monkeypatch.context() as patch:
        patch.setattr(experiment.SwingUpSupervisor, "raw_force", lambda *_args: np.inf)
        failed = run_swing_up_experiment(*setup)
        assert failed.failure_reason == "numeric_control" and failed.completed_steps == 0
        assert failed.attempted_step[1] is None
        json.dumps(failed.to_report(), allow_nan=False)
    for invalid in ([0, 0, np.nan, 0], [0, 0, 0], [0, True, 0, 0]):
        with monkeypatch.context() as patch:
            patch.setattr(experiment.CartPolePlant, "step", lambda *_args, invalid=invalid: invalid)
            failed = run_swing_up_experiment(*setup)
            assert failed.completed_steps == 0 and len(failed.state) == 1
            assert failed.failure_interval_step == 0 and failed.failure_reason == "numeric_step"
            json.dumps(failed.to_report(), allow_nan=False)


@pytest.mark.parametrize("initial", [(0, 0, np.pi + .01, 0)])
@pytest.mark.stress
def test_predeclared_small_initial_changes_are_recorded_without_success_selection(setup, initial):
    """事先声明四个小初态变化；保留成功/失败，不把单条最佳轨迹当鲁棒性证明。"""
    result = run_swing_up_experiment(setup[0], setup[1], replace(setup[2], initial_state=initial))
    np.testing.assert_array_equal(result.state[0], initial)
    assert len(result.state) == result.completed_steps + 1
    assert result.goal_met == (result.termination == "observed_success")
    if result.goal_met:
        assert result.observations[-1].status == "stable" and result.completed_steps == 1500
    else:
        assert result.failure_reason in ("track_limit", "overspeed", "acquisition_timeout",
                                         "capture_timeout", "capture_attempts_exhausted",
                                         "balance_domain_exceeded") or result.termination == "time_limit"
