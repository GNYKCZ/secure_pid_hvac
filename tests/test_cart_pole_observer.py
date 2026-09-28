"""两测量动态设计、独立闭环oracle与真实执行/失败边界。"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from dataclasses import replace
from math import pi
from pathlib import Path

import numpy as np
import pytest
import yaml
from scipy.integrate import solve_ivp
from scipy.linalg import expm
from test_cart_pole_balance import FIVE_DEG, ORACLE_K, _oracle_rhs

from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.scenarios.cart_pole import (
    ActuationReceipt,
    CartPoleObserverSimulation,
    CartPolePlant,
    ControlCommand,
    MeasurementSample,
    ObserverBalanceEpisode,
    build_cart_pole_observer_design,
    load_cart_pole_observer_design,
    run_observer_balance_experiment,
    write_observer_balance_report,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/cart_pole_observer.yaml"
# 独立隐式模型的增广指数、对偶极点配置离线计算；oracle不调用生产builder。
ORACLE_L = np.array([
    [.4900867928207506, -.017482811400744373],
    [2.921598305182016, -.1705716458919118],
    [-.02757535611126442, .5525273195122129],
    [-.45701172061782813, 4.401767914962103],
])


@pytest.fixture
def design():
    """统一加载真实三源，而不是在测试配置里手抄生产矩阵。"""
    return load_cart_pole_observer_design(CONFIG)


def independent_model():
    """从已核对的CTMS有理数Jacobian构造独立ZOH，不调用生产模型函数。"""
    ac = np.array([[0, 1, 0, 0], [0, -2/11, 29.4/11, 0],
                   [0, 0, 0, 1], [0, -5/11, 343/11, 0]])
    bc = np.array([0, 20/11, 0, 50/11])
    augmented = np.zeros((5, 5))
    augmented[:4, :4], augmented[:4, 4] = ac, bc
    zoh = expm(augmented * .02)
    return ac, bc, zoh[:4, :4], zoh[:4, 4]


def test_model_observer_and_guaranteed_linear_domain(design):
    """检查模型、可控观性、独立冻结L、分离谱、Lyapunov与力/状态投影。"""
    ac, bc, ap, bp = independent_model()
    np.testing.assert_allclose(design.Ac, ac, rtol=0, atol=2e-14)
    np.testing.assert_allclose(design.Bc[:, 0], bc, rtol=0, atol=2e-14)
    np.testing.assert_allclose(design.Ap, ap, rtol=0, atol=2e-14)
    np.testing.assert_allclose(design.Bp[:, 0], bp, rtol=0, atol=2e-14)
    np.testing.assert_allclose(design.K[0], ORACLE_K, rtol=0, atol=2e-11)
    np.testing.assert_allclose(design.L, ORACLE_L, rtol=0, atol=2e-11)
    assert np.linalg.matrix_rank(np.vstack([design.Cp @ np.linalg.matrix_power(ap, j)
                                          for j in range(4)])) == 4
    assert np.linalg.matrix_rank(np.column_stack([np.linalg.matrix_power(ap, j) @ bp
                                                for j in range(4)])) == 4
    np.testing.assert_array_equal(design.Dp, np.zeros((2, 1)))
    actual = np.linalg.eigvals(ap - ORACLE_L @ design.Cp)
    np.testing.assert_allclose(np.sort(actual), np.sort(np.exp(-np.array([12,14,16,18]) * .02)),
                               rtol=0, atol=1e-12)
    triangular = np.block([[ap - bp[:, None] @ ORACLE_K[None, :], bp[:, None] @ ORACLE_K[None, :]],
                           [np.zeros((4, 4)), ap - ORACLE_L @ design.Cp]])
    np.testing.assert_allclose(np.sort_complex(np.linalg.eigvals(triangular)),
                               np.sort_complex(np.linalg.eigvals(design.Phi)), rtol=0, atol=1e-12)
    w = np.diag(1/np.tile(np.array([.45,.6,.2,1]), 2)**2)
    np.testing.assert_allclose(design.Phi.T @ design.P @ design.Phi - design.P, -w,
                               rtol=0, atol=1e-9)
    assert np.linalg.eigvalsh(design.P).min() > 0
    constraints = np.vstack([np.eye(8)[:4], np.r_[np.zeros(4), -ORACLE_K]])
    limits = np.array([.45,.6,.2,1,10])
    projection = np.diag(constraints @ np.linalg.solve(design.P, constraints.T))
    assert np.all(np.sqrt(design.domain_c * projection) <= limits * (1 + 1e-14))
    assert design.domain_c == pytest.approx(3.73609, abs=1e-5)
    init = design.initialize(MeasurementSample(0, 0, 0, FIVE_DEG))
    assert init.linear_initial_value > design.domain_c  # 5°见证不冒充保证域。
    snapshot = design.to_snapshot()
    assert snapshot["spectral_radius"]["augmented"] == pytest.approx(.975793840705157, abs=2e-12)
    assert snapshot["spectral_radius"]["controller"] < 1
    assert snapshot["hold_span_s"] == 1 and snapshot["horizon_time_s"] == 8
    assert len(snapshot["source_snapshots"]) == 3
    for value in (design.L, design.Ap, init.spec.x0, init.state_abs_bound):
        with pytest.raises(ValueError):
            value.flat[0] = 0


def test_runtime_matches_expanded_equations_and_one_sample_delay(design):
    """输入维数2、真非零递推；D=0使本轮测量先影响下一力，不能偷偷先校正输出。"""
    init = design.initialize(MeasurementSample(0, 0, .02, .05), velocity_seed=(.05, -.05))
    spec = init.spec
    assert (spec.A.shape, spec.B.shape, spec.C.shape, spec.D.shape, spec.x0.shape) == (
        (4,4), (4,2), (1,4), (1,2), (4,)
    )
    assert spec.scale_metadata is None
    np.testing.assert_array_equal(spec.x0, [.02,.05,.05,-.05])
    np.testing.assert_array_equal(spec.D, [[0,0]])
    runtime, alternate = PlaintextStateSpaceRuntime(spec), PlaintextStateSpaceRuntime(spec)
    old = spec.x0.copy()
    for index in range(15):
        measured = np.array([.02 * np.cos(index), .05 * np.sin(index)])
        raw = runtime.step(measured)
        np.testing.assert_allclose(raw, -design.K @ old, rtol=0, atol=1e-12)
        independent = design.Ap @ old + design.Bp[:, 0]*raw[0] + design.L @ (measured-design.Cp@old)
        np.testing.assert_allclose(runtime.state, independent, rtol=0, atol=1e-12)
        old = independent
    first = PlaintextStateSpaceRuntime(spec)
    np.testing.assert_array_equal(first.step(np.array([.02,.05])), alternate.step(np.array([.1,-.1])))
    assert not np.array_equal(first.state, alternate.state)
    assert not np.array_equal(first.step(np.zeros(2)), alternate.step(np.zeros(2)))
    np.testing.assert_array_equal(spec.x0, [.02,.05,.05,-.05])
    # 下游实数范围用A的矩阵幂，不用仿真峰值冒充全输入界。
    for k in (0, 1, 20, 400):
        bound = abs(np.linalg.matrix_power(spec.A, k)) @ abs(spec.x0)
        for j in range(k):
            bound += abs(np.linalg.matrix_power(spec.A, j) @ spec.B) @ np.array(init.y_abs)
        np.testing.assert_allclose(init.state_abs_bound[k], bound, rtol=1e-12, atol=1e-12)
    np.testing.assert_allclose(init.raw_abs_bound[:, 0], init.state_abs_bound @ abs(ORACLE_K),
                               rtol=0, atol=1e-11)


def oracle_closed_loop(initial, seed, pulse):
    """完整独立闭环：自身状态测量/估计/力，DOP853与独立门禁，不重放生产输出。"""
    _, _, ap, bp = independent_model()
    truth = np.array(initial, dtype=float)
    branch = int(np.floor((truth[2] + pi)/(2*pi)))
    zero = branch * 2*pi
    estimate = np.array([truth[0], seed[0], truth[2]-zero, seed[1]])
    states, estimates, forces, statuses, counts = [], [], [], [], []
    count = 0
    for k in range(401):
        local = truth.copy()
        local[2] -= zero
        assert np.all(abs(local) <= [.45,.6,.2,1])
        count = count + 1 if np.all(abs(local) <= [.02,.03,.02,.05]) else 0
        statuses.append("stable" if count >= 51 else "recovering")
        counts.append(count)
        states.append(truth.copy())
        estimates.append(estimate.copy())
        if k == 400:
            break
        raw = float(-ORACLE_K @ estimate)
        assert abs(raw) <= 10
        measured = local[[0,2]]
        estimate = ap@estimate + bp*raw + ORACLE_L@(measured-estimate[[0,2]])
        actual = pulse if k == 200 else 0.
        assert abs(raw + actual) <= 10
        solved = solve_ivp(_oracle_rhs, (0., .02), truth, args=(raw+actual,), method="DOP853",
                           rtol=1e-12, atol=1e-14, dense_output=True)
        assert solved.success
        assert np.max(abs(solved.sol(np.linspace(0,.02,21))[0])) <= .5
        truth = solved.y[:, -1]
        forces.append(raw)
    return np.array(states), np.array(estimates), np.array(forces), statuses, counts


CASES = [
    ((0,0,FIVE_DEG,0), (0,0), 0),
    ((0,0,-FIVE_DEG,0), (0,0), 0),
    ((.02,.1,.05,-.15), (0,0), 0),
    ((.02,.1,.05,-.15), (.05,-.05), 0),
    ((0,0,2*pi+FIVE_DEG,0), (0,0), 1),
    ((0,0,-4*pi-FIVE_DEG,0), (0,0), -1),
]


@pytest.mark.parametrize("initial,seed,pulse", CASES)
def test_nonlinear_witness_and_independent_closed_loop(design, initial, seed, pulse):
    """预声明六例逐行比对，并用8子步收敛支持SI容差，终态/误差分别验收。"""
    events = ((200, pulse),) if pulse else ()
    result = run_observer_balance_experiment(design, initial_state=initial, velocity_seed=seed,
                                             disturbances=events)
    assert result.goal_met and result.completed_steps == 400
    assert result.measurement.shape == (401,2) and result.estimate.shape == (401,4)
    expected_state, expected_estimate, expected_force, statuses, counts = oracle_closed_loop(initial, seed, pulse)
    np.testing.assert_allclose(result.truth, expected_state, rtol=0, atol=3e-8)
    np.testing.assert_allclose(result.estimate, expected_estimate, rtol=0, atol=3e-8)
    np.testing.assert_allclose(result.raw_force[:, 0], expected_force, rtol=0, atol=1e-7)
    assert list(result.observed_status) == statuses and list(result.stable_count) == counts
    refined = build_cart_pole_observer_design(replace(design.plant, rk4_substeps=8),
                                              design.balance, design.config)
    fine = run_observer_balance_experiment(refined, initial_state=initial, velocity_seed=seed,
                                           disturbances=events)
    assert fine.observed_status == result.observed_status
    assert np.max(abs(fine.truth-expected_state)) < np.max(abs(result.truth-expected_state))/8
    assert np.max(abs(fine.estimate-expected_estimate)) < np.max(abs(result.estimate-expected_estimate))/8
    np.testing.assert_array_less(abs(result.local_truth[-1]-result.estimate[-1]), [1e-4,1e-3,1e-4,1e-3])
    np.testing.assert_array_equal(result.command_force, result.raw_force)
    np.testing.assert_array_equal(result.applied_force, result.raw_force)
    np.testing.assert_array_equal(result.total_force, result.applied_force+result.disturbance_force)
    if pulse:
        assert result.disturbance_events == ((200,float(pulse),float(pulse),"accepted"),)
        assert abs(result.local_truth[201, 3]-result.estimate[201, 3]) > .01
    report = result.to_report()
    assert report["supervision_source"] == "ideal_simulation_truth"
    assert report["computation_mode"] == "plaintext" and "secure" not in report
    np.testing.assert_array_equal(report["estimation_error"], result.local_truth-result.estimate)
    assert report["summary"]["max_abs_estimation_error"] == np.max(abs(result.local_truth-result.estimate), axis=0).tolist()


def test_provider_replacement_never_reads_truth_to_seed_or_control(design):
    """替身没有state/output能力；真速度与seed不同，controller仍只读取两测量。"""
    physical = replace(design.plant, initial_state=(.02,.1,.05,-.15))
    sim = CartPoleObserverSimulation(CartPolePlant(physical), physical)
    class DeviceOnly:
        def read_measurement(self):
            return sim.read_measurement()

        def send_control(self, command):
            return sim.send_control(command)

    device = DeviceOnly()
    assert not hasattr(device, "state") and not hasattr(device, "output")
    result = run_observer_balance_experiment(design, device=device,
                                             truth_provider=sim.read_diagnostic_truth,
                                             force_evidence=sim.read_interval_forces)
    assert result.goal_met
    np.testing.assert_array_equal(result.estimate[0], [.02,0,.05,0])
    np.testing.assert_array_equal(result.truth[0], [.02,.1,.05,-.15])
    report = result.to_report()
    assert report["effective_options"]["initial_state"] == result.truth[0].tolist()
    assert report["effective_options"]["initial_state_source"] == "injected_diagnostic_truth"
    with pytest.raises(ValueError, match="另外注入"):
        run_observer_balance_experiment(design, device=device)


def test_episode_no_secret_state_access_exit_reentry_and_consumption(design):
    """episode只调用step；连续运行不重初始化，退出后不可再消费，新身份才重入。"""
    sample = MeasurementSample(10, .2, .01, 6*pi+.03)
    init = design.initialize(sample)
    backing = PlaintextStateSpaceRuntime(init.spec)
    class StepOnly:
        def step(self, y):
            return backing.step(y)

    episode = ObserverBalanceEpisode(init, StepOnly(), episode_id="first")
    assert init.branch == 3 and init.theta_star == 6*pi
    episode.step(sample)
    episode.step(MeasurementSample(11, .22, .01, 6*pi+.03))
    assert not np.array_equal(backing.state, init.spec.x0)
    episode.end("exit")
    with pytest.raises(RuntimeError, match="结束"):
        episode.step(MeasurementSample(12, .24, .01, 6*pi+.03))
    second_sample = MeasurementSample(12, .24, .02, 6*pi+.02)
    second_init = design.initialize(second_sample, (.05,-.1))
    second = ObserverBalanceEpisode(second_init, PlaintextStateSpaceRuntime(second_init.spec), episode_id="second")
    np.testing.assert_array_equal(second_init.spec.x0, [.02,.05,second_sample.theta_rad-6*pi,-.1])
    second.step(second_sample)
    with pytest.raises(ValueError, match="identity"):
        second.step(second_sample)
    assert not second.active and episode.end_reason == "exit"


@pytest.mark.parametrize("change", ["mass", "period", "feedback", "observer"])
def test_single_source_parameter_propagation(design, tmp_path, change):
    """每个案例只改拥有该量的源字段；矩阵/极点/秒数/摘要自动重算，不手抄gain。"""
    for name in ("cart_pole_plant.yaml", "cart_pole_balance.yaml", "cart_pole_observer.yaml"):
        (tmp_path/name).write_bytes((ROOT/"configs"/name).read_bytes())
    filename, key, value = {
        "mass": ("cart_pole_plant.yaml", "cart_mass_kg", .55),
        "period": ("cart_pole_plant.yaml", "sample_period_s", .025),
        "feedback": ("cart_pole_balance.yaml", "r_force_weight", 1.25),
        "observer": ("cart_pole_observer.yaml", "observer_decay_rates_per_s", [13,14,16,18]),
    }[change]
    path = tmp_path/filename
    root = yaml.safe_load(path.read_bytes())
    root[key] = value
    path.write_text(yaml.safe_dump(root), encoding="utf-8")
    changed = load_cart_pole_observer_design(tmp_path/"cart_pole_observer.yaml")
    assert not np.array_equal(changed.A, design.A)
    if change in {"mass", "period", "feedback"}:
        assert not np.array_equal(changed.K, design.K)
    if change in {"period", "observer"}:
        assert not np.array_equal(changed.observer_poles, design.observer_poles)
    if change == "period":
        assert changed.to_snapshot()["hold_span_s"] == 1.25
    changed.initialize(MeasurementSample(0,0,0,.03))


@pytest.mark.parametrize("name,value", [
    ("observer_decay_rates_per_s", [12,12,16,18]),
    ("observer_decay_rates_per_s", [True,14,16,18]),
    ("observer_decay_rates_per_s", [0,14,16,18]),
    ("observer_decay_rates_per_s", [float("nan"),14,16,18]),
    ("observer_decay_rates_per_s", [12,14,16]),
    ("observer_decay_rates_per_s", [1e6,1e6+1,1e6+2,1e6+3]),
    ("observer_decay_rates_per_s", [12,12+1e-12,16,18]),
    ("initial_velocity_estimate", [0,"0"]),
    ("initial_velocity_estimate", [0,float("inf")]),
    ("initial_error_abs", [0,-.1,0,.15]),
    ("initial_error_abs", [0,True,0,.15]),
])
def test_invalid_observer_parameters_fail_before_run(design, name, value):
    """无穷/字符串/bool/坏维度及转换后的病态极点不进入设备路径。"""
    with pytest.raises((TypeError, ValueError, FloatingPointError)):
        config = replace(design.config, **{name: value})
        build_cart_pole_observer_design(design.plant, design.balance, config)


@pytest.mark.parametrize("suffix", ["unknown: 1\n", "schema_version: 1\n"])
def test_unknown_and_duplicate_yaml_rejected(tmp_path, suffix):
    """严格键集合和重复键在源解析阶段拒绝。"""
    path = tmp_path/"observer.yaml"
    path.write_text(CONFIG.read_text(encoding="utf-8")+suffix, encoding="utf-8")
    with pytest.raises(ValueError):
        load_cart_pole_observer_design(path)


@pytest.mark.parametrize("key,value", [("schema_version", 1.0), ("schema_version", True),
                                      ("plant_source", ""), ("balance_source", 12), ("scenario", "other")])
def test_bad_reference_and_schema(tmp_path, key, value):
    """引用路径和schema不隐式转换。"""
    root = yaml.safe_load(CONFIG.read_bytes())
    root[key] = value
    path = tmp_path/"observer.yaml"
    path.write_text(yaml.safe_dump(root), encoding="utf-8")
    with pytest.raises((TypeError, ValueError, OSError)):
        load_cart_pole_observer_design(path)


@pytest.mark.parametrize("kwargs", [{"sample_id": True}, {"sample_id": 1.0}, {"time_s": float("inf")},
                                    {"p_m": True}, {"theta_rad": float("nan")}, {"valid": (1,True)}])
def test_sample_strict_types(kwargs):
    """坏采样字段在不可变契约构造时拒绝。"""
    with pytest.raises((TypeError, ValueError)):
        MeasurementSample(**({"sample_id": 0, "time_s": 0, "p_m": 0, "theta_rad": 0} | kwargs))


@pytest.mark.parametrize("sample", [None, np.zeros(4), MeasurementSample(0,0,0,0,(False,True)),
                                    MeasurementSample(1,.02,0,0), MeasurementSample(0,.001,0,0)])
def test_invalid_initial_measurement_has_no_fabricated_rows(design, sample):
    """无效首样本保留零合法观测/零区间，不补NaN或读取真值来修复。"""
    class BrokenDevice:
        def read_measurement(self):
            return sample

        def send_control(self, command):
            pytest.fail("无效测量不能发命令")

    result = run_observer_balance_experiment(design, device=BrokenDevice(),
                                             truth_provider=lambda: pytest.fail("不能读真值补输入"),
                                             force_evidence=lambda: pytest.fail("没有区间"))
    assert not result.goal_met and len(result.time_s) == 0 and result.completed_steps == 0
    assert result.failure_reason == "measurement"
    json.dumps(result.to_report(), allow_nan=False)
    assert result.to_report()["effective_options"]["initial_state"] is None
    assert result.to_report()["effective_options"]["initial_state_source"] == "unavailable"


@pytest.mark.parametrize("disposition", ["accepted", "unknown", "rejected"])
def test_ack_is_not_completed_interval(design, disposition):
    """ACK/不确定/拒绝均不追加力区间；已递推估计只在attempt，不当成功N+1行。"""
    class AckDevice:
        def read_measurement(self):
            return MeasurementSample(0,0,0,.03)

        def send_control(self, cmd):
            return ActuationReceipt(cmd.command_id, cmd.episode_id, cmd.sample_id,
                                    disposition, None, "unconfirmed")

    result = run_observer_balance_experiment(design, device=AckDevice(),
                                             truth_provider=lambda: np.array([0,0,.03,0]),
                                             force_evidence=lambda: pytest.fail("未确认回执不能读已完成力"))
    assert result.completed_steps == 0 and result.estimate.shape == (1,4)
    assert result.termination == ("failed" if disposition == "rejected" else "uncertain")
    attempt = result.to_report()["attempted"]
    assert not attempt["physical_interval_completed"]
    assert attempt["receipt"]["applied_force_n"] is None
    assert attempt["mathematical_next_estimate"] != result.estimate[0].tolist()


def test_saturation_equal_boundary_pulse_rejection_and_atomic_failure(design, monkeypatch):
    """raw边界不加epsilon；超界未发送/推进。总力拒外扰不二次限幅。"""
    init = design.initialize(MeasurementSample(0,0,0,FIVE_DEG))
    force = abs(float((init.spec.C @ init.spec.x0)[0]))
    short = replace(design.balance, horizon_steps=1)
    for limit, expected in ((force, 1), (np.nextafter(force, 0), 0), (np.nextafter(force,np.inf), 1)):
        changed = build_cart_pole_observer_design(replace(design.plant, max_applied_force_n=limit),
                                                  short, design.config)
        result = run_observer_balance_experiment(changed)
        assert result.completed_steps == expected
        if not expected:
            assert result.failure_reason == "saturation_outside_contract"
            assert not result.to_report()["attempted"]["physical_interval_completed"]
    pulse_design = build_cart_pole_observer_design(replace(design.plant, max_applied_force_n=force),
                                                  short, design.config)
    pulse = run_observer_balance_experiment(pulse_design, disturbances=((0,-1),))
    assert pulse.completed_steps == 1 and pulse.disturbance_events == ((0,-1.,0.,"rejected_total_force_limit"),)
    original_step = CartPolePlant.step
    states = []
    def fail(self, command):
        before = self.state.copy()
        with pytest.raises(ValueError):
            original_step(self, np.array([100.]))
        np.testing.assert_array_equal(self.state, before)
        states.append(before)
        raise ValueError("track_center_limit_m simulated atomic failure")

    monkeypatch.setattr(CartPolePlant, "step", fail)
    failed = run_observer_balance_experiment(design)
    assert failed.completed_steps == 0 and len(states) == 1
    assert failed.failure_reason == "actuation" and failed.termination == "failed"


def test_initial_error_assumption_and_terminal_lost_stability(design):
    """误差假设不是全真值seed；历史stable不替代受扰后终点。"""
    bad = run_observer_balance_experiment(design, initial_state=(0,.10001,.03,0))
    assert bad.completed_steps == 0 and bad.failure_reason == "initial_error_outside_assumption"
    short = build_cart_pole_observer_design(design.plant, replace(design.balance, horizon_steps=201), design.config)
    disturbed = run_observer_balance_experiment(short, disturbances=((200,1),))
    assert "stable" in disturbed.observed_status[:-1]
    assert disturbed.termination == "time_limit" and not disturbed.goal_met
    assert disturbed.completed_steps == 201 and disturbed.raw_force.shape == (201,1)


@pytest.mark.parametrize("theta", [.2, -.2, 2*pi+.03, -2*pi-.03, 8*pi+.03])
def test_fixed_chart_and_domain_gate(design, theta):
    """整圈坐标保持物理theta，局部阈值等号合法，下一浮点超界直接拒绝。"""
    init = design.initialize(MeasurementSample(0,0,0,theta))
    episode = ObserverBalanceEpisode(init, PlaintextStateSpaceRuntime(init.spec), episode_id="chart")
    np.testing.assert_array_equal(episode.local_measurement(MeasurementSample(0,0,0,theta)),
                                   [0,theta-init.theta_star])
    with pytest.raises(ValueError, match="local_domain"):
        design.initialize(MeasurementSample(0,0,0,np.nextafter(.2,np.inf)))
    with pytest.raises(ValueError, match="local_domain"):
        episode.step(MeasurementSample(0,0,0,init.theta_star+pi))
    assert not episode.active


def test_report_freezing_repeatability_and_io(design, tmp_path):
    """重复实例不共享估计/plant；报告从行复算、不覆盖已有文件、不伪造provenance。"""
    result, again = run_observer_balance_experiment(design), run_observer_balance_experiment(design)
    for name in ("estimate", "truth", "measurement", "raw_force"):
        np.testing.assert_array_equal(getattr(result,name), getattr(again,name))
        assert not np.shares_memory(getattr(result,name), getattr(again,name))
        with pytest.raises(ValueError):
            getattr(result,name).flat[0] = 0
    path = write_observer_balance_report(result, tmp_path/"result.json")
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["kind"] == "cart_pole_observer_plaintext" and report["version"] == 1
    assert report["effective_options"]["initial_state"] == list(design.plant.initial_state)
    assert report["effective_options"]["initial_state_source"] == "canonical_simulation_contract"
    override = (.02,.1,.05,-.15)
    overridden = run_observer_balance_experiment(design, initial_state=override).to_report()
    assert overridden["effective_options"]["initial_state"] == list(override)
    assert overridden["effective_options"]["initial_state_source"] == "canonical_simulation_contract"
    assert not report["provenance"]["available"]
    assert report["summary"]["completed_steps"] == 400
    report["truth"][0][0] = 99
    assert result.to_report()["truth"][0][0] == 0
    with pytest.raises(FileExistsError):
        write_observer_balance_report(result, path)
    blocker = tmp_path/"blocker"
    blocker.write_text("keep", encoding="utf-8")
    with pytest.raises(OSError):
        write_observer_balance_report(result, blocker/"result.json")


def test_cli_from_yaml_to_saved_report_and_save_failure(tmp_path):
    """真实脚本贯通；覆盖失败不声称保存成功，非法事件启动前拒绝。"""
    output = tmp_path/"cli.json"
    args = ["uv", "run", "python", "scripts/run_cart_pole_observer.py", str(CONFIG),
            "--disturbance", "200:1", "--output", str(output)]
    environment = dict(os.environ, PYTHONUTF8="1")
    process = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                             env=environment, check=False)
    assert process.returncode == 0, process.stderr+process.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["goal_met"] and report["effective_options"]["disturbances"] == [[200,1]]
    assert report["provenance"]["code_version"] and len(report["design"]["source_snapshots"]) == 3
    repeated = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                              env=environment, check=False)
    assert repeated.returncode == 1 and 'FileExistsError' in repeated.stdout
    bad = subprocess.run(args[:-4]+["--disturbance", "400:1", "--output", str(tmp_path/"bad.json")],
                         cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                         env=environment, check=False)
    assert bad.returncode == 1 and not (tmp_path/"bad.json").exists()


def test_cli_source_change_rejected(design, tmp_path, monkeypatch):
    """统一编译之后源字节变更，不能发布与运行来源不一致的报告。"""
    for filename in ("cart_pole_plant.yaml", "cart_pole_balance.yaml", "cart_pole_observer.yaml"):
        (tmp_path/filename).write_bytes((ROOT/"configs"/filename).read_bytes())
    spec = importlib.util.spec_from_file_location("observer_cli_test", ROOT/"scripts/run_cart_pole_observer.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.run_observer_balance_experiment
    def changed(loaded, **kwargs):
        result = original(loaded, **kwargs)
        with (tmp_path/"cart_pole_plant.yaml").open("a", encoding="utf-8") as stream:
            stream.write("\n# changed\n")
        return result

    monkeypatch.setattr(module, "run_observer_balance_experiment", changed)
    monkeypatch.setattr("sys.argv", ["run", str(tmp_path/"cart_pole_observer.yaml"),
                                     "--output", str(tmp_path/"out.json")])
    assert module.main() == 1 and not (tmp_path/"out.json").exists()


@pytest.mark.parametrize("bad", [MeasurementSample(0,0,0,0), MeasurementSample(2,.04,0,0),
                                MeasurementSample(1,.03,0,0), MeasurementSample(1,.02,0,0,(True,False)),
                                MeasurementSample(1,.02,0,.21), None])
def test_post_commit_missing_or_bad_sample_preserves_only_trusted_prefix(design, bad):
    """一次物理确认后下个测量失效，不复用旧值、不多发力、不制造第2个观测。"""
    sim = CartPoleObserverSimulation(CartPolePlant(design.plant), design.plant)
    calls = []
    class Device:
        def read_measurement(self):
            return sim.read_measurement() if not calls else bad

        def send_control(self, command):
            calls.append(command)
            return sim.send_control(command)

    result = run_observer_balance_experiment(design, device=Device(),
                                             truth_provider=sim.read_diagnostic_truth,
                                             force_evidence=sim.read_interval_forces)
    assert result.completed_steps == len(calls) == 1 and len(result.sample_ids) == 1
    assert not result.goal_met and result.estimate.shape == (1,4)
    assert result.failure_step == 1 and result.failure_reason == "measurement"
    assert result.to_report()["attempted"] is None


@pytest.mark.parametrize("bad", ["identity", "applied", "source", "none"])
def test_completed_receipt_must_match_command_and_force_source(design, bad):
    """名为完成的错误回执也不能转换成成功前缀，来源和身份都要确认。"""
    class Device:
        def read_measurement(self):
            return MeasurementSample(0,0,0,.03)

        def send_control(self, cmd):
            if bad == "none":
                return None
            return ActuationReceipt(cmd.command_id+(bad == "identity"), cmd.episode_id, cmd.sample_id,
                                    "simulated_interval_completed",
                                    cmd.target_force_n+(bad == "applied"),
                                    "ACK" if bad == "source" else "canonical_simulation")

    result = run_observer_balance_experiment(design, device=Device(),
                                             truth_provider=lambda: np.array([0,0,.03,0]),
                                             force_evidence=lambda: pytest.fail("坏回执不读完成力"))
    assert result.termination == "uncertain" and result.completed_steps == 0
    assert len(result.time_s) == 1 and not result.goal_met


@pytest.mark.parametrize("events", [((400,1),), ((1,1),(1,-1)), ((2,1),(1,-1)),
                                   ((True,1),), ((1.,1),), ((0,True),), ((0,2),), ((0,float("nan")),)])
def test_illegal_event_and_bad_seed_startup_rejection(design, events):
    """非法运行参数在读测量/发送之前拒绝；源参数与探索覆盖都保持严格类型。"""
    with pytest.raises((TypeError, ValueError)):
        run_observer_balance_experiment(design, disturbances=events)
    with pytest.raises((TypeError, ValueError)):
        run_observer_balance_experiment(design, velocity_seed=(True,0))


def test_actual_simulation_atomic_track_failure_and_no_resend(design):
    """真实canonical RK4中间越轨不提交任何plant状态；回执不得伪装区间完成。"""
    contract = replace(design.plant, initial_state=(.499,1,0,0))
    plant = CartPolePlant(contract)
    sim = CartPoleObserverSimulation(plant, contract)
    before = plant.state.copy()
    with pytest.raises(ValueError, match="track_center_limit_m"):
        sim.send_control(ControlCommand(0,"track",0,0))
    np.testing.assert_array_equal(plant.state, before)
    with pytest.raises(RuntimeError, match="终止"):
        sim.send_control(ControlCommand(0,"track",0,0))
    with pytest.raises(ValueError, match="没有"):
        sim.read_interval_forces()


def test_simulation_consumes_live_interval_requests_but_keeps_future_events(design):
    class ConstantPlant:
        def __init__(self):
            self.completed = 0
            self.last_force = None

        def output(self):
            return np.zeros(4)

        def step(self, force):
            self.completed += 1
            self.last_force = float(force[0])
            return self.output()

    plant = ConstantPlant()
    sim = CartPoleObserverSimulation(plant, design.plant, ((2003, 1.),))
    for step in range(2001):
        force = 1. if step % 2 else -1.
        sim.request_disturbance(step, force)
        receipt = sim.send_control(ControlCommand(step, "live", step, 0.))
        assert receipt.disposition == "simulated_interval_completed"
        assert sim.read_interval_forces() == (force, force, force, "accepted")
        assert sim._scheduled == {2003: 1.}
    sim.request_disturbance(2001, 1.)
    sim.send_control(ControlCommand(2001, "live", 2001,
                                    design.plant.max_applied_force_n))
    requested, actual, total, disposition = sim.read_interval_forces()
    assert requested == 1. and actual == 0.
    assert total == design.plant.max_applied_force_n
    assert disposition == "rejected_total_force_limit"
    assert sim._scheduled == {2003: 1.}
    assert plant.completed == 2002 and plant.last_force == total


@pytest.mark.parametrize("output", [np.array([np.inf]), np.array([np.nan]), np.array([1,2]), np.array([True])])
def test_runtime_failure_ends_episode_and_does_not_reinitialize(design, output):
    """数值/shape失败不重复step或读取秘密state，后续必须显式新episode。"""
    class BadRuntime:
        def step(self, sample):
            return output

    sample = MeasurementSample(0,0,0,.03)
    episode = ObserverBalanceEpisode(design.initialize(sample), BadRuntime(), episode_id="numeric")
    with pytest.raises((ValueError, TypeError, FloatingPointError)):
        episode.step(sample)
    assert not episode.active
    with pytest.raises(RuntimeError):
        episode.step(sample)


def test_safe_and_stable_monitor_gates_use_exact_canonical_thresholds(design):
    """理想监督复用原门禁，safe/stable等号合法，邻接浮点不扩大阈值。"""
    for safe_value, expected in ((.6, "time_limit"), (np.nextafter(.6,np.inf), "failed")):
        config = replace(design.config, initial_error_abs=(0,1,0,1))
        short = build_cart_pole_observer_design(design.plant, replace(design.balance,horizon_steps=1),config)
        class Device:
            def read_measurement(self):
                return MeasurementSample(0,0,0,0)

            def send_control(self, command):
                return ActuationReceipt(0,"finite-0",0,"rejected",None,"unconfirmed")

        result = run_observer_balance_experiment(short, device=Device(),
                                                 truth_provider=lambda value=safe_value: np.array([0,value,0,0]),
                                                 force_evidence=lambda: pytest.fail("no interval"))
        assert result.failure_reason == ("outside_safe_domain" if expected == "failed" else "actuation_rejected")
    from secure_control.scenarios.cart_pole import BalanceMonitor

    for value, count in ((.03,1),(np.nextafter(.03,np.inf),0)):
        monitor = BalanceMonitor(design.balance)
        monitor.observe(np.array([0,value,0,0]))
        assert monitor.stable_count == count
