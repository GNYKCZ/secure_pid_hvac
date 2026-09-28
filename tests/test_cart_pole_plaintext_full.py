"""#103 明文完整路线：独立非线性/observer oracle 与阶段重入边界。"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from math import pi
from pathlib import Path
from threading import Event

import numpy as np
import pytest
from scipy.integrate import solve_ivp
from test_cart_pole_balance import ORACLE_K, _oracle_rhs
from test_cart_pole_observer import ORACLE_L, independent_model

from secure_control.experiments.cart_pole_full_evidence import (
    open_verified_cart_pole_full_run,
    write_cart_pole_plaintext_full_run,
)
from secure_control.experiments.cart_pole_segmented_evidence import _bytes
from secure_control.scenarios.cart_pole.adapter import MeasurementSample
from secure_control.scenarios.cart_pole.observer import (
    build_cart_pole_observer_design,
    load_cart_pole_observer_design,
)
from secure_control.scenarios.cart_pole.swing_up import (
    CausalVelocityEstimator,
    SwingUpSupervisor,
    load_cart_pole_swing_up_config,
)
from secure_control.scenarios.cart_pole.swing_up_experiment import run_plaintext_full_experiment

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/cart_pole_swing_up.yaml"


def test_plaintext_full_v3_verified_reader(tmp_path):
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(CONFIG, design.plant, design.balance)
    result = run_plaintext_full_experiment(design.plant, design.balance, swing, design)
    verified = open_verified_cart_pole_full_run(
        write_cart_pole_plaintext_full_run(result, tmp_path / "plain-v3")
    )
    assert verified.manifest["N"] == 1500
    assert verified.manifest["resource_counts"] == {
        "beaver_triples": 0, "truncations": 0,
    }
    assert verified.observation(309)["phase"] == "capture"
    physical = json.loads((verified.path / "physical.json").read_text(encoding="utf-8"))
    manifest = json.loads((verified.path / "run.json").read_text(encoding="utf-8"))
    for field, value in (
        ("goal_met", False),
        ("termination", "time_limit"),
        ("failure", {"observation_step": None, "interval_step": None,
                     "reason": "protocol_or_control", "detail": "invented"}),
    ):
        altered = copy.deepcopy(physical)
        altered[field] = value
        raw = _bytes(altered)
        (verified.path / "physical.json").write_bytes(raw)
        updated_manifest = copy.deepcopy(manifest)
        updated_manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
        (verified.path / "run.json").write_bytes(_bytes(updated_manifest))
        with pytest.raises(ValueError, match="v3"):
            open_verified_cart_pole_full_run(verified.path)
    invented_failure = copy.deepcopy(physical)
    invented_failure["termination"] = "failed"
    invented_failure["goal_met"] = False
    invented_failure["failure"]["reason"] = "setup_or_switch"
    raw = _bytes(invented_failure)
    (verified.path / "physical.json").write_bytes(raw)
    updated_manifest = copy.deepcopy(manifest)
    updated_manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
    updated_manifest["status"] = "failed_prefix"
    (verified.path / "run.json").write_bytes(_bytes(updated_manifest))
    with pytest.raises(ValueError, match="v3"):
        open_verified_cart_pole_full_run(verified.path)
    invented_unsealed = copy.deepcopy(physical)
    invented_unsealed["termination"] = "failed"
    invented_unsealed["goal_met"] = False
    invented_unsealed["failure"] = {
        "observation_step": None, "interval_step": None,
        "reason": "protocol_or_control", "detail": "invented unsealed tail",
    }
    invented_unsealed["unsealed_failure"] = {
        "physical_steps_before_failure": 1500, "first_unsealed_step": 1500,
        "attempted_step": None, "unconfirmed_protocol_step": None,
    }
    raw = _bytes(invented_unsealed)
    (verified.path / "physical.json").write_bytes(raw)
    updated_manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
    (verified.path / "run.json").write_bytes(_bytes(updated_manifest))
    with pytest.raises(ValueError, match="v3"):
        open_verified_cart_pole_full_run(verified.path)
    impossible_interval = copy.deepcopy(physical)
    impossible_interval["termination"] = "failed"
    impossible_interval["goal_met"] = False
    impossible_interval["failure"] = {
        "observation_step": None, "interval_step": 1500,
        "reason": "numeric_control", "detail": "invented terminal control",
    }
    raw = _bytes(impossible_interval)
    (verified.path / "physical.json").write_bytes(raw)
    updated_manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
    (verified.path / "run.json").write_bytes(_bytes(updated_manifest))
    with pytest.raises(ValueError, match="v3"):
        open_verified_cart_pole_full_run(verified.path)


def test_plaintext_v3_reader_accepts_confirmed_stop_prefix(tmp_path):
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(CONFIG, design.plant, design.balance)
    stop = Event()

    def after_step(step, *_args):
        if step == 5:
            stop.set()

    result = run_plaintext_full_experiment(
        design.plant, design.balance, swing, design,
        on_step=after_step, stop_event=stop,
    )
    assert result.completed_steps == 5 and result.termination == "stopped"
    verified = open_verified_cart_pole_full_run(
        write_cart_pole_plaintext_full_run(result, tmp_path / "plain-stopped")
    )
    assert verified.manifest["N"] == 5
    assert verified.report["termination"] == "stopped"
    physical = copy.deepcopy(verified.report)
    physical["termination"] = "failed"
    physical["goal_met"] = False
    physical["failure"] = {
        "observation_step": None, "interval_step": 5,
        "reason": "numeric_control", "detail": "invented unobserved control",
    }
    raw = _bytes(physical)
    (verified.path / "physical.json").write_bytes(raw)
    manifest = copy.deepcopy(verified.manifest)
    manifest["status"] = "failed_prefix"
    manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
    (verified.path / "run.json").write_bytes(_bytes(manifest))
    with pytest.raises(ValueError, match="v3"):
        open_verified_cart_pole_full_run(verified.path)


def test_plaintext_v3_reader_accepts_time_limit_and_failed_interval(tmp_path):
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(CONFIG, design.plant, design.balance)
    cases = (
        (replace(swing, horizon_steps=320, acquisition_deadline_steps=320), "time_limit"),
        (replace(swing, initial_state=(.49, 0., pi, 0.)), "failed"),
    )
    for index, (config, termination) in enumerate(cases):
        result = run_plaintext_full_experiment(design.plant, design.balance, config, design)
        assert result.termination == termination
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_plaintext_full_run(result, tmp_path / f"plain-prefix-{index}")
        )
        assert verified.report["termination"] == termination
        assert verified.manifest["N"] == result.completed_steps


def test_plaintext_v3_reader_rejects_rehashed_false_outcomes(tmp_path):
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(CONFIG, design.plant, design.balance)
    short = replace(swing, horizon_steps=16, acquisition_deadline_steps=16)
    result = run_plaintext_full_experiment(design.plant, design.balance, short, design)
    assert result.termination == "failed" and not result.goal_met
    path = write_cart_pole_plaintext_full_run(result, tmp_path / "plain-failed")
    physical = json.loads((path / "physical.json").read_text(encoding="utf-8"))
    manifest = json.loads((path / "run.json").read_text(encoding="utf-8"))
    assert open_verified_cart_pole_full_run(path).report["goal_met"] is False

    for field, value in (
        ("goal_met", True),
        ("termination", "observed_success"),
        ("failure", {"observation_step": None, "interval_step": None,
                     "reason": None, "detail": None}),
        ("summary.first_stable_step", 16),
        ("summary.stable_entry_steps", [16]),
        ("summary.final_stable_count", 99),
        ("manifest.status", "complete"),
    ):
        altered = copy.deepcopy(physical)
        altered_manifest = copy.deepcopy(manifest)
        if field == "manifest.status":
            altered_manifest["status"] = value
        elif field.startswith("summary."):
            altered["summary"][field.split(".", 1)[1]] = value
        else:
            altered[field] = value
        raw = _bytes(altered)
        (path / "physical.json").write_bytes(raw)
        altered_manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
        (path / "run.json").write_bytes(_bytes(altered_manifest))
        with pytest.raises(ValueError, match="v3"):
            open_verified_cart_pole_full_run(path)


@pytest.fixture(scope="module")
def inputs():
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    config = load_cart_pole_swing_up_config(CONFIG, design.plant, design.balance)
    return design, config


def test_causal_two_measurement_differences_keep_continuous_angle_and_identity():
    estimator = CausalVelocityEstimator(.02)
    values = [
        MeasurementSample(0, 0., 0., 3 * pi),
        MeasurementSample(1, .02, .02, 3 * pi + .04),
        MeasurementSample(2, .04, .08, 3 * pi + .12),
    ]
    np.testing.assert_allclose(estimator.observe(values[0]), [0, 0, 3 * pi, 0], atol=0)
    np.testing.assert_allclose(estimator.observe(values[1]), [.02, 1, 3 * pi + .04, 2], atol=1e-13)
    np.testing.assert_allclose(estimator.observe(values[2]), [.08, 4, 3 * pi + .12, 5], atol=1e-13)
    assert len(estimator._previous) == 2
    for bad in (values[2], MeasurementSample(3, .07, .1, 3 * pi),
                MeasurementSample(3, .06, .1, 3 * pi, (False, True))):
        with pytest.raises(ValueError):
            estimator.observe(bad)
    assert estimator.next_step == 3


def _independent_full_route(direction: int, pulse: tuple[int, float] | None):
    """自身积分的双测量闭环；不调用生产 plant、阶段机、估计器或控制输出。"""
    _, _, ap, bp = independent_model()
    truth = np.array([0., 0., pi, 0.])
    history = []
    phase, stable_count, capture_count, capture_step = "swing_up", 0, 0, None
    observer = None
    theta_star = None
    states, estimates, raws, sources, observer_before, transitions = [], [], [], [], [], []
    for step in range(1501):
        y = truth[[0, 2]].copy()
        if step == 0:
            v, omega = 0., 0.
        elif step == 1:
            v, omega = (y - history[-1]) / .02
        else:
            v, omega = (3 * y - 4 * history[-1] + history[-2]) / .04
        history = [*history[-1:], y]
        estimated = np.array([y[0], v, y[1], omega])
        alpha = (y[1] + pi) % (2 * pi) - pi
        local = np.array([y[0], v, alpha, omega])
        if phase == "swing_up" and step >= 10 and np.all(abs(local) <= [.35, .5, .15, .8]) and alpha * omega <= 0:
            phase, capture_step, capture_count, stable_count = "capture", step, 0, 0
            theta_star = 2 * pi * int(np.floor((y[1] + pi) / (2 * pi)))
            observer = np.array([y[0], v, y[1] - theta_star, omega])
            transitions.append((step, "capture"))
        if phase in ("capture", "balance"):
            assert np.all(abs(local) <= [.45, .6, .2, 1.])
            stable_count = stable_count + 1 if np.all(abs(local) <= [.02, .03, .02, .05]) else 0
            if phase == "capture":
                capture_count = capture_count + 1 if np.all(abs(local) <= [.35, .5, .15, .8]) else 0
                if capture_count == 3:
                    phase = "balance"
                    transitions.append((step, "balance"))
                else:
                    assert step - capture_step < 100
        assert abs(y[0]) <= .5 and abs(v) <= 3 and abs(omega) <= 15
        states.append(truth.copy())
        estimates.append(estimated)
        if step == 1500:
            break
        if phase in ("capture", "balance"):
            source = "plaintext_dynamic_observer"
            observer_before.append(observer.copy())
            raw = float(-ORACLE_K @ observer)
            measured = np.array([y[0], y[1] - theta_star])
            observer = ap @ observer + bp * raw + ORACLE_L @ (measured - observer[[0, 2]])
        elif step < 10:
            source, raw = "plaintext_kick", float(direction)
            observer_before.append(None)
        else:
            source = "plaintext_energy"
            observer_before.append(None)
            p, velocity, theta, angular = estimated
            error = .012 * angular**2 + .588 * np.cos(theta) - .588
            acceleration = -8 * error * angular * np.cos(theta) - 16 * p - 8 * velocity
            raw = ((.7 - .15 * np.cos(theta)**2) * acceleration + .1 * velocity
                   + .06 * angular**2 * np.sin(theta) - 1.47 * np.sin(theta) * np.cos(theta))
        applied = float(np.clip(raw, -10., 10.))
        actual = pulse[1] if pulse is not None and step == pulse[0] else 0.
        if abs(applied + actual) > 10:
            actual = 0.
        solved = solve_ivp(_oracle_rhs, (0., .02), truth, args=(applied + actual,),
                           method="DOP853", rtol=1e-12, atol=1e-14)
        assert solved.success
        truth = solved.y[:, -1]
        raws.append(raw)
        sources.append(source)
    assert phase == "balance" and stable_count >= 51
    return (np.array(states), np.array(estimates), np.array(raws), sources,
            observer_before, transitions)


@pytest.mark.parametrize("direction,pulse", [
    (1, None), (-1, None), (1, (600, 1.)), (-1, (600, -1.)),
])
def test_full_route_matches_independent_closed_loop(inputs, direction, pulse):
    design, config = inputs
    config = replace(config, kick_direction=direction,
                     disturbances=() if pulse is None else (pulse,))
    result = run_plaintext_full_experiment(design.plant, design.balance, config, design)
    states, estimates, raws, sources, observer_before, transitions = _independent_full_route(direction, pulse)
    assert result.goal_met and result.completed_steps == 1500
    assert [(item.observation_step, item.to_phase) for item in result.transitions] == transitions
    assert transitions == [(309, "capture"), (311, "balance")]
    assert np.all(np.max(abs(result.state - states), axis=0) <= [5e-8, 2e-7, 1e-6, 2e-6])
    np.testing.assert_allclose(result.estimated_state, estimates, rtol=0, atol=3e-6)
    np.testing.assert_allclose(result.raw_force[:, 0], raws, rtol=0, atol=1e-5)
    assert list(result.controller_source) == sources
    for actual, expected in zip(result.observer_state_before, observer_before, strict=True):
        if expected is None:
            assert actual is None
        else:
            np.testing.assert_allclose(actual, expected, rtol=0, atol=3e-6)
    assert result.observer_initializations[0][0] == 309
    np.testing.assert_allclose(result.observer_initializations[0][3], result.estimated_state[309]
                               - [0, 0, result.observer_initializations[0][2], 0], atol=1e-12)
    report = result.to_report()
    assert report["kind"] == "cart_pole_plaintext_full"
    assert report["resource_counts"] == {"beaver_triples": 0, "truncations": 0}
    assert len(report["measurement"]) == 1501 and len(report["controller_source"]) == 1500
    assert report["summary"]["saturated_intervals"] == 7
    assert report["summary"]["stable_entry_steps"] == ([480] if pulse is None else [480, 682])
    assert max(abs(result.estimated_state[:, 1] - result.state[:, 1])) > 0
    if pulse is not None:
        assert result.disturbance_events == ((600, pulse[1], pulse[1], "accepted"),)


def test_dynamic_capture_exit_discards_observer_and_restarts_after_dwell(inputs):
    design, config = inputs
    effective = replace(design.plant, initial_state=config.initial_state)
    supervisor = SwingUpSupervisor(effective, design.balance, config, observer_design=design)
    for step in range(10):
        assert supervisor.observe(step, [0, 0, pi, 0]).phase == "swing_up"
    for step in range(10, 13):
        assert supervisor.observe(step, [0, 0, .1, -.1]).phase == (
            "capture" if step < 12 else "balance")
        supervisor.raw_force(step, [0, 0, .1, -.1])
    previous = supervisor.runtime
    assert supervisor.observe(13, [0, 0, .21, 0]).phase == "swing_up"
    assert supervisor.runtime is None and supervisor.episode is None
    assert supervisor.capture_attempt == 0 and supervisor.acquisition_started == 13
    for step in range(14, 18):
        assert supervisor.observe(step, [0, 0, .1, -.1]).phase == "swing_up"
    assert supervisor.observe(18, [0, 0, .1, -.1]).phase == "capture"
    assert supervisor.runtime is not previous and len(supervisor.initializations) == 2
    assert supervisor.raw_force(18, [0, 0, .1, -.1]) == pytest.approx(
        float(-ORACLE_K @ [0, 0, .1, -.1]), abs=1e-10)
    assert supervisor.observe(19, [.51, 0, .1, 0]).failure_reason == "track_limit"


def test_dynamic_capture_boundary_jitter_does_not_initialize_early(inputs):
    design, config = inputs
    effective = replace(design.plant, initial_state=config.initial_state)
    supervisor = SwingUpSupervisor(effective, design.balance, config, observer_design=design)
    for step in range(10):
        supervisor.observe(step, [0, 0, pi, 0])
    outside = np.nextafter(config.capture_enter_abs[2], np.inf)
    assert supervisor.observe(10, [0, 0, outside, -.1]).phase == "swing_up"
    assert not supervisor.initializations
    assert supervisor.observe(11, [0, 0, config.capture_enter_abs[2], -.1]).phase == "capture"
    assert len(supervisor.initializations) == 1


def test_capture_timeout_reentry_budget_and_initial_error(inputs):
    design, config = inputs
    config = replace(config, capture_timeout_steps=2, capture_max_attempts=1)
    effective = replace(design.plant, initial_state=config.initial_state)
    supervisor = SwingUpSupervisor(effective, design.balance, config, observer_design=design)
    for step in range(10):
        supervisor.observe(step, [0, 0, pi, 0])
    assert supervisor.observe(10, [0, 0, .1, -.1]).phase == "capture"
    supervisor.raw_force(10, [0, 0, .1, -.1])
    assert supervisor.observe(11, [.36, 0, .1, 0]).phase == "capture"
    assert supervisor.observe(12, [.36, 0, .1, 0]).phase == "swing_up"
    for step in range(13, 17):
        supervisor.observe(step, [0, 0, .1, -.1])
    assert supervisor.observe(17, [0, 0, .1, -.1]).failure_reason == "capture_attempts_exhausted"

    perturbed = replace(inputs[1], initial_state=(0., .02, pi, .03))
    result = run_plaintext_full_experiment(design.plant, design.balance, perturbed, design)
    assert result.goal_met and result.first_stable_step == 468
    np.testing.assert_array_equal(result.estimated_state[0], [0, 0, pi, 0])
    np.testing.assert_array_equal(result.state[0], [0, .02, pi, .03])


@pytest.mark.parametrize("angle", [pi - .01, pi + .01])
def test_small_drooping_angle_errors_reach_dynamic_balance(inputs, angle):
    design, config = inputs
    changed = replace(config, initial_state=(0., 0., angle, 0.))
    result = run_plaintext_full_experiment(design.plant, design.balance, changed, design)
    assert result.goal_met and result.completed_steps == 1500
    assert [event.to_phase for event in result.transitions] == ["capture", "balance"]
    branch = result.observer_initializations[0][1]
    assert branch in (0, 1)
    assert abs(result.state[-1, 2] - 2 * pi * branch) < 1e-8


def test_real_track_speed_and_rejected_disturbance_boundaries(inputs):
    design, config = inputs
    track = run_plaintext_full_experiment(
        design.plant, design.balance, replace(config, initial_state=(.49, 0., pi, 0.)), design)
    assert track.termination == "failed" and track.failure_reason == "track_limit"
    assert track.completed_steps == 5 and track.failure_interval_step == 5
    assert len(track.state) == 6 and len(track.raw_force) == 5
    speed = run_plaintext_full_experiment(
        design.plant, design.balance, replace(config, max_cart_speed_m_per_s=.01), design)
    assert speed.termination == "failed" and speed.failure_reason == "overspeed"
    assert speed.completed_steps == 1 and speed.failure_observation_step == 1
    rejected = run_plaintext_full_experiment(
        design.plant, design.balance, replace(config, disturbances=((28, -1.),)), design)
    assert rejected.goal_met
    assert rejected.disturbance_events == ((28, -1., 0., "rejected_total_force_limit"),)
    assert rejected.applied_force[28, 0] == rejected.total_force[28, 0] == -10.
    assert rejected.disturbance_force[28, 0] == 0.


def test_changed_physical_parameter_rederives_observer_and_rejects_stale_design(inputs):
    design, config = inputs
    changed_plant = replace(design.plant, cart_mass_kg=.6)
    effective = replace(changed_plant, initial_state=config.initial_state)
    with pytest.raises(ValueError, match="来源不一致"):
        SwingUpSupervisor(effective, design.balance, config, observer_design=design)
    rebuilt = build_cart_pole_observer_design(changed_plant, design.balance, design.config)
    assert not np.array_equal(rebuilt.K, design.K)
    supervisor = SwingUpSupervisor(effective, design.balance, config, observer_design=rebuilt)
    for step in range(10):
        supervisor.observe(step, [0, 0, pi, 0])
    assert supervisor.observe(10, [0, 0, .1, -.1]).phase == "capture"
    np.testing.assert_allclose(supervisor.runtime.spec.C, -rebuilt.K, atol=0)


def test_cli_plaintext_full_source_snapshot_and_no_overwrite(inputs, tmp_path):
    output = tmp_path / "full.json"
    command = [sys.executable, "scripts/run_cart_pole_swing_up.py", str(CONFIG),
               "--route", "plaintext_full", "--direction", "-1", "--output", str(output)]
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert process.returncode == 0, process.stdout + process.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["goal_met"] and report["route"] == "plaintext_full"
    assert len(report["provenance"]["source_snapshots"]) == 4
    assert report["observer_initializations"][0]["branch"] == 0
    previous = output.read_bytes()
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert process.returncode != 0 and output.read_bytes() == previous
