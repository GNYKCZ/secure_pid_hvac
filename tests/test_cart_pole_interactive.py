"""#93：外力归属、双支确定性重放与正式 v2 倒立摆证据。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pytest
from scipy.integrate import solve_ivp
from test_cart_pole_balance import ORACLE_K, _oracle_rhs
from test_cart_pole_lan import _SECOND_ROUND_DISCONNECT, _profile_for, _QuantizedLqrRuntime
from test_lan_continuous import _finish, _plain_deployment, _run

from secure_control.experiments import cart_pole_evidence
from secure_control.experiments.artifacts import _write_artifacts, write_artifacts
from secure_control.experiments.cart_pole_evidence import (
    EVIDENCE_NAME,
    MOTION_MANIFEST_NAME,
    MOTION_NAME,
    load_verified_cart_pole_run,
    verify_cart_pole_evidence,
)
from secure_control.experiments.cart_pole_lan_profile import load_cart_pole_lan_profile
from secure_control.experiments.lan_continuous_profile import load_interactive_cart_pole_experiment
from secure_control.experiments.plotting import write_control_triptych
from secure_control.scenarios.cart_pole.interactive import (
    DisturbedCartPolePlant,
    InteractiveSession,
)
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_experiment import CartPoleSecureExperiment

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "configs" / "cart_pole_lan.example.yaml"


def _oracle_with_pulse(initial: tuple[float, ...]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """#91 的独立 CTMS 隐式方程与 DOP853，只在 k=200 添加物理外力。"""
    state = np.array(initial, dtype=float)
    states = [state.copy()]
    applied: list[float] = []
    statuses: list[str] = []
    count = 0
    for step in range(401):
        count = count + 1 if np.all(np.abs(state) <= [.02, .03, .02, .05]) else 0
        statuses.append("stable" if count >= 51 else "recovering")
        assert np.all(np.abs(state) <= [.45, .6, .20, 1.0])
        if step == 400:
            break
        control = float(np.clip(-ORACLE_K @ state, -10, 10))
        applied.append(control)
        disturbance = 1.0 if step == 200 else 0.0
        solved = solve_ivp(_oracle_rhs, (0, .02), state, args=(control + disturbance,),
                           method="DOP853", rtol=1e-13, atol=1e-15)
        assert solved.success
        state = solved.y[:, -1]
        states.append(state.copy())
    return np.array(states), np.array(applied), statuses


def test_scheduled_pulse_replays_both_branches_and_v2_artifact(tmp_path: Path) -> None:
    frames: list[dict[str, object]] = []
    session = InteractiveSession(
        scheduled={200: 1.0},
        notify=lambda kind, value: frames.append(value) if kind == "frame" else None,
    )
    prepared = load_interactive_cart_pole_experiment(PROFILE, session)
    profile = load_cart_pole_lan_profile(PROFILE)
    plan = prepared.build_plan(_QuantizedLqrRuntime(profile))
    assert plan.ideal.plant is not plan.secure.plant
    assert plan.ideal.adapter is not plan.secure.adapter
    assert prepared.execute_plan is not None
    result = prepared.execute_plan(plan)
    prepared.validate_result(result)
    assert len(frames) == 400
    assert [frame["step"] for frame in frames] == list(range(1, 401))
    assert frames[200]["disturbance_force_n"] == 1.0
    assert frames[199]["disturbance_force_n"] == 0.0
    assert frames[-1]["status"] == "stable"
    states, applied, statuses = _oracle_with_pulse(profile.plant.initial_state)
    np.testing.assert_allclose(result.output_ideal, states[:-1], atol=3e-8, rtol=0)
    np.testing.assert_allclose(result.output_secure, states[:-1], atol=4e-8, rtol=0)
    np.testing.assert_allclose(result.control_ideal[:, 0], applied, atol=3e-8, rtol=0)
    np.testing.assert_allclose(result.control_secure[:, 0], applied, atol=9e-8, rtol=0)
    assert statuses[201] == "recovering" and statuses[-1] == "stable"
    np.testing.assert_allclose(frames[200]["state"], states[201], atol=4e-8, rtol=0)

    def derived(record, stage):
        return (write_control_triptych(record, stage, 0)
                + prepared.write_scenario_evidence(record, stage))

    artifact = _write_artifacts(
        result, plan.metadata, prepared.effective_config,
        {"scenario_name": "cart_pole", "scenario_version": "2", "schema_version": 1},
        output_root=tmp_path / "runs", derived_writer=derived,
        publication_guard=session.publication_guard,
    )
    record, sidecar = load_verified_cart_pole_run(artifact.run_dir)
    session.close()
    assert load_verified_cart_pole_run(artifact.run_dir)[0].run_id == artifact.run_id
    assert sidecar["schema_version"] == 2
    assert sidecar["events"] == [{
        "step": 200, "force_n": 1.0, "duration_steps": 1,
        "phase": "after_controller_commit_before_plant_step",
    }]
    assert sidecar["disturbance_force_n"][200] == 1.0
    assert sidecar["branches"]["ideal"]["statuses"] == statuses
    assert sidecar["branches"]["secure"]["statuses"] == statuses
    assert (artifact.run_dir / MOTION_NAME).is_file()
    assert (artifact.run_dir / MOTION_MANIFEST_NAME).is_file()
    np.testing.assert_allclose(record.result.control_secure, result.control_secure)

    original = (artifact.run_dir / EVIDENCE_NAME).read_text(encoding="utf-8")
    for mutate in (
        lambda data: data["events"][0].update({"step": 199}),
        lambda data: data["events"][0].update({"force_n": -1.0}),
        lambda data: data.update({"schema_version": 1}),
        lambda data: data["disturbance_force_n"].__setitem__(200, 0.0),
        lambda data: data["branches"]["secure"]["statuses"].__setitem__(201, "stable"),
    ):
        changed = json.loads(original)
        mutate(changed)
        (artifact.run_dir / EVIDENCE_NAME).write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises((ValueError, AssertionError)):
            verify_cart_pole_evidence(record, artifact.run_dir)
    (artifact.run_dir / EVIDENCE_NAME).write_text(original, encoding="utf-8")
    (artifact.run_dir / MOTION_NAME).write_bytes(b"altered")
    with pytest.raises(ValueError):
        load_verified_cart_pole_run(artifact.run_dir)


def test_queue_rejection_and_cancel_before_step() -> None:
    session = InteractiveSession()
    assert all(session.request(1.0) for _ in range(8))
    assert not session.request(1.0)
    assert session.take(7) == 1.0
    session.close()
    assert not session.request(-1.0)
    with pytest.raises(ValueError):
        session.request(0.5)
    finished = InteractiveSession()
    assert finished.request(1.0)
    finished.stop_accepting()
    assert not finished.request(1.0)
    assert finished.take(0) == 0.0


def test_total_force_request_rejected_without_clipping() -> None:
    profile = load_cart_pole_lan_profile(PROFILE)
    scenario = CartPoleSecureExperiment(profile.plant, profile.balance, profile.spec)
    notices: list[tuple[str, object]] = []
    session = InteractiveSession(notify=lambda kind, value: notices.append((kind, value)))
    plant = DisturbedCartPolePlant(CartPolePlant(profile.plant), scenario, session=session)
    assert session.request(1.0)
    plant.step(np.array([profile.plant.max_applied_force_n]))
    assert plant.forces == [0.0]
    assert ("rejected", {"step": 0, "reason": "total_force_limit"}) in notices


def test_motion_plot_failure_leaves_no_success_run(tmp_path: Path, monkeypatch) -> None:
    profile = load_cart_pole_lan_profile(PROFILE)
    session = InteractiveSession(scheduled={200: 1.0})
    prepared = load_interactive_cart_pole_experiment(PROFILE, session)
    plan = prepared.build_plan(_QuantizedLqrRuntime(profile))
    assert prepared.execute_plan is not None
    result = prepared.execute_plan(plan)
    prepared.validate_result(result)

    def fail_plot(*_args):
        raise RuntimeError("injected motion plot failure")

    monkeypatch.setattr(cart_pole_evidence, "_write_motion_plot", fail_plot)
    output_root = tmp_path / "runs"
    with pytest.raises(RuntimeError, match="injected motion plot failure"):
        write_artifacts(
            result, plan.metadata, prepared.effective_config,
            {"scenario_name": "cart_pole", "scenario_version": "2", "schema_version": 1},
            output_root=output_root,
            derived_writer=lambda record, stage: prepared.write_scenario_evidence(record, stage),
        )
    assert not list(output_root.glob("*/metadata.json"))


_CLIENT = r"""
import json
import sys
from pathlib import Path
from secure_control.experiments import artifacts
from secure_control.execution.lan_config import load_lan_config
from secure_control.experiments.lan_continuous_profile import load_interactive_cart_pole_experiment
from secure_control.experiments.lan_runner import _run_prepared_client
from secure_control.scenarios.cart_pole.interactive import InteractiveSession

mode = sys.argv[2]
def notify(kind, value):
    if mode == 'cancel' and kind == 'frame' and value['step'] == 10:
        session.close()
session = InteractiveSession(scheduled={200: 1.0}, notify=notify)
if mode == 'late_cancel':
    original_digest = artifacts._digest
    def cancel_during_derived_digest(path):
        if path.name == 'cart_pole_evidence.json':
            session.close()
        return original_digest(path)
    artifacts._digest = cancel_during_derived_digest
config = load_lan_config(Path(sys.argv[1]), 'Client')
prepared = load_interactive_cart_pole_experiment(config.experiment_config, session)
try:
    result = _run_prepared_client(
        config, prepared, cancelled=session.cancelled,
        publication_guard=session.publication_guard,
    )
except Exception:
    print(json.dumps({'status': 'failed'}))
    raise SystemExit(1)
print(json.dumps(result))
"""


@pytest.mark.parametrize("mode", ["complete", "cancel", "late_cancel"])
def test_interactive_three_processes_and_cancel(tmp_path: Path, mode: str) -> None:
    """P1/P2 为独立真实进程，交互 Client 仍走唯一 runner 与会话资源门禁。"""
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        client = subprocess.Popen(
            [sys.executable, "-c", _CLIENT, str(paths["Client"]), mode],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        code, result, errors = _finish(client, 600)
        if mode in ("cancel", "late_cancel"):
            assert code != 0 and result["status"] == "failed", errors
            assert not list((tmp_path / "runs").glob("*/metadata.json"))
            return
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 600) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert result["status"] == "complete"
        assert result["resource_counts"] == {
            "products_consumed": 1600, "truncations_consumed": 0,
        }
        record, sidecar = load_verified_cart_pole_run(result["run_dir"])
        assert len(record.provenance["confirmed_steps"]) == 400
        assert all(item["status"] == "double_committed"
                   for item in record.provenance["confirmed_steps"])
        assert sidecar["events"][0]["step"] == 200
        assert sidecar["branches"]["secure"]["statuses"][-1] == "stable"
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_interactive_disconnect_has_no_success_run(tmp_path: Path) -> None:
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    captured = tmp_path / "failed-session.txt"
    p1 = subprocess.Popen(
        [sys.executable, "-c", _SECOND_ROUND_DISCONNECT, str(captured), str(paths["P1"])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p2 = _run("P2", paths["P2"])
    try:
        time.sleep(.5)
        client = subprocess.Popen(
            [sys.executable, "-c", _CLIENT, str(paths["Client"]), "complete"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        code, result, _ = _finish(client, 30)
        assert code != 0 and result["status"] == "failed"
        assert captured.is_file() and captured.read_text(encoding="utf-8")
        assert not list((tmp_path / "runs").glob("*/metadata.json"))
    finally:
        for party in (p1, p2):
            if party.poll() is None:
                party.kill()
            party.communicate()
