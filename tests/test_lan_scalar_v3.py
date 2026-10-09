"""#103 固定非线性门在真实 Client/P1/P2 进程中的有限回归。"""

from __future__ import annotations

import copy
import hashlib
import sys
from dataclasses import fields, replace
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest
from lan_test_support import reap_processes, start_processes
from test_lan_continuous import _plain_deployment

from secure_control.execution import lan_scalar_runtime as scalar_runtime_module
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import LanSegmentedRuntime, RunControl
from secure_control.execution.lan_scalar_runtime import LanScalarRuntime
from secure_control.execution.localhost_codec import (
    LocalhostCodecError,
    ScalarFrameV3,
    ScalarSetupV3,
    decode_scalar_frame_v3,
    encode_scalar_frame_v3,
)
from secure_control.experiments.cart_pole_full_evidence import (
    open_verified_cart_pole_full_run,
    write_cart_pole_full_run,
)
from secure_control.experiments.cart_pole_segmented_evidence import _bytes
from secure_control.experiments.lan_profile import _load_prime
from secure_control.protocol.arithmetic import ScalarProgram, certify_scalar_program
from secure_control.scenarios.cart_pole import secure_full_experiment as secure_full_module
from secure_control.scenarios.cart_pole.adapter import MeasurementSample
from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
from secure_control.scenarios.cart_pole.secure_experiment import (
    sustained_observer_numeric_contract,
)
from secure_control.scenarios.cart_pole.secure_full_experiment import run_secure_full_experiment
from secure_control.scenarios.cart_pole.swing_up import (
    energy_shaping_force,
    load_cart_pole_swing_up_config,
)
from secure_control.scenarios.cart_pole.swing_up_numeric import certify_swing_up_arithmetic

ROOT = Path(__file__).resolve().parents[1]
_PARTY = """
import json, sys
from pathlib import Path
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import run_party_single_step
result = run_party_single_step(load_lan_config(Path(sys.argv[2]), sys.argv[1]))
print(json.dumps(result))
"""


def _inputs():
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(
        ROOT / "configs/cart_pole_swing_up.yaml", design.plant, design.balance,
    )
    modulus, evidence, _ = _load_prime(
        ROOT / "configs/shared_prime_256_pocklington.yaml"
    )
    program, certificate = certify_swing_up_arithmetic(
        design.plant, design.balance, swing, modulus=modulus,
        modulus_evidence=evidence,
    )
    return design, swing, modulus, evidence, program, certificate


@pytest.fixture(scope="module")
def scalar_inputs():
    """只共享公开 canonical 设计/证明；数组由不可写 bytes 持有。"""
    design, *rest = _inputs()
    arrays = {field.name: np.frombuffer(value.tobytes(), dtype=value.dtype).reshape(value.shape)
              for field in fields(design)
              if isinstance(value := getattr(design, field.name), np.ndarray)}
    return replace(design, **arrays), *rest


def test_v3_codec_sends_topology_without_secret_constants(scalar_inputs):
    _, _, modulus, evidence, program, _ = scalar_inputs
    frame = ScalarFrameV3(
        "Client", "P1", "run", "epoch", "session", 0, 0, None, None,
        "setup", ScalarSetupV3(program, modulus, 80, 80, evidence),
    )
    encoded = encode_scalar_frame_v3(frame)
    decoded = decode_scalar_frame_v3(encoded)
    assert decoded.payload.program.topology_sha256() == program.topology_sha256()
    assert all(value == 0 for _, value in decoded.payload.program.constants)
    with pytest.raises(LocalhostCodecError):
        encode_scalar_frame_v3(ScalarFrameV3(
            "P1", "Client", "run", "epoch", "session", 0, 0, None, None,
            "setup", frame.payload,
        ))
    with pytest.raises(LocalhostCodecError):
        decode_scalar_frame_v3(encoded.replace(b'"physical_step":0', b'"physical_step":-1'))


@pytest.mark.integration
def test_real_three_process_scalar_gates_and_double_commit(tmp_path, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    design, swing, modulus, evidence, program, certificate = scalar_inputs
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    try:
        client = load_lan_config(paths["Client"], "Client")
        kick_program = ScalarProgram(("kick",), (), (), "kick")
        kick_proof = certify_scalar_program(
            kick_program, {"kick": Fraction(1)}, modulus=modulus,
            fractional_bits=80, security_parameter=80,
            modulus_evidence=evidence,
        )
        kick = LanScalarRuntime(
            client, kick_program, kick_proof, modulus=modulus,
            modulus_evidence=evidence, run_id="issue103-test-run",
            epoch_id="kick-epoch", start_physical_step=0,
        )
        for step in range(2):
            receipt = kick.step({"kick": 1.}, step)
            assert receipt.output == 1. and receipt.products == receipt.truncations == 0
        kick.end("switch")
        runtime = LanScalarRuntime(
            client, program, certificate, modulus=modulus,
            modulus_evidence=evidence, run_id="issue103-test-run",
            epoch_id="issue103-test-epoch", start_physical_step=2,
        )
        for step, values in enumerate((
            {"p": .2, "v": -.4, "beta": .31, "omega": 1.7},
            {"p": -.1, "v": .8, "beta": -1.45, "omega": -4.2},
        )):
            receipt = runtime.step(values, step + 2)
            expected = energy_shaping_force(
                design.plant, swing,
                (values["p"], values["v"], values["beta"], values["omega"]),
            )
            assert receipt.products == receipt.truncations == 38
            assert len(set(receipt.resource_ids)) == 38
            assert abs(receipt.output - expected) < 5e-8
        runtime.end()
        for process in parties:
            out, err = process.communicate(timeout=20)
            assert process.returncode == 0, (out, err)
            assert '"steps_committed": 2' in out
            assert '"products": 76' in out
    finally:
        reap_processes(parties)


@pytest.mark.integration
def test_v3_unknown_commit_burns_round_and_refuses_retry(tmp_path, monkeypatch, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    _, _, modulus, evidence, program, certificate = scalar_inputs
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    try:
        runtime = LanScalarRuntime(
            load_lan_config(paths["Client"], "Client"), program, certificate,
            modulus=modulus, modulus_evidence=evidence,
            run_id="issue103-unknown-commit", epoch_id="first",
            start_physical_step=0,
        )
        receive = scalar_runtime_module._receive

        def drop_commit(sock, expected, deadline):
            if expected.operation == "committed":
                raise TimeoutError("injected_unknown_commit")
            return receive(sock, expected, deadline)

        monkeypatch.setattr(scalar_runtime_module, "_receive", drop_commit)
        values = {"p": .1, "v": 0., "beta": 2., "omega": .5}
        with pytest.raises(TimeoutError, match="injected_unknown_commit"):
            runtime.step(values, 0)
        assert runtime.local_step == 0
        assert len(runtime._spent) == 38
        with pytest.raises(RuntimeError):
            runtime.step(values, 0)
        with pytest.raises(RuntimeError):
            runtime.end()
    finally:
        reap_processes(parties)


@pytest.mark.integration
def test_secure_full_boundary_track_failure_keeps_only_confirmed_prefix(tmp_path, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    design, swing, modulus, evidence, _, _ = scalar_inputs
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance,
            replace(swing, initial_state=(.5, 3., 0., 0.),
                    horizon_steps=16, acquisition_deadline_steps=16),
            design, load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence,
        )
        assert result.physical.completed_steps == 0
        assert result.physical.failure_reason == "track_limit"
        assert result.unconfirmed_protocol_step == 0
        with pytest.raises(ValueError, match="双方密封"):
            write_cart_pole_full_run(result, tmp_path / "should-not-publish")
        assert not (tmp_path / "should-not-publish").exists()
    finally:
        reap_processes(parties)


@pytest.mark.integration
def test_v3_scalar_to_secret_observer_to_new_scalar_epoch(tmp_path, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    design, _, modulus, evidence, program, proof = scalar_inputs
    processes = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])] for role in ("P1", "P2")
    ])
    try:
        client = load_lan_config(paths["Client"], "Client")
        first = LanScalarRuntime(
            client, program, proof, modulus=modulus, modulus_evidence=evidence,
            run_id="issue103-epoch-test", epoch_id="swing-first",
            start_physical_step=0,
        )
        first.step({"p": .1, "v": 0., "beta": 2., "omega": .5}, 0)
        first_session = first.session_id
        first.end("switch")
        init = design.initialize(
            MeasurementSample(0, 0., 0., .1), velocity_seed=(0., 0.),
        )
        fixed, contract, _ = sustained_observer_numeric_contract(
            init, fractional_bits=32, parameter_bits=40,
            runtime_payload_bits=46, modulus=modulus,
        )
        dynamic = LanSegmentedRuntime(
            client, init.spec, fixed, contract, 80, evidence,
            control=RunControl(), segment_capacity=2,
            full_run_id="issue103-epoch-test",
            previous_epoch_session=first_session,
        )
        for _ in range(2):
            identity = dynamic.step(np.array([0., .1]))
            assert identity is not None
            dynamic.confirm_applied(identity)
        dynamic_session = dynamic._segment.session_id
        assert dynamic.controller_epoch != "swing-first"
        record = dynamic.end_segment(switch_epoch=True)
        assert record.receipts[0].end.action == "switch"
        assert dynamic.phase == "SWITCHED"
        second = LanScalarRuntime(
            client, program, proof, modulus=modulus, modulus_evidence=evidence,
            run_id="issue103-epoch-test", epoch_id="swing-again",
            start_physical_step=3,
        )
        assert second.session_id != dynamic_session
        receipt = second.step({"p": -.1, "v": .1, "beta": 2.2, "omega": -.5}, 3)
        assert receipt.products == 38
        second.end()
        for process in processes:
            out, err = process.communicate(timeout=20)
            assert process.returncode == 0, (out, err)
            assert '"steps_committed": 1' in out
    finally:
        reap_processes(processes)


@pytest.mark.integration
def test_secure_full_real_unsealed_interval_keeps_only_receipted_prefix(tmp_path, monkeypatch, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    design, swing, modulus, evidence, _, _ = scalar_inputs
    original_step = LanScalarRuntime.step

    def disconnect_before_round(runtime, values, physical_step):
        if physical_step == 16:
            raise OSError("injected unsealed round failure")
        return original_step(runtime, values, physical_step)

    monkeypatch.setattr(LanScalarRuntime, "step", disconnect_before_round)
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance,
            replace(swing, horizon_steps=20, acquisition_deadline_steps=20),
            design, load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence,
        )
        assert result.physical.completed_steps == 16
        assert result.physical.failure_observation_step is None
        assert result.physical.failure_interval_step == 16
        assert result.unconfirmed_protocol_step == 16
        assert [row["phase"] for row in result.epoch_events] == ["kick", "energy"]
        assert result.epoch_events[0]["closed_segments"][-1]["action"] == "switch"
        assert not result.epoch_events[1]["closed_segments"]
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_full_run(result, tmp_path / "real-sealed-prefix")
        )
        assert verified.manifest["N"] == 10
        assert verified.manifest["status"] == "failed_prefix"
        assert verified.report["unsealed_failure"]["physical_steps_before_failure"] == 16
    finally:
        reap_processes(parties)


@pytest.mark.parametrize("next_phase, sealed_steps", [("energy", 10), ("dynamic", 309)])
@pytest.mark.integration
def test_secure_full_switch_setup_failure_publishes_receipted_prefix(
    tmp_path, monkeypatch, next_phase, sealed_steps, scalar_inputs,
):
    paths = _plain_deployment(tmp_path)
    design, swing, modulus, evidence, _, _ = scalar_inputs
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    if next_phase == "energy":
        original = secure_full_module.LanScalarRuntime

        def fail_energy(*args, **kwargs):
            if kwargs["epoch_id"].startswith("energy-"):
                raise OSError("injected energy setup failure")
            return original(*args, **kwargs)

        monkeypatch.setattr(secure_full_module, "LanScalarRuntime", fail_energy)
    else:
        def fail_dynamic(*_args, **_kwargs):
            raise OSError("injected dynamic setup failure")

        monkeypatch.setattr(secure_full_module, "LanSegmentedRuntime", fail_dynamic)
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance, swing, design,
            load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence,
        )
        assert result.physical.completed_steps == sealed_steps
        assert result.physical.termination == "failed"
        assert result.physical.failure_reason == "setup_or_switch"
        assert result.physical.failure_observation_step is None
        assert result.physical.failure_interval_step is None
        assert result.physical.attempted_step is None
        assert result.unconfirmed_protocol_step is None
        closure = result.epoch_events[-1]["closed_segments"][-1]
        assert closure["action"] == "switch" and closure["physical_end"] == sealed_steps
        assert [item["role"] for item in closure["receipts"]] == ["P1", "P2"]
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_full_run(result, tmp_path / "sealed-switch-failure")
        )
        assert verified.manifest["N"] == sealed_steps
        assert verified.manifest["status"] == "failed_prefix"
        assert verified.report["failure"]["reason"] == "setup_or_switch"

        missing_receipt = copy.deepcopy(result.epoch_events)
        missing_receipt[-1]["closed_segments"][-1]["receipts"].pop()
        with pytest.raises(ValueError, match="回执"):
            write_cart_pole_full_run(
                replace(result, epoch_events=tuple(missing_receipt)),
                tmp_path / "missing-switch-receipt",
            )
        assert not (tmp_path / "missing-switch-receipt").exists()
    finally:
        reap_processes(parties)


@pytest.mark.parametrize("direction", [-1])
@pytest.mark.integration
@pytest.mark.stress
def test_secure_full_real_process_capture_and_long_secret_epoch(tmp_path, direction, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    design, swing, modulus, evidence, _, _ = scalar_inputs
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance,
            replace(swing, kick_direction=direction, horizon_steps=450,
                    acquisition_deadline_steps=450),
            design, load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence, segment_capacity=16,
        )
        assert result.physical.completed_steps == 450, (
            result.physical.failure_reason, result.physical.failure_detail,
        )
        assert len(result.steps) == 450
        assert [row["phase"] for row in result.epoch_events] == [
            "kick", "energy", "dynamic",
        ]
        assert sum(row["source"] == "secure_dynamic_observer" for row in result.steps) > 100
        assert result.protocol_products > 38 * 200
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_full_run(result, tmp_path / "v3-long")
        )
        assert verified.observation(309)["phase"] == "capture"
        for process in parties:
            out, err = process.communicate(timeout=20)
            assert process.returncode == 0, (out, err)
    finally:
        reap_processes(parties)


@pytest.mark.integration
@pytest.mark.stress
def test_secure_full_real_process_nominal_stable_horizon(tmp_path, scalar_inputs):
    paths = _plain_deployment(tmp_path)
    design, swing, modulus, evidence, _, _ = scalar_inputs
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role])]
        for role in ("P1", "P2")
    ])
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance, swing, design,
            load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence, segment_capacity=100,
        )
        assert result.physical.completed_steps == 1500, result.physical.failure_detail
        assert result.physical.goal_met
        assert result.physical.termination == "observed_success"
        assert result.physical.first_stable_step is not None
        assert result.physical.first_stable_step > 309
        assert result.protocol_products > 10_000
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_full_run(result, tmp_path / "secure-nominal")
        )
        assert verified.manifest["status"] == "complete"
        assert verified.manifest["N"] == 1500
        physical = copy.deepcopy(verified.report)
        physical["termination"] = "failed"
        physical["goal_met"] = False
        physical["failure"] = {
            "observation_step": None, "interval_step": 1500,
            "reason": "protocol_or_control", "detail": "invented terminal round",
        }
        raw = _bytes(physical)
        (verified.path / "physical.json").write_bytes(raw)
        manifest = copy.deepcopy(verified.manifest)
        manifest["status"] = "failed_prefix"
        manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
        (verified.path / "run.json").write_bytes(_bytes(manifest))
        with pytest.raises(ValueError, match="v3"):
            open_verified_cart_pole_full_run(verified.path)
        invented_unsealed = copy.deepcopy(verified.report)
        invented_unsealed["termination"] = "failed"
        invented_unsealed["goal_met"] = False
        invented_unsealed["failure"] = {
            "observation_step": None, "interval_step": None,
            "reason": "setup_or_switch", "detail": "invented unsealed tail",
        }
        invented_unsealed["unsealed_failure"] = {
            "physical_steps_before_failure": 1500, "first_unsealed_step": 1500,
            "attempted_step": None, "unconfirmed_protocol_step": None,
        }
        raw = _bytes(invented_unsealed)
        (verified.path / "physical.json").write_bytes(raw)
        manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
        (verified.path / "run.json").write_bytes(_bytes(manifest))
        with pytest.raises(ValueError, match="v3"):
            open_verified_cart_pole_full_run(verified.path)
        for process in parties:
            out, err = process.communicate(timeout=20)
            assert process.returncode == 0, (out, err)
    finally:
        reap_processes(parties)


def test_shared_scalar_inputs_are_immutable_and_instances_stay_independent(scalar_inputs):
    """共享对象图无活状态，initialize 每次仍产生独立 controller x0。"""
    design, swing, modulus, evidence, program, certificate = scalar_inputs
    for field in fields(design):
        value = getattr(design, field.name)
        if isinstance(value, np.ndarray):
            with pytest.raises(ValueError):
                value.setflags(write=True)
            with pytest.raises(ValueError):
                value.flat[0] = 42
    with pytest.raises((AttributeError, TypeError)):
        swing.horizon_steps = 1
    assert isinstance(program.constants, tuple) and isinstance(program.gates, tuple)
    assert isinstance(certificate.bounds, tuple) and isinstance(certificate.multiplication_bounds, tuple)
    assert evidence.certificate.candidate == modulus
    first = design.initialize(MeasurementSample(0, 0., 0., .005))
    second = design.initialize(MeasurementSample(0, 0., 0., .005))
    assert first.spec is not second.spec
    assert not np.shares_memory(first.spec.x0, second.spec.x0)
