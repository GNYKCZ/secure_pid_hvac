"""#103 固定非线性门在真实 Client/P1/P2 进程中的有限回归。"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import time
import tkinter as tk
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest
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
from secure_control.scenarios.cart_pole.gui import FullRouteWindow
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


def test_v3_codec_sends_topology_without_secret_constants():
    _, _, modulus, evidence, program, _ = _inputs()
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


def test_real_three_process_scalar_gates_and_double_commit(tmp_path):
    paths = _plain_deployment(tmp_path)
    client_source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(
        client_source.replace(
            "experiment: paper_pid_lan.example.yaml",
            f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
        ), encoding="utf-8",
    )
    design, swing, modulus, evidence, program, certificate = _inputs()
    parties = [
        subprocess.Popen(
            [sys.executable, "-c", _PARTY, role, str(paths[role])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for role in ("P1", "P2")
    ]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_v3_unknown_commit_burns_round_and_refuses_retry(tmp_path, monkeypatch):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    _, _, modulus, evidence, program, certificate = _inputs()
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_secure_full_boundary_track_failure_keeps_only_confirmed_prefix(tmp_path):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_v3_scalar_to_secret_observer_to_new_scalar_epoch(tmp_path):
    paths = _plain_deployment(tmp_path)
    client_source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(
        client_source.replace(
            "experiment: paper_pid_lan.example.yaml",
            f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
        ), encoding="utf-8",
    )
    design, _, modulus, evidence, program, proof = _inputs()
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", _PARTY, role, str(paths[role])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) for role in ("P1", "P2")
    ]
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
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_secure_full_real_process_kick_to_energy(tmp_path):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance,
            replace(swing, horizon_steps=16, acquisition_deadline_steps=16,
                    disturbances=()),
            design, load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence,
        )
        assert result.physical.completed_steps == 16, result.physical.failure_detail
        assert result.physical.failure_observation_step == 16
        assert [row["phase"] for row in result.epoch_events] == ["kick", "energy"]
        assert result.protocol_products == result.protocol_truncations == 6 * 38
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_full_run(result, tmp_path / "v3-short")
        )
        assert verified.manifest["N"] == 16
        folder = verified.path
        original_manifest = json.loads((folder / "run.json").read_text(encoding="utf-8"))
        original_physical = json.loads((folder / "physical.json").read_text(encoding="utf-8"))
        original_steps = [json.loads(line) for line in
                          (folder / "steps.jsonl").read_text(encoding="utf-8").splitlines()]
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
            altered_physical = copy.deepcopy(original_physical)
            altered_manifest = copy.deepcopy(original_manifest)
            if field == "manifest.status":
                altered_manifest["status"] = value
            elif field.startswith("summary."):
                altered_physical["summary"][field.split(".", 1)[1]] = value
            else:
                altered_physical[field] = value
            raw = _bytes(altered_physical)
            (folder / "physical.json").write_bytes(raw)
            altered_manifest["physical_sha256"] = hashlib.sha256(raw).hexdigest()
            (folder / "run.json").write_bytes(_bytes(altered_manifest))
            with pytest.raises(ValueError, match="v3"):
                open_verified_cart_pole_full_run(folder)
        (folder / "physical.json").write_bytes(_bytes(original_physical))
        (folder / "run.json").write_bytes(_bytes(original_manifest))
        for field, replacement in (("source", "plaintext_energy"),
                                   ("epoch_id", "old-epoch"),
                                   ("raw_force_n", 100.0)):
            altered = copy.deepcopy(original_steps)
            altered[10][field] = replacement
            raw = b"".join(_bytes(row) for row in altered)
            (folder / "steps.jsonl").write_bytes(raw)
            manifest = copy.deepcopy(original_manifest)
            manifest["steps_sha256"] = hashlib.sha256(raw).hexdigest()
            (folder / "run.json").write_bytes(_bytes(manifest))
            with pytest.raises(ValueError):
                open_verified_cart_pole_full_run(folder)
        (folder / "steps.jsonl").write_bytes(b"".join(_bytes(row) for row in original_steps))
        for field, replacement in (("fractional_bits", 32), ("program_sha256", "0" * 64)):
            manifest = copy.deepcopy(original_manifest)
            manifest["epochs"][1][field] = replacement
            (folder / "run.json").write_bytes(_bytes(manifest))
            with pytest.raises(ValueError):
                open_verified_cart_pole_full_run(folder)
        manifest = copy.deepcopy(original_manifest)
        manifest["epochs"][0]["closed_segments"][0]["receipts"][1]["committed_steps"] += 1
        (folder / "run.json").write_bytes(_bytes(manifest))
        with pytest.raises(ValueError, match="回执"):
            open_verified_cart_pole_full_run(folder)
        (folder / "run.json").write_bytes(_bytes(original_manifest))
        assert open_verified_cart_pole_full_run(folder).manifest["N"] == 16
        failed_physical = replace(
            result.physical, termination="failed", goal_met=False,
            failure_interval_step=16, failure_reason="protocol_or_control",
            failure_detail="injected_after_sealed_kick",
        )
        unsealed_epochs = [copy.deepcopy(row) for row in result.epoch_events]
        unsealed_epochs[-1]["closed_segments"] = []
        failed = replace(
            result, physical=failed_physical, epoch_events=tuple(unsealed_epochs),
            unconfirmed_protocol_step=16,
        )
        # 此合成记录同时声称 k=16 的观测失败和区间失败，且 k=16 已是 horizon。
        with pytest.raises(ValueError, match="同时声明"):
            write_cart_pole_full_run(failed, tmp_path / "impossible-prefix")
        assert not (tmp_path / "impossible-prefix").exists()
        for process in parties:
            out, err = process.communicate(timeout=20)
            assert process.returncode == 0, (out, err)
    finally:
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_secure_full_real_unsealed_interval_keeps_only_receipted_prefix(tmp_path, monkeypatch):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    original_step = LanScalarRuntime.step

    def disconnect_before_round(runtime, values, physical_step):
        if physical_step == 16:
            raise OSError("injected unsealed round failure")
        return original_step(runtime, values, physical_step)

    monkeypatch.setattr(LanScalarRuntime, "step", disconnect_before_round)
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_secure_full_real_unsealed_switch_failure_keeps_receipted_prefix(
    tmp_path, monkeypatch,
):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    original_end = LanScalarRuntime.end

    def fail_energy_switch(runtime, action="stop"):
        if runtime.epoch_id.startswith("energy-") and action == "switch":
            raise OSError("injected unsealed energy switch failure")
        return original_end(runtime, action)

    monkeypatch.setattr(LanScalarRuntime, "end", fail_energy_switch)
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
    try:
        result = run_secure_full_experiment(
            design.plant, design.balance, swing, design,
            load_lan_config(paths["Client"], "Client"),
            modulus=modulus, modulus_evidence=evidence,
        )
        assert result.physical.completed_steps == 309
        assert result.physical.failure_reason == "setup_or_switch"
        assert result.physical.failure_observation_step is None
        assert result.physical.failure_interval_step is None
        assert result.epoch_events[0]["closed_segments"][-1]["action"] == "switch"
        assert not result.epoch_events[1]["closed_segments"]
        verified = open_verified_cart_pole_full_run(
            write_cart_pole_full_run(result, tmp_path / "unsealed-switch-failure")
        )
        assert verified.manifest["N"] == 10
        assert verified.manifest["status"] == "failed_prefix"
        assert verified.report["unsealed_failure"]["physical_steps_before_failure"] == 309
    finally:
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


@pytest.mark.parametrize("next_phase, sealed_steps", [("energy", 10), ("dynamic", 309)])
def test_secure_full_switch_setup_failure_publishes_receipted_prefix(
    tmp_path, monkeypatch, next_phase, sealed_steps,
):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


@pytest.mark.parametrize("direction", [1, -1])
def test_secure_full_real_process_capture_and_long_secret_epoch(tmp_path, direction):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_secure_full_real_process_nominal_stable_horizon(tmp_path):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    design, swing, modulus, evidence, _, _ = _inputs()
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
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
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)


def test_actual_tk_secure_full_route_uses_three_processes(tmp_path):
    paths = _plain_deployment(tmp_path)
    source = paths["Client"].read_text(encoding="utf-8")
    paths["Client"].write_text(source.replace(
        "experiment: paper_pid_lan.example.yaml",
        f"experiment: {ROOT / 'configs/paper_pid_lan.example.yaml'}",
    ), encoding="utf-8")
    swing_source = (ROOT / "configs/cart_pole_swing_up.yaml").read_text(encoding="utf-8")
    swing_source = swing_source.replace("horizon_steps: 1500", "horizon_steps: 16")
    swing_source = swing_source.replace("acquisition_deadline_steps: 600",
                                        "acquisition_deadline_steps: 16")
    swing_source = swing_source.replace("plant_source: cart_pole_plant.yaml",
                                        f"plant_source: {ROOT / 'configs/cart_pole_plant.yaml'}")
    swing_source = swing_source.replace("balance_source: cart_pole_balance.yaml",
                                        f"balance_source: {ROOT / 'configs/cart_pole_balance.yaml'}")
    swing_file = tmp_path / "swing-short.yaml"
    swing_file.write_text(swing_source, encoding="utf-8")
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
    root = tk.Tk()
    window = FullRouteWindow(
        root, route="secure", client_path=paths["Client"],
        observer_path=ROOT / "configs/cart_pole_observer.yaml",
        swing_path=swing_file,
        prime_path=ROOT / "configs/shared_prime_256_pocklington.yaml",
        output=tmp_path / "gui-secure-v3", segment_steps=8,
    )
    outcome = []
    deadline = time.monotonic() + 30

    def check():
        if window.verified is not None:
            window._seek("12")
            outcome.append((window.verified.manifest["N"], window.detail.get()))
            window._close()
        elif window.status.get().startswith("运行/发布失败") or time.monotonic() >= deadline:
            outcome.append(("failed", window.status.get()))
            window._close()
        else:
            root.after(50, check)

    try:
        window.start()
        root.after(50, check)
        root.mainloop()
        window.worker.join(timeout=5)
        assert outcome and outcome[0][0] == 16, outcome
        assert "source=secure_energy_gates" in outcome[0][1]
        for process in parties:
            out, err = process.communicate(timeout=20)
            assert process.returncode == 0, (out, err)
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
        for process in parties:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)
