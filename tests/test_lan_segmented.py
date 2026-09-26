"""#100：真实角色、段链、停止竞争和持续物理前缀的回归门禁。"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace

import numpy as np
import pytest
import yaml
from scipy.integrate import solve_ivp
from test_cart_pole_balance import ORACLE_K, _oracle_rhs
from test_cart_pole_lan import PROFILE, ROOT, _profile_for
from test_lan_continuous import _plain_deployment
from test_lan_single_step import _finish
from test_lan_single_step import deployment as _tls_deployment

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import lan_runtime
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import LanSegmentedRuntime, RunControl
from secure_control.execution.localhost_codec import (
    SCHEMA_VERSION,
    LanSegmentedHelloPayload,
    LocalhostCodecError,
    SegmentEndPayload,
    SegmentEndReceipt,
    WireEnvelope,
    decode_envelope,
    decode_wire_value,
    encode_envelope,
    encode_wire_value,
)
from secure_control.execution.localhost_transport import LocalhostTransportDisconnected
from secure_control.experiments.cart_pole_lan_profile import load_cart_pole_lan_profile
from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
from secure_control.protocol import ControllerRangeContract
from secure_control.scenarios.cart_pole.interactive import InteractiveSession

_PARTY = r"""
import json, sys, time
from dataclasses import asdict
from pathlib import Path
from secure_control.execution import lan_runtime as lan
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.localhost_codec import PartyOfflineMaterial
fault = sys.argv[3]
original = lan.send_envelope
ready_count = 0
def send(sock, message, **kwargs):
    global ready_count
    if message.kind == 'reply' and message.sender == 'P2':
        if message.operation == 'lan_ready':
            ready_count += 1
            if fault == 'next_timeout' and ready_count == 2:
                time.sleep(6)
        if fault == 'step_timeout' and message.operation == 'online':
            time.sleep(1)
        if fault == 'commit_lost' and message.operation == 'endpoint' and message.payload is None:
            # Only the commit response is after a stage response, not another endpoint command.
            if send.staged:
                sock.close()
                raise RuntimeError('injected lost commit')
        if message.operation == 'endpoint' and message.payload is not None:
            send.staged = True
        if fault in ('end_lost', 'shutdown_timeout') and message.operation == 'segment_end':
            if fault == 'shutdown_timeout':
                time.sleep(2)
            sock.close()
            raise RuntimeError('injected lost segment receipt')
    return original(sock, message, **kwargs)
send.staged = False
lan.send_envelope = send
if fault == 'peer_disconnect':
    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    def broken_peer(self, *args):
        self.close()
        raise RuntimeError('injected peer disconnect')
    LocalhostProtocol3PeerPort._send = broken_peer
try:
    result = lan.run_party_single_step(load_lan_config(Path(sys.argv[2]), sys.argv[1]))
except Exception as error:
    print(json.dumps({'status':'failed', 'category':type(error).__name__}))
    raise SystemExit(1)
print(json.dumps(result))
"""

_CLIENT = r"""
import gc, json, sys, time, weakref
from dataclasses import asdict, replace
from pathlib import Path
import numpy as np
from secure_control.execution import lan_runtime as lan
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution._localhost_workers import _ClientPartyEndpoint
from secure_control.experiments.lan_runner import run_client_segmented
from secure_control.protocol import Client
from secure_control.scenarios.cart_pole.interactive import InteractiveSession
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_experiment import SustainedCartPoleExperiment
config = load_lan_config(Path(sys.argv[1]), 'Client')
mode, count, capacity = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
control = lan.RunControl()
session = InteractiveSession(scheduled={capacity-1:1.0, capacity:-1.0})
frames, segments, refs, peaks = [], [], [], []
connect = lan.LanSegmentedRuntime._connect
def connected(self):
    if mode == 'tls_identity' and self.segment_index == 1:
        other = load_lan_config(Path(sys.argv[5]), 'P1')
        self.config = replace(self.config, certificate=other.certificate, private_key=other.private_key)
    connect(self)
    refs.append(weakref.ref(self._segment))
    gc.collect()
    peaks.append(sum(ref() is not None for ref in refs))
    if mode == 'zero' or (mode == 'next_handshake' and self.segment_index == 1):
        control.request_stop()
    if mode == 'idle_timeout':
        time.sleep(1)
lan.LanSegmentedRuntime._connect = connected
command = _ClientPartyEndpoint._command
def cmd(self, operation, *args):
    result = command(self, operation, *args)
    if mode == 'stage' and operation == 'stage_output':
        control.request_stop()
    if mode == 'commit_p1' and operation == 'commit' and self.party == 0:
        control.request_stop()
    if mode == 'commit_p2' and operation == 'commit' and self.party == 1:
        control.request_stop()
    return result
_ClientPartyEndpoint._command = cmd
reconstruct = Client.reconstruct_control
def rebuilt(self, *args, **kwargs):
    result = reconstruct(self, *args, **kwargs)
    if mode == 'reconstruct':
        control.request_stop()
    return result
Client.reconstruct_control = rebuilt
request = lan._request
def requested(*args, **kwargs):
    result = request(*args, **kwargs)
    if mode in ('p1_disconnect', 'p2_disconnect') and args[3] == 'online':
        if args[1] == ('P1' if mode == 'p1_disconnect' else 'P2'):
            args[0].close()
    if mode == 'online' and args[3] == 'online':
        control.request_stop()
    return result
lan._request = requested
send = lan.send_envelope
def sent(sock, message, **kwargs):
    if mode == 'bad_end_count' and message.operation == 'segment_end':
        end = message.payload
        message = replace(message,payload=replace(end,confirmed_count=end.confirmed_count+1,
                                                global_end_exclusive=end.global_end_exclusive+1))
    return send(sock,message,**kwargs)
lan.send_envelope = sent
receive = lan.receive_envelope
def received(*args, **kwargs):
    result = receive(*args, **kwargs)
    if mode == 'between_end_receipts' and result.operation == 'segment_end':
        control.request_stop()
    if mode == 'cancel_during_end' and result.operation == 'segment_end':
        session.close()
    return result
lan.receive_envelope = received
hello = lan._hello
def greeted(sock, sender, recipient, session_id, payload, timeout):
    if mode == 'bad_chain' and payload.segment_index == 1:
        payload = replace(payload, global_start=payload.global_start+1)
    return hello(sock,sender,recipient,session_id,payload,timeout)
lan._hello = greeted
advance = SustainedCartPoleExperiment.advance
def advanced(self, *args):
    if mode == 'plant_before':
        control.request_stop()
    if mode == 'cancel':
        session.close()
    return advance(self,*args)
SustainedCartPoleExperiment.advance = advanced
plant_step = CartPolePlant.step
def physical(self, *args):
    if mode == 'plant_error':
        raise ValueError('injected plant failure')
    if mode == 'shape':
        return np.zeros(3)
    if mode == 'nonfinite':
        return np.array([0.,0.,float('nan'),0.])
    if mode == 'outside':
        return np.array([1.,0.,0.,0.])
    return plant_step(self,*args)
CartPolePlant.step = physical
def on_step(record):
    frames.append(asdict(record))
    assert not session.cancelled.is_set()
    if mode == 'record_error':
        raise RuntimeError('record sink failed')
    if len(frames) == count:
        control.request_stop()
def on_segment(segment):
    segments.append(asdict(segment))
    if mode == 'after_continue':
        control.request_stop()
result = run_client_segmented(config, segment_steps=capacity, control=control,
                              session=session, on_step=on_step, on_segment=on_segment)
print(json.dumps({'result':result,'frames':frames,'segments':segments,'live_segments':peaks}))
"""

_SCRIPT_CLIENT = r"""
import contextlib, io, json, runpy, signal, sys
from pathlib import Path
from secure_control.experiments import lan_runner
original = lan_runner.run_client_segmented
def worker(config, **kwargs):
    def stop_at_five(record):
        if record.protocol.global_step == 4:
            signal.raise_signal(signal.SIGINT)
    return original(config, **kwargs, on_step=stop_at_five)
lan_runner.run_client_segmented = worker
config = sys.argv[1]
sys.argv = ['run_cart_pole_client.py', config, '--headless-continuous', '--segment-steps', '3']
output = io.StringIO()
with contextlib.redirect_stdout(output):
    try:
        runpy.run_path('scripts/run_cart_pole_client.py', run_name='__main__')
    except SystemExit as error:
        assert error.code == 0, error.code
assert 'tkinter' not in sys.modules
print(json.dumps({'result':json.loads(output.getvalue())}))
"""


def _three(tmp_path, mode="normal", count=7, capacity=3, transport="insecure_tcp",
           fault="none"):
    paths = (_plain_deployment(tmp_path) if transport == "insecure_tcp"
             else _tls_deployment.__wrapped__(tmp_path))
    profile = _profile_for(paths)
    if transport == "mutual_tls":
        client = yaml.safe_load(paths["Client"].read_text(encoding="utf-8"))
        client.pop("controller", None)
        client["experiment"] = str(profile)
        paths["Client"].write_text(yaml.safe_dump(client), encoding="utf-8")
    # Short deterministic fault deadlines; no phase guessed from a sleep.
    if fault in ("shutdown_timeout", "step_timeout", "next_timeout") or mode == "idle_timeout":
        for path in (paths["P1"], paths["P2"], paths["Client"]):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            key = {"shutdown_timeout":"shutdown", "step_timeout":"step",
                   "next_timeout":"startup"}.get(fault, "idle")
            data["timeouts"][key] = .25 if key != "startup" else 5
            path.write_text(yaml.safe_dump(data), encoding="utf-8")
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role]), fault],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
    try:
        client = subprocess.Popen(
            [sys.executable, "-c", _SCRIPT_CLIENT if mode == "script" else _CLIENT,
             str(paths["Client"]), mode, str(count), str(capacity),
             str(paths["P1"])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        code, report, errors = _finish(client, 100)
        assert code == 0, (report, errors)
        if report["result"]["status"] == "stopped":
            outcomes = [_finish(party, 30) for party in parties]
            assert all(item[0] == 0 for item in outcomes), outcomes
            assert len({report["result"]["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
            assert all(item[1]["steps_committed"] == report["result"]["confirmed_step_count"]
                       for item in outcomes)
        assert not list(tmp_path.glob("runs/*/metadata.json"))
        return report
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


@pytest.mark.parametrize("transport", ["insecure_tcp", "mutual_tls"])
def test_three_processes_1001_steps_preserve_state_monitor_and_fresh_identities(tmp_path, transport):
    report = _three(tmp_path, count=1001, capacity=400, transport=transport)
    result = report["result"]
    assert result["status"] == "stopped"
    assert result["confirmed_step_count"] == result["protocol_committed_count"] == 1001
    assert result["terminal_time_s"] == 1001 * .02
    assert result["resource_counts"] == {"products_consumed": 4004, "truncations_consumed": 0}
    assert [segment["protocol"]["hello"]["global_start"]
            for segment in report["segments"]] == [0, 400, 800]
    assert report["live_segments"] == [1, 1, 1]
    sessions, rounds, resources = set(), set(), set()
    state = np.array(load_cart_pole_lan_profile(PROFILE).plant.initial_state)
    stable_count = 0
    for g, frame in enumerate(report["frames"]):
        protocol, snapshot = frame["protocol"], frame["snapshot"]
        assert protocol["global_step"] == g and protocol["local_step"] == g % 400
        assert snapshot["t_before_s"] == g * .02
        assert snapshot["t_after_s"] == (g + 1) * .02
        np.testing.assert_allclose(snapshot["observation_before"], state, rtol=0, atol=4e-8)
        scale = 1 << 32
        # Independent Python integers, not the range builder or encoded controller.
        d = [int(np.floor(-gain * scale + .5)) for gain in ORACLE_K]
        v = [int(np.floor(value * scale + .5)) for value in snapshot["observation_before"]]
        expected = sum(a * b for a, b in zip(d, v, strict=True)) / scale**2
        assert snapshot["raw_force_n"] == pytest.approx(expected, abs=1e-14)
        force = float(np.clip(-ORACLE_K @ state, -10, 10))
        disturbance = 1. if g == 399 else -1. if g == 400 else 0.
        assert snapshot["disturbance_force_n"] == disturbance
        state = solve_ivp(_oracle_rhs, (0, .02), state, args=(force + disturbance,),
                          method="DOP853", rtol=1e-13, atol=1e-15).y[:, -1]
        np.testing.assert_allclose(snapshot["observation_after"], state, rtol=0, atol=4e-8)
        if g == 0:
            initial = np.array(snapshot["observation_before"])
            stable_count = int(np.all(np.abs(initial) <= [.02,.03,.02,.05]))
        stable_count = stable_count + 1 if np.all(np.abs(state) <= [.02,.03,.02,.05]) else 0
        assert snapshot["stable_count"] == stable_count
        assert protocol["round_id"] not in rounds
        rounds.add(protocol["round_id"])
        assert not resources.intersection(protocol["resource_ids"])
        resources.update(protocol["resource_ids"])
        sessions.add(protocol["session_id"])
    assert len(sessions) == 3 and len(resources) == 4004
    for segment in report["segments"]:
        protocol = segment["protocol"]
        assert protocol["setup"]["horizon_steps"] == 400
        assert protocol["scale_ledger"]["output"] == 64
        assert protocol["modulus_verification"]["status"] == "verified"
        assert protocol["range_verification"]["proof_mode"] == "finite_horizon"


@pytest.mark.parametrize("mode", ["online", "stage", "reconstruct", "commit_p1",
                                 "commit_p2", "plant_before"])
def test_stop_with_round_in_flight_finishes_exactly_one_physical_interval(tmp_path, mode):
    report = _three(tmp_path, mode=mode, count=99)
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == 1
    assert len(report["frames"]) == 1
    assert report["result"]["observed_status"] == "recovering"


@pytest.mark.parametrize("mode", ["between_end_receipts", "after_continue", "next_handshake"])
def test_stop_after_continue_requires_new_zero_step_stop_segment(tmp_path, mode):
    report = _three(tmp_path, mode=mode, count=99)
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == 3
    assert [len(item["steps"]) for item in report["segments"]] == [3, 0]
    assert report["result"]["final_segment"]["receipts"][0]["end"]["last_round_id"] is None


@pytest.mark.parametrize("count", [0, 1, 3, 7])
def test_confirmed_stop_prefix_and_exact_segment_tail(tmp_path, count):
    report = _three(tmp_path, mode="zero" if count == 0 else "normal", count=count)
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == count
    assert report["result"]["resource_counts"]["products_consumed"] == 4 * count


@pytest.mark.parametrize("mode", ["plant_error", "shape", "nonfinite", "outside", "cancel"])
def test_physical_failure_or_cancel_cannot_close_successfully(tmp_path, mode):
    report = _three(tmp_path, mode=mode)
    assert report["result"]["status"] == ("cancelled" if mode == "cancel" else "failed")
    assert report["result"]["failure_phase"] == "AWAITING_PLANT"
    assert report["result"]["protocol_committed_count"] == 1
    assert report["result"]["confirmed_step_count"] == 0
    assert not report["segments"] and not report["frames"]


@pytest.mark.parametrize("fault", ["commit_lost", "end_lost", "shutdown_timeout"])
def test_missing_commit_or_end_receipt_is_uncertain(tmp_path, fault):
    report = _three(tmp_path, count=1, fault=fault)
    assert report["result"]["status"] == "uncertain"
    assert not report["segments"]
    assert report["result"]["confirmed_step_count"] == (0 if fault == "commit_lost" else 1)


@pytest.mark.parametrize("fault", ["step_timeout", "next_timeout", "peer_disconnect"])
def test_phase_deadlines_and_peer_failure_stop_the_run(tmp_path, fault):
    report = _three(tmp_path, count=99, fault=fault)
    assert report["result"]["status"] in ("uncertain", "failed")
    assert report["result"]["confirmed_step_count"] == (3 if fault == "next_timeout" else 0)


@pytest.mark.parametrize("mode", ["p1_disconnect", "p2_disconnect", "idle_timeout",
                                 "bad_end_count"])
def test_client_connection_loss_or_false_prefix_is_not_success(tmp_path, mode):
    report = _three(tmp_path, count=1, mode=mode)
    assert report["result"]["status"] == "uncertain"
    assert not report["segments"]


def test_many_small_segments_release_protocol_objects_and_bound_record_lists(tmp_path):
    report = _three(tmp_path, count=31, capacity=2)
    assert report["result"]["status"] == "stopped"
    assert report["live_segments"] == [1] * 16
    assert all(len(segment["steps"]) <= 2 for segment in report["segments"])
    assert all(len(segment["protocol"]["steps"]) <= 2 for segment in report["segments"])


def test_tls_identity_checked_again_on_next_segment(tmp_path):
    report = _three(tmp_path, mode="tls_identity", count=99, transport="mutual_tls")
    assert report["result"]["status"] == "failed"
    assert report["result"]["confirmed_step_count"] == 3
    assert report["result"]["failure_phase"] == "CONNECTING_NEXT"


def test_hard_cancel_between_final_receipts_is_not_normal_stop(tmp_path):
    report = _three(tmp_path, mode="cancel_during_end", count=1)
    assert report["result"]["status"] == "cancelled"
    assert report["result"]["confirmed_step_count"] == 1
    assert not report["segments"]


def test_bad_next_chain_and_record_failure_do_not_resume(tmp_path):
    report = _three(tmp_path, mode="bad_chain", count=99)
    assert report["result"]["status"] == "failed"
    assert report["result"]["confirmed_step_count"] == 3
    report = _three(tmp_path, mode="record_error")
    assert report["result"]["status"] == "failed"
    assert report["result"]["confirmed_step_count"] == 1
    assert not report["segments"]


def test_strict_new_payload_codec_and_legacy_mode_separation():
    hello = LanSegmentedHelloPayload("a"*64, "b"*64, "run", 0, 0, None)
    end = SegmentEndPayload("run", 0, 0, 0, 0, None, "stop")
    receipt = SegmentEndReceipt("P1", "session", end, 0, 0, 0)
    for value in (hello, end, receipt):
        assert decode_wire_value(encode_wire_value(value)) == value
    for kind, sender, recipient, payload in (
        ("hello", "Client", "P1", hello), ("request", "Client", "P1", end),
        ("reply", "P1", "Client", receipt),
    ):
        envelope = WireEnvelope(SCHEMA_VERSION, kind, sender, recipient, 0,
                                "lan_hello" if kind == "hello" else "segment_end",
                                "session", None, None, None, payload)
        assert decode_envelope(encode_envelope(envelope)) == envelope
        with pytest.raises(LocalhostCodecError):
            replace(envelope, operation="shutdown")
        wire = json.loads(encode_envelope(envelope))
        wire["payload"]["extra"] = True
        with pytest.raises(LocalhostCodecError):
            decode_envelope(json.dumps(wire).encode())
    with pytest.raises(LocalhostCodecError):
        replace(hello, segment_index=True)
    with pytest.raises(LocalhostCodecError):
        replace(end, global_end_exclusive=1)


@pytest.mark.parametrize("count", [True, 0, 1001, None])
def test_invalid_segment_capacity_fails_before_network(count):
    with pytest.raises(ValueError):
        load_segmented_experiment(PROFILE, count, InteractiveSession())


def test_nonzero_state_rejected_before_connect(tmp_path, monkeypatch):
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    profile = load_cart_pole_lan_profile(PROFILE)
    spec = ControllerSpec(np.zeros((1,1)), np.zeros((1,4)), np.zeros((1,1)),
                          profile.spec.D, np.zeros(1))
    monkeypatch.setattr(lan_runtime, "connect_role", lambda *_args: pytest.fail("connected"))
    with pytest.raises(ValueError, match="非零"):
        LanSegmentedRuntime(load_lan_config(paths["Client"], "Client"), spec, profile.context,
                            profile.contract, profile.security_parameter, profile.evidence,
                            control=RunControl())


def test_normal_stop_retains_inflight_queue_but_rejects_new_requests():
    session = InteractiveSession()
    control = RunControl()
    control.bind_stop(session.reject_new)
    assert session.request(1.)
    control.request_stop()
    assert not session.cancelled.is_set() and not session.request(-1.)
    assert session.latch(399, 0., 10.) == 1.
    session.stop_accepting()
    assert session.take(400) == 0.


def test_headless_script_sigint_is_normal_stop_without_loading_tk(tmp_path):
    report = _three(tmp_path, mode="script")
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == 5


@pytest.fixture
def generic_runtime(tmp_path):
    """小静态通用 spec 用真实双方进程验证生命周期，无倒立摆字段进入执行层。"""
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    parties = [subprocess.Popen(
        [sys.executable, "-c", _PARTY, role, str(paths[role]), "none"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for role in ("P1", "P2")]
    runtime = None
    try:
        spec = ControllerSpec(np.zeros((0,0)), np.zeros((0,1)), np.zeros((1,0)),
                              np.array([[2.]]), np.zeros(0))
        runtime = LanSegmentedRuntime(
            load_lan_config(paths["Client"], "Client"), spec,
            FixedPointContext(2147483647, 8, 4), ControllerRangeContract((), (16,), 2),
            8, None, control=RunControl(),
        )
        yield runtime, parties
    finally:
        if runtime is not None:
            runtime.close()
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_generic_static_segments_use_fresh_parameter_shares_and_exact_prefix(generic_runtime):
    runtime, parties = generic_runtime
    old_share = runtime._segment.distribution.p1.controller.D.value.copy()
    old_session = runtime._segment.session_id
    for g in range(2):
        identity = runtime.step(np.array([.5]))
        assert identity.global_step == g and identity.raw_control == (1.,)
        runtime.confirm_applied(identity)
    record = runtime.end_segment()
    assert record.receipts[0].products == 2 and record.receipts[1].products == 2
    runtime.next_segment()
    assert runtime._segment.session_id != old_session
    assert not np.array_equal(old_share, runtime._segment.distribution.p1.controller.D.value)
    runtime.control.request_stop()
    assert runtime.step(np.array([.5])) is None
    final = runtime.end_segment()
    assert final.steps == () and final.receipts[0].cumulative_committed_count == 2
    assert all(_finish(party, 20)[0] == 0 for party in parties)


@pytest.mark.parametrize("misuse", ["copy", "duplicate", "close"])
def test_unconfirmed_and_invalid_capabilities_cannot_end_or_restart(generic_runtime, misuse):
    runtime, _parties = generic_runtime
    identity = runtime.step(np.array([.5]))
    with pytest.raises(RuntimeError):
        runtime.step(np.array([.5]))
    with pytest.raises(RuntimeError):
        runtime.end_segment()
    with pytest.raises(RuntimeError):
        runtime.next_segment()
    if misuse == "copy":
        with pytest.raises(RuntimeError):
            runtime.confirm_applied(replace(identity))
    elif misuse == "duplicate":
        runtime.confirm_applied(identity)
        with pytest.raises(RuntimeError):
            runtime.confirm_applied(identity)
    else:
        runtime.close()
    runtime.control.request_stop()
    assert runtime.phase == "FAILED"
    with pytest.raises(RuntimeError):
        runtime.end_segment()


@pytest.mark.parametrize("step", [0, 2])
def test_repeated_or_skipped_local_online_is_rejected(generic_runtime, monkeypatch, step):
    runtime, _parties = generic_runtime
    identity = runtime.step(np.array([.5]))
    runtime.confirm_applied(identity)
    request = lan_runtime._request

    def corrupt(sock, role, sequence, operation, session, timeout, *args, **kwargs):
        if operation == "online":
            args = (*args[:2], step)
        return request(sock, role, sequence, operation, session, timeout, *args, **kwargs)

    monkeypatch.setattr(lan_runtime, "_request", corrupt)
    with pytest.raises(LocalhostTransportDisconnected):
        runtime.step(np.array([.5]))
    assert runtime.phase == "UNCERTAIN"
    assert runtime.confirmed_step_count == 1


@pytest.mark.parametrize("field", ["run_id", "segment_index", "global_start", "previous_session_id"])
def test_next_hello_cannot_change_chain(generic_runtime, monkeypatch, field):
    runtime, _parties = generic_runtime
    for _ in range(2):
        runtime.confirm_applied(runtime.step(np.array([.5])))
    runtime.end_segment()
    hello = lan_runtime._hello

    def changed(sock, sender, recipient, session, payload, timeout):
        value = "wrong" if field in ("run_id", "previous_session_id") else 99
        return hello(sock, sender, recipient, session, replace(payload, **{field:value}), timeout)

    monkeypatch.setattr(lan_runtime, "_hello", changed)
    with pytest.raises(LocalhostTransportDisconnected):
        runtime.next_segment()
    assert runtime.confirmed_step_count == 2
    assert runtime.phase == "FAILED"
    with pytest.raises(RuntimeError):
        runtime.next_segment()


def test_forged_nonzero_offline_layout_rejected_by_party(generic_runtime, monkeypatch):
    runtime, _parties = generic_runtime
    for _ in range(2):
        runtime.confirm_applied(runtime.step(np.array([.5])))
    runtime.end_segment()
    request = lan_runtime._request

    def changed(sock, role, sequence, operation, session, timeout, *args, **kwargs):
        if operation == "offline":
            # 故意构造错误 wire 布局；角色必须在 rehydrate 之前拒绝。
            object.__setattr__(args[0].layout, "state_dimension", 1)
        return request(sock, role, sequence, operation, session, timeout, *args, **kwargs)

    monkeypatch.setattr(lan_runtime, "_request", changed)
    with pytest.raises(LocalhostTransportDisconnected):
        runtime.next_segment()
    assert runtime.confirmed_step_count == 2


@pytest.mark.parametrize("value", [float("nan"), 2.])
def test_local_input_failure_before_online_is_failed_not_uncertain(generic_runtime, value):
    runtime, _parties = generic_runtime
    with pytest.raises((ValueError, FloatingPointError)):
        runtime.step(np.array([value]))
    assert runtime.phase == "FAILED"
    assert runtime.protocol_committed_count == runtime.confirmed_step_count == 0
