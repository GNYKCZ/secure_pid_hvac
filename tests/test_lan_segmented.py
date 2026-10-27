"""#100：真实角色、段链、停止竞争和持续物理前缀的回归门禁。"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import FrozenInstanceError, asdict, replace
from types import SimpleNamespace

import numpy as np
import pytest
import yaml
from lan_test_support import reap_processes, start_processes
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
    BatchHelloPayload,
    decode_envelope,
    encode_envelope,
)
from secure_control.execution.localhost_transport import LocalhostTransportDisconnected
from secure_control.experiments.cart_pole_lan_profile import load_cart_pole_lan_profile
from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
from secure_control.protocol import ControllerRangeContract
from secure_control.scenarios.cart_pole.interactive import InteractiveSession


@pytest.fixture(params=("control-dynamic-compact-v2", "control-dynamic-compact-v3", "control-dynamic-matrix-v1"))
def compact_advance(monkeypatch, request):
    """400个已双提交且确认的公开条目；所有网络操作可逐项注入失败。"""
    from secure_control.execution import localhost_codec as codec

    runtime = LanSegmentedRuntime.__new__(LanSegmentedRuntime)
    segment = lan_runtime.LanContinuousRuntime.__new__(lan_runtime.LanContinuousRuntime)
    closed, sent, fault = [], [], {"kind": None}
    segment.__dict__.update(_v2=True, _failed=False, _finished=False, _step=400,
        _segment_start=0, _confirmed_steps=list(range(400)), _confirmed_plans=list(range(400)),
        _sequences=[17, 17], _sockets=["P1", "P2"], session_id="session",
        _products=12000, _truncations=1600, setup=None, scale_ledger=None,
        range_verification=None, modulus_verification=None, _material_pool=None,
        last_commit_observation=None, _last_phase_ns={}, close=lambda: closed.append(True))
    runtime.__dict__.update(_v2=True, _full_v3=False, _wire_profile=request.param,
        config=SimpleNamespace(shutdown_timeout=1.), control=RunControl(), _segment=segment,
        _pending=None, phase="RUNNING", run_id="run", controller_epoch="e"*64,
        segment_capacity=400, segment_index=0, global_start=0, confirmed_step_count=400,
        _last_end_round_id=None, _last_closed_segment_count=0, last_sealed_record=None,
        last_segment_receipts=(), _advance_begin=None, connection_seconds=0.,
        preload_steps=0, _attempted_round=None, _products=12000, _truncations=1600,
        hello=codec.LanSegmentedHelloPayload("a"*64, "b"*64, "run", 0, 0, None, "lan-segmented-v2"),
        _records=[lan_runtime.SegmentedStep("run", 0, "session", f"round-{i}", i, i,
                    (0.,), 30, 4, ()) for i in range(400)])

    def send(sock, data, **_kwargs):
        request = decode_envelope(data)
        if fault["kind"] == "partial_send" and sock == "P2":
            raise TimeoutError("partial request")
        sent.append(request)

    def receive(sock, **_kwargs):
        assert len(sent) % 2 == 0  # 两方先发后收。
        request = next(r for r in reversed(sent) if r.recipient == sock)
        if sock == "P2" and fault["kind"] in {"timeout", "partial_reply", "eof"}:
            raise (EOFError() if fault["kind"] == "eof" else TimeoutError())
        payload = request.payload
        end = payload.end if isinstance(payload, codec.SegmentAdvancePayload) else payload
        receipt = codec.SegmentEndReceipt(sock, "session", end, 400, 12000, 1600)
        if fault["kind"] == "both_wrong":
            receipt = replace(receipt, products=11999)
        if isinstance(payload, codec.SegmentAdvancePayload):
            begin = payload.begin
            if fault["kind"] == "bad_begin" and sock == "P2":
                begin = replace(begin, controller_epoch="f"*64)
            payload = codec.SegmentAdvanceReceipt(receipt, begin)
        else:
            payload = receipt
        if fault["kind"] == "stop_after_send":
            runtime.control.request_stop()
        return replace(request, kind="reply", sender=sock, recipient="Client", payload=payload)

    monkeypatch.setattr(lan_runtime.localhost_transport, "send_frame", send)
    monkeypatch.setattr(lan_runtime, "send_envelope", lambda sock, request, **kw: send(sock, encode_envelope(request), **kw))
    monkeypatch.setattr(lan_runtime, "receive_envelope", receive)
    return runtime, sent, fault, closed


@pytest.mark.parametrize("fault", ["timeout", "partial_send", "partial_reply", "eof", "both_wrong", "bad_begin"])
def test_compact_advance_partial_confirmation_never_allows_next_input(compact_advance, fault):
    runtime, sent, injection, closed = compact_advance
    injection["kind"] = fault
    with pytest.raises((ValueError, TimeoutError, EOFError)):
        runtime.end_segment()
    assert runtime.phase == "UNCERTAIN" and closed
    assert runtime.confirmed_step_count == 400 and runtime._segment._step == 400
    assert runtime.last_sealed_record is None
    assert len(runtime.last_segment_receipts) == (1 if fault in {"timeout", "partial_reply", "eof", "bad_begin"} else 0)
    assert len(sent) <= 2
    with pytest.raises(RuntimeError):
        runtime.next_segment()
    with pytest.raises(RuntimeError):
        runtime.step([0.])


def test_compact_advance_keeps_old_seal_and_sequence_then_zero_step_stop(compact_advance):
    runtime, sent, injection, _closed = compact_advance
    injection["kind"] = "stop_after_send"
    record = runtime.end_segment()
    assert record.hello.segment_index == 0 and len(record.steps) == 400
    assert record.receipts == runtime.last_segment_receipts and runtime.last_sealed_record is record
    assert runtime._segment._sequences == [18, 18]
    assert runtime.phase == "CONNECTING_NEXT" and runtime.segment_index == 0
    runtime.next_segment()
    assert len(sent) == 2 and runtime._segment._step == 400
    assert runtime._segment._products == 12000 and runtime._segment._truncations == 1600
    assert runtime._segment._segment_start == 400 and not runtime._segment._confirmed_steps
    assert runtime.segment_index == 1 and runtime.global_start == 400
    final = runtime.end_segment()
    assert runtime.phase == "STOPPED" and not final.steps
    assert final.receipts[0].end.action == "stop" and final.receipts[0].end.confirmed_count == 0
    assert [r.operation for r in sent] == ["segment_advance"]*2 + ["segment_end"]*2
    assert runtime._segment._sequences == [19, 19]


@pytest.mark.parametrize("stage", ["seal", "source", "release", "deadline"])
@pytest.mark.parametrize("configured", [False, True])
def test_compact_advance_local_failure_keeps_both_known_seals(compact_advance, monkeypatch, stage, configured):
    from secure_control.execution.cycle_timing import CycleDeadlineExceeded
    from secure_control.experiments import lan_runner

    runtime, sent, _injection, closed = compact_advance
    runtime._begin_material_control = lambda: None
    runtime.enable_material_preparation = lambda **kw: None
    calls = []
    def source():
        calls.append("source")
        if stage == "source" and calls.count("source") == 2:
            raise RuntimeError("source changed")
    def callback(name):
        calls.append(name)
        assert runtime.phase == "CONNECTING_NEXT" and runtime.segment_index == 0
        if name == stage:
            raise RuntimeError(name)
    def deadline(_ns, phase):
        if stage == "deadline" and phase == "SEGMENT_RELEASE":
            raise CycleDeadlineExceeded(phase)
    monkeypatch.setattr(lan_runner, "LanSegmentedRuntime", lambda *a, **k: runtime)
    monkeypatch.setattr(lan_runner, "check_deadline", deadline)
    experiment = SimpleNamespace(spec=SimpleNamespace(state_dimension=1), context=None,
        contract=None, security_parameter=8, evidence=None, segment_capacity=400,
        recheck_sources=source, scene=SimpleNamespace(period=.02))
    result = lan_runner._run_prepared_segmented(SimpleNamespace(transport="fixture", wire_profile=runtime._wire_profile,
                                                               client_io="blocking-v1"), experiment,
        control=runtime.control, session=InteractiveSession(), realtime=False,
        on_segment=lambda _packet: callback("seal"), on_segment_ready=lambda _packet: callback("release"),
        **({} if configured else {"_wire_profile":runtime._wire_profile}))
    assert runtime.phase == "UNCERTAIN" and closed and len(sent) == 2
    assert result["status"] == "uncertain" and len(result["known_segment_receipts"]) == 2
    assert result["last_sealed_segment"]["hello"]["segment_index"] == 0
    assert runtime.last_sealed_record is not None and len(runtime.last_segment_receipts) == 2
    assert runtime.confirmed_step_count == 400 and runtime.segment_index == 0


def test_compact_advance_preflights_second_request_before_any_send(compact_advance, monkeypatch):
    runtime, sent, _injection, closed = compact_advance
    encode = lan_runtime.localhost_transport.encode_envelope
    def fail_second(request):
        if request.recipient == "P2":
            raise ValueError("invalid second request")
        return encode(request)
    monkeypatch.setattr(lan_runtime.localhost_transport, "encode_envelope", fail_second)
    with pytest.raises(ValueError):
        runtime.end_segment()
    assert not sent and closed and runtime.phase == "UNCERTAIN"


def test_compact_advance_stop_before_decision_uses_original_stop(compact_advance):
    runtime, sent, _injection, closed = compact_advance
    runtime.control.request_stop()
    record = runtime.end_segment()
    assert runtime.phase == "STOPPED" and closed and runtime._advance_begin is None
    assert all(r.operation == "segment_end" and r.payload.action == "stop" for r in sent)
    assert record.hello.segment_index == 0 and len(record.steps) == 400
    with pytest.raises(RuntimeError):
        runtime.next_segment()


def test_compact_advance_already_expired_budget_closes_without_send(compact_advance):
    from secure_control.execution.cycle_timing import CycleDeadlineExceeded
    runtime, sent, _injection, closed = compact_advance
    with pytest.raises(CycleDeadlineExceeded):
        runtime.end_segment(deadline_ns=1)
    assert runtime.phase == "UNCERTAIN" and closed and not sent
    assert runtime.confirmed_step_count == 400 and not runtime.last_segment_receipts


@pytest.mark.parametrize("expected,received", [("control-batch-v1", "control-dynamic-compact-v2"),
    ("control-dynamic-compact-v1", "control-dynamic-compact-v2"),
    ("control-dynamic-matrix-preauthorized-v1", "control-dynamic-matrix-preauthorized-v2"),
    ("control-dynamic-matrix-preauthorized-v2", "control-dynamic-matrix-preauthorized-v1"),
    ("control-dynamic-matrix-seeded-v1", "control-dynamic-matrix-preauthorized-v2")])
def test_party_rejects_mixed_compact_hello_before_offline_or_peer(monkeypatch, expected, received):
    from secure_control.execution import localhost_codec as codec
    hello = codec._CompactHelloPayload(codec.BatchHelloPayload(codec.LanSegmentedHelloPayload(
        "a"*64, "b"*64, "run", 0, 0, None, "lan-segmented-v2")), received)
    closed = []
    monkeypatch.setattr(lan_runtime, "accept_role", lambda *a: SimpleNamespace(close=lambda: closed.append(True)))
    monkeypatch.setattr(lan_runtime, "_accept_hello", lambda *a: ("session", hello))
    with pytest.raises(ValueError, match="profile"):
        lan_runtime._run_party_session(SimpleNamespace(role="P1", startup_timeout=1.), None, None,
            None, expected_batch=True, expected_wire_profile=expected)
    assert closed == [True]


@pytest.mark.parametrize("mode", ["release_overrun", "stop_receipt_failure"])
def test_compact_advance_maintenance_overrun_has_no_complete_cycle(compact_advance, monkeypatch, mode):
    from secure_control.execution import cycle_timing
    from secure_control.experiments import lan_runner

    runtime, sent, injection, closed = compact_advance
    identity = runtime._records.pop()
    runtime.confirmed_step_count = runtime._segment._step = 399
    clock = [1_000_000_000]
    inputs, cycles = [], []
    def step(value, **_kw):
        inputs.append(value)
        runtime._segment._step = 400
        runtime._pending = identity
        runtime.phase = "AWAITING_PLANT"
        return identity
    runtime.step = step
    monkeypatch.setattr(cycle_timing.time, "perf_counter_ns", lambda: clock[0])
    monkeypatch.setattr(lan_runner, "perf_counter_ns", lambda: clock[0])
    monkeypatch.setattr(lan_runner, "LanSegmentedRuntime", lambda *a, **k: runtime)
    monkeypatch.setattr(lan_runner, "AbsoluteCycleClock", lambda _p: SimpleNamespace(
        period_ns=20_000_000, wait=lambda _step: (1_000_000_000, 1_020_000_000)))
    def release(_packet):
        assert runtime.phase == "CONNECTING_NEXT"
        if mode == "release_overrun":
            clock[0] += 21_000_000
    def observed(cycle):
        cycles.append(cycle)
        if mode == "stop_receipt_failure":
            runtime.control.request_stop()
            injection["kind"] = "timeout"
    scene = SimpleNamespace(period=.02, controller_input=lambda: [0.], advance=lambda *a, **k: None)
    experiment = SimpleNamespace(spec=SimpleNamespace(state_dimension=1), context=None,
        contract=None, security_parameter=8, evidence=None, segment_capacity=400,
        recheck_sources=lambda: None, scene=scene)
    result = lan_runner._run_prepared_segmented(SimpleNamespace(transport="fixture"), experiment,
        control=runtime.control, session=InteractiveSession(), realtime=True, material_slots=0,
        on_segment=lambda _p: None, on_segment_ready=release, on_cycle=observed,
        _wire_profile="control-dynamic-compact-v2")
    if mode == "stop_receipt_failure":
        assert result["status"] == "uncertain" and result["category"] == "TimeoutError"
        assert len(sent) == 4 and len(inputs) == len(cycles) == 1 and closed
        assert cycles[0].status == "confirmed" and runtime.confirmed_step_count == 400
        assert result["last_sealed_segment"]["hello"]["segment_index"] == 0
        return
    assert result["status"] == "uncertain" and result["failure_phase"] == "SEGMENT_RELEASE"
    assert runtime.confirmed_step_count == 400 and runtime.segment_index == 0 and closed
    assert len(inputs) == 1 and len(sent) == 2 and len(cycles) == 1
    cycle = cycles[0]
    assert cycle.global_step == 399 and cycle.status == "miss_after_apply" and cycle.cycle_completed_ns is None
    assert cycle.device_completed_ns == 1_000_000_000 and cycle.deadline_ns == 1_020_000_000
    assert "maintenance_advance" in cycle.phase_durations_ns
    assert "maintenance_end" not in cycle.phase_durations_ns and "maintenance_begin" not in cycle.phase_durations_ns
    assert len(result["known_segment_receipts"]) == 2


@pytest.mark.parametrize("field,value", [("segment_index", 2), ("global_start", 401),
                                         ("run_id", "wrong"), ("previous_round_id", "wrong")])
def test_compact_advance_codec_rejects_bad_begin_link(field, value):
    from secure_control.execution import localhost_codec as codec
    end = codec.SegmentEndPayload("run", 0, 0, 400, 400, "last", "continue")
    begin = codec.SegmentBeginPayload("run", 1, 400, "e"*64, "last")
    payload = codec.SegmentAdvancePayload(end, begin)
    frame = codec.WireEnvelope(codec.SCHEMA_VERSION, "request", "Client", "P1", 7,
                              "segment_advance", "session", None, None, None, payload)
    assert decode_envelope(encode_envelope(frame)) == frame
    with pytest.raises(ValueError):
        codec.SegmentAdvancePayload(end, replace(begin, **{field: value}))

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
    def broken_peer(self, *args, **kwargs):
        self.close()
        raise RuntimeError('injected peer disconnect')
    LocalhostProtocol3PeerPort._send_batch = broken_peer
try:
    result = lan.run_party_single_step(load_lan_config(Path(sys.argv[2]), sys.argv[1]))
except Exception as error:
    print(json.dumps({'status':'failed', 'category':type(error).__name__, 'message':str(error)}))
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
from secure_control.execution.localhost_codec import decode_envelope
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
    if mode == 'commit_p1' and operation == 'commit' and self.party == 0:
        control.request_stop()
    if mode == 'commit_p2' and operation == 'commit' and self.party == 1:
        control.request_stop()
    return result
_ClientPartyEndpoint._command = cmd
finish_batch = _ClientPartyEndpoint.finish_stage_batch
def batch_staged(self):
    result = finish_batch(self)
    if mode == 'stage':
        control.request_stop()
    return result
_ClientPartyEndpoint.finish_stage_batch = batch_staged
reconstruct = Client.reconstruct_control
def rebuilt(self, *args, **kwargs):
    result = reconstruct(self, *args, **kwargs)
    if mode == 'reconstruct':
        control.request_stop()
    return result
Client.reconstruct_control = rebuilt
send_frame = lan.localhost_transport.send_frame
def sent_frame(sock, payload, **kwargs):
    message = decode_envelope(payload)
    result = send_frame(sock, payload, **kwargs)
    if mode in ('p1_disconnect', 'p2_disconnect') and message.operation == 'online':
        if message.recipient == ('P1' if mode == 'p1_disconnect' else 'P2'):
            sock.close()
    if mode == 'online' and message.operation == 'online':
        control.request_stop()
    return result
lan.localhost_transport.send_frame = sent_frame
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
    base = payload.base if hasattr(payload, 'base') else payload
    if mode == 'bad_chain' and base.segment_index == 1:
        changed = replace(base, global_start=base.global_start+1)
        payload = replace(payload, base=changed) if hasattr(payload, 'base') else changed
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
import contextlib, faulthandler, inspect, io, json, runpy, signal, sys
from pathlib import Path
from secure_control.experiments import lan_runner
from secure_control.scenarios.cart_pole.interactive import InteractiveSession
mode = sys.argv[2]
windows = []
session = InteractiveSession()
if mode != 'script':
    # 按原函数行事件选取已持锁窗口，不替换锁、停止回调或协议计算。
    targets = {InteractiveSession.reject_new.__code__: 'callback',
               InteractiveSession.stop_accepting.__code__: 'cleanup'}
    lines = {}
    for code in targets:
        source, start = inspect.getsourcelines(code)
        lines[code] = start + next(i for i, text in enumerate(source)
                                   if text.strip() == 'self._accepting = False')
    def trace(frame, event, arg):
        code = frame.f_code
        if code not in targets:
            return None
        if event == 'line' and frame.f_lineno == lines[code]:
            window = targets[code]
            if window not in windows:
                windows.append(window)
                signal.raise_signal(signal.SIGINT)
                signal.raise_signal(signal.SIGINT)
        return trace
    sys.settrace(trace)
    faulthandler.dump_traceback_later(8)
original = lan_runner.run_client_segmented
def worker(config, **kwargs):
    def stop_at_five(record):
        if record.protocol.global_step == 4:
            assert session.request(1.)
            if mode == 'script_first_sigint_cleanup':
                raise ValueError('record sink failed before any stop request')
            signal.raise_signal(signal.SIGINT)
    return original(config, **kwargs, session=session, on_step=stop_at_five)
lan_runner.run_client_segmented = worker
config = sys.argv[1]
sys.argv = ['run_cart_pole_client.py', config, '--headless-continuous', '--segment-steps', '3']
output = io.StringIO()
with contextlib.redirect_stdout(output):
    try:
        runpy.run_path('scripts/run_cart_pole_client.py', run_name='__main__')
    except SystemExit as error:
        assert error.code == (1 if mode == 'script_first_sigint_cleanup' else 0), error.code
sys.settrace(None)
faulthandler.cancel_dump_traceback_later()
assert 'tkinter' not in sys.modules
assert not session.cancelled.is_set()
assert not session.request(-1.) and session.take(5) == 0.
print(json.dumps({'result':json.loads(output.getvalue()), 'signal_windows':windows}))
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
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role]), fault]
        for role in ("P1", "P2")
    ])
    client = None
    try:
        client = subprocess.Popen(
            [sys.executable, "-c", _SCRIPT_CLIENT if mode.startswith("script") else _CLIENT,
             str(paths["Client"]), mode, str(count), str(capacity),
             str(paths["P1"])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        code, report, errors = _finish(client, 12 if mode.startswith("script") else 100)
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
        reap_processes([*parties, *([client] if client is not None else [])])


@pytest.mark.parametrize("transport", ["mutual_tls"])
@pytest.mark.integration
@pytest.mark.stress
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
@pytest.mark.integration
def test_stop_with_round_in_flight_finishes_exactly_one_physical_interval(tmp_path, mode):
    report = _three(tmp_path, mode=mode, count=99)
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == 1
    assert len(report["frames"]) == 1
    assert report["result"]["observed_status"] == "recovering"


@pytest.mark.parametrize("mode", ["between_end_receipts", "after_continue", "next_handshake"])
@pytest.mark.integration
def test_stop_after_continue_requires_new_zero_step_stop_segment(tmp_path, mode):
    report = _three(tmp_path, mode=mode, count=99)
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == 3
    assert [len(item["steps"]) for item in report["segments"]] == [3, 0]
    assert report["result"]["final_segment"]["receipts"][0]["end"]["last_round_id"] is None


@pytest.mark.parametrize("count", [0, 7])
@pytest.mark.integration
def test_confirmed_stop_prefix_and_exact_segment_tail(tmp_path, count):
    report = _three(tmp_path, mode="zero" if count == 0 else "normal", count=count)
    assert report["result"]["status"] == "stopped"
    assert report["result"]["confirmed_step_count"] == count
    assert report["result"]["resource_counts"]["products_consumed"] == 4 * count


@pytest.mark.parametrize("mode", ["plant_error", "nonfinite", "cancel"])
@pytest.mark.integration
def test_physical_failure_or_cancel_cannot_close_successfully(tmp_path, mode):
    report = _three(tmp_path, mode=mode)
    assert report["result"]["status"] == ("cancelled" if mode == "cancel" else "failed")
    assert report["result"]["failure_phase"] == "AWAITING_PLANT"
    assert report["result"]["protocol_committed_count"] == 1
    assert report["result"]["confirmed_step_count"] == 0
    assert not report["segments"] and not report["frames"]


@pytest.mark.parametrize("fault", ["commit_lost", "end_lost"])
@pytest.mark.integration
def test_missing_commit_or_end_receipt_is_uncertain(tmp_path, fault):
    report = _three(tmp_path, count=1, fault=fault)
    assert report["result"]["status"] == "uncertain"
    assert not report["segments"]
    assert report["result"]["confirmed_step_count"] == (0 if fault == "commit_lost" else 1)


@pytest.mark.parametrize("fault", ["step_timeout", "peer_disconnect"])
@pytest.mark.integration
def test_phase_deadlines_and_peer_failure_stop_the_run(tmp_path, fault):
    report = _three(tmp_path, count=99, fault=fault)
    assert report["result"]["status"] in ("uncertain", "failed")
    assert report["result"]["confirmed_step_count"] == (3 if fault == "next_timeout" else 0)


@pytest.mark.parametrize("mode", ["p1_disconnect", "bad_end_count"])
@pytest.mark.integration
def test_client_connection_loss_or_false_prefix_is_not_success(tmp_path, mode):
    report = _three(tmp_path, count=1, mode=mode)
    assert report["result"]["status"] == "uncertain"
    assert not report["segments"]


@pytest.mark.integration
def test_tls_identity_checked_again_on_next_segment(tmp_path):
    report = _three(tmp_path, mode="tls_identity", count=99, transport="mutual_tls")
    assert report["result"]["status"] == "failed"
    assert report["result"]["confirmed_step_count"] == 3
    assert report["result"]["failure_phase"] == "CONNECTING_NEXT"


@pytest.mark.integration
def test_hard_cancel_between_final_receipts_is_not_normal_stop(tmp_path):
    report = _three(tmp_path, mode="cancel_during_end", count=1)
    assert report["result"]["status"] == "cancelled"
    assert report["result"]["confirmed_step_count"] == 1
    assert not report["segments"]


@pytest.mark.parametrize("count", [True, 0])
def test_invalid_segment_capacity_fails_before_network(count):
    with pytest.raises(ValueError):
        load_segmented_experiment(PROFILE, count, InteractiveSession())


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


@pytest.mark.parametrize("mode", ["script_repeated_sigint", "script_first_sigint_cleanup"])
@pytest.mark.integration
def test_headless_script_sigint_in_locked_stop_and_cleanup_windows_returns(tmp_path, mode):
    """RV-001：原脚本和真实双方进程在确定持锁窗口接受信号，有界返回。"""
    report = _three(tmp_path, mode=mode)
    result = report["result"]
    assert result["confirmed_step_count"] == result["protocol_committed_count"] == 5
    assert result["resource_counts"] == {"products_consumed": 20, "truncations_consumed": 0}
    if mode == "script_repeated_sigint":
        assert report["signal_windows"] == ["callback", "cleanup"]
        assert result["status"] == "stopped"
        assert len(result["final_segment"]["steps"]) == 2
        assert all(receipt["end"]["action"] == "stop"
                   and receipt["cumulative_committed_count"] == 5
                   for receipt in result["final_segment"]["receipts"])
    else:
        assert report["signal_windows"] == ["cleanup"]
        assert result["status"] == "failed" and result["failure_phase"] == "RECORDING_STEP"
        assert "final_segment" not in result


@pytest.mark.parametrize("stop_before_bind", [False, True])
def test_stop_callback_is_once_only_for_reentrant_and_concurrent_requests(stop_before_bind):
    """RV-001：包括先 stop 后绑定，重入/并发请求都不能重复场景回调。"""
    from concurrent.futures import ThreadPoolExecutor

    control = RunControl()
    calls = []

    def callback():
        calls.append("stop")
        control.request_stop()

    if stop_before_bind:
        control.request_stop()
    control.bind_stop(callback)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: control.request_stop(), range(8)))
    assert control.stop_requested and calls == ["stop"]


def test_concurrent_stop_preserves_pending_queue_and_rejects_later_requests():
    """停止返回后跨线程新请求被拒绝，旧请求仍可供唯一 worker 的在途步锁存。"""
    from concurrent.futures import ThreadPoolExecutor

    session, control = InteractiveSession(), RunControl()
    control.bind_stop(session.reject_new)
    assert session.request(1.)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: control.request_stop(), range(8)))
        assert not any(pool.map(lambda _: session.request(-1.), range(8)))
    assert not session.cancelled.is_set()
    assert session.latch(5, 0., 10.) == 1.
    assert session.latch(6, 0., 10.) == 0.


@pytest.fixture
def generic_runtime(tmp_path):
    """小静态通用 spec 用真实双方进程验证生命周期，无倒立摆字段进入执行层。"""
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role]), "none"]
        for role in ("P1", "P2")
    ])
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
        reap_processes(parties)


@pytest.mark.integration
def test_dynamic_v2_keeps_secret_state_in_one_session_across_segments(tmp_path):
    """#109：真实双方进程按全局 step 续算，不重分发 x0 或换 session。"""
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    parties = start_processes([
        [sys.executable, "-c", _PARTY, role, str(paths[role]), "none"]
        for role in ("P1", "P2")
    ])
    runtime = None
    try:
        spec = ControllerSpec(np.array([[.5]]), np.array([[.25]]),
                              np.array([[1.]]), np.array([[0.]]), np.array([0.]))
        runtime = LanSegmentedRuntime(
            load_lan_config(paths["Client"], "Client"), spec,
            FixedPointContext(2147483647, 8, 4),
            ControllerRangeContract((11,), (16,), reachability_block_steps=1),
            8, None, control=RunControl(), segment_capacity=2,
        )
        session = runtime._segment.session_id
        epoch = runtime.controller_epoch
        outputs = []
        for segment_index in range(3):
            for _ in range(2):
                identity = runtime.step(np.array([1.]))
                assert identity.global_step == len(outputs)
                assert identity.local_step == len(outputs) % 2
                assert identity.session_id == session
                public = runtime.snapshot()
                assert public.attempted_round == identity.global_step
                assert public.attempted_round_id == identity.round_id
                assert not {"state", "shares", "mask", "secret"} & asdict(public).keys()
                with pytest.raises(FrozenInstanceError):
                    public.phase = "forged"
                outputs.append(identity.raw_control[0])
                runtime.confirm_applied(identity)
            if segment_index < 2:
                record = runtime.end_segment()
                assert record.hello.mode == "lan-segmented-v2"
                assert record.setup.controller_epoch == epoch
                assert all(receipt.cumulative_committed_count == len(outputs)
                           for receipt in record.receipts)
                runtime.next_segment()
                assert runtime._segment.session_id == session
                assert runtime.snapshot().physically_confirmed_count == len(outputs)
        assert outputs[0] == 0. and outputs[2] > 0.
        runtime.control.request_stop()
        final = runtime.end_segment()
        assert all(receipt.cumulative_committed_count == 6 for receipt in final.receipts)
        assert runtime.snapshot().phase == "STOPPED"
        assert all(_finish(party, 20)[0] == 0 for party in parties)
    except Exception as error:
        diagnostics = []
        for party in parties:
            try:
                party.wait(timeout=2)
                diagnostics.append(party.communicate())
            except subprocess.TimeoutExpired:
                diagnostics.append(("running", ""))
        raise AssertionError(f"v2 parties: {diagnostics}") from error
    finally:
        if runtime is not None:
            runtime.close()
        reap_processes(parties)


@pytest.mark.parametrize("delay_ns", [0, 55_000_000])
@pytest.mark.parametrize("non_realtime", [True, False])
@pytest.mark.parametrize("wire", ["control-batch-v1", "control-dynamic-compact-v2", "control-dynamic-matrix-v1",
                                  "control-dynamic-matrix-preauthorized-v2"])
def test_demo_paces_actual_samples_and_slow_steps_do_not_refresh_realtime_deadline(
    tmp_path, monkeypatch, delay_ns, non_realtime, wire,
):
    from secure_control.execution.cycle_timing import AbsoluteCycleClock, check_deadline
    from secure_control.experiments import lan_runner as runner

    paths = _plain_deployment(tmp_path)
    from test_cart_pole_lan import _observer_profile_for
    _observer_profile_for(paths)
    config = replace(load_lan_config(paths["Client"], "Client"), wire_profile=wire,
                     client_io='ready-v1' if wire=='control-dynamic-matrix-preauthorized-v2' else 'blocking-v1')
    control, session = RunControl(), InteractiveSession()
    prepared = load_segmented_experiment(config.experiment_config, 3, session)
    now, samples, deadlines, initialized, sleeps, closed = [1_000_000_000], [], [], [], [], []
    class Runtime:
        def __init__(self, *args, **kwargs):
            self.phase = "RUNNING"
            self.last_maintenance_operation = None
            self.last_sealed_record = None
            self.last_segment_receipts = ()
            self.run_id = "r"
            self.confirmed_step_count = self.protocol_committed_count = 0
            self.cycle_phase_ns = self.cycle_queue_levels = self.material_summary = {}
            self.resource_counts = {}
        @property
        def segment_full(self):
            return False
        def enable_material_preparation(self, **kwargs):
            initialized.append(kwargs)
        def _begin_material_control(self):
            pass
        def snapshot(self):
            n = self.confirmed_step_count
            return lan_runtime.LanLifecycleSnapshot(self.phase, "r", "s", "e", 0, 0,
                n, f"round-{n}", self.protocol_committed_count, n, 0, 0, 0)
        def step(self, value, **kwargs):
            deadlines.append(kwargs.get("deadline_ns"))
            now[0] += delay_ns
            self.protocol_committed_count += 1
            return SimpleNamespace(global_step=self.confirmed_step_count, raw_control=(0.,), round_id="r")
        def confirm_applied(self, identity):
            self.confirmed_step_count += 1
            if self.confirmed_step_count == 3:
                control.request_stop()
        def end_segment(self):
            self.phase = "STOPPED"
            return lan_runtime.SegmentRecord(None, "s", (), (), None, 0., None, None, None)
        def close(self):
            closed.append(True)
    def sample():
        samples.append(now[0])
        return [0., 0.]
    def wait(seconds):
        sleeps.append(seconds)
        now[0] += round(seconds * 1e9)
    scene = SimpleNamespace(period=.02, controller_input=sample, advance=lambda *a, **k: {}, terminal_summary=dict)
    monkeypatch.setattr(runner, "LanSegmentedRuntime", Runtime)
    monkeypatch.setattr(runner, "perf_counter_ns", lambda: now[0])
    monkeypatch.setattr(runner, "sleep", wait)
    monkeypatch.setattr(runner, "check_deadline", lambda d, p: check_deadline(d, p, now=lambda: now[0]))
    monkeypatch.setattr(runner, "AbsoluteCycleClock", lambda p: AbsoluteCycleClock(p, now=lambda: now[0], sleep=wait))
    from secure_control.experiments.live_timing import LiveTimingCollector
    collector = LiveTimingCollector("samples",sample_limit=2)
    result = runner._run_prepared_segmented(config, replace(prepared, scene=scene),
        control=control, session=session, non_realtime=non_realtime,timing_observer=collector)
    statistics = collector.report()
    assert statistics["statistics_complete"]
    assert statistics['format_version']==2
    if non_realtime:
        assert all(statistics['metrics'][key]['missing_count']==statistics['observations']
                   for key in ('lateness_ns','cycle_remaining_ns','cycle_overrun_ns'))
    elif delay_ns:
        assert statistics['metrics']['cycle_remaining_ns']['count']==0
    else:
        assert statistics['metrics']['cycle_remaining_ns']['count']==3
        assert statistics['metrics']['cycle_remaining_ns']['min_ns']==20_000_000
    if non_realtime:
        assert all(0 < seconds <= .005 for seconds in sleeps)
        if delay_ns:
            assert not sleeps
        expected_wait = 0 if delay_ns else 40_000_000
        assert statistics["metrics"]["pacing_requested_ns"]["sum_ns"] == expected_wait
        assert statistics["metrics"]["pacing_elapsed_ns"]["sum_ns"] == expected_wait
        assert statistics["metrics"]["pacing_excess_ns"]["sum_ns"] == 0
    if non_realtime or not delay_ns:
        assert statistics["observations"] == 3 and statistics["raw"]["omitted"] == 1
        assert statistics["metrics"]["work_elapsed_ns"]["sum_ns"] == 3*delay_ns
        assert statistics["metrics"]["sample_interval_ns"]["sum_ns"] == 2*max(20_000_000,delay_ns)
        assert statistics["recent"][0]["sample_interval_ns"] is None
        assert all(row["deadline_ns"] is None for row in statistics["recent"]) is non_realtime
    else:
        assert statistics["observations"] == 1 and statistics["recent"][0]["work_completed_ns"] is None
    if non_realtime or wire != "control-batch-v1":
        assert result["wire_profile"] == wire and result["transport"] == "insecure_tcp"
        assert result["model_period_s"] == .02
        assert result["timing_mode"] == ("non_realtime_demo" if non_realtime else "absolute")
        assert result["material_source"] == ("inline" if wire == "control-batch-v1" else "worker")
    if delay_ns and not non_realtime:
        assert result["status"] == "failed" and len(samples) == 1
        assert result["cycle_summary"]["misses"] == 1
        assert result["confirmed_step_count"] == 0
    else:
        assert result["status"] == "stopped" and result["confirmed_step_count"] == 3
        assert samples == [1_000_000_000 + i * max(20_000_000, delay_ns) for i in range(3)]
        if non_realtime:
            assert deadlines == [None] * 3
            assert initialized == ([] if wire == "control-batch-v1" else [{"slots":16,"_candidate":"worker"}])
            assert result["cycle_summary"] == {"attempts": 3, "misses": None, "last_cycle": None}
            assert result["model_period_s"] == .02 and result["timing_mode"] == "non_realtime_demo"
    if non_realtime and not delay_ns and wire == "control-dynamic-matrix-v1":
        # 在两次采样之间取消/停止：保留等待终态，不制造第二个已采样步骤。
        for reason in ("cancelled","stopped"):
            control,session = RunControl(),InteractiveSession()
            now[0] = 1_000_000_000
            def interrupted_wait(seconds,session=session,reason=reason,control=control):
                now[0] += round(seconds*1e9)
                session.cancelled.set() if reason == "cancelled" else control.request_stop()
            monkeypatch.setattr(runner,"sleep",interrupted_wait)
            observed = LiveTimingCollector("samples",sample_limit=2)
            terminal = runner._run_prepared_segmented(config,replace(prepared,scene=scene),
                control=control,session=session,non_realtime=True,timing_observer=observed)
            assert terminal["status"] == reason
            assert observed.count == 1 and observed.waiting_terminal["status"] == reason
            assert observed.waiting_terminal["actual_sample_start_ns"] is None
            assert observed.waiting_terminal["pacing_excess_ns"] is None
        control,session = RunControl(),InteractiveSession()
        observed = LiveTimingCollector("samples",sample_limit=2)
        def failed_before_sample():
            raise ValueError("test failure before actual sample")
        terminal = runner._run_prepared_segmented(config,replace(prepared,scene=scene),
            control=control,session=session,non_realtime=True,timing_observer=observed,
            before_sample=failed_before_sample)
        assert terminal["status"] == "failed" and observed.count == 1
        row = observed.report()["recent"][0]
        assert row["status"] == "failed" and row["actual_sample_start_ns"] is None
        assert row["control_applied_ns"] is row["work_completed_ns"] is None
        # 关闭观察不选择另一套等待；睡眠错误仍走原失败/清退，不回退Event等待。
        for performance_mode in ("off", "summary", "sleep_failure"):
            control,session = RunControl(),InteractiveSession()
            now[0] = 1_000_000_000
            samples.clear()
            observed = LiveTimingCollector(performance_mode if performance_mode == "summary" else "samples",sample_limit=2)
            def failing_sleep(_seconds):
                raise OSError("test sleep failure")
            monkeypatch.setattr(runner,"sleep",failing_sleep if performance_mode == "sleep_failure" else wait)
            close_count = len(closed)
            terminal = runner._run_prepared_segmented(config,replace(prepared,scene=scene),
                control=control,session=session,non_realtime=True,
                **({"timing_observer":observed} if performance_mode != "off" else {}))
            assert len(closed) == close_count+1 and closed[-1] is True
            if performance_mode == "sleep_failure":
                assert terminal["status"] == "failed" and terminal["category"] == "OSError"
                assert terminal["confirmed_step_count"] == observed.count == len(samples) == 1
            else:
                assert terminal["status"] == "stopped"
                assert samples == [1_000_000_000,1_020_000_000,1_040_000_000]


def test_nonrealtime_sleep_keeps_fixed_target_and_observes_interruptions(monkeypatch):
    """独立整数时刻预期：早醒重算同目标，迟醒不补睡，终点前后均核停止。"""
    from secure_control.experiments import lan_runner as runner

    now,calls = [100_000_000],[]
    control,session = RunControl(),InteractiveSession()
    monkeypatch.setattr(runner,"perf_counter_ns",lambda:now[0])
    def early(seconds):
        calls.append(round(seconds*1e9))
        now[0] += min(round(seconds*1e9),2_000_000)
    monkeypatch.setattr(runner,"sleep",early)
    assert runner._wait_nonrealtime(109_000_000,session.cancelled,control) == (9_000_000,9_000_000,0)
    assert calls == [5_000_000,5_000_000,5_000_000,3_000_000,1_000_000]
    calls.clear()
    for target in (now[0],now[0]-1):
        assert runner._wait_nonrealtime(target,session.cancelled,control) == (0,0,0)
    assert not calls
    def late(seconds):
        calls.append(round(seconds*1e9))
        now[0] += round(seconds*1e9)+8_000_000
    monkeypatch.setattr(runner,"sleep",late)
    assert runner._wait_nonrealtime(now[0]+9_000_000,session.cancelled,control) == (9_000_000,13_000_000,4_000_000)
    assert calls == [5_000_000]
    for cancel in (False,True):
        for when in ("before","slice","target"):
            control,session = RunControl(),InteractiveSession()
            now[0] = 100_000_000
            calls.clear()
            def signal(session=session,cancel=cancel,control=control):
                session.cancelled.set() if cancel else control.request_stop()
            def interrupted(seconds,when=when,signal=signal):
                calls.append(round(seconds*1e9))
                now[0] += 20_000_000 if when == "target" else round(seconds*1e9)
                signal()
            monkeypatch.setattr(runner,"sleep",interrupted)
            if when == "before":
                signal()
            requested,elapsed,excess = runner._wait_nonrealtime(120_000_000,session.cancelled,control)
            assert excess is None
            assert calls == ([] if when == "before" else [5_000_000])
            assert requested == (0 if when == "before" else 20_000_000)
            assert elapsed == (0 if when == "before" else 20_000_000 if when == "target" else 5_000_000)


@pytest.mark.parametrize("misuse", ["copy", "duplicate", "close"])
@pytest.mark.integration
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
@pytest.mark.integration
def test_repeated_or_skipped_local_online_is_rejected(generic_runtime, monkeypatch, step):
    runtime, _parties = generic_runtime
    identity = runtime.step(np.array([.5]))
    runtime.confirm_applied(identity)
    send_frame = lan_runtime.localhost_transport.send_frame
    injected = []

    def corrupt(sock, payload, **kwargs):
        message = decode_envelope(payload)
        if message.operation == "online":
            injected.append(message.step)
            payload = encode_envelope(replace(message, step=step))
        return send_frame(sock, payload, **kwargs)

    monkeypatch.setattr(lan_runtime.localhost_transport, "send_frame", corrupt)
    with pytest.raises(LocalhostTransportDisconnected):
        runtime.step(np.array([.5]))
    assert runtime.phase == "UNCERTAIN"
    assert runtime.confirmed_step_count == 1
    assert injected == [1, 1]


@pytest.mark.parametrize("field", ["run_id", "segment_index", "global_start", "previous_session_id"])
@pytest.mark.integration
def test_next_hello_cannot_change_chain(generic_runtime, monkeypatch, field):
    runtime, _parties = generic_runtime
    for _ in range(2):
        runtime.confirm_applied(runtime.step(np.array([.5])))
    runtime.end_segment()
    hello = lan_runtime._hello

    def changed(sock, sender, recipient, session, payload, timeout):
        value = "wrong" if field in ("run_id", "previous_session_id") else 99
        base = payload.base if isinstance(payload, BatchHelloPayload) else payload
        changed = replace(base, **{field:value})
        wire = replace(payload, base=changed) if isinstance(payload, BatchHelloPayload) else changed
        return hello(sock, sender, recipient, session, wire, timeout)

    monkeypatch.setattr(lan_runtime, "_hello", changed)
    with pytest.raises(LocalhostTransportDisconnected):
        runtime.next_segment()
    assert runtime.confirmed_step_count == 2
    assert runtime.phase == "FAILED"
    with pytest.raises(RuntimeError):
        runtime.next_segment()


@pytest.mark.integration
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
@pytest.mark.integration
def test_local_input_failure_before_online_is_failed_not_uncertain(generic_runtime, value):
    runtime, _parties = generic_runtime
    with pytest.raises((ValueError, FloatingPointError)):
        runtime.step(np.array([value]))
    assert runtime.phase == "FAILED"
    assert runtime.protocol_committed_count == runtime.confirmed_step_count == 0
