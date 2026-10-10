"""#101：真实持续计算的聚合发布、跨块 replay 与语义篡改回归。"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from math import pi
from pathlib import Path
from threading import Event
from types import MappingProxyType, SimpleNamespace

import numpy as np
import pytest
import yaml
from lan_test_support import reap_processes
from test_cart_pole_lan import ROOT, _observer_profile_for, _profile_for
from test_lan_continuous import _plain_deployment
from test_lan_segmented import _PARTY
from test_lan_single_step import _finish, deployment

from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import SegmentedStep, SegmentRecord
from secure_control.execution.localhost_codec import decode_wire_value
from secure_control.experiments import cart_pole_segmented_evidence as evidence
from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
from secure_control.experiments.lan_runner import CompletedSegment, ConfirmedStep
from secure_control.scenarios.cart_pole.interactive import InteractiveSession


@dataclass(frozen=True)
class _GateHeader:
    index: int
    steps: tuple


@dataclass(frozen=True)
class _GateRecord:
    protocol: int


def _gate_writer(tmp_path, batch):
    """只替换磁盘接收器，实际队列、条件变量、预算和线程保持原实现。"""
    spool = SimpleNamespace(root=tmp_path, run_id="gate", end=0, tail_count=0,
                            begin=lambda *args: None)

    def persist(rows, segment):
        batch(rows, segment)
        spool.end += len(rows)

    spool.record_batch = persist
    return evidence._BatchWriter(spool)


def _gate_segment(writer, index):
    record = _GateRecord(index)
    writer.record_step(record)
    return CompletedSegment(_GateHeader(index, (index,)), (record,))


def test_deferred_writer_waits_for_original_release_even_when_busy_or_notified(tmp_path):
    entered, free_first, second, free_second, held_front = (Event() for _ in range(5))
    calls = []

    def batch(rows, segment):
        index = json.loads(segment[0])["index"]
        calls.append(index)
        if index == 1:
            entered.set()
            assert free_first.wait(5)
        else:
            second.set()
            assert free_second.wait(5)

    writer = _gate_writer(tmp_path, batch)
    original_wait = writer._condition.wait_for

    def wait(predicate):
        def checked():
            result = predicate()
            if writer._pending and not writer._pending[0][4] and not writer._closing:
                assert not result
                assert calls == [1]
                held_front.set()
            return result
        return original_wait(checked)

    writer._condition.wait_for = wait
    writer.begin(None, None)
    try:
        writer.record(_gate_segment(writer, 1))
        assert entered.wait(5)
        packet = _gate_segment(writer, 2)
        writer.record_deferred(packet)
        held = writer.snapshot()["writer_encoded_bytes"]
        assert writer.snapshot()["writer_sealed_segments"] == 2
        with pytest.raises(BufferError):
            writer.record(CompletedSegment(_GateHeader(3, ()), ()))
        with pytest.raises(ValueError):
            writer.release_segment(replace(packet))
        assert writer.snapshot()["writer_encoded_bytes"] == held
        free_first.set()
        assert held_front.wait(5)
        assert writer.snapshot()["durable_step_count"] == 1
        held_front.clear()
        with writer._condition:
            writer._condition.notify_all()  # 唤醒不能绕过 ready 条件。
        assert held_front.wait(5)
        assert not second.is_set()
        writer.release_segment(packet)
        assert second.wait(5)
        snapshot = writer.snapshot()
        assert snapshot["writer_sealed_segments"] == 1
        assert snapshot["durable_step_count"] == 1 and snapshot["writer_encoded_bytes"] > 0
        assert snapshot["writer_encoded_high_water"] <= evidence.SEGMENT_LIMIT
    finally:
        free_first.set()
        free_second.set()
        writer.finish()
    assert calls == [1, 2]
    assert writer.snapshot()["durable_step_count"] == 2
    assert writer.snapshot()["writer_encoded_bytes"] == writer.snapshot()["writer_sealed_segments"] == 0


def test_deferred_writer_finish_drains_fifo_without_release(tmp_path):
    calls, held_front = [], Event()
    writer = _gate_writer(tmp_path, lambda rows, segment: calls.append(json.loads(segment[0])["index"]))
    original_wait = writer._condition.wait_for

    def wait(predicate):
        def checked():
            result = predicate()
            if writer._pending and not writer._pending[0][4] and not writer._closing:
                assert not result and not calls
                held_front.set()
            return result
        return original_wait(checked)

    writer._condition.wait_for = wait
    writer.begin(None, None)
    try:
        writer.record_deferred(_gate_segment(writer, 1))
        # 第二个 ready 项也不能越过队首尚未 ready 的项。
        writer.record(_gate_segment(writer, 2))
        assert held_front.wait(5)
        assert writer.snapshot()["writer_sealed_segments"] == 2
    finally:
        writer.finish()
    assert calls == [1, 2] and writer.snapshot()["durable_step_count"] == 2
    assert not writer._thread.is_alive()


def test_streamed_spool_preserves_canonical_bytes_with_bounded_writes(tmp_path):
    """逐字对照旧规范编码，包括UTF8、负零、布尔、空段和超过一个块的输入。"""
    for count in (0, 1, 80):
        identities = tuple(_GateRecord(i) for i in range(count))
        rows = tuple(evidence._bytes({"protocol": {"protocol": i}, "snapshot": {
            "text": '汉字λ\\"steps":[]' * 250, "negative_zero": -0.0,
            "bool": True, "none": None,
        }}) for i in range(count))
        header = {"steps": [], "unicode": "汉", "float": -0.0, "flag": False}
        expected = evidence._bytes({"protocol": {**header, "steps": [
            {"protocol": i} for i in range(count)]}, "steps": [evidence._decode(row) for row in rows]})
        stats = {}
        path = tmp_path / f"stream-{count}.json"
        size = evidence._write(path, None, _chunks=evidence._spool_chunks(header, identities, rows),
                               _stats=stats)
        assert path.read_bytes() == expected and size == len(expected)
        assert stats["buffer_high_water"] <= 64 * 1024
        assert stats["write_calls"] == (len(expected) + 64 * 1024 - 1) // (64 * 1024)
        with pytest.raises(FileExistsError):
            evidence._write(path, None, _chunks=iter((b"{}\n",)))
    with pytest.raises(ValueError):
        evidence._write(tmp_path / "limited.json", None, 10, _chunks=iter((b"123456", b"123456")))


_CLIENT = r'''
import json, sys
from pathlib import Path
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import RunControl
from secure_control.experiments import cart_pole_segmented_evidence as e
from secure_control.scenarios.cart_pole.interactive import InteractiveSession
config = load_lan_config(Path(sys.argv[1]), 'Client')
mode, count, capacity = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
control, session = RunControl(), InteractiveSession(scheduled={399:1.,400:-1.,799:1.,800:-1.})
frames, phases = [], {}
if count == 0:
    control.request_stop()
if mode in ('spool', 'disk_full'):
    original = e._write
    def write(path, *args, **kwargs):
        if path.name.startswith('spool-'):
            raise OSError(28, 'injected disk full')
        return original(path, *args, **kwargs)
    e._write = write
if mode == 'plot':
    def plot(*args, **kwargs):
        raise RuntimeError('injected mandatory plot failure')
    e.write_segmented_overview = plot
if mode == 'reader':
    e._verify = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('reader failed'))
if mode == 'replay':
    e._Replay.convert = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('replay failed'))
def phase(value):
    phases[value] = phases.get(value, 0) + 1
    if mode == 'zero_tail' and value == 'RECORDING_SEGMENT' and len(frames) == count:
        control.request_stop()
    if mode.startswith('cancel_') and value == mode.removeprefix('cancel_'):
        session.close()
    if mode == 'source' and value == 'REPLAYING':
        with config.experiment_config.open('ab') as output:
            output.write(b'\n# changed during replay\n')
    if mode == 'cancel_before_rename' and value == 'PUBLISHING':
        session.close()
    if mode == 'cancel_after_rename' and value == 'COMPLETE':
        session.close()
def step(record):
    frames.append({'g':record.protocol.global_step, 'state':record.snapshot.observation_after})
    if len(frames) == count and mode != 'zero_tail':
        control.request_stop()
try:
    result = e.run_cart_pole_segmented(config, control=control, session=session,
                                      segment_steps=capacity, on_step=step, phase=phase)
except Exception as error:
    import traceback
    result = {'status':'failed','category':type(error).__name__, 'traceback':traceback.format_exc()}
print(json.dumps({'result':result,'frames':frames,'phases':phases}))
'''

_DYNAMIC_CLIENT = r'''
import json, os, signal, subprocess, sys, time, tracemalloc
from dataclasses import replace
from pathlib import Path
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import RunControl
from secure_control.execution import lan_runtime as lan
from secure_control.experiments.cart_pole_segmented_evidence import run_cart_pole_segmented
from secure_control.protocol import Client
from secure_control.scenarios.cart_pole.interactive import InteractiveSession
config = load_lan_config(Path(sys.argv[1]), 'Client')
count, capacity = int(sys.argv[3]), int(sys.argv[4])
mode = sys.argv[2]
scheduled = {step: 1. if step % 2 else -1. for step in range(count)} if mode == 'pulses' else {}
control, session = RunControl(), InteractiveSession(scheduled=scheduled)
prepared = None
if mode == 'pulses':
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    prepared = load_segmented_experiment(config.experiment_config, capacity, session)
replacement = None
if mode == 'prepare_fail':
    original_prepare = Client.prepare_online
    def prepare(self, distribution, value, *, step):
        if step == 2:
            raise RuntimeError('injected material supply failure')
        return original_prepare(self, distribution, value, step=step)
    Client.prepare_online = prepare
if mode == 'stop_inflight':
    original_reconstruct = Client.reconstruct_control
    def reconstruct(self, *args, **kwargs):
        value = original_reconstruct(self, *args, **kwargs)
        control.request_stop()
        return value
    Client.reconstruct_control = reconstruct
if mode == 'bad_begin':
    original_begin = lan.LanContinuousRuntime.begin_segment
    def begin(self, payload):
        return original_begin(self, replace(payload, segment_index=payload.segment_index+1))
    lan.LanContinuousRuntime.begin_segment = begin
boundaries = []
tracemalloc.start()
started = time.monotonic()
def phase(value):
    global replacement
    if mode in ('p1_restart', 'p2_restart') and value == 'CONNECTING_NEXT' and replacement is None:
        index = 5 if mode == 'p1_restart' else 7
        os.kill(int(sys.argv[index]), signal.SIGTERM)
        replacement = subprocess.Popen([sys.executable,
            'scripts/run_continuous_p1.py' if mode == 'p1_restart' else 'scripts/run_continuous_p2.py',
            sys.argv[index+1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(.3)
def step(record):
    g = record.protocol.global_step
    if mode == 'fail_after_confirmed' and g == 2:
        raise RuntimeError('injected record sink failure')
    if mode == 'cancel_after_confirmed' and g == 2:
        session.close()
    if g in (0, capacity-1, capacity, count-1):
        boundaries.append({'step': g, 'raw': record.protocol.raw_control,
                           'session': record.protocol.session_id,
                           'snapshot': record.snapshot.__dict__ if hasattr(record.snapshot, '__dict__')
                           else {key:getattr(record.snapshot,key) for key in record.snapshot.__dataclass_fields__}})
    if g + 1 == count:
        control.request_stop()
try:
    result = run_cart_pole_segmented(config, control=control, session=session,
                                     segment_steps=capacity, on_step=step, phase=phase,
                                     prepared=prepared, realtime=False)
except Exception as error:
    import traceback
    result = {'status':'failed', 'category':type(error).__name__, 'traceback':traceback.format_exc()}
finally:
    if replacement is not None:
        replacement.terminate()
        replacement.wait(timeout=10)
print(json.dumps({'result':result,'boundaries':boundaries,
                  'wall_s':time.monotonic()-started,'peak_bytes':tracemalloc.get_traced_memory()[1],
                  'device_pending':len(prepared.scene.device._scheduled) if prepared else None}))
'''


def _run(tmp_path, *, count=7, capacity=3, mode="normal", tls=False, client_code=_CLIENT,
         party_fault="none", dynamic=False, dynamic_initial=(0, 0, .005, 0)):
    paths = deployment.__wrapped__(tmp_path) if tls else _plain_deployment(tmp_path)
    profile = (_observer_profile_for(paths, initial_state=dynamic_initial)
               if dynamic else _profile_for(paths))
    if tls:
        value = yaml.safe_load(paths["Client"].read_text())
        value.pop("controller", None)
        value["experiment"] = str(profile)
        paths["Client"].write_text(yaml.safe_dump(value, sort_keys=False))
    processes = []
    try:
        for role in ("P1", "P2"):
            processes.append(subprocess.Popen(
                [sys.executable, "-c", _PARTY, role, str(paths[role]), party_fault], cwd=ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        client = subprocess.Popen(
            [sys.executable, "-c", client_code, str(paths["Client"]), mode, str(count),
             str(capacity), str(processes[0].pid), str(paths["P1"]),
             str(processes[1].pid), str(paths["P2"])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        processes.append(client)
        try:
            code, report, errors = _finish(client, 600)
        except subprocess.TimeoutExpired:
            client.kill()
            output, errors = client.communicate()
            pytest.fail(f"Client timeout: {output} / {errors}")
        if code != 0:
            pytest.fail(json.dumps(report, ensure_ascii=False, indent=2) + "\n" + errors)
        if report["result"]["status"] == "complete":
            outcomes = [_finish(p, 20) for p in processes[:2]]
            assert all(row[0] == 0 for row in outcomes), outcomes
            assert len({report["result"]["backend"]["pid"], *(row[1]["pid"] for row in outcomes)}) == 3
            expected = 1 if dynamic and mode == "stop_inflight" else count
            assert all(row[1]["steps_committed"] == expected for row in outcomes)
        return report
    finally:
        reap_processes(processes)


def _freeze_report(value):
    """共享报告只保存不可变快照，不保留 runner 的可变容器。"""
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_report(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_report(item) for item in value)
    return value


@pytest.fixture(scope="module")
def _published_source(tmp_path_factory):
    root = tmp_path_factory.mktemp("segmented-result")
    report = _run(root)
    assert report["result"]["status"] == "complete", report
    path = Path(report["result"]["run_dir"])
    return path, _freeze_report(report), _redraw_source_fingerprint(path)


@pytest.fixture(scope="module")
def _dynamic_source(tmp_path_factory):
    root = tmp_path_factory.mktemp("dynamic-result")
    report = _run(root, count=7, capacity=3, client_code=_DYNAMIC_CLIENT, dynamic=True)
    assert report["result"]["status"] == "complete", report
    path = Path(report["result"]["run_dir"])
    return path, _freeze_report(report), _redraw_source_fingerprint(path)


@pytest.fixture
def published(_published_source):
    path, report, fingerprint = _published_source
    assert _redraw_source_fingerprint(path) == fingerprint
    yield path, report
    assert _redraw_source_fingerprint(path) == fingerprint


@pytest.fixture
def dynamic_published(_dynamic_source):
    path, report, fingerprint = _dynamic_source
    assert _redraw_source_fingerprint(path) == fingerprint
    yield path, report
    assert _redraw_source_fingerprint(path) == fingerprint


@pytest.mark.integration
def test_real_segments_publish_and_observation_seek_matches_confirmed_frames(published):
    path, report = published
    run = evidence.open_verified_cart_pole_segmented_run(path)
    assert run.metadata["N"] == 7 and run.metadata["segment_count"] == 3
    assert run.metadata["termination"]["stop_reason"] == "user_requested"
    assert run.metadata["termination"]["observed_status"] == "recovering"
    for frame in report["frames"]:
        point = run.observation_at(frame["g"]+1)
        np.testing.assert_allclose(point["state"], frame["state"], rtol=0, atol=1e-12)
        assert point["time_s"] == (frame["g"]+1)*.02
    assert run.observation_at(0)["applied_force_n"] is None
    assert len(run._cache) <= 2
    with pytest.raises(TypeError):
        run.metadata["N"] = 1
    for value in (-1, 8, True):
        with pytest.raises(ValueError):
            run.observation_at(value)


@pytest.mark.integration
def test_dynamic_v2_publishes_verified_continuous_state(dynamic_published):
    _, report = dynamic_published
    assert report["result"]["status"] == "complete", report["result"].get("traceback", report)
    run = evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"])
    assert run.metadata["format_version"] == 2
    assert run.metadata["N"] == 7
    assert run.metadata["termination"]["resource_counts"] == {
        "products_consumed": 210, "truncations_consumed": 28,
    }
    assert len({item["session"] for item in report["boundaries"]}) == 1


@pytest.mark.integration
@pytest.mark.parametrize("failure", ["disk", "source"])
def test_batch_writer_counts_inflight_and_preserves_checkpoint_on_disk_failure(
    dynamic_published, tmp_path, monkeypatch, failure,
):
    """在真实 v2 记录上冻结 writer，验证两段门禁、可靠批次和写盘失败旧前缀。"""
    source, _ = dynamic_published
    paths = _plain_deployment(tmp_path)
    _observer_profile_for(paths)
    config = load_lan_config(paths["Client"], "Client")
    session = InteractiveSession()
    prepared = load_segmented_experiment(config.experiment_config, 3, session)
    spool = evidence._Spool(prepared, config, session, lambda _: None)
    definition = json.loads((source / "config.json").read_bytes())
    spool.config = definition
    manifest = json.loads((source / "run.json").read_bytes())
    setup = decode_wire_value(evidence._bytes(definition["setup"]))
    entered, release = Event(), Event()
    original_batch = spool.record_batch
    calls = [0]
    original_checkpoint = spool._checkpoint

    def batch(rows, segment):
        calls[0] += 1
        if calls[0] == 1:
            entered.set()
            assert release.wait(timeout=5)
        if calls[0] == 2 and failure == "disk":
            def failed_checkpoint(*args):
                raise OSError("injected checkpoint disk failure")
            monkeypatch.setattr(spool, "_checkpoint", failed_checkpoint)
        elif calls[0] == 2:
            with config.experiment_config.open("a", encoding="utf-8") as profile:
                profile.write("\n# changed after deferred handoff\n")
        original_batch(rows, segment)

    monkeypatch.setattr(spool, "record_batch", batch)
    writer = evidence._BatchWriter(spool)
    writer.begin(SimpleNamespace(run_id=manifest["backend_run_id"],
                                 controller_epoch=setup.controller_epoch), setup)

    # 只重建公开 immutable 协议身份，秘密材料不进入 writer 测试。
    def submit(index):
        data = json.loads((source / "segments" / str(index) / "protocol.json").read_bytes())
        identities = tuple(SegmentedStep(**{**row, "raw_control": tuple(row["raw_control"]),
                                            "resource_ids": tuple(row["resource_ids"])})
                           for row in data["protocol"]["steps"])
        records = tuple(ConfirmedStep(identity, row["snapshot"])
                        for identity, row in zip(identities, data["steps"], strict=True))
        for record in records:
            writer.record_step(record)
        public = data["protocol"]
        protocol = SegmentRecord(
            public["hello"], public["session_id"], identities, tuple(public["receipts"]),
            public["setup"], public["connection_seconds"], public["scale_ledger"],
            public["range_verification"], public["modulus_verification"],
        )
        return CompletedSegment(protocol, records)

    packet = None
    try:
        first = submit(0)
        writer.record(first)
        assert entered.wait(timeout=5)
        assert writer.snapshot()["durable_step_count"] == 0
        packet = submit(1)
        writer.record_deferred(packet)
        assert writer.snapshot()["writer_sealed_segments"] == 2
        with pytest.raises(BufferError):
            writer.record(submit(2))
        assert writer.snapshot()["writer_encoded_high_water"] <= evidence.SEGMENT_LIMIT
    finally:
        release.set()
        if packet is not None:
            writer.release_segment(packet)
        with pytest.raises(OSError):
            writer.finish()
    assert not writer._thread.is_alive()
    assert writer.snapshot()["durable_step_count"] == 3
    # 与改动前的canonical实现逐字对照，包含真实v2字段和哈希链。
    assert (spool.stage / "spool-0.json").read_bytes() == evidence._bytes(asdict(first))
    previous, journal = None, bytearray()
    for record in first.steps:
        entry = {"step": asdict(record), "prev_sha256": previous}
        previous = sha256(evidence._bytes(entry)).hexdigest()
        journal.extend(evidence._bytes({**entry, "sha256": previous}))
    assert (spool.stage / "journal/0.jsonl").read_bytes() == journal
    assert spool.last_batch["error_type"] == ("OSError" if failure == "disk" else "ValueError")
    assert spool.last_batch["buffer_high_water"] <= 64 * 1024
    monkeypatch.setattr(spool, "_checkpoint", original_checkpoint)
    spool.fail({"status": "failed", "category": "OSError", "failure_phase": "WRITER"})
    prefix = evidence.open_verified_cart_pole_segmented_prefix(spool.stage)
    assert prefix["confirmed_step_count"] == 3 and prefix["sealed_segment_count"] == 1
    if failure == "disk":
        assert spool.disk_metrics["fsync_count"] == 8  # 两批均 fsync，只有首批 checkpoint 发布
    else:
        assert spool.disk_metrics["fsync_count"] < 8  # 来源变化在第二批写盘前拒绝。


def test_stream_batch_rejects_invalid_data_and_partial_io_without_promoting_prefix(
    dynamic_published, tmp_path, monkeypatch,
):
    source, _ = dynamic_published
    for fault in ("noncanonical", "duplicate", "nan", "identity", "extra_journal",
                  "journal_write", "spool_write", "fsync", "checkpoint", "limit"):
        _check_stream_fault(source, tmp_path / fault, monkeypatch, fault)


def _check_stream_fault(source, root, monkeypatch, fault):
    root.mkdir()
    paths = _plain_deployment(root)
    _observer_profile_for(paths)
    config = load_lan_config(paths["Client"], "Client")
    session = InteractiveSession()
    prepared = load_segmented_experiment(config.experiment_config, 3, session)
    spool = evidence._Spool(prepared, config, session, lambda _: None)
    spool.config = json.loads((source / "config.json").read_bytes())
    setup = decode_wire_value(evidence._bytes(spool.config["setup"]))
    backend = json.loads((source / "run.json").read_bytes())["backend_run_id"]
    spool.begin(SimpleNamespace(run_id=backend, controller_epoch=setup.controller_epoch), setup)
    data = json.loads((source / "segments/0/protocol.json").read_bytes())
    rows = [evidence._bytes(row) for row in data["steps"]]
    identities = tuple(SegmentedStep(**{**row, "raw_control": tuple(row["raw_control"]),
                                        "resource_ids": tuple(row["resource_ids"])})
                       for row in data["protocol"]["steps"])
    header = evidence._bytes({**data["protocol"], "steps": []})
    initial_checkpoint = (spool.stage / "checkpoint.json").read_bytes()
    with monkeypatch.context() as patch:
        if fault == "noncanonical":
            rows[-1] = json.dumps(data["steps"][-1], indent=1).encode()
        elif fault == "duplicate":
            rows[-1] = b'{"protocol":{},"protocol":{}}\n'
        elif fault == "nan":
            rows[-1] = b'{"protocol":{},"value":NaN}\n'
        elif fault == "identity":
            identities = (identities[0], replace(identities[1], global_step=True), identities[2])
        elif fault == "extra_journal":
            original_iter = evidence._iter_journal

            def tampered(path, *args, **kwargs):
                with path.open("ab") as output:
                    output.write(b"extra")
                yield from original_iter(path, *args, **kwargs)

            patch.setattr(evidence, "_iter_journal", tampered)
        elif fault == "journal_write":
            original_finish = evidence._BufferedChunks.finish

            def partial(writer):
                if str(writer.stream.name).endswith(".jsonl"):
                    writer.stream.write(writer.buffer[:10])
                    raise OSError("injected partial journal write")
                return original_finish(writer)

            patch.setattr(evidence._BufferedChunks, "finish", partial)
        elif fault in {"spool_write", "limit"}:
            original_write = evidence._write

            def partial_spool(path, value, *args, **kwargs):
                if path.name.startswith("spool-"):
                    if fault == "limit":
                        return original_write(path, value, 10, **kwargs)
                    with path.open("xb") as output:
                        output.write(b"partial")
                    raise OSError("injected partial spool write")
                return original_write(path, value, *args, **kwargs)

            patch.setattr(evidence, "_write", partial_spool)
        elif fault == "fsync":
            def failed_fsync(fd):
                raise OSError("injected fsync failure")
            patch.setattr(evidence.os, "fsync", failed_fsync)
        elif fault == "checkpoint":
            def failed_checkpoint(*args):
                raise OSError("injected checkpoint failure")
            patch.setattr(spool, "_checkpoint", failed_checkpoint)
        with pytest.raises((ValueError, OSError)):
            spool.record_batch(rows, (header, identities))
    assert (spool.count, spool.end, spool.tail_count, spool.tail_bytes, spool.tail_hash) == (0, 0, 0, 0, None)
    assert (spool.stage / "checkpoint.json").read_bytes() == initial_checkpoint
    assert spool.last_batch["error_type"] is not None
    assert spool.last_batch["buffer_high_water"] <= 64 * 1024
    spool.fail({"status": "failed", "category": "injected", "failure_phase": "WRITER"})
    prefix = evidence.open_verified_cart_pole_segmented_prefix(spool.stage)
    assert prefix["confirmed_step_count"] == prefix["sealed_segment_count"] == 0


@pytest.mark.integration
def test_dynamic_v2_failed_run_exposes_verified_unsealed_prefix(tmp_path_factory):
    root = tmp_path_factory.mktemp("dv2fail")
    report = _run(root, count=7, capacity=5,
                  mode="fail_after_confirmed", client_code=_DYNAMIC_CLIENT, dynamic=True)
    assert report["result"]["status"] == "failed"
    prefix = evidence.open_verified_cart_pole_segmented_prefix(
        report["result"]["prefix_dir"])
    assert prefix["status"] == "failed"
    assert prefix["confirmed_step_count"] == prefix["unsealed_step_count"] == 3
    assert prefix["sealed_step_count"] == 0
    assert prefix["unsealed_tail_is_complete"] is False
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_run(report["result"]["prefix_dir"])
    forged = root / "forged" / Path(report["result"]["prefix_dir"]).name
    forged.parent.mkdir()
    shutil.copytree(report["result"]["prefix_dir"], forged)
    journal = forged / "journal" / "0.jsonl"
    entries = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
    entries[0]["step"]["protocol"]["raw_control"] = [9.]
    entries[0]["step"]["snapshot"]["raw_force_n"] = 9.
    entries[0]["step"]["snapshot"]["applied_force_n"] = 9.
    previous = None
    raw = b""
    for entry in entries:
        entry["prev_sha256"] = previous
        previous = sha256(evidence._bytes({"step": entry["step"],
                                           "prev_sha256": previous})).hexdigest()
        entry["sha256"] = previous
        raw += evidence._bytes(entry)
    journal.write_bytes(raw)
    checkpoint_file = forged / "checkpoint.json"
    checkpoint = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    checkpoint["active_sha256"] = previous
    checkpoint["active_bytes"] = len(raw)
    checkpoint_file.write_bytes(evidence._bytes(checkpoint))
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_prefix(forged)

    crashed = root / "crashed" / Path(report["result"]["prefix_dir"]).name
    crashed.parent.mkdir()
    shutil.copytree(report["result"]["prefix_dir"], crashed)
    checkpoint_file = crashed / "checkpoint.json"
    checkpoint = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    checkpoint["status"] = "running"
    checkpoint["failure"] = None
    checkpoint_file.write_bytes(evidence._bytes(checkpoint))
    with (crashed / "journal" / "0.jsonl").open("ab") as stream:
        stream.write(b'{"partial":')  # a crash after append, before atomic checkpoint
    prefix = evidence.open_verified_cart_pole_segmented_prefix(crashed)
    assert prefix["status"] == "in_progress_or_crashed"
    assert prefix["confirmed_step_count"] == 3
    assert prefix["unsealed_tail_is_complete"] is False


@pytest.mark.parametrize(("mode", "party_fault", "status", "sealed", "active"), [
    ("prepare_fail", "none", "failed", 0, 2),
    ("cancel_after_confirmed", "none", "cancelled", 0, 3),
    ("normal", "end_lost", "uncertain", 0, 3),
    ("bad_begin", "none", "uncertain", 1, 0),
    ("p1_restart", "none", "uncertain", 1, 0),
    ("p2_restart", "none", "uncertain", 1, 0),
    ("normal", "commit_lost", "uncertain", 0, 0),
    ("normal", "peer_disconnect", "uncertain", 0, 0),
])
@pytest.mark.integration
def test_dynamic_v2_faults_keep_only_verified_prefix(tmp_path_factory, mode, party_fault,
                                                      status, sealed, active):
    report = _run(tmp_path_factory.mktemp("dv2fault"), count=7, capacity=3, mode=mode,
                  party_fault=party_fault, client_code=_DYNAMIC_CLIENT, dynamic=True)
    assert report["result"]["status"] == status, report["result"]
    prefix = evidence.open_verified_cart_pole_segmented_prefix(
        report["result"]["prefix_dir"])
    assert prefix["status"] == status
    assert prefix["sealed_segment_count"] == sealed
    assert prefix["unsealed_step_count"] == active
    assert prefix["unsealed_tail_is_complete"] is False


@pytest.mark.integration
def test_dynamic_v2_inflight_stop_confirms_one_round(tmp_path_factory):
    report = _run(tmp_path_factory.mktemp("dv2stop"), count=7, capacity=3,
                  mode="stop_inflight", client_code=_DYNAMIC_CLIENT, dynamic=True)
    assert report["result"]["status"] == "complete", report["result"]
    assert report["result"]["confirmed_step_count"] == 1


@pytest.mark.integration
def test_dynamic_v2_reader_rejects_journal_and_rehashed_spec_tamper(dynamic_published, tmp_path):
    source, report = dynamic_published
    root = tmp_path
    assert report["result"]["status"] == "complete", report["result"]
    journal_copy = root / "journal-copy" / source.name
    journal_copy.parent.mkdir()
    shutil.copytree(source, journal_copy)
    journal = journal_copy / "journal" / "0.jsonl"
    journal.write_bytes(journal.read_bytes().replace(b'"raw_control"', b'"raw_controls"', 1))
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_run(journal_copy)

    spec_copy = root / "spec-copy" / source.name
    spec_copy.parent.mkdir()
    shutil.copytree(source, spec_copy)
    config_file = spec_copy / "config.json"
    config = json.loads(config_file.read_text(encoding="utf-8"))
    config["definition"]["controller_spec"]["A"][0][0] += 0.01
    config_file.write_bytes(evidence._bytes(config))
    plot_file = spec_copy / "plots.json"
    plot = json.loads(plot_file.read_text(encoding="utf-8"))
    plot["config_sha256"] = sha256(config_file.read_bytes()).hexdigest()
    plot_file.write_bytes(evidence._bytes(plot))
    manifest_file = spec_copy / "run.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    manifest["config_sha256"] = plot["config_sha256"]
    manifest["plots_sha256"] = sha256(plot_file.read_bytes()).hexdigest()
    manifest_file.write_bytes(evidence._bytes(manifest))
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_run(spec_copy)
    assert evidence.open_verified_cart_pole_segmented_run(source).metadata["N"] == 7


@pytest.mark.integration
@pytest.mark.stress
def test_dynamic_v2_three_processes_continue_past_400(tmp_path_factory):
    shorter = _run(tmp_path_factory.mktemp("dv2bounded"), count=201, capacity=200,
                   client_code=_DYNAMIC_CLIENT, dynamic=True,
                   dynamic_initial=(0, 0, 2*pi+.005, 0))
    assert shorter["result"]["status"] == "complete", shorter["result"]
    report = _run(tmp_path_factory.mktemp("dv2long"), count=401, capacity=200,
                  client_code=_DYNAMIC_CLIENT, dynamic=True,
                  dynamic_initial=(0, 0, 2*pi+.005, 0))
    assert report["result"]["status"] == "complete", report["result"].get("traceback", report)
    run = evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"])
    assert run.metadata["N"] == 401 and run.metadata["segment_count"] == 3
    assert run.metadata["termination"]["terminal_time_s"] == 401*.02
    assert run.metadata["termination"]["resource_counts"] == {
        "products_consumed": 401*30, "truncations_consumed": 401*4,
    }
    assert len({item["session"] for item in report["boundaries"]}) == 1
    assert report["peak_bytes"] <= shorter["peak_bytes"] + 8 * 1024 * 1024
    print(json.dumps({"N": 401, "sample_period_s": .02, "wall_s": report["wall_s"],
                      "peak_python_bytes": report["peak_bytes"],
                      "peak_python_bytes_at_201": shorter["peak_bytes"]}))
    for item in report["boundaries"]:
        np.testing.assert_allclose(run.observation_at(item["step"]+1)["state"],
                                   item["snapshot"]["observation_after"], atol=1e-12, rtol=0)


@pytest.mark.parametrize("count", [0, 3])
@pytest.mark.integration
def test_empty_partial_and_full_stop_results_have_no_dummy_rows(tmp_path, count):
    report = _run(tmp_path, count=count)
    assert report["result"]["status"] == "complete", report
    run = evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"])
    assert run.metadata["N"] == count
    entries = list(run.iter_segments())
    if count == 0:
        assert entries[0][1] is None and run.observation_at(0)["applied_force_n"] is None
    else:
        assert sum(record.result.time.size for _, record, _, _ in entries) == count


@pytest.mark.integration
def test_confirmed_continue_then_zero_step_stop_is_retained(tmp_path):
    report = _run(tmp_path, count=3, capacity=3, mode="zero_tail")
    assert report["result"]["status"] == "complete", report
    path = Path(report["result"]["run_dir"])
    run = evidence.open_verified_cart_pole_segmented_run(path)
    entries = list(run.iter_segments())
    assert run.metadata["N"] == 3 and run.metadata["segment_count"] == 2
    assert entries[-1][0]["global_start"] == entries[-1][0]["global_end"] == 3
    assert entries[-1][1] is None
    assert entries[-1][3]["protocol"]["receipts"][0]["end"]["last_round_id"] is None
    assert run.observation_at(3)["applied_force_n"] is not None
    shutil.rmtree(path / "segments/1")
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_run(path)


@pytest.mark.parametrize("fault", ["commit_lost", "end_lost", "peer_disconnect"])
@pytest.mark.integration
def test_real_network_fault_cannot_publish_complete_result(tmp_path, fault):
    report = _run(tmp_path, party_fault=fault)
    assert report["result"]["status"] in ("failed", "uncertain")
    assert not list(tmp_path.rglob("run.json")) and not list(tmp_path.rglob(".incomplete-*"))


def _redraw_source_fingerprint(path):
    """RV-001：测试的小型真实产物同时比较目录成员及全部文件字节摘要。"""
    return {str(item.relative_to(path)): evidence._hash(item) if item.is_file() else None
            for item in path.rglob("*")}


@pytest.mark.integration
def test_shared_reports_and_clone_keep_source_immutable(dynamic_published, tmp_path):
    """负例副本的写入不能污染本轮正常源及另一独立副本。"""
    source, report = dynamic_published
    with pytest.raises(TypeError):
        report["result"]["status"] = "forged"
    with pytest.raises(TypeError):
        report["boundaries"][0]["snapshot"]["observation_after"][0] = 42
    fingerprint = _redraw_source_fingerprint(source)
    first, second = tmp_path / "first" / source.name, tmp_path / "second" / source.name
    first.parent.mkdir()
    second.parent.mkdir()
    shutil.copytree(source, first)
    shutil.copytree(source, second)
    (first / "run.json").write_bytes(b"{}")
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_run(first)
    assert _redraw_source_fingerprint(source) == fingerprint
    assert evidence.open_verified_cart_pole_segmented_run(source).metadata["N"] == 7
    assert evidence.open_verified_cart_pole_segmented_run(second).metadata["N"] == 7
