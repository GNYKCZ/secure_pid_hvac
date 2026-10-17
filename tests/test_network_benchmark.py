"""网络模型的独立整数oracle、字节/TLS软件反例和有界额度；不运行控制长测。"""

from __future__ import annotations

import copy
import json
import math
import os
import socket
import subprocess
import sys
import time
from dataclasses import replace
from datetime import timedelta
from fractions import Fraction
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from lan_test_support import ROOT, free_ports

from secure_control.execution import lan_transport, localhost_transport
from secure_control.experiments import _network_emulator as emulator
from secure_control.experiments import communication_benchmark as benchmark
from secure_control.experiments import network_benchmark as network


def test_schedule_matches_independent_fraction_oracle_and_direction_domains():
    schedule = emulator.Schedule(emulator.LinkModel(250000, 500000, 100000003), "Client->P1")
    twin = emulator.Schedule(schedule.model, "Client->P1")
    other = emulator.Schedule(schedule.model, "Client->P2")
    tx = due = offset = 0
    observed, distinct = [], []
    for arrival, size in ((100000, 3), (100001, 4096), (200000, 17), (900000, 1)):
        row = schedule.enqueue(arrival, size)
        assert row == twin.enqueue(arrival, size)
        tx = max(arrival, tx) + math.ceil(Fraction(8 * size * 10**9, 100000003))
        due = max(due, tx + row[2])
        assert row == (offset, tx, row[2], due) and 250000 <= row[2] <= 500000
        offset += size
        observed.append(row[2])
        distinct.append(other.enqueue(arrival, size)[2])
    assert observed != distinct
    zero = emulator.Schedule(emulator.models("N1")["P1->P2"], "P1->P2")
    assert zero.enqueue(123, 4096) == (0, 123, 0, 123)
    assert emulator.models("N3")["P1->P2"].low_ns == 1000000
    assert emulator.models("N3")["Client->P1"] == emulator.models("N2")["Client->P1"]


def test_due_short_writes_backpressure_and_late_dispatch_are_distinct(monkeypatch):
    class Writer:
        def __init__(self):
            self.actions = [BlockingIOError(), 2, 4]
            self.written = bytearray()

        def send(self, data):
            action = self.actions.pop(0)
            if isinstance(action, Exception):
                raise action
            self.written.extend(data[:action])
            return action

    writer = Writer()
    direction = emulator.Direction(None, writer, "Client->P1", None)
    direction.queue.append(emulator.Block(b"abcdef", 0, 50, 50, 50, 100))
    direction.queued = 6
    ring = emulator.PublicRing()
    clock = [100]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    with pytest.raises(RuntimeError, match="提前"):
        emulator._progress(direction, 99, 99, ring)
    emulator._progress(direction, 100, 100, ring)
    clock[0] = 10000100
    emulator._progress(direction, clock[0], clock[0], ring)
    emulator._progress(direction, clock[0], clock[0], ring)
    assert writer.written == b"abcdef" and not direction.queue and direction.queued == 0
    assert direction.stats["backpressure_count"] == direction.stats["short_writes"] == 1
    assert direction.stats["unexplained_over_tolerance"] == 0 and ring.seen == 3
    assert ring.rows()[0][8] == 0 and ring.rows()[0][12] == 100
    writer.actions = [1]
    direction.queue.append(emulator.Block(b"g", 6, 0, 0, 0, clock[0]))
    direction.queued = 1
    clock[0] += 2000000
    emulator._progress(direction, clock[0], clock[0], ring)
    assert direction.stats["unexplained_over_tolerance"] == 1 and ring.first_anomaly is not None
    writer.actions = [1]
    direction.queue.append(emulator.Block(b"h", 7, 0, 0, 0, clock[0]))
    direction.queued = 1
    send = writer.send
    def delayed_send(data):
        clock[0] += 2000000
        return send(data)
    monkeypatch.setattr(writer, "send", delayed_send)
    emulator._progress(direction, clock[0], clock[0], ring)
    assert direction.stats["unexplained_over_tolerance"] == 2  # syscall内调度耗时也不能隐藏。
    for _ in range(300):
        ring.append(ring.rows()[-1])
    assert len(ring.rows()) == ring.CAPACITY and len(ring.data)*ring.data.itemsize <= 64*1024


def test_full_queue_stops_reading_and_admits_only_available_room():
    class Source:
        def __init__(self):
            self.requests = []

        def recv(self, limit):
            self.requests.append(limit)
            return b"x"*limit
    source = Source()
    schedule = emulator.Schedule(emulator.models("N2")["Client->P1"], "Client->P1")
    direction = emulator.Direction(source, None, "Client->P1", schedule, queued=emulator.QUEUE_LIMIT-3)
    emulator._read(direction)
    emulator._read(direction)
    assert source.requests == [3] and direction.queued == emulator.QUEUE_LIMIT
    assert direction.stats["received_bytes"] == 3 and direction.stats["queue_high_water"] == emulator.QUEUE_LIMIT


@pytest.mark.parametrize("profile,empty_readers,late_sleep", (
    ("N1", False, False), ("N2", False, False), ("N3", False, False),
    ("N2", True, False), ("N2", False, True)))
def test_windows_relay_due_does_not_depend_on_positive_select_timer(monkeypatch, profile, empty_readers, late_sleep):
    """驱动真实代理循环：模拟正timeout延后一个tick，不运行socket或性能补测。"""
    clock = [1_000_000_000]
    stopped, reports = [False], []
    payload = b"opaque" * 246 + b"xx"
    written, idle_waits, sleeps = bytearray(), [], []
    startup_idle, blocked, waited_for_writable = [False], [False], [False]
    selectors, sleeps_without_fds = [], []
    scheduled_due = [None]

    class Socket:
        def __init__(self, *_args):
            self.front = None
            self.read = 0

        def accept(self):
            return self.front, None

        def connect_ex(self, _address):
            return 0

        def getsockopt(self, *_args):
            return 0

        def recv(self, _limit):
            self.read += 1
            return payload if self is active_front and self.read == 1 else b""

        def send(self, data):
            if not blocked[0]:
                blocked[0] = True
                raise BlockingIOError
            written.extend(data)
            stopped[0] = True
            return len(data)

        def __getattr__(self, _name):
            return lambda *_args: None

    fronts = [Socket() for _ in range(3)]
    active_front = fronts[2] if profile == "N3" else fronts[0]
    created = []

    def socket_factory(*args):
        sock = Socket(*args)
        if len(created) < 3:
            sock.front = fronts[len(created)]
        created.append(sock)
        return sock

    class Selector:
        def __init__(self):
            self.mapping = {}
            selectors.append(self)

        def register(self, sock, events, data):
            self.mapping[sock] = SimpleNamespace(fileobj=sock, events=events, data=data)

        modify = register

        def unregister(self, sock):
            del self.mapping[sock]

        def get_key(self, sock):
            return self.mapping[sock]

        def get_map(self):
            return self.mapping

        def close(self):
            self.mapping.clear()

        def select(self, timeout):
            if scheduled_due[0] is not None and clock[0] >= scheduled_due[0] and not blocked[0]:
                pytest.fail("到期队头首次发送不应再经过 selector")
            if not startup_idle[0]:
                assert timeout > 0  # 没有数据时不忙轮询。
                startup_idle[0] = True
                clock[0] += 15_625_000
                return []
            if blocked[0] and not waited_for_writable[0]:
                assert timeout > 0  # 已到期但真正不可写时也应允许阻塞。
                waited_for_writable[0] = True
                clock[0] += 15_625_000
                return []
            ready = []
            for key in self.mapping.values():
                if key.data[0] != "stream":
                    ready.append((key, key.events))
                elif key.events & emulator.selectors.EVENT_READ and (
                        key.fileobj is active_front and not key.fileobj.read
                        or empty_readers and key.fileobj.read < (2 if key.fileobj is active_front else 1)):
                    ready.append((key, emulator.selectors.EVENT_READ))
                elif key.events & emulator.selectors.EVENT_WRITE:
                    ready.append((key, emulator.selectors.EVENT_WRITE))
            if ready:
                clock[0] += 10_000
            else:
                idle_waits.append(timeout)
                clock[0] += 15_625_000 if timeout > 0 else 50_000
            return ready

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(emulator.socket, "socket", socket_factory)
    monkeypatch.setattr(emulator.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    enqueue = emulator.Schedule.enqueue
    def remember_due(self, *args):
        row = enqueue(self, *args)
        scheduled_due[0] = row[3]
        return row
    monkeypatch.setattr(emulator.Schedule, "enqueue", remember_due)
    def sleep(delay):
        assert 0 < delay <= min(.00025, (scheduled_due[0] - clock[0])/1e9)
        sleeps.append(delay)
        sleeps_without_fds.append(not selectors[0].mapping)
        clock[0] += math.ceil(delay * 10**9) + (15_625_000 if late_sleep else 0)
    monkeypatch.setattr(emulator.time, "sleep", sleep)
    monkeypatch.setattr(benchmark, "_process_memory", lambda: {"current_rss_bytes": 32 * 1024**2})
    stop = SimpleNamespace(is_set=lambda: stopped[0], wait=lambda _timeout: pytest.fail("不应丢失活动FD"))
    pipe = SimpleNamespace(send=reports.append, close=lambda: None)
    emulator._relay_main(profile, [("127.0.0.1", port, "127.0.0.2") for port in (1, 2, 3)], stop, pipe)
    report = reports[-1]
    assert report["error_type"] is None and written == payload
    direction = report["directions"]["P2->P1" if profile == "N3" else "Client->P1"]
    assert report["model_valid"] is not late_sleep, direction
    assert direction["early_sends"] == 0
    assert direction["backpressure_count"] == 1 and waited_for_writable[0]
    if late_sleep:
        assert report["first_anomaly"] is not None and direction["unexplained_over_tolerance"] > 0
    if profile != "N1":
        assert all(timeout == 0 for timeout in idle_waits)
        assert sleeps and len(idle_waits) <= len(sleeps) + 1  # 每次无就绪都阻塞，不忙等。
        assert any(sleeps_without_fds) is empty_readers
    else:
        assert not sleeps
    assert report["ring"][0][7] >= report["ring"][0][6]
    assert report["ring_version"] == 2 and report["ring"][0][13] == -1
    if late_sleep:
        snapshot = dict(zip(report["first_anomaly_timing_fields"], report["first_anomaly_timing"], strict=True))
        assert snapshot["wait_kind"] == 2
        assert snapshot["wait_returned_ns"] > snapshot["planned_wake_ns"]
        assert snapshot["send_ended_ns"] >= snapshot["send_started_ns"]


def test_due_first_is_fair_bounded_and_blocked_heads_require_real_writable(monkeypatch):
    calls = []
    clock = [100]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    class Writer:
        def __init__(self, name):
            self.name = name
        def send(self, data):
            calls.append(self.name)
            if self.name == emulator.DIRECTIONS[0]:
                raise BlockingIOError()
            return 1 if self.name == emulator.DIRECTIONS[1] else len(data)
    directions = []
    for name in emulator.DIRECTIONS:
        direction = emulator.Direction(None, Writer(name), name, None)
        direction.queue.extend((emulator.Block(b"ab", 0, 0, 0, 0, 100),
                                emulator.Block(b"cd", 2, 0, 0, 0, 100)))
        direction.queued = 4
        directions.append(direction)
    ring = emulator.PublicRing()
    serviced = emulator._serve_due(directions, 3, ring)
    assert calls == list(emulator.DIRECTIONS[3:]+emulator.DIRECTIONS[:3])
    assert serviced == set(emulator.DIRECTIONS) and all(row[13] == -1 for row in ring.rows())
    assert all(d.queued >= 2 for d in directions)  # 每方向一块，不贪婪排空。
    calls.clear()
    directions[2].queue[0].due = 200
    emulator._serve_due(directions, 4, ring)
    assert not set(emulator.DIRECTIONS[:3]).intersection(calls)
    assert directions[0].queue[0].first_attempt == directions[1].queue[0].first_attempt == 100
    for direction in directions[:2]:
        with pytest.raises(RuntimeError, match="真实可写"):
            emulator._progress(direction, 100, None, ring)
    emulator._progress(directions[1], 100, 100, ring)
    assert ring.rows()[-1][13] == 100 and directions[1].queue[0].offset == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows memory API binding")
def test_windows_memory_binding_once_but_each_sample_queries_os(monkeypatch):
    import ctypes
    calls, samples = [], []
    def memory(_handle, pointer, _size):
        samples.append(True)
        if len(samples) == 3:
            return 0
        pointer._obj.peak = 300
        pointer._obj.current = len(samples)*100
        return 1
    def dll(name, **_kwargs):
        calls.append(name)
        return SimpleNamespace(GetCurrentProcess=lambda: 17) if name == "kernel32" else SimpleNamespace(GetProcessMemoryInfo=memory)
    benchmark._windows_memory_api.cache_clear()
    try:
        monkeypatch.setattr(ctypes, "WinDLL", dll)
        assert benchmark._process_memory()["current_rss_bytes"] == 100
        assert benchmark._process_memory()["current_rss_bytes"] == 200
        assert benchmark._process_memory() == {"peak_rss_bytes": None, "scope": "unavailable"}
        assert calls == ["kernel32", "psapi"] and len(samples) == 3
    finally:
        benchmark._windows_memory_api.cache_clear()


@pytest.mark.parametrize("memory", [{"peak_rss_bytes": None}, {"current_rss_bytes": 257*1024**2}])
def test_relay_missing_or_excess_rss_still_fails_before_wait(monkeypatch, memory):
    reports = []
    class Socket:
        def __getattr__(self, _name):
            return lambda *a: None
    selector = SimpleNamespace(register=lambda *a: None, close=lambda: None)
    monkeypatch.setattr(emulator.socket, "socket", lambda *a: Socket())
    monkeypatch.setattr(emulator.selectors, "DefaultSelector", lambda: selector)
    monkeypatch.setattr(benchmark, "_process_memory", lambda: memory)
    emulator._relay_main("N2", [("127.0.0.1", p, "127.0.0.2") for p in (1, 2, 3)],
        SimpleNamespace(is_set=lambda: False), SimpleNamespace(send=reports.append, close=lambda: None))
    assert reports[-1]["error_type"] == "MemoryError" and not reports[-1]["model_valid"]
    assert reports[-1]["first_failure"]["operation"] == "rss"


def _entry(profile, *, passed=True, head="a", sources=None, phase="discovery"):
    return {"profile": profile, "phase": phase, "head": head, "source_sha256": sources or {"src": "a"},
            "maximum_attempts": 10000 if phase == "qualification" else 1000, "finished": True, "sample_pass": passed}


@pytest.fixture
def v2_candidate_context(tmp_path, monkeypatch):
    """软件夹具的五项封闭历史；只替换测试根目录及对应固定摘要，不读真实账本。"""
    monkeypatch.setattr(network, "ROOT", tmp_path)
    head, sources = "c"*40, {"src": "d"*64}
    monkeypatch.setattr(network, "source", lambda: (head, sources))
    directory = tmp_path/".tmp"
    directory.mkdir()
    certs = directory/"certs"
    certs.mkdir()
    hashes = {}
    for name in ("ca.pem", "client.pem", "p1.pem", "p2.pem"):
        (certs/name).write_bytes(name.encode())
        hashes[name] = network.hashlib.sha256(name.encode()).hexdigest()
    environment = {"platform": network.platform.platform(), "python": sys.version.split()[0],
                   "openssl": network.ssl.OPENSSL_VERSION}
    conditions = network.digest({"ports": list(network.V2_PORTS), "environment": environment,
                                "public_certificate_sha256": hashes, "seed": network.SEED})
    history = [_entry("N0"), _entry("N1"), _entry("N2", passed=False),
        _entry("N2", head="b", phase="recheck", passed=False),
        dict(_entry("N2", head="b", phase="candidate", passed=False), wire_profile=network._COMPACT_PROFILE,
             authorization_url="https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-2")]
    for i, entry in enumerate(history):
        entry.update(call=i+1, conditions_sha256=conditions)
    closed = network.digest(history)
    monkeypatch.setattr(network, "V2_CLOSED_HISTORY", closed)
    ledger = directory/"issue120-network-budget.json"
    ledger.write_text(json.dumps({"schema": "network-call-budget-v1", "entries": history}), encoding="utf-8")
    manifest = {"wire_profile": network._COMPACT_PROFILE_V2, "authorization_url": network.V2_AUTHORIZATION,
        "closed_history_sha256": closed, "profile": "N2", "phase": "candidate", "head": head,
        "source_sha256": sources, "call": 6, "maximum_calls": 6, "maximum_attempts": 1000,
        "total_maximum_attempts": 6000, "continuation_maximum_calls": 1, "continuation_maximum_attempts": 1000,
        "eligible_for_candidate": True, "qualification_allowed": False, "ports": list(network.V2_PORTS),
        "environment": environment, "public_certificate_sha256": hashes, "conditions_sha256": conditions,
        "seed": network.SEED, "gc": {"enabled": True, "threshold": [700, 10, 10], "freeze_count": 0, "debug": 0},
        "review_url": "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-1",
        "budget_path": str(ledger.resolve())}
    return history, manifest, ledger, certs


def test_v2_candidate_reserves_original_sixth_once_and_never_qualification(v2_candidate_context):
    history, manifest, ledger, _certs = v2_candidate_context
    for entries in ([], history[:4], history+[dict(history[-1])],
                    [dict(e, finished=False) if i == 4 else e for i, e in enumerate(history)],
                    [dict(e, head="changed") if i == 0 else e for i, e in enumerate(history)]):
        with pytest.raises(ValueError):
            network._next_compact_call(entries, "N2", "candidate", manifest["head"], manifest["source_sha256"], manifest)
    for changes in ({"authorization_url": "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-9"},
                    {"closed_history_sha256": network.digest(history[:4])}, {"wire_profile": network._COMPACT_PROFILE}):
        with pytest.raises(ValueError):
            network._next_compact_call(history, "N2", "candidate", manifest["head"], manifest["source_sha256"], manifest|changes)
    with network.RunBudget(ledger) as budget:
        assert budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"raw.json",
            conditions_sha256=manifest["conditions_sha256"], continuation={k:manifest[k] for k in
                ("wire_profile", "authorization_url", "closed_history_sha256")}) == 1000
        # 实际entry只包含生产reserve生成的字段；夹具manifest的多余报告字段不充当许可。
        network.require_v2_candidate(manifest)
        assert budget.entries[:5] == history and len(budget.entries) == 6
        with pytest.raises(ValueError):
            network.require_v2_candidate(manifest|{"head": "f"*40})
        budget.finish({"cycles": [], "network_sample_pass": False, "failure_category": "StartupError"}, "raw")
    saved = json.loads(ledger.read_text())["entries"]
    assert saved[:5] == history and saved[-1]["actual_attempts"] == 0 and saved[-1]["finished"]
    for entries in (saved, [*history, dict(saved[-1], sample_pass=True)]):
        for phase in ("candidate", "qualification"):
            with pytest.raises(ValueError):
                network._next_compact_call(entries, "N2", phase, manifest["head"], manifest["source_sha256"], manifest)


@pytest.mark.parametrize("passed", [False, True])
def test_v2_candidate_original_wrapper_preserves_manifest_and_consumes_startup(v2_candidate_context, monkeypatch, passed):
    history, manifest, ledger, certs = v2_candidate_context
    approval = ledger.parent/"approval.json"
    approval.write_text(json.dumps(manifest|{"software_pass": True, "readback_exact": True}), encoding="utf-8")
    calls = []
    def observed(**kwargs):
        calls.append(kwargs)
        network.require_v2_candidate(kwargs["candidate_manifest"])
        assert kwargs["steps"] == 1000 and kwargs["wire_profile"] == network._COMPACT_PROFILE_V2
        if not passed:
            raise RuntimeError("software startup witness")
        return {"status": "stopped", "requested_steps": 1000, "cycles": [{}]*1000,
            "wire_profile": network._COMPACT_PROFILE_V2, "network_history": {"finite_sample_pass": True},
            "material_summary": {"encoding_profile": network._COMPACT_PROFILE_V2,
                                 "worker": {"encoding_profile": network._COMPACT_PROFILE_V2}},
            "party_outcomes": [{"wire_profile": network._COMPACT_PROFILE_V2} for _ in range(2)]}
    class Relay:
        def __init__(self, *_args):
            self.report = {"model_valid": True, "process_exited": True, "forced_termination": False}
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
    monkeypatch.setattr(network, "NetworkRelay", Relay)
    monkeypatch.setattr(benchmark, "run_network_observation", observed)
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *a, **k: True)
    monkeypatch.setattr(network, "_tls_pass", lambda _r: True)
    options = {"profile": "N2", "phase": "candidate", "certs": certs, "ports": network.V2_PORTS,
        "ledger": ledger, "approval": approval, "wire_profile": network._COMPACT_PROFILE_V2,
        "authorization": network.V2_AUTHORIZATION}
    result = network.run_network_benchmark(**options, output=ledger.parent/"raw.json")
    assert len(calls) == 1 and result["network_sample_pass"] is passed
    assert all(result[k] is False for k in ("network_dynamic_qualification_pass", "qualification_pass", "stage_pass"))
    assert result["network_manifest"]["continuation_maximum_calls"] == 1
    assert result["network_manifest"]["total_maximum_attempts"] == 6000
    saved = json.loads(ledger.read_text())["entries"]
    assert saved[:5] == history and len(saved) == 6 and saved[-1]["finished"]
    assert saved[-1]["actual_attempts"] == (1000 if passed else 0)
    for changed in ({}, {"phase": "qualification"}, {"authorization": network.V2_AUTHORIZATION+"0"}):
        with pytest.raises(ValueError):
            network.run_network_benchmark(**(options|changed), output=ledger.parent/"retry.json")
    assert len(calls) == 1 and not (ledger.parent/"retry.json").exists()


def test_v2_candidate_assembly_requires_exact_finite_binding(v2_candidate_context, monkeypatch):
    _history, manifest, _ledger, _certs = v2_candidate_context
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *a, **k: True)
    monkeypatch.setattr(network, "_tls_pass", lambda _r: True)
    result = {"status": "stopped", "requested_steps": 1000, "code_sha": manifest["head"],
        "source_sha256": manifest["source_sha256"], "wire_profile": network._COMPACT_PROFILE_V2,
        "network_history": {"finite_sample_pass": True}, "party_outcomes": [{"wire_profile": network._COMPACT_PROFILE_V2}]*2,
        "material_summary": {"encoding_profile": network._COMPACT_PROFILE_V2,
                             "worker": {"encoding_profile": network._COMPACT_PROFILE_V2}}}
    relay = {"model_valid": True, "process_exited": True, "forced_termination": False}
    assert network.assemble(copy.deepcopy(result), profile="N2", phase="candidate", manifest=manifest,
                            relay=relay)["network_sample_pass"]
    assert not network.assemble(copy.deepcopy(result), profile="N2", phase="candidate", manifest={},
                                relay=relay)["network_sample_pass"]
    for key, value in (("head", "old"), ("closed_history_sha256", "0"*64), ("phase", "qualification"),
            ("authorization_url", network.V2_AUTHORIZATION+"0"), ("maximum_attempts", 10000),
            ("eligible_for_candidate", False), ("qualification_allowed", True), ("maximum_calls", True),
            ("continuation_maximum_calls", 2), ("ports", [1,2,3])):
        assert not network.assemble(copy.deepcopy(result), profile="N2", phase="candidate", manifest=manifest|{key:value},
                                    relay=relay)["network_sample_pass"]
    for changed in ({"model_valid": False}, {"forced_termination": True}, {"process_exited": False}):
        assert not network.assemble(copy.deepcopy(result), profile="N2", phase="candidate", manifest=manifest,
                                    relay=relay|changed)["network_sample_pass"]
    for changed in ({"code_sha": "old"}, {"source_sha256": {}}, {"network_source_integrity_failed": True},
                    {"network_history": {"finite_sample_pass": False}}, {"requested_steps": 10000}):
        assert not network.assemble(copy.deepcopy(result)|changed, profile="N2", phase="candidate", manifest=manifest,
                                    relay=relay)["network_sample_pass"]
    assert not network.assemble(copy.deepcopy(result), profile="N2", phase="qualification", manifest=manifest,
                                relay=relay)["network_dynamic_qualification_pass"]


def test_v2_candidate_shared_and_actual_loop_require_reserved_context(v2_candidate_context, monkeypatch):
    _history, manifest, ledger, certs = v2_candidate_context
    configs = network.role_configs(certs, network.V2_PORTS, "N2")
    captured = []
    monkeypatch.setattr(benchmark, "_run_material_comparison", lambda options, *a, **k: captured.append(options))
    with pytest.raises(ValueError):
        benchmark.run_network_observation(configs=configs, steps=1000, wire_profile=network._COMPACT_PROFILE_V2)
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"raw.json",
            conditions_sha256=manifest["conditions_sha256"], continuation={k:manifest[k] for k in
                ("wire_profile", "authorization_url", "closed_history_sha256")})
        benchmark.run_network_observation(configs=configs, steps=1000,
            wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
        assert len(captured) == 1 and captured[0]["network_candidate_manifest"] == manifest
        for wrong in (network.role_configs(certs, network.V2_PORTS, "N0"),
                      network.role_configs(certs, (55131, 55132, 55133), "N2")):
            with pytest.raises(ValueError):
                benchmark.run_network_observation(configs=wrong, steps=1000,
                    wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
        with pytest.raises(ValueError):
            benchmark.run_network_observation(configs=configs, steps=10000,
                wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
        def forbidden_context(*_args):
            raise RuntimeError("software witness before creating any process")
        monkeypatch.setattr(benchmark.mp, "get_context", forbidden_context)
        actual_options = captured[0]|{"stage_wait_diagnostic": True}
        with pytest.raises(ValueError):
            benchmark._run_continuous_observation(**(actual_options|{"network_candidate_manifest": None}),
                material_candidate="worker")
        for wrong in ({"steps": 10000}, {"segment_steps": 2}, {"delay_ms": 1}, {"_gc_trial": object()},
                      {"recording_mode": "full"}, {"timeout_trace": True}, {"preload_steps": 1000},
                      {"stage_wait_diagnostic": False}):
            with pytest.raises(ValueError):
                benchmark._run_continuous_observation(**(actual_options|wrong), material_candidate="worker")
        with pytest.raises(RuntimeError, match="software witness"):
            benchmark._run_continuous_observation(**actual_options, material_candidate="worker")


def test_v2_candidate_real_adapter_selects_versioned_history_before_processes(v2_candidate_context, monkeypatch):
    _history, manifest, ledger, certs = v2_candidate_context
    configs = network.role_configs(certs, network.V2_PORTS, "N2")
    captured, process_contexts = [], []
    original = benchmark._run_continuous_observation
    def observed(**kwargs):
        captured.append(kwargs)
        return original(**kwargs)
    def context(*_args):
        process_contexts.append(True)
        raise RuntimeError("software witness before constructing any role")
    monkeypatch.setattr(benchmark, "_run_continuous_observation", observed)
    monkeypatch.setattr(benchmark.mp, "get_context", context)
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"raw.json",
            conditions_sha256=manifest["conditions_sha256"], continuation={k:manifest[k] for k in
                ("wire_profile", "authorization_url", "closed_history_sha256")})
        result = benchmark.run_network_observation(configs=configs, steps=1000,
            wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
    assert len(captured) == len(process_contexts) == 1
    assert captured[0]["stage_wait_diagnostic"] is True
    assert captured[0]["_compact_history"].wire_profile == network._COMPACT_PROFILE_V2
    assert captured[0]["network_candidate_manifest"] == manifest
    assert result["status"] == "failed" and result["cycles"] == []


@pytest.mark.parametrize("entrypoint", ["shared", "actual"])
def test_v2_changed_certificate_and_matching_reservation_cannot_bypass_history(
        v2_candidate_context, monkeypatch, entrypoint):
    """RV-005：同时改候选和占项也不能自行改变冻结条件。"""
    _history, manifest, ledger, certs = v2_candidate_context
    configs = network.role_configs(certs, network.V2_PORTS, "N2")
    captured = []
    monkeypatch.setattr(benchmark, "_run_material_comparison", lambda options, *a, **k: captured.append(options))
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"raw.json",
            conditions_sha256=manifest["conditions_sha256"], continuation={k: manifest[k] for k in
                ("wire_profile", "authorization_url", "closed_history_sha256")})
        benchmark.run_network_observation(configs=configs, steps=1000,
            wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
        (certs/"p1.pem").write_bytes(b"unapproved replacement")
        changed = copy.deepcopy(manifest)
        changed["public_certificate_sha256"]["p1.pem"] = network.hashlib.sha256(b"unapproved replacement").hexdigest()
        changed["conditions_sha256"] = network.digest({k: changed[k] for k in
            ("ports", "environment", "public_certificate_sha256", "seed")})
        budget.entries[-1]["conditions_sha256"] = changed["conditions_sha256"]
        budget._save()
        def forbidden(*_args):
            pytest.fail("unapproved conditions reached process creation")
        monkeypatch.setattr(benchmark.mp, "get_context", forbidden)
        with pytest.raises(ValueError):
            if entrypoint == "shared":
                benchmark.run_network_observation(configs=configs, steps=1000,
                    wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=changed)
            else:
                benchmark._run_continuous_observation(**(captured[0]|{"stage_wait_diagnostic": True,
                    "network_candidate_manifest": changed}), material_candidate="worker")


@pytest.fixture
def v2_certificate_context(v2_candidate_context):
    """只在隔离测试根目录生成软件证书；不创建本次真实运行证书。"""
    history, original, ledger, _certs = v2_candidate_context
    certs = ledger.parent/"issue120-compact-v2-certs"
    subprocess.run([sys.executable, str(ROOT/"tests/fixtures/prepare_local_lan_certs.py"),
                    "--output", str(certs)], check=True, capture_output=True)
    validity = {}
    for name in original["public_certificate_sha256"]:
        decoded = network.ssl._ssl._test_decode_cert(str(certs/name))
        validity[name] = {key: network.datetime.fromtimestamp(network.ssl.cert_time_to_seconds(decoded[field]),
            network.UTC).isoformat() for key, field in (("not_before", "notBefore"), ("not_after", "notAfter"))}
    manifest = original | {"certificate_change_authorization_url": network.V2_CERTIFICATE_AUTHORIZATION,
        "previous_public_certificate_sha256": original["public_certificate_sha256"],
        "previous_conditions_sha256": original["conditions_sha256"],
        "public_certificate_sha256": {name: network.hashlib.sha256((certs/name).read_bytes()).hexdigest()
                                      for name in original["public_certificate_sha256"]},
        "public_certificate_validity": validity, "certificate_change_reason": "expired_test_certificates"}
    manifest["conditions_sha256"] = network.digest({k: manifest[k] for k in
        ("ports", "environment", "public_certificate_sha256", "seed")})
    return history, manifest, ledger, certs


def test_v2_certificate_exception_is_bound_before_shared_and_actual_processes(v2_certificate_context, monkeypatch):
    history, manifest, ledger, certs = v2_certificate_context
    configs = network.role_configs(certs, network.V2_PORTS, "N2")
    captured, contexts = [], []
    original = benchmark._run_continuous_observation
    def observe(**kwargs):
        captured.append(kwargs)
        return original(**kwargs)
    def forbidden(*_args):
        contexts.append(True)
        raise RuntimeError("approved software boundary; no role constructed")
    monkeypatch.setattr(benchmark, "_run_continuous_observation", observe)
    monkeypatch.setattr(benchmark.mp, "get_context", forbidden)
    continuation = {k: manifest[k] for k in ("wire_profile", "authorization_url", "closed_history_sha256",
                                            *network.V2_CERTIFICATE_FIELDS, "public_certificate_sha256")}
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"raw.json",
            conditions_sha256=manifest["conditions_sha256"], continuation=continuation)
        result = benchmark.run_network_observation(configs=configs, steps=1000,
            wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
        assert result["failure_category"] == "RuntimeError" and contexts == [True]
        assert budget.entries[:5] == history
        for field in (*network.V2_CERTIFICATE_FIELDS, "public_certificate_sha256"):
            assert budget.entries[-1][field] == manifest[field]
        wrongs = [{k: v for k, v in manifest.items() if k != field} for field in network.V2_CERTIFICATE_FIELDS]
        wrongs += [manifest|{"certificate_change_authorization_url": network.V2_CERTIFICATE_AUTHORIZATION+"0"},
                   manifest|{"previous_conditions_sha256": "0"*64}]
        for field, value in (("ports", [55131, 55132, 55133]), ("environment", manifest["environment"]|{"python": "other"}),
                             ("seed", network.SEED+1)):
            changed = manifest | {field: value}
            changed["conditions_sha256"] = network.digest({k: changed[k] for k in
                ("ports", "environment", "public_certificate_sha256", "seed")})
            wrongs.append(changed)
        for wrong in wrongs:
            # 占项跟着错误manifest一起改，仍须由共同历史约束拒绝。
            budget.entries[-1].update({k: wrong.get(k) for k in (*continuation, "conditions_sha256")})
            budget._save()
            with pytest.raises(ValueError):
                benchmark.run_network_observation(configs=configs, steps=1000,
                    wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=wrong)
            with pytest.raises(ValueError):
                original(**(captured[0]|{"network_candidate_manifest": wrong}))
        assert contexts == [True]
        budget.entries[-1].update(continuation, conditions_sha256=manifest["conditions_sha256"])
        budget._save()
        (certs/"p1.pem").write_bytes(b"changed after public fingerprint freeze")
        with pytest.raises(ValueError):
            benchmark.run_network_observation(configs=configs, steps=1000,
                wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=manifest)
        assert contexts == [True]


def test_v2_certificate_wrapper_preflight_and_startup_failure_preserve_five(v2_certificate_context, monkeypatch):
    history, manifest, ledger, certs = v2_certificate_context
    approval = ledger.parent/"approval.json"
    options = {"profile": "N2", "phase": "candidate", "certs": certs, "ports": network.V2_PORTS,
        "ledger": ledger, "approval": approval, "output": ledger.parent/"raw.json",
        "wire_profile": network._COMPACT_PROFILE_V2, "authorization": network.V2_AUTHORIZATION}
    wrong_hash = manifest|{"public_certificate_sha256": manifest["public_certificate_sha256"]|{"p1.pem": "0"*64}}
    wrong_hash["conditions_sha256"] = network.digest({k: wrong_hash[k] for k in
        ("ports", "environment", "public_certificate_sha256", "seed")})
    for wrong in (manifest|{"previous_conditions_sha256": "0"*64},
                  manifest|{"public_certificate_validity": {}},
                  {k: v for k, v in manifest.items() if k != "certificate_change_authorization_url"},
                  wrong_hash):
        approval.write_text(json.dumps(wrong|{"software_pass": True, "readback_exact": True}), encoding="utf-8")
        with pytest.raises(ValueError):
            network.run_network_benchmark(**options)
        assert json.loads(ledger.read_text())["entries"] == history and not options["output"].exists()
    class Relay:
        def __init__(self, *_args):
            pytest.fail("software startup stopped before relay creation")
    def startup(*_args):
        raise RuntimeError("software startup failure after reservation")
    monkeypatch.setattr(network, "NetworkRelay", Relay)
    monkeypatch.setattr(network, "role_configs", startup)
    approval.write_text(json.dumps(manifest|{"software_pass": True, "readback_exact": True}), encoding="utf-8")
    result = network.run_network_benchmark(**options)
    saved = json.loads(ledger.read_text())["entries"]
    assert saved[:5] == history and len(saved) == 6 and saved[-1]["finished"]
    assert saved[-1]["actual_attempts"] == 0 and not result["network_sample_pass"]
    assert result["network_manifest"]["certificate_change_authorization_url"] == network.V2_CERTIFICATE_AUTHORIZATION
    with pytest.raises(ValueError):
        network.run_network_benchmark(**(options|{"output": ledger.parent/"retry.json"}))


def test_v2_certificate_offline_check_rejects_expiry_identity_chain_and_hash(v2_certificate_context):
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import Encoding

    _history, manifest, _ledger, certs = v2_certificate_context
    assert network.certificate_validity(certs) == manifest["public_certificate_validity"]
    end = network.datetime.fromisoformat(manifest["public_certificate_validity"]["p1.pem"]["not_after"])
    for offset in (0, 3599, 25*3600+1):
        with pytest.raises(ValueError):
            network.certificate_validity(certs, now=end-timedelta(seconds=offset))
    original = (certs/"p1.pem").read_bytes()
    (certs/"p1.pem").write_bytes((certs/"p2.pem").read_bytes())
    with pytest.raises(ValueError):
        network.certificate_validity(certs)
    (certs/"p1.pem").write_bytes(original)
    encoded = bytearray(x509.load_pem_x509_certificate(original).public_bytes(Encoding.DER))
    encoded[-1] ^= 1
    (certs/"p1.pem").write_bytes(x509.load_der_x509_certificate(bytes(encoded)).public_bytes(Encoding.PEM))
    with pytest.raises(InvalidSignature):
        network.certificate_validity(certs)
    (certs/"p1.pem").write_bytes(original)
    (certs/"ca.pem").write_bytes(original)
    with pytest.raises(ValueError):
        network.certificate_validity(certs)


def test_budget_failure_repair_recheck_and_final_call_cap(tmp_path):
    entries = [_entry("N0", passed=False)]
    with pytest.raises(ValueError, match="暂停"):
        network.next_call(entries, "N1", "discovery", "a", {"src": "a"})
    with pytest.raises(ValueError, match="唯一同条件"):
        network.next_call(entries, "N0", "recheck", "a", {"src": "a"}, "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-1")
    note = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-2"
    assert network.next_call(entries, "N0", "recheck", "b", {"src": "b"}, note) == 1000
    entries.append(_entry("N0", head="b", sources={"src": "b"}, phase="recheck"))
    with pytest.raises(ValueError, match="暂停"):
        network.next_call(entries+[_entry("N1", head="b", sources={"src": "b"}, passed=False)],
                          "N2", "discovery", "b", {"src": "b"})
    for profile in ("N1", "N2", "N3"):
        assert network.next_call(entries, profile, "discovery", "b", {"src": "b"}) == 1000
        entries.append(_entry(profile, head="b", sources={"src": "b"}))
    assert network.next_call(entries, "N2", "qualification", "b", {"src": "b"}) == 10000
    with pytest.raises(ValueError, match="当前SHA"):
        network.next_call(entries, "N2", "qualification", "c", {"src": "b"})
    entries.append(_entry("N2", head="b", sources={"src": "b"}, phase="qualification"))
    with pytest.raises(ValueError, match="额度耗尽"):
        network.next_call(entries, "N2", "qualification", "b", {"src": "b"})
    path = tmp_path/"calls.json"
    with network.RunBudget(path) as budget:
        budget.reserve("N0", "discovery", "a", {"src": "a"}, tmp_path/"raw.json")
        with pytest.raises(FileExistsError), network.RunBudget(path):
            pytest.fail("cannot acquire an active session")
    with network.RunBudget(path) as budget, pytest.raises(ValueError, match="在途"):
        budget.reserve("N1", "discovery", "a", {"src": "a"}, tmp_path/"second.json")
    assert len(json.loads(path.read_text())["entries"]) == 1


def test_compact_continuation_appends_same_closed_ledger_and_never_retries(tmp_path):
    """新批准保留四项旧失败；失败启动、改源、二次候选与第三次调用均拒绝。"""
    old = [_entry("N0"), _entry("N1"), _entry("N2", passed=False),
           _entry("N2", head="b", sources={"src": "b"}, phase="recheck", passed=False)]
    continuation = {"wire_profile": network._COMPACT_PROFILE,
        "authorization_url": "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-2",
        "closed_history_sha256": network.digest(old)}
    path = tmp_path/"same-ledger.json"
    path.write_text(json.dumps({"schema": "network-call-budget-v1", "entries": old}), encoding="utf-8")
    for entries in ([], old[:-1], [dict(e, sample_pass=True) for e in old]):
        with pytest.raises(ValueError):
            network._next_compact_call(entries, "N2", "candidate", "c", {"src": "c"}, continuation)
    with network.RunBudget(path) as budget:
        assert budget.reserve("N2", "candidate", "c", {"src": "c"}, tmp_path/"candidate.json",
                              continuation=continuation) == 1000
    saved = json.loads(path.read_text())["entries"]
    assert saved[:4] == old and len(saved) == 5
    with network.RunBudget(path) as budget, pytest.raises(ValueError):
        budget.reserve("N2", "candidate", "c", {"src": "c"}, tmp_path/"retry.json", continuation=continuation)
    for passed in (False, True):
        entries = copy.deepcopy(saved)
        entries[-1].update(finished=True, sample_pass=passed)
        for profile, phase, head, sources in (("N3", "candidate", "c", {"src": "c"}),
                ("N2", "candidate", "c", {"src": "c"}), ("N2", "qualification", "d", {"src": "d"})):
            with pytest.raises(ValueError):
                network._next_compact_call(entries, profile, phase, head, sources, continuation)
        if not passed:
            with pytest.raises(ValueError):
                network._next_compact_call(entries, "N2", "qualification", "c", {"src": "c"}, continuation)
        else:
            assert network._next_compact_call(entries, "N2", "qualification", "c", {"src": "c"}, continuation) == 10000
            entries.append(dict(entries[-1], phase="qualification", maximum_attempts=10000))
            with pytest.raises(ValueError):
                network._next_compact_call(entries, "N2", "qualification", "c", {"src": "c"}, continuation)
    assert json.loads(path.read_text())["entries"][:4] == old
    with network.RunBudget(path) as budget:
        budget.finish({"cycles": [], "network_sample_pass": False, "failure_category": "StartupError"}, "raw")
    stopped = json.loads(path.read_text())["entries"]
    assert stopped[-1]["actual_attempts"] == 0 and stopped[-1]["finished"]
    with pytest.raises(ValueError):
        network._next_compact_call(stopped, "N2", "candidate", "c", {"src": "c"}, continuation)


def test_peer_stress_failure_does_not_redefine_target_or_allow_seventh_call():
    entries = [_entry(p, passed=p != "N3") for p in network.PROFILES]
    assert network.next_call(entries, "N2", "qualification", "a", {"src": "a"}) == 10000
    note = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-3"
    with pytest.raises(ValueError, match="唯一同条件"):
        network.next_call(entries, "N3", "recheck", "b", {"src": "b"}, note)
    assert network.next_call(entries, "N2", "recheck", "b", {"src": "b"}, note) == 1000
    entries.append(_entry("N2", phase="recheck", head="b", sources={"src": "b"}, passed=False))
    with pytest.raises(ValueError, match="闭环已结束"):
        network.next_call(entries, "N2", "qualification", "b", {"src": "b"})
    with pytest.raises(ValueError, match="结构或步数"):
        network.next_call([_entry("N0") | {"maximum_attempts": -1}], "N1", "discovery", "a", {"src": "a"})


def test_network_gate_requires_shared_full_evidence_tls_and_model(monkeypatch):
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *_args, **_kwargs: True)
    states = {role: {"restored": True, "links": [{"role": role,
        "peer_identity": f"{peer.lower()}.secure-control.test", "version": "TLSv1.3", "tcp_nodelay": 1,
        "peer_san": [("DNS", f"{peer.lower()}.secure-control.test")]} for peer in ("Client", "P1", "P2") if peer != role]}
        for role in ("Client", "P1", "P2")}
    base = {"status": "stopped", "requested_steps": 10000, "network_history": {"finite_sample_pass": True},
        "network_tls": states["Client"], "party_outcomes": [{"role": r, "network_tls": states[r]} for r in ("P1", "P2")]}
    relay = {"model_valid": True, "process_exited": True, "forced_termination": False}
    result = network.assemble(copy.deepcopy(base), profile="N2", phase="qualification", manifest={}, relay=relay)
    assert result["network_dynamic_qualification_pass"] and not result["qualification_pass"] and not result["local_dynamic_qualification_pass"]
    for mutation in (lambda r: r["network_tls"].update(restored=False),
                     lambda r: r["network_tls"]["links"][0].update(version="TLSv1.2"),
                     lambda r: r["network_tls"]["links"][0].update(peer_san=[("DNS", "other")])):
        bad = copy.deepcopy(base)
        mutation(bad)
        assert not network.assemble(bad, profile="N2", phase="qualification", manifest={}, relay=relay)["network_sample_pass"]
    assert not network.assemble(copy.deepcopy(base), profile="N2", phase="qualification", manifest={},
                               relay=relay | {"model_valid": False})["network_dynamic_qualification_pass"]
    compact = copy.deepcopy(base)
    compact["wire_profile"] = network._COMPACT_PROFILE
    compact["material_summary"] = {"encoding_profile": network._COMPACT_PROFILE,
        "worker": {"encoding_profile": network._COMPACT_PROFILE}}
    for outcome in compact["party_outcomes"]:
        outcome["wire_profile"] = network._COMPACT_PROFILE
    manifest = {"wire_profile": network._COMPACT_PROFILE}
    assert network.assemble(copy.deepcopy(compact), profile="N2", phase="qualification", manifest=manifest,
                            relay=relay)["network_dynamic_qualification_pass"]
    software_only = copy.deepcopy(compact)
    software_only["wire_profile"] = network._COMPACT_PROFILE_V2
    software_only["material_summary"] = {"encoding_profile": network._COMPACT_PROFILE_V2,
        "worker": {"encoding_profile": network._COMPACT_PROFILE_V2}}
    for outcome in software_only["party_outcomes"]:
        outcome["wire_profile"] = network._COMPACT_PROFILE_V2
    assert not network.assemble(software_only, profile="N2", phase="qualification",
        manifest={"wire_profile": network._COMPACT_PROFILE_V2}, relay=relay)["network_dynamic_qualification_pass"]
    for remove in (lambda r: r.pop("wire_profile"), lambda r: r["material_summary"]["worker"].clear(),
                   lambda r: r["party_outcomes"][1].pop("wire_profile")):
        bad = copy.deepcopy(compact)
        remove(bad)
        assert not network.assemble(bad, profile="N2", phase="qualification", manifest=manifest, relay=relay)["network_sample_pass"]
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *_args, **_kwargs: False)
    assert not network.assemble(copy.deepcopy(base), profile="N2", phase="qualification", manifest={}, relay=relay)["network_dynamic_qualification_pass"]


def test_new_shared_entry_keeps_old_bare_tcp_guard_and_rejects_mixed_configs(tmp_path, monkeypatch):
    configs = network.role_configs(tmp_path, (55121, 55122, 55123), "N2")
    captured = []
    monkeypatch.setattr(benchmark, "_run_material_comparison", lambda *a, **k: captured.append((a, k)))
    benchmark.run_network_observation(configs=configs, steps=1000)
    assert captured[0][0][0]["network_configs"] == configs
    benchmark.run_network_observation(configs=configs, steps=1000, wire_profile=network._COMPACT_PROFILE)
    assert captured[-1][0][0]["network_wire_profile"] == network._COMPACT_PROFILE
    with pytest.raises(ValueError):
        benchmark.run_network_observation(configs=configs, steps=1000, wire_profile="unknown")
    with pytest.raises(ValueError):
        benchmark.run_network_observation(configs=configs, steps=1000, wire_profile=network._COMPACT_PROFILE_V2)
    for bad in (configs[:2], (replace(configs[0], transport="insecure_tcp"), *configs[1:]),
                (configs[0], replace(configs[1], topology=replace(configs[1].topology, digest="different")), configs[2])):
        with pytest.raises(ValueError):
            benchmark.run_network_observation(configs=bad, steps=1000)
    with pytest.raises(ValueError):
        benchmark.run_network_observation(configs=configs, steps=20)
    with pytest.raises(ValueError, match="QPC接收"):
        benchmark.run_continuous_observation(steps=10000, delay_ms=0, segment_steps=400, optimized=True,
            recording_mode="light", qpc_dynamic_qualification=True, role_config=tmp_path/"tls.yaml")


def test_network_cli_is_exclusive_and_does_not_accept_arbitrary_steps(tmp_path, monkeypatch):
    from secure_control.experiments import lan_runner

    calls = []
    def completed(**kwargs):
        calls.append(kwargs)
        return {"status": "stopped", "network_sample_pass": True,
                "network_dynamic_qualification_pass": False, "cycles": [], "network_export_ns": 1}
    monkeypatch.setattr(network, "run_network_benchmark", completed)
    argv = ["secure-control", "benchmark", "--case", "cycle", "--network-profile", "N0",
        "--network-phase", "discovery", "--network-certs", str(tmp_path), "--network-ports", "55121,55122,55123",
        "--network-ledger", str(tmp_path/"calls.json"), "--network-approval", str(tmp_path/"approval.json"),
        "--output", str(tmp_path/"raw.json")]
    monkeypatch.setattr(sys, "argv", argv)
    assert lan_runner._run() == 0 and len(calls) == 1
    for extra in (("--steps", "20"), ("--qpc-dynamic-qualification",), ("--diagnostic",),
                  ("--recording", "full"), ("--segment-steps", "8"), ("--mode", "legacy")):
        monkeypatch.setattr(sys, "argv", argv+list(extra))
        assert lan_runner._run() == 5 and len(calls) == 1
    compact = ["N2" if a == "N0" else "candidate" if a == "discovery" else a for a in argv]
    compact += ["--network-wire-profile", network._COMPACT_PROFILE, "--network-authorization",
                "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-2"]
    monkeypatch.setattr(sys, "argv", compact)
    assert lan_runner._run() == 0 and calls[-1]["wire_profile"] == network._COMPACT_PROFILE
    for key, bad in (("--network-authorization", "wrong"), ("--network-profile", "N1"), ("--network-phase", "recheck")):
        invalid = list(compact)
        invalid[invalid.index(key)+1] = bad
        monkeypatch.setattr(sys, "argv", invalid)
        assert lan_runner._run() == 5 and len(calls) == 2
    v2 = [network._COMPACT_PROFILE_V2 if v == network._COMPACT_PROFILE else
          network.V2_AUTHORIZATION if v.endswith("issuecomment-2") else v for v in compact]
    monkeypatch.setattr(sys, "argv", v2)
    assert lan_runner._run() == 0 and calls[-1]["wire_profile"] == network._COMPACT_PROFILE_V2
    for key, bad in (("--network-phase", "qualification"), ("--network-profile", "N3"),
                     ("--network-authorization", network.V2_AUTHORIZATION+"0"), ("--network-ports", "55131,55132,55133")):
        invalid = list(v2)
        invalid[invalid.index(key)+1] = bad
        monkeypatch.setattr(sys, "argv", invalid)
        assert lan_runner._run() == 5 and len(calls) == 3


def test_startup_failure_is_exported_and_consumes_unique_discovery(tmp_path, monkeypatch):
    import platform

    head, fingerprints = "a", {"src": "a"}
    monkeypatch.setattr(network, "source", lambda: (head, fingerprints))
    def failed(**kwargs):
        raise RuntimeError("software startup witness")
    monkeypatch.setattr(benchmark, "run_network_observation", failed)
    certificate_hashes = {}
    for name in ("ca.pem", "client.pem", "p1.pem", "p2.pem"):
        (tmp_path/name).write_bytes(name.encode())
        certificate_hashes[name] = network.hashlib.sha256(name.encode()).hexdigest()
    approval = tmp_path/"approval.json"
    approval.write_text(json.dumps({"head": head, "source_sha256": fingerprints, "software_pass": True,
        "readback_exact": True, "ports": [55121, 55122, 55123],
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0], "openssl": network.ssl.OPENSSL_VERSION},
        "review_url": "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-1",
        "public_certificate_sha256": certificate_hashes}), encoding="utf-8")
    options = {"profile": "N0", "phase": "discovery", "certs": tmp_path, "ports": (55121, 55122, 55123),
               "ledger": tmp_path/"ledger.json", "approval": approval}
    result = network.run_network_benchmark(**options, output=tmp_path/"first.json")
    assert result["status"] == "failed" and result["cycles"] == [] and result["failure_category"] == "RuntimeError"
    assert not result["network_dynamic_qualification_pass"]
    stored = json.loads((tmp_path/"ledger.json").read_text())
    assert len(stored["entries"]) == 1 and stored["entries"][0]["finished"] and stored["entries"][0]["actual_attempts"] == 0
    with pytest.raises(ValueError):
        network.run_network_benchmark(**options, output=tmp_path/"second.json")
    assert not (tmp_path/"second.json").exists() and not (tmp_path/"ledger.json.lock").exists()


@pytest.mark.integration
def test_three_tls_links_cross_opaque_relay_and_wrong_role_still_fails(tmp_path):
    subprocess.run([sys.executable, str(ROOT/"tests/fixtures/prepare_local_lan_certs.py"),
                    "--output", str(tmp_path)], check=True, capture_output=True)
    ports = free_ports()
    configs = {c.role: c for c in network.role_configs(tmp_path, ports, "N1")}
    endpoints = (configs["Client"].topology.p1_client, configs["Client"].topology.p2_client, configs["Client"].topology.p1_peer)
    servers = [lan_transport.listener(e) for e in endpoints]
    payload = b"opaque-test-marker-" + bytes(range(256))*64
    errors, versions = [], []
    relay = emulator.NetworkRelay("N1", tuple(("127.0.0.1", p, "127.0.0.2") for p in ports))
    try:
        with relay:
            for index, (dialer, acceptor) in enumerate((("Client", "P1"), ("Client", "P2"), ("P2", "P1"))):
                replied = Event()
                def accept(index=index, dialer=dialer, acceptor=acceptor, replied=replied):
                    secure = None
                    try:
                        secure = lan_transport.accept_role(servers[index], configs[acceptor], dialer, time.monotonic()+5)
                        versions.append(secure.version())
                        assert localhost_transport.receive_frame(secure, deadline=time.monotonic()+5, limit=65536) == payload
                        localhost_transport.send_frame(secure, payload[::-1], deadline=time.monotonic()+5, limit=65536)
                        replied.set()
                    except Exception as error:  # noqa: BLE001 - 测试线程把原失败交回父断言。
                        errors.append(error)
                    finally:
                        if secure is not None:
                            secure.close()
                thread = Thread(target=accept)
                thread.start()
                client = lan_transport.connect_role(endpoints[index], configs[dialer], acceptor, time.monotonic()+5)
                try:
                    versions.append(client.version())
                    localhost_transport.send_frame(client, payload, deadline=time.monotonic()+5, limit=65536)
                    assert replied.wait(5)
                    # 同一进程中的服务端已退出framing；只装Client的原轻量观察，验证TLS透明包装。
                    observer = benchmark._StageWaitDiagnostic(dialer, ports)
                    with observer.installed():
                        deadline = benchmark.time.perf_counter_ns()+5_000_000_000
                        from secure_control.execution.cycle_timing import network_deadline
                        assert localhost_transport.receive_frame(client, deadline=network_deadline(5, deadline), limit=65536) == payload[::-1]
                    assert observer.trace_restored and observer.first_failure is None
                finally:
                    client.close()
                    thread.join(6)
                assert not thread.is_alive() and not errors
        assert versions == ["TLSv1.3"]*6 and relay.report["process_exited"]
        assert relay.report["encoded_bytes"] <= 64*1024 and "opaque-test-marker" not in json.dumps(relay.report)
        assert all(s["received_bytes"] == s["sent_bytes"] for s in relay.report["directions"].values())
    finally:
        for server in servers:
            server.close()
    # 原SAN验证器拒绝其他角色；转发层不持钥也没有更改此边界。
    class WrongPeer:
        def getpeercert(self):
            return {"subjectAltName": (("DNS", "p2.secure-control.test"),)}

        def version(self):
            return "TLSv1.3"
    with pytest.raises(lan_transport.LanIdentityError):
        lan_transport._verify_identity(WrongPeer(), "client.secure-control.test")


def _tls_protocol_party_fixture(config, ports, queue, wire_profile):
    """子进程实际 framing 计数；不使用协议常数代替发包事实。"""
    operations = []
    original = localhost_transport.send_frame
    def sent(sock, data, **kwargs):
        operations.append(localhost_transport.decode_envelope(data).operation)
        return original(sock, data, **kwargs)
    def put(outcome):
        outcome["fixture_sent_operations"] = operations
        queue.put(outcome)
    localhost_transport.send_frame = sent
    try:
        benchmark._party_job(config, ports, 0., True, SimpleNamespace(put=put),
            network_observation=True, wire_profile=wire_profile, stage_wait_diagnostic=True)
    finally:
        localhost_transport.send_frame = original


@pytest.mark.integration
@pytest.mark.parametrize("wire_profile,expected_frames,fault", (
    (None, 19, None), (network._COMPACT_PROFILE, 15, None),
    ("control-dynamic-compact-v2", 15, None), ("control-dynamic-compact-v2", 15, "bad_epoch"),
    ("control-dynamic-compact-v2", 15, "bad_global"), ("control-dynamic-compact-v2", 15, "duplicate")))
def test_tls_protocol_fixture_preserves_fused_frames_worker_cleanup_segments_and_stop(
        tmp_path, monkeypatch, wire_profile, expected_frames, fault):
    """仅五轮协议功能夹具，无 plant、20ms周期或性能资格入口。"""
    import multiprocessing as mp

    from secure_control.execution import lan_runtime as runtime_module
    from secure_control.execution.lan_runtime import LanSegmentedRuntime, RunControl
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    subprocess.run([sys.executable, str(ROOT/"tests/fixtures/prepare_local_lan_certs.py"),
                    "--output", str(tmp_path)], check=True, capture_output=True)
    ports = free_ports()
    configs = network.role_configs(tmp_path, ports, "N0")
    context = mp.get_context("spawn")
    queue = context.Queue()
    parties = [context.Process(target=_tls_protocol_party_fixture,
        args=(config, ports, queue, wire_profile)) for config in configs[1:]]
    runtime = None
    restore = lambda: None
    try:
        for process in parties:
            process.start()
        prepared = load_segmented_experiment(configs[0].experiment_config, 400, InteractiveSession())
        control = RunControl()
        counts, _, restore = benchmark._meter("Client", ports, 0.)
        runtime = LanSegmentedRuntime(configs[0], prepared.spec, prepared.context, prepared.contract,
            prepared.security_parameter, prepared.evidence, control=control, segment_capacity=2,
            **({"wire_profile": wire_profile} if wire_profile else {}))
        runtime.enable_material_preparation(slots=16, _candidate="worker")
        before = sum(row["frames"] for row in counts.values())
        operations = []
        previous_advance = []
        original_send = runtime_module.localhost_transport.send_frame
        def sent(sock, data, **kwargs):
            request = runtime_module.localhost_transport.decode_envelope(data)
            operations.append(request.operation)
            if request.operation == "segment_advance" and request.recipient == "P2":
                if fault == "duplicate" and previous_advance:
                    data = previous_advance[0]
                elif fault in {"bad_epoch", "bad_global"}:
                    value = json.loads(data)
                    value["payload"]["begin"]["controller_epoch" if fault == "bad_epoch" else "global_start"] = (
                        "f"*64 if fault == "bad_epoch" else 999)
                    data = json.dumps(value, separators=(",", ":")).encode()
                previous_advance.append(data)
            return original_send(sock, data, **kwargs)
        monkeypatch.setattr(runtime_module.localhost_transport, "send_frame", sent)
        boundaries = []
        for step in range(5):
            result = runtime.step([0., 0.])
            assert result.global_step == step and result.products == 30 and result.truncations == 4
            runtime.confirm_applied(result)  # 测试只验证确认门禁；不创建物理完成证据。
            if step == 0:
                client_frames = sum(row["frames"] for row in counts.values()) - before
            if runtime.segment_full:
                start = sum(row["frames"] for row in counts.values())
                if fault is not None and (fault != "duplicate" or boundaries):
                    with pytest.raises((ValueError, OSError, EOFError, RuntimeError)):
                        runtime.end_segment()
                    assert runtime.phase == "UNCERTAIN" and len(runtime.last_segment_receipts) == 1
                    assert runtime.confirmed_step_count == step+1
                    assert runtime.last_segment_receipts[0].end.global_end_exclusive == step+1
                    with pytest.raises(RuntimeError):
                        runtime.step([0., 0.])
                    return
                record = runtime.end_segment()
                runtime.next_segment()
                boundaries.append(sum(row["frames"] for row in counts.values()) - start)
                assert record.hello.segment_index == len(boundaries)-1
                assert len(record.steps) == 2 and record.receipts[0].end.segment_index == record.hello.segment_index
        control.request_stop()
        runtime.end_segment()
        assert runtime.phase == "STOPPED" and runtime.confirmed_step_count == 5
        runtime.close()
        summary = runtime.material_summary
        assert all(summary[name] for name in ("worker_exited", "receiver_exited", "credit_thread_exited"))
        assert summary["claimed"] == 5 and not summary["cleanup_failed"]
        outcomes = [queue.get(timeout=15.) for _ in parties]
        for process in parties:
            process.join(10.)
            assert not process.is_alive() and process.exitcode == 0
        assert all(outcome["status"] == "closed" for outcome in outcomes), outcomes
        party_frames = sum(sum(row["frames"] for row in outcome["steps"][0]["sent"].values())
                           for outcome in outcomes)
        assert boundaries == ([2, 2] if wire_profile == "control-dynamic-compact-v2" else [4, 4])
        if wire_profile == "control-dynamic-compact-v2":
            assert operations.count("segment_advance") == 4 and "segment_begin" not in operations
            replies = [o["fixture_sent_operations"].count("segment_advance") for o in outcomes]
            assert replies == [2, 2]  # 每段双方各一个实际回复，额外四帧。
            assert all("segment_begin" not in o["fixture_sent_operations"] for o in outcomes)
            assert client_frames + party_frames + boundaries[0] + sum(replies)//2 == 19
        assert client_frames + party_frames == expected_frames
        assert client_frames == (4 if wire_profile else 6)
        if wire_profile:
            assert all(outcome["wire_profile"] == wire_profile for outcome in outcomes)
        assert len(outcomes) == 2 and all(len(o["steps"]) == 5 for o in outcomes)
        assert all(o["stage_wait"]["first_failure"] is None and o["stage_wait"]["hooks_restored"]
                   for o in outcomes)
    finally:
        if runtime is not None:
            runtime.close()
        restore()
        for process in parties:
            if process.is_alive():
                process.terminate()
            if process.pid is not None:
                process.join(10.)
        queue.close()


@pytest.mark.integration
def test_relay_half_close_preserves_reverse_stream():
    ports = free_ports()
    servers = []
    for port in ports:
        server = socket.socket()
        server.bind(("127.0.0.2", port))
        server.listen(1)
        servers.append(server)
    errors, threads = [], []
    def echo(server):
        try:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5)
                data = bytearray()
                while chunk := conn.recv(71):
                    data.extend(chunk)
                assert data == b"forward"*1024
                conn.sendall(b"reverse"*1024)
                conn.shutdown(socket.SHUT_WR)
        except Exception as error:  # noqa: BLE001 - 测试线程把原失败交回父断言。
            errors.append(error)
    relay = emulator.NetworkRelay("N1", tuple(("127.0.0.1", p, "127.0.0.2") for p in ports))
    try:
        with relay:
            for server, port in zip(servers, ports, strict=True):
                thread = Thread(target=echo, args=(server,))
                threads.append(thread)
                thread.start()
                with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                    client.sendall(b"forward"*1024)
                    client.shutdown(socket.SHUT_WR)
                    received = bytearray()
                    while chunk := client.recv(53):
                        received.extend(chunk)
                    assert received == b"reverse"*1024
                thread.join(6)
                assert not thread.is_alive() and not errors
        first = relay.report["first_failure"] or {}
        assert relay.report["error_type"] is None and relay.report["process_exited"], (
            first.get("errno"), first.get("winerror"), first.get("operation"), first.get("direction"))
        assert all(s["read_eof"] and s["write_shutdown"] and s["queue_high_water"] <= emulator.QUEUE_LIMIT
                   for s in relay.report["directions"].values())
    finally:
        for server in servers:
            server.close()
        for thread in threads:
            thread.join(6)
