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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows原生事件ABI功能检查")
def test_native_wait_socket_read_pause_halfclose_and_reused_timer():
    """只有本机socket字节/句柄功能，没有控制循环或性能分位测量。"""
    from secure_control.experiments._network_wait_win32 import NativeWait
    left, right = socket.socketpair()
    left.setblocking(False)
    try:
        with NativeWait() as wait:
            wait.register(left, emulator.selectors.EVENT_READ, ("stream", None, None))
            timer = wait.timer
            right.sendall(b"ab")
            selected, returned, kind = wait.wait_until(time.perf_counter_ns()+1_000_000_000)
            assert selected[0][0].fileobj is left and selected[0][1] & emulator.selectors.EVENT_READ
            assert type(returned) is int and kind == 5
            wait.read_started(left)
            assert left.recv(1) == b"a"
            wait.modify(left, 0, ("stream", None, None))
            due = time.perf_counter_ns()+1_000_000
            assert wait.wait_until(due)[0] == []
            wait.modify(left, emulator.selectors.EVENT_READ, ("stream", None, None))
            assert wait.wait_until(time.perf_counter_ns()+1_000_000_000)[0]
            wait.read_started(left)
            assert left.recv(1) == b"b"
            right.shutdown(socket.SHUT_WR)
            assert wait.wait_until(time.perf_counter_ns()+1_000_000_000)[0]
            wait.read_started(left)
            assert left.recv(1) == b""
            wait.unregister(left)
            assert not wait.get_map() and wait.timer == timer
            due = time.perf_counter_ns()+1_000_000
            selected, returned, kind = wait.wait_until(due)
            assert not selected and returned >= due and kind == 6
            assert wait.report()["active_poll"] is False and wait.report()["handle_high_water"] <= 16
        assert wait.report()["handles_open"] == 0
    finally:
        left.close()
        right.close()


class _WaitAPI:
    """确定性FFI替身只查通知/生命周期/失败，不提供性能成绩。"""

    def __init__(self):
        self.next_handle = 10
        self.open = set()
        self.events = {}
        self.fail = None
        self.bound = {}
        self.due = None

    def error(self, *_args):
        return OSError("native fixture failure")

    def CreateWaitableTimerExW(self, security, name, flags, access):
        assert security is name is None and flags == 2 and access == 0x100002
        return self.WSACreateEvent() if self.fail != "create" else 0

    def WSACreateEvent(self):
        self.next_handle += 1
        self.open.add(self.next_handle)
        return self.next_handle

    def WSAEventSelect(self, fd, handle, mask):
        self.bound[fd] = (handle, mask)
        return -1 if self.fail == "bind" and mask else 0

    def WSAEnumNetworkEvents(self, fd, _handle, pointer):
        bits, errors = self.events.pop(fd, (0, {}))
        pointer._obj.events = bits
        for index, value in errors.items():
            pointer._obj.errors[index] = value
        return -1 if self.fail == "enum" else 0

    def SetWaitableTimerEx(self, _timer, due, period, apc, argument, context, tolerance):
        assert period == 0 and apc is argument is context is None and tolerance == 0
        self.due = due._obj.value
        return self.fail != "timer"

    def WaitForMultipleObjects(self, count, _handles, all_events, timeout):
        assert 1 <= count <= 16 and all_events is False and timeout == 0xFFFFFFFF
        return 0xFFFFFFFF if self.fail == "wait" else 0

    def WSACloseEvent(self, handle):
        self.open.remove(handle)
        return self.fail != "event_close"

    def CancelWaitableTimer(self, _handle):
        return self.fail != "cancel"

    def CloseHandle(self, handle):
        self.open.remove(handle)
        return self.fail != "close"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows原生背压通知")
def test_native_write_would_block_then_real_notification_and_bounded_handles():
    from secure_control.experiments._network_wait_win32 import NativeWait
    left, right = socket.socketpair()
    left.setblocking(False)
    right.setblocking(False)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    try:
        with NativeWait() as wait:
            wait.register(left, emulator.selectors.EVENT_WRITE, ("stream", None, None))
            assert wait.wait_until(time.perf_counter_ns()+1_000_000_000)[0]
            assert wait.writable_return(left) is not None
            total, blocked = 0, False
            for _ in range(128):
                try:
                    total += left.send(b"x"*65536)
                except BlockingIOError:
                    wait.write_blocked(left)
                    blocked = True
                    break
            assert blocked and total <= 8*1024**2
            received = 0
            while received < total:
                try:
                    received += len(right.recv(65536))
                except BlockingIOError:
                    # 有界等待socket数据，不测量吞吐或循环控制性能。
                    right.settimeout(1)
                    received += len(right.recv(65536))
                    right.setblocking(False)
            selected, _returned, _kind = wait.wait_until(time.perf_counter_ns()+1_000_000_000)
            assert selected and wait.writable_return(left) is not None and left.send(b"y") == 1
            assert wait.report()["handle_high_water"] == 2
    finally:
        left.close()
        right.close()


def test_native_wait_notification_state_relative_timer_and_no_fabricated_write(monkeypatch):
    from secure_control.experiments import _network_wait_win32 as native
    api, clock = _WaitAPI(), [10000]
    monkeypatch.setattr(native.time, "perf_counter_ns", lambda: clock[0])
    sock = SimpleNamespace(fileno=lambda: 101)
    with native.NativeWait(_api=api) as wait:
        wait.register(sock, emulator.selectors.EVENT_WRITE, ("stream", None, None))
        api.events[101] = (native.FD_WRITE, {})
        assert wait.wait_until(11000)[0][0][1] == emulator.selectors.EVENT_WRITE
        assert wait.writable_return(sock) == 10000
        clock[0] = 10200
        assert wait.wait_until(11000)[0] and wait.writable_return(sock) is None  # 缓存状态不伪造新通知。
        wait.write_blocked(sock)
        selected, _returned, kind = wait.wait_until(11001)
        assert not selected and kind == 6 and api.due == -9  # ceil(801ns/100)，不是UTC/QPC绝对值。
        api.events[101] = (native.FD_WRITE | native.FD_READ, {})
        wait.modify(sock, emulator.selectors.EVENT_READ | emulator.selectors.EVENT_WRITE, ("stream", None, None))
        assert wait.wait_until(11000)[0][0][1] == 3
        wait.read_started(sock)
        wait.modify(sock, 0, ("stream", None, None))
        assert not wait.wait_until(11000)[0]
        with pytest.raises(ValueError, match="复用"):
            wait.get_key(SimpleNamespace(fileno=lambda: 101))
        wait.unregister(sock)
        wait.register(sock, emulator.selectors.EVENT_WRITE, ("connect", 0))
        api.events[101] = (native.FD_CONNECT, {4: 10061})
        assert wait.wait_until(11000)[0] and wait.connection_error(sock) == 10061
        assert wait.report()["native_wait_calls"] == 2
    assert not api.open


def test_native_half_close_does_not_restore_write_after_backpressure(monkeypatch):
    """读侧 EOF 不替代发送 would-block 后所需的新 FD_WRITE。"""
    from secure_control.experiments import _network_wait_win32 as native
    api, clock = _WaitAPI(), [10000]
    monkeypatch.setattr(native.time, "perf_counter_ns", lambda: clock[0])
    sock = SimpleNamespace(fileno=lambda: 101)
    with native.NativeWait(_api=api) as wait:
        wait.register(sock, 3, ("stream", None, None))
        api.events[101] = (native.FD_WRITE | native.FD_CLOSE, {})
        assert wait.wait_until(11000)[0][0][1] == 3
        assert wait.writable_return(sock) == 10000
        wait.read_started(sock)
        wait.write_blocked(sock)
        # EOF 仍可读，但关闭通知不得合成写就绪或新可写取回时刻。
        assert wait.wait_until(11000)[0][0][1] == emulator.selectors.EVENT_READ
        wait.modify(sock, emulator.selectors.EVENT_WRITE, ("stream", None, None))
        assert not wait.wait_until(11000)[0] and wait.writable_return(sock) is None
        api.events[101] = (native.FD_WRITE, {})
        clock[0] = 10500
        assert wait.wait_until(11000)[0][0][1] == emulator.selectors.EVENT_WRITE
        assert wait.writable_return(sock) == 10500
    assert not api.open


@pytest.mark.skipif(sys.platform != "win32", reason="Windows原生半关闭与发送背压组合")
def test_native_half_close_backpressure_preserves_pending_reverse_bytes():
    """原生 socket 与真实 relay 派发：半关闭后排空反向数据，绝不测量性能。"""
    from secure_control.experiments._network_wait_win32 import NativeWait
    left, right = socket.socketpair()
    left.setblocking(False)
    right.setblocking(False)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    right.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    try:
        with NativeWait() as wait:
            wait.register(left, 3, ("stream", None, None))
            assert wait.wait_until(time.perf_counter_ns()+1_000_000_000)[0]
            wait.writable_return(left)
            right.shutdown(socket.SHUT_WR)
            assert wait.wait_until(time.perf_counter_ns()+1_000_000_000)[0]
            wait.read_started(left)
            assert left.recv(1) == b""
            wait.modify(left, emulator.selectors.EVENT_WRITE, ("stream", None, None))
            filled = 0
            for _ in range(128):
                try:
                    filled += left.send(b"x"*65536)
                except BlockingIOError:
                    wait.write_blocked(left)
                    break
            else:
                pytest.fail("有界发送没有产生预期背压")
            pending = b"pending-reverse-bytes"
            direction = emulator.Direction(None, left, "P1->Client", None)
            now = time.perf_counter_ns()
            direction.queue.append(emulator.Block(pending, 0, now, now, 0, now))
            direction.queued = len(pending)
            ring = emulator.PublicRing()
            emulator._dispatch(direction, now, None, ring, wait)
            assert direction.stats["backpressure_count"] == 1 and direction.queued == len(pending)
            assert not wait.wait_until(time.perf_counter_ns()+1_000_000)[0]
            assert wait.writable_return(left) is None
            right.settimeout(1)
            received = bytearray()
            while len(received) < filled:
                received.extend(right.recv(min(65536, filled-len(received))))
            assert received == b"x"*filled
            selected, returned, _kind = wait.wait_until(time.perf_counter_ns()+1_000_000_000)
            assert selected and selected[0][1] == emulator.selectors.EVENT_WRITE
            writable = wait.writable_return(left)
            assert writable is not None and writable <= returned
            emulator._dispatch(direction, returned, writable, ring, wait)
            assert not direction.queue and direction.queued == 0
            assert direction.stats["sent_bytes"] == len(pending)
            assert right.recv(len(pending)) == pending
            left.shutdown(socket.SHUT_WR)
            assert right.recv(1) == b""
        assert wait.report()["handles_open"] == 0
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("failure", ["create", "bind", "enum", "timer", "wait", "event_close", "cancel", "close"])
def test_native_wait_fail_closed_and_partial_initialization_reclaims_handles(failure):
    from secure_control.experiments._network_wait_win32 import NativeWait
    api = _WaitAPI()
    if failure == "create":
        api.fail = failure
        with pytest.raises(OSError):
            NativeWait(_api=api)
    else:
        wait = NativeWait(_api=api)
        sock = SimpleNamespace(fileno=lambda: 101)
        if failure == "bind":
            api.fail = failure
            with pytest.raises(OSError):
                wait.register(sock, 1, ("stream", None, None))
        else:
            wait.register(sock, 1, ("stream", None, None))
            api.fail = failure
            if failure in ("enum", "timer", "wait"):
                with pytest.raises(OSError):
                    wait.wait_until(time.perf_counter_ns()+1_000_000_000)
        if failure in ("event_close", "cancel", "close"):
            with pytest.raises(OSError):
                wait.close()
            assert wait.report()["handles_open"] == (0 if failure == "cancel" else None)
        else:
            api.fail = None
            wait.close()
        wait.close()
    assert not api.open


def test_native_wait_collects_all_notifications_caps_handles_and_rejects_clock_errors(monkeypatch):
    from secure_control.experiments import _network_wait_win32 as native
    api, clock = _WaitAPI(), [100]
    monkeypatch.setattr(native.time, "perf_counter_ns", lambda: clock[0])
    with native.NativeWait(_api=api) as wait:
        socks = [SimpleNamespace(fileno=lambda i=i: 100+i) for i in range(16)]
        for sock in socks[:15]:
            wait.register(sock, 1, ("stream", None, None))
        with pytest.raises(ValueError, match="上限"):
            wait.register(socks[15], 1, ("stream", None, None))
        api.events[100] = (native.FD_READ, {})
        api.events[114] = (native.FD_READ | native.FD_CLOSE, {})
        selected, _returned, _kind = wait.wait_until(200)
        assert {x[0].fd for x in selected} == {100, 114} and wait.report()["handle_high_water"] == 16
        clock[0] = 99
        with pytest.raises(ValueError, match="QPC"):
            wait.wait_until(200)
    assert not api.open


def test_native_short_write_continuation_keeps_real_elapsed_and_requires_write_after_block(monkeypatch):
    clock = [100]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    actions = [2, BlockingIOError(), 2]
    def send(_data):
        action = actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action
    direction = emulator.Direction(None, SimpleNamespace(send=send), "Client->P1", None)
    direction.queue.append(emulator.Block(b"abcd", 0, 0, 0, 0, 100))
    direction.queued = 4
    ring = emulator.PublicRing()
    blocked = []
    native = SimpleNamespace(write_blocked=blocked.append, writable_return=lambda _sock: None,
                             write_progressed=lambda _sock: None)
    emulator._dispatch(direction, 100, None, ring, native)
    clock[0] = 1000101
    emulator._dispatch(direction, clock[0], None, ring, native)
    assert blocked == [direction.destination] and ring.rows()[-1][10] == 1000001
    assert ring.rows()[-1][13] == -1 and direction.queue[0].continuation_at is None
    with pytest.raises(RuntimeError):
        emulator._dispatch(direction, clock[0], None, ring, native)
    emulator._dispatch(direction, clock[0], clock[0], ring, native)
    assert not direction.queue and direction.stats["sent_bytes"] == 4


def test_native_first_due_send_consumes_old_write_notification_before_short_continuation(monkeypatch):
    clock, pending = [2000000], [1]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    def consume(_sock):
        value, pending[0] = pending[0], None
        return value
    native = SimpleNamespace(writable_return=consume, write_blocked=lambda _sock: None,
                             write_progressed=lambda _sock: None)
    direction = emulator.Direction(None, SimpleNamespace(send=lambda _data: 2), "Client->P1", None)
    direction.queue.append(emulator.Block(b"abcd", 0, 0, 0, 0, 2000000))
    direction.queued = 4
    ring = emulator.PublicRing()
    emulator._dispatch(direction, clock[0], None, ring, native)
    assert pending == [None]
    clock[0] += 100
    emulator._dispatch(direction, clock[0], native.writable_return(direction.destination), ring, native)
    assert not direction.queue and direction.stats["max_unexplained_excess_ns"] == 100
    assert ring.rows()[-1][13] == -1  # 没有新FD_WRITE的继续发送，不能填入旧时刻。


@pytest.mark.parametrize("failure", ["enum", "timer"])
@pytest.mark.parametrize("previous_success", [False, True])
def test_native_wait_failed_attempt_has_no_previous_return(monkeypatch, failure, previous_success):
    """当前调用未返回必须明确为空；原异常传播与句柄回收保持。"""
    from secure_control.experiments import _network_wait_win32 as native
    api, clock = _WaitAPI(), [1000]
    monkeypatch.setattr(native.time, "perf_counter_ns", lambda: clock[0])
    with native.NativeWait(_api=api) as wait:
        sock = SimpleNamespace(fileno=lambda: 101)
        wait.register(sock, 1, ("stream", None, None))
        if previous_success:
            wait.wait_until(2000)
            assert wait.report()["last_wait_returned_ns"] == 1000
        clock[0] = 3000
        api.fail = failure
        with pytest.raises(OSError, match="native fixture failure"):
            wait.wait_until(5000)
        report = wait.report()
        assert report["last_wait_started_ns"] == 3000 and report["last_wait_target_ns"] == 5000
        assert report["last_wait_returned_ns"] is None
        api.fail = None
        clock[0] = 6000
        wait.wait_until(7000)
        assert wait.report()["last_wait_returned_ns"] == wait.report()["last_wait_started_ns"] == 6000
    assert wait.report()["handles_open"] == 0 and not api.open


@pytest.mark.parametrize("write_mode", ["drain", "backpressure", "short_write"])
def test_native_relay_connect_transition_and_consecutive_due_heads_do_not_wait_for_resource_deadline(monkeypatch, write_mode):
    """执行原relay全路径：连接转换、双向连续队头、无新WRITE与真实would-block。"""
    from secure_control.experiments import _network_wait_win32 as native
    clock, reports, waits, sent, bindings = [10000], [], [], [], []
    backpressure = write_mode == "backpressure"
    blocked, notified, stopped = [False], [False], [False]
    waits_owner = []

    class API(_WaitAPI):
        def WSAEventSelect(self, fd, handle, mask):
            result = super().WSAEventSelect(fd, handle, mask)
            if mask:
                bindings.append((fd, handle))
                if mask & native.FD_ACCEPT:
                    self.events[fd] = (native.FD_ACCEPT, {})
                elif mask & native.FD_CONNECT:
                    self.events[fd] = (native.FD_CONNECT | native.FD_WRITE, {})
                elif mask & native.FD_READ:
                    self.events[fd] = (native.FD_READ, {})
            return result

        def WaitForMultipleObjects(self, count, handles, all_events, timeout):
            assert len(waits) < 15, "生产循环没有在有界功能序列内完成"
            waits.append(self.due)
            if blocked[0]:
                clock[0] += 10000
                blocked[0], notified[0] = False, True
                self.events[303] = (native.FD_WRITE, {})
                return 1
            clock[0] += -self.due*100
            return super().WaitForMultipleObjects(count, handles, all_events, timeout)

    api = API()

    class Socket:
        def __init__(self, fd):
            self.fd, self.reads = fd, 0

        def fileno(self):
            return self.fd

        def setsockopt(self, *_args):
            pass

        def bind(self, *_args):
            pass

        def listen(self, *_args):
            pass

        def setblocking(self, *_args):
            pass

        def connect_ex(self, *_args):
            return 0

        def getsockopt(self, *_args):
            return 0

        def accept(self):
            return front, None

        def recv(self, _limit):
            if self.reads == 2:
                raise BlockingIOError()
            self.reads += 1
            if self.reads < 2:
                api.events[self.fd] = (native.FD_READ, {})
            return b"ab" if self.reads == 1 else b"cd"

        def send(self, data):
            if backpressure and self.fd == 303 and not notified[0]:
                assert not blocked[0], "真实would-block后没有新FD_WRITE不得重试"
                blocked[0] = True
                raise BlockingIOError()
            count = 1 if write_mode == "short_write" and self.fd == 202 and not any(fd == 202 for fd, *_ in sent) else len(data)
            sent.append((self.fd, bytes(data[:count]), clock[0]))
            if sum(len(payload) for _fd, payload, _when in sent) == 8:
                stopped[0] = True
            return count

        def close(self):
            self.fd = -1

    listener, front, rear = Socket(101), Socket(202), Socket(303)
    sockets = iter((listener, rear))
    factory = native.NativeWait

    def wait_factory():
        wait = factory(_api=api)
        waits_owner.append(wait)
        return wait

    monkeypatch.setattr(native, "NativeWait", wait_factory)
    monkeypatch.setattr(emulator.socket, "socket", lambda *_args: next(sockets))

    def now():
        clock[0] += 1000
        return clock[0]

    monkeypatch.setattr(emulator.time, "perf_counter_ns", now)
    monkeypatch.setattr(emulator.time, "process_time_ns", lambda: clock[0]//10)
    monkeypatch.setattr(benchmark, "_process_memory", lambda: {"current_rss_bytes": 32*1024**2})
    due = [None]

    def schedule(self, arrival, size):
        due[0] = due[0] or arrival+1000000
        return 0, arrival, 0, due[0]

    monkeypatch.setattr(emulator.Schedule, "enqueue", schedule)
    emulator._relay_main("N2", [("127.0.0.1", 1, "127.0.0.2")],
        SimpleNamespace(is_set=lambda: stopped[0]), SimpleNamespace(send=reports.append, close=lambda: None), native.STRATEGY)
    report = reports[-1]
    assert report["error_type"] is None and len(sent) == (5 if write_mode == "short_write" else 4)
    for fd in (202, 303):
        rows = [data for target, data, _when in sent if target == fd]
        assert b"".join(rows) == b"abcd"
    assert all(when >= due[0] for _fd, _data, when in sent)
    assert all(x["unexplained_over_tolerance"] == 0 for x in report["directions"].values())
    assert report["directions"]["Client->P1"]["backpressure_count"] == int(backpressure)
    assert report["directions"]["P1->Client"]["short_writes"] == int(write_mode == "short_write")
    assert notified[0] is backpressure
    assert len({handle for fd, handle in bindings if fd == 303}) == 1  # connect转stream不丢原事件。
    assert waits_owner[0].report()["handles_open"] == 0 and not api.open
    assert report["wait_policy"]["poll_episodes"] == 0


def test_native_initialization_failure_is_reported_without_fallback_or_fake_policy(monkeypatch):
    from secure_control.experiments import _network_wait_win32 as native
    reports = []
    def unsupported():
        raise OSError("software native initialization failure")
    monkeypatch.setattr(native, "NativeWait", unsupported)
    monkeypatch.setattr(emulator.selectors, "DefaultSelector", lambda: pytest.fail("不得降级selector"))
    emulator._relay_main("N2", [], SimpleNamespace(is_set=lambda: False),
        SimpleNamespace(send=reports.append, close=lambda: None), native.STRATEGY)
    report = reports[-1]
    assert report["error_type"] == "OSError" and report["first_failure"]["operation"] == "wait_initialization"
    assert not report["ready"] and not report["model_valid"] and report["wait_policy"] is None
    assert report["requested_wait_strategy"] == native.STRATEGY and not report["directions"]


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


@pytest.mark.parametrize("profile,empty_readers,late_sleep,near_no_sleep", (
    ("N1", False, False, False), ("N2", False, False, False), ("N3", False, False, False),
    ("N2", True, False, False), ("N2", False, True, False), ("N2", False, False, True),
    ("N3", False, True, False)))
def test_windows_relay_due_does_not_depend_on_positive_select_timer(
        monkeypatch, profile, empty_readers, late_sleep, near_no_sleep):
    """驱动真实代理循环：模拟正timeout延后一个tick，不运行socket或性能补测。"""
    clock = [1_000_000_000]
    stopped, reports = [False], []
    payload = b"opaque" * 246 + b"xx"
    written, idle_waits, sleeps = bytearray(), [], []
    startup_idle, blocked, waited_for_writable = [False], [False], [False]
    selectors, empty_poll_reads = [], []
    scheduled_due = [None]
    poll_preempted = [False]

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
                if late_sleep and profile == "N2" and not poll_preempted[0]:
                    poll_preempted[0] = True
                    clock[0] += 1_451_000  # 主动检查也会被抢占；原1ms门禁仍须失败。
                else:
                    clock[0] += 15_625_000 if timeout > 0 else 50_000
            return ready

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(emulator.socket, "socket", socket_factory)
    monkeypatch.setattr(emulator.selectors, "DefaultSelector", Selector)
    def read_clock():
        clock[0] += 1_000
        if selectors and not selectors[0].mapping and scheduled_due[0] is not None and not blocked[0]:
            empty_poll_reads.append(True)
        return clock[0]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", read_clock)
    monkeypatch.setattr(emulator.time, "process_time_ns", lambda: clock[0]//10)
    enqueue = emulator.Schedule.enqueue
    def remember_due(self, *args):
        row = enqueue(self, *args)
        scheduled_due[0] = row[3]
        return row
    monkeypatch.setattr(emulator.Schedule, "enqueue", remember_due)
    def sleep(delay):
        assert 0 < delay <= min(.00025, (scheduled_due[0] - clock[0])/1e9)
        sleeps.append(delay)
        clock[0] += (1_451_000 if near_no_sleep else math.ceil(delay * 10**9) + (15_625_000 if late_sleep else 0))
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
        if profile == "N3":
            assert sleeps  # 远期仍正sleep，到guard外沿后进入有界检查。
        else:
            assert not sleeps  # 近到期不再以正sleep主动让出CPU。
        if not late_sleep:
            assert report["wait_policy"]["poll_episodes"] > 0
        if empty_readers:
            assert empty_poll_reads
    else:
        assert not sleeps
    assert report["ring"][0][7] >= report["ring"][0][6]
    assert report["ring_version"] == 2 and report["ring"][0][13] == -1
    if late_sleep:
        snapshot = dict(zip(report["first_anomaly_timing_fields"], report["first_anomaly_timing"], strict=True))
        assert snapshot["wait_kind"] == (4 if profile == "N2" else 2)
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


def test_relay_cpu_windows_use_actual_intervals_keep_first_limit_and_partial_tail(monkeypatch):
    wall, cpu = [1_000_000_000], [0]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: wall[0])
    monkeypatch.setattr(emulator.time, "process_time_ns", lambda: cpu[0])
    policy = emulator._WaitPolicy()
    policy.start(wall[0], cpu[0])
    for elapsed, consumed in ((100_000_000, 50_000_000), (300_000_000, 150_000_000)):
        wall[0] += elapsed
        cpu[0] += consumed
        policy.sample_cpu()
    assert policy.windows == 2 and policy.first_over is None
    assert policy.next_cpu_check == 1_500_000_000  # 长窗从实际采样时点重新计时。
    wall[0] += 100_000_000
    cpu[0] += 50_000_001
    with pytest.raises(emulator.RelayCpuLimitError):
        policy.sample_cpu()
    first = dict(policy.first_over)
    assert first["wall_delta_ns"] == 100_000_000 and first["cpu_delta_ns"] == 50_000_001
    wall[0] += 50_000_000
    cpu[0] += 50_000_000
    policy.sample_cpu(final=True)
    report = policy.report()
    assert report["cpu_complete_windows"] == 3 and report["first_cpu_limit_window"] == first
    assert report["tail_cpu_window"] == {"start_qpc_ns": 1_500_000_000, "end_qpc_ns": 1_550_000_000,
        "wall_delta_ns": 50_000_000, "cpu_delta_ns": 50_000_000, "complete_window": False}
    assert report["lifecycle_wall_ns"] == 550_000_000 and report["lifecycle_cpu_ns"] == 300_000_001
    assert report["lifecycle_complete"] and report["peak_cpu_window"] == first
    for bad in (True, False, 1.5, -1, 2**63):
        with pytest.raises(ValueError):
            emulator._clock_ns(bad)
    wall[0] -= 1
    with pytest.raises(ValueError, match="倒退"):
        policy.sample_cpu()
    wall[0] += 1
    cpu[0] -= 1
    with pytest.raises(ValueError, match="倒退"):
        policy.sample_cpu()


def test_bounded_wait_edges_stop_readiness_resource_and_empty_sets(monkeypatch):
    """可控QPC验证真实事件时刻；主动检查不读CPU/RSS、不处理字节流。"""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(emulator.time, "process_time_ns", lambda: pytest.fail("CPU sampled inside wait"))
    for mode, remaining in (("due", 396_000), ("guard", 500_000), ("outside", 500_001),
            ("far", 3_000_000), ("empty", 396_000), ("idle", None), ("blocked", None),
            ("event", 396_000), ("stop", 396_000), ("draining", 396_000),
            ("resource", 396_000), ("preempted", 396_000)):
        state = {"now": 1_000_000_000, "reads": 0, "stop": mode == "draining"}
        calls, sleeps, waits = [], [], []
        def clock(state=state):
            if state["reads"]:
                state["now"] += 1_000
            state["reads"] += 1
            return state["now"]
        def select(timeout, state=state, mode=mode, calls=calls):
            calls.append(timeout)
            state["now"] += 2_000_000 if mode == "preempted" else 10_000
            if mode == "stop":
                state["stop"] = True
            return [("actual-ready", emulator.selectors.EVENT_WRITE)] if mode == "event" else []
        def sleep(delay, state=state, sleeps=sleeps):
            sleeps.append(delay)
            state["now"] += math.ceil(delay*1e9)
        selector = SimpleNamespace(get_map=lambda mode=mode: {} if mode in ("empty", "idle") else {1: True}, select=select)
        stop = SimpleNamespace(is_set=lambda state=state: state["stop"], wait=waits.append)
        monkeypatch.setattr(emulator.time, "perf_counter_ns", clock)
        monkeypatch.setattr(emulator.time, "sleep", sleep)
        policy, ring = emulator._WaitPolicy(), emulator.PublicRing()
        policy.start(state["now"], 0)
        resource = state["now"]+(100_000 if mode == "resource" else 100_000_000)
        selected, returned = emulator._wait_for_events(selector, stop,
            None if remaining is None else state["now"]+remaining, resource, policy, ring, stopping=mode == "draining")
        report = policy.report()
        assert report["cpu_complete_windows"] == 0
        if mode == "event":
            assert selected and returned == ring.timing[2] == state["now"] and returned != ring.timing[1]
        else:
            assert not selected and returned is None
        if mode in ("idle", "blocked"):
            assert not sleeps and not report["poll_episodes"]
            assert waits and not calls if mode == "idle" else calls and calls[0] > 0
        elif mode in ("far", "outside"):
            assert not report["poll_episodes"]
            if mode == "far":
                assert sleeps and 0 < sleeps[0] <= .00025
        else:
            assert report["poll_episodes"] == 1 and not sleeps
            assert ring.timing[0] == 4 and report["poll_wall_ns"] == ring.timing[2]-ring.timing[1]
            if mode == "preempted":
                assert report["max_poll_wall_ns"] > 500_000 and ring.timing[2] > ring.timing[3]
            else:
                assert ring.timing[3]-ring.timing[1] <= 500_000
                assert report["max_poll_wall_ns"] <= ring.timing[3]-ring.timing[1]+11_000
            if mode == "empty":
                assert not calls  # Windows空FD不交给selector。
            if mode == "stop":
                assert ring.timing[2] < ring.timing[3]
            if mode == "resource":
                assert ring.timing[3] == resource
    # 已到资源检查点的立即返回清空旧等待，不能关联无关旧sleep。
    ring.timing[:4] = [2, 1, 2, 2]
    emulator._wait_for_events(selector, stop, None, 0, policy, ring)
    assert ring.timing[:4] == [0, -1, -1, -1]


@pytest.mark.parametrize("first_rss_failure", [False, True])
def test_relay_cpu_failure_exports_full_bounded_ring_and_preserves_first_error(monkeypatch, first_rss_failure):
    clock, cpu = [4_000_000_000_000_000_000], [0]
    reports, closed = [], []
    class Socket:
        def close(self):
            closed.append(True)
            if first_rss_failure:
                raise OSError("software cleanup failure")
        def __getattr__(self, _name):
            return lambda *a: None
    def select(_timeout):
        clock[0] += 120_000_000
        cpu[0] += 60_000_001
        return []
    def close_selector():
        clock[0] += 120_000_000
        cpu[0] += 60_000_001  # 退出完整窗也要检查，但不能覆盖先发生的RSS错误。
    selector = SimpleNamespace(register=lambda *a: None, get_map=lambda: {1: True}, select=select,
                               close=close_selector)
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    monkeypatch.setattr(emulator.time, "process_time_ns", lambda: cpu[0])
    monkeypatch.setattr(emulator.socket, "socket", lambda *a: Socket())
    monkeypatch.setattr(emulator.selectors, "DefaultSelector", lambda: selector)
    monkeypatch.setattr(benchmark, "_process_memory", lambda: {"current_rss_bytes": None if first_rss_failure else 32*1024**2})
    def fill_ring(_directions, _rotation, ring):
        if not ring.seen:
            for i in range(300):
                ring.append((0, i*4096, 4096, clock[0], clock[0], 500_000, clock[0], clock[0]+2_000_000,
                    4096, 0, 2_000_000, 0, clock[0]+1_000_000, -1, clock[0]))
        return set()
    monkeypatch.setattr(emulator, "_serve_due", fill_ring)
    emulator._relay_main("N2", [("127.0.0.1", p, "127.0.0.2") for p in (1, 2, 3)],
        SimpleNamespace(is_set=lambda: False), SimpleNamespace(send=reports.append, close=lambda: None))
    report = reports[-1]
    assert report["error_type"] == ("MemoryError" if first_rss_failure else "RelayCpuLimitError")
    assert report["first_failure"]["operation"] == ("rss" if first_rss_failure else "cpu")
    assert report["wait_policy"]["first_cpu_limit_window"]["cpu_delta_ns"] == 60_000_001
    assert not report["model_valid"] and len(closed) == 3
    assert report["cleanup_error_type"] == ("OSError" if first_rss_failure else None)
    assert len(report["ring"]) == 256 and report["ring_evicted"] == 44 and report["first_anomaly"] is not None
    assert len(report["first_anomaly_timing_fields"]) == 9 and report["wait_kinds"]["4"] == "bounded_poll"
    assert len(json.dumps(report, separators=(",", ":")).encode()) <= 64*1024


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


@pytest.fixture
def staged_context(v2_candidate_context, monkeypatch):
    """新批次独立的九项封闭夹具，绝不读取本机真实性能额度。"""
    old, legacy, ledger, _ = v2_candidate_context
    history = copy.deepcopy(old)
    for call in range(6, 10):
        history.append(dict(history[-1], call=call, public_certificate_sha256=legacy["public_certificate_sha256"]))
    native = [{"completed": True, "native_exit": 5} for _ in history]
    monkeypatch.setattr(network, "STAGED_HISTORY", network.digest(history))
    monkeypatch.setattr(network, "STAGED_NATIVE_HISTORY", network.digest(native))
    native_path = ledger.parent/"issue120-network-invocations.json"
    manifest = legacy | {
        "authorization_url": network.STAGED_AUTHORIZATION,
        "comparison_design_url": network.STAGED_DESIGN,
        "comparison_stage": "T1", "profile": "N0", "phase": "candidate", "call": 10,
        "closed_history_sha256": network.STAGED_HISTORY,
        "closed_native_history_sha256": network.STAGED_NATIVE_HISTORY,
        "maximum_calls": 12, "maximum_attempts": 1000, "total_maximum_attempts": 12000,
        "batch_maximum_calls": 3, "batch_maximum_attempts": 3000,
        "wait_strategy": network.EVENT_STRATEGY, "software_pass": True, "readback_exact": True,
        "native_ledger_path": str(native_path.resolve()),
        "certificate_directory": str((ledger.parent/"issue120-stage-authorized-certs").resolve()),
        "previous_public_certificate_sha256": legacy["public_certificate_sha256"],
        "public_certificate_validity": {},
    }
    ledger.write_text(json.dumps({"schema": "network-call-budget-v1", "entries": history}), encoding="utf-8")
    native_path.write_text(json.dumps({"entries": native+[manifest | {
        "completed": False, "native_exit": None, "started_utc": "start"}]}), encoding="utf-8")
    return history, manifest, ledger, native, native_path


@pytest.fixture
def local_context(staged_context, monkeypatch):
    """封存旧T2退出5，新的U1/U2只追加，不重写失败。"""
    history, old, ledger, native, native_path = staged_context
    for i in range(2):
        entry = old | {"comparison_stage": f"T{i+1}", "call": 10+i,
                       "finished": True, "sample_pass": i == 0, "actual_attempts": 1000}
        history.append(entry)
        native.append(entry | {"completed": True, "native_exit": 0 if i == 0 else 5})
    monkeypatch.setattr(network, "LOCAL_HISTORY", network.digest(history))
    monkeypatch.setattr(network, "LOCAL_NATIVE_HISTORY", network.digest(native))
    m = {k: v for k, v in old.items() if k not in network.V2_CERTIFICATE_FIELDS}
    m.update(authorization_url=network.LOCAL_DESIGN, comparison_design_url=network.LOCAL_DESIGN,
        comparison_stage="U1", closed_history_sha256=network.LOCAL_HISTORY,
        closed_native_history_sha256=network.LOCAL_NATIVE_HISTORY, call=12, maximum_calls=13,
        total_maximum_attempts=13000, batch_maximum_calls=2, batch_maximum_attempts=2000,
        public_certificate_validity=old["public_certificate_validity"])
    m.update(head="e"*40, source_sha256={"src": "f"*64})
    monkeypatch.setattr(network, "source", lambda: (m["head"], m["source_sha256"]))
    ledger.write_text(json.dumps({"schema": "network-call-budget-v1", "entries": history}), encoding="utf-8")
    def start(current):
        native_path.write_text(json.dumps({"entries": native+[current | {
            "completed": False, "native_exit": None, "started_utc": "start"}]}), encoding="utf-8")
    start(m)
    return history, m, ledger, native, start


@pytest.mark.parametrize("change", [{"call": 13}, {"comparison_stage": "T3"},
    {"profile": "N2"}, {"maximum_calls": 14}, {"maximum_attempts": 10000}, {"maximum_attempts": True},
    {"authorization_url": network.STAGED_AUTHORIZATION}, {"closed_history_sha256": "0"*64},
    {"certificate_change_reason": "renew"}, {"phase": "qualification"}])
def test_local_comparison_scope_and_old_batch_stay_closed(local_context, change):
    history, m, _, _, _ = local_context
    assert network._local_manifest_valid(m)
    assert not network._staged_manifest_valid(m)
    with pytest.raises(ValueError):
        network._next_local_call(history, "N0", "candidate", m["head"], m["source_sha256"], m | change)
    with pytest.raises(ValueError):
        network._next_staged_call(history, "N0", "candidate", m["head"], m["source_sha256"], m)


@pytest.mark.parametrize("failed_u1", [False, True])
def test_local_comparison_appends_preserved_eleven_and_requires_real_u1(local_context, monkeypatch, failed_u1):
    history, m, ledger, native, start = local_context
    monkeypatch.setattr(network, "_require_local_certificates", lambda *_: None)
    # 用真实旧门禁验证完整前件；不运行控制或忽略TLS/材料/端点检查。
    result = _repair_software_result(m)
    result.update(status="stopped", failure_category=None, failed_phase=None)
    for i, row in enumerate(result["steps"]):
        row["sent"] = {"Client": {"frames": 4}}
        result["cycles"][i]["public_frame_counts"] = {"Client": 4+2*int(i in (399,799))}
        for p, party in enumerate(result["party_outcomes"]):
            party["steps"][i]["sent"] = {"Party": {"frames": 5+p+int(i in (400,800))}}
    result = network.assemble(result, profile="N0", phase="candidate", manifest=m, relay=result["network_relay"])
    assert result["network_sample_pass"]
    if failed_u1:
        result["cycles"][0]["cycle_completed_ns"] = None
    raw = ledger.parent/"U1.json"
    with network.RunBudget(ledger) as budget:
        assert budget.reserve("N0", "candidate", m["head"], m["source_sha256"], raw,
            conditions_sha256=m["conditions_sha256"], continuation=m) == 1000
        network.require_network_candidate(m, m["wire_profile"])
        raw.write_text(json.dumps(result), encoding="utf-8")
        budget.finish(result, network.hashlib.sha256(raw.read_bytes()).hexdigest())
        assert budget.entries[:11] == history
        previous = copy.deepcopy(budget.entries[-1])
    native.append(previous | {"completed": True, "native_exit": 0})
    second = m | {"call": 13, "comparison_stage": "U2", "wire_profile": network._COMPACT_PROFILE_V3}
    start(second)
    entries = history+[previous]
    if failed_u1:
        with pytest.raises(ValueError):
            network._next_local_call(entries, "N0", "candidate", second["head"], second["source_sha256"], second)
    else:
        assert network._next_local_call(entries, "N0", "candidate", second["head"], second["source_sha256"], second) == 1000
        for changed in ({"head": "8"*40}, {"public_certificate_validity": {}}, {"conditions_sha256": "0"*64}):
            if changed == {"public_certificate_validity": {}}:
                changed = {"public_certificate_validity": {"changed": True}}
            wrong = second | changed
            with pytest.raises(ValueError):
                network._next_local_call(entries, "N0", "candidate", wrong["head"], wrong["source_sha256"], wrong)
        with network.RunBudget(ledger) as budget:
            budget.reserve("N0", "candidate", second["head"], second["source_sha256"], ledger.parent/"U2.json",
                conditions_sha256=second["conditions_sha256"], continuation=second)
            network.require_local_candidate(second)
            budget.finish({"cycles": [], "network_sample_pass": False}, "failed")
            with pytest.raises(ValueError):
                network._next_local_call(budget.entries, "N0", "candidate", second["head"], second["source_sha256"], second)


@pytest.mark.parametrize("change", [
    {"maximum_attempts": 10000}, {"maximum_attempts": True}, {"call": 11},
    {"maximum_calls": 13}, {"batch_maximum_calls": 4}, {"batch_maximum_attempts": 4000},
    {"profile": "N2"}, {"phase": "qualification"}, {"comparison_stage": "T3"},
    {"wire_profile": network._COMPACT_PROFILE_V3}, {"software_pass": False},
    {"authorization_url": network.REPAIR_AUTHORIZATION}, {"closed_history_sha256": "0"*64},
    {"qualification_allowed": True}, {"readback_exact": False},
    {"closure_stage": "B"}, {"continuation_stage": "repair_qualification"},
])
def test_staged_batch_rejects_scope_budget_and_legacy_borrowing(staged_context, change):
    history, manifest, _, _, _ = staged_context
    assert network._staged_manifest_valid(manifest)
    with pytest.raises(ValueError):
        network._next_compact_call(history, "N0", "candidate", manifest["head"], manifest["source_sha256"], manifest | change)


def test_staged_reservation_preserves_nine_and_startup_failure_seals_batch(staged_context, monkeypatch):
    history, manifest, ledger, native, native_path = staged_context
    monkeypatch.setattr(network, "_require_staged_certificates", lambda *_: None)
    with network.RunBudget(ledger) as budget:
        assert budget.reserve("N0", "candidate", manifest["head"], manifest["source_sha256"],
            ledger.parent/"T1.json", conditions_sha256=manifest["conditions_sha256"], continuation=manifest) == 1000
        network.require_staged_candidate(manifest)
        assert budget.entries[:9] == history and len(budget.entries) == 10
        budget.finish({"cycles": [], "network_sample_pass": False}, "raw")
    saved = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    assert saved[:9] == history and saved[-1]["actual_attempts"] == 0
    next_manifest = manifest | {"comparison_stage": "T2", "wire_profile": network._COMPACT_PROFILE_V3, "call": 11}
    native_path.write_text(json.dumps({"entries": native+[saved[-1] | {
        "completed": True, "native_exit": 5}, next_manifest | {
        "completed": False, "native_exit": None, "started_utc": "next"}]}), encoding="utf-8")
    for entries, m in ((history, manifest), (saved, next_manifest)):
        with pytest.raises(ValueError):
            network._next_staged_call(entries, m["profile"], "candidate", m["head"], m["source_sha256"], m)
    # 历史不完整、原对象变化以及额外在途都不能重新开始。
    for entries in ([], history[:-1], [dict(item, call=99) if i == 0 else item for i, item in enumerate(history)]):
        with pytest.raises(ValueError):
            network._next_staged_call(entries, "N0", "candidate", manifest["head"], manifest["source_sha256"], manifest)


@pytest.mark.parametrize("median,p99,maximum,expected", [
    (9_000_000, 11_000_000, 19_000_000, True),
    (9_000_001, 11_000_000, 19_000_000, False),
    (9_000_000, 12_000_001, 19_000_000, False),
    (9_000_000, 11_000_000, 20_000_001, False),
])
def test_staged_gain_uses_all_integer_endpoints_including_first_and_boundaries(median, p99, maximum, expected):
    def result(mid, tail, last):
        values = [mid]*980+[tail]*19+[last]
        return {"cycles": [{"scheduled_start_ns": i*20_000_000, "cycle_completed_ns": i*20_000_000+value}
                            for i, value in enumerate(values)]}
    baseline = result(10_000_000, 12_000_000, 19_000_000)
    assert network._staged_gain(baseline, result(median, p99, maximum)) is expected
    with pytest.raises(ValueError):
        network._staged_gain(baseline, {"cycles": baseline["cycles"][1:]})


def test_staged_t1_t2_t3_require_same_source_full_raw_gain_and_independent_audit(staged_context, monkeypatch):
    """合成完整原件复用真实门禁；只隔离磁盘根及证书读取，不运行性能。"""
    history, first, ledger, native, native_path = staged_context
    monkeypatch.setattr(network, "_require_staged_certificates", lambda *_: None)
    manifests, entries = [], copy.deepcopy(history)
    for stage, (label, profile, wire) in enumerate(network.STAGED_STAGES):
        m = first | {"comparison_stage": label, "profile": profile, "wire_profile": wire, "call": 10+stage}
        if stage == 2:
            m.update(comparison_raw_sha256=[e["raw_sha256"] for e in entries[9:]],
                     comparison_review_url=first["review_url"])
        start = m | {"completed": False, "native_exit": None, "started_utc": "start"}
        native_path.write_text(json.dumps({"entries": native+[start]}), encoding="utf-8")
        with network.RunBudget(ledger) as budget:
            if stage:
                for wrong in ({"head": "f"*40}, {"conditions_sha256": "0"*64}):
                    invalid = m | wrong
                    with pytest.raises(ValueError):
                        network._next_staged_call(budget.entries, profile, "candidate", invalid["head"], invalid["source_sha256"], invalid)
            if stage == 2:
                for wrong in ({"comparison_review_url": None}, {"comparison_raw_sha256": []}):
                    with pytest.raises((ValueError, TypeError)):
                        network._next_staged_call(budget.entries, profile, "candidate", m["head"], m["source_sha256"], m | wrong)
            raw = ledger.parent/f"{label}.json"
            assert budget.reserve(profile, "candidate", m["head"], m["source_sha256"], raw,
                conditions_sha256=m["conditions_sha256"], continuation=m) == 1000
            network.require_staged_candidate(m)
            result = _repair_software_result(m)
            result.update(status="stopped", wire_profile=wire, failure_category=None, failed_phase=None)
            result["material_summary"]["encoding_profile"] = wire
            result["material_summary"]["worker"]["encoding_profile"] = wire
            for step, row in enumerate(result["steps"]):
                row["sent"] = {"Client->P1": {"frames": 2}, "Client->P2": {"frames": 2}}
                cycle = result["cycles"][step]
                cycle["cycle_completed_ns"] = cycle["scheduled_start_ns"]+(15_000_000 if stage == 0 else 13_000_000)
                cycle["public_frame_counts"] = {"Client->P1": 2+int(step in (399, 799)),
                                                  "Client->P2": 2+int(step in (399, 799))}
                for i, party in enumerate(result["party_outcomes"]):
                    party["wire_profile"] = wire
                    party["steps"][step]["sent"] = {"test": {"frames": (3+i if stage else 5+i)
                        +int(step in (400, 800))}}
            result = network.assemble(result, profile=profile, phase="candidate", manifest=m,
                                      relay=result["network_relay"])
            assert result["network_sample_pass"], (label,
                network._staged_manifest_valid(m), network._staged_frames_pass(result, wire),
                benchmark._compact_sample_pass(result, result["material_comparison"], result["network_history"], target_steps=1000),
                network._tls_pass(result))
            assert not result["network_dynamic_qualification_pass"]
            broken = copy.deepcopy(result)
            broken["party_outcomes"][0]["steps"][400]["sent"]["test"]["frames"] += 1
            assert not network.assemble(broken, profile=profile, phase="candidate", manifest=m,
                                        relay=result["network_relay"])["network_sample_pass"]
            raw.write_text(json.dumps(result), encoding="utf-8")
            budget.finish(result, network.hashlib.sha256(raw.read_bytes()).hexdigest())
            entries = copy.deepcopy(budget.entries)
        native.append(start | {"completed": True, "native_exit": 0})
        manifests.append(m)
    assert entries[:9] == history and len(entries) == 12
    with pytest.raises(ValueError):
        network._next_staged_call(entries, "N2", "candidate", first["head"], first["source_sha256"], manifests[-1])


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


@pytest.fixture
def closure_context(v2_certificate_context, monkeypatch):
    """隔离的六项旧历史及A许可；不读取真实账本或运行性能。"""
    history, old, ledger, certs = v2_certificate_context
    history = history+[dict(history[-1], call=6, wire_profile=network._COMPACT_PROFILE_V2,
        conditions_sha256=old["conditions_sha256"], public_certificate_sha256=old["public_certificate_sha256"])]
    closed = network.digest(history)
    monkeypatch.setattr(network, "CLOSURE_HISTORY", closed, raising=False)
    ledger.write_text(json.dumps({"schema": "network-call-budget-v1", "entries": history}), encoding="utf-8")
    m = {k: v for k, v in old.items() if k not in network.V2_CERTIFICATE_FIELDS}
    m.update(authorization_url="https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6235872603",
        closed_history_sha256=closed, closure_stage="A", call=7, maximum_calls=9, total_maximum_attempts=18000,
        continuation_maximum_calls=3, continuation_maximum_attempts=12000,
        certificate_directory=str(certs.resolve()), public_certificate_validity=old["public_certificate_validity"],
        previous_public_certificate_sha256=old["public_certificate_sha256"], previous_conditions_sha256=old["conditions_sha256"],
        software_pass=True, readback_exact=True)
    return history, m, ledger, certs


def test_closure_reserves_only_A_after_closed_six_and_never_retries(closure_context):
    history, manifest, ledger, _certs = closure_context
    with network.RunBudget(ledger) as budget:
        assert budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"A.json",
            conditions_sha256=manifest["conditions_sha256"], continuation=manifest) == 1000
        network.require_v2_candidate(manifest)
        assert budget.entries[:6] == history
        with pytest.raises(ValueError):
            budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"retry.json",
                conditions_sha256=manifest["conditions_sha256"], continuation=manifest)
        budget.finish({"cycles": [], "network_sample_pass": False}, "raw")
    with network.RunBudget(ledger) as budget, pytest.raises(ValueError):
        budget.reserve("N2", "candidate", manifest["head"], manifest["source_sha256"], ledger.parent/"retry.json",
            conditions_sha256=manifest["conditions_sha256"], continuation=manifest)


def _closure_software_result(manifest, *, goal=True, model=True):
    """仅供许可/重算反例的公开结构；不是实际控制或密码门禁成绩。"""
    target = manifest["maximum_attempts"]
    window = {"start_qpc_ns": 0, "end_qpc_ns": 100000000, "wall_delta_ns": 100000000,
              "cpu_delta_ns": 50000000, "complete_window": True}
    return {"status": "stopped", "requested_steps": target, "code_sha": manifest["head"],
        "source_sha256": manifest["source_sha256"], "wire_profile": network._COMPACT_PROFILE_V2,
        "network_manifest": manifest, "network_history": {"finite_sample_pass": True},
        "material_summary": {"encoding_profile": network._COMPACT_PROFILE_V2,
                             "worker": {"encoding_profile": network._COMPACT_PROFILE_V2}},
        "party_outcomes": [{"wire_profile": network._COMPACT_PROFILE_V2} for _ in range(2)],
        "cycles": [{"scheduled_start_ns": i*20000000,
                    "cycle_completed_ns": i*20000000+(19000000 if not goal and i == target-1 else 15000000)}
                   for i in range(target)],
        "network_relay": {"model_valid": model, "process_exited": True, "forced_termination": False,
            "wait_policy": {"version": 1, "strategy": "bounded-near-due-v1", "guard_ns": 500000,
                "max_poll_episode_ns": 500000, "cpu_window_ns": 100000000, "cpu_limit_percent": 50,
                "lifecycle_complete": True, "cpu_complete_windows": 1, "peak_cpu_window": window,
                "tail_cpu_window": window, "first_cpu_limit_window": None, "cpu_sample_error_type": None}}}


@pytest.mark.parametrize("use_patch", [False, True])
def test_closure_A_optional_B_same_source_C_and_failed_B_cannot_qualify(closure_context, monkeypatch, use_patch):
    history, m, ledger, certs = closure_context
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *a, **k: True)
    monkeypatch.setattr(network, "_tls_pass", lambda _r: True)
    def finish(budget, manifest, *, goal):
        path = ledger.parent/(manifest["closure_stage"]+".json")
        result = _closure_software_result(manifest, goal=goal)
        result = network.assemble(result, profile="N2", phase=manifest["phase"], manifest=manifest,
                                  relay=result["network_relay"])
        path.write_text(json.dumps(result), encoding="utf-8")
        budget.finish(result, network.hashlib.sha256(path.read_bytes()).hexdigest())
        return result
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", m["head"], m["source_sha256"], ledger.parent/"A.json",
            conditions_sha256=m["conditions_sha256"], continuation=m)
        finish(budget, m, goal=not use_patch)
        predecessor = budget.entries[-1]
        next_m = m | {"closure_stage": "B" if use_patch else "C", "call": 8,
            "phase": "candidate" if use_patch else "qualification", "maximum_attempts": 1000 if use_patch else 10000,
            "eligible_for_candidate": use_patch, "qualification_allowed": not use_patch,
            "predecessor_raw_sha256": predecessor["raw_sha256"], "predecessor_review_url": m["review_url"],
            "predecessor_readback_exact": True}
        if use_patch:
            next_m.update(head="e"*40, source_sha256={"src": "f"*64}, patch_evidence_url=m["review_url"])
            monkeypatch.setattr(network, "source", lambda: (next_m["head"], next_m["source_sha256"]))
        for wrong in (next_m|{"predecessor_raw_sha256": "0"*64},
                      next_m|{"conditions_sha256": "0"*64}, next_m|{"predecessor_readback_exact": False},
                      next_m|{"certificate_directory": str(certs.parent/"other")}, next_m|{"call": 9}):
            with pytest.raises(ValueError):
                network._next_compact_call(budget.entries, "N2", wrong["phase"], wrong["head"], wrong["source_sha256"], wrong)
        steps = budget.reserve("N2", next_m["phase"], next_m["head"], next_m["source_sha256"],
            ledger.parent/(next_m["closure_stage"]+".json"), conditions_sha256=next_m["conditions_sha256"], continuation=next_m)
        assert steps == (1000 if use_patch else 10000)
        network.require_v2_candidate(next_m, network.role_configs(certs, network.V2_PORTS, "N2"))
        if use_patch:
            finish(budget, next_m, goal=False)
            c = next_m | {"closure_stage": "C", "call": 9, "phase": "qualification", "maximum_attempts": 10000,
                          "eligible_for_candidate": False, "qualification_allowed": True,
                          "predecessor_raw_sha256": budget.entries[-1]["raw_sha256"]}
            with pytest.raises(ValueError):
                network._next_compact_call(budget.entries, "N2", "qualification", c["head"], c["source_sha256"], c)
            # 同一B原件若达到目标，只有C可取得最后一项，绝无第二次B。
            finish(budget, next_m, goal=True)
            c["predecessor_raw_sha256"] = budget.entries[-1]["raw_sha256"]
            budget.reserve("N2", "qualification", c["head"], c["source_sha256"], ledger.parent/"C.json",
                conditions_sha256=c["conditions_sha256"], continuation=c)
            network.require_v2_candidate(c)
            finish(budget, c, goal=True)
        else:
            # 通过真实共享适配和实际循环，恰在创建任何子进程前截断，证明C选择10000/v2历史。
            captured, contexts = [], []
            original = benchmark._run_continuous_observation
            def observed(**kwargs):
                captured.append(kwargs)
                return original(**kwargs)
            def context(*_args):
                contexts.append(True)
                raise RuntimeError("software witness before constructing any role")
            monkeypatch.setattr(benchmark, "_run_continuous_observation", observed)
            monkeypatch.setattr(benchmark.mp, "get_context", context)
            failed = benchmark.run_network_observation(configs=network.role_configs(certs, network.V2_PORTS, "N2"),
                steps=10000, wire_profile=network._COMPACT_PROFILE_V2, candidate_manifest=next_m)
            assert len(captured) == len(contexts) == 1 and failed["status"] == "failed" and failed["cycles"] == []
            assert captured[0]["steps"] == 10000 and captured[0]["network_candidate_manifest"] == next_m
            assert captured[0]["_compact_history"].wire_profile == network._COMPACT_PROFILE_V2
            for wrong in ({"steps": 1000}, {"network_candidate_manifest": None}, {"segment_steps": 2}):
                with pytest.raises(ValueError):
                    original(**(captured[0]|wrong))
            result = finish(budget, next_m, goal=True)
            assert result["network_dynamic_qualification_pass"] and result["network_progress_goal_pass"]
        assert budget.entries[:6] == history
        with pytest.raises(ValueError):
            network._next_compact_call(budget.entries, "N2", "candidate", m["head"], m["source_sha256"], m)


def test_closure_wrong_permission_empty_history_goal_and_cpu_fail_closed(closure_context, monkeypatch):
    history, m, _ledger, _certs = closure_context
    for entries in ([], history[:5], [dict(e, finished=False) for e in history], [dict(e, head="changed") for e in history]):
        with pytest.raises(ValueError):
            network._next_compact_call(entries, "N2", "candidate", m["head"], m["source_sha256"], m)
    for wrong in (m|{"authorization_url": network.CLOSURE_AUTHORIZATION+"0"}, m|{"closure_stage": "C"},
                  m|{"closure_stage": "B"}, m|{"maximum_attempts": 10000}, m|{"call": True},
                  m|{"previous_conditions_sha256": "0"*64}, m|{"closed_history_sha256": "0"*64}):
        with pytest.raises(ValueError):
            network._next_compact_call(history, "N2", wrong["phase"], wrong["head"], wrong["source_sha256"], wrong)
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *a, **k: True)
    monkeypatch.setattr(network, "_tls_pass", lambda _r: True)
    for goal, model, expected in ((True, True, True), (False, True, False), (True, False, False)):
        result = _closure_software_result(m, goal=goal, model=model)
        result["cycle_timing"] = {"max_ms": 1., "p99_ms": 1.}  # 虚假摘要不能覆盖全分母重算。
        result = network.assemble(result, profile="N2", phase="candidate", manifest=m, relay=result["network_relay"])
        assert result["network_progress_goal_pass"] is expected
        assert result["network_sample_pass"] is model
    relay = _closure_software_result(m)["network_relay"]
    relay["wait_policy"]["first_cpu_limit_window"] = relay["wait_policy"]["peak_cpu_window"]
    assert not network._closure_cpu_pass(relay)


def test_closure_wrapper_consumes_startup_and_direct_actual_rejects_unreserved(closure_context, monkeypatch):
    history, m, ledger, certs = closure_context
    approval = ledger.parent/"approval.json"
    approval.write_text(json.dumps(m), encoding="utf-8")
    calls = []
    def observed(**kwargs):
        network.require_v2_candidate(kwargs["candidate_manifest"], kwargs["configs"])
        calls.append(kwargs)
        raise RuntimeError("software startup boundary")
    class Relay:
        def __init__(self, *_args):
            self.report = {"model_valid": False, "process_exited": True, "forced_termination": False}
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return None
    monkeypatch.setattr(network, "NetworkRelay", Relay)
    monkeypatch.setattr(benchmark, "run_network_observation", observed)
    result = network.run_network_benchmark(profile="N2", phase="candidate", certs=certs,
        ports=network.V2_PORTS, ledger=ledger, approval=approval, output=ledger.parent/"A.json",
        wire_profile=network._COMPACT_PROFILE_V2, authorization=network.CLOSURE_AUTHORIZATION)
    assert len(calls) == 1 and result["failure_category"] == "RuntimeError"
    saved = json.loads(ledger.read_text())
    assert saved["entries"][:6] == history and saved["maximum_calls"] == 9 and saved["maximum_attempts"] == 18000
    assert saved["entries"][-1]["finished"] and saved["entries"][-1]["actual_attempts"] == 0
    assert not result["network_progress_goal_pass"]
    with pytest.raises(ValueError):
        network.require_v2_candidate(m)


def test_closure_v2_10000_history_preserves_all_rows_and_missing_failure_endpoints(monkeypatch):
    layouts = {role: benchmark._CompactHistory.layout(role, 10000, qualification=True,
        wire_profile=network._COMPACT_PROFILE_V2) for role in ("Client", "P1", "P2")}
    assert sum(v["reserved_bound_bytes"] for v in layouts.values()) == 39129163 < 48*1024**2
    assert layouts["Client"]["reserved_bound_bytes"] < 32*1024**2
    assert all(v["reserved_bound_bytes"] < 16*1024**2 for k, v in layouts.items() if k != "Client")
    monkeypatch.setattr(benchmark, "_process_memory", lambda: {"current_rss_bytes": 32*1024**2})
    history = benchmark._CompactHistory("Client", 10000, qualification=True, wire_profile=network._COMPACT_PROFILE_V2)
    for i in range(10000):
        history.tables["cycles"].append((("global_step", i), ("round_id", str(i)), ("cycle_completed_ns", None),
            ("status", "failed"), ("phase_durations_ns", {}), (("phase_durations_ns", "maintenance_advance"), i)))
    rows = history.expand()["cycles"]
    assert len(rows) == 10000 and len({r["round_id"] for r in rows}) == 10000
    assert rows[-1]["global_step"] == 9999 and all(r["cycle_completed_ns"] is None for r in rows)
    assert rows[-1]["phase_durations_ns"]["maintenance_advance"] == 9999 and history.report()["format_version"] == 2


@pytest.fixture
def event_context(closure_context, monkeypatch):
    """真实A的隔离结构反例，原件/门禁替身仅验证新许可，不读真实预算。"""
    _history, a, ledger, certs = closure_context
    monkeypatch.setattr(benchmark, "_compact_sample_pass", lambda *a, **k: True)
    monkeypatch.setattr(network, "_tls_pass", lambda _r: True)
    path = ledger.parent/"A.json"
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", a["head"], a["source_sha256"], path,
            conditions_sha256=a["conditions_sha256"], continuation=a)
        result = _closure_software_result(a, model=False)
        result = network.assemble(result, profile="N2", phase="candidate", manifest=a, relay=result["network_relay"])
        path.write_text(json.dumps(result), encoding="utf-8")
        budget.finish(result, network.hashlib.sha256(path.read_bytes()).hexdigest())
        entries = copy.deepcopy(budget.entries)
    closed = network.digest(entries)
    monkeypatch.setattr(network, "EVENT_HISTORY", closed)
    sources = {"src": "f"*64, "src/secure_control/experiments/_network_wait_win32.py": "b"*64}
    m = a|{"head": "e"*40, "source_sha256": sources, "closure_stage": "B", "call": 8,
        "wait_strategy": network.EVENT_STRATEGY, "wait_design_url": network.EVENT_DESIGN,
        "wait_authorization_url": network.EVENT_AUTHORIZATION, "closed_seven_history_sha256": closed,
        "patch_evidence_url": network.EVENT_DESIGN, "predecessor_raw_sha256": entries[-1]["raw_sha256"],
        "predecessor_review_url": a["review_url"], "predecessor_readback_exact": True}
    monkeypatch.setattr(network, "source", lambda: (m["head"], m["source_sha256"]))
    return entries, m, ledger, certs


def _event_software_result(m, *, model=True, goal=True):
    result = _closure_software_result(m, model=model, goal=goal)
    result["network_relay"]["wait_policy"].update(version=2, strategy=network.EVENT_STRATEGY, guard_ns=None,
        max_poll_episode_ns=0, active_poll=False, poll_episodes=0, poll_wall_ns=0, max_poll_wall_ns=0,
        native_wait_calls=10, network_notifications=5, handle_high_water=7, handles_open=0,
        last_wait_started_ns=10, last_wait_returned_ns=20, last_wait_target_ns=20)
    return network.assemble(result, profile="N2", phase=m["phase"], manifest=m, relay=result["network_relay"])


@pytest.fixture
def repair_real_gates():
    """在历史fixture替身生效前保存真正的完整样本和TLS事实门禁。"""
    return benchmark._compact_sample_pass,network._tls_pass


@pytest.fixture
def repair_context(repair_real_gates,event_context, monkeypatch):
    """封闭八项软件历史和native START；不访问真实实验账本或运行控制。"""
    _old, b, ledger, certs = event_context
    directory = ledger.parent/"issue120-network-closure-certs"
    directory.mkdir()
    for path in certs.iterdir():
        (directory/path.name).write_bytes(path.read_bytes())
    b = b|{"certificate_directory": str(directory.resolve()),
           "certificate_change_authorization_url": network.EVENT_AUTHORIZATION,
           "certificate_change_reason": "insufficient_validity_before_B"}
    with network.RunBudget(ledger) as budget:
        path = ledger.parent/"B.json"
        budget.reserve("N2", "candidate", b["head"], b["source_sha256"], path,
            conditions_sha256=b["conditions_sha256"], continuation=b)
        result = _event_software_result(b, model=False)
        path.write_text(json.dumps(result), encoding="utf8")
        budget.finish(result, network.hashlib.sha256(path.read_bytes()).hexdigest())
        entries = copy.deepcopy(budget.entries)
    native_path = ledger.parent/"issue120-network-invocations.json"
    native = [{"completed": True, "native_exit": 5, "call": i+1} for i in range(8)]
    native_path.write_text(json.dumps({"entries": native}), encoding="utf8")
    monkeypatch.setattr(network, "REPAIR_HISTORY", network.digest(entries))
    monkeypatch.setattr(network, "REPAIR_NATIVE_HISTORY", network.digest(native))
    m = {k:v for k,v in b.items() if k not in ("closure_stage", *network.EVENT_FIELDS, *network.V2_CERTIFICATE_FIELDS)}
    m.update(authorization_url=network.REPAIR_AUTHORIZATION, continuation_design_url=network.REPAIR_DESIGN,
        closed_history_sha256=network.REPAIR_HISTORY, closed_native_history_sha256=network.REPAIR_NATIVE_HISTORY,
        continuation_stage="repair_recheck", call=9, maximum_calls=10, total_maximum_attempts=19000,
        continuation_maximum_calls=2, continuation_maximum_attempts=11000,
        head="9"*40, source_sha256={"src":"9"*64,"src/secure_control/experiments/_network_wait_win32.py":"b"*64},
        native_ledger_path=str(native_path.resolve()),wait_strategy=network.EVENT_STRATEGY,
        predecessor_raw_sha256=entries[-1]["raw_sha256"],predecessor_review_url=b["review_url"],
        predecessor_readback_exact=True,public_certificate_validity=network.certificate_validity(directory),
        previous_public_certificate_sha256=b["public_certificate_sha256"], previous_conditions_sha256=b["conditions_sha256"])
    monkeypatch.setattr(network,"source",lambda:(m["head"],m["source_sha256"]))
    monkeypatch.setattr(benchmark,"_compact_sample_pass",repair_real_gates[0])
    monkeypatch.setattr(network,"_tls_pass",repair_real_gates[1])
    return entries,m,ledger,directory,native_path,native


def _repair_native_start(path, old, m):
    entry = {k:m[k] for k in ("call","head","source_sha256","conditions_sha256","continuation_stage",
                              "authorization_url","maximum_attempts","profile","phase")}
    entry.update(completed=False,native_exit=None,started_utc="2026-10-19T00:00:00+00:00")
    path.write_text(json.dumps({"entries":old+[entry]}),encoding="utf8")


def _repair_software_result(m, *, model=True, goal=True):
    """完整公开字段的合成软件原件；实际样本/TLS/CPU/18-16门禁均不mock。"""
    from test_communication_batch import _s9_public_result
    r=_s9_public_result()
    target=m["maximum_attempts"]
    r["cycles"]=r["cycles"][:target]
    for c in r["cycles"]:
        c["cycle_completed_ns"]=c["scheduled_start_ns"]+15000000
        if c["global_step"] in range(399,target-1,400):c["phase_durations_ns"]={"maintenance":1}
    if not goal:r["cycles"][-1]["cycle_completed_ns"]=r["cycles"][-1]["scheduled_start_ns"]+19000000
    r.update(requested_steps=target,successful_steps=target,protocol_committed_count=target,physically_confirmed_count=target,
        cycle_summary={"attempts":target,"misses":0},code_sha=m["head"],source_sha256=m["source_sha256"],
        resource_counts={"products_consumed":30*target,"truncations_consumed":4*target},
        wire_profile=network._COMPACT_PROFILE_V2,
        steps=[{k:c[k] for k in ("global_step","status","session_id","round_id")} for c in r["cycles"]],
        numeric_profile={"fractional_bits":32,"security_parameter":80,"period_s":.02,"modulus_bits":256,
            "state_dimension":4,"input_dimension":2,"output_dimension":1},
        material_comparison={"memory_guard_failed":False,"cleanup_failed":False,"producer_exited":True})
    numeric=r.pop("worker_long_run")["numeric_contract"]|{"block_steps":19,"parameter_bits":40,"runtime_payload_bits":46}
    r["stage_wait_diagnostic"]={"evidence_complete":True,"numeric_contract":numeric,
        "roles":[{"role":p,"gc":{"normal_stop_ack_sent":True}} for p in ("P1","P2")]}
    r["network_history"]={"finite_sample_pass":True,"representation_complete":True,"thread_registration_complete":True,
        "numeric_contract":numeric,"roles":[{"role":role,"tables":{name:{"captured":target,"expanded":target}
            for name in ("steps","cycles")}} for role in ("Client","P1","P2")]}
    r["material_summary"].update(claimed=target,generated_received=target+16,encoding_profile=network._COMPACT_PROFILE_V2)
    r["material_summary"]["worker"]["encoding_profile"]=network._COMPACT_PROFILE_V2
    for p in r["party_outcomes"]:
        p["steps"]=p["steps"][:target];p["wire_profile"]=network._COMPACT_PROFILE_V2
    last=r["cycles"][-1]
    r["last_commit_observation"].update({k:last[k] for k in ("round_id","global_step")})
    r["last_commit_observation"]["step"]=target-1
    for row,role in [(r,"Client"),*[(p,p["role"]) for p in r["party_outcomes"]]]:
        row["network_tls"]={"restored":True,"links":[{"role":role,"peer_identity":f"{peer.lower()}.secure-control.test",
            "peer_san":[["DNS",f"{peer.lower()}.secure-control.test"]],"version":"TLSv1.3","tcp_nodelay":1}
            for peer in ("Client","P1","P2") if peer!=role]}
    relay=_event_software_result(m,model=model)["network_relay"]
    return network.assemble(r,profile="N2",phase=m["phase"],manifest=m,relay=relay)


def test_repair_r1_q1_use_canonical_budget_native_start_and_recompute_predecessor(repair_context,monkeypatch):
    entries,m,ledger,certs,npath,native = repair_context
    assert network._repair_manifest_valid(m)
    with pytest.raises(ValueError):  # 无native START，即使软件放行也不得占项。
        network._next_compact_call(entries,"N2","candidate",m["head"],m["source_sha256"],m)
    _repair_native_start(npath,native,m)
    with network.RunBudget(ledger) as budget:
        raw = ledger.parent/"R1.json"
        assert budget.reserve("N2","candidate",m["head"],m["source_sha256"],raw,
            conditions_sha256=m["conditions_sha256"],continuation=m)==1000
        network.require_v2_candidate(m,network.role_configs(certs,network.V2_PORTS,"N2"))
        result=_repair_software_result(m)
        assert result["network_sample_pass"] and result["network_progress_goal_pass"]
        raw.write_text(json.dumps(result),encoding="utf8")
        budget.finish(result,network.hashlib.sha256(raw.read_bytes()).hexdigest())
        r1 = copy.deepcopy(budget.entries[-1])
    actual=json.loads(npath.read_text())["entries"]
    actual[-1].update(completed=True,native_exit=0)
    q=m|{"continuation_stage":"repair_qualification","call":10,"phase":"qualification","maximum_attempts":10000,
         "eligible_for_candidate":False,"qualification_allowed":True,"predecessor_raw_sha256":r1["raw_sha256"]}
    _repair_native_start(npath,actual,q)
    good_raw=raw.read_bytes()
    for fault in ("incomplete","commit","tls","model","cpu","goal"):
        bad=json.loads(good_raw)
        if fault=="incomplete":bad["cycles"].pop()
        elif fault=="commit":bad["last_commit_observation"]["parties"]["P2"]["valid_ack_received"]=False
        elif fault=="tls":bad["network_tls"]["links"]=[]
        elif fault=="model":bad["network_relay"]["model_valid"]=False
        elif fault=="cpu":bad["network_relay"]["wait_policy"]["last_wait_returned_ns"]=None
        else:bad["cycles"][-1]["cycle_completed_ns"]=bad["cycles"][-1]["scheduled_start_ns"]+19000000
        # 重新绑定真实被改原件hash，确保拒绝来自门禁重算，而非仅hash不同。
        raw.write_text(json.dumps(bad),encoding="utf8")
        changed=r1|{"raw_sha256":network.hashlib.sha256(raw.read_bytes()).hexdigest(),"sample_pass":True}
        wrong=q|{"predecessor_raw_sha256":changed["raw_sha256"]}
        with pytest.raises(ValueError):
            network._next_compact_call(entries+[changed],"N2","qualification",wrong["head"],wrong["source_sha256"],wrong)
    raw.write_bytes(good_raw)
    for wrong in ({"head":"8"*40},{"conditions_sha256":"0"*64},{"predecessor_raw_sha256":"0"*64}):
        w=q|wrong
        with pytest.raises(ValueError):network._next_compact_call(entries+[r1],"N2","qualification",w["head"],w["source_sha256"],w)
    with network.RunBudget(ledger) as budget:
        assert budget.reserve("N2","qualification",q["head"],q["source_sha256"],ledger.parent/"Q1.json",
            conditions_sha256=q["conditions_sha256"],continuation=q)==10000
        network.require_v2_candidate(q)
        assert budget.entries[:8]==entries
        assert _repair_software_result(q)["network_dynamic_qualification_pass"]
        budget.finish({"cycles":[],"network_sample_pass":False},"failure")
        with pytest.raises(ValueError):
            network._next_compact_call(budget.entries,"N2","qualification",q["head"],q["source_sha256"],q)
    saved=json.loads(ledger.read_text())
    assert saved["maximum_calls"]==10 and saved["maximum_attempts"]==19000


def test_repair_wrong_permission_history_native_and_model_or_cpu_cannot_release(repair_context,monkeypatch):
    entries,m,_ledger,_certs,npath,native=repair_context
    for wrong in ({"authorization_url":network.EVENT_AUTHORIZATION},{"call":True},{"maximum_calls":9},
                  {"continuation_stage":"repair_qualification"},{"closure_stage":"C"},
                  {"closed_native_history_sha256":"0"*64},{"wait_strategy":"other"}):
        assert not network._repair_manifest_valid(m|wrong)
    _repair_native_start(npath,native,m)
    assert network._next_compact_call(entries,"N2","candidate",m["head"],m["source_sha256"],m)==1000
    for bad in ([],entries[:-1],entries+[entries[-1]], [entries[0]|{"head":"tampered"}]+entries[1:]):
        with pytest.raises(ValueError): network._next_compact_call(bad,"N2","candidate",m["head"],m["source_sha256"],m)
    rows=json.loads(npath.read_text())["entries"]
    for changed in (rows[:-1],rows+[rows[-1]],rows[:-1]+[rows[-1]|{"completed":True}],
                    [rows[0]|{"native_exit":0}]+rows[1:]):
        npath.write_text(json.dumps({"entries":changed}),encoding="utf8")
        with pytest.raises(ValueError):network._next_compact_call(entries,"N2","candidate",m["head"],m["source_sha256"],m)
    npath.write_text(json.dumps({"entries":rows}),encoding="utf8")
    for fields in ({"poll_episodes":1},{"last_wait_returned_ns":None},{"cpu_limit_percent":51}):
        r=_repair_software_result(m);r["network_relay"]["wait_policy"].update(fields)
        assert not network.assemble(r,profile="N2",phase="candidate",manifest=m,relay=r["network_relay"])["network_sample_pass"]
    assert not _repair_software_result(m,model=False)["network_sample_pass"]
    assert not _repair_software_result(m,goal=False)["network_progress_goal_pass"]


def test_repair_actual_wrapper_native_strategy_shared_checks_and_failed_start_consumes(repair_context,monkeypatch):
    entries,m,ledger,certs,npath,native=repair_context
    m=m|{"environment":{"platform":network.platform.platform(),"python":sys.version.split()[0],
                          "openssl":network.ssl.OPENSSL_VERSION}}
    # 原有软件fixture已固定相同环境；若不同不可偷偷修改封闭历史。
    assert m["environment"]==entries[-1]["environment"]
    approval=ledger.parent/"repair-approval.json"
    approval.write_text(json.dumps(m),encoding="utf8")
    _repair_native_start(npath,native,m)
    observed=[]
    class Relay:
        def __init__(self,profile,endpoints,*,wait_strategy):
            assert profile=="N2" and len(endpoints)==3 and wait_strategy==network.EVENT_STRATEGY
            self.report={"model_valid":False,"process_exited":True,"forced_termination":False}
        def __enter__(self):return self
        def __exit__(self,*args):return None
    original=benchmark._run_continuous_observation
    def observe(**kwargs):
        observed.append(True)
        return original(**kwargs)
    def no_process(*args):raise RuntimeError("software boundary before role creation")
    monkeypatch.setattr(network,"NetworkRelay",Relay)
    monkeypatch.setattr(benchmark,"_run_continuous_observation",observe)
    monkeypatch.setattr(benchmark.mp,"get_context",no_process)
    r=network.run_network_benchmark(profile="N2",phase="candidate",certs=certs,ports=network.V2_PORTS,
        ledger=ledger,approval=approval,output=ledger.parent/"R1.json",wire_profile=network._COMPACT_PROFILE_V2,
        authorization=network.REPAIR_AUTHORIZATION)
    assert observed==[True] and r["failure_category"]=="RuntimeError"
    saved=json.loads(ledger.read_text())["entries"]
    assert saved[:8]==entries and len(saved)==9 and saved[-1]["finished"] and saved[-1]["actual_attempts"]==0
    with pytest.raises(ValueError):network.require_v2_candidate(m)
    with pytest.raises(ValueError):
        network.run_network_benchmark(profile="N2",phase="candidate",certs=certs,ports=network.V2_PORTS,
            ledger=ledger,approval=approval,output=ledger.parent/"retry.json",wire_profile=network._COMPACT_PROFILE_V2,
            authorization=network.REPAIR_AUTHORIZATION)


def test_repair_certificate_exception_only_for_insufficient_original_and_exact_approval(repair_context,monkeypatch):
    entries,m,ledger,certs,npath,native=repair_context
    fresh=ledger.parent/"issue120-network-repair-certs"
    subprocess.run([sys.executable,str(ROOT/"tests/fixtures/prepare_local_lan_certs.py"),"--output",str(fresh)],
        check=True,capture_output=True)
    hashes={name:network.hashlib.sha256((fresh/name).read_bytes()).hexdigest() for name in m["public_certificate_sha256"]}
    changed=m|{"certificate_directory":str(fresh.resolve()),"public_certificate_sha256":hashes,
        "public_certificate_validity":network.certificate_validity(fresh),
        "certificate_change_reason":"insufficient_validity_before_R1","certificate_change_authorization_url":network.REPAIR_AUTHORIZATION}
    changed["conditions_sha256"]=network.digest({k:changed[k] for k in ("ports","environment","public_certificate_sha256","seed")})
    _repair_native_start(npath,native,changed)
    assert network._next_compact_call(entries,"N2","candidate",changed["head"],changed["source_sha256"],changed)==1000
    with pytest.raises(ValueError):network._require_repair_certificates(changed)
    decode=network.ssl._ssl._test_decode_cert
    def expired(path):
        value=decode(path)
        if network.Path(path).parent==certs:value["notAfter"]="Oct 17 00:00:00 2000 GMT"
        return value
    monkeypatch.setattr(network.ssl._ssl,"_test_decode_cert",expired)
    network._require_repair_certificates(changed,network.role_configs(fresh,network.V2_PORTS,"N2"))
    for wrong in ({"certificate_change_authorization_url":network.REPAIR_DESIGN},
                  {"certificate_change_reason":"insufficient_validity_before_B"},{"public_certificate_validity":{}}):
        with pytest.raises(ValueError):network._require_repair_certificates(changed|wrong)


def test_event_B_C_exact_new_strategy_history_and_predecessor_goals(event_context):
    entries, b, ledger, certs = event_context
    assert network._closure_manifest_valid(b)
    for wrong in (b|{"wait_strategy": "other"}, b|{"wait_authorization_url": network.EVENT_DESIGN},
                  b|{"closed_seven_history_sha256": "0"*64}, b|{"closure_stage": "A", "call": 7},
                  {k:v for k,v in b.items() if k not in network.EVENT_FIELDS}):
        with pytest.raises(ValueError):
            network._next_closure_call(entries, "N2", wrong["phase"], wrong["head"], wrong["source_sha256"], wrong)
    with network.RunBudget(ledger) as budget:
        budget.reserve("N2", "candidate", b["head"], b["source_sha256"], ledger.parent/"B.json",
            conditions_sha256=b["conditions_sha256"], continuation=b)
        network.require_v2_candidate(b, network.role_configs(certs, network.V2_PORTS, "N2"))
        result = _event_software_result(b)
        assert result["network_sample_pass"] and result["network_progress_goal_pass"]
        path = ledger.parent/"B.json"
        def finish(value):
            path.write_text(json.dumps(value), encoding="utf-8")
            budget.finish(value, network.hashlib.sha256(path.read_bytes()).hexdigest())
        finish(result)
        c = b|{"closure_stage": "C", "call": 9, "phase": "qualification", "maximum_attempts": 10000,
            "eligible_for_candidate": False, "qualification_allowed": True, "predecessor_raw_sha256": budget.entries[-1]["raw_sha256"]}
        for bad in ({"head": "d"*40}, {"conditions_sha256": "0"*64}, {"certificate_directory": str(certs.parent/"other")}):
            wrong = c|bad
            with pytest.raises(ValueError):
                network._next_closure_call(budget.entries, "N2", "qualification", wrong["head"], wrong["source_sha256"], wrong)
        for fail in (_event_software_result(b, goal=False), _event_software_result(b, model=False)):
            finish(fail)
            c["predecessor_raw_sha256"] = budget.entries[-1]["raw_sha256"]
            with pytest.raises(ValueError):
                network._next_closure_call(budget.entries, "N2", "qualification", c["head"], c["source_sha256"], c)
        finish(result)
        c["predecessor_raw_sha256"] = budget.entries[-1]["raw_sha256"]
        assert budget.reserve("N2", "qualification", c["head"], c["source_sha256"], ledger.parent/"C.json",
            conditions_sha256=c["conditions_sha256"], continuation=c) == 10000
        network.require_v2_candidate(c)
        assert _event_software_result(c)["network_dynamic_qualification_pass"]
        budget.finish({"cycles": [], "network_sample_pass": False}, "software fixture")
        with pytest.raises(ValueError):
            network._next_closure_call(budget.entries, "N2", "qualification", c["head"], c["source_sha256"], c)
        assert budget.entries[:7] == entries


def test_event_cpu_version_cannot_accept_poll_or_unknown_strategy(event_context):
    _entries, b, _ledger, _certs = event_context
    relay = _event_software_result(b)["network_relay"]
    assert network._closure_cpu_pass(relay, native=True)
    assert not network._closure_cpu_pass(relay)
    for wrong in ({"strategy": "other"}, {"active_poll": True}, {"poll_wall_ns": 1},
                  {"handle_high_water": 17}, {"handles_open": 1}, {"cpu_limit_percent": 51}, {"guard_ns": 500000},
                  {"last_wait_returned_ns": None}):
        altered = copy.deepcopy(relay)
        altered["wait_policy"].update(wrong)
        assert not network._closure_cpu_pass(altered, native=True)
    legacy = _closure_software_result(b)["network_relay"]
    assert not network._closure_cpu_pass(legacy, native=True)


def test_event_wrapper_passes_explicit_strategy_and_consumes_failed_startup(event_context, monkeypatch):
    entries, b, ledger, certs = event_context
    approval = ledger.parent/"event-approval.json"
    approval.write_text(json.dumps(b), encoding="utf-8")
    observed = []
    class Relay:
        def __init__(self, profile, endpoints, *, wait_strategy):
            assert profile == "N2" and len(endpoints) == 3 and wait_strategy == network.EVENT_STRATEGY
            observed.append(wait_strategy)
            self.report = {"model_valid": False, "process_exited": True, "forced_termination": False}
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return None
    def start(**kwargs):
        network.require_v2_candidate(kwargs["candidate_manifest"], kwargs["configs"])
        raise RuntimeError("software startup boundary")
    monkeypatch.setattr(network, "NetworkRelay", Relay)
    monkeypatch.setattr(benchmark, "run_network_observation", start)
    r = network.run_network_benchmark(profile="N2", phase="candidate", certs=certs, ports=network.V2_PORTS,
        ledger=ledger, approval=approval, output=ledger.parent/"B.json", wire_profile=network._COMPACT_PROFILE_V2,
        authorization=network.CLOSURE_AUTHORIZATION)
    assert observed == [network.EVENT_STRATEGY] and r["failure_category"] == "RuntimeError"
    saved = json.loads(ledger.read_text())["entries"]
    assert saved[:7] == entries and saved[-1]["finished"] and saved[-1]["actual_attempts"] == 0
    assert not r["network_progress_goal_pass"]
    with pytest.raises(ValueError):
        network.require_v2_candidate(b)


def test_event_B_certificate_exception_requires_expired_previous_and_exact_approval(event_context, monkeypatch):
    entries, b, ledger, certs = event_context
    new = ledger.parent/"issue120-network-closure-certs"
    subprocess.run([sys.executable, str(ROOT/"tests/fixtures/prepare_local_lan_certs.py"), "--output", str(new)],
        check=True, capture_output=True)
    hashes = {name: network.hashlib.sha256((new/name).read_bytes()).hexdigest() for name in b["public_certificate_sha256"]}
    m = b|{"certificate_directory": str(new.resolve()), "public_certificate_sha256": hashes,
        "public_certificate_validity": network.certificate_validity(new),
        "conditions_sha256": network.digest({"ports": b["ports"], "environment": b["environment"],
            "public_certificate_sha256": hashes, "seed": network.SEED}),
        "certificate_change_authorization_url": network.EVENT_AUTHORIZATION,
        "certificate_change_reason": "insufficient_validity_before_B"}
    assert network._next_closure_call(entries, "N2", "candidate", m["head"], m["source_sha256"], m) == 1000
    with pytest.raises(ValueError):  # 原证仍充分有效，不得借例外搜索条件。
        network._require_closure_certificates(m)
    decode = network.ssl._ssl._test_decode_cert
    def expired(path):
        result = decode(path)
        if network.Path(path).parent == certs:
            result["notAfter"] = "Oct 17 00:00:00 2000 GMT"
        return result
    monkeypatch.setattr(network.ssl._ssl, "_test_decode_cert", expired)
    network._require_closure_certificates(m, network.role_configs(new, network.V2_PORTS, "N2"))
    for wrong in ({"certificate_change_authorization_url": network.EVENT_DESIGN},
                  {"certificate_change_reason": "insufficient_validity_before_A"},
                  {"public_certificate_validity": {}},
                  {"previous_public_certificate_sha256": hashes}):
        with pytest.raises(ValueError):
            network._require_closure_certificates(m|wrong)


def test_native_wait_late_return_is_still_model_failure_and_stop_is_not_a_write(monkeypatch):
    clock = [100]
    monkeypatch.setattr(emulator.time, "perf_counter_ns", lambda: clock[0])
    policy, ring = emulator._WaitPolicy(), emulator.PublicRing()
    calls = []
    def wait_until(target):
        calls.append(target)
        clock[0] = target+1000001  # 原生timer不是调度保证，真实迟醒不能删去。
        return [], clock[0], 6
    native = SimpleNamespace(wait_until=wait_until, last_start=100)
    policy.native_wait = native
    selected, returned = emulator._wait_for_events(native, Event(), 200, 100000000, policy, ring)
    assert not selected and returned is None and calls == [200] and ring.timing[:4] == [6, 100, 1000201, 200]
    direction = emulator.Direction(None, SimpleNamespace(send=lambda data: len(data)), "Client->P1", None)
    direction.queue.append(emulator.Block(b"x", 0, 0, 0, 0, 200))
    direction.queued = 1
    emulator._serve_due([direction], 0, ring)
    assert direction.stats["unexplained_over_tolerance"] == 1 and ring.rows()[-1][13] == -1
    stop = Event()
    stop.set()
    emulator._wait_for_events(native, stop, None, clock[0]+1000, policy, ring)
    assert calls == [200]
    emulator._wait_for_events(native, stop, None, clock[0]+1000, policy, ring, stopping=True)
    assert len(calls) == 2


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
    repair=[network.REPAIR_AUTHORIZATION if a==network.V2_AUTHORIZATION else a for a in v2]
    for phase in ("candidate","qualification"):
        current=list(repair);current[current.index("--network-phase")+1]=phase
        monkeypatch.setattr(sys,"argv",current)
        assert lan_runner._run()==0 and calls[-1]["authorization"]==network.REPAIR_AUTHORIZATION
    assert len(calls)==5
    local=[network.LOCAL_DESIGN if a==network.V2_AUTHORIZATION else "N0" if a=="N2" else a for a in v2]
    monkeypatch.setattr(sys, "argv", local)
    assert lan_runner._run() == 0 and calls[-1]["authorization"] == network.LOCAL_DESIGN
    for key, bad in (("--network-profile", "N2"), ("--network-phase", "qualification")):
        invalid = list(local)
        invalid[invalid.index(key)+1] = bad
        monkeypatch.setattr(sys, "argv", invalid)
        assert lan_runner._run() == 5 and len(calls) == 6


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
@pytest.mark.parametrize("wait_strategy", [None, pytest.param(network.EVENT_STRATEGY,
    marks=pytest.mark.skipif(sys.platform != "win32", reason="Windows原生等待"))])
def test_three_tls_links_cross_opaque_relay_and_wrong_role_still_fails(tmp_path, wait_strategy):
    subprocess.run([sys.executable, str(ROOT/"tests/fixtures/prepare_local_lan_certs.py"),
                    "--output", str(tmp_path)], check=True, capture_output=True)
    ports = free_ports()
    configs = {c.role: c for c in network.role_configs(tmp_path, ports, "N1")}
    endpoints = (configs["Client"].topology.p1_client, configs["Client"].topology.p2_client, configs["Client"].topology.p1_peer)
    servers = [lan_transport.listener(e) for e in endpoints]
    payload = b"opaque-test-marker-" + bytes(range(256))*64
    errors, versions = [], []
    relay = emulator.NetworkRelay("N1", tuple(("127.0.0.1", p, "127.0.0.2") for p in ports), wait_strategy=wait_strategy)
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
        if wait_strategy is not None:
            policy = relay.report["wait_policy"]
            assert policy["version"] == 2 and policy["strategy"] == network.EVENT_STRATEGY
            assert policy["active_poll"] is False and policy["poll_episodes"] == policy["handles_open"] == 0
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
    ("control-dynamic-compact-v2", 15, "bad_global"), ("control-dynamic-compact-v2", 15, "duplicate"),
    ("control-dynamic-compact-v3", 11, None), ("control-dynamic-compact-v3", 11, "bad_epoch"),
    ("control-dynamic-compact-v3", 11, "bad_global"), ("control-dynamic-compact-v3", 11, "duplicate")))
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
        advances = wire_profile in (network._COMPACT_PROFILE_V2, network._COMPACT_PROFILE_V3)
        assert boundaries == ([2, 2] if advances else [4, 4])
        if advances:
            assert operations.count("segment_advance") == 4 and "segment_begin" not in operations
            replies = [o["fixture_sent_operations"].count("segment_advance") for o in outcomes]
            assert replies == [2, 2]  # 每段双方各一个实际回复，额外四帧。
            assert all("segment_begin" not in o["fixture_sent_operations"] for o in outcomes)
            assert client_frames + party_frames + boundaries[0] + sum(replies)//2 == expected_frames+4
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
