"""实验relay私有的Windows网络事件/单计时器等待；不解释载荷或另起线程。"""

from __future__ import annotations

import ctypes
import os
import selectors
import sys
import threading
import time
from array import array
from ctypes import wintypes as w
from dataclasses import dataclass

STRATEGY = "win32-event-wait-v1"
FD_READ, FD_WRITE, FD_ACCEPT, FD_CONNECT, FD_CLOSE = 1, 2, 8, 16, 32
MAX_HANDLES = 16


class WaitEvidence:
    """仅W1显式启用的8次等待整数环；时点是Python可观察FFI边界而非内核signal。"""

    FIELDS = ("wait_id", "pid", "native_tid", "wait_started_ns", "target_ns", "calc_ns", "relative_100ns",
              "set_enter_ns", "set_leave_ns", "handles_ready_ns", "wait_enter_ns", "wait_leave_ns",
              "collect_end_ns", "relay_return_ns", "return_kind", "completed")
    CAPACITY = 8

    def __init__(self):
        self.rows = array("q", [-1]) * (self.CAPACITY*len(self.FIELDS))
        self.current = array("q", [-1]) * len(self.FIELDS)
        self.count = 0

    def begin(self):
        self.count += 1
        for i in range(len(self.current)):
            self.current[i] = -1
        self.current[0], self.current[1], self.current[2] = self.count, os.getpid(), threading.get_native_id()

    def finish(self):
        start = (self.count-1) % self.CAPACITY * len(self.FIELDS)
        for i, value in enumerate(self.current):
            self.rows[start+i] = value

    def report(self):
        """退出后才构建列表；-1明确表示没有执行/没有返回。"""
        width = len(self.FIELDS)
        return {"version": 1, "clock": "perf_counter_ns/QPC", "fields": self.FIELDS,
                "capacity": self.CAPACITY, "waits_seen": self.count,
                "scope": "Python-visible FFI boundaries; no kernel timer signal timestamp",
                "rows": [list(self.rows[(i % self.CAPACITY)*width:(i % self.CAPACITY+1)*width])
                         for i in range(max(0, self.count-self.CAPACITY), self.count)]}


class _Events(ctypes.Structure):
    _fields_ = [("events", ctypes.c_long), ("errors", ctypes.c_int * 10)]


class _API:
    """显式声明指针宽度/调用约定；能力缺失直接失败，不回退到sleep或轮询。"""

    def __init__(self):
        if sys.platform != "win32":
            raise OSError("此实验等待适配器仅支持Windows。")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        winsock = ctypes.WinDLL("ws2_32", use_last_error=True)
        declarations = (
            (kernel, "CreateWaitableTimerExW", [ctypes.c_void_p, w.LPCWSTR, w.DWORD, w.DWORD], w.HANDLE),
            (kernel, "SetWaitableTimerEx", [w.HANDLE, ctypes.POINTER(ctypes.c_longlong), w.LONG,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, w.ULONG], w.BOOL),
            (kernel, "CancelWaitableTimer", [w.HANDLE], w.BOOL),
            (kernel, "WaitForMultipleObjects", [w.DWORD, ctypes.POINTER(w.HANDLE), w.BOOL, w.DWORD], w.DWORD),
            (kernel, "CloseHandle", [w.HANDLE], w.BOOL),
            (kernel, "QueryPerformanceCounter", [ctypes.POINTER(ctypes.c_longlong)], w.BOOL),
            (kernel, "QueryPerformanceFrequency", [ctypes.POINTER(ctypes.c_longlong)], w.BOOL),
            (winsock, "WSACreateEvent", [], w.HANDLE),
            (winsock, "WSACloseEvent", [w.HANDLE], w.BOOL),
            (winsock, "WSAEventSelect", [ctypes.c_size_t, w.HANDLE, ctypes.c_long], ctypes.c_int),
            (winsock, "WSAEnumNetworkEvents", [ctypes.c_size_t, w.HANDLE, ctypes.POINTER(_Events)], ctypes.c_int),
            (winsock, "WSAGetLastError", [], ctypes.c_int),
        )
        for library, name, arguments, result in declarations:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
            setattr(self, name, function)

    def error(self, winsock=False):
        """错误码在失败后立即捕获，避免后续清理覆盖。"""
        return ctypes.WinError(self.WSAGetLastError() if winsock else ctypes.get_last_error())


@dataclass
class _SocketEvent:
    key: selectors.SelectorKey
    handle: int
    native_mask: int
    readable: bool = False
    closed: bool = False
    writable: bool = False
    write_returned: int | None = None
    connect_error: int = 0


class NativeWait:
    """单relay持有≤16句柄；缓存FD_WRITE边沿的状态，不伪造新可写通知。"""

    def __init__(self, *, _api=None, observe_wait=False):
        if type(observe_wait) is not bool:
            raise ValueError("等待观察开关必须是bool。")
        self.evidence = WaitEvidence() if observe_wait else None
        self.api = _API() if _api is None else _api
        self.clock_mapping = None
        if observe_wait and _api is None:
            raw, frequency = ctypes.c_longlong(), ctypes.c_longlong()
            before = time.perf_counter_ns()
            if not self.api.QueryPerformanceCounter(ctypes.byref(raw)):
                raise self.api.error()
            after = time.perf_counter_ns()
            if not self.api.QueryPerformanceFrequency(ctypes.byref(frequency)):
                raise self.api.error()
            self.clock_mapping = {"qpc_raw":raw.value,"frequency_hz":frequency.value,
                                  "perf_before_ns":before,"perf_after_ns":after}
        self.entries = {}
        self.closed = False
        self.cleanup_uncertain = False
        self.waits = self.notifications = self.high_water = 0
        self.previous_qpc = 0
        self.last_start = self.last_end = self.last_target = None
        self.timer = self.api.CreateWaitableTimerExW(None, None, 2, 0x100002)
        if not self.timer:
            raise self.api.error()
        self.high_water = 1

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def _now(self):
        value = time.perf_counter_ns()
        if type(value) is not int or not self.previous_qpc <= value < 2**63:
            raise ValueError("原生等待QPC必须是单调非负整数。")
        self.previous_qpc = value
        return value

    def _entry(self, sock):
        entry = self.entries[sock.fileno()]
        if entry.key.fileobj is not sock:
            raise ValueError("socket描述符被复用，不能继承旧事件。")
        return entry

    def get_key(self, sock):
        """仅返回当前socket对象拥有的登记，不按复用的数字FD认领。"""
        return self._entry(sock).key

    def get_map(self):
        """提供原relay所需的有界兴趣表，不暴露控制状态。"""
        return {fd: entry.key for fd, entry in self.entries.items()}

    @staticmethod
    def _mask(events, data):
        kind = data[0]
        if kind == "accept":
            return FD_ACCEPT | FD_CLOSE
        if kind == "connect":
            return FD_CONNECT | FD_WRITE | FD_CLOSE
        if kind != "stream":
            raise ValueError("未知relay socket类型。")
        # 即使暂时没有发送队列，也必须保存初始FD_WRITE；它不是电平通知。
        return FD_WRITE | FD_CLOSE | (FD_READ if events & selectors.EVENT_READ else 0)

    def register(self, sock, events, data):
        """新socket独占新事件；分配/绑定部分失败也回收，不创建继承句柄。"""
        if self.closed or sock.fileno() < 0 or sock.fileno() in self.entries:
            raise ValueError("等待器已关闭、socket无效或重复登记。")
        if len(self.entries)+2 > MAX_HANDLES:
            raise ValueError("relay事件句柄超过固定上限。")
        mask = self._mask(events, data)
        handle = self.api.WSACreateEvent()
        if not handle:
            raise self.api.error(True)
        if self.api.WSAEventSelect(sock.fileno(), handle, mask) != 0:
            error = self.api.error(True)
            if not self.api.WSACloseEvent(handle):
                self.cleanup_uncertain = True
            raise error
        key = selectors.SelectorKey(sock, sock.fileno(), events, data)
        self.entries[key.fd] = _SocketEvent(key, handle, mask)
        self.high_water = max(self.high_water, len(self.entries)+1)
        return key

    def detach_accepted(self, sock):
        """accept继承listener事件；在关闭listener前解除，之后单独登记。"""
        if self.api.WSAEventSelect(sock.fileno(), None, 0) != 0:
            raise self.api.error(True)

    def _collect(self, entry, returned):
        events = _Events()
        if self.api.WSAEnumNetworkEvents(entry.key.fd, entry.handle, ctypes.byref(events)) != 0:
            raise self.api.error(True)
        bits = events.events
        self.notifications += bool(bits)
        for bit in (FD_READ, FD_WRITE, FD_ACCEPT, FD_CONNECT, FD_CLOSE):
            error = events.errors[bit.bit_length()-1] if bits & bit else 0
            if error:
                if bit == FD_CONNECT and entry.key.data[0] == "connect":
                    entry.connect_error = error  # 交原后端重拨责任，不当成功可写。
                else:
                    raise ctypes.WinError(error)
        if bits & (FD_READ | FD_ACCEPT):
            entry.readable = True
        if bits & FD_CLOSE:
            entry.closed = True
        if bits & (FD_WRITE | FD_CONNECT):
            entry.writable = True
            entry.write_returned = returned

    def modify(self, sock, events, data):
        """暂停读时保存已发生事实；恢复读通过WSA重新通知，不清空其他边沿。"""
        entry = self._entry(sock)
        mask = self._mask(events, data)
        if mask != entry.native_mask:
            self._collect(entry, self._now())
            if self.api.WSAEventSelect(entry.key.fd, entry.handle, mask) != 0:
                raise self.api.error(True)
            entry.native_mask = mask
        entry.key = selectors.SelectorKey(sock, entry.key.fd, events, data)
        return entry.key

    def unregister(self, sock):
        """先注销再关事件；两步均尝试，保留第一个清理错误。"""
        entry = self._entry(sock)
        del self.entries[entry.key.fd]
        self._release(entry)
        return entry.key

    def _release(self, entry):
        error = None
        # 已关闭socket会自动取消关联；不得向可能复用的旧数字FD发解绑调用。
        if entry.key.fileobj.fileno() == entry.key.fd and self.api.WSAEventSelect(entry.key.fd, None, 0) != 0:
            error = self.api.error(True)
        if not self.api.WSACloseEvent(entry.handle):
            self.cleanup_uncertain = True
            error = error or self.api.error(True)
        if error is not None:
            raise error

    def read_started(self, sock):
        """必须在recv/accept前消费通知；recv会按Winsock契约重新启用FD_READ。"""
        self._entry(sock).readable = False

    def write_blocked(self, sock):
        """只有真实would-block清除可写状态，正数短写继续按原公平限制推进。"""
        entry = self._entry(sock)
        entry.writable = False
        entry.write_returned = None

    def write_progressed(self, sock):
        """实际正数send确认可继续尝试；不伪造FD_WRITE或新的取回时刻。"""
        self._entry(sock).writable = True

    def writable_return(self, sock):
        """只消费真实FD_WRITE/CONNECT取回时刻；缓存可写状态返回None。"""
        entry = self._entry(sock)
        value, entry.write_returned = entry.write_returned, None
        return value

    def connection_error(self, sock):
        """保留FD_CONNECT错误，不依赖枚举后SO_ERROR是否仍保存该值。"""
        return self._entry(sock).connect_error

    def _ready(self):
        ready = []
        for entry in self.entries.values():
            mask = 0
            if entry.key.events & selectors.EVENT_READ and (entry.readable or entry.closed):
                mask |= selectors.EVENT_READ
            # FD_CLOSE 只保留读 EOF；反向发送背压必须等真实 FD_WRITE 重新激活。
            if entry.key.events & selectors.EVENT_WRITE and entry.writable:
                mask |= selectors.EVENT_WRITE
            if mask:
                ready.append((entry.key, mask))
        return ready

    def wait_until(self, wake_at_ns):
        """保持原等待算法，只在显式W1模式记录有界时间事实。"""
        evidence = self.evidence
        if evidence is None:
            return self._wait_until(wake_at_ns)
        evidence.begin()
        try:
            result = self._wait_until(wake_at_ns)
            evidence.current[14], evidence.current[15] = result[2], 1
            return result
        finally:
            evidence.finish()

    def _wait_until(self, wake_at_ns):
        """一次有界收集＋一次原生等待；QPC绝对期限转负相对100ns，绝不主动轮询。"""
        if self.closed or type(wake_at_ns) is not int or not 0 <= wake_at_ns < 2**63:
            raise ValueError("原生等待需要有效QPC整数期限。")
        start = self._now()
        if self.evidence is not None:
            self.evidence.current[3], self.evidence.current[4] = start, wake_at_ns
        # 新调用在真正返回前没有返回事实；异常不得拼接前次 last_end。
        self.last_start, self.last_target, self.last_end = start, wake_at_ns, None
        if wake_at_ns <= start:
            self.last_end = start
            return [], start, 6
        for entry in self.entries.values():
            self._collect(entry, start)
        ready = self._ready()
        if ready:
            if self.evidence is not None:
                self.evidence.current[12] = self._now()
            self.last_end = self._now()
            return ready, self.last_end, 5
        now = self._now()
        remaining = wake_at_ns-now
        if self.evidence is not None:
            self.evidence.current[5] = now
        if remaining <= 0:
            self.last_end = now
            return [], now, 6
        # 相对计时向上取整，timer唤醒后仍由外层QPC判due，绝不提前发送。
        due = ctypes.c_longlong(-((remaining+99)//100))
        if self.evidence is not None:
            self.evidence.current[6], self.evidence.current[7] = due.value, self._now()
        timer_set = self.api.SetWaitableTimerEx(self.timer, ctypes.byref(due), 0, None, None, None, 0)
        timer_error = self.api.error() if not timer_set else None
        if self.evidence is not None:
            self.evidence.current[8] = self._now()
        if not timer_set:
            raise timer_error
        handles = (w.HANDLE * (len(self.entries)+1))(self.timer, *(e.handle for e in self.entries.values()))
        if self.evidence is not None:
            self.evidence.current[9] = self._now()
        self.waits += 1
        if self.evidence is not None:
            self.evidence.current[10] = self._now()
        result = self.api.WaitForMultipleObjects(len(handles), handles, False, 0xFFFFFFFF)
        returned = self._now()
        if self.evidence is not None:
            self.evidence.current[11] = returned
        self.last_end = returned
        if not 0 <= result < len(handles):
            raise self.api.error() if result == 0xFFFFFFFF else OSError("原生等待返回异常状态。")
        # 枚举全部socket通知，避免最小句柄索引偏置；timer永远不合成FD_WRITE。
        for entry in self.entries.values():
            self._collect(entry, returned)
        if self.evidence is not None:
            self.evidence.current[12] = self._now()
        return self._ready(), returned, 6 if result == 0 else 5

    def report(self):
        """固定标量摘要；last_wait_returned_ns 为 None 表示本次调用未返回。"""
        return {"active_poll": False, "native_wait_calls": self.waits, "network_notifications": self.notifications,
            "handle_high_water": self.high_water,
            "handles_open": None if self.cleanup_uncertain else len(self.entries)+bool(self.timer),
            "last_wait_started_ns": self.last_start, "last_wait_returned_ns": self.last_end,
            "last_wait_target_ns": self.last_target}

    def close(self):
        """所有事件和timer均尝试关闭；不关闭由原relay拥有的socket。"""
        if self.closed:
            return
        self.closed = True
        error = None
        for entry in list(self.entries.values()):
            del self.entries[entry.key.fd]
            try:
                self._release(entry)
            except Exception as failure:  # noqa: BLE001 - 继续收回其余句柄，首错交relay保存。
                error = error or failure
        timer, self.timer = self.timer, None
        if not self.api.CancelWaitableTimer(timer):
            error = error or self.api.error()
        if not self.api.CloseHandle(timer):
            self.cleanup_uncertain = True
            error = error or self.api.error()
        if error is not None:
            raise error
