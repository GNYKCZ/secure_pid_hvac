"""仅实验使用的有界TCP字节流转发；不持TLS密钥或解释协议内容。"""

from __future__ import annotations

import errno
import gc
import hashlib
import json
import multiprocessing as mp
import random
import selectors
import socket
import sys
import time
from array import array
from collections import deque
from dataclasses import dataclass, field

SEED = 12020261016
QUEUE_LIMIT = 1024 * 1024
READ_LIMIT = 4096
MODEL_TOLERANCE_NS = 1_000_000
DIRECTIONS = ("Client->P1", "P1->Client", "Client->P2", "P2->Client", "P2->P1", "P1->P2")
WAIT_GUARD_NS = 500_000
MAX_POLL_EPISODE_NS = 500_000
CPU_WINDOW_NS = 100_000_000


def _clock_ns(value):
    """时间事实仅接受非负整数；不截断浮点或把布尔值当ns。"""
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("转发器时钟必须是非负有符号64位整数ns。")
    return value


class RelayCpuLimitError(RuntimeError):
    """完整实际观测窗超过单核50%；不能用CPU开销解释掉模型误差。"""


class _WaitPolicy:
    """单个relay拥有的有界等待/CPU累计事实，无逐窗列表或额外采样线程。"""

    def __init__(self):
        self.start_wall = self.start_cpu = self.wall = self.cpu = None
        self.poll_count = self.poll_wall = self.poll_max = self.windows = 0
        self.peak = self.first_over = self.tail = None
        self.sample_error = None
        self.final_sample_complete = False
        self.native_wait = None

    def start(self, wall, cpu):
        self.start_wall = self.wall = _clock_ns(wall)
        self.start_cpu = self.cpu = _clock_ns(cpu)

    @property
    def next_cpu_check(self):
        """从上次实际采样计时；延后的窗口不得伪装为固定100ms。"""
        return self.wall + CPU_WINDOW_NS

    def sample_cpu(self, *, final=False):
        """仅在外层资源点和退出时采样，超限窗先保存再抛错。"""
        wall, cpu = _clock_ns(time.perf_counter_ns()), _clock_ns(time.process_time_ns())
        if wall < self.wall or cpu < self.cpu:
            raise ValueError("转发器CPU或QPC时钟倒退。")
        elapsed, consumed = wall-self.wall, cpu-self.cpu
        complete = elapsed >= CPU_WINDOW_NS
        if not complete and not final:
            return
        row = {"start_qpc_ns": self.wall, "end_qpc_ns": wall,
               "cpu_delta_ns": consumed, "wall_delta_ns": elapsed, "complete_window": complete}
        self.wall, self.cpu = wall, cpu
        if final:
            self.tail = row
            self.final_sample_complete = True
        if complete:
            self.windows += 1
            if self.peak is None or consumed*self.peak["wall_delta_ns"] > self.peak["cpu_delta_ns"]*elapsed:
                self.peak = row
            if 2*consumed > elapsed:
                if self.first_over is None:
                    self.first_over = row
                raise RelayCpuLimitError("转发器完整CPU观测窗超过单核50%。")

    def poll_finished(self, start, end):
        """保留真实持续时间；被抢占超过计划上限时不裁剪。"""
        _clock_ns(start)
        _clock_ns(end)
        if end < start:
            raise ValueError("转发器主动检查QPC倒退。")
        self.poll_count += 1
        self.poll_wall += end-start
        self.poll_max = max(self.poll_max, end-start)

    def report(self):
        """仅追加固定大小的公开摘要；旧报告缺此字段表示未记录。"""
        report = {"version": 1, "strategy": "bounded-near-due-v1" if sys.platform == "win32" else "selector-blocking",
            "guard_ns": WAIT_GUARD_NS, "max_poll_episode_ns": MAX_POLL_EPISODE_NS,
            "cpu_window_ns": CPU_WINDOW_NS, "cpu_limit_percent": 50,
            "poll_episodes": self.poll_count, "poll_wall_ns": self.poll_wall, "max_poll_wall_ns": self.poll_max,
            "cpu_complete_windows": self.windows, "peak_cpu_window": self.peak,
            "first_cpu_limit_window": self.first_over, "tail_cpu_window": self.tail,
            "cpu_sample_error_type": self.sample_error,
            "lifecycle_start_qpc_ns": self.start_wall, "lifecycle_end_qpc_ns": self.wall,
            "lifecycle_start_cpu_ns": self.start_cpu, "lifecycle_end_cpu_ns": self.cpu,
            "lifecycle_wall_ns": None if self.start_wall is None else self.wall-self.start_wall,
            "lifecycle_cpu_ns": None if self.start_cpu is None else self.cpu-self.start_cpu,
            "lifecycle_complete": self.final_sample_complete,
            "scope": "actual process CPU / actual QPC wall; one-core ratio; relay service interval after imports, includes socket startup/exit; sampled guard, not OS quota"}
        if self.native_wait is not None:
            from ._network_wait_win32 import STRATEGY
            report.update(version=2, strategy=STRATEGY, guard_ns=None, max_poll_episode_ns=0,
                          **self.native_wait.report())
        return report


@dataclass(frozen=True, slots=True)
class LinkModel:
    """额外单向传播和独立方向带宽；不是总RTT或无线共享空口。"""

    low_ns: int
    high_ns: int
    rate_bps: int | None

    def __post_init__(self):
        if (type(self.low_ns) is not int or type(self.high_ns) is not int
                or not 0 <= self.low_ns <= self.high_ns
                or self.rate_bps is not None and (type(self.rate_bps) is not int or self.rate_bps <= 0)):
            raise ValueError("非法网络模型。")


def models(profile):
    """固定四场景；公开延迟随机源与密码随机源完全分离。"""
    if profile not in ("N0", "N1", "N2", "N3"):
        raise ValueError("未知网络profile。")
    return {name: LinkModel(0, 0, None) if profile in ("N0", "N1") else
            LinkModel(1_000_000, 1_500_000, 100_000_000) if profile == "N3" and name in
            ("P1->P2", "P2->P1") else LinkModel(250_000, 500_000, 100_000_000)
            for name in DIRECTIONS}


class Schedule:
    """每方向固定seed、整数向上取整及FIFO；分块是socket读取块而非TCP包。"""

    def __init__(self, model, direction):
        self.model = model
        domain = hashlib.sha256(f"network-cycle-v1:{SEED}:{direction}".encode()).digest()
        self.rng = random.Random(int.from_bytes(domain, "big"))
        self.tx_ns = self.due_ns = self.offset = 0

    def enqueue(self, arrival_ns, size):
        if type(arrival_ns) is not int or arrival_ns < 0 or type(size) is not int or size <= 0:
            raise ValueError("网络调度只接受非负QPC时间及正字节数。")
        model = self.model
        serialization = ((8 * size * 1_000_000_000 + model.rate_bps - 1) // model.rate_bps
                         if model.rate_bps is not None else 0)
        self.tx_ns = max(arrival_ns, self.tx_ns) + serialization if model.rate_bps else arrival_ns
        propagation = self.rng.randint(model.low_ns, model.high_ns)
        self.due_ns = max(self.tx_ns + propagation, self.due_ns)
        offset = self.offset
        self.offset += size
        return offset, self.tx_ns, propagation, self.due_ns


@dataclass(slots=True)
class Block:
    """不透明暂存块，唯一发送游标；内容不会进入公开报告。"""

    data: bytes
    offset: int
    arrival: int
    tx: int
    propagation: int
    due: int
    cursor: int = 0
    first_attempt: int | None = None
    blocked: bool = False
    continuation_at: int | None = None


@dataclass(slots=True)
class Direction:
    """一个方向的有界队列及公开累计事实，绝不丢弃中间字节换取推进。"""

    source: socket.socket
    destination: socket.socket
    name: str
    schedule: Schedule
    queue: deque = field(default_factory=deque)
    queued: int = 0
    eof: bool = False
    shutdown: bool = False
    previous_completed: int = 0
    stats: dict = field(default_factory=lambda: {"received_bytes": 0, "sent_bytes": 0, "chunks": 0,
        "queue_high_water": 0, "backpressure_count": 0, "short_writes": 0, "max_release_excess_ns": 0,
        "max_unexplained_excess_ns": 0, "unexplained_over_tolerance": 0, "early_sends": 0,
        "fifo_wait_ns": 0, "blocked_release_count": 0, "completed_chunks": 0})


class PublicRing:
    """固定30KiB数值环加固定首异常槽；只在退出后编码，公开总预算64KiB。"""

    FIELDS = ("direction", "offset", "bytes", "arrival_ns", "tx_ns", "propagation_ns", "due_ns",
              "progress_ns", "sent_bytes", "queued_bytes", "unexplained_excess_ns", "backpressure",
              "first_attempt_ns", "writable_return_ns", "eligible_ns")
    CAPACITY = 256
    TIMING_FIELDS = ("wait_kind", "wait_started_ns", "wait_returned_ns", "planned_wake_ns",
                     "loop_started_ns", "rss_started_ns", "rss_ended_ns", "send_started_ns", "send_ended_ns")

    def __init__(self):
        self.data = array("q", [0]) * (self.CAPACITY * len(self.FIELDS))
        self.seen = 0
        self.first_anomaly = None
        self.first_anomaly_timing = None
        self.timing = [0, -1, -1, -1, -1, -1, -1]
        self.active_direction = None

    def append(self, values, *, send_started_ns=None):
        start = self.seen % self.CAPACITY * len(self.FIELDS)
        for index, value in enumerate(values):
            self.data[start + index] = value
        self.seen += 1
        if (values[10] > MODEL_TOLERANCE_NS or values[7] < values[6]) and self.first_anomaly is None:
            self.first_anomaly = tuple(values)
            self.first_anomaly_timing = (*self.timing,
                values[12] if send_started_ns is None else send_started_ns, values[7])

    def rows(self):
        width = len(self.FIELDS)
        return [list(self.data[(i % self.CAPACITY)*width:(i % self.CAPACITY+1)*width])
                for i in range(max(0, self.seen-self.CAPACITY), self.seen)]


def _read(direction):
    """队列满时不调用recv；每次读取最多原4096B且不超过剩余额度。"""
    room = QUEUE_LIMIT-direction.queued
    if room <= 0 or direction.eof:
        return
    try:
        data = direction.source.recv(min(READ_LIMIT, room))
    except BlockingIOError:
        return
    if not data:
        direction.eof = True
        return
    arrival = time.perf_counter_ns()
    offset, tx, propagation, due = direction.schedule.enqueue(arrival, len(data))
    direction.queue.append(Block(data, offset, arrival, tx, propagation, due))
    direction.queued += len(data)
    direction.stats["received_bytes"] += len(data)
    direction.stats["chunks"] += 1
    direction.stats["queue_high_water"] = max(direction.stats["queue_high_water"], direction.queued)


def _progress(direction, now, writable_at, ring, *, known_writable=False):
    """就绪后推进一次短写；FIFO阻挡和已观察到的socket背压单列。"""
    block = direction.queue[0]
    if now < block.due:
        raise RuntimeError("禁止提前转发字节。")
    eligible = max(block.due, direction.previous_completed)
    first = block.first_attempt is None
    if not first and writable_at is None and not (known_writable and block.continuation_at is not None):
        raise RuntimeError("已尝试块只能由真实可写事件推进")
    if first:
        block.first_attempt = now
    # 首次尝试必须及时；发生真实would-block后，另记录等待及返回就绪后的派发开销。
    # Native FD_WRITE是边沿状态：正短写后的继续发送从上次实际send结束计时，
    # 不伪造一次新可写事件。真正would-block必须由下次FD_WRITE重新激活。
    ready_at = eligible if first else writable_at if writable_at is not None else block.continuation_at
    residual = max(0, now - ready_at)
    stats = direction.stats
    try:
        sent = direction.destination.send(memoryview(block.data)[block.cursor:])
    except BlockingIOError:
        observed = time.perf_counter_ns()
        residual = max(residual, observed-ready_at)
        stats["max_unexplained_excess_ns"] = max(stats["max_unexplained_excess_ns"], residual)
        stats["unexplained_over_tolerance"] += residual > MODEL_TOLERANCE_NS
        stats["backpressure_count"] += 1
        block.blocked = True
        block.continuation_at = None
        ring.append((DIRECTIONS.index(direction.name), block.offset, len(block.data), block.arrival, block.tx,
                     block.propagation, block.due, observed, 0, direction.queued, residual, 1,
                     block.first_attempt, -1 if writable_at is None else writable_at, eligible), send_started_ns=now)
        return
    if sent <= 0:
        raise ConnectionError("网络字节流写端已关闭。")
    completed = time.perf_counter_ns()
    residual = max(residual, completed-ready_at)
    stats["max_unexplained_excess_ns"] = max(stats["max_unexplained_excess_ns"], residual)
    stats["unexplained_over_tolerance"] += residual > MODEL_TOLERANCE_NS
    short = sent < len(block.data) - block.cursor
    stats["short_writes"] += short
    block.blocked = block.blocked or short
    stats["sent_bytes"] += sent
    stats["max_release_excess_ns"] = max(stats["max_release_excess_ns"], completed-block.due)
    stats["early_sends"] += completed < block.due
    block.cursor += sent
    block.continuation_at = completed
    direction.queued -= sent
    ring.append((DIRECTIONS.index(direction.name), block.offset, len(block.data), block.arrival, block.tx,
                 block.propagation, block.due, completed, sent, direction.queued, residual, int(block.blocked),
                  block.first_attempt, -1 if writable_at is None else writable_at, eligible), send_started_ns=now)
    if block.cursor == len(block.data):
        stats["completed_chunks"] += 1
        stats["fifo_wait_ns"] += max(0, direction.previous_completed-block.due)
        stats["blocked_release_count"] += block.blocked
        direction.previous_completed = completed
        direction.queue.popleft()


def _dispatch(direction, now, writable_at, ring, native=None):
    """原一次send责任不变，仅将真实would-block反馈给FD_WRITE状态owner。"""
    if native is not None and direction.queue[0].first_attempt is None:
        # 首次到期发送已使用此前的可写状态；旧通知不得留给将来的短写继续。
        native.writable_return(direction.destination)
    before = direction.stats["backpressure_count"]
    _progress(direction, now, writable_at, ring, **({"known_writable": True} if native is not None else {}))
    if native is not None and direction.stats["backpressure_count"] != before:
        native.write_blocked(direction.destination)


def _serve_due(directions, rotation, ring, native=None):
    """每方向每遍至多一个原读块；只直接首次尝试，短写/背压等待可写事件。"""
    serviced = set()
    for offset in range(len(directions)):
        direction = directions[(rotation + offset) % len(directions)]
        now = time.perf_counter_ns()
        if (direction.queue and direction.queue[0].first_attempt is None
                and direction.queue[0].due <= now):
            ring.active_direction = direction.name
            _dispatch(direction, now, None, ring, native)
            serviced.add(direction.name)
    ring.active_direction = None
    return serviced


def _wait_for_events(selector, stop, future_due, wake_at, policy, ring, *, stopping=False):
    """只等待并返回真实就绪时刻；所有收发/FIFO仍由原外层循环处理。"""
    ring.timing[:4] = [0, -1, -1, -1]
    now = _clock_ns(time.perf_counter_ns())
    if now >= wake_at or stop.is_set() and not stopping:
        return [], None
    if policy.native_wait is not None:
        target = min(wake_at, future_due) if future_due is not None else wake_at
        selected, returned, kind = selector.wait_until(target)
        ring.timing[:4] = [kind, selector.last_start, returned, target]
        return selected, returned if selected else None
    if sys.platform == "win32" and future_due is not None:
        if future_due <= now:
            return [], None
        if future_due-now <= WAIT_GUARD_NS:
            start = now
            deadline = min(future_due, wake_at, start+MAX_POLL_EPISODE_NS)
            ring.timing[:4] = [4, start, -1, deadline]
            selected, returned, last = [], None, start
            try:
                while True:
                    now = _clock_ns(time.perf_counter_ns())
                    if now < last:
                        raise ValueError("转发器主动检查QPC倒退。")
                    last = now
                    if now >= deadline or stop.is_set() and not stopping:
                        break
                    # Windows不接受空FD；空集合时仅检查QPC/STOP，仍受同一episode上限。
                    if selector.get_map():
                        selected = selector.select(0)
                        returned = _clock_ns(time.perf_counter_ns())
                        if returned < last:
                            raise ValueError("转发器selector返回QPC倒退。")
                        last = returned
                        if selected:
                            break
            finally:
                ring.timing[2] = last
                policy.poll_finished(start, last)
            return selected, returned if selected else None
        # 远期先服务即时事件；正sleep仅走到guard外沿，醒后回外层重新求due。
        if selector.get_map():
            ring.timing[:4] = [1, now, -1, now]
            selected = selector.select(0)
            returned = _clock_ns(time.perf_counter_ns())
            ring.timing[2] = returned
            if selected:
                return selected, returned
        now = _clock_ns(time.perf_counter_ns())
        delay = min(250_000, future_due-now-WAIT_GUARD_NS, wake_at-now)
        if delay > 0:
            ring.timing[:4] = [2, now, -1, now+delay]
            time.sleep(delay/1e9)
            ring.timing[2] = _clock_ns(time.perf_counter_ns())
        return [], None
    # 没有未来首次发送（含仅真实背压）、空闲和非Windows路径保留阻塞。
    wait = min(100_000_000, wake_at-now)/1e9
    ring.timing[:4] = [1 if selector.get_map() else 3, now, -1, now+int(wait*1e9)]
    if selector.get_map():
        selected = selector.select(wait)
        returned = _clock_ns(time.perf_counter_ns())
        ring.timing[2] = returned
        return selected, returned if selected else None
    stop.wait(wait)
    ring.timing[2] = _clock_ns(time.perf_counter_ns())
    return [], None


def _relay_main(profile, endpoints, stop, pipe, wait_strategy=None):
    """一个临时子进程、一个selector，三连接六方向；TLS在原角色内完成。"""
    from .communication_benchmark import _process_memory

    selector, initialization_error = None, None
    try:
        if wait_strategy is not None:
            from ._network_wait_win32 import STRATEGY, NativeWait
            if wait_strategy != STRATEGY:
                raise ValueError("未知原生等待候选。")
            selector = NativeWait()
        else:
            selector = selectors.DefaultSelector()
    except Exception as failure:  # noqa: BLE001 - 初始化能力失败也由原报告保存首因，绝不回退。
        initialization_error = failure
    listeners, sockets, directions, pending = [], [], [], {}
    ring, policy, error, ready = PublicRing(), _WaitPolicy(), None, False
    native = selector if wait_strategy is not None else None
    policy.native_wait = native
    cleanup_error = None
    failure_at, operation, event_direction, error_errno, error_winerror = None, "startup", None, None, None
    peak, next_memory, stopping_at = 0, 0, None
    accepted = set()
    outgoing_by_socket, incoming_by_socket = {}, {}
    rotation = 0
    connection_attempts = [0, 0, 0]
    gc_before = {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                 "freeze_count": gc.get_freeze_count(), "debug": gc.get_debug()}
    link_models = models(profile)
    started = time.perf_counter_ns()
    try:
        if initialization_error is not None:
            operation = "wait_initialization"
            raise initialization_error
        policy.start(started, time.process_time_ns())
        for index, (host, port, backend) in enumerate(endpoints):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(listener)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind((host, port))
            listener.listen(1)
            listener.setblocking(False)
            selector.register(listener, selectors.EVENT_READ, ("accept", index, backend))
        pipe.send({"ready": True, "pid": mp.current_process().pid})
        ready = True
        while True:
            now = time.perf_counter_ns()
            ring.timing[4] = now
            operation, event_direction = "due_first", None
            serviced = _serve_due(directions, rotation, ring, *([native] if native is not None else []))
            rotation = (rotation + 1) % max(1, len(directions))
            now = time.perf_counter_ns()
            if now >= policy.next_cpu_check:
                operation, event_direction = "cpu", None
                policy.sample_cpu()
            if now >= next_memory:
                operation, event_direction = "rss", None
                ring.timing[5] = time.perf_counter_ns()
                memory = _process_memory()
                ring.timing[6] = time.perf_counter_ns()
                current = memory.get("current_rss_bytes", memory.get("peak_rss_bytes"))
                if type(current) is not int or current > 256*1024*1024:
                    raise MemoryError("网络子进程RSS保护触发。")
                peak = max(peak, current)
                next_memory = now + 100_000_000
            if stop.is_set():
                stopping_at = stopping_at or now
                if not any(d.queue for d in directions):
                    break
                if now-stopping_at > 5_000_000_000:
                    raise TimeoutError("网络队列关闭排空超时。")
            next_due = min(next_memory, policy.next_cpu_check)
            future_due = None
            # 后端监听可能稍晚于P2拨号；只在尚未转发字节的建连阶段等待。
            # 使用同一selector，不让一条启动连接阻塞其他TLS字节流。
            for index, connection in list(pending.items()):
                if now-started > 30_000_000_000:
                    raise TimeoutError("网络后端启动期限耗尽。")
                if connection["rear"] is None:
                    if now < connection["retry_at"]:
                        next_due = min(next_due, connection["retry_at"])
                        continue
                    rear = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection_attempts[index] += 1
                    rear.setblocking(False)
                    connection["rear"] = rear
                    result = rear.connect_ex((endpoints[index][2], endpoints[index][1]))
                    if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                                      getattr(errno, "WSAEWOULDBLOCK", 10035)):
                        if result not in (errno.ECONNREFUSED, 10061):
                            raise OSError(result, "backend connect")
                        rear.close()
                        connection.update(rear=None, retry_at=now+10_000_000)
                        next_due = min(next_due, now+10_000_000)
                    else:
                        selector.register(rear, selectors.EVENT_WRITE, ("connect", index))
            for sock in sockets:
                outgoing = outgoing_by_socket[sock]
                incoming = incoming_by_socket[sock]
                mask = (selectors.EVENT_READ if not outgoing.eof and outgoing.queued < QUEUE_LIMIT
                        and not stop.is_set() else 0)
                if incoming.queue:
                    due = incoming.queue[0].due
                    if due <= now:
                        mask |= selectors.EVENT_WRITE
                    else:
                        next_due = min(next_due, due)
                        if incoming.queue[0].first_attempt is None:
                            future_due = due if future_due is None else min(future_due, due)
                if incoming.eof and not incoming.queue and not incoming.shutdown:
                    operation, event_direction = "shutdown_write", incoming.name
                    sock.shutdown(socket.SHUT_WR)
                    incoming.shutdown = True
                try:
                    key = selector.get_key(sock)
                except KeyError:
                    if mask:
                        selector.register(sock, mask, ("stream", outgoing, incoming))
                else:
                    if not mask and native is None:
                        selector.unregister(sock)
                    elif key.events != mask:
                        selector.modify(sock, mask, key.data)
            if len(directions) == 6 and not pending and all(d.eof and d.shutdown and not d.queue for d in directions):
                break
            operation, event_direction = "wait", None
            selected, writable_at = _wait_for_events(selector, stop, future_due, next_due, policy, ring,
                                                     stopping=stopping_at is not None)
            for key, mask in selected:
                if key.data[0] == "accept":
                    operation, event_direction = "accept", None
                    _, index, backend = key.data
                    front, _ = key.fileobj.accept()
                    if index in accepted:
                        front.close()
                        raise ConnectionError("同一网络链路禁止第二条连接。")
                    accepted.add(index)
                    pending[index] = {"front": front, "rear": None, "retry_at": 0}
                    if native is not None:
                        # Winsock accept继承listener事件，先解绑再关闭listener。
                        native.detach_accepted(front)
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data[0] == "connect":
                    operation, event_direction = "connect", None
                    _, index = key.data
                    connection = pending[index]
                    front, rear = connection["front"], connection["rear"]
                    result = (native.connection_error(rear) if native is not None else 0) or rear.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    selector.unregister(rear)
                    if result:
                        if result not in (errno.ECONNREFUSED, 10061):
                            raise OSError(result, "backend connect")
                        rear.close()
                        connection.update(rear=None, retry_at=time.perf_counter_ns()+10_000_000)
                        continue
                    del pending[index]
                    sockets.extend((front, rear))
                    for sock in (front, rear):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        sock.setblocking(False)
                    for source, destination, name in ((front, rear, DIRECTIONS[2*index]),
                                                       (rear, front, DIRECTIONS[2*index+1])):
                        direction = Direction(source, destination, name, Schedule(link_models[name], name))
                        directions.append(direction)
                        outgoing_by_socket[source] = incoming_by_socket[destination] = direction
                    continue
                _, outgoing, incoming = key.data
                if mask & selectors.EVENT_READ:
                    operation, event_direction = "recv", outgoing.name
                    if native is not None:
                        native.read_started(key.fileobj)
                    _read(outgoing)
                if (mask & selectors.EVENT_WRITE and incoming.queue and incoming.name not in serviced
                        and incoming.queue[0].due <= time.perf_counter_ns()):
                    operation, event_direction = "send", incoming.name
                    actual_write_return = native.writable_return(key.fileobj) if native is not None else writable_at
                    _dispatch(incoming, time.perf_counter_ns(), actual_write_return, ring, native)
    except Exception as failure:  # noqa: BLE001 - 不保存载荷、异常对象或异常原文。
        if operation == "due_first":
            event_direction = ring.active_direction
        error = type(failure).__name__
        failure_at = time.perf_counter_ns()
        error_errno, error_winerror = getattr(failure, "errno", None), getattr(failure, "winerror", None)
    finally:
        resources = [*([selector] if selector is not None else []), *sockets, *listeners]
        for connection in pending.values():
            resources.append(connection["front"])
            if connection["rear"] is not None:
                resources.append(connection["rear"])
        for resource in resources:
            try:
                resource.close()
            except Exception as failure:  # noqa: BLE001 - 继续关闭其余资源且不覆盖首错。
                cleanup_error = cleanup_error or type(failure).__name__
                if error is None:
                    error, operation, event_direction = type(failure).__name__, "cleanup", None
                    failure_at = time.perf_counter_ns()
                    error_errno, error_winerror = getattr(failure, "errno", None), getattr(failure, "winerror", None)
        # 退出窗不稀释完整超限窗；后续采样错误不得覆盖已经保留的首个运行错误。
        try:
            if policy.start_cpu is not None:
                policy.sample_cpu(final=True)
        except Exception as failure:  # noqa: BLE001 - 公开类别，保留既有首错。
            if not isinstance(failure, RelayCpuLimitError):
                policy.sample_error = type(failure).__name__
            if error is None:
                error, operation, event_direction = type(failure).__name__, "cpu_exit", None
                failure_at = time.perf_counter_ns()
        public = {d.name: {**d.stats, "queued_at_exit": d.queued, "read_eof": d.eof,
            "write_shutdown": d.shutdown} for d in directions}
        report = {"profile": profile, "seed": SEED, "pid": mp.current_process().pid,
            "ready": ready, "error_type": error, "directions": public,
            "cleanup_error_type": cleanup_error,
            "accepted_connections": len(accepted), "peak_sampled_rss_bytes": peak,
            "backend_connection_attempts": connection_attempts,
            "started_qpc_ns": started, "ended_qpc_ns": time.perf_counter_ns(),
            "gc_before": gc_before, "gc_after": {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                "freeze_count": gc.get_freeze_count(), "debug": gc.get_debug()},
            "queue_limit_per_direction": QUEUE_LIMIT, "combined_queue_limit": 6*QUEUE_LIMIT,
            "read_block_limit": READ_LIMIT, "model_tolerance_ns": MODEL_TOLERANCE_NS,
            "ring_fields": PublicRing.FIELDS, "ring": ring.rows(), "first_anomaly": ring.first_anomaly,
            "ring_version": 2, "missing_writable_return_ns": -1,
            "first_anomaly_timing_fields": PublicRing.TIMING_FIELDS,
            "first_anomaly_timing": ring.first_anomaly_timing,
            "wait_kinds": {"0": "none", "1": "selector", "2": "release_wait", "3": "stop_wait", "4": "bounded_poll"},
            "wait_policy": policy.report() if selector is not None else None,
            "ring_capacity": ring.CAPACITY, "ring_reserved_bytes": len(ring.data)*ring.data.itemsize,
            "ring_evicted": max(0, ring.seen-ring.CAPACITY), "encoded_limit": 64*1024,
            "first_failure": {"error_type": error, "qpc_ns": failure_at, "operation": operation,
                              "direction": event_direction, "errno": error_errno,
                              "winerror": error_winerror} if error is not None else None,
            "pending_heads": [[d.name, b.offset, len(b.data), b.cursor, b.arrival, b.tx, b.due,
                               b.first_attempt, b.blocked] for d in directions if d.queue for b in [d.queue[0]]],
            "encoded_omitted": 0, "encoded_bytes": 0,
            "scope": "opaque TCP read blocks; no packet/loss/WiFi model; readiness timestamp is userspace select return; sampled RSS"}
        if wait_strategy is not None:
            report["requested_wait_strategy"] = wait_strategy
        if native is not None:
            report.update(ring_version=3, scope="opaque TCP read blocks; native event notification and cached write state; sampled RSS",
                writable_state_scope="writable_return_ns=-1: no new FD_WRITE; positive short-write continuation measured from prior send completion")
            report["wait_kinds"].update({"5": "native_network", "6": "native_timer"})
        for _ in range(3):
            report["encoded_bytes"] = len(json.dumps(report, separators=(",", ":")).encode())
        report["model_valid"] = (error is None and set(public) == set(DIRECTIONS)
            and report["gc_before"] == report["gc_after"] == {"enabled": True, "threshold": [700, 10, 10],
                                                              "freeze_count": 0, "debug": 0}
            and all(r["received_bytes"] == r["sent_bytes"] and r["queued_at_exit"] == 0
                    and r["early_sends"] == r["unexplained_over_tolerance"] == 0
                    and r["queue_high_water"] <= QUEUE_LIMIT for r in public.values())
            and report["encoded_bytes"]+256 <= report["encoded_limit"])
        try:
            pipe.send(report)
        finally:
            pipe.close()


class NetworkRelay:
    """实验编排持有的单个转发进程；启动失败和强制退出均显式拒绝模型资格。"""

    def __init__(self, profile, endpoints, *, wait_strategy=None):
        if profile not in ("N1", "N2", "N3") or len(endpoints) != 3:
            raise ValueError("转发器仅支持三条固定本机实验链路。")
        for host, port, backend in endpoints:
            if host != "127.0.0.1" or backend != "127.0.0.2" or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("网络模型不能转发任意外部地址。")
        if len({v[1] for v in endpoints}) != 3:
            raise ValueError("三链路端口必须互异。")
        if wait_strategy is not None:
            from ._network_wait_win32 import STRATEGY
            if sys.platform != "win32" or wait_strategy != STRATEGY:
                raise ValueError("显式原生候选只允许固定Windows策略。")
        context = mp.get_context("spawn")
        self.stop = context.Event()
        self.reader, writer = context.Pipe(duplex=False)
        args = (profile, endpoints, self.stop, writer)
        self.process = context.Process(target=_relay_main, args=args+((wait_strategy,) if wait_strategy is not None else ()))
        self.writer = writer
        self.report = None
        self.closed = False

    def __enter__(self):
        try:
            self.process.start()
            self.writer.close()
            if not self.reader.poll(35):
                raise TimeoutError("网络转发器没有按期启动。")
            message = self.reader.recv()
            if message.get("ready") is not True or "directions" in message:
                self.report = message
                raise RuntimeError("网络转发器启动失败。")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        if self.process.pid is not None and self.report is None and self.reader.poll(10):
            try:
                self.report = self.reader.recv()
            except EOFError:
                self.report = None
        if self.process.pid is not None:
            self.process.join(5)
        forced = self.process.pid is not None and self.process.is_alive()
        if forced:
            self.process.terminate()
            self.process.join(5)
        self.reader.close()
        self.writer.close()
        self.report = self.report or {"model_valid": False, "error_type": "RelayReportMissing"}
        self.report.update(process_exited=not self.process.is_alive(), forced_termination=forced,
                           exitcode=self.process.exitcode)
        self.report["model_valid"] = bool(self.report["model_valid"] and not forced and self.process.exitcode == 0)
        for _ in range(3):
            self.report["encoded_bytes"] = len(json.dumps(self.report, separators=(",", ":")).encode())
        if self.report["encoded_bytes"] > 64*1024:
            self.report["model_valid"] = False
