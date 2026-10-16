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

    def __init__(self):
        self.data = array("q", [0]) * (self.CAPACITY * len(self.FIELDS))
        self.seen = 0
        self.first_anomaly = None

    def append(self, values):
        start = self.seen % self.CAPACITY * len(self.FIELDS)
        for index, value in enumerate(values):
            self.data[start + index] = value
        self.seen += 1
        if (values[10] > MODEL_TOLERANCE_NS or values[7] < values[6]) and self.first_anomaly is None:
            self.first_anomaly = tuple(values)

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


def _progress(direction, now, writable_at, ring):
    """就绪后推进一次短写；FIFO阻挡和已观察到的socket背压单列。"""
    block = direction.queue[0]
    if now < block.due:
        raise RuntimeError("禁止提前转发字节。")
    eligible = max(block.due, direction.previous_completed)
    first = block.first_attempt is None
    if first:
        block.first_attempt = now
    # 首次尝试必须及时；发生真实would-block后，另记录等待及返回就绪后的派发开销。
    residual = max(0, now - (eligible if first else writable_at))
    stats = direction.stats
    try:
        sent = direction.destination.send(memoryview(block.data)[block.cursor:])
    except BlockingIOError:
        observed = time.perf_counter_ns()
        residual = max(residual, observed-(eligible if first else writable_at))
        stats["max_unexplained_excess_ns"] = max(stats["max_unexplained_excess_ns"], residual)
        stats["unexplained_over_tolerance"] += residual > MODEL_TOLERANCE_NS
        stats["backpressure_count"] += 1
        block.blocked = True
        ring.append((DIRECTIONS.index(direction.name), block.offset, len(block.data), block.arrival, block.tx,
                     block.propagation, block.due, observed, 0, direction.queued, residual, 1,
                     block.first_attempt, writable_at, eligible))
        return
    if sent <= 0:
        raise ConnectionError("网络字节流写端已关闭。")
    completed = time.perf_counter_ns()
    residual = max(residual, completed-(eligible if first else writable_at))
    stats["max_unexplained_excess_ns"] = max(stats["max_unexplained_excess_ns"], residual)
    stats["unexplained_over_tolerance"] += residual > MODEL_TOLERANCE_NS
    short = sent < len(block.data) - block.cursor
    stats["short_writes"] += short
    block.blocked = block.blocked or short
    stats["sent_bytes"] += sent
    stats["max_release_excess_ns"] = max(stats["max_release_excess_ns"], completed-block.due)
    stats["early_sends"] += completed < block.due
    block.cursor += sent
    direction.queued -= sent
    ring.append((DIRECTIONS.index(direction.name), block.offset, len(block.data), block.arrival, block.tx,
                 block.propagation, block.due, completed, sent, direction.queued, residual, int(block.blocked),
                 block.first_attempt, writable_at, eligible))
    if block.cursor == len(block.data):
        stats["completed_chunks"] += 1
        stats["fifo_wait_ns"] += max(0, direction.previous_completed-block.due)
        stats["blocked_release_count"] += block.blocked
        direction.previous_completed = completed
        direction.queue.popleft()


def _relay_main(profile, endpoints, stop, pipe):
    """一个临时子进程、一个selector，三连接六方向；TLS在原角色内完成。"""
    from .communication_benchmark import _process_memory

    selector = selectors.DefaultSelector()
    listeners, sockets, directions, pending = [], [], [], {}
    ring, error, ready = PublicRing(), None, False
    failure_at, operation, event_direction, error_errno, error_winerror = None, "startup", None, None, None
    peak, next_memory, stopping_at = 0, 0, None
    accepted = set()
    connection_attempts = [0, 0, 0]
    gc_before = {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                 "freeze_count": gc.get_freeze_count(), "debug": gc.get_debug()}
    link_models = models(profile)
    started = time.perf_counter_ns()
    try:
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
            if now >= next_memory:
                memory = _process_memory()
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
            next_due = next_memory
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
                outgoing = next(d for d in directions if d.source is sock)
                incoming = next(d for d in directions if d.destination is sock)
                mask = (selectors.EVENT_READ if not outgoing.eof and outgoing.queued < QUEUE_LIMIT
                        and not stop.is_set() else 0)
                if incoming.queue:
                    due = incoming.queue[0].due
                    if due <= now:
                        mask |= selectors.EVENT_WRITE
                    else:
                        next_due = min(next_due, due)
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
                    if not mask:
                        selector.unregister(sock)
                    elif key.events != mask:
                        selector.modify(sock, mask, key.data)
            if len(directions) == 6 and not pending and all(d.eof and d.shutdown and not d.queue for d in directions):
                break
            wait = max(0., min(.1, (next_due-time.perf_counter_ns())/1e9))
            operation, event_direction = "select", None
            if sys.platform == "win32" and any(d.queue and d.queue[0].due > now for d in directions):
                # 正select timeout不能充当亚毫秒定时器；先处理即时就绪，无事件才阻塞让出CPU。
                # Python3.11在Windows以waitable timer执行正sleep；每次最多250us后重新核对QPC。
                selected = selector.select(0) if selector.get_map() else []
                if not selected:
                    remaining = (next_due-time.perf_counter_ns())/1e9
                    if remaining > 0:
                        operation = "release_wait"
                        time.sleep(min(remaining, .00025))
                    continue
            else:
                # Windows select不接受空集合；空闲或已到期但不可写时保留原阻塞等待。
                if not selector.get_map():
                    stop.wait(wait)
                    continue
                selected = selector.select(wait)
            writable_at = time.perf_counter_ns()
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
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data[0] == "connect":
                    operation, event_direction = "connect", None
                    _, index = key.data
                    connection = pending[index]
                    front, rear = connection["front"], connection["rear"]
                    result = rear.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
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
                        directions.append(Direction(source, destination, name, Schedule(link_models[name], name)))
                    continue
                _, outgoing, incoming = key.data
                if mask & selectors.EVENT_READ:
                    operation, event_direction = "recv", outgoing.name
                    _read(outgoing)
                if mask & selectors.EVENT_WRITE and incoming.queue:
                    operation, event_direction = "send", incoming.name
                    _progress(incoming, time.perf_counter_ns(), writable_at, ring)
    except Exception as failure:  # noqa: BLE001 - 不保存载荷、异常对象或异常原文。
        error = type(failure).__name__
        failure_at = time.perf_counter_ns()
        error_errno, error_winerror = getattr(failure, "errno", None), getattr(failure, "winerror", None)
    finally:
        selector.close()
        for sock in (*sockets, *listeners):
            sock.close()
        for connection in pending.values():
            connection["front"].close()
            if connection["rear"] is not None:
                connection["rear"].close()
        public = {d.name: {**d.stats, "queued_at_exit": d.queued, "read_eof": d.eof,
            "write_shutdown": d.shutdown} for d in directions}
        report = {"profile": profile, "seed": SEED, "pid": mp.current_process().pid,
            "ready": ready, "error_type": error, "directions": public,
            "accepted_connections": len(accepted), "peak_sampled_rss_bytes": peak,
            "backend_connection_attempts": connection_attempts,
            "started_qpc_ns": started, "ended_qpc_ns": time.perf_counter_ns(),
            "gc_before": gc_before, "gc_after": {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                "freeze_count": gc.get_freeze_count(), "debug": gc.get_debug()},
            "queue_limit_per_direction": QUEUE_LIMIT, "combined_queue_limit": 6*QUEUE_LIMIT,
            "read_block_limit": READ_LIMIT, "model_tolerance_ns": MODEL_TOLERANCE_NS,
            "ring_fields": PublicRing.FIELDS, "ring": ring.rows(), "first_anomaly": ring.first_anomaly,
            "ring_capacity": ring.CAPACITY, "ring_reserved_bytes": len(ring.data)*ring.data.itemsize,
            "ring_evicted": max(0, ring.seen-ring.CAPACITY), "encoded_limit": 64*1024,
            "first_failure": {"error_type": error, "qpc_ns": failure_at, "operation": operation,
                              "direction": event_direction, "errno": error_errno,
                              "winerror": error_winerror} if error is not None else None,
            "pending_heads": [[d.name, b.offset, len(b.data), b.cursor, b.arrival, b.tx, b.due,
                               b.first_attempt, b.blocked] for d in directions if d.queue for b in [d.queue[0]]],
            "encoded_omitted": 0, "encoded_bytes": 0,
            "scope": "opaque TCP read blocks; no packet/loss/WiFi model; readiness timestamp is userspace select return; sampled RSS"}
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

    def __init__(self, profile, endpoints):
        if profile not in ("N1", "N2", "N3") or len(endpoints) != 3:
            raise ValueError("转发器仅支持三条固定本机实验链路。")
        for host, port, backend in endpoints:
            if host != "127.0.0.1" or backend != "127.0.0.2" or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("网络模型不能转发任意外部地址。")
        if len({v[1] for v in endpoints}) != 3:
            raise ValueError("三链路端口必须互异。")
        context = mp.get_context("spawn")
        self.stop = context.Event()
        self.reader, writer = context.Pipe(duplex=False)
        self.process = context.Process(target=_relay_main, args=(profile, endpoints, self.stop, writer))
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
