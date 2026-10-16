"""S5 私有本地供料：一个 spawn 工人、两个单向 Pipe 和有界累计额度。"""

from __future__ import annotations

import gc
import hashlib
import multiprocessing as mp
import os
import secrets
import struct
import time
from collections import deque
from dataclasses import dataclass
from threading import Condition, Thread

from secure_control.crypto import BeaverMultiplier, SecureTruncation, TwoPartySharing
from secure_control.protocol.messages import public_step_plan_sha256
from secure_control.protocol.roles import Client, _create_resource_pair

from .localhost_codec import (
    _COMPACT_PROFILE,
    _canonical_json,
    _encode_online_fragment,
    _encode_preloaded_values,
    _load_json,
    _preloaded_values_size,
)

_SLOT_LIMIT = 512 * 1024
_RSS_LIMIT = 256 * 1024 * 1024
_HEADER_LIMIT = 4096


@dataclass(frozen=True, slots=True)
class _WorkerSpec:
    """仅公开生成资格；没有 Client、参数矩阵、测量、state 或控制连接。"""

    layout: object
    modulus: int
    ell: int
    security_parameter: int
    modulus_evidence: object
    horizon: int | None
    run_id: str
    session_id: str
    epoch: str
    start: int
    slots: int
    encoding_profile: str = "control-batch-v1"


def _check_spec(spec):
    if (not isinstance(spec, _WorkerSpec) or spec.encoding_profile not in {"control-batch-v1", _COMPACT_PROFILE}
            or type(spec.slots) is not int
            or not 1 <= spec.slots <= 16 or type(spec.start) is not int or spec.start < 0
            or any(type(v) is not str or not 1 <= len(v) <= 256
                   for v in (spec.run_id, spec.session_id, spec.epoch))):
        raise ValueError("本地供料规格无效")
    n, m, p = spec.layout.state_dimension, spec.layout.input_dimension, spec.layout.output_dimension
    products = n * n + n * m + p * n + p * m
    truncations = n if spec.layout.scale_ledger.state_truncation_bits else 0
    digits = spec.modulus.bit_length() * 30103 // 100000 + 1
    bound = products * (4096 + 12 * digits) + truncations * (4096 + 8 * digits) + 4096 + 512 * m
    if spec.encoding_profile == _COMPACT_PROFILE:
        row = (3 * products + 2 * truncations) * ((spec.modulus.bit_length() + 7) // 8)
        # 三份 IPC 临时包均计入原槽上限；生成资源前就排除最大合法头的最坏尺寸。
        bound = 3 * (2 * row + _HEADER_LIMIT + 5)
    else:
        bound *= 2
    if bound > _SLOT_LIMIT:
        raise ValueError("公开布局超过材料编码预留，不能先生成后拒绝")


def _memory():
    """本地工人 OS 内存采样；512 KiB 槽预留并非 RSS 上限。"""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD),
                        *((name, ctypes.c_size_t) for name in (
                            "peak", "current", "peak_paged", "paged", "peak_nonpaged",
                            "nonpaged", "pagefile", "peak_pagefile"))]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        api = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        api.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
        value = Counters()
        value.cb = ctypes.sizeof(value)
        if not api.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(value), value.cb):
            raise RuntimeError("工人内存读数不可用")
        return {"current_rss_bytes": value.current, "peak_rss_bytes": value.peak}
    import resource
    import sys
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {"current_rss_bytes": None, "peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024}


def _gc_snapshot():
    return {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()), "stats": gc.get_stats()}


def _package(spec, plan, fragments, prepared_ns, cpu_ns):
    header = {"version": 1, "run": spec.run_id, "session": spec.session_id, "epoch": spec.epoch,
              "step": plan.step, "round": plan.round_id, "plan": public_step_plan_sha256(plan),
              "recipients": [0, 1], "lengths": [len(v) for v in fragments],
              "sha256": [hashlib.sha256(v).hexdigest() for v in fragments],
              "prepared_ns": prepared_ns, "cpu_ns": cpu_ns, "encoding_profile": spec.encoding_profile}
    encoded = _canonical_json(header)
    package = b"M" + struct.pack(">I", len(encoded)) + encoded + b"".join(fragments)
    # 保守预留包含片段、编码包与 IPC 临时副本；已领取当前轮另报。
    if len(encoded) > _HEADER_LIMIT or 3 * len(package) > _SLOT_LIMIT:
        raise ValueError("材料包超出槽预留")
    return package


def _unpack(spec, packet, step):
    """只校验原专属通道包的公开结构；不在父进程恢复秘密 DTO 树。"""
    if type(packet) is not bytes or not 5 <= len(packet) <= _SLOT_LIMIT // 3 or packet[:1] != b"M":
        raise ValueError("材料包长度或类型无效")
    size = struct.unpack(">I", packet[1:5])[0]
    if not 1 <= size <= _HEADER_LIMIT or 5 + size > len(packet):
        raise ValueError("材料包头被截断或超限")
    head = _load_json(packet[5:5 + size])
    fields = {"version", "run", "session", "epoch", "step", "round", "plan", "recipients",
              "lengths", "sha256", "prepared_ns", "cpu_ns", "encoding_profile"}
    if (type(head) is not dict or set(head) != fields or type(head["version"]) is not int
            or head["version"] != 1 or head["encoding_profile"] != spec.encoding_profile
            or type(head["step"]) is not int or head["step"] != step
            or (head["run"], head["session"], head["epoch"]) != (spec.run_id, spec.session_id, spec.epoch)
            or head["recipients"] != [0, 1] or any(type(v) is not int for v in head["recipients"])
            or type(head["round"]) is not str or len(head["round"]) != 38
            or not head["round"].startswith("round-")
            or any(c not in "0123456789abcdef" for c in head["round"][6:])
            or any(type(head[v]) is not int or head[v] < 0 for v in ("prepared_ns", "cpu_ns"))
            or type(head["lengths"]) is not list or len(head["lengths"]) != 2
            or any(type(v) is not int or v < 1 for v in head["lengths"])
            or type(head["sha256"]) is not list or len(head["sha256"]) != 2
            or sum(head["lengths"]) + 5 + size != len(packet)):
        raise ValueError("材料包公开身份/尺寸/计数不匹配")
    plan = Client._resource_plan(spec.layout, spec.session_id, head["round"], step)
    if head["plan"] != public_step_plan_sha256(plan):
        raise ValueError("材料包与父进程公开计划摘要不匹配")
    if spec.encoding_profile == _COMPACT_PROFILE and head["lengths"] != [
        _preloaded_values_size(plan, spec.modulus)] * 2:
        raise ValueError("紧凑材料片段长度与公开计划不匹配")
    split = 5 + size + head["lengths"][0]
    fragments = (packet[5 + size:split], packet[split:])
    if any(hashlib.sha256(v).hexdigest() != digest for v, digest in zip(fragments, head["sha256"], strict=True)):
        raise ValueError("材料片段完整性不匹配")
    return plan, fragments, head


def _worker_main(spec, credit, output):
    """唯一生产者；只使用新的安全随机源，累计前缀不依赖材料总步数。"""
    report = {"pid": os.getpid(), "generated": 0, "error_type": None,
              "encoding_profile": spec.encoding_profile,
              "memory": deque(maxlen=32), "memory_guard_failed": False,
              "gc_begin": None, "gc_end": None, "process_cpu_ns": 0}
    cpu_started = time.process_time_ns()
    next_step, allowed, stop = spec.start, spec.start, False
    def command(packet):
        nonlocal allowed, stop
        if packet == b"S":
            stop = True
            return
        if len(packet) != 10 or packet[:1] != b"C" or packet[-1:] not in (b"0", b"1"):
            raise ValueError("额度包非法")
        prefix = struct.unpack(">Q", packet[1:9])[0]
        if prefix < allowed or prefix > next_step + spec.slots:
            raise ValueError("累计额度倒退或超过窗口")
        allowed = prefix
        if packet[-1:] == b"1" and report["gc_begin"] is None:
            report["gc_begin"] = _gc_snapshot()
    def sample(moment):
        value = {"moment": moment, "generated": report["generated"], **_memory()}
        report["memory"].append(value)
        if (value["current_rss_bytes"] or value["peak_rss_bytes"]) > _RSS_LIMIT:
            report["memory_guard_failed"] = True
            raise RuntimeError("工人内存保护触发")
    try:
        _check_spec(spec)
        sharing = TwoPartySharing(spec.modulus)
        multiplier = BeaverMultiplier(sharing)
        truncation = SecureTruncation(sharing, ell=spec.ell, security_parameter=spec.security_parameter,
                                     modulus_evidence=spec.modulus_evidence)
        sample("startup")
        while not stop:
            if next_step >= allowed:
                if credit.poll(.1):
                    command(credit.recv_bytes(10))
                continue
            while credit.poll(0):
                command(credit.recv_bytes(10))
            if stop:
                break
            if spec.horizon is not None and next_step >= spec.horizon:
                raise ValueError("工人越过已证明范围")
            started, cpu = time.perf_counter_ns(), time.process_time_ns()
            plan = Client._resource_plan(spec.layout, spec.session_id, "round-" + secrets.token_hex(16), next_step)
            resources = _create_resource_pair(plan, multiplier, truncation)
            encoder = _encode_preloaded_values if spec.encoding_profile == _COMPACT_PROFILE else _encode_online_fragment
            fragments = tuple(encoder(v, spec.modulus) for v in resources)
            packet = _package(spec, plan, fragments, time.perf_counter_ns() - started,
                              time.process_time_ns() - cpu)
            output.send_bytes(packet)
            del resources, fragments, packet, plan
            next_step += 1
            report["generated"] += 1
            if report["generated"] % 100 == 0:
                sample("generation")
    except Exception as error:  # noqa: BLE001 - 不输出材料或异常文本
        report["error_type"] = type(error).__name__
    finally:
        report["gc_end"] = _gc_snapshot() if report["gc_begin"] is not None else None
        report["process_cpu_ns"] = time.process_time_ns() - cpu_started
        try:
            sample("stop")
        except (OSError, ValueError, RuntimeError) as error:
            report["error_type"] = report["error_type"] or type(error).__name__
        report["memory"] = list(report["memory"])
        try:
            encoded = _canonical_json(report)
            if len(encoded) > 16 * 1024:
                raise RuntimeError("工人公开汇总超限")
            output.send_bytes(b"R" + encoded)
        except (OSError, ValueError, RuntimeError) as error:
            report["error_type"] = type(error).__name__  # 父进程将缺最终汇总视为清理失败。
        credit.close()
        output.close()


class _MaterialWorkerPool:
    """父进程专属接收器/额度线程；控制线程只领取，不触碰 Pipe。"""

    def __init__(self, client, distribution, *, run_id, epoch, start=0, slots=16,
                 encoding_profile="control-batch-v1"):
        self.owner = client._material_owner(distribution)
        self.spec = _WorkerSpec(self.owner.layout, client.fixed_point.modulus,
            client.fixed_point.fractional_bits, client.truncation.security_parameter,
            client.truncation.modulus_evidence, self.owner.horizon,
            run_id, distribution.session_id, epoch, start, slots, encoding_profile)
        _check_spec(self.spec)
        self._condition, self._queue = Condition(), deque()
        self._stop = self._closed = self._begin = False
        self._error = None
        self._claimed = 0
        self._received = self._next = start
        self._allowed = start + slots
        self._report = None
        self._current = None
        self._stats = {"material_mode": "local-worker-v1", "material_slots": 0,
            "encoding_profile": encoding_profile,
            "material_high_water": 0, "inventory_inflight_high_water": slots,
            "material_reserved_bytes": slots * _SLOT_LIMIT, "material_encoded_bound_high_water": 0,
            "material_prepare_ns": 0, "material_cpu_ns": 0, "ipc_bytes": 0,
            "current_round_bytes_high_water": 0, "ipc_temporary_bytes_high_water": 0,
            "credits_sent": 0, "cleanup_failed": False, "worker_exited": False,
            "receiver_exited": False, "credit_thread_exited": False}
        self._source = object()
        self.owner.open_encoded_source(self._source, encoding_profile=encoding_profile)
        context = mp.get_context("spawn")
        worker_credit, self._credit = context.Pipe(duplex=False)
        self._output, worker_output = context.Pipe(duplex=False)
        self._process = context.Process(target=_worker_main, args=(self.spec, worker_credit, worker_output),
                                        name="local-material-worker")
        self._receiver = Thread(target=self._receive, name="material-receiver")
        self._notifier = Thread(target=self._notify, name="material-credit")
        started = time.perf_counter_ns()
        try:
            self._process.start()
            worker_credit.close()
            worker_output.close()
            self._receiver.start()
            self._notifier.start()
            with self._condition:
                ready = self._condition.wait_for(lambda: len(self._queue) == slots or self._error, timeout=30)
                if not ready or self._error:
                    raise RuntimeError("本地材料工人初填失败")
            self._stats["startup_duration_ns"] = time.perf_counter_ns() - started
        except Exception as error:
            worker_credit.close()
            worker_output.close()
            self.close()
            self._stats["startup_duration_ns"] = time.perf_counter_ns() - started
            error._public_material_summary = self.snapshot()
            raise

    def _fail(self, error):
        with self._condition:
            if self._error is None:
                self._error = type(error).__name__
            self._condition.notify_all()

    def _receive(self):
        try:
            while True:
                packet = self._output.recv_bytes(_SLOT_LIMIT // 3)
                if packet[:1] == b"R":
                    if len(packet) > 16 * 1024 + 1:
                        raise ValueError("工人汇总超限")
                    report = _load_json(packet[1:])
                    with self._condition:
                        self._report = report
                        if not self._stop or report.get("error_type") is not None:
                            raise RuntimeError("工人提前终止")
                    return
                plan, fragments, header = _unpack(self.spec, packet, self._received)
                with self._condition:
                    stats = self._stats
                    stats["ipc_bytes"] += len(packet)
                    stats["material_prepare_ns"] += header["prepared_ns"]
                    stats["material_cpu_ns"] += header["cpu_ns"]
                    stats["ipc_temporary_bytes_high_water"] = max(stats["ipc_temporary_bytes_high_water"],
                                                                 3 * len(packet))
                    if self._stop:
                        self._received += 1
                        continue
                    if self._received >= self._allowed or len(self._queue) >= self.spec.slots:
                        raise ValueError("材料超出已授累计额度")
                    capability = self.owner.register_encoded(self._source, plan, fragments,
                        encoding_profile=self.spec.encoding_profile)
                    self._queue.append((capability, len(packet)))
                    self._received += 1
                    stats["material_high_water"] = max(stats["material_high_water"], len(self._queue))
                    stats["material_encoded_bound_high_water"] = max(stats["material_encoded_bound_high_water"],
                                                                    2 * sum(v[1] for v in self._queue))
                    self._condition.notify_all()
        except Exception as error:  # noqa: BLE001 - 通道失败只公开类别
            self._fail(error)

    def _notify(self):
        last, sent_begin = None, False
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: self._stop or self._allowed != last or self._begin != sent_begin)  # noqa: B023 - 同步读取本线程状态
                    if self._stop:
                        packet = b"S"
                    else:
                        last, sent_begin = self._allowed, self._begin
                        packet = b"C" + struct.pack(">Q", last) + (b"1" if sent_begin else b"0")
                self._credit.send_bytes(packet)
                with self._condition:
                    self._stats["credits_sent"] += 1
                    if self._stop and packet == b"S":
                        return
        except Exception as error:  # noqa: BLE001 - 不公开异常文本
            self._fail(error)

    def control_begin(self):
        with self._condition:
            self._begin = True
            self._condition.notify_all()

    def take(self, step):
        """领取当前原始能力后释放一份额度；库存短缺立刻失败。"""
        with self._condition:
            if self._stop or self._error or not self._process.is_alive() or not self._queue:
                raise RuntimeError("本地材料工人失败或库存短缺")
            if type(step) is not int or step != self._next:
                raise ValueError("工人材料领取步号不匹配")
            if self._current is not None and self.owner.encoded_pending(self._current):
                raise RuntimeError("上一材料能力尚未绑定")
            capability, size = self._queue.popleft()
            self._current = capability
            self._next += 1
            self._claimed += 1
            self._allowed += 1
            self._stats["current_round_bytes_high_water"] = max(self._stats["current_round_bytes_high_water"], size)
            self._condition.notify_all()
            return capability

    def snapshot(self):
        with self._condition:
            return {**self._stats, "material_slots": len(self._queue), "generated_received": self._received - self.spec.start,
                    "claimed": self._claimed, "inventory_inflight": 0 if self._closed else self._allowed - self._next,
                    "inventory_inflight_scope": "unclaimed authorized prefix bound including unused credits; closed=0",
                    "error_type": self._error, "worker": self._report}

    def observe_current_encoded(self, size):
        """当前轮的静态片段与两份完整信封字节合计，非 Python 对象/RSS。"""
        with self._condition:
            self._stats["current_round_bytes_high_water"] = max(self._stats["current_round_bytes_high_water"], size)

    def close(self):
        """最多五秒关闭工人和两线程；缺汇总或强制终止均不能通过资格。"""
        if self._closed:
            return
        self._closed = True
        with self._condition:
            self._stop = True
            self._stats["material_slots_before_close"] = len(self._queue)
            self._stats["cancelled_credit_slots"] = self._allowed - self._next
            self._condition.notify_all()
            while self._queue:
                self.owner.discard_encoded(self._queue.popleft()[0])
            if self._current is not None:
                self.owner.discard_encoded(self._current)
                self._current = None
        deadline = time.monotonic() + 5
        for item in (self._notifier, self._process, self._receiver):
            if getattr(item, "ident", None) is not None or getattr(item, "pid", None) is not None:
                item.join(timeout=max(0, deadline - time.monotonic()))
        if self._process.pid is not None and self._process.is_alive():
            self._stats["cleanup_failed"] = True
            self._process.terminate()
            self._process.join(timeout=1)
        self._credit.close()
        self._output.close()
        for item in (self._notifier, self._receiver):
            if item.ident is not None:
                item.join(timeout=.2)
        self._stats.update(worker_exited=not self._process.is_alive(),
                           receiver_exited=not self._receiver.is_alive(),
                           credit_thread_exited=not self._notifier.is_alive())
        if (not all(self._stats[v] for v in ("worker_exited", "receiver_exited", "credit_thread_exited"))
                or self._report is None or self._report.get("error_type") is not None
                or self._process.exitcode not in (None, 0)):
            self._stats["cleanup_failed"] = True
        # 清理事实由运行报告强制降为失败；不覆盖更早的周期失败和全部尝试。
