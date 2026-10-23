"""#116/#121 本机三进程公开观察；只保存身份、计数和本机时长。"""

from __future__ import annotations

import gc
import json
import multiprocessing as mp
import os
import platform
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import asdict, replace
from functools import cache
from hashlib import sha256
from itertools import count, pairwise
from math import isfinite
from pathlib import Path
from queue import Empty
from threading import active_count, current_thread, get_ident, get_native_id, local, main_thread
from typing import ClassVar
from unittest.mock import patch

import numpy as np

from secure_control.execution.lan_config import LanConfig, LanEndpoint, LanTopology, load_lan_config
from secure_control.execution.lan_runtime import LanContinuousRuntime, run_party_single_step
from secure_control.execution.lan_scalar_runtime import LanScalarRuntime
from secure_control.execution.localhost_codec import (
    _COMPACT_ADVANCE_PROFILES,
)

_ROOT = Path(__file__).resolve().parents[3]


class _HistoryTable:
    """S13私有固定行；0缺失/1None/2值，完整写入后才发布count。"""

    def __init__(self, capacity, schema):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("非法历史容量")
        self.capacity, self.count = capacity, 0
        self.fields, self.row_bytes = {}, 0
        for path, code in schema.items():
            width = code + 2 if type(code) is int else 8 if code in ("u", "d") else 0
            if not isinstance(path, tuple) or not path or (code != "m" and width < 1):
                raise ValueError("非法历史字段表")
            self.fields[path] = (code, self.row_bytes, width)
            self.row_bytes += width + 1
        self.buffer = bytearray(capacity * self.row_bytes)
        self.error_type = self.expansion_error_type = None
        self.expanded_count = None

    def _write(self, base, path, value):
        code, offset, _width = self.fields[path]
        offset += base
        if any(self.buffer[base+self.fields[path[:n]][1]] != 2 for n in range(1, len(path))):
            raise ValueError("历史父映射缺失")
        if self.buffer[offset] != 0:
            raise ValueError("重复历史字段")
        if value is None:
            self.buffer[offset] = 1
            return
        if code == "m":
            if type(value) is not dict:
                raise TypeError("历史映射类型")
            self.buffer[offset] = 2
            for name, child in value.items():
                self._write(base, (*path, name), child)
        elif code == "u":
            if type(value) is not int or not 0 <= value < 2**64:
                raise ValueError("历史整数范围")
            struct.pack_into(">Q", self.buffer, offset+1, value)
        elif code == "d":
            if type(value) is not float or not isfinite(value):
                raise ValueError("历史浮点类型或范围")
            struct.pack_into(">d", self.buffer, offset+1, value)
        else:
            if type(value) is not str:
                raise TypeError("历史字符串类型")
            encoded = value.encode("utf-8")
            if len(encoded) > code:
                raise ValueError("历史UTF8超长")
            struct.pack_into(">H", self.buffer, offset+1, len(encoded))
            self.buffer[offset+3:offset+3+len(encoded)] = encoded
        self.buffer[offset] = 2

    def append(self, values):
        try:
            if self.error_type is not None or self.count >= self.capacity:
                raise ValueError("历史容量或前次写入失败")
            base = self.count * self.row_bytes
            for path, value in values:
                self._write(base, (path,) if type(path) is str else path, value)
            self.count += 1
        except Exception as error:
            self.error_type = self.error_type or type(error).__name__
            raise RuntimeError("紧凑历史捕获失败") from error

    def expand(self):
        rows = []
        try:
            for index in range(self.count):
                row = {}
                for path, (code, offset, width) in self.fields.items():
                    offset += index * self.row_bytes
                    tag = self.buffer[offset]
                    if tag == 0:
                        continue
                    if tag not in (1, 2):
                        raise ValueError("历史标记损坏")
                    owner = row
                    for parent in path[:-1]:
                        owner = owner[parent]
                    if tag == 1:
                        value = None
                    elif code == "m":
                        value = {}
                    elif code in ("u", "d"):
                        value = struct.unpack_from(">Q" if code == "u" else ">d", self.buffer, offset+1)[0]
                    else:
                        size = struct.unpack_from(">H", self.buffer, offset+1)[0]
                        if size > code:
                            raise ValueError("历史UTF8长度损坏")
                        value = bytes(self.buffer[offset+3:offset+3+size]).decode("utf-8")
                    owner[path[-1]] = value
                rows.append(row)
        except Exception as error:  # noqa: BLE001 - 只保留完整展开前缀和公开错误类别
            self.expansion_error_type = type(error).__name__
        self.expanded_count = len(rows)
        return rows


class _CompactHistory:
    """仅有限实验历史；字段白名单/容量在端口与t0之前固定，不保存输入DTO。"""

    ACTIVITY = ("send_ms", "receive_ms", "encode_ms", "decode_ms", "recovery_ms",
                "local_arithmetic_ms", "peer_exchange_ms", "plan_digest_ms", "dto_validation_ms")
    PHASES = ("input", "material_bind", "material_prepare", "online_distribution", "stage", "reconstruct",
              "commit", "p1_commit_send", "p1_commit_ack_wait", "p1_commit_latency",
              "p2_commit_send", "p2_commit_ack_wait", "p2_commit_latency", "device", "recording",
              "maintenance", "maintenance_end", "maintenance_source", "maintenance_begin", "maintenance_release",
              "maintenance_seal", "p1_commit", "p2_commit")
    STORAGE = ("fsync_ms", "fsync_count", "checkpoint_ms", "source_check_ms", "source_check_control_ms",
               "source_check_writer_ms", "source_check_control_count", "source_check_writer_count")
    QUEUE = ("material_slots", "material_high_water", "inventory_inflight_high_water", "material_reserved_bytes",
             "material_encoded_bound_high_water", "material_prepare_ns", "material_cpu_ns", "ipc_bytes",
             "current_round_bytes_high_water", "ipc_temporary_bytes_high_water", "credits_sent", "startup_duration_ns",
             "material_slots_before_close", "cancelled_credit_slots", "generated_received", "claimed", "inventory_inflight")
    DIRECTIONS = ("Client->P1", "Client->P2", "P1->Client", "P1->P2", "P2->Client", "P2->P1")

    @classmethod
    def schemas(cls, role, steps, *, qualification=False, wire_profile=None):
        if wire_profile not in (None, *_COMPACT_ADVANCE_PROFILES):
            raise ValueError("非法维护历史版本")
        phases = (*cls.PHASES, "maintenance_advance") if wire_profile else cls.PHASES
        if (role not in ("Client", "P1", "P2") or type(steps) is not int or type(qualification) is not bool
                or not (steps == 10000 if qualification else 1 <= steps <= 4000)):
            raise ValueError("非法紧凑历史范围")
        def mapping(schema, name, children):
            schema[(name,)] = "m"
            schema.update({(name, k): code for k, code in children})
        row = {("global_step" if role == "Client" else "step",): "u", ("round_id",): 128}
        activity_name = "activity" if role == "Client" else "activity_ms"
        if role == "Client":
            row.update({("segment_index",): "u", ("session_id",): 128, ("status",): 64,
                        ("duration_ms",): "d", ("failure_phase",): 64, ("error_type",): 64})
            mapping(row, "components_ms", ((k+"_ms", "d") for k in phases))
            mapping(row, "storage", ((k, "u" if k.endswith("count") else "d") for k in cls.STORAGE))
        mapping(row, activity_name, ((k, "d") for k in cls.ACTIVITY))
        row[("sent",)] = "m"
        for direction in cls.DIRECTIONS:
            row[("sent", direction)] = "m"
            for name in ("frames", "application_bytes"):
                row[("sent", direction, name)] = "u"
        tables = {"steps": (steps+1, row)}
        if role == "Client":
            cycle = { (k,): 128 for k in ("run_id", "session_id", "controller_epoch", "round_id") }
            cycle.update({(k,): "u" for k in ("segment_index", "global_step", "period_ns", "scheduled_start_ns",
                "actual_sample_start_ns", "deadline_ns", "device_completed_ns", "bookkeeping_completed_ns",
                "cycle_completed_ns", "protocol_committed_count", "physically_confirmed_count", "durable_step_count",
                "format_version")})
            cycle.update({("status",): 64, ("failure_phase",): 64})
            mapping(cycle, "phase_durations_ns", ((k, "u") for k in phases))
            mapping(cycle, "queue_levels", ((k, "u") for k in cls.QUEUE))
            for name in ("public_frame_counts", "public_byte_counts"):
                mapping(cycle, name, ((k, "u") for k in cls.DIRECTIONS))
            tables.update(cycles=(steps+1, cycle), events=(16*steps+64,
                {("phase",): 32, ("duration_ms",): "d", ("attempt",): "u"}))
        return tables

    @classmethod
    def layout(cls, role, steps=4000, *, qualification=False, wire_profile=None):
        if type(qualification) is not bool or qualification and (steps != 10000 or role not in {"Client", "P1", "P2"}):
            raise ValueError("资格历史只支持固定10000及三个原角色。")
        tables = {}
        for name, (capacity, schema) in cls.schemas(role, steps, qualification=qualification,
                                                  wire_profile=wire_profile).items():
            row_bytes = sum(1 + (code+2 if type(code) is int else 8 if code in ("u", "d") else 0)
                            for code in schema.values())
            tables[name] = {"capacity": capacity, "row_bytes": row_bytes, "buffer_bytes": capacity*row_bytes,
                            "fields": [{"path": list(path), "code": code} for path, code in schema.items()]}
        # 固定白名单表/计数/线程登记/报告的保守上界；不随样本数增长，不是测得的RSS。
        buffer_bytes = sum(t["buffer_bytes"] for t in tables.values())
        reserved = buffer_bytes + 512*1024
        limit = (32 if qualification and role == "Client" else 16)*1024*1024
        if reserved > limit:
            raise ValueError("历史布局超出本profile角色上限")
        return {"role": role, "tables": tables, "buffer_bytes": buffer_bytes,
                "metadata_bound_bytes": 512*1024, "reserved_bound_bytes": reserved, "limit_bytes": limit}

    def __init__(self, role, steps=4000, *, qualification=False, wire_profile=None):
        if type(qualification) is not bool:
            raise ValueError("资格历史选择必须为bool。")
        self.role, self.target = role, steps
        self.wire_profile = wire_profile
        self.layout_info = self.layout(role, steps, qualification=qualification, wire_profile=wire_profile)
        self.tables = {k: _HistoryTable(n, schema) for k, (n, schema) in
                       self.schemas(role, steps, qualification=qualification, wire_profile=wire_profile).items()}
        self.threads, self.error_type = [], None
        self.tail_correction = None
        self.last_confirmed_step = self.last_confirmed_return_qpc_ns = self.normal_stop_start_qpc_ns = None
        self.expansion_ns, self.expansion_memory = None, None
        self.preallocated_memory = _process_memory()
        if self.preallocated_memory["current_rss_bytes"] > 256*1024*1024:
            raise RuntimeError("历史预分配RSS超限")
        self.register_thread("control", native=get_native_id(), ident=get_ident(), alive=True)

    def register_thread(self, role, *, native, ident, alive):
        if len(self.threads) >= 3 or any(row["thread_role"] == role for row in self.threads):
            raise RuntimeError("线程登记重复或超限")
        self.threads.append({"thread_role": role, "pid": os.getpid(), "native_id": native,
            "ident": ident, "registered_at_qpc_ns": time.perf_counter_ns(), "alive_at_registration": alive,
            "observation_end_qpc_ns": None, "alive_at_observation_end": None})

    def worker_threads(self, pool, *, ending=False):
        for name, thread in (("material-receiver", pool._receiver), ("material-credit", pool._notifier)):
            if ending:
                row = next((r for r in self.threads if r["thread_role"] == name), None)
                if row is not None and row["observation_end_qpc_ns"] is None:
                    row.update(observation_end_qpc_ns=time.perf_counter_ns(), alive_at_observation_end=thread.is_alive())
            else:
                self.register_thread(name, native=thread.native_id, ident=thread.ident, alive=thread.is_alive())

    @staticmethod
    def deltas(activity, before, counts, before_counts, *, activity_name):
        yield (activity_name,), {}
        for k, value in activity.items():
            yield (activity_name, k), value-before[k]
        yield ("sent",), {}
        for direction, fields in counts.items():
            yield ("sent", direction), {}
            for k, value in fields.items():
                yield ("sent", direction, k), value-before_counts.get(direction, {}).get(k, 0)

    def event(self, phase, duration, attempt):
        self.tables["events"].append((("phase", phase), ("duration_ms", duration), ("attempt", attempt)))

    def step(self, record, *, duration, marks, activity, before_activity, counts, before_counts,
             storage, before_storage, failure_phase=None, error_type=None):
        def values():
            if record is None:
                yield "global_step", self.tables["steps"].count
                yield "status", "failed"
                yield "failure_phase", failure_phase
                yield "error_type", error_type
            else:
                for name in ("global_step", "segment_index", "session_id", "round_id"):
                    yield name, getattr(record.protocol, name)
                yield "status", "confirmed"
            yield "duration_ms", duration
            yield "components_ms", {}
            for k, value in marks.items():
                if k.endswith("_ms"):
                    yield ("components_ms", k), value
            yield from self.deltas(activity, before_activity, counts, before_counts, activity_name="activity")
            yield "storage", {}
            for k, value in storage.items():
                yield ("storage", k), None if k in ("fsync_ms", "fsync_count", "checkpoint_ms") else value-before_storage[k]
        self.tables["steps"].append(values())

    def party_step(self, request, activity, before, counts, before_counts):
        def values():
            yield "step", request.step
            yield "round_id", request.round_id
            yield from self.deltas(activity, before, counts, before_counts, activity_name="activity_ms")
        self.tables["steps"].append(values())

    def cycle(self, timing, counts, before_counts):
        def values():
            for name in timing.__dataclass_fields__:
                if name not in ("public_frame_counts", "public_byte_counts"):
                    yield name, getattr(timing, name)
            for name, field in (("public_frame_counts", "frames"), ("public_byte_counts", "application_bytes")):
                yield name, {}
                for direction, counters in counts.items():
                    yield (name, direction), counters[field]-before_counts.get(direction, {}).get(field, 0)
        self.tables["cycles"].append(values())

    def expand(self):
        started = time.perf_counter_ns()
        for row in self.threads:
            if row["thread_role"] == "control" and row["observation_end_qpc_ns"] is None:
                row.update(observation_end_qpc_ns=started, alive_at_observation_end=True)
        rows = {}
        for name, table in self.tables.items():
            try:
                rows[name] = table.expand()
            except Exception as error:  # noqa: BLE001 - 单表展开失败仍恢复其他完整表
                self.error_type = self.error_type or type(error).__name__
                rows[name] = []
        self.expansion_ns = time.perf_counter_ns()-started
        try:
            self.expansion_memory = _process_memory()
            if self.expansion_memory["current_rss_bytes"] > 256*1024*1024:
                self.error_type = "HistoryExpansionMemory"
        except Exception as error:  # noqa: BLE001 - 退出观察不能覆盖控制首错
            self.error_type = type(error).__name__
        return rows

    def report(self):
        tables = {name: {"captured": t.count, "expanded": t.expanded_count, "error_type": t.error_type,
                         "expansion_error_type": t.expansion_error_type} for name, t in self.tables.items()}
        return {"role": self.role, "format_version": 2 if self.wire_profile else 1,
            **({"wire_profile": self.wire_profile} if self.wire_profile else {}),
            "layout": self.layout_info, "tables": tables,
            "representation_complete": self.error_type is None and all(t.error_type is None
                and t.expansion_error_type is None and t.expanded_count == t.count for t in self.tables.values()),
            "error_type": self.error_type, "threads": self.threads, "preallocated_memory": self.preallocated_memory,
            "expansion_memory": self.expansion_memory, "expansion_ns": self.expansion_ns,
            "tail_correction": self.tail_correction,
            "control_observation": {"last_confirmed_step": self.last_confirmed_step,
                "last_confirmed_return_qpc_ns": self.last_confirmed_return_qpc_ns,
                "normal_stop_start_qpc_ns": self.normal_stop_start_qpc_ns}}


class _ServerGCObservation:
    """S11单方轻量gen2观察；不读对象/秘密身份，不安装逐帧或阶段探针。"""

    def __init__(self, role, *, wall=None):
        self.role, self.wall = role, wall or time.perf_counter_ns
        self.slots = [None] * 64
        self.count = self.evicted = self.unpaired = self.max_ns = self.total_ns = 0
        self.pending = self.startup = self.error_type = None
        self.collecting = self.startup_attempted = self.normal_stop_ack_sent = False
        self.memory = []
        self.gc_before = self.gc_after = None
        self.restored = False

    @staticmethod
    def state():
        return {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                "freeze_count": gc.get_freeze_count(), "debug": gc.get_debug(), "stats": gc.get_stats()}

    def _gc(self, phase, info):
        # 回调不能冒用上轮身份；启动主动清理单独计时，不计作运行期gen2覆盖。
        if self.collecting or info.get("generation") != 2:
            return
        try:
            stamp = self.wall()
            thread = get_native_id()
            if phase == "start":
                if self.pending is not None:
                    self.unpaired += 1
                self.pending = (stamp, thread)
            elif phase == "stop":
                if self.pending is None or self.pending[1] != thread:
                    self.unpaired += 1
                    return
                started, thread = self.pending
                self.pending = None
                elapsed = stamp-started
                if elapsed < 0:
                    raise ValueError("S11观察时钟逆序。")
                self.slots[self.count % 64] = (started, stamp, thread, 2,
                    info.get("collected"), info.get("uncollectable"))
                self.count += 1
                self.evicted = max(0, self.count-64)
                self.max_ns = max(self.max_ns, elapsed)
                self.total_ns += elapsed
        except Exception as error:  # noqa: BLE001 - GC不会传播回调错误；下次原回复前拒绝
            self.error_type = type(error).__name__

    def _memory(self, moment):
        value = _process_memory()
        self.memory.append({"moment": moment, **value})
        if value["current_rss_bytes"] > 256 * 1024 * 1024:
            raise RuntimeError("S11子角色离散RSS超出原256MiB保护。")

    @contextmanager
    def installed(self, *, server_startup=True):
        """服务器offline ACK前仅清理一次；False只观察Client，不干预原启动GC。"""
        from secure_control.execution import lan_runtime

        original = lan_runtime._party_reply
        self.gc_before = self.state()
        if (not gc.isenabled() or gc.get_threshold() != (700, 10, 10)
                or gc.get_freeze_count() or gc.get_debug() or gc.callbacks):
            raise ValueError("S11子角色必须使用原正常GC且没有外部callback。")
        self._memory("before_offline")
        def replied(sock, request, *args, **kwargs):
            if self.error_type is not None:
                raise RuntimeError("S11轻量观察失败。")
            if request.operation == "offline" and not self.startup_attempted:
                self.startup_attempted = True
                self.collecting = True
                self.startup = {"start_ns": self.wall(), "end_ns": None, "collected": None,
                    "completed": False, "error_type": None, "native_thread_id": get_native_id()}
                try:
                    self.startup["collected"] = gc.collect(2)
                    self.startup["end_ns"] = self.wall()
                    self._memory("after_startup_collect")
                    self.startup["completed"] = True
                except Exception as error:  # 原异常直接传播，不伪造offline ACK
                    self.startup["error_type"] = type(error).__name__
                    raise
                finally:
                    self.collecting = False
            value = original(sock, request, *args, **kwargs)
            if request.operation == "segment_end" and getattr(request.payload, "action", None) == "stop":
                self.normal_stop_ack_sent = True
            return value
        gc.callbacks.append(self._gc)
        try:
            with (patch.object(lan_runtime, "_party_reply", replied) if server_startup else nullcontext()):
                yield self
        finally:
            if self._gc in gc.callbacks:
                gc.callbacks.remove(self._gc)
            self.restored = self._gc not in gc.callbacks and lan_runtime._party_reply is original
            try:
                self.gc_after = self.state()
                self._memory("exit")
            except Exception as error:  # noqa: BLE001 - 清理观察附加错误，不覆盖原首错
                self.error_type = self.error_type or type(error).__name__

    def report(self):
        """仅退出时编码；环淘汰/未配对/编码省略与未知身份如实保留。"""
        events = [slot for slot in self.slots if slot is not None]
        events.sort(key=lambda slot: slot[0])
        result = {"format_version": 1, "role": self.role, "profile": "server-gen2-light-v1",
            "fields": ["start_ns", "end_ns", "native_thread_id", "generation", "collected", "uncollectable"],
            "events": events, "pending": self.pending, "completed_count": self.count,
            "evicted_count": self.evicted, "unpaired_count": self.unpaired, "max_interval_ns": self.max_ns,
            "total_interval_ns": self.total_ns, "startup_collect": self.startup,
            "startup_attempted": self.startup_attempted, "normal_stop_ack_sent": self.normal_stop_ack_sent,
            "gc_before": self.gc_before, "gc_after": self.gc_after, "memory": self.memory,
            "callback_and_hook_restored": self.restored, "error_type": self.error_type,
            "scope": "public gen2 QPC intervals; round/step unknown; excludes explicit startup collect; no CPU/kernel attribution",
            "event_limit": 64, "pending_limit": 1, "encoded_limit": 32 * 1024,
            "encoded_omitted": 0, "budget_failed": False, "encoded_bytes": 0}
        def size():
            for _ in range(3):
                result["encoded_bytes"] = len(json.dumps(result, separators=(",", ":"), allow_nan=False).encode())
        size()
        while result["encoded_bytes"] > result["encoded_limit"] and result["events"]:
            result["budget_failed"] = True
            result["encoded_omitted"] += 1
            result["events"].pop(0)
            size()
        if result["encoded_bytes"] > result["encoded_limit"]:
            result["budget_failed"] = True
        return result


class _Diagnostic:
    """基准专用有界观测；嵌套/重复阶段不可相加成独占成本。"""

    LIMIT = 512

    def __init__(self, role, *, wall=None, cpu=None, limit=LIMIT, supply=False, all_gc=False):
        self.role = role
        self.wall = wall or time.perf_counter_ns
        self.cpu = cpu or getattr(time, "thread_time_ns", None)
        self.slots = [None] * limit
        self.overflow = 0
        self.free = iter(range(limit))
        self.dropped = count(1)
        self.keys = {}
        self.state = local()
        self.cpu_errors = 0
        self.gc_before = None
        self.supply = supply
        self.all_gc = all_gc
        self.control = (None, False)
        self.gc_pending = None
        samples = []
        for _ in range(16):
            started = self.wall()
            self._cpu()
            self._cpu()
            samples.append(self.wall() - started)
        self.clock_probe = {"pairs": 16, "min_ns": min(samples), "max_ns": max(samples),
                            "mean_ns": sum(samples) / len(samples),
                            "scope": "startup clock reads only; observer/GC allocations are additional"}

    def reserve(self):
        # next在本CPython里原子领取唯一槽位；callback不拿会重入死锁的锁。
        try:
            return next(self.free)
        except StopIteration:
            self.overflow = next(self.dropped)
            return None

    def _cpu(self):
        if self.cpu is None:
            return None
        try:
            return self.cpu()
        except (OSError, NotImplementedError):
            self.cpu_errors += 1
            return None

    def select(self, step):
        self.state.step = step
        if self.supply:
            self.control = (step, True if self.role == "Client" else None)

    def finish_control(self):
        self.control = (self.control[0], False if self.role == "Client" else None)

    def _selected_step(self, step):
        if self.supply:
            return type(step) is int and (0 <= step <= 1 or 165 <= step <= 168 or 176 <= step <= 180)
        return type(step) is int and (0 <= step <= 1 or 397 <= step <= 405)

    def _label(self):
        """诊断标签不参与供料/调度；未来材料步号与控制回调标签分开。"""
        owner = getattr(self.state, "owner", None) or (self.role + " control" if self.role == "Client" else self.role)
        step, active = self.control
        return owner, step, active, getattr(self.state, "prepared_step", None)

    def selected(self):
        step = self.control[0] if self.supply else getattr(self.state, "step", None)
        return self._selected_step(step)

    def begin(self, phase):
        if not self.selected():
            return None
        previous = getattr(self.state, "phase", None)
        self.state.phase = phase
        token = (get_ident(), get_native_id(), getattr(self.state, "step", None), phase, previous,
                 self.wall(), self._cpu())
        return token + self._label() if self.supply else token

    def end(self, token, *, status="complete", direction=None, public_bytes=None):
        if token is None:
            return
        ended, cpu = self.wall(), self._cpu()
        thread, native, step, phase, previous, started, initial_cpu = token[:7]
        if thread != get_ident():
            raise RuntimeError("CPU时钟区间必须在同一线程结束。")
        self.state.phase = previous
        if self.supply:
            index = self.reserve()
            if index is not None:
                owner, control_step, active, prepared_step = token[7:]
                self.slots[index] = ("interval", owner, native, control_step, active, prepared_step,
                                     phase, started, ended,
                                     None if cpu is None or initial_cpu is None else cpu - initial_cpu,
                                     *self.control, status, direction, public_bytes)
            return
        owner = "writer" if current_thread().name == "segment-evidence-writer" else self.role
        key = (owner, thread, step, phase)
        index = self.keys.get(key)
        if index is None:
            index = self.reserve()
            if index is None:
                return
            self.keys[key] = index
            self.slots[index] = {"kind": "phase", "owner": owner, "thread_id": thread,
                                 "native_thread_id": native, "global_step": step,
                                 "phase": phase, "first_start_ns": started,
                                 "last_end_ns": ended, "wall_ns": 0, "cpu_ns": 0,
                                 "calls": 0, "cpu_missing_calls": 0}
        value = self.slots[index]
        value["last_end_ns"] = max(value["last_end_ns"], ended)
        value["wall_ns"] += ended - started
        value["calls"] += 1
        if cpu is None or initial_cpu is None:
            value["cpu_missing_calls"] += 1
        else:
            value["cpu_ns"] += cpu - initial_cpu

    @contextmanager
    def scope(self, phase):
        token = self.begin(phase)
        status = "complete"
        try:
            yield
        except BaseException as error:
            status = type(error).__name__
            raise
        finally:
            self.end(token, status=status)

    def wrap(self, phase, original):
        # S0保留关键区间，避免无关嵌套事件挤掉末轮任务/GC；原meter仍完整累计。
        if (self.supply and not getattr(self, "wait_profile", False)
                and phase not in {"encode_ms", "material_restore", "party_stage"}):
            return original
        def measured(*args, **kwargs):
            if not self.selected():
                return original(*args, **kwargs)
            with self.scope(phase):
                return original(*args, **kwargs)
        return measured

    def _gc(self, phase, info):
        # callback只存定长公共tuple；不查看对象、不调用JSON/I/O或主动GC。
        if self.supply:
            self._supply_gc(phase, info.get("generation"), info.get("collected"), info.get("uncollectable"))
            return
        if not self.selected():
            return
        index = self.reserve()
        if index is None:
            return
        self.slots[index] = ("gc", phase, info.get("generation"), self.wall(),
                                 self._cpu(), get_ident(), get_native_id(),
                                 self.state.step, getattr(self.state, "phase", None))

    def _supply_gc(self, phase, generation, collected=None, uncollectable=None):
        thread = get_ident()
        stamp = ("gc_interval", *self._label(), get_native_id(), thread, generation,
                 getattr(self.state, "phase", None), self.wall(), self._cpu(),
                 collected if phase == "stop" else None, uncollectable if phase == "stop" else None)
        if phase == "start":
            self.gc_pending = stamp
            return
        if phase != "stop":
            return
        initial, self.gc_pending = self.gc_pending, None
        paired = initial is not None and initial[6:8] == stamp[6:8]
        if initial is not None and not paired and (self.all_gc or self._selected_step(initial[2])):
            index = self.reserve()
            if index is not None:
                self.slots[index] = (initial, None, "missing_stop")
        if self.all_gc or self._selected_step(stamp[2]) or (paired and self._selected_step(initial[2])):
            index = self.reserve()
            if index is not None:
                self.slots[index] = (initial if paired else None, stamp,
                                     "complete" if paired else "missing_start")

    def _supply_event(self, slot):
        """停止后才展开固定tuple；不把嵌套区间或非CPU差值作为唯一归因。"""
        if slot[0] == "interval":
            (_, owner, native, step, active, prepared, phase, started, ended,
             cpu, end_step, end_active, status, direction, size) = slot
            value = {"kind": "interval", "owner": owner, "native_thread_id": native,
                     "control_global_step": step, "control_active": active,
                     "prepared_step": prepared, "phase": phase, "start_ns": started,
                     "end_ns": ended, "cpu_delta_ns": cpu, "status": status,
                     "control_global_step_end": end_step, "control_active_end": end_active}
            if direction is not None:
                value.update(direction=direction, public_bytes=size)
            return value
        initial, final, pairing = slot
        item = initial if initial is not None else final
        return {"kind": "gc_interval", "owner": item[1], "control_global_step": item[2],
                "control_active": item[3], "prepared_step": item[4], "native_thread_id": item[5],
                "generation": item[7], "active_phase": item[8], "pairing": pairing,
                "start_ns": None if initial is None else initial[9],
                "end_ns": None if final is None else final[9],
                "collected": None if final is None else final[11],
                "uncollectable": None if final is None else final[12],
                "cpu_delta_ns": (None if initial is None or final is None
                                 or initial[10] is None or final[10] is None else final[10] - initial[10]),
                "control_global_step_end": None if final is None else final[2],
                "control_active_end": None if final is None else final[3]}

    @contextmanager
    def installed(self):
        self.gc_before = {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold())}
        gc.callbacks.append(self._gc)
        try:
            yield self
        finally:
            gc.callbacks.remove(self._gc)

    def report(self):
        # count的归约参数是下一个整数；只读快照，不因多次report改变overflow。
        overflow = self.dropped.__reduce__()[1][0] - 1
        events = []
        for slot in self.slots:
            if slot is None:
                continue
            if self.supply:
                events.append(self._supply_event(slot))
            elif isinstance(slot, tuple):
                _, phase, generation, wall, cpu, thread, native, step, active = slot
                events.append({"kind": "gc", "phase": phase, "generation": generation,
                               "wall_ns": wall, "cpu_ns": cpu, "thread_id": thread,
                               "native_thread_id": native, "global_step": step,
                               "active_phase": active})
            else:
                value = dict(slot)
                if value["cpu_missing_calls"]:
                    value["cpu_ns"] = None
                value["non_cpu_ns"] = (None if value["cpu_ns"] is None else
                                       value["wall_ns"] - value["cpu_ns"])
                events.append(value)
        if self.supply and self.gc_pending is not None and (self.all_gc or self._selected_step(self.gc_pending[2])):
            if len(events) < len(self.slots):
                events.append(self._supply_event((self.gc_pending, None, "missing_stop")))
            else:
                overflow += 1
        clocks = {}
        for name in ("perf_counter", "thread_time"):
            try:
                value = time.get_clock_info(name)
                clocks[name] = {field: getattr(value, field) for field in
                                ("implementation", "monotonic", "adjustable", "resolution")}
            except ValueError:
                clocks[name] = None
        # 三角色总编码上界；退出后才计算长度，超过的尾事件显式计数。
        if self.supply:
            # 仅停止后按保留优先级稳定排序：预算紧张时先省嵌套细项，保护失败轮。
            priority = {"control_cycle": 0, "material_produce": 0, "send_ms": 0,
                        "encode_ms": 1, "material_create": 2, "party_stage": 3,
                        "material_restore": 4, "receive_request": 5}
            events.sort(key=lambda item: -1 if item["kind"] == "gc_interval"
                        else priority.get(item["phase"], 6))
        bounded, encoded, omitted = [], 0, 0
        for event in events:
            size = len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode()) + 1
            if encoded + size > 72 * 1024:
                omitted += 1
            else:
                bounded.append(event)
                encoded += size
        return {"role": self.role, "events": bounded, "event_limit": len(self.slots),
                "encoded_events_limit": 72 * 1024, "encoded_overflow": omitted,
                "overflow": overflow, "cpu_errors": self.cpu_errors,
                "cpu_function_available": self.cpu is not None,
                "cpu_supported": self.cpu is not None and self.cpu_errors == 0, "clocks": clocks,
                "clock_pair_probe": self.clock_probe,
                "gc_before": self.gc_before,
                "gc_after": {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold())},
                "callback_restored": self._gc not in gc.callbacks}


class _TimeoutDiagnostic(_Diagnostic):
    """S3共享304槽；首错锁存，普通滚动与编码省略分别公开。"""

    RINGS: ClassVar = {"socket": (0, 128), "frame": (128, 64), "gc": (192, 64),
             "producer": (256, 32), "critical": (288, 16)}
    CONTEXT = ("source", "sender", "recipient", "operation", "endpoint_operation",
               "session_id", "round_id", "step", "sequence")
    FIELDS = ("operation", "start_ns", "end_ns", "qpc_before_ns", "monotonic_ns", "qpc_after_ns",
              "deadline_domain", "deadline_s", "deadline_ns", "remaining_ns", "timeout_s", "actual_timeout_s",
              "requested_bytes", "confirmed_bytes_before", "returned_bytes", "error_type", "cause_type",
              "errno", "winerror", "timeout_origin", "native_progress_unknown", "native_thread_id",
              "direction", "frame_part", "context", "control_label", "cpu_delta_ns")

    ENTRY_FIELDS = ("operation", "peer", "direction", "frame_part", "entry_time_ns",
                    "clock_domain", "deadline_ns", "remaining_at_entry_ns", "requested_timeout_s",
                    "actual_timeout_s", "native_called", "requested_bytes", "confirmed_bytes_before",
                    "thread_id", "native_thread_id", "context", "control_label",
                    "qpc_before_ns", "monotonic_ns", "qpc_after_ns")

    def __init__(self, role, ports, *, wait_profile=False):
        super().__init__(role, limit=304, supply=True, all_gc=True)
        self.ports = ports
        self.tracing = False
        self.latched = False
        self.seen = dict.fromkeys(self.RINGS, 0)
        self.probes, self.contexts = {}, {}
        self.first_failure = self.outer_failure = None
        self.context_dropped = self.suppressed = 0
        self.time_fields_unavailable = 0
        self.trace_restored = False
        self.wait_profile = wait_profile
        self.first_failure_entry = None
        # S10从收第一帧前开始观察；服务器解码前的身份未知，不能沿用上轮。
        self.tracing = wait_profile

    def _label(self):
        if self.wait_profile and self.role != "Client" and getattr(self.state, "frame_unknown", True):
            return self.role, None, None, None
        return super()._label()

    def select(self, step):
        super().select(step)
        self.tracing = True

    def selected(self):
        return self.tracing and not self.latched

    def reserve(self, bucket=None):
        bucket = bucket or getattr(self.state, "bucket", "frame")
        if (not self.tracing and bucket != "critical"
                or self.latched and bucket not in {"critical", "gc", "producer"}):
            self.suppressed += 1
            return None
        start, size = self.RINGS[bucket]
        if bucket == "critical":
            start, size = start + 1, size - 1  # 第一槽专属首错，不被close覆盖。
        number = self.seen[bucket]
        self.seen[bucket] = number + 1
        return start + number % size

    def begin(self, phase):
        if (phase not in {"control_cycle", "material_produce", "party_stage", "receive_request"}
                and not (self.wait_profile and phase in {"encode_ms", "decode_ms", "material_restore",
                    "online_wait_P1", "online_wait_P2", "online_ack"})):
            return None
        return super().begin(phase)

    def end(self, token, **kwargs):
        previous = getattr(self.state, "bucket", "frame")
        self.state.bucket = ("producer" if token and token[3] == "material_produce"
                             else "critical" if self.latched else "frame")
        try:
            return super().end(token, **kwargs)
        finally:
            self.state.bucket = previous

    def _supply_gc(self, phase, generation, collected=None, uncollectable=None):
        if not self.tracing or self.latched and (phase == "start" or self.gc_pending is None):
            return
        previous = getattr(self.state, "bucket", "frame")
        self.state.bucket = "gc"
        try:
            super()._supply_gc(phase, generation, collected, uncollectable)
        finally:
            self.state.bucket = previous

    def put(self, bucket, values, *, entry=None):
        index = self.reserve(bucket)
        if index is not None:
            self.slots[index] = (("trace", bucket, values, entry) if entry is not None
                                 else ("trace", bucket, values))

    def failed(self, values):
        if self.first_failure is None:
            self.first_failure = values
            self.slots[288] = ("trace", "critical", values)
            self.latched = True

    @staticmethod
    def error_type(error):
        if error is None:
            return None
        name = type(error).__name__
        return name if name in {"TimeoutError", "OSError", "ValueError", "RuntimeError", "TypeError",
            "LocalhostTransportTimeout", "LocalhostTransportDisconnected", "LocalhostTransportError",
            "LocalhostCodecError", "ConnectionResetError", "BrokenPipeError", "ConnectionAbortedError",
            "BlockingIOError", "SSLWantReadError", "SSLWantWriteError", "SSLError", "SSLEOFError",
            "SSLZeroReturnError", "SSLCertVerificationError", "ConnectionError", "KeyboardInterrupt", "EOFError"} else "OtherException"

    def marker(self, operation):
        index = self.reserve("critical")
        if index is not None:
            self.slots[index] = ("marker", operation, self.wall(), get_native_id(), self._label())

    def remember(self, message):
        # 仅浅读固定公开identity/操作名；不保留信封、payload或异常对象。
        sender, recipient = getattr(message, "sender", None), getattr(message, "recipient", None)
        if sender not in {"Client", "P1", "P2"} or recipient not in {"Client", "P1", "P2"}:
            return
        key = (sender, recipient)
        if key not in self.contexts and len(self.contexts) >= 8:
            raise RuntimeError("S3公开上下文超过有界表。")
        values = []
        for name in self.CONTEXT[3:]:
            value = (getattr(getattr(message, "payload", None), "operation", None)
                     if name == "endpoint_operation" else getattr(message, name, None))
            if value is not None and not (type(value) is int and 0 <= value < 2**63
                    or type(value) is str and len(value) <= 128):
                value = None
                self.context_dropped += 1
            values.append(value)
        self.contexts[key] = ("public_envelope", sender, recipient, *values)

    def probe(self, sock):
        if sock not in self.probes:
            if len(self.probes) >= 4:
                raise RuntimeError("S3每角色socket探针超过4个。")
            try:
                local_port, remote_port = sock.getsockname()[1], sock.getpeername()[1]
            except OSError:
                local_port = remote_port = None  # 已关闭通道仍交给原canonical异常转换。
            if local_port is None:
                peer = "unknown"
            elif self.role == "Client":
                peer = "P1" if remote_port == self.ports[0] else "P2"
            elif self.role == "P1":
                peer = "Client" if local_port == self.ports[0] else "P2"
            else:
                peer = "Client" if local_port == self.ports[1] else "P1"
            self.probes[sock] = getattr(self, "SOCKET_TYPE", _TraceSocket)(sock, self, peer)
        return self.probes[sock]

    def values(self, probe, operation, started, ended, *, requested=None, returned=None,
               error=None, origin=None, timeout=None, cpu=None):
        deadline = probe.deadline
        domain = "qpc_cycle" if hasattr(deadline, "deadline_ns") else "legacy_monotonic"
        before = self.wall()
        monotonic = time.monotonic_ns()
        after = self.wall()
        deadline_ns = (deadline.deadline_ns if domain == "qpc_cycle" else round(deadline * 1e9))
        remaining = deadline_ns - (before if domain == "qpc_cycle" else monotonic)
        try:
            actual = probe.sock.gettimeout()
        except Exception:  # noqa: BLE001 - 额外查询失败不替换原socket调用/异常
            actual = None
            self.time_fields_unavailable += 1
        reported_timeout = probe.requested_timeout if timeout is None else timeout
        for value in (reported_timeout, actual):
            if value is not None and (type(value) not in (int, float) or not isfinite(value)):
                self.time_fields_unavailable += 1
        reported_timeout = (reported_timeout if reported_timeout is None or
                type(reported_timeout) in (int, float) and isfinite(reported_timeout) else None)
        actual = actual if actual is None or type(actual) in (int, float) and isfinite(actual) else None
        cause = getattr(error, "__cause__", None)
        errno, winerror = getattr(error, "errno", None), getattr(error, "winerror", None)
        return (operation, started, ended, before, monotonic, after, domain, float(deadline), deadline_ns, remaining,
                reported_timeout, actual, requested, probe.confirmed, returned,
                self.error_type(error), self.error_type(cause),
                errno if type(errno) is int and -2**31 <= errno < 2**31 else None,
                winerror if type(winerror) is int and -2**31 <= winerror < 2**31 else None,
                origin, error is not None and operation in {"send", "recv"}, get_native_id(),
                probe.direction, probe.part, probe.context, self._label(), cpu)

    def entry(self, probe, operation, *, requested=None, native_called=False):
        """S10调用前固定公共快照；旧values仍是调用后的字段，不能改标。"""
        deadline = probe.deadline
        domain = "qpc_cycle" if hasattr(deadline, "deadline_ns") else "legacy_monotonic"
        try:
            actual = probe.sock.gettimeout()
        except Exception:  # noqa: BLE001 - 查询失败不改变原调用
            actual = None
            self.time_fields_unavailable += 1
        if actual is not None and (type(actual) not in (int, float) or not isfinite(actual)):
            actual = None
            self.time_fields_unavailable += 1
        requested_timeout = probe.requested_timeout if native_called else None
        if requested_timeout is not None and (type(requested_timeout) not in (int, float)
                                             or not isfinite(requested_timeout)):
            requested_timeout = None
            self.time_fields_unavailable += 1
        # 最后才读入口时钟；原生方法及canonical precheck仍使用原deadline/参数。
        qpc_before = self.wall()
        monotonic = time.monotonic_ns()
        qpc_after = self.wall()
        stamp = qpc_before if domain == "qpc_cycle" else monotonic
        deadline_ns = deadline.deadline_ns if domain == "qpc_cycle" else round(deadline * 1e9)
        value = (operation, probe.peer, probe.direction, probe.part, stamp, domain, deadline_ns,
                 deadline_ns-stamp, requested_timeout, actual, native_called, requested,
                 probe.confirmed, get_ident(), get_native_id(), probe.context, self._label(),
                 qpc_before, monotonic, qpc_after)
        probe.current_entry = value
        return value

    def frame(self, original, sock, value, deadline, *, sending):
        from secure_control.execution.cycle_timing import _CycleDeadline

        probe = self.probe(sock)
        probe.deadline, probe.confirmed, probe.native_error = deadline, 0, None
        probe.direction = f"{self.role}->{probe.peer}" if sending else f"{probe.peer}->{self.role}"
        metadata = self.contexts.get((self.role, probe.peer) if sending else (probe.peer, self.role))
        if not sending and self.role == "Client":
            metadata = self.contexts.get((self.role, probe.peer))
            metadata = ("expected_from_last_request", *metadata[1:]) if metadata else None
        elif not sending and metadata:
            metadata = ("last_received_envelope", *metadata[1:])
        if self.wait_profile and not sending and self.role != "Client":
            metadata = None  # 收帧前不知道当前帧，不能冒用最近解码的identity。
            self.state.frame_unknown = True
        probe.context = metadata
        # send_exact包含header+body；receive_exact分别读取header和body，不能拼造业务进度。
        probe.part = "header_and_body" if sending else "header" if probe.receive_header else "body"
        started, cpu = self.wall(), self._cpu()
        requested = len(value) if sending else value
        probe.frame_requested = requested
        if self.wait_profile and not sending and hasattr(deadline, "deadline_ns"):
            self.entry(probe, "timeout_precheck", requested=requested)
        previous_qpc_probe = getattr(self.state, "qpc_receive_probe", None)
        # 仅本线程当前canonical QPC接收可恢复瞬态；发送/旧float及其它通道不借用此状态。
        self.state.qpc_receive_probe = probe if not sending and isinstance(deadline, _CycleDeadline) else None
        try:
            result = original(probe, value, deadline)
        except BaseException as error:
            ended = self.wall()  # 清理前首个公开异常锚点。
            origin = probe.native_error or "unknown"
            if origin == "unknown" and type(error).__name__ == "LocalhostTransportTimeout":
                from secure_control.execution.cycle_timing import remaining_seconds
                if remaining_seconds(deadline) <= 0:
                    origin = "absolute_precheck"
            if self.wait_profile and self.first_failure_entry is None:
                self.first_failure_entry = probe.current_entry
            record = self.values(probe, "frame_send" if sending else "frame_recv", started, ended,
                                 requested=requested, error=error, origin=origin)
            self.failed(record)
            if self.outer_failure is None:
                self.outer_failure = record
            self.put("critical", record)
            raise
        else:
            ended, final_cpu = self.wall(), self._cpu()
            if not sending:
                probe.receive_header = not probe.receive_header
                if self.wait_profile and probe.receive_header:
                    self.marker("frame_body_received_identity_unknown")
            self.put("frame", self.values(probe, "frame_send" if sending else "frame_recv", started, ended,
                requested=requested, returned=probe.confirmed,
                cpu=None if cpu is None or final_cpu is None else final_cpu-cpu))
            return result
        finally:
            self.state.qpc_receive_probe = previous_qpc_probe

    @contextmanager
    def sockets(self):
        from secure_control.execution import lan_runtime, localhost_transport

        send, receive = localhost_transport._send_exact, localhost_transport._receive_exact
        encode, decode = localhost_transport.encode_envelope, localhost_transport.decode_envelope
        runtime_close = lan_runtime.LanSegmentedRuntime.close
        precheck = localhost_transport._set_remaining_timeout
        receive_reply = lan_runtime._receive_reply
        party_reply = lan_runtime._party_reply

        def encoded(message):
            self.remember(message)
            return encode(message)

        def decoded(payload):
            # 解码区间开始时身份未知；只在原解码成功后登记本帧公开身份。
            with self.scope("decode_ms") if self.wait_profile else nullcontext():
                message = decode(payload)
            self.remember(message)
            if self.wait_profile:
                self.state.frame_unknown = False
                if message.sender == "Client" and message.operation == "online":
                    self.select(message.step)
                    self.marker("online_decode_return")
            return message

        def checked(sock, deadline):
            if not isinstance(sock, _TraceSocket) or sock.diagnostic is not self:
                return precheck(sock, deadline)
            entry = self.entry(sock, "timeout_precheck", requested=sock.frame_requested-sock.confirmed)
            try:
                return precheck(sock, deadline)
            except BaseException:
                if self.first_failure_entry is None:
                    self.first_failure_entry = entry
                raise

        def waited(sock, request, **kwargs):
            if request.operation != "online":
                return receive_reply(sock, request, **kwargs)
            self.remember(request)
            with self.scope("online_wait_" + request.recipient):
                return receive_reply(sock, request, **kwargs)

        def replied(sock, request, *args, **kwargs):
            if request.operation != "online":
                return party_reply(sock, request, *args, **kwargs)
            with self.scope("online_ack"):
                return party_reply(sock, request, *args, **kwargs)

        def closed(runtime):
            self.marker("runtime_close_begin")
            try:
                return runtime_close(runtime)
            finally:
                self.marker("runtime_close_end")

        with (patch.object(localhost_transport, "_send_exact", lambda s, v, d: self.frame(send, s, v, d, sending=True)),
              patch.object(localhost_transport, "_receive_exact", lambda s, v, d: self.frame(receive, s, v, d, sending=False)),
              patch.object(localhost_transport, "encode_envelope", encoded),
              patch.object(localhost_transport, "decode_envelope", decoded),
              patch.object(lan_runtime.LanSegmentedRuntime, "close", closed),
              patch.object(localhost_transport, "_set_remaining_timeout", checked) if self.wait_profile else nullcontext(),
              patch.object(lan_runtime, "_receive_reply", waited) if self.wait_profile else nullcontext(),
              patch.object(lan_runtime, "_party_reply", replied) if self.wait_profile else nullcontext()):
            try:
                yield self
            finally:
                self.marker("probe_scope_exit")
                self.trace_restored = True

    def report(self):
        # 全部角色只在退出后编码；每个表schema只导出一次，首错/当前失败优先。
        records = []
        for index, slot in enumerate(self.slots):
            if slot is not None:
                record = ({"kind": slot[1], "values": slot[2]} if slot[0] == "trace" else
                          {"kind": "marker", "operation": slot[1], "start_ns": slot[2],
                           "end_ns": slot[2], "native_thread_id": slot[3], "control_label": slot[4]}
                          if slot[0] == "marker" else super()._supply_event(slot))
                record["critical"] = index >= 288
                if slot[0] == "trace" and len(slot) == 4:
                    record["entry"] = slot[3]
                records.append(record)
        if self.gc_pending is not None:
            records.append(super()._supply_event((self.gc_pending, None, "missing_stop")))
        records.sort(key=lambda r: (not r.get("critical", False), -(r["values"][2] if "values" in r
                        else r.get("end_ns") or r.get("start_ns") or 0)))
        result = {"role": self.role, "format_version": 1, "schemas": {"trace": self.FIELDS, "context": self.CONTEXT},
                  "events": [], "event_limit": 512, "ring_slots": 304, "active_pair_limit": 16,
                  "ring_capacities": {k: s for k, (_, s) in self.RINGS.items()},
                  "evicted_count": {k: max(0, self.seen[k] - (s-1 if k == "critical" else s))
                                    for k, (_, s) in self.RINGS.items()},
                  "oldest_retained_ns": min((r["values"][1] if "values" in r else
                       r.get("start_ns") or r.get("end_ns") for r in records), default=None),
                  "encoded_omitted": 0, "encoded_limit": 72 * 1024, "encoded_bytes": 0,
                  "first_failure": self.first_failure, "outer_failure": self.outer_failure,
                  "latched": self.latched, "suppressed_after_latch_or_startup": self.suppressed,
                  "context_dropped": self.context_dropped, "socket_count": len(self.probes),
                  "time_fields_unavailable": self.time_fields_unavailable,
                  "cpu_errors": self.cpu_errors, "clock_pair_probe": self.clock_probe,
                  "gc_before": self.gc_before,
                  "gc_after": {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold())},
                  "clocks": {name: {key: getattr(time.get_clock_info(name), key)
                      for key in ("implementation", "resolution", "monotonic", "adjustable")}
                      for name in ("monotonic", "perf_counter", "thread_time")},
                  "callback_restored": self._gc not in gc.callbacks, "socket_hooks_restored": self.trace_restored,
                  "scope": "rolling public Python call boundaries; clock pairs sampled after each call; timeout queried after call; native failed-call progress unknown; Python cannot see C/kernel retries"}
        if self.wait_profile:
            result.update(format_version=2, profile="worker-online-wait-v1",
                first_failure_entry=self.first_failure_entry,
                socket_current_entries=[p.current_entry for p in self.probes.values()],
                identity_before_server_decode="unknown; prior round never copied into current frame",
                scope="S10 entry sampled before original native/precheck; legacy trace values sampled after call; failure progress unknown; no kernel/GIL attribution")
            result["schemas"]["entry"] = self.ENTRY_FIELDS
        for record in records:
            result["events"].append(record)
            if len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode()) + 256 > 72 * 1024:
                result["events"].pop()
                result["encoded_omitted"] += 1
        result["oldest_retained_ns"] = min((r["values"][1] if "values" in r else
                       r.get("start_ns") or r.get("end_ns") for r in result["events"]), default=None)
        for _ in range(3):
            result["encoded_bytes"] = len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode())
        return result


class _TraceSocket:
    """同buffer/参数/返回/异常透传；不改cursor、blocking或重试。"""

    def __init__(self, sock, diagnostic, peer):
        self.sock, self.diagnostic, self.peer = sock, diagnostic, peer
        self.deadline = self.context = self.direction = self.part = self.native_error = None
        self.confirmed = 0
        self.requested_timeout = None
        self.receive_header = True
        self.current_entry = None
        self.frame_requested = 0

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def call(self, operation, *args, **kwargs):
        observer = self.diagnostic
        started, cpu = observer.wall(), observer._cpu()
        requested = len(args[0]) if operation == "send" else args[0] if operation == "recv" else None
        entry = (observer.entry(self, operation, requested=requested, native_called=True)
                 if observer.wait_profile and operation in {"send", "recv"} else None)
        try:
            result = getattr(self.sock, operation)(*args, **kwargs)
        except BaseException as error:
            ended = observer.wall()
            origin = "socket_send" if operation == "send" else "socket_recv" if operation == "recv" else "unknown"
            recoverable = ((operation == "recv" and getattr(observer.state, "qpc_receive_probe", None) is self
                            or operation in {"send", "recv"} and getattr(observer.state, "duplex_probe", None) is self)
                           and isinstance(error, (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError)))
            self.native_error = None if recoverable else origin
            record = observer.values(self, operation, started, ended, requested=requested,
                                     error=error, origin=origin,
                                     timeout=args[0] if operation == "settimeout" else None)
            observer.put("socket", record, entry=entry)
            if recoverable:
                self.current_entry = None  # 保留原生环事件，但不能把瞬态入口借作后续终止首错。
            else:
                if entry is not None and observer.first_failure_entry is None:
                    observer.first_failure_entry = entry
                observer.failed(record)
            raise
        else:
            ended, final_cpu = observer.wall(), observer._cpu()
            amount = result if operation == "send" else len(result) if operation == "recv" else None
            observer.put("socket", observer.values(self, operation, started, ended, requested=requested,
                returned=amount, timeout=args[0] if operation == "settimeout" else None,
                cpu=None if cpu is None or final_cpu is None else final_cpu-cpu), entry=entry)
            if amount is not None:
                self.confirmed += amount
            return result

    def settimeout(self, *args, **kwargs):
        self.requested_timeout = args[0] if args else kwargs.get("value")
        return self.call("settimeout", *args, **kwargs)

    def send(self, *args, **kwargs):
        return self.call("send", *args, **kwargs)

    def recv(self, *args, **kwargs):
        return self.call("recv", *args, **kwargs)


class _StageTraceSocket(_TraceSocket):
    """复用已审透明调用；最新native边界仅在本次framing在途期间有效。"""

    def call(self, operation, *args, **kwargs):
        previous_entry = self.current_entry
        mode_change = operation == "settimeout" and previous_entry is not None and previous_entry[6] is True
        if mode_change:
            self.current_entry = None  # 模式恢复首错不能借用之前的native recv入口。
        self.native_in_flight = operation in {"send", "recv"}
        try:
            value = super().call(operation, *args, **kwargs)
            if mode_change:
                self.current_entry = previous_entry
            if operation in {"send", "recv"}:
                self.last_returned = value if operation == "send" else len(value)
            return value
        finally:
            self.native_in_flight = False


class _StageWaitDiagnostic(_TimeoutDiagnostic):
    """S12只保留stage滚动区间和全I/O首错；不安装旧重诊断/CPU观察。"""

    SOCKET_TYPE = _StageTraceSocket
    FIELDS = ("kind", "operation", "start_qpc_ns", "end_qpc_ns", "thread_id", "native_thread_id",
              "peer", "direction", "frame_part", "context", "phase", "entry", "returned_bytes",
              "error_type", "cause_type", "errno", "winerror", "timeout_origin", "native_progress_unknown",
              "last_native_returned_bytes", "native_in_flight")
    ENTRY_FIELDS = ("entry_qpc_ns", "clock_domain", "deadline_ns", "remaining_at_entry_ns",
                    "requested_timeout_s", "observed_timeout_s", "native_called", "requested_bytes",
                    "confirmed_bytes_before", "monotonic_entry_ns", "thread_id", "native_thread_id")
    CONTEXT = (*_TimeoutDiagnostic.CONTEXT, "run_id", "controller_epoch", "segment_index", "global_step")
    QPC_FIELDS = ("operation", "start_qpc_ns", "end_qpc_ns", "peer", "frame_part", "context",
                  "deadline_ns", "remaining_before_ns", "requested_wait_ns", "ready_count",
                  "confirmed_bytes", "no_progress_count", "outcome", "error_type", "errno", "winerror")

    def __init__(self, role, ports, *, wall=None, gc_observer=None, qpc_receive_candidate=False,
                 all_qpc_receives=False):
        if (type(qpc_receive_candidate) is not bool or qpc_receive_candidate and role != "Client"
                or type(all_qpc_receives) is not bool or all_qpc_receives and not qpc_receive_candidate):
            raise ValueError("S15仅选择Client裸TCP接收。")
        # 不调用父类init：避免304槽、CPU和旧GC/阶段探针。
        self.role, self.ports, self.state = role, ports, local()
        self._wall = wall or time.perf_counter_ns
        self.slots, self.seen = [None] * 128, 0
        self.probes, self.contexts = {}, {}
        self.first_failure = self.first_failure_entry = self.outer_failure = None
        self.wait_profile, self.trace_restored = True, False
        self.observation_error_type = None
        self.context_dropped = self.time_fields_unavailable = 0
        self.close_begin_ns = self.close_end_ns = None
        self.gc_observer = gc_observer
        self.run_identity = [None, None, None]
        self.qpc_receive_candidate, self.qpc_receiving = qpc_receive_candidate, False
        self.all_qpc_receives = all_qpc_receives
        if qpc_receive_candidate:
            self.qpc_slots, self.qpc_seen = [None] * 16, 0
            self.qpc_first_anomaly = self.qpc_first_exception = self.qpc_restore_error_type = None
            self.qpc_calls = self.qpc_completed = self.qpc_empty = self.qpc_would_block = self.qpc_guards = 0

    def _qpc_note(self, probe, operation, started, *, remaining=None, wait=None, ready=None,
                  no_progress=0, outcome, error=None):
        # 只保存有界公开tuple；socket/bytes/异常对象不进入历史。
        row = (operation, started, self.wall(), probe.peer, probe.part, probe.context,
               probe.deadline.deadline_ns, remaining, wait, ready, probe.confirmed, no_progress,
               outcome, self.error_type(error), getattr(error, "errno", None), getattr(error, "winerror", None))
        self.qpc_slots[self.qpc_seen % 16] = row
        self.qpc_seen += 1
        if outcome != "ready" and self.qpc_first_anomaly is None:
            self.qpc_first_anomaly = row
        if error is not None and self.qpc_first_exception is None:
            self.qpc_first_exception = row

    def qpc_receive(self, original, probe, length, deadline):
        """实验只做选路/公开观察；唯一接收算法属于canonical transport。"""
        from secure_control.execution.cycle_timing import _CycleDeadline
        from secure_control.execution.localhost_transport import _receive_qpc_exact

        selected = self.all_qpc_receives or getattr(self.state, "phase", None) == "finish_stage_batch"
        if not self.qpc_receive_candidate or self.role != "Client" or not selected:
            return original(probe, length, deadline)
        if self.all_qpc_receives and not isinstance(deadline, _CycleDeadline):
            return original(probe, length, deadline)
        context, expected = getattr(probe, "context", None), getattr(self.state, "context", None)
        if (not isinstance(probe, _StageTraceSocket) or probe.diagnostic is not self or probe.peer not in {"P1", "P2"}
                or type(probe.sock) is not socket.socket or not isinstance(deadline, _CycleDeadline)
                or type(deadline.deadline_ns) is not int or deadline.deadline_ns < 0 or probe.deadline is not deadline
                or type(length) is not int or length <= 0 or context is None
                or not self.all_qpc_receives and (expected is None
                    or context[1:5] != ("Client", probe.peer, "endpoint", "stage_batch")
                    or context[5:8] != expected[5:8])):
            raise ValueError("实验接收作用域/身份/裸TCP/deadline不匹配。")
        if (probe.sock.getpeername()[:2] != ("127.0.0.1", self.ports[0 if probe.peer == "P1" else 1])
                or probe.sock.getsockname()[0] != "127.0.0.1"):
            raise ValueError("实验只观察当前本机P1/P2通道。")
        self.qpc_calls += 1
        previous = self.qpc_receiving
        self.qpc_receiving = True
        def observe(operation, started, **facts):
            outcome, error = facts["outcome"], facts.get("error")
            if operation == "recv":
                self.qpc_would_block += 1
            elif operation == "restore_error":
                self.qpc_restore_error_type = self.error_type(error)
            elif operation == "select" and outcome == "empty":
                self.qpc_empty += 1
            if operation == "failure":
                if outcome == "no_progress_guard":
                    self.qpc_guards += 1
                    probe.native_error = "qpc_no_progress_guard"
                elif outcome == "deadline":
                    probe.native_error = "qpc_deadline"
                    self.entry(probe, "qpc_deadline", requested=length-probe.confirmed)
                elif outcome == "select_error":
                    probe.native_error, probe.current_entry = "qpc_select", None
            self._qpc_note(probe, operation, started, **facts)
            if operation == "failure":
                self.failed(self.values(probe, "qpc_receive", self.wall(), self.wall(), error=error,
                                        origin=probe.native_error or outcome))
            if self.observation_error_type is not None:
                raise RuntimeError("QPC接收观察损坏。")
        try:
            result = _receive_qpc_exact(probe, length, deadline, _observe=observe)
            self.qpc_completed += 1
            return result
        finally:
            self.qpc_receiving = previous

    def _observe_error(self, error):
        self.observation_error_type = self.observation_error_type or self.error_type(error)

    def wall(self):
        try:
            value = self._wall()
            if type(value) is not int or value < 0:
                raise ValueError("S12观察时间必须是非负整数ns。")
            return value
        except Exception as error:  # noqa: BLE001 - 观察故障不能替换原调用/首错
            self._observe_error(error)
            return 0

    @staticmethod
    def _cpu():
        return None

    def _label(self):
        return self.role, getattr(self.state, "step", None), None, None

    def select(self, step):
        self.state.step = step

    def _public(self, value):
        if value is None or type(value) is int and 0 <= value < 2**63 or type(value) is str and len(value) <= 128:
            return value
        self.context_dropped += 1
        return None

    def remember(self, message):
        try:
            super().remember(message)
            key = (getattr(message, "sender", None), getattr(message, "recipient", None))
            if key not in self.contexts:
                return
            payload = message.payload
            values = [self._public(getattr(payload, name, None)) for name in
                      ("run_id", "controller_epoch", "segment_index")]
            values[1] = values[1] or self._public(getattr(payload, "epoch_id", None))
            for i, value in enumerate(values):
                if value is not None:
                    self.run_identity[i] = value
            step = self._public(getattr(payload, "physical_step", None))
            self.contexts[key] = (*self.contexts[key][:9], *self.run_identity, step)
        except Exception as error:  # noqa: BLE001 - 只读公开metadata失败不阻断原编码/解码
            self._observe_error(error)

    def _plan_identity(self, plan, peer, sequence=None):
        return ("expected_from_validated_stage_plan", self.role, peer, "stage", None,
                self._public(plan.session_id), self._public(plan.round_id), self._public(plan.step),
                self._public(sequence), *self.run_identity, self._public(plan.step))

    def put(self, bucket, values, *, entry=None):
        # 全I/O仍保存固定入口/首错；仅stage历史进入128槽。
        if getattr(self.state, "phase", None) is not None or values[0] == "phase":
            self.slots[self.seen % 128] = values
            self.seen += 1

    def failed(self, values):
        if self.qpc_receiving and values[1] == "recv" and values[13] in {
                "BlockingIOError", "SSLWantReadError", "SSLWantWriteError"}:
            return  # S15预期would-block仍写环，不伪作终止首错。
        if self.first_failure is None:
            self.first_failure = values
            self.first_failure_entry = values[11]

    def marker(self, operation):
        # 父frame的收齐标记仅在stage写环；close使用独立固定锚点。
        stamp = self.wall()
        if operation == "runtime_close_begin":
            self.close_begin_ns = self.close_begin_ns if self.close_begin_ns is not None else stamp
        elif operation == "runtime_close_end":
            self.close_end_ns = stamp

    def entry(self, probe, operation, *, requested=None, native_called=False):
        try:
            actual = probe.sock.gettimeout()
            if actual is not None and (type(actual) not in (int, float) or not isfinite(actual)):
                raise ValueError("S12 timeout观察无效。")
            deadline = probe.deadline
            cycle = hasattr(deadline, "deadline_ns")
            deadline_ns = deadline.deadline_ns if cycle else round(float(deadline) * 1e9)
            thread, native = get_ident(), get_native_id()
            monotonic = None if cycle else time.monotonic_ns()
            qpc = self.wall()
            value = (qpc, "qpc_cycle" if cycle else "legacy_monotonic", deadline_ns,
                deadline_ns - (qpc if cycle else monotonic),
                probe.requested_timeout if native_called else None, actual, native_called, requested,
                probe.confirmed, monotonic, thread, native)
            probe.current_entry = value
            return value
        except Exception as error:  # noqa: BLE001 - 固定入口观察损坏也仍执行原调用
            self._observe_error(error)
            return None

    def values(self, probe, operation, started, ended, *, requested=None, returned=None,
               error=None, origin=None, timeout=None, cpu=None):
        cause = getattr(error, "__cause__", None)
        errno, winerror = getattr(error, "errno", None), getattr(error, "winerror", None)
        return ("io", operation, started, ended, get_ident(), get_native_id(), probe.peer,
            probe.direction, probe.part, probe.context or getattr(self.state, "context", None),
            getattr(self.state, "phase", None), probe.current_entry, returned,
            self.error_type(error), self.error_type(cause),
            errno if type(errno) is int and -2**31 <= errno < 2**31 else None,
            winerror if type(winerror) is int and -2**31 <= winerror < 2**31 else None,
            origin, error is not None and operation in {"send", "recv"},
            getattr(probe, "last_returned", None), ended is None and getattr(probe, "native_in_flight", False))

    def frame(self, original, sock, value, deadline, *, sending):
        from secure_control.execution.cycle_timing import _CycleDeadline

        try:
            probe = self.probe(sock)
        except Exception as error:  # noqa: BLE001 - 探针容量/地址观察失败不伪造原通信错误
            self._observe_error(error)
            return original(sock, value, deadline)
        probe.current_entry, probe.last_returned = None, None
        previous_qpc = self.qpc_receiving
        if not sending and isinstance(deadline, _CycleDeadline):
            self.qpc_receiving = True
        try:
            return super().frame(original, sock, value, deadline, sending=sending)
        finally:
            probe.current_entry = None
            self.qpc_receiving = previous_qpc

    def _wrapped(self, original, operation, identity):
        def observed(*args, **kwargs):
            previous = (getattr(self.state, "phase", None), getattr(self.state, "context", None))
            try:
                context = identity(*args, **kwargs)
            except Exception as error:  # noqa: BLE001 - 不保存参数，也不因观察拒绝合法调用
                self._observe_error(error)
                context = None
            self.state.phase, self.state.context = operation, context
            started = self.wall()
            def record(ended, error=None):
                self.put("stage", ("phase", operation, started, ended, get_ident(), get_native_id(),
                    None if context is None else context[2], None, None, context, operation, None, None,
                    self.error_type(error), self.error_type(getattr(error, "__cause__", None)),
                    None, None, None, False, None, False))
            record(None)
            try:
                result = original(*args, **kwargs)
            except BaseException as error:
                record(self.wall(), error)
                raise
            else:
                record(self.wall())
                return result
            finally:
                self.state.phase, self.state.context = previous
        return observed

    @contextmanager
    def installed(self):
        """后装先卸；只包原阶段和原framing，不安装父类全阶段诊断。"""
        from secure_control.execution import (
            _localhost_peer,
            _localhost_workers,
            lan_runtime,
            localhost_transport,
        )

        send, receive = localhost_transport._send_exact, localhost_transport._receive_exact
        encode, decode = localhost_transport.encode_envelope, localhost_transport.decode_envelope
        precheck, close = localhost_transport._set_remaining_timeout, lan_runtime.LanSegmentedRuntime.close
        def encoded(message):
            result = encode(message)
            self.remember(message)
            return result
        def decoded(payload):
            message = decode(payload)
            self.remember(message)
            return message
        def checked(sock, deadline):
            if not isinstance(sock, _StageTraceSocket) or sock.diagnostic is not self:
                return precheck(sock, deadline)
            entry = self.entry(sock, "timeout_precheck", requested=sock.frame_requested-sock.confirmed)
            try:
                return precheck(sock, deadline)
            except BaseException as error:
                if self.first_failure is None:
                    self.failed(self.values(sock, "timeout_precheck", entry[0] if entry else self.wall(),
                                            self.wall(), error=error, origin="absolute_precheck"))
                raise
        def closed(runtime):
            self.marker("runtime_close_begin")
            try:
                return close(runtime)
            finally:
                self.marker("runtime_close_end")
        originals = []
        with ExitStack() as stack:
            def install(owner, name, replacement):
                originals.append((owner, name, getattr(owner, name)))
                stack.enter_context(patch.object(owner, name, replacement))
            for owner, name, replacement in (
                (localhost_transport, "_send_exact", lambda s, v, d: self.frame(send, s, v, d, sending=True)),
                (localhost_transport, "_receive_exact", lambda s, v, d: self.frame(receive, s, v, d, sending=False)),
                (localhost_transport, "_set_remaining_timeout", checked),
                (localhost_transport, "encode_envelope", encoded), (localhost_transport, "decode_envelope", decoded)):
                install(owner, name, replacement)
            if self.role == "Client":
                install(lan_runtime.LanSegmentedRuntime, "close", closed)
                for name in ("start_stage_batch", "finish_stage_batch"):
                    owner = _localhost_workers._ClientPartyEndpoint
                    def identity(endpoint, finish=name == "finish_stage_batch"):
                        request = endpoint._pending_batch if finish else None
                        return self._plan_identity(endpoint.plan, endpoint._role,
                            endpoint.sequence if request is None else request.sequence)
                    install(owner, name, self._wrapped(getattr(owner, name), name, identity))
            else:
                stage = lan_runtime.stage_protocol3_batch
                install(lan_runtime, "stage_protocol3_batch",
                    self._wrapped(stage, "party_stage", lambda endpoint, peer:
                                  self._plan_identity(endpoint.plan, "P2" if self.role == "P1" else "P1")))
                reply = lan_runtime._party_reply
                stage_reply = self._wrapped(reply, "stage_reply", lambda sock, request, *a, **k:
                    ("validated_stage_request_for_reply", self.role, request.sender, request.operation,
                     "stage_batch", self._public(request.session_id), self._public(request.round_id),
                     self._public(request.step), self._public(request.sequence), *self.run_identity, self._public(request.step)))
                def replied(sock, request, *args, **kwargs):
                    selected = (request.operation == "online_stage" or request.operation == "endpoint"
                                and getattr(request.payload, "operation", None) == "stage_batch")
                    return (stage_reply if selected else reply)(sock, request, *args, **kwargs)
                install(lan_runtime, "_party_reply", replied)
                exchange = _localhost_peer._exchange_frame
                def duplex(sock, payload, *, deadline, limit):
                    # 同阶段双向帧的瞬态 WANT 只在这个原调用内可恢复，不污染终止首错。
                    try:
                        probe = self.probe(sock)
                    except Exception as error:  # noqa: BLE001 - 观察失败不改变原传输。
                        self._observe_error(error)
                        return exchange(sock, payload, deadline=deadline, limit=limit)
                    previous = (probe.deadline, probe.context, probe.direction, probe.part,
                                probe.confirmed, probe.frame_requested, probe.current_entry)
                    previous_probe = getattr(self.state, "duplex_probe", None)
                    self.state.duplex_probe = probe
                    probe.deadline, probe.context = deadline, getattr(self.state, "context", None)
                    probe.direction, probe.part = "duplex", "duplex_frame"
                    probe.confirmed, probe.frame_requested, probe.current_entry = 0, len(payload)+4, None
                    probe.native_error = None
                    started = self.wall()
                    try:
                        return exchange(probe, payload, deadline=deadline, limit=limit)
                    except BaseException as error:
                        from secure_control.execution.cycle_timing import remaining_seconds
                        origin = ("absolute_precheck" if isinstance(error, TimeoutError)
                                  and remaining_seconds(deadline) <= 0 else probe.native_error or "unknown")
                        if origin == "absolute_precheck" and probe.native_error is None:
                            probe.current_entry = None  # 没有观察到该期限检查入口，不能借用已返回的 native 入口。
                        record = self.values(probe, "frame_exchange", started, self.wall(),
                            error=error, origin=origin)
                        self.failed(record)
                        if self.outer_failure is None:
                            self.outer_failure = record
                        self.put("critical", record)
                        raise
                    finally:
                        self.state.duplex_probe = previous_probe
                        (probe.deadline, probe.context, probe.direction, probe.part,
                         probe.confirmed, probe.frame_requested, probe.current_entry) = previous
                install(_localhost_peer, "_exchange_frame", duplex)
                for name in ("exchange_products", "product_complete", "send_truncations", "receive_truncations", "state_complete"):
                    owner = _localhost_peer.LocalhostProtocol3PeerPort
                    install(owner, name, self._wrapped(getattr(owner, name), name,
                        lambda peer, plan, *a, **k: self._plan_identity(plan, peer._peer)))
            try:
                yield self
            finally:
                stack.close()
                self.trace_restored = all(getattr(owner, name) is original for owner, name, original in originals)

    def report(self):
        """退出后去重公开identity并编码；首错先入表且不因预算被截去。"""
        events = sorted((v for v in self.slots if v is not None), key=lambda v: v[3] or v[2])
        gc_report = self.gc_observer.report() if self.gc_observer else None
        if gc_report and self.role == "Client":
            gc_report.update(profile="client-gen2-light-v1", scope="Client gen2; original startup may appear before control window; no phase/round identity")
            for _ in range(3):
                gc_report["encoded_bytes"] = len(json.dumps(gc_report, separators=(",", ":"), allow_nan=False).encode())
        result = {"format_version": 1, "profile": ("canonical-qpc-receive-v1" if self.all_qpc_receives else
                  "qpc-stage-receive-v1" if self.qpc_receive_candidate else "stage-wait-light-v1"), "role": self.role,
            "schemas": {"event": self.FIELDS, "entry": self.ENTRY_FIELDS, "context": self.CONTEXT},
            "event_limit": 128, "in_flight_limit": 4, "first_error_limit": 1,
            "evicted_count": max(0, self.seen-128), "encoded_omitted": 0,
            "context_dropped": self.context_dropped, "socket_count": len(self.probes),
            "close_begin_ns": self.close_begin_ns, "close_end_ns": self.close_end_ns,
            "observation_error_type": self.observation_error_type, "hooks_restored": self.trace_restored,
            "gc": gc_report, "encoded_limit": 64*1024, "encoded_bytes": 0, "budget_failed": False,
            "scope": "stage Python boundaries only; other I/O in-flight and first error; expected identities not received-frame proof; no CPU/kernel/GIL attribution"}
        in_flight = [self.values(p, "in_flight", p.current_entry[0], None) for p in self.probes.values() if p.current_entry]
        def encode():
            contexts = []
            def packed(row, context_index=9):
                if row is None:
                    return None
                row = list(row)
                if row[context_index] is not None:
                    if row[context_index] not in contexts:
                        contexts.append(row[context_index])
                    row[context_index] = contexts.index(row[context_index])
                return row
            result.update(first_failure=packed(self.first_failure), outer_failure=packed(self.outer_failure),
                in_flight=[packed(row) for row in in_flight], events=[packed(row) for row in events], contexts=contexts)
            if self.qpc_receive_candidate:
                result["qpc_receive"] = {"fields": self.QPC_FIELDS, "event_limit": 16,
                    "events": [packed(row, 5) for row in sorted((r for r in self.qpc_slots if r), key=lambda r: r[2])],
                    "evicted_count": max(0, self.qpc_seen-16), "encoded_omitted": 0,
                    "first_anomaly": packed(self.qpc_first_anomaly, 5), "first_exception": packed(self.qpc_first_exception, 5),
                    "selected_exact_calls": self.qpc_calls, "completed_exact_calls": self.qpc_completed,
                    "empty_count": self.qpc_empty, "would_block_count": self.qpc_would_block,
                    "no_progress_guard_count": self.qpc_guards, "restore_error_type": self.qpc_restore_error_type,
                    "scope": "nonblocking recv timeout0; select wait separate; no transaction resend; QPC original deadline"}
            for _ in range(3):
                result["encoded_bytes"] = len(json.dumps(result, separators=(",", ":"), allow_nan=False).encode())
        encode()
        while result["encoded_bytes"] > result["encoded_limit"] and events:
            result["budget_failed"] = True
            result["encoded_omitted"] += 1
            events.pop(0)
            encode()
        if result["encoded_bytes"] > result["encoded_limit"]:
            result["budget_failed"] = True
        return result


def _source_fingerprints(extra=()):
    """区分同一 HEAD 上的观察补丁和优化补丁；只保存内容摘要。"""
    paths = (
        "src/secure_control/protocol/coordinator.py",
        "src/secure_control/protocol/roles.py", "src/secure_control/protocol/messages.py",
        "src/secure_control/execution/lan_runtime.py",
        "src/secure_control/execution/_material_worker.py",
        "src/secure_control/execution/localhost_transport.py",
        "src/secure_control/execution/localhost_codec.py",
        "src/secure_control/execution/_localhost_workers.py",
        "src/secure_control/execution/_localhost_peer.py",
        "src/secure_control/execution/lan_transport.py",
        "src/secure_control/experiments/communication_benchmark.py",
        "src/secure_control/experiments/lan_runner.py",
        "src/secure_control/experiments/cart_pole_segmented_evidence.py",
        "src/secure_control/experiments/plotting.py",
        "src/secure_control/experiments/cart_pole_evidence.py",
        "src/secure_control/experiments/__init__.py",
        "src/secure_control/execution/cycle_timing.py",
        "configs/cart_pole_observer_lan.example.yaml", "configs/cart_pole_observer.yaml",
    )
    return {name: sha256((_ROOT / name).read_bytes()).hexdigest() for name in (*paths, *extra)}


@cache
def _windows_memory_api():
    """每进程只初始化结构和函数签名；不保存任何 RSS 样本。"""
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
    kernel.GetCurrentProcess.argtypes = ()
    api.GetProcessMemoryInfo.restype = wintypes.BOOL
    return Counters, kernel, api


def _process_memory():
    """每次重新读取 OS RSS/working set；仅缓存平台 API 绑定。"""
    if os.name == "nt":
        import ctypes
        Counters, kernel, api = _windows_memory_api()
        value = Counters()
        value.cb = ctypes.sizeof(value)
        if not api.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(value), value.cb):
            return {"peak_rss_bytes": None, "scope": "unavailable"}
        return {"peak_rss_bytes": value.peak, "current_rss_bytes": value.current,
                "scope": "Client OS working set, includes libraries and observation arrays"}
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {"peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
            "scope": "Client OS peak RSS, includes libraries and observation arrays"}


def _ports() -> tuple[int, int, int]:
    sockets = [socket.socket() for _ in range(3)]
    try:
        for item in sockets:
            item.bind(("127.0.0.1", 0))
        return tuple(item.getsockname()[1] for item in sockets)
    finally:
        for item in sockets:
            item.close()


def _config(role: str, ports: tuple[int, int, int]) -> LanConfig:
    identities = {name: f"{name.lower()}.secure-control.test"
                  for name in ("Client", "P1", "P2")}
    endpoints = tuple(LanEndpoint("127.0.0.1", "127.0.0.1", port) for port in ports)
    public = {"version": 1, "identities": identities,
              **{name: asdict(endpoint) for name, endpoint in zip(
                  ("p1_client", "p2_client", "p1_peer"), endpoints, strict=True,
              )}}
    digest = sha256(json.dumps(public, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode()).hexdigest()
    topology = LanTopology(identities, *endpoints, digest)
    return LanConfig(
        role, topology, None, None, None, 30., 30., 5., None,
        _ROOT / "configs/cart_pole_observer_lan.example.yaml" if role == "Client" else None,
        30., "insecure_tcp",
    )


def _meter(role: str, ports: tuple[int, int, int], delay_ms: float, role_steps=None,
           diagnostic=None, full_observation=False, gc_boundaries=None, compact_history=None, qpc_receiver=None):
    """包住既有 framing 最外层，只数发送次数/字节，不解码或保存 payload。"""
    from secure_control.execution import lan_scalar_runtime, localhost_transport

    counts: dict[str, dict[str, int]] = {}
    activity = {name: 0. for name in (
        "send_ms", "receive_ms", "encode_ms", "decode_ms", "recovery_ms",
        "local_arithmetic_ms", "peer_exchange_ms", "plan_digest_ms", "dto_validation_ms",
    )}
    originals = {
        "send": localhost_transport._send_exact,
        "receive": localhost_transport._receive_exact,
        "encode": localhost_transport.encode_envelope,
        "decode": localhost_transport.decode_envelope,
        "scalar_encode": lan_scalar_runtime.encode_scalar_frame_v3,
        "scalar_decode": lan_scalar_runtime.decode_scalar_frame_v3,
    }

    def timed(name, original, label=None):
        def call(*args, **kwargs):
            started = time.perf_counter_ns()
            try:
                return original(*args, **kwargs)
            finally:
                activity[name] += (time.perf_counter_ns() - started) / 1e6
        return diagnostic.wrap(label or name, call) if diagnostic else call

    def encoded(*args, **kwargs):
        token = diagnostic.begin("encode_ms")
        started = time.perf_counter_ns()
        value, status = None, "complete"
        try:
            value = originals["encode"](*args, **kwargs)
            return value
        except BaseException as error:
            status = type(error).__name__
            raise
        finally:
            activity["encode_ms"] += (time.perf_counter_ns() - started) / 1e6
            # 仅公开信封方向及返回bytes长度；不访问payload/材料或异常文本。
            message = args[0] if args else kwargs.get("message")
            sender, recipient = getattr(message, "sender", None), getattr(message, "recipient", None)
            direction = (sender + "->" + recipient if sender in {"Client", "P1", "P2"}
                         and recipient in {"Client", "P1", "P2"} else None)
            diagnostic.end(token, status=status, direction=direction,
                           public_bytes=len(value) if isinstance(value, bytes) else None)

    def count_frame(sock, length):
        local = sock.getsockname()[1]
        remote = sock.getpeername()[1]
        if role == "Client":
            recipient = "P1" if remote == ports[0] else "P2"
        elif role == "P1":
            recipient = "Client" if local == ports[0] else "P2"
        else:
            recipient = "Client" if local == ports[1] else "P1"
        direction = f"{role}->{recipient}"
        entry = counts.setdefault(direction, {"frames": 0, "application_bytes": 0})
        entry["frames"] += 1
        entry["application_bytes"] += length
        return direction

    def measured(sock, payload, deadline):
        started = time.perf_counter_ns()
        if delay_ms:
            time.sleep(delay_ms / 1000)
        direction = count_frame(sock, len(payload))
        # S0区间包住原_send_exact；原meter另含公开计数/注入等待，不声称纯OS耗时。
        token = diagnostic.begin("send_ms") if diagnostic and diagnostic.supply else None
        status = "complete"
        try:
            return originals["send"](sock, payload, deadline)
        except BaseException as error:
            status = type(error).__name__
            raise
        finally:
            activity["send_ms"] += (time.perf_counter_ns() - started) / 1e6
            if token is not None:
                diagnostic.end(token, status=status, direction=direction, public_bytes=len(payload))

    localhost_transport._send_exact = (diagnostic.wrap("send_ms", measured)
                                       if diagnostic else measured)
    def received(sock, length, deadline):
        return qpc_receiver(originals["receive"], sock, length, deadline)
    localhost_transport._receive_exact = timed("receive_ms", received if qpc_receiver else originals["receive"])
    localhost_transport.encode_envelope = (encoded if diagnostic and diagnostic.supply
                                          else timed("encode_ms", originals["encode"]))
    localhost_transport.decode_envelope = timed("decode_ms", originals["decode"])
    lan_scalar_runtime.encode_scalar_frame_v3 = timed("encode_ms", originals["scalar_encode"])
    lan_scalar_runtime.decode_scalar_frame_v3 = timed("decode_ms", originals["scalar_decode"])
    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.protocol.coordinator import LocalProtocol3PartyEndpoint

    # 只在基准进程包住现有方法；不输出参数、返回值或任意秘密 payload。
    observations = ExitStack()
    from secure_control.execution import _localhost_peer, lan_runtime
    from secure_control.protocol import coordinator

    original_exchange = _localhost_peer._exchange_frame
    def exchanged(sock, payload, *, deadline, limit):
        # 与旧 _send_exact 相同：包含4字节帧头，失败调用也保留已尝试发送计数。
        count_frame(sock, len(payload) + 4)
        return original_exchange(sock, payload, deadline=deadline, limit=limit)
    observations.enter_context(patch.object(_localhost_peer, "_exchange_frame", exchanged))
    observations.enter_context(patch.object(_localhost_peer, "encode_envelope",
        timed("encode_ms", _localhost_peer.encode_envelope)))
    observations.enter_context(patch.object(_localhost_peer, "decode_envelope",
        timed("decode_ms", _localhost_peer.decode_envelope)))

    if gc_boundaries is not None and role != "Client":
        # 每层保留独立前驱；后续诊断包装不能重绑定本层闭包而形成自递归。
        boundary_receive = lan_runtime.receive_envelope
        def boundary_request(*args, **kwargs):
            request = boundary_receive(*args, **kwargs)
            if request.sender == "Client" and request.operation in {"online", "online_stage"} and "begin" not in gc_boundaries:
                gc_boundaries["begin"] = {"stats": gc.get_stats(), "enabled": gc.isenabled(),
                                           "threshold": list(gc.get_threshold())}
            if (request.sender == "Client" and request.operation == "segment_end"
                    and request.payload.action == "stop" and "end" not in gc_boundaries):
                gc_boundaries["end"] = {"stats": gc.get_stats(), "enabled": gc.isenabled(),
                                         "threshold": list(gc.get_threshold())}
            return request
        observations.enter_context(patch.object(lan_runtime, "receive_envelope", boundary_request))

    if diagnostic and role != "Client":
        observed_receive = lan_runtime.receive_envelope

        def observed_request(*args, **kwargs):
            started, cpu = diagnostic.wall(), diagnostic._cpu()
            request = observed_receive(*args, **kwargs)
            if request.sender == "Client" and request.step is not None:
                diagnostic.select(request.step)
                if diagnostic.selected():
                    if diagnostic.supply:
                        token = diagnostic.begin("receive_request")
                        diagnostic.end((*token[:5], started, cpu, *token[7:]))
                    else:
                        diagnostic.end((get_ident(), get_native_id(), request.step, "receive_request",
                                        getattr(diagnostic.state, "phase", None), started, cpu))
            return request

        observations.enter_context(patch.object(lan_runtime, "receive_envelope", observed_request))
        observations.enter_context(patch.object(
            coordinator._OnlineMaterialRecovery, "restore",
            diagnostic.wrap("material_restore", coordinator._OnlineMaterialRecovery.restore),
        ))
        observations.enter_context(patch.object(
            lan_runtime, "_party_reply", diagnostic.wrap("result_reply", lan_runtime._party_reply),
        ))
        observations.enter_context(patch.object(
            lan_runtime, "stage_protocol3_batch",
            diagnostic.wrap("party_stage", lan_runtime.stage_protocol3_batch),
        ))

    observations.enter_context(patch.object(
        _localhost_peer, "public_step_plan_sha256",
        timed("plan_digest_ms", _localhost_peer.public_step_plan_sha256),
    ))
    if hasattr(lan_runtime, "encode_wire_value"):
        observations.enter_context(patch.object(
            lan_runtime, "encode_wire_value", timed("dto_validation_ms", lan_runtime.encode_wire_value),
        ))

    recovery_name = ("_rehydrate_online_material" if hasattr(coordinator, "_rehydrate_online_material")
                     else "rehydrate_online_material")
    observations.enter_context(patch.object(
        coordinator, recovery_name, timed("recovery_ms", getattr(coordinator, recovery_name)),
    ))
    if recovery_name == "rehydrate_online_material":
        observations.enter_context(patch.object(
            lan_runtime, recovery_name, timed("recovery_ms", getattr(lan_runtime, recovery_name)),
        ))
    for owner, names, category in (
        (LocalProtocol3PartyEndpoint, (
            "mask_product", "finish_product", "complete_product", "finish_products",
            "mask_truncation", "p2_truncation_message_direct", "finish_truncation_p1_direct",
            "finish_truncation_p2", "complete_truncation", "stage_output", "commit", "commit_staged",
        ), "local_arithmetic_ms"),
        (LocalhostProtocol3PeerPort, (
            "exchange_products", "product_complete", "send_truncations",
            "receive_truncations", "state_complete",
        ), "peer_exchange_ms"),
    ):
        for name in names:
            observations.enter_context(patch.object(
                owner, name, timed(category, getattr(owner, name), category + "." + name),
            ))
    if full_observation:
        from secure_control.protocol.arithmetic import ScalarPartyExecutor

        for owner, names, category in (
            (ScalarPartyExecutor, ("_prepare_product", "_finish_product", "_p2_truncation_message",
                                  "_finish_truncation", "_complete_gate"), "local_arithmetic_ms"),
            (lan_scalar_runtime._SocketScalarPeer,
             ("exchange_layer_products", "send_layer_truncations", "receive_layer_truncations",
              "complete_layer"), "peer_exchange_ms"),
        ):
            for name in names:
                observations.enter_context(patch.object(owner, name, timed(category, getattr(owner, name))))
        if role_steps is not None:
            scalar_send = lan_scalar_runtime._send
            scalar_previous, scalar_counts = dict(activity), {}

            def scalar_reply(sock, frame, deadline):
                nonlocal scalar_previous, scalar_counts
                result = scalar_send(sock, frame, deadline)
                if (frame.sender != "Client" and frame.operation == "committed"
                        and len(role_steps) < 1500):
                    role_steps.append({"physical_step": frame.physical_step,
                                           "local_step": frame.local_step, "epoch_id": frame.epoch_id,
                                           "session_id": frame.session_id, "round_id": frame.round_id,
                                           "activity_ms": {k: v-scalar_previous[k] for k, v in activity.items()},
                                           "sent": {k: {f: n-scalar_counts.get(k, {}).get(f, 0)
                                                        for f, n in v.items()} for k, v in counts.items()}})
                if frame.operation == "committed" or (frame.operation == "ready" and frame.round_id == "setup"):
                    scalar_previous = dict(activity)
                    scalar_counts = {k: dict(v) for k, v in counts.items()}
                return result
            observations.enter_context(patch.object(lan_scalar_runtime, "_send", scalar_reply))
    if role_steps is not None or compact_history is not None:
        reply = lan_runtime._party_reply
        previous = dict(activity)
        previous_counts = {}

        def observed_reply(sock, request, *args, **kwargs):
            nonlocal previous, previous_counts
            value = reply(sock, request, *args, **kwargs)
            if (request.operation == "endpoint"
                    and getattr(request.payload, "operation", None) in {"commit", "commit_staged"}):
                if compact_history is not None:
                    compact_history.party_step(request, activity, previous, counts, previous_counts)
                else:
                    role_steps.append({"step": request.step, "round_id": request.round_id,
                                   "activity_ms": {k: activity[k] - v for k, v in previous.items()},
                                   "sent": {k: {field: v[field] - previous_counts.get(k, {}).get(field, 0)
                                                for field in v} for k, v in counts.items()}})
            if request.operation in {"offline", "preload_seal"} or (request.operation == "endpoint"
                    and getattr(request.payload, "operation", None) in {"commit", "commit_staged"}):
                previous = dict(activity)
                previous_counts = {k: dict(v) for k, v in counts.items()}
            return value

        observations.enter_context(patch.object(lan_runtime, "_party_reply", observed_reply))

    restored = False

    def restore():
        nonlocal restored
        if restored:
            return
        restored = True
        observations.close()
        localhost_transport._send_exact = originals["send"]
        localhost_transport._receive_exact = originals["receive"]
        localhost_transport.encode_envelope = originals["encode"]
        localhost_transport.decode_envelope = originals["decode"]
        lan_scalar_runtime.encode_scalar_frame_v3 = originals["scalar_encode"]
        lan_scalar_runtime.decode_scalar_frame_v3 = originals["scalar_decode"]

    return counts, activity, restore


def _party_job(
    config: LanConfig, ports: tuple[int, int, int], delay_ms: float, batch: bool, queue,
    diagnostic_enabled=False, full_observation=False, tcp_nodelay=None, supply_diagnostic=False,
    timeout_trace=False, material_comparison=False, worker_wait_diagnostic=False, server_gc_candidate=False,
    stage_wait_diagnostic=False, compact_history_candidate=False, compact_history_steps=4000,
    compact_history_qualification=False, network_observation=False, wire_profile=None,
    source_manifest=None,
) -> None:
    source_binding = None
    if source_manifest is not None:
        from .network_benchmark import matrix_process_binding
        try:
            source_binding = matrix_process_binding(source_manifest)
        except (OSError, ValueError, RuntimeError) as error:
            queue.put({"role":config.role, "status":"failed", "error_type":type(error).__name__, "steps":[]})
            return
    role_steps = []
    history = None
    if compact_history_candidate:
        try:
            history = _CompactHistory(config.role, compact_history_steps,
                **({"qualification": True} if compact_history_qualification else {}),
                **({"wire_profile": wire_profile} if wire_profile in _COMPACT_ADVANCE_PROFILES else {}))
        except Exception as error:  # noqa: BLE001 - 启动失败不建角色，不隐去缺失记录
            queue.put({"role": config.role, "status": "failed", "error_type": type(error).__name__,
                       "steps": [], "directions": {}, "activity_ms": {},
                       "compact_history": {"role": config.role, "representation_complete": False,
                                           "error_type": type(error).__name__}})
            return
    diagnostic = (_TimeoutDiagnostic(config.role, ports, wait_profile=worker_wait_diagnostic) if timeout_trace else
                  _Diagnostic(config.role, supply=supply_diagnostic) if diagnostic_enabled else None)
    observations = ExitStack()
    network_tls = {"links": [], "restored": False}
    if network_observation:
        observations.enter_context(_observe_network_tls(config.role, network_tls))
    socket_options = []
    gc_boundaries = {} if material_comparison else None
    observations.enter_context(_observe_tcp(socket_options, tcp_nodelay))
    if diagnostic:
        observations.enter_context(diagnostic.installed())
        if timeout_trace:
            observations.enter_context(diagnostic.sockets())
    counts, activity, restore = _meter(config.role, ports, delay_ms, None if history else role_steps, diagnostic,
        full_observation=full_observation, gc_boundaries=gc_boundaries,
        **({"compact_history": history} if history else {}))
    outcome = {"role": config.role}
    server_gc = _ServerGCObservation(config.role) if server_gc_candidate or stage_wait_diagnostic else None
    stage_wait = _StageWaitDiagnostic(config.role, ports, gc_observer=server_gc) if stage_wait_diagnostic else None
    try:
        if server_gc:
            observations.enter_context(server_gc.installed())
        if stage_wait:
            observations.enter_context(stage_wait.installed())
        result = run_party_single_step(config, batch=batch,
            **({"wire_profile": wire_profile} if wire_profile is not None else {}))
        outcome.update({"status": result.get("status", "closed"),
                   "directions": counts, "activity_ms": activity, "steps": role_steps,
                   "memory": _process_memory(), "material_summary": result.get("material_summary")})
    except Exception as error:  # noqa: BLE001 - 基准仅导出公开错误类别
        outcome.update({"status": "failed",
                   "error_type": type(error).__name__, "directions": counts,
                   "activity_ms": activity, "steps": role_steps, "memory": _process_memory()})
    finally:
        # S11后装在meter之外，必须先退出外层，再恢复meter，避免留下旧包装。
        if server_gc:
            try:
                observations.close()
            finally:
                restore()
        else:
            restore()
            observations.close()
        outcome["tcp_socket_options"] = socket_options
        if network_observation:
            outcome["network_tls"] = network_tls
        if wire_profile is not None:
            outcome["wire_profile"] = wire_profile
        if source_manifest is not None:
            try:
                outcome["source_binding"] = matrix_process_binding(source_manifest)
                if outcome["source_binding"] != source_binding:
                    raise ValueError("角色源绑定发生变化")
            except (OSError, ValueError, RuntimeError) as error:
                outcome.update(status="failed", source_binding_error=type(error).__name__)
        if diagnostic:
            outcome["diagnostic"] = diagnostic.report()
        if stage_wait:
            try:
                outcome["stage_wait"] = stage_wait.report()
            except Exception as error:  # noqa: BLE001 - 只附加报告错误，保留原调用的结果/异常类别
                outcome["stage_wait"] = {"role": config.role, "observation_error_type": stage_wait.error_type(error)}
        elif server_gc:
            try:
                outcome["server_gc"] = server_gc.report()
            except Exception as error:  # noqa: BLE001 - 编码失败也交回公开类别，不覆盖原首错
                outcome["server_gc"] = {"role": config.role, "error_type": type(error).__name__,
                                        "observation_report_failed": True}
        if gc_boundaries is not None:
            if "begin" in gc_boundaries and "end" not in gc_boundaries:
                gc_boundaries["end"] = {"stats": gc.get_stats(), "enabled": gc.isenabled(),
                                         "threshold": list(gc.get_threshold())}
            outcome["gc_boundaries"] = gc_boundaries
        if history is not None:
            try:
                outcome["steps"] = history.expand()["steps"]
            except Exception as error:  # noqa: BLE001 - 报告错误不取代原角色首错
                history.error_type = type(error).__name__
            outcome["compact_history"] = history.report()
        queue.put(outcome)


def _quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _party_outcomes(queue):
    outcomes = []
    for _ in range(2):
        try:
            outcomes.append(queue.get(timeout=10))
        except Empty:
            break
    for role in sorted({"P1", "P2"} - {item["role"] for item in outcomes}):
        outcomes.append({"role": role, "status": "not_reported", "directions": {},
                         "activity_ms": {}, "steps": []})
    return outcomes


def _timing(values: list[float]) -> dict[str, object]:
    samples = values
    if not samples:
        return {"warmup_steps": 0, "sample_count": 0, "samples_ms": [], "p50_ms": None}
    jitter = [abs(current - previous) for previous, current in pairwise(samples)]
    return {
        "warmup_steps": 0, "sample_count": len(samples),
        "quantile_method": "linear interpolation at (n-1)*p",
        "p50_ms": _quantile(samples, .5), "p95_ms": _quantile(samples, .95),
        "p99_ms": _quantile(samples, .99), "max_ms": max(samples),
        "jitter_definition": "absolute difference of adjacent observed step attempt times",
        "jitter_p95_ms": _quantile(jitter, .95) if jitter else None,
        "jitter_max_ms": max(jitter) if jitter else None,
        "over_20_ms": sum(value > 20 for value in samples),
        "samples_ms": samples,
    }


@contextmanager
def _observe_dynamic(marks):
    """复用内核的阶段回调和既有方法；仅保存本机时长和公开角色号。"""
    from secure_control.execution import lan_runtime
    from secure_control.execution._localhost_workers import _ClientPartyEndpoint
    from secure_control.protocol import Client

    prepare, complete = Client.prepare_online, lan_runtime._complete_client_round
    bind = Client.bind_online_input
    preload_bind = Client.bind_preloaded_input
    commit = _ClientPartyEndpoint.commit
    finish_commit = _ClientPartyEndpoint.finish_commit

    def measured_prepare(self, *args, **kwargs):
        started = time.perf_counter_ns()
        try:
            return prepare(self, *args, **kwargs)
        finally:
            marks["material_prepare_ms"] = (time.perf_counter_ns() - started) / 1e6
            marks["prepare_end_ns"] = time.perf_counter_ns()

    def measured_complete(client, p1, p2, plan, **kwargs):
        started = time.perf_counter_ns()
        marks["online_distribution_ms"] = (started - marks["prepare_end_ns"]) / 1e6
        stamps = {"start": started}
        original_phase = kwargs.pop("on_phase", None)
        def measured_phase(name):
            stamps[name] = time.perf_counter_ns()
            if original_phase is not None:
                original_phase(name)
        try:
            return complete(client, p1, p2, plan, **kwargs,
                            on_phase=measured_phase)
        finally:
            for label, begin, end in (("stage_ms", "start", "stage"),
                                      ("reconstruct_ms", "stage", "reconstruct")):
                if end in stamps:
                    marks[label] = (stamps[end] - stamps[begin]) / 1e6

    def measured_bind(self, *args, **kwargs):
        started = time.perf_counter_ns()
        try:
            return bind(self, *args, **kwargs)
        finally:
            marks["material_bind_ms"] = (time.perf_counter_ns() - started) / 1e6
            marks["prepare_end_ns"] = time.perf_counter_ns()

    def measured_encoded_bind(self, *args, **kwargs):
        started = time.perf_counter_ns()
        try:
            return encoded_bind(self, *args, **kwargs)
        finally:
            marks["material_bind_ms"] = (time.perf_counter_ns() - started) / 1e6
            marks["prepare_end_ns"] = time.perf_counter_ns()

    encoded_bind = Client._bind_encoded_input

    def measured_commit(self):
        started = time.perf_counter_ns()
        try:
            return commit(self)
        finally:
            marks[f"p{self.party + 1}_commit_ms"] = (time.perf_counter_ns() - started) / 1e6

    def measured_finish_commit(self):
        try:
            return finish_commit(self)
        finally:
            for key, duration in self.commit_timings.items():
                marks[f"p{self.party + 1}_commit_{key}_ms"] = duration / 1e6

    def measured_preload_bind(self, *args, **kwargs):
        started = time.perf_counter_ns()
        try:
            return preload_bind(self, *args, **kwargs)
        finally:
            marks["material_bind_ms"] = (time.perf_counter_ns() - started) / 1e6
            marks["prepare_end_ns"] = time.perf_counter_ns()

    with (patch.object(Client, "prepare_online", measured_prepare),
          patch.object(Client, "bind_online_input", measured_bind),
          patch.object(Client, "_bind_encoded_input", measured_encoded_bind),
          patch.object(Client, "bind_preloaded_input", measured_preload_bind),
          patch.object(lan_runtime, "_complete_client_round", measured_complete),
          patch.object(_ClientPartyEndpoint, "commit", measured_commit),
          patch.object(_ClientPartyEndpoint, "finish_commit", measured_finish_commit)):
        yield


@contextmanager
def _observe_tcp(rows, choice):
    """每个角色在原工厂建连期读取一次选项；不包每步 send/recv。"""
    from secure_control.execution import localhost_transport

    original = localhost_transport._configure_tcp

    def configure(sock, *, enabled=True):
        original(sock, enabled=enabled if choice is None else choice)
        rows.append({"local": list(sock.getsockname()), "peer": list(sock.getpeername()),
                     "tcp_nodelay": sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)})

    with patch.object(localhost_transport, "_configure_tcp", configure):
        yield


@contextmanager
def _commit_policy(choice):
    from secure_control.execution import lan_runtime

    original = lan_runtime._complete_client_round

    def complete(*args, **kwargs):
        if choice == "serial":
            kwargs["overlap_commit"] = False
        return original(*args, **kwargs)

    with patch.object(lan_runtime, "_complete_client_round", complete):
        yield


@contextmanager
def _observe_diagnostic(diagnostic, *, recording=True):
    """临时包住canonical方法；只读取公开阶段，不另建控制实现。"""
    from secure_control.execution import lan_runtime
    from secure_control.execution._localhost_workers import _ClientPartyEndpoint
    from secure_control.protocol import Client
    from secure_control.protocol.coordinator import Protocol3Orchestrator

    from . import cart_pole_segmented_evidence as evidence

    if diagnostic.supply:
        from secure_control.protocol.roles import _PreparedResourceOwner

        produce, create = lan_runtime._OnlineResourcePool._produce, _PreparedResourceOwner.create

        def produced(self):
            previous = (getattr(diagnostic.state, "owner", None),
                        getattr(diagnostic.state, "prepared_step", None))
            diagnostic.state.owner, diagnostic.state.prepared_step = "Client producer", self._next
            try:
                with diagnostic.scope("material_produce"):
                    return produce(self)
            finally:
                diagnostic.state.owner, diagnostic.state.prepared_step = previous

        def created(self, *args, **kwargs):
            if getattr(diagnostic.state, "owner", None) != "Client producer":
                return create(self, *args, **kwargs)
            with diagnostic.scope("material_create"):
                return create(self, *args, **kwargs)

        with (patch.object(lan_runtime._OnlineResourcePool, "_produce", produced),
              patch.object(_PreparedResourceOwner, "create", created)):
            yield
        return

    original_phase = evidence._batch_phase
    original_batch = evidence._Spool.record_batch
    original_commit = _ClientPartyEndpoint.commit
    original_start, original_finish = _ClientPartyEndpoint.start_commit, _ClientPartyEndpoint.finish_commit

    def committed(self):
        with diagnostic.scope(f"p{self.party + 1}_commit"):
            return original_commit(self)

    def start_commit(self, *args):
        with diagnostic.scope(f"p{self.party + 1}_commit_send"):
            return original_start(self, *args)

    def finish_commit(self):
        with diagnostic.scope(f"p{self.party + 1}_commit_ack_wait"):
            return original_finish(self)

    @contextmanager
    def batch_phase(stats, name):
        with diagnostic.scope(name), original_phase(stats, name):
            yield

    def batch(self, rows, segment=None):
        # identities是已有公开DTO。残段没有header，使用本方已确认前缀定位。
        diagnostic.select(segment[1][-1].global_step if segment and segment[1]
                          else max(0, self.end + len(rows) - 1))
        had_observer = "_validation_observer" in self.__dict__
        previous_observer = getattr(self, "_validation_observer", None)
        self._validation_observer = diagnostic
        try:
            with diagnostic.scope("record_batch"):
                return original_batch(self, rows, segment)
        finally:
            if had_observer:
                self._validation_observer = previous_observer
            else:
                del self._validation_observer

    with ExitStack() as stack:
        if recording:
            stack.enter_context(patch.object(evidence, "_batch_phase", batch_phase))
            stack.enter_context(patch.object(evidence._Spool, "record_batch", batch))
        stack.enter_context(patch.object(_ClientPartyEndpoint, "commit", committed))
        stack.enter_context(patch.object(_ClientPartyEndpoint, "start_commit", start_commit))
        stack.enter_context(patch.object(_ClientPartyEndpoint, "finish_commit", finish_commit))
        for owner, names in (
            (Client, ("prepare_online", "bind_online_input", "bind_preloaded_input",
                      "reconstruct_control")),
            (Protocol3Orchestrator, ("stage_batch",)),
            (lan_runtime.LanSegmentedRuntime, ("end_segment", "next_segment")),
            (evidence._Spool, ("_append_step",)),
            (evidence._BufferedChunks, ("finish",)),
            (evidence._BatchWriter, ("record_deferred", "release_segment")),
        ):
            if not recording and owner in (evidence._Spool, evidence._BufferedChunks, evidence._BatchWriter):
                continue
            for name in names:
                stack.enter_context(patch.object(owner, name,
                    diagnostic.wrap(owner.__name__ + "." + name, getattr(owner, name))))
        yield


_gc_trial_used = False


class _StartupGCTrial:
    """独占 Client 进程一次性试验；不冻结随后创建的会话或材料。"""

    RSS_LIMIT = 256 * 1024 * 1024

    def __init__(self, policy):
        self.policy = policy
        self.owns_freeze = False
        self.final_cleanup = False
        self.control_started = self.control_ended = False
        self.producers = []
        self.cleanup = ExitStack()
        self.before = None
        self.report = {"policy": policy, "scope": "exclusive Client process; all startup tracked objects",
                       "current_rss_limit_bytes": self.RSS_LIMIT, "memory_samples": [],
                       "gc_snapshots": [], "cold_collect": None, "freeze": None,
                       "original_startup_gc": None, "shutdown_collect": None,
                       "cleanup_errors": [], "restored": False,
                       "memory_guard_failed": False,
                       "unavailable_scope": "null means stage not reached or OS/clock field unavailable; GC counters are not restored",
                       "memory_scope": "sampled current/peak OS memory; between-sample spikes not excluded"}

    def snapshot(self, moment):
        value = {"moment": moment, "sample_ns": time.perf_counter_ns(),
                 "enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                 "debug": gc.get_debug(), "freeze_count": gc.get_freeze_count(),
                 "callback_count": len(gc.callbacks), "stats": gc.get_stats()}
        self.report["gc_snapshots"].append(value)
        return value

    def memory(self, moment, *, step=None, guard=False):
        try:
            value = _process_memory()
        except (OSError, RuntimeError) as error:
            value = {"current_rss_bytes": None, "peak_rss_bytes": None,
                     "scope": "unavailable", "error_type": type(error).__name__}
        value = {"moment": moment, "global_step": step, "sample_ns": time.perf_counter_ns(), **value}
        self.report["memory_samples"].append(value)
        if guard and (value.get("current_rss_bytes") is None or value.get("peak_rss_bytes") is None):
            self.report["memory_guard_failed"] = True
            raise RuntimeError("GC试验的OS内存指标不可用。")
        if guard and value["current_rss_bytes"] > self.RSS_LIMIT:
            self.report["memory_guard_failed"] = True
            raise RuntimeError("GC试验Client当前RSS超出256MiB保护线。")

    @contextmanager
    def installed(self):
        global _gc_trial_used
        from secure_control.execution.lan_runtime import LanSegmentedRuntime, _OnlineResourcePool

        if (self.policy not in ("baseline", "startup-freeze") or _gc_trial_used
                or current_thread() is not main_thread() or active_count() != 1
                or mp.current_process().name != "MainProcess"
                or not gc.isenabled() or gc.get_freeze_count() or gc.get_debug() or gc.callbacks):
            raise RuntimeError("GC试验仅允许无外部GC策略的独占Client主进程一次运行。")
        _gc_trial_used = True
        self.before = self.snapshot("before_cold_collect")
        original_init, original_close = _OnlineResourcePool.__init__, _OnlineResourcePool.close
        runtime_close = LanSegmentedRuntime.close

        def initialized(pool, *args, **kwargs):
            if self.report["cleanup_errors"]:
                raise RuntimeError("GC试验清理失败后不得再创建材料池。")
            try:
                return original_init(pool, *args, **kwargs)
            finally:
                thread = getattr(pool, "_thread", None)
                if thread is not None:
                    self.producers.append(thread)

        def closed(pool):
            previous_error = sys.exception()
            try:
                return original_close(pool)
            except Exception as error:  # 清理仅公开类别，不能覆盖原控制失败
                self.report["cleanup_errors"].append(type(error).__name__)
                if not self.final_cleanup and previous_error is None:
                    # 段界close失败必须交给原runner停止，不能静默进入新段/建池。
                    raise

        def close_runtime(runtime):
            if self.control_started and not self.control_ended:
                self.control_ended = True
                try:
                    self.memory("control_end", guard=True)
                except RuntimeError:
                    pass  # 已记录保护失败；仍须原close，且不能替换原控制错误。
                self.snapshot("control_end")
            previous, self.final_cleanup = self.final_cleanup, True
            try:
                return runtime_close(runtime)
            finally:
                self.final_cleanup = previous

        try:
            self.memory("before_cold_collect", guard=True)
            started = time.perf_counter_ns()
            collected = gc.collect(2)
            self.report["cold_collect"] = {"duration_ns": time.perf_counter_ns() - started,
                                           "collected": collected}
            self.memory("after_cold_collect", guard=True)
            self.snapshot("after_cold_collect")
            count_before = gc.get_freeze_count()
            started = time.perf_counter_ns()
            if self.policy == "startup-freeze":
                gc.freeze()
                self.owns_freeze = True
            self.report["freeze"] = {"duration_ns": time.perf_counter_ns() - started,
                                     "before_count": count_before, "after_count": gc.get_freeze_count()}
            self.snapshot("after_policy")
            with (patch.object(_OnlineResourcePool, "__init__", initialized),
                  patch.object(_OnlineResourcePool, "close", closed),
                  patch.object(LanSegmentedRuntime, "close", close_runtime)):
                try:
                    yield self
                finally:
                    # 内层探针必须先还原其前驱，再退出本层GC/close owner。
                    try:
                        self.cleanup.close()
                    except Exception as error:  # noqa: BLE001 - 清理不覆盖原控制异常
                        self.report["cleanup_errors"].append(type(error).__name__)
        finally:
            # 原池先完成5秒join；即使join失败也先解冻自有永久代，但不再主动收集。
            try:
                self.cleanup.close()
            except Exception as error:  # noqa: BLE001 - 仅释放自有初始化钩子，保留原异常
                self.report["cleanup_errors"].append(type(error).__name__)
            self.snapshot("before_restore")
            exited = all(not thread.is_alive() for thread in self.producers)
            self.report["producer_count"] = len(self.producers)
            self.report["producers_exited"] = exited
            if not exited:
                self.report["cleanup_errors"].append("producer_not_exited")
            try:
                if self.owns_freeze:
                    gc.unfreeze()
                    self.owns_freeze = False
                if (gc.isenabled() != self.before["enabled"]
                        or list(gc.get_threshold()) != self.before["threshold"]
                        or gc.get_debug() != self.before["debug"] or gc.callbacks):
                    self.report["cleanup_errors"].append("unexpected_gc_state")
                gc.set_threshold(*self.before["threshold"])
                gc.set_debug(self.before["debug"])
                gc.enable() if self.before["enabled"] else gc.disable()
                if exited:
                    started = time.perf_counter_ns()
                    collected = gc.collect(2)
                    self.report["shutdown_collect"] = {
                        "duration_ns": time.perf_counter_ns() - started, "collected": collected}
            except Exception as error:  # noqa: BLE001 - finally不能替换原始错误
                self.report["cleanup_errors"].append(type(error).__name__)
            after = self.snapshot("after_restore")
            self.report["restored"] = (after["freeze_count"] == self.before["freeze_count"]
                and after["enabled"] == self.before["enabled"]
                and after["threshold"] == self.before["threshold"]
                and after["debug"] == self.before["debug"] and not gc.callbacks)
            self.memory("after_restore")
            self.report["cleanup_failed"] = bool(self.report["cleanup_errors"]) or not self.report["restored"]


def run_continuous_observation(*, steps: int, delay_ms: float,
                               segment_steps: int, optimized=False, material_slots=16,
                               role_config: Path | None = None, preload_steps=0,
                               preload_execution="fused", diagnostic=False,
                               recording_mode="full", tcp_nodelay=None,
                               commit_policy="default", gc_trial_policy=None, timeout_trace=False,
                               material_candidate=None, worker_timeout_diagnostic=False,
                               worker_long_run=False, worker_wait_diagnostic=False,
                               server_gc_candidate=False, stage_wait_diagnostic=False,
                               compact_history_candidate=False, qpc_stage_receive_candidate=False,
                               qpc_dynamic_qualification=False) -> dict[str, object]:
    # 所有试验参数在任何端口/角色/材料创建前拒绝；默认入口走原路径。
    options = {"steps": steps, "delay_ms": delay_ms, "segment_steps": segment_steps,
               "optimized": optimized, "material_slots": material_slots, "role_config": role_config,
               "preload_steps": preload_steps, "preload_execution": preload_execution,
               "diagnostic": diagnostic, "recording_mode": recording_mode,
                   "tcp_nodelay": tcp_nodelay, "commit_policy": commit_policy,
                   "timeout_trace": timeout_trace}
    if type(server_gc_candidate) is not bool:
        raise ValueError("S11候选选择必须为严格bool。")
    if type(stage_wait_diagnostic) is not bool:
        raise ValueError("S12定位选择必须为严格bool。")
    if type(compact_history_candidate) is not bool:
        raise ValueError("S13候选选择必须为严格bool。")
    if type(qpc_stage_receive_candidate) is not bool:
        raise ValueError("S15候选选择必须为严格bool。")
    if type(qpc_dynamic_qualification) is not bool:
        raise ValueError("QPC动态资格选择必须为严格bool。")
    if qpc_stage_receive_candidate or qpc_dynamic_qualification:
        if (optimized is not True or recording_mode != "light" or diagnostic is not False
                or qpc_stage_receive_candidate and qpc_dynamic_qualification
                or any(v is not False for v in (server_gc_candidate, stage_wait_diagnostic, compact_history_candidate,
                    worker_long_run, worker_timeout_diagnostic, worker_wait_diagnostic, timeout_trace))
                or material_candidate is not None or gc_trial_policy is not None
                or type(steps) is not int or not (steps == 10000 if qpc_dynamic_qualification else 1 <= steps <= 1000)
                or type(segment_steps) is not int or segment_steps != 400
                or type(material_slots) is not int or material_slots != 16
                or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
                or type(delay_ms) not in (int, float) or delay_ms != 0 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default"
                or not gc.isenabled() or gc.get_threshold() != (700, 10, 10)
                or gc.get_freeze_count() or gc.get_debug() or gc.callbacks):
            raise ValueError("QPC接收仅允许独立正常GC的本机worker/cycle/batch/light/400段/16库存；S15为1..1000，资格固定10000。")
        if qpc_dynamic_qualification:
            layouts = [_CompactHistory.layout(role, steps, qualification=True) for role in ("Client", "P1", "P2")]
            if sum(v["reserved_bound_bytes"] for v in layouts) > 48*1024*1024:
                raise ValueError("资格合并历史超过48MiB。")
        selector = "qpc_dynamic_qualification" if qpc_dynamic_qualification else "qpc_stage_receive_candidate"
        return _run_material_comparison({**options, selector: True}, "worker", target_steps=steps)
    if server_gc_candidate or stage_wait_diagnostic or compact_history_candidate:
        if (optimized is not True or recording_mode != "light" or diagnostic is not False
                or sum((server_gc_candidate, stage_wait_diagnostic, compact_history_candidate)) != 1
                or worker_long_run is not False or worker_timeout_diagnostic is not False
                or worker_wait_diagnostic is not False or material_candidate is not None
                or gc_trial_policy is not None or timeout_trace is not False
                or type(steps) is not int or steps != 4000
                or type(segment_steps) is not int or segment_steps != 400
                or type(material_slots) is not int or material_slots != 16
                or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
                or type(delay_ms) not in (int, float) or delay_ms != 0 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default"
                or not gc.isenabled() or gc.get_threshold() != (700, 10, 10)
                or gc.get_freeze_count() or gc.get_debug() or gc.callbacks):
            raise ValueError("S11/S12只允许独立正常GC的worker/cycle/batch/light/4000/400/16/无预送/默认通信。")
        selector = ("compact_history_candidate" if compact_history_candidate else
                    "stage_wait_diagnostic" if stage_wait_diagnostic else "server_gc_candidate")
        return _run_material_comparison({**options, selector: True}, "worker", target_steps=4000)
    if type(worker_wait_diagnostic) is not bool:
        raise ValueError("S10诊断选择必须为严格bool。")
    if worker_wait_diagnostic:
        if (optimized is not True or recording_mode != "light" or diagnostic is not False
                or worker_long_run is not False or worker_timeout_diagnostic is not False
                or material_candidate is not None or gc_trial_policy is not None or timeout_trace is not False
                or type(steps) is not int or steps != 4000
                or type(segment_steps) is not int or segment_steps != 400
                or type(material_slots) is not int or material_slots != 16
                or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
                or type(delay_ms) not in (int, float) or delay_ms != 0 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default"
                or not gc.isenabled() or gc.get_freeze_count() or gc.callbacks or gc.get_debug()
                or gc.get_threshold() != (700, 10, 10)):
            raise ValueError("S10只允许独立正常GC的worker/cycle/batch/light/4000/400/16/无预送/默认通信。")
        return _run_material_comparison({**options, "diagnostic": True, "timeout_trace": True,
                                        "worker_wait_diagnostic": True}, "worker", target_steps=4000)
    if type(worker_long_run) is not bool:
        raise ValueError("worker长期选择必须为严格bool。")
    if worker_long_run:
        if (optimized is not True or recording_mode != "light" or diagnostic is not False
                or worker_timeout_diagnostic is not False or material_candidate is not None
                or gc_trial_policy is not None or timeout_trace is not False
                or type(steps) is not int or steps != 10000
                or type(segment_steps) is not int or segment_steps != 400
                or type(material_slots) is not int or material_slots != 16
                or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
                or type(delay_ms) not in (int, float) or delay_ms != 0 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default"
                or not gc.isenabled() or gc.get_freeze_count() or gc.callbacks or gc.get_debug()
                or gc.get_threshold() != (700, 10, 10)):
            raise ValueError("S9只允许正常GC的worker/cycle/batch/light/10000/400/16/无预送/默认通信。")
        return _run_material_comparison(options, "worker", target_steps=10000)
    if type(worker_timeout_diagnostic) is not bool:
        raise ValueError("S6诊断选择必须为严格bool。")
    if worker_timeout_diagnostic:
        if (optimized is not True or recording_mode != "light" or diagnostic is not False
                or gc_trial_policy is not None or timeout_trace is not False or material_candidate is not None
                or type(steps) is not int or steps != 20
                or type(segment_steps) is not int or segment_steps != 400
                or type(material_slots) is not int or material_slots != 16
                or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
                or type(delay_ms) not in (int, float) or delay_ms != 0 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default"
                or not gc.isenabled() or gc.get_freeze_count() or gc.callbacks or gc.get_debug()
                or gc.get_threshold() != (700, 10, 10)):
            raise ValueError("S6只允许正常GC的worker/cycle/batch/light/20/400/16/无预送/默认通信独立诊断。")
        return _run_material_comparison({**options, "diagnostic": True, "timeout_trace": True,
                                        "worker_timeout_diagnostic": True}, "worker")
    if type(timeout_trace) is not bool or timeout_trace and gc_trial_policy not in ("baseline", "startup-freeze"):
        raise ValueError("timeout_trace仅支持显式baseline或startup-freeze。")
    if material_candidate is not None:
        if (material_candidate not in ("thread", "worker") or optimized is not True
                or recording_mode != "light" or diagnostic is not False or gc_trial_policy is not None
                or timeout_trace or type(steps) is not int or steps != 1000
                or type(segment_steps) is not int or segment_steps != 400
                or type(material_slots) is not int or material_slots != 16
                or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
                or type(delay_ms) not in (int, float) or delay_ms != 0 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default"
                or not gc.isenabled() or gc.get_freeze_count() or gc.callbacks or gc.get_debug()
                or gc.get_threshold() != (700, 10, 10)):
            raise ValueError("S5仅允许正常GC的cycle/batch/light/1000/400/16/无预送/默认通信两模式")
        return _run_material_comparison(options, material_candidate)
    if gc_trial_policy is None:
        return _run_continuous_observation(**options)
    if (type(gc_trial_policy) is not str or gc_trial_policy not in ("baseline", "startup-freeze")
            or optimized is not True or diagnostic is not True or recording_mode != "light"
            or type(steps) is not int or steps != (200 if timeout_trace else 1000)
            or type(material_slots) is not int or material_slots != 16
            or type(preload_steps) is not int or preload_steps != 0 or preload_execution != "fused"
            or type(segment_steps) is not int or segment_steps != 400
            or type(delay_ms) not in (int, float) or delay_ms != 0
            or role_config is not None or tcp_nodelay is not None or commit_policy != "default"):
        raise ValueError("GC限定试验只允许cycle/batch/light/diagnostic/无trace1000或trace200/400/16/无预送/零延迟/默认通信。")
    # 固定依赖先导入，再进入冷GC边界；不预建试验对象。
    from secure_control.execution.lan_runtime import RunControl  # noqa: F401
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession  # noqa: F401

    from .cart_pole_segmented_evidence import _BatchWriter, _Spool  # noqa: F401
    from .lan_continuous_profile import load_segmented_experiment  # noqa: F401
    from .lan_runner import _run_prepared_segmented  # noqa: F401

    trial = _StartupGCTrial(gc_trial_policy)
    try:
        with trial.installed():
            report = _run_continuous_observation(**options, _gc_trial=trial)
    except Exception as error:  # noqa: BLE001 - 异常也留存公开恢复事实，不透传载荷
        report = {"schema": "cycle-qualification-v1", "case": "cycle", "mode": "batch",
                  "status": "failed", "failure_category": type(error).__name__,
                  "requested_steps": steps, "cycles": [], "cycle_timing": {"p50_ms": None},
                  "qualification_pass": False, "stage_pass": False, "diagnostic": True,
                  "code_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=_ROOT, text=True).strip(),
                  "source_sha256": _source_fingerprints()}
    report.update(gc_trial=trial.report, diagnostic=True, comparison_only=True,
                  qualification_pass=False, stage_pass=False)
    if timeout_trace:
        report.setdefault("timeout_trace", {"format_version": 1, "diagnostic_missing": True,
                                           "first_failure_observed_ns": None})
    if trial.report.get("cleanup_failed") and report["status"] == "stopped":
        report.update(status="failed", failure_category="GCTrialCleanup", failed_phase="GC_RESTORE")
    if trial.report["memory_guard_failed"] and report["status"] == "stopped":
        report.update(status="failed", failure_category="GCTrialMemory", failed_phase="MEMORY_SAMPLE")
    combined = {"diagnostic_report": report.get("diagnostic_report"), "gc_trial": trial.report}
    if timeout_trace:
        combined["timeout_trace"] = report.get("timeout_trace")
    trial.report["combined_encoded_bytes"] = 0
    trial.report["combined_encoded_limit"] = 256 * 1024
    for _ in range(3):
        trial.report["combined_encoded_bytes"] = len(json.dumps(
            combined, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    if trial.report["combined_encoded_bytes"] > 256 * 1024:
        report.update(status="failed", failure_category="DiagnosticBudget", stage_pass=False)
    return report


def _material_run_gate(result, report, candidate, target_steps, *, strict=False, numeric_key="worker_long_run",
                       expected_resources=None):
    """复用S5材料/周期门禁；长期样本还须有全分母、身份链与双方确认。"""
    material = result.get("material_summary") or {}
    cycles = result.get("cycles", [])
    try:
        complete = (candidate == "worker" and result["status"] == "stopped"
            and len(cycles) == target_steps and result.get("cycle_summary", {}).get("misses") == 0
            and all(row["status"] == "confirmed" and row["global_step"] == step
                    and row["segment_index"] == step // 400 and row["cycle_completed_ns"] is not None
                    and row["cycle_completed_ns"] < row["deadline_ns"]
                    for step, row in enumerate(cycles))
            and len({row["session_id"] for row in cycles}) == 1
            and len({row["controller_epoch"] for row in cycles}) == 1
            and result.get("protocol_committed_count") == target_steps
            and result.get("physically_confirmed_count") == target_steps
            and material.get("claimed") == target_steps and material.get("generated_received", 0) >= target_steps
            and material.get("inventory_inflight_high_water", 17) <= 16
            and material.get("material_encoded_bound_high_water", 8 * 1024 * 1024 + 1) <= 8 * 1024 * 1024
            and material.get("error_type") is None and (material.get("worker") or {}).get("error_type") is None
            and material.get("worker_exited") is True and material.get("receiver_exited") is True
            and material.get("credit_thread_exited") is True and material.get("cleanup_failed") is False
            and not report["memory_guard_failed"] and not report["cleanup_failed"])
        if not complete or not strict:
            return complete
        if (result.get("requested_steps") != target_steps or result.get("successful_steps") != target_steps
                or result.get("failed_attempts") != 0 or result["cycle_summary"].get("attempts") != target_steps
                or result.get("failure_category") is not None or result.get("failed_phase") is not None
                or result.get("resource_counts") != (expected_resources if expected_resources is not None else
                    {"products_consumed": 30 * target_steps, "truncations_consumed": 4 * target_steps})
                or len({row["round_id"] for row in cycles}) != target_steps
                or len({row["run_id"] for row in cycles}) != 1
                or material["worker"].get("memory_guard_failed") is not False
                or report.get("producer_exited") is not True):
            return False
        numeric = result[numeric_key]["numeric_contract"]
        if (numeric["mode"] != "bounded_input_reachability" or numeric["horizon_steps"] is not None
                or numeric["proof_algorithm"] != "encoded-block-power-rational-v1"):
            return False
        first = cycles[0]
        for step, row in enumerate(cycles):
            if (any(not isinstance(row[key], str) or not row[key] for key in
                    ("run_id", "session_id", "controller_epoch", "round_id"))
                    or row["period_ns"] != 20000000
                    or row["scheduled_start_ns"] != first["scheduled_start_ns"] + step * 20000000
                    or row["deadline_ns"] != row["scheduled_start_ns"] + 20000000
                    or not row["scheduled_start_ns"] <= row["actual_sample_start_ns"]
                        <= row["device_completed_ns"] <= row["bookkeeping_completed_ns"]
                        <= row["cycle_completed_ns"] < row["deadline_ns"]
                    or row["protocol_committed_count"] != step + 1
                    or row["physically_confirmed_count"] != step + 1
                    or row.get("failure_phase") is not None):
                return False
        parties = result["party_outcomes"]
        if len(parties) != 2 or {party["role"] for party in parties} != {"P1", "P2"}:
            return False
        for party in parties:
            if (party["status"] != "closed" or len(party["steps"]) != target_steps
                    or any(row["step"] != step or row["round_id"] != cycles[step]["round_id"]
                           for step, row in enumerate(party["steps"]))):
                return False
        last, commit = cycles[-1], result["last_commit_observation"]
        return (all(commit[key] == last[key] for key in ("run_id", "session_id", "controller_epoch",
                                                       "round_id", "global_step"))
                and commit["step"] == target_steps - 1
                and set(commit["parties"]) == {"P1", "P2"}
                and all(p["request_state"] == "sent" and p["valid_ack_received"] is True
                        for p in commit["parties"].values()))
    except (KeyError, TypeError, ValueError, IndexError):
        # 缺失或畸形公开证据拒绝门禁，仍保留原失败结果供导出。
        return False


def _server_gc_run_gate(result, report):
    """有限4000候选独立门禁；运行gen2覆盖单独判断，不授予原长期资格。"""
    if not _material_run_gate(result, report, "worker", 4000, strict=True, numeric_key="server_gc_candidate"):
        return False
    try:
        metadata = result["server_gc_candidate"]
        if (metadata["observation_failed"] or metadata["budget_failed"]
                or result.get("diagnostic") is not False or result.get("diagnostic_report") is not None
                or result.get("timeout_trace") is not None):
            return False
        for row in result["cycles"]:
            if any(type(row[k]) is not int for k in ("global_step", "segment_index", "period_ns",
                    "scheduled_start_ns", "actual_sample_start_ns", "deadline_ns", "device_completed_ns",
                    "bookkeeping_completed_ns", "cycle_completed_ns", "protocol_committed_count", "physically_confirmed_count")):
                return False
        if any(type(result[k]) is not int for k in ("requested_steps", "successful_steps", "failed_attempts",
                "protocol_committed_count", "physically_confirmed_count")):
            return False
        if any(type(result["cycle_summary"][k]) is not int for k in ("attempts", "misses")):
            return False
        material = result["material_summary"]
        if any(type(material[k]) is not int or material[k] < 0 for k in
               ("claimed", "generated_received", "inventory_inflight_high_water", "material_encoded_bound_high_water")):
            return False
        numeric = metadata["numeric_contract"]
        if any(type(numeric[k]) is not int or numeric[k] != v for k, v in
               (("block_steps", 19), ("parameter_bits", 40), ("runtime_payload_bits", 46))):
            return False
        boundaries = [r for r in result["cycles"] if "maintenance" in r.get("phase_durations_ns", {})]
        if ([r["global_step"] for r in boundaries] != list(range(399, 3999, 400))
                or any(type(r["phase_durations_ns"]["maintenance"]) is not int
                       or r["phase_durations_ns"]["maintenance"] < 0 for r in boundaries)):
            return False
        roles = metadata["roles"]
        if len(roles) != 2 or {role["role"] for role in roles} != {"P1", "P2"}:
            return False
        for role in roles:
            if (role["startup_attempted"] is not True or role["startup_collect"]["completed"] is not True
                    or role["startup_collect"]["error_type"] is not None
                    or role["normal_stop_ack_sent"] is not True):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def _finish_server_gc(result, report, metadata):
    """退出后统一编码轻量公开证据；附加失败不覆盖原控制首错/全分母。"""
    roles = [party.pop("server_gc") for party in result.get("party_outcomes", []) if "server_gc" in party]
    metadata.update(roles=roles, actual_attempts=len(result.get("cycles", [])),
        failed_attempts=result.get("failed_attempts"), invocation_budget_consumed=True,
        encoded_limit=96 * 1024, encoded_bytes=0, budget_failed=False,
        observation_failed=False, runtime_gen2_covered=False)
    def normal(state):
        return (isinstance(state, dict) and state.get("enabled") is True and state.get("threshold") == [700, 10, 10]
                and state.get("freeze_count") == 0 and state.get("debug") == 0)
    metadata["observation_failed"] = (len(roles) != 2
        or any(not isinstance(r, dict) for r in roles)
        or {r.get("role") for r in roles} != {"P1", "P2"}
        or any(r.get("error_type") is not None or r.get("callback_and_hook_restored") is not True
            or r.get("budget_failed") is not False or not normal(r.get("gc_before"))
            or not normal(r.get("gc_after")) for r in roles))
    cycles = result.get("cycles", [])
    window = None
    if cycles:
        try:
            window = (cycles[0]["scheduled_start_ns"], cycles[-1].get("cycle_completed_ns") or cycles[-1]["deadline_ns"])
        except (KeyError, TypeError):
            metadata["observation_failed"] = True
    coverage = {}
    for role in roles:
        try:
            retained = sum(window is not None and window[0] <= e[0] <= e[1] <= window[1]
                           for e in role["events"])
            coverage[role["role"]] = {"retained_complete_in_control_window": retained,
                "covered": bool(retained and not role["pending"] and not role["unpaired_count"]
                                and not role["evicted_count"] and not role["encoded_omitted"])}
        except (KeyError, TypeError, ValueError, IndexError):
            metadata["observation_failed"] = True
    metadata.update(runtime_gen2_coverage=coverage,
        runtime_gen2_covered=set(coverage) == {"P1", "P2"} and all(r["covered"] for r in coverage.values()),
        control_window_ns=window, scope="finite candidate; runtime gen2 coverage separately reported; not long-run qualification")
    for _ in range(3):
        metadata["encoded_bytes"] = len(json.dumps(metadata, separators=(",", ":"), allow_nan=False).encode())
    if metadata["encoded_bytes"] > metadata["encoded_limit"]:
        metadata["budget_failed"] = True
        for role in roles:
            if isinstance(role, dict):
                role["encoded_omitted"] = role.get("encoded_omitted", 0) + len(role.get("events", []))
                role["events"] = []
        metadata["runtime_gen2_covered"] = False
        for value in coverage.values():
            value.update(covered=False, retained_complete_in_control_window=0)
        for _ in range(3):
            metadata["encoded_bytes"] = len(json.dumps(metadata, separators=(",", ":"), allow_nan=False).encode())
    result.update(server_gc_candidate=metadata, diagnostic=False, diagnostic_report=None, timeout_trace=None,
                  candidate_gate_pass=False, worker_long_run_gate_pass=False)
    if result["status"] == "stopped" and (metadata["observation_failed"] or metadata["budget_failed"]):
        result.update(status="failed", failure_category="ServerGCObservation", failed_phase="GC_OBSERVATION")
    result["server_gc_candidate_gate_pass"] = _server_gc_run_gate(result, report)


def _finish_stage_wait(result, report, metadata, observers):
    """阶段定位仅判公开证据/复现，不调用S11候选或原长期资格门禁。"""
    roles = []
    for observer in observers:
        try:
            roles.append(observer.report())
        except Exception as error:  # noqa: BLE001 - 结果编码失败也不覆盖原控制首错
            roles.append({"role": observer.role, "observation_error_type": observer.error_type(error)})
    roles.extend(p.pop("stage_wait") for p in result.get("party_outcomes", []) if "stage_wait" in p)
    metadata.update(roles=roles, actual_attempts=len(result.get("cycles", [])), failed_attempts=result.get("failed_attempts"),
        invocation_budget_consumed=True, encoded_limit=192*1024, encoded_bytes=0, budget_failed=False,
        evidence_complete=False, control_failure_observed=bool(result.get("failed_attempts")),
        first_io_error_observed=any(r.get("first_failure") is not None for r in roles))
    def complete(role):
        observation = role.get("gc") or {}
        def normal(state):
            return (isinstance(state, dict) and state.get("enabled") is True and state.get("threshold") == [700, 10, 10]
                    and state.get("freeze_count") == 0 and state.get("debug") == 0)
        return (role.get("hooks_restored") is True and role.get("observation_error_type") is None
            and role.get("format_version") == 1 and role.get("profile") == (
                metadata.get("profile", "stage-wait-light-v1") if role.get("role") == "Client" else "stage-wait-light-v1")
            and role.get("budget_failed") is False and observation.get("error_type") is None
            and observation.get("callback_and_hook_restored") is True and observation.get("budget_failed") is False
            and normal(observation.get("gc_before")) and normal(observation.get("gc_after"))
            and observation.get("pending") is None and observation.get("unpaired_count") == 0
            and observation.get("evicted_count") == 0 and observation.get("encoded_omitted") == 0
            and (role.get("role") == "Client" or (observation.get("startup_collect") or {}).get("completed") is True)
            and (role.get("first_failure") is None or role["first_failure"][11] is not None))
    material = result.get("material_summary") or {}
    metadata["evidence_complete"] = (len(roles) == 3 and {r.get("role") for r in roles} == {"Client", "P1", "P2"}
        and all(complete(r) for r in roles) and not report["cleanup_failed"] and not report["memory_guard_failed"]
        and report.get("producer_exited") is True and material.get("cleanup_failed") is False
        and all(material.get(key) is True for key in ("worker_exited", "receiver_exited", "credit_thread_exited"))
        and (material.get("worker") or {}).get("memory_guard_failed") is False
        and (result.get("failure_category") not in {"LocalhostTransportTimeout", "LocalhostTransportDisconnected"}
             or metadata["first_io_error_observed"]))
    descriptor = {"profile": metadata.get("profile", "stage-wait-light-v1"), "roles_location": "stage_wait_diagnostic.roles",
                  "scope": ("canonical QPC receive; all Client cycle replies, original first I/O and GC" if
                    metadata.get("profile") == "canonical-qpc-receive-v1" else
                    "S15 nonblocking stage receive/select QPC; first I/O and original GC" if
                    metadata.get("profile") == "qpc-stage-receive-v1" else "stage and first I/O error; no S10 heavy probes")}
    def size():
        for _ in range(3):
            metadata["encoded_bytes"] = len(json.dumps({"stage_wait_diagnostic": metadata,
                "diagnostic_report": descriptor}, separators=(",", ":"), allow_nan=False).encode())
    size()
    if metadata["encoded_bytes"] > metadata["encoded_limit"]:
        metadata.update(budget_failed=True, evidence_complete=False)
        for role in roles:
            role["encoded_omitted"] = role.get("encoded_omitted", 0) + len(role.get("events", []))
            role["events"] = []
            # 普通事件去除后同时移除无引用身份，首错/外层错/在途引用原样重映射。
            old_contexts, contexts = role.get("contexts", []), []
            def packed(row, old_contexts=old_contexts, contexts=contexts, context_index=9):
                if row is None:
                    return None
                row = list(row)
                if row[context_index] is not None:
                    context = old_contexts[row[context_index]]
                    if context not in contexts:
                        contexts.append(context)
                    row[context_index] = contexts.index(context)
                return row
            role.update(first_failure=packed(role.get("first_failure")), outer_failure=packed(role.get("outer_failure")),
                        in_flight=[packed(row) for row in role.get("in_flight", [])], contexts=contexts)
            if role.get("qpc_receive") is not None:
                receive = role["qpc_receive"]
                receive.update(events=[packed(row, context_index=5) for row in receive["events"]],
                    first_anomaly=packed(receive["first_anomaly"], context_index=5),
                    first_exception=packed(receive["first_exception"], context_index=5))
            for _ in range(3):
                role["encoded_bytes"] = len(json.dumps(role, separators=(",", ":"), allow_nan=False).encode())
        size()
    result.update(stage_wait_diagnostic=metadata, diagnostic=True,
        diagnostic_report=descriptor,
        timeout_trace=None, comparison_only=True, server_gc_candidate_gate_pass=False,
        candidate_gate_pass=False, worker_long_run_gate_pass=False, stage_pass=False, qualification_pass=False)
    if result["status"] == "stopped" and not metadata["evidence_complete"]:
        result.update(status="failed", failure_category="StageWaitObservation", failed_phase="DIAGNOSTIC_REPORT")


def _compact_sample_pass(result, report, metadata, *, target_steps=4000):
    """复用原身份/材料检查；独立补充本候选的数值、维护和观察完整性。"""
    matrix = result.get("wire_profile") == "control-dynamic-matrix-v1"
    expected = ({"matrix_products_consumed": target_steps, "scalar_equivalent_products": 30*target_steps,
                 "multiplication_material_elements": 41*target_steps, "truncations_consumed": 4*target_steps}
                if matrix else None)
    if not (metadata["representation_complete"] and metadata["thread_registration_complete"]
            and (result.get("stage_wait_diagnostic") or {}).get("evidence_complete") is True
            and (not matrix or result.get("schema") == "matrix-dynamic-evidence-v1")
            and _material_run_gate(result, report, "worker", target_steps, strict=True,
                                  numeric_key="stage_wait_diagnostic", expected_resources=expected)):
        return False
    numeric = metadata["numeric_contract"] or {}
    if any(numeric.get(k) != v for k, v in (("block_steps", 19), ("parameter_bits", 40), ("runtime_payload_bits", 46))):
        return False
    if result.get("numeric_profile") != {"fractional_bits": 32, "security_parameter": 80, "period_s": .02,
            "modulus_bits": 256, "state_dimension": 4, "input_dimension": 2, "output_dimension": 1}:
        return False
    integer_fields = ("global_step", "segment_index", "period_ns", "scheduled_start_ns", "actual_sample_start_ns",
        "deadline_ns", "device_completed_ns", "bookkeeping_completed_ns", "cycle_completed_ns",
        "protocol_committed_count", "physically_confirmed_count")
    if any(type(row.get(k)) is not int or row[k] < 0 for row in result["cycles"] for k in integer_fields):
        return False
    if any(type(result.get(k)) is not int for k in ("requested_steps", "successful_steps", "failed_attempts",
            "protocol_committed_count", "physically_confirmed_count")):
        return False
    if any(type(result["cycle_summary"].get(k)) is not int for k in ("attempts", "misses")):
        return False
    rows = result.get("steps", [])
    if len(rows) != target_steps or any(r.get("status") != "confirmed" or r.get("global_step") != step
            or r.get("session_id") != result["cycles"][step]["session_id"]
            or r.get("round_id") != result["cycles"][step]["round_id"] for step, r in enumerate(rows)):
        return False
    for role in metadata["roles"]:
        if role["tables"]["steps"]["captured"] != target_steps or role["tables"]["steps"]["expanded"] != target_steps:
            return False
        if role["role"] == "Client" and (role["tables"]["cycles"]["captured"] != target_steps
                                         or role["tables"]["cycles"]["expanded"] != target_steps):
            return False
    maintenance = [r for r in result["cycles"] if "maintenance" in r.get("phase_durations_ns", {})]
    return ({r["global_step"] for r in maintenance} == set(range(399, target_steps-1, 400))
        and all(type(r["phase_durations_ns"]["maintenance"]) is int and r["phase_durations_ns"]["maintenance"] >= 0
                for r in maintenance)
        and all((r.get("gc") or {}).get("normal_stop_ack_sent") is True
                for r in result["stage_wait_diagnostic"]["roles"] if r.get("role") in ("P1", "P2")))


def _compact_gc_boundary(cycles, roles):
    """只用实际观察出口；保护检查到STOPPING间隙不冒充精确控制结束。"""
    client = next((r for r in roles if r.get("role") == "Client"), {})
    observed = client.get("control_observation") or {}
    start = cycles[0].get("scheduled_start_ns") if cycles else None
    step, end, stop = (observed.get(k) for k in
        ("last_confirmed_step", "last_confirmed_return_qpc_ns", "normal_stop_start_qpc_ns"))
    def stamp(value):
        return type(value) is int and value >= 0
    row = next((c for c in reversed(cycles) if c.get("global_step") == step), {}) if type(step) is int else {}
    control = next((t for t in client.get("threads", []) if t.get("thread_role") == "control"), {})
    life_end = control.get("observation_end_qpc_ns")
    valid = (stamp(start) and stamp(end) and stamp(life_end) and start <= end <= life_end
        and row.get("status") in {"confirmed", "miss_after_apply"}
        and stamp(row.get("scheduled_start_ns")) and start <= row["scheduled_start_ns"] <= end
        and (row.get("cycle_completed_ns") is None or
             stamp(row["cycle_completed_ns"]) and row["cycle_completed_ns"] <= end)
        and (stop is None or stamp(stop) and end <= stop <= life_end))
    return {"classification_version": 2, "start_qpc_ns": start, "last_confirmed_step": step,
        "confirmed_observation_end_qpc_ns": end, "normal_stop_start_qpc_ns": stop,
        "control_boundary_valid": bool(valid),
        "normal_stop_boundary_valid": bool(valid and stop is not None),
        "failure_extension": "none; failed I/O and cleanup do not extend the confirmed observation",
        "scope": "local QPC; post-callback guard to STOPPING is unknown; no deadline fallback"}


def _finish_compact_history(result, report, history, *, qpc_stage_receive_candidate=False,
                            qpc_dynamic_qualification=False, network_observation=False):
    """S13完整展开与有限样本检查独立记账，绝不借用原资格flag。"""
    if history is not None and history.expansion_ns is None:
        expanded = history.expand()
        if "steps" not in result:
            result.update(steps=expanded["steps"], events=expanded["events"], cycles=expanded["cycles"])
            if any(expanded.values()):
                history.error_type = history.error_type or "HistoryControlResultMissing"
    roles = [history.report()] if history is not None else []
    roles.extend(p.pop("compact_history") for p in result.get("party_outcomes", []) if "compact_history" in p)
    cycles = result.get("cycles", [])
    attempts = (result.get("cycle_summary") or {}).get("attempts", len(cycles))
    stage = result.get("stage_wait_diagnostic") or {}
    target = (result.get("requested_steps", 1000) if network_observation else
              10000 if qpc_dynamic_qualification else result.get("requested_steps", 1000) if qpc_stage_receive_candidate else 4000)
    large_history = qpc_dynamic_qualification or network_observation and target == 10000
    meta = {"format_version": 1, "target_steps": target, "maximum_attempts": (10000 if qpc_dynamic_qualification else
        1000 if qpc_stage_receive_candidate else 4000),
        "first_failure_stop": True, "actual_attempts": attempts, "captured_cycles": len(cycles),
        "failed_attempts": result.get("failed_attempts"), "invocation_budget_consumed": True,
        "field_codec": "checked-u64-binary64-utf8-presence-v1",
        "equivalence_validation": "software same-input oracle; runtime checked complete rows and expansion",
        "role_limit_bytes": 16*1024*1024, "combined_limit_bytes": 48*1024*1024, "roles": roles,
        "numeric_contract": stage.get("numeric_contract"), "representation_complete": False,
        "finite_sample_pass": False, "thread_registration_complete": False,
        "runtime_gen2_coverage": {}, "gc_thread_matches": []}
    meta["combined_reserved_bound_bytes"] = sum((r.get("layout") or {}).get("reserved_bound_bytes", 0) for r in roles)
    if qpc_stage_receive_candidate or qpc_dynamic_qualification:
        meta.update(profile="canonical-qpc-receive-v1" if qpc_dynamic_qualification else "qpc-stage-receive-v1",
                    qpc_receive_location="stage_wait_diagnostic.roles[Client].qpc_receive")
    if network_observation:
        meta.update(profile="network-cycle-v1", maximum_attempts=target)
    if large_history:
        meta["client_role_limit_bytes"] = 32*1024*1024
    meta["representation_complete"] = (len(roles) == 3 and {r.get("role") for r in roles} == {"Client", "P1", "P2"}
        and all(r.get("representation_complete") is True and r.get("layout", {}).get("reserved_bound_bytes", 2**63)
                <= (32 if large_history and r.get("role") == "Client" else 16)*1024*1024
                for r in roles) and meta["combined_reserved_bound_bytes"] <= 48*1024*1024
        and len(cycles) == attempts)
    meta["thread_registration_complete"] = len(roles) == 3 and all(
        {t["thread_role"] for t in r.get("threads", [])} == (
            {"control", "material-receiver", "material-credit"} if r["role"] == "Client" else {"control"})
        and all(type(t.get("pid")) is int and t["pid"] > 0 and type(t.get("native_id")) is int and t["native_id"] > 0
                and t.get("observation_end_qpc_ns") is not None
                and t["observation_end_qpc_ns"] >= t["registered_at_qpc_ns"] for t in r.get("threads", [])) for r in roles)
    boundary = meta["control_observation_boundary"] = _compact_gc_boundary(cycles, roles)
    start, end, stop = (boundary[k] for k in
        ("start_qpc_ns", "confirmed_observation_end_qpc_ns", "normal_stop_start_qpc_ns"))
    for observed in stage.get("roles", []):
        role = observed["role"]
        registry = next((r.get("threads", []) for r in roles if r.get("role") == role), [])
        events = (observed.get("gc") or {}).get("events", [])
        meta["runtime_gen2_coverage"][role] = False
        for event in events:
            classification = "overlap_or_unknown"
            ordered = type(event[0]) is int and type(event[1]) is int and 0 <= event[0] <= event[1]
            if ordered and type(start) is int and event[1] <= start:
                classification = "outside"
            elif ordered and boundary["control_boundary_valid"] and start <= event[0] and event[1] <= end:
                classification = "control"
            elif ordered and boundary["normal_stop_boundary_valid"] and stop <= event[0]:
                classification = "normal_stop"
            # 时间归属与完整性独立；缺配对/淘汰/省略/恢复证据不授予肯定覆盖。
            reliable = stage.get("evidence_complete") is True and event[3] == 2
            if classification == "control" and reliable:
                meta["runtime_gen2_coverage"][role] = True
            match = [r for r in registry if r["native_id"] == event[2] and r["registered_at_qpc_ns"] <= event[0]
                and r["observation_end_qpc_ns"] is not None and event[1] <= r["observation_end_qpc_ns"]]
            meta["gc_thread_matches"].append({"role": role, "start_qpc_ns": event[0], "end_qpc_ns": event[1],
                "native_id": event[2], "thread_role": match[0]["thread_role"] if len(match) == 1 else None,
                "pid": match[0]["pid"] if len(match) == 1 else None,
                "classification": classification, "coverage_evidence_complete": reliable,
                "scope": "registered identity/lifetime; not allocation stack or exclusive CPU"})
    result["network_history" if network_observation else "qpc_dynamic_qualification" if qpc_dynamic_qualification else
           "qpc_stage_receive_candidate" if qpc_stage_receive_candidate else "compact_history_candidate"] = meta
    if result.get("status") == "stopped" and not meta["representation_complete"]:
        result.update(status="failed", failure_category="CompactHistoryObservation", failed_phase="HISTORY_EXPANSION")
    try:
        meta["finite_sample_pass"] = _compact_sample_pass(result, report, meta, target_steps=target)
        if qpc_stage_receive_candidate or qpc_dynamic_qualification:
            client = next((r for r in stage.get("roles", []) if r.get("role") == "Client"), {})
            receive = client.get("qpc_receive") or {}
            expected_calls = 12*target+8*len(range(399, target-1, 400)) if qpc_dynamic_qualification else 4*target
            meta["finite_sample_pass"] = (meta["finite_sample_pass"] and stage.get("profile") == meta["profile"]
                and client.get("profile") == meta["profile"]
                and all(type(receive.get(k)) is int and receive[k] >= 0 for k in
                    ("selected_exact_calls", "completed_exact_calls", "empty_count", "would_block_count",
                     "no_progress_guard_count", "evicted_count", "encoded_omitted"))
                and receive.get("selected_exact_calls") == receive.get("completed_exact_calls") == expected_calls
                and receive.get("first_exception") is None and receive.get("restore_error_type") is None
                and receive.get("no_progress_guard_count") == receive.get("encoded_omitted") == 0)
        if qpc_dynamic_qualification:
            meta["finite_sample_pass"] = meta["finite_sample_pass"] and all(
                r.get("layout") == _CompactHistory.layout(r["role"], 10000, qualification=True) for r in roles)
    except (KeyError, TypeError, ValueError, IndexError):
        meta["finite_sample_pass"] = False
    if (qpc_stage_receive_candidate or qpc_dynamic_qualification) and result.get("status") == "stopped" and not meta["finite_sample_pass"]:
        result.update(status="failed", failure_category="QPCReceiveObservation", failed_phase="QPC_RECEIVE_REPORT")
    if qpc_dynamic_qualification:
        result["local_dynamic_qualification_pass"] = meta["finite_sample_pass"]
    if network_observation and result.get("status") == "stopped" and not meta["finite_sample_pass"]:
        result.update(status="failed", failure_category="NetworkObservation", failed_phase="HISTORY_REPORT")
    result.update(diagnostic=True, comparison_only=True, server_gc_candidate_gate_pass=False,
                  candidate_gate_pass=False, worker_long_run_gate_pass=False, stage_pass=False, qualification_pass=False)


def _run_material_comparison(options, candidate, *, target_steps=1000):
    """S5仅边界快照；S6独立持有既有探针退出栈，不改变GC策略。"""
    from secure_control.execution import lan_runtime
    report = {"candidate": candidate, "gc_begin": None, "gc_end": None, "memory": [],
              "memory_guard_failed": False, "cleanup_failed": False, "process_cpu_ns": None,
              "producer_exited": None, "memory_sample_error_type": None, "cleanup_error_type": None}
    started_cpu = time.process_time_ns()
    wait_diagnostic = options.get("worker_wait_diagnostic", False)
    server_gc_candidate = options.get("server_gc_candidate", False)
    qpc_candidate = options.get("qpc_stage_receive_candidate", False)
    qpc_qualification = options.get("qpc_dynamic_qualification", False)
    network = options.get("network_configs") is not None
    large_history = qpc_qualification or network and target_steps == 10000
    compact_candidate = options.get("compact_history_candidate", False) or qpc_candidate or qpc_qualification or network
    history = None
    stage_wait_diagnostic = options.get("stage_wait_diagnostic", False) or compact_candidate
    if compact_candidate:
        options = {**options, "stage_wait_diagnostic": True}
    traced = options.get("worker_timeout_diagnostic", False) or wait_diagnostic
    long_run = target_steps == 10000 and not qpc_qualification and not network
    long_metadata = {"format_version": 1, "target_steps": 10000, "maximum_attempts": 10000,
                     "candidate": "worker", "period_ns": 20000000, "segment_steps": 400,
                     "recording_mode": "light", "first_failure_stop": True,
                     "numeric_contract": None} if long_run else None
    wait_metadata = {"format_version": 1, "maximum_attempts": 4000, "first_failure_stop": True,
                     "numeric_contract": None} if wait_diagnostic else None
    server_gc_metadata = {"format_version": 1, "target_steps": 4000, "maximum_attempts": 4000,
        "first_failure_stop": True, "numeric_contract": None} if server_gc_candidate else None
    stage_metadata = {"format_version": 1, "profile": ("canonical-qpc-receive-v1" if qpc_qualification else
        "qpc-stage-receive-v1" if qpc_candidate else "stage-wait-light-v1"),
        "maximum_attempts": target_steps if network else 10000 if qpc_qualification else 1000 if qpc_candidate else 4000,
        "first_failure_stop": True, "numeric_contract": None} if stage_wait_diagnostic else None
    stage_observers = []
    trace_observers = []
    original_close = lan_runtime.LanContinuousRuntime.close
    original_pool_init = lan_runtime._MaterialWorkerPool.__init__
    def initialized(pool, *args, **kwargs):
        original_pool_init(pool, *args, **kwargs)
        history.worker_threads(pool)
    def sample(moment):
        value = {"moment": moment, **_process_memory()}
        report["memory"].append(value)
        if value.get("current_rss_bytes", value.get("peak_rss_bytes")) is None or value.get(
                "current_rss_bytes", value.get("peak_rss_bytes", 0)) > 256 * 1024 * 1024:
            report["memory_guard_failed"] = True
            raise RuntimeError("S5 Client内存保护触发")
    def snapshot():
        return {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()), "stats": gc.get_stats()}
    def event(moment):
        if moment == "control_begin" and report["gc_begin"] is None:
            report["gc_begin"] = snapshot()
        sample(moment)
    def close(runtime):
        pool = runtime._material_pool
        try:
            if report["gc_begin"] is not None and report["gc_end"] is None:
                report["gc_end"] = snapshot()
                event("control_end")
        except Exception as error:  # noqa: BLE001 - 关闭观察只记类别，不覆盖原协议错误
            report["memory_guard_failed"] = True
            report["memory_sample_error_type"] = type(error).__name__
        finally:
            try:
                original_close(runtime)
                if history is not None and isinstance(pool, lan_runtime._MaterialWorkerPool):
                    history.worker_threads(pool, ending=True)
                if isinstance(pool, lan_runtime._OnlineResourcePool):
                    report["producer_exited"] = not pool._thread.is_alive()
                elif pool is not None:
                    report["producer_exited"] = pool.snapshot()["worker_exited"]
            except Exception as error:  # noqa: BLE001 - 清理失败附加记录，仍保留先发生的错误
                report["cleanup_failed"] = True
                report["cleanup_error_type"] = type(error).__name__
        # runner可能已把首错转成返回结果，finally中异常栈已空；关闭观察不再抛出覆盖结果。
        # 保留公开附加失败并执行原关闭，返回后统一门禁；无原失败也不能因此获得成功资格。
    try:
        with ExitStack() as cleanup:
            if compact_candidate:
                history = _CompactHistory("Client", target_steps if qpc_candidate or qpc_qualification or network else 4000,
                    **({"qualification": True} if large_history else {}),
                    **({"wire_profile": options["network_wire_profile"]}
                       if options.get("network_wire_profile") in _COMPACT_ADVANCE_PROFILES else {}))
            cleanup.enter_context(patch.object(lan_runtime.LanContinuousRuntime, "close", close))
            if history is not None:
                cleanup.enter_context(patch.object(lan_runtime._MaterialWorkerPool, "__init__", initialized))
            def register(callback):
                # 初始化尚未进入runner也要逆序还原；附加清理失败不能抹掉已返回的周期。
                def restored():
                    try:
                        callback()
                    except Exception as error:  # noqa: BLE001 - 只记录公开类别，最终门禁拒绝
                        report["cleanup_failed"] = True
                        report["cleanup_error_type"] = type(error).__name__
                cleanup.callback(restored)
                return restored
            result = _run_continuous_observation(**options, material_candidate=candidate,
                _material_event=event, **({"_long_run_metadata": long_metadata or wait_metadata or server_gc_metadata or stage_metadata}
                                        if long_run or wait_diagnostic or server_gc_candidate or stage_wait_diagnostic else {}),
                **({"_register_trace_cleanup": register} if traced or long_run or server_gc_candidate or stage_wait_diagnostic else {}),
                **({"_stage_observers": stage_observers} if stage_wait_diagnostic else {}),
                **({"_compact_history": history} if history is not None else {}),
                **({"_trace_observers": trace_observers} if traced else {}))
    except Exception as error:  # noqa: BLE001 - 初始化/清理失败也保留，不启动替代路线
        result = {"schema": "cycle-qualification-v1", "case": "cycle", "mode": "batch",
                  "status": "failed", "failure_category": type(error).__name__,
                  "requested_steps": options["steps"], "cycles": [], "cycle_timing": _timing([]),
                  "material_summary": getattr(error, "_public_material_summary", {}), "qualification_pass": False,
                  "stage_pass": False, "code_sha": subprocess.check_output(
                      ["git", "rev-parse", "HEAD"], cwd=_ROOT, text=True).strip(),
                  "source_sha256": _source_fingerprints()}
    report["process_cpu_ns"] = time.process_time_ns() - started_cpu
    result.update(material_comparison=report, comparison_only=True, qualification_pass=False, stage_pass=False)
    if "environment" in result and candidate == "worker":
        result["environment"]["roles"] = "three local control roles plus one local material worker"
    material = result.get("material_summary") or {}
    if result["status"] == "stopped" and (material.get("cleanup_failed") or report["cleanup_failed"]
                                           or report["memory_guard_failed"]):
        result.update(status="failed", failure_category=(report["memory_sample_error_type"]
            or report["cleanup_error_type"] or "MaterialComparisonCleanupOrMemory"),
            failed_phase="MEMORY_SAMPLE" if report["memory_guard_failed"] else "CLEANUP")
    if long_run:
        result["worker_long_run"] = long_metadata
        result["worker_long_run_gate_pass"] = _material_run_gate(
            result, report, candidate, target_steps, strict=True)
    result["candidate_gate_pass"] = not long_run and _material_run_gate(result, report, candidate, 1000)
    if server_gc_candidate:
        _finish_server_gc(result, report, server_gc_metadata)
    if stage_wait_diagnostic:
        _finish_stage_wait(result, report, stage_metadata, stage_observers)
    if compact_candidate:
        _finish_compact_history(result, report, history, **({"network_observation": True} if network else
                                                        {"qpc_dynamic_qualification": True} if qpc_qualification else
                                                        {"qpc_stage_receive_candidate": True} if qpc_candidate else {}))
    if traced:
        result["diagnostic"] = True
        if result.get("diagnostic_report") is None:
            result["diagnostic_report"] = {"diagnostic": True, "roles": [v.report() for v in trace_observers],
                                           "incomplete": True, "scope": "initialization or report failure"}
        result.setdefault("timeout_trace", {"format_version": 1, "diagnostic_missing": True})
        budget_key = "worker_wait_diagnostic" if wait_diagnostic else "worker_timeout_diagnostic"
        result[budget_key] = {"scope": "single normal-GC worker diagnosis, not qualification",
            "maximum_attempts": 4000 if wait_diagnostic else 20, "diagnostic_encoded_limit": 256 * 1024,
            "diagnostic_encoded_bytes": 0, "diagnostic_budget_failed": False,
            "precompact_encoded_bytes": None, "compacted_event_count": 0, "material_summary_omitted": False}
        if wait_diagnostic:
            result[budget_key].update(wait_metadata, actual_attempts=len(result.get("cycles", [])),
                failed_attempts=result.get("failed_attempts"), invocation_budget_consumed=True)
            result["worker_long_run_gate_pass"] = False
        combined = {name: result.get(name) for name in ("diagnostic_report", "timeout_trace",
                    "material_comparison", "material_summary", budget_key)}
        for _ in range(3):
            result[budget_key]["diagnostic_encoded_bytes"] = len(json.dumps(
                combined, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
        if result[budget_key]["diagnostic_encoded_bytes"] > 256 * 1024:
            budget = result[budget_key]
            budget["diagnostic_budget_failed"] = True
            budget["precompact_encoded_bytes"] = budget["diagnostic_encoded_bytes"]
            # 总预算不足时只留下各角色首错/外层错及恢复事实，省略普通历史并明确拒绝资格。
            roles = []
            for role in result["diagnostic_report"].get("roles", []):
                compact = {key: role.get(key) for key in ("role", "format_version", "trace_fields",
                    "trace_context_fields", "first_failure", "outer_failure", "evictions", "clocks",
                    "callback_restored", "socket_hooks_restored", "schemas", "profile",
                    "first_failure_entry", "socket_current_entries", "evicted_count")}
                omitted = len(role.get("events", []))
                budget["compacted_event_count"] += omitted
                compact.update(events=[], encoded_omitted=role.get("encoded_omitted", 0) + omitted,
                               incomplete=True, encoded_limit=72 * 1024, encoded_bytes=0)
                for _ in range(3):
                    compact["encoded_bytes"] = len(json.dumps(compact, separators=(",", ":"),
                                                              ensure_ascii=False, allow_nan=False).encode())
                roles.append(compact)
            result["diagnostic_report"] = {"diagnostic": True, "roles": roles, "incomplete": True,
                                           "budget_compacted": True}
            combined["diagnostic_report"] = result["diagnostic_report"]
            for _ in range(3):
                budget["diagnostic_encoded_bytes"] = len(json.dumps(combined, separators=(",", ":"),
                                                                    ensure_ascii=False, allow_nan=False).encode())
            if budget["diagnostic_encoded_bytes"] > 256 * 1024:
                # 材料摘要亦可能占用总预算；缺测明确标记，不丢runner权威周期或制造退出事实。
                result["material_summary"] = combined["material_summary"] = None
                budget["material_summary_omitted"] = True
                for _ in range(3):
                    budget["diagnostic_encoded_bytes"] = len(json.dumps(combined, separators=(",", ":"),
                                                                        ensure_ascii=False, allow_nan=False).encode())
            if result["status"] == "stopped":
                result.update(status="failed", failure_category="DiagnosticBudget", failed_phase="DIAGNOSTIC_REPORT")
        result["candidate_gate_pass"] = False
    return result


@contextmanager
def _observe_network_tls(role, facts):
    """仅新实验记录原认证成功事实；证书/SAN/TLS核验仍由transport拥有。"""
    from secure_control.execution import lan_transport

    original = lan_transport._verify_identity
    def verified(sock, expected):
        original(sock, expected)
        if len(facts["links"]) >= 2:
            raise RuntimeError("网络实验角色出现额外连接。")
        facts["links"].append({"role": role, "peer_identity": expected, "version": sock.version(),
            "peer_san": list(sock.getpeercert()["subjectAltName"]),
            "tcp_nodelay": sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY),
            "local": list(sock.getsockname()), "remote": list(sock.getpeername())})
    try:
        with patch.object(lan_transport, "_verify_identity", verified):
            yield
    finally:
        facts["restored"] = lan_transport._verify_identity is original


def run_network_observation(*, configs, steps, wire_profile=None, candidate_manifest=None):
    """独立TLS实验共享入口；先严格校验再复用原循环，旧裸TCP门禁不变。"""
    from secure_control.execution.localhost_codec import _COMPACT_PROFILES

    if (wire_profile not in (None, *_COMPACT_PROFILES)
            or wire_profile not in _COMPACT_ADVANCE_PROFILES and candidate_manifest is not None
            or type(configs) is not tuple or len(configs) != 3 or type(steps) is not int or steps not in (1000, 10000)
            or tuple(getattr(c, "role", None) for c in configs) != ("Client", "P1", "P2")
            or not all(isinstance(c, LanConfig) and c.transport == "mutual_tls" for c in configs)
            or any(c.topology != configs[0].topology or c.startup_timeout != 30. or c.step_timeout != 30.
                   or c.shutdown_timeout != 5. or c.idle_timeout != 30. for c in configs)
            or configs[0].experiment_config != _ROOT / "configs/cart_pole_observer_lan.example.yaml"
            or any(c.ca is None or c.certificate is None or c.private_key is None for c in configs)
            or any(c.controller_config is not None for c in configs)
            or not gc.isenabled() or gc.get_threshold() != (700, 10, 10)
            or gc.get_freeze_count() or gc.get_debug() or gc.callbacks):
        raise ValueError("网络实验只允许原配置、正常GC、三角色TLS及固定1000/10000。")
    if wire_profile in _COMPACT_ADVANCE_PROFILES:
        from .network_benchmark import require_network_candidate
        require_network_candidate(candidate_manifest, wire_profile, configs)
        if steps != candidate_manifest["maximum_attempts"]:
            raise ValueError("实际步数必须等于本次已占许可。")
    topology = configs[0].topology
    endpoints = (topology.p1_client, topology.p2_client, topology.p1_peer)
    if (topology.identities != {r: f"{r.lower()}.secure-control.test" for r in ("Client", "P1", "P2")}
            or len({e.port for e in endpoints}) != 3
            or any(e.host != "127.0.0.1" or e.bind not in ("127.0.0.1", "127.0.0.2") for e in endpoints)
            or len({e.bind for e in endpoints}) != 1):
        raise ValueError("网络实验拓扑/身份不匹配。")
    return _run_material_comparison({"steps": steps, "delay_ms": 0., "segment_steps": 400, "optimized": True,
        "material_slots": 16, "role_config": None, "preload_steps": 0, "preload_execution": "fused", "diagnostic": False,
        "recording_mode": "light", "tcp_nodelay": None, "commit_policy": "default", "timeout_trace": False,
        "network_configs": configs, **({"network_wire_profile": wire_profile} if wire_profile is not None else {}),
        **({"network_candidate_manifest": candidate_manifest} if wire_profile in _COMPACT_ADVANCE_PROFILES else {})},
        "worker", target_steps=steps)


def _run_continuous_observation(*, steps: int, delay_ms: float,
                               segment_steps: int, optimized=False, material_slots=16,
                               role_config: Path | None = None, preload_steps=0,
                               preload_execution="fused", diagnostic=False,
                               recording_mode="full", tcp_nodelay=None,
                               commit_policy="default", _gc_trial=None, timeout_trace=False,
                               material_candidate=None, _material_event=None, worker_timeout_diagnostic=False,
                               _register_trace_cleanup=None, _trace_observers=None,
                               _long_run_metadata=None, worker_wait_diagnostic=False,
                               server_gc_candidate=False, stage_wait_diagnostic=False, _stage_observers=None,
                               compact_history_candidate=False, _compact_history=None,
                               qpc_stage_receive_candidate=False, qpc_dynamic_qualification=False,
                               network_configs=None, network_wire_profile=None,
                               network_candidate_manifest=None) -> dict[str, object]:
    """实际持续动态循环及原同步 writer；退出后报告观察，不发布图或更改调度。"""
    from secure_control.execution.lan_runtime import RunControl
    from secure_control.execution.localhost_codec import _COMPACT_PROFILES
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    from .cart_pole_segmented_evidence import _BatchWriter, _correct_cycle_tail, _Spool
    from .lan_continuous_profile import load_segmented_experiment
    from .lan_runner import _run_prepared_segmented

    if network_wire_profile is not None and (network_wire_profile not in _COMPACT_PROFILES
            or network_configs is None or material_candidate != "worker" or not optimized
            or preload_steps or material_slots != 16 or recording_mode != "light"):
        raise ValueError("紧凑动态 profile 只允许显式原网络工人实验入口")
    if network_wire_profile in _COMPACT_ADVANCE_PROFILES:
        from .network_benchmark import require_network_candidate
        if (type(steps) is not int or steps not in (1000, 10000) or delay_ms != 0 or segment_steps != 400 or role_config is not None
                or tcp_nodelay is not None or commit_policy != "default" or _gc_trial is not None
                or any((diagnostic, timeout_trace, worker_timeout_diagnostic, worker_wait_diagnostic,
                        server_gc_candidate, compact_history_candidate,
                        qpc_stage_receive_candidate, qpc_dynamic_qualification))
                or stage_wait_diagnostic is not True
                or not gc.isenabled() or gc.get_threshold() != (700, 10, 10)
                or gc.get_freeze_count() or gc.get_debug()):
            raise ValueError("v2仅允许已批准1000或10000、段400和正常GC的原网络入口")
        require_network_candidate(network_candidate_manifest, network_wire_profile, network_configs)
        if steps != network_candidate_manifest["maximum_attempts"]:
            raise ValueError("实际步数必须等于本次已占许可。")
    elif network_candidate_manifest is not None:
        raise ValueError("候选manifest只能用于v2")

    maximum = 10000 if optimized else 400
    if tcp_nodelay is not None and type(tcp_nodelay) is not bool:
        raise TypeError("tcp_nodelay 必须为 bool 或 None。")
    if type(commit_policy) is not str or commit_policy not in ("default", "serial"):
        raise ValueError("非法 commit_policy。")
    comparison_only = (tcp_nodelay is not None or commit_policy != "default"
                       or _gc_trial is not None or material_candidate is not None)
    if comparison_only and (not optimized or role_config is not None):
        raise ValueError("通信策略对照只支持内部三进程 cycle。")
    if type(recording_mode) is not str or recording_mode not in ("light", "full") or recording_mode == "light" and not optimized:
        raise ValueError("轻量记录只支持cycle动态持续观察。")
    light = recording_mode == "light"
    minimum = 1 if diagnostic or qpc_stage_receive_candidate else 2
    if type(diagnostic) is not bool or (diagnostic and (not optimized or role_config is not None)):
        raise ValueError("有限诊断只支持本机canonical cycle观察。")
    if type(steps) is not int or not minimum <= steps <= maximum:
        raise ValueError(f"观察步数必须在{minimum}..{maximum}，首步不剔除。")
    if material_slots not in (0, 4, 16) or isinstance(material_slots, bool):
        raise ValueError("资格观察材料库存只可显式选择 0/4/16。")
    if (type(preload_steps) is not int or not 0 <= preload_steps <= 1000
            or preload_execution not in {"staged", "fused"}
            or (preload_steps and (not optimized or steps > preload_steps or material_slots != 16))):
        raise ValueError("预送cycle观察必须在有限库存内，且与显式非默认材料池互斥")
    if type(segment_steps) is not int or not 1 <= segment_steps <= 1000:
        raise ValueError("段容量必须在1..1000")
    if not isinstance(delay_ms, (int, float)) or not 0 <= delay_ms <= 3:
        raise ValueError("单帧注入等待必须在0..3ms")
    supply_diagnostic = (diagnostic and light and not preload_steps and material_slots == 16
                         and (not comparison_only or _gc_trial is not None or worker_timeout_diagnostic
                              or worker_wait_diagnostic))
    ports = _ports() if network_configs is None else tuple(e.port for e in (
        network_configs[0].topology.p1_client, network_configs[0].topology.p2_client, network_configs[0].topology.p1_peer))
    config = (network_configs[0] if network_configs is not None else
              _config("Client", ports) if role_config is None else load_lan_config(role_config, "Client"))
    if (qpc_stage_receive_candidate or qpc_dynamic_qualification) and config.transport != "insecure_tcp":
        raise ValueError("S15不适用于TLS或未知传输。")
    if role_config is not None:
        ports = tuple(endpoint.port for endpoint in (
            config.topology.p1_client, config.topology.p2_client, config.topology.p1_peer,
        ))
    context = mp.get_context("spawn")
    queue = context.Queue()
    if _gc_trial:
        _gc_trial.cleanup.callback(queue.close)
    parties, roles_closed = [], False
    def stop_roles():
        nonlocal roles_closed
        if roles_closed:
            return
        roles_closed = True
        try:
            for party in parties:
                if party.is_alive():
                    party.terminate()
                    party.join(timeout=5)
        finally:
            queue.close()
    if _register_trace_cleanup:
        stop_roles = _register_trace_cleanup(stop_roles)
    parties = [context.Process(target=_party_job, args=(
        network_configs[index+1] if network_configs is not None else _config(role, ports), ports, delay_ms, True, queue, diagnostic, False, tcp_nodelay,
        supply_diagnostic, timeout_trace, material_candidate is not None, worker_wait_diagnostic, server_gc_candidate,
        stage_wait_diagnostic, compact_history_candidate or qpc_stage_receive_candidate or qpc_dynamic_qualification or network_configs is not None,
        steps if qpc_stage_receive_candidate or qpc_dynamic_qualification or network_configs is not None else 4000,
        qpc_dynamic_qualification or network_configs is not None and steps == 10000,
        *((True, network_wire_profile) if network_configs is not None else ()),
    ), **({"kwargs":{"source_manifest":network_candidate_manifest}}
          if isinstance(network_candidate_manifest, dict)
          and network_candidate_manifest.get("scope") == "issue128-matrix-comparison-v1" else {}))
        for index, role in enumerate(("P1", "P2"))] if role_config is None else []
    records, events, outcomes, writer_batches = [], [], [], []
    history = _compact_history
    def record_count():
        return history.tables["steps"].count if history is not None else len(records)
    socket_options = []
    network_tls = {"links": [], "restored": False}
    cycles = []
    marks, storage = {}, {"fsync_ms": 0., "fsync_count": 0, "checkpoint_ms": 0.,
                          "source_check_ms": 0., "source_check_control_ms": 0.,
                          "source_check_writer_ms": 0., "source_check_control_count": 0,
                          "source_check_writer_count": 0}
    diagnostic_observer = (_TimeoutDiagnostic("Client", ports, wait_profile=worker_wait_diagnostic) if timeout_trace else
                          _Diagnostic("Client", supply=supply_diagnostic,
                                      all_gc=_gc_trial is not None) if diagnostic else None)
    # 必须先装在meter内层；退出先还原meter前驱，再卸下探针。
    socket_context = ExitStack() if timeout_trace else None
    register_cleanup = _gc_trial.cleanup.callback if _gc_trial else _register_trace_cleanup
    socket_close = None
    if timeout_trace:
        if _trace_observers is not None:
            _trace_observers.append(diagnostic_observer)
        socket_close = register_cleanup(socket_context.close)
        socket_context.enter_context(diagnostic_observer.sockets())
    qpc_observer = (_StageWaitDiagnostic("Client", ports, gc_observer=_ServerGCObservation("Client"),
                    qpc_receive_candidate=True, all_qpc_receives=qpc_dynamic_qualification)
                    if qpc_stage_receive_candidate or qpc_dynamic_qualification else None)
    counts, activity, restore = _meter("Client", ports, delay_ms, diagnostic=diagnostic_observer,
        **({"qpc_receiver": qpc_observer.qpc_receive} if qpc_observer else {}))
    if register_cleanup:
        restore = register_cleanup(restore)
    stage_wait, stage_close = None, None
    if stage_wait_diagnostic:
        stage_context = ExitStack()
        stage_close = register_cleanup(stage_context.close)
        client_gc = qpc_observer.gc_observer if qpc_observer else _ServerGCObservation("Client")
        stage_wait = qpc_observer or _StageWaitDiagnostic("Client", ports, gc_observer=client_gc)
        _stage_observers.append(stage_wait)
        stage_context.enter_context(client_gc.installed(server_startup=False))
        stage_context.enter_context(stage_wait.installed())
    control, session = RunControl(), InteractiveSession()
    fsync, checkpoint = os.fsync, None if light else _Spool._checkpoint
    before_activity, before_storage = dict(activity), dict(storage)
    before_counts = {}
    current_phase, phase_start, started = None, time.perf_counter_ns(), time.perf_counter_ns()
    attempt = None
    diagnostic_phase = None

    def phase(name):
        nonlocal current_phase, phase_start, attempt, before_activity, before_storage, before_counts
        nonlocal diagnostic_phase
        if history is not None and name == "STOPPING" and history.normal_stop_start_qpc_ns is None:
            history.normal_stop_start_qpc_ns = time.perf_counter_ns()
        if _material_event and (name == "RUNNING" and record_count() == 0 or name == "INPUT" and record_count() % 100 == 0):
            _material_event("control_begin" if name == "RUNNING" else "before_input")
        if _gc_trial and name == "RUNNING":
            if timeout_trace:
                diagnostic_observer.tracing = True
                diagnostic_observer.marker("control_scope_begin")
            _gc_trial.control_started = True
            _gc_trial.memory("control_start", guard=True)
            _gc_trial.snapshot("control_start")
        if diagnostic_observer:
            if not supply_diagnostic or name == "INPUT":
                diagnostic_observer.end(diagnostic_phase)
            if name == "INPUT":
                diagnostic_observer.select(record_count())
            if not supply_diagnostic or name == "INPUT":
                diagnostic_phase = diagnostic_observer.begin("control_cycle" if supply_diagnostic else name)
        if _gc_trial and name == "INPUT" and record_count() % 100 == 0:
            _gc_trial.memory("before_input", step=record_count(), guard=True)
        now = time.perf_counter_ns()
        if current_phase is not None:
            if history is not None:
                history.event(current_phase, (now-phase_start)/1e6, record_count() if attempt is not None else None)
            else:
                events.append({"phase": current_phase, "duration_ms": (now - phase_start) / 1e6,
                               "attempt": record_count() if attempt is not None else None})
        if name == "INPUT":
            if stage_wait:
                stage_wait.select(record_count())
            attempt = now
            marks.clear()
            before_activity, before_storage = dict(activity), dict(storage)
            before_counts = {k: dict(v) for k, v in counts.items()}
        current_phase, phase_start = name, now

    def durable_step(record):
        nonlocal attempt
        if sink is not None:
            sink.record_step(record)
        now = time.perf_counter_ns()
        if history is not None:
            history.step(record, duration=(now-attempt)/1e6, marks=marks, activity=activity,
                before_activity=before_activity, counts=counts, before_counts=before_counts,
                storage=storage, before_storage=before_storage)
        else:
            records.append({"global_step": record.protocol.global_step,
                        "segment_index": record.protocol.segment_index,
                        "session_id": record.protocol.session_id,
                        "round_id": record.protocol.round_id, "status": "confirmed",
                        "duration_ms": (now - attempt) / 1e6,
                        "components_ms": {k: v for k, v in marks.items() if k.endswith("_ms")},
                        "activity": {k: activity[k] - v for k, v in before_activity.items()},
                        "sent": {k: {field: v[field] - before_counts.get(k, {}).get(field, 0)
                                     for field in v} for k, v in counts.items()},
                        "storage": {k: None if light and k in ("fsync_ms", "fsync_count", "checkpoint_ms")
                                    else storage[k] - v for k, v in before_storage.items()}})
        attempt = None
        if record_count() >= steps:
            control.request_stop()

    def observed_cycle(timing):
        nonlocal diagnostic_phase
        if diagnostic_observer:
            diagnostic_observer.end(diagnostic_phase, status=timing.status)
            diagnostic_phase = None
            if supply_diagnostic:
                diagnostic_observer.finish_control()
        if history is not None:
            history.cycle(timing, counts, before_counts)
        else:
            sent = {k: v["frames"] - before_counts.get(k, {}).get("frames", 0)
                    for k, v in counts.items()}
            byte_counts = {k: v["application_bytes"] - before_counts.get(k, {}).get("application_bytes", 0)
                           for k, v in counts.items()}
            timing = replace(timing, public_frame_counts=sent, public_byte_counts=byte_counts)
            cycles.append(asdict(timing))
        if writer is not None:
            writer.record_cycle(timing)
        if history is not None and timing.status == "confirmed":
            history.last_confirmed_step = timing.global_step
            history.last_confirmed_return_qpc_ns = time.perf_counter_ns()

    def measured_fsync(fd):
        start = time.perf_counter_ns()
        try:
            return fsync(fd)
        finally:
            storage["fsync_ms"] += (time.perf_counter_ns() - start) / 1e6
            storage["fsync_count"] += 1

    def measured_checkpoint(self, *args, **kwargs):
        start = time.perf_counter_ns()
        try:
            return checkpoint(self, *args, **kwargs)
        finally:
            storage["checkpoint_ms"] += (time.perf_counter_ns() - start) / 1e6

    diagnostic_context = ExitStack()
    diagnostic_close = diagnostic_context.close
    if register_cleanup:
        diagnostic_close = register_cleanup(diagnostic_close)
    if diagnostic_observer:
        diagnostic_context.enter_context(diagnostic_observer.installed())
        diagnostic_context.enter_context(_observe_diagnostic(diagnostic_observer, recording=not light))
        if not light:
            fsync = diagnostic_observer.wrap("fsync", fsync)
            checkpoint = diagnostic_observer.wrap("checkpoint_call", checkpoint)
    try:
        with (nullcontext(None) if light else
              tempfile.TemporaryDirectory(prefix="secure-control-observation-")) as folder:
            assembly_start = time.perf_counter_ns()
            prepared = load_segmented_experiment(config.experiment_config, segment_steps, session)
            if _long_run_metadata is not None:
                # 只公开持续证明的适用模式，不导出矩阵、编码初态或秘密范围数值。
                effective = prepared.effective_config
                numeric = {"mode": effective["range"]["mode"],
                           "horizon_steps": prepared.contract.horizon_steps,
                           "proof_algorithm": effective["range"]["proof"]["algorithm"],
                           "block_steps": prepared.contract.reachability_block_steps,
                           "parameter_bits": effective["paper_parameter_bits"],
                           "runtime_payload_bits": effective["runtime_payload_bits"],
                           "client_validation": "original range validation before control and each input"}
                _long_run_metadata["numeric_contract"] = numeric
                if numeric["mode"] != "bounded_input_reachability" or numeric["horizon_steps"] is not None:
                    raise ValueError("worker长期验证需要原持续有界输入证明。")
            recheck = prepared.recheck_sources

            def measured_sources():
                start = time.perf_counter_ns()
                try:
                    return recheck()
                finally:
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    storage["source_check_ms"] += elapsed
                    owner = "writer" if current_thread().name == "segment-evidence-writer" else "control"
                    storage[f"source_check_{owner}_ms"] += elapsed
                    storage[f"source_check_{owner}_count"] += 1

            if diagnostic_observer:
                measured_sources = diagnostic_observer.wrap("source_check", measured_sources)

            prepared = replace(prepared, recheck_sources=measured_sources,
                               **({"output_root": Path(folder)} if folder is not None else {}))
            transaction = None if light else _Spool(prepared, config, session, phase)
            writer = _BatchWriter(transaction, on_batch=writer_batches.append) if optimized and not light else None
            sink = writer if writer is not None else transaction
            initial_assembly_ms = (time.perf_counter_ns() - assembly_start) / 1e6
            for party in parties:
                party.start()
            with (_observe_dynamic(marks), _commit_policy(commit_policy),
                  _observe_network_tls("Client", network_tls) if network_configs is not None else nullcontext(),
                  _observe_tcp(socket_options, tcp_nodelay), ExitStack() as io_hooks):
                if not light:
                    io_hooks.enter_context(patch.object(os, "fsync", measured_fsync))
                    io_hooks.enter_context(patch.object(_Spool, "_checkpoint", measured_checkpoint))
                result = _run_prepared_segmented(
                    config, prepared, control=control, session=session,
                    on_step=durable_step, on_segment=writer.record_deferred if writer else sink.record if sink else None,
                    on_segment_ready=writer.release_segment if writer else None,
                    on_start=sink.begin if sink else None, phase=phase, realtime=optimized,
                    material_slots=material_slots,
                    preload_steps=preload_steps, preload_execution=preload_execution,
                    on_cycle=observed_cycle if optimized else None,
                    cycle_snapshot=writer.snapshot if writer else None,
                    before_sample=writer.check if writer else None,
                    **({"_material_candidate": material_candidate} if material_candidate else {}),
                    **({"_wire_profile": network_wire_profile} if network_wire_profile is not None else {}),
                )
                if _gc_trial:
                    _gc_trial.report["original_startup_gc"] = result.get("startup_gc")
                active_storage = dict(storage)
                if writer is not None:
                    try:
                        writer.finish()
                    except OSError:
                        result = {**result, "status": "failed", "category": "OSError",
                                  "failure_phase": "WRITER_DRAIN"}
                if transaction is not None and result["status"] != "stopped":
                    try:
                        transaction.fail(result)
                    except OSError:
                        result["checkpoint_error"] = "OSError"
            if attempt is not None:
                if history is not None:
                    try:
                        history.step(None, duration=(time.perf_counter_ns()-attempt)/1e6, marks=marks,
                            activity=activity, before_activity=before_activity, counts=counts, before_counts=before_counts,
                            storage=storage, before_storage=before_storage,
                            failure_phase=result.get("failure_phase"), error_type=result.get("category"))
                    except RuntimeError:
                        pass  # 已记录捕获失败；不覆盖runner原控制首错或伪造一行。
                else:
                    records.append({"global_step": record_count(), "status": "failed",
                                "duration_ms": (time.perf_counter_ns() - attempt) / 1e6,
                                "failure_phase": result.get("failure_phase"),
                                "error_type": result.get("category"),
                                "components_ms": {k: v for k, v in marks.items() if k.endswith("_ms")},
                                "activity": {k: activity[k] - v for k, v in before_activity.items()},
                                "sent": {k: {field: v[field] - before_counts.get(k, {}).get(field, 0)
                                             for field in v} for k, v in counts.items()},
                                "storage": {k: None if light and k in ("fsync_ms", "fsync_count", "checkpoint_ms")
                                            else storage[k] - v for k, v in before_storage.items()}})
            if history is not None:
                try:
                    history.event(current_phase, (time.perf_counter_ns()-phase_start)/1e6, None)
                except RuntimeError:
                    pass  # 有效事件前缀仍展开，报告不完整。
            else:
                events.append({"phase": current_phase,
                           "duration_ms": (time.perf_counter_ns() - phase_start) / 1e6,
                           "attempt": None})
            outcomes = _party_outcomes(queue) if parties else []
            for party in parties:
                party.join(timeout=10)
    finally:
        if stage_close:
            stage_close()
        restore()
        if diagnostic_observer:
            diagnostic_observer.end(diagnostic_phase)
            diagnostic_observer.finish_control()
        diagnostic_close()
        if socket_context is not None:
            socket_close()
        stop_roles()
    if history is not None:
        try:
            expanded = history.expand()
        except Exception as error:  # noqa: BLE001 - 完整展开故障不能替换runner已有首错
            history.error_type = type(error).__name__
            history.expansion_ns = 0
            expanded = {"steps": [], "events": [], "cycles": []}
        records, events, cycles = expanded["steps"], expanded["events"], expanded["cycles"]
    directions = dict(counts)
    for item in outcomes:
        directions.update(item["directions"])
    # on_cycle之后的成本仍可超期：两种模式均以原runner最终事实校正。
    captured_cycles = len(cycles)
    _correct_cycle_tail(cycles, result, project=dict)
    if history is not None:
        history.tail_correction = {"captured_cycles": captured_cycles, "exported_cycles": len(cycles),
            "canonical_last_cycle_present": (result.get("cycle_summary") or {}).get("last_cycle") is not None}
    cycle_timing = _timing([(row["cycle_completed_ns"] - row["scheduled_start_ns"]) / 1e6
                            for row in cycles if row["cycle_completed_ns"] is not None])
    device_timing = _timing([(row["device_completed_ns"] - row["scheduled_start_ns"]) / 1e6
                             for row in cycles if row["device_completed_ns"] is not None])
    diagnostic_report = None
    if diagnostic_observer:
        diagnostic_report = {"diagnostic": True, "roles": [diagnostic_observer.report()] +
            [item.pop("diagnostic", {"role": item["role"], "missing": True}) for item in outcomes],
            "selected_global_steps": ("0..1, 165..168, 176..180; control labels, not prepared_step"
                                      if supply_diagnostic else
                                      "0..1 and 397..405; writer batch identified by final public step"),
            "supply_diagnostic": supply_diagnostic,
            "client_gc_scope": "entire trial including startup/close" if _gc_trial else "selected windows",
            "control_label_scope": ("Client: INPUT through cycle export callback; P1/P2: last completed "
                                    "Client request, Client active unknown; not CPU execution or GIL ownership"),
            "scope": ("same-host perf_counter/QPC; individual task/send/encode/GC intervals; "
                      "same-thread CPU may be quantized; nested durations overlap; no pure OS/GIL attribution"
                      if supply_diagnostic else
                      "same-host perf_counter/QPC; same-thread CPU; repeated windows are envelopes, "
                      "not continuous execution; nested durations overlap; non_cpu is not a GIL/I/O cause"),
            "python_implementation": platform.python_implementation(),
            "encoded_limit": 256 * 1024}
        if timeout_trace:
            diagnostic_report.update(selected_global_steps="rolling recent public events; first error latched",
                                     client_gc_scope="rolling recent GC intervals",
                                     timeout_trace=True, format_version=1)
        diagnostic_report["encoded_bytes"] = 0
        for _ in range(3):
            diagnostic_report["encoded_bytes"] = len(json.dumps(
                diagnostic_report, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
        if diagnostic_report["encoded_bytes"] > diagnostic_report["encoded_limit"]:
            raise RuntimeError("有限诊断编码超出预声明预算。")
    return {
        "schema": ("matrix-dynamic-evidence-v1" if network_wire_profile == "control-dynamic-matrix-v1"
                   else "cycle-qualification-v1" if optimized else "continuous-observation-v1"),
        **({"network_tls": network_tls} if network_configs is not None else {}),
        **({"wire_profile": network_wire_profile} if network_wire_profile is not None else {}),
        "recording_mode": recording_mode,
        "evidence_state": "not_recorded" if light else "full_observation_spool",
        "diagnostic": diagnostic, "diagnostic_report": diagnostic_report,
        "timeout_trace": ({"format_version": 1, "scope": (f"single bounded {_gc_trial.policy} timeout diagnosis"
                              if _gc_trial else "single bounded normal-GC worker timeout diagnosis"),
                           "first_failure_observed_ns": (diagnostic_observer.first_failure[2]
                                if diagnostic_observer.first_failure is not None else None)}
                          if timeout_trace else None),
        "case": "cycle" if optimized else "continuous", "mode": "batch",
        "code_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=_ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=_ROOT, text=True)),
        "source_sha256": _source_fingerprints(),
        "environment": {"os": platform.platform(), "python": sys.version.split()[0],
                        "roles": "three local processes" if parties else "Client with externally started roles",
                        "transport": config.transport,
                        "cpu_count": mp.cpu_count(), "timer": "local perf_counter_ns",
                        "delay_model": "sleep before each application frame send",
                        "one_way_delay_ms": delay_ms},
        "clock_info": {name: {field: getattr(time.get_clock_info(name), field)
                              for field in ("implementation", "monotonic", "adjustable", "resolution")}
                       for name in ("monotonic", "perf_counter")},
        "configuration_reference": ("configs/cart_pole_observer_lan.example.yaml"
                                    if role_config is None else "external Client profile"),
        "configuration_sha256": {name: prepared.effective_config.get(name)
                                  for name in ("profile_sha256", "plant_source_sha256",
                                               "observer_source_sha256", "prime_source_sha256")},
        "input_policy": "fresh device two-measurement local chart at each scheduled attempt",
        "initial_state": prepared.effective_config["plant_contract"]["initial_state"],
        "numeric_profile": {"fractional_bits": prepared.context.fractional_bits,
                            "security_parameter": prepared.security_parameter,
                            "period_s": prepared.scene.period,
                            "modulus_bits": prepared.context.modulus.bit_length(),
                            "state_dimension": prepared.spec.state_dimension,
                            "input_dimension": prepared.spec.input_dimension,
                            "output_dimension": prepared.spec.output_dimension},
        "segment_capacity": segment_steps, "requested_steps": steps,
        "material_slots": material_slots if optimized and not preload_steps else 0,
        "preload_steps": preload_steps, "preload_execution": preload_execution if preload_steps else None,
        "status": result["status"], "failed_phase": result.get("failure_phase"),
        "failure_category": result.get("category"),
        "protocol_committed_count": result.get("protocol_committed_count"),
        "physically_confirmed_count": result.get("confirmed_step_count"),
        "durable_step_count": 0 if light else result.get("recording_summary", {}).get("durable_step_count"),
        "successful_steps": sum(row["status"] == "confirmed" for row in records),
        "failed_attempts": (sum(row["status"] != "confirmed" for row in cycles) if optimized
                            else sum(row["status"] == "failed" for row in records)),
        "steps": records, "events": events, "party_outcomes": outcomes,
        "cycles": cycles, "cycle_summary": result.get("cycle_summary"),
        "cycle_timing": cycle_timing, "device_timing": device_timing,
        "startup_jitter_ms": [(row["actual_sample_start_ns"] - row["scheduled_start_ns"]) / 1e6
                              if row["actual_sample_start_ns"] is not None else None for row in cycles],
        "material_summary": result.get("material_summary"),
        "recording_summary": writer.snapshot() if writer else None,
        "stop_drain_ns": None if light else writer.drain_ns if writer else 0,
        "spool_io": dict(transaction.disk_metrics) if transaction is not None else None,
        "writer_batches": None if light else writer_batches,
        "writer_batch_scope": None if light else ("Client perf_counter_ns windows include waits; rows_journal includes "
                               "row_validation_ns, spool includes spool fsync; nested durations cannot "
                               "be added as exclusive costs; buffer high water is bytes, not a time bound"),
        "storage_active": {**active_storage, **({k: None for k in ("fsync_ms", "fsync_count", "checkpoint_ms")} if light else {})},
        "storage_all": {**storage, **({k: None for k in ("fsync_ms", "fsync_count", "checkpoint_ms")} if light else {})},
        "client_memory": _process_memory(),
        "resource_counts": result["resource_counts"], "directions_all_session": directions,
        "timing": _timing([row["duration_ms"] for row in records]),
        "timing_scope": ("timing: work attempt input through record callback (failure includes cleanup); "
                         "cycle_timing: completed scheduled-start through maintenance, before timing export; "
                         "device_timing: scheduled-start through confirmed device receipt; "
                         "unfinished attempts remain in cycles with null endpoints and miss status; "
                         "timing export is separately guarded and cycle_summary is authoritative"),
        "all_observation_ms": (time.perf_counter_ns() - started) / 1e6,
        "initial_assembly_ms": initial_assembly_ms,
        "startup_gc": result.get("startup_gc"),
        "last_commit_observation": result.get("last_commit_observation"),
        "comparison_only": comparison_only,
        "commit_policy": ("overlap" if commit_policy == "default" and optimized
                          and prepared.spec.state_dimension else "serial"),
        "tcp_nodelay_policy": "default" if tcp_nodelay is None else "on" if tcp_nodelay else "off",
        "tcp_socket_options": {"Client": socket_options,
                               **{row["role"]: row.get("tcp_socket_options", []) for row in outcomes}},
        "recording_scope": "bounded benchmark history (maximum 10000 cycles); production recent window 256",
        "activity_scope": "local arithmetic excludes peer calls; peer_exchange includes I/O, encoding and waits; send/receive/codec overlap; checkpoint includes its fsync",
        "byte_scope": "application payload plus 4-byte header; excludes TCP/TLS overhead",
        "qualification_pass": (not comparison_only and not diagnostic and optimized and steps == 10000 and result["status"] == "stopped"
                               and len(cycles) == steps
                               and result.get("cycle_summary", {}).get("misses") == 0
                               and all(row["status"] == "confirmed" and row["cycle_completed_ns"] is not None
                                       and row["cycle_completed_ns"] < row["deadline_ns"]
                                       for row in cycles)),
        "stage_pass": (optimized and result["status"] == "stopped" and len(cycles) == steps
                       and result.get("cycle_summary", {}).get("misses") == 0
                       and all(row["status"] == "confirmed" and row["cycle_completed_ns"] is not None
                               and row["cycle_completed_ns"] < row["deadline_ns"] for row in cycles)),
        "limits": ("actual sustained simulation runner; observation overhead included and guarded; "
                   "local frame delay is not Wi-Fi or real hardware evidence; no plots published; "
                   "spool I/O excludes timing sidecar and stop-time replay/plots; "
                   "memory is Client OS peak RSS/working set, not encoded-budget size; "
                   "baseline continuous mode explicitly has no absolute scheduling"),
    }


class _FullObservation:
    """P0只记录公开边界；有界观察不改变完整路线的调度或失败语义。"""

    def __init__(self, capacity, counts, activity):
        self.capacity = capacity
        self.counts, self.activity = counts, activity
        self.rows, self.events = [], []
        self.current = None
        self.read_stamp = None
        self.components = {}
        self.event_overflow = 0
        self.detail_overflow = 0
        self.encoded_charge = 0
        self.observations = 0
        self.started = time.perf_counter_ns()

    def event(self, name, start, end, status):
        row = {"phase": name, "start_ns": start, "end_ns": end, "status": status,
               "physical_step": self.current["physical_step"] if self.current else None}
        if len(self.events) < 256:
            self.events.append(row)
        else:
            self.event_overflow += 1

    def begin(self):
        # 初始及上一步尾部提前读取的测量只保存时刻，不保存其值或对象。
        if self.current is not None:
            self.finish("observation_only")
        self.current = {"physical_step": self.observations, "phase": None,
                        "consumption_start_ns": time.perf_counter_ns(),
                        "measurement_read": self.read_stamp, "status": "observing",
                        "duration_ms": None, "protocol_completed": False,
                        "device_confirmed": False, "control_started": False}
        self.current["measurement_age_at_consumption_ms"] = (
            (self.current["consumption_start_ns"]-self.read_stamp["end_ns"])/1e6
            if self.read_stamp else None)
        self.observations += 1
        self.components.clear()
        self.before_activity = dict(self.activity)
        self.before_counts = {k: dict(v) for k, v in self.counts.items()}

    def finish(self, status):
        row = self.current
        if row is None:
            return
        row["status"] = status
        row["components_ms"] = {k: v for k, v in self.components.items() if k.endswith("_ms")}
        row["activity_ms"] = {k: v - self.before_activity[k] for k, v in self.activity.items()}
        row["sent"] = {k: {f: n - self.before_counts.get(k, {}).get(f, 0)
                          for f, n in v.items()} for k, v in self.counts.items()}
        # 每项至多4KiB细节；核心失败事实不因细节超限丢弃。+128预留最后时戳。
        charge = len(json.dumps(row, allow_nan=False).encode()) + 128
        if charge > 4096:
            for key in ("components_ms", "activity_ms", "sent"):
                row.pop(key, None)
            self.detail_overflow += 1
            charge = len(json.dumps(row, allow_nan=False).encode()) + 128
        if len(self.rows) < self.capacity + 1:
            self.rows.append(row)
            self.encoded_charge += charge
        else:
            self.detail_overflow += 1
        end = time.perf_counter_ns()
        row["observation_end_ns"] = end
        if status == "confirmed":
            row["duration_ms"] = (end - row["consumption_start_ns"]) / 1e6
        else:
            row["failure_or_terminal_observed_ms"] = (end - row["consumption_start_ns"]) / 1e6
        self.current = None

    def confirmed(self, *_args):
        self.finish("confirmed")

    @contextmanager
    def installed(self):
        from secure_control.execution import lan_runtime, lan_scalar_runtime, lan_transport
        from secure_control.scenarios.cart_pole import secure_full_experiment as full

        stack = ExitStack()

        def wrap(owner, name, label, *, lifecycle=False, control=False):
            original = getattr(owner, name)
            def call(*args, **kwargs):
                start, status = time.perf_counter_ns(), "failed"
                if control and self.current:
                    self.current["control_started"] = True
                    self.current["epoch_id"] = getattr(args[0], "epoch_id", None) or getattr(args[0], "controller_epoch", None)
                    self.current["phase"] = ("dynamic" if label == "dynamic_step" else
                                             "kick" if args[0].epoch_id.startswith("kick-") else "energy")
                try:
                    result = original(*args, **kwargs)
                    status = "complete"
                    if control and self.current:
                        self.current.update({"protocol_completed": True,
                                             "round_id": result.round_id,
                                             "session_id": args[0].session_id if hasattr(args[0], "session_id")
                                             else result.session_id,
                                             "products": result.products, "truncations": result.truncations})
                    return result
                finally:
                    end = time.perf_counter_ns()
                    if self.current:
                        key = label + "_ms"
                        self.components[key] = self.components.get(key, 0.) + (end-start)/1e6
                    if lifecycle:
                        self.event(label, start, end, status)
            stack.enter_context(patch.object(owner, name, call))

        read = full.CartPoleObserverSimulation.read_measurement
        consume = full.CausalVelocityEstimator.observe
        observe = full.SwingUpSupervisor.observe
        send = full.CartPoleObserverSimulation.send_control

        def measured_read(*args, **kwargs):
            start = time.perf_counter_ns()
            result = read(*args, **kwargs)
            self.read_stamp = {"start_ns": start, "end_ns": time.perf_counter_ns()}
            return result

        def measured_consume(*args, **kwargs):
            self.begin()
            return consume(*args, **kwargs)

        def measured_observe(*args, **kwargs):
            result = observe(*args, **kwargs)
            if self.current:
                self.current["phase"] = result.phase
                self.current["supervision_phase"] = result.phase
            return result

        def measured_send(*args, **kwargs):
            result = send(*args, **kwargs)
            if self.current:
                self.current["device_confirmed"] = result.disposition == "simulated_interval_completed"
                self.current["device_return_ns"] = time.perf_counter_ns()
            return result

        try:
            stack.enter_context(patch.object(full.CartPoleObserverSimulation, "read_measurement", measured_read))
            stack.enter_context(patch.object(full.CausalVelocityEstimator, "observe", measured_consume))
            stack.enter_context(patch.object(full.SwingUpSupervisor, "observe", measured_observe))
            stack.enter_context(patch.object(full.CartPoleObserverSimulation, "send_control", measured_send))
            stack.enter_context(_observe_dynamic(self.components))
            for owner, name, label in (
                (full, "certify_swing_up_arithmetic", "energy_certificate"),
                (full, "certify_scalar_program", "kick_certificate"),
                (full, "sustained_observer_numeric_contract", "dynamic_numeric_proof"),
                (LanScalarRuntime, "__init__", "scalar_epoch_setup"),
                (lan_runtime.LanSegmentedRuntime, "__init__", "dynamic_epoch_setup"),
                (LanScalarRuntime, "end", "scalar_epoch_end"),
                (lan_runtime.LanSegmentedRuntime, "end_segment", "dynamic_segment_end"),
                (lan_runtime.LanSegmentedRuntime, "next_segment", "dynamic_segment_begin"),
                (lan_scalar_runtime, "connect_role", "scalar_connect"),
                (lan_runtime, "connect_role", "dynamic_connect"),
                (lan_transport, "connect_tls", "authentication_connect"),
            ):
                wrap(owner, name, label, lifecycle=True)
            wrap(LanScalarRuntime, "step", "scalar_step", control=True)
            wrap(lan_runtime.LanSegmentedRuntime, "step", "dynamic_step", control=True)
            wrap(lan_scalar_runtime, "prepare_scalar_round", "scalar_material_prepare")
            wrap(lan_scalar_runtime.FixedPointContext, "decode_residue", "scalar_reconstruct")
            for name in ("_send", "_receive"):
                original = getattr(lan_scalar_runtime, name)
                def io(sock, frame, deadline, *, _call=original, _name=name):
                    label = {"material": "scalar_distribution", "ready": "scalar_distribution",
                             "compute": "scalar_stage", "result": "scalar_stage",
                             "commit": "scalar_commit", "committed": "scalar_commit"}.get(frame.operation)
                    start = time.perf_counter_ns()
                    try:
                        return _call(sock, frame, deadline)
                    finally:
                        if label and self.current:
                            self.components[label+"_ms"] = self.components.get(label+"_ms", 0.) + (time.perf_counter_ns()-start)/1e6
                stack.enter_context(patch.object(lan_scalar_runtime, name, io))
            yield self
        finally:
            stack.close()


def run_full_observation(*, steps: int, delay_ms: float, segment_steps: int = 400,
                         role_config: Path | None = None, fixed_proof_cache: bool = False) -> dict[str, object]:
    """有界P0完整路线观察；原非实时循环、提前测量与失败契约保持。"""
    from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
    from secure_control.scenarios.cart_pole.secure_full_experiment import run_secure_full_experiment
    from secure_control.scenarios.cart_pole.swing_up import load_cart_pole_swing_up_config

    from .lan_profile import _load_prime

    started = time.perf_counter_ns()
    if type(fixed_proof_cache) is not bool:
        raise ValueError("fixed_proof_cache必须是显式bool")
    if type(steps) is not int or not 1 <= steps <= 1500:
        raise ValueError("full观察只允许原有限范围内1..1500步，不自动运行10k")
    if type(segment_steps) is not int or not 1 <= segment_steps <= 1000:
        raise ValueError("段容量必须在1..1000")
    if isinstance(delay_ms, bool) or not isinstance(delay_ms, (int, float)) or not 0 <= delay_ms <= 3:
        raise ValueError("每应用帧注入等待必须在0..3ms")
    design = load_cart_pole_observer_design(_ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(_ROOT / "configs/cart_pole_swing_up.yaml", design.plant, design.balance)
    # 不调整acquisition或其他控制参数来凑短horizon；非法组合在建连前拒绝。
    swing = replace(swing, horizon_steps=steps)
    swing.validate(design.plant, design.balance)
    modulus, evidence, _ = _load_prime(_ROOT / "configs/shared_prime_256_pocklington.yaml")
    ports = _ports()
    config = _config("Client", ports) if role_config is None else load_lan_config(role_config, "Client")
    if role_config is not None:
        ports = tuple(e.port for e in (config.topology.p1_client, config.topology.p2_client, config.topology.p1_peer))
    context = mp.get_context("spawn")
    queue = context.Queue()
    parties = [context.Process(target=_party_job, args=(_config(role, ports), ports, delay_ms, True, queue, False, True))
               for role in ("P1", "P2")] if role_config is None else []
    counts, activity, restore = _meter("Client", ports, delay_ms)
    observer = _FullObservation(steps, counts, activity)
    observer.started = started
    result, failure, outcomes = None, None, []
    try:
        for party in parties:
            party.start()
        with observer.installed():
            result = run_secure_full_experiment(design.plant, design.balance, swing, design, config,
                       modulus=modulus, modulus_evidence=evidence, segment_capacity=segment_steps,
                       on_step=observer.confirmed,
                       **({"fixed_proof_cache": True} if fixed_proof_cache else {}))
        if observer.current:
            terminal = (observer.current["physical_step"] == steps and result.physical.failure_reason is None)
            observer.finish("terminal_observation" if terminal else "failed")
        failure = result.physical.failure_reason
    except Exception as error:  # noqa: BLE001 - 失败只导出类别，不导出消息/payload
        failure = type(error).__name__
        observer.finish("failed")
    finally:
        restore()
        # Queue先读后join，避免较大公开汇总占满管道；异常也回收已有子进程。
        if parties:
            outcomes = _party_outcomes(queue)
        for party in parties:
            if party.pid is not None:
                party.join(timeout=5)
                if party.is_alive():
                    party.terminate()
                    party.join(timeout=5)
        queue.close()
    attempts = [r for r in observer.rows if r["status"] != "terminal_observation"]
    complete = [r for r in attempts if r["status"] == "confirmed"]
    directions = dict(counts)
    for item in outcomes:
        directions.update(item["directions"])
    return {
        "schema": "communication-benchmark-v1", "case": "full-observation", "mode": "batch",
        "code_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=_ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=_ROOT, text=True).strip()),
        "source_sha256": _source_fingerprints((
            "src/secure_control/scenarios/cart_pole/secure_full_experiment.py",
            "src/secure_control/scenarios/cart_pole/swing_up.py",
            "src/secure_control/scenarios/cart_pole/swing_up_numeric.py",
            "src/secure_control/execution/lan_scalar_runtime.py", "src/secure_control/protocol/arithmetic.py",
            "configs/cart_pole_swing_up.yaml", "configs/shared_prime_256_pocklington.yaml",
            "configs/cart_pole_plant.yaml", "configs/cart_pole_balance.yaml")),
        "configuration": {"horizon_steps": steps, "segment_steps": segment_steps,
                          "fixed_proof_cache": fixed_proof_cache,
                          "profile_sha256": config.topology.digest, "period_s": design.plant.sample_period_s,
                          "role_config_sha256": sha256(role_config.read_bytes()).hexdigest() if role_config else None},
        "environment": {"os": platform.platform(), "python": platform.python_version(),
                        "cpu_count": os.cpu_count(), "roles": "three local processes" if parties else "external parties",
                        "transport": config.transport, "delay_model": "sleep before each application frame send",
                        "injected_delay_ms": delay_ms, "injection_roles": ["Client", "P1", "P2"] if parties else ["Client"]},
        "status": "failed" if failure else "complete", "failure_type": failure,
        "termination": result.physical.termination if result else "failed",
        "goal_met": result.physical.goal_met if result else False,
        "successful_steps": len(complete), "failed_attempts": sum(r["status"] == "failed" for r in attempts),
        "canonical_physical_confirmed_steps": result.physical.completed_steps if result else 0,
        "epochs": [{k: e.get(k) for k in ("physical_start", "phase", "epoch_id", "session_id",
                                         "previous_session_id", "program_sha256", "fractional_bits")}
                   for e in result.epoch_events] if result else [],
        "steps": attempts, "terminal_observation": [r for r in observer.rows if r["status"] == "terminal_observation"],
        "events": observer.events, "party_outcomes": outcomes, "directions_all_session": directions,
        "client_memory": _process_memory(), "activity_all_session_ms": activity,
        "timing": _timing([r["duration_ms"] for r in complete]),
        "phase_timing": {p: _timing([r["duration_ms"] for r in complete if r["phase"] == p])
                         for p in sorted({r["phase"] for r in complete})},
        "initial_preparation_ms": ((observer.rows[0]["consumption_start_ns"]-observer.started)/1e6
                                   if observer.rows else None),
        "role_exit_codes": [p.exitcode for p in parties],
        "qualification_pass": False, "absolute_scheduling": False,
        "proof_cache": result.proof_cache_summary if result else None,
        "observation_limits": {"step_capacity": steps+1, "event_capacity": 256, "step_detail_bytes": 4096,
                               "event_overflow": observer.event_overflow, "detail_overflow": observer.detail_overflow,
                               "step_encoded_charge_bytes": observer.encoded_charge},
        "timing_scope": "measurement consumption through confirmed callback; measurement was read earlier; failed elapsed includes unwind; nested costs cannot be summed; no scheduled jitter/deadline or real hardware evidence",
        "byte_scope": "attempted application sends including 4-byte framing; failed sends may be partial; not TCP packet or actual failed wire-byte counts",
        "party_scope": "local per-role wall includes socket waits; no uncalibrated cross-host subtraction; external party internals not observed",
    }


def run_local_benchmark(
    case: str, mode: str, *, steps: int, delay_ms: float,
) -> dict[str, object]:
    """同一代码头上可重复选择显式旧协议或默认批量协议。"""
    if case not in {"dynamic", "scalar"} or mode not in {"legacy", "batch"}:
        raise ValueError("基准 case/mode 无效")
    if type(steps) is not int or not 2 <= steps <= 400:
        raise ValueError("基准须含2..400个观测步骤，首步不剔除")
    if not isinstance(delay_ms, (int, float)) or not 0 <= delay_ms <= 3:
        raise ValueError("单向注入延迟必须在0..3ms")
    ports = _ports()
    context = mp.get_context("spawn")
    queue = context.Queue()
    parties = [context.Process(target=_party_job,
                               args=(_config(role, ports), ports, delay_ms,
                                     mode == "batch", queue))
               for role in ("P1", "P2")]
    for party in parties:
        party.start()
    counts, activity, restore = _meter("Client", ports, delay_ms)
    timings: list[float] = []
    per_step_activity: list[dict[str, float]] = []
    phase_samples: list[dict[str, float]] = []
    attempts = []
    outcomes = []
    numeric_profile = {}
    failure = None
    initial_setup_ms = None

    def measured_step(call):
        started = time.perf_counter_ns()
        status = "confirmed"
        try:
            return call()
        except Exception:
            status = "failed"
            raise
        finally:
            elapsed = (time.perf_counter_ns() - started) / 1e6
            timings.append(elapsed)
            attempts.append({"step": len(attempts), "status": status, "duration_ms": elapsed})
    try:
        config = _config("Client", ports)
        if case == "dynamic":
            from secure_control.execution import lan_runtime
            from secure_control.protocol import Client

            from .lan_continuous_profile import load_prepared_lan_experiment

            prepared = load_prepared_lan_experiment(config.experiment_config)
            contract = replace(prepared.contract, horizon_steps=steps)
            numeric_profile = {
                "fractional_bits": prepared.context.fractional_bits,
                "modulus_bits": prepared.context.modulus.bit_length(),
                "state_dimension": prepared.spec.state_dimension,
                "input_dimension": prepared.spec.input_dimension,
                "output_dimension": prepared.spec.output_dimension,
            }
            prepare = Client.prepare_online
            complete = lan_runtime._complete_client_round
            marks: dict[str, int] = {}

            def measured_prepare(self, *args, **kwargs):
                marks["prepare_start"] = time.perf_counter_ns()
                result = prepare(self, *args, **kwargs)
                marks["prepare_end"] = time.perf_counter_ns()
                return result

            def measured_complete(client, p1, p2, plan, *, batch, on_phase=None):
                marks["stage_start"] = time.perf_counter_ns()
                def measured_phase(name):
                    marks[name] = time.perf_counter_ns()
                    if on_phase is not None:
                        on_phase(name)
                return complete(client, p1, p2, plan, on_phase=measured_phase, batch=batch)

            with (patch.object(Client, "prepare_online", measured_prepare),
                  patch.object(lan_runtime, "_complete_client_round", measured_complete)):
                setup_start = time.perf_counter_ns()
                runtime = LanContinuousRuntime(
                    config, prepared.spec, prepared.context, contract,
                    prepared.security_parameter, prepared.evidence, batch=mode == "batch",
                )
                initial_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
                try:
                    for _ in range(steps):
                        marks.clear()
                        before = dict(activity)
                        measured_step(lambda: runtime.step(np.zeros(prepared.spec.input_dimension)))
                        per_step_activity.append({name: activity[name] - value
                                                  for name, value in before.items()})
                        phase_samples.append({
                            "material_prepare_ms": (marks["prepare_end"] -
                                                    marks["prepare_start"]) / 1e6,
                            "online_distribution_ms": (marks["stage_start"] -
                                                       marks["prepare_end"]) / 1e6,
                            "stage_ms": (marks["stage"] - marks["stage_start"]) / 1e6,
                            "reconstruct_ms": (marks["reconstruct"] - marks["stage"]) / 1e6,
                            "commit_ms": (marks["commit"] - marks["reconstruct"]) / 1e6,
                        })
                    runtime.finish()
                finally:
                    runtime.close()
        else:
            from secure_control.execution import lan_scalar_runtime
            from secure_control.experiments.lan_profile import _load_prime
            from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
            from secure_control.scenarios.cart_pole.swing_up import load_cart_pole_swing_up_config
            from secure_control.scenarios.cart_pole.swing_up_numeric import (
                certify_swing_up_arithmetic,
            )

            design = load_cart_pole_observer_design(_ROOT / "configs/cart_pole_observer.yaml")
            swing = load_cart_pole_swing_up_config(
                _ROOT / "configs/cart_pole_swing_up.yaml", design.plant, design.balance,
            )
            modulus, evidence, _ = _load_prime(
                _ROOT / "configs/shared_prime_256_pocklington.yaml"
            )
            program, certificate = certify_swing_up_arithmetic(
                design.plant, design.balance, swing, modulus=modulus,
                modulus_evidence=evidence,
            )
            numeric_profile = {
                "fractional_bits": certificate.fractional_bits,
                "modulus_bits": modulus.bit_length(),
                "multiplication_gates": 38,
            }
            prepare = lan_scalar_runtime.prepare_scalar_round
            send = lan_scalar_runtime._send
            receive = lan_scalar_runtime._receive
            marks: dict[str, int] = {}

            def measured_prepare(*args, **kwargs):
                marks["prepare_start"] = time.perf_counter_ns()
                result = prepare(*args, **kwargs)
                marks["prepare_end"] = time.perf_counter_ns()
                return result

            def measured_send(sock, frame, deadline):
                if frame.sender == "Client" and frame.recipient == "P1" and frame.operation in {
                    "compute", "commit",
                }:
                    marks[f"{frame.operation}_start"] = time.perf_counter_ns()
                return send(sock, frame, deadline)

            def measured_receive(sock, expected, deadline):
                result = receive(sock, expected, deadline)
                if expected.sender == "P2" and expected.recipient == "Client" and (
                    expected.operation in {"ready", "result", "committed"}
                ):
                    marks[f"{expected.operation}_end"] = time.perf_counter_ns()
                return result

            with (patch.object(lan_scalar_runtime, "prepare_scalar_round", measured_prepare),
                  patch.object(lan_scalar_runtime, "_send", measured_send),
                  patch.object(lan_scalar_runtime, "_receive", measured_receive)):
                setup_start = time.perf_counter_ns()
                runtime = LanScalarRuntime(
                    config, program, certificate, modulus=modulus,
                    modulus_evidence=evidence, run_id="public-communication-benchmark",
                    epoch_id="synthetic-step", start_physical_step=0,
                    batch=mode == "batch",
                )
                initial_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
                try:
                    values = {"p": .2, "v": -.4, "beta": .31, "omega": 1.7}
                    for step in range(steps):
                        marks.clear()
                        before = dict(activity)
                        measured_step(lambda current_step=step: runtime.step(values, current_step))
                        per_step_activity.append({name: activity[name] - value
                                                  for name, value in before.items()})
                        phase_samples.append({
                            "material_prepare_ms": (marks["prepare_end"] -
                                                    marks["prepare_start"]) / 1e6,
                            "online_distribution_ms": (marks["ready_end"] -
                                                       marks["prepare_end"]) / 1e6,
                            "stage_ms": (marks["result_end"] -
                                         marks["compute_start"]) / 1e6,
                            "reconstruct_ms": (marks["commit_start"] -
                                               marks["result_end"]) / 1e6,
                            "commit_ms": (marks["committed_end"] -
                                          marks["commit_start"]) / 1e6,
                        })
                    runtime.end()
                finally:
                    runtime.close()
        outcomes = _party_outcomes(queue)
        for party in parties:
            party.join(timeout=10)
        if any(party.exitcode != 0 for party in parties) or any(
            item["status"] not in {"closed", "complete"} for item in outcomes
        ):
            raise RuntimeError("角色未成功完成基准会话")
    except Exception as error:  # noqa: BLE001 - 原始失败只保留公开错误类别及已观测尝试
        failure = type(error).__name__
        if not outcomes:
            outcomes = _party_outcomes(queue)
    finally:
        restore()
        for party in parties:
            if party.is_alive():
                party.terminate()
                party.join(timeout=5)
        queue.close()
    directions = dict(counts)
    for item in outcomes:
        directions.update(item["directions"])
    overhead = {name: 5 if case == "dynamic" else 4
                for name in ("Client->P1", "Client->P2", "P1->Client", "P2->Client")}
    overhead.update({"P1->P2": 1, "P2->P1": 1})
    online_frames = {}
    for direction, fixed_frames in overhead.items():
        if failure is not None:
            break
        actual = directions[direction]["frames"] - fixed_frames
        if actual < 0 or actual % steps:
            raise RuntimeError("公开帧数不符合固定会话 setup/结束边界")
        online_frames[direction] = actual // steps
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                                  text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"],
                                         cwd=_ROOT, text=True).strip())
    return {
        "schema": "communication-benchmark-v1", "case": case, "mode": mode,
        "status": "failed" if failure else "complete", "failure_type": failure,
        "code_sha": sha, "dirty": dirty,
        "source_sha256": _source_fingerprints(),
        "command": ["secure-control", "benchmark", "--case", case, "--mode", mode,
                    "--steps", str(steps), "--delay-ms", str(delay_ms)],
        "environment": {"os": platform.platform(), "python": sys.version.split()[0],
                        "cpu_count": mp.cpu_count(), "architecture": platform.machine(),
                        "roles": "three local processes", "transport": "insecure_tcp",
                        "delay_model": "sleep before each application frame send",
                        "one_way_delay_ms": delay_ms,
                        "timer": "perf_counter_ns; Client online prepare through double commit"},
        "configuration_reference": "configs/cart_pole_observer_lan.example.yaml"
        if case == "dynamic" else "configs/cart_pole_swing_up.yaml",
        "public_topology_sha256": config.topology.digest,
        "numeric_profile": numeric_profile,
        "steps": steps, "successful_steps": sum(item["status"] == "confirmed" for item in attempts),
        "failed_steps": sum(item["status"] == "failed" for item in attempts),
        "raw_attempts": attempts, "initial_setup_ms": initial_setup_ms,
        "resources_per_step": {"products": 30 if case == "dynamic" else 38,
                               "truncations": 4 if case == "dynamic" else 38},
        "timing": _timing(timings), "directions_all_session": directions,
        "online_frames_per_step": online_frames,
        "client_request_reply_groups_per_step": (
            online_frames["Client->P1"] + online_frames["Client->P2"] if not failure else None
        ),
        "peer_frames_per_step": online_frames["P1->P2"] + online_frames["P2->P1"] if not failure else None,
        "online_frame_derivation": "whole-session directional frames minus fixed setup/end frames (Client 5 dynamic or 4 scalar per direction; peer 1 per direction), divided by steps",
        "client_phase_p50_ms": {
            name: _quantile([item[name] for item in phase_samples], .5)
            for name in (phase_samples[0] if phase_samples else {})
        },
        "client_step_activity_p50_ms": {
            name: _quantile([item[name] for item in per_step_activity], .5) if per_step_activity else None
            for name in activity
        },
        "party_activity_all_session_ms": {
            item["role"]: item["activity_ms"] for item in outcomes
        },
        "party_steps": {item["role"]: item["steps"] for item in outcomes},
        "raw_step_phases_ms": phase_samples,
        "raw_step_activity_ms": per_step_activity,
        "activity_scope": "Client activity is within step; send includes injected delay, receive includes waiting; encode/decode and wall phases overlap, stage includes remote compute and peer I/O",
        "byte_scope": "application frame payload plus 4-byte header; includes setup/end; excludes TCP/TLS overhead",
        "limits": "synthetic kernel benchmark, no plant, GUI, three-machine network or 20ms guarantee",
    }
