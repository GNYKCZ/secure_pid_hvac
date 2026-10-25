"""普通持续实验的有界公开计时汇总；不拥有控制、网络或密码材料。"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import struct
import subprocess
import tempfile
from array import array
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter_ns
from uuid import uuid4

from secure_control.execution.cycle_timing import StepTimingObservation

PHASES = (
    "input",
    "material_bind",
    "online_distribution",
    "stage",
    "single_exchange",
    "reconstruct",
    "commit",
    "device",
    "recording",
    "maintenance",
    "maintenance_end",
    "maintenance_advance",
    "maintenance_seal",
    "maintenance_source",
    "maintenance_begin",
    "maintenance_release",
    "p1_commit",
    "p2_commit",
)
QUEUES = (
    "level",
    "capacity",
    "material_slots",
    "inventory_inflight",
    "material_high_water",
    "generated_received",
    "claimed",
)
NUMBERS = tuple(
    k
    for k in StepTimingObservation.__dataclass_fields__
    if k.endswith("_ns") and k != "phase_durations_ns"
)
NUMBERS = ("attempt_seq", "global_step", "segment_index", *NUMBERS)
ROW = struct.Struct("<" + "q" * (len(NUMBERS) + len(PHASES) + len(QUEUES)) + "128s32s64s")
BIN_NS = 100_000
BINS = 10_001
STATUSES = {
    "confirmed",
    "failed",
    "cancelled",
    "uncertain",
    "miss_after_apply",
    "miss_before_apply",
    "stopped_before_commit",
}


def performance_options(mode, *, supported, output=None, sample_limit=None):
    """联网前选择默认值并拒绝被忽略的选项，off 不创建观察器。"""
    selected = ("summary" if supported else "off") if mode is None else mode
    if selected not in ("off", "summary", "samples") or selected != "off" and not supported:
        raise ValueError("性能观察只支持动态持续light。")
    if sample_limit is not None and (
        selected != "samples" or type(sample_limit) is not int or not 1 <= sample_limit <= 10_000
    ):
        raise ValueError("sample-limit 仅支持samples，范围1..10000；它不是运行步数。")
    if selected == "off" and output is not None:
        raise ValueError("performance off 不能指定报告输出。")
    target = None
    if selected != "off":
        target = (
            Path(output)
            if output is not None
            else Path("results/lan_continuous/performance") / f"{uuid4().hex}.json"
        )
        if target.exists() or target.is_symlink():
            raise ValueError("性能报告目标已存在，不能覆盖。")
        target = target.resolve()
        if target.exists() or target.is_symlink():
            raise ValueError("性能报告目标已存在，不能覆盖。")
        if target.suffix.lower() != ".json":
            raise ValueError("性能报告必须是新JSON文件。")
        if any((parent / "run.json").is_file() for parent in target.parents):
            raise ValueError("性能报告不能写入正式轨迹目录。")
        for parent in target.parents:
            if parent.exists():
                if not parent.is_dir():
                    raise ValueError("性能报告父路径不是目录。")
                break
    return selected, target, sample_limit if sample_limit is not None else 10_000


class _Metric:
    """计数/极值精确累计；只有三个主要耗时使用固定直方图。"""

    def __init__(self, histogram=False):
        self.count = self.total = self.above15 = self.above20 = 0
        self.minimum = self.maximum = None
        self.hist = array("Q", [0]) * BINS if histogram else None

    def add(self, value):
        previous = (self.count, self.total, self.minimum, self.maximum, self.above15, self.above20)
        if type(value) is not int or value < 0 or self.total + value >= 2**63:
            raise ValueError("统计值或累计值溢出。")
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        self.above15 += value > 15_000_000
        self.above20 += value > 20_000_000
        index = min(value // BIN_NS, BINS - 1)
        if self.hist is not None:
            self.hist[index] += 1
        return previous, index

    def undo(self, saved):
        previous, index = saved
        (self.count, self.total, self.minimum, self.maximum, self.above15, self.above20) = previous
        if self.hist is not None:
            self.hist[index] -= 1

    def report(self):
        result = {
            "count": self.count,
            "sum_ns": self.total,
            "min_ns": self.minimum,
            "max_ns": self.maximum,
            "mean_ns": self.total / self.count if self.count else None,
            "above_15ms": self.above15,
            "above_20ms": self.above20,
        }
        if self.hist is not None:
            quantiles = {}
            for name, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
                quantiles[name] = None
                rank, cumulative = math.ceil(fraction * self.count), 0
                if self.count:
                    for k, count in enumerate(self.hist):
                        cumulative += count
                        if cumulative >= rank:
                            quantiles[name] = {
                                "lower_ns": k * BIN_NS,
                                "upper_ns": (k + 1) * BIN_NS if k < BINS - 1 else None,
                            }
                            break
            result.update(
                quantiles=quantiles,
                histogram={
                    "method": "nearest_rank_interval",
                    "bin_width_ns": BIN_NS,
                    "overflow_lower_ns": 1_000_000_000,
                    "counts": list(self.hist),
                },
            )
        return result


def _pack(row):
    values = [getattr(row, k) for k in NUMBERS]
    if row.status not in STATUSES:
        raise ValueError("未知观察状态。")
    for mapping in (row.phase_durations_ns, row.queue_levels):
        if any(type(v) is not int or not 0 <= v < 2**63 for v in mapping.values()):
            raise ValueError("公开阶段/库存不是有界非负整数。")
    values += [row.phase_durations_ns.get(k) for k in PHASES]
    values += [row.queue_levels.get(k) for k in QUEUES]
    strings = []
    for value, capacity in ((row.round_id, 128), (row.status, 32), (row.failure_phase, 64)):
        encoded = (value or "").encode("utf-8")
        if len(encoded) >= capacity or b"\0" in encoded:
            raise ValueError("公开身份或阶段名超过记录容量。")
        strings.append(encoded)
    return ROW.pack(*[-1 if v is None else v for v in values], *strings)


def _unpack(data):
    values = ROW.unpack(data)
    row = {k: None if v == -1 else v for k, v in zip(NUMBERS, values, strict=False)}
    offset = len(NUMBERS)
    row["phase_durations_ns"] = {
        k: v for k, v in zip(PHASES, values[offset : offset + len(PHASES)], strict=True) if v != -1
    }
    offset += len(PHASES)
    row["queue_levels"] = {
        k: v for k, v in zip(QUEUES, values[offset : offset + len(QUEUES)], strict=True) if v != -1
    }
    for key, value in zip(("round_id", "status", "failure_phase"), values[-3:], strict=True):
        row[key] = value.rstrip(b"\0").decode("utf-8") or None
    start = row["actual_sample_start_ns"]
    for key, end in (
        ("control_latency_ns", "control_applied_ns"),
        ("work_elapsed_ns", "work_completed_ns"),
    ):
        row[key] = row[end] - start if row[end] is not None else None
    row["lateness_ns"] = (
        max(0, start - row["scheduled_start_ns"])
        if start is not None and row["scheduled_start_ns"] is not None
        else None
    )
    return row


class LiveTimingCollector:
    """单控制线程拥有汇总；固定数值缓冲，UI只接收独立的有界快照。"""

    def __init__(self, mode="summary", *, sample_limit=10_000, on_snapshot=None):
        if (
            mode not in ("summary", "samples")
            or type(sample_limit) is not int
            or not 1 <= sample_limit <= 10_000
        ):
            raise ValueError("性能采样模式/容量无效。")
        self.mode, self.limit = mode, sample_limit if mode == "samples" else 0
        self.raw = bytearray(ROW.size * self.limit)
        self.recent = bytearray(ROW.size * 256)
        self.slowest = []
        self.metrics = {
            k: _Metric(True)
            for k in ("control_latency_ns", "work_elapsed_ns", "sample_interval_ns")
        }
        self.metrics.update(
            {
                k: _Metric()
                for k in (
                    *PHASES,
                    "pacing_requested_ns",
                    "pacing_elapsed_ns",
                    "pacing_excess_ns",
                    "observation_ns",
                )
            }
        )
        self.buffer_bytes = (
            len(self.raw) + len(self.recent) + 3 * BINS * 8 + ROW.size * 16 + 262_144
        )
        if self.buffer_bytes > 8 * 1024 * 1024:
            raise ValueError("性能缓冲超过8MiB。")
        self.count = 0
        self.status_counts = {k: 0 for k in STATUSES}
        self.first_failure = self.observation_error = self.waiting_terminal = None
        self.lifecycle_ns = {}
        self._undo = None
        self._last = None
        self._first = None
        self._correcting = False
        self._publish_at = 0
        self.on_snapshot = on_snapshot
        self.completion_clock = None

    def disable(self, error):
        """观察错误只使统计partial；不冒充控制失败或吞掉原始控制异常。"""
        if self.observation_error is None:
            self.observation_error = type(error).__name__

    def record(self, row):
        """记录一份最终事实；常数容量，不排序全历史或写盘。"""
        if self.observation_error:
            return
        saved = None
        previous_undo = self._undo
        try:
            started = self.completion_clock() if self.completion_clock else perf_counter_ns()
            packed = _pack(row)
            if self.count >= 2**63 - 1:
                raise ValueError("观察计数溢出。")
            if row.attempt_seq != self.count:
                raise ValueError("观察序号不连续。")
            saved = ({}, self.first_failure, list(self.slowest))
            self._undo = saved
            data = _unpack(packed)
            measurements = {
                k: data[k]
                for k in (
                    "control_latency_ns",
                    "work_elapsed_ns",
                    "sample_interval_ns",
                    "pacing_requested_ns",
                    "pacing_elapsed_ns",
                    "pacing_excess_ns",
                    "observation_ns",
                )
            }
            measurements.update(data["phase_durations_ns"])
            for key, value in measurements.items():
                if value is not None and key not in ("work_elapsed_ns", "observation_ns"):
                    saved[0][key] = self.metrics[key].add(value)
            # 显示上一份已提交观察；本次统计仍逐步记录，不受显示合并影响。
            self.publish()
            endpoint = self.completion_clock() if self.completion_clock else perf_counter_ns()
            row = replace(
                row,
                observation_ns=row.observation_ns + endpoint - started,
                work_completed_ns=endpoint
                if self.completion_clock and row.work_completed_ns is not None
                else row.work_completed_ns,
            )
            packed = _pack(row)
            data = _unpack(packed)
            for key in ("work_elapsed_ns", "observation_ns"):
                if data[key] is not None:
                    saved[0][key] = self.metrics[key].add(data[key])
            slot = self.count % 256
            self.recent[slot * ROW.size : (slot + 1) * ROW.size] = packed
            if self.count < self.limit:
                self.raw[self.count * ROW.size : (self.count + 1) * ROW.size] = packed
            if self.count == 0:
                self._first = packed
            self.count += 1
            self.status_counts[row.status] += 1
            if (
                row.status not in ("confirmed", "stopped_before_commit")
                and self.first_failure is None
            ):
                self.first_failure = packed
            work = data["work_elapsed_ns"]
            if work is not None:
                if len(self.slowest) < 8:
                    self.slowest.append((work, packed))
                elif work > min(self.slowest, key=lambda item: item[0])[0]:
                    at = min(range(8), key=lambda k: self.slowest[k][0])
                    self.slowest[at] = (work, packed)
            self._last = packed
        except Exception as error:  # noqa: BLE001 - 观察故障与控制故障分开
            if saved is not None and self.count == row.attempt_seq:
                for key, state in saved[0].items():
                    self.metrics[key].undo(state)
                self.first_failure, self.slowest = saved[1:]
                self._undo = previous_undo
            self.disable(error)

    def correct_last(self, row):
        """撤销同一尝试的临时成功贡献，含极值/直方图/最慢样本，不追加第二行。"""
        if self.observation_error:
            return
        try:
            started = self.completion_clock() if self.completion_clock else perf_counter_ns()
            if not self._last or row.attempt_seq != self.count - 1:
                raise ValueError("只允许修正最后同一观察。")
            self._correcting = True
            previous_cost = _unpack(self._last)["observation_ns"]
            for key, state in self._undo[0].items():
                self.metrics[key].undo(state)
            self.first_failure, self.slowest = self._undo[1:]
            self.status_counts[_unpack(self._last)["status"]] -= 1
            self.count -= 1
            # 修正期间只能发布前一份最终事实；首次尝试撤销后没有可发布的旧行。
            self._last = bytes(self._recent_at(self.count - 1)) if self.count else None
            now = self.completion_clock() if self.completion_clock else perf_counter_ns()
            row = replace(
                row, observation_ns=max(row.observation_ns, previous_cost) + now - started
            )
            self.record(row)
            self._correcting = False
            self.publish()
        except Exception as error:  # noqa: BLE001
            self.disable(error)
        finally:
            self._correcting = False

    def publish(self, *, force=False):
        """最多100ms一次的不可变副本；不向UI暴露直方图或共享可变容器。"""
        if self._correcting:
            return
        now = perf_counter_ns()
        if self.on_snapshot is not None and (force or now >= self._publish_at):
            self._publish_at = now + 100_000_000
            latest = _unpack(self._last) if self._last else None
            points = []
            for k in range(max(0, self.count - 256), self.count):
                values = ROW.unpack(self._recent_at(k))
                start, end = (
                    values[NUMBERS.index("actual_sample_start_ns")],
                    values[NUMBERS.index("work_completed_ns")],
                )
                points.append((values[1], end - start if end != -1 else None))
            trend = tuple(points)
            self.on_snapshot(
                {
                    "observations": self.count,
                    "latest": latest,
                    "trend": trend,
                    "statistics_complete": not self.observation_error,
                }
            )

    def _recent_at(self, k):
        at = k % 256 * ROW.size
        return self.recent[at : at + ROW.size]

    def report(self):
        """退出后才展开原始样本/扫描直方图，分位明确全程近似与首N范围。"""
        captured = min(self.limit, self.count)

        def boundary(packed):
            row = _unpack(packed)
            return {
                key: row[key]
                for key in (
                    "attempt_seq",
                    "global_step",
                    "segment_index",
                    "actual_sample_start_ns",
                    "control_applied_ns",
                    "work_completed_ns",
                )
            }

        return {
            "schema": "cart_pole_live_timing",
            "format_version": 1,
            "mode": self.mode,
            "observations": self.count,
            "observation_range": {
                "first": boundary(self._first) if self.count else None,
                "last": boundary(self._last) if self.count else None,
            },
            "statistics_complete": not self.observation_error,
            "observation_error": self.observation_error,
            "status_counts": dict(self.status_counts),
            "metrics": {
                k: {**v.report(), "missing_count": self.count - v.count}
                for k, v in self.metrics.items()
            },
            "first_failure": _unpack(self.first_failure) if self.first_failure else None,
            "recent": [
                _unpack(self._recent_at(k)) for k in range(max(0, self.count - 256), self.count)
            ],
            "slowest": [_unpack(p) for _, p in sorted(self.slowest, reverse=True)],
            "raw": {
                "enabled": self.mode == "samples",
                "capacity": self.limit,
                "captured": captured,
                "omitted": self.count - captured,
                "complete": captured == self.count,
                "scope": "first N observations; includes failures; capacity does not stop control",
                "samples": [
                    _unpack(self.raw[k * ROW.size : (k + 1) * ROW.size]) for k in range(captured)
                ],
            },
            "waiting_terminal": self.waiting_terminal,
            "lifecycle_ns": dict(self.lifecycle_ns),
            "buffer_bytes": self.buffer_bytes,
            "observation_boundary": "observation_ns measures assembly/aggregation/UI snapshot up to terminal stamp; fixed final histogram/packing/buffer stores are not self-measured; all remain inside original strict deadline check",
            "phase_semantics": "stage/single_exchange include distribution/server processing/network wait, not pure RTT; preauthorized single_exchange includes READY and commit; old stage/commit absent there; maintenance parent contains maintenance_*; commit contains p1/p2_commit; do not sum nested times",
        }


def timing_metadata(config, prepared, *, non_realtime, mode):
    """建连前只采一次本机来源，不复制秘密/测量轨迹，不探测对端。"""
    root = Path(__file__).resolve().parents[3]
    try:
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=3
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=root, text=True, timeout=3
            ).strip()
        )
        local = {"head": head, "dirty": dirty}
    except (OSError, subprocess.SubprocessError):
        local = {"head": None, "dirty": None}
    return {
        "started_at_utc": datetime.now(UTC).isoformat(),
        "local_git": local,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "transport": config.transport,
        "wire_profile": config.wire_profile,
        "client_io": config.client_io,
        "timing_mode": "non_realtime_demo" if non_realtime else "absolute",
        "model_period_s": prepared.scene.period,
        "segment_steps": prepared.segment_capacity,
        "performance_mode": mode,
        "topology_digest": config.topology.digest,
        "peer_head": "unknown",
        "peer_network": "unknown",
        "experiment_sha256": hashlib.sha256(config.experiment_config.read_bytes()).hexdigest(),
        "effective_config_sha256": hashlib.sha256(
            json.dumps(
                prepared.effective_config, sort_keys=True, default=str, separators=(",", ":")
            ).encode()
        ).hexdigest(),
        "clock": "local perf_counter_ns; never subtract clocks across hosts",
        "reference_thresholds_ns": [15_000_000, 20_000_000],
        "scope": "performance observation, not full trajectory or safety qualification",
    }


def export_timing(collector, target, metadata, outcome):
    """控制和worker已退出后集中导出；硬链接原子发布且拒绝覆盖原文件。"""
    report = None
    temporary = None
    try:
        report = collector.report()
        report.update(
            metadata=metadata,
            control_outcome={
                k: outcome.get(k)
                for k in (
                    "status",
                    "category",
                    "failure_phase",
                    "run_id",
                    "confirmed_step_count",
                    "protocol_committed_count",
                    "cycle_summary",
                    "material_source",
                    "wall_elapsed_s",
                )
            },
        )
        report["export"] = {"status": "saved", "path": str(target)}
        validate_timing_report(report)
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=".timing-",
            suffix=".partial",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        os.link(temporary, target)
        saved = {"status": "saved", "path": str(target)}
    except Exception as error:  # noqa: BLE001 - 统计/保存错误不能覆盖已知控制终态
        if report is None:
            collector.disable(error)
        saved = {"status": "failed", "path": str(target), "error_type": type(error).__name__}
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return {
        "mode": collector.mode,
        "export": saved,
        "observations": collector.count,
        "statistics_complete": not collector.observation_error,
        "observation_error": collector.observation_error,
        "status_counts": dict(collector.status_counts),
        "metrics": {
            k: {a: b for a, b in v.items() if a != "histogram"}
            for k, v in (report["metrics"] if report else {}).items()
        },
    }


def _validate_timing_report(report):
    """离线严格校验版本、端点、全程分母与固定容量；报告存在不代表控制成功。"""
    expected = {
        "schema",
        "format_version",
        "mode",
        "observations",
        "observation_range",
        "statistics_complete",
        "observation_error",
        "status_counts",
        "metrics",
        "first_failure",
        "recent",
        "slowest",
        "raw",
        "waiting_terminal",
        "lifecycle_ns",
        "buffer_bytes",
        "observation_boundary",
        "phase_semantics",
        "metadata",
        "control_outcome",
        "export",
    }
    if not isinstance(report, dict) or set(report) != expected:
        raise ValueError("性能报告字段不匹配。")
    if (
        report["schema"] != "cart_pole_live_timing"
        or type(report["format_version"]) is not int
        or report["format_version"] != 1
    ):
        raise ValueError("不支持的性能报告版本。")

    def integer(value):
        if type(value) is not int or not 0 <= value < 2**63:
            raise ValueError("报告计数/时长必须是有界非负整数。")

    count = report["observations"]
    integer(count)
    bounds = report["observation_range"]
    if set(bounds) != {"first", "last"}:
        raise ValueError("观察范围字段无效。")
    if not count:
        if bounds != {"first": None, "last": None}:
            raise ValueError("零观察不能伪造范围。")
    elif bounds["first"]["attempt_seq"] != 0 or bounds["last"]["attempt_seq"] != count - 1:
        raise ValueError("全程观察范围不符。")
    integer(report["buffer_bytes"])
    if report["buffer_bytes"] > 8 * 1024 * 1024 or report["mode"] not in ("summary", "samples"):
        raise ValueError("性能报告模式/内存无效。")
    if type(report["statistics_complete"]) is not bool:
        raise ValueError("统计完整性不是布尔值。")
    statuses = report["status_counts"]
    if set(statuses) != STATUSES:
        raise ValueError("报告状态集合无效。")
    for value in statuses.values():
        integer(value)
    if sum(statuses.values()) != count:
        raise ValueError("状态计数与全程分母不符。")
    metrics = report["metrics"]
    names = {
        "control_latency_ns",
        "work_elapsed_ns",
        "sample_interval_ns",
        *PHASES,
        "pacing_requested_ns",
        "pacing_elapsed_ns",
        "pacing_excess_ns",
        "observation_ns",
    }
    if set(metrics) not in (names, names-{"single_exchange"}):
        raise ValueError("指标集合无效。")
    for name, metric in metrics.items():
        fields = {
            "count",
            "sum_ns",
            "min_ns",
            "max_ns",
            "mean_ns",
            "above_15ms",
            "above_20ms",
            "missing_count",
        }
        if name in ("control_latency_ns", "work_elapsed_ns", "sample_interval_ns"):
            fields |= {"histogram", "quantiles"}
        if set(metric) != fields:
            raise ValueError("指标字段缺失或未知。")
        n = metric["count"]
        for k in ("count", "sum_ns", "above_15ms", "above_20ms"):
            integer(metric[k])
        integer(metric["missing_count"])
        if metric["missing_count"] + n != count:
            raise ValueError("指标缺失数与全程分母不符。")
        if n > count or not 0 <= metric["above_20ms"] <= metric["above_15ms"] <= n:
            raise ValueError("指标分母或参考计数无效。")
        if not n:
            if metric["sum_ns"] or any(
                metric[k] is not None for k in ("min_ns", "max_ns", "mean_ns")
            ):
                raise ValueError("零样本指标不能伪造数值。")
        else:
            integer(metric["min_ns"])
            integer(metric["max_ns"])
            if (
                not n * metric["min_ns"] <= metric["sum_ns"] <= n * metric["max_ns"]
                or metric["mean_ns"] != metric["sum_ns"] / n
            ):
                raise ValueError("指标均值/极值与总和矛盾。")
        if "histogram" in metric:
            hist = metric["histogram"]
            if (
                set(hist) != {"method", "bin_width_ns", "overflow_lower_ns", "counts"}
                or hist["overflow_lower_ns"] != 1_000_000_000
                or set(metric["quantiles"]) != {"p50", "p95", "p99"}
                or hist["bin_width_ns"] != BIN_NS
                or hist["method"] != "nearest_rank_interval"
                or len(hist["counts"]) != BINS
            ):
                raise ValueError("直方图定义无效。")
            for value in hist["counts"]:
                integer(value)
            if sum(hist["counts"]) != n:
                raise ValueError("直方图分母不符。")
            for key, p in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
                interval = metric["quantiles"][key]
                if not n:
                    if interval is not None:
                        raise ValueError("零样本分位不是null。")
                    continue
                cumulative = 0
                for k, value in enumerate(hist["counts"]):
                    cumulative += value
                    if cumulative >= math.ceil(p * n):
                        if interval != {
                            "lower_ns": k * BIN_NS,
                            "upper_ns": (k + 1) * BIN_NS if k < BINS - 1 else None,
                        }:
                            raise ValueError("分位区间与直方图矛盾。")
                        break
    raw = report["raw"]
    if set(raw) != {"enabled", "capacity", "captured", "omitted", "complete", "scope", "samples"}:
        raise ValueError("原始样本字段不匹配。")
    if (
        type(raw["enabled"]) is not bool
        or type(raw["complete"]) is not bool
        or raw["enabled"] != (report["mode"] == "samples")
    ):
        raise ValueError("原始样本模式不匹配。")
    integer(raw["captured"])
    integer(raw["omitted"])
    integer(raw["capacity"])
    if (
        raw["enabled"]
        and not 1 <= raw["capacity"] <= 10000
        or not raw["enabled"]
        and raw["capacity"] != 0
        or raw["captured"] > raw["capacity"]
    ):
        raise ValueError("原始样本容量无效。")
    if (
        raw["captured"] > 10_000
        or raw["captured"] + raw["omitted"] != count
        or raw["complete"] != (raw["captured"] == count)
    ):
        raise ValueError("原始样本范围矛盾。")
    if (
        len(raw["samples"]) != raw["captured"]
        or len(report["recent"]) != min(256, count)
        or len(report["slowest"]) > 8
    ):
        raise ValueError("样本容量/计数不匹配。")
    for rows in (
        raw["samples"],
        report["recent"],
        report["slowest"],
        [report["first_failure"]] if report["first_failure"] else [],
    ):
        for row in rows:
            value = StepTimingObservation(
                **{k: row[k] for k in StepTimingObservation.__dataclass_fields__}
            )
            if row != _unpack(_pack(value)) or row["attempt_seq"] >= count:
                raise ValueError("样本端点或派生耗时不符。")
    if [r["attempt_seq"] for r in raw["samples"]] != list(range(raw["captured"])):
        raise ValueError("原始样本不是首N次观察。")
    if [r["attempt_seq"] for r in report["recent"]] != list(range(max(0, count - 256), count)):
        raise ValueError("近期样本范围不符。")
    return report


def validate_timing_report(report):
    """统一拒绝结构错误，不让损坏JSON以KeyError等内部错误绕过报告校验。"""
    try:
        return _validate_timing_report(report)
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError("性能报告结构或类型无效。") from error


def load_timing_report(path):
    """读取新格式性能文件；拒绝重复键、非有限值与异常大文件。"""
    source = Path(path)
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("性能报告超过32MiB。")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("性能报告有重复字段。")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("性能报告有非有限值。")

    return validate_timing_report(
        json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=invalid
        )
    )
