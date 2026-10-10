"""本机绝对周期预算和公开计时；不拥有控制器、设备、密码材料或网络。"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


class CycleDeadlineExceeded(TimeoutError):
    """本周期预算已经耗尽；phase 只含公开阶段名。"""

    def __init__(self, phase: str):
        super().__init__("本周期截止时间已过。")
        self.phase = phase


def check_deadline(deadline_ns: int | None, phase: str, *, now=None) -> None:
    """CPU 边界和设备调用之前核验同一 deadline，不重新分配整步 timeout。"""
    if deadline_ns is not None:
        if type(deadline_ns) is not int or deadline_ns < 0:
            raise ValueError("deadline_ns 必须是非负整数或 None。")
        current = time.perf_counter_ns() if now is None else now()
        if current >= deadline_ns:
            raise CycleDeadlineExceeded(phase)


def network_deadline(timeout: float, deadline_ns: int | None) -> float:
    """只在本机标记 QPC 秒域；未传周期时保留旧 monotonic，绝对钟不进入 wire。"""
    check_deadline(deadline_ns, "NETWORK")
    if deadline_ns is None:
        return time.monotonic() + timeout
    protective = time.perf_counter_ns() + round(timeout * 1_000_000_000)
    return _CycleDeadline(min(protective, deadline_ns))


class _CycleDeadline(float):
    """新周期的本机高精度 deadline 标记；旧 transport float 仍使用原 monotonic 钟。"""

    def __new__(cls, deadline_ns):
        value = super().__new__(cls, deadline_ns / 1_000_000_000)
        value.deadline_ns = deadline_ns
        return value


def remaining_seconds(deadline: float) -> float:
    """canonical transport 唯一换算边界，禁止混用 GetTickCount 与 QPC 的不同 epoch。"""
    if isinstance(deadline, _CycleDeadline):
        return (deadline.deadline_ns - time.perf_counter_ns()) / 1_000_000_000
    return deadline - time.monotonic()


class AbsoluteCycleClock:
    """t0 仅建立一次；第 k 步永远使用 t0+kT，不跳步或重置迟到样本。"""

    def __init__(self, period_s: float, *, now=time.perf_counter_ns, sleep=time.sleep):
        if isinstance(period_s, bool) or not math.isfinite(period_s) or period_s <= 0:
            raise ValueError("period 必须是有限正数秒。")
        self.period_ns = round(period_s * 1_000_000_000)
        if self.period_ns < 1:
            raise ValueError("period 不能小于 1 ns。")
        self._now, self._sleep = now, sleep
        self.t0_ns = now()

    def bounds(self, step: int) -> tuple[int, int]:
        """返回计划采样时刻及其唯一截止时刻。"""
        if type(step) is not int or step < 0:
            raise ValueError("step 必须是非负整数。")
        start = self.t0_ns + step * self.period_ns
        return start, start + self.period_ns

    def wait(self, step: int) -> tuple[int, int]:
        """等待绝对起点；操作系统过度睡眠如实计入启动偏差。"""
        start, deadline = self.bounds(step)
        while (remaining := start - self._now()) > 0:
            self._sleep(remaining / 1_000_000_000)
        return start, deadline


@dataclass(frozen=True, slots=True)
class CycleTiming:
    """版本 1 公开事实；未到达的区间端点用 None，不伪造成功耗时。"""

    run_id: str
    session_id: str | None
    controller_epoch: str | None
    segment_index: int
    global_step: int
    round_id: str | None
    period_ns: int
    scheduled_start_ns: int
    actual_sample_start_ns: int | None
    deadline_ns: int
    device_completed_ns: int | None = None
    bookkeeping_completed_ns: int | None = None
    cycle_completed_ns: int | None = None
    status: str = "failed"
    failure_phase: str | None = None
    protocol_committed_count: int = 0
    physically_confirmed_count: int = 0
    durable_step_count: int = 0
    phase_durations_ns: dict[str, int] = field(default_factory=dict)
    queue_levels: dict[str, int] = field(default_factory=dict)
    public_frame_counts: dict[str, int] | None = None
    public_byte_counts: dict[str, int] | None = None
    format_version: int = 1

    def __post_init__(self):
        """拒绝 bool/负数；不同机器的绝对时钟从不相减。"""
        for name in ("segment_index", "global_step", "period_ns", "scheduled_start_ns",
                     "actual_sample_start_ns", "deadline_ns", "device_completed_ns",
                     "bookkeeping_completed_ns", "cycle_completed_ns",
                     "protocol_committed_count", "physically_confirmed_count", "durable_step_count"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{name} 必须是非负整数 ns/count 或 None。")
        if self.period_ns < 1 or self.deadline_ns != self.scheduled_start_ns + self.period_ns:
            raise ValueError("周期起点与 deadline 不一致。")
        for mapping in (self.phase_durations_ns, self.queue_levels,
                        self.public_frame_counts, self.public_byte_counts):
            if mapping is not None and any(type(v) is not int or v < 0 for v in mapping.values()):
                raise ValueError("公开时长/队列/流量必须是非负整数。")
        if self.durable_step_count > self.physically_confirmed_count:
            raise ValueError("可靠前缀不能超过物理确认计数。")
