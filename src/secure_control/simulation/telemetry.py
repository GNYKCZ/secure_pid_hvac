"""Client 公开遥测 v1：受限事件、白名单编码和有损异步派发。"""

from __future__ import annotations

import json
import math
import secrets
import threading
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from .contracts import ChannelMetadata, ScenarioMetadata

EVENT_SCHEMA_VERSION = 1
RoleState = Literal["last_observed_ready", "failed", "closed", "unknown"]
RoleSource = Literal["session_topology", "unavailable"]
Roles = tuple[tuple[str, RoleState, RoleSource], ...]
UNKNOWN_ROLES: Roles = tuple((role, "unknown", "unavailable") for role in ("Client", "P1", "P2"))


def _identity(session_id: str, event_seq: int) -> None:
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
        raise ValueError("公开 session_id 无效。")
    if type(event_seq) is not int or event_seq < 0:
        raise ValueError("event_seq 必须是非负整数。")


def _number(value: float, name: str, *, nonnegative: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} 必须是实数。")
    result = float(value)
    if not math.isfinite(result) or (nonnegative and result < 0):
        raise ValueError(f"{name} 必须是有限有效数值。")
    return result


def _signal(value: tuple[float, ...], channels: ChannelMetadata, name: str) -> None:
    if not isinstance(value, tuple) or len(value) != len(channels.names):
        raise ValueError(f"{name} 与 channel metadata 不一致。")
    for number in value:
        _number(number, name)


def _roles(roles: Roles) -> None:
    if not isinstance(roles, tuple) or len(roles) != 3:
        raise ValueError("roles 必须列出 Client/P1/P2。")
    for index, role in enumerate(("Client", "P1", "P2")):
        item = roles[index]
        if (
            not isinstance(item, tuple)
            or len(item) != 3
            or item[0] != role
            or item[1] not in ("last_observed_ready", "failed", "closed", "unknown")
            or item[2] not in ("session_topology", "unavailable")
        ):
            raise ValueError("roles 含非法状态或来源。")


@dataclass(frozen=True, slots=True)
class SessionStarted:
    """从场景通道元数据生成的公开会话头。"""

    session_id: str
    event_seq: int
    metadata: ScenarioMetadata
    roles: Roles = UNKNOWN_ROLES

    def __post_init__(self) -> None:
        _identity(self.session_id, self.event_seq)
        if self.event_seq != 0:
            raise ValueError("session_started 的 event_seq 必须为 0。")
        if not isinstance(self.metadata, ScenarioMetadata):
            raise TypeError("metadata 必须是 ScenarioMetadata。")
        _roles(self.roles)


@dataclass(frozen=True, slots=True)
class Sample:
    """plant.step 成功后的一步公开快照；比较值全有或全无。"""

    session_id: str
    event_seq: int
    step: int
    time_s: float
    reference: tuple[float, ...]
    output_secure: tuple[float, ...]
    control_secure: tuple[float, ...]
    metadata: ScenarioMetadata
    output_ideal: tuple[float, ...] | None = None
    control_ideal: tuple[float, ...] | None = None
    control_error: tuple[float, ...] | None = None
    output_error: tuple[float, ...] | None = None
    roles: Roles = UNKNOWN_ROLES
    controller_round_ms: float | None = None
    actuator_plant_ms: float | None = None

    def __post_init__(self) -> None:
        _identity(self.session_id, self.event_seq)
        if type(self.step) is not int or self.step < 0:
            raise ValueError("step 必须是非负整数。")
        _number(self.time_s, "time_s")
        if not isinstance(self.metadata, ScenarioMetadata):
            raise TypeError("metadata 必须是 ScenarioMetadata。")
        for name, channels in (
            ("reference", self.metadata.reference),
            ("output_secure", self.metadata.output),
            ("control_secure", self.metadata.control),
        ):
            _signal(getattr(self, name), channels, name)
        comparison = (self.output_ideal, self.control_ideal, self.control_error, self.output_error)
        if any(value is None for value in comparison) != all(value is None for value in comparison):
            raise ValueError("ideal 比较字段必须全有或全为 null。")
        if self.output_ideal is not None:
            for name, channels in (
                ("output_ideal", self.metadata.output),
                ("control_ideal", self.metadata.control),
                ("control_error", self.metadata.control),
                ("output_error", self.metadata.output),
            ):
                _signal(getattr(self, name), channels, name)
            if any(
                left - right != error
                for left, right, error in zip(
                    self.control_ideal, self.control_secure, self.control_error
                )
            ) or any(
                left - right != error
                for left, right, error in zip(
                    self.output_ideal, self.output_secure, self.output_error
                )
            ):
                raise ValueError("error 必须严格等于 ideal-minus-secure。")
        _roles(self.roles)
        for name in ("controller_round_ms", "actuator_plant_ms"):
            value = getattr(self, name)
            if value is not None:
                _number(value, name, nonnegative=True)


@dataclass(frozen=True, slots=True)
class SessionFault:
    """只保存固定故障类别，不保存异常文本或 payload。"""

    session_id: str
    event_seq: int
    step: int | None
    category: Literal["timeout", "disconnected", "protocol", "plant", "control"]
    roles: Roles = UNKNOWN_ROLES

    def __post_init__(self) -> None:
        _identity(self.session_id, self.event_seq)
        if self.step is not None and (type(self.step) is not int or self.step < 0):
            raise ValueError("fault step 无效。")
        if self.category not in ("timeout", "disconnected", "protocol", "plant", "control"):
            raise ValueError("fault category 无效。")
        _roles(self.roles)


@dataclass(frozen=True, slots=True)
class SessionEnded:
    """会话唯一终态；仅完整结果通过验证后才 completed。"""

    session_id: str
    event_seq: int
    status: Literal["completed", "failed", "cancelled"]
    last_successful_step: int | None
    roles: Roles = UNKNOWN_ROLES

    def __post_init__(self) -> None:
        _identity(self.session_id, self.event_seq)
        if self.status not in ("completed", "failed", "cancelled"):
            raise ValueError("结束状态无效。")
        if self.last_successful_step is not None and (
            type(self.last_successful_step) is not int or self.last_successful_step < 0
        ):
            raise ValueError("last_successful_step 无效。")
        _roles(self.roles)


PublicEvent = SessionStarted | Sample | SessionFault | SessionEnded


def _channels(value: ChannelMetadata) -> dict[str, list[str]]:
    return {"names": list(value.names), "units": list(value.units)}


def _public_roles(value: Roles) -> dict[str, dict[str, str]]:
    return {role: {"state": state, "source": source} for role, state, source in value}


def public_event_dict(event: PublicEvent) -> dict[str, object]:
    """显式列出每个允许字段；不递归读取对象或异常。"""
    if not isinstance(event, (SessionStarted, Sample, SessionFault, SessionEnded)):
        raise TypeError("只允许公开遥测事件。")
    data: dict[str, object] = {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "session_id": event.session_id,
        "event_seq": event.event_seq,
        "roles": _public_roles(event.roles),
    }
    if isinstance(event, SessionStarted):
        data.update(
            kind="session_started",
            channels={
                "reference": _channels(event.metadata.reference),
                "output": _channels(event.metadata.output),
                "control": _channels(event.metadata.control),
            },
            sample_time_unit="s",
        )
    elif isinstance(event, Sample):
        data.update(
            kind="sample",
            step=event.step,
            time_s=event.time_s,
            reference=list(event.reference),
            output_secure=list(event.output_secure),
            control_secure=list(event.control_secure),
            output_ideal=None if event.output_ideal is None else list(event.output_ideal),
            control_ideal=None if event.control_ideal is None else list(event.control_ideal),
            control_error=None if event.control_error is None else list(event.control_error),
            output_error=None if event.output_error is None else list(event.output_error),
            latency_ms={
                "controller_round": event.controller_round_ms,
                "actuator_plant": event.actuator_plant_ms,
                "prepare": None,
                "stage": None,
                "commit": None,
            },
        )
    elif isinstance(event, SessionFault):
        data.update(kind="session_fault", step=event.step, category=event.category)
    else:
        data.update(
            kind="session_ended",
            status=event.status,
            last_successful_step=event.last_successful_step,
        )
    return data


def public_event_json(event: PublicEvent) -> str:
    """公开日志也应调用此白名单编码；禁止记录异常字符串。"""
    return json.dumps(public_event_dict(event), ensure_ascii=False, allow_nan=False)


def observe_roles(topology: object | None) -> Roles:
    """仅映射已观察的 session 投影，不推断独立角色心跳。"""
    if topology is None:
        return UNKNOWN_ROLES
    observed = getattr(topology, "roles", ())
    if len(observed) != 3 or tuple(item.role for item in observed) != ("Client", "P1", "P2"):
        raise ValueError("topology 缺少 Client/P1/P2。")
    states = {"ready": "last_observed_ready", "failed": "failed", "closed": "closed"}
    return tuple((item.role, states[item.status], "session_topology") for item in observed)  # type: ignore[return-value]


class BoundedPublisher:
    """控制线程仅立即入队；消费者仅在 daemon 派发线程调用。"""

    def __init__(self, consumer: Callable[[PublicEvent], None], *, capacity: int = 16) -> None:
        if not callable(consumer) or type(capacity) is not int or capacity < 3:
            raise ValueError("consumer 必须可调用，capacity 至少为 3。")
        self._consumer = consumer
        self._capacity = capacity
        self._pending: deque[PublicEvent] = deque()
        self._condition = threading.Condition()
        self._closed = False
        self._delivery_failed = False
        self._dropped_samples = 0
        self._worker = threading.Thread(target=self._dispatch, name="public-telemetry", daemon=True)
        self._worker.start()

    @property
    def status(self) -> Mapping[str, int | bool]:
        """只公开聚合派发状态，不泄露异常对象。"""
        with self._condition:
            return {
                "delivery_failed": self._delivery_failed,
                "dropped_samples": self._dropped_samples,
                "pending": len(self._pending),
            }

    def publish(self, event: PublicEvent) -> None:
        """满队列丢旧 sample；保留生命周期/终态，绝不等待消费者。"""
        if type(event) not in (SessionStarted, Sample, SessionFault, SessionEnded):
            raise TypeError("只允许公开事件。")
        with self._condition:
            if self._closed or self._delivery_failed:
                return
            if len(self._pending) >= self._capacity:
                index = next(
                    (i for i, item in enumerate(self._pending) if isinstance(item, Sample)), None
                )
                if index is None:
                    if isinstance(event, Sample):
                        self._dropped_samples += 1
                        return
                    # 三种生命周期事件的最大容量为 3；非法再次结束由 Session 控制。
                    raise RuntimeError("遥测生命周期队列已满。")
                del self._pending[index]
                self._dropped_samples += 1
            self._pending.append(event)
            self._condition.notify()

    def _dispatch(self) -> None:
        while True:
            with self._condition:
                while not self._pending and not self._closed:
                    self._condition.wait()
                if not self._pending:
                    return
                event = self._pending.popleft()
            try:
                self._consumer(event)
            except Exception:  # noqa: BLE001 - 消费端的任意异常必须隔离于控制线程。
                with self._condition:
                    self._delivery_failed = True
                    self._pending.clear()
                return

    def close(self) -> None:
        """仅通知派发线程退出，不在控制线程 join 或 flush。"""
        with self._condition:
            self._closed = True
            self._condition.notify_all()


class TelemetrySession:
    """给单次控制运行分配公开 ID、顺序号与唯一终态。"""

    def __init__(
        self,
        publisher: BoundedPublisher,
        *,
        session_id: str | None = None,
        roles: Roles = UNKNOWN_ROLES,
    ) -> None:
        if not isinstance(publisher, BoundedPublisher):
            raise TypeError("publisher 必须是有界异步发布器。")
        self.publisher = publisher
        self.session_id = session_id or secrets.token_hex(16)
        _identity(self.session_id, 0)
        _roles(roles)
        self.roles = roles
        self._seq = 0
        self._started = False
        self._ended = False
        self._last_step: int | None = None
        self._last_time: float | None = None
        self._header: SessionStarted | None = None

    @property
    def current_header(self) -> SessionStarted | None:
        """晚加入者可先取得当前公开 header，再按 next_event_seq 发现缺口。"""
        return self._header

    @property
    def next_event_seq(self) -> int:
        """下一个尝试发布的序号，包括已丢弃帧。"""
        return self._seq

    def _send(self, event: PublicEvent) -> None:
        self._seq += 1  # 丢弃的帧仍占序号，接收方据此看见 gap。
        self.publisher.publish(event)

    def start(self, metadata: ScenarioMetadata) -> None:
        if self._started or self._ended:
            raise RuntimeError("遥测会话已经启动或结束。")
        self._started = True
        self._header = SessionStarted(self.session_id, self._seq, metadata, self.roles)
        self._send(self._header)

    def sample(
        self,
        *,
        step: int,
        time_s: float,
        metadata: ScenarioMetadata,
        reference: tuple[float, ...],
        output_secure: tuple[float, ...],
        control_secure: tuple[float, ...],
        output_ideal: tuple[float, ...] | None = None,
        control_ideal: tuple[float, ...] | None = None,
        control_error: tuple[float, ...] | None = None,
        output_error: tuple[float, ...] | None = None,
        controller_round_ms: float | None = None,
        actuator_plant_ms: float | None = None,
    ) -> None:
        """只接受连续成功步；值来自已记录的通用轨迹。"""
        next_step = 0 if self._last_step is None else self._last_step + 1
        if not self._started or self._ended or step != next_step:
            raise RuntimeError("遥测 sample 次序无效。")
        if self._header is None or metadata != self._header.metadata:
            raise ValueError("遥测 sample channel metadata 与会话头不一致。")
        if self._last_time is not None and time_s <= self._last_time:
            raise ValueError("遥测 time_s 必须严格递增。")
        event = Sample(
            self.session_id,
            self._seq,
            step,
            time_s,
            reference,
            output_secure,
            control_secure,
            metadata,
            output_ideal,
            control_ideal,
            control_error,
            output_error,
            self.roles,
            controller_round_ms,
            actuator_plant_ms,
        )
        self._last_step = step
        self._last_time = time_s
        self._send(event)

    def fault(self, step: int | None, category: str) -> None:
        if not self._started or self._ended:
            raise RuntimeError("遥测 fault 次序无效。")
        self._send(SessionFault(self.session_id, self._seq, step, category, self.roles))  # type: ignore[arg-type]

    def end(self, status: Literal["completed", "failed", "cancelled"]) -> None:
        if not self._started or self._ended:
            raise RuntimeError("遥测终态只能发一次。")
        self._ended = True
        self._send(SessionEnded(self.session_id, self._seq, status, self._last_step, self.roles))


class EventReceiver:
    """直播接收方检测重复、错序、缺口与缺失终态。"""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, int], str] = {}
        self._last: dict[str, int] = {}
        self._ended: dict[str, str] = {}

    def accept(self, event: PublicEvent) -> Literal["accepted", "duplicate", "late", "gap"]:
        encoded = public_event_json(event)
        key = (event.session_id, event.event_seq)
        previous = self._seen.get(key)
        if previous is not None:
            if previous != encoded:
                raise ValueError("同一事件序号内容冲突。")
            return "duplicate"
        self._seen[key] = encoded
        last = self._last.get(event.session_id, -1)
        if event.event_seq < last or event.session_id in self._ended:
            return "late"
        self._last[event.session_id] = event.event_seq
        if isinstance(event, SessionEnded):
            self._ended[event.session_id] = event.status
        return "gap" if event.event_seq > last + 1 else "accepted"

    def display_status(self, session_id: str) -> str:
        """断连且未见终态时应显示 unknown/disconnected。"""
        return self._ended.get(session_id, "unknown/disconnected")
