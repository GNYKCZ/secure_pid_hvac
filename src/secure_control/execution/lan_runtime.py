"""无 Supervisor 的三主机单 session 单步生命周期与公开时延测量。"""

from __future__ import annotations

import logging
import os
import secrets
import socket
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from threading import RLock
from typing import Any, Literal

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import (
    FixedPointContext,
    PrimeModulusEvidence,
    TwoPartySharing,
    verify_prime_modulus,
)
from secure_control.protocol import P1, P2, Client, ControllerRangeContract
from secure_control.protocol.coordinator import (
    DirectProtocol3PartyEndpoint,
    LocalProtocol3PartyEndpoint,
    dispatch_direct_protocol3_command,
    rehydrate_offline_material,
    rehydrate_online_material,
)
from secure_control.protocol.messages import (
    ControlShareMessage,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyOnlineRound,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
)

from ._inputs import normalize_step_input
from ._localhost_peer import LocalhostProtocol3PeerPort
from ._localhost_workers import (
    _capture_stage_share,
    _ClientPartyEndpoint,
    _complete_client_round,
    _validate_party_reply,
)
from .lan_config import LanConfig, Role
from .lan_transport import accept_role, connect_role, listener
from .localhost_codec import (
    SCHEMA_VERSION,
    LanContinuousSetupPayload,
    LanHelloPayload,
    LanSegmentedHelloPayload,
    LanSetupPayload,
    PartyStageResult,
    RemoteErrorPayload,
    SegmentEndPayload,
    SegmentEndReceipt,
    WireEnvelope,
)
from .localhost_transport import deadline_after, receive_envelope, send_envelope

_FRAME_LIMIT = 8 * 1024 * 1024
_MAX_CONTINUOUS_STEPS = 1000
_LAN_LOG = logging.getLogger("secure_control.lan")


def run_client_single_step(config: LanConfig, trial: Any) -> dict[str, object]:
    """Client 独立拨号、分发、驱动一次协议、双提交并有界关闭三条连接。"""
    if config.role != "Client":
        raise ValueError("只有 Client 配置可启动 LAN 单步。")
    if trial.modulus_evidence is not None or trial.range_contract.closed_loop_evidence is not None:
        raise ValueError("LAN 首个冻结单步仅支持内置 64-bit 素数与有限时域范围契约。")
    client = Client(
        trial.fixed_point,
        TwoPartySharing(trial.fixed_point.modulus),
        security_parameter=trial.security_parameter,
        modulus_evidence=trial.modulus_evidence,
    )
    distribution = client.distribute_controller(trial.spec, trial.range_contract)
    session = distribution.session_id
    hello = LanHelloPayload(config.topology.digest, secrets.token_hex(32))
    stamps: dict[str, int] = {"trial_start": time.perf_counter_ns()}
    sockets: list[socket.socket] = []
    committed = False
    try:
        for role, address in (("P1", config.topology.p1_client), ("P2", config.topology.p2_client)):
            _LAN_LOG.info("Client 正在连接 %s…", role)
            sock = connect_role(address, config, role, deadline_after(config.startup_timeout))
            sockets.append(sock)
            _hello(sock, "Client", role, session, hello, config.startup_timeout)
            _LAN_LOG.info("Client 与 %s 的协议连接已建立。", role)
        stamps["tls_hello"] = time.perf_counter_ns()
        for party, sock in enumerate(sockets):
            _request(
                sock, "P1" if party == 0 else "P2", 1, "lan_ready", session, config.startup_timeout
            )
        _LAN_LOG.info("三方已就绪，开始计算。")
        stamps["peer_ready"] = time.perf_counter_ns()
        setup = LanSetupPayload(
            trial.fixed_point.modulus,
            trial.fixed_point.integer_bits,
            trial.fixed_point.fractional_bits,
            trial.security_parameter,
            trial.range_contract.state_payload_bounds,
            trial.range_contract.input_payload_bounds,
            trial.range_contract.horizon_steps,
        )
        for party, sock in enumerate(sockets):
            role: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
            _request(sock, role, 2, "lan_setup", session, config.startup_timeout, setup)
            material = distribution.p1 if party == 0 else distribution.p2
            _request(
                sock,
                role,
                3,
                "offline",
                session,
                config.startup_timeout,
                PartyOfflineMaterial.from_message(material),
            )
        stamps["offline"] = time.perf_counter_ns()
        stamps["step_start"] = time.perf_counter_ns()
        step_deadline = deadline_after(config.step_timeout)
        current = client.prepare_online(distribution, trial.controller_input, step=0)
        plan = current.p1_resources.plan
        if current.p2_resources.plan != plan:
            raise ValueError("两方在线资源计划不一致。")
        stamps["prepared"] = time.perf_counter_ns()
        endpoints: list[_ClientPartyEndpoint] = []
        for party, sock in enumerate(sockets):
            role = "P1" if party == 0 else "P2"
            online = PartyOnlineRound(
                current.p1_input if party == 0 else current.p2_input,
                current.p1_resources if party == 0 else current.p2_resources,
            )
            _request(
                sock,
                role,
                4,
                "online",
                session,
                config.step_timeout,
                PartyOnlineMaterial.from_round(online),
                plan.round_id,
                0,
                deadline=step_deadline,
            )
            endpoints.append(
                _ClientPartyEndpoint(
                    sock, party, plan, 5, _FRAME_LIMIT, config.step_timeout, step_deadline
                )
            )
        stamps["distributed"] = time.perf_counter_ns()
        result = _complete_client_round(
            client,
            endpoints[0],
            endpoints[1],
            plan,
            lambda phase: stamps.__setitem__(phase, time.perf_counter_ns()),
        )
        committed = True
        for party, sock in enumerate(sockets):
            role = "P1" if party == 0 else "P2"
            _request(
                sock,
                role,
                endpoints[party].sequence,
                "shutdown",
                session,
                config.shutdown_timeout,
                shutdown=True,
            )
        stamps["closed"] = time.perf_counter_ns()
        output = np.asarray(result.output, dtype=float)
        return {
            "status": "complete",
            "pid": os.getpid(),
            "profile_sha256": config.topology.digest,
            "raw_control": output.tolist(),
            "baseline_raw_control": np.asarray(trial.expected_raw_output, dtype=float).tolist(),
            "maximum_raw_difference": float(np.max(np.abs(output - trial.expected_raw_output))),
            "controller_config_sha256": trial.config_sha256,
            "resource_counts": {
                "products_consumed": result.products,
                "truncations_consumed": result.truncations,
            },
            "timings_ms": _timings(stamps),
            "transport": config.transport,
            "tls_version": "TLSv1.3" if config.transport == "mutual_tls" else None,
        }
    except Exception:
        # 双提交完成但关闭回执不确定时也不输出完整成功结果；不重新拨号或重放材料。
        if committed:
            raise RuntimeError("控制步已双提交，但安全会话关闭未确认。") from None
        raise
    finally:
        for sock in sockets:
            sock.close()


class LanContinuousRuntime:
    """Client 独占一组 socket 与单方资源；每个 step 只在双提交后返回。"""

    def __init__(
        self, config: LanConfig, spec: ControllerSpec, fixed_point: FixedPointContext,
        range_contract: ControllerRangeContract, security_parameter: int,
        modulus_evidence: PrimeModulusEvidence | None,
        *, _segment_hello: LanSegmentedHelloPayload | None = None,
    ) -> None:
        if config.role != "Client" or config.experiment_config is None:
            raise ValueError("连续运行必须使用 Client experiment 配置。")
        if (range_contract.horizon_steps is None
                or not 1 <= range_contract.horizon_steps <= _MAX_CONTINUOUS_STEPS):
            raise ValueError("LAN 连续会话步数超出有界范围。")
        self.spec = spec
        self.fixed_point = fixed_point
        self.range_contract = range_contract
        self.security_parameter = security_parameter
        self.modulus_evidence = modulus_evidence
        self.client = Client(fixed_point, TwoPartySharing(fixed_point.modulus),
                             security_parameter=security_parameter,
                             modulus_evidence=modulus_evidence)
        # 所有参数、模数与范围验证在网络拨号及离线分享前完成。
        self.distribution = self.client.distribute_controller(spec, range_contract)
        self.scale_ledger = self.distribution.p1.layout.scale_ledger
        self.range_verification = self.client.range_verification
        self.modulus_verification = self.client.truncation.modulus_verification
        self.config = config
        self._sockets: list[socket.socket] = []
        self._sequences = [4, 4]
        self._step = 0
        self._products = 0
        self._truncations = 0
        self._confirmed_steps: list[dict[str, int | str]] = []
        self._failed = False
        self._finished = False
        self.session_id = self.distribution.session_id
        hello = (_segment_hello if _segment_hello is not None else
                 LanHelloPayload(config.topology.digest, secrets.token_hex(32),
                                 "lan-continuous-v1"))
        self._last_result = None
        self._round_started = False
        try:
            for role, address in (("P1", config.topology.p1_client),
                                  ("P2", config.topology.p2_client)):
                _LAN_LOG.info("Client 正在连接 %s…", role)
                sock = connect_role(address, config, role, deadline_after(config.startup_timeout))
                self._sockets.append(sock)
                _hello(sock, "Client", role, self.session_id, hello, config.startup_timeout)
                _LAN_LOG.info("Client 与 %s 的协议连接已建立。", role)
            for party, sock in enumerate(self._sockets):
                _request(sock, "P1" if party == 0 else "P2", 1, "lan_ready",
                         self.session_id, config.startup_timeout)
            _LAN_LOG.info("三方已就绪，开始连续计算。")
            setup = LanContinuousSetupPayload(
                fixed_point.modulus, fixed_point.integer_bits, fixed_point.fractional_bits,
                security_parameter, range_contract.state_payload_bounds,
                range_contract.input_payload_bounds, range_contract.horizon_steps,
                modulus_evidence,
            )
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _request(sock, role, 2, "lan_setup", self.session_id,
                         config.startup_timeout, setup)
                material = self.distribution.p1 if party == 0 else self.distribution.p2
                _request(sock, role, 3, "offline", self.session_id,
                         config.startup_timeout, PartyOfflineMaterial.from_message(material))
        except Exception:
            self._failed = True
            self.close()
            raise

    @property
    def resource_counts(self) -> dict[str, int]:
        return {"products_consumed": self._products,
                "truncations_consumed": self._truncations}

    @property
    def confirmed_steps(self) -> tuple[dict[str, int | str], ...]:
        """只导出双提交后确认的公开 step 与逻辑资源计数。"""
        return tuple(dict(item) for item in self._confirmed_steps)

    def step(self, v: Any) -> np.ndarray:
        """同一 session 逐轮推进；任何未确认回执使整个运行时失效。"""
        if self._failed or self._finished or self._step >= self.range_contract.horizon_steps:
            raise RuntimeError("LAN session 已失败、结束或超出配置步数。")
        self._round_started = False
        try:
            value = normalize_step_input(v, self.spec.input_dimension)
            current = self.client.prepare_online(self.distribution, value, step=self._step)
            plan = current.p1_resources.plan
            if current.p2_resources.plan != plan:
                raise ValueError("两方在线资源计划不一致。")
            self._last_plan = plan
            deadline = deadline_after(self.config.step_timeout)
            endpoints: list[_ClientPartyEndpoint] = []
            for party, sock in enumerate(self._sockets):
                self._round_started = True
                online = PartyOnlineRound(
                    current.p1_input if party == 0 else current.p2_input,
                    current.p1_resources if party == 0 else current.p2_resources,
                )
                _request(sock, "P1" if party == 0 else "P2", self._sequences[party],
                         "online", self.session_id, self.config.step_timeout,
                         PartyOnlineMaterial.from_round(online), plan.round_id,
                         self._step, deadline=deadline)
                endpoints.append(_ClientPartyEndpoint(
                    sock, party, plan, self._sequences[party] + 1, _FRAME_LIMIT,
                    self.config.step_timeout, deadline,
                ))
            result = _complete_client_round(self.client, endpoints[0], endpoints[1], plan)
            self._sequences = [endpoint.sequence for endpoint in endpoints]
            self._step += 1
            self._products += result.products
            self._truncations += result.truncations
            self._confirmed_steps.append({
                "step": plan.step, "status": "double_committed",
                "products": result.products, "truncations": result.truncations,
            })
            self._last_result = result
            return np.array(result.output, dtype=float, copy=True)
        except Exception:
            self._failed = True
            self.close()
            raise

    def finish(self) -> None:
        """只在全部 N 步、plant 更新成功后双角色关闭确认。"""
        if self._failed or self._finished or self._step != self.range_contract.horizon_steps:
            raise RuntimeError("LAN session 未完成全部配置步数。")
        try:
            for party, sock in enumerate(self._sockets):
                _request(sock, "P1" if party == 0 else "P2", self._sequences[party],
                         "shutdown", self.session_id, self.config.shutdown_timeout,
                         shutdown=True)
            self._finished = True
        except Exception:
            self._failed = True
            raise
        finally:
            self.close()

    def reset(self) -> None:
        raise RuntimeError("LAN reset 必须重新启动三方并使用新 session。")

    def close(self) -> None:
        for sock in self._sockets:
            sock.close()
        self._sockets.clear()


class RunControl:
    """线程安全、幂等的正常停止请求；发起门禁与请求共享锁，不关闭网络。"""

    def __init__(self) -> None:
        self._lock = RLock()
        self._stop = False
        self._on_stop: Callable[[], None] | None = None

    def request_stop(self) -> None:
        """停止先取得门禁则不再发起下一轮；已发起轮继续双提交及物理推进。"""
        with self._lock:
            self._stop = True
            if self._on_stop is not None:
                self._on_stop()

    @property
    def stop_requested(self) -> bool:
        with self._lock:
            return self._stop

    def bind_stop(self, callback: Callable[[], None]) -> None:
        """场景接入拒绝新扰动的回调；不消费或取消已排队的区间事件。"""
        with self._lock:
            self._on_stop = callback
            if self._stop:
                callback()


@dataclass(frozen=True, slots=True)
class SegmentedStep:
    """双提交后的只读控制能力；物理确认只能消费同一个对象一次。"""

    run_id: str
    segment_index: int
    session_id: str
    round_id: str
    local_step: int
    global_step: int
    raw_control: tuple[float, ...]
    products: int
    truncations: int
    resource_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SegmentRecord:
    """双方核验的公开段记录；调用者交接后运行时释放旧段全部列表。"""

    hello: LanSegmentedHelloPayload
    session_id: str
    steps: tuple[SegmentedStep, ...]
    receipts: tuple[SegmentEndReceipt, ...]
    setup: LanContinuousSetupPayload
    connection_seconds: float
    scale_ledger: object
    range_verification: object
    modulus_verification: object


class LanSegmentedRuntime:
    """有限静态控制器 session 的持续协调；物理状态由上层唯一 worker 拥有。"""

    def __init__(self, config: LanConfig, spec: ControllerSpec,
                 fixed_point: FixedPointContext, range_contract: ControllerRangeContract,
                 security_parameter: int, modulus_evidence: PrimeModulusEvidence | None,
                 *, control: RunControl) -> None:
        if spec.state_dimension != 0:
            raise ValueError("持续模式不支持非零 controller state；不能重置秘密状态。")
        if (type(range_contract.horizon_steps) is not int
                or not 1 <= range_contract.horizon_steps <= _MAX_CONTINUOUS_STEPS):
            raise ValueError("segment_steps 必须是 1…1000 的整数。")
        self.config, self.spec, self.fixed_point = config, spec, fixed_point
        self.contract, self.security_parameter = range_contract, security_parameter
        self.evidence, self.control = modulus_evidence, control
        self.run_id = secrets.token_hex(32)
        self.segment_index = self.global_start = self.confirmed_step_count = 0
        self._previous_session = None
        self._segment: LanContinuousRuntime | None = None
        self._pending: SegmentedStep | None = None
        self._records: list[SegmentedStep] = []
        self._products = self._truncations = 0
        self.phase = "CONNECTING"
        self._connect()

    def _connect(self) -> None:
        self.phase = "CONNECTING" if self.segment_index == 0 else "CONNECTING_NEXT"
        self.hello = LanSegmentedHelloPayload(
            self.config.topology.digest, secrets.token_hex(32), self.run_id,
            self.segment_index, self.global_start, self._previous_session,
        )
        started = time.monotonic()
        self._segment = LanContinuousRuntime(
            self.config, self.spec, self.fixed_point, self.contract,
            self.security_parameter, self.evidence, _segment_hello=self.hello,
        )
        self.connection_seconds = time.monotonic() - started
        self.phase = "RUNNING"

    @property
    def protocol_committed_count(self) -> int:
        return self.global_start + (self._segment._step if self._segment else 0)

    @property
    def resource_counts(self) -> dict[str, int]:
        return {"products_consumed": self._products, "truncations_consumed": self._truncations}

    @property
    def segment_full(self) -> bool:
        return self.confirmed_step_count - self.global_start == self.contract.horizon_steps

    def step(self, v: Any) -> SegmentedStep | None:
        """轮发起门禁成功后只完成该轮；停止请求不会中断 commit I/O。"""
        if self.phase != "RUNNING" or self._pending is not None or self.segment_full:
            raise RuntimeError("当前状态不能发起下一轮。")
        with self.control._lock:
            if self.control._stop:
                return None
            self.phase = "ROUND_IN_FLIGHT"
        assert self._segment is not None
        try:
            raw = self._segment.step(v)
            result = self._segment._last_result
            # 资源身份由 Client 的原计划产生；不另造身份或重新生成材料。
            plan = self._segment._last_plan
            self._pending = SegmentedStep(
                self.run_id, self.segment_index, self._segment.session_id,
                result.round_id, result.step, self.confirmed_step_count,
                tuple(float(value) for value in raw), result.products, result.truncations,
                tuple(item.resource_id for item in (*plan.product_resources,
                                                    *plan.state_truncation_resources)),
            )
            self._products += result.products
            self._truncations += result.truncations
            self.phase = "AWAITING_PLANT"
            return self._pending
        except Exception:
            self.phase = "UNCERTAIN" if self._segment._round_started else "FAILED"
            self.close()
            raise

    def confirm_applied(self, identity: SegmentedStep) -> None:
        """场景推进并验证后消费控制能力，拒绝复制、重复和错段确认。"""
        if self.phase != "AWAITING_PLANT" or identity is not self._pending:
            self.phase = "FAILED"
            self.close()
            raise RuntimeError("物理确认不匹配当前唯一控制结果。")
        self._records.append(identity)
        self.confirmed_step_count += 1
        self._pending = None
        self.phase = "RUNNING"

    def end_segment(self) -> SegmentRecord:
        """向双方先发送同一个 action，再于共享 deadline 验证独立计数回执。"""
        if self.phase != "RUNNING" or self._pending is not None:
            raise RuntimeError("未确认物理推进或失败状态不得正常结束。")
        assert self._segment is not None
        segment = self._segment
        with self.control._lock:
            action = "stop" if self.control._stop else "continue"
            if action == "continue" and not self.segment_full:
                raise RuntimeError("只有满段才能继续。")
            self.phase = "STOPPING" if action == "stop" else "ENDING_SEGMENT"
        end = SegmentEndPayload(
            self.run_id, self.segment_index, self.global_start, len(self._records),
            self.confirmed_step_count,
            self._records[-1].round_id if self._records else None, action,
        )
        deadline = deadline_after(self.config.shutdown_timeout)
        requests = []
        try:
            for party, sock in enumerate(segment._sockets):
                request = WireEnvelope(
                    SCHEMA_VERSION, "request", "Client", "P1" if party == 0 else "P2",
                    segment._sequences[party], "segment_end", segment.session_id,
                    None, None, None, end,
                )
                requests.append(request)
                send_envelope(sock, request, deadline=deadline, limit=_FRAME_LIMIT)
            receipts = []
            for sock, request in zip(segment._sockets, requests, strict=True):
                response = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
                _validate_party_reply(response, request)
                receipt = response.payload
                expected = SegmentEndReceipt(
                    request.recipient, segment.session_id, end, self.confirmed_step_count,
                    segment._products, segment._truncations,
                )
                if receipt != expected:
                    raise ValueError("段关闭回执与双提交/物理确认前缀不一致。")
                receipts.append(receipt)
            setup = LanContinuousSetupPayload(
                self.fixed_point.modulus, self.fixed_point.integer_bits,
                self.fixed_point.fractional_bits, self.security_parameter,
                self.contract.state_payload_bounds, self.contract.input_payload_bounds,
                self.contract.horizon_steps, self.evidence,
            )
            record = SegmentRecord(
                self.hello, segment.session_id, tuple(self._records), tuple(receipts), setup,
                self.connection_seconds, segment.scale_ledger, segment.range_verification,
                segment.modulus_verification,
            )
            self._records.clear()
            self.phase = "STOPPED" if action == "stop" else "CONNECTING_NEXT"
            return record
        except Exception:
            self.phase = "UNCERTAIN"
            raise
        finally:
            segment.close()

    def next_segment(self) -> None:
        """只有双方 continue 已确认才能计划重连；停止位贯穿新握手。"""
        if self.phase != "CONNECTING_NEXT":
            raise RuntimeError("段过渡未确认，禁止重连。")
        assert self._segment is not None
        self._previous_session = self._segment.session_id
        self.global_start = self.confirmed_step_count
        self.segment_index += 1
        self._segment = None
        try:
            self._connect()
        except Exception:
            self.phase = "FAILED"
            self.close()
            raise

    def close(self) -> None:
        """故障清理只关闭连接，不能产生正常停止结果。"""
        if self.phase not in {"STOPPED", "FAILED", "UNCERTAIN", "CANCELLED"}:
            self.phase = "FAILED"
        if self._segment is not None:
            self._segment.close()


def run_party_single_step(config: LanConfig) -> dict[str, object]:
    """P1/P2 只监听固定端口；由 hello 选择单步或有界连续模式。"""
    if config.role not in {"P1", "P2"}:
        raise ValueError("角色命令必须是 P1 或 P2。")
    role: Literal["P1", "P2"] = config.role
    party = 0 if role == "P1" else 1
    address = config.topology.p1_client if party == 0 else config.topology.p2_client
    client_listener = listener(address)
    peer_listener = None
    try:
        if party == 0:
            peer_listener = listener(config.topology.p1_peer)
        tail = None
        while True:
            summary, tail = _run_party_session(config, client_listener, peer_listener, tail)
            if tail is None:
                return summary
    finally:
        client_listener.close()
        if peer_listener is not None:
            peer_listener.close()


@dataclass(frozen=True, slots=True)
class _PartyRunTail:
    """角色仅保留已确认的公开链尾；旧协议对象和材料均随 session 释放。"""

    run_id: str
    next_segment: int
    global_start: int
    session_id: str
    setup: LanContinuousSetupPayload
    layout: object


def _validate_segment_chain(hello: LanSegmentedHelloPayload, session: str,
                            tail: _PartyRunTail | None) -> None:
    if tail is None:
        if (hello.segment_index, hello.global_start, hello.previous_session_id) != (0, 0, None):
            raise ValueError("首段身份错误。")
    elif (hello.run_id, hello.segment_index, hello.global_start, hello.previous_session_id) != (
        tail.run_id, tail.next_segment, tail.global_start, tail.session_id
    ) or session == tail.session_id:
        raise ValueError("段链存在外来 run、跳段或旧 session。")


def _run_party_session(config: LanConfig, client_listener: socket.socket,
                       peer_listener: socket.socket | None,
                       tail: _PartyRunTail | None) -> tuple[dict[str, object], _PartyRunTail | None]:
    """旧模式与新模式共享唯一的握手、离线装配和 Protocol 3 单段计算。"""
    role = config.role
    party = 0 if role == "P1" else 1
    client_socket = peer_socket = peer_port = None
    try:
        startup_deadline = deadline_after(config.startup_timeout)
        _LAN_LOG.info("%s 已启动，正在等待 Client（最多 %.0f 秒）。", role,
                      config.startup_timeout)
        client_socket = accept_role(client_listener, config, "Client", startup_deadline)
        session, hello = _accept_hello(
            client_socket,
            "Client",
            role,
            config,
            startup_deadline,
        )
        if isinstance(hello, LanSegmentedHelloPayload):
            _validate_segment_chain(hello, session, tail)
        elif tail is not None:
            raise ValueError("持续 run 不允许切回旧模式。")
        _LAN_LOG.info("%s 与 Client 的协议连接已建立。", role)
        if party == 0:
            assert peer_listener is not None
            peer_socket = accept_role(peer_listener, config, "P2", startup_deadline)
            _accept_hello(
                peer_socket, "P2", "P1", config, startup_deadline, expected=(session, hello)
            )
            _LAN_LOG.info("P1 与 P2 的协议连接已建立。")
        else:
            peer_socket = connect_role(config.topology.p1_peer, config, "P1", startup_deadline)
            _hello(peer_socket, "P2", "P1", session, hello, config.startup_timeout)
            _LAN_LOG.info("P2 与 P1 的协议连接已建立。")
        _party_reply(
            client_socket,
            _party_receive(client_socket, role, 1, "lan_ready", session, config.startup_timeout),
            None,
            config.startup_timeout,
        )
        setup_request = _party_receive(
            client_socket, role, 2, "lan_setup", session, config.startup_timeout
        )
        setup = setup_request.payload
        if hello.mode == "lan-single-step-v1" and not isinstance(setup, LanSetupPayload):
            raise TypeError("单步模式的公开 setup 类型不合法。")
        if (hello.mode in {"lan-continuous-v1", "lan-segmented-v1"}
                and not isinstance(setup, LanContinuousSetupPayload)):
            raise TypeError("连续模式的公开 setup 类型不合法。")
        if not isinstance(setup, (LanSetupPayload, LanContinuousSetupPayload)):
            raise TypeError("公开 LAN setup 类型不合法。")
        if (hello.mode in {"lan-continuous-v1", "lan-segmented-v1"}
                and not 1 <= setup.horizon_steps <= _MAX_CONTINUOUS_STEPS):
            raise ValueError("LAN 连续 setup 步数超出有界范围。")
        modulus_evidence = (setup.modulus_evidence
                            if isinstance(setup, LanContinuousSetupPayload) else None)
        verify_prime_modulus(setup.modulus, modulus_evidence)
        fixed = FixedPointContext(
            setup.modulus, integer_bits=setup.integer_bits, fractional_bits=setup.fractional_bits
        )
        range_contract = ControllerRangeContract(
            setup.state_payload_bounds,
            setup.input_payload_bounds,
            setup.horizon_steps,
        )
        if isinstance(hello, LanSegmentedHelloPayload) and (
            setup.state_payload_bounds or (tail is not None and setup != tail.setup)
        ):
            raise ValueError("持续模式只接受冻结的零维状态数值契约。")
        _party_reply(client_socket, setup_request, None, config.startup_timeout)
        offline_request = _party_receive(
            client_socket, role, 3, "offline", session, config.startup_timeout
        )
        material = offline_request.payload
        if (
            not isinstance(material, PartyOfflineMaterial)
            or material.recipient != party
            or material.session_id != session
        ):
            raise ValueError("离线单方材料的角色不匹配。")
        if isinstance(hello, LanSegmentedHelloPayload) and (
            material.layout.state_dimension != 0
            or (tail is not None and material.layout != tail.layout)
        ):
            raise ValueError("持续模式只支持冻结的零维 controller layout。")
        offline = rehydrate_offline_material(material, range_contract)
        role_object = P1(offline) if party == 0 else P2(offline)
        _party_reply(client_socket, offline_request, None, config.startup_timeout)
        sequence = 4
        peer_port = LocalhostProtocol3PeerPort(
            peer_socket, role, _FRAME_LIMIT, config.step_timeout
        )
        peer_port.bind(session)
        steps = 1 if hello.mode == "lan-single-step-v1" else setup.horizon_steps
        segmented = isinstance(hello, LanSegmentedHelloPayload)
        products = truncations = committed = 0
        last_round = None
        while True:
            # 首轮也允许等待 Client 先完成纯场景预检；每轮操作有独立总 deadline。
            if not segmented and committed == steps:
                break
            online_request = receive_envelope(
                client_socket, deadline=deadline_after(config.idle_timeout), limit=_FRAME_LIMIT
            )
            if segmented and online_request.operation == "segment_end":
                _check_request(online_request, role, sequence, "segment_end", session)
                end = online_request.payload
                if not isinstance(end, SegmentEndPayload):
                    raise TypeError("段结束请求类型错误。")
                actual = SegmentEndPayload(
                    hello.run_id, hello.segment_index, hello.global_start, committed,
                    hello.global_start + committed, last_round, end.action,
                )
                if end != actual or (end.action == "continue" and committed != steps):
                    raise ValueError("段结束与本方实际提交前缀不一致。")
                receipt = SegmentEndReceipt(role, session, actual,
                                            hello.global_start + committed, products, truncations)
                _party_reply(client_socket, online_request, receipt, config.shutdown_timeout)
                tail = _PartyRunTail(hello.run_id, hello.segment_index + 1,
                                     hello.global_start + committed, session, setup, material.layout)
                summary = {"status": "closed", "role": role, "pid": os.getpid(),
                           "steps_committed": receipt.cumulative_committed_count,
                           "final_receipt": asdict(receipt), "transport": config.transport}
                return summary, tail if end.action == "continue" else None
            _check_request(online_request, role, sequence, "online", session)
            expected_step = committed
            if expected_step >= steps:
                raise ValueError("当前有限段已耗尽，必须先确认段结束。")
            if (online_request.step != expected_step or online_request.round_id is None
                    or online_request.resource_id is not None):
                raise ValueError("LAN online step 必须连续递增。")
            online_material = online_request.payload
            if not isinstance(online_material, PartyOnlineMaterial):
                raise TypeError("在线单方材料类型错误。")
            online = rehydrate_online_material(
                online_material, modulus=fixed.modulus,
                security_parameter=setup.security_parameter,
                modulus_evidence=modulus_evidence,
            )
            staged: list[ControlShareMessage] = []
            endpoint = LocalProtocol3PartyEndpoint(
                role_object, online,
                lambda message, collected=staged: _capture_stage_share(message, collected),
            )
            if (endpoint.plan.round_id, endpoint.plan.step) != (
                online_request.round_id, expected_step
            ):
                raise ValueError("在线材料与信封 round identity 不匹配。")
            step_deadline = deadline_after(config.step_timeout)
            peer_port.set_round_deadline(step_deadline)
            direct = DirectProtocol3PartyEndpoint(endpoint, peer_port)
            _party_reply(client_socket, online_request, None, config.step_timeout,
                         deadline=step_deadline)
            sequence += 1
            while True:
                command_request = receive_envelope(
                    client_socket, deadline=step_deadline, limit=_FRAME_LIMIT
                )
                _check_request(command_request, role, sequence, "endpoint", session)
                if (command_request.round_id, command_request.step) != (
                    endpoint.plan.round_id, expected_step
                ) or not isinstance(command_request.payload, Protocol3EndpointCommand):
                    raise ValueError("endpoint command 与当前 round 不匹配。")
                try:
                    result = dispatch_direct_protocol3_command(direct, command_request.payload)
                    if command_request.payload.operation == "stage_output":
                        if not isinstance(result, Protocol3StageReceipt) or len(staged) != 1:
                            raise ValueError("暂存回执与输出份额不完整。")
                        result = PartyStageResult(result, staged[0])
                    _party_reply(client_socket, command_request, result,
                                 config.step_timeout, deadline=step_deadline)
                except Exception as error:
                    _party_error(client_socket, command_request, error, config.step_timeout)
                    raise
                sequence += 1
                if command_request.payload.operation == "commit":
                    committed += 1
                    products += len(endpoint.plan.product_resources)
                    truncations += len(endpoint.plan.state_truncation_resources)
                    last_round = endpoint.plan.round_id
                    break
        shutdown_request = _party_receive(
            client_socket, role, sequence, "shutdown", session, config.shutdown_timeout
        )
        _party_reply(client_socket, shutdown_request, None, config.shutdown_timeout)
        summary: dict[str, object] = {
            "status": "closed", "role": role, "pid": os.getpid(),
            "profile_sha256": config.topology.digest,
        }
        if hello.mode in {"lan-continuous-v1", "lan-segmented-v1"}:
            summary.update({
                "steps_committed": steps,
                "transport": config.transport,
                "tls_version": (client_socket.version()
                                if config.transport == "mutual_tls" else None),
            })
        return summary, None
    finally:
        if client_socket is not None:
            client_socket.close()
        if peer_port is not None:
            peer_port.close()
        elif peer_socket is not None:
            peer_socket.close()


def _hello(
    sock: socket.socket,
    sender: Role,
    recipient: Role,
    session: str,
    hello: LanHelloPayload | LanSegmentedHelloPayload,
    timeout: float,
) -> None:
    envelope = WireEnvelope(
        SCHEMA_VERSION,
        "hello",
        sender,
        recipient,
        0,
        "lan_hello",
        session,
        None,
        None,
        None,
        hello,
    )
    deadline = deadline_after(timeout)
    send_envelope(sock, envelope, deadline=deadline, limit=_FRAME_LIMIT)
    response = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    if (
        response.kind,
        response.sender,
        response.recipient,
        response.sequence,
        response.operation,
        response.session_id,
        response.payload,
    ) != (
        "hello",
        recipient,
        sender,
        0,
        "lan_hello",
        session,
        hello,
    ):
        raise ValueError("LAN hello 的角色、版本、拓扑或 session 不匹配。")


def _accept_hello(
    sock: socket.socket,
    sender: Role,
    recipient: Role,
    config: LanConfig,
    deadline: float,
    *,
    expected: tuple[str, LanHelloPayload | LanSegmentedHelloPayload] | None = None,
) -> tuple[str, LanHelloPayload | LanSegmentedHelloPayload]:
    request = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    payload = request.payload
    if (
        request.kind != "hello"
        or request.sender != sender
        or request.recipient != recipient
        or request.sequence != 0
        or request.operation != "lan_hello"
        or request.session_id is None
        or request.round_id is not None
        or request.step is not None
        or request.resource_id is not None
        or not isinstance(payload, (LanHelloPayload, LanSegmentedHelloPayload))
        or payload.profile_sha256 != config.topology.digest
        or (expected is not None and (request.session_id, payload) != expected)
    ):
        raise ValueError("LAN hello 的身份、模式、拓扑或 session 不匹配。")
    send_envelope(
        sock,
        WireEnvelope(
            SCHEMA_VERSION,
            "hello",
            recipient,
            sender,
            0,
            "lan_hello",
            request.session_id,
            None,
            None,
            None,
            payload,
        ),
        deadline=deadline,
        limit=_FRAME_LIMIT,
    )
    return request.session_id, payload


def _request(
    sock: socket.socket,
    role: Literal["P1", "P2"],
    sequence: int,
    operation: str,
    session: str,
    timeout: float,
    payload: object = None,
    round_id: str | None = None,
    step: int | None = None,
    *,
    shutdown: bool = False,
    deadline: float | None = None,
) -> object:
    request = WireEnvelope(
        SCHEMA_VERSION,
        "shutdown" if shutdown else "request",
        "Client",
        role,
        sequence,
        operation,
        session,
        round_id,
        step,
        None,
        payload,  # type: ignore[arg-type]
    )
    deadline = deadline_after(timeout) if deadline is None else deadline
    send_envelope(sock, request, deadline=deadline, limit=_FRAME_LIMIT)
    response = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    _validate_party_reply(response, request)
    if response.payload is not None:
        raise ValueError("LAN 准备或关闭回执不得携带私有 payload。")
    return response.payload


def _party_receive(
    sock: socket.socket,
    role: Literal["P1", "P2"],
    sequence: int,
    operation: str,
    session: str,
    timeout: float,
    *,
    deadline: float | None = None,
) -> WireEnvelope:
    message = receive_envelope(
        sock,
        deadline=deadline_after(timeout) if deadline is None else deadline,
        limit=_FRAME_LIMIT,
    )
    _check_request(message, role, sequence, operation, session)
    if operation in {"lan_ready", "lan_setup", "offline", "shutdown"} and (
        message.round_id is not None or message.step is not None or message.resource_id is not None
    ):
        raise ValueError("LAN 准备或关闭请求不得携带 round identity。")
    return message


def _check_request(
    message: WireEnvelope,
    role: Literal["P1", "P2"],
    sequence: int,
    operation: str,
    session: str,
) -> None:
    if (
        message.kind,
        message.sender,
        message.recipient,
        message.sequence,
        message.operation,
        message.session_id,
    ) != (
        "shutdown" if operation == "shutdown" else "request",
        "Client",
        role,
        sequence,
        operation,
        session,
    ):
        raise ValueError("LAN 请求的角色、顺序、操作或 session 不匹配。")


def _party_reply(
    sock: socket.socket,
    request: WireEnvelope,
    payload: object,
    timeout: float,
    *,
    deadline: float | None = None,
) -> None:
    send_envelope(
        sock,
        WireEnvelope(
            SCHEMA_VERSION,
            "reply",
            request.recipient,
            request.sender,
            request.sequence,
            request.operation,
            request.session_id,
            request.round_id,
            request.step,
            request.resource_id,
            payload,  # type: ignore[arg-type]
        ),
        deadline=deadline_after(timeout) if deadline is None else deadline,
        limit=_FRAME_LIMIT,
    )


def _party_error(
    sock: socket.socket, request: WireEnvelope, error: Exception, timeout: float
) -> None:
    try:
        send_envelope(
            sock,
            WireEnvelope(
                SCHEMA_VERSION,
                "error",
                request.recipient,
                request.sender,
                request.sequence,
                request.operation,
                request.session_id,
                request.round_id,
                request.step,
                request.resource_id,
                RemoteErrorPayload(type(error).__name__, "protocol failure"),
            ),
            deadline=deadline_after(timeout),
            limit=_FRAME_LIMIT,
        )
    except Exception:  # noqa: BLE001 - 通知失败不能覆盖原始协议异常
        return


def _timings(stamps: dict[str, int]) -> dict[str, float]:
    spans = {
        "tcp_tls_hello": ("trial_start", "tls_hello"),
        "peer_ready": ("tls_hello", "peer_ready"),
        "offline": ("peer_ready", "offline"),
        "online_prepare": ("step_start", "prepared"),
        "online_distribute": ("prepared", "distributed"),
        "party_compute_stage": ("distributed", "stage"),
        "reconstruct": ("stage", "reconstruct"),
        "double_commit": ("reconstruct", "commit"),
        "shutdown": ("commit", "closed"),
        "step_end_to_end": ("step_start", "commit"),
        "trial_total": ("trial_start", "closed"),
    }
    return {name: (stamps[end] - stamps[start]) / 1_000_000 for name, (start, end) in spans.items()}
