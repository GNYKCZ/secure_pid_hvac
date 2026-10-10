"""P1↔P2 localhost 在线消息通道；只负责 identity、顺序与有界收发。"""

from __future__ import annotations

import os
import socket
from copy import deepcopy
from typing import Literal

from secure_control.protocol.messages import (
    P2TruncationPayload,
    ProductMaskPayload,
    Protocol3BatchPayload,
    ResourceMetadata,
    StepResourcePlan,
    public_step_plan_sha256,
)

from .localhost_codec import SCHEMA_VERSION, BatchHelloPayload, HelloPayload, WireEnvelope
from .localhost_transport import (
    accept_loopback,
    connect_loopback,
    deadline_after,
    receive_envelope,
    send_envelope,
)

Address = tuple[str, int]
Role = Literal["P1", "P2"]


class LocalhostProtocol3PeerPort:
    """绑定单一 P1/P2 session 的双工在线 peer port。"""

    def __init__(
        self,
        connection: socket.socket,
        role: Role,
        limit: int,
        timeout: float,
        deadline: float | None = None,
        batch_enabled: bool = False,
    ) -> None:
        self._connection = connection
        self._role = role
        self._peer: Role = "P2" if role == "P1" else "P1"
        self._limit = limit
        self._timeout = timeout
        self._deadline = deadline
        self._session_id: str | None = None
        self._send_sequence = 1
        self._receive_sequence = 1
        self._batch_enabled = batch_enabled
        self._batch_context: tuple[StepResourcePlan, str | None, str, int | None, int] | None = None

    def bind(self, session_id: str) -> None:
        if self._session_id is not None or not isinstance(session_id, str) or not session_id:
            raise ValueError("peer session identity 必须且只能绑定一次。")
        self._session_id = session_id

    def set_round_deadline(self, deadline: float) -> None:
        """跨轮刷新绝对截止时间，同时保留双向 peer sequence。"""
        if self._session_id is None:
            raise ValueError("peer port 尚未绑定 session。")
        self._deadline = deadline

    def set_batch_round(
        self, plan: StepResourcePlan, *, modulus: int,
        run_id: str | None = None, epoch_id: str | None = None,
        physical_step: int | None = None,
    ) -> None:
        if not self._batch_enabled or self._session_id != plan.session_id:
            raise ValueError("peer 未协商批量能力或 session 不匹配")
        if type(modulus) is not int or modulus < 3:
            raise ValueError("批量 peer 模数无效")
        self._batch_context = (deepcopy(plan), run_id, epoch_id or plan.session_id,
                               physical_step, modulus)
        # 独立快照保留每次调用的变化检测；摘要仅计算一次，不信任调用者的对象 identity。
        self._batch_digest = public_step_plan_sha256(plan)

    def exchange_products(
        self, plan: StepResourcePlan, masks: tuple[ProductMaskPayload, ...],
    ) -> tuple[ProductMaskPayload, ...]:
        ids = tuple(item.resource_id for item in plan.product_resources)
        self._check_batch_values(masks, len(ids), "product", sender=self._role)
        if self._role == "P1":
            self._send_batch(plan, "product", ids, products=masks)
            incoming = self._receive_batch(plan, "product", ids).products
        else:
            incoming = self._receive_batch(plan, "product", ids).products
            self._send_batch(plan, "product", ids, products=masks)
        self._check_batch_values(incoming, len(ids), "product", sender=self._peer)
        return incoming

    def product_complete(self, plan: StepResourcePlan) -> None:
        self._barrier(plan, "product_complete",
                      tuple(item.resource_id for item in plan.product_resources))

    def send_truncations(
        self, plan: StepResourcePlan, values: tuple[P2TruncationPayload, ...],
    ) -> None:
        if self._role != "P2":
            raise ValueError("只有 P2 能发送截断批次")
        ids = tuple(item.resource_id for item in plan.state_truncation_resources)
        self._check_batch_values(values, len(ids), "truncation")
        self._send_batch(plan, "truncation", ids, truncations=values)

    def receive_truncations(self, plan: StepResourcePlan) -> tuple[P2TruncationPayload, ...]:
        if self._role != "P1":
            raise ValueError("只有 P1 能接收截断批次")
        ids = tuple(item.resource_id for item in plan.state_truncation_resources)
        values = self._receive_batch(plan, "truncation", ids).truncations
        self._check_batch_values(values, len(ids), "truncation")
        return values

    def state_complete(self, plan: StepResourcePlan) -> None:
        self._barrier(plan, "state_complete",
                      tuple(item.resource_id for item in plan.state_truncation_resources))

    def _barrier(self, plan: StepResourcePlan, phase: str, ids: tuple[str, ...]) -> None:
        if self._role == "P1":
            self._send_batch(plan, phase, ids)
            self._receive_batch(plan, phase, ids)
        else:
            self._receive_batch(plan, phase, ids)
            self._send_batch(plan, phase, ids)

    def _batch_identity(self, plan: StepResourcePlan) -> tuple[str | None, str, int | None, int]:
        if not self._batch_enabled or self._session_id != plan.session_id:
            raise ValueError("批量 peer 没有绑定本轮 session")
        if self._batch_context is None or self._batch_context[0] != plan:
            raise ValueError("批量 peer 未绑定本轮公开身份")
        return self._batch_context[1:]

    def _batch_payload(
        self, plan: StepResourcePlan, phase: str, ids: tuple[str, ...],
        *, products: tuple[ProductMaskPayload, ...] = (),
        truncations: tuple[P2TruncationPayload, ...] = (),
    ) -> Protocol3BatchPayload:
        run_id, epoch_id, physical_step, _ = self._batch_identity(plan)
        return Protocol3BatchPayload(
            phase, self._batch_digest, run_id, epoch_id, physical_step,
            {"product": 0, "product_complete": 1, "truncation": 2,
             "state_complete": 3}[phase], ids, products, truncations,
        )

    def _send_batch(
        self, plan: StepResourcePlan, phase: str, ids: tuple[str, ...],
        *, products: tuple[ProductMaskPayload, ...] = (),
        truncations: tuple[P2TruncationPayload, ...] = (),
    ) -> None:
        payload = self._batch_payload(plan, phase, ids, products=products,
                                      truncations=truncations)
        send_envelope(self._connection, WireEnvelope(
            SCHEMA_VERSION, "request", self._role, self._peer,
            self._send_sequence, "peer_batch", plan.session_id, plan.round_id,
            plan.step, None, payload,
        ), deadline=self._deadline if self._deadline is not None
           else deadline_after(self._timeout), limit=self._limit)
        self._send_sequence += 1

    def _receive_batch(
        self, plan: StepResourcePlan, phase: str, ids: tuple[str, ...],
    ) -> Protocol3BatchPayload:
        message = receive_envelope(
            self._connection,
            deadline=self._deadline if self._deadline is not None
            else deadline_after(self._timeout), limit=self._limit,
        )
        run_id, epoch_id, physical_step, _ = self._batch_identity(plan)
        payload = message.payload
        if (message.kind, message.sender, message.recipient, message.sequence,
            message.operation, message.session_id, message.round_id, message.step,
            message.resource_id) != (
            "request", self._peer, self._role, self._receive_sequence,
            "peer_batch", plan.session_id, plan.round_id, plan.step, None,
        ) or not isinstance(payload, Protocol3BatchPayload) or (
            payload.phase, payload.plan_sha256, payload.run_id, payload.epoch_id,
            payload.physical_step, payload.batch_index, payload.resource_ids,
            payload.version,
        ) != (
            phase, self._batch_digest, run_id, epoch_id,
            physical_step, {"product": 0, "product_complete": 1,
                            "truncation": 2, "state_complete": 3}[phase], ids,
            "control-batch-v1",
        ):
            raise ValueError("批量 peer 阶段、顺序或公开身份不匹配")
        self._receive_sequence += 1
        return payload

    def _check_batch_values(
        self, values: tuple[ProductMaskPayload, ...] | tuple[P2TruncationPayload, ...],
        count: int, phase: str, *, sender: str | None = None,
    ) -> None:
        if len(values) != count:
            raise ValueError("批次缺项或超出本地计划")
        if self._batch_context is None:
            raise ValueError("批次缺少模数")
        modulus = self._batch_context[4]
        for item in values:
            if phase == "product":
                if not isinstance(item, ProductMaskPayload) or item.party != (
                    0 if sender == "P1" else 1
                ):
                    raise ValueError("乘法批次角色或类型无效")
                shares = (item.d, item.e)
            else:
                if not isinstance(item, P2TruncationPayload):
                    raise ValueError("截断批次类型无效")
                shares = (item.value,)
            for share in shares:
                value = share.value
                if type(value) is not int or not 0 <= value < modulus:
                    raise ValueError("批次份额必须是 canonical residue")

    def send_product(self, metadata: ResourceMetadata, payload: ProductMaskPayload) -> None:
        if payload.party != (0 if self._role == "P1" else 1):
            raise ValueError("Protocol 1 peer payload 的发送方错误。")
        self._send("peer_product", metadata, payload)

    def receive_product(self, metadata: ResourceMetadata) -> ProductMaskPayload:
        value = self._receive("peer_product", metadata)
        if not isinstance(value, ProductMaskPayload) or value.party != (
            1 if self._role == "P1" else 0
        ):
            raise ValueError("Protocol 1 peer payload 的接收方错误。")
        return value

    def send_truncation(self, metadata: ResourceMetadata, payload: P2TruncationPayload) -> None:
        if self._role != "P2" or not isinstance(payload, P2TruncationPayload):
            raise ValueError("只有 P2 可以发送 Protocol 2 消息。")
        self._send("peer_truncation", metadata, payload)

    def receive_truncation(self, metadata: ResourceMetadata) -> P2TruncationPayload:
        if self._role != "P1":
            raise ValueError("只有 P1 可以接收 Protocol 2 消息。")
        value = self._receive("peer_truncation", metadata)
        if not isinstance(value, P2TruncationPayload):
            raise TypeError("Protocol 2 peer payload 类型错误。")
        return value

    def close(self) -> None:
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._connection.close()

    def _send(
        self,
        operation: Literal["peer_product", "peer_truncation"],
        metadata: ResourceMetadata,
        payload: object,
    ) -> None:
        session_id = self._bound_session(metadata)
        send_envelope(
            self._connection,
            WireEnvelope(
                SCHEMA_VERSION,
                "request",
                self._role,
                self._peer,
                self._send_sequence,
                operation,
                session_id,
                metadata.round_id,
                metadata.step,
                metadata.resource_id,
                payload,  # type: ignore[arg-type]
            ),
            deadline=self._deadline
            if self._deadline is not None
            else deadline_after(self._timeout),
            limit=self._limit,
        )
        self._send_sequence += 1

    def _receive(
        self, operation: Literal["peer_product", "peer_truncation"], metadata: ResourceMetadata
    ) -> object:
        session_id = self._bound_session(metadata)
        message = receive_envelope(
            self._connection,
            deadline=self._deadline
            if self._deadline is not None
            else deadline_after(self._timeout),
            limit=self._limit,
        )
        if (
            message.kind,
            message.sender,
            message.recipient,
            message.sequence,
            message.operation,
            message.session_id,
            message.round_id,
            message.step,
            message.resource_id,
        ) != (
            "request",
            self._peer,
            self._role,
            self._receive_sequence,
            operation,
            session_id,
            metadata.round_id,
            metadata.step,
            metadata.resource_id,
        ):
            raise ValueError("P1/P2 peer 信封的顺序、方向或 identity 不匹配。")
        self._receive_sequence += 1
        return message.payload

    def _bound_session(self, metadata: ResourceMetadata) -> str:
        if self._session_id is None or metadata.session_id != self._session_id:
            raise ValueError("P1/P2 peer session 或资源 identity 不匹配。")
        return self._session_id


def accept_p1_peer(
    listener: socket.socket, nonce: str, deadline: float, limit: int, timeout: float,
    *, batch: bool = True,
) -> LocalhostProtocol3PeerPort:
    """P1 接受唯一 P2 连接并完成 nonce 绑定。"""
    connection = accept_loopback(listener, deadline=deadline)
    try:
        hello = receive_envelope(connection, deadline=deadline, limit=limit)
        _validate_peer_hello(hello, "P2", "P1", nonce, batch=batch)
        send_envelope(
            connection,
            WireEnvelope(
                SCHEMA_VERSION,
                "hello",
                "P1",
                "P2",
                0,
                "hello",
                None,
                None,
                None,
                None,
                BatchHelloPayload(HelloPayload(nonce, os.getpid())) if batch
                else HelloPayload(nonce, os.getpid()),
            ),
            deadline=deadline,
            limit=limit,
        )
        return LocalhostProtocol3PeerPort(connection, "P1", limit, timeout,
                                          batch_enabled=batch)
    except Exception:
        connection.close()
        raise


def connect_p2_peer(
    address: Address, nonce: str, deadline: float, limit: int, timeout: float,
    *, batch: bool = True,
) -> LocalhostProtocol3PeerPort:
    """P2 主动连接 P1 并完成 nonce 绑定。"""
    connection = connect_loopback(address, deadline=deadline)
    try:
        send_envelope(
            connection,
            WireEnvelope(
                SCHEMA_VERSION,
                "hello",
                "P2",
                "P1",
                0,
                "hello",
                None,
                None,
                None,
                None,
                BatchHelloPayload(HelloPayload(nonce, os.getpid())) if batch
                else HelloPayload(nonce, os.getpid()),
            ),
            deadline=deadline,
            limit=limit,
        )
        hello = receive_envelope(connection, deadline=deadline, limit=limit)
        _validate_peer_hello(hello, "P1", "P2", nonce, batch=batch)
        return LocalhostProtocol3PeerPort(connection, "P2", limit, timeout,
                                          batch_enabled=batch)
    except Exception:
        connection.close()
        raise


def _validate_peer_hello(
    message: WireEnvelope, sender: Role, recipient: Role, nonce: str, *, batch: bool = True,
) -> None:
    payload = message.payload
    base = payload.base if isinstance(payload, BatchHelloPayload) else payload
    if (
        message.kind != "hello"
        or message.sender != sender
        or message.recipient != recipient
        or message.sequence != 0
        or message.operation != "hello"
        or message.session_id is not None
        or (batch and not isinstance(payload, BatchHelloPayload))
        or (not batch and not isinstance(payload, HelloPayload))
        or not isinstance(base, HelloPayload)
        or base.nonce != nonce
    ):
        raise ValueError("P1/P2 peer hello 的角色或 nonce 不匹配。")
