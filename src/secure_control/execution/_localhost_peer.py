"""P1↔P2 localhost 在线消息通道；只负责 identity、顺序与有界收发。"""

from __future__ import annotations

import os
import socket
from typing import Literal

from secure_control.protocol.messages import (
    P2TruncationPayload,
    ProductMaskPayload,
    ResourceMetadata,
)

from .localhost_codec import SCHEMA_VERSION, HelloPayload, WireEnvelope
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

    def bind(self, session_id: str) -> None:
        if self._session_id is not None or not isinstance(session_id, str) or not session_id:
            raise ValueError("peer session identity 必须且只能绑定一次。")
        self._session_id = session_id

    def set_round_deadline(self, deadline: float) -> None:
        """跨轮刷新绝对截止时间，同时保留双向 peer sequence。"""
        if self._session_id is None:
            raise ValueError("peer port 尚未绑定 session。")
        self._deadline = deadline

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
    listener: socket.socket, nonce: str, deadline: float, limit: int, timeout: float
) -> LocalhostProtocol3PeerPort:
    """P1 接受唯一 P2 连接并完成 nonce 绑定。"""
    connection = accept_loopback(listener, deadline=deadline)
    try:
        hello = receive_envelope(connection, deadline=deadline, limit=limit)
        _validate_peer_hello(hello, "P2", "P1", nonce)
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
                HelloPayload(nonce, os.getpid()),
            ),
            deadline=deadline,
            limit=limit,
        )
        return LocalhostProtocol3PeerPort(connection, "P1", limit, timeout)
    except Exception:
        connection.close()
        raise


def connect_p2_peer(
    address: Address, nonce: str, deadline: float, limit: int, timeout: float
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
                HelloPayload(nonce, os.getpid()),
            ),
            deadline=deadline,
            limit=limit,
        )
        hello = receive_envelope(connection, deadline=deadline, limit=limit)
        _validate_peer_hello(hello, "P1", "P2", nonce)
        return LocalhostProtocol3PeerPort(connection, "P2", limit, timeout)
    except Exception:
        connection.close()
        raise


def _validate_peer_hello(message: WireEnvelope, sender: Role, recipient: Role, nonce: str) -> None:
    if (
        message.kind != "hello"
        or message.sender != sender
        or message.recipient != recipient
        or message.sequence != 0
        or message.operation != "hello"
        or message.session_id is not None
        or not isinstance(message.payload, HelloPayload)
        or message.payload.nonce != nonce
    ):
        raise ValueError("P1/P2 peer hello 的角色或 nonce 不匹配。")
