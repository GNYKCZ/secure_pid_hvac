"""仅绑定 IPv4 loopback 的有界 TCP framing 与连接机制。"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass
from math import isfinite

from .localhost_codec import WireEnvelope, decode_envelope, encode_envelope

_HEADER = struct.Struct("!I")
_LOOPBACK = "127.0.0.1"


class LocalhostTransportError(RuntimeError):
    """localhost framing、连接或 socket 状态错误。"""


class LocalhostTransportTimeout(LocalhostTransportError, TimeoutError):
    """某个使用绝对 deadline 的 socket 操作超时。"""


class LocalhostTransportProtocolError(LocalhostTransportError):
    """frame 长度、截断或 loopback 地址违反传输契约。"""


class LocalhostTransportDisconnected(LocalhostTransportError):
    """对端在完整 frame 完成前关闭连接。"""


@dataclass(frozen=True, slots=True)
class LocalhostTimeouts:
    """启动、单步与关闭阶段的严格正数秒数上限。"""

    startup: float = 10.0
    step: float = 30.0
    shutdown: float = 5.0

    def __post_init__(self) -> None:
        for name in ("startup", "step", "shutdown"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} timeout 必须是有限正数。")
            if not isfinite(float(value)) or value <= 0:
                raise ValueError(f"{name} timeout 必须是有限正数。")


_DEFAULT_TIMEOUTS = LocalhostTimeouts()


@dataclass(frozen=True, slots=True)
class LocalhostTransportConfig:
    """首版本机 TCP 配置；禁止 wildcard、主机名和外部地址。"""

    host: str = _LOOPBACK
    port: int = 0
    max_frame_bytes: int = 8 * 1024 * 1024
    timeouts: LocalhostTimeouts = _DEFAULT_TIMEOUTS

    def __post_init__(self) -> None:
        if self.host != _LOOPBACK:
            raise ValueError("localhost transport 只允许字面量 127.0.0.1。")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("port 必须是整数。")
        if not 0 <= self.port <= 65535:
            raise ValueError("port 必须是 0 或 1..65535。")
        if isinstance(self.max_frame_bytes, bool) or not isinstance(self.max_frame_bytes, int):
            raise TypeError("max_frame_bytes 必须是整数。")
        if not 1 <= self.max_frame_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_frame_bytes 必须位于 1..67108864。")
        if not isinstance(self.timeouts, LocalhostTimeouts):
            raise TypeError("timeouts 必须是 LocalhostTimeouts。")


def deadline_after(timeout: float) -> float:
    """由有限正 timeout 生成 monotonic 绝对 deadline。"""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout 必须是有限正数。")
    if not isfinite(float(timeout)) or timeout <= 0:
        raise ValueError("timeout 必须是有限正数。")
    return time.monotonic() + float(timeout)


def create_listener(host: str, port: int, *, backlog: int = 4) -> socket.socket:
    """在字面量 IPv4 loopback 上建立 listener，并让端口冲突直接失败。"""
    if host != _LOOPBACK:
        raise ValueError("listener 只允许绑定 127.0.0.1。")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((host, port))
        listener.listen(backlog)
        return listener
    except Exception:
        listener.close()
        raise


def accept_loopback(listener: socket.socket, *, deadline: float) -> socket.socket:
    """在总 deadline 内接受一条连接，并拒绝非 IPv4 loopback peer。"""
    _set_remaining_timeout(listener, deadline)
    try:
        connection, address = listener.accept()
    except TimeoutError as error:
        raise LocalhostTransportTimeout("等待 localhost 连接超时。") from error
    except OSError as error:
        raise LocalhostTransportError("接受 localhost 连接失败。") from error
    if address[0] != _LOOPBACK:
        connection.close()
        raise LocalhostTransportProtocolError("只接受 127.0.0.1 peer。")
    return connection


def connect_loopback(address: tuple[str, int], *, deadline: float) -> socket.socket:
    """在绝对 deadline 内连接字面量 loopback 地址。"""
    host, port = address
    if host != _LOOPBACK:
        raise ValueError("只允许连接 127.0.0.1。")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _set_remaining_timeout(sock, deadline)
        sock.connect((host, port))
        return sock
    except TimeoutError as error:
        sock.close()
        raise LocalhostTransportTimeout("连接 localhost peer 超时。") from error
    except OSError as error:
        sock.close()
        raise LocalhostTransportError("连接 localhost peer 失败。") from error


def send_frame(
    sock: socket.socket,
    payload: bytes,
    *,
    deadline: float,
    limit: int,
) -> None:
    """发送 ``4-byte network order length + payload``，全过程共用一个 deadline。"""
    if not isinstance(payload, bytes):
        raise TypeError("frame payload 必须是 bytes。")
    if not 0 < len(payload) <= limit:
        raise LocalhostTransportProtocolError("frame 长度必须为正且不超过上限。")
    _send_exact(sock, _HEADER.pack(len(payload)) + payload, deadline)


def receive_frame(sock: socket.socket, *, deadline: float, limit: int) -> bytes:
    """先验证长度再分配/读取 payload，拒绝空帧、超长帧和截断帧。"""
    header = _receive_exact(sock, _HEADER.size, deadline)
    (length,) = _HEADER.unpack(header)
    if not 0 < length <= limit:
        raise LocalhostTransportProtocolError("frame 声明长度为空或超过上限。")
    return _receive_exact(sock, length, deadline)


def send_envelope(
    sock: socket.socket,
    message: WireEnvelope,
    *,
    deadline: float,
    limit: int,
) -> None:
    """编码并发送一条固定 schema 信封。"""
    send_frame(sock, encode_envelope(message), deadline=deadline, limit=limit)


def receive_envelope(sock: socket.socket, *, deadline: float, limit: int) -> WireEnvelope:
    """接收并严格解码一条固定 schema 信封。"""
    return decode_envelope(receive_frame(sock, deadline=deadline, limit=limit))


def _send_exact(sock: socket.socket, payload: bytes, deadline: float) -> None:
    view = memoryview(payload)
    while view:
        _set_remaining_timeout(sock, deadline)
        try:
            sent = sock.send(view)
        except TimeoutError as error:
            raise LocalhostTransportTimeout("发送 localhost frame 超时。") from error
        except OSError as error:
            raise LocalhostTransportDisconnected("发送 localhost frame 时连接断开。") from error
        if sent == 0:
            raise LocalhostTransportDisconnected("发送 localhost frame 时连接已关闭。")
        view = view[sent:]


def _receive_exact(sock: socket.socket, length: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < length:
        _set_remaining_timeout(sock, deadline)
        try:
            chunk = sock.recv(length - len(data))
        except TimeoutError as error:
            raise LocalhostTransportTimeout("接收 localhost frame 超时。") from error
        except OSError as error:
            raise LocalhostTransportDisconnected("接收 localhost frame 时连接断开。") from error
        if not chunk:
            raise LocalhostTransportDisconnected("对端在完整 frame 到达前关闭连接。")
        data.extend(chunk)
    return bytes(data)


def _set_remaining_timeout(sock: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LocalhostTransportTimeout("localhost socket 操作超过绝对 deadline。")
    sock.settimeout(remaining)
