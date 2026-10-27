"""仅绑定 IPv4 loopback 的有界 TCP framing 与连接机制。"""

from __future__ import annotations

import select
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from math import isfinite

from .cycle_timing import _CycleDeadline, remaining_seconds
from .localhost_codec import WireEnvelope, decode_envelope, encode_envelope

_HEADER = struct.Struct("!I")
_LOOPBACK = "127.0.0.1"


def _configure_tcp(sock: socket.socket, *, enabled: bool = True) -> None:
    """建连 owner 在正式时钟前设置；失败时由 owner 关闭连接。"""
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, int(enabled))
    if sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != int(enabled):
        raise OSError("TCP_NODELAY 设置未生效。")


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
    try:
        _configure_tcp(connection)
    except OSError as error:
        connection.close()
        raise LocalhostTransportError("设置 localhost TCP 连接失败。") from error
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
        _configure_tcp(sock)
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
    _validate_frame_payload(payload, limit)
    _send_exact(sock, _HEADER.pack(len(payload)) + payload, deadline)


def _validate_frame_payload(payload: bytes, limit: int) -> None:
    """预发送检查与真实 framing 共用同一长度契约。"""
    if not isinstance(payload, bytes):
        raise TypeError("frame payload 必须是 bytes。")
    if not 0 < len(payload) <= limit:
        raise LocalhostTransportProtocolError("frame 长度必须为正且不超过上限。")


def receive_frame(sock: socket.socket, *, deadline: float, limit: int) -> bytes:
    """先验证长度再分配/读取 payload，拒绝空帧、超长帧和截断帧。"""
    header = _receive_exact(sock, _HEADER.size, deadline)
    (length,) = _HEADER.unpack(header)
    if not 0 < length <= limit:
        raise LocalhostTransportProtocolError("frame 声明长度为空或超过上限。")
    return _receive_exact(sock, length, deadline)


def _exchange_two_frames(sockets, payloads, *, deadline, limit, on_request, on_reply, observer=None):
    """原线程推进两路各一请求/回复；回调只报告字节事实，不解释业务授权。"""
    if len(sockets) != 2 or len(payloads) != 2 or sockets[0] is sockets[1]:
        raise ValueError("双连接交换需要两条独立socket及两份payload。")
    # 两路都先检查，避免第二份非法时第一份已经发出。
    for payload in payloads:
        _validate_frame_payload(payload, limit)
    outgoing = [memoryview(_HEADER.pack(len(p)) + p) for p in payloads]
    incoming = [bytearray(), bytearray()]
    targets, headers, complete, attempted = [4, 4], [False, False], [False, False], [False, False]
    previous = [sock.gettimeout() for sock in sockets]
    primary = None
    read_mask = 0

    def budget():
        remaining = remaining_seconds(deadline)
        if remaining <= 0:
            raise LocalhostTransportTimeout("双连接交换超过原绝对deadline。")
        return remaining

    def wait(readers, writers):
        try:
            ready_r, ready_w, errors = select.select(readers, writers, [], budget())
        except TimeoutError as error:
            raise LocalhostTransportTimeout("双连接就绪等待超时。") from error
        except OSError as error:
            raise LocalhostTransportDisconnected("双连接就绪等待失败。") from error
        budget()
        if errors or any(s not in readers for s in ready_r) or any(s not in writers for s in ready_w):
            raise LocalhostTransportProtocolError("双连接就绪结果不属于当前通道。")

    try:
        budget()
        for sock in sockets:
            sock.settimeout(0.)
        stalled = 0
        while any(outgoing):
            progressed = False
            for p, sock in enumerate(sockets):
                if not outgoing[p]:
                    continue
                budget()
                if not attempted[p]:
                    on_request(p, "uncertain")
                    attempted[p] = True
                budget()
                try:
                    count = sock.send(outgoing[p])
                except BlockingIOError:
                    continue
                except TimeoutError as error:
                    raise LocalhostTransportTimeout("双连接发送超时。") from error
                except OSError as error:
                    raise LocalhostTransportDisconnected("双连接发送失败。") from error
                if count <= 0:
                    raise LocalhostTransportDisconnected("发送完整请求前连接关闭。")
                outgoing[p] = outgoing[p][count:]
                progressed = True
                if not outgoing[p]:
                    on_request(p, "sent")
                budget()
            stalled = 0 if progressed else stalled + 1
            if stalled >= 8:
                raise LocalhostTransportError("双连接发送连续8次无进展。")
            if not progressed:
                wait([], [s for p, s in enumerate(sockets) if outgoing[p]])

        # 两份请求全部交给socket后才接收，不改变原协议阶段顺序。
        stalled = 0
        while not all(complete):
            progressed = False
            for p, sock in enumerate(sockets):
                if complete[p]:
                    continue
                budget()
                try:
                    chunk = sock.recv(targets[p] - len(incoming[p]))
                except BlockingIOError:
                    continue
                except TimeoutError as error:
                    raise LocalhostTransportTimeout("双连接接收超时。") from error
                except OSError as error:
                    raise LocalhostTransportDisconnected("双连接接收失败。") from error
                if not chunk:
                    raise LocalhostTransportDisconnected("完整回复到达前连接关闭。")
                if observer is not None and not read_mask & (1 << p):
                    observer('reply_read', 0, aux=p)
                    read_mask |= 1 << p
                incoming[p].extend(chunk)
                progressed = True
                if len(incoming[p]) == targets[p]:
                    if not headers[p]:
                        (targets[p],) = _HEADER.unpack(incoming[p])
                        if not 0 < targets[p] <= limit:
                            raise LocalhostTransportProtocolError("frame声明长度为空或超限。")
                        incoming[p].clear()
                        headers[p] = True
                    else:
                        budget()
                        if observer is not None:
                            observer('reply_frame', 0, aux=p)
                        on_reply(p, bytes(incoming[p]))
                        complete[p] = True
                budget()
            stalled = 0 if progressed else stalled + 1
            if stalled >= 8:
                raise LocalhostTransportError("双连接接收连续8次无进展。")
            if not progressed:
                wait([s for p, s in enumerate(sockets) if not complete[p]], [])
    except BaseException as error:
        primary = error
        raise
    finally:
        restoration = None
        for sock, mode in zip(sockets, previous, strict=True):
            try:
                sock.settimeout(mode)
            except BaseException as error:  # noqa: BLE001 - 继续恢复另一通道，循环后保留首错抛出。
                # 第一条恢复失败也必须尝试第二条；绝不覆盖已经发生的首错。
                if primary is not None:
                    BaseException.add_note(primary, "双连接交换恢复socket模式失败。")
                elif restoration is None:
                    restoration = error
                else:
                    BaseException.add_note(restoration, "另一条socket模式恢复也失败。")
        if primary is None and restoration is not None:
            raise restoration
    budget()


def _exchange_frame(sock, payload: bytes, *, deadline, limit: int) -> bytes:
    """单 owner 同时推进各一帧；只在双方均无进展时等待原绝对期限。"""
    _validate_frame_payload(payload, limit)
    outgoing = memoryview(_HEADER.pack(len(payload)) + payload)
    incoming = bytearray()
    target, header_done = _HEADER.size, False
    send_want, recv_want = "write", "read"
    previous, primary = sock.gettimeout(), None

    def budget():
        remaining = remaining_seconds(deadline)
        if remaining <= 0:
            raise LocalhostTransportTimeout("双向 frame 交换超过原绝对 deadline。")
        return remaining

    try:
        budget()
        sock.settimeout(0.)
        while outgoing or not header_done or len(incoming) < target:
            budget()
            progressed = False
            if outgoing:
                try:
                    sent = sock.send(outgoing)
                except ssl.SSLWantReadError:
                    send_want = "read"
                except (ssl.SSLWantWriteError, BlockingIOError):
                    send_want = "write"
                else:
                    if sent == 0:
                        raise LocalhostTransportDisconnected("双向交换发送时连接关闭。")
                    outgoing = outgoing[sent:]
                    progressed = True
            budget()
            if not header_done or len(incoming) < target:
                try:
                    chunk = sock.recv(target - len(incoming))
                except ssl.SSLWantWriteError:
                    recv_want = "write"
                except (ssl.SSLWantReadError, BlockingIOError):
                    recv_want = "read"
                else:
                    if not chunk:
                        raise LocalhostTransportDisconnected("对端在双向完整 frame 到达前关闭。")
                    incoming.extend(chunk)
                    progressed = True
                    if not header_done and len(incoming) == _HEADER.size:
                        (target,) = _HEADER.unpack(incoming)
                        if not 0 < target <= limit:
                            raise LocalhostTransportProtocolError("双向 frame 声明长度为空或超限。")
                        incoming.clear()
                        header_done = True
            budget()
            if progressed:
                continue
            # TLS recv 先行尝试，已覆盖 pending；WANT 的相反方向也必须等待。
            wants = ([send_want] if outgoing else []) + (
                [recv_want] if not header_done or len(incoming) < target else [])
            select.select([sock] if "read" in wants else [],
                          [sock] if "write" in wants else [], [], budget())
        result = bytes(incoming)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            sock.settimeout(previous)
        except BaseException:
            if primary is None:
                raise
            BaseException.add_note(primary, "双向 frame 交换恢复 socket timeout 失败。")
    budget()
    return result


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
    if isinstance(deadline, _CycleDeadline):
        return _receive_qpc_exact(sock, length, deadline)
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


def _receive_qpc_exact(sock, length, deadline, *, _observe=None):
    """同一QPC期限/字节游标；仅无就绪和非阻塞续读可等待，不重试事务。"""
    if (not isinstance(deadline, _CycleDeadline) or type(deadline.deadline_ns) is not int
            or deadline.deadline_ns < 0 or type(length) is not int or length < 1):
        raise ValueError("QPC接收需要原绝对deadline和正整数字节数。")
    data, no_progress, reason = bytearray(), 0, "native_error"
    primary = None
    # TLS内部可推进数据不一定对应底层可读；透明socket包装也保留pending接口。
    want = None if callable(getattr(sock, "pending", None)) else "read"

    def budget():
        nonlocal reason
        remaining = remaining_seconds(deadline)
        if remaining <= 0:
            reason = "deadline"
            raise LocalhostTransportTimeout("接收超过原QPC deadline。")
        return remaining

    def note(operation, started, *, remaining=None, wait=None, ready=None, outcome, error=None):
        if _observe is not None:
            _observe(operation, started, remaining=remaining, wait=wait, ready=ready,
                     no_progress=no_progress, outcome=outcome, error=error)

    def failed(error):
        try:
            note("failure", time.perf_counter_ns(), outcome=reason, error=error)
        except BaseException:  # noqa: BLE001 - 观察失败只附注，保留已经发生的接收/模式首错。
            BaseException.add_note(error, "QPC接收错误观察未完成。")

    try:
        budget()
    except BaseException as error:
        failed(error)
        raise
    previous = sock.gettimeout()
    try:
        sock.settimeout(0.)
        while len(data) < length:
            budget()
            if want is not None:
                started = time.perf_counter_ns()
                reason = "select_error"
                remaining = budget()
                readers, writers = ([sock], []) if want == "read" else ([], [sock])
                try:
                    readable, writable, exceptional = select.select(readers, writers, [], remaining)
                except TimeoutError as error:
                    raise LocalhostTransportTimeout("QPC接收就绪等待异常超时。") from error
                except OSError as error:
                    raise LocalhostTransportDisconnected("QPC接收就绪等待失败。") from error
                budget()
                if exceptional or readable not in ([], readers) or writable not in ([], writers):
                    raise ValueError("接收就绪结果与当前通道不匹配。")
                ready = len(readable)+len(writable)
                if not ready:
                    no_progress += 1
                note("select", started, remaining=round(remaining*1e9), wait=round(remaining*1e9),
                     ready=ready, outcome="ready" if ready else "empty")
                budget()  # 包括可选观察成本；迟到结果不再开始读取。
                if not ready:
                    if no_progress >= 8:
                        reason = "no_progress_guard"
                        raise LocalhostTransportError("QPC接收连续8次无进展。")
                    continue
            reason = "native_error"
            started = time.perf_counter_ns()
            budget()
            try:
                chunk = sock.recv(length-len(data))
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError) as error:
                want = "write" if isinstance(error, ssl.SSLWantWriteError) else "read"
                no_progress += 1
                outcome = ("want_write" if want == "write" else "want_read"
                           if isinstance(error, ssl.SSLWantReadError) else "would_block")
                note("recv", started, outcome=outcome)
            except TimeoutError as error:
                raise LocalhostTransportTimeout("QPC非阻塞接收异常超时。") from error
            except OSError as error:
                raise LocalhostTransportDisconnected("QPC接收时连接或TLS失败。") from error
            else:
                if not chunk:
                    reason = "eof"
                    raise LocalhostTransportDisconnected("对端在完整frame到达前关闭连接。")
                data.extend(chunk)
                no_progress = 0
                want = None if callable(getattr(sock, "pending", None)) else "read"
            budget()
            if no_progress >= 8:
                reason = "no_progress_guard"
                raise LocalhostTransportError("QPC接收连续8次无进展。")
        budget()
        result = bytes(data)
    except BaseException as error:
        primary = error
        failed(error)
        raise
    finally:
        try:
            sock.settimeout(previous)
        except BaseException as error:
            try:
                note("restore_error", time.perf_counter_ns(), outcome="restore_error", error=error)
            except BaseException:  # noqa: BLE001 - 模式错误观察不能覆盖原接收首错。
                BaseException.add_note(primary if primary is not None else error, "QPC模式恢复观察未完成。")
            if primary is None:
                reason = "restore_error"
                failed(error)
                raise
    try:
        budget()  # 收齐、转换和模式恢复均占同一期限。
    except BaseException as error:
        failed(error)
        raise
    return result


def _set_remaining_timeout(sock: socket.socket, deadline: float) -> None:
    remaining = remaining_seconds(deadline)
    if remaining <= 0:
        raise LocalhostTransportTimeout("localhost socket 操作超过绝对 deadline。")
    sock.settimeout(remaining)
