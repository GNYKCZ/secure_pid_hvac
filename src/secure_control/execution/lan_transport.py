"""独立角色的固定端口建连：显式实验明文或 TLS 1.3 双向认证。"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from queue import Empty, Queue

from .lan_config import LanConfig, LanEndpoint, Role


class LanConnectionError(RuntimeError):
    """名称解析、路由、监听或 TCP 建连失败。"""


class LanIdentityError(RuntimeError):
    """CA、用途、SAN 或 TLS 握手身份不匹配。"""


class LanTimeoutError(TimeoutError):
    """一条建连或 TLS 握手超过配置的绝对 deadline。"""


def listener(endpoint: LanEndpoint) -> socket.socket:
    """仅在显式 IPv4 bind 与固定端口监听，不允许 OS 分配公开端口。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((endpoint.bind, endpoint.port))
        sock.listen(1)
        return sock
    except OSError as error:
        sock.close()
        raise LanConnectionError("固定监听端口不可用或 bind 地址不存在。") from error


def connect_role(endpoint: LanEndpoint, config: LanConfig, peer: Role, deadline: float) -> socket.socket:
    """按显式配置建连；实验明文模式不验证网络对端身份。"""
    if config.transport == "mutual_tls":
        return connect_tls(endpoint, config, peer, deadline)
    if config.transport == "insecure_tcp":
        return _dial(_resolve(endpoint, deadline), deadline)
    raise ValueError("未知 LAN transport。")


def accept_role(sock: socket.socket, config: LanConfig, peer: Role, deadline: float) -> socket.socket:
    """按显式配置接受连接；实验明文模式只接受 TCP 连接。"""
    if config.transport == "mutual_tls":
        return accept_tls(sock, config, peer, deadline)
    if config.transport != "insecure_tcp":
        raise ValueError("未知 LAN transport。")
    try:
        sock.settimeout(_remaining(deadline))
        raw, _ = sock.accept()
    except TimeoutError as error:
        raise LanTimeoutError("等待对端 TCP 连接超时。") from error
    except OSError as error:
        raise LanConnectionError("接受 TCP 连接失败。") from error
    try:
        raw.settimeout(_remaining(deadline))
        return raw
    except Exception:
        raw.close()
        raise


def connect_tls(
    endpoint: LanEndpoint, config: LanConfig, peer: Role, deadline: float
) -> ssl.SSLSocket:
    """用拨号地址连接，但只信任稳定角色 DNS SAN；身份与 IP 分离。"""
    context = _context(config, server=False)
    addresses = _resolve(endpoint, deadline)
    raw = _dial(addresses, deadline)
    secure = None
    try:
        identity = config.topology.identities[peer]
        secure = context.wrap_socket(raw, server_hostname=identity, do_handshake_on_connect=False)
        secure.settimeout(_remaining(deadline))
        secure.do_handshake()
        _verify_identity(secure, identity)
        return secure
    except Exception as error:  # noqa: BLE001 - 握手异常必须关闭 socket
        (secure or raw).close()
        _raise_tls(error)


def accept_tls(
    sock: socket.socket, config: LanConfig, peer: Role, deadline: float
) -> ssl.SSLSocket:
    """接受一条连接并核对客户端角色 SAN，握手前不读取应用帧。"""
    context = _context(config, server=True)
    secure = None
    try:
        sock.settimeout(_remaining(deadline))
        raw, _ = sock.accept()
    except TimeoutError as error:
        raise LanTimeoutError("等待对端 TCP 连接超时。") from error
    except OSError as error:
        raise LanConnectionError("接受 TCP 连接失败。") from error
    try:
        secure = context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        secure.settimeout(_remaining(deadline))
        secure.do_handshake()
        _verify_identity(secure, config.topology.identities[peer])
        return secure
    except Exception as error:  # noqa: BLE001 - 握手异常必须关闭 socket
        (secure or raw).close()
        _raise_tls(error)


def _context(config: LanConfig, *, server: bool) -> ssl.SSLContext:
    if config.ca is None or config.certificate is None or config.private_key is None:
        raise LanIdentityError("TLS 配置缺少 CA、证书或私钥。")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    if not server:
        context.check_hostname = True
    if hasattr(ssl, "OP_NO_TICKET"):
        context.options |= ssl.OP_NO_TICKET
    try:
        context.load_verify_locations(cafile=str(config.ca))
        context.load_cert_chain(str(config.certificate), str(config.private_key))
    except (OSError, ssl.SSLError) as error:
        raise LanIdentityError("本机 CA、证书或私钥无法载入。") from error
    return context


def _verify_identity(sock: ssl.SSLSocket, expected: str) -> None:
    certificate = sock.getpeercert()
    names = certificate.get("subjectAltName", ())
    # 不接受 CN 回退、通配 SAN 或一张证书同时冒充多个协议角色。
    if names != (("DNS", expected),) or sock.version() != "TLSv1.3":
        raise LanIdentityError("对端 TLS 角色 SAN 或协议版本不匹配。")


def _resolve(endpoint: LanEndpoint, deadline: float) -> list[tuple]:
    """DNS 使用 daemon helper；超时后 CLI 可退出，不等待系统 resolver。"""
    answers: Queue[list[tuple] | Exception] = Queue(maxsize=1)

    def lookup() -> None:
        try:
            answers.put(socket.getaddrinfo(endpoint.host, endpoint.port, type=socket.SOCK_STREAM))
        except Exception as error:  # noqa: BLE001 - 传回主线程统一分类
            answers.put(error)

    threading.Thread(target=lookup, daemon=True).start()
    try:
        result = answers.get(timeout=_remaining(deadline))
    except Empty as error:
        raise LanTimeoutError("对端名称解析超过 startup deadline。") from error
    if isinstance(result, socket.gaierror):
        raise LanConnectionError("对端名称解析失败。") from result
    if isinstance(result, Exception):
        raise LanConnectionError("对端名称解析失败。") from result
    return result


def _dial(addresses: list[tuple], deadline: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, protocol, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, protocol)
        try:
            sock.settimeout(_remaining(deadline))
            sock.connect(sockaddr)
            return sock
        except TimeoutError as error:
            sock.close()
            raise LanTimeoutError("TCP 建连超时；网络不可达或被过滤，需两端核验。") from error
        except OSError as error:
            last_error = error
            sock.close()
    raise LanConnectionError("TCP 连接失败；检查地址、监听端口与防火墙。") from last_error


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LanTimeoutError("LAN 连接或握手超过绝对 deadline。")
    return remaining


def _raise_tls(error: Exception) -> None:
    if isinstance(error, (LanIdentityError, LanTimeoutError)):
        raise error
    if isinstance(error, TimeoutError):
        raise LanTimeoutError("TLS 握手超时。") from error
    if isinstance(error, ssl.SSLError):
        raise LanIdentityError("TLS 证书、身份或握手验证失败。") from error
    if isinstance(error, OSError):
        raise LanConnectionError("TLS 连接在握手期间中断。") from error
    raise error
