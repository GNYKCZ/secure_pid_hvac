"""三机单步试验的严格角色配置与唯一拓扑 profile。"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

import yaml

Role = Literal["Client", "P1", "P2"]
_IDENTITY = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?\Z")
_MAX_CONFIG_BYTES = 64 * 1024


class _StrictLoader(yaml.SafeLoader):
    """配置键不能重复，避免不同工具对身份或地址得出不同解释。"""

    def compose_node(self, parent: yaml.nodes.Node | None, index: object) -> yaml.nodes.Node:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("LAN YAML 不允许 alias。")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[object, object]:
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError("LAN YAML 包含重复配置键。")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True, slots=True)
class LanEndpoint:
    """固定监听与拨号地址；角色身份由拓扑另一字段单独确定。"""

    bind: str
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class LanTopology:
    """三条连接的唯一部署来源与规范内容摘要。"""

    identities: dict[Role, str]
    p1_client: LanEndpoint
    p2_client: LanEndpoint
    p1_peer: LanEndpoint
    digest: str


@dataclass(frozen=True, slots=True)
class LanConfig:
    """一台主机的本地密钥路径、拓扑与有界 timeout。"""

    role: Role
    topology: LanTopology
    ca: Path
    certificate: Path
    private_key: Path
    startup_timeout: float
    step_timeout: float
    shutdown_timeout: float
    controller_config: Path | None


def load_lan_config(path: str | Path, role: Role) -> LanConfig:
    """拒绝未知字段、缺项、动态端口和不一致角色，不读取私钥内容。"""
    source = Path(path).resolve()
    data = _load_yaml(source)
    _fields(
        data,
        {"role", "topology", "tls", "timeouts"} | ({"controller"} if role == "Client" else set()),
    )
    if data["role"] != role:
        raise ValueError("角色配置与命令角色不匹配。")
    topology_path = _relative(source, data["topology"])
    profile = _load_yaml(topology_path)
    _fields(profile, {"version", "identities", "p1_client", "p2_client", "p1_peer"})
    if type(profile["version"]) is not int or profile["version"] != 1:
        raise ValueError("不支持的 LAN topology version。")
    identities = profile["identities"]
    _fields(identities, {"Client", "P1", "P2"})
    if (
        any(
            not isinstance(value, str) or not _IDENTITY.fullmatch(value) or ".." in value
            for value in identities.values()
        )
        or len(set(identities.values())) != 3
    ):
        raise ValueError("角色 TLS DNS 身份必须合法且唯一。")
    endpoints = tuple(_endpoint(profile[name]) for name in ("p1_client", "p2_client", "p1_peer"))
    if len({item.port for item in endpoints}) != 3:
        raise ValueError("三个固定监听端口不得冲突。")
    canonical = json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    topology = LanTopology(identities, *endpoints, sha256(canonical.encode()).hexdigest())
    tls = data["tls"]
    _fields(tls, {"ca", "certificate", "private_key"})
    ca, certificate, private_key = (
        _relative(source, tls[name]) for name in ("ca", "certificate", "private_key")
    )
    for name, file in (("CA", ca), ("证书", certificate), ("私钥", private_key)):
        if not file.is_file():
            raise ValueError(f"{name} 路径不是存在的普通文件。")
    timeouts = data["timeouts"]
    _fields(timeouts, {"startup", "step", "shutdown"})
    seconds = tuple(_timeout(timeouts[name], name) for name in ("startup", "step", "shutdown"))
    controller = _relative(source, data["controller"]) if role == "Client" else None
    if controller is not None and not controller.is_file():
        raise ValueError("Client controller 配置不存在。")
    return LanConfig(role, topology, ca, certificate, private_key, *seconds, controller)


def _load_yaml(path: Path) -> dict[str, object]:
    try:
        source = path.read_bytes()
    except OSError as error:
        raise ValueError("无法读取 LAN 配置。") from error
    if len(source) > _MAX_CONFIG_BYTES:
        raise ValueError("LAN 配置超过大小限制。")
    try:
        value = yaml.load(source, Loader=_StrictLoader)
    except yaml.YAMLError as error:
        raise ValueError("LAN YAML 解析失败。") from error
    if not isinstance(value, dict):
        raise TypeError("LAN 配置根节点必须是映射。")
    return value


def _fields(value: object, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("LAN 配置字段缺失或包含未知字段。")


def _relative(config: Path, value: object) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("LAN 文件路径必须是非空字符串。")
    item = Path(value)
    return (config.parent / item).resolve() if not item.is_absolute() else item.resolve()


def _endpoint(value: object) -> LanEndpoint:
    _fields(value, {"bind", "host", "port"})
    bind, host, port = value["bind"], value["host"], value["port"]
    if not isinstance(bind, str):
        raise TypeError("bind 必须是显式 IPv4 地址。")
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as error:
        raise ValueError("bind 必须是显式 IPv4 地址。") from error
    if address.version != 4:
        raise ValueError("bind 只支持显式 IPv4 地址。")
    if not isinstance(host, str) or not _HOST.fullmatch(host) or ".." in host:
        raise ValueError("拨号地址必须是非空 DNS 名称或 IP。")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("LAN 监听端口必须是固定的 1..65535 整数。")
    return LanEndpoint(bind, host, port)


def _timeout(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} timeout 必须是正数。")
    result = float(value)
    if not 0 < result <= 3600:
        raise ValueError(f"{name} timeout 必须在 (0, 3600] 秒。")
    return result
