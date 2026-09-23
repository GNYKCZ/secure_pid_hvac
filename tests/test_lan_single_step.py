"""固定端口 LAN 模式的真实多进程 mTLS 与失败回归测试。"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from secure_control.execution.lan_config import LanEndpoint, load_lan_config
from secure_control.execution.lan_runtime import _check_request
from secure_control.execution.lan_transport import (
    LanConnectionError,
    LanIdentityError,
    LanTimeoutError,
    _resolve,
    _verify_identity,
    listener,
)
from secure_control.execution.localhost_codec import (
    SCHEMA_VERSION,
    LanHelloPayload,
    LocalhostCodecError,
    WireEnvelope,
    decode_envelope,
    encode_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
NAMES = {
    "Client": "client.secure-control.test",
    "P1": "p1.secure-control.test",
    "P2": "p2.secure-control.test",
}


def _free_ports() -> tuple[int, int, int]:
    sockets = [socket.socket() for _ in range(3)]
    try:
        for item in sockets:
            item.bind(("127.0.0.1", 0))
        return tuple(item.getsockname()[1] for item in sockets)
    finally:
        for item in sockets:
            item.close()


@pytest.fixture
def deployment(tmp_path: Path) -> dict[str, Path]:
    """每次试验使用隔离的拓扑、随机固定端口和不入库的角色私钥。"""
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "prepare_local_lan_certs.py"),
            "--output",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    p1, p2, peer = _free_ports()
    topology = tmp_path / "topology.yaml"
    topology.write_text(
        "version: 1\nidentities:\n"
        + "".join(f"  {role}: {dns}\n" for role, dns in NAMES.items())
        + "".join(
            f"{name}:\n  bind: 127.0.0.1\n  host: 127.0.0.1\n  port: {port}\n"
            for name, port in (("p1_client", p1), ("p2_client", p2), ("p1_peer", peer))
        ),
        encoding="utf-8",
    )
    paths = {"topology": topology}
    for role in NAMES:
        config = tmp_path / f"{role.lower()}.yaml"
        config.write_text(
            f"role: {role}\ntopology: topology.yaml\n"
            + (
                f"controller: {ROOT / 'configs' / 'hvac_dual_loop.yaml'}\n"
                if role == "Client"
                else ""
            )
            + "tls:\n  ca: ca.pem\n"
            + f"  certificate: {role.lower()}.pem\n"
            + f"  private_key: {role.lower()}.key\n"
            + "timeouts:\n  startup: 8\n  step: 15\n  shutdown: 3\n",
            encoding="utf-8",
        )
        paths[role] = config
    return paths


def _run(role: str, config: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "uv",
            "run",
            "secure-control",
            role.lower(),
            "--config",
            str(config),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _finish(
    process: subprocess.Popen[str], timeout: float = 25
) -> tuple[int, dict[str, object], str]:
    output, errors = process.communicate(timeout=timeout)
    return process.returncode, json.loads(output), errors


def test_three_independent_commands_complete_mtls_step(deployment: dict[str, Path]) -> None:
    """三个独立 PID 沿 Client→双方和 P2→P1 peer 通道完成双提交。"""
    p1 = _run("P1", deployment["P1"])
    p2 = _run("P2", deployment["P2"])
    try:
        time.sleep(0.5)
        client = _run("Client", deployment["Client"])
        code, result, errors = _finish(client)
        assert code == 0, (result, errors)
        assert result["status"] == "complete"
        assert result["tls_version"] == "TLSv1.3"
        assert result["maximum_raw_difference"] < 0.01
        assert result["resource_counts"]["products_consumed"] > 0
        assert result["resource_counts"]["truncations_consumed"] >= 0
        assert all(value >= 0 for value in result["timings_ms"].values())
        c1, r1, e1 = _finish(p1)
        c2, r2, e2 = _finish(p2)
        assert (c1, c2) == (0, 0), (r1, e1, r2, e2)
        assert r1["status"] == r2["status"] == "closed"
        assert len({result["pid"], r1["pid"], r2["pid"]}) == 3
        assert result["profile_sha256"] == r1["profile_sha256"] == r2["profile_sha256"]
    finally:
        for process in (p1, p2):
            if process.poll() is None:
                process.kill()
                process.communicate()


def test_wrong_role_san_rejected(deployment: dict[str, Path]) -> None:
    """CA 正确但 P1 用 P2 身份证书仍须在握手后拒绝。"""
    config = deployment["P1"]
    config.write_text(
        config.read_text(encoding="utf-8").replace("p1.pem", "p2.pem").replace("p1.key", "p2.key"),
        encoding="utf-8",
    )
    p1 = _run("P1", config)
    try:
        time.sleep(0.5)
        client = _run("Client", deployment["Client"])
        code, result, _ = _finish(client, 15)
        assert code == 4
        assert result["category"] == "identity_or_protocol"
    finally:
        if p1.poll() is None:
            p1.kill()
        p1.communicate()


def test_untrusted_ca_rejected(deployment: dict[str, Path]) -> None:
    other = deployment["P1"].parent / "other-ca"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "prepare_local_lan_certs.py"),
            "--output",
            str(other),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    config = deployment["P1"]
    config.write_text(
        config.read_text(encoding="utf-8").replace("ca: ca.pem", "ca: other-ca/ca.pem"),
        encoding="utf-8",
    )
    p1 = _run("P1", config)
    try:
        time.sleep(0.5)
        code, result, _ = _finish(_run("Client", deployment["Client"]), 12)
        pcode, presult, _ = _finish(p1, 12)
        assert code != 0 and "raw_control" not in result
        assert pcode == 4 and presult["category"] == "identity_or_protocol"
    finally:
        if p1.poll() is None:
            p1.kill()
            p1.communicate()


def test_missing_listener_and_wait_timeout_fail_closed(deployment: dict[str, Path]) -> None:
    """拒绝连接和无 Client 等待都限时非零结束，不输出控制结果。"""
    code, result, errors = _finish(_run("Client", deployment["Client"]), 12)
    assert code == 3, (result, errors)
    assert result["category"] == "connection"
    assert "raw_control" not in result
    config = deployment["P1"]
    config.write_text(
        config.read_text(encoding="utf-8").replace("startup: 8", "startup: 0.3"),
        encoding="utf-8",
    )
    code, result, errors = _finish(_run("P1", config), 8)
    assert code == 5, (result, errors)
    assert result["category"] == "uncertain_or_disconnected"


def test_profile_mismatch_rejected_before_offline(deployment: dict[str, Path]) -> None:
    """TLS 身份正确但拓扑快照不同，P1 不接收离线单方材料。"""
    changed = deployment["topology"].with_name("changed.yaml")
    changed.write_text(
        deployment["topology"]
        .read_text(encoding="utf-8")
        .replace("p2.secure-control.test", "new-p2.secure-control.test"),
        encoding="utf-8",
    )
    config = deployment["P1"]
    config.write_text(
        config.read_text(encoding="utf-8").replace("topology.yaml", "changed.yaml"),
        encoding="utf-8",
    )
    p1 = _run("P1", config)
    try:
        time.sleep(0.5)
        client = _run("Client", deployment["Client"])
        code, result, _ = _finish(client, 12)
        pcode, presult, _ = _finish(p1, 12)
        assert code != 0 and "raw_control" not in result
        assert pcode == 4 and presult["category"] == "identity_or_protocol"
    finally:
        if p1.poll() is None:
            p1.kill()
            p1.communicate()


def test_old_sequence_and_session_rejected() -> None:
    """同一连接不接受旧 sequence 或跨 session 操作。"""
    request = WireEnvelope(
        SCHEMA_VERSION,
        "request",
        "Client",
        "P1",
        1,
        "lan_ready",
        "old-session",
        None,
        None,
        None,
        None,
    )
    with pytest.raises(ValueError, match="session"):
        _check_request(request, "P1", 2, "lan_ready", "new-session")


def test_configuration_rejects_duplicate_key_and_role(deployment: dict[str, Path]) -> None:
    config = deployment["P1"]
    original = config.read_text(encoding="utf-8")
    config.write_text(original + "role: P2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="重复"):
        load_lan_config(config, "P1")
    config.write_text(original.replace("role: P1", "role: P2"), encoding="utf-8")
    with pytest.raises(ValueError, match="角色"):
        load_lan_config(config, "P1")
    config.write_text(
        original.replace("topology: topology.yaml", "topology: &path topology.yaml").replace(
            "ca: ca.pem", "ca: *path"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="alias"):
        load_lan_config(config, "P1")


def test_dns_lookup_respects_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow_lookup(*args: object, **kwargs: object) -> list[tuple]:
        time.sleep(0.5)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", slow_lookup)
    start = time.monotonic()
    with pytest.raises(LanTimeoutError, match="名称解析"):
        _resolve(LanEndpoint("127.0.0.1", "slow.example.test", 34401), start + 0.05)
    assert time.monotonic() - start < 0.3


def test_extra_role_san_is_not_accepted() -> None:
    class FakePeer:
        def getpeercert(self) -> dict[str, tuple[tuple[str, str], ...]]:
            return {"subjectAltName": (("DNS", NAMES["P1"]), ("DNS", NAMES["P2"]))}

        def version(self) -> str:
            return "TLSv1.3"

    with pytest.raises(LanIdentityError, match="SAN"):
        _verify_identity(FakePeer(), NAMES["P1"])  # type: ignore[arg-type]


def test_address_change_requires_shared_profile(deployment: dict[str, Path]) -> None:
    """可变拨号地址独立于证书身份，profile 变更反映在摘要中。"""
    first = load_lan_config(deployment["Client"], "Client")
    topology = deployment["topology"]
    topology.write_text(
        topology.read_text(encoding="utf-8").replace("host: 127.0.0.1", "host: localhost", 1),
        encoding="utf-8",
    )
    second = load_lan_config(deployment["Client"], "Client")
    assert first.topology.identities == second.topology.identities
    assert first.topology.digest != second.topology.digest
    assert second.topology.p1_client.host == "localhost"


def test_fixed_port_collision_fails_before_session(deployment: dict[str, Path]) -> None:
    config = load_lan_config(deployment["P1"], "P1")
    occupied = listener(config.topology.p1_client)
    try:
        with pytest.raises(LanConnectionError, match="固定监听端口"):
            listener(config.topology.p1_client)
    finally:
        occupied.close()


def test_lan_hello_codec_rejects_wrong_mode_and_replay_shape() -> None:
    valid = WireEnvelope(
        SCHEMA_VERSION,
        "hello",
        "Client",
        "P1",
        0,
        "lan_hello",
        "session",
        None,
        None,
        None,
        LanHelloPayload("a" * 64, "b" * 64),
    )
    encoded = encode_envelope(valid)
    assert decode_envelope(encoded) == valid
    with pytest.raises(LocalhostCodecError):
        decode_envelope(encoded.replace(b"lan-single-step-v1", b"other-mode"))
    with pytest.raises(LocalhostCodecError):
        decode_envelope(encoded.replace(b'"nonce":"' + b"b" * 64 + b'"', b'"nonce":"x"'))
