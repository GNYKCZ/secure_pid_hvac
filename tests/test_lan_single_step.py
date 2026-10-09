"""固定端口 LAN 模式的真实多进程 mTLS 与失败回归测试。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from lan_test_support import free_ports, reap_processes, role_command, run_role, start_processes

from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import _check_request
from secure_control.execution.lan_transport import (
    LanConnectionError,
    LanIdentityError,
    _verify_identity,
    listener,
)
from secure_control.execution.localhost_codec import (
    SCHEMA_VERSION,
    WireEnvelope,
    decode_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
NAMES = {
    "Client": "client.secure-control.test",
    "P1": "p1.secure-control.test",
    "P2": "p2.secure-control.test",
}

# 故障进程仍使用仓库原有 LAN 入口、真实 TLS socket 与独立 PID；只在该进程内
# 替换一个发送/回执边界。生产代码不提供故障开关或 TLS 隐式明文回退。
_FAULT_BOOTSTRAP = r"""
import struct
import sys
from pathlib import Path
import secure_control.execution.lan_runtime as lan
from secure_control.execution import _localhost_peer as peer
from secure_control.execution.localhost_codec import (
    SCHEMA_VERSION, WireEnvelope, decode_envelope, encode_envelope,
)
from secure_control.execution.localhost_transport import (
    deadline_after, receive_envelope, send_envelope, send_frame,
)
from secure_control.experiments.lan_runner import cli

fault = sys.argv[1]
capture_path = sys.argv[2]
command = sys.argv[3:]
if fault in {'offline_disconnect', 'stage_ack_loss', 'commit_ack_loss'}:
    original = lan._party_reply
    def reply(sock, request, payload, timeout, **kwargs):
        endpoint_op = getattr(request.payload, 'operation', None)
        if (fault == 'offline_disconnect' and request.operation == 'offline'):
            original(sock, request, payload, timeout, **kwargs)
            print('fault:offline_ack_then_disconnect', file=sys.stderr, flush=True)
            sock.close()
            raise RuntimeError('injected disconnect')
        if ((fault == 'stage_ack_loss' and endpoint_op in {'stage_output', 'stage_batch'}) or
                (fault == 'commit_ack_loss' and endpoint_op == 'commit')):
            print('fault:' + fault, file=sys.stderr, flush=True)
            sock.close()
            raise RuntimeError('injected lost ack')
        return original(sock, request, payload, timeout, **kwargs)
    lan._party_reply = reply
elif fault in {'peer_half_frame', 'peer_resource_replay'}:
    original = peer.LocalhostProtocol3PeerPort._send_batch
    injected = False
    def send(self, plan, phase, ids, *, products=(), truncations=()):
        global injected
        if not injected and phase == 'product':
            injected = True
            if fault == 'peer_half_frame':
                print('fault:peer_half_frame', file=sys.stderr, flush=True)
                self._connection.sendall(struct.pack('!I', 32) + b'abc')
                self._connection.close()
                raise RuntimeError('injected partial frame')
            sequence = self._send_sequence
            original(self, plan, phase, ids, products=products,
                     truncations=truncations)
            repeated = WireEnvelope(
                SCHEMA_VERSION, 'request', self._role, self._peer, sequence,
                'peer_batch', plan.session_id, plan.round_id, plan.step,
                None, self._batch_payload(plan, phase, ids, products=products,
                                          truncations=truncations),
            )
            print('fault:peer_resource_replay', file=sys.stderr, flush=True)
            send_envelope(self._connection, repeated,
                          deadline=self._deadline or deadline_after(self._timeout),
                          limit=self._limit)
            return
        return original(self, plan, phase, ids, products=products,
                        truncations=truncations)
    peer.LocalhostProtocol3PeerPort._send_batch = send
elif fault in {'client_ready_replay', 'capture_ready', 'old_session_replay'}:
    original = lan._request
    injected = False
    def request(sock, role, sequence, operation, session, timeout, *args, **kwargs):
        global injected
        if not injected and role == 'P1' and operation == 'lan_ready' and fault == 'old_session_replay':
            injected = True
            old_frame = Path(capture_path).read_bytes()
            if decode_envelope(old_frame).session_id == session:
                raise RuntimeError('expected a new session')
            print('fault:old_session_replay', file=sys.stderr, flush=True)
            send_frame(sock, old_frame, deadline=deadline_after(timeout),
                       limit=lan._FRAME_LIMIT)
            receive_envelope(sock, deadline=deadline_after(timeout), limit=lan._FRAME_LIMIT)
            raise RuntimeError('old session unexpectedly accepted')
        result = original(sock, role, sequence, operation, session, timeout, *args, **kwargs)
        if not injected and role == 'P1' and operation == 'lan_ready' and fault == 'capture_ready':
            injected = True
            accepted = WireEnvelope(
                SCHEMA_VERSION, 'request', 'Client', role, sequence,
                operation, session, None, None, None, None,
            )
            Path(capture_path).write_bytes(encode_envelope(accepted))
        if not injected and role == 'P1' and operation == 'lan_ready' and fault == 'client_ready_replay':
            injected = True
            repeated = WireEnvelope(
                SCHEMA_VERSION, 'request', 'Client', role, sequence,
                operation, session, None, None, None, None,
            )
            print('fault:client_ready_replay', file=sys.stderr, flush=True)
            send_envelope(sock, repeated, deadline=deadline_after(timeout),
                          limit=lan._FRAME_LIMIT)
        return result
    lan._request = request
else:
    raise ValueError('unknown fault')
sys.argv = ['secure-control', *command]
cli()
"""


def _free_ports() -> tuple[int, int, int]:
    return free_ports()


@pytest.fixture
def deployment(tmp_path: Path) -> dict[str, Path]:
    """每次试验使用隔离的拓扑、随机固定端口和不入库的角色私钥。"""
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tests" / "fixtures" / "prepare_local_lan_certs.py"),
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
                f"controller: {ROOT / 'tests' / 'fixtures' / 'legacy_hvac' / 'hvac_dual_loop.yaml'}\n"
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
    return run_role(role, config)


def _run_fault(
    role: str, config: Path, fault: str, capture_path: Path | None = None
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _FAULT_BOOTSTRAP,
            fault,
            str(capture_path) if capture_path is not None else "",
            role.lower(),
            "--config",
            str(config),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _short_fault_timeouts(deployment: dict[str, Path]) -> None:
    for role in NAMES:
        config = deployment[role]
        config.write_text(
            config.read_text(encoding="utf-8")
            .replace("startup: 8", "startup: 6")
            .replace("step: 15", "step: 3")
            .replace("shutdown: 3", "shutdown: 2"),
            encoding="utf-8",
        )


def _fault_trial(
    deployment: dict[str, Path],
    fault: str,
    actor: str,
    capture_path: Path | None = None,
) -> dict[str, tuple[int, dict[str, object], str]]:
    started = time.monotonic()
    _short_fault_timeouts(deployment)
    processes: dict[str, subprocess.Popen[str]] = {}
    try:
        for role in ("P1", "P2"):
            processes[role] = (
                _run_fault(role, deployment[role], fault, capture_path)
                if actor == role
                else _run(role, deployment[role])
            )
        time.sleep(0.5)
        processes["Client"] = (
            _run_fault("Client", deployment["Client"], fault, capture_path)
            if actor == "Client"
            else _run("Client", deployment["Client"])
        )
        results = {role: _finish(process, 15) for role, process in processes.items()}
        assert all(code != 0 for code, _, _ in results.values()), results
        assert all(item[1]["status"] == "failed" for item in results.values()), results
        assert "raw_control" not in results["Client"][1]
        assert time.monotonic() - started < 12, results
        assert f"fault:{fault}" in results[actor][2] or (
            fault == "offline_disconnect"
            and "fault:offline_ack_then_disconnect" in results[actor][2]
        )
        return results
    finally:
        reap_processes(processes.values())


def _finish(
    process: subprocess.Popen[str], timeout: float = 25
) -> tuple[int, dict[str, object], str]:
    try:
        output, errors = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        reap_processes([process])
        raise
    return process.returncode, json.loads(output), errors


def test_partial_role_start_failure_reaps_only_owned_process(monkeypatch):
    """第二个 Popen 抛错时，第一个已启动进程也必须被回收。"""
    from types import SimpleNamespace

    owned = SimpleNamespace(killed=False, reaped=False)
    owned.poll = lambda: None if not owned.killed else -1
    owned.kill = lambda: setattr(owned, "killed", True)
    owned.communicate = lambda **kwargs: setattr(owned, "reaped", True)
    calls = []

    def popen(command, **kwargs):
        calls.append(command)
        if len(calls) == 2:
            raise OSError("injected second role startup failure")
        return owned

    monkeypatch.setattr(subprocess, "Popen", popen)
    with pytest.raises(OSError, match="second role"):
        start_processes([["owned-P1"], ["failed-P2"], ["never-started-Client"]])
    assert calls == [["owned-P1"], ["failed-P2"]]
    assert owned.killed and owned.reaped


@pytest.mark.integration
@pytest.mark.parametrize("entry", ["python", "uv"])
def test_client_timeout_reaps_process_before_propagating_failure(tmp_path, entry):
    """Client 超时不能把仍活着的 Python 进程遗留给后续测试。"""
    marker = tmp_path / "child-pid.txt"
    script = (
        "import os, sys, time; from pathlib import Path; "
        "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)"
    )
    command = [sys.executable] if entry == "python" else ["uv", "run", "python"]
    process = start_processes([[*command, "-c", script, str(marker)]])[0]
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert marker.exists(), "sleeping child did not start"
        child_pid = int(marker.read_text())
        if sys.platform == "win32":
            import ctypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.restype = ctypes.c_void_p
            handle = kernel.OpenProcess(0x00100000, False, child_pid)  # SYNCHRONIZE
            assert handle
        else:
            handle = None
        with pytest.raises(subprocess.TimeoutExpired):
            _finish(process, .1)
        assert process.poll() is not None
        if handle is not None:
            kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
            assert kernel.WaitForSingleObject(handle, 0) == 0  # WAIT_OBJECT_0
    finally:
        reap_processes([process])
        if "handle" in locals() and handle is not None:
            # 保留句柄验证真实子进程，断言失败时也不遗留本测试的睡眠进程。
            kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
            if kernel.WaitForSingleObject(handle, 0) == 258:  # WAIT_TIMEOUT
                subprocess.run(
                    ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                    capture_output=True, timeout=5, check=True,
                )
            kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
            kernel.CloseHandle(handle)


@pytest.mark.integration
def test_three_independent_commands_complete_mtls_step(deployment: dict[str, Path]) -> None:
    """三个独立 PID 沿 Client→双方和 P2→P1 peer 通道完成双提交。"""
    p1, p2 = start_processes([
        role_command(role, deployment[role], console=True) for role in ("P1", "P2")
    ])
    try:
        time.sleep(0.5)
        client = run_role("Client", deployment["Client"], console=True)
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
        reap_processes((p1, p2))


@pytest.mark.parametrize(
    ("fault", "actor"),
    [
        ("stage_ack_loss", "P1"),
        ("commit_ack_loss", "P2"),
        ("peer_resource_replay", "P2"),
    ],
)
@pytest.mark.integration
def test_lan_mid_session_faults_fail_closed(
    deployment: dict[str, Path], fault: str, actor: str
) -> None:
    """真实三进程/mTLS 上注入中途断线、半帧、丢 ack 和已接受帧重放。"""
    results = _fault_trial(deployment, fault, actor)
    if fault in {"offline_disconnect", "stage_ack_loss", "commit_ack_loss"}:
        assert results["Client"][1]["category"] == "uncertain_or_disconnected"
    if fault in {"client_ready_replay", "peer_resource_replay"}:
        assert results["P1"][1]["category"] == "identity_or_protocol"
    if fault == "peer_half_frame":
        assert results["P1"][1]["category"] == "uncertain_or_disconnected"


@pytest.mark.integration
def test_previously_accepted_session_frame_rejected_on_new_trial(
    deployment: dict[str, Path], tmp_path: Path
) -> None:
    """先完成一个有效会话，再通过新 mTLS 会话重放其真实已接受 ready 帧。"""
    capture = tmp_path / "accepted-ready.frame"
    processes = dict(zip(("P1", "P2"), start_processes([
        role_command(role, deployment[role]) for role in ("P1", "P2")
    ]), strict=True))
    try:
        time.sleep(0.5)
        processes["Client"] = _run_fault("Client", deployment["Client"], "capture_ready", capture)
        first = {role: _finish(process, 20) for role, process in processes.items()}
        assert all(code == 0 for code, _, _ in first.values()), first
        accepted = decode_envelope(capture.read_bytes())
        assert (accepted.kind, accepted.operation, accepted.sequence) == (
            "request",
            "lan_ready",
            1,
        )
        assert accepted.session_id is not None
    finally:
        reap_processes(processes.values())
    second = _fault_trial(deployment, "old_session_replay", "Client", capture)
    assert second["P1"][1]["category"] == "identity_or_protocol"
    # 重放失败后只能从新进程、新 session 和新资源启动完整试验。
    fresh = dict(zip(("P1", "P2"), start_processes([
        role_command(role, deployment[role]) for role in ("P1", "P2")
    ]), strict=True))
    try:
        time.sleep(0.5)
        fresh["Client"] = _run("Client", deployment["Client"])
        restored = {role: _finish(process, 15) for role, process in fresh.items()}
        assert all(code == 0 for code, _, _ in restored.values()), restored
        assert restored["Client"][1]["status"] == "complete"
    finally:
        reap_processes(fresh.values())


@pytest.mark.integration
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
        reap_processes([p1])


@pytest.mark.integration
def test_untrusted_ca_rejected(deployment: dict[str, Path]) -> None:
    other = deployment["P1"].parent / "other-ca"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tests" / "fixtures" / "prepare_local_lan_certs.py"),
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
        reap_processes([p1])


@pytest.mark.integration
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


@pytest.mark.integration
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
        reap_processes([p1])


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


def test_extra_role_san_is_not_accepted() -> None:
    class FakePeer:
        def getpeercert(self) -> dict[str, tuple[tuple[str, str], ...]]:
            return {"subjectAltName": (("DNS", NAMES["P1"]), ("DNS", NAMES["P2"]))}

        def version(self) -> str:
            return "TLSv1.3"

    with pytest.raises(LanIdentityError, match="SAN"):
        _verify_identity(FakePeer(), NAMES["P1"])  # type: ignore[arg-type]


@pytest.mark.integration
def test_fixed_port_collision_fails_before_session(deployment: dict[str, Path]) -> None:
    config = load_lan_config(deployment["P1"], "P1")
    occupied = listener(config.topology.p1_client)
    try:
        with pytest.raises(LanConnectionError, match="固定监听端口"):
            listener(config.topology.p1_client)
    finally:
        occupied.close()
