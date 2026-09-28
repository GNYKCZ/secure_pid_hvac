"""v3 本机/局域网三进程固定标量门 session；复用既有 LAN socket 与配置。"""

from __future__ import annotations

import secrets
import socket
from dataclasses import dataclass

from secure_control.crypto.fixed_point import FixedPointContext
from secure_control.crypto.primes import PrimeModulusEvidence, verify_prime_modulus
from secure_control.protocol.arithmetic import (
    ScalarCertificate,
    ScalarPartyExecutor,
    ScalarPartyMaterial,
    ScalarPeerPort,
    ScalarProgram,
    prepare_scalar_round,
)

from .lan_config import LanConfig
from .lan_transport import connect_role
from .localhost_codec import (
    LanHelloPayload,
    ScalarFrameV3,
    ScalarSetupV3,
    ScalarStageV3,
    decode_scalar_frame_v3,
    encode_scalar_frame_v3,
)
from .localhost_transport import deadline_after, receive_frame, send_frame

_FRAME_LIMIT = 8 * 1024 * 1024


def _send(sock: socket.socket, frame: ScalarFrameV3, deadline: float) -> None:
    send_frame(sock, encode_scalar_frame_v3(frame), deadline=deadline, limit=_FRAME_LIMIT)


def _receive(
    sock: socket.socket, expected: ScalarFrameV3, deadline: float,
) -> ScalarFrameV3:
    actual = decode_scalar_frame_v3(receive_frame(sock, deadline=deadline, limit=_FRAME_LIMIT))
    if (
        actual.sender, actual.recipient, actual.run_id, actual.epoch_id,
        actual.session_id, actual.physical_step, actual.local_step,
        actual.round_id, actual.resource_id, actual.operation,
    ) != (
        expected.sender, expected.recipient, expected.run_id, expected.epoch_id,
        expected.session_id, expected.physical_step, expected.local_step,
        expected.round_id, expected.resource_id, expected.operation,
    ):
        raise ValueError("v3 消息身份、步号、门或方向不匹配")
    return actual


@dataclass(frozen=True, slots=True)
class ScalarStepReceipt:
    """双 party 提交后的公开资源身份与 Client 解码 raw 力。"""

    physical_step: int
    local_step: int
    round_id: str
    resource_ids: tuple[str, ...]
    output: float
    products: int
    truncations: int


@dataclass(frozen=True, slots=True)
class ScalarEndReceipt:
    """从双方独立 ended 消息核验并保留的公开 epoch 前缀。"""

    role: str
    session_id: str
    epoch_id: str
    action: str
    physical_end: int
    committed_steps: int


class _SocketScalarPeer(ScalarPeerPort):
    """每门 P1↔P2 直连，只传掩蔽值、P2 截断消息及完成屏障。"""

    def __init__(
        self, sock: socket.socket, *, party: int, run_id: str, epoch_id: str,
        session_id: str, physical_step: int, local_step: int,
        round_id: str, deadline: float,
    ) -> None:
        self.sock = sock
        self.party = party
        self.run_id = run_id
        self.epoch_id = epoch_id
        self.session_id = session_id
        self.physical_step = physical_step
        self.local_step = local_step
        self.round_id = round_id
        self.deadline = deadline

    def _frame(self, operation: str, resource: str, payload: object, *, incoming=False):
        sender = "P1" if self.party == 0 else "P2"
        recipient = "P2" if self.party == 0 else "P1"
        if incoming:
            sender, recipient = recipient, sender
        return ScalarFrameV3(
            sender, recipient, self.run_id, self.epoch_id, self.session_id,
            self.physical_step, self.local_step, self.round_id, resource,
            operation, payload,
        )

    def exchange_product(self, resource_id: str, d: int, e: int) -> tuple[int, int]:
        _send(self.sock, self._frame("peer_product", resource_id, (d, e)), self.deadline)
        result = _receive(
            self.sock, self._frame("peer_product", resource_id, None, incoming=True),
            self.deadline,
        ).payload
        if not isinstance(result, tuple) or len(result) != 2:
            raise ValueError("v3 对端乘法遮蔽值无效")
        return result

    def send_truncation(self, resource_id: str, masked: int) -> None:
        if self.party != 1:
            raise ValueError("只有 P2 可发送截断消息")
        _send(self.sock, self._frame("peer_truncation", resource_id, masked), self.deadline)

    def receive_truncation(self, resource_id: str) -> int:
        if self.party != 0:
            raise ValueError("只有 P1 可接收截断消息")
        result = _receive(
            self.sock, self._frame("peer_truncation", resource_id, None, incoming=True),
            self.deadline,
        ).payload
        if type(result) is not int:
            raise ValueError("v3 截断消息无效")
        return result

    def complete_gate(self, resource_id: str) -> None:
        _send(self.sock, self._frame("peer_complete", resource_id, None), self.deadline)
        _receive(
            self.sock, self._frame("peer_complete", resource_id, None, incoming=True),
            self.deadline,
        )


class LanScalarRuntime:
    """Client 对一个无递推状态的固定门 epoch 独占两条 party 连接。"""

    def __init__(
        self, config: LanConfig, program: ScalarProgram, certificate: ScalarCertificate,
        *, modulus: int, modulus_evidence: PrimeModulusEvidence | None,
        run_id: str, epoch_id: str, start_physical_step: int,
    ) -> None:
        if config.role != "Client" or config.experiment_config is None:
            raise ValueError("v3 标量运行须使用 Client 配置")
        if (not run_id or not epoch_id or type(start_physical_step) is not int
                or start_physical_step < 0
                or certificate.program_sha256 != program.topology_sha256()):
            raise ValueError("v3 run/epoch/程序证书身份无效")
        verify_prime_modulus(modulus, modulus_evidence)
        self.config = config
        self.program = program
        self.certificate = certificate
        self.modulus = modulus
        self.modulus_evidence = modulus_evidence
        self.run_id = run_id
        self.epoch_id = epoch_id
        self.session_id = f"scalar-{secrets.token_hex(16)}"
        self.start_physical_step = start_physical_step
        self.local_step = 0
        self._sockets: list[socket.socket] = []
        self._spent: set[str] = set()
        self._failed = False
        self._ended = False
        hello = LanHelloPayload(config.topology.digest, secrets.token_hex(32), "lan-scalar-v3")
        try:
            from .lan_runtime import _hello, _request

            for role, address in (( "P1", config.topology.p1_client),
                                  ("P2", config.topology.p2_client)):
                sock = connect_role(address, config, role, deadline_after(config.startup_timeout))
                self._sockets.append(sock)
                _hello(sock, "Client", role, self.session_id, hello, config.startup_timeout)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _request(sock, role, 1, "lan_ready", self.session_id, config.startup_timeout)
            public = ScalarSetupV3(
                program, modulus, certificate.fractional_bits,
                modulus.bit_length() - certificate.kappa - 2, modulus_evidence,
            )
            deadline = deadline_after(config.startup_timeout)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _send(sock, self._frame("Client", role, "setup", public, round_id=None), deadline)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _receive(sock, self._frame(role, "Client", "ready", None,
                                           round_id="setup"), deadline)
        except Exception:
            self._failed = True
            self.close()
            raise

    def _frame(
        self, sender: str, recipient: str, operation: str, payload: object, *,
        round_id: str | None, resource_id: str | None = None,
    ) -> ScalarFrameV3:
        return ScalarFrameV3(
            sender, recipient, self.run_id, self.epoch_id, self.session_id,
            self.start_physical_step + self.local_step, self.local_step,
            round_id, resource_id, operation, payload,
        )

    def step(self, values: dict[str, float], physical_step: int) -> ScalarStepReceipt:
        """双方 stage、重构、双提交后返回；物理推进仍由 Client 场景层负责。"""
        if self._failed or self._ended or physical_step != self.start_physical_step + self.local_step:
            raise RuntimeError("v3 session 失败、结束或物理步失序")
        round_id = f"{self.epoch_id}:{self.local_step}:{secrets.token_hex(16)}"
        try:
            materials = prepare_scalar_round(
                self.program, values, self.certificate, modulus=self.modulus,
                modulus_evidence=self.modulus_evidence, round_id=round_id,
                step=self.local_step,
            )
            ids = tuple(item.resource_id for item in materials[0].gates)
            if set(ids) & self._spent or len(set(ids)) != len(ids):
                raise ValueError("v3 一次性材料身份重用")
            # 一旦发出任何单方材料，即便断连也烧毁全部本轮身份。
            self._spent.update(ids)
            deadline = deadline_after(self.config.step_timeout)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _send(sock, self._frame("Client", role, "material", materials[party],
                                        round_id=round_id), deadline)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _receive(sock, self._frame(role, "Client", "ready", None,
                                           round_id=round_id), deadline)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _send(sock, self._frame("Client", role, "compute", None,
                                        round_id=round_id), deadline)
            results = []
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                result = _receive(
                    sock, self._frame(role, "Client", "result", None,
                                      round_id=round_id), deadline,
                ).payload
                if (not isinstance(result, ScalarStageV3)
                        or result.products != len(ids) or result.truncations != len(ids)
                        or not 0 <= result.output_share < self.modulus):
                    raise ValueError("v3 单方输出收据、资源计数或 share 无效")
                results.append(result)
            context = FixedPointContext(
                self.modulus, self.certificate.kappa, self.certificate.fractional_bits,
            )
            output = float(context.decode_residue(
                (results[0].output_share + results[1].output_share) % self.modulus,
            ))
            if abs(output) > float(self.certificate.bound(self.program.output).ideal_abs
                                   + self.certificate.bound(self.program.output).error_abs):
                raise ValueError("v3 解码力越出证书")
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _send(sock, self._frame("Client", role, "commit", None,
                                        round_id=round_id), deadline)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                committed = _receive(
                    sock, self._frame(role, "Client", "committed", None,
                                      round_id=round_id), deadline,
                ).payload
                if committed != self.local_step + 1:
                    raise ValueError("v3 双方提交前缀不一致")
            receipt = ScalarStepReceipt(
                physical_step, self.local_step, round_id, ids, output, len(ids), len(ids),
            )
            self.local_step += 1
            return receipt
        except Exception:
            self._failed = True
            self.close()
            raise

    def end(self, action: str = "stop") -> tuple[ScalarEndReceipt, ScalarEndReceipt]:
        if self._failed or self._ended or action not in {"stop", "switch"}:
            raise RuntimeError("v3 epoch 不处于可结束状态")
        deadline = deadline_after(self.config.shutdown_timeout)
        try:
            receipts = []
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                _send(sock, self._frame("Client", role, "end", action, round_id=None), deadline)
            for party, sock in enumerate(self._sockets):
                role = "P1" if party == 0 else "P2"
                count = _receive(
                    sock, self._frame(role, "Client", "ended", None, round_id=None),
                    deadline,
                ).payload
                if count != self.local_step:
                    raise ValueError("v3 双方 epoch end 前缀不一致")
                receipts.append(ScalarEndReceipt(
                    role, self.session_id, self.epoch_id, action,
                    self.start_physical_step + self.local_step, count,
                ))
            self._ended = True
            return tuple(receipts)
        except Exception:
            self._failed = True
            raise
        finally:
            self.close()

    def close(self) -> None:
        for sock in self._sockets:
            sock.close()
        self._sockets.clear()


def run_party_scalar_session(
    config: LanConfig, client_sock: socket.socket, peer_sock: socket.socket,
    *, role: str, session_id: str, expected_run_id: str | None = None,
    expected_physical_step: int | None = None, previous_epoch_id: str | None = None,
) -> dict[str, object]:
    """已完成既有 hello/peer 身份验证后执行一个 v3 固定门 epoch。"""
    party = 0 if role == "P1" else 1
    startup_deadline = deadline_after(config.startup_timeout)
    first = decode_scalar_frame_v3(
        receive_frame(client_sock, deadline=startup_deadline, limit=_FRAME_LIMIT)
    )
    if (first.operation != "setup" or first.sender != "Client"
            or first.recipient != role or first.session_id != session_id
            or first.round_id is not None or not isinstance(first.payload, ScalarSetupV3)):
        raise ValueError("v3 setup 身份或类型无效")
    if ((expected_run_id is not None and first.run_id != expected_run_id)
            or (expected_physical_step is not None
                and first.physical_step != expected_physical_step)
            or (previous_epoch_id is not None and first.epoch_id == previous_epoch_id)):
        raise ValueError("v3 rearm 不得回退物理步、换 run 或复用旧 epoch")
    setup = first.payload
    verify_prime_modulus(setup.modulus, setup.modulus_evidence)
    if (setup.fractional_bits < 1 or setup.security_parameter < 1
            or setup.modulus.bit_length() - setup.security_parameter - 2
            <= setup.fractional_bits):
        raise ValueError("v3 数值前置条件无效")
    public = setup.program
    run_id, epoch_id = first.run_id, first.epoch_id
    physical_start = first.physical_step
    _send(client_sock, ScalarFrameV3(
        role, "Client", run_id, epoch_id, session_id, physical_start, 0,
        "setup", None, "ready", None,
    ), startup_deadline)
    committed = 0
    spent: set[str] = set()
    while True:
        deadline = deadline_after(config.idle_timeout)
        request = decode_scalar_frame_v3(
            receive_frame(client_sock, deadline=deadline, limit=_FRAME_LIMIT)
        )
        if (
            request.sender != "Client" or request.recipient != role
            or (request.run_id, request.epoch_id, request.session_id)
            != (run_id, epoch_id, session_id)
            or (request.physical_step, request.local_step)
            != (physical_start + committed, committed)
        ):
            raise ValueError("v3 run/epoch/物理前缀失序")
        if request.operation == "end":
            if request.round_id is not None:
                raise ValueError("v3 end 不得带 round")
            _send(client_sock, ScalarFrameV3(
                role, "Client", run_id, epoch_id, session_id,
                physical_start + committed, committed, None, None, "ended", committed,
            ), deadline_after(config.shutdown_timeout))
            return {"role": role, "steps_committed": committed,
                    "products": len(spent), "truncations": len(spent),
                    "action": request.payload, "run_id": run_id, "epoch_id": epoch_id,
                    "physical_end": physical_start + committed,
                    "session_id": session_id}
        material = request.payload
        if (request.operation != "material" or not isinstance(material, ScalarPartyMaterial)
                or material.party != party or material.step != committed
                or material.round_id != request.round_id
                or material.program_sha256 != public.topology_sha256()):
            raise ValueError("v3 在线单方材料身份无效")
        ids = {item.resource_id for item in material.gates}
        if len(ids) != len(material.gates) or ids & spent:
            raise ValueError("v3 材料身份重复")
        spent.update(ids)
        executor = ScalarPartyExecutor(
            public, material, modulus=setup.modulus,
            fractional_bits=setup.fractional_bits,
            security_parameter=setup.security_parameter,
            modulus_evidence=setup.modulus_evidence,
        )
        round_id = request.round_id
        step_deadline = deadline_after(config.step_timeout)
        _send(client_sock, ScalarFrameV3(
            role, "Client", run_id, epoch_id, session_id,
            physical_start + committed, committed, round_id, None, "ready", None,
        ), step_deadline)
        expected = ScalarFrameV3(
            "Client", role, run_id, epoch_id, session_id,
            physical_start + committed, committed, round_id, None, "compute", None,
        )
        _receive(client_sock, expected, step_deadline)
        peer = _SocketScalarPeer(
            peer_sock, party=party, run_id=run_id, epoch_id=epoch_id,
            session_id=session_id, physical_step=physical_start + committed,
            local_step=committed, round_id=round_id, deadline=step_deadline,
        )
        share = executor.evaluate(peer)
        _send(client_sock, ScalarFrameV3(
            role, "Client", run_id, epoch_id, session_id,
            physical_start + committed, committed, round_id, None, "result",
            ScalarStageV3(share, executor.consumed, executor.consumed),
        ), step_deadline)
        _receive(client_sock, ScalarFrameV3(
            "Client", role, run_id, epoch_id, session_id,
            physical_start + committed, committed, round_id, None, "commit", None,
        ), step_deadline)
        committed += 1
        _send(client_sock, ScalarFrameV3(
            role, "Client", run_id, epoch_id, session_id,
            physical_start + committed - 1, committed - 1,
            round_id, None, "committed", committed,
        ), step_deadline)
