"""无 Supervisor 的三主机单 session 单步生命周期与公开时延测量。"""

from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import time
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from hashlib import sha256
from threading import Condition, RLock, Thread
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
    _OnlineMaterialRecovery,
    dispatch_direct_protocol3_command,
    rehydrate_offline_material,
    stage_protocol3_batch,
)
from secure_control.protocol.messages import (
    ControlShareMessage,
    InputShareMessage,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyOnlineRound,
    PreloadReceipt,
    ProductResourceMaterial,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
    TruncationResourceMaterial,
    preloaded_material_budget,
    public_step_plan_sha256,
)

from . import localhost_transport
from ._inputs import normalize_step_input
from ._localhost_peer import LocalhostProtocol3PeerPort
from ._localhost_workers import (
    _capture_stage_share,
    _ClientPartyEndpoint,
    _complete_client_round,
    _validate_party_reply,
)
from .cycle_timing import check_deadline, network_deadline
from .lan_config import LanConfig, Role
from .lan_transport import accept_role, connect_role, listener
from .localhost_codec import (
    SCHEMA_VERSION,
    BatchHelloPayload,
    LanContinuousSetupPayload,
    LanHelloPayload,
    LanSegmentedHelloPayload,
    LanSegmentedSetupV2Payload,
    LanSetupPayload,
    PartyStageResult,
    PreloadedBlock,
    PreloadedHelloPayload,
    PreloadedInitPayload,
    PreloadedInputPayload,
    PreloadedReadyPayload,
    RemoteErrorPayload,
    SegmentBeginPayload,
    SegmentEndPayload,
    SegmentEndReceipt,
    WireEnvelope,
    _decode_preloaded_values,
    encode_wire_value,
)
from .localhost_transport import deadline_after, receive_envelope, send_envelope

_FRAME_LIMIT = 8 * 1024 * 1024
_MAX_CONTINUOUS_STEPS = 1000
_LAN_LOG = logging.getLogger("secure_control.lan")


class _PreloadMaterialStore:
    """本方唯一紧凑库存；领取不可逆，当前 DTO 仍由原 recovery 恢复。"""

    def __init__(self, manifest, *, party, session, layout, modulus, run_id, epoch,
                 count, stage_mode):
        if (manifest.session_id != session or manifest.layout != layout
                or manifest.modulus != modulus or manifest.run_id != run_id
                or manifest.controller_epoch != epoch or len(manifest.round_ids) != count
                or manifest.stage_mode != stage_mode or type(party) is not int
                or party not in (0, 1)):
            raise ValueError("预送 manifest 与已认证 session/setup 不匹配")
        self.budget = preloaded_material_budget(layout, modulus, count, manifest.block_steps)
        self.manifest, self.party = manifest, party
        self.digest = manifest.sha256()
        self.data = bytearray(self.budget["cache_bytes"])
        self.loaded = self.next_slot = self.committed = 0
        self.armed = self.closed = False
        self.active = None

    def receipt(self, phase, *, first=None, count=None):
        return PreloadReceipt(self.party, self.digest, phase,
            first // self.manifest.block_steps if first is not None else None,
            first, len(self.manifest.round_ids) if count is None else count)

    def load(self, block):
        if self.closed or self.armed or not isinstance(block, PreloadedBlock):
            raise ValueError("预送库存不接受当前块")
        count = min(self.manifest.block_steps, len(self.manifest.round_ids) - self.loaded)
        expected = self.receipt("block", first=self.loaded, count=count) if count else None
        row, width = self.budget["row_bytes"], self.budget["residue_bytes"]
        if block.receipt != expected or len(block.values) != count * row:
            raise ValueError("预送块不是下一完整前缀或长度错误")
        if any(int.from_bytes(block.values[i:i + width], "big") >= self.manifest.modulus
               for i in range(0, len(block.values), width)):
            raise ValueError("预送块存在非 canonical residue")
        start = self.loaded * row
        self.data[start:start + len(block.values)] = block.values
        self.loaded += count
        return expected

    def seal(self, payload):
        if (self.closed or self.armed or self.loaded != len(self.manifest.round_ids)
                or payload != PreloadedReadyPayload(self.digest, self.loaded)):
            raise ValueError("预送窗口未完整安装或重复封存")
        self.armed = True
        return self.receipt("seal")

    def claim(self, payload):
        if (self.closed or not self.armed or self.active is not None
                or not isinstance(payload, PreloadedInputPayload)
                or payload.manifest_sha256 != self.digest
                or payload.slot_index != self.next_slot
                or self.next_slot >= len(self.manifest.round_ids)):
            raise ValueError("预送窗口未就绪、重复领取或耗尽")
        step = self.next_slot
        plan = Client._resource_plan(self.manifest.layout, self.manifest.session_id,
                                     self.manifest.round_ids[step], step)
        inp = payload.input_message
        if (inp.recipient, inp.session_id, inp.round_id, inp.step) != (
                self.party, plan.session_id, plan.round_id, step
        ) or payload.plan_sha256 != public_step_plan_sha256(plan):
            raise ValueError("预送当前输入或本机规范计划摘要不匹配")
        self.next_slot += 1
        self.active = plan
        row = self.budget["row_bytes"]
        start = step * row
        data = bytes(self.data[start:start + row])
        self.data[start:start + row] = bytes(row)
        return _decode_preloaded_values(data, inp, plan, self.manifest.modulus)

    def commit(self, plan):
        if self.closed or self.active is not plan or self.committed + 1 != self.next_slot:
            raise ValueError("预送提交不是当前已领取计划")
        self.committed += 1
        self.active = None

    def close(self):
        self.closed = True
        self.active = None
        self.data.clear()


class _OnlineResourcePool:
    """一个 session 的有界材料库存；唯一生产者不接触 socket、输入或签发表。"""

    def __init__(self, client, distribution, *, start: int, slots: int = 16):
        if type(slots) is not int or not 1 <= slots <= 16:
            raise ValueError("材料库存须为 1…16 轮。")
        self.owner = client._material_owner(distribution)
        self.slots, self.low_water = slots, min(4, slots - 1)
        self._condition = Condition()
        self._queue = deque()
        self._stop = False
        self._error = None
        self._next = start
        self.generated_ns = self.generated_cpu_ns = self.high_water = self.encoded_high_water = 0
        # 每槽预留 512 KiB，涵盖本轮两方 canonical 编码及瞬时编码副本。
        # 16 槽（含正在生产的一槽）总预留不超过 8 MiB；不是 RSS 上界。
        self._slot_limit = _FRAME_LIMIT // 16
        layout = self.owner.layout
        n, m, p = layout.state_dimension, layout.input_dimension, layout.output_dimension
        products = n * n + n * m + p * n + p * m
        truncations = n if layout.scale_ledger.state_truncation_bits else 0
        digits = self.owner.multiplier.sharing.modulus.bit_length() * 30103 // 100000 + 1
        # 在创建任何材料前以公开 shape/q 预留 canonical 上界；巨大计划不能先生成再拒绝。
        # 每资源固定余量覆盖双份 metadata/ID/JSON，变量项覆盖 canonical residue 十进制。
        pair_bound = (products * (4096 + 12 * digits)
                      + truncations * (4096 + 8 * digits) + 4096 + 512 * m)
        if 2 * pair_bound > self._slot_limit:
            raise ValueError("单轮公开材料计划超过预准备编码预算。")
        # 只编码一次公开最大值模板，不生成 triple，也不读取或绑定未来测量。
        # 本工厂的 round/resource ID 固定 ASCII 长度；同一 session 的其余字段不变。
        # canonical residue 均在 [0,q)；q-1 的十进制长度覆盖两方所有随机份额。
        from secure_control.crypto import AdditiveShare
        plan = Client._resource_plan(layout, self.owner.session_id, "round-" + "0" * 32, 0)
        q = self.owner.multiplier.sharing.modulus
        largest = AdditiveShare(q - 1)
        template = PartyOnlineMaterial(
            InputShareMessage(0, plan.session_id, plan.round_id, 0,
                              AdditiveShare(np.full(plan.input_shape, q - 1, dtype=object))),
            plan,
            tuple(ProductResourceMaterial(0, item, largest, largest, largest)
                  for item in plan.product_resources),
            tuple(TruncationResourceMaterial(0, item, largest, largest)
                  for item in plan.state_truncation_resources),
        )
        self._base_encoded_bound = 2 * len(encode_wire_value(template))
        # 每方 input/plan 各一次，资源 metadata 在 plan/material 各一次。
        self._step_occurrences = 2 * (2 + 2 * (products + truncations))
        if 2 * self._encoded_bound(start + slots - 1) > self._slot_limit:
            raise ValueError("单轮公开材料计划超过预准备编码预算。")
        try:
            for _ in range(slots):
                self._produce()
        except Exception:
            while self._queue:
                prepared, _ = self._queue.popleft()
                self.owner.discard(prepared)
            raise
        self._thread = Thread(target=self._run, name="online-material-producer")
        self._thread.start()

    def _produce(self):
        started, cpu = time.perf_counter_ns(), time.thread_time_ns()
        encoded_bound = self._encoded_bound(self._next)
        if 2 * encoded_bound > self._slot_limit:
            raise ValueError("单轮预准备材料超出有界编码预留。")
        prepared = self.owner.create(self._next)
        try:
            with self._condition:
                if self._stop:
                    self.owner.discard(prepared)
                    return
                self._queue.append((prepared, encoded_bound))
                self._next += 1
                self.generated_ns += time.perf_counter_ns() - started
                self.generated_cpu_ns += time.thread_time_ns() - cpu
                self.high_water = max(self.high_water, len(self._queue))
                self.encoded_high_water = max(self.encoded_high_water,
                                              sum(size for _, size in self._queue))
        except Exception:
            self.owner.discard(prepared)
            raise

    def _encoded_bound(self, step):
        """同一公开模板仅修正 step 十进制位宽；不是实际已发送字节数。"""
        return self._base_encoded_bound + self._step_occurrences * (len(str(step)) - 1)

    def _run(self):
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: self._stop or len(self._queue) <= self.low_water)
                    if self._stop:
                        return
                while True:
                    with self._condition:
                        if self._stop or len(self._queue) >= self.slots:
                            break
                    self._produce()
        except Exception as error:  # noqa: BLE001 - 主线程只公开类别，不能透传材料载荷
            with self._condition:
                self._error = type(error).__name__

    def take(self, step):
        """只领取本步，不等待补货，不在短缺时现场生成或改 deadline。"""
        with self._condition:
            if self._error is not None or not self._queue:
                raise RuntimeError("预准备材料供给失败或库存短缺。")
            prepared, _ = self._queue.popleft()
            if prepared.p1_resources.plan.step != step:
                self.owner.discard(prepared)
                raise ValueError("预准备材料步号不匹配。")
            self._condition.notify()
            return prepared

    def snapshot(self):
        """仅公开库存及生产成本，不暴露份额或 RNG。"""
        with self._condition:
            return {"material_slots": len(self._queue), "material_high_water": self.high_water,
                    "material_encoded_bound_high_water": self.encoded_high_water,
                    "material_reserved_bytes": self.slots * self._slot_limit,
                    "material_prepare_ns": self.generated_ns,
                    "material_cpu_ns": self.generated_cpu_ns}

    def close(self):
        """停止唯一生产者并废弃所有未使用能力，不能跨 run 复用。"""
        with self._condition:
            self._stop = True
            self._condition.notify_all()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("材料生产者尚未退出。")
        with self._condition:
            while self._queue:
                prepared, _ = self._queue.popleft()
                self.owner.discard(prepared)


def _public_reachability_digest(contract: ControllerRangeContract,
                                verification: object) -> str:
    """仅摘要公开范围契约与 Client 重算结果，不对秘密参数做承诺。"""
    public = {"contract": asdict(contract), "verification": asdict(verification)}
    encoded = json.dumps(public, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    return sha256(b"lan-segmented-v2-public-range\0" + encoded).hexdigest()


def run_client_single_step(config: LanConfig, trial: Any, *, batch: bool = True) -> dict[str, object]:
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
    base_hello = LanHelloPayload(config.topology.digest, secrets.token_hex(32))
    hello = BatchHelloPayload(base_hello) if batch else base_hello
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
        materials = tuple(PartyOnlineMaterial.from_round(PartyOnlineRound(
            current.p1_input if party == 0 else current.p2_input,
            current.p1_resources if party == 0 else current.p2_resources,
        )) for party in (0, 1))
        prepared_requests = _prepare_online_requests(materials, session, plan.round_id, 0, (4, 4))
        pending = []
        for party, sock in enumerate(sockets):
            request, encoded = prepared_requests[party]
            localhost_transport.send_frame(sock, encoded, deadline=step_deadline, limit=_FRAME_LIMIT)
            pending.append(request)
            endpoints.append(
                _ClientPartyEndpoint(
                    sock, party, plan, 5, _FRAME_LIMIT, config.step_timeout, step_deadline
                )
            )
        for sock, request in zip(sockets, pending, strict=True):
            _receive_reply(sock, request, deadline=step_deadline)
        stamps["distributed"] = time.perf_counter_ns()
        result = _complete_client_round(
            client,
            endpoints[0],
            endpoints[1],
            plan,
            lambda phase: stamps.__setitem__(phase, time.perf_counter_ns()),
            batch=batch,
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
        _segment_capacity: int | None = None,
        _controller_epoch: str | None = None,
        batch: bool = True,
        preload_steps: int = 0, preload_execution: str = "fused",
    ) -> None:
        if config.role != "Client" or config.experiment_config is None:
            raise ValueError("连续运行必须使用 Client experiment 配置。")
        v2 = _segment_hello is not None and _segment_hello.mode in {
            "lan-segmented-v2", "lan-full-v3",
        }
        if v2:
            if (range_contract.reachability_block_steps is None
                    or range_contract.horizon_steps is not None
                    or type(_segment_capacity) is not int
                    or not 1 <= _segment_capacity <= _MAX_CONTINUOUS_STEPS
                    or _controller_epoch is None):
                raise ValueError("v2 持续 session 缺少范围证明、段容量或 controller epoch")
        elif (range_contract.horizon_steps is None
              or not 1 <= range_contract.horizon_steps <= _MAX_CONTINUOUS_STEPS):
            raise ValueError("LAN 连续会话步数超出有界范围。")
        if (type(preload_steps) is not int or not 0 <= preload_steps <= 1000
                or preload_execution not in {"staged", "fused"}
                or (preload_steps and (not batch or _segment_hello is None
                    or _segment_hello.mode != "lan-segmented-v2"))):
            raise ValueError("预送仅允许显式动态v2有限窗口与staged/fused模式")
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
        if preload_steps:
            preloaded_material_budget(self.distribution.p1.layout, fixed_point.modulus, preload_steps)
        self.scale_ledger = self.distribution.p1.layout.scale_ledger
        self.range_verification = self.client.range_verification
        self.modulus_verification = self.client.truncation.modulus_verification
        self.config = config
        self._sockets: list[socket.socket] = []
        self._sequences = [4, 4]
        self._step = 0
        self._segment_start = 0
        self._segment_capacity = _segment_capacity if v2 else range_contract.horizon_steps
        self._v2 = v2
        self._batch = batch
        self._products = 0
        self._truncations = 0
        self._confirmed_steps: list[dict[str, int | str]] = []
        self._confirmed_plans: list[dict[str, object]] = []
        self._failed = False
        self._finished = False
        self.session_id = self.distribution.session_id
        base_hello = (_segment_hello if _segment_hello is not None else
                      LanHelloPayload(config.topology.digest, secrets.token_hex(32),
                                      "lan-continuous-v1"))
        hello = BatchHelloPayload(base_hello) if batch else base_hello
        if preload_steps:
            hello = PreloadedHelloPayload(hello, preload_steps, preload_execution)
        self._preload_steps, self._preload_execution = preload_steps, preload_execution
        self._preloaded = None
        self._preload_digest = None
        self._preload_statistics = {}
        self.setup_run_id = base_hello.run_id if preload_steps else None
        self._last_result = None
        self._round_started = False
        self._material_pool = None
        self._last_phase_ns = {}
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
            if v2:
                setup = LanSegmentedSetupV2Payload(
                    fixed_point.modulus, fixed_point.integer_bits, fixed_point.fractional_bits,
                    security_parameter, range_contract.state_payload_bounds,
                    range_contract.input_payload_bounds, range_contract.reachability_block_steps,
                    _segment_capacity, _controller_epoch,
                    _public_reachability_digest(range_contract, self.range_verification),
                    modulus_evidence,
                )
            else:
                setup = LanContinuousSetupPayload(
                    fixed_point.modulus, fixed_point.integer_bits, fixed_point.fractional_bits,
                    security_parameter, range_contract.state_payload_bounds,
                    range_contract.input_payload_bounds, range_contract.horizon_steps,
                    modulus_evidence,
                )
            self.setup = setup
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

    def enable_material_preload(self, *, cancelled=None):
        """同一总启动deadline，双信封先编码后发送；每轮导出立即释放原材料。"""
        if not self._preload_steps or self._preloaded is not None or self._material_pool is not None or self._step:
            raise RuntimeError("预送必须在指定窗口的初始准备期执行一次")
        started = time.perf_counter_ns()
        deadline = deadline_after(self.config.startup_timeout)
        batch = self.client.begin_preloaded_resources(self.distribution,
            run_id=self.setup_run_id, controller_epoch=self.setup.controller_epoch,
            count=self._preload_steps, stage_mode=self._preload_execution)
        self._preloaded = batch
        manifest = batch.manifest
        self._preload_digest = manifest.sha256()
        budget = preloaded_material_budget(manifest.layout, manifest.modulus,
                                          self._preload_steps, manifest.block_steps)
        encoded_bytes = 0

        def check():
            if time.monotonic() >= deadline or (cancelled is not None and cancelled()):
                raise RuntimeError("预送启动超时或已取消")

        def exchange(operation, payloads, receipts, *, step=None, limit=64 * 1024):
            nonlocal encoded_bytes
            check()
            prepared = _prepare_requests(payloads, operation, self.session_id, None, step,
                                         self._sequences, limit)
            for sock, (request, encoded) in zip(self._sockets, prepared, strict=True):
                localhost_transport.send_frame(sock, encoded, deadline=deadline, limit=limit)
                encoded_bytes += len(encoded) + 4
            got = tuple(_receive_reply(sock, request, deadline=deadline, expected_payload=receipt,
                                       limit=64 * 1024)
                        for sock, (request, _), receipt in zip(self._sockets, prepared, receipts, strict=True))
            self.client.record_preloaded_receipts(self.distribution, batch, got)
            self._sequences = [v + 1 for v in self._sequences]

        def receipts(phase, first=None, count=None):
            return tuple(PreloadReceipt(party, self._preload_digest, phase,
                first // manifest.block_steps if first is not None else None, first,
                self._preload_steps if count is None else count) for party in (0, 1))

        try:
            init = PreloadedInitPayload(manifest, self._preload_digest)
            exchange("preload_init", (init, init), receipts("init"))
            width = budget["residue_bytes"]
            for first in range(0, self._preload_steps, manifest.block_steps):
                buffers = (bytearray(), bytearray())
                count = min(manifest.block_steps, self._preload_steps - first)
                for step in range(first, first + count):
                    check()
                    exported = self.client.export_preloaded_step(self.distribution, batch, step=step)
                    for buffer, values in zip(buffers, (exported.p1_values, exported.p2_values), strict=True):
                        for value in values:
                            buffer.extend(value.to_bytes(width, "big"))
                    del exported
                expected = receipts("block", first, count)
                payloads = tuple(PreloadedBlock(receipt, bytes(buffer))
                                 for receipt, buffer in zip(expected, buffers, strict=True))
                del buffers
                exchange("preload_block", payloads, expected, step=first, limit=256 * 1024)
                del payloads
            ready = PreloadedReadyPayload(self._preload_digest, self._preload_steps)
            exchange("preload_seal", (ready, ready), receipts("seal"))
            self._preload_statistics = {"material_mode": "control-preloaded-v1",
                "preload_steps": self._preload_steps, "preload_execution": self._preload_execution,
                "startup_duration_ns": time.perf_counter_ns() - started,
                "startup_client_sent_bytes": encoded_bytes, "raw_bytes_per_party": budget["cache_bytes"],
                "budget": budget, "capacity": self._preload_steps, "producer_present": False}
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

    @property
    def confirmed_plans(self) -> tuple[dict[str, object], ...]:
        """只公开已双提交轮次的身份与资源索引，不暴露随机材料。"""
        return tuple(dict(item) for item in self._confirmed_plans)

    def step(self, v: Any, *, deadline_ns: int | None = None) -> np.ndarray:
        """同一 session 逐轮推进；任何未确认回执使整个运行时失效。"""
        if (self._failed or self._finished
                or (not self._v2 and self._step >= self.range_contract.horizon_steps)
                or (self._v2 and self._step - self._segment_start >= self._segment_capacity)):
            raise RuntimeError("LAN session 已失败、结束或超出配置步数。")
        self._round_started = False
        current = None
        prepared = None
        endpoints = []
        self._last_phase_ns = {}
        try:
            deadline = (network_deadline(self.config.step_timeout, deadline_ns)
                        if deadline_ns is not None else None)
            started = time.perf_counter_ns()
            check_deadline(deadline_ns, "MATERIAL_BIND")
            value = normalize_step_input(v, self.spec.input_dimension)
            if self._preload_steps:
                if self._preloaded is None:
                    raise RuntimeError("显式预送窗口尚未安装")
                current = self.client.bind_preloaded_input(self.distribution, self._preloaded,
                                                          value, step=self._step)
            elif self._material_pool is None:
                current = self.client.prepare_online(self.distribution, value, step=self._step)
            else:
                prepared = self._material_pool.take(self._step)
                current = self.client.bind_online_input(self.distribution, prepared, value,
                                                        step=self._step)
            self._last_phase_ns["material_bind"] = time.perf_counter_ns() - started
            check_deadline(deadline_ns, "MATERIAL_BIND")
            plan = current.plan if self._preload_steps else current.p1_resources.plan
            if not self._preload_steps and current.p2_resources.plan != plan:
                raise ValueError("两方在线资源计划不一致。")
            self._last_plan = plan
            if deadline is None:
                # 旧有限/非实时调用保留原先从 online 分发开始计算保护 timeout 的语义。
                deadline = deadline_after(self.config.step_timeout)
            online_started = time.perf_counter_ns()
            endpoints: list[_ClientPartyEndpoint] = []
            fused = self._preload_steps and self._preload_execution == "fused"
            if self._preload_steps:
                digest = public_step_plan_sha256(plan)
                materials = tuple(PreloadedInputPayload(self._preload_digest, inp,
                    self._step, digest) for inp in (current.p1_input, current.p2_input))
                prepared_requests = _prepare_requests(materials,
                    "activate_stage" if fused else "activate", self.session_id,
                    plan.round_id, self._step, self._sequences, _FRAME_LIMIT)
            else:
                materials = tuple(PartyOnlineMaterial.from_round(PartyOnlineRound(
                    current.p1_input if party == 0 else current.p2_input,
                    current.p1_resources if party == 0 else current.p2_resources,
                )) for party in (0, 1))
                prepared_requests = _prepare_online_requests(
                    materials, self.session_id, plan.round_id, self._step, self._sequences,
                )
            check_deadline(deadline_ns, "ENCODING")
            pending = []
            for party, sock in enumerate(self._sockets):
                request, encoded = prepared_requests[party]
                if not fused:
                    self._round_started = True
                    localhost_transport.send_frame(sock, encoded, deadline=deadline, limit=_FRAME_LIMIT)
                    pending.append(request)
                endpoints.append(_ClientPartyEndpoint(
                    sock, party, plan, self._sequences[party] + (0 if fused else 1), _FRAME_LIMIT,
                    self.config.step_timeout, deadline,
                    activation=(request, encoded) if fused else None,
                    on_send=lambda: setattr(self, "_round_started", True),
                ))
            if not fused:
                for sock, request in zip(self._sockets, pending, strict=True):
                    _receive_reply(sock, request, deadline=deadline)
            self._last_phase_ns["online_distribution"] = time.perf_counter_ns() - online_started
            check_deadline(deadline_ns, "ONLINE_DISTRIBUTION")
            stamps = {"start": time.perf_counter_ns()}
            def record_phase(name):
                stamps[name] = time.perf_counter_ns()
                previous = {"stage": "start", "reconstruct": "stage", "commit": "reconstruct"}[name]
                if previous in stamps:
                    self._last_phase_ns[name] = stamps[name] - stamps[previous]
                # commit 回调在双方 ACK 后：先登记已双提交事实，再由 runner 拒绝迟到施力。
                if name != "commit":
                    check_deadline(deadline_ns, name.upper())
            result = _complete_client_round(
                self.client, endpoints[0], endpoints[1], plan, batch=self._batch,
                on_phase=record_phase,
            )
            if self._preload_steps:
                self.client.retire_preloaded_round(current, success=True)
                current = None
            for name, begin in (("stage", "start"), ("reconstruct", "stage"),
                                ("commit", "reconstruct")):
                if name in stamps and begin in stamps:
                    self._last_phase_ns[name] = stamps[name] - stamps[begin]
            for party, endpoint in enumerate(endpoints):
                if hasattr(endpoint, "commit_duration_ns"):
                    self._last_phase_ns[f"p{party + 1}_commit"] = endpoint.commit_duration_ns
            self._sequences = [endpoint.sequence for endpoint in endpoints]
            self._step += 1
            self._products += result.products
            self._truncations += result.truncations
            self._confirmed_steps.append({
                "step": plan.step, "status": "double_committed",
                "products": result.products, "truncations": result.truncations,
            })
            self._confirmed_plans.append({
                "step": plan.step, "round_id": plan.round_id,
                "product_resource_ids": [item.resource_id for item in plan.product_resources],
                "truncation_resource_ids": [item.resource_id
                                            for item in plan.state_truncation_resources],
            })
            self._last_result = result
            return np.array(result.output, dtype=float, copy=True)
        except Exception:
            for party, endpoint in enumerate(endpoints):
                if hasattr(endpoint, "commit_duration_ns"):
                    self._last_phase_ns[f"p{party + 1}_commit"] = endpoint.commit_duration_ns
            if current is not None:
                identity = (current.session_id, current.round_id, current.step)
                if self._preload_steps:
                    self.client.retire_preloaded_round(current, success=False)
                elif identity in self.client._issued_rounds:
                    self.client.abort_round(current)
            if prepared is not None:
                self._material_pool.owner.discard(prepared)
            self._failed = True
            self.close()
            raise

    def begin_segment(self, begin: SegmentBeginPayload, *, deadline_ns: int | None = None) -> None:
        """v2 保留同一 controller/session 与全局 step，只确认新的逻辑段。"""
        if (not self._v2 or self._failed or self._finished
                or begin.global_start != self._step):
            raise RuntimeError("v2 段开始身份或状态无效")
        try:
            deadline = network_deadline(self.config.shutdown_timeout, deadline_ns)
            pending = []
            for party, sock in enumerate(self._sockets):
                pending.append(_request(sock, "P1" if party == 0 else "P2", self._sequences[party],
                         "segment_begin", self.session_id, self.config.shutdown_timeout,
                         begin, deadline=deadline, send_only=True))
            for party, (sock, request) in enumerate(zip(self._sockets, pending, strict=True)):
                _receive_reply(sock, request, deadline=deadline, expected_payload=begin)
                self._sequences[party] += 1
            self._segment_start = self._step
            self._confirmed_steps.clear()
            self._confirmed_plans.clear()
            check_deadline(deadline_ns, "SEGMENT_BEGIN")
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
        if self._preloaded is not None:
            self.client.discard_preloaded_resources(self.distribution, self._preloaded)
        if self._material_pool is not None:
            pool, self._material_pool = self._material_pool, None
            self._material_statistics = pool.snapshot()
            pool.close()


class RunControl:
    """线程安全、幂等的正常停止请求；发起门禁与请求共享锁，不关闭网络。"""

    def __init__(self) -> None:
        self._lock = RLock()
        self._stop = False
        self._on_stop: Callable[[], None] | None = None

    def request_stop(self) -> None:
        """停止先取得门禁则不再发起下一轮；已发起轮继续双提交及物理推进。"""
        with self._lock:
            # 在场景回调前发布停止位，重复 SIGINT/回调重入只读取意图，不能再调回场景。
            if self._stop:
                return
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
    setup: LanContinuousSetupPayload | LanSegmentedSetupV2Payload
    connection_seconds: float
    scale_ledger: object
    range_verification: object
    modulus_verification: object


@dataclass(frozen=True, slots=True)
class LanLifecycleSnapshot:
    """仅含公开身份、提交与物理确认计数的持续会话快照。"""

    phase: str
    run_id: str
    session_id: str | None
    controller_epoch: str | None
    segment_index: int
    global_start: int
    attempted_round: int | None
    attempted_round_id: str | None
    protocol_committed_count: int
    physically_confirmed_count: int
    products_consumed: int
    truncations_consumed: int
    last_closed_segment_count: int


class LanSegmentedRuntime:
    """持续协调器；v2 的秘密状态留在同一协议 session 与双方 role。"""

    def __init__(self, config: LanConfig, spec: ControllerSpec,
                 fixed_point: FixedPointContext, range_contract: ControllerRangeContract,
                 security_parameter: int, modulus_evidence: PrimeModulusEvidence | None,
                 *, control: RunControl, segment_capacity: int | None = None,
                 full_run_id: str | None = None,
                 previous_epoch_session: str | None = None,
                 preload_steps: int = 0, preload_execution: str = "fused") -> None:
        self._v2 = spec.state_dimension != 0
        self._full_v3 = full_run_id is not None
        if (type(preload_steps) is not int or not 0 <= preload_steps <= 1000
                or preload_execution not in {"staged", "fused"}
                or (preload_steps and (not self._v2 or self._full_v3))):
            raise ValueError("预送仅用于动态v2有限窗口")
        self.preload_steps, self.preload_execution = preload_steps, preload_execution
        if self._full_v3 and (
            not self._v2 or not previous_epoch_session or not full_run_id
        ):
            raise ValueError("v3 动态 epoch 需要原物理 run 与上一安全 session")
        if not self._full_v3 and previous_epoch_session is not None:
            raise ValueError("旧持续模式不得引用 v3 epoch session")
        if self._v2 and segment_capacity is None:
            raise ValueError("非零秘密状态持续模式必须显式声明 segment_capacity")
        capacity = segment_capacity if self._v2 else range_contract.horizon_steps
        if (type(capacity) is not int
                or not 1 <= capacity <= _MAX_CONTINUOUS_STEPS):
            raise ValueError("segment_steps 必须是 1…1000 的整数。")
        if self._v2 and (range_contract.reachability_block_steps is None
                         or range_contract.horizon_steps is not None):
            raise ValueError("非零秘密状态持续模式要求已证明的无界可达契约")
        if not self._v2 and segment_capacity is not None:
            raise ValueError("静态 v1 由原有限契约给出段容量")
        self.config, self.spec, self.fixed_point = config, spec, fixed_point
        self.contract, self.security_parameter = range_contract, security_parameter
        self.segment_capacity = capacity
        self.evidence, self.control = modulus_evidence, control
        self.run_id = full_run_id if self._full_v3 else secrets.token_hex(32)
        self.controller_epoch = secrets.token_hex(32) if self._v2 else None
        self.segment_index = self.global_start = self.confirmed_step_count = 0
        self._previous_session = previous_epoch_session
        self._segment: LanContinuousRuntime | None = None
        self._pending: SegmentedStep | None = None
        self._records: list[SegmentedStep] = []
        self._products = self._truncations = 0
        self._last_end_round_id: str | None = None
        self._last_closed_segment_count = 0
        self._attempted_round: int | None = None
        self.phase = "CONNECTING"
        self._connect()

    def _connect(self) -> None:
        self.phase = "CONNECTING" if self.segment_index == 0 else "CONNECTING_NEXT"
        self.hello = LanSegmentedHelloPayload(
            self.config.topology.digest, secrets.token_hex(32), self.run_id,
            self.segment_index, self.global_start, self._previous_session,
            "lan-full-v3" if self._full_v3 else
            "lan-segmented-v2" if self._v2 else "lan-segmented-v1",
        )
        started = time.monotonic()
        self._segment = LanContinuousRuntime(
            self.config, self.spec, self.fixed_point, self.contract,
            self.security_parameter, self.evidence, _segment_hello=self.hello,
            _segment_capacity=self.segment_capacity if self._v2 else None,
            _controller_epoch=self.controller_epoch,
            preload_steps=self.preload_steps, preload_execution=self.preload_execution,
        )
        self.connection_seconds = time.monotonic() - started
        self.phase = "RUNNING"

    @property
    def protocol_committed_count(self) -> int:
        if self._segment is None:
            return self.global_start
        return self._segment._step if self._v2 else self.global_start + self._segment._step

    @property
    def resource_counts(self) -> dict[str, int]:
        return {"products_consumed": self._products, "truncations_consumed": self._truncations}

    def snapshot(self) -> LanLifecycleSnapshot:
        """错误出口可读取的不可变公开进度，不穿透 protocol 对象。"""
        segment = self._segment
        round_id = (segment._last_plan.round_id
                    if segment is not None and self._attempted_round is not None
                    and hasattr(segment, "_last_plan")
                    and segment._last_plan.step == self._attempted_round else None)
        return LanLifecycleSnapshot(
            self.phase, self.run_id, segment.session_id if segment else None,
            self.controller_epoch, self.segment_index, self.global_start,
            self._attempted_round, round_id,
            self.protocol_committed_count, self.confirmed_step_count,
            self._products, self._truncations, self._last_closed_segment_count,
        )

    @property
    def public_setup(self) -> LanContinuousSetupPayload | LanSegmentedSetupV2Payload:
        """Frozen public setup for an evidence sink before the first round starts."""
        if self._segment is None:
            raise RuntimeError("协议尚未建立。")
        return self._segment.setup

    @property
    def segment_full(self) -> bool:
        return self.confirmed_step_count - self.global_start == self.segment_capacity

    def enable_material_preparation(self, *, slots: int = 16) -> None:
        """只在动态初始准备期填充库存；计时开始后禁止重新填充初始池。"""
        if (self.preload_steps or not self._v2 or self.confirmed_step_count
                or self.phase != "RUNNING"):
            raise RuntimeError("材料池仅用于动态 session 的初始准备。")
        segment = self._segment
        if segment is None or segment._material_pool is not None:
            raise RuntimeError("材料池不存在或已经安装。")
        segment._material_pool = _OnlineResourcePool(segment.client, segment.distribution,
                                                   start=segment._step, slots=slots)

    def enable_material_preload(self, *, cancelled=None):
        if self.phase != "RUNNING" or self.confirmed_step_count or self._segment is None:
            raise RuntimeError("预送只可在初始准备期安装")
        self._segment.enable_material_preload(cancelled=cancelled)

    @property
    def cycle_phase_ns(self):
        """当前轮的 Client 本机阶段时长；不跨主机相减。"""
        return dict(self._segment._last_phase_ns) if self._segment is not None else {}

    @property
    def cycle_queue_levels(self):
        """当前 session 的有界库存与生产成本，也保留停止时的末次摘要。"""
        if self._segment is None:
            return {}
        if self.preload_steps:
            return {"capacity": self.preload_steps,
                    "level": max(0, self.preload_steps - self._segment._step)}
        pool = self._segment._material_pool
        return pool.snapshot() if pool is not None else getattr(self._segment, "_material_statistics", {})

    @property
    def material_summary(self):
        if self.preload_steps and self._segment is not None:
            return {**self._segment._preload_statistics, **self.cycle_queue_levels}
        return self.cycle_queue_levels

    def step(self, v: Any, *, deadline_ns: int | None = None) -> SegmentedStep | None:
        """轮发起门禁成功后只完成该轮；停止请求不会中断 commit I/O。"""
        if self.phase != "RUNNING" or self._pending is not None or self.segment_full:
            raise RuntimeError("当前状态不能发起下一轮。")
        with self.control._lock:
            if self.control._stop:
                return None
            self.phase = "ROUND_IN_FLIGHT"
            self._attempted_round = self.confirmed_step_count
        assert self._segment is not None
        try:
            raw = (self._segment.step(v) if deadline_ns is None
                   else self._segment.step(v, deadline_ns=deadline_ns))
            result = self._segment._last_result
            # 资源身份由 Client 的原计划产生；不另造身份或重新生成材料。
            plan = self._segment._last_plan
            self._pending = SegmentedStep(
                self.run_id, self.segment_index, self._segment.session_id,
                result.round_id, self.confirmed_step_count - self.global_start,
                self.confirmed_step_count,
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
        self._attempted_round = None
        self.phase = "RUNNING"

    def end_segment(self, *, switch_epoch: bool = False,
                    deadline_ns: int | None = None) -> SegmentRecord:
        """向双方先发送同一个 action，再于共享 deadline 验证独立计数回执。"""
        if self.phase != "RUNNING" or self._pending is not None:
            raise RuntimeError("未确认物理推进或失败状态不得正常结束。")
        assert self._segment is not None
        segment = self._segment
        with self.control._lock:
            if switch_epoch and not self._full_v3:
                raise ValueError("只有 v3 动态 epoch 可以显式切换")
            action = "switch" if switch_epoch else "stop" if self.control._stop else "continue"
            if action == "continue" and not self.segment_full:
                raise RuntimeError("只有满段才能继续。")
            self.phase = "STOPPING" if action == "stop" else "ENDING_SEGMENT"
        end = SegmentEndPayload(
            self.run_id, self.segment_index, self.global_start, len(self._records),
            self.confirmed_step_count,
            self._records[-1].round_id if self._records else None, action,
        )
        deadline = network_deadline(self.config.shutdown_timeout, deadline_ns)
        requests = []
        completed = False
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
                segment._sequences[0 if request.recipient == "P1" else 1] += 1
            setup = segment.setup
            record = SegmentRecord(
                self.hello, segment.session_id, tuple(self._records), tuple(receipts), setup,
                self.connection_seconds, segment.scale_ledger, segment.range_verification,
                segment.modulus_verification,
            )
            self._records.clear()
            self._last_end_round_id = end.last_round_id
            self._last_closed_segment_count = self.confirmed_step_count
            self.phase = ("SWITCHED" if action == "switch" else
                          "STOPPED" if action == "stop" else "CONNECTING_NEXT")
            check_deadline(deadline_ns, "SEGMENT_END")
            completed = True
            return record
        except Exception:
            self.phase = "UNCERTAIN"
            raise
        finally:
            if not self._v2 or action in {"stop", "switch"} or not completed:
                segment.close()

    def next_segment(self, *, deadline_ns: int | None = None) -> None:
        """只有双方 continue 已确认才能计划重连；停止位贯穿新握手。"""
        if self.phase != "CONNECTING_NEXT":
            raise RuntimeError("段过渡未确认，禁止重连。")
        assert self._segment is not None
        if self._v2:
            self.global_start = self.confirmed_step_count
            self.segment_index += 1
            begin = SegmentBeginPayload(
                self.run_id, self.segment_index, self.global_start,
                self.controller_epoch, self._last_end_round_id,
            )
            try:
                if deadline_ns is None:
                    self._segment.begin_segment(begin)
                else:
                    self._segment.begin_segment(begin, deadline_ns=deadline_ns)
                self.hello = LanSegmentedHelloPayload(
                    self.hello.profile_sha256, self.hello.nonce, self.run_id,
                    self.segment_index, self.global_start, self._segment.session_id,
                    "lan-full-v3" if self._full_v3 else "lan-segmented-v2",
                )
                self.phase = "RUNNING"
            except Exception:
                self.phase = "UNCERTAIN"
                self.close()
                raise
            return
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
        if self.phase not in {"STOPPED", "SWITCHED", "FAILED", "UNCERTAIN", "CANCELLED"}:
            self.phase = "FAILED"
        if self._segment is not None:
            self._segment.close()


def run_party_single_step(config: LanConfig, *, batch: bool = True) -> dict[str, object]:
    """P1/P2 默认只接受批量能力；旧 wire 须由双方显式选择诊断模式。"""
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
            summary, tail = _run_party_session(
                config, client_listener, peer_listener, tail, expected_batch=batch,
            )
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


@dataclass(frozen=True, slots=True)
class _ScalarRunTail:
    """v3 安全结束屏障后的物理前缀；下一 epoch 必须显式 rearm。"""

    run_id: str
    physical_end: int
    session_id: str
    epoch_id: str


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
                       tail: _PartyRunTail | _ScalarRunTail | None, *, expected_batch: bool
                       ) -> tuple[dict[str, object], _PartyRunTail | _ScalarRunTail | None]:
    """旧模式与新模式共享唯一的握手、离线装配和 Protocol 3 单段计算。"""
    role = config.role
    party = 0 if role == "P1" else 1
    client_socket = peer_socket = peer_port = None
    preload_store = None
    endpoint = None
    try:
        startup_deadline = deadline_after(config.startup_timeout)
        _LAN_LOG.info("%s 已启动，正在等待 Client（最多 %.0f 秒）。", role,
                      config.startup_timeout)
        client_socket = accept_role(client_listener, config, "Client", startup_deadline)
        session, wire_hello = _accept_hello(
            client_socket,
            "Client",
            role,
            config,
            startup_deadline,
        )
        preload_hello = wire_hello if isinstance(wire_hello, PreloadedHelloPayload) else None
        inner_hello = preload_hello.base if preload_hello is not None else wire_hello
        batch = isinstance(inner_hello, BatchHelloPayload)
        if batch != expected_batch:
            raise ValueError("LAN Client 与 Party 批量能力不一致；旧协议须双方显式诊断启用")
        hello = inner_hello.base if batch else inner_hello
        if isinstance(hello, LanSegmentedHelloPayload):
            if isinstance(tail, _ScalarRunTail):
                if (
                    hello.mode != "lan-full-v3"
                    or hello.run_id != tail.run_id
                    or hello.segment_index != 0 or hello.global_start != 0
                    or hello.previous_session_id != tail.session_id
                    or session == tail.session_id
                ):
                    raise RuntimeError("v3 动态捕获没有绑定已结束的安全 epoch")
            else:
                if hello.mode == "lan-full-v3":
                    raise RuntimeError("v3 动态捕获缺少上一 epoch 的结束屏障")
                _validate_segment_chain(hello, session, tail)
        elif tail is not None and not (
            isinstance(tail, _ScalarRunTail)
            and isinstance(hello, LanHelloPayload) and hello.mode == "lan-scalar-v3"
            and session != tail.session_id
        ):
            raise ValueError("持续 run 不允许切回旧模式。")
        _LAN_LOG.info("%s 与 Client 的协议连接已建立。", role)
        if party == 0:
            assert peer_listener is not None
            peer_socket = accept_role(peer_listener, config, "P2", startup_deadline)
            _accept_hello(
                peer_socket, "P2", "P1", config, startup_deadline,
                expected=(session, wire_hello)
            )
            _LAN_LOG.info("P1 与 P2 的协议连接已建立。")
        else:
            peer_socket = connect_role(config.topology.p1_peer, config, "P1", startup_deadline)
            _hello(peer_socket, "P2", "P1", session, wire_hello, config.startup_timeout)
            _LAN_LOG.info("P2 与 P1 的协议连接已建立。")
        _party_reply(
            client_socket,
            _party_receive(client_socket, role, 1, "lan_ready", session, config.startup_timeout),
            None,
            config.startup_timeout,
        )
        if isinstance(hello, LanHelloPayload) and hello.mode == "lan-scalar-v3":
            from .lan_scalar_runtime import run_party_scalar_session

            summary = run_party_scalar_session(
                config, client_socket, peer_socket, role=role, session_id=session,
                expected_run_id=tail.run_id if isinstance(tail, _ScalarRunTail) else None,
                expected_physical_step=(
                    tail.physical_end if isinstance(tail, _ScalarRunTail) else None
                ),
                previous_epoch_id=tail.epoch_id if isinstance(tail, _ScalarRunTail) else None,
                batch=batch,
            )
            next_tail = (
                _ScalarRunTail(
                    summary["run_id"], summary["physical_end"],
                    summary["session_id"], summary["epoch_id"],
                )
                if summary["action"] == "switch" else None
            )
            return summary, next_tail
        setup_request = _party_receive(
            client_socket, role, 2, "lan_setup", session, config.startup_timeout
        )
        setup = setup_request.payload
        if hello.mode == "lan-single-step-v1" and not isinstance(setup, LanSetupPayload):
            raise TypeError("单步模式的公开 setup 类型不合法。")
        if (hello.mode in {"lan-continuous-v1", "lan-segmented-v1"}
                and not isinstance(setup, LanContinuousSetupPayload)):
            raise TypeError("连续模式的公开 setup 类型不合法。")
        v2 = hello.mode in {"lan-segmented-v2", "lan-full-v3"}
        if v2 and not isinstance(setup, LanSegmentedSetupV2Payload):
            raise TypeError("v2 持续模式的公开 setup 类型不合法。")
        if (hello.mode == "lan-full-v3" and isinstance(tail, _ScalarRunTail)
                and setup.controller_epoch == tail.epoch_id):
            raise ValueError("v3 新动态捕获必须使用新 epoch")
        if not isinstance(setup, (LanSetupPayload, LanContinuousSetupPayload,
                                  LanSegmentedSetupV2Payload)):
            raise TypeError("公开 LAN setup 类型不合法。")
        if (hello.mode in {"lan-continuous-v1", "lan-segmented-v1"}
                and not 1 <= setup.horizon_steps <= _MAX_CONTINUOUS_STEPS):
            raise ValueError("LAN 连续 setup 步数超出有界范围。")
        modulus_evidence = (setup.modulus_evidence
                            if isinstance(setup, (LanContinuousSetupPayload,
                                                  LanSegmentedSetupV2Payload)) else None)
        verify_prime_modulus(setup.modulus, modulus_evidence)
        fixed = FixedPointContext(
            setup.modulus, integer_bits=setup.integer_bits, fractional_bits=setup.fractional_bits
        )
        range_contract = ControllerRangeContract(
            setup.state_payload_bounds, setup.input_payload_bounds,
            None if v2 else setup.horizon_steps,
            reachability_block_steps=setup.reachability_block_steps if v2 else None,
        )
        if isinstance(hello, LanSegmentedHelloPayload) and not v2 and (
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
        if isinstance(hello, LanSegmentedHelloPayload) and not v2 and (
            material.layout.state_dimension != 0
            or (tail is not None and material.layout != tail.layout)
        ):
            raise ValueError("持续模式只支持冻结的零维 controller layout。")
        if v2 and (
            (tail is not None and not (
                hello.mode == "lan-full-v3" and isinstance(tail, _ScalarRunTail)
            ))
            or material.layout.state_dimension == 0
        ):
            raise ValueError("v2 仅允许首段建立非零秘密状态 session")
        offline = rehydrate_offline_material(material, range_contract)
        role_object = P1(offline) if party == 0 else P2(offline)
        recovery = _OnlineMaterialRecovery(
            offline, modulus=fixed.modulus, security_parameter=setup.security_parameter,
            modulus_evidence=modulus_evidence,
        )
        _party_reply(client_socket, offline_request, None, config.startup_timeout)
        sequence = 4
        if preload_hello is not None:
            request = receive_envelope(client_socket, deadline=startup_deadline, limit=64 * 1024)
            _check_request(request, role, sequence, "preload_init", session)
            if not isinstance(request.payload, PreloadedInitPayload):
                raise TypeError("预送清单类型错误")
            preload_store = _PreloadMaterialStore(request.payload.manifest,
                party=party, session=session, layout=material.layout, modulus=fixed.modulus,
                run_id=hello.run_id, epoch=setup.controller_epoch,
                count=preload_hello.count, stage_mode=preload_hello.stage_mode)
            _party_reply(client_socket, request, preload_store.receipt("init"),
                         config.startup_timeout, deadline=startup_deadline)
            sequence += 1
            while preload_store.loaded < preload_hello.count:
                request = receive_envelope(client_socket, deadline=startup_deadline, limit=256 * 1024)
                _check_request(request, role, sequence, "preload_block", session)
                receipt = preload_store.load(request.payload)
                if request.step != receipt.first_step:
                    raise ValueError("预送块信封步数错误")
                _party_reply(client_socket, request, receipt, config.startup_timeout,
                             deadline=startup_deadline)
                sequence += 1
            request = receive_envelope(client_socket, deadline=startup_deadline, limit=64 * 1024)
            _check_request(request, role, sequence, "preload_seal", session)
            receipt = preload_store.seal(request.payload)
            _party_reply(client_socket, request, receipt, config.startup_timeout,
                         deadline=startup_deadline)
            sequence += 1
        peer_port = LocalhostProtocol3PeerPort(
            peer_socket, role, _FRAME_LIMIT, config.step_timeout, batch_enabled=batch
        )
        peer_port.bind(session)
        steps = (setup.segment_capacity if v2 else
                 1 if hello.mode == "lan-single-step-v1" else setup.horizon_steps)
        segmented = isinstance(hello, LanSegmentedHelloPayload)
        products = truncations = committed = 0
        global_committed = 0
        last_round = None
        awaiting_begin = False
        while True:
            # 首轮也允许等待 Client 先完成纯场景预检；每轮操作有独立总 deadline。
            if not segmented and committed == steps:
                break
            online_request = receive_envelope(
                client_socket, deadline=deadline_after(config.idle_timeout), limit=_FRAME_LIMIT
            )
            if v2 and awaiting_begin:
                _check_request(online_request, role, sequence, "segment_begin", session)
                begin = online_request.payload
                expected = SegmentBeginPayload(
                    hello.run_id, hello.segment_index + 1, global_committed,
                    setup.controller_epoch, last_round,
                )
                if begin != expected:
                    raise ValueError("v2 segment_begin 身份、轮次或 epoch 不匹配")
                _party_reply(client_socket, online_request, begin, config.shutdown_timeout)
                sequence += 1
                hello = LanSegmentedHelloPayload(
                    hello.profile_sha256, hello.nonce, hello.run_id,
                    begin.segment_index, begin.global_start, session,
                    "lan-full-v3" if hello.mode == "lan-full-v3" else "lan-segmented-v2",
                )
                committed = 0
                last_round = None
                awaiting_begin = False
                continue
            if segmented and online_request.operation == "segment_end":
                _check_request(online_request, role, sequence, "segment_end", session)
                end = online_request.payload
                if not isinstance(end, SegmentEndPayload):
                    raise TypeError("段结束请求类型错误。")
                if end.action == "switch" and hello.mode != "lan-full-v3":
                    raise ValueError("旧分段模式不得执行 v3 epoch switch")
                actual = SegmentEndPayload(
                    hello.run_id, hello.segment_index, hello.global_start, committed,
                    hello.global_start + committed, last_round, end.action,
                )
                if end != actual or (end.action == "continue" and committed != steps):
                    raise ValueError("段结束与本方实际提交前缀不一致。")
                receipt = SegmentEndReceipt(role, session, actual,
                                            hello.global_start + committed, products, truncations)
                _party_reply(client_socket, online_request, receipt, config.shutdown_timeout)
                if v2 and end.action == "continue":
                    sequence += 1
                    awaiting_begin = True
                    continue
                if hello.mode == "lan-full-v3" and end.action == "switch":
                    assert isinstance(tail, _ScalarRunTail)
                    tail = _ScalarRunTail(
                        tail.run_id, tail.physical_end + global_committed,
                        session, setup.controller_epoch,
                    )
                else:
                    tail = (
                        _PartyRunTail(
                            hello.run_id, hello.segment_index + 1,
                            hello.global_start + committed, session, setup, material.layout,
                        ) if not v2 and end.action == "continue" else None
                    )
                summary = {"status": "closed", "role": role, "pid": os.getpid(),
                           "steps_committed": receipt.cumulative_committed_count,
                           "final_receipt": asdict(receipt), "transport": config.transport}
                if preload_store is not None:
                    summary["material_summary"] = {"material_mode": "control-preloaded-v1",
                        "budget": preload_store.budget, "claimed": preload_store.next_slot,
                        "committed": preload_store.committed, "exported_count": preload_store.loaded}
                return summary, tail
            fused = preload_hello is not None and preload_hello.stage_mode == "fused"
            operation = "activate_stage" if fused else "activate" if preload_store is not None else "online"
            _check_request(online_request, role, sequence, operation, session)
            expected_step = global_committed if v2 else committed
            if committed >= steps:
                raise ValueError("当前有限段已耗尽，必须先确认段结束。")
            if (online_request.step != expected_step or online_request.round_id is None
                    or online_request.resource_id is not None):
                raise ValueError("LAN online step 必须连续递增。")
            online_material = (preload_store.claim(online_request.payload)
                               if preload_store is not None else online_request.payload)
            if not isinstance(online_material, PartyOnlineMaterial):
                raise TypeError("在线单方材料类型错误。")
            online = recovery.restore(online_material)
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
            if batch:
                peer_port.set_batch_round(
                    endpoint.plan, modulus=fixed.modulus,
                    run_id=hello.run_id if isinstance(hello, LanSegmentedHelloPayload)
                    else None,
                    epoch_id=setup.controller_epoch if v2 else session,
                    physical_step=(tail.physical_end + global_committed
                                   if hello.mode == "lan-full-v3"
                                   and isinstance(tail, _ScalarRunTail) else None),
                )
            direct = DirectProtocol3PartyEndpoint(endpoint, peer_port)
            activation_result = None
            if fused:
                receipt = stage_protocol3_batch(endpoint, peer_port)
                if not isinstance(receipt, Protocol3StageReceipt) or len(staged) != 1:
                    raise ValueError("融合暂存回执与输出份额不完整")
                activation_result = PartyStageResult(receipt, staged[0])
            _party_reply(client_socket, online_request, activation_result, config.step_timeout,
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
                    command = command_request.payload.operation
                    if fused and command != "commit":
                        raise ValueError("融合激活后只允许原双提交命令")
                    if batch and command == "stage_batch":
                        result = stage_protocol3_batch(endpoint, peer_port)
                    elif (batch and command != "commit") or (not batch and command == "stage_batch"):
                        raise ValueError("endpoint 操作与协商的批量能力不匹配")
                    else:
                        result = dispatch_direct_protocol3_command(direct, command_request.payload)
                    if command in {"stage_output", "stage_batch"}:
                        if not isinstance(result, Protocol3StageReceipt) or len(staged) != 1:
                            raise ValueError("暂存回执与输出份额不完整。")
                        result = PartyStageResult(result, staged[0])
                    _party_reply(client_socket, command_request, result,
                                 config.step_timeout, deadline=step_deadline)
                except Exception as error:
                    _party_error(client_socket, command_request, error, config.step_timeout)
                    raise
                sequence += 1
                if command == "commit":
                    if preload_store is not None:
                        preload_store.commit(endpoint.plan)
                    committed += 1
                    if v2:
                        global_committed += 1
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
        if preload_store is not None:
            preload_store.close()
            if endpoint is not None:
                endpoint.abort()
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
    hello: LanHelloPayload | LanSegmentedHelloPayload | BatchHelloPayload | PreloadedHelloPayload,
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
    expected: tuple[str, LanHelloPayload | LanSegmentedHelloPayload | BatchHelloPayload | PreloadedHelloPayload]
    | None = None,
) -> tuple[str, LanHelloPayload | LanSegmentedHelloPayload | BatchHelloPayload]:
    request = receive_envelope(sock, deadline=deadline, limit=_FRAME_LIMIT)
    payload = request.payload
    base = payload.base if isinstance(payload, PreloadedHelloPayload) else payload
    base = base.base if isinstance(base, BatchHelloPayload) else base
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
        or not isinstance(payload, (LanHelloPayload, LanSegmentedHelloPayload,
                                    BatchHelloPayload, PreloadedHelloPayload))
        or base.profile_sha256 != config.topology.digest
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


def _prepare_online_requests(materials, session, round_id, step, sequences):
    """本轮两方完整信封各编码一次、均通过长度检查后才允许首次发送。"""
    return _prepare_requests(materials, "online", session, round_id, step, sequences, _FRAME_LIMIT)


def _prepare_requests(materials, operation, session, round_id, step, sequences, limit):
    """共享完整信封预检；两方编码均成功之后调用者才可开始发送。"""
    prepared = []
    for party, material in enumerate(materials):
        request = WireEnvelope(
            SCHEMA_VERSION, "request", "Client", "P1" if party == 0 else "P2",
            sequences[party], operation, session, round_id, step, None, material,
        )
        encoded = localhost_transport.encode_envelope(request)
        localhost_transport._validate_frame_payload(encoded, limit)
        prepared.append((request, encoded))
    return prepared


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
    expected_payload: object = None,
    send_only: bool = False,
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
    if send_only:
        return request
    return _receive_reply(sock, request, deadline=deadline, expected_payload=expected_payload)


def _receive_reply(sock: socket.socket, request: WireEnvelope, *, deadline: float,
                   expected_payload: object = None, limit: int = _FRAME_LIMIT) -> object:
    """单 socket 只有一个读者；两方独立请求先发送，回执仍逐一完整校验。"""
    response = receive_envelope(sock, deadline=deadline, limit=limit)
    _validate_party_reply(response, request)
    if response.payload != expected_payload:
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
