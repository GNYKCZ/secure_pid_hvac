"""P1↔P2 localhost 在线消息通道；只负责 identity、顺序与有界收发。"""

from __future__ import annotations

import os
import socket
from copy import deepcopy
from typing import Literal

from secure_control.crypto import AdditiveShare
from secure_control.crypto.seeded_material import PREAUTHORIZED_PROFILE_V2, PREAUTHORIZED_PROFILES
from secure_control.protocol.messages import (
    _PUBLIC_PLAN_JSON_FIELDS,
    MatrixMaskPayload,
    MatrixStepResourcePlan,
    P2TruncationPayload,
    ProductMaskPayload,
    Protocol3BatchPayload,
    ReadyReceipt,
    ResourceMetadata,
    StepResourcePlan,
    _deeply_immutable_public_plan,
    public_step_plan_sha256,
)

from .localhost_codec import (
    _CLIENT_AUTH_PROFILES,
    _COMPACT_PROFILES,
    _MATRIX_PROFILES,
    SCHEMA_VERSION,
    BatchHelloPayload,
    HelloPayload,
    WireEnvelope,
    _CompactBatchPayload,
    _decode_integer_residues,
    _decode_residues,
    _encode_integer_residues,
    _encode_residues,
    _PermitContext,
    _PrefixPayload,
    _ReadyReference,
    _SuffixPayload,
    _SuffixReference,
    decode_envelope,
    encode_envelope,
)
from .localhost_transport import (
    _exchange_frame,
    accept_loopback,
    connect_loopback,
    deadline_after,
    receive_envelope,
    send_envelope,
)
from .tail_diagnostics import current

Address = tuple[str, int]
Role = Literal["P1", "P2"]


def _snapshot_public_plan(plan):
    """仅为规范矩阵图复制独立记录；其他表示保留标准库深复制语义。"""
    if type(plan) is not MatrixStepResourcePlan:
        return deepcopy(plan)
    try:
        standard = _deeply_immutable_public_plan(plan)
    except AttributeError:
        # 缺字段不具备快路资格；仍由原复制/摘要路径决定失败类别及赋值阶段。
        standard = False
    if not standard:
        return deepcopy(plan)
    memo = {}
    def clone(value):
        kind = type(value)
        if kind in (int, str, type(None)):
            return value
        key = id(value)
        if key in memo:
            return memo[key]
        if kind is tuple:
            copied = tuple(clone(item) for item in value)
            memo[key] = copied
            return copied
        # 资格已限定有限已知记录；按现有字段表复制存储，不重跑构造/校验。
        copied = object.__new__(kind)
        memo[key] = copied
        for name in _PUBLIC_PLAN_JSON_FIELDS[kind]:
            object.__setattr__(copied, name, clone(getattr(value, name)))
        return copied
    return clone(plan)


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
        wire_profile: str = "control-batch-v1",
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
        if wire_profile not in {"control-batch-v1", *_COMPACT_PROFILES} or (
            wire_profile in _COMPACT_PROFILES and not batch_enabled
        ):
            raise ValueError("peer 编码 profile 无效")
        self._wire_profile = wire_profile
        self._batch_context: tuple[StepResourcePlan, str | None, str, int | None, int] | None = None
        self._permit_context: _PermitContext | None = None

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
        if (type(plan) is MatrixStepResourcePlan) != (self._wire_profile in _MATRIX_PROFILES):
            raise ValueError("矩阵计划与显式协商的wire不一致")
        if not self._batch_enabled or self._session_id != plan.session_id:
            raise ValueError("peer 未协商批量能力或 session 不匹配")
        if type(modulus) is not int or modulus < 3:
            raise ValueError("批量 peer 模数无效")
        if self._wire_profile in _CLIENT_AUTH_PROFILES and (
                not plan.truncation_count or getattr(self, "_v3_last_step", -1)+1 != plan.step
                or getattr(self, "_v3_phase", "ready" if self._wire_profile in PREAUTHORIZED_PROFILES else "truncated")
                    != ("ready" if self._wire_profile in PREAUTHORIZED_PROFILES else "truncated")):
            raise ValueError("局部暂存 peer 需要连续新鲜且前轮完整的动态截断轮次。")
        self._batch_context = (_snapshot_public_plan(plan), run_id, epoch_id or plan.session_id,
                               physical_step, modulus)
        # 独立快照保留每次调用的变化检测；摘要仅计算一次，不信任调用者的对象 identity。
        self._batch_digest = public_step_plan_sha256(plan)
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_last_step = plan.step
            self._v3_phase = "prepared"

    def exchange_products(
        self, plan: StepResourcePlan, masks: tuple[ProductMaskPayload, ...],
    ) -> tuple[ProductMaskPayload, ...]:
        self._check_v3_phase("prepared")
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_phase = "in_flight"
        ids = tuple(item.resource_id for item in plan.product_resources)
        self._check_batch_values(masks, len(ids), "product", sender=self._role)
        if self._wire_profile in _COMPACT_PROFILES:
            incoming = self._exchange_batch(plan, "product", ids, products=masks).products
        elif self._role == "P1":
            self._send_batch(plan, "product", ids, products=masks)
            incoming = self._receive_batch(plan, "product", ids).products
        else:
            incoming = self._receive_batch(plan, "product", ids).products
            self._send_batch(plan, "product", ids, products=masks)
        self._check_batch_values(incoming, len(ids), "product", sender=self._peer)
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_phase = "products"
        return incoming

    def _exchange_preauthorized(self, operation, payload, session, round_id, step):
        if self._wire_profile not in PREAUTHORIZED_PROFILES or session != self._session_id:
            raise ValueError("前缀/预授权需要显式同一session")
        diagnostic = current()
        phase = 'prefix_peer' if operation == 'peer_prefix' else 'suffix' if operation == 'peer_suffix' else 'ready'
        if diagnostic is not None:
            diagnostic.emit(phase,0,-1 if operation == 'peer_prefix' else step,
                            step if operation == 'peer_prefix' else -1)
        outgoing = WireEnvelope(SCHEMA_VERSION, "request", self._role, self._peer,
            self._send_sequence, operation, session, round_id, step, None, payload)
        incoming = decode_envelope(_exchange_frame(self._connection, encode_envelope(outgoing),
            deadline=self._deadline if self._deadline is not None else deadline_after(self._timeout),
            limit=self._limit))
        if (incoming.kind, incoming.sender, incoming.recipient, incoming.sequence, incoming.operation,
                incoming.session_id, incoming.round_id, incoming.step, incoming.resource_id) != (
                "request", self._peer, self._role, self._receive_sequence, operation, session, round_id, step, None):
            raise ValueError("预授权peer身份/序号/阶段错误")
        self._send_sequence += 1
        self._receive_sequence += 1
        if diagnostic is not None:
            diagnostic.emit(phase,1,-1 if operation == 'peer_prefix' else step,
                            step if operation == 'peer_prefix' else -1)
        return incoming.payload

    def install_permit(self, permit):
        """v2仅安装当前已验证完整许可；退休前不接受另一许可，不保存历史引用。"""
        if (self._wire_profile != PREAUTHORIZED_PROFILE_V2 or self._permit_context is not None
                or self._batch_context is None or getattr(self, "_v3_phase", None) != "prepared"
                or permit.version != self._wire_profile
                or (permit.session_id, permit.round_id, permit.global_step, permit.plan_sha256) != (
                    self._session_id, self._batch_context[0].round_id,
                    self._batch_context[0].step, self._batch_digest)):
            raise ValueError("缺少当前轮次或重复/错误v2许可安装")
        self._permit_context = _PermitContext(permit)
        return self._permit_context

    def retire_permit(self):
        """当前最终回复完成后丢弃引用，下一步必须重新安装完整许可。"""
        if self._wire_profile != PREAUTHORIZED_PROFILE_V2 or self._v3_phase != "ready":
            raise ValueError("许可只能在实际READY完成后退休")
        self._permit_context = None

    def _current_permit(self, permit):
        context = self._permit_context
        if context is None or context.permit != permit:
            raise ValueError("缺少当前一步许可上下文")
        return context

    def exchange_prefix(self, identity, e, fx, modulus):
        import numpy as np
        if (getattr(self, "_prefix_next", 0) != identity[4]
                or getattr(self, "_v3_phase", "ready") != "ready" or self._permit_context is not None):
            raise ValueError("前缀错步或上一轮尚未完成")
        self._prefix_next = identity[4]+1
        values = [int(v) for arr in (e, fx) for v in arr.flat]
        payload = _PrefixPayload(identity, 0 if self._role == "P1" else 1,
                                 _encode_integer_residues(values, len(values), modulus))
        incoming = self._exchange_preauthorized("peer_prefix", payload, identity[1], None, identity[4])
        if (type(incoming) is not _PrefixPayload or incoming.identity != identity
                or incoming.party != 1-payload.party):
            raise ValueError("对端前缀上下文/状态版本错误")
        values = _decode_integer_residues(incoming.values, len(values), modulus)
        count = e.size
        return (AdditiveShare(np.array(values[:count], dtype=object).reshape(e.shape)),
                AdditiveShare(np.array(values[count:], dtype=object).reshape(fx.shape)))

    def exchange_suffix(self, plan, permit, value):
        import numpy as np
        self._check_v3_phase("prepared")
        self._batch_identity(plan)
        self._v3_phase = "in_flight"
        q = self._batch_context[4]
        party = 0 if self._role == "P1" else 1
        data = _encode_integer_residues(tuple(int(v) for v in value.value.flat), value.value.size, q)
        context = self._current_permit(permit) if self._wire_profile == PREAUTHORIZED_PROFILE_V2 else None
        payload = (_SuffixReference(context.permit_ref, party, data) if context is not None else
                   _SuffixPayload(permit, party, data))
        incoming = self._exchange_preauthorized("peer_suffix", payload, plan.session_id, plan.round_id, plan.step)
        if context is not None:
            if type(incoming) is not _SuffixReference:
                raise ValueError("v2后缀禁止旧嵌套许可")
            context.check(incoming.permit_ref)
        elif type(incoming) is not _SuffixPayload or incoming.permit != permit:
            raise ValueError("v1后缀禁止引用/错误许可")
        if incoming.party != 1-payload.party:
            raise ValueError("后缀permit/角色不匹配")
        values = _decode_integer_residues(incoming.values, plan.input_shape[0], q)
        self._v3_phase = "products"
        return AdditiveShare(np.array(values, dtype=object).reshape(plan.input_shape[0], 1))

    def exchange_ready(self, ready):
        self._check_v3_phase("truncated")
        if type(ready) is not ReadyReceipt:
            raise ValueError("需要局部READY")
        p = ready.permit
        context = self._current_permit(p) if self._wire_profile == PREAUTHORIZED_PROFILE_V2 else None
        payload = context.compact_ready(ready) if context is not None else ready
        self._v3_phase = "in_flight"
        incoming = self._exchange_preauthorized("peer_ready", payload, p.session_id, p.round_id, p.global_step)
        if context is not None:
            incoming = context.restore_ready(incoming)
        elif type(incoming) is _ReadyReference:
            raise ValueError("v1不接受READY引用")
        if (type(incoming) is not ReadyReceipt or incoming.permit != p
                or incoming.party != 1-ready.party or incoming.truncations != ready.truncations):
            raise ValueError("对方READY不匹配")
        self._v3_phase = "ready"
        return incoming

    def product_complete(self, plan: StepResourcePlan) -> None:
        self._barrier(plan, "product_complete",
                      tuple(item.resource_id for item in plan.product_resources))

    def send_truncations(
        self, plan: StepResourcePlan, values: tuple[P2TruncationPayload, ...],
    ) -> None:
        if self._role != "P2":
            raise ValueError("只有 P2 能发送截断批次")
        self._check_v3_phase("products")
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_phase = "in_flight"
        ids = tuple(item.resource_id for item in plan.state_truncation_resources)
        self._check_batch_values(values, len(ids), "truncation")
        self._send_batch(plan, "truncation", ids, truncations=values)
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_phase = "truncated"

    def receive_truncations(self, plan: StepResourcePlan) -> tuple[P2TruncationPayload, ...]:
        if self._role != "P1":
            raise ValueError("只有 P1 能接收截断批次")
        self._check_v3_phase("products")
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_phase = "in_flight"
        ids = tuple(item.resource_id for item in plan.state_truncation_resources)
        values = self._receive_batch(plan, "truncation", ids).truncations
        self._check_batch_values(values, len(ids), "truncation")
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            self._v3_phase = "truncated"
        return values

    def state_complete(self, plan: StepResourcePlan) -> None:
        self._barrier(plan, "state_complete",
                      tuple(item.resource_id for item in plan.state_truncation_resources))

    def _barrier(self, plan: StepResourcePlan, phase: str, ids: tuple[str, ...]) -> None:
        if self._wire_profile in _CLIENT_AUTH_PROFILES:
            raise ValueError("局部暂存 peer 拒绝完成屏障。")
        if self._wire_profile in _COMPACT_PROFILES:
            self._exchange_batch(plan, phase, ids)
        elif self._role == "P1":
            self._send_batch(plan, phase, ids)
            self._receive_batch(plan, phase, ids)
        else:
            self._receive_batch(plan, phase, ids)
            self._send_batch(plan, phase, ids)

    def _check_v3_phase(self, expected: str) -> None:
        """严格保留实际传输次序，跳过的语义索引不允许重新进入。"""
        if (self._wire_profile in _CLIENT_AUTH_PROFILES
                and getattr(self, "_v3_phase", None) != expected):
            raise ValueError("局部暂存 peer 阶段重复或提前。")

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
            plan.step, None, self._wire_batch(payload),
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
        return self._validate_batch(message, plan, phase, ids)

    def _exchange_batch(self, plan, phase, ids, *, products=()):
        """完整本地消息就绪后，单线程双向推进；完成后仍通过原批次身份检查。"""
        payload = self._batch_payload(plan, phase, ids, products=products)
        message = WireEnvelope(SCHEMA_VERSION, "request", self._role, self._peer,
            self._send_sequence, "peer_batch", plan.session_id, plan.round_id,
            plan.step, None, self._wire_batch(payload))
        incoming = decode_envelope(_exchange_frame(self._connection, encode_envelope(message),
            deadline=self._deadline if self._deadline is not None else deadline_after(self._timeout),
            limit=self._limit))
        result = self._validate_batch(incoming, plan, phase, ids)
        self._send_sequence += 1
        return result

    def _wire_batch(self, payload):
        if self._wire_profile not in _COMPACT_PROFILES:
            return payload
        if self._wire_profile in _MATRIX_PROFILES:
            from secure_control.crypto.matrix_beaver import matrix_values
            meta = self._batch_context[0].product_resources[0]
            modulus = self._batch_context[4]
            values = [int(v) for item in payload.products
                      for share,shape in ((item.e,(meta.rows,meta.inner)),(item.f,(meta.inner,1)))
                      for v in matrix_values(share,shape,modulus).flat]
            values.extend(item.value.value for item in payload.truncations)
            encoded = _encode_integer_residues(values,len(values),modulus)
        else:
            values = [share for item in payload.products for share in (item.d, item.e)]
            values.extend(item.value for item in payload.truncations)
            encoded = _encode_residues(values, self._batch_context[4])
        return _CompactBatchPayload(payload.phase, payload.plan_sha256, payload.run_id,
            payload.epoch_id, payload.physical_step, payload.batch_index,
            encoded, self._wire_profile)

    def _validate_batch(self, message, plan, phase, ids):
        run_id, epoch_id, physical_step, _ = self._batch_identity(plan)
        if (message.kind, message.sender, message.recipient, message.sequence,
            message.operation, message.session_id, message.round_id, message.step,
            message.resource_id) != (
            "request", self._peer, self._role, self._receive_sequence,
            "peer_batch", plan.session_id, plan.round_id, plan.step, None,
        ):
            raise ValueError("批量 peer 阶段、顺序或公开身份不匹配")
        payload = message.payload
        if self._wire_profile in _COMPACT_PROFILES:
            if not isinstance(payload, _CompactBatchPayload) or payload.version != self._wire_profile:
                raise ValueError("紧凑 peer 禁止混入旧批次")
            # 先检验公开身份及精确长度；不得依据字节外观猜测格式。
            if (payload.phase, payload.plan_sha256, payload.run_id, payload.epoch_id,
                payload.physical_step, payload.batch_index) != (
                phase, self._batch_digest, run_id, epoch_id, physical_step,
                {"product": 0, "product_complete": 1, "truncation": 2, "state_complete": 3}[phase]
            ):
                raise ValueError("紧凑 peer 阶段或公开身份不匹配")
            count = (plan.multiplication_mask_elements if self._wire_profile in _MATRIX_PROFILES
                     and phase == "product" else len(ids) * (2 if phase == "product" else 1)
                     if phase in {"product", "truncation"} else 0)
            matrix_product = self._wire_profile in _MATRIX_PROFILES and phase == "product"
            values = iter((_decode_integer_residues if matrix_product else _decode_residues)(payload.values,
                count,
                self._batch_context[4]))
            if matrix_product:
                import numpy as np

                from secure_control.crypto import AdditiveShare
                meta = plan.product_resources[0]
                e = AdditiveShare(np.array([next(values) for _ in range(meta.rows*meta.inner)],
                                          dtype=object).reshape(meta.rows, meta.inner))
                f = AdditiveShare(np.array([next(values) for _ in range(meta.inner)],
                                          dtype=object).reshape(meta.inner, 1))
                products = (MatrixMaskPayload(e, f, 0 if self._peer == "P1" else 1),)
            else:
                products = (tuple(ProductMaskPayload(next(values), next(values), 0 if self._peer == "P1" else 1)
                                  for _ in ids) if phase == "product" else ())
            payload = Protocol3BatchPayload(payload.phase, payload.plan_sha256, payload.run_id,
                payload.epoch_id, payload.physical_step, payload.batch_index, ids,
                products,
                tuple(P2TruncationPayload(next(values)) for _ in ids) if phase == "truncation" else ())
        if not isinstance(payload, Protocol3BatchPayload) or (
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
                if self._wire_profile in _MATRIX_PROFILES:
                    from secure_control.crypto.matrix_beaver import matrix_values
                    if (type(item) is not MatrixMaskPayload or type(item.party) is not int
                            or item.party != (0 if sender == "P1" else 1)):
                        raise ValueError("矩阵mask角色/类型错误")
                    plan = self._batch_context[0]
                    if type(plan) is not MatrixStepResourcePlan:
                        raise ValueError("矩阵peer缺少矩阵计划")
                    meta = plan.product_resources[0]
                    matrix_values(item.e, (meta.rows, meta.inner), modulus)
                    matrix_values(item.f, (meta.inner, 1), modulus)
                    continue
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
        self._permit_context = None
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
