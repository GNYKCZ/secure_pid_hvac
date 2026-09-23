"""单进程下的 Protocol 3 消息协调，不向 Server 提供明文或完整 state。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

import numpy as np

from secure_control.crypto import (
    AdditiveShare,
    BeaverMultiplier,
    BeaverTripleShare,
    MaskedDifferenceShare,
    MaskedTruncationShare,
    P2MaskedMessage,
    PrimeModulusEvidence,
    PublicMaskedDifferences,
    SecureTruncation,
    TruncationAuxiliaryShare,
    TwoPartySharing,
)
from secure_control.crypto.beaver import _TripleLifecycle
from secure_control.crypto.truncation import _MaskLifecycle

from .evidence import ProtocolStepSnapshot, copy_share
from .messages import (
    _PROTOCOL3_TERM_ORDER,
    ControllerRangeContract,
    ControlShareMessage,
    OfflineControllerMessage,
    OnlineRound,
    P2TruncationPayload,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyOnlineRound,
    PartyResources,
    ProductMaskPayload,
    ProductResourceMaterial,
    ProductResourceShare,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
    ResourceMetadata,
    StateTruncationResourceShare,
    StepResourcePlan,
    TruncationMaskPayload,
    TruncationResourceMaterial,
    _ResourceLifecycle,
)
from .roles import P1, P2, _Server, _vector_from_scalars


@runtime_checkable
class Protocol3PartyEndpoint(Protocol):
    """Protocol 3 唯一调度所需的最小单方 endpoint contract。"""

    @property
    def party(self) -> int: ...

    @property
    def session_id(self) -> str: ...

    @property
    def plan(self) -> StepResourcePlan: ...

    def mask_product(self, metadata: ResourceMetadata) -> None: ...

    def finish_product(self, metadata: ResourceMetadata) -> None: ...

    def complete_product(self, metadata: ResourceMetadata) -> None: ...

    def finish_products(self) -> None: ...

    def mask_truncation(self, metadata: ResourceMetadata) -> None: ...

    def send_truncation(self, metadata: ResourceMetadata) -> None: ...

    def finish_truncation_p1(self, metadata: ResourceMetadata) -> None: ...

    def finish_truncation_p2(self, metadata: ResourceMetadata) -> None: ...

    def complete_truncation(self, metadata: ResourceMetadata) -> None: ...

    def stage_output(self) -> Protocol3StageReceipt: ...

    def commit(self) -> None: ...


class Protocol3Orchestrator:
    """唯一的 transport-neutral Protocol 3 操作与消息顺序。"""

    def stage(
        self,
        p1: Protocol3PartyEndpoint,
        p2: Protocol3PartyEndpoint,
        plan: StepResourcePlan,
    ) -> tuple[Protocol3StageReceipt, Protocol3StageReceipt]:
        """驱动两方完成乘法、可选截断并暂存 output/state，不提交 state。"""
        self._validate_endpoints(p1, p2, plan)
        for metadata in plan.product_resources:
            p1.mask_product(metadata)
            p2.mask_product(metadata)
            p1.finish_product(metadata)
            p2.finish_product(metadata)
            p1.complete_product(metadata)
            p2.complete_product(metadata)
        p1.finish_products()
        p2.finish_products()
        for metadata in plan.state_truncation_resources:
            p1.mask_truncation(metadata)
            p2.mask_truncation(metadata)
            p2.send_truncation(metadata)
            p1.finish_truncation_p1(metadata)
            p2.finish_truncation_p2(metadata)
            p1.complete_truncation(metadata)
            p2.complete_truncation(metadata)
        receipts = p1.stage_output(), p2.stage_output()
        expected = (
            plan.session_id,
            plan.round_id,
            plan.step,
            plan.triple_count,
            plan.truncation_count,
        )
        if any(
            receipt.party != party
            or (
                receipt.session_id,
                receipt.round_id,
                receipt.step,
                receipt.products,
                receipt.truncations,
            )
            != expected
            for party, receipt in enumerate(receipts)
        ):
            raise ValueError("Protocol 3 暂存回执与资源计划不匹配。")
        return receipts

    def commit(self, p1: Protocol3PartyEndpoint, p2: Protocol3PartyEndpoint) -> None:
        """在调用方完成输出验证后按固定 P1/P2 顺序提交两方 state。"""
        p1.commit()
        p2.commit()

    @staticmethod
    def _validate_endpoints(
        p1: Protocol3PartyEndpoint,
        p2: Protocol3PartyEndpoint,
        plan: StepResourcePlan,
    ) -> None:
        if not isinstance(plan, StepResourcePlan):
            raise TypeError("Protocol 3 调度需要 StepResourcePlan。")
        if (p1.party, p2.party) != (0, 1):
            raise ValueError("Protocol 3 endpoint 必须按 P1/P2 顺序提供。")
        if p1.session_id != plan.session_id or p2.session_id != plan.session_id:
            raise ValueError("Protocol 3 endpoint 与资源计划的 session 不匹配。")
        if p1.plan != plan or p2.plan != plan:
            raise ValueError("Protocol 3 endpoint 必须绑定同一资源计划。")


class Protocol3PeerPort(Protocol):
    """仅承载 P1/P2 在线消息的传输端口，不拥有协议计算或调度。"""

    def send_product(self, metadata: ResourceMetadata, payload: ProductMaskPayload) -> None: ...

    def receive_product(self, metadata: ResourceMetadata) -> ProductMaskPayload: ...

    def send_truncation(self, metadata: ResourceMetadata, payload: P2TruncationPayload) -> None: ...

    def receive_truncation(self, metadata: ResourceMetadata) -> P2TruncationPayload: ...


class DirectProtocol3PartyEndpoint:
    """将既有本地数学内核与 P1↔P2 peer port 组合为无 share 回执的 endpoint。"""

    def __init__(self, endpoint: LocalProtocol3PartyEndpoint, peer: Protocol3PeerPort) -> None:
        if not isinstance(endpoint, LocalProtocol3PartyEndpoint):
            raise TypeError("endpoint 必须是 LocalProtocol3PartyEndpoint。")
        self._endpoint = endpoint
        self._peer = peer

    @property
    def party(self) -> int:
        return self._endpoint.party

    @property
    def session_id(self) -> str:
        return self._endpoint.session_id

    @property
    def plan(self) -> StepResourcePlan:
        return self._endpoint.plan

    def mask_product(self, metadata: ResourceMetadata) -> None:
        self._peer.send_product(metadata, self._endpoint.mask_product(metadata))

    def finish_product(self, metadata: ResourceMetadata) -> None:
        self._endpoint.finish_product(metadata, self._peer.receive_product(metadata))

    def complete_product(self, metadata: ResourceMetadata) -> None:
        self._endpoint.complete_product(metadata)

    def finish_products(self) -> None:
        self._endpoint.finish_products()

    def mask_truncation(self, metadata: ResourceMetadata) -> None:
        self._endpoint.mask_truncation(metadata)

    def send_truncation(self, metadata: ResourceMetadata) -> None:
        if self.party != 1:
            raise ValueError("只有 P2 endpoint 可以发送截断消息。")
        self._peer.send_truncation(
            metadata, self._endpoint.p2_truncation_message_direct(metadata)
        )

    def finish_truncation_p1(self, metadata: ResourceMetadata) -> None:
        if self.party != 0:
            raise ValueError("只有 P1 endpoint 可以接收截断消息。")
        self._endpoint.finish_truncation_p1_direct(
            metadata, self._peer.receive_truncation(metadata)
        )

    def finish_truncation_p2(self, metadata: ResourceMetadata) -> None:
        self._endpoint.finish_truncation_p2(metadata)

    def complete_truncation(self, metadata: ResourceMetadata) -> None:
        self._endpoint.complete_truncation(metadata)

    def stage_output(self) -> Protocol3StageReceipt:
        return self._endpoint.stage_output()

    def commit(self) -> None:
        self._endpoint.commit()


class _InMemoryProtocol3PeerPort:
    """单进程基线使用的 peer port；保持与直连 endpoint 相同的消息边界。"""

    def __init__(self, party: int, inbox: dict[tuple[int, str, str], object]) -> None:
        self._party = party
        self._inbox = inbox

    def send_product(self, metadata: ResourceMetadata, payload: ProductMaskPayload) -> None:
        self._send("product", metadata, payload)

    def receive_product(self, metadata: ResourceMetadata) -> ProductMaskPayload:
        value = self._receive("product", metadata)
        if not isinstance(value, ProductMaskPayload):
            raise TypeError("Protocol 1 peer payload 类型错误。")
        return value

    def send_truncation(self, metadata: ResourceMetadata, payload: P2TruncationPayload) -> None:
        self._send("truncation", metadata, payload)

    def receive_truncation(self, metadata: ResourceMetadata) -> P2TruncationPayload:
        value = self._receive("truncation", metadata)
        if not isinstance(value, P2TruncationPayload):
            raise TypeError("Protocol 2 peer payload 类型错误。")
        return value

    def _send(self, kind: str, metadata: ResourceMetadata, payload: object) -> None:
        key = (1 - self._party, kind, metadata.resource_id)
        if key in self._inbox:
            raise ValueError("Protocol 3 peer 消息不得重复发送。")
        self._inbox[key] = payload

    def _receive(self, kind: str, metadata: ResourceMetadata) -> object:
        key = (self._party, kind, metadata.resource_id)
        try:
            return self._inbox.pop(key)
        except KeyError as error:
            raise ValueError("Protocol 3 peer 消息顺序错误。") from error


class LocalProtocol3PartyEndpoint:
    """把现有 P1/P2 本地角色操作适配到统一 Protocol 3 endpoint。"""

    def __init__(
        self,
        role: _Server,
        online: PartyOnlineRound,
        control_sender: Callable[[ControlShareMessage], None],
    ) -> None:
        """安装单方 round，并只信任本地 metadata 与 lifecycle registry。"""
        if not isinstance(online, PartyOnlineRound):
            raise TypeError("online 必须是单方 PartyOnlineRound。")
        resources = online.resources
        if resources.recipient not in {0, 1} or resources.recipient != role._party:
            raise ValueError("单方在线资源的角色路由错误。")
        plan = resources.plan
        if role.session_id != plan.session_id:
            raise ValueError("角色与在线资源不属于同一 session。")
        if (plan.state_shape, plan.input_shape, plan.output_shape) != (
            (role.layout.state_dimension,),
            (role.layout.input_dimension,),
            (role.layout.output_dimension,),
        ) or plan.scale_ledger != role.layout.scale_ledger:
            raise ValueError("在线资源计划的 shape 或 scale ledger 不匹配。")
        if (
            len(resources.product_resources) != plan.triple_count
            or len(resources.state_truncation_resources) != plan.truncation_count
        ):
            raise ValueError("单方在线资源数量与计划不匹配。")
        self._role = role
        self._resources = resources
        self._plan = plan
        self._input = role.input_share(
            online.input_message,
            session_id=plan.session_id,
            round_id=plan.round_id,
            step=plan.step,
        )
        self._control_sender = control_sender
        self._products = {item.metadata.resource_id: item for item in resources.product_resources}
        self._truncations = {
            item.metadata.resource_id: item for item in resources.state_truncation_resources
        }
        if (
            len(self._products) != plan.triple_count
            or len(self._truncations) != plan.truncation_count
        ):
            raise ValueError("Protocol 3 资源 ID 必须在当前 round 内唯一。")
        self._product_state: dict[
            str, tuple[ProductResourceShare, BeaverMultiplier, MaskedDifferenceShare]
        ] = {}
        self._truncation_state: dict[
            str,
            tuple[
                StateTruncationResourceShare,
                SecureTruncation,
                MaskedTruncationShare,
                AdditiveShare,
            ],
        ] = {}
        self._completed_products: set[str] = set()
        self._completed_truncations: set[str] = set()
        rows = {
            "C": role.layout.output_dimension,
            "D": role.layout.output_dimension,
            "A": role.layout.state_dimension,
            "B": role.layout.state_dimension,
        }
        self._sums = {
            (term, row): AdditiveShare(0)
            for term in _PROTOCOL3_TERM_ORDER
            for row in range(rows[term])
        }
        self._sharing = self._resolve_sharing(resources)
        self._output: AdditiveShare | None = None
        self._raw_state: AdditiveShare | None = None
        self._next_state: AdditiveShare | None = None
        self._truncated_values: dict[int, AdditiveShare] = {}
        self._staged = False

    @property
    def party(self) -> int:
        return self._resources.recipient

    @property
    def session_id(self) -> str:
        return self._plan.session_id

    @property
    def plan(self) -> StepResourcePlan:
        return self._plan

    @property
    def input_share(self) -> AdditiveShare:
        return self._input

    @property
    def output_share(self) -> AdditiveShare:
        if self._output is None:
            raise RuntimeError("Protocol 3 尚未形成 output share。")
        return self._output

    @property
    def raw_state_share(self) -> AdditiveShare:
        if self._raw_state is None:
            raise RuntimeError("Protocol 3 尚未形成 state accumulator。")
        return self._raw_state

    @property
    def next_state_share(self) -> AdditiveShare:
        if self._next_state is None:
            raise RuntimeError("Protocol 3 尚未形成 next state share。")
        return self._next_state

    def mask_product(self, metadata: ResourceMetadata) -> ProductMaskPayload:
        resource = self._product_resource(metadata)
        if metadata.resource_id in self._product_state:
            raise ValueError("同一乘法资源不得重复开始。")
        multiplier = resource.triple._lifecycle.owner
        right = (
            self._role.state_value(metadata.index[1])
            if metadata.term in {"A", "C"}
            else self._role.input_value(self._input, metadata.index[1])
        )
        masked = self._role.start_product(
            multiplier,
            self._role.matrix_value(metadata.term, *metadata.index),
            right,
            resource,
        )
        self._product_state[metadata.resource_id] = (resource, multiplier, masked)
        return ProductMaskPayload(masked.d, masked.e, self.party)

    def finish_product(self, metadata: ResourceMetadata, peer: ProductMaskPayload) -> None:
        resource, multiplier, masked = self._product_entry(metadata)
        other = 1 - self.party
        if not isinstance(peer, ProductMaskPayload) or peer.party != other:
            raise ValueError("Protocol 1 对端遮蔽消息的角色错误。")
        lifecycle = masked._lifecycle
        if other not in lifecycle.masked_parties:
            lifecycle.claim_masking(other)
        rebound = MaskedDifferenceShare(peer.d, peer.e, peer.party, lifecycle)
        if lifecycle.opened:
            d = self._scalar(self._sharing.reconstruct(masked.d, rebound.d), "d")
            e = self._scalar(self._sharing.reconstruct(masked.e, rebound.e), "e")
            opened = PublicMaskedDifferences(d, e, lifecycle)
        else:
            opened = multiplier.open_masked_differences(masked, rebound)
        product = self._role.finish_product(multiplier, resource, opened)
        row = metadata.index[0]
        key = (metadata.term, row)
        self._sums[key] = self._role.add(self._sharing, self._sums[key], product)

    def complete_product(self, metadata: ResourceMetadata) -> None:
        resource, _, masked = self._product_entry(metadata)
        lifecycle = masked._lifecycle
        if not lifecycle.consumed and 1 - self.party not in lifecycle.finished_parties:
            lifecycle.claim_finish(1 - self.party)
        if not lifecycle.consumed:
            raise ValueError("Protocol 1 两方尚未完成同一资源。")
        if resource._lifecycle.status == "prepared":
            if 1 - self.party not in resource._lifecycle.claimed_by:
                resource._lifecycle.claim(1 - self.party)
            resource._lifecycle.complete()
        elif resource._lifecycle.status != "consumed":
            raise ValueError("乘法资源未处于可完成状态。")
        self._completed_products.add(metadata.resource_id)

    def finish_products(self) -> None:
        if len(self._completed_products) != self._plan.triple_count:
            raise ValueError("Protocol 3 尚未完成全部乘法资源。")
        self._output = self._role.add(
            self._sharing,
            self._term_vector("C", self._role.layout.output_dimension),
            self._term_vector("D", self._role.layout.output_dimension),
        )
        self._raw_state = self._role.add(
            self._sharing,
            self._term_vector("A", self._role.layout.state_dimension),
            self._term_vector("B", self._role.layout.state_dimension),
        )
        if self._plan.truncation_count == 0:
            self._next_state = self._raw_state

    def mask_truncation(self, metadata: ResourceMetadata) -> TruncationMaskPayload:
        if self._raw_state is None:
            raise RuntimeError("必须先完成 state accumulator 才能截断。")
        resource = self._truncation_resource(metadata)
        if metadata.resource_id in self._truncation_state:
            raise ValueError("同一截断资源不得重复开始。")
        truncation = resource.truncation._lifecycle.owner
        raw = self._scalar_share(self._raw_state, metadata.index[0])
        masked = self._role.mask_truncation(truncation, raw, resource)
        self._truncation_state[metadata.resource_id] = (
            resource,
            truncation,
            masked,
            raw,
        )
        return TruncationMaskPayload(masked.value, self.party)

    def p2_truncation_message(
        self, metadata: ResourceMetadata, peer: TruncationMaskPayload
    ) -> P2TruncationPayload:
        if self.party != 1:
            raise ValueError("只有 P2 endpoint 可以发送截断消息。")
        _, truncation, masked, _ = self._truncation_entry(metadata)
        self._bind_truncation_peer(masked, peer)
        message = truncation.p2_send_masked(masked)
        return P2TruncationPayload(message.value)

    def p2_truncation_message_direct(self, metadata: ResourceMetadata) -> P2TruncationPayload:
        """生成唯一 P2→P1 截断消息；直连路径不传输 P1 的 masked share。"""
        if self.party != 1:
            raise ValueError("只有 P2 endpoint 可以发送截断消息。")
        _, truncation, masked, _ = self._truncation_entry(metadata)
        lifecycle = masked._lifecycle
        if 0 not in lifecycle.masked_parties:
            lifecycle.claim_mask(0)
        message = truncation.p2_send_masked(masked)
        return P2TruncationPayload(message.value)

    def finish_truncation_p1(
        self,
        metadata: ResourceMetadata,
        peer: TruncationMaskPayload,
        message: P2TruncationPayload,
    ) -> None:
        if self.party != 0 or not isinstance(message, P2TruncationPayload):
            raise ValueError("P1 endpoint 截断消息的角色或类型错误。")
        resource, truncation, masked, raw = self._truncation_entry(metadata)
        self._bind_truncation_peer(masked, peer)
        lifecycle = masked._lifecycle
        if not lifecycle.p2_sent:
            lifecycle.claim_p2_send()
        rebound = P2MaskedMessage(message.value, lifecycle)
        masked_value = truncation.p1_reconstruct_masked(masked, rebound)
        self._truncated_values[metadata.index[0]] = self._role.finish_truncation_p1(
            truncation, raw, resource, masked_value
        )

    def finish_truncation_p1_direct(
        self, metadata: ResourceMetadata, message: P2TruncationPayload
    ) -> None:
        """消费 P2→P1 截断消息；对端 masked 阶段只在本地 lifecycle 中确认。"""
        if self.party != 0 or not isinstance(message, P2TruncationPayload):
            raise ValueError("P1 endpoint 截断消息的角色或类型错误。")
        resource, truncation, masked, raw = self._truncation_entry(metadata)
        lifecycle = masked._lifecycle
        if 1 not in lifecycle.masked_parties:
            lifecycle.claim_mask(1)
        if not lifecycle.p2_sent:
            lifecycle.claim_p2_send()
        rebound = P2MaskedMessage(message.value, lifecycle)
        masked_value = truncation.p1_reconstruct_masked(masked, rebound)
        self._truncated_values[metadata.index[0]] = self._role.finish_truncation_p1(
            truncation, raw, resource, masked_value
        )

    def finish_truncation_p2(self, metadata: ResourceMetadata) -> None:
        if self.party != 1:
            raise ValueError("只有 P2 endpoint 可以完成 P2 截断分支。")
        resource, truncation, masked, raw = self._truncation_entry(metadata)
        lifecycle = masked._lifecycle
        if not lifecycle.p1_reconstructed:
            lifecycle.claim_p1_reconstruction()
        self._truncated_values[metadata.index[0]] = self._role.finish_truncation_p2(
            truncation, raw, resource
        )

    def complete_truncation(self, metadata: ResourceMetadata) -> None:
        resource, _, masked, _ = self._truncation_entry(metadata)
        lifecycle = masked._lifecycle
        if not lifecycle.consumed and 1 - self.party not in lifecycle.finished_parties:
            lifecycle.claim_finish(1 - self.party)
        if not lifecycle.consumed:
            raise ValueError("Protocol 2 两方尚未完成同一资源。")
        if resource._lifecycle.status == "prepared":
            if 1 - self.party not in resource._lifecycle.claimed_by:
                resource._lifecycle.claim(1 - self.party)
            resource._lifecycle.complete()
        elif resource._lifecycle.status != "consumed":
            raise ValueError("截断资源未处于可完成状态。")
        self._completed_truncations.add(metadata.resource_id)

    def stage_output(self) -> Protocol3StageReceipt:
        if self._output is None or self._raw_state is None:
            raise RuntimeError("Protocol 3 尚未完成乘法阶段。")
        if self._plan.truncation_count:
            if len(self._completed_truncations) != self._plan.truncation_count:
                raise ValueError("Protocol 3 尚未完成全部截断资源。")
            self._next_state = _vector_from_scalars(
                [self._truncated_values[row] for row in range(self._role.layout.state_dimension)]
            )
        if self._next_state is None:
            raise RuntimeError("Protocol 3 尚未形成待提交 state。")
        self._control_sender(
            ControlShareMessage(
                self.party,
                self._plan.session_id,
                self._plan.round_id,
                self._plan.step,
                self._role.layout.scale_ledger.output,
                self._output,
            )
        )
        self._staged = True
        return Protocol3StageReceipt(
            self.party,
            self._plan.session_id,
            self._plan.round_id,
            self._plan.step,
            self._plan.triple_count,
            self._plan.truncation_count,
        )

    def commit(self) -> None:
        if not self._staged or self._next_state is None:
            raise RuntimeError("Protocol 3 state 尚未暂存。")
        self._role.commit_state(self._next_state)
        self._staged = False

    def abort(self) -> None:
        """废弃本 endpoint 尚未完成的 protocol 资源，不提交 state。"""
        for resource in (*self._products.values(), *self._truncations.values()):
            resource._lifecycle.abort()
        self._staged = False

    def _product_resource(self, metadata: ResourceMetadata) -> ProductResourceShare:
        resource = self._products.get(metadata.resource_id)
        if not isinstance(resource, ProductResourceShare) or resource.metadata != metadata:
            raise ValueError("乘法资源与 Protocol 3 计划不匹配。")
        right_scale = (
            self._plan.scale_ledger.state
            if metadata.term in {"A", "C"}
            else self._plan.scale_ledger.input
        )
        left_scale = getattr(self._plan.scale_ledger, metadata.term)
        if (
            metadata.kind != "multiplication"
            or metadata.index not in self._expected_product_indices(metadata.term)
            or (
                metadata.left_fractional_bits,
                metadata.right_fractional_bits,
                metadata.output_fractional_bits,
            )
            != (left_scale, right_scale, left_scale + right_scale)
        ):
            raise ValueError("乘法资源的 term、index 或 scale 错误。")
        return resource

    def _truncation_resource(self, metadata: ResourceMetadata) -> StateTruncationResourceShare:
        resource = self._truncations.get(metadata.resource_id)
        ledger = self._plan.scale_ledger
        if (
            not isinstance(resource, StateTruncationResourceShare)
            or resource.metadata != metadata
            or metadata.kind != "state_truncation"
            or metadata.term != "state"
            or metadata.index not in {(row,) for row in range(self._role.layout.state_dimension)}
            or (
                metadata.left_fractional_bits,
                metadata.right_fractional_bits,
                metadata.output_fractional_bits,
            )
            != (ledger.state_accumulator, None, ledger.state)
        ):
            raise ValueError("截断资源的 row 或 scale 错误。")
        return resource

    def _product_entry(
        self, metadata: ResourceMetadata
    ) -> tuple[ProductResourceShare, BeaverMultiplier, MaskedDifferenceShare]:
        self._product_resource(metadata)
        entry = self._product_state.get(metadata.resource_id)
        if entry is None:
            raise RuntimeError("乘法资源尚未开始。")
        resource, multiplier, masked = entry
        if not isinstance(resource, ProductResourceShare):
            raise TypeError("乘法 endpoint 内部资源类型错误。")
        return resource, multiplier, masked

    def _truncation_entry(
        self, metadata: ResourceMetadata
    ) -> tuple[
        StateTruncationResourceShare,
        SecureTruncation,
        MaskedTruncationShare,
        AdditiveShare,
    ]:
        self._truncation_resource(metadata)
        entry = self._truncation_state.get(metadata.resource_id)
        if entry is None:
            raise RuntimeError("截断资源尚未开始。")
        resource, truncation, masked, raw = entry
        if not isinstance(resource, StateTruncationResourceShare):
            raise TypeError("截断 endpoint 内部资源类型错误。")
        return resource, truncation, masked, raw

    def _bind_truncation_peer(
        self, masked: MaskedTruncationShare, peer: TruncationMaskPayload
    ) -> None:
        other = 1 - self.party
        if not isinstance(peer, TruncationMaskPayload) or peer.party != other:
            raise ValueError("Protocol 2 对端遮蔽消息的角色错误。")
        lifecycle = masked._lifecycle
        if other not in lifecycle.masked_parties:
            lifecycle.claim_mask(other)

    def _term_vector(self, term: str, rows: int) -> AdditiveShare:
        return _vector_from_scalars([self._sums[(term, row)] for row in range(rows)])

    def _expected_product_indices(self, term: str) -> set[tuple[int, int]]:
        shapes = {
            "A": (self._role.layout.state_dimension, self._role.layout.state_dimension),
            "B": (self._role.layout.state_dimension, self._role.layout.input_dimension),
            "C": (self._role.layout.output_dimension, self._role.layout.state_dimension),
            "D": (self._role.layout.output_dimension, self._role.layout.input_dimension),
        }
        try:
            rows, columns = shapes[term]
        except KeyError as error:
            raise ValueError("矩阵项必须是通用 A、B、C 或 D。") from error
        return {(row, column) for row in range(rows) for column in range(columns)}

    @staticmethod
    def _resolve_sharing(resources: PartyResources) -> TwoPartySharing:
        products = resources.product_resources
        if not products:
            raise ValueError("Protocol 3 资源计划缺少必须存在的 D 项乘法。")
        multiplier = products[0].triple._lifecycle.owner
        if not isinstance(multiplier, BeaverMultiplier):
            raise TypeError("乘法资源未绑定 BeaverMultiplier。")
        return multiplier.sharing

    @staticmethod
    def _scalar_share(vector: AdditiveShare, row: int) -> AdditiveShare:
        value = np.asarray(vector.value, dtype=object)[row]
        return AdditiveShare(value.item() if isinstance(value, np.generic) else value)

    @staticmethod
    def _scalar(value: object, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} 必须是标量整数。")
        return value


def rehydrate_offline_material(
    material: PartyOfflineMaterial,
    range_contract: ControllerRangeContract,
) -> OfflineControllerMessage:
    """在 protocol 边界把单方 wire DTO 恢复为既有离线消息。"""
    if not isinstance(material, PartyOfflineMaterial):
        raise TypeError("material 必须是 PartyOfflineMaterial。")
    if not isinstance(range_contract, ControllerRangeContract):
        raise TypeError("range_contract 必须是 ControllerRangeContract。")
    return OfflineControllerMessage(
        material.recipient,
        material.session_id,
        material.controller,
        material.initial_state,
        material.layout,
        range_contract,
    )


def rehydrate_online_material(
    material: PartyOnlineMaterial,
    *,
    modulus: int,
    security_parameter: int,
    modulus_evidence: PrimeModulusEvidence | None = None,
) -> PartyOnlineRound:
    """以本地算术 owner 和全新 lifecycle 恢复单方在线材料。

    Wire 只提供数值 share 与不可变 identity；所有 consumed/owner 状态均在接收角色
    内重新建立，因此对端不能伪造资源已经完成或把旧 lifecycle 带入新 session。
    """
    if not isinstance(material, PartyOnlineMaterial):
        raise TypeError("material 必须是 PartyOnlineMaterial。")
    party = material.input_message.recipient
    if party not in {0, 1}:
        raise ValueError("在线材料 recipient 必须是 P1 或 P2。")
    plan = material.plan
    if (
        material.input_message.session_id,
        material.input_message.round_id,
        material.input_message.step,
    ) != (plan.session_id, plan.round_id, plan.step):
        raise ValueError("在线输入与资源计划 identity 不匹配。")
    if (
        len(material.product_resources) != plan.triple_count
        or len(material.state_truncation_resources) != plan.truncation_count
    ):
        raise ValueError("在线数值材料数量与资源计划不匹配。")

    sharing = TwoPartySharing(modulus)
    multiplier = BeaverMultiplier(sharing)
    truncation = SecureTruncation(
        sharing,
        ell=plan.scale_ledger.state,
        security_parameter=security_parameter,
        modulus_evidence=modulus_evidence,
    )
    # protocol 是既有 crypto lifecycle 的拥有边界；execution/wire 不实例化或传输私有对象。
    products: list[ProductResourceShare] = []
    for expected, item in zip(plan.product_resources, material.product_resources, strict=True):
        _validate_product_material(item, expected, party)
        triple_lifecycle = _TripleLifecycle(multiplier)
        triple = BeaverTripleShare(item.a, item.b, item.c, party, triple_lifecycle)
        products.append(ProductResourceShare(party, item.metadata, triple, _ResourceLifecycle()))

    truncations: list[StateTruncationResourceShare] = []
    for expected, item in zip(
        plan.state_truncation_resources, material.state_truncation_resources, strict=True
    ):
        _validate_truncation_material(item, expected, party)
        mask_lifecycle = _MaskLifecycle(truncation)
        auxiliary = TruncationAuxiliaryShare(item.r, item.r_prime, party, mask_lifecycle)
        truncations.append(
            StateTruncationResourceShare(party, item.metadata, auxiliary, _ResourceLifecycle())
        )
    resources = PartyResources(party, plan, tuple(products), tuple(truncations))
    return PartyOnlineRound(material.input_message, resources)


def _validate_product_material(
    material: ProductResourceMaterial, expected: ResourceMetadata, party: int
) -> None:
    if (
        not isinstance(material, ProductResourceMaterial)
        or material.owner != party
        or material.metadata != expected
        or expected.kind != "multiplication"
    ):
        raise ValueError("乘法 wire 材料的角色或 metadata 不匹配。")


def _validate_truncation_material(
    material: TruncationResourceMaterial, expected: ResourceMetadata, party: int
) -> None:
    if (
        not isinstance(material, TruncationResourceMaterial)
        or material.owner != party
        or material.metadata != expected
        or expected.kind != "state_truncation"
    ):
        raise ValueError("截断 wire 材料的角色或 metadata 不匹配。")


def dispatch_protocol3_command(
    endpoint: LocalProtocol3PartyEndpoint,
    command: Protocol3EndpointCommand,
) -> object | None:
    """执行一条已类型化 endpoint 命令，不拥有 Protocol 3 的完整消息顺序。"""
    if not isinstance(endpoint, LocalProtocol3PartyEndpoint):
        raise TypeError("endpoint 必须是 LocalProtocol3PartyEndpoint。")
    if not isinstance(command, Protocol3EndpointCommand):
        raise TypeError("command 必须是 Protocol3EndpointCommand。")
    operation = command.operation
    metadata = command.metadata
    if operation == "mask_product" and metadata is not None and _only(command, "metadata"):
        return endpoint.mask_product(metadata)
    if (
        operation == "finish_product"
        and metadata is not None
        and command.product_mask is not None
        and _only(command, "metadata", "product_mask")
    ):
        endpoint.finish_product(metadata, command.product_mask)
        return None
    if operation == "complete_product" and metadata is not None and _only(command, "metadata"):
        endpoint.complete_product(metadata)
        return None
    if operation == "finish_products" and _only(command):
        endpoint.finish_products()
        return None
    if operation == "mask_truncation" and metadata is not None and _only(command, "metadata"):
        return endpoint.mask_truncation(metadata)
    if (
        operation == "p2_truncation_message"
        and metadata is not None
        and command.truncation_mask is not None
        and _only(command, "metadata", "truncation_mask")
    ):
        return endpoint.p2_truncation_message(metadata, command.truncation_mask)
    if (
        operation == "finish_truncation_p1"
        and metadata is not None
        and command.truncation_mask is not None
        and command.p2_truncation is not None
        and _only(command, "metadata", "truncation_mask", "p2_truncation")
    ):
        endpoint.finish_truncation_p1(metadata, command.truncation_mask, command.p2_truncation)
        return None
    if operation == "finish_truncation_p2" and metadata is not None and _only(command, "metadata"):
        endpoint.finish_truncation_p2(metadata)
        return None
    if operation == "complete_truncation" and metadata is not None and _only(command, "metadata"):
        endpoint.complete_truncation(metadata)
        return None
    if operation == "stage_output" and _only(command):
        return endpoint.stage_output()
    if operation == "commit" and _only(command):
        endpoint.commit()
        return None
    raise ValueError(f"Protocol 3 endpoint 命令字段与操作不匹配：{operation}")


def dispatch_direct_protocol3_command(
    endpoint: DirectProtocol3PartyEndpoint,
    command: Protocol3EndpointCommand,
) -> Protocol3StageReceipt | None:
    """执行 share-free 调度命令；peer payload 仅由 direct endpoint 的 port 处理。"""
    if not isinstance(endpoint, DirectProtocol3PartyEndpoint):
        raise TypeError("endpoint 必须是 DirectProtocol3PartyEndpoint。")
    if not isinstance(command, Protocol3EndpointCommand):
        raise TypeError("command 必须是 Protocol3EndpointCommand。")
    operation = command.operation
    metadata = command.metadata
    if operation == "mask_product" and metadata is not None and _only(command, "metadata"):
        endpoint.mask_product(metadata)
        return None
    if operation == "finish_product" and metadata is not None and _only(command, "metadata"):
        endpoint.finish_product(metadata)
        return None
    if operation == "complete_product" and metadata is not None and _only(command, "metadata"):
        endpoint.complete_product(metadata)
        return None
    if operation == "finish_products" and _only(command):
        endpoint.finish_products()
        return None
    if operation == "mask_truncation" and metadata is not None and _only(command, "metadata"):
        endpoint.mask_truncation(metadata)
        return None
    if operation == "send_truncation" and metadata is not None and _only(command, "metadata"):
        endpoint.send_truncation(metadata)
        return None
    if operation == "finish_truncation_p1" and metadata is not None and _only(command, "metadata"):
        endpoint.finish_truncation_p1(metadata)
        return None
    if operation == "finish_truncation_p2" and metadata is not None and _only(command, "metadata"):
        endpoint.finish_truncation_p2(metadata)
        return None
    if operation == "complete_truncation" and metadata is not None and _only(command, "metadata"):
        endpoint.complete_truncation(metadata)
        return None
    if operation == "stage_output" and _only(command):
        return endpoint.stage_output()
    if operation == "commit" and _only(command):
        endpoint.commit()
        return None
    raise ValueError(f"直连 Protocol 3 endpoint 命令字段与操作不匹配：{operation}")


def _only(command: Protocol3EndpointCommand, *names: str) -> bool:
    populated = {
        name
        for name in ("metadata", "product_mask", "truncation_mask", "p2_truncation")
        if getattr(command, name) is not None
    }
    return populated == set(names)


class SingleProcessCoordinator:
    """协调本地消息投递与公开 masked 值；输出尺度由同一 round 的 ledger 决定。

    该类只是当前 transport/协调选择。它只能暂态配对 Beaver 遮蔽差值而得到允许公开
    的 ``d/e``，从不重构参数、state、input 或 control output；明文重构仅在 Client
    的显式边界发生。
    """

    def __init__(
        self, sharing: TwoPartySharing, multiplier: BeaverMultiplier, truncation: SecureTruncation
    ) -> None:
        """绑定同一 ``Z_q`` 下的既有算术原语，不保存 Client 或任何明文控制器。"""
        if not isinstance(sharing, TwoPartySharing):
            raise TypeError("sharing 必须是 TwoPartySharing。")
        if multiplier.sharing is not sharing or truncation.sharing is not sharing:
            raise ValueError("协调器与所有算术原语必须共享同一个 TwoPartySharing 实例。")
        self._sharing = sharing
        self._multiplier = multiplier
        self._truncation = truncation

    def execute(
        self, p1: P1, p2: P2, online: OnlineRound
    ) -> tuple[ControlShareMessage, ControlShareMessage]:
        """按 Protocol 3 执行 ``u=Cx+Dv`` 与 metadata 驱动的 state rescale。

        所有标量乘积按 ledger 声明的尺度完成行内加法；只有 state accumulator 比 state
        多 ``ell`` 位时，聚合后的每一行才使用一对 Trunc 随机量。输出不截断，保持 ledger
        的 output scale 直到 Client 解码。任意失败均废弃本轮未完成资源且不提交新 state。
        """
        output, _ = self._execute(p1, p2, online, capture_evidence=False)
        return output

    def execute_with_evidence(
        self, p1: P1, p2: P2, online: OnlineRound
    ) -> tuple[tuple[ControlShareMessage, ControlShareMessage], ProtocolStepSnapshot]:
        """执行同一 Protocol 3 路径，并复制诊断所需 share，不做任何重构。

        该入口只供显式 opt-in 的 execution 诊断使用。它不增加随机数、triple、mask
        或协议消息，只在现有计算点复制不可变快照，因此不能改变被诊断 round 的数值。
        """
        output, evidence = self._execute(p1, p2, online, capture_evidence=True)
        if evidence is None:
            raise RuntimeError("诊断执行未产生协议快照。")
        return output, evidence

    def _execute(
        self,
        p1: P1,
        p2: P2,
        online: OnlineRound,
        *,
        capture_evidence: bool,
    ) -> tuple[
        tuple[ControlShareMessage, ControlShareMessage],
        ProtocolStepSnapshot | None,
    ]:
        """共享普通/诊断执行实现，确保两条入口使用完全相同的协议顺序。"""
        first_endpoint: LocalProtocol3PartyEndpoint | None = None
        second_endpoint: LocalProtocol3PartyEndpoint | None = None
        try:
            self._validate_round(p1, p2, online)
            state_before = (
                (copy_share(p1.state_share), copy_share(p2.state_share))
                if capture_evidence
                else None
            )
            output_messages: list[ControlShareMessage] = []
            first_endpoint = LocalProtocol3PartyEndpoint(
                p1,
                PartyOnlineRound(online.p1_input, online.p1_resources),
                output_messages.append,
            )
            second_endpoint = LocalProtocol3PartyEndpoint(
                p2,
                PartyOnlineRound(online.p2_input, online.p2_resources),
                output_messages.append,
            )
            peer_inbox: dict[tuple[int, str, str], object] = {}
            direct_first = DirectProtocol3PartyEndpoint(
                first_endpoint, _InMemoryProtocol3PeerPort(0, peer_inbox)
            )
            direct_second = DirectProtocol3PartyEndpoint(
                second_endpoint, _InMemoryProtocol3PeerPort(1, peer_inbox)
            )
            orchestrator = Protocol3Orchestrator()
            orchestrator.stage(
                direct_first,
                direct_second,
                online.p1_resources.plan,
            )
            orchestrator.commit(direct_first, direct_second)
            if len(output_messages) != 2:
                raise RuntimeError("Protocol 3 未生成两条 control share 消息。")
            output = output_messages[0], output_messages[1]
            if not capture_evidence:
                return output, None
            if state_before is None:
                raise RuntimeError("诊断执行缺少更新前 state 快照。")
            snapshot = ProtocolStepSnapshot(
                session_id=online.session_id,
                round_id=online.round_id,
                step=online.step,
                plan=online.p1_resources.plan,
                input_p1=copy_share(first_endpoint.input_share),
                input_p2=copy_share(second_endpoint.input_share),
                output_p1=copy_share(first_endpoint.output_share),
                output_p2=copy_share(second_endpoint.output_share),
                state_before_p1=state_before[0],
                state_before_p2=state_before[1],
                state_accumulator_p1=copy_share(first_endpoint.raw_state_share),
                state_accumulator_p2=copy_share(second_endpoint.raw_state_share),
                state_after_p1=copy_share(first_endpoint.next_state_share),
                state_after_p2=copy_share(second_endpoint.next_state_share),
            )
            return output, snapshot
        except Exception:
            if first_endpoint is not None:
                first_endpoint.abort()
            if second_endpoint is not None:
                second_endpoint.abort()
            self._abort_round(online)
            raise

    def _validate_round(self, p1: P1, p2: P2, online: OnlineRound) -> None:
        """在资源 claim 前验证角色、session、round、shape、scale 及两方资源配对。"""
        if not isinstance(p1, P1) or not isinstance(p2, P2) or not isinstance(online, OnlineRound):
            raise TypeError("execute 需要 P1、P2 与 Client 准备的 OnlineRound。")
        if (
            p1.layout != p2.layout
            or p1.session_id != p2.session_id
            or p1.session_id != online.session_id
        ):
            raise ValueError("P1、P2 与 OnlineRound 必须绑定同一 controller session。")
        if any(
            (message.session_id, message.round_id, message.step)
            != (online.session_id, online.round_id, online.step)
            for message in (online.p1_input, online.p2_input)
        ):
            raise ValueError("在线输入必须绑定同一 session、round 与 step。")
        if (
            online.p1_resources.recipient != 0
            or online.p2_resources.recipient != 1
            or online.p1_resources.plan != online.p2_resources.plan
        ):
            raise ValueError("在线资源包的角色路由或资源计划不一致。")
        plan = online.p1_resources.plan
        if (plan.session_id, plan.round_id, plan.step) != (
            online.session_id,
            online.round_id,
            online.step,
        ):
            raise ValueError("资源计划必须绑定当前 session、round 与 step。")
        if (plan.state_shape, plan.input_shape, plan.output_shape) != (
            (p1.layout.state_dimension,),
            (p1.layout.input_dimension,),
            (p1.layout.output_dimension,),
        ) or plan.scale_ledger != p1.layout.scale_ledger:
            raise ValueError("资源计划的公开 shape 或 fractional bits 与控制器不匹配。")
        self._validate_resource_collection(
            online.p1_resources.product_resources,
            online.p2_resources.product_resources,
            plan.product_resources,
        )
        self._validate_resource_collection(
            online.p1_resources.state_truncation_resources,
            online.p2_resources.state_truncation_resources,
            plan.state_truncation_resources,
        )
        if any(
            resource.triple._lifecycle.owner is not self._multiplier
            for resource in (
                *online.p1_resources.product_resources,
                *online.p2_resources.product_resources,
            )
        ):
            raise ValueError("乘法资源不属于当前 coordinator 的 BeaverMultiplier。")
        if any(
            resource.truncation._lifecycle.owner is not self._truncation
            for resource in (
                *online.p1_resources.state_truncation_resources,
                *online.p2_resources.state_truncation_resources,
            )
        ):
            raise ValueError("截断资源不属于当前 coordinator 的 SecureTruncation。")

    def _validate_resource_collection(
        self, first: tuple[object, ...], second: tuple[object, ...], metadata: tuple[object, ...]
    ) -> None:
        """确认两方资源按同一 metadata 一一配对且全部仍处于 prepared 状态。"""
        if len(first) != len(metadata) or len(second) != len(metadata):
            raise ValueError("在线资源数量与资源计划不匹配。")
        for first_item, second_item, expected in zip(first, second, metadata, strict=True):
            if (
                (getattr(first_item, "owner", None), getattr(second_item, "owner", None)) != (0, 1)
                or getattr(first_item, "metadata", None) != expected
                or getattr(second_item, "metadata", None) != expected
                or getattr(first_item, "_lifecycle", None)
                is not getattr(second_item, "_lifecycle", None)
                or getattr(first_item, "_lifecycle", None).status != "prepared"
            ):
                raise ValueError("在线资源必须成对、同元数据且尚未使用。")

    def _abort_round(self, online: OnlineRound) -> None:
        """在任意失败路径废弃本轮全部未完成 triples/masks，阻止残留材料重放。"""
        if not isinstance(online, OnlineRound):
            return
        resources = (
            *online.p1_resources.product_resources,
            *online.p2_resources.product_resources,
            *online.p1_resources.state_truncation_resources,
            *online.p2_resources.state_truncation_resources,
        )
        for resource in resources:
            resource._lifecycle.abort()
