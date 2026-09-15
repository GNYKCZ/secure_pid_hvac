"""领域无关两方控制协议的消息、公开范围契约与一次性资源模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from numbers import Integral
from typing import Literal

from secure_control.crypto import (
    AdditiveShare,
    BeaverTripleShare,
    MaskedDifferenceShare,
    P2MaskedMessage,
    PublicMaskedDifferences,
    TruncationAuxiliaryShare,
)

PartyIndex = Literal[0, 1]


@dataclass(frozen=True, slots=True)
class ControllerLayout:
    """描述共享控制器的公开维度与统一 ``Q<ell>`` 定点尺度。"""

    state_dimension: int
    input_dimension: int
    output_dimension: int
    fractional_bits: int


@dataclass(frozen=True, slots=True)
class ControllerRangeContract:
    """以编码 payload 的绝对值声明输入与 state 的公开无限时域范围。"""

    state_payload_bounds: tuple[int, ...]
    input_payload_bounds: tuple[int, ...]

    def __post_init__(self) -> None:
        """拒绝负数、布尔值和非整数范围，避免将实数界误作编码 payload。"""
        for name in ("state_payload_bounds", "input_payload_bounds"):
            values = getattr(self, name)
            if not isinstance(values, tuple):
                raise TypeError(f"{name} 必须是整数 tuple。")
            normalized: list[int] = []
            for value in values:
                if isinstance(value, bool) or not isinstance(value, Integral) or value < 0:
                    raise ValueError(f"{name} 必须只包含非负整数 payload 上界。")
                normalized.append(int(value))
            object.__setattr__(self, name, tuple(normalized))

    def validate_layout(self, layout: ControllerLayout) -> None:
        """确认公开范围长度覆盖已安装控制器的 state 与 input channel。"""
        if len(self.state_payload_bounds) != layout.state_dimension:
            raise ValueError("state_payload_bounds 的长度必须等于 state dimension。")
        if len(self.input_payload_bounds) != layout.input_dimension:
            raise ValueError("input_payload_bounds 的长度必须等于 input dimension。")


@dataclass(frozen=True, slots=True)
class ControllerShare:
    """一个 Server 持有的 ``A/B/C/D`` 本地参数份额，绝不包含另一方份额。"""

    A: AdditiveShare
    B: AdditiveShare
    C: AdditiveShare
    D: AdditiveShare


@dataclass(frozen=True, slots=True)
class OfflineControllerMessage:
    """Client 离线分发给单个参与方的参数、初态和 controller session 标识。"""

    recipient: PartyIndex
    session_id: str
    controller: ControllerShare
    initial_state: AdditiveShare
    layout: ControllerLayout
    range_contract: ControllerRangeContract


@dataclass(frozen=True, slots=True)
class OfflineDistribution:
    """Client 保留的一次离线分发；两个 Server 只能接收同一 session 的各自消息。"""

    session_id: str
    range_contract: ControllerRangeContract
    p1: OfflineControllerMessage
    p2: OfflineControllerMessage


@dataclass(frozen=True, slots=True)
class InputShareMessage:
    """Client 在线发送给单个参与方的 input share，绑定 controller session 与唯一 round。"""

    recipient: PartyIndex
    session_id: str
    round_id: str
    step: int
    value: AdditiveShare


@dataclass(frozen=True, slots=True)
class ResourceMetadata:
    """标记一次乘法或 state 截断资源的公开索引、shape、scale 与会话身份。"""

    resource_id: str
    session_id: str
    round_id: str
    step: int
    kind: Literal["multiplication", "state_truncation"]
    term: Literal["A", "B", "C", "D", "state"]
    index: tuple[int, ...]
    shape: tuple[int, ...]
    input_fractional_bits: int
    output_fractional_bits: int


@dataclass(frozen=True, slots=True)
class StepResourcePlan:
    """列出一个 Protocol 3 step 的 triples 与每个 state 行的一次截断资源。"""

    session_id: str
    round_id: str
    step: int
    state_shape: tuple[int]
    input_shape: tuple[int]
    output_shape: tuple[int]
    fractional_bits: int
    product_resources: tuple[ResourceMetadata, ...]
    state_truncation_resources: tuple[ResourceMetadata, ...]

    @property
    def triple_count(self) -> int:
        """返回 A/B/C/D 所有标量乘法各自所需的 Beaver triple 数量。"""
        return len(self.product_resources)

    @property
    def truncation_count(self) -> int:
        """返回 state 向量逐元素截断所需的新鲜 ``r/r'`` 对数量。"""
        return len(self.state_truncation_resources)


class _ResourceLifecycle:
    """绑定同一逻辑资源的两份局部材料，阻止跨会话、跨轮次或失败后的重放。"""

    def __init__(self) -> None:
        self.claimed_by: set[int] = set()
        self.status = "prepared"

    def claim(self, party: PartyIndex) -> None:
        """登记某一角色开始使用资源；每轮仅允许 P1/P2 各一次。"""
        if self.status != "prepared" or party in self.claimed_by:
            raise ValueError("协议资源已经使用、完成或因失败失效，不能复用。")
        self.claimed_by.add(party)

    def complete(self) -> None:
        """仅在双方均完成对应子协议后永久消费资源。"""
        if self.status != "prepared" or self.claimed_by != {0, 1}:
            raise ValueError("协议资源必须由 P1 与 P2 各使用一次后才能完成。")
        self.status = "consumed"

    def abort(self) -> None:
        """废弃未完成资源，使失败 round 无法拼接或重试。"""
        if self.status == "prepared":
            self.status = "aborted"


@dataclass(frozen=True, slots=True)
class ProductResourceShare:
    """一个 Server 的单项 Beaver triple share；结果保持 ``2^(2ell)`` 尺度。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    triple: BeaverTripleShare
    _lifecycle: _ResourceLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class StateTruncationResourceShare:
    """一个 Server 的 state 行截断随机量 share；只用于聚合后的双尺度状态和。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    truncation: TruncationAuxiliaryShare
    _lifecycle: _ResourceLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class PartyResources:
    """Client 为单个参与方准备的一轮 triples 与 state truncation resources。"""

    recipient: PartyIndex
    plan: StepResourcePlan
    product_resources: tuple[ProductResourceShare, ...]
    state_truncation_resources: tuple[StateTruncationResourceShare, ...]

    @property
    def consumed_count(self) -> int:
        """返回已由双方完整消费的所有逻辑资源数量。"""
        resources = (*self.product_resources, *self.state_truncation_resources)
        return sum(resource._lifecycle.status == "consumed" for resource in resources)

    @property
    def aborted_count(self) -> int:
        """返回因当前 round 失败而不可恢复地废弃的资源数量。"""
        resources = (*self.product_resources, *self.state_truncation_resources)
        return sum(resource._lifecycle.status == "aborted" for resource in resources)


@dataclass(frozen=True, slots=True)
class OnlineRound:
    """Client 准备的唯一在线 round；不得整体交给任一 Server。"""

    session_id: str
    round_id: str
    step: int
    p1_input: InputShareMessage
    p2_input: InputShareMessage
    p1_resources: PartyResources
    p2_resources: PartyResources


@dataclass(frozen=True, slots=True)
class MaskedExchangeMessage:
    """模拟 P1↔P2 的 Beaver 遮蔽差值发送，绑定 session、round、step 与资源。"""

    sender: PartyIndex
    recipient: PartyIndex
    session_id: str
    round_id: str
    step: int
    resource_id: str
    value: MaskedDifferenceShare


@dataclass(frozen=True, slots=True)
class OpenedMaskedMessage:
    """协调器由两条遮蔽消息得到的公开 ``d/e``；不包含原始输入或 state 明文。"""

    recipients: tuple[PartyIndex, PartyIndex]
    session_id: str
    round_id: str
    step: int
    resource_id: str
    value: PublicMaskedDifferences


@dataclass(frozen=True, slots=True)
class TruncationMaskedMessage:
    """Protocol 2 中 P2 发给 P1 的唯一 masked-value 消息及其 session/round 路由。"""

    sender: Literal[1]
    recipient: Literal[0]
    session_id: str
    round_id: str
    step: int
    resource_id: str
    value: P2MaskedMessage


@dataclass(frozen=True, slots=True)
class ControlShareMessage:
    """一个 Server 返回给 Client 的双尺度 control share，绑定同一 session/round。"""

    sender: PartyIndex
    session_id: str
    round_id: str
    step: int
    fractional_bits: int
    value: AdditiveShare
