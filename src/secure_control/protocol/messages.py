"""领域无关两方控制协议的消息、份额与一次性资源契约。"""

from __future__ import annotations

from dataclasses import dataclass, field
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
    """描述共享控制器的公开维度与统一定点尺度。

    当前 crypto 原语的截断实例只支持一个 ``ell``，所以本协议核心要求状态、输入、
    输出和全部矩阵在同一个 ``Q<ell>`` 尺度中编码。该限制会在 Client 离线阶段
    显式检查，避免把不同 fractional bits 的乘积悄悄相加。
    """

    state_dimension: int
    input_dimension: int
    output_dimension: int
    fractional_bits: int


@dataclass(frozen=True, slots=True)
class ControllerShare:
    """一个 Server 持有的 ``A/B/C/D`` 本地参数份额，绝不包含另一方份额。"""

    A: AdditiveShare
    B: AdditiveShare
    C: AdditiveShare
    D: AdditiveShare


@dataclass(frozen=True, slots=True)
class OfflineControllerMessage:
    """Client 离线分发给单个 P1 或 P2 的参数和初态消息。"""

    recipient: PartyIndex
    controller: ControllerShare
    initial_state: AdditiveShare
    layout: ControllerLayout


@dataclass(frozen=True, slots=True)
class OfflineDistribution:
    """Client 保留的离线分发结果；两个 Server 只能各自接收其中一条消息。"""

    p1: OfflineControllerMessage
    p2: OfflineControllerMessage


@dataclass(frozen=True, slots=True)
class InputShareMessage:
    """Client 在线发送给一个参与方的 controller input ``v`` 本地份额。"""

    recipient: PartyIndex
    step: int
    value: AdditiveShare


@dataclass(frozen=True, slots=True)
class ResourceMetadata:
    """标记一个标量乘法资源属于哪一矩阵项及其公开 shape/scale 语义。"""

    resource_id: str
    step: int
    term: Literal["A", "B", "C", "D"]
    index: tuple[int, int]
    matrix_shape: tuple[int, int]
    fractional_bits: int


@dataclass(frozen=True, slots=True)
class StepResourcePlan:
    """列出一个通用状态空间 step 所需资源，供 Client 在离线预处理时计数。"""

    step: int
    state_shape: tuple[int]
    input_shape: tuple[int]
    output_shape: tuple[int]
    fractional_bits: int
    resources: tuple[ResourceMetadata, ...]

    @property
    def resource_count(self) -> int:
        """返回本 step 的标量 Beaver triple/Trunc mask 对数量。"""
        return len(self.resources)


class _ResourceLifecycle:
    """在协调器中绑定同一资源的两份本地材料，阻止重放或失败后再次使用。"""

    def __init__(self) -> None:
        self.claimed_by: set[int] = set()
        self.status = "prepared"

    def claim(self, party: PartyIndex) -> None:
        """登记参与方开始使用资源；只有一轮的两个对应角色可各登记一次。"""
        if self.status != "prepared" or party in self.claimed_by:
            raise ValueError("协议资源已经使用、完成或因失败失效，不能复用。")
        self.claimed_by.add(party)

    def complete(self) -> None:
        """只在双方均完成该标量协议后将资源永久标记为已消费。"""
        if self.status != "prepared" or self.claimed_by != {0, 1}:
            raise ValueError("协议资源必须由 P1 与 P2 各使用一次后才能完成。")
        self.status = "consumed"

    def abort(self) -> None:
        """使尚未完成的预处理材料失效，防止失败轮次被重试或拼接。"""
        if self.status == "prepared":
            self.status = "aborted"


@dataclass(frozen=True, slots=True)
class ScalarResourceShare:
    """一个 Server 的单项 triple 与 truncation mask；同一资源没有对方的数值份额。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    triple: BeaverTripleShare
    truncation: TruncationAuxiliaryShare
    _lifecycle: _ResourceLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class PartyResources:
    """Client 为一个 Server 准备的一轮一次性资源包。"""

    recipient: PartyIndex
    plan: StepResourcePlan
    resources: tuple[ScalarResourceShare, ...]

    @property
    def consumed_count(self) -> int:
        """返回已经由双方完整消费的逻辑资源数量。"""
        return sum(resource._lifecycle.status == "consumed" for resource in self.resources)

    @property
    def aborted_count(self) -> int:
        """返回因轮次失败而被不可恢复地废弃的逻辑资源数量。"""
        return sum(resource._lifecycle.status == "aborted" for resource in self.resources)


@dataclass(frozen=True, slots=True)
class OnlineRound:
    """Client 持有的一次在线输入和资源分发结果，不应整体交给任一 Server。"""

    step: int
    p1_input: InputShareMessage
    p2_input: InputShareMessage
    p1_resources: PartyResources
    p2_resources: PartyResources


@dataclass(frozen=True, slots=True)
class MaskedExchangeMessage:
    """模拟 P1↔P2 的 Beaver 遮蔽差值发送，保留发送、接收、step 与资源标识。"""

    sender: PartyIndex
    recipient: PartyIndex
    step: int
    resource_id: str
    value: MaskedDifferenceShare


@dataclass(frozen=True, slots=True)
class OpenedMaskedMessage:
    """协调器由两条遮蔽消息得到的公开 ``d/e``，不包含原始输入或状态明文。"""

    recipients: tuple[PartyIndex, PartyIndex]
    step: int
    resource_id: str
    value: PublicMaskedDifferences


@dataclass(frozen=True, slots=True)
class TruncationMaskedMessage:
    """Protocol 2 中 P2 发给 P1 的唯一 masked-value 消息及其路由元数据。"""

    sender: Literal[1]
    recipient: Literal[0]
    step: int
    resource_id: str
    value: P2MaskedMessage


@dataclass(frozen=True, slots=True)
class ControlShareMessage:
    """一个 Server 返回给 Client 的 control output 本地份额。"""

    sender: PartyIndex
    step: int
    value: AdditiveShare
