"""领域无关两方控制协议的消息、公开范围契约与一次性资源模型。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from numbers import Integral
from typing import Any, Literal

import numpy as np

from secure_control.core import (
    EllipsoidalInvariantWitness,
    RationalValue,
    RobustAffineInvariantProblem,
)
from secure_control.crypto import (
    AdditiveShare,
    BeaverTripleShare,
    MaskedDifferenceShare,
    P2MaskedMessage,
    PublicMaskedDifferences,
    TruncationAuxiliaryShare,
)

_PROTOCOL3_TERM_ORDER = ("C", "D", "A", "B")

PartyIndex = Literal[0, 1]
RangeProofMode = Literal[
    "finite_horizon",
    "independent_input_invariant",
    "closed_loop_invariant",
]


@dataclass(frozen=True, slots=True)
class ControllerScaleLedger:
    """冻结一次控制递推中各 operand、accumulator、Trunc 与输出的公开尺度。

    首版协议要求 state/input 使用同一基础 ``ell``。state accumulator 只能保持原尺度
    或比 state 多 ``ell`` 位；前者无需 Trunc，后者恰好执行一次 Protocol 2。output
    不执行截断，因此 Cx 与 Dv 必须直接具有声明的 output 尺度。
    """

    state: int
    input: int
    A: int
    B: int
    C: int
    D: int
    state_accumulator: int
    state_truncation_bits: int
    output_accumulator: int
    output: int

    def __post_init__(self) -> None:
        """在任何分享或资源创建前拒绝负尺度和不相容的乘积账本。"""
        names = (
            "state",
            "input",
            "A",
            "B",
            "C",
            "D",
            "state_accumulator",
            "state_truncation_bits",
            "output_accumulator",
            "output",
        )
        for name in names:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, Integral) or value < 0:
                raise ValueError(f"{name} scale 必须是非负整数。")

        if self.state != self.input:
            raise ValueError("首版 scale ledger 要求 state/input 使用同一基础 ell。")
        if self.A + self.state != self.B + self.input:
            raise ValueError("A*x 与 B*v 的 state products 必须具有相同 accumulator scale。")
        if self.state_accumulator != self.A + self.state:
            raise ValueError("state accumulator scale 与 A*x/B*v 乘积尺度不一致。")
        if self.state_accumulator - self.state != self.state_truncation_bits:
            raise ValueError("state Trunc shift 必须等于 accumulator 与 state 的尺度差。")
        if self.state_truncation_bits not in {0, self.state}:
            raise ValueError("首版 state Trunc shift 只支持 0 或基础 ell。")

        if self.C + self.state != self.D + self.input:
            raise ValueError("C*x 与 D*v 的 output accumulator scale 必须一致。")
        if self.output_accumulator != self.C + self.state or self.output != self.output_accumulator:
            raise ValueError("声明的 output 必须等于未经截断的 output accumulator scale。")


@dataclass(frozen=True, slots=True)
class ControllerLayout:
    """描述共享控制器的公开维度与完整尺度账本。"""

    state_dimension: int
    input_dimension: int
    output_dimension: int
    scale_ledger: ControllerScaleLedger

    @property
    def fractional_bits(self) -> int:
        """返回兼容 #10 API 的基础 state/input ``ell``。"""
        return self.scale_ledger.state


@dataclass(frozen=True, slots=True)
class ClosedLoopAffineComposition:
    """声明控制器与外部仿射系统如何共同生成完整闭环问题。

    设证书状态为 ``z``、扰动为 ``w``，本记录公开
    ``v=Lz+l+Mw`` 与 ``z_e+=Fz+f+Gw+Hu``。Client 使用已安装控制器的
    ``A/B/C/D`` 精确重建完整 ``z+``，从而不能把无关的稳定问题附到控制器上。
    字段只表达通用仿射组合，不含任何场景或物理量语义。
    """

    controller_state_indices: tuple[int, ...]
    external_state_indices: tuple[int, ...]
    input_state_matrix: tuple[tuple[RationalValue, ...], ...]
    input_affine: tuple[RationalValue, ...]
    input_disturbance_matrix: tuple[tuple[RationalValue, ...], ...]
    external_transition: tuple[tuple[RationalValue, ...], ...]
    external_affine: tuple[RationalValue, ...]
    external_disturbance_matrix: tuple[tuple[RationalValue, ...], ...]
    output_injection: tuple[tuple[RationalValue, ...], ...]

    def __post_init__(self) -> None:
        """拒绝负索引和非精确有理数，矩阵维数由 Client 结合控制器复验。"""
        for name in ("controller_state_indices", "external_state_indices"):
            indices = getattr(self, name)
            if any(
                isinstance(value, bool) or not isinstance(value, Integral) or value < 0
                for value in indices
            ):
                raise ValueError(f"{name} 必须是非负整数 tuple")
            object.__setattr__(self, name, tuple(int(value) for value in indices))
        vectors = (self.input_affine, self.external_affine)
        matrices = (
            self.input_state_matrix,
            self.input_disturbance_matrix,
            self.external_transition,
            self.external_disturbance_matrix,
            self.output_injection,
        )
        if any(not isinstance(value, RationalValue) for vector in vectors for value in vector):
            raise TypeError("closed-loop composition 向量必须使用 RationalValue")
        if any(
            not isinstance(value, RationalValue)
            for matrix in matrices
            for row in matrix
            for value in row
        ):
            raise TypeError("closed-loop composition 矩阵必须使用 RationalValue")


def closed_loop_composition_sha256(composition: ClosedLoopAffineComposition) -> str:
    """返回带版本域分离的规范组合记录 SHA-256。"""
    if not isinstance(composition, ClosedLoopAffineComposition):
        raise TypeError("composition 必须是 ClosedLoopAffineComposition")
    encoded = json.dumps(
        asdict(composition),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(b"secure_control.protocol.closed_loop_composition.v1\0" + encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ClosedLoopRangeEvidence:
    """绑定通用闭环不变集证书、controller 指纹和 payload 投影。"""

    problem: RobustAffineInvariantProblem
    witness: EllipsoidalInvariantWitness
    certificate_sha256: str
    controller_fingerprint: str
    controller_state_indices: tuple[int, ...]
    state_payload_bounds: tuple[int, ...]
    input_payload_bounds: tuple[int, ...]
    composition: ClosedLoopAffineComposition | None = None
    composition_sha256: str | None = None

    def __post_init__(self) -> None:
        """冻结索引与摘要格式，详细数学复验由 Client 在分享前完成。"""
        for name in ("certificate_sha256", "controller_fingerprint"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f"{name} 必须是 64 字符 SHA-256")
            try:
                int(value, 16)
            except ValueError as error:
                raise ValueError(f"{name} 必须是十六进制 SHA-256") from error
        indices = self.controller_state_indices
        if any(
            isinstance(value, bool) or not isinstance(value, Integral) or value < 0
            for value in indices
        ):
            raise ValueError("controller_state_indices 必须是非负整数 tuple")
        object.__setattr__(self, "controller_state_indices", tuple(int(value) for value in indices))
        for name in ("state_payload_bounds", "input_payload_bounds"):
            values = getattr(self, name)
            if any(
                isinstance(value, bool) or not isinstance(value, Integral) or value < 0
                for value in values
            ):
                raise ValueError(f"{name} 必须是非负整数 tuple")
            object.__setattr__(self, name, tuple(int(value) for value in values))
        if self.composition is not None and not isinstance(
            self.composition, ClosedLoopAffineComposition
        ):
            raise TypeError("composition 必须是 ClosedLoopAffineComposition 或 None")
        if self.composition_sha256 is not None:
            if not isinstance(self.composition_sha256, str) or len(self.composition_sha256) != 64:
                raise ValueError("composition_sha256 必须是 64 字符 SHA-256")
            try:
                int(self.composition_sha256, 16)
            except ValueError as error:
                raise ValueError("composition_sha256 必须是十六进制 SHA-256") from error


@dataclass(frozen=True, slots=True)
class ControllerRangeVerification:
    """保存离线分享前完成的不可变范围验证摘要。"""

    proof_mode: RangeProofMode
    certificate_sha256: str | None
    state_accumulator_bounds: tuple[int, ...]
    output_accumulator_bounds: tuple[int, ...]
    centered_modulus_limit: int
    maximum_truncation_message: int


@dataclass(frozen=True, slots=True)
class ControllerRangeContract:
    """以编码 payload 的绝对值声明输入与 state 的公开范围。

    默认要求无限时域不变界；显式给出 ``horizon_steps`` 时，仅证明该有限步数
    内的状态、乘积和输出，并在在线阶段拒绝超出已证明时域的 round。
    """

    state_payload_bounds: tuple[int, ...]
    input_payload_bounds: tuple[int, ...]
    horizon_steps: int | None = None
    closed_loop_evidence: ClosedLoopRangeEvidence | None = None

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
        if self.horizon_steps is not None:
            if (
                isinstance(self.horizon_steps, bool)
                or not isinstance(self.horizon_steps, Integral)
                or self.horizon_steps <= 0
            ):
                raise ValueError("horizon_steps 必须是正整数或 None。")
            object.__setattr__(self, "horizon_steps", int(self.horizon_steps))
        if self.closed_loop_evidence is not None and not isinstance(
            self.closed_loop_evidence, ClosedLoopRangeEvidence
        ):
            raise TypeError("closed_loop_evidence 必须是 ClosedLoopRangeEvidence 或 None")
        if self.horizon_steps is not None and self.closed_loop_evidence is not None:
            raise ValueError("finite horizon 与 closed-loop invariant 证据不得同时声明")

    def validate_layout(self, layout: ControllerLayout) -> None:
        """确认公开范围长度覆盖已安装控制器的 state 与 input channel。"""
        if len(self.state_payload_bounds) != layout.state_dimension:
            raise ValueError("state_payload_bounds 的长度必须等于 state dimension。")
        if len(self.input_payload_bounds) != layout.input_dimension:
            raise ValueError("input_payload_bounds 的长度必须等于 input dimension。")

    @property
    def proof_mode(self) -> RangeProofMode:
        """返回当前契约明确选择的三种证明模式之一。"""
        if self.horizon_steps is not None:
            return "finite_horizon"
        if self.closed_loop_evidence is not None:
            return "closed_loop_invariant"
        return "independent_input_invariant"


def controller_payload_fingerprint(
    payloads: Mapping[str, np.ndarray], layout: ControllerLayout
) -> str:
    """规范化编码后的 A/B/C/D/x0 与完整 ledger，返回稳定 SHA-256。"""
    if set(payloads) != {"A", "B", "C", "D", "x0"}:
        raise ValueError("controller payload fingerprint 字段必须恰为 A/B/C/D/x0")

    def encoded_array(value: Any) -> dict[str, Any]:
        array = np.asarray(value, dtype=object)
        return {
            "shape": list(array.shape),
            "values": [int(item) for item in array.flat],
        }

    ledger = layout.scale_ledger
    payload = {
        "controller": {name: encoded_array(payloads[name]) for name in ("A", "B", "C", "D", "x0")},
        "layout": {
            "state_dimension": layout.state_dimension,
            "input_dimension": layout.input_dimension,
            "output_dimension": layout.output_dimension,
            "scale_ledger": {name: getattr(ledger, name) for name in ledger.__dataclass_fields__},
        },
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


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
    left_fractional_bits: int
    right_fractional_bits: int | None
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
    scale_ledger: ControllerScaleLedger
    product_resources: tuple[ResourceMetadata, ...]
    state_truncation_resources: tuple[ResourceMetadata, ...]

    @property
    def fractional_bits(self) -> int:
        """返回兼容 #10 API 的基础 state/input ``ell``。"""
        return self.scale_ledger.state

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
    """一个 Server 的单项 Beaver triple share；结果尺度由公开 ledger 决定。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    triple: BeaverTripleShare
    _lifecycle: _ResourceLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class StateTruncationResourceShare:
    """一个 Server 的 state 行截断随机量 share；只用于需要缩放的聚合状态和。"""

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
class PartyOnlineRound:
    """Client 交给单个角色的输入与本方资源，不包含对方任何 share。"""

    input_message: InputShareMessage
    resources: PartyResources


@dataclass(frozen=True, slots=True)
class ProductMaskPayload:
    """Protocol 1 单方遮蔽差值的 transport-neutral 表示。"""

    d: AdditiveShare
    e: AdditiveShare
    party: PartyIndex


@dataclass(frozen=True, slots=True)
class TruncationMaskPayload:
    """Protocol 2 单方遮蔽份额的 transport-neutral 表示。"""

    value: AdditiveShare
    party: PartyIndex


@dataclass(frozen=True, slots=True)
class P2TruncationPayload:
    """P2 发给 P1 的截断消息表示，不携带进程内 lifecycle identity。"""

    value: AdditiveShare


@dataclass(frozen=True, slots=True)
class Protocol3StageReceipt:
    """角色完成 Protocol 3 暂存后返回的公开、无 share 回执。"""

    party: PartyIndex
    session_id: str
    round_id: str
    step: int
    products: int
    truncations: int


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
    """一个 Server 返回给 Client 的 ledger 输出尺度 share，绑定同一 session/round。"""

    sender: PartyIndex
    session_id: str
    round_id: str
    step: int
    fractional_bits: int
    value: AdditiveShare
