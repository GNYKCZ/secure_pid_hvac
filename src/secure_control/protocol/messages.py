"""领域无关两方控制协议的消息、公开范围契约与一次性资源模型。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields, is_dataclass
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
    "bounded_input_reachability",
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
    reachability_block_steps: int | None = None

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
        if self.reachability_block_steps is not None:
            if (type(self.reachability_block_steps) is not int
                    or not 1 <= self.reachability_block_steps <= 128):
                raise ValueError("reachability_block_steps 必须是 1…128 的整数")
            if self.horizon_steps is not None or self.closed_loop_evidence is not None:
                raise ValueError("bounded-input reachability 不得与其他范围证明模式混用")

    def validate_layout(self, layout: ControllerLayout) -> None:
        """确认公开范围长度覆盖已安装控制器的 state 与 input channel。"""
        if len(self.state_payload_bounds) != layout.state_dimension:
            raise ValueError("state_payload_bounds 的长度必须等于 state dimension。")
        if len(self.input_payload_bounds) != layout.input_dimension:
            raise ValueError("input_payload_bounds 的长度必须等于 input dimension。")

    @property
    def proof_mode(self) -> RangeProofMode:
        """返回当前契约明确选择的范围证明模式。"""
        if self.reachability_block_steps is not None:
            return "bounded_input_reachability"
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


@dataclass(frozen=True, slots=True)
class MatrixProductMetadata:
    """一个完整矩阵operation的公开身份，不冒充标量乘法索引。"""

    resource_id: str
    session_id: str
    round_id: str
    step: int
    rows: int
    inner: int

    def __post_init__(self):
        if (any(type(v) is not str or not v for v in
                (self.resource_id, self.session_id, self.round_id))
                or type(self.step) is not int or self.step < 0
                or any(type(v) is not int or v < 1 for v in (self.rows, self.inner))):
            raise ValueError("矩阵材料身份和维度必须准确且非布尔")


@dataclass(frozen=True, slots=True)
class MatrixStepResourcePlan:
    """D128-1同ell动态矩阵计划；旧triple_count接口不适用于本类型。"""

    session_id: str
    round_id: str
    step: int
    state_shape: tuple[int]
    input_shape: tuple[int]
    output_shape: tuple[int]
    scale_ledger: ControllerScaleLedger
    product_resources: tuple[MatrixProductMetadata]
    state_truncation_resources: tuple[ResourceMetadata, ...]
    version: str = "matrix-dynamic-plan-v1"
    arithmetic_profile: str = "matrix-beaver-v1"
    order: str = "row-major/state-first"

    def __post_init__(self):
        from secure_control.crypto.matrix_beaver import matrix_shape
        if (self.version != "matrix-dynamic-plan-v1" or self.arithmetic_profile != "matrix-beaver-v1"
                or self.order != "row-major/state-first" or type(self.step) is not int or self.step < 0
                or any(type(v) is not str or not v for v in (self.session_id, self.round_id))
                or any(type(s) is not tuple or len(s) != 1 or type(s[0]) is not int or s[0] < 1
                       for s in (self.state_shape, self.input_shape, self.output_shape))):
            raise ValueError("矩阵计划公开身份/维度/版本错误")
        n, m, p = self.state_shape[0], self.input_shape[0], self.output_shape[0]
        ledger = self.scale_ledger
        if (type(ledger) is not ControllerScaleLedger
                or any(type(getattr(ledger, name)) is not int for name in ledger.__dataclass_fields__)):
            raise TypeError("矩阵计划需要规范尺度账本")
        ell = ledger.state
        if (ell < 1 or any(getattr(ledger,k) != ell for k in ('input','A','B','C','D','state_truncation_bits'))
                or ledger.output != 2*ell):
            raise ValueError("矩阵首版只接受同ell动态布局")
        matrix_shape(n+p, n+m, 3)
        expected = MatrixProductMetadata(self.round_id+':matrix', self.session_id, self.round_id,
                                         self.step, n+p, n+m)
        if (type(self.product_resources) is not tuple or len(self.product_resources) != 1
                or type(self.product_resources[0]) is not MatrixProductMetadata
                or self.product_resources != (expected,)):
            raise ValueError("矩阵operation身份错误")
        truncations = tuple(ResourceMetadata(f'{self.round_id}:state[{i}]', self.session_id,
            self.round_id, self.step, 'state_truncation', 'state', (i,), (n,), 2*ell, None, ell)
            for i in range(n))
        # 仅精确不可变类型图可直接相等比较，避免False==0/1.0==1绕过旧JSON类型语义。
        # 其他输入保留原比较与异常，包括index/shape为list的历史兼容形式。
        if (type(self.state_truncation_resources) is not tuple
                or any(type(v) is not ResourceMetadata for v in self.state_truncation_resources)
                or (self.state_truncation_resources != truncations
                    if _deeply_immutable_public_plan(self)
                    else json.dumps([asdict(v) for v in self.state_truncation_resources], sort_keys=True)
                         != json.dumps([asdict(v) for v in truncations], sort_keys=True))):
            raise ValueError("矩阵状态截断计划错误")

    @property
    def matrix_products(self):
        return 1

    @property
    def scalar_equivalent_products(self):
        item = self.product_resources[0]
        return item.rows * item.inner

    @property
    def multiplication_material_elements(self):
        item = self.product_resources[0]
        return item.rows * item.inner + item.inner + item.rows

    @property
    def multiplication_mask_elements(self):
        item = self.product_resources[0]
        return item.rows * item.inner + item.inner

    @property
    def truncation_count(self):
        return len(self.state_truncation_resources)

    @property
    def fractional_bits(self):
        return self.scale_ledger.state


def product_operation_count(plan):
    """明确区分矩阵操作次数与旧标量三元组次数，不改变旧计数定义。"""
    if type(plan) is MatrixStepResourcePlan:
        return plan.matrix_products
    return plan.triple_count


_PUBLIC_PLAN_JSON_FIELDS = {kind: tuple(item.name for item in fields(kind))
                            for kind in (StepResourcePlan, ResourceMetadata, ControllerScaleLedger,
                                         MatrixStepResourcePlan, MatrixProductMetadata)}


def _deeply_immutable_public_plan(plan: StepResourcePlan) -> bool:
    """只证明确切 canonical 类型图的不可变性；兼容可变输入仍走原即时摘要。"""
    def immutable(value):
        kind = type(value)
        if kind in (str, int, type(None)):
            return True
        if kind is tuple:
            return all(immutable(item) for item in value)
        names = _PUBLIC_PLAN_JSON_FIELDS.get(kind)
        return names is not None and all(immutable(getattr(value, name)) for name in names)
    try:
        return type(plan) in (StepResourcePlan, MatrixStepResourcePlan) and immutable(plan)
    except RecursionError:
        # 不缓存非法循环；由未修改的 canonical 函数保持原失败类别。
        return False


def _public_plan_json_fields(value):
    """按标准JSON需求逐个投影公开记录，不预先复制整棵计划；只缓存有限类型的字段名。"""
    names = _PUBLIC_PLAN_JSON_FIELDS.get(type(value))
    if names is None:
        if not isinstance(value, type) and is_dataclass(value):
            names = tuple(item.name for item in fields(value))
        else:
            raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
    return {name: getattr(value, name) for name in names}


def public_step_plan_sha256(plan: StepResourcePlan) -> str:
    """仅绑定公开 layout、尺度、资源身份和顺序，不摘要秘密矩阵值。"""
    if not isinstance(plan, StepResourcePlan) and type(plan) is not MatrixStepResourcePlan:
        raise TypeError("批次计划需要 StepResourcePlan")
    # 旧asdict在循环记录进入JSON前即RecursionError；保持非法循环的失败类别。
    encoded = json.dumps(plan, default=_public_plan_json_fields, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False, check_circular=False).encode("utf-8")
    prefix = b"matrix-dynamic-plan-v1\0" if type(plan) is MatrixStepResourcePlan else b"control-batch-v1-plan\0"
    return sha256(prefix + encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class Protocol3BatchPayload:
    """Peer 单帧完整批次；数值仅限既有允许公开的遮蔽份额。"""

    phase: Literal["product", "product_complete", "truncation", "state_complete"]
    plan_sha256: str
    run_id: str | None
    epoch_id: str
    physical_step: int | None
    batch_index: int
    resource_ids: tuple[str, ...]
    products: tuple[ProductMaskPayload, ...] = ()
    truncations: tuple[P2TruncationPayload, ...] = ()
    version: Literal["control-batch-v1"] = "control-batch-v1"

    def __post_init__(self) -> None:
        if (self.version != "control-batch-v1"
                or self.phase not in {"product", "product_complete", "truncation",
                                      "state_complete"}
                or type(self.batch_index) is not int or self.batch_index < 0
                or not isinstance(self.plan_sha256, str)
                or len(self.plan_sha256) != 64
                or not isinstance(self.epoch_id, str) or not self.epoch_id
                or self.run_id is not None and (not isinstance(self.run_id, str)
                                                 or not self.run_id)
                or self.physical_step is not None and (
                    type(self.physical_step) is not int or self.physical_step < 0
                )
                or not isinstance(self.resource_ids, tuple)
                or any(not isinstance(item, str) or not item for item in self.resource_ids)
                or len(set(self.resource_ids)) != len(self.resource_ids)):
            raise ValueError("Protocol 3 批次身份不合法")
        if self.phase == "product":
            valid = (len(self.products) == len(self.resource_ids)
                     and not self.truncations
                     and all(type(item) in (ProductMaskPayload, MatrixMaskPayload) for item in self.products))
        elif self.phase == "truncation":
            valid = (len(self.truncations) == len(self.resource_ids)
                     and not self.products
                     and all(isinstance(item, P2TruncationPayload)
                             for item in self.truncations))
        else:
            valid = not self.products and not self.truncations
        if not valid:
            raise ValueError("Protocol 3 批次 shape、类型或阶段不匹配")


class _ResourceLifecycle:
    """绑定同一逻辑资源的两份局部材料，阻止跨会话、跨轮次或失败后的重放。"""

    # 每个逻辑资源仍拥有独立状态；固定字段只省实例字典，保留弱引用。
    __slots__ = ("__weakref__", "claimed_by", "client_attested", "peer_ready", "status")

    def __init__(self) -> None:
        self.claimed_by: set[int] = set()
        self.status = "prepared"
        self.client_attested = False
        self.peer_ready = False

    def accept_peer_ready(self, party):
        if self.status != "prepared" or self.claimed_by != {party}:
            raise ValueError("资源本方未领取或已失效")
        self.peer_ready = True
        self.status = "consumed"

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

    def attest_completion(self, party: PartyIndex) -> None:
        """可信 Client 确认双方暂存；保留本地实际领取集合，不伪造对端观察。"""
        if self.status != "prepared" or self.claimed_by != {party}:
            raise ValueError("仅单方已领取且未废弃的资源可以接受 Client 确认。")
        self.client_attested = True
        self.status = "consumed"

    def export(self) -> None:
        """移交到单方预送缓存；已导出并不代表实际计算已消费。"""
        if self.status != "prepared" or self.claimed_by:
            raise ValueError("已领取资源不能导出")
        self.status = "exported"


@dataclass(frozen=True, slots=True)
class ProductResourceShare:
    """一个 Server 的单项 Beaver triple share；结果尺度由公开 ledger 决定。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    triple: BeaverTripleShare
    _lifecycle: _ResourceLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class MatrixProductResourceShare:
    """单方矩阵三元组，独立类型及operation生命周期。"""

    owner: PartyIndex
    metadata: MatrixProductMetadata
    triple: object
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


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedOnlineResources:
    """输入无关的本机一次性能力；不属于 wire 类型，不能作为输出签发凭据。"""

    p1_resources: PartyResources
    p2_resources: PartyResources
    _owner: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _PreparedEncodedResources:
    """专属本地工人字节的父进程原始能力；不能 pickle 后恢复授权。"""

    plan: StepResourcePlan
    fragments: tuple[bytes, bytes] = field(repr=False)
    _owner: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)
    encoding_profile: str = "control-batch-v1"


@dataclass(frozen=True, slots=True)
class _EncodedInputRound:
    """测量后绑定的当前轮；仅有公开计划、输入份额和不透明静态字节。"""

    session_id: str
    round_id: str
    step: int
    p1_input: InputShareMessage
    p2_input: InputShareMessage
    prepared: _PreparedEncodedResources = field(repr=False)


@dataclass(frozen=True, slots=True)
class PreloadedResourceManifest:
    """有限预送窗口的公开身份；不携带数值材料或输出签发能力。"""

    run_id: str
    controller_epoch: str
    session_id: str
    batch_id: str
    start_step: int
    round_ids: tuple[str, ...]
    layout: ControllerLayout
    modulus: int
    stage_mode: Literal["staged", "fused"]
    block_steps: int
    version: Literal["control-preloaded-v1"] = "control-preloaded-v1"

    def __post_init__(self) -> None:
        if (self.version != "control-preloaded-v1"
                or self.stage_mode not in {"staged", "fused"}
                or type(self.start_step) is not int or self.start_step != 0
                or type(self.modulus) is not int or self.modulus < 3
                or not isinstance(self.layout, ControllerLayout)
                or not isinstance(self.round_ids, tuple) or not 1 <= len(self.round_ids) <= 1000
                or any(not isinstance(v, str) or len(v) != 38 or not v.startswith("round-")
                       or any(c not in "0123456789abcdef" for c in v[6:]) for v in self.round_ids)
                or len(set(self.round_ids)) != len(self.round_ids)
                or any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in (
                    self.run_id, self.controller_epoch, self.session_id, self.batch_id))):
            raise ValueError("预送 manifest 身份、模式或有限窗口无效")
        preloaded_material_budget(self.layout, self.modulus, len(self.round_ids), self.block_steps)

    def sha256(self) -> str:
        """启动时计算完整公开清单摘要，不在控制周期重复序列化1000轮清单。"""
        fields = asdict(self)
        fields["modulus"] = str(self.modulus)
        fields["derived"] = self.derived()
        return sha256(b"control-preloaded-v1-manifest\0" + json.dumps(
            fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")).hexdigest()

    def derived(self) -> dict[str, int]:
        budget = preloaded_material_budget(self.layout, self.modulus, len(self.round_ids), self.block_steps)
        return {"count": len(self.round_ids), **{name: budget[name] for name in (
            "products", "truncations", "residue_bytes", "row_bytes")}}


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedPreloadedResources:
    """Client 原始预送窗口能力；不进入 wire，不以拷贝替代本机登记。"""

    manifest: PreloadedResourceManifest
    _owner: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class PreloadedInputRound:
    """当前新测量的两份输入及原资源计划；只在 Client 内部同时持有两份。"""

    session_id: str
    round_id: str
    step: int
    p1_input: InputShareMessage
    p2_input: InputShareMessage
    plan: StepResourcePlan
    _owner: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ExportedPreloadedStep:
    """单轮新材料的移交值；不保留原Prepared能力和生命周期。"""

    plan: StepResourcePlan
    p1_values: tuple[int, ...] = field(repr=False)
    p2_values: tuple[int, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class PreloadReceipt:
    """单方启动清单、连续材料块或完整窗口的确认，协议边界独立校验。"""

    party: PartyIndex
    manifest_sha256: str
    phase: Literal["init", "block", "seal"]
    block_index: int | None
    first_step: int | None
    count: int

    def __post_init__(self):
        if (type(self.party) is not int or self.party not in (0, 1)
                or not isinstance(self.manifest_sha256, str) or len(self.manifest_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.manifest_sha256)
                or self.phase not in {"init", "block", "seal"}
                or type(self.count) is not int or not 1 <= self.count <= 1000
                or self.phase == "block" and (
                    type(self.block_index) is not int or self.block_index < 0
                    or type(self.first_step) is not int or self.first_step < 0 or self.count > 32)
                or self.phase != "block" and (self.block_index is not None or self.first_step is not None)):
            raise ValueError("预送回执身份、类型或区间无效")


def preloaded_material_budget(layout: ControllerLayout, modulus: int, count: int,
                              block_steps: int | None = None) -> dict[str, int]:
    """纯公开数据预算，先于身份、随机材料和缓存分配；编码预算不是RSS保证。"""
    if (not isinstance(layout, ControllerLayout) or type(modulus) is not int or modulus < 3
            or type(count) is not int or not 1 <= count <= 1000):
        raise ValueError("预送公开预算参数无效")
    n, m, p = layout.state_dimension, layout.input_dimension, layout.output_dimension
    if any(type(v) is not int or v < 1 for v in (n, m, p)):
        raise ValueError("预送只用于非零秘密状态控制器")
    products, truncations = n * n + n * m + p * n + p * m, n if layout.scale_ledger.state_truncation_bits else 0
    width = (modulus.bit_length() + 7) // 8
    row = width * (3 * products + 2 * truncations)
    if not 0 < row <= 128 * 1024 or count * row + (2 * 1024 + 256 + 512) * 1024 > 8 * 1024 * 1024:
        raise ValueError("预送缓存超出公开编码预算")
    digits = modulus.bit_length() * 30103 // 100000 + 1
    # 原canonical DTO的公开保守界仅预留当前一轮；块内不累积Prepared对象。
    generation = 2 * (products * (4096 + 12 * digits) + truncations * (4096 + 8 * digits)
                      + 4096 + 512 * m)
    maximum = min(32, 128 * 1024 // row)
    feasible = [v for v in range(1, maximum + 1)
                if 12 * v * row + 2 * generation + 128 * 1024 <= 2 * 1024 * 1024]
    if not feasible or generation > 512 * 1024:
        raise ValueError("预送临时编码副本超出预算")
    chosen = max(feasible) if block_steps is None else block_steps
    if type(chosen) is not int or chosen not in feasible:
        raise ValueError("预送块大小超出公开预算")
    return {"row_bytes": row, "residue_bytes": width, "products": products,
            "truncations": truncations, "block_steps": chosen, "cache_bytes": count * row,
            "scratch_bound_bytes": 12 * chosen * row + 2 * generation + 128 * 1024,
            "current_round_bound_bytes": generation}


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
class PartyOfflineMaterial:
    """可经显式 transport 发送的单方离线材料，不包含另一方 share。"""

    recipient: PartyIndex
    session_id: str
    controller: ControllerShare
    initial_state: AdditiveShare
    layout: ControllerLayout

    @classmethod
    def from_message(cls, message: OfflineControllerMessage) -> PartyOfflineMaterial:
        """从既有单方离线消息投影网络安全字段，排除运行时对象 identity。"""
        if not isinstance(message, OfflineControllerMessage):
            raise TypeError("message 必须是 OfflineControllerMessage。")
        return cls(
            message.recipient,
            message.session_id,
            message.controller,
            message.initial_state,
            message.layout,
        )


@dataclass(frozen=True, slots=True)
class ProductResourceMaterial:
    """一个角色的一份 Beaver 数值材料；lifecycle 必须在接收端重新建立。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    a: AdditiveShare
    b: AdditiveShare
    c: AdditiveShare


@dataclass(frozen=True, slots=True)
class MatrixProductMaterial:
    """矩阵材料wire DTO；不携带lifecycle或对方份额。"""

    owner: PartyIndex
    metadata: MatrixProductMetadata
    u: AdditiveShare
    v: AdditiveShare
    w: AdditiveShare


@dataclass(frozen=True, slots=True)
class TruncationResourceMaterial:
    """一个角色的一份 Trunc 数值材料；不信任 wire 上的消费状态。"""

    owner: PartyIndex
    metadata: ResourceMetadata
    r: AdditiveShare
    r_prime: AdditiveShare


@dataclass(frozen=True, slots=True)
class PartyOnlineMaterial:
    """单方在线 wire DTO，只含输入、公开计划和本方一次性数值材料。"""

    input_message: InputShareMessage
    plan: StepResourcePlan
    product_resources: tuple[ProductResourceMaterial, ...]
    state_truncation_resources: tuple[TruncationResourceMaterial, ...]

    @classmethod
    def from_round(cls, online: PartyOnlineRound) -> PartyOnlineMaterial:
        """投影单方在线 round，明确丢弃 Python lifecycle/owner object。"""
        if not isinstance(online, PartyOnlineRound):
            raise TypeError("online 必须是 PartyOnlineRound。")
        resources = online.resources
        if type(resources.plan) is MatrixStepResourcePlan:
            return cls(online.input_message, resources.plan,
                tuple(MatrixProductMaterial(item.owner, item.metadata, item.triple.u,
                                             item.triple.v, item.triple.w)
                      for item in resources.product_resources),
                tuple(TruncationResourceMaterial(item.owner, item.metadata,
                    item.truncation.r, item.truncation.r_prime)
                      for item in resources.state_truncation_resources))
        return cls(
            online.input_message,
            resources.plan,
            tuple(
                ProductResourceMaterial(
                    item.owner,
                    item.metadata,
                    item.triple.a,
                    item.triple.b,
                    item.triple.c,
                )
                for item in resources.product_resources
            ),
            tuple(
                TruncationResourceMaterial(
                    item.owner,
                    item.metadata,
                    item.truncation.r,
                    item.truncation.r_prime,
                )
                for item in resources.state_truncation_resources
            ),
        )


@dataclass(frozen=True, slots=True)
class ProductMaskPayload:
    """Protocol 1 单方遮蔽差值的 transport-neutral 表示。"""

    d: AdditiveShare
    e: AdditiveShare
    party: PartyIndex


@dataclass(frozen=True, slots=True)
class MatrixMaskPayload:
    """矩阵E_i/F_i掩码，不与标量d/e类型混用。"""

    e: AdditiveShare
    f: AdditiveShare
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


def _validate_stage_counts(plan_sha256: str, products: int, truncations: int) -> None:
    if (not isinstance(plan_sha256, str) or len(plan_sha256) != 64
            or any(char not in "0123456789abcdef" for char in plan_sha256)):
        raise ValueError("暂存计划摘要必须是 canonical SHA256。")
    if any(type(value) is not int or value < 0 for value in (products, truncations)):
        raise ValueError("暂存资源计数必须为严格非负整数。")


@dataclass(frozen=True, slots=True)
class Protocol3LocalStageReceipt:
    """仅证明本方算术与暂存完成；不声称对端完成或 state 已提交。"""

    party: PartyIndex
    session_id: str
    round_id: str
    step: int
    products: int
    truncations: int
    plan_sha256: str
    scope: Literal["local_staged"] = "local_staged"

    def __post_init__(self) -> None:
        if type(self.party) is not int or self.party not in (0, 1):
            raise ValueError("局部暂存角色必须是严格 int 0/1。")
        if any(not isinstance(value, str) or not value for value in (
                self.session_id, self.round_id)):
            raise ValueError("局部暂存身份不能为空。")
        if type(self.step) is not int or self.step < 0 or self.scope != "local_staged":
            raise ValueError("局部暂存 step 或 scope 不合法。")
        _validate_stage_counts(self.plan_sha256, self.products, self.truncations)


@dataclass(frozen=True, slots=True)
class Protocol3CommitAuthorization:
    """Client 验证两份局部回执及输出后签发的本轮提交授权。"""

    plan_sha256: str
    prepared_parties: tuple[PartyIndex, PartyIndex]
    products: int
    truncations: int

    def __post_init__(self) -> None:
        _validate_stage_counts(self.plan_sha256, self.products, self.truncations)
        if (type(self.prepared_parties) is not tuple or self.prepared_parties != (0, 1)
                or any(type(value) is not int for value in self.prepared_parties)):
            raise ValueError("提交授权必须确认严格的 P1/P2 两方。")


@dataclass(frozen=True, slots=True)
class MatrixLocalStageReceipt:
    """矩阵本方暂存；一个operation，不声称30份标量材料。"""

    party: PartyIndex
    session_id: str
    round_id: str
    step: int
    matrix_products: int
    truncations: int
    plan_sha256: str
    scope: str = "local_staged"

    def __post_init__(self):
        Protocol3LocalStageReceipt(self.party, self.session_id, self.round_id, self.step,
                                   self.matrix_products, self.truncations, self.plan_sha256, self.scope)
        if type(self.matrix_products) is not int or self.matrix_products != 1 or self.truncations < 1:
            raise ValueError("矩阵暂存计数错误")


@dataclass(frozen=True, slots=True)
class MatrixCommitAuthorization:
    """矩阵Client授权，仅接受精确矩阵计划与两方回执。"""

    plan_sha256: str
    prepared_parties: tuple[PartyIndex, PartyIndex]
    matrix_products: int
    truncations: int

    def __post_init__(self):
        Protocol3CommitAuthorization(self.plan_sha256, self.prepared_parties,
                                      self.matrix_products, self.truncations)
        if type(self.matrix_products) is not int or self.matrix_products != 1 or self.truncations < 1:
            raise ValueError("矩阵授权计数错误")


def receipt_operation_count(value):
    """回执的矩阵operation与标量product保持显式类型区别。"""
    if type(value) in (MatrixLocalStageReceipt, MatrixCommitAuthorization, MatrixClientStepResult):
        return value.matrix_products
    return value.products


def local_receipt_type(plan):
    return MatrixLocalStageReceipt if type(plan) is MatrixStepResourcePlan else Protocol3LocalStageReceipt


def commit_authorization_type(plan):
    return MatrixCommitAuthorization if type(plan) is MatrixStepResourcePlan else Protocol3CommitAuthorization


@dataclass(frozen=True, slots=True)
class MatrixClientStepResult:
    """Client完成双ACK后的矩阵结果；独立资源计数而非旧products。"""

    output: np.ndarray
    round_id: str
    step: int
    matrix_products: int
    truncations: int


@dataclass(frozen=True, slots=True)
class StepAdvancePermit:
    """可信Client仅授权当前步；不证明算术完成或输出已经检查。"""

    run_id: str
    session_id: str
    controller_epoch: str
    segment_index: int
    global_step: int
    round_id: str
    permit_id: str
    plan_sha256: str
    expected_state_version: int
    previous_physically_confirmed_count: int
    policy: str = "commit_after_both_ready"
    version: str = "control-dynamic-matrix-preauthorized-v1"

    def __post_init__(self):
        if (self.version != "control-dynamic-matrix-preauthorized-v1"
                or self.policy != "commit_after_both_ready"
                or any(type(v) is not str or not 1 <= len(v) <= 256 for v in
                       (self.run_id, self.session_id, self.controller_epoch, self.round_id))
                or type(self.permit_id) is not str or len(self.permit_id) != 32
                or any(c not in "0123456789abcdef" for c in self.permit_id)
                or any(type(v) is not int or v < 0 for v in (self.segment_index,
                    self.global_step, self.expected_state_version, self.previous_physically_confirmed_count))
                or self.global_step >= 1 << 64
                or self.expected_state_version != self.global_step
                or self.previous_physically_confirmed_count != self.global_step):
            raise ValueError("单步预授权身份/版本/物理前缀错误")
        _validate_stage_counts(self.plan_sha256, 1, 0)


@dataclass(frozen=True, slots=True)
class ReadyReceipt:
    """本方实际暂存事实；不含对方秘密份额或其摘要。"""

    permit: StepAdvancePermit
    party: int
    truncations: int
    matrix_products: int = 1
    scope: str = "local_staged"

    def __post_init__(self):
        if (type(self.permit) is not StepAdvancePermit
                or type(self.party) is not int or self.party not in (0, 1)
                or type(self.matrix_products) is not int or self.matrix_products != 1
                or type(self.truncations) is not int or self.truncations < 1
                or self.scope != "local_staged"):
            raise ValueError("READY角色/计数/范围错误")


@dataclass(frozen=True, slots=True)
class CommittedStepReply:
    """真实提交后的回执；输出子块延迟解码，坏输出不能抹掉提交事实。"""

    ready: ReadyReceipt
    peer_ready: ReadyReceipt
    state_version: int
    cumulative_committed_count: int
    output: bytes = field(repr=False)
    commit_status: str = "committed"

    def __post_init__(self):
        if (type(self.ready) is not ReadyReceipt or type(self.peer_ready) is not ReadyReceipt
                or self.peer_ready.permit != self.ready.permit
                or self.peer_ready.party != 1-self.ready.party
                or self.peer_ready.truncations != self.ready.truncations
                or self.commit_status != "committed"
                or any(type(v) is not int or v != self.ready.permit.global_step+1
                       for v in (self.state_version, self.cumulative_committed_count))
                or type(self.output) is not bytes or not 1 <= len(self.output) <= 512*1024):
            raise ValueError("最终回执缺少匹配的双方READY或真实提交版本")


Protocol3Operation = Literal[
    "stage_batch",
    "mask_product",
    "finish_product",
    "complete_product",
    "finish_products",
    "mask_truncation",
    "send_truncation",
    "p2_truncation_message",
    "finish_truncation_p1",
    "finish_truncation_p2",
    "complete_truncation",
    "stage_output",
    "commit",
    "commit_staged",
]


@dataclass(frozen=True, slots=True)
class Protocol3EndpointCommand:
    """一条 transport-neutral endpoint 命令；完整顺序仍由 orchestrator 拥有。"""

    operation: Protocol3Operation
    metadata: ResourceMetadata | None = None
    product_mask: ProductMaskPayload | None = None
    truncation_mask: TruncationMaskPayload | None = None
    p2_truncation: P2TruncationPayload | None = None
    authorization: Protocol3CommitAuthorization | None = None


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
