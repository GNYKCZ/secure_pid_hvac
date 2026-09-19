"""协议真实执行中产生的领域无关诊断快照与重构证据。"""

from __future__ import annotations

from dataclasses import dataclass
from numbers import Integral

import numpy as np

from secure_control.crypto import AdditiveShare

from .messages import StepResourcePlan


def _integer_tuple(value: object, name: str) -> tuple[int, ...]:
    """复制一维任意精度整数，避免诊断对象继续引用协议内部数组。"""
    array = np.asarray(value, dtype=object)
    if array.ndim != 1:
        raise ValueError(f"{name} 必须是一维整数向量。")
    result: list[int] = []
    for item in array:
        if isinstance(item, bool) or not isinstance(item, Integral):
            raise TypeError(f"{name} 必须只包含整数。")
        result.append(int(item))
    return tuple(result)


def copy_share(share: AdditiveShare) -> AdditiveShare:
    """复制单方 share；该操作不接触或组合另一方 share。"""
    if not isinstance(share, AdditiveShare):
        raise TypeError("share 必须是 AdditiveShare。")
    return AdditiveShare(np.array(share.value, dtype=object, copy=True))


@dataclass(frozen=True, slots=True)
class IntegerVectorEvidence:
    """保存真实 canonical residue、centered integer 与公开分数位数。"""

    residue: tuple[int, ...]
    centered: tuple[int, ...]
    fractional_bits: int

    def __post_init__(self) -> None:
        """拒绝维数漂移和负尺度；模数范围由 Client 重构时验证。"""
        if not self.residue or len(self.residue) != len(self.centered):
            raise ValueError("residue/centered 必须是同长度非空向量。")
        for name in ("residue", "centered"):
            values = getattr(self, name)
            if any(isinstance(item, bool) or not isinstance(item, Integral) for item in values):
                raise TypeError(f"{name} 必须只包含整数。")
            object.__setattr__(self, name, tuple(int(item) for item in values))
        if (
            isinstance(self.fractional_bits, bool)
            or not isinstance(self.fractional_bits, Integral)
            or self.fractional_bits < 0
        ):
            raise ValueError("fractional_bits 必须是非负整数。")
        object.__setattr__(self, "fractional_bits", int(self.fractional_bits))


@dataclass(frozen=True, slots=True, repr=False)
class ProtocolStepSnapshot:
    """保存 coordinator 已执行轮次的 share 快照，但不在协调器中重构。"""

    session_id: str
    round_id: str
    step: int
    plan: StepResourcePlan
    input_p1: AdditiveShare
    input_p2: AdditiveShare
    output_p1: AdditiveShare
    output_p2: AdditiveShare
    state_before_p1: AdditiveShare
    state_before_p2: AdditiveShare
    state_accumulator_p1: AdditiveShare
    state_accumulator_p2: AdditiveShare
    state_after_p1: AdditiveShare
    state_after_p2: AdditiveShare


@dataclass(frozen=True, slots=True, repr=False)
class CombinedShareStepAudit:
    """仅供显式离线审计保存的输入/输出两方 share；不包含 controller state。"""

    step: int
    input_p1: tuple[int, ...]
    input_p2: tuple[int, ...]
    output_p1: tuple[int, ...]
    output_p2: tuple[int, ...]
    reconstruction_verified: bool

    @classmethod
    def from_shares(
        cls,
        *,
        step: int,
        input_p1: AdditiveShare,
        input_p2: AdditiveShare,
        output_p1: AdditiveShare,
        output_p2: AdditiveShare,
        reconstruction_verified: bool,
    ) -> CombinedShareStepAudit:
        """无损复制选定 step 的两类 share，禁止浮点化大整数。"""
        return cls(
            step=int(step),
            input_p1=_integer_tuple(input_p1.value, "input_p1"),
            input_p2=_integer_tuple(input_p2.value, "input_p2"),
            output_p1=_integer_tuple(output_p1.value, "output_p1"),
            output_p2=_integer_tuple(output_p2.value, "output_p2"),
            reconstruction_verified=bool(reconstruction_verified),
        )


@dataclass(frozen=True, slots=True)
class ProtocolReconstructionEvidence:
    """Client 对同一真实 round 完成的输出、输入和可选状态重构事实。"""

    session_id: str
    round_id: str
    step: int
    controller_input: IntegerVectorEvidence
    raw_control: IntegerVectorEvidence
    decoded_raw_control: tuple[float, ...]
    state_before: IntegerVectorEvidence | None
    state_accumulator: IntegerVectorEvidence | None
    state_after: IntegerVectorEvidence | None
    state_truncation_bits: int
    state_equation_verified: bool | None
    plan: StepResourcePlan
    combined_share_audit: CombinedShareStepAudit | None = None
