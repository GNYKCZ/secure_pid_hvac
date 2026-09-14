"""场景无关的 2-out-of-2 加法秘密共享原语。"""

from __future__ import annotations

import random
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import numpy as np


def _require_integer(value: Any, name: str) -> int:
    """验证整数输入，避免布尔值隐式成为模环元素。"""
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} 必须是整数，不能是布尔值。")
    return int(value)


def _map_values(value: Any, mapper: Callable[[Any], int]) -> int | np.ndarray:
    """逐元素处理标量、向量或矩阵，并用 object dtype 保留任意精度整数。"""
    try:
        array = np.asarray(value, dtype=object)
    except ValueError as error:
        raise ValueError("输入必须是形状规则的标量、向量或矩阵。") from error

    if array.ndim == 0:
        return mapper(array.item())

    mapped = np.empty(array.shape, dtype=object)
    for index in np.ndindex(array.shape):
        mapped[index] = mapper(array[index])
    return mapped


@dataclass(frozen=True)
class AdditiveShare:
    """保存单个参与方持有的一份 canonical residue。

    该数据结构刻意只含一个 ``value`` 字段，不能携带另一参与方的份额。两份份额的
    配对只在分发端 ``share`` 的返回值以及客户端/测试的 ``reconstruct`` 边界出现。
    """

    value: int | np.ndarray


@dataclass(frozen=True)
class TwoPartySharing:
    """在固定 ``Z_q`` 上执行 2-out-of-2 加法共享和线性局部运算。"""

    modulus: int

    def __post_init__(self) -> None:
        """验证模数是足以定义中心化表示的正整数。"""
        modulus = _require_integer(self.modulus, "modulus")
        if modulus < 3:
            raise ValueError("modulus 必须不小于 3。")
        object.__setattr__(self, "modulus", modulus)

    def share(
        self, message: Any, *, rng: random.Random | None = None
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """将消息分为两份独立的 canonical additive shares。

        未注入 ``rng`` 时，每个元素通过 ``secrets.randbelow`` 独立取样；这是正常
        运行的默认路径。测试可注入 ``random.Random(seed)`` 获得可复现结果，但其
        伪随机性不应替代正常协议随机性。
        """
        normalized_message = self._normalize_message(message)

        if isinstance(normalized_message, int):
            first = self._random_residue(rng)
            return AdditiveShare(first), AdditiveShare((normalized_message - first) % self.modulus)

        first_share = np.empty(normalized_message.shape, dtype=object)
        second_share = np.empty(normalized_message.shape, dtype=object)
        for index in np.ndindex(normalized_message.shape):
            first = self._random_residue(rng)
            first_share[index] = first
            second_share[index] = (normalized_message[index] - first) % self.modulus
        return AdditiveShare(first_share), AdditiveShare(second_share)

    def reconstruct(self, first: AdditiveShare, second: AdditiveShare) -> int | np.ndarray:
        """仅在客户端或测试边界重构两份 share 对应的 canonical residue。"""
        return self._binary_values(first, second, lambda left, right: left + right)

    def add(self, left: AdditiveShare, right: AdditiveShare) -> AdditiveShare:
        """局部计算 share 加 share，不重构任何明文消息。"""
        return AdditiveShare(self._binary_values(left, right, lambda first, second: first + second))

    def subtract(self, left: AdditiveShare, right: AdditiveShare) -> AdditiveShare:
        """局部计算 share 减 share，不重构任何明文消息。"""
        return AdditiveShare(self._binary_values(left, right, lambda first, second: first - second))

    def add_public(self, share: AdditiveShare, constant: Any) -> AdditiveShare:
        """将公开常数加到一份选定 share 上。

        若目标是共享消息加常数，调用方必须只更新两份 share 中预先约定的一份，另一份
        保持不变；若双方都执行此操作，重构结果会增加两次常数。
        """
        return AdditiveShare(
            self._share_public_operation(share, constant, lambda left, right: left + right)
        )

    def subtract_public(self, share: AdditiveShare, constant: Any) -> AdditiveShare:
        """从一份选定 share 上减去公开常数，调用方需遵循与 ``add_public`` 相同的约定。"""
        return AdditiveShare(
            self._share_public_operation(share, constant, lambda left, right: left - right)
        )

    def multiply_public(self, share: AdditiveShare, constant: Any) -> AdditiveShare:
        """局部计算公开常数乘单份 share；两方均执行后重构值相应乘该常数。"""
        return AdditiveShare(
            self._share_public_operation(share, constant, lambda left, right: left * right)
        )

    def _normalize_message(self, message: Any) -> int | np.ndarray:
        """将待共享的有符号整数规范化到 ``[0, q)``。"""
        return _map_values(message, lambda item: _require_integer(item, "message") % self.modulus)

    def _random_residue(self, rng: random.Random | None) -> int:
        """为一个 share 元素生成独立 residue，并验证可注入随机源的返回值。"""
        sampled = secrets.randbelow(self.modulus) if rng is None else rng.randrange(self.modulus)
        residue = _require_integer(sampled, "随机源返回值")
        if not 0 <= residue < self.modulus:
            raise ValueError("随机源返回值必须位于 [0, modulus)。")
        return residue

    def _validated_share_values(self, share: AdditiveShare) -> int | np.ndarray:
        """验证传入对象只含本上下文可接受的 canonical residue。"""
        if not isinstance(share, AdditiveShare):
            raise TypeError("操作数必须是 AdditiveShare，不能直接传入两份 share。")
        return _map_values(share.value, self._validate_residue)

    def _validate_residue(self, value: Any) -> int:
        """拒绝非 canonical 输入，避免把 payload 与模表示混用。"""
        residue = _require_integer(value, "share value")
        if not 0 <= residue < self.modulus:
            raise ValueError("share value 必须位于 canonical 区间 [0, modulus)。")
        return residue

    def _binary_values(
        self,
        left: AdditiveShare,
        right: AdditiveShare,
        operation: Callable[[int, int], int],
    ) -> int | np.ndarray:
        """在严格兼容的 shape 上逐元素执行 Python 整数模线性运算。"""
        left_values = self._validated_share_values(left)
        right_values = self._validated_share_values(right)
        return self._combine_values(left_values, right_values, operation)

    def _share_public_operation(
        self,
        share: AdditiveShare,
        constant: Any,
        operation: Callable[[int, int], int],
    ) -> int | np.ndarray:
        """将公开常数规范化后，与单份 share 执行逐元素局部线性运算。"""
        share_values = self._validated_share_values(share)
        constant_values = _map_values(
            constant, lambda item: _require_integer(item, "constant") % self.modulus
        )
        return self._combine_values(share_values, constant_values, operation)

    def _combine_values(
        self,
        left: int | np.ndarray,
        right: int | np.ndarray,
        operation: Callable[[int, int], int],
    ) -> int | np.ndarray:
        """组合标量或相同 shape 的数组，拒绝隐式广播造成的份额错配。"""
        left_array = np.asarray(left, dtype=object)
        right_array = np.asarray(right, dtype=object)
        if left_array.ndim != 0 and right_array.ndim != 0 and left_array.shape != right_array.shape:
            raise ValueError("两个输入必须同形，或其中一个必须是标量。")

        if left_array.ndim == 0 and right_array.ndim == 0:
            return operation(left_array.item(), right_array.item()) % self.modulus

        if left_array.ndim == 0:
            left_array = np.full(right_array.shape, left_array.item(), dtype=object)
        if right_array.ndim == 0:
            right_array = np.full(left_array.shape, right_array.item(), dtype=object)

        result = np.empty(left_array.shape, dtype=object)
        for index in np.ndindex(left_array.shape):
            result[index] = operation(left_array[index], right_array[index]) % self.modulus
        return result
