"""场景无关的定点编码与中心化模表示。"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from numbers import Rational, Real
from typing import Any

import numpy as np


def _require_integer(value: Any, name: str) -> int:
    """验证并转换整数参数，避免布尔值被当作 0 或 1 使用。"""
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} 必须是整数，不能是布尔值。")
    return int(value)


def _map_values(value: Any, mapper: Callable[[Any], int]) -> int | np.ndarray:
    """逐元素映射标量、向量或矩阵，并以 object dtype 保存任意精度整数。"""
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
class FixedPointContext:
    """定义 ``Q<k, ell>``、有限模环及其安全的 Python 表示。

    编码后的普通整数属于 ``[-2^(k-1), 2^(k-1)-1]``，并以 ``[0, q)``
    的 canonical residue 存入 ``Z_q``。所有模乘法逐元素使用 Python ``int``，
    因而不会经过 NumPy ``int64`` 的静默溢出路径。
    """

    modulus: int
    integer_bits: int
    fractional_bits: int

    def __post_init__(self) -> None:
        """在构造时验证编码范围可由中心化模表示完整容纳。"""
        modulus = _require_integer(self.modulus, "modulus")
        integer_bits = _require_integer(self.integer_bits, "integer_bits")
        fractional_bits = _require_integer(self.fractional_bits, "fractional_bits")

        if modulus < 3:
            raise ValueError("modulus 必须不小于 3。")
        if integer_bits < 1:
            raise ValueError("integer_bits 必须不小于 1。")
        if fractional_bits < 0:
            raise ValueError("fractional_bits 必须不小于 0。")

        # 中心化区间的负端为 -floor(q / 2)。这里确保 k 位有符号 payload 完全可表示。
        if 1 << (integer_bits - 1) > modulus // 2:
            raise ValueError("integer_bits 定义的负数范围不能由中心化模表示容纳。")

        object.__setattr__(self, "modulus", modulus)
        object.__setattr__(self, "integer_bits", integer_bits)
        object.__setattr__(self, "fractional_bits", fractional_bits)

    @property
    def scale(self) -> int:
        """返回普通编码的缩放因子 ``2^ell``。"""
        return 1 << self.fractional_bits

    @property
    def product_fractional_bits(self) -> int:
        """返回两个普通编码相乘后的分数位数 ``2 * ell``。"""
        return 2 * self.fractional_bits

    @property
    def minimum_payload(self) -> int:
        """返回允许编码的最小有符号整数 payload。"""
        return -(1 << (self.integer_bits - 1))

    @property
    def maximum_payload(self) -> int:
        """返回允许编码的最大有符号整数 payload。"""
        return (1 << (self.integer_bits - 1)) - 1

    def encode(self, value: Any) -> int | np.ndarray:
        """按论文 ``floor(x * 2^ell + 1/2)`` 编码实数输入。

        这不是 Python 的 banker rounding。对负数同样严格采用向下取整，例如
        ``-0.25`` 在 ``ell=1`` 时编码为 ``0``。
        """
        return _map_values(value, self._encode_one)

    def decode(
        self, payload: Any, *, fractional_bits: int | None = None
    ) -> int | float | np.ndarray:
        """将范围已验证的有符号 payload 解码为数值近似值。

        默认按照当前 ``ell`` 解码；调用者可显式给出其他分数位数以记录已知尺度。
        在尚未执行截断前，乘法结果不应被误当作普通 ``ell`` 尺度的数据解码。

        当分数位数为零时，结果保留为 Python ``int``（数组使用 ``object`` dtype），
        避免合法的大 payload 在仅为了解码而转换成浮点数时再次丢失低位。
        """
        bits = (
            self.fractional_bits
            if fractional_bits is None
            else _require_integer(fractional_bits, "fractional_bits")
        )
        if bits < 0:
            raise ValueError("fractional_bits 必须不小于 0。")

        def decode_one(item: Any) -> int | float:
            integer = _require_integer(item, "payload")
            self._validate_payload(integer)
            if bits == 0:
                return integer
            try:
                decoded = integer / (1 << bits)
            except OverflowError as error:
                raise ValueError("payload 过大，无法安全解码为有限浮点数。") from error
            if not math.isfinite(decoded):
                raise ValueError("payload 无法安全解码为有限浮点数。")
            return decoded

        return self._map_decoded_values(
            payload,
            decode_one,
            preserve_integer_precision=bits == 0,
        )

    def to_residue(self, payload: Any) -> int | np.ndarray:
        """将任意 Python 整数规范化为 ``[0, q)`` 中的 canonical residue。"""
        return _map_values(payload, lambda item: _require_integer(item, "payload") % self.modulus)

    def from_residue(self, residue: Any) -> int | np.ndarray:
        """从 canonical residue 恢复唯一的中心化有符号代表元。"""
        return _map_values(residue, self._from_residue_one)

    def encode_to_residue(self, value: Any) -> int | np.ndarray:
        """将实数编码后转换为用于 ``Z_q`` 运算的 canonical residue。"""
        return self.to_residue(self.encode(value))

    def decode_residue(
        self, residue: Any, *, fractional_bits: int | None = None
    ) -> int | float | np.ndarray:
        """从中心化 residue 恢复并解码普通尺度的 payload。

        此接口会拒绝超出 ``k`` 位 payload 范围的代表元。它不能在结果恰好回绕到
        合法范围时推断历史模回绕；上层协议仍须依据其已知输入范围证明不会发生回绕。
        """
        return self.decode(self.from_residue(residue), fractional_bits=fractional_bits)

    def add_residues(self, left: Any, right: Any) -> int | np.ndarray:
        """在 ``Z_q`` 中逐元素相加，输入必须已是 canonical residue。"""
        return self._binary_residue_operation(left, right, lambda first, second: first + second)

    def multiply_residues(self, left: Any, right: Any) -> int | np.ndarray:
        """在 ``Z_q`` 中逐元素相乘，结果的分数位数为 ``2 * ell``。

        本方法只完成数学模乘法，不包含未来协议所需的截断。为避免把可检测的数学
        回绕伪装成小 payload，它会验证每个输入仍是声明的 ``k`` 位 payload，并拒绝
        精确乘积越出中心化模区间的情形。该局部检查不能证明上游 residue 从未回绕；
        完整协议仍须对所有中间量建立全局范围证明。
        """
        return self._binary_residue_operation(left, right, self._multiply_residue_pair)

    def _encode_one(self, item: Any) -> int:
        """执行单个实数的论文取整与 payload 范围检查。"""
        if isinstance(item, (bool, np.bool_)) or not isinstance(item, Real):
            raise TypeError("待编码值必须是有限实数，不能是布尔值。")

        if isinstance(item, (int, np.integer)):
            # Python 整数没有固定字长；直接缩放可避免合法 payload 经 float 丢失低位。
            payload = int(item) * self.scale
            self._validate_payload(payload)
            return payload

        if isinstance(item, Rational):
            # 对 Fraction 等精确有理数按 floor(x * 2^ell + 1/2) 计算，避免中间浮点化。
            numerator = int(item.numerator) * self.scale
            denominator = int(item.denominator)
            payload = (2 * numerator + denominator) // (2 * denominator)
            self._validate_payload(payload)
            return payload

        try:
            real_value = float(item)
            scaled = real_value * self.scale
        except OverflowError as error:
            raise ValueError("待编码值过大，无法安全缩放。") from error
        if not math.isfinite(real_value) or not math.isfinite(scaled):
            raise ValueError("待编码值及其缩放结果必须是有限数。")

        # 论文规定 floor(x + 1/2)，故不能使用 Python/NumPy 的 round。
        payload = math.floor(scaled + 0.5)
        self._validate_payload(payload)
        return payload

    def _from_residue_one(self, item: Any) -> int:
        """验证 canonical 范围并转换为 ``[-floor(q/2), ceil(q/2)-1]``。"""
        residue = _require_integer(item, "residue")
        if not 0 <= residue < self.modulus:
            raise ValueError("residue 必须位于 canonical 区间 [0, modulus)。")

        # 对偶数 q，q/2 被映射为负端；对奇数 q，正端多一个代表元。
        return residue if residue < (self.modulus + 1) // 2 else residue - self.modulus

    def _validate_payload(self, payload: int) -> None:
        """确认有符号 payload 未超出本上下文声明的可表示范围。"""
        if not self.minimum_payload <= payload <= self.maximum_payload:
            raise ValueError(
                f"payload 超出可表示范围 [{self.minimum_payload}, {self.maximum_payload}]。"
            )

    def _binary_residue_operation(
        self, left: Any, right: Any, operation: Callable[[int, int], int]
    ) -> int | np.ndarray:
        """在广播形状上逐元素执行 Python 整数模运算，避免固定位宽中间值。"""
        try:
            left_array, right_array = np.broadcast_arrays(
                np.asarray(left, dtype=object), np.asarray(right, dtype=object)
            )
        except ValueError as error:
            raise ValueError("两个 residue 输入必须具有可广播的形状。") from error

        if left_array.ndim == 0:
            return (
                operation(
                    self._canonical_residue(left_array.item()),
                    self._canonical_residue(right_array.item()),
                )
                % self.modulus
            )

        result = np.empty(left_array.shape, dtype=object)
        for index in np.ndindex(left_array.shape):
            result[index] = (
                operation(
                    self._canonical_residue(left_array[index]),
                    self._canonical_residue(right_array[index]),
                )
                % self.modulus
            )
        return result

    def _canonical_residue(self, item: Any) -> int:
        """仅接受 canonical 输入，防止调用方混淆 payload 与模表示。"""
        return self._from_residue_one(item) % self.modulus

    def _multiply_residue_pair(self, left: int, right: int) -> int:
        """计算可追溯的整数乘积，并在取模前拒绝可检测的数学回绕。"""
        first = self._payload_from_residue(left)
        second = self._payload_from_residue(right)
        product = first * second

        # 中心化 Z_q 的唯一整数范围为 [-floor(q/2), floor((q-1)/2)]。
        if not -(self.modulus // 2) <= product <= (self.modulus - 1) // 2:
            raise ValueError("精确乘积越出中心化模区间，会发生数学模回绕。")
        return product

    def _payload_from_residue(self, residue: int) -> int:
        """恢复普通 payload，并拒绝已超出当前上下文声明范围的 operand。"""
        payload = self._from_residue_one(residue)
        self._validate_payload(payload)
        return payload

    def _map_decoded_values(
        self,
        value: Any,
        mapper: Callable[[Any], int | float],
        *,
        preserve_integer_precision: bool,
    ) -> int | float | np.ndarray:
        """保持输入 shape；零分数位数组使用 object dtype 以保留任意精度整数。"""
        try:
            array = np.asarray(value, dtype=object)
        except ValueError as error:
            raise ValueError("输入必须是形状规则的标量、向量或矩阵。") from error
        if array.ndim == 0:
            return mapper(array.item())

        mapped = np.empty(array.shape, dtype=object if preserve_integer_precision else float)
        for index in np.ndindex(array.shape):
            mapped[index] = mapper(array[index])
        return mapped
