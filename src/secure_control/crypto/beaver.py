"""基于一次性 Beaver 三元组的标量 2-out-of-2 安全乘法。"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass, field
from typing import Any

from .secret_sharing import AdditiveShare, TwoPartySharing


class _TripleLifecycle:
    """记录一个三元组的分阶段使用状态，阻止跨乘法或跨参与方复用。"""

    def __init__(self, owner: object) -> None:
        self.owner = owner
        self.masked_parties: set[int] = set()
        self.opened = False
        self.finished_parties: set[int] = set()
        self.consumed = False

    def claim_masking(self, party_index: int) -> None:
        """记录该参与方已用此三元组生成遮蔽差值。"""
        if self.consumed or party_index in self.masked_parties:
            raise ValueError("Beaver 三元组已经用于遮蔽，不能复用。")
        self.masked_parties.add(party_index)

    def claim_opening(self) -> None:
        """仅允许两方各提交一次遮蔽差值后公开 d/e。"""
        if self.consumed or self.opened or self.masked_parties != {0, 1}:
            raise ValueError("遮蔽差值必须由同一三元组的两方各提交一次后才能公开。")
        self.opened = True

    def claim_finish(self, party_index: int) -> bool:
        """记录一方完成计算，并在两方均完成时标记资源已消费。"""
        if self.consumed or not self.opened or party_index in self.finished_parties:
            raise ValueError("Beaver 三元组已经完成或不处于可完成状态。")
        self.finished_parties.add(party_index)
        if self.finished_parties == {0, 1}:
            self.consumed = True
            return True
        return False


@dataclass(frozen=True)
class BeaverTripleShare:
    """一个参与方持有的三元组份额 ``(a_i, b_i, c_i)``。

    该对象只含本方的三份 `AdditiveShare`；它不保存另一方份额，也不保存明文
    ``a``、``b`` 或 ``c``。私有生命周期令牌只用于防复用，不携带数值秘密。
    """

    a: AdditiveShare
    b: AdditiveShare
    c: AdditiveShare
    party_index: int
    _lifecycle: _TripleLifecycle = field(repr=False, compare=False)

    @property
    def is_consumed(self) -> bool:
        """返回该三元组是否已被两方完整消费。"""
        return self._lifecycle.consumed


@dataclass(frozen=True)
class MaskedDifferenceShare:
    """一个参与方本地计算的 ``d_i=x_i-a_i`` 与 ``e_i=y_i-b_i``。"""

    d: AdditiveShare
    e: AdditiveShare
    party_index: int
    _lifecycle: _TripleLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True)
class PublicMaskedDifferences:
    """两方公开并重构后的标量 ``d=x-a`` 与 ``e=y-b``。"""

    d: int
    e: int
    _lifecycle: _TripleLifecycle = field(repr=False, compare=False)


@dataclass
class BeaverMultiplier:
    """执行论文 Protocol 1 标量乘法所需的三元组管理与局部步骤。"""

    sharing: TwoPartySharing
    _created_triples: int = field(default=0, init=False, repr=False)
    _consumed_triples: int = field(default=0, init=False, repr=False)

    @property
    def created_triples(self) -> int:
        """返回本实例生成的三元组数量。"""
        return self._created_triples

    @property
    def consumed_triples(self) -> int:
        """返回已由两方完整消费的三元组数量。"""
        return self._consumed_triples

    @property
    def pending_triples(self) -> int:
        """返回已生成但尚未完成两方计算的三元组数量。"""
        return self._created_triples - self._consumed_triples

    def create_triple(
        self, *, rng: random.Random | None = None
    ) -> tuple[BeaverTripleShare, BeaverTripleShare]:
        """生成满足 ``c=a*b mod q`` 的一次性标量共享三元组。

        默认通过系统安全随机源抽取 ``a`` 与 ``b``；测试可注入固定 seed 的 RNG。
        各份额仍由 ``TwoPartySharing.share`` 独立随机化。
        """
        a = self._random_residue(rng)
        b = self._random_residue(rng)
        c = (a * b) % self.sharing.modulus
        a_shares = self.sharing.share(a, rng=rng)
        b_shares = self.sharing.share(b, rng=rng)
        c_shares = self.sharing.share(c, rng=rng)
        lifecycle = _TripleLifecycle(self)
        self._created_triples += 1
        return (
            BeaverTripleShare(a_shares[0], b_shares[0], c_shares[0], 0, lifecycle),
            BeaverTripleShare(a_shares[1], b_shares[1], c_shares[1], 1, lifecycle),
        )

    def mask_inputs(
        self,
        x_share: AdditiveShare,
        y_share: AdditiveShare,
        triple_share: BeaverTripleShare,
    ) -> MaskedDifferenceShare:
        """本地计算 ``[[d]]=[[x]]-[[a]]`` 与 ``[[e]]=[[y]]-[[b]]``。

        此步骤只接收一个参与方的输入份额与本方三元组份额，不会重构 ``x`` 或 ``y``。
        """
        triple = self._validated_triple(triple_share)
        x = self._validated_scalar_share(x_share, "x_share")
        y = self._validated_scalar_share(y_share, "y_share")
        triple._lifecycle.claim_masking(triple.party_index)
        return MaskedDifferenceShare(
            self.sharing.subtract(x, triple.a),
            self.sharing.subtract(y, triple.b),
            triple.party_index,
            triple._lifecycle,
        )

    def open_masked_differences(
        self,
        first: MaskedDifferenceShare,
        second: MaskedDifferenceShare,
    ) -> PublicMaskedDifferences:
        """只重构已遮蔽的 ``d/e``，而不重构任一输入消息。"""
        first_masked = self._validated_masked(first)
        second_masked = self._validated_masked(second)
        if first_masked._lifecycle is not second_masked._lifecycle:
            raise ValueError("两份遮蔽差值必须来自同一个 Beaver 三元组。")
        if {first_masked.party_index, second_masked.party_index} != {0, 1}:
            raise ValueError("公开 d/e 时必须各提供一方的遮蔽差值。")

        lifecycle = first_masked._lifecycle
        lifecycle.claim_opening()
        d = self._scalar_value(self.sharing.reconstruct(first_masked.d, second_masked.d), "d")
        e = self._scalar_value(self.sharing.reconstruct(first_masked.e, second_masked.e), "e")
        return PublicMaskedDifferences(d, e, lifecycle)

    def finish(
        self,
        triple_share: BeaverTripleShare,
        opened: PublicMaskedDifferences,
    ) -> AdditiveShare:
        """按 Protocol 1 计算本方输出 share。

        公式为 ``e*a_i + d*b_i + c_i``，公开 ``d*e`` 仅加到第 0 方。这样两方
        重构后恰为 ``e*a + d*b + c + d*e``，不会漏加或重复计入公开项。
        """
        triple = self._validated_triple(triple_share)
        public = self._validated_opened(opened, triple._lifecycle)
        result = self.sharing.add(
            self.sharing.multiply_public(triple.a, public.e),
            self.sharing.multiply_public(triple.b, public.d),
        )
        result = self.sharing.add(result, triple.c)
        if triple.party_index == 0:
            result = self.sharing.add_public(result, (public.d * public.e) % self.sharing.modulus)

        if triple._lifecycle.claim_finish(triple.party_index):
            self._consumed_triples += 1
        return result

    def _random_residue(self, rng: random.Random | None) -> int:
        """为三元组明文预处理值抽取一个 canonical residue。"""
        return (
            secrets.randbelow(self.sharing.modulus)
            if rng is None
            else rng.randrange(self.sharing.modulus)
        )

    def _validated_triple(self, triple: BeaverTripleShare) -> BeaverTripleShare:
        """确认三元组属于当前乘法器，并且所有局部份额均为标量。"""
        if not isinstance(triple, BeaverTripleShare):
            raise TypeError("triple_share 必须是 BeaverTripleShare。")
        if triple._lifecycle.owner is not self:
            raise ValueError("Beaver 三元组不属于当前乘法器。")
        if triple.party_index not in {0, 1}:
            raise ValueError("party_index 必须是 0 或 1。")
        self._validated_scalar_share(triple.a, "triple.a")
        self._validated_scalar_share(triple.b, "triple.b")
        self._validated_scalar_share(triple.c, "triple.c")
        return triple

    def _validated_masked(self, masked: MaskedDifferenceShare) -> MaskedDifferenceShare:
        """确认遮蔽差值来自当前乘法器的单个参与方。"""
        if not isinstance(masked, MaskedDifferenceShare):
            raise TypeError("masked 必须是 MaskedDifferenceShare。")
        if masked._lifecycle.owner is not self:
            raise ValueError("遮蔽差值不属于当前乘法器。")
        if masked.party_index not in {0, 1}:
            raise ValueError("party_index 必须是 0 或 1。")
        self._validated_scalar_share(masked.d, "masked.d")
        self._validated_scalar_share(masked.e, "masked.e")
        return masked

    def _validated_opened(
        self,
        opened: PublicMaskedDifferences,
        lifecycle: _TripleLifecycle,
    ) -> PublicMaskedDifferences:
        """确认公开 d/e 由当前三元组产生且仍处于可完成状态。"""
        if not isinstance(opened, PublicMaskedDifferences):
            raise TypeError("opened 必须是 PublicMaskedDifferences。")
        if opened._lifecycle is not lifecycle:
            raise ValueError("公开 d/e 必须来自同一个 Beaver 三元组。")
        self._scalar_value(opened.d, "opened.d")
        self._scalar_value(opened.e, "opened.e")
        return opened

    def _validated_scalar_share(self, share: AdditiveShare, name: str) -> AdditiveShare:
        """利用现有线性原语验证单份 canonical 标量 share。"""
        try:
            normalized = self.sharing.add(share, AdditiveShare(0))
        except (TypeError, ValueError) as error:
            raise type(error)(f"{name} 非法：{error}") from error
        self._scalar_value(normalized.value, name)
        return normalized

    def _scalar_value(self, value: Any, name: str) -> int:
        """限制本 Issue 的协议实现为 scalar-first 路径。"""
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} 必须是标量整数；矩阵三元组不属于当前 Issue。")
        if not 0 <= value < self.sharing.modulus:
            raise ValueError(f"{name} 必须位于 canonical 区间 [0, modulus)。")
        return value
