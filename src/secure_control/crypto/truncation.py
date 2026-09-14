"""论文 Protocol 2 的 scalar-first 安全截断本地消息语义。"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass, field
from typing import Any

from .secret_sharing import AdditiveShare, TwoPartySharing


def _centered_mod(value: int, modulus: int) -> int:
    """按论文定义将整数约简到 ``[-modulus/2, modulus/2)``。"""
    return value - ((value + modulus // 2) // modulus) * modulus


def _is_prime_candidate(value: int) -> bool:
    """使用 Miller--Rabin 筛除合数；调用方仍须为大模数提供已验证的素数。"""
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % divisor == 0 for divisor in small_primes):
        return False
    exponent, twos = value - 1, 0
    while exponent % 2 == 0:
        exponent //= 2
        twos += 1
    # 这些基在 64 位以内构成确定性判据；对更大 q 是严格的合数筛查而非素数证书。
    for base in (2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022):
        if base % value == 0:
            continue
        witness = pow(base, exponent, value)
        if witness in {1, value - 1}:
            continue
        for _ in range(twos - 1):
            witness = (witness * witness) % value
            if witness == value - 1:
                break
        else:
            return False
    return True


class _MaskLifecycle:
    """记录 Protocol 2 辅助随机量的单次遮蔽、发送、重构和完成顺序。"""

    def __init__(self, owner: object) -> None:
        self.owner = owner
        self.masked_parties: set[int] = set()
        self.p2_sent = False
        self.p1_reconstructed = False
        self.finished_parties: set[int] = set()
        self.consumed = False

    def claim_mask(self, party: int) -> None:
        """记录一方使用辅助随机量生成一次遮蔽份额。"""
        if self.consumed or party in self.masked_parties:
            raise ValueError("截断随机量已经用于遮蔽，不能复用。")
        self.masked_parties.add(party)

    def claim_p2_send(self) -> None:
        """仅允许 P2 在两方均完成遮蔽后发送一次本地份额。"""
        if self.consumed or self.p2_sent or self.masked_parties != {0, 1}:
            raise ValueError("P2 必须在两方各遮蔽一次后才能发送一次消息。")
        self.p2_sent = True

    def claim_p1_reconstruction(self) -> None:
        """仅允许 P1 在收到 P2 消息后重构一次 masked 值。"""
        if self.consumed or not self.p2_sent or self.p1_reconstructed:
            raise ValueError("P1 masked 值不处于可重构状态。")
        self.p1_reconstructed = True

    def claim_finish(self, party: int) -> bool:
        """两方各完成一次输出后，将该随机量标记为已消费。"""
        if self.consumed or not self.p1_reconstructed or party in self.finished_parties:
            raise ValueError("截断随机量已经完成或不处于可完成状态。")
        self.finished_parties.add(party)
        if self.finished_parties == {0, 1}:
            self.consumed = True
            return True
        return False


@dataclass(frozen=True)
class TruncationAuxiliaryShare:
    """一个参与方持有的随机 ``r``、``r'`` 的单份 share。"""

    r: AdditiveShare
    r_prime: AdditiveShare
    party_index: int
    _lifecycle: _MaskLifecycle = field(repr=False, compare=False)

    @property
    def is_consumed(self) -> bool:
        """返回该对辅助随机量是否已经被两方完整消费。"""
        return self._lifecycle.consumed


@dataclass(frozen=True)
class MaskedTruncationShare:
    """一方本地计算的 ``[[m_r]]_i``，其中 ``m_r`` 是被随机量遮蔽的值。"""

    value: AdditiveShare
    party_index: int
    _lifecycle: _MaskLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True)
class P2MaskedMessage:
    """P2 发给 P1 的唯一消息：P2 的单份 ``[[m_r]]_2``。"""

    value: AdditiveShare
    _lifecycle: _MaskLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True)
class P1MaskedValue:
    """仅 P1 可见的中心化 ``m_r``，用于计算中心化低 ``ell`` 位。"""

    value: int
    _lifecycle: _MaskLifecycle = field(repr=False, compare=False)


@dataclass
class SecureTruncation:
    """实现论文 Protocol 2 的标量消息流、算术和一次性随机量约束。"""

    sharing: TwoPartySharing
    ell: int
    security_parameter: int
    _created_masks: int = field(default=0, init=False, repr=False)
    _consumed_masks: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        """验证素模数和 ``kappa > ell`` 等 Protocol 2 前置条件。"""
        if isinstance(self.ell, bool) or not isinstance(self.ell, int) or self.ell < 1:
            raise ValueError("ell 必须是正整数。")
        if (
            isinstance(self.security_parameter, bool)
            or not isinstance(self.security_parameter, int)
            or self.security_parameter < 1
        ):
            raise ValueError("security_parameter 必须是正整数。")
        if not _is_prime_candidate(self.sharing.modulus):
            raise ValueError("Protocol 2 要求 modulus 为素数。")
        kappa = self.sharing.modulus.bit_length() - 1 - self.security_parameter - 1
        if kappa <= self.ell:
            raise ValueError("必须满足 kappa=floor(log2(q))-lambda-1 > ell。")
        object.__setattr__(self, "ell", int(self.ell))
        object.__setattr__(self, "security_parameter", int(self.security_parameter))

    @property
    def kappa(self) -> int:
        """返回论文定义的 ``floor(log2(q))-lambda-1``。"""
        return self.sharing.modulus.bit_length() - self.security_parameter - 2

    @property
    def scale(self) -> int:
        """返回待截断的位尺度 ``2^ell``。"""
        return 1 << self.ell

    @property
    def inverse_scale(self) -> int:
        """返回 ``inv(2^ell, q)``，其存在性由素模数和参数约束保证。"""
        return pow(self.scale, -1, self.sharing.modulus)

    @property
    def minimum_message(self) -> int:
        """返回 ``Z<kappa>`` 的下边界。"""
        return -(1 << (self.kappa - 1))

    @property
    def maximum_message(self) -> int:
        """返回 ``Z<kappa>`` 的上边界。"""
        return (1 << (self.kappa - 1)) - 1

    @property
    def created_masks(self) -> int:
        """返回已生成的辅助随机量对数量。"""
        return self._created_masks

    @property
    def consumed_masks(self) -> int:
        """返回已由两方完整消费的辅助随机量对数量。"""
        return self._consumed_masks

    def paper_round_divide(self, message: int) -> int:
        """按论文中心化模定义计算 ``floor(message/2^ell + 1/2)``。"""
        self.validate_message(message)
        return (message - _centered_mod(message, self.scale)) // self.scale

    def validate_message(self, message: Any) -> int:
        """在客户端/测试边界验证明文输入属于 ``Z<kappa>``。"""
        if isinstance(message, bool) or not isinstance(message, int):
            raise TypeError("message 必须是标量整数。")
        if not self.minimum_message <= message <= self.maximum_message:
            raise ValueError("message 超出 Z<kappa> 的允许范围。")
        return message

    def share_message(
        self, message: int, *, rng: random.Random | None = None
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """验证客户端输入范围后生成其两份 share。"""
        return self.sharing.share(self.validate_message(message), rng=rng)

    def create_auxiliary(
        self, *, rng: random.Random | None = None
    ) -> tuple[TruncationAuxiliaryShare, TruncationAuxiliaryShare]:
        """生成并共享一次性的 ``r`` 与 ``r'``，其范围严格遵循 Protocol 2。"""
        r = self._sample_centered(self.kappa - self.ell + self.security_parameter, rng)
        r_prime = self._sample_centered(self.ell, rng)
        r_shares = self.sharing.share(r, rng=rng)
        r_prime_shares = self.sharing.share(r_prime, rng=rng)
        lifecycle = _MaskLifecycle(self)
        self._created_masks += 1
        return (
            TruncationAuxiliaryShare(r_shares[0], r_prime_shares[0], 0, lifecycle),
            TruncationAuxiliaryShare(r_shares[1], r_prime_shares[1], 1, lifecycle),
        )

    def mask_input(
        self, message_share: AdditiveShare, auxiliary: TruncationAuxiliaryShare
    ) -> MaskedTruncationShare:
        """各方局部计算 ``[[m_r]]=[[m]]+2^ell[[r]]+[[r']]+2^(ell-1)``。"""
        auxiliary = self._valid_auxiliary(auxiliary)
        message = self._scalar_share(message_share, "message_share")
        auxiliary._lifecycle.claim_mask(auxiliary.party_index)
        masked = self.sharing.add(message, self.sharing.multiply_public(auxiliary.r, self.scale))
        masked = self.sharing.add(masked, auxiliary.r_prime)
        if auxiliary.party_index == 0:
            masked = self.sharing.add_public(masked, self.scale // 2)
        return MaskedTruncationShare(masked, auxiliary.party_index, auxiliary._lifecycle)

    def p2_send_masked(self, masked: MaskedTruncationShare) -> P2MaskedMessage:
        """P2 仅发送自己的 masked share；该 API 不接收 P1 消息。"""
        masked = self._valid_masked(masked)
        if masked.party_index != 1:
            raise ValueError("只有 P2 的 masked share 可以发送给 P1。")
        masked._lifecycle.claim_p2_send()
        return P2MaskedMessage(masked.value, masked._lifecycle)

    def p1_reconstruct_masked(
        self, masked: MaskedTruncationShare, message: P2MaskedMessage
    ) -> P1MaskedValue:
        """P1 用自己的 masked share 与 P2 消息重构中心化 ``m_r``。"""
        masked = self._valid_masked(masked)
        if masked.party_index != 0 or not isinstance(message, P2MaskedMessage):
            raise TypeError("P1 重构需要 P1 的 masked share 和 P2MaskedMessage。")
        if message._lifecycle is not masked._lifecycle:
            raise ValueError("P2 消息必须来自同一对截断随机量。")
        masked._lifecycle.claim_p1_reconstruction()
        residue = self.sharing.reconstruct(masked.value, message.value)
        return P1MaskedValue(
            _centered_mod(self._scalar_value(residue, "m_r residue"), self.sharing.modulus),
            masked._lifecycle,
        )

    def finish_p1(
        self,
        message_share: AdditiveShare,
        auxiliary: TruncationAuxiliaryShare,
        masked_value: P1MaskedValue,
    ) -> AdditiveShare:
        """P1 按 Protocol 2 使用其私有 ``m_r`` 低位计算输出 share。"""
        auxiliary = self._valid_auxiliary(auxiliary)
        if auxiliary.party_index != 0 or not isinstance(masked_value, P1MaskedValue):
            raise TypeError("finish_p1 需要 P1 的辅助随机量和 P1MaskedValue。")
        if masked_value._lifecycle is not auxiliary._lifecycle:
            raise ValueError("P1 masked 值必须来自同一对截断随机量。")
        message_share = self._scalar_share(message_share, "message_share")
        low_bits = _centered_mod(masked_value.value - self.scale // 2, self.scale)
        result = self.sharing.add(message_share, auxiliary.r_prime)
        result = self.sharing.subtract_public(result, low_bits)
        result = self.sharing.multiply_public(result, self.inverse_scale)
        if auxiliary._lifecycle.claim_finish(0):
            self._consumed_masks += 1
        return result

    def finish_p2(
        self, message_share: AdditiveShare, auxiliary: TruncationAuxiliaryShare
    ) -> AdditiveShare:
        """P2 无需接收 P1 消息，仅局部计算其输出 share。"""
        auxiliary = self._valid_auxiliary(auxiliary)
        if auxiliary.party_index != 1:
            raise ValueError("finish_p2 只能使用 P2 的辅助随机量。")
        message_share = self._scalar_share(message_share, "message_share")
        result = self.sharing.add(message_share, auxiliary.r_prime)
        result = self.sharing.multiply_public(result, self.inverse_scale)
        if auxiliary._lifecycle.claim_finish(1):
            self._consumed_masks += 1
        return result

    def _sample_centered(self, bits: int, rng: random.Random | None) -> int:
        """从论文 ``Z<bits>`` 的中心化有符号区间均匀抽样。"""
        lower, width = -(1 << (bits - 1)), 1 << bits
        return lower + (secrets.randbelow(width) if rng is None else rng.randrange(width))

    def _valid_auxiliary(self, auxiliary: TruncationAuxiliaryShare) -> TruncationAuxiliaryShare:
        """验证辅助随机量属于当前协议、角色正确且均为标量 share。"""
        if not isinstance(auxiliary, TruncationAuxiliaryShare):
            raise TypeError("auxiliary 必须是 TruncationAuxiliaryShare。")
        if auxiliary._lifecycle.owner is not self or auxiliary.party_index not in {0, 1}:
            raise ValueError("辅助随机量不属于当前截断协议。")
        self._scalar_share(auxiliary.r, "auxiliary.r")
        self._scalar_share(auxiliary.r_prime, "auxiliary.r_prime")
        return auxiliary

    def _valid_masked(self, masked: MaskedTruncationShare) -> MaskedTruncationShare:
        """验证 masked share 的所有权和标量表示。"""
        if not isinstance(masked, MaskedTruncationShare):
            raise TypeError("masked 必须是 MaskedTruncationShare。")
        if masked._lifecycle.owner is not self or masked.party_index not in {0, 1}:
            raise ValueError("masked share 不属于当前截断协议。")
        self._scalar_share(masked.value, "masked.value")
        return masked

    def _scalar_share(self, share: AdditiveShare, name: str) -> AdditiveShare:
        """复用线性原语验证单份 canonical 标量 share。"""
        try:
            normalized = self.sharing.add(share, AdditiveShare(0))
        except (TypeError, ValueError) as error:
            raise type(error)(f"{name} 非法：{error}") from error
        self._scalar_value(normalized.value, name)
        return normalized

    def _scalar_value(self, value: Any, name: str) -> int:
        """拒绝数组和非 canonical 值，保持本 Issue 的 scalar-first 边界。"""
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} 必须是标量整数。")
        if not 0 <= value < self.sharing.modulus:
            raise ValueError(f"{name} 必须位于 canonical 区间 [0, modulus)。")
        return value
