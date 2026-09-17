"""Protocol 2 模数的确定性素数验证与可审计 Pocklington 证据。"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from itertools import islice
from math import gcd
from typing import Literal, cast

PrimeVerificationMethod = Literal[
    "deterministic_miller_rabin_64_v1",
    "pocklington_v1",
]
PrimeVerificationReason = Literal[
    "invalid_modulus",
    "composite",
    "evidence_required",
    "unsupported_method",
    "candidate_mismatch",
    "certificate_hash_mismatch",
    "incomplete_factorization",
    "invalid_factor_certificate",
    "invalid_witness",
    "resource_limit_exceeded",
]

_MR64_LIMIT = 1 << 64
_MR64_BASES = (2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022)
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
_MAX_CERTIFICATE_BITS = 4096
_MAX_CERTIFICATE_DEPTH = 32
_MAX_CERTIFICATE_NODES = 256
_MAX_FACTOR_EXPONENT = 4096


class PrimeVerificationError(ValueError):
    """携带稳定 reason code 的素数可信性验证失败。"""

    def __init__(
        self,
        reason_code: PrimeVerificationReason | str,
        message: str | None = None,
    ) -> None:
        # 既有边界会用 type(error)(context_message) 增补上下文；该兼容路径不冒充原始精确原因。
        if message is None:
            message = str(reason_code)
            reason_code = "invalid_modulus"
        super().__init__(message)
        self.reason_code = cast(PrimeVerificationReason, reason_code)


def _require_integer(value: object, name: str, *, minimum: int) -> int:
    """拒绝 bool 和非整数，避免证书字段发生隐式类型转换。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} 必须是整数。")
    if value < minimum:
        raise ValueError(f"{name} 必须不小于 {minimum}。")
    return value


def _require_nonempty(value: object, name: str) -> str:
    """要求公开来源字段为非空字符串并保留原始可审计文本。"""
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{name} 必须是非空字符串。")
    return value


def _validate_factor_resource_bounds(prime: int, exponent: int, witness: int) -> None:
    """在 canonical 字符串转换前限制 factor 的公开整数工作量。"""
    if (
        prime.bit_length() > _MAX_CERTIFICATE_BITS
        or witness.bit_length() > _MAX_CERTIFICATE_BITS
        or exponent > _MAX_FACTOR_EXPONENT
    ):
        raise PrimeVerificationError(
            "resource_limit_exceeded", "Pocklington factor 整数字段超过资源限制。"
        )


@dataclass(frozen=True, slots=True)
class PocklingtonFactorEvidence:
    """记录 ``n-1`` 中一个不同素因子的指数、witness 与递归证书。"""

    prime: int
    exponent: int
    witness: int
    certificate: PocklingtonCertificate | None = None

    def __post_init__(self) -> None:
        """冻结并校验公开整数；witness 的候选相关范围由验证器检查。"""
        _require_integer(self.prime, "factor prime", minimum=2)
        _require_integer(self.exponent, "factor exponent", minimum=1)
        _require_integer(self.witness, "factor witness", minimum=0)
        _validate_factor_resource_bounds(self.prime, self.exponent, self.witness)
        if self.certificate is not None and not isinstance(
            self.certificate, PocklingtonCertificate
        ):
            raise TypeError("factor certificate 必须是 PocklingtonCertificate 或 None。")


@dataclass(frozen=True, slots=True)
class PocklingtonCertificate:
    """记录候选数及满足 Pocklington 条件所需的公开已知因子。"""

    candidate: int
    factors: tuple[PocklingtonFactorEvidence, ...]

    def __post_init__(self) -> None:
        """将因子集合冻结为 tuple，并拒绝空证书或错误元素类型。"""
        _require_integer(self.candidate, "certificate candidate", minimum=2)
        if self.candidate.bit_length() > _MAX_CERTIFICATE_BITS:
            raise PrimeVerificationError(
                "resource_limit_exceeded", "Pocklington candidate 超过资源限制。"
            )
        try:
            # 最多读取上限数量的元素；无限迭代器或超长输入不能先被完整物化。
            factors = tuple(islice(iter(self.factors), _MAX_CERTIFICATE_NODES))
        except TypeError as error:
            raise TypeError("certificate factors 必须是可迭代的因子证据。") from error
        if len(factors) >= _MAX_CERTIFICATE_NODES:
            raise PrimeVerificationError(
                "resource_limit_exceeded", "Pocklington factor entries 超过资源限制。"
            )
        if not factors or not all(isinstance(item, PocklingtonFactorEvidence) for item in factors):
            raise TypeError("certificate factors 必须包含 PocklingtonFactorEvidence。")
        object.__setattr__(self, "factors", factors)


@dataclass(frozen=True, slots=True)
class PrimeModulusEvidence:
    """把本地可验证证书与其公开来源、标识和规范化摘要绑定。"""

    method: Literal["pocklington_v1"]
    source: str
    source_version: str
    certificate_id: str
    certificate_sha256: str
    certificate: PocklingtonCertificate

    def __post_init__(self) -> None:
        """校验证据 schema；数学条件和摘要一致性仍由统一验证入口负责。"""
        if self.method != "pocklington_v1":
            raise PrimeVerificationError("unsupported_method", "仅支持 pocklington_v1 证据。")
        _require_nonempty(self.source, "evidence source")
        _require_nonempty(self.source_version, "evidence source_version")
        _require_nonempty(self.certificate_id, "evidence certificate_id")
        if (
            not isinstance(self.certificate_sha256, str)
            or len(self.certificate_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.certificate_sha256)
        ):
            raise TypeError("certificate_sha256 必须是 64 位小写十六进制字符串。")
        if not isinstance(self.certificate, PocklingtonCertificate):
            raise TypeError("certificate 必须是 PocklingtonCertificate。")


@dataclass(frozen=True, slots=True)
class PrimeModulusVerification:
    """记录确定验证成功的模数、方法和可公开审计的来源摘要。"""

    modulus: int
    bit_length: int
    method: PrimeVerificationMethod
    status: Literal["verified"]
    source: str
    source_version: str
    certificate_id: str | None
    certificate_sha256: str | None


@dataclass(slots=True)
class _VerificationBudget:
    """限制证书、factor entries 的总节点数和递归循环，防止资源耗尽。"""

    nodes: int = 0
    active_candidates: set[int] | None = None

    def __post_init__(self) -> None:
        if self.active_candidates is None:
            self.active_candidates = set()


def _consume_structure_budget(budget: _VerificationBudget, factor_count: int) -> None:
    """在排序、序列化或数学循环前统一计入 certificate 与全部 factor 节点。"""
    budget.nodes += 1 + factor_count
    if budget.nodes > _MAX_CERTIFICATE_NODES:
        raise PrimeVerificationError("resource_limit_exceeded", "Pocklington 证书节点过多。")


def _passes_miller_rabin_screen(value: int) -> bool:
    """用 MR64 固定 bases 筛除合数；仅在 ``value < 2^64`` 时可证明素数。"""
    if value < 2:
        return False
    if value in _SMALL_PRIMES:
        return True
    if any(value % divisor == 0 for divisor in _SMALL_PRIMES):
        return False
    exponent, twos = value - 1, 0
    while exponent % 2 == 0:
        exponent //= 2
        twos += 1
    for base in _MR64_BASES:
        if base % value == 0:
            continue
        witness = pow(base, exponent, value)
        if witness in {1, value - 1}:
            continue
        for _ in range(twos - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def _canonical_certificate(
    certificate: PocklingtonCertificate,
    *,
    depth: int,
    budget: _VerificationBudget,
) -> dict[str, object]:
    """生成字段和因子顺序稳定的公开结构，并对 hash 路径施加同等资源限制。"""
    if depth > _MAX_CERTIFICATE_DEPTH or certificate.candidate.bit_length() > _MAX_CERTIFICATE_BITS:
        raise PrimeVerificationError("resource_limit_exceeded", "Pocklington 证书超过资源限制。")
    assert budget.active_candidates is not None
    if certificate.candidate in budget.active_candidates:
        raise PrimeVerificationError("resource_limit_exceeded", "Pocklington 证书存在递归循环。")
    _consume_structure_budget(budget, len(certificate.factors))
    budget.active_candidates.add(certificate.candidate)
    try:
        factors = []
        for factor in certificate.factors:
            _validate_factor_resource_bounds(factor.prime, factor.exponent, factor.witness)
        for factor in sorted(certificate.factors, key=lambda item: item.prime):
            nested = (
                None
                if factor.certificate is None
                else _canonical_certificate(
                    factor.certificate,
                    depth=depth + 1,
                    budget=budget,
                )
            )
            factors.append(
                {
                    "certificate": nested,
                    "exponent": str(factor.exponent),
                    "prime": str(factor.prime),
                    "witness": str(factor.witness),
                }
            )
        return {"candidate": str(certificate.candidate), "factors": factors}
    finally:
        budget.active_candidates.remove(certificate.candidate)


def pocklington_certificate_sha256(certificate: PocklingtonCertificate) -> str:
    """返回与映射字段和不同素因子排列顺序无关的 canonical SHA-256。"""
    if not isinstance(certificate, PocklingtonCertificate):
        raise TypeError("certificate 必须是 PocklingtonCertificate。")
    normalized = _canonical_certificate(certificate, depth=0, budget=_VerificationBudget())
    payload = json.dumps(
        normalized,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _verify_pocklington(
    certificate: PocklingtonCertificate,
    expected_candidate: int,
    *,
    depth: int,
    budget: _VerificationBudget,
) -> None:
    """以纯整数条件验证一个候选及其所有递归大素因子。"""
    if certificate.candidate != expected_candidate:
        raise PrimeVerificationError("candidate_mismatch", "证书 candidate 与待验证模数不一致。")
    if depth > _MAX_CERTIFICATE_DEPTH or expected_candidate.bit_length() > _MAX_CERTIFICATE_BITS:
        raise PrimeVerificationError("resource_limit_exceeded", "Pocklington 证书超过资源限制。")
    assert budget.active_candidates is not None
    if expected_candidate in budget.active_candidates:
        raise PrimeVerificationError("resource_limit_exceeded", "Pocklington 证书存在递归循环。")
    _consume_structure_budget(budget, len(certificate.factors))
    if not _passes_miller_rabin_screen(expected_candidate):
        raise PrimeVerificationError("composite", "固定 Miller--Rabin bases 已证明候选为合数。")

    budget.active_candidates.add(expected_candidate)
    try:
        known_factor_product = 1
        distinct_primes: set[int] = set()
        for factor in certificate.factors:
            if factor.prime in distinct_primes:
                raise PrimeVerificationError(
                    "invalid_factor_certificate", "Pocklington factors 必须按不同素因子记录。"
                )
            distinct_primes.add(factor.prime)
            if factor.exponent > _MAX_FACTOR_EXPONENT:
                raise PrimeVerificationError(
                    "resource_limit_exceeded", "Pocklington factor exponent 超过资源限制。"
                )
            if factor.prime < _MR64_LIMIT:
                if not _passes_miller_rabin_screen(factor.prime):
                    raise PrimeVerificationError(
                        "invalid_factor_certificate", "Pocklington factor 不是已验证素数。"
                    )
            else:
                if factor.certificate is None:
                    raise PrimeVerificationError(
                        "invalid_factor_certificate", "超 64 位 factor 缺少递归证书。"
                    )
                try:
                    _verify_pocklington(
                        factor.certificate,
                        factor.prime,
                        depth=depth + 1,
                        budget=budget,
                    )
                except PrimeVerificationError as error:
                    if error.reason_code == "resource_limit_exceeded":
                        raise
                    raise PrimeVerificationError(
                        "invalid_factor_certificate",
                        f"递归 factor 证书无效：{error.reason_code}。",
                    ) from error
            factor_power = 1
            for _ in range(factor.exponent):
                factor_power *= factor.prime
                if factor_power > expected_candidate - 1:
                    raise PrimeVerificationError(
                        "incomplete_factorization", "已知因子乘积不整除 candidate-1。"
                    )
            known_factor_product *= factor_power
            if known_factor_product > expected_candidate - 1:
                raise PrimeVerificationError(
                    "incomplete_factorization", "已知因子乘积不整除 candidate-1。"
                )

        if (expected_candidate - 1) % known_factor_product != 0:
            raise PrimeVerificationError(
                "incomplete_factorization", "已知因子乘积不整除 candidate-1。"
            )
        # Pocklington 的严格覆盖条件使用整数乘法，避免 sqrt 的浮点舍入影响结论。
        if known_factor_product * known_factor_product <= expected_candidate:
            raise PrimeVerificationError(
                "incomplete_factorization", "已知素因子部分未满足 F^2 > candidate。"
            )
        for factor in certificate.factors:
            witness = factor.witness
            if not 1 < witness < expected_candidate:
                raise PrimeVerificationError("invalid_witness", "Pocklington witness 超出范围。")
            if pow(witness, expected_candidate - 1, expected_candidate) != 1:
                raise PrimeVerificationError("invalid_witness", "witness 不满足 Fermat 条件。")
            reduced = pow(
                witness,
                (expected_candidate - 1) // factor.prime,
                expected_candidate,
            )
            if gcd(reduced - 1, expected_candidate) != 1:
                raise PrimeVerificationError("invalid_witness", "witness 不满足 gcd 条件。")
    finally:
        budget.active_candidates.remove(expected_candidate)


def verify_prime_modulus(
    modulus: int,
    evidence: PrimeModulusEvidence | None = None,
) -> PrimeModulusVerification:
    """只在 MR64 或本地 Pocklington 确定验证成功后返回不可变报告。"""
    if isinstance(modulus, bool) or not isinstance(modulus, int):
        raise TypeError("modulus 必须是整数。")
    if modulus < 2:
        raise PrimeVerificationError("invalid_modulus", "modulus 必须是不小于 2 的素数。")
    if modulus.bit_length() > _MAX_CERTIFICATE_BITS:
        raise PrimeVerificationError("resource_limit_exceeded", "modulus 超过验证资源限制。")
    if not _passes_miller_rabin_screen(modulus):
        raise PrimeVerificationError("composite", "Protocol 2 要求 modulus 为素数。")
    if modulus < _MR64_LIMIT:
        return PrimeModulusVerification(
            modulus=modulus,
            bit_length=modulus.bit_length(),
            method="deterministic_miller_rabin_64_v1",
            status="verified",
            source="secure_control.crypto.primes",
            source_version="mr64-v1",
            certificate_id=None,
            certificate_sha256=None,
        )
    if evidence is None:
        raise PrimeVerificationError(
            "evidence_required", "modulus >= 2^64 时必须提供确定性素数证据。"
        )
    if not isinstance(evidence, PrimeModulusEvidence):
        raise TypeError("evidence 必须是 PrimeModulusEvidence 或 None。")
    if evidence.method != "pocklington_v1":
        raise PrimeVerificationError("unsupported_method", "仅支持 pocklington_v1 证据。")
    if evidence.certificate.candidate != modulus:
        raise PrimeVerificationError("candidate_mismatch", "证书 candidate 与 modulus 不一致。")
    actual_hash = pocklington_certificate_sha256(evidence.certificate)
    if not hmac.compare_digest(actual_hash, evidence.certificate_sha256):
        raise PrimeVerificationError(
            "certificate_hash_mismatch", "证书 canonical SHA-256 与声明不一致。"
        )
    _verify_pocklington(
        evidence.certificate,
        modulus,
        depth=0,
        budget=_VerificationBudget(),
    )
    return PrimeModulusVerification(
        modulus=modulus,
        bit_length=modulus.bit_length(),
        method="pocklington_v1",
        status="verified",
        source=evidence.source,
        source_version=evidence.source_version,
        certificate_id=evidence.certificate_id,
        certificate_sha256=actual_hash,
    )
