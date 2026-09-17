"""Issue #33 超 64 位素数证据、Pocklington 证明与失败原因测试。"""

from __future__ import annotations

from dataclasses import replace

import pytest

from secure_control.crypto import (
    PocklingtonCertificate,
    PocklingtonFactorEvidence,
    PrimeModulusEvidence,
    PrimeVerificationError,
    pocklington_certificate_sha256,
    verify_prime_modulus,
)

INNER_FACTOR = 9_223_372_036_854_777_359
INNER_PRIME = 18_446_744_073_709_554_719
LARGE_PRIME = 590_295_810_358_705_751_009


def _recursive_certificate() -> PocklingtonCertificate:
    """返回根候选及其 65-bit 素因子的两层确定性 Pocklington 证书。"""
    inner = PocklingtonCertificate(
        candidate=INNER_PRIME,
        factors=(
            PocklingtonFactorEvidence(prime=2, exponent=1, witness=7),
            PocklingtonFactorEvidence(prime=INNER_FACTOR, exponent=1, witness=2),
        ),
    )
    return PocklingtonCertificate(
        candidate=LARGE_PRIME,
        factors=(
            PocklingtonFactorEvidence(
                prime=INNER_PRIME,
                exponent=1,
                witness=2,
                certificate=inner,
            ),
        ),
    )


def large_prime_evidence() -> PrimeModulusEvidence:
    """构造带规范化摘要和公开来源的固定大素数证据。"""
    certificate = _recursive_certificate()
    return PrimeModulusEvidence(
        method="pocklington_v1",
        source="Issue #33 deterministic fixture",
        source_version="1",
        certificate_id="issue33-recursive-70bit-v1",
        certificate_sha256=pocklington_certificate_sha256(certificate),
        certificate=certificate,
    )


def test_mr64_verifies_small_prime_and_rejects_composite() -> None:
    """64 位范围继续使用确定性 bases，并保持当前 31/61-bit 基线兼容。"""
    for modulus in (2_147_483_647, 2_305_843_009_213_693_951):
        report = verify_prime_modulus(modulus)
        assert report.modulus == modulus
        assert report.bit_length == modulus.bit_length()
        assert report.method == "deterministic_miller_rabin_64_v1"
        assert report.status == "verified"
        assert report.certificate_id is None
        assert report.certificate_sha256 is None

    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus(65_535)
    assert captured.value.reason_code == "composite"


def test_large_prime_requires_evidence_even_when_it_passes_candidate_screen() -> None:
    """超过 MR64 确定范围的真实素数没有证书也必须 fail closed。"""
    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus(LARGE_PRIME)
    assert captured.value.reason_code == "evidence_required"


def test_recursive_pocklington_certificate_verifies_large_prime_and_source() -> None:
    """递归证书须验证根候选、65-bit 因子、来源和实际 canonical hash。"""
    evidence = large_prime_evidence()
    report = verify_prime_modulus(LARGE_PRIME, evidence)

    assert report.modulus == LARGE_PRIME
    assert report.bit_length == 70
    assert report.method == "pocklington_v1"
    assert report.status == "verified"
    assert report.source == "Issue #33 deterministic fixture"
    assert report.source_version == "1"
    assert report.certificate_id == "issue33-recursive-70bit-v1"
    assert report.certificate_sha256 == pocklington_certificate_sha256(evidence.certificate)


def test_certificate_hash_is_independent_of_factor_order() -> None:
    """规范化摘要不受证书映射或不同素因子排列顺序影响。"""
    original = _recursive_certificate()
    inner = original.factors[0].certificate
    assert inner is not None
    reversed_inner = replace(inner, factors=tuple(reversed(inner.factors)))
    reordered = replace(
        original,
        factors=(replace(original.factors[0], certificate=reversed_inner),),
    )
    assert pocklington_certificate_sha256(reordered) == pocklington_certificate_sha256(original)


def test_known_large_composite_is_rejected_without_trusting_metadata() -> None:
    """公开来源字符串不能使固定 bases 已识别的大合数获得 verified 状态。"""
    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus((1 << 64) + 1)
    assert captured.value.reason_code == "composite"


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [
        ("candidate", "candidate_mismatch"),
        ("hash", "certificate_hash_mismatch"),
        ("witness", "invalid_witness"),
        ("exponent", "incomplete_factorization"),
        ("nested", "invalid_factor_certificate"),
    ],
)
def test_tampered_pocklington_evidence_fails_with_stable_reason(
    replacement: str, reason: str
) -> None:
    """候选、摘要、witness、分解或递归因子证书被篡改时均给出稳定原因。"""
    evidence = large_prime_evidence()
    certificate = evidence.certificate
    if replacement == "candidate":
        tampered = replace(certificate, candidate=certificate.candidate + 2)
        changed = replace(
            evidence,
            certificate=tampered,
            certificate_sha256=pocklington_certificate_sha256(tampered),
        )
    elif replacement == "hash":
        changed = replace(evidence, certificate_sha256="0" * 64)
    elif replacement == "witness":
        factor = replace(certificate.factors[0], witness=1)
        tampered = replace(certificate, factors=(factor,))
        changed = replace(
            evidence,
            certificate=tampered,
            certificate_sha256=pocklington_certificate_sha256(tampered),
        )
    elif replacement == "exponent":
        factor = replace(certificate.factors[0], exponent=2)
        tampered = replace(certificate, factors=(factor,))
        changed = replace(
            evidence,
            certificate=tampered,
            certificate_sha256=pocklington_certificate_sha256(tampered),
        )
    else:
        factor = certificate.factors[0]
        assert factor.certificate is not None
        nested_factors = list(factor.certificate.factors)
        nested_factors[0] = replace(nested_factors[0], witness=1)
        nested = replace(factor.certificate, factors=tuple(nested_factors))
        tampered = replace(certificate, factors=(replace(factor, certificate=nested),))
        changed = replace(
            evidence,
            certificate=tampered,
            certificate_sha256=pocklington_certificate_sha256(tampered),
        )

    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus(LARGE_PRIME, changed)
    assert captured.value.reason_code == reason


def test_incomplete_factor_coverage_and_certificate_cycle_fail_closed() -> None:
    """不足平方根的已知因子与递归循环不能形成素数证明。"""
    incomplete = PocklingtonCertificate(
        candidate=LARGE_PRIME,
        factors=(PocklingtonFactorEvidence(prime=2, exponent=1, witness=2),),
    )
    evidence = replace(
        large_prime_evidence(),
        certificate=incomplete,
        certificate_sha256=pocklington_certificate_sha256(incomplete),
    )
    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus(LARGE_PRIME, evidence)
    assert captured.value.reason_code == "incomplete_factorization"

    inner = _recursive_certificate().factors[0].certificate
    assert inner is not None
    cyclic_factor = PocklingtonFactorEvidence(
        prime=INNER_PRIME,
        exponent=1,
        witness=2,
        certificate=inner,
    )
    # frozen dataclass 仍可能被恶意底层反射制造循环；验证器必须有独立资源防线。
    object.__setattr__(inner, "factors", (cyclic_factor,))
    cyclic = PocklingtonCertificate(
        candidate=LARGE_PRIME,
        factors=(replace(cyclic_factor, certificate=inner),),
    )
    cyclic_evidence = replace(
        large_prime_evidence(),
        certificate=cyclic,
        certificate_sha256="0" * 64,
    )
    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus(LARGE_PRIME, cyclic_evidence)
    assert captured.value.reason_code == "resource_limit_exceeded"

    with pytest.raises(PrimeVerificationError) as captured:
        verify_prime_modulus((1 << 4096) + 1)
    assert captured.value.reason_code == "resource_limit_exceeded"
