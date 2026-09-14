"""安全算术原语的组合门禁：尺度、中心化表示、资源与随机性。"""

import random

import numpy as np
import pytest

from secure_control.crypto import (
    BeaverMultiplier,
    FixedPointContext,
    SecureTruncation,
    TwoPartySharing,
)

MODULUS = 2_147_483_647
SECURITY_PARAMETER = 8


def centered(residue: int, modulus: int) -> int:
    """将 canonical residue 转换为本项目约定的中心化有符号整数。"""
    return residue if residue < (modulus + 1) // 2 else residue - modulus


def make_context(ell: int) -> tuple[FixedPointContext, TwoPartySharing, SecureTruncation]:
    """建立共享同一素模数且满足 Protocol 2 前置条件的组合测试上下文。"""
    fixed_point = FixedPointContext(modulus=MODULUS, integer_bits=20, fractional_bits=ell)
    sharing = TwoPartySharing(MODULUS)
    truncation = SecureTruncation(sharing, ell=ell, security_parameter=SECURITY_PARAMETER)
    return fixed_point, sharing, truncation


def run_secure_product(
    fixed_point: FixedPointContext,
    sharing: TwoPartySharing,
    truncation: SecureTruncation,
    left: float,
    right: float,
    *,
    seed: int,
) -> tuple[int, int, BeaverMultiplier]:
    """组合编码、共享、Beaver 与 Protocol 2，返回乘积和截断输出的中心化整数。"""
    rng = random.Random(seed)
    left_encoded = fixed_point.encode(left)
    right_encoded = fixed_point.encode(right)
    left_shares = sharing.share(left_encoded, rng=rng)
    right_shares = sharing.share(right_encoded, rng=rng)
    multiplier = BeaverMultiplier(sharing)
    triples = multiplier.create_triple(rng=rng)
    first_masked = multiplier.mask_inputs(left_shares[0], right_shares[0], triples[0])
    second_masked = multiplier.mask_inputs(left_shares[1], right_shares[1], triples[1])
    opened = multiplier.open_masked_differences(first_masked, second_masked)
    product_shares = (
        multiplier.finish(triples[0], opened),
        multiplier.finish(triples[1], opened),
    )
    product = centered(sharing.reconstruct(*product_shares), sharing.modulus)
    truncation.validate_message(product)
    auxiliary = truncation.create_auxiliary(rng=rng)
    first_truncation = truncation.mask_input(product_shares[0], auxiliary[0])
    second_truncation = truncation.mask_input(product_shares[1], auxiliary[1])
    p1_value = truncation.p1_reconstruct_masked(
        first_truncation, truncation.p2_send_masked(second_truncation)
    )
    output_shares = (
        truncation.finish_p1(product_shares[0], auxiliary[0], p1_value),
        truncation.finish_p2(product_shares[1], auxiliary[1]),
    )
    output = centered(sharing.reconstruct(*output_shares), sharing.modulus)
    return product, output, multiplier


def test_fixed_point_share_reconstruct_decode_preserves_scale_shape_and_dtype() -> None:
    """验证编码→共享→重构→解码保留 2^ell 尺度、矩阵 shape 和 object residue 容器。"""
    fixed_point, sharing, _ = make_context(8)
    values = np.array([[-3.25, 0.0], [1.5, 7.125]])
    rng = random.Random(101)

    encoded_residues = fixed_point.encode_to_residue(values)
    first, second = sharing.share(encoded_residues, rng=rng)
    reconstructed = sharing.reconstruct(first, second)
    decoded = fixed_point.decode_residue(reconstructed)

    assert reconstructed.dtype == object
    assert reconstructed.shape == values.shape
    assert np.all(np.abs(decoded - values) <= 0.5 / fixed_point.scale), "seed=101 stage=decode"


def test_known_value_gate_tracks_scale_from_product_to_truncation_and_decode() -> None:
    """验证乘法从 2^(2ell) 经 Protocol 2 回到 2^ell，且资源各消费一次。"""
    fixed_point, sharing, truncation = make_context(8)
    left, right, seed = 1.25, -0.75, 202609

    product, output, multiplier = run_secure_product(
        fixed_point, sharing, truncation, left, right, seed=seed
    )
    expected_product = fixed_point.encode(left) * fixed_point.encode(right)
    expected_round = truncation.paper_round_divide(expected_product)

    assert fixed_point.product_fractional_bits == 16
    assert product == expected_product, f"seed={seed} stage=Beaver product={product}"
    assert output - expected_round in {-1, 0, 1}, f"seed={seed} stage=Trunc output={output}"
    assert fixed_point.decode(product, fractional_bits=16) == pytest.approx(left * right)
    assert fixed_point.decode(output) == pytest.approx(left * right, abs=1.0 / fixed_point.scale)
    assert multiplier.created_triples == multiplier.consumed_triples == 1
    assert truncation.created_masks == truncation.consumed_masks == 1


@pytest.mark.parametrize("ell", [4, 8, 12])
def test_fixed_seed_randomized_gate_trials_are_isolated_and_reproducible(ell: int) -> None:
    """验证多尺度随机试验不污染资源状态，并可用 seed 单命令重现。"""
    seed = 91_000 + ell
    fixed_point, sharing, truncation = make_context(ell)
    rng = random.Random(seed)
    magnitude = min(8.0, 0.25 * (truncation.maximum_message**0.5) / fixed_point.scale)
    transcript: list[tuple[int, int]] = []

    for trial in range(16):
        left, right = rng.uniform(-magnitude, magnitude), rng.uniform(-magnitude, magnitude)
        product, output, multiplier = run_secure_product(
            fixed_point, sharing, truncation, left, right, seed=rng.randrange(1 << 30)
        )
        expected_product = fixed_point.encode(left) * fixed_point.encode(right)
        expected_round = truncation.paper_round_divide(expected_product)
        assert product == expected_product, f"seed={seed} trial={trial} stage=Beaver"
        assert output - expected_round in {-1, 0, 1}, f"seed={seed} trial={trial} stage=Trunc"
        assert multiplier.created_triples == multiplier.consumed_triples == 1
        transcript.append((product, output))

    repeat_fixed, repeat_sharing, repeat_truncation = make_context(ell)
    repeat_rng = random.Random(seed)
    repeated: list[tuple[int, int]] = []
    for _ in range(16):
        left, right = (
            repeat_rng.uniform(-magnitude, magnitude),
            repeat_rng.uniform(-magnitude, magnitude),
        )
        product, output, _ = run_secure_product(
            repeat_fixed,
            repeat_sharing,
            repeat_truncation,
            left,
            right,
            seed=repeat_rng.randrange(1 << 30),
        )
        repeated.append((product, output))

    assert transcript == repeated, f"seed={seed} stage=reproducibility"
    assert truncation.created_masks == truncation.consumed_masks == 16
    assert repeat_truncation.created_masks == repeat_truncation.consumed_masks == 16


def test_large_modulus_path_uses_object_residues_without_machine_integer_wraparound() -> None:
    """验证大模数下的定点共享重构不经过固定宽度整数中间值。"""
    modulus = (1 << 256) - 189
    fixed_point = FixedPointContext(modulus=modulus, integer_bits=128, fractional_bits=8)
    sharing = TwoPartySharing(modulus)
    values = np.array([-(1 << 50) / 256, (1 << 50) / 256])

    first, second = sharing.share(fixed_point.encode_to_residue(values), rng=random.Random(31))
    reconstructed = sharing.reconstruct(first, second)

    assert reconstructed.dtype == object
    assert all(isinstance(value, int) for value in reconstructed)
    assert np.allclose(fixed_point.decode_residue(reconstructed), values)


def test_gate_rejects_product_outside_truncation_range_before_masking() -> None:
    """验证数学范围违规被显式识别，而不是取模后伪装成正常截断。"""
    _, _, truncation = make_context(8)

    with pytest.raises(ValueError, match="Z<kappa>"):
        truncation.validate_message(truncation.maximum_message + 1)
