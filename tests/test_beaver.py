"""Beaver Protocol 1 标量乘法、公开项归属和资源生命周期测试。"""

import random

import pytest

from secure_control.crypto import AdditiveShare, BeaverMultiplier, TwoPartySharing


def run_scalar_protocol(
    multiplier: BeaverMultiplier,
    x: int,
    y: int,
    *,
    rng: random.Random,
) -> tuple[int, object, object, object]:
    """按两方局部步骤运行一次测试协议，并只在公开边界重构 d/e。"""
    x_shares = multiplier.sharing.share(x, rng=rng)
    y_shares = multiplier.sharing.share(y, rng=rng)
    triple_shares = multiplier.create_triple(rng=rng)
    first_masked = multiplier.mask_inputs(x_shares[0], y_shares[0], triple_shares[0])
    second_masked = multiplier.mask_inputs(x_shares[1], y_shares[1], triple_shares[1])
    opened = multiplier.open_masked_differences(first_masked, second_masked)
    first_result = multiplier.finish(triple_shares[0], opened)
    second_result = multiplier.finish(triple_shares[1], opened)
    return (
        multiplier.sharing.reconstruct(first_result, second_result),
        triple_shares,
        opened,
        first_result,
    )


@pytest.mark.parametrize("x, y", [(0, 0), (0, -4), (3, 5), (-3, 5), (-3, -5), (256, 2), (257, -1)])
def test_protocol_one_reconstruction_matches_modular_product(x: int, y: int) -> None:
    """验证正负、零与模边界输入均重构为 x*y mod q。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)

    product, triple_shares, _, _ = run_scalar_protocol(
        multiplier, x, y, rng=random.Random(100 + x - y)
    )

    assert product == (x * y) % 257
    assert triple_shares[0].is_consumed
    assert triple_shares[1].is_consumed
    assert multiplier.created_triples == 1
    assert multiplier.consumed_triples == 1
    assert multiplier.pending_triples == 0


def test_generated_triple_reconstructs_to_c_equals_a_times_b() -> None:
    """验证预处理三元组自身满足 c=a*b mod q。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)
    first, second = multiplier.create_triple(rng=random.Random(23))

    a = sharing.reconstruct(first.a, second.a)
    b = sharing.reconstruct(first.b, second.b)
    c = sharing.reconstruct(first.c, second.c)

    assert c == (a * b) % 257
    assert multiplier.created_triples == 1
    assert multiplier.consumed_triples == 0


def test_public_de_is_added_once_to_first_party_and_detects_double_or_missing_term() -> None:
    """选择非零 d/e 用例，验证公开项一次归属是乘法正确性的必要条件。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)
    product, _, opened, _ = run_scalar_protocol(multiplier, 19, 43, rng=random.Random(1234))

    assert opened.d != 0
    assert opened.e != 0
    assert product == (19 * 43) % 257


def test_triple_cannot_be_reused_after_masking_or_completion() -> None:
    """验证同一资源不能再次生成遮蔽值或重复完成一方输出。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)
    rng = random.Random(8)
    x_shares = sharing.share(8, rng=rng)
    y_shares = sharing.share(9, rng=rng)
    triples = multiplier.create_triple(rng=rng)
    first_masked = multiplier.mask_inputs(x_shares[0], y_shares[0], triples[0])
    second_masked = multiplier.mask_inputs(x_shares[1], y_shares[1], triples[1])
    opened = multiplier.open_masked_differences(first_masked, second_masked)
    multiplier.finish(triples[0], opened)

    with pytest.raises(ValueError, match="完成"):
        multiplier.finish(triples[0], opened)
    with pytest.raises(ValueError, match="遮蔽"):
        multiplier.mask_inputs(x_shares[0], y_shares[0], triples[0])

    multiplier.finish(triples[1], opened)
    assert triples[0].is_consumed
    assert multiplier.consumed_triples == 1


def test_random_trials_use_one_independent_triple_per_secret_product() -> None:
    """验证 64 次固定 seed 随机试验均正确，并一一消费独立三元组。"""
    sharing = TwoPartySharing(65_537)
    multiplier = BeaverMultiplier(sharing)
    rng = random.Random(2026)

    for _ in range(64):
        x = rng.randrange(-(1 << 40), 1 << 40)
        y = rng.randrange(-(1 << 40), 1 << 40)
        product, _, _, _ = run_scalar_protocol(multiplier, x, y, rng=rng)
        assert product == (x * y) % sharing.modulus

    assert multiplier.created_triples == 64
    assert multiplier.consumed_triples == 64
    assert multiplier.pending_triples == 0


def test_public_times_share_does_not_consume_a_beaver_triple() -> None:
    """验证公开常数乘 share 是线性操作，不应申请或消费三元组。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)
    first, second = sharing.share(17, rng=random.Random(5))

    product = (
        sharing.multiply_public(first, -3),
        sharing.multiply_public(second, -3),
    )

    assert sharing.reconstruct(*product) == (17 * -3) % 257
    assert multiplier.created_triples == 0
    assert multiplier.consumed_triples == 0


def test_large_modulus_product_uses_python_integer_path() -> None:
    """验证 256 位模数下的 Protocol 1 仍避免固定宽度整数回绕。"""
    modulus = (1 << 256) - 189
    sharing = TwoPartySharing(modulus)
    multiplier = BeaverMultiplier(sharing)

    product, _, _, _ = run_scalar_protocol(
        multiplier,
        modulus - 2,
        modulus - 3,
        rng=random.Random(77),
    )

    assert product == 6


def test_scalar_first_api_rejects_array_shares_and_mixed_triples() -> None:
    """验证矩阵路径未被伪装实现，且不同三元组的 d/e 不能混用。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)
    vector_x = sharing.share([1, 2], rng=random.Random(1))
    scalar_y = sharing.share(3, rng=random.Random(2))
    first_triple, second_triple = multiplier.create_triple(rng=random.Random(3))

    with pytest.raises(TypeError, match="标量"):
        multiplier.mask_inputs(vector_x[0], scalar_y[0], first_triple)

    first_x, second_x = sharing.share(4, rng=random.Random(4))
    first_y, second_y = sharing.share(5, rng=random.Random(5))
    other_first, other_second = multiplier.create_triple(rng=random.Random(6))
    masked_first = multiplier.mask_inputs(first_x, first_y, first_triple)
    masked_second = multiplier.mask_inputs(second_x, second_y, other_second)

    with pytest.raises(ValueError, match="同一个"):
        multiplier.open_masked_differences(masked_first, masked_second)
    assert not second_triple.is_consumed
    assert not other_first.is_consumed


def test_no_server_step_accepts_plaintext_inputs_or_two_share_container() -> None:
    """验证局部遮蔽步骤只接收单份 AdditiveShare，拒绝明文和 share 二元组。"""
    sharing = TwoPartySharing(257)
    multiplier = BeaverMultiplier(sharing)
    triples = multiplier.create_triple(rng=random.Random(9))
    y_shares = sharing.share(5, rng=random.Random(11))

    with pytest.raises(TypeError, match="AdditiveShare"):
        multiplier.mask_inputs(AdditiveShare(4), (y_shares[0], y_shares[1]), triples[0])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="AdditiveShare"):
        multiplier.mask_inputs(4, y_shares[0], triples[0])  # type: ignore[arg-type]
