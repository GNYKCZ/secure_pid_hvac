"""2-out-of-2 加法秘密共享的性质与边界测试。"""

import random

import numpy as np
import pytest

from secure_control.crypto import AdditiveShare, TwoPartySharing


@pytest.mark.parametrize("message", [0, 1, -1, 256, 257, 258, -257])
def test_reconstruction_matches_canonical_message_for_scalar_inputs(message: int) -> None:
    """验证零、正负值和模边界在分发重构后均满足基本不变量。"""
    sharing = TwoPartySharing(modulus=257)
    first, second = sharing.share(message, rng=random.Random(20260914 + message))

    assert sharing.reconstruct(first, second) == message % 257


def test_parameterized_random_messages_preserve_reconstruction_invariant() -> None:
    """验证一批可复现实例均满足 Reconst(Share(m)) == m mod q。"""
    sharing = TwoPartySharing(modulus=65_537)
    message_rng = random.Random(7)
    share_rng = random.Random(11)

    for _ in range(64):
        message = message_rng.randrange(-(1 << 80), 1 << 80)
        first, second = sharing.share(message, rng=share_rng)
        assert sharing.reconstruct(first, second) == message % sharing.modulus


def test_linear_operations_reconstruct_to_their_modular_counterparts() -> None:
    """验证 share 线性运算全程无需重构，且最终结果符合模运算。"""
    sharing = TwoPartySharing(modulus=257)
    left = sharing.share(31, rng=random.Random(1))
    right = sharing.share(-42, rng=random.Random(2))

    summed = (sharing.add(left[0], right[0]), sharing.add(left[1], right[1]))
    difference = (sharing.subtract(left[0], right[0]), sharing.subtract(left[1], right[1]))
    shifted = (sharing.add_public(left[0], 9), left[1])
    reduced = (sharing.subtract_public(left[0], 9), left[1])
    scaled = (sharing.multiply_public(left[0], -3), sharing.multiply_public(left[1], -3))

    assert sharing.reconstruct(*summed) == (31 - 42) % 257
    assert sharing.reconstruct(*difference) == (31 + 42) % 257
    assert sharing.reconstruct(*shifted) == (31 + 9) % 257
    assert sharing.reconstruct(*reduced) == (31 - 9) % 257
    assert sharing.reconstruct(*scaled) == (31 * -3) % 257


def test_vector_and_matrix_shares_match_elementwise_scalar_semantics() -> None:
    """验证向量和矩阵的分发、线性运算与逐元素模计算一致。"""
    sharing = TwoPartySharing(modulus=257)
    message = np.array([[0, -1], [256, 258]], dtype=object)
    first, second = sharing.share(message, rng=random.Random(42))
    doubled = (
        sharing.multiply_public(first, 2),
        sharing.multiply_public(second, 2),
    )

    reconstructed = sharing.reconstruct(first, second)
    doubled_reconstructed = sharing.reconstruct(*doubled)

    assert reconstructed.dtype == object
    assert reconstructed.shape == (2, 2)
    assert reconstructed.tolist() == [[0, 256], [256, 1]]
    assert doubled_reconstructed.tolist() == [[0, 255], [255, 2]]


def test_seeded_rng_is_reproducible_but_default_path_uses_system_random_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """验证测试可重放，而无注入时明确调用生产默认的系统随机源。"""
    sharing = TwoPartySharing(modulus=257)

    first_run = sharing.share([1, 2, 3], rng=random.Random(99))
    second_run = sharing.share([1, 2, 3], rng=random.Random(99))
    assert first_run[0].value.tolist() == second_run[0].value.tolist()
    assert first_run[1].value.tolist() == second_run[1].value.tolist()

    requested_moduli: list[int] = []

    def deterministic_system_random(modulus: int) -> int:
        requested_moduli.append(modulus)
        return 5

    monkeypatch.setattr(
        "secure_control.crypto.secret_sharing.secrets.randbelow", deterministic_system_random
    )
    default_first, default_second = sharing.share([10, 11])

    assert requested_moduli == [257, 257]
    assert default_first.value.tolist() == [5, 5]
    assert default_second.value.tolist() == [5, 6]


def test_server_facing_share_object_contains_only_one_local_value() -> None:
    """验证单份 share 数据结构没有容纳另一份 share 的字段。"""
    sharing = TwoPartySharing(modulus=257)
    first, _ = sharing.share(17, rng=random.Random(3))

    assert isinstance(first, AdditiveShare)
    assert tuple(first.__dataclass_fields__) == ("value",)


def test_large_modulus_uses_arbitrary_precision_integer_path() -> None:
    """验证 256 位模数与大整数消息不会落入固定宽度整数运算。"""
    modulus = (1 << 256) - 189
    sharing = TwoPartySharing(modulus=modulus)
    first, second = sharing.share([modulus - 1, -2], rng=random.Random(123))

    reconstructed = sharing.reconstruct(first, second)

    assert reconstructed.dtype == object
    assert reconstructed.tolist() == [modulus - 1, modulus - 2]
    assert all(isinstance(item, int) for item in reconstructed)


def test_invalid_modulus_share_values_and_shapes_fail_explicitly() -> None:
    """验证非法模数、非 canonical share 与错配 shape 不会被静默接受。"""
    with pytest.raises(ValueError, match="modulus"):
        TwoPartySharing(2)
    with pytest.raises(TypeError, match="modulus"):
        TwoPartySharing(True)

    sharing = TwoPartySharing(257)
    valid_vector, _ = sharing.share([1, 2], rng=random.Random(4))
    valid_matrix, _ = sharing.share([[1, 2], [3, 4]], rng=random.Random(5))

    with pytest.raises(ValueError, match="canonical"):
        sharing.reconstruct(AdditiveShare(-1), AdditiveShare(1))
    with pytest.raises(ValueError, match="同形"):
        sharing.add(valid_vector, valid_matrix)
    with pytest.raises(TypeError, match="AdditiveShare"):
        sharing.add((valid_vector, valid_matrix), valid_vector)  # type: ignore[arg-type]
