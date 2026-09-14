"""定点编码与中心化模表示的边界测试。"""

from collections.abc import Callable

import numpy as np
import pytest

from secure_control.crypto import FixedPointContext


def test_paper_rounding_handles_positive_and_negative_half_ties() -> None:
    """验证论文 floor(x + 1/2) 规则，而非 banker rounding。"""
    context = FixedPointContext(modulus=257, integer_bits=8, fractional_bits=1)

    encoded = context.encode(np.array([0.25, -0.25, 0.75, -0.75, -1.25]))

    assert encoded.tolist() == [1, 0, 2, -1, -2]


def test_encode_decode_round_trip_is_bounded_by_half_quantization_step() -> None:
    """验证编码解码误差不超过一个量化步长的一半。"""
    context = FixedPointContext(modulus=257, integer_bits=8, fractional_bits=3)
    values = np.array([-3.125, -0.2, 0.0, 1.26, 7.75])

    decoded = context.decode(context.encode(values))

    assert np.all(np.abs(decoded - values) <= 0.5 / context.scale)


def test_centered_mapping_covers_even_and_odd_modulus_boundaries() -> None:
    """验证 q/2 附近的 canonical 与中心化表示保持唯一且一致。"""
    even_context = FixedPointContext(modulus=16, integer_bits=4, fractional_bits=0)
    odd_context = FixedPointContext(modulus=17, integer_bits=4, fractional_bits=0)

    assert even_context.from_residue(np.array([0, 7, 8, 15])).tolist() == [0, 7, -8, -1]
    assert odd_context.from_residue(np.array([0, 8, 9, 16])).tolist() == [0, 8, -8, -1]
    assert even_context.to_residue(np.array([-8, -1, 0, 7])).tolist() == [8, 15, 0, 7]


def test_scalar_vector_and_matrix_shapes_preserve_arbitrary_precision_integer_storage() -> None:
    """验证标量、向量和矩阵均保持 shape，模整数容器不退化为固定位宽。"""
    context = FixedPointContext(modulus=257, integer_bits=8, fractional_bits=2)

    scalar = context.encode_to_residue(-1.25)
    vector = context.encode_to_residue([0.0, 0.25, -0.5])
    matrix = context.add_residues(np.array([[1], [2]]), np.array([3, 4]))

    assert scalar == 252
    assert vector.shape == (3,)
    assert vector.dtype == object
    assert vector.tolist() == [0, 1, 255]
    assert matrix.shape == (2, 2)
    assert matrix.dtype == object
    assert matrix.tolist() == [[4, 5], [5, 6]]


def test_large_modulus_product_uses_python_integers_without_int64_wraparound() -> None:
    """验证大模数乘法没有经由 NumPy 固定位宽整数产生静默回绕。"""
    modulus = (1 << 256) - 189
    context = FixedPointContext(modulus=modulus, integer_bits=255, fractional_bits=0)
    values = np.array([modulus - 2, modulus - 3], dtype=object)

    product = context.multiply_residues(values, values)

    assert product.dtype == object
    assert product.tolist() == [4, 9]
    assert all(isinstance(item, int) for item in product)


@pytest.mark.parametrize(
    ("constructor", "error_type"),
    [
        (lambda: FixedPointContext(modulus=2, integer_bits=1, fractional_bits=0), ValueError),
        (lambda: FixedPointContext(modulus=17, integer_bits=5, fractional_bits=0), ValueError),
        (lambda: FixedPointContext(modulus=17, integer_bits=4, fractional_bits=-1), ValueError),
        (lambda: FixedPointContext(modulus=True, integer_bits=1, fractional_bits=0), TypeError),
    ],
)
def test_context_rejects_illegal_parameters(
    constructor: Callable[[], FixedPointContext], error_type: type[Exception]
) -> None:
    """验证模数、位数和类型不满足前提时会明确失败。"""
    with pytest.raises(error_type):
        constructor()


def test_encoding_and_decoding_reject_nonfinite_and_out_of_range_values() -> None:
    """验证非有限值、payload 越界和非 canonical residue 不会被静默接受。"""
    context = FixedPointContext(modulus=17, integer_bits=4, fractional_bits=1)

    with pytest.raises(ValueError, match="有限"):
        context.encode(float("nan"))
    with pytest.raises(ValueError, match="payload"):
        context.encode(4.0)
    with pytest.raises(ValueError, match="payload"):
        context.decode(8)
    with pytest.raises(ValueError, match="canonical"):
        context.from_residue(17)


def test_decode_residue_rejects_centered_value_outside_declared_payload_range() -> None:
    """验证解码不把大模代表元误解释为当前 k 位普通 payload。"""
    context = FixedPointContext(modulus=257, integer_bits=4, fractional_bits=0)

    with pytest.raises(ValueError, match="payload"):
        context.decode_residue(100)
