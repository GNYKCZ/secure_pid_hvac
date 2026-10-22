"""2-out-of-2 加法秘密共享的性质与边界测试。"""

import random

import numpy as np
import pytest

from secure_control.crypto import AdditiveShare, TwoPartySharing


@pytest.mark.parametrize("message", [0, -1, 256])
def test_reconstruction_matches_canonical_message_for_scalar_inputs(message: int) -> None:
    """验证零、正负值和模边界在分发重构后均满足基本不变量。"""
    sharing = TwoPartySharing(modulus=257)
    first, second = sharing.share(message, rng=random.Random(20260914 + message))

    assert sharing.reconstruct(first, second) == message % 257


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


@pytest.mark.parametrize("modulus", [257, (1 << 256) - 189])
def test_scalar_linear_paths_match_independent_integer_formulas(modulus):
    sharing = TwoPartySharing(modulus)
    for left in (0, 1, modulus - 1):
        for right in (0, 1, modulus - 1):
            a, b = AdditiveShare(left), AdditiveShare(right)
            results = (sharing.add(a, b).value, sharing.subtract(a, b).value,
                       sharing.reconstruct(a, b))
            assert results == ((left + right) % modulus, (left - right) % modulus,
                               (left + right) % modulus)
            assert all(type(x) is int for x in results)
        for constant in (-modulus - 1, -1, 0, 1, modulus + 1):
            assert sharing.add_public(a, constant).value == (left + constant) % modulus
            assert sharing.subtract_public(a, constant).value == (left - constant) % modulus
            assert sharing.multiply_public(a, constant).value == (left * constant) % modulus
            first, second = sharing.share(constant, rng=random.Random(39))
            assert sharing.reconstruct(first, second) == constant % modulus


def test_integer_subclasses_numpy_scalars_and_zero_dimensional_inputs_keep_contract():
    class IntChild(int):
        pass

    sharing = TwoPartySharing(257)
    for value in (IntChild(256), np.int32(256), np.int64(256), np.uint64(256),
                  np.array(256, dtype=object), np.array(256, dtype=np.int64)):
        result = sharing.add_public(AdditiveShare(value), IntChild(-3)).value
        assert result == 253 and type(result) is int
        first, second = sharing.share(value, rng=random.Random(1))
        assert sharing.reconstruct(first, second) == 256


def test_invalid_scalar_and_array_values_are_rejected_before_modulo():
    sharing = TwoPartySharing(257)
    for value in (True, np.bool_(True), 1.5, np.float64(1), np.array(True),
                  np.array([1, True], dtype=object), np.array([1.0]), object()):
        with pytest.raises(TypeError, match="整数"):
            sharing.add(AdditiveShare(value), AdditiveShare(0))
        with pytest.raises(TypeError, match="整数"):
            sharing.multiply_public(AdditiveShare(1), value)
        with pytest.raises(TypeError, match="整数"):
            sharing.share(value)
    for value in (-1, 257, np.array([-1], dtype=object), np.array([257], dtype=object)):
        for a, b in ((AdditiveShare(value), AdditiveShare(0)),
                     (AdditiveShare(0), AdditiveShare(value))):
            with pytest.raises(ValueError, match="canonical"):
                sharing.reconstruct(a, b)
        with pytest.raises(ValueError, match="canonical"):
            sharing.add_public(AdditiveShare(value), -1)
    with pytest.raises(TypeError, match="AdditiveShare"):
        sharing.add(1, AdditiveShare(1))


def test_arrays_broadcast_only_scalars_and_return_independent_object_arrays():
    class ArrayChild(np.ndarray):
        pass

    sharing = TwoPartySharing((1 << 256) - 189)
    q = sharing.modulus
    for values in ([], [0, 1, q - 1], [[0, q - 1], [1, 7]]):
        original = np.array(values, dtype=object).view(ArrayChild)
        before = original.copy()
        for left, right in ((original, 2), (2, original), (original, before)):
            result = sharing.add(AdditiveShare(left), AdditiveShare(right)).value
            expected = (np.asarray(left, dtype=object) + np.asarray(right, dtype=object)) % q
            assert np.array_equal(result, expected)
            assert type(result) is np.ndarray and result.dtype == object
            assert result is not original and not np.shares_memory(result, original)
            if result.size:
                result.flat[0] = 99
            assert np.array_equal(original, before)
        result = sharing.multiply_public(AdditiveShare(original), -3).value
        assert np.array_equal(result, (before * -3) % q)
        assert not np.shares_memory(result, original)
    with pytest.raises(ValueError, match="同形"):
        sharing.add(AdditiveShare(np.array([1, 2])), AdditiveShare(np.array([[1, 2]])))
    # list/tuple仍按原数组路径接受，不引入NumPy隐式多维广播。
    assert sharing.subtract(AdditiveShare([1, 2]), AdditiveShare((2, 1))).value.tolist() == [q - 1, 1]


def test_builtin_integer_callbacks_run_once_without_array_boxing(monkeypatch):
    from secure_control.crypto import secret_sharing as module

    calls = []
    def mapper(value):
        calls.append(value)
        return value + 1
    def operation(left, right):
        calls.append((left, right))
        return left - right
    monkeypatch.setattr(module.np, "asarray", lambda *a, **k: pytest.fail("builtin int was boxed"))
    assert module._map_values(2**255, mapper) == 2**255 + 1
    assert TwoPartySharing(257)._combine_values(1, 2, operation) == 256
    assert calls == [2**255, (1, 2)]
    marker = RuntimeError("original callback error")
    def fail(*args):
        raise marker
    with pytest.raises(RuntimeError) as result:
        module._map_values(3, fail)
    assert result.value is marker
    with pytest.raises(RuntimeError) as result:
        TwoPartySharing(257)._combine_values(1, 2, fail)
    assert result.value is marker
