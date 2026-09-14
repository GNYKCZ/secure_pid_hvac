"""论文 Protocol 2 截断的参数、消息流、误差和随机量生命周期测试。"""

import random

import pytest

from secure_control.crypto import SecureTruncation, TwoPartySharing


def protocol() -> SecureTruncation:
    """建立满足 kappa=21、ell=8、lambda=8 的已验证素数测试上下文。"""
    return SecureTruncation(TwoPartySharing(2_147_483_647), ell=8, security_parameter=8)


def run_protocol(
    instance: SecureTruncation, message: int, rng: random.Random
) -> tuple[int, object, object]:
    """按 P2→P1 的单向消息顺序运行一次本地 Protocol 2 仿真。"""
    shares = instance.share_message(message, rng=rng)
    auxiliary = instance.create_auxiliary(rng=rng)
    first_masked = instance.mask_input(shares[0], auxiliary[0])
    second_masked = instance.mask_input(shares[1], auxiliary[1])
    p2_message = instance.p2_send_masked(second_masked)
    p1_masked_value = instance.p1_reconstruct_masked(first_masked, p2_message)
    first_output = instance.finish_p1(shares[0], auxiliary[0], p1_masked_value)
    second_output = instance.finish_p2(shares[1], auxiliary[1])
    residue = instance.sharing.reconstruct(first_output, second_output)
    output = (
        residue
        if residue < (instance.sharing.modulus + 1) // 2
        else residue - instance.sharing.modulus
    )
    return output, auxiliary, p1_masked_value


@pytest.mark.parametrize("message", [0, 1, -1, 127, 128, -128, (1 << 20) - 1, -(1 << 20)])
def test_protocol_two_output_has_only_the_paper_allowed_one_bit_error(message: int) -> None:
    """验证零、正负和 Z<kappa> 边界的误差属于 {-1,0,1}。"""
    instance = protocol()
    output, auxiliary, _ = run_protocol(instance, message, random.Random(1000 + message))

    assert output - instance.paper_round_divide(message) in {-1, 0, 1}
    assert auxiliary[0].is_consumed
    assert auxiliary[1].is_consumed
    assert instance.created_masks == instance.consumed_masks == 1


def test_known_step_mapping_uses_centered_masked_value_and_centered_low_bits() -> None:
    """逐步验证 m_r、中心化低位和两份输出的 Protocol 2 公式。"""
    instance = protocol()
    rng = random.Random(42)
    message = -321
    shares = instance.share_message(message, rng=rng)
    auxiliary = instance.create_auxiliary(rng=rng)
    first_masked = instance.mask_input(shares[0], auxiliary[0])
    second_masked = instance.mask_input(shares[1], auxiliary[1])
    p1_value = instance.p1_reconstruct_masked(first_masked, instance.p2_send_masked(second_masked))
    r = instance.sharing.reconstruct(auxiliary[0].r, auxiliary[1].r)
    r_prime = instance.sharing.reconstruct(auxiliary[0].r_prime, auxiliary[1].r_prime)
    centered_r = r if r < (instance.sharing.modulus + 1) // 2 else r - instance.sharing.modulus
    centered_r_prime = (
        r_prime
        if r_prime < (instance.sharing.modulus + 1) // 2
        else r_prime - instance.sharing.modulus
    )
    expected_masked = message + instance.scale * centered_r + centered_r_prime + instance.scale // 2
    low_bits = (
        p1_value.value - instance.scale // 2 + instance.scale // 2
    ) % instance.scale - instance.scale // 2

    first_output = instance.finish_p1(shares[0], auxiliary[0], p1_value)
    second_output = instance.finish_p2(shares[1], auxiliary[1])
    expected_first = (
        (shares[0].value + auxiliary[0].r_prime.value - low_bits)
        * instance.inverse_scale
        % instance.sharing.modulus
    )
    expected_second = (
        (shares[1].value + auxiliary[1].r_prime.value)
        * instance.inverse_scale
        % instance.sharing.modulus
    )

    assert p1_value.value == expected_masked
    assert -(1 << (instance.kappa - instance.ell + instance.security_parameter - 1)) <= centered_r
    assert centered_r < 1 << (instance.kappa - instance.ell + instance.security_parameter - 1)
    assert -(1 << (instance.ell - 1)) <= centered_r_prime < 1 << (instance.ell - 1)
    assert first_output.value == expected_first
    assert second_output.value == expected_second


def test_fixed_seed_random_trials_cover_allowed_error_set_and_fresh_masks() -> None:
    """验证 64 次随机输入均满足允许误差，并且每次独立消费随机量。"""
    instance = protocol()
    rng = random.Random(202608)
    errors: set[int] = set()

    for _ in range(64):
        message = rng.randrange(instance.minimum_message, instance.maximum_message + 1)
        output, _, _ = run_protocol(instance, message, rng)
        error = output - instance.paper_round_divide(message)
        assert error in {-1, 0, 1}
        errors.add(error)

    assert errors <= {-1, 0, 1}
    assert instance.created_masks == instance.consumed_masks == 64


def test_p2_only_sends_one_masked_share_and_receives_no_p1_message() -> None:
    """验证消息边界：P2 只发送，P1 才能重构 masked 值。"""
    instance = protocol()
    shares = instance.share_message(17, rng=random.Random(3))
    auxiliary = instance.create_auxiliary(rng=random.Random(4))
    first_masked = instance.mask_input(shares[0], auxiliary[0])
    second_masked = instance.mask_input(shares[1], auxiliary[1])

    message = instance.p2_send_masked(second_masked)
    assert tuple(message.__dataclass_fields__) == ("value", "_lifecycle")
    assert instance.p1_reconstruct_masked(first_masked, message).value != shares[0].value
    with pytest.raises(TypeError, match="P1"):
        instance.p1_reconstruct_masked(second_masked, message)


def test_auxiliary_randomness_cannot_be_reused() -> None:
    """验证已遮蔽或已完成的 r/r_prime 均不能在后续调用中复用。"""
    instance = protocol()
    rng = random.Random(8)
    shares = instance.share_message(23, rng=rng)
    auxiliary = instance.create_auxiliary(rng=rng)
    first_masked = instance.mask_input(shares[0], auxiliary[0])

    with pytest.raises(ValueError, match="遮蔽"):
        instance.mask_input(shares[0], auxiliary[0])

    second_masked = instance.mask_input(shares[1], auxiliary[1])
    p1_value = instance.p1_reconstruct_masked(first_masked, instance.p2_send_masked(second_masked))
    instance.finish_p1(shares[0], auxiliary[0], p1_value)
    with pytest.raises(ValueError, match="完成"):
        instance.finish_p1(shares[0], auxiliary[0], p1_value)
    instance.finish_p2(shares[1], auxiliary[1])
    assert auxiliary[0].is_consumed


def test_parameters_inverse_and_input_range_fail_before_protocol_execution() -> None:
    """验证合数模数、kappa 关系和消息范围会明确失败。"""
    with pytest.raises(ValueError, match="素数"):
        SecureTruncation(TwoPartySharing(65_535), ell=4, security_parameter=2)
    with pytest.raises(ValueError, match="kappa"):
        SecureTruncation(TwoPartySharing(257), ell=4, security_parameter=3)

    instance = protocol()
    assert instance.inverse_scale * instance.scale % instance.sharing.modulus == 1
    with pytest.raises(ValueError, match="Z<kappa>"):
        instance.share_message(instance.maximum_message + 1, rng=random.Random(1))
    with pytest.raises(TypeError, match="标量"):
        instance.validate_message(True)
