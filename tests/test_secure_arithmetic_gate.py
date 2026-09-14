"""安全算术原语的组合门禁：尺度、中心化表示、资源与随机性。"""

from __future__ import annotations

import random
from dataclasses import dataclass

import numpy as np
import pytest

from secure_control.crypto import (
    AdditiveShare,
    BeaverMultiplier,
    FixedPointContext,
    SecureTruncation,
    TwoPartySharing,
)

MODULUS = 2_147_483_647
SECURITY_PARAMETER = 8
GATE_CONFIGURATIONS = (
    (2_147_483_647, 8, 4),
    (2_147_483_647, 8, 8),
    (2_147_483_647, 8, 12),
    (2_147_483_647, 7, 8),
    (65_537, 2, 4),
)


def centered(residue: int, modulus: int) -> int:
    """将 canonical residue 转换为本项目约定的中心化有符号整数。"""
    return residue if residue < (modulus + 1) // 2 else residue - modulus


@dataclass(frozen=True)
class GateTrial:
    """保存单个 Gate trial 的可复现输入、结果及测试边界可审计资源序列。"""

    left_payload: int
    right_payload: int
    expected_product: int
    beaver_product: int
    truncation_output: int
    triple_sequence: tuple[int, int, int]
    mask_sequence: tuple[int, int]
    created_triples: int
    consumed_triples: int
    created_masks: int
    consumed_masks: int


def parameter_context(*, modulus: int, ell: int, security_parameter: int) -> str:
    """生成与具体输入无关的 q、ell、lambda 和尺度诊断字段。"""
    scale = 1 << ell if isinstance(ell, int) and not isinstance(ell, bool) and ell >= 0 else "n/a"
    return f"q={modulus} ell={ell} lambda={security_parameter} scale={scale}"


def make_context(
    ell: int,
    *,
    modulus: int = MODULUS,
    security_parameter: int = SECURITY_PARAMETER,
) -> tuple[FixedPointContext, TwoPartySharing, SecureTruncation]:
    """建立指定合法参数下共享同一模数的固定点、分享与 Protocol 2 上下文。"""
    sharing = TwoPartySharing(modulus)
    truncation = SecureTruncation(sharing, ell=ell, security_parameter=security_parameter)
    # Z<kappa> 是 Trunc 的消息域；令固定点 payload 覆盖该域，才可测试其精确边界。
    fixed_point = FixedPointContext(
        modulus=modulus,
        integer_bits=truncation.kappa,
        fractional_bits=ell,
    )
    return fixed_point, sharing, truncation


def case_context(
    *,
    seed: int,
    trial: int,
    left: object,
    right: object,
    ell: int,
    modulus: int = MODULUS,
    security_parameter: int = SECURITY_PARAMETER,
) -> str:
    """生成包含复现所需输入、参数和活动尺度的失败诊断前缀。"""
    return f"seed={seed} trial={trial} left={left!r} right={right!r} " + parameter_context(
        modulus=modulus,
        ell=ell,
        security_parameter=security_parameter,
    )


def reconstruct_residue(
    sharing: TwoPartySharing,
    first: AdditiveShare,
    second: AdditiveShare,
) -> int:
    """仅在测试边界重构标量 resource 或结果的 canonical residue。"""
    residue = sharing.reconstruct(first, second)
    if not isinstance(residue, int):
        raise TypeError("组合 Gate 的 scalar-first 路径重构出了非标量结果。")
    return residue


def run_secure_product(
    ell: int,
    left: float,
    right: float,
    *,
    seed: int,
    trial: int = 0,
    modulus: int = MODULUS,
    security_parameter: int = SECURITY_PARAMETER,
) -> GateTrial:
    """执行单个完全隔离的编码、分享、Beaver 与 Protocol 2 组合 trial。

    每次调用都重新创建 RNG、BeaverMultiplier、SecureTruncation 和所有中间份额。测试
    使用编码 payload 的精确 Python 整数乘积作为 oracle；该 oracle 只存在于测试边界，
    用来阻止 Beaver 的 ``mod q`` 重构结果在发生数学回绕后被误送入截断协议。
    """
    context = case_context(
        seed=seed,
        trial=trial,
        left=left,
        right=right,
        ell=ell,
        modulus=modulus,
        security_parameter=security_parameter,
    )
    rng = random.Random(seed)
    stage = "context"

    try:
        fixed_point, sharing, truncation = make_context(
            ell,
            modulus=modulus,
            security_parameter=security_parameter,
        )
        stage = "encode"
        left_payload = fixed_point.encode(left)
        right_payload = fixed_point.encode(right)
        if not isinstance(left_payload, int) or not isinstance(right_payload, int):
            raise TypeError("组合 Gate 的 Beaver 路径只接受标量 payload。")
        expected_product = left_payload * right_payload

        stage = "Share"
        left_shares = sharing.share(left_payload, rng=rng)
        right_shares = sharing.share(right_payload, rng=rng)

        stage = "Beaver triple"
        multiplier = BeaverMultiplier(sharing)
        triples = multiplier.create_triple(rng=rng)
        triple_sequence = (
            reconstruct_residue(sharing, triples[0].a, triples[1].a),
            reconstruct_residue(sharing, triples[0].b, triples[1].b),
            reconstruct_residue(sharing, triples[0].c, triples[1].c),
        )

        stage = "Beaver multiply"
        first_masked = multiplier.mask_inputs(left_shares[0], right_shares[0], triples[0])
        second_masked = multiplier.mask_inputs(left_shares[1], right_shares[1], triples[1])
        opened = multiplier.open_masked_differences(first_masked, second_masked)
        product_shares = (
            multiplier.finish(triples[0], opened),
            multiplier.finish(triples[1], opened),
        )
        beaver_product = centered(
            reconstruct_residue(sharing, product_shares[0], product_shares[1]),
            sharing.modulus,
        )

        # 与测试边界精确乘积不一致只能由 Z_q 数学回绕造成，不能再进入 Trunc。
        stage = "Beaver product range"
        if beaver_product != expected_product:
            raise ValueError("Beaver 重构与精确编码乘积不一致，检测到数学模回绕。")

        stage = "Trunc input range"
        truncation.validate_message(expected_product)

        stage = "Trunc auxiliary"
        auxiliary = truncation.create_auxiliary(rng=rng)
        mask_sequence = (
            centered(reconstruct_residue(sharing, auxiliary[0].r, auxiliary[1].r), sharing.modulus),
            centered(
                reconstruct_residue(sharing, auxiliary[0].r_prime, auxiliary[1].r_prime),
                sharing.modulus,
            ),
        )

        stage = "Trunc protocol"
        first_truncation = truncation.mask_input(product_shares[0], auxiliary[0])
        second_truncation = truncation.mask_input(product_shares[1], auxiliary[1])
        p1_value = truncation.p1_reconstruct_masked(
            first_truncation,
            truncation.p2_send_masked(second_truncation),
        )
        output_shares = (
            truncation.finish_p1(product_shares[0], auxiliary[0], p1_value),
            truncation.finish_p2(product_shares[1], auxiliary[1]),
        )
        truncation_output = centered(
            reconstruct_residue(sharing, output_shares[0], output_shares[1]),
            sharing.modulus,
        )
    except (TypeError, ValueError) as error:
        raise type(error)(f"{context} stage={stage}; {error}") from error

    return GateTrial(
        left_payload=left_payload,
        right_payload=right_payload,
        expected_product=expected_product,
        beaver_product=beaver_product,
        truncation_output=truncation_output,
        triple_sequence=triple_sequence,
        mask_sequence=mask_sequence,
        created_triples=multiplier.created_triples,
        consumed_triples=multiplier.consumed_triples,
        created_masks=truncation.created_masks,
        consumed_masks=truncation.consumed_masks,
    )


@pytest.mark.parametrize(("modulus", "security_parameter", "ell"), GATE_CONFIGURATIONS)
def test_fixed_point_share_reconstruct_decode_randomized_parameter_matrix(
    modulus: int,
    security_parameter: int,
    ell: int,
) -> None:
    """验证多组合法 q/lambda/ell 下随机矩阵与零值保持编码、共享和解码契约。"""
    seed = 100_000 + modulus % 1_000 + security_parameter * 100 + ell
    fixed_point, sharing, _ = make_context(
        ell,
        modulus=modulus,
        security_parameter=security_parameter,
    )
    rng = random.Random(seed)
    values = np.array(
        [
            [0.0, rng.uniform(-8.0, 8.0), rng.uniform(-8.0, 8.0)],
            [rng.uniform(-8.0, 8.0), rng.uniform(-8.0, 8.0), rng.uniform(-8.0, 8.0)],
        ]
    )
    context = case_context(
        seed=seed,
        trial=0,
        left=values.tolist(),
        right="n/a",
        ell=ell,
        modulus=modulus,
        security_parameter=security_parameter,
    )

    encoded_residues = fixed_point.encode_to_residue(values)
    first, second = sharing.share(encoded_residues, rng=rng)
    reconstructed = sharing.reconstruct(first, second)
    decoded = fixed_point.decode_residue(reconstructed)

    assert reconstructed.dtype == object, f"{context} stage=Share/Reconst dtype"
    assert reconstructed.shape == values.shape, f"{context} stage=Share/Reconst shape"
    assert np.all(np.abs(decoded - values) <= 0.5 / fixed_point.scale), (
        f"{context} stage=decode quantization"
    )


def test_known_value_gate_tracks_scale_from_product_to_truncation_and_decode() -> None:
    """验证乘法从 2^(2ell) 经 Protocol 2 回到 2^ell，且资源各消费一次。"""
    left, right, seed = 1.25, -0.75, 202_609
    fixed_point, _, truncation = make_context(8)
    result = run_secure_product(8, left, right, seed=seed)
    context = case_context(seed=seed, trial=0, left=left, right=right, ell=8)
    expected_round = truncation.paper_round_divide(result.expected_product)

    assert fixed_point.product_fractional_bits == 16, f"{context} stage=scale"
    assert result.beaver_product == result.expected_product, f"{context} stage=Beaver"
    assert result.truncation_output - expected_round in {-1, 0, 1}, f"{context} stage=Trunc"
    assert fixed_point.decode(result.beaver_product, fractional_bits=16) == pytest.approx(
        left * right
    ), f"{context} stage=product decode"
    assert fixed_point.decode(result.truncation_output) == pytest.approx(
        left * right,
        abs=1.0 / fixed_point.scale,
    ), f"{context} stage=Trunc decode"
    assert (result.created_triples, result.consumed_triples) == (1, 1), f"{context} stage=triple"
    assert (result.created_masks, result.consumed_masks) == (1, 1), f"{context} stage=mask"


def test_same_seed_replays_inputs_full_resource_sequence_and_results() -> None:
    """验证同一 trial seed 重放相同输入、triple、掩码与最终数值 transcript。"""
    left, right, seed, trial = 1.25, -0.75, 202_609, 3
    context = case_context(seed=seed, trial=trial, left=left, right=right, ell=8)
    first = run_secure_product(8, left, right, seed=seed, trial=trial)
    second = run_secure_product(8, left, right, seed=seed, trial=trial)

    assert first == second, f"{context} stage=full transcript replay"
    assert first.triple_sequence == second.triple_sequence, f"{context} stage=triple replay"
    assert first.mask_sequence == second.mask_sequence, f"{context} stage=mask replay"


@pytest.mark.parametrize(("modulus", "security_parameter", "ell"), GATE_CONFIGURATIONS)
def test_fixed_seed_randomized_gate_trials_reset_all_state_and_replay_resources(
    modulus: int,
    security_parameter: int,
    ell: int,
) -> None:
    """验证合法参数矩阵下每个随机 trial 独立重置所有状态并重放资源。"""
    seed = 91_000 + modulus % 1_000 + security_parameter * 100 + ell
    input_rng = random.Random(seed)
    _, _, truncation = make_context(
        ell,
        modulus=modulus,
        security_parameter=security_parameter,
    )
    magnitude = min(8.0, 0.25 * (truncation.maximum_message**0.5) / (1 << ell))
    cases = [
        (
            input_rng.uniform(-magnitude, magnitude),
            input_rng.uniform(-magnitude, magnitude),
            input_rng.randrange(1 << 30),
        )
        for _ in range(16)
    ]
    repeat_input_rng = random.Random(seed)
    replayed_cases = [
        (
            repeat_input_rng.uniform(-magnitude, magnitude),
            repeat_input_rng.uniform(-magnitude, magnitude),
            repeat_input_rng.randrange(1 << 30),
        )
        for _ in range(16)
    ]

    assert cases == replayed_cases, (
        f"{parameter_context(modulus=modulus, ell=ell, security_parameter=security_parameter)} "
        f"seed={seed} trial=all left=randomized right=randomized stage=input replay"
    )

    for trial, (left, right, trial_seed) in enumerate(cases):
        context = case_context(
            seed=trial_seed,
            trial=trial,
            left=left,
            right=right,
            ell=ell,
            modulus=modulus,
            security_parameter=security_parameter,
        )
        result = run_secure_product(
            ell,
            left,
            right,
            seed=trial_seed,
            trial=trial,
            modulus=modulus,
            security_parameter=security_parameter,
        )
        replay = run_secure_product(
            ell,
            left,
            right,
            seed=trial_seed,
            trial=trial,
            modulus=modulus,
            security_parameter=security_parameter,
        )
        expected_round = truncation.paper_round_divide(result.expected_product)

        assert result.beaver_product == result.expected_product, f"{context} stage=Beaver"
        assert result.truncation_output - expected_round in {-1, 0, 1}, f"{context} stage=Trunc"
        assert (result.created_triples, result.consumed_triples) == (1, 1), (
            f"{context} stage=triple"
        )
        assert (result.created_masks, result.consumed_masks) == (1, 1), f"{context} stage=mask"
        assert result == replay, f"{context} stage=resource replay"


def test_large_modulus_path_uses_object_residues_without_machine_integer_wraparound() -> None:
    """验证大模数下的定点共享重构不经过固定宽度整数中间值。"""
    modulus = (1 << 256) - 189
    fixed_point = FixedPointContext(modulus=modulus, integer_bits=128, fractional_bits=8)
    sharing = TwoPartySharing(modulus)
    values = np.array([-(1 << 50) / 256, (1 << 50) / 256])
    context = case_context(
        seed=31,
        trial=0,
        left=values.tolist(),
        right="n/a",
        ell=8,
        modulus=modulus,
        security_parameter=SECURITY_PARAMETER,
    )

    first, second = sharing.share(fixed_point.encode_to_residue(values), rng=random.Random(31))
    reconstructed = sharing.reconstruct(first, second)

    assert reconstructed.dtype == object, f"{context} stage=large-q dtype"
    assert all(isinstance(value, int) for value in reconstructed), f"{context} stage=large-q type"
    assert np.allclose(fixed_point.decode_residue(reconstructed), values), (
        f"{context} stage=large-q decode"
    )


@pytest.mark.parametrize(("modulus", "security_parameter", "ell"), GATE_CONFIGURATIONS)
def test_gate_handles_zero_and_exact_truncation_message_boundaries_for_every_configuration(
    modulus: int,
    security_parameter: int,
    ell: int,
) -> None:
    """验证每组合法参数的零值与 Z<kappa> 精确上下边界通过完整组合路径。"""
    fixed_point, _, truncation = make_context(
        ell,
        modulus=modulus,
        security_parameter=security_parameter,
    )
    boundary_cases = (
        (0.0, 1.0 / fixed_point.scale, 0),
        (
            1.0 / fixed_point.scale,
            truncation.maximum_message / fixed_point.scale,
            truncation.maximum_message,
        ),
        (
            1.0 / fixed_point.scale,
            truncation.minimum_message / fixed_point.scale,
            truncation.minimum_message,
        ),
    )

    for trial, (left, right, expected_product) in enumerate(boundary_cases):
        seed = 202_610 + ell * 100 + security_parameter * 10 + trial
        context = case_context(
            seed=seed,
            trial=trial,
            left=left,
            right=right,
            ell=ell,
            modulus=modulus,
            security_parameter=security_parameter,
        )
        result = run_secure_product(
            ell,
            left,
            right,
            seed=seed,
            trial=trial,
            modulus=modulus,
            security_parameter=security_parameter,
        )

        assert result.expected_product == expected_product, (
            f"{context} stage=encoded boundary product"
        )
        assert result.beaver_product == expected_product, f"{context} stage=Beaver boundary product"
        assert result.truncation_output - truncation.paper_round_divide(expected_product) in {
            -1,
            0,
            1,
        }, f"{context} stage=Trunc boundary output"
        assert (result.created_triples, result.consumed_triples) == (1, 1), (
            f"{context} stage=triple"
        )
        assert (result.created_masks, result.consumed_masks) == (1, 1), f"{context} stage=mask"


def test_gate_rejects_product_outside_truncation_range_before_masking() -> None:
    """验证完整 Gate 路径在乘积属于 Z_q 但越出 Z<kappa> 时不会创建掩码。"""
    left, right, seed = 4.0, 4.0, 202_611

    with pytest.raises(ValueError, match="Z<kappa>") as error:
        run_secure_product(8, left, right, seed=seed, trial=5)

    detail = str(error.value)
    for required in (
        f"seed={seed}",
        "trial=5",
        f"left={left!r}",
        f"right={right!r}",
        f"q={MODULUS}",
        "ell=8",
        f"lambda={SECURITY_PARAMETER}",
        "scale=256",
        "stage=Trunc input range",
    ):
        assert required in detail, f"{detail}; missing={required}"


def test_gate_rejects_real_beaver_product_wraparound_before_truncation() -> None:
    """验证真实组合路径在创建截断掩码前拒绝已模回绕的 Beaver 乘积。"""
    left, right, seed = 256.0, 128.0, 202_609

    with pytest.raises(ValueError, match="数学模回绕") as error:
        run_secure_product(8, left, right, seed=seed, trial=7)

    detail = str(error.value)
    for required in (
        f"seed={seed}",
        "trial=7",
        f"left={left!r}",
        f"right={right!r}",
        f"q={MODULUS}",
        "ell=8",
        f"lambda={SECURITY_PARAMETER}",
        "scale=256",
        "stage=Beaver product range",
    ):
        assert required in detail, f"{detail}; missing={required}"


@pytest.mark.parametrize(
    ("modulus", "security_parameter", "ell", "error_text"),
    [
        (MODULUS, SECURITY_PARAMETER, 0, "ell 必须是正整数"),
        (65_535, 2, 4, "素数"),
        (257, 3, 4, "kappa"),
        (MODULUS, True, 4, "security_parameter"),
    ],
)
def test_gate_rejects_illegal_parameter_combinations_with_context(
    modulus: int,
    security_parameter: int,
    ell: int,
    error_text: str,
) -> None:
    """验证非法 ell、q 或 lambda 组合在 Gate 上下文创建阶段明确失败。"""
    seed = 202_612
    context = case_context(
        seed=seed,
        trial=0,
        left=0.0,
        right=0.0,
        ell=ell,
        modulus=modulus,
        security_parameter=security_parameter,
    )

    with pytest.raises(ValueError, match=error_text) as error:
        run_secure_product(
            ell,
            0.0,
            0.0,
            seed=seed,
            modulus=modulus,
            security_parameter=security_parameter,
        )

    assert context in str(error.value), f"{context} stage=configuration error context"
    assert "stage=context" in str(error.value), f"{context} stage=configuration stage"
