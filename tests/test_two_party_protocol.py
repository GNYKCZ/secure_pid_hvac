"""领域无关 Client/P1/P2 Protocol 3 的角色、尺度、范围与身份绑定测试。"""

from __future__ import annotations

import random
from dataclasses import fields, replace

import numpy as np
import pytest

from secure_control.core import (
    ControllerScaleMetadata,
    ControllerSpec,
    EllipsoidalInvariantWitness,
    LinearSafetyConstraint,
    RationalBox,
    RationalValue,
    RobustAffineInvariantProblem,
    invariant_certificate_sha256,
)
from secure_control.crypto import (
    AdditiveShare,
    FixedPointContext,
    PrimeVerificationError,
    TwoPartySharing,
)
from secure_control.protocol import (
    P1,
    P2,
    Client,
    ClosedLoopAffineComposition,
    ClosedLoopRangeEvidence,
    ControllerLayout,
    ControllerRangeContract,
    ControllerScaleLedger,
    OfflineDistribution,
    OnlineRound,
    SingleProcessCoordinator,
    closed_loop_composition_sha256,
    controller_payload_fingerprint,
)


def make_stack(
    *, seed: int = 10
) -> tuple[Client, P1, P2, SingleProcessCoordinator, OfflineDistribution]:
    """建立满足公开不变范围的二维状态、一维输入和一维输出通用 Protocol 3 夹具。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[0.5, 0.0], [0.0, 0.5]]),
        B=np.array([[0.25], [-0.25]]),
        C=np.array([[1.0, 1.0]]),
        D=np.array([[0.5]]),
        x0=np.array([0.5, 0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=8, B=8, C=8, D=8),
    )
    contract = ControllerRangeContract(state_payload_bounds=(256, 256), input_payload_bounds=(64,))
    distribution = client.distribute_controller(spec, contract, rng=random.Random(seed))
    assert client.range_verification.proof_mode == "independent_input_invariant"
    assert client.range_verification.certificate_sha256 is None
    return (
        client,
        P1(distribution.p1),
        P2(distribution.p2),
        SingleProcessCoordinator(sharing, client.multiplier, client.truncation),
        distribution,
    )


def share_values(share: AdditiveShare) -> list[int]:
    """把测试边界中的本地 share 转为普通列表，避免 object ndarray 比较歧义。"""
    return np.asarray(share.value, dtype=object).tolist()


def test_prepared_resources_bind_only_fresh_input_once_and_reject_foreign_copies():
    """预创建本身不签发输出，合法新测量才领取；保留真实算术与一次性生命周期。"""
    client, p1, p2, coordinator, distribution = make_stack()
    prepared = client.precompute_online_resources(distribution, step=0, rng=random.Random(91))
    assert not client._issued_rounds
    other = make_stack(seed=11)[0]
    for owner, token, step in ((client, replace(prepared), 0), (client, prepared, 1),
                               (other, prepared, 0)):
        with pytest.raises(ValueError):
            owner.bind_online_input(distribution, token, [.25], step=step)
    with pytest.raises(ValueError, match="input_payload_bounds"):
        client.bind_online_input(distribution, prepared, [10], step=0)
    online = client.bind_online_input(replace(distribution), prepared, [.25], step=0)
    with pytest.raises(ValueError):
        client.bind_online_input(distribution, prepared, [.25], step=0)
    output = coordinator.execute(p1, p2, online)
    np.testing.assert_allclose(client.reconstruct_control(*output), [.625])
    abandoned = client.precompute_online_resources(distribution, step=1)
    client._material_owner(distribution).discard(abandoned)
    assert abandoned.p1_resources.aborted_count == 11
    with pytest.raises(ValueError):
        client.bind_online_input(distribution, abandoned, [.25], step=1)


def test_client_cannot_bypass_large_modulus_evidence_contract() -> None:
    """Client 必须把大模数交给 Protocol 2 验证，不能仅建立一般模环后继续。"""
    modulus = 18_446_744_073_709_554_719
    fixed_point = FixedPointContext(modulus, integer_bits=60, fractional_bits=8)
    with pytest.raises(PrimeVerificationError) as captured:
        Client(fixed_point, TwoPartySharing(modulus), security_parameter=8)
    assert captured.value.reason_code == "evidence_required"


def test_protocol_three_keeps_output_at_double_scale_and_truncates_once_per_state_row() -> None:
    """锁定 Protocol 3：输出保持双尺度，state 聚合后才逐行截断一次。"""
    client, p1, p2, coordinator, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))

    first, second = coordinator.execute(p1, p2, online)
    output_payload = client.sharing.reconstruct(first.value, second.value)
    output = client.reconstruct_control(first, second)
    reconstructed_state = client.fixed_point.decode_residue(
        client.sharing.reconstruct(p1.state_share, p2.state_share)
    )

    # u(0)=0.5+0.125=0.625；输出 payload 仍是 0.625*2^(2*8)=40960。
    assert output_payload.tolist() == [40_960]
    assert output[0] == pytest.approx(0.625)
    np.testing.assert_allclose(
        reconstructed_state,
        np.array([0.3125, -0.0625]),
        atol=1.0 / client.fixed_point.scale,
    )
    assert online.p1_resources.plan.triple_count == 9
    assert online.p1_resources.plan.truncation_count == 2
    assert distribution.p1.layout.scale_ledger == ControllerScaleLedger(
        state=8,
        input=8,
        A=8,
        B=8,
        C=8,
        D=8,
        state_accumulator=16,
        state_truncation_bits=8,
        output_accumulator=16,
        output=16,
    )
    assert {
        (
            resource.term,
            resource.left_fractional_bits,
            resource.right_fractional_bits,
            resource.output_fractional_bits,
        )
        for resource in online.p1_resources.plan.product_resources
    } == {
        ("A", 8, 8, 16),
        ("B", 8, 8, 16),
        ("C", 8, 8, 16),
        ("D", 8, 8, 16),
    }
    assert {
        (
            resource.left_fractional_bits,
            resource.right_fractional_bits,
            resource.output_fractional_bits,
        )
        for resource in online.p1_resources.plan.state_truncation_resources
    } == {(16, None, 8)}
    assert online.p1_resources.consumed_count == online.p2_resources.consumed_count == 11
    assert (client.multiplier.created_triples, client.multiplier.consumed_triples) == (9, 9)
    assert (client.truncation.created_masks, client.truncation.consumed_masks) == (2, 2)


def test_zero_state_static_controller_uses_only_d_products() -> None:
    """验证零维 state 的通用静态控制器只计算 ``D*v``，无需虚构 state 或 Trunc 资源。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.empty((0, 0)),
        B=np.empty((0, 2)),
        C=np.empty((1, 0)),
        D=np.array([[-1.5, -0.25]]),
        x0=np.empty(0),
    )
    distribution = client.distribute_controller(
        spec,
        ControllerRangeContract(state_payload_bounds=(), input_payload_bounds=(128, 64)),
        rng=random.Random(3),
    )
    assert client.range_verification.proof_mode == "independent_input_invariant"
    p1, p2 = P1(distribution.p1), P2(distribution.p2)
    online = client.prepare_online(distribution, [0.5, -0.25], step=0, rng=random.Random(4))

    output = SingleProcessCoordinator(sharing, client.multiplier, client.truncation).execute(
        p1, p2, online
    )

    np.testing.assert_allclose(client.reconstruct_control(*output), np.array([-0.6875]))
    assert online.p1_resources.plan.triple_count == 2
    assert online.p1_resources.plan.truncation_count == 0
    assert np.asarray(p1.state_share.value, dtype=object).shape == (0,)
    assert np.asarray(p2.state_share.value, dtype=object).shape == (0,)


def test_aggregate_state_row_has_one_truncation_error_not_one_error_per_product() -> None:
    """验证多项 state 行先聚合，结果只允许单个 Protocol 2 ``w∈{-1,0,1}`` 误差。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.array(
            [[0.5, 0.5, 0.5, 0.5], [0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0]]
        ),
        B=np.zeros((4, 1)),
        C=np.zeros((1, 4)),
        D=np.zeros((1, 1)),
        x0=np.full(4, 1.0 / 256),
    )
    contract = ControllerRangeContract(state_payload_bounds=(5, 1, 1, 1), input_payload_bounds=(0,))
    distribution = client.distribute_controller(spec, contract, rng=random.Random(5))
    p1, p2 = P1(distribution.p1), P2(distribution.p2)
    coordinator = SingleProcessCoordinator(sharing, client.multiplier, client.truncation)
    output = coordinator.execute(
        p1, p2, client.prepare_online(distribution, [0.0], step=0, rng=random.Random(5))
    )

    state_payload = client.fixed_point.from_residue(
        client.sharing.reconstruct(p1.state_share, p2.state_share)
    )
    assert int(np.asarray(state_payload, dtype=object)[0]) in {1, 2, 3}
    assert client.truncation.created_masks == client.truncation.consumed_masks == 4
    assert output[0].fractional_bits == 16


def test_range_contract_rejects_pretruncation_value_outside_z_kappa_before_resources() -> None:
    """验证最终 state 尚可表示但聚合双尺度值越出 ``Z<kappa>`` 时 Client 明确拒绝。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[8.0]]),
        B=np.array([[0.0]]),
        C=np.array([[0.0]]),
        D=np.array([[0.0]]),
        x0=np.array([4.0]),
    )

    with pytest.raises(ValueError, match="Z<kappa>"):
        client.distribute_controller(
            spec,
            ControllerRangeContract(state_payload_bounds=(1_024,), input_payload_bounds=(0,)),
            rng=random.Random(31),
        )
    assert (client.multiplier.created_triples, client.truncation.created_masks) == (0, 0)


def test_server_visible_state_and_input_interfaces_reject_plaintext_or_two_share_containers() -> (
    None
):
    """验证 P1/P2 只接受自己的消息，不持有 Client、共享器或另一方 state。"""
    client, p1, p2, _, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))

    assert isinstance(p1.state_share, AdditiveShare)
    assert isinstance(p2.state_share, AdditiveShare)
    assert {field.name for field in fields(p1)} == {
        "_party",
        "_session_id",
        "_controller",
        "_state",
        "_layout",
    }
    assert all(
        isinstance(getattr(p1.controller_share, name), AdditiveShare)
        for name in ("A", "B", "C", "D")
    )
    assert not hasattr(p1.controller_share, "x0")
    assert not hasattr(p1, "sharing")
    assert not hasattr(p1, "client")
    with pytest.raises(ValueError, match="OfflineControllerMessage"):
        P1(distribution.p2)
    with pytest.raises(TypeError, match="InputShareMessage"):
        p1.input_share(
            (online.p1_input, online.p2_input),
            session_id=online.session_id,
            round_id=online.round_id,
            step=0,
        )  # type: ignore[arg-type]


def test_resource_pair_cannot_be_reused_after_a_successful_step() -> None:
    """验证所有 triple/mask 逻辑资源仅消费一次，重放 OnlineRound 被拒绝。"""
    client, p1, p2, coordinator, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    coordinator.execute(p1, p2, online)
    state_after_success = share_values(p1.state_share)

    with pytest.raises(ValueError, match="在线资源"):
        coordinator.execute(p1, p2, online)

    assert share_values(p1.state_share) == state_after_success
    assert online.p1_resources.consumed_count == 11
    assert online.p1_resources.aborted_count == 0


def test_explicit_system_random_is_not_downgraded_to_test_prng(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """验证调用方显式提供 OS 安全随机源时，协议不会改用测试用 Mersenne Twister。"""
    client, _, _, _, distribution = make_stack()
    secure_rng = random.SystemRandom()
    share_sources: list[random.Random | None] = []
    triple_sources: list[random.Random | None] = []
    mask_sources: list[random.Random | None] = []
    sharing_type = type(client.sharing)
    multiplier_type = type(client.multiplier)
    truncation_type = type(client.truncation)
    original_share = sharing_type.share
    original_triple = multiplier_type.create_triple
    original_mask = truncation_type.create_auxiliary

    def capture_share(
        sharing: TwoPartySharing, value: object, *, rng: random.Random | None = None
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """记录实际用于 input/triple/mask 分享的随机源，再执行既有共享实现。"""
        share_sources.append(rng)
        return original_share(sharing, value, rng=rng)

    def capture_triple(
        multiplier: object, *, rng: random.Random | None = None
    ) -> tuple[object, object]:
        """记录创建 Beaver 材料的随机源，避免只检查 helper 而遗漏调用路径。"""
        triple_sources.append(rng)
        return original_triple(multiplier, rng=rng)

    def capture_mask(
        truncation: object, *, rng: random.Random | None = None
    ) -> tuple[object, object]:
        """记录创建 Protocol 2 辅助材料的随机源，确保不会静默降级。"""
        mask_sources.append(rng)
        return original_mask(truncation, rng=rng)

    monkeypatch.setattr(sharing_type, "share", capture_share)
    monkeypatch.setattr(multiplier_type, "create_triple", capture_triple)
    monkeypatch.setattr(truncation_type, "create_auxiliary", capture_mask)

    assert client._online_material_rng(secure_rng) is secure_rng
    client.prepare_online(distribution, [0.25], step=0, rng=secure_rng)
    assert share_sources and all(source is secure_rng for source in share_sources)
    assert triple_sources and all(source is secure_rng for source in triple_sources)
    assert mask_sources and all(source is secure_rng for source in mask_sources)


def test_failed_resource_pairing_aborts_all_reserved_material_without_committing_state() -> None:
    """验证 P1 已开始乘法后发现 P2 triple 错配，整轮资源废弃且 state 不提交。"""
    client, p1, p2, coordinator, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    malformed_product = replace(
        online.p2_resources.product_resources[0],
        triple=online.p1_resources.product_resources[0].triple,
    )
    malformed_resources = replace(
        online.p2_resources,
        product_resources=(malformed_product, *online.p2_resources.product_resources[1:]),
    )
    malformed: OnlineRound = replace(online, p2_resources=malformed_resources)
    initial_p1_state, initial_p2_state = share_values(p1.state_share), share_values(p2.state_share)

    with pytest.raises(ValueError, match="乘法资源"):
        coordinator.execute(p1, p2, malformed)

    assert share_values(p1.state_share) == initial_p1_state
    assert share_values(p2.state_share) == initial_p2_state
    assert online.p1_resources.aborted_count == online.p2_resources.aborted_count == 11


def test_cross_session_servers_and_cross_round_inputs_are_rejected_before_state_commit() -> None:
    """验证同 shape controller 或同 step input 的跨 session/round 拼接在 claim 前被拒绝。"""
    client, p1, _, coordinator, distribution = make_stack(seed=10)
    _, _, foreign_p2, _, foreign_distribution = make_stack(seed=11)
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    initial_state = share_values(p1.state_share)

    with pytest.raises(ValueError, match="session"):
        coordinator.execute(p1, foreign_p2, online)
    assert share_values(p1.state_share) == initial_state
    assert online.p1_resources.aborted_count == 11

    client, p1, p2, coordinator, distribution = make_stack(seed=12)
    first = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    second = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(21))
    mixed = replace(first, p2_input=second.p2_input)
    initial_state = share_values(p1.state_share)
    with pytest.raises(ValueError, match="输入"):
        coordinator.execute(p1, p2, mixed)
    assert share_values(p1.state_share) == initial_state
    assert first.p1_resources.aborted_count == 11
    assert foreign_distribution.session_id != distribution.session_id


def test_client_rejects_complete_output_pair_from_another_client() -> None:
    """验证两条彼此匹配的外来输出也不能绕过 Client 的已签发 round 登记。"""
    client, _, _, _, _ = make_stack(seed=40)
    foreign_client, foreign_p1, foreign_p2, foreign_coordinator, foreign_distribution = make_stack(
        seed=42
    )
    with pytest.raises(ValueError, match="当前 Client"):
        client.prepare_online(foreign_distribution, [0.25], step=0, rng=random.Random(43))
    assert (client.multiplier.created_triples, client.truncation.created_masks) == (0, 0)
    foreign_output = foreign_coordinator.execute(
        foreign_p1,
        foreign_p2,
        foreign_client.prepare_online(foreign_distribution, [0.25], step=0, rng=random.Random(43)),
    )

    with pytest.raises(ValueError, match="当前 Client"):
        client.reconstruct_control(*foreign_output)


def test_client_validates_output_shape_and_reconstructs_each_round_once() -> None:
    """验证 Client 不接受错误输出 shape，且成功重构后会关闭该 round capability。"""
    client, p1, p2, coordinator, distribution = make_stack(seed=44)
    output = coordinator.execute(
        p1, p2, client.prepare_online(distribution, [0.25], step=0, rng=random.Random(45))
    )
    malformed = client.sharing.share(np.array([0, 0], dtype=object), rng=random.Random(46))

    with pytest.raises(ValueError, match="output dimension"):
        client.reconstruct_control(
            replace(output[0], value=malformed[0]),
            replace(output[1], value=malformed[1]),
        )

    np.testing.assert_allclose(client.reconstruct_control(*output), np.array([0.625]))
    with pytest.raises(ValueError, match="已完成"):
        client.reconstruct_control(*output)


def test_protocol_rejects_incompatible_controller_scale_metadata() -> None:
    """验证不相容乘积尺度被显式拒绝，而不是在模环中直接相加。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[0.0]]),
        C=np.array([[0.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=8, A=8, B=8, C=7, D=8),
    )

    with pytest.raises(ValueError, match="output accumulator"):
        client.distribute_controller(
            spec,
            ControllerRangeContract(state_payload_bounds=(1,), input_payload_bounds=(0,)),
            rng=random.Random(50),
        )


def test_integer_a_b_scale_uses_no_state_truncation_and_field_specific_payloads() -> None:
    """验证显式整数 A/B 按零分数位编码，并保持 state 尺度而不创建 Trunc 资源。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[-1.0]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(
            state=8,
            input=8,
            output=8,
            A=0,
            B=0,
            C=0,
            D=0,
        ),
    )
    distribution = client.distribute_controller(
        spec,
        ControllerRangeContract(state_payload_bounds=(128,), input_payload_bounds=(64,)),
        rng=random.Random(60),
    )
    p1, p2 = P1(distribution.p1), P2(distribution.p2)
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(61))

    encoded_b = fixed_point.from_residue(
        sharing.reconstruct(distribution.p1.controller.B, distribution.p2.controller.B)
    )
    encoded_state = fixed_point.from_residue(
        sharing.reconstruct(distribution.p1.initial_state, distribution.p2.initial_state)
    )
    output = SingleProcessCoordinator(sharing, client.multiplier, client.truncation).execute(
        p1, p2, online
    )

    assert np.asarray(encoded_b, dtype=object).tolist() == [[1]]
    assert np.asarray(encoded_state, dtype=object).tolist() == [128]
    assert distribution.p1.layout.scale_ledger.state_truncation_bits == 0
    assert online.p1_resources.plan.triple_count == 4
    assert online.p1_resources.plan.truncation_count == 0
    assert client.truncation.created_masks == client.truncation.consumed_masks == 0
    assert output[0].fractional_bits == 8
    assert {
        (
            resource.term,
            resource.left_fractional_bits,
            resource.right_fractional_bits,
            resource.output_fractional_bits,
        )
        for resource in online.p1_resources.plan.product_resources
    } == {
        ("A", 0, 8, 8),
        ("B", 0, 8, 8),
        ("C", 0, 8, 8),
        ("D", 0, 8, 8),
    }
    np.testing.assert_allclose(client.reconstruct_control(*output), np.array([0.25]))
    np.testing.assert_allclose(
        fixed_point.decode_residue(sharing.reconstruct(p1.state_share, p2.state_share)),
        np.array([0.25]),
    )


def test_integer_valued_a_b_still_truncate_when_metadata_declares_fixed_point() -> None:
    """验证 Trunc 决策只读取公开 metadata，不通过矩阵数值看起来像整数来猜测。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[0.0]]),
        C=np.array([[0.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(
            state=8,
            input=8,
            output=16,
            A=8,
            B=8,
            C=8,
            D=8,
        ),
    )
    distribution = client.distribute_controller(
        spec,
        ControllerRangeContract(state_payload_bounds=(1,), input_payload_bounds=(0,)),
        rng=random.Random(64),
    )

    online = client.prepare_online(distribution, [0.0], step=0, rng=random.Random(65))

    assert distribution.p1.layout.scale_ledger.state_truncation_bits == 8
    assert online.p1_resources.plan.truncation_count == 1


@pytest.mark.parametrize(
    ("metadata", "message"),
    [(
            ControllerScaleMetadata(state=8, input=8, output=16, A=0, B=8, C=8, D=8),
            "state products",
        ), (
            ControllerScaleMetadata(state=8, input=8, output=15, A=8, B=8, C=8, D=8),
            "output accumulator",
        )],
)
def test_scale_ledger_rejects_unsupported_combinations_before_sharing(
    metadata: ControllerScaleMetadata, message: str
) -> None:
    """验证不支持的尺度组合在生成参数 share 和在线资源前 fail closed。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[0.0]]),
        C=np.array([[0.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=metadata,
    )

    with pytest.raises(ValueError, match=message):
        client.distribute_controller(
            spec,
            ControllerRangeContract(state_payload_bounds=(1,), input_payload_bounds=(1,)),
            rng=random.Random(62),
        )
    assert (client.multiplier.created_triples, client.truncation.created_masks) == (0, 0)


def test_integrator_needs_proven_finite_horizon_and_rejects_overrun_before_resources() -> None:
    """积分态不满足无限不变界；有限时间证明与在线步数必须先于分享/资源创建。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[1.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=8, A=0, B=0, C=0, D=0),
    )

    with pytest.raises(ValueError, match="不变安全范围"):
        client.distribute_controller(
            spec,
            ControllerRangeContract(state_payload_bounds=(768,), input_payload_bounds=(256,)),
        )
    with pytest.raises(ValueError, match="state_payload_bounds"):
        client.distribute_controller(
            spec,
            ControllerRangeContract(
                state_payload_bounds=(511,), input_payload_bounds=(256,), horizon_steps=3
            ),
        )
    distribution = client.distribute_controller(
        spec,
        ControllerRangeContract(
            state_payload_bounds=(768,), input_payload_bounds=(256,), horizon_steps=3
        ),
    )
    assert client.range_verification.proof_mode == "finite_horizon"

    with pytest.raises(ValueError, match="horizon"):
        client.prepare_online(distribution, [0.25], step=3)
    with pytest.raises(ValueError, match="input_payload_bounds"):
        client.prepare_online(distribution, [2.0], step=0)
    assert (client.multiplier.created_triples, client.truncation.created_masks) == (0, 0)


def test_closed_loop_evidence_rejects_unrelated_stable_problem_before_sharing(
    monkeypatch,
) -> None:
    """无关稳定 problem 即使带正确 controller 指纹，也不得绕过积分器反例。"""
    q = RationalValue
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[1.0]]),
        B=np.array([[1.0]]),
        C=np.array([[0.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=8, A=0, B=0, C=0, D=0),
    )
    layout = ControllerLayout(
        1,
        1,
        1,
        ControllerScaleLedger(8, 8, 0, 0, 0, 0, 8, 0, 8, 8),
    )
    payloads = {
        "A": np.array([[1]], dtype=object),
        "B": np.array([[1]], dtype=object),
        "C": np.array([[0]], dtype=object),
        "D": np.array([[0]], dtype=object),
        "x0": np.array([0], dtype=object),
    }
    fake_problem = RobustAffineInvariantProblem(
        transition=((q(0),),),
        affine=(q(0),),
        disturbance_matrix=((),),
        disturbance_abs_bounds=(),
        initial_set=RationalBox((q(0),), (q(0),)),
        constraints=(
            LinearSafetyConstraint(
                "controller_input_payload[0]",
                (q(0),),
                q(0),
                (),
                q(-1, 256),
                q(1, 256),
            ),
        ),
        state_labels=("controller_state",),
    )
    witness = EllipsoidalInvariantWitness(
        equilibrium=(q(0),),
        shape_matrix=((q(1),),),
        contraction_bound=q(1, 2),
        disturbance_norm_bounds=(),
        radius=q(1),
        constraint_dual_norm_bounds=(q(1),),
    )
    # 攻击证据声明 v=0，因此 composition 与 problem 自洽外观成立；但代入实际 A=1
    # 后闭环 transition 应为 1，而不是 fake problem 中的 0。
    composition = ClosedLoopAffineComposition(
        controller_state_indices=(0,),
        external_state_indices=(),
        input_state_matrix=((q(0),),),
        input_affine=(q(0),),
        input_disturbance_matrix=((),),
        external_transition=(),
        external_affine=(),
        external_disturbance_matrix=(),
        output_injection=(),
    )
    evidence = ClosedLoopRangeEvidence(
        fake_problem,
        witness,
        invariant_certificate_sha256(fake_problem, witness),
        controller_payload_fingerprint(payloads, layout),
        (0,),
        (256,),
        (1,),
        composition,
        closed_loop_composition_sha256(composition),
    )
    contract = ControllerRangeContract((256,), (1,), closed_loop_evidence=evidence)
    called = False

    def forbidden_share(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("composition 验证失败前不得创建 share")

    monkeypatch.setattr(TwoPartySharing, "share", forbidden_share)
    with pytest.raises(ValueError, match="transition"):
        client.distribute_controller(spec, contract)
    assert called is False


def test_finite_horizon_proves_general_trunc_path_with_rounding_margin() -> None:
    """通用固定点 A/B 的有限时域上界须逐步保留 Protocol 2 的 ±1 误差。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[1.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=8, B=8, C=8, D=8),
    )
    with pytest.raises(ValueError, match="state_payload_bounds"):
        client.distribute_controller(
            spec,
            ControllerRangeContract(
                state_payload_bounds=(194,), input_payload_bounds=(64,), horizon_steps=3
            ),
        )
    distribution = client.distribute_controller(
        spec,
        ControllerRangeContract(
            state_payload_bounds=(195,), input_payload_bounds=(64,), horizon_steps=3
        ),
    )
    online = client.prepare_online(distribution, [0.25], step=0)
    assert online.p1_resources.plan.truncation_count == 1


def test_finite_horizon_keeps_encoded_matrix_cancellation() -> None:
    """幂次先合成再取绝对值；符号抵消的 nilpotent 控制器不被 |A|^N 误拒。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=16, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[.8, .8], [-.8, -.8]]), B=np.zeros((2, 1)),
        C=np.array([[1., 0.]]), D=np.zeros((1, 1)), x0=np.array([.1, .1]),
    )
    contract = ControllerRangeContract(
        state_payload_bounds=(1000, 1000), input_payload_bounds=(0,), horizon_steps=100,
    )
    client.distribute_controller(spec, contract)
    assert client.range_verification.proof_mode == "finite_horizon"
    assert client.range_verification.state_accumulator_bounds[0] < 1000 * 256


def test_encoded_power_bounds_cover_all_small_rounding_paths() -> None:
    """枚举负系数、全部有界输入及±1误差，独立检查每步累加器与终点。"""
    from itertools import product

    from secure_control.protocol.roles import _finite_horizon_encoded_trace

    payloads = {
        "A": np.array([[3, 3], [-3, -3]], dtype=object),
        "B": np.array([[1], [-2]], dtype=object),
        "C": np.array([[3, -2]], dtype=object),
        "D": np.array([[1]], dtype=object), "x0": np.array([2, -1], dtype=object),
    }
    trace = list(_finite_horizon_encoded_trace(payloads, (2,), 2, 4))
    states = {(2, -1)}
    for step in range(5):
        certificate = trace[step]
        following = set()
        for state in states:
            assert all(abs(value) <= bound for value, bound in zip(
                state, certificate["state_payload_bounds"], strict=True
            ))
            if step == 4:
                continue
            for measurement in range(-2, 3):
                raw = payloads["A"] @ np.array(state, dtype=object) + (
                    payloads["B"][:, 0] * measurement
                )
                assert all(abs(value) <= bound for value, bound in zip(
                    raw, certificate["state_accumulator_bounds"], strict=True
                ))
                output = 3 * state[0] - 2 * state[1] + measurement
                assert abs(output) <= certificate["output_accumulator_bounds"][0]
                # floor(m/S+1/2) 的整数形式，避免用被测实现或 Python round。
                rounded = [(2 * int(value) + 4) // 8 for value in raw]
                for errors in product((-1, 0, 1), repeat=2):
                    following.add(tuple(value + error for value, error in zip(
                        rounded, errors, strict=True
                    )))
        states = following
    assert trace[-1]["state_accumulator_bounds"] == []
    assert trace[-1]["output_accumulator_bounds"] == []
