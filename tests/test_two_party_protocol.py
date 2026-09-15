"""领域无关 Client/P1/P2 Protocol 3 的角色、尺度、范围与身份绑定测试。"""

from __future__ import annotations

import random
from dataclasses import fields, replace

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import AdditiveShare, FixedPointContext, TwoPartySharing
from secure_control.protocol import (
    P1,
    P2,
    Client,
    ControllerRangeContract,
    OfflineDistribution,
    OnlineRound,
    SingleProcessCoordinator,
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
    assert online.p1_resources.consumed_count == online.p2_resources.consumed_count == 11
    assert (client.multiplier.created_triples, client.multiplier.consumed_triples) == (9, 9)
    assert (client.truncation.created_masks, client.truncation.consumed_masks) == (2, 2)


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


def test_reseeded_test_rng_domain_separates_each_online_round_material() -> None:
    """验证同一 Client 重新播种测试 RNG 时，各 round 的 triple 与 mask 仍不重复。"""
    client, _, _, _, distribution = make_stack()
    first = client.prepare_online(distribution, [0.0], step=0, rng=random.Random(20))
    second = client.prepare_online(distribution, [0.25], step=1, rng=random.Random(20))

    first_triples = [
        client.sharing.reconstruct(first_item.triple.b, second_item.triple.b)
        for first_item, second_item in zip(
            first.p1_resources.product_resources,
            first.p2_resources.product_resources,
            strict=True,
        )
    ]
    second_triples = [
        client.sharing.reconstruct(first_item.triple.b, second_item.triple.b)
        for first_item, second_item in zip(
            second.p1_resources.product_resources,
            second.p2_resources.product_resources,
            strict=True,
        )
    ]
    first_masks = [
        (
            client.sharing.reconstruct(first_item.truncation.r, second_item.truncation.r),
            client.sharing.reconstruct(
                first_item.truncation.r_prime, second_item.truncation.r_prime
            ),
        )
        for first_item, second_item in zip(
            first.p1_resources.state_truncation_resources,
            first.p2_resources.state_truncation_resources,
            strict=True,
        )
    ]
    second_masks = [
        (
            client.sharing.reconstruct(first_item.truncation.r, second_item.truncation.r),
            client.sharing.reconstruct(
                first_item.truncation.r_prime, second_item.truncation.r_prime
            ),
        )
        for first_item, second_item in zip(
            second.p1_resources.state_truncation_resources,
            second.p2_resources.state_truncation_resources,
            strict=True,
        )
    ]

    assert first.round_id != second.round_id
    # 每个公开 e 都减去其对应 triple 的 b；逐项不同才不会暴露跨轮 input 差值。
    assert all(
        first_value != second_value
        for first_value, second_value in zip(first_triples, second_triples, strict=True)
    )
    assert all(
        first_value != second_value
        for first_value, second_value in zip(first_masks, second_masks, strict=True)
    )


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


def test_client_rejects_cross_session_control_output_shares() -> None:
    """验证 Client 不会重构来自不同 controller session 或 round 的 output shares。"""
    client, p1, p2, coordinator, distribution = make_stack(seed=40)
    first = coordinator.execute(
        p1, p2, client.prepare_online(distribution, [0.25], step=0, rng=random.Random(41))
    )
    other_client, other_p1, other_p2, other_coordinator, other_distribution = make_stack(seed=42)
    second = other_coordinator.execute(
        other_p1,
        other_p2,
        other_client.prepare_online(other_distribution, [0.25], step=0, rng=random.Random(43)),
    )

    with pytest.raises(ValueError, match="session/round"):
        client.reconstruct_control(first[0], second[1])


def test_fixed_resource_seed_cannot_collide_controller_sessions_or_mix_servers() -> None:
    """验证资源随机源可重放时，身份仍唯一且跨 controller 组合会在 claim 前拒绝。"""
    first_client, first_p1, _, first_coordinator, first_distribution = make_stack(seed=10)
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    second_client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    second_spec = ControllerSpec(
        A=np.array([[0.5, 0.0], [0.0, 0.5]]),
        B=np.array([[0.25], [-0.25]]),
        C=np.array([[2.0, 2.0]]),
        D=np.array([[0.5]]),
        x0=np.array([0.5, 0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=8, B=8, C=8, D=8),
    )
    second_distribution = second_client.distribute_controller(
        second_spec,
        ControllerRangeContract(state_payload_bounds=(256, 256), input_payload_bounds=(64,)),
        rng=random.Random(10),
    )
    online = first_client.prepare_online(first_distribution, [0.25], step=0, rng=random.Random(20))
    initial_state = share_values(first_p1.state_share)

    assert first_distribution.session_id != second_distribution.session_id
    with pytest.raises(ValueError, match="session"):
        first_coordinator.execute(first_p1, P2(second_distribution.p2), online)
    assert share_values(first_p1.state_share) == initial_state
    assert online.p1_resources.aborted_count == 11


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


def test_fixed_seed_replays_crypto_material_but_not_session_round_identities() -> None:
    """验证固定 seed 仅重放密码材料与输出 share，绝不重放身份标识。"""
    first_client, first_p1, first_p2, first_coordinator, first_distribution = make_stack(seed=30)
    second_client, second_p1, second_p2, second_coordinator, second_distribution = make_stack(
        seed=30
    )
    first_online = first_client.prepare_online(
        first_distribution, [0.25], step=3, rng=random.Random(40)
    )
    second_online = second_client.prepare_online(
        second_distribution, [0.25], step=3, rng=random.Random(40)
    )

    first_output = first_coordinator.execute(first_p1, first_p2, first_online)
    second_output = second_coordinator.execute(second_p1, second_p2, second_online)

    assert first_online.session_id != second_online.session_id
    assert first_online.round_id != second_online.round_id
    assert share_values(first_output[0].value) == share_values(second_output[0].value)
    assert share_values(first_output[1].value) == share_values(second_output[1].value)


def test_protocol_rejects_non_uniform_controller_scale_metadata() -> None:
    """验证混合尺度被显式拒绝，而不是静默错配 Protocol 3 的乘法尺度。"""
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

    with pytest.raises(ValueError, match="output 为 2\\*ell"):
        client.distribute_controller(
            spec,
            ControllerRangeContract(state_payload_bounds=(1,), input_payload_bounds=(0,)),
            rng=random.Random(50),
        )
