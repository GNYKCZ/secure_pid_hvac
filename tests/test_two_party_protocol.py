"""领域无关 Client/P1/P2 协议核心的角色、资源和算术语义测试。"""

from __future__ import annotations

import random
from dataclasses import fields, replace

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import AdditiveShare, FixedPointContext, TwoPartySharing
from secure_control.protocol import P1, P2, Client, OnlineRound, SingleProcessCoordinator


def make_stack(*, seed: int = 10) -> tuple[Client, P1, P2, SingleProcessCoordinator, object]:
    """建立固定 seed 的二维状态、一维输入和一维输出通用控制器协议夹具。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed_point.modulus)
    client = Client(fixed_point, sharing, security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[1.0, 0.0], [0.0, 1.0]]),
        B=np.array([[1.0], [-1.0]]),
        C=np.array([[1.0, 1.0]]),
        D=np.array([[0.5]]),
        x0=np.array([1.0, -0.5]),
    )
    distribution = client.distribute_controller(spec, rng=random.Random(seed))
    return (
        client,
        P1(distribution.p1),
        P2(distribution.p2),
        SingleProcessCoordinator(sharing, client.multiplier, client.truncation),
        distribution,
    )


def share_values(share: AdditiveShare) -> list[int]:
    """把测试边界中的本地 share 转为普通列表，避免 object ndarray 的比较歧义。"""
    return np.asarray(share.value, dtype=object).tolist()


def test_generic_matrix_vector_step_uses_real_crypto_and_consumes_one_resource_per_term() -> None:
    """验证 A/B/C/D 的实际共享矩阵步骤、输出时序与按 shape 计数的资源消费。"""
    client, p1, p2, coordinator, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))

    first, second = coordinator.execute(p1, p2, online)
    output = client.reconstruct_control(first, second)
    reconstructed_state = client.fixed_point.decode_residue(
        client.sharing.reconstruct(p1.state_share, p2.state_share)
    )

    # u(0)=C*x0+D*v=0.5+0.125，x(1)=A*x0+B*v=(1.25,-0.75)。
    assert output.shape == (1,)
    assert output[0] == pytest.approx(0.625, abs=2.0 / client.fixed_point.scale)
    np.testing.assert_allclose(
        reconstructed_state,
        np.array([1.25, -0.75]),
        atol=2.0 / client.fixed_point.scale,
    )

    plan = online.p1_resources.plan
    assert (plan.state_shape, plan.input_shape, plan.output_shape) == ((2,), (1,), (1,))
    assert plan.resource_count == 9  # C(1*2) + D(1*1) + A(2*2) + B(2*1)
    assert [item.term for item in plan.resources] == ["C", "C", "D", "A", "A", "A", "A", "B", "B"]
    assert all(item.fractional_bits == 8 for item in plan.resources)
    assert online.p1_resources.consumed_count == online.p2_resources.consumed_count == 9
    assert online.p1_resources.aborted_count == online.p2_resources.aborted_count == 0
    assert (client.multiplier.created_triples, client.multiplier.consumed_triples) == (9, 9)
    assert (client.truncation.created_masks, client.truncation.consumed_masks) == (9, 9)


def test_server_visible_state_and_input_interfaces_reject_plaintext_or_two_share_containers() -> (
    None
):
    """验证 P1/P2 对外只接受自己的消息，不持有 Client、共享器或另一方 state。"""
    client, p1, p2, _, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))

    assert isinstance(p1.state_share, AdditiveShare)
    assert isinstance(p2.state_share, AdditiveShare)
    assert {field.name for field in fields(p1)} == {"_party", "_controller", "_state", "_layout"}
    assert all(
        isinstance(getattr(p1.controller_share, name), AdditiveShare)
        for name in ("A", "B", "C", "D")
    )
    assert not hasattr(p1.controller_share, "x0")
    assert not hasattr(p1, "sharing")
    assert not hasattr(p1, "client")
    assert not hasattr(p1, "reconstruct_control")
    with pytest.raises(ValueError, match="OfflineControllerMessage"):
        P1(distribution.p2)
    with pytest.raises(TypeError, match="InputShareMessage"):
        p1.input_share((online.p1_input, online.p2_input), step=0)  # type: ignore[arg-type]


def test_resource_pair_cannot_be_reused_after_a_successful_step() -> None:
    """验证每个 triple/mask 逻辑资源只完成一次，重放同一 OnlineRound 会被拒绝。"""
    client, p1, p2, coordinator, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    coordinator.execute(p1, p2, online)
    state_after_success = share_values(p1.state_share)

    with pytest.raises(ValueError, match="在线资源"):
        coordinator.execute(p1, p2, online)

    assert share_values(p1.state_share) == state_after_success
    assert online.p1_resources.consumed_count == 9
    assert online.p1_resources.aborted_count == 0


def test_failed_resource_pairing_aborts_all_reserved_material_without_committing_state() -> None:
    """验证资源错配失败会废弃本轮材料，且任何半完成计算都不会写入 controller state。"""
    client, p1, p2, coordinator, distribution = make_stack()
    first = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    malformed_first_p2_resource = replace(
        first.p2_resources.resources[0],
        triple=first.p1_resources.resources[0].triple,
    )
    malformed_resources = replace(
        first.p2_resources,
        resources=(malformed_first_p2_resource, *first.p2_resources.resources[1:]),
    )
    malformed: OnlineRound = replace(first, p2_resources=malformed_resources)
    initial_p1_state = share_values(p1.state_share)
    initial_p2_state = share_values(p2.state_share)

    # P1 已开始第一项的遮蔽后，P2 才发现 triple 的角色标签不属于自己。
    with pytest.raises(ValueError, match="角色不一致"):
        coordinator.execute(p1, p2, malformed)

    assert share_values(p1.state_share) == initial_p1_state
    assert share_values(p2.state_share) == initial_p2_state
    assert first.p1_resources.aborted_count == 9
    assert first.p2_resources.aborted_count == 9
    with pytest.raises(ValueError, match="在线资源"):
        coordinator.execute(p1, p2, first)


def test_fixed_seed_replays_generic_online_resources_and_output_shares() -> None:
    """验证相同 seed 重放本轮输入、triple、mask 与输出 shares，支持确定性测试路径。"""
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

    assert share_values(first_output[0].value) == share_values(second_output[0].value)
    assert share_values(first_output[1].value) == share_values(second_output[1].value)
    assert [item.metadata for item in first_online.p1_resources.resources] == [
        item.metadata for item in second_online.p1_resources.resources
    ]


def test_protocol_rejects_non_uniform_controller_scale_metadata() -> None:
    """验证当前 scalar-first 截断限制会显式拒绝混合尺度，而非静默得到错误控制量。"""
    fixed_point = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    client = Client(fixed_point, TwoPartySharing(fixed_point.modulus), security_parameter=8)
    spec = ControllerSpec(
        A=np.array([[1.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[1.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(
            state=8,
            input=8,
            output=8,
            A=8,
            B=8,
            C=7,
            D=8,
        ),
    )

    with pytest.raises(ValueError, match="相同 fractional bits"):
        client.distribute_controller(spec, rng=random.Random(50))
