"""通用 secure execution evidence、状态转移和独立性回归。"""

from __future__ import annotations

import random
from dataclasses import replace

import numpy as np
import pytest

from secure_control import protocol
from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import AdditiveShare, FixedPointContext, TwoPartySharing
from secure_control.execution import (
    PlaintextStateSpaceRuntime,
    SecureStateSpaceRuntime,
    SecureTraceCollector,
    SecureTracePolicy,
)
from secure_control.protocol import (
    P1,
    P2,
    Client,
    ControllerRangeContract,
    SingleProcessCoordinator,
)


def test_raw_share_evidence_types_are_not_public_protocol_interfaces() -> None:
    """原始 share 审计类型不得从 protocol 顶层公共接口泄漏。"""
    assert not hasattr(protocol, "CombinedShareStepAudit")
    assert not hasattr(protocol, "ProtocolReconstructionEvidence")


def _spec(*, truncate_state: bool) -> ControllerSpec:
    """返回一维非场景控制器，分别覆盖 Protocol 2 与整数 A/B 路径。"""
    if truncate_state:
        return ControllerSpec(
            A=np.array([[0.5]]),
            B=np.array([[0.25]]),
            C=np.array([[1.0]]),
            D=np.array([[0.5]]),
            x0=np.array([0.5]),
            scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=8, B=8, C=8, D=8),
        )
    return ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[-1.0]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=0, B=0, C=8, D=8),
    )


def _runtime(
    spec: ControllerSpec,
    *,
    collector: SecureTraceCollector | None = None,
    policy: SecureTracePolicy | None = None,
) -> SecureStateSpaceRuntime:
    """建立具有显式有限范围的领域无关测试 runtime。"""
    return SecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(256,) * spec.state_dimension,
            input_payload_bounds=(64,) * spec.input_dimension,
        ),
        security_parameter=8,
        test_seed=91,
        trace_policy=policy,
        trace_collector=collector,
    )


@pytest.mark.parametrize("truncate_state", [False, True])
def test_opt_in_trace_preserves_outputs_and_records_actual_state_resources(
    truncate_state: bool,
) -> None:
    """trace 不改变数值，并按真实 ledger 记录 no-Trunc/Trunc 状态证据。"""
    spec = _spec(truncate_state=truncate_state)
    baseline = _runtime(spec)
    collector = SecureTraceCollector()
    traced = _runtime(
        spec,
        collector=collector,
        policy=SecureTracePolicy(selected_step=1, allow_combined_share_diagnostic=True),
    )
    inputs = (0.125, -0.0625, 0.03125)

    baseline_outputs = np.vstack([baseline.step(value) for value in inputs])
    traced_outputs = np.vstack([traced.step(value) for value in inputs])
    traces = collector.traces()

    assert np.array_equal(traced_outputs, baseline_outputs)
    assert [trace.step for trace in traces] == [0, 1, 2]
    assert [trace.state_transition is not None for trace in traces] == [False, True, False]
    assert traces[-1].resources_after.triples_consumed == (
        3 * traces[0].operations.protocol1_triples
    )
    assert traces[-1].resources_after.truncations_consumed == (3 if truncate_state else 0)
    assert traces[1].state_transition is not None
    assert traces[1].state_transition.equation_verified is True
    assert collector.selected_share_audit() is not None
    assert collector.selected_share_audit().reconstruction_verified is True


def test_trace_configuration_is_explicit_and_default_runtime_exposes_no_evidence() -> None:
    """缺少 policy/collector 或 deterministic seed 时 fail closed，默认接口保持原样。"""
    spec = _spec(truncate_state=False)
    default = _runtime(spec)
    assert np.isfinite(default.step(0.0)).all()
    assert not hasattr(default, "traces")
    assert not hasattr(default, "_resource_totals")

    with pytest.raises(ValueError, match="同时提供"):
        SecureStateSpaceRuntime(
            spec,
            FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
            ControllerRangeContract(state_payload_bounds=(256,), input_payload_bounds=(64,)),
            security_parameter=8,
            test_seed=1,
            trace_policy=SecureTracePolicy(selected_step=0),
        )
    with pytest.raises(ValueError, match="deterministic test_seed"):
        SecureStateSpaceRuntime(
            spec,
            FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
            ControllerRangeContract(state_payload_bounds=(256,), input_payload_bounds=(64,)),
            security_parameter=8,
            trace_policy=SecureTracePolicy(selected_step=0),
            trace_collector=SecureTraceCollector(),
        )


def test_reconstruction_boundary_one_lsb_changes_only_secure_centered_integer() -> None:
    """在测试边界给真实 output share 加 1 LSB，centered 精确加一且明文不变。"""
    spec = _spec(truncate_state=False)
    fixed = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    sharing = TwoPartySharing(fixed.modulus)
    client = Client(fixed, sharing, security_parameter=8)
    distribution = client.distribute_controller(
        spec,
        ControllerRangeContract(state_payload_bounds=(256,), input_payload_bounds=(64,)),
        rng=random.Random(4),
    )
    p1, p2 = P1(distribution.p1), P2(distribution.p2)
    coordinator = SingleProcessCoordinator(sharing, client.multiplier, client.truncation)
    online = client.prepare_online(distribution, [0.125], step=0, rng=random.Random(5))
    messages, snapshot = coordinator.execute_with_evidence(p1, p2, online)
    original_residue = sharing.reconstruct(messages[0].value, messages[1].value)
    original_centered = int(np.asarray(fixed.from_residue(original_residue), dtype=object)[0])
    changed_first = replace(
        messages[0],
        value=AdditiveShare(
            (np.asarray(messages[0].value.value, dtype=object) + 1) % fixed.modulus
        ),
    )
    changed_snapshot = replace(snapshot, output_p1=changed_first.value)
    plaintext = PlaintextStateSpaceRuntime(spec)
    plaintext_before = plaintext.step(0.125).copy()

    _, evidence = client.reconstruct_control_with_evidence(
        changed_first,
        messages[1],
        changed_snapshot,
        include_state=True,
        include_combined_share_audit=False,
    )

    assert evidence.raw_control.centered == (original_centered + 1,)
    assert evidence.step == 0
    assert evidence.raw_control.fractional_bits == 16
    assert np.array_equal(plaintext_before, PlaintextStateSpaceRuntime(spec).step(0.125))


def test_generic_non_saturated_secure_only_perturbation_leaves_plaintext_bitwise_unchanged() -> (
    None
):
    """可表示的 secure-only 测试扰动只改变安全输出，证明两条数据流不共享结果。"""
    spec = _spec(truncate_state=False)
    plain_reference = PlaintextStateSpaceRuntime(spec)
    plain_control = plain_reference.step(0.25).copy()
    secure = _runtime(spec)
    secure_control = secure.step(0.25)
    perturbed_secure = secure_control + np.array([0.25])

    assert not np.array_equal(perturbed_secure, secure_control)
    assert np.array_equal(plain_control, PlaintextStateSpaceRuntime(spec).step(0.25))
