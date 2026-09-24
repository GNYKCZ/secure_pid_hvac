"""#70 paper-inspired PID 的无参考、无裁剪双闭环装配。"""

from __future__ import annotations

import numpy as np

from secure_control.crypto import FixedPointContext, PrimeModulusEvidence
from secure_control.execution import (
    LocalhostSecureStateSpaceRuntime,
    PlaintextStateSpaceRuntime,
    SecureStateSpaceRuntime,
    SecureTraceCollector,
    SecureTracePolicy,
)
from secure_control.protocol import ControllerRangeContract
from secure_control.simulation import (
    ChannelMetadata,
    ScenarioMetadata,
    SimulationBranch,
    SimulationPlan,
)

from .pid import paper_sec_vii_controller_spec
from .plant import PaperPidCascadePlant


class PaperPidOutputAdapter:
    """v=y；schema v1 所需的恒零 reference 不参与控制计算。"""

    metadata = ScenarioMetadata(
        "paper_pid_fig3",
        ChannelMetadata(("unused_zero",), ("dimensionless",)),
        ChannelMetadata(("y",), ("paper_unit_unspecified",)),
        ChannelMetadata(("raw_u",), ("paper_unit_unspecified",)),
    )

    def reference_at(self, time: float) -> np.ndarray:
        return np.array([0.0])

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        return np.array(output, copy=True)

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        return np.array(raw_control, copy=True)


def build_paper_pid_plan(
    *,
    fractional_bits: int,
    modulus: int,
    modulus_evidence: PrimeModulusEvidence,
    security_parameter: int,
    sample_count: int,
    measurement_absolute_bound: int,
    runtime_payload_headroom_bits: int,
    test_seed: int | None,
    backend: str,
) -> tuple[SimulationPlan, SecureStateSpaceRuntime | LocalhostSecureStateSpaceRuntime,
           SecureTraceCollector | None]:
    """四级对象两次独立构造；预分享验证 51 步输入与 state 的公开界。"""
    if backend not in {"single_process", "localhost"}:
        raise ValueError("backend 必须是 single_process 或 localhost")
    spec = paper_sec_vii_controller_spec()
    paper_parameters = FixedPointContext(modulus, fractional_bits + 8, fractional_bits)
    for name in ("A", "B", "C", "D", "x0"):
        paper_parameters.encode(getattr(spec, name))
    context = FixedPointContext(modulus, fractional_bits + runtime_payload_headroom_bits,
                                fractional_bits)
    input_bound = measurement_absolute_bound * context.scale
    # A=[[1,0],[1,0]], B=[[1],[0]]。每次 Trunc 最多引入一单位 payload 误差。
    state_bound = sample_count * (input_bound + 1)
    contract = ControllerRangeContract((state_bound, state_bound), (input_bound,),
                                       horizon_steps=sample_count)
    collector = SecureTraceCollector() if backend == "single_process" and test_seed is not None else None
    if backend == "single_process":
        secure = SecureStateSpaceRuntime(
            spec, context, contract, security_parameter=security_parameter,
            modulus_evidence=modulus_evidence, test_seed=test_seed,
            trace_policy=SecureTracePolicy(0) if collector is not None else None,
            trace_collector=collector,
        )
    else:
        secure = LocalhostSecureStateSpaceRuntime(
            spec, context, contract, security_parameter=security_parameter,
            modulus_evidence=modulus_evidence, test_seed=test_seed,
        )
    ideal = SimulationBranch(
        PaperPidCascadePlant(0.2, 0.1, np.full(4, 100.0)),
        PaperPidOutputAdapter(), PlaintextStateSpaceRuntime(spec),
    )
    secure_branch = SimulationBranch(
        PaperPidCascadePlant(0.2, 0.1, np.full(4, 100.0)),
        PaperPidOutputAdapter(), secure,
    )
    plan = SimulationPlan(PaperPidOutputAdapter.metadata, np.arange(sample_count) * 0.1,
                          ideal, secure_branch)
    return plan, secure, collector
