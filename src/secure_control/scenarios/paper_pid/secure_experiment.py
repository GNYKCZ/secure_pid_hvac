"""#70 paper-inspired PID 的无参考、无裁剪双闭环装配。"""

from __future__ import annotations

import numpy as np

from secure_control.core import ControllerSpec
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
    spec, context, contract = paper_pid_numeric_contract(
        fractional_bits=fractional_bits, parameter_bits=fractional_bits + 8,
        runtime_payload_bits=fractional_bits + runtime_payload_headroom_bits,
        modulus=modulus, sample_count=sample_count,
        measurement_absolute_bound=measurement_absolute_bound,
    )
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
    plan = assemble_paper_pid_plan(spec, secure, sample_count)
    return plan, secure, collector


def paper_pid_numeric_contract(
    *, fractional_bits: int, parameter_bits: int, runtime_payload_bits: int,
    modulus: int, sample_count: int, measurement_absolute_bound: int,
) -> tuple[ControllerSpec, FixedPointContext, ControllerRangeContract]:
    """场景独占的数值装配；两种后端使用相同 spec、range 公式。"""
    if (type(sample_count) is not int or not 1 <= sample_count <= 1000
            or type(measurement_absolute_bound) is not int
            or measurement_absolute_bound <= 0
            or type(parameter_bits) is not int or type(runtime_payload_bits) is not int
            or not runtime_payload_bits >= parameter_bits > fractional_bits >= 1):
        raise ValueError("paper PID 精度、样本数或测量界无效。")
    spec = paper_sec_vii_controller_spec()
    parameter_context = FixedPointContext(modulus, parameter_bits, fractional_bits)
    for name in ("A", "B", "C", "D", "x0"):
        parameter_context.encode(getattr(spec, name))
    context = FixedPointContext(modulus, runtime_payload_bits, fractional_bits)
    input_bound = measurement_absolute_bound * context.scale
    # A=[[1,0],[1,0]], B=[[1],[0]]。每次 Trunc 最多引入一单位 payload 误差。
    state_bound = sample_count * (input_bound + 1)
    contract = ControllerRangeContract((state_bound, state_bound), (input_bound,),
                                       horizon_steps=sample_count)
    return spec, context, contract


def assemble_paper_pid_plan(spec: ControllerSpec, secure: object,
                            sample_count: int) -> SimulationPlan:
    """构造互不共享的 ideal/secure plant 与 adapter，runtime 由调用方注入。"""
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
    return plan
