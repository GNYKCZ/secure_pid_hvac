"""冻结 2R2C plant 与位置式 PID 的局部未饱和闭环稳定性分析。"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from numbers import Real
from pathlib import Path
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from secure_control.core import (
    ControllerSpec,
    SchurStabilityReport,
    check_discrete_schur_stability,
)

from .contract import Hvac2R2CModelContract, load_hvac_scenario_contract
from .plant import Hvac2R2CStateSpace, build_hvac_2r2c_state_space
from .tuning import load_hvac_pid_tuning_contract

ApplicabilityStatus = Literal["applicable", "not_applicable", "indeterminate"]

_STATE_ORDER = (
    "integral_error",
    "previous_error",
    "air_temperature",
    "wall_temperature",
)
_STATE_UNITS = ("degC_second", "degC", "degC", "degC")
_EQUILIBRIUM_RESIDUAL_TOLERANCE = 1e-10
_EQUILIBRIUM_CONDITION_LIMIT = 1e12


@dataclass(frozen=True, slots=True)
class HvacEquilibriumReport:
    """保存单个 reference/ambient 工作点的平衡解与严格执行器适用性。"""

    reference_celsius: float
    ambient_celsius: float
    controller_state: tuple[float, ...]
    plant_state_celsius: tuple[float, ...]
    error_celsius: float | None
    raw_control_kw: float | None
    lower_margin_kw: float | None
    upper_margin_kw: float | None
    equilibrium_residual: float | None
    equilibrium_condition_number: float | None
    unsaturated_linf_radius: float | None
    applicability: ApplicabilityStatus
    reason: str


@dataclass(frozen=True, slots=True)
class HvacClosedLoopStabilityReport:
    """组合闭环 Schur 诊断、逐工作点适用性及可审计配置来源。"""

    state_order: tuple[str, ...]
    state_units: tuple[str, ...]
    matrix_dimension: int
    closed_loop_matrix: tuple[tuple[float, ...], ...]
    schur: SchurStabilityReport
    equilibria: tuple[HvacEquilibriumReport, ...]
    plant_source_sha256: str
    pid_source_sha256: str
    assumptions: tuple[str, ...]
    claim_boundary: str


def build_hvac_closed_loop_matrix(
    plant: Hvac2R2CStateSpace,
    controller: ControllerSpec,
) -> NDArray[np.float64]:
    """按 ``[I,e_previous,T_air,T_wall]`` 和更新前控制状态装配 ``Phi``。"""
    if not isinstance(plant, Hvac2R2CStateSpace):
        raise TypeError("plant 必须是 Hvac2R2CStateSpace")
    if not isinstance(controller, ControllerSpec):
        raise TypeError("controller 必须是 ControllerSpec")
    if controller.input_dimension != 1 or controller.output_dimension != 1:
        raise ValueError("HVAC 闭环稳定性装配要求 SISO controller")
    if plant.C_p.shape != (1, 2) or plant.B_p.shape != (2, 1):
        raise ValueError("2R2C plant 的 input/output shape 与冻结 HVAC 模型不兼容")

    # reference 与 ambient 是仿射项；此处只装配齐次闭环状态矩阵。
    matrix = np.block(
        [
            [controller.A, -controller.B @ plant.C_p],
            [
                plant.B_p @ controller.C,
                plant.A_p - plant.B_p @ controller.D @ plant.C_p,
            ],
        ]
    ).astype(float, copy=False)
    if not np.isfinite(matrix).all():
        raise FloatingPointError("HVAC 闭环矩阵包含 NaN 或无穷大")
    matrix.setflags(write=False)
    return matrix


def analyze_hvac_closed_loop_stability(
    plant_config: str | Path,
    pid_config: str | Path,
    *,
    references_celsius: Sequence[float] | None = None,
    boundary_tolerance: float = 1e-9,
) -> HvacClosedLoopStabilityReport:
    """从冻结配置生成局部、未饱和、明文实数闭环的完整只读报告。"""
    plant_path = Path(plant_config)
    pid_path = Path(pid_config)
    try:
        plant_source = plant_path.read_bytes()
        pid_source = pid_path.read_bytes()
    except OSError as error:
        raise ValueError("无法读取 HVAC 稳定性分析配置") from error

    contract = load_hvac_scenario_contract(plant_path)
    if not isinstance(contract.model, Hvac2R2CModelContract):
        raise TypeError("稳定性分析只接受 2R2C HVAC plant 配置")
    design, _, _ = load_hvac_pid_tuning_contract(pid_path, contract)
    plant = build_hvac_2r2c_state_space(contract.model, contract.timing.sampling_period_seconds)
    controller = design.to_controller_spec()
    matrix = build_hvac_closed_loop_matrix(plant, controller)
    schur = check_discrete_schur_stability(matrix, boundary_tolerance=boundary_tolerance)
    try:
        sources_unchanged = (
            plant_path.read_bytes() == plant_source and pid_path.read_bytes() == pid_source
        )
    except OSError as error:
        raise ValueError("无法复验 HVAC 稳定性配置") from error
    if not sources_unchanged:
        raise ValueError("HVAC 稳定性配置在分析期间发生变化")
    references = _reference_values(references_celsius, contract.reference_segments)
    equilibria = tuple(
        _analyze_equilibrium(
            matrix,
            plant,
            controller,
            reference,
            contract.model.ambient_temperature_celsius,
            contract.model.lower_control_bound_kw,
            contract.model.upper_control_bound_kw,
        )
        for reference in references
    )
    return HvacClosedLoopStabilityReport(
        state_order=_STATE_ORDER,
        state_units=_STATE_UNITS,
        matrix_dimension=matrix.shape[0],
        closed_loop_matrix=tuple(tuple(float(value) for value in row) for row in matrix),
        schur=schur,
        equilibria=equilibria,
        plant_source_sha256=sha256(plant_source).hexdigest(),
        pid_source_sha256=sha256(pid_source).hexdigest(),
        assumptions=(
            "2R2C exact-ZOH plant 参数与采样周期固定不变",
            "位置式 PID 使用更新前状态且 reference 与 ambient 在工作点附近固定",
            "仅 applicability=applicable 的所报告邻域保证执行器严格未饱和",
            "计算采用明文精确实数线性模型，不含定点量化或协议误差",
        ),
        claim_boundary=(
            "结论仅覆盖各平衡点附近的未饱和、明文、精确实数线性模型；不证明饱和切换"
            "系统、定点量化、安全协议执行或无限时域安全性。"
        ),
    )


def _reference_values(references: Sequence[float] | None, segments) -> tuple[float, ...]:
    """校验显式 reference，或按配置区段顺序去重取得默认工作点。"""
    source = (
        [segment.target_temperature_celsius for segment in segments]
        if references is None
        else list(references)
    )
    if not source:
        raise ValueError("references_celsius 不得为空")
    result: list[float] = []
    for value in source:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise TypeError("reference 必须是有限实数")
        converted = float(value)
        if not isfinite(converted):
            raise ValueError("reference 必须是有限实数")
        if converted not in result:
            result.append(converted)
    return tuple(result)


def _analyze_equilibrium(
    matrix: NDArray[np.float64],
    plant: Hvac2R2CStateSpace,
    controller: ControllerSpec,
    reference: float,
    ambient: float,
    lower_bound: float,
    upper_bound: float,
) -> HvacEquilibriumReport:
    """求解单个仿射平衡点，并给出不触及饱和的保守 ``L_inf`` 半径。"""
    system = np.eye(matrix.shape[0]) - matrix
    affine = np.concatenate(
        (
            controller.B[:, 0] * reference,
            plant.B_p[:, 0] * controller.D[0, 0] * reference + plant.E_p[:, 0] * ambient,
        )
    )
    try:
        condition = float(np.linalg.cond(system))
        if not isfinite(condition) or condition > _EQUILIBRIUM_CONDITION_LIMIT:
            return _indeterminate_equilibrium(
                reference,
                ambient,
                condition if isfinite(condition) else None,
                "equilibrium_condition_limit_exceeded",
            )
        state = np.linalg.solve(system, affine)
    except (np.linalg.LinAlgError, ValueError, FloatingPointError) as error:
        return _indeterminate_equilibrium(
            reference, ambient, None, f"equilibrium_solve_failed:{type(error).__name__}"
        )

    denominator = max(
        float(np.linalg.norm(system, ord=np.inf) * np.linalg.norm(state, ord=np.inf)),
        float(np.linalg.norm(affine, ord=np.inf)),
        np.finfo(float).tiny,
    )
    residual = float(np.linalg.norm(system @ state - affine, ord=np.inf) / denominator)
    if not np.isfinite(state).all() or not isfinite(residual):
        return _indeterminate_equilibrium(
            reference, ambient, condition, "non_finite_equilibrium_diagnostic"
        )
    if residual > _EQUILIBRIUM_RESIDUAL_TOLERANCE:
        return _indeterminate_equilibrium(
            reference, ambient, condition, "equilibrium_residual_limit_exceeded"
        )

    controller_dimension = controller.state_dimension
    controller_state = state[:controller_dimension]
    plant_state = state[controller_dimension:]
    error = float(reference - plant.C_p[0] @ plant_state)
    raw_control = float(controller.C[0] @ controller_state + controller.D[0, 0] * error)
    lower_margin = raw_control - lower_bound
    upper_margin = upper_bound - raw_control
    if lower_margin <= 0.0 or upper_margin <= 0.0:
        applicability: ApplicabilityStatus = "not_applicable"
        radius = None
        reason = "equilibrium_not_strictly_inside_actuator_bounds"
    else:
        # 对标量 raw control，delta-u 关于 ||delta-z||_inf 的诱导界是行向量元素绝对值之和。
        sensitivity = np.concatenate((controller.C[0], (-controller.D @ plant.C_p)[0]))
        sensitivity_norm = float(np.sum(np.abs(sensitivity)))
        if sensitivity_norm <= 0.0 or not isfinite(sensitivity_norm):
            applicability = "indeterminate"
            radius = None
            reason = "invalid_control_sensitivity"
        else:
            applicability = "applicable"
            radius = min(lower_margin, upper_margin) / sensitivity_norm
            reason = "equilibrium_in_strict_actuator_interior"
    return HvacEquilibriumReport(
        reference_celsius=reference,
        ambient_celsius=ambient,
        controller_state=tuple(float(value) for value in controller_state),
        plant_state_celsius=tuple(float(value) for value in plant_state),
        error_celsius=error,
        raw_control_kw=raw_control,
        lower_margin_kw=lower_margin,
        upper_margin_kw=upper_margin,
        equilibrium_residual=residual,
        equilibrium_condition_number=condition,
        unsaturated_linf_radius=radius,
        applicability=applicability,
        reason=reason,
    )


def _indeterminate_equilibrium(
    reference: float,
    ambient: float,
    condition: float | None,
    reason: str,
) -> HvacEquilibriumReport:
    """在平衡数值不可判定时返回空数值载荷，避免伪造工作点。"""
    return HvacEquilibriumReport(
        reference,
        ambient,
        (),
        (),
        None,
        None,
        None,
        None,
        None,
        condition,
        None,
        "indeterminate",
        reason,
    )
