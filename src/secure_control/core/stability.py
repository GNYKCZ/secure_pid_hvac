"""领域无关的离散时间 Schur 稳定性数值诊断。"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Real
from typing import Literal

import numpy as np
from numpy.typing import ArrayLike

SchurStatus = Literal["stable", "unstable", "near_boundary", "indeterminate"]


@dataclass(frozen=True, slots=True)
class EigenvalueDiagnostic:
    """保存单个特征值及其归一化右特征向量残差。"""

    real: float
    imaginary: float
    magnitude: float
    normalized_residual: float


@dataclass(frozen=True, slots=True)
class SchurStabilityReport:
    """保存显式容差、谱、残差和条件指标，不把结论压缩为布尔值。"""

    status: SchurStatus
    eigenvalues: tuple[EigenvalueDiagnostic, ...]
    spectral_radius: float | None
    margin_to_unit_circle: float | None
    boundary_tolerance: float
    residual_tolerance: float
    matrix_condition_number: float | None
    eigenvector_condition_number: float | None
    reason: str


def check_discrete_schur_stability(
    matrix: ArrayLike,
    *,
    boundary_tolerance: float = 1e-9,
    residual_tolerance: float = 1e-10,
    eigenvector_condition_limit: float = 1e12,
) -> SchurStabilityReport:
    """检查有限实方阵的离散 Schur 条件，并保守处理数值不确定性。

    ``rho < 1-boundary_tolerance`` 判为稳定，``rho > 1+boundary_tolerance``
    判为不稳定，中间灰区判为 ``near_boundary``。合法矩阵若无法可靠完成特征
    分解，返回 ``indeterminate``；输入契约错误则直接抛出异常。
    """
    boundary = _positive_finite_threshold("boundary_tolerance", boundary_tolerance)
    residual_limit = _positive_finite_threshold("residual_tolerance", residual_tolerance)
    condition_limit = _positive_finite_threshold(
        "eigenvector_condition_limit", eigenvector_condition_limit
    )
    values = _finite_real_square_matrix(matrix)

    try:
        eigenvalues, eigenvectors = np.linalg.eig(values)
    except (np.linalg.LinAlgError, ValueError, FloatingPointError) as error:
        return _indeterminate_report(
            boundary,
            residual_limit,
            reason=f"eigendecomposition_failed:{type(error).__name__}",
        )

    try:
        matrix_condition = _finite_condition_or_none(np.linalg.cond(values))
        eigenvector_condition = _finite_condition_or_none(np.linalg.cond(eigenvectors))
        matrix_norm = float(np.linalg.norm(values, ord=2))
        diagnostics = []
        tiny = np.finfo(float).tiny
        for index, eigenvalue in enumerate(eigenvalues):
            vector = eigenvectors[:, index]
            vector_norm = float(np.linalg.norm(vector, ord=2))
            numerator = float(np.linalg.norm(values @ vector - eigenvalue * vector, ord=2))
            denominator = max(matrix_norm * vector_norm, abs(eigenvalue) * vector_norm, tiny)
            diagnostics.append(
                EigenvalueDiagnostic(
                    real=float(eigenvalue.real),
                    imaginary=float(eigenvalue.imag),
                    magnitude=float(abs(eigenvalue)),
                    normalized_residual=numerator / denominator,
                )
            )
    except (np.linalg.LinAlgError, ValueError, FloatingPointError, OverflowError) as error:
        return _indeterminate_report(
            boundary,
            residual_limit,
            reason=f"numeric_diagnostics_failed:{type(error).__name__}",
        )

    diagnostics.sort(key=lambda item: (item.real, item.imaginary, item.magnitude))
    eigenvalue_reports = tuple(diagnostics)
    spectral_radius = max(item.magnitude for item in eigenvalue_reports)
    margin = 1.0 - spectral_radius
    numeric_values = (
        spectral_radius,
        margin,
        *(item.normalized_residual for item in eigenvalue_reports),
    )
    if not all(isfinite(item) for item in numeric_values):
        return SchurStabilityReport(
            "indeterminate",
            eigenvalue_reports,
            None,
            None,
            boundary,
            residual_limit,
            matrix_condition,
            eigenvector_condition,
            "non_finite_numeric_diagnostic",
        )
    if eigenvector_condition is None or eigenvector_condition > condition_limit:
        return SchurStabilityReport(
            "indeterminate",
            eigenvalue_reports,
            spectral_radius,
            margin,
            boundary,
            residual_limit,
            matrix_condition,
            eigenvector_condition,
            "eigenvector_condition_limit_exceeded",
        )
    if max(item.normalized_residual for item in eigenvalue_reports) > residual_limit:
        return SchurStabilityReport(
            "indeterminate",
            eigenvalue_reports,
            spectral_radius,
            margin,
            boundary,
            residual_limit,
            matrix_condition,
            eigenvector_condition,
            "eigenpair_residual_limit_exceeded",
        )

    if spectral_radius < 1.0 - boundary:
        status: SchurStatus = "stable"
        reason = "spectral_radius_strictly_inside_unit_circle"
    elif spectral_radius > 1.0 + boundary:
        status = "unstable"
        reason = "spectral_radius_strictly_outside_unit_circle"
    else:
        status = "near_boundary"
        reason = "spectral_radius_within_unit_circle_tolerance_band"
    return SchurStabilityReport(
        status,
        eigenvalue_reports,
        spectral_radius,
        margin,
        boundary,
        residual_limit,
        matrix_condition,
        eigenvector_condition,
        reason,
    )


def _finite_real_square_matrix(matrix: ArrayLike) -> np.ndarray:
    """复制并校验非空有限实方阵，拒绝布尔、复数和字符串隐式转换。"""
    raw = np.asarray(matrix)
    if raw.ndim != 2 or raw.shape[0] != raw.shape[1] or raw.shape[0] == 0:
        raise ValueError("matrix must be a non-empty square matrix")
    if raw.dtype.kind not in "iuf" or raw.dtype.kind == "b":
        raise TypeError("matrix must contain real numeric values")
    values = np.array(raw, dtype=float, copy=True)
    if not np.isfinite(values).all():
        raise ValueError("matrix must contain only finite values")
    return values


def _positive_finite_threshold(name: str, value: float) -> float:
    """校验不接受布尔值的严格正有限数值阈值。"""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{name} must be a real number")
    result = float(value)
    if not isfinite(result) or result <= 0.0:
        raise ValueError(f"{name} must be finite and strictly positive")
    return result


def _finite_condition_or_none(value: float) -> float | None:
    """把奇异矩阵的无穷条件数表示为 ``None``，保持标准 JSON 可序列化。"""
    result = float(value)
    return result if isfinite(result) else None


def _indeterminate_report(
    boundary_tolerance: float,
    residual_tolerance: float,
    *,
    reason: str,
) -> SchurStabilityReport:
    """构造没有可用谱诊断时的统一保守报告。"""
    return SchurStabilityReport(
        "indeterminate",
        (),
        None,
        None,
        boundary_tolerance,
        residual_tolerance,
        None,
        None,
        reason,
    )
