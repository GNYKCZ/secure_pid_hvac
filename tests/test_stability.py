"""领域无关离散 Schur 判定器的手算 oracle 与失败边界测试。"""

from __future__ import annotations

import numpy as np
import pytest

from secure_control.core import check_discrete_schur_stability


def test_diagonal_matrix_is_stable_with_hand_computed_spectrum() -> None:
    """对角阵的特征值可直接手算，避免以被测实现生成期望值。"""
    report = check_discrete_schur_stability(np.diag([0.5, -0.25]))

    assert report.status == "stable"
    assert report.spectral_radius == pytest.approx(0.5)
    assert report.margin_to_unit_circle == pytest.approx(0.5)
    assert [(item.real, item.imaginary) for item in report.eigenvalues] == pytest.approx(
        [(-0.25, 0.0), (0.5, 0.0)]
    )
    assert max(item.normalized_residual for item in report.eigenvalues) < 1e-14


def test_triangular_matrix_is_unstable_with_hand_computed_spectrum() -> None:
    """上三角阵的对角元素就是特征值，锁定单位圆外分类。"""
    report = check_discrete_schur_stability(np.array([[0.5, 3.0], [0.0, 1.2]]))

    assert report.status == "unstable"
    assert report.spectral_radius == pytest.approx(1.2)
    assert report.margin_to_unit_circle == pytest.approx(-0.2)


def test_unit_circle_tolerance_band_is_near_boundary() -> None:
    """落入显式容差带的谱半径不能被静默判为稳定或不稳定。"""
    report = check_discrete_schur_stability(np.diag([1.0 + 5e-10, 0.25]), boundary_tolerance=1e-9)

    assert report.status == "near_boundary"
    assert report.spectral_radius == pytest.approx(1.0 + 5e-10)


def test_checker_supports_arbitrary_state_dimension() -> None:
    """通用层不得把当前 HVAC 的四维闭环写死。"""
    report = check_discrete_schur_stability(np.diag([0.1, 0.2, 0.3, 0.4, 0.5]))

    assert report.status == "stable"
    assert len(report.eigenvalues) == 5


@pytest.mark.parametrize(
    ("matrix", "error"),
    [
        ([], ValueError),
        ([[1.0, 2.0, 3.0]], ValueError),
        ([[1.0, np.nan], [0.0, 1.0]], ValueError),
        ([[1.0, np.inf], [0.0, 1.0]], ValueError),
        ([[1.0 + 1.0j]], TypeError),
        ([[True]], TypeError),
        ([["not-a-number"]], TypeError),
    ],
)
def test_checker_rejects_invalid_matrix_inputs(matrix, error: type[Exception]) -> None:
    """类型、shape、空矩阵和非有限数在数值分解前明确失败。"""
    with pytest.raises(error):
        check_discrete_schur_stability(matrix)


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("boundary_tolerance", 0.0),
        ("boundary_tolerance", np.inf),
        ("residual_tolerance", -1.0),
        ("residual_tolerance", True),
        ("eigenvector_condition_limit", 0.0),
    ],
)
def test_checker_rejects_invalid_numeric_thresholds(keyword: str, value: object) -> None:
    """所有分类与诊断阈值必须是严格为正的有限实数。"""
    with pytest.raises((TypeError, ValueError)):
        check_discrete_schur_stability(np.eye(2), **{keyword: value})


def test_eigendecomposition_failure_returns_indeterminate(monkeypatch: pytest.MonkeyPatch) -> None:
    """合法矩阵上的底层数值失败应保守降级，而不是冒充输入错误。"""
    from secure_control.core import stability

    def fail(_matrix):
        raise np.linalg.LinAlgError("synthetic decomposition failure")

    monkeypatch.setattr(stability.np.linalg, "eig", fail)
    report = check_discrete_schur_stability(np.eye(2) * 0.5)

    assert report.status == "indeterminate"
    assert report.spectral_radius is None
    assert report.eigenvalues == ()
    assert "eigendecomposition_failed" in report.reason


def test_excessive_eigenvector_condition_returns_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """特征向量条件指标超过阈值时不得仅凭计算出的谱半径判稳。"""
    from secure_control.core import stability

    calls = iter([2.0, 1e13])
    monkeypatch.setattr(stability.np.linalg, "cond", lambda _matrix: next(calls))
    report = check_discrete_schur_stability(np.diag([0.25, 0.5]), eigenvector_condition_limit=1e12)

    assert report.status == "indeterminate"
    assert report.spectral_radius == pytest.approx(0.5)
    assert report.eigenvector_condition_number == pytest.approx(1e13)
    assert report.reason == "eigenvector_condition_limit_exceeded"
