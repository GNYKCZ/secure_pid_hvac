"""2R2C HVAC 局部未饱和闭环稳定性报告的独立装配与适用性测试。"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest

from secure_control.core import ControllerSpec
from secure_control.scenarios.hvac import (
    analyze_hvac_closed_loop_stability,
    build_hvac_2r2c_state_space,
    build_hvac_closed_loop_matrix,
    load_hvac_pid_tuning_contract,
    load_hvac_scenario_contract,
)

PROJECT_ROOT = Path(__file__).parents[1]
PLANT_CONFIG = PROJECT_ROOT / "configs" / "hvac_2r2c_plant.yaml"
PID_CONFIG = PROJECT_ROOT / "configs" / "hvac_2r2c_pid_baseline.yaml"


def _frozen_components():
    """加载同一组冻结 plant/PID，供独立矩阵 oracle 使用。"""
    contract = load_hvac_scenario_contract(PLANT_CONFIG)
    design, _, _ = load_hvac_pid_tuning_contract(PID_CONFIG, contract)
    plant = build_hvac_2r2c_state_space(contract.model, contract.timing.sampling_period_seconds)
    return contract, plant, design.to_controller_spec()


def test_closed_loop_matrix_matches_independent_block_formula() -> None:
    """独立按冻结公式锁定状态顺序、负反馈符号和更新前控制器状态时序。"""
    _, plant, controller = _frozen_components()
    expected = np.block(
        [
            [controller.A, -controller.B @ plant.C_p],
            [
                plant.B_p @ controller.C,
                plant.A_p - plant.B_p @ controller.D @ plant.C_p,
            ],
        ]
    )

    actual = build_hvac_closed_loop_matrix(plant, controller)

    assert actual.shape == (4, 4)
    assert np.array_equal(actual, expected)
    assert not actual.flags.writeable


def test_frozen_report_reproduces_spectrum_sources_and_claim_boundary() -> None:
    """正式报告绑定冻结来源并复现设计阶段独立核对的谱与数值诊断。"""
    report = analyze_hvac_closed_loop_stability(PLANT_CONFIG, PID_CONFIG)

    assert report.state_order == (
        "integral_error",
        "previous_error",
        "air_temperature",
        "wall_temperature",
    )
    assert report.state_units == ("degC_second", "degC", "degC", "degC")
    assert report.matrix_dimension == 4
    assert report.schur.status == "stable"
    assert [item.real for item in report.schur.eigenvalues] == pytest.approx(
        [-0.00146661, 0.87086944, 0.95275712, 0.99938114], abs=5e-8
    )
    assert report.schur.spectral_radius == pytest.approx(0.99938114, abs=5e-8)
    assert report.schur.margin_to_unit_circle == pytest.approx(6.1886e-4, abs=5e-8)
    assert report.schur.matrix_condition_number == pytest.approx(6.41e4, rel=0.02)
    assert report.schur.eigenvector_condition_number == pytest.approx(2.38e3, rel=0.02)
    assert report.plant_source_sha256 == sha256(PLANT_CONFIG.read_bytes()).hexdigest()
    assert report.pid_source_sha256 == sha256(PID_CONFIG.read_bytes()).hexdigest()
    assert len(report.assumptions) >= 4
    assert "未饱和" in report.claim_boundary
    assert "安全协议" in report.claim_boundary


def test_each_reference_has_consistent_equilibrium_and_unsaturated_radius() -> None:
    """三个工作点分别求解，不共享饱和裕量；raw control 在区间内时等于 applied control。"""
    contract, plant, controller = _frozen_components()
    report = analyze_hvac_closed_loop_stability(PLANT_CONFIG, PID_CONFIG)
    phi = np.asarray(report.closed_loop_matrix)
    state_matrix = np.eye(4) - phi
    control_sensitivity = np.concatenate((controller.C[0], (-controller.D @ plant.C_p)[0]))
    sensitivity_norm = np.sum(np.abs(control_sensitivity))

    assert [item.reference_celsius for item in report.equilibria] == [15.0, 20.0, 25.0]
    assert [item.raw_control_kw for item in report.equilibria] == pytest.approx(
        [1.525940996948118, 1.017293997965412, 0.508646998982706], rel=2e-10
    )
    for equilibrium in report.equilibria:
        assert equilibrium.applicability == "applicable"
        assert equilibrium.error_celsius == pytest.approx(0.0, abs=2e-10)
        assert equilibrium.equilibrium_residual < 1e-14
        assert equilibrium.equilibrium_condition_number == pytest.approx(5.00e7, rel=0.02)
        assert equilibrium.raw_control_kw == pytest.approx(
            np.clip(
                equilibrium.raw_control_kw,
                contract.model.lower_control_bound_kw,
                contract.model.upper_control_bound_kw,
            )
        )
        assert equilibrium.lower_margin_kw == pytest.approx(
            equilibrium.raw_control_kw - contract.model.lower_control_bound_kw
        )
        assert equilibrium.upper_margin_kw == pytest.approx(
            contract.model.upper_control_bound_kw - equilibrium.raw_control_kw
        )
        assert equilibrium.unsaturated_linf_radius == pytest.approx(
            min(equilibrium.lower_margin_kw, equilibrium.upper_margin_kw) / sensitivity_norm
        )
        state = np.array((*equilibrium.controller_state, *equilibrium.plant_state_celsius))
        reference = equilibrium.reference_celsius
        affine = np.concatenate(
            (
                controller.B[:, 0] * reference,
                plant.B_p[:, 0] * controller.D[0, 0] * reference
                + plant.E_p[:, 0] * equilibrium.ambient_celsius,
            )
        )
        assert np.linalg.norm(state_matrix @ state - affine, ord=np.inf) < 2e-12


def test_boundary_and_outside_actuator_points_are_not_applicable() -> None:
    """室外温度参考需要零或负制冷，不能附带局部未饱和适用声明。"""
    report = analyze_hvac_closed_loop_stability(
        PLANT_CONFIG, PID_CONFIG, references_celsius=[30.0, 31.0]
    )

    assert [item.applicability for item in report.equilibria] == [
        "not_applicable",
        "not_applicable",
    ]
    assert all(item.unsaturated_linf_radius is None for item in report.equilibria)
    assert all("strict_actuator_interior" not in item.reason for item in report.equilibria)


def test_matrix_builder_rejects_non_siso_controller() -> None:
    """HVAC 装配只接受和单测量、单执行器 plant 兼容的控制器。"""
    _, plant, _ = _frozen_components()
    incompatible = ControllerSpec(
        A=np.eye(1),
        B=np.ones((1, 2)),
        C=np.ones((1, 1)),
        D=np.ones((1, 2)),
        x0=np.zeros(1),
    )

    with pytest.raises(ValueError, match="SISO"):
        build_hvac_closed_loop_matrix(plant, incompatible)


def test_equilibrium_solver_failure_is_indeterminate_without_fake_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """合法配置若平衡方程数值求解失败，应保留 Schur 结果并仅降级工作点。"""
    from secure_control.scenarios.hvac import stability

    def fail(_matrix, _affine):
        raise np.linalg.LinAlgError("synthetic singular equilibrium")

    monkeypatch.setattr(stability.np.linalg, "solve", fail)
    report = analyze_hvac_closed_loop_stability(PLANT_CONFIG, PID_CONFIG)

    assert report.schur.status == "stable"
    assert all(item.applicability == "indeterminate" for item in report.equilibria)
    assert all(item.controller_state == () for item in report.equilibria)
    assert all(item.raw_control_kw is None for item in report.equilibria)
    assert all("equilibrium_solve_failed" in item.reason for item in report.equilibria)


def test_thin_runner_emits_complete_standard_json(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI 只序列化同一报告，并禁止 NaN/Infinity 破坏标准 JSON。"""
    from secure_control.scenarios.hvac.stability_runner import main

    assert main([str(PLANT_CONFIG), str(PID_CONFIG)]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["state_order"] == [
        "integral_error",
        "previous_error",
        "air_temperature",
        "wall_temperature",
    ]
    assert payload["state_units"] == ["degC_second", "degC", "degC", "degC"]
    assert payload["matrix_dimension"] == 4
    assert payload["schur"]["status"] == "stable"
    assert [item["applicability"] for item in payload["equilibria"]] == [
        "applicable",
        "applicable",
        "applicable",
    ]
