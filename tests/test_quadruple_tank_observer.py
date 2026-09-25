"""论文四水箱 observer 印刷矩阵、独立递推和明文闭环交叉核验。"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from secure_control.core import ControllerSpec, check_discrete_schur_stability
from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.scenarios.quadruple_tank import (
    QuadrupleTankAdapter,
    QuadrupleTankPlant,
    load_quadruple_tank_contract,
    load_quadruple_tank_observer_spec,
)
from secure_control.simulation import SimulationBranch, simulate_branch

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "configs" / "quadruple_tank_observer.yaml"
PLANT = ROOT / "configs" / "quadruple_tank_plant.yaml"

# 独立从 Teranishi–Tanaka v3 §VII 原页转录；不从被测配置生成 expected。
PRINTED_A = np.array([
    [0.56817627, -0.00167847, 0.01213074, -0.00909424],
    [-0.00201416, 0.57826233, -0.00939941, 0.00976562],
    [-0.15261841, -0.01811218, 0.97219849, -0.00508118],
    [-0.01197815, -0.15417480, -0.00314331, 0.98011780],
])
PRINTED_B = np.array([
    [0.78367615, 0], [0, 0.78463745],
    [0.30230713, 0], [0, 0.30718994],
])
PRINTED_C = np.array([
    [-0.77249146, -0.03674316, -0.20259094, -0.21775818],
    [-0.06149292, -0.76373291, -0.29937744, -0.21432495],
])

# 用印刷矩阵与独立固定的 #73 ZOH 矩阵一次计算后冻结；行 k 为更新前值。
ORACLE_Y = np.array([
    [5.0, 5.0],
    [5.063433803466770, 5.054834705896795],
    [5.044712421868113, 5.044822329548815],
    [4.977292752648793, 4.996433570108328],
    [4.881521286090569, 4.925754331156242],
])
ORACLE_U = np.array([
    [0.0, 0.0],
    [-3.811755002660662, -4.018931904927438],
    [-6.005923924873247, -6.347403359208546],
    [-7.219009737832782, -7.650282522100470],
    [-7.838368382546492, -8.332297008279001],
])
ORACLE_XC = np.array([
    [0.0, 0.0, 0.0, 0.0],
    [3.91838075, 3.92318725, 1.51153565, 1.53594970],
    [6.192206066523143, 6.227743726051581, 2.323345867200233, 2.401663223753100],
    [7.467574876452501, 7.548769682292290, 2.713759935005603, 2.861996231121746],
    [8.137706313207618, 8.272958575410614, 2.852028000784002, 3.078139601509741],
])


def test_printed_observer_is_single_float64_controller_source() -> None:
    """逐项核对印刷 A/B/C/D/x0、转置方向、dtype 与只读规格。"""
    spec = load_quadruple_tank_observer_spec(OBSERVER)
    assert isinstance(spec, ControllerSpec)
    assert (spec.state_dimension, spec.input_dimension, spec.output_dimension) == (4, 2, 2)
    for actual, expected in (
        (spec.A, PRINTED_A), (spec.B, PRINTED_B), (spec.C, PRINTED_C),
        (spec.D, np.zeros((2, 2))), (spec.x0, np.zeros(4)),
    ):
        assert actual.dtype == np.float64
        assert not actual.flags.writeable
        np.testing.assert_array_equal(actual, expected)
    assert spec.scale_metadata is None


@pytest.mark.parametrize(
    ("old", "new", "error"),
    [
        ("schema_version: 1", "schema_version: true", ValueError),
        ("scenario: quadruple_tank", "scenario: hvac", ValueError),
        ('source: "arxiv:2503.02176v3 §VII"', "source: wrong", ValueError),
        ("  x0: [0, 0, 0, 0]", "  x0: [0, 0, 0]", ValueError),
        ("  x0: [0, 0, 0, 0]", "  x0: [0, false, 0, 0]", TypeError),
        ("  x0: [0, 0, 0, 0]", "  x0: [0, .nan, 0, 0]", ValueError),
        ("    - [0.78367615, 0]", "    - [0.78367615, 0, 0]", ValueError),
    ],
)
def test_bad_observer_config_fails_before_spec_construction(
    tmp_path: Path, old: str, new: str, error: type[Exception]
) -> None:
    """错版本/来源/shape/类型/非有限输入均不能形成部分 ControllerSpec。"""
    source = OBSERVER.read_text(encoding="utf-8")
    assert source.count(old) == 1
    bad = tmp_path / "observer.yaml"
    bad.write_text(source.replace(old, new), encoding="utf-8")
    with pytest.raises(error):
        load_quadruple_tank_observer_spec(bad)


def test_observer_rejects_unknown_and_duplicate_keys(tmp_path: Path) -> None:
    """根层或 controller 层的重复定义不能覆盖印刷来源。"""
    source = OBSERVER.read_text(encoding="utf-8")
    bad = tmp_path / "observer.yaml"
    for text in (
        source + "extra: 1\n",
        source + "scenario: hvac\n",
        source.replace("  x0: [0, 0, 0, 0]", "  x0: [0, 0, 0, 0]\n  x0: [1, 1, 1, 1]"),
    ):
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError):
            load_quadruple_tank_observer_spec(bad)


def test_printed_observer_runtime_matches_independent_multistep_equations() -> None:
    """先用旧状态输出，再用两路测量更新；扁平与列向量输入等价。"""
    spec = load_quadruple_tank_observer_spec(OBSERVER)
    flat = PlaintextStateSpaceRuntime(spec)
    column = PlaintextStateSpaceRuntime(spec)
    reference_state = np.zeros(4)
    for k, measurement in enumerate(ORACLE_Y):
        np.testing.assert_allclose(reference_state, ORACLE_XC[k], atol=2e-10, rtol=0)
        expected_control = PRINTED_C @ reference_state
        np.testing.assert_allclose(expected_control, ORACLE_U[k], atol=2e-10, rtol=0)
        np.testing.assert_allclose(flat.state, reference_state, atol=2e-10, rtol=0)
        np.testing.assert_allclose(flat.step(measurement), expected_control, atol=2e-10, rtol=0)
        np.testing.assert_allclose(
            column.step(measurement.reshape(2, 1)), expected_control, atol=2e-10, rtol=0
        )
        reference_state = PRINTED_A @ reference_state + PRINTED_B @ measurement
        np.testing.assert_allclose(flat.state, reference_state, atol=2e-10, rtol=0)
        np.testing.assert_allclose(column.state, reference_state, atol=2e-10, rtol=0)
    flat.reset()
    np.testing.assert_array_equal(flat.state, np.zeros(4))
    np.testing.assert_array_equal(flat.step(ORACLE_Y[0]), [0, 0])
    # 两个 runtime 共享只读 spec，但状态互不共享。
    assert not np.array_equal(flat.state, column.state)


def test_observer_runtime_rejects_bad_input_without_state_change() -> None:
    """shape、非有限或运算溢出时保持上一步有效 observer 状态。"""
    runtime = PlaintextStateSpaceRuntime(load_quadruple_tank_observer_spec(OBSERVER))
    runtime.step(ORACLE_Y[0])
    for bad in ([1], [[1, 2]], [np.nan, 0], [np.inf, 0], ["1", 0]):
        previous = runtime.state
        with pytest.raises((ValueError, TypeError, FloatingPointError)):
            runtime.step(bad)
        np.testing.assert_array_equal(runtime.state, previous)
    runtime.reset()
    huge = np.full(2, np.finfo(float).max)
    runtime.step(huge)
    previous = runtime.state
    with pytest.raises(FloatingPointError):
        runtime.step(huge)
    np.testing.assert_array_equal(runtime.state, previous)


def test_observer_plant_relation_and_closed_loop_schur_diagnostic() -> None:
    """逐项残差与 8×8 Φ 检查只作当前 #73 ZOH 口径的数值诊断。"""
    spec = load_quadruple_tank_observer_spec(OBSERVER)
    plant = QuadrupleTankPlant(load_quadruple_tank_contract(PLANT)).state_space
    residual = spec.A - (plant.A_p + plant.B_p @ spec.C - spec.B @ plant.C_p)
    expected_residual = np.array([
        [-0.00000097, 0.00003429, -0.00002480, -0.00001295],
        [0.00001153, 0.00002517, 0.00000310, 0.00001971],
        [-0.00000870, -0.00002706, -0.00000053, -0.00000599],
        [-0.00001999, -0.00001105, -0.00000721, 0.00002108],
    ])
    np.testing.assert_allclose(residual, expected_residual, atol=1e-8, rtol=0)
    assert np.max(np.abs(residual)) < 5e-5
    phi = np.block([
        [plant.A_p + plant.B_p @ spec.D @ plant.C_p, plant.B_p @ spec.C],
        [spec.B @ plant.C_p, spec.A],
    ])
    assert phi.shape == (8, 8)
    report = check_discrete_schur_stability(phi)
    assert report.status == "stable"
    assert report.spectral_radius == pytest.approx(0.9921134672, abs=1e-6)
    assert report.spectral_radius < 1
    assert report.eigenvector_condition_number is not None
    assert max(item.normalized_residual for item in report.eigenvalues) < report.residual_tolerance


def test_observer_runs_with_generic_branch_and_pre_step_outputs() -> None:
    """真实 plant/adapter/明文 runtime 的五步输出对照独立闭环 oracle。"""
    plant_contract = load_quadruple_tank_contract(PLANT)
    plant = QuadrupleTankPlant(plant_contract)
    runtime = PlaintextStateSpaceRuntime(load_quadruple_tank_observer_spec(OBSERVER))
    times = np.arange(5) * plant_contract.sample_period_seconds
    trajectory = simulate_branch(
        SimulationBranch(plant, QuadrupleTankAdapter(), runtime), times
    )
    np.testing.assert_array_equal(times, [0, 0.5, 1.0, 1.5, 2.0])
    np.testing.assert_array_equal(trajectory.reference, np.zeros((5, 2)))
    np.testing.assert_allclose(trajectory.output, ORACLE_Y, atol=2e-10, rtol=0)
    np.testing.assert_allclose(trajectory.control, ORACLE_U, atol=2e-10, rtol=0)
    np.testing.assert_allclose(
        runtime.state, [8.441901384100788, 8.635733538131948, 2.841010311032386, 3.148160382984322],
        atol=2e-10, rtol=0,
    )
