"""四水箱物理参数、独立数值基线及向量仿真时序回归。"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

from secure_control.scenarios.quadruple_tank import (
    QuadrupleTankAdapter,
    QuadrupleTankPlant,
    load_quadruple_tank_contract,
)
from secure_control.simulation import Plant, ScenarioAdapter, SimulationBranch, simulate_branch

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "quadruple_tank_plant.yaml"


@pytest.fixture
def contract():
    """加载受版本控制的唯一物理参数配置。"""
    return load_quadruple_tank_contract(CONFIG)


def test_source_parameters_and_continuous_matrices(contract) -> None:
    """固定原论文/Johansson 参数，并以原式手算分量核对泵路。"""
    assert contract.tank_cross_sections_cm2 == (28, 32, 28, 32)
    assert contract.outlet_cross_sections_cm2 == (0.071, 0.057, 0.071, 0.057)
    assert contract.pump_flow_coefficients_cm3_per_v_s == (3.33, 3.35)
    assert contract.heights_cm == (12.4, 12.7, 1.8, 1.4)
    assert contract.pump_voltages_v == (3, 3)
    assert contract.valve_fractions == (0.7, 0.6)
    assert contract.sample_period_seconds == 0.5
    assert contract.initial_state_deviation_cm == (10, 10, 10, 10)
    m = QuadrupleTankPlant(contract).state_space
    np.testing.assert_allclose(
        m.F,
        [[-0.015948101119320, 0, 0.041858491263020, 0],
         [0, -0.011069870050971, 0, 0.033341133876149],
         [0, 0, -0.041858491263020, 0],
         [0, 0, 0, -0.033341133876149]],
        atol=2e-15,
    )
    np.testing.assert_allclose(
        m.G,
        [[0.08325, 0], [0, 0.0628125], [0, 0.047857142857143], [0.03121875, 0]],
        atol=1e-15,
    )
    np.testing.assert_array_equal(m.C, [[0.5, 0, 0, 0], [0, 0.5, 0, 0]])
    np.testing.assert_array_equal(m.D_p, np.zeros((2, 2)))


def test_zoh_matrices_and_zero_input_trajectory(contract) -> None:
    """独立固定的 SciPy cont2discrete 基准覆盖 k=0/1/2 与多步。"""
    plant = QuadrupleTankPlant(contract)
    m = plant.state_space
    np.testing.assert_allclose(
        m.A_p,
        [[0.992057657844057, 0, 0.020629102849297, 0],
         [0, 0.994480354505523, 0, 0.016486586673836],
         [0, 0, 0.979288251040042, 0],
         [0, 0, 0, 0.983467618023506]],
        atol=2e-14,
    )
    np.testing.assert_allclose(
        m.B_p,
        [[0.041459480319024, 0.000248004868724],
         [0.000129149854358, 0.031319494359506],
         [0, 0.023679905770365], [0.015479986425953, 0]],
        atol=2e-14,
    )
    expected = [
        [5, 5],
        [5.063433803466769, 5.054834705896797],
        [5.124227469964732, 5.108003930914347],
        [5.182446215371368, 5.159539398457492],
        [5.238153821164452, 5.209472284345622],
        [5.291412664795480, 5.257833225993186],
    ]
    np.testing.assert_array_equal(plant.output(), expected[0])
    for expected_next in expected[1:]:
        np.testing.assert_allclose(plant.step(np.zeros(2)), expected_next, atol=2e-13)
    assert plant.state.shape == (4,)
    plant.reset()
    np.testing.assert_array_equal(plant.output(), expected[0])


@pytest.mark.parametrize(
    ("pulse", "expected_y1", "expected_y2"),
    [
        ([1, 0], [5.084163543626281, 5.054899280823975],
         [5.144792567435094, 5.108195755479780]),
        ([0, 1], [5.063557805901130, 5.070494453076550],
         [5.124594735135131, 5.123577241841134]),
    ],
)
def test_individual_pump_pulses_show_cross_coupling(contract, pulse, expected_y1, expected_y2) -> None:
    """两路单独脉冲均影响另一测量，固定直接与间接泵路的数值。"""
    plant = QuadrupleTankPlant(contract)
    np.testing.assert_allclose(plant.step(np.array(pulse)), expected_y1, atol=2e-13)
    np.testing.assert_allclose(plant.step(np.zeros(2)), expected_y2, atol=2e-13)


@pytest.mark.parametrize(
    "bad", [[1], [1, 2, 3], [[1, 2]], [np.nan, 0], [np.inf, 0], ["1", 0], [1j, 0]],
)
def test_bad_control_does_not_change_state(contract, bad) -> None:
    """拒绝错误 shape、类型或非有限值，并保持单步更新原子性。"""
    plant = QuadrupleTankPlant(contract)
    before = plant.state
    with pytest.raises((TypeError, ValueError, FloatingPointError)):
        plant.step(bad)
    np.testing.assert_array_equal(plant.state, before)


def test_contract_validation_and_snapshot_isolation(contract, tmp_path: Path) -> None:
    """非法来源拒绝加载；契约、状态及矩阵返回值不共享可变缓冲区。"""
    with pytest.raises(ValueError):
        replace(contract, valve_fractions=(0, 1))
    with pytest.raises(ValueError):
        replace(contract, heights_cm=(12.4, 12.7, np.nan, 1.4))
    with pytest.raises(TypeError):
        replace(contract, tank_cross_sections_cm2=(28, 32, True, 32))
    with pytest.raises(ValueError):
        replace(contract, sample_period_seconds=0)
    with pytest.raises(ValueError):
        replace(contract, pump_flow_coefficients_cm3_per_v_s=(0, 3.35))
    with pytest.raises(ValueError):
        replace(contract, outlet_cross_sections_cm2=(0.071, 0.057, -1, 0.057))
    with pytest.raises(ValueError):
        replace(contract, gravity_cm_per_s2=float("inf"))
    with pytest.raises(ValueError):
        replace(contract, heights_cm=(12.4, 12.7, 1.8))
    with pytest.raises(ValueError):
        replace(contract, state_coordinate="absolute_height_cm")
    bad = tmp_path / "bad.yaml"
    bad.write_text(CONFIG.read_text(encoding="utf-8") + "unknown: 1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_quadruple_tank_contract(bad)

    plant = QuadrupleTankPlant(contract)
    state = plant.state
    assert not state.flags.writeable
    output = plant.output()
    output[0] = 99
    np.testing.assert_array_equal(plant.output(), [5, 5])
    external = plant.state_space
    external.A_p.setflags(write=True)
    external.A_p[0, 0] = 99
    np.testing.assert_allclose(plant.state_space.A_p[0, 0], 0.992057657844057)
    other = QuadrupleTankPlant(contract)
    plant.step(np.array([1, 0]))
    np.testing.assert_array_equal(other.output(), [5, 5])


@pytest.mark.parametrize(
    ("original", "duplicate"),
    [
        ("initial_state_deviation_cm: [10, 10, 10, 10]",
         "initial_state_deviation_cm: [0, 0, 0, 0]"),
        ("  gravity_cm_per_s2: 981", "  gravity_cm_per_s2: 100"),
        ("  valve_fractions: [0.7, 0.6]", "  valve_fractions: [0.6, 0.7]"),
    ],
)
def test_config_rejects_duplicate_keys_at_each_mapping_level(
    tmp_path: Path, original: str, duplicate: str
) -> None:
    """同一层重复字段必须在参数快照形成前失败，不能静默覆盖基线。"""
    source = CONFIG.read_text(encoding="utf-8")
    assert source.count(original) == 1
    bad = tmp_path / "duplicate.yaml"
    bad.write_text(source.replace(original, original + "\n" + duplicate), encoding="utf-8")
    with pytest.raises(ValueError, match="重复"):
        load_quadruple_tank_contract(bad)


class _PulseRuntime:
    """只用于验证引擎对本场景的调用顺序，不代表论文 observer。"""

    def __init__(self) -> None:
        self.seen: list[np.ndarray] = []

    def step(self, measurement: np.ndarray) -> np.ndarray:
        """记录未经 reference 求差的测量，仅在首步输出泵 1 脉冲。"""
        self.seen.append(measurement.copy())
        return np.array([1.0, 0.0]) if len(self.seen) == 1 else np.zeros(2)


def test_adapter_and_generic_engine_pre_step_timing(contract) -> None:
    """通用引擎记录 k=0..2 更新前输出，末态不误标在最后一行。"""
    plant = QuadrupleTankPlant(contract)
    adapter = QuadrupleTankAdapter()
    assert isinstance(plant, Plant)
    assert isinstance(adapter, ScenarioAdapter)
    assert adapter.metadata.output.units == ("V_deviation", "V_deviation")
    assert adapter.metadata.control.units == ("V_deviation", "V_deviation")
    np.testing.assert_array_equal(adapter.reference_at(0.5), [0, 0])
    np.testing.assert_array_equal(adapter.controller_input(np.ones(2), np.array([5., 6.])), [5, 6])
    raw = np.array([7., -8.])
    applied = adapter.apply_control(raw)
    np.testing.assert_array_equal(applied, raw)
    applied[0] = 99
    assert raw[0] == 7
    for method, value in (
        (adapter.apply_control, [1]),
        (adapter.apply_control, [np.nan, 0]),
    ):
        with pytest.raises((ValueError, FloatingPointError)):
            method(value)
    with pytest.raises(ValueError):
        adapter.controller_input([0], [5, 5])
    runtime = _PulseRuntime()
    times = np.arange(3) * contract.sample_period_seconds
    trajectory = simulate_branch(SimulationBranch(plant, adapter, runtime), times)
    np.testing.assert_array_equal(times, [0, 0.5, 1.0])
    np.testing.assert_allclose(
        trajectory.output,
        [[5, 5], [5.084163543626281, 5.054899280823975],
         [5.144792567435094, 5.108195755479780]], atol=2e-13,
    )
    np.testing.assert_allclose(trajectory.output, runtime.seen, atol=0)
    np.testing.assert_array_equal(trajectory.reference, np.zeros((3, 2)))
    np.testing.assert_array_equal(trajectory.control, [[1, 0], [0, 0], [0, 0]])
    np.testing.assert_allclose(plant.output(), [5.202847977801150, 5.159855660656015], atol=2e-13)
