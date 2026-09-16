"""HVAC plant、reference 与 SignalAdapter 的数值和边界测试。"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest
import yaml

from secure_control.scenarios.hvac import (
    Hvac2R2CPlant,
    Hvac2R2CStateSpace,
    HvacPlant,
    HvacSignalAdapter,
    HvacStepReference,
    build_hvac_2r2c_state_space,
    load_hvac_scenario_contract,
)
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation import Plant, ScenarioAdapter

BASELINE_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_baseline.yaml"
TWO_R_TWO_C_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_plant.yaml"


def _contract():
    """加载受版本管理的 HVAC 基线契约，避免测试各自复制模型参数。"""
    return load_hvac_scenario_contract(BASELINE_CONFIG_PATH)


def _two_r_two_c_contract():
    """加载受版本管理的 2R2C plant-only 契约。"""
    return load_hvac_scenario_contract(TWO_R_TWO_C_CONFIG_PATH)


def _write_2r2c_initial_state(tmp_path: Path, *, air: float, wall: float, ambient: float):
    """同步修改配置值与 provenance，用于验证热交换方向而不绕过 loader。"""
    loaded = yaml.safe_load(TWO_R_TWO_C_CONFIG_PATH.read_text(encoding="utf-8"))
    mapping = deepcopy(loaded)
    model = mapping["scenario"]["hvac"]["model"]
    changes = {
        "initial_air_temperature_celsius": air,
        "initial_wall_temperature_celsius": wall,
        "ambient_temperature_celsius": ambient,
    }
    for name, value in changes.items():
        model[name] = value
        provenance = next(
            item for item in model["parameter_provenance"] if item["parameter_name"] == name
        )
        provenance["original_value"] = value
        provenance["configured_value"] = value
    path = tmp_path / "hvac_2r2c_direction.yaml"
    path.write_text(yaml.safe_dump(mapping, sort_keys=False), encoding="utf-8")
    return load_hvac_scenario_contract(path)


def test_plant_matches_independent_hand_calculation_for_two_steps() -> None:
    """RC plant 的已知值不得通过调用生产递推公式来计算 expected。"""
    plant = HvacPlant(_contract())

    # 对 R=2、C=1200、Ts=60、eta=1 手算得 a≈0.9753099120、b≈0.0493801759。
    assert np.array_equal(plant.output(), np.array([30.0]))
    assert np.allclose(plant.step(np.array([10.0])), np.array([29.506198240566654]))
    assert np.allclose(plant.step(np.array([10.0])), np.array([29.02458849001428]))


def test_plant_is_deterministic_resets_and_keeps_instances_independent() -> None:
    """相同输入序列必须确定一致，且两个闭环未来可持有独立 plant state。"""
    first = HvacPlant(_contract())
    second = HvacPlant(_contract())
    controls = (0.0, 5.0, 12.0)

    first_outputs = [first.step(control) for control in controls]
    second_outputs = [second.step(control) for control in controls]

    assert all(np.array_equal(left, right) for left, right in zip(first_outputs, second_outputs))
    first.reset()
    assert np.array_equal(first.output(), np.array([30.0]))
    assert not np.array_equal(first.output(), second.output())
    assert isinstance(first, Plant)


def test_2r2c_continuous_and_exact_zoh_matrices_match_independent_golden_values() -> None:
    """矩阵 oracle 固定为独立复核值，避免用被测离散化函数生成 expected。"""
    contract = _two_r_two_c_contract()
    state_space = build_hvac_2r2c_state_space(
        contract.model, contract.timing.sampling_period_seconds
    )

    np.testing.assert_allclose(
        state_space.F,
        [
            [-8.992805755395684e-04, 8.992805755395684e-04],
            [7.371152258521052e-06, -1.027779102145560e-05],
        ],
        rtol=1e-13,
        atol=1e-15,
    )
    np.testing.assert_allclose(state_space.G, [[-2.5e-03], [0.0]], rtol=0.0, atol=1e-15)
    np.testing.assert_allclose(
        state_space.H, [[0.0], [2.906638762934543e-06]], rtol=1e-13, atol=1e-15
    )
    np.testing.assert_allclose(
        state_space.A_p,
        [
            [9.474845124536359e-01, 5.251086699334964e-02],
            [4.304169425684396e-04, 9.993952378093333e-01],
        ],
        rtol=1e-13,
        atol=1e-15,
    )
    np.testing.assert_allclose(
        state_space.B_p,
        [[-1.460256302776450e-01], [-3.257489875250655e-05]],
        rtol=1e-13,
        atol=1e-15,
    )
    np.testing.assert_allclose(
        state_space.E_p,
        [[4.620553014539936e-06], [1.743452480982650e-04]],
        rtol=1e-13,
        atol=1e-15,
    )
    np.testing.assert_array_equal(state_space.C_p, [[1.0, 0.0]])
    assert all(
        not getattr(state_space, name).flags.writeable
        for name in ("F", "G", "H", "A_p", "B_p", "E_p", "C_p")
    )
    with pytest.raises(ValueError):
        state_space.A_p[0, 0] = 0.0


def test_2r2c_equilibrium_and_positive_cooling_direction() -> None:
    """均温零输入保持平衡，正制冷相对零输入降低下一步空气温度。"""
    zero = Hvac2R2CPlant(_two_r_two_c_contract())
    cooling = Hvac2R2CPlant(_two_r_two_c_contract())

    assert zero.output().shape == (1,)
    assert zero.state_celsius.shape == (2,)
    np.testing.assert_allclose(zero.step(0.0), [30.0], rtol=0.0, atol=1e-13)
    cooled_output = cooling.step(10.0)
    assert cooled_output[0] < zero.output()[0]
    np.testing.assert_allclose(
        cooling.state_celsius,
        [28.539743697223553, 29.999674251012475],
        rtol=1e-13,
        atol=1e-13,
    )


def test_2r2c_heat_exchange_moves_air_and_wall_toward_each_other(tmp_path: Path) -> None:
    """无控制时，air-wall 温差必须按方程符号驱动热量由热端流向冷端。"""
    plant = Hvac2R2CPlant(_write_2r2c_initial_state(tmp_path, air=30.0, wall=20.0, ambient=20.0))

    plant.step(0.0)

    assert plant.air_temperature_celsius < 30.0
    assert plant.wall_temperature_celsius > 20.0


def test_2r2c_multiple_steps_reset_snapshots_and_instances_are_isolated() -> None:
    """二状态递推可复现，reset 与复制式快照不能让两个 plant 共享可变状态。"""
    first = Hvac2R2CPlant(_two_r_two_c_contract())
    second = Hvac2R2CPlant(_two_r_two_c_contract())

    for control, expected in zip(
        (10.0, 0.0, 12.0),
        (
            [28.539743697223553, 29.999674251012475],
            [28.616412663544754, 29.999045928959937],
            [26.93671476465245, 29.998060087729865],
        ),
    ):
        first.step(control)
        np.testing.assert_allclose(first.state_celsius, expected, rtol=1e-13, atol=1e-13)

    np.testing.assert_array_equal(second.state_celsius, [30.0, 30.0])
    snapshot = first.state_celsius
    assert not snapshot.flags.writeable
    with pytest.raises(ValueError):
        snapshot[0] = 100.0
    output = first.output()
    output[0] = 100.0
    assert first.air_temperature_celsius != 100.0
    first.reset()
    np.testing.assert_array_equal(first.state_celsius, [30.0, 30.0])
    assert isinstance(first, Plant)


@pytest.mark.parametrize(
    ("control", "exception", "message"),
    [
        (np.array([[1.0]]), ValueError, "shape"),
        (np.array([12.1]), ValueError, "超出"),
        (np.array([np.nan]), FloatingPointError, "NaN"),
        ("cooling", TypeError, "实数"),
    ],
)
def test_invalid_2r2c_control_fails_without_changing_state(
    control: object, exception: type[Exception], message: str
) -> None:
    """2R2C plant 延续一阶输入边界，并以事务式更新保护完整二维状态。"""
    plant = Hvac2R2CPlant(_two_r_two_c_contract())
    before = plant.state_celsius

    with pytest.raises(exception, match=message):
        plant.step(control)  # type: ignore[arg-type]

    np.testing.assert_array_equal(plant.state_celsius, before)


def test_2r2c_state_space_rejects_invalid_shape_and_non_finite_values() -> None:
    """公开矩阵记录不能持有错误 shape 或非有限系数。"""
    valid = {
        "F": np.eye(2),
        "G": np.ones((2, 1)),
        "H": np.ones((2, 1)),
        "A_p": np.eye(2),
        "B_p": np.ones((2, 1)),
        "E_p": np.ones((2, 1)),
        "C_p": np.ones((1, 2)),
    }
    with pytest.raises(ValueError, match="F"):
        Hvac2R2CStateSpace(**{**valid, "F": np.eye(3)})
    with pytest.raises(FloatingPointError, match="G"):
        Hvac2R2CStateSpace(**{**valid, "G": np.array([[np.inf], [0.0]])})


def test_2r2c_state_space_snapshot_cannot_mutate_plant_dynamics() -> None:
    """即使恢复快照写权限并改写矩阵，plant 后续动力学也必须保持冻结。"""
    plant = Hvac2R2CPlant(_two_r_two_c_contract())
    exposed = plant.state_space
    exposed.A_p.setflags(write=True)
    exposed.A_p.fill(0.0)

    assert np.all(exposed.A_p == 0.0)
    assert not np.all(plant.state_space.A_p == 0.0)
    np.testing.assert_allclose(plant.step(0.0), [30.0], rtol=0.0, atol=1e-13)


@pytest.mark.parametrize(
    ("sample_period", "exception"),
    [(True, TypeError), (60.0, TypeError), (0, ValueError)],
)
def test_2r2c_builder_rejects_invalid_sample_period(
    sample_period: object, exception: type[Exception]
) -> None:
    """ZOH 采样周期只接受正整数秒，避免 bool 或浮点配置被静默解释。"""
    with pytest.raises(exception, match="sample_period_seconds"):
        build_hvac_2r2c_state_space(_two_r_two_c_contract().model, sample_period)  # type: ignore[arg-type]


def test_first_order_plant_and_dual_loop_reject_2r2c_contract_explicitly(tmp_path: Path) -> None:
    """#41 不把旧一阶证书误用于 2R2C，后续接入必须留给 #42。"""
    contract = _two_r_two_c_contract()
    with pytest.raises(TypeError, match="一阶"):
        HvacPlant(contract)
    with pytest.raises(TypeError, match="Hvac2R2C"):
        Hvac2R2CPlant(_contract())
    with pytest.raises(TypeError, match="Hvac2R2CModelContract"):
        build_hvac_2r2c_state_space(_contract().model, 60)  # type: ignore[arg-type]

    wrapper = tmp_path / "hvac_dual_loop.yaml"
    wrapper.write_text(
        yaml.safe_dump(
            {
                "scenario": {"name": "hvac"},
                "baseline_config": str(TWO_R_TWO_C_CONFIG_PATH.resolve()),
                "security": {
                    "modulus": 2305843009213693951,
                    "integer_bits": 48,
                    "fractional_bits": 20,
                    "security_parameter": 8,
                    "horizon_steps": 180,
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="#42"):
        HvacScenario(wrapper)


@pytest.mark.parametrize(
    ("control", "exception", "message"),
    [
        (np.array([[1.0]]), ValueError, "shape"),
        (np.array([12.1]), ValueError, "超出"),
        (np.array([np.nan]), FloatingPointError, "NaN"),
        ("cooling", TypeError, "实数"),
    ],
)
def test_invalid_plant_control_fails_without_changing_temperature(
    control: object, exception: type[Exception], message: str
) -> None:
    """非法 shape、范围或数值不能静默裁剪，也不能造成半步状态更新。"""
    plant = HvacPlant(_contract())

    with pytest.raises(exception, match=message):
        plant.step(control)  # type: ignore[arg-type]
    assert plant.temperature_celsius == 30.0


@pytest.mark.parametrize(
    ("time_seconds", "expected_temperature"),
    [
        (0.0, 15.0),
        (3599.999, 15.0),
        (3600.0, 20.0),
        (7199.999, 20.0),
        (7200.0, 25.0),
        (10799.999, 25.0),
        (10800.0, 25.0),
    ],
)
def test_reference_obeys_left_closed_right_open_segments_and_terminal_value(
    time_seconds: float, expected_temperature: float
) -> None:
    """reference 切换点必须严格遵循 #2 规定，避免三小时仿真的 off-by-one。"""
    reference = HvacStepReference(_contract())

    assert np.array_equal(reference.reference_at(time_seconds), np.array([expected_temperature]))


@pytest.mark.parametrize(
    ("time_seconds", "exception", "message"),
    [
        (-0.001, ValueError, "位于"),
        (10800.001, ValueError, "位于"),
        (float("nan"), ValueError, "有限"),
        (True, TypeError, "实数"),
    ],
)
def test_reference_rejects_invalid_times(
    time_seconds: float, exception: type[Exception], message: str
) -> None:
    """reference API 不得为越界、NaN 或布尔时间猜测默认温度。"""
    with pytest.raises(exception, match=message):
        HvacStepReference(_contract()).reference_at(time_seconds)


def test_adapter_keeps_hvac_error_formula_outside_generic_simulation() -> None:
    """仅 HVAC adapter 计算 v=r-T，并提供通用 ScenarioAdapter 所需成员。"""
    adapter = HvacSignalAdapter(_contract())

    assert isinstance(adapter, ScenarioAdapter)
    assert np.array_equal(adapter.reference_at(3600.0), np.array([20.0]))
    assert np.array_equal(
        adapter.controller_input(np.array([20.0]), np.array([20.0])), np.array([0.0])
    )
    assert np.array_equal(
        adapter.controller_input(np.array([15.0]), np.array([20.0])), np.array([-5.0])
    )
    assert np.array_equal(
        adapter.controller_input(np.array([25.0]), np.array([20.0])), np.array([5.0])
    )
    assert adapter.metadata.output.units == ("degC",)
    assert adapter.metadata.control.units == ("kW_thermal_cooling",)


@pytest.mark.parametrize(
    ("reference", "output", "exception", "message"),
    [
        (np.array([[20.0]]), np.array([20.0]), ValueError, "reference"),
        (np.array([20.0]), np.array([np.inf]), FloatingPointError, "output"),
        (np.array([20.0]), np.array(["20"], dtype=str), TypeError, "output"),
    ],
)
def test_adapter_rejects_ambiguous_or_non_finite_temperature_signals(
    reference: np.ndarray, output: np.ndarray, exception: type[Exception], message: str
) -> None:
    """adapter 只接受通用边界传来的有限单通道温度数组。"""
    with pytest.raises(exception, match=message):
        HvacSignalAdapter(_contract()).controller_input(reference, output)
