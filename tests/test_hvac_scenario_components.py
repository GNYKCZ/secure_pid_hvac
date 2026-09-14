"""HVAC plant、reference 与 SignalAdapter 的数值和边界测试。"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from secure_control.scenarios.hvac import (
    HvacPlant,
    HvacSignalAdapter,
    HvacStepReference,
    load_hvac_scenario_contract,
)
from secure_control.simulation import Plant, ScenarioAdapter

BASELINE_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_baseline.yaml"


def _contract():
    """加载受版本管理的 HVAC 基线契约，避免测试各自复制模型参数。"""
    return load_hvac_scenario_contract(BASELINE_CONFIG_PATH)


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
