"""HVAC 场景配置契约的边界与错误处理测试。"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from secure_control.scenarios.hvac import (
    Hvac2R2CModelContract,
    load_hvac_scenario_contract,
)

BASELINE_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_baseline.yaml"
TWO_R_TWO_C_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_2r2c_plant.yaml"


def _baseline_mapping() -> dict[str, Any]:
    """读取受版本管理的基线 YAML；测试修改其副本而不污染正式配置。"""
    loaded = yaml.safe_load(BASELINE_CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _two_r_two_c_mapping() -> dict[str, Any]:
    """读取 2R2C 正式配置的副本，供 fail-closed 参数化测试修改。"""
    loaded = yaml.safe_load(TWO_R_TWO_C_CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_mapping(tmp_path: Path, mapping: dict[str, Any]) -> Path:
    """将单个测试的无效配置写入临时目录，验证 loader 的显式失败行为。"""
    path = tmp_path / "hvac.yaml"
    path.write_text(yaml.safe_dump(mapping, sort_keys=False), encoding="utf-8")
    return path


def test_baseline_contract_freezes_model_timing_channels_and_reference_boundaries() -> None:
    """基线必须完整表达 HVAC 专有语义，且不需要 plant/PID 实现即可验证。"""
    contract = load_hvac_scenario_contract(BASELINE_CONFIG_PATH)

    assert contract.timing.sampling_period_seconds == 60
    assert contract.timing.horizon_seconds == 10800
    assert contract.timing.sample_count == 180
    assert contract.timing.sample_times_seconds[:2] == (0, 60)
    assert contract.timing.sample_times_seconds[-1] == 10740
    assert 10800 not in contract.timing.sample_times_seconds
    assert contract.timing.update_order == "measure_adapt_control_plant_record"
    assert contract.timing.output_log_time_index == "pre_plant_step"

    assert contract.model.lower_control_bound_kw == 0.0
    assert contract.model.upper_control_bound_kw == 12.0
    assert [
        (item.start_seconds, item.end_seconds, item.target_temperature_celsius)
        for item in contract.reference_segments
    ] == [
        (0, 3600, 15.0),
        (3600, 7200, 20.0),
        (7200, 10800, 25.0),
    ]
    # 端点值供后续 reference API 在 t=10800 s 使用，即使记录网格默认不含该时刻。
    assert contract.endpoint_reference_celsius == 25.0
    assert contract.metadata.reference.names == ("target_temperature",)
    assert contract.metadata.output.names == ("temperature",)
    assert contract.metadata.control.names == ("cooling_power",)


def test_2r2c_contract_parses_all_parameters_and_auditable_provenance() -> None:
    """2R2C 配置必须保留归一化参数及逐项来源，不能只依赖 YAML 注释。"""
    contract = load_hvac_scenario_contract(TWO_R_TWO_C_CONFIG_PATH)

    assert isinstance(contract.model, Hvac2R2CModelContract)
    assert contract.model.air_wall_thermal_resistance_celsius_per_kw == 2.78
    assert contract.model.wall_outdoor_thermal_resistance_celsius_per_kw == 7.05
    assert contract.model.air_thermal_capacitance_kj_per_celsius == 400.0
    assert contract.model.wall_thermal_capacitance_kj_per_celsius == 48800.0
    assert contract.model.cooling_coefficient == 1.0
    assert contract.model.initial_air_temperature_celsius == 30.0
    assert contract.model.initial_wall_temperature_celsius == 30.0
    assert contract.metadata.output.names == ("air_temperature",)
    assert len(contract.model.parameter_provenance) == 10
    assert {item.source_kind for item in contract.model.parameter_provenance} == {
        "literature",
        "project_assumption",
    }


@pytest.mark.parametrize(
    ("mutate", "exception", "message"),
    [
        (
            lambda model: model.__setitem__("air_wall_thermal_resistance_celsius_per_kw", 0.0),
            ValueError,
            "air_wall_thermal_resistance",
        ),
        (
            lambda model: model.__setitem__(
                "wall_thermal_capacitance_kj_per_celsius", float("inf")
            ),
            ValueError,
            "wall_thermal_capacitance",
        ),
        (
            lambda model: model.pop("wall_outdoor_thermal_resistance_celsius_per_kw"),
            ValueError,
            "wall_outdoor_thermal_resistance",
        ),
        (
            lambda model: model.__setitem__("cooling_coefficient", 0.0),
            ValueError,
            "cooling_coefficient",
        ),
        (
            lambda model: model.__setitem__("continuous_model_version", ""),
            ValueError,
            "continuous_model_version",
        ),
        (
            lambda model: model.__setitem__("discretization", "explicit_euler"),
            ValueError,
            "exact_zero_order_hold",
        ),
        (
            lambda model: model["control"].__setitem__("unit", "kW"),
            ValueError,
            "kW_thermal_cooling",
        ),
        (
            lambda model: model["control"].__setitem__("lower_bound_kw", -0.1),
            ValueError,
            "下限",
        ),
        (
            lambda model: model["control"].__setitem__("upper_bound_kw", 0.0),
            ValueError,
            "上限",
        ),
        (
            lambda model: model["parameter_provenance"].pop(),
            ValueError,
            "provenance",
        ),
        (
            lambda model: model["parameter_provenance"].append(
                deepcopy(model["parameter_provenance"][0])
            ),
            ValueError,
            "provenance",
        ),
        (
            lambda model: model["parameter_provenance"][0].__setitem__(
                "parameter_name", "unknown_parameter"
            ),
            ValueError,
            "provenance",
        ),
        (
            lambda model: model["parameter_provenance"][0].__setitem__("reference", ""),
            ValueError,
            "reference",
        ),
        (
            lambda model: model["parameter_provenance"][0].__setitem__("source_kind", "unverified"),
            ValueError,
            "source_kind",
        ),
        (
            lambda model: model["parameter_provenance"][0].__setitem__("configured_value", 999.0),
            ValueError,
            "configured_value",
        ),
    ],
)
def test_invalid_2r2c_model_or_provenance_fails_closed(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    exception: type[Exception],
    message: str,
) -> None:
    """2R2C 数值、单位、离散化与来源不完整时必须在配置边界拒绝。"""
    invalid_config = _two_r_two_c_mapping()
    model = invalid_config["scenario"]["hvac"]["model"]
    mutate(model)

    with pytest.raises(exception, match=message):
        load_hvac_scenario_contract(_write_mapping(tmp_path, invalid_config))


def test_unknown_hvac_model_kind_is_not_guessed(tmp_path: Path) -> None:
    """loader 只接受已实现的两种显式 kind，不把未知类型回退为一阶模型。"""
    invalid_config = _two_r_two_c_mapping()
    invalid_config["scenario"]["hvac"]["model"]["kind"] = "other_thermal_model"

    with pytest.raises(ValueError, match="model.kind"):
        load_hvac_scenario_contract(_write_mapping(tmp_path, invalid_config))


ConfigMutation = Callable[[dict[str, Any]], None]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["scenario"].__setitem__("name", "other"),
            "scenario.name",
        ),
        (
            lambda value: value["scenario"]["hvac"]["timing"].__setitem__("sample_count", 181),
            "sample_count",
        ),
        (
            lambda value: value["scenario"]["hvac"]["reference"]["segments"][1].__setitem__(
                "start_seconds", 3599
            ),
            "连续",
        ),
        (
            lambda value: value["scenario"]["hvac"]["model"]["control"].__setitem__(
                "positive_direction", "heating"
            ),
            "cooling",
        ),
        (
            lambda value: value["scenario"]["hvac"]["model"]["control"].__setitem__(
                "lower_bound_kw", -0.1
            ),
            "下限",
        ),
        (
            lambda value: value["scenario"]["hvac"]["channels"]["control"].__setitem__(
                "units", ["kW"]
            ),
            "kW_thermal_cooling",
        ),
    ],
)
def test_invalid_hvac_config_fails_without_silent_unit_or_timing_correction(
    tmp_path: Path, mutate: ConfigMutation, message: str
) -> None:
    """关键 selector、时序、reference、符号和单位错误必须明确失败。"""
    invalid_config = deepcopy(_baseline_mapping())
    mutate(invalid_config)

    with pytest.raises(ValueError, match=message):
        load_hvac_scenario_contract(_write_mapping(tmp_path, invalid_config))


def test_terminal_sample_contract_includes_horizon_only_when_explicitly_enabled(
    tmp_path: Path,
) -> None:
    """终点记录是配置契约的一部分，不能由 runner 隐式决定。"""
    terminal_config = _baseline_mapping()
    timing = terminal_config["scenario"]["hvac"]["timing"]
    timing["terminal_sample_included"] = True
    timing["sample_count"] = 181

    contract = load_hvac_scenario_contract(_write_mapping(tmp_path, terminal_config))

    assert contract.timing.sample_times_seconds[-1] == 10800
    assert len(contract.timing.sample_times_seconds) == 181


def test_invalid_yaml_node_types_raise_type_error(tmp_path: Path) -> None:
    """结构类型错误与数值范围错误必须区分，避免调用方误判配置问题。"""
    non_mapping_path = tmp_path / "not-a-mapping.yaml"
    non_mapping_path.write_text("- hvac\n", encoding="utf-8")
    with pytest.raises(TypeError, match="根节点"):
        load_hvac_scenario_contract(non_mapping_path)

    wrong_type_config = _baseline_mapping()
    wrong_type_config["scenario"]["hvac"]["timing"]["sampling_period_seconds"] = True
    with pytest.raises(TypeError, match="sampling_period_seconds"):
        load_hvac_scenario_contract(_write_mapping(tmp_path, wrong_type_config))
