"""HVAC 场景配置契约的边界与错误处理测试。"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from secure_control.scenarios.hvac import load_hvac_scenario_contract

BASELINE_CONFIG_PATH = Path(__file__).parents[1] / "configs" / "hvac_baseline.yaml"


def _baseline_mapping() -> dict[str, Any]:
    """读取受版本管理的基线 YAML；测试修改其副本而不污染正式配置。"""
    loaded = yaml.safe_load(BASELINE_CONFIG_PATH.read_text(encoding="utf-8"))
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
