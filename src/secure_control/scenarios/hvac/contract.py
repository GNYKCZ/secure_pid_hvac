"""HVAC 场景配置的显式契约与 YAML 校验。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from numbers import Integral, Real
from pathlib import Path
from typing import Any

import yaml

from secure_control.simulation import ChannelMetadata, ScenarioMetadata

ConfigMapping = Mapping[str, Any]

_UPDATE_ORDER = "measure_adapt_control_plant_record"
_OUTPUT_LOG_TIME_INDEX = "pre_plant_step"


@dataclass(frozen=True, slots=True)
class HvacTimingContract:
    """冻结 HVAC 单步时序、记录网格和终点是否参与记录的约定。"""

    sampling_period_seconds: int
    horizon_seconds: int
    sample_count: int
    terminal_sample_included: bool
    update_order: str
    output_log_time_index: str

    def __post_init__(self) -> None:
        if self.sampling_period_seconds <= 0 or self.horizon_seconds <= 0:
            raise ValueError("采样周期和仿真时长必须为正整数秒")
        if self.horizon_seconds % self.sampling_period_seconds != 0:
            raise ValueError("仿真时长必须能被采样周期整除")
        expected_count = self.horizon_seconds // self.sampling_period_seconds
        if self.terminal_sample_included:
            expected_count += 1
        if self.sample_count != expected_count:
            raise ValueError("sample_count 与采样周期、时长和终点记录约定不一致")
        if self.update_order != _UPDATE_ORDER:
            raise ValueError(f"update_order 必须为 {_UPDATE_ORDER}")
        if self.output_log_time_index != _OUTPUT_LOG_TIME_INDEX:
            raise ValueError(f"output_log_time_index 必须为 {_OUTPUT_LOG_TIME_INDEX}")

    @property
    def sample_times_seconds(self) -> tuple[int, ...]:
        """返回结果记录的时刻；默认不记录 plant 更新后的终点状态。"""
        end = (
            self.horizon_seconds + int(self.terminal_sample_included) * self.sampling_period_seconds
        )
        return tuple(range(0, end, self.sampling_period_seconds))


@dataclass(frozen=True, slots=True)
class HvacModelContract:
    """冻结一阶 RC 冷却模型的参数、单位和执行器正负号。"""

    thermal_resistance_celsius_per_kw: float
    thermal_capacitance_kj_per_celsius: float
    cooling_coefficient: float
    ambient_temperature_celsius: float
    initial_temperature_celsius: float
    lower_control_bound_kw: float
    upper_control_bound_kw: float

    def __post_init__(self) -> None:
        for name in (
            "thermal_resistance_celsius_per_kw",
            "thermal_capacitance_kj_per_celsius",
            "cooling_coefficient",
            "ambient_temperature_celsius",
            "initial_temperature_celsius",
            "lower_control_bound_kw",
            "upper_control_bound_kw",
        ):
            if not isfinite(getattr(self, name)):
                raise ValueError(f"{name} 必须是有限实数")
        if self.thermal_resistance_celsius_per_kw <= 0:
            raise ValueError("thermal_resistance_celsius_per_kw 必须为正数")
        if self.thermal_capacitance_kj_per_celsius <= 0:
            raise ValueError("thermal_capacitance_kj_per_celsius 必须为正数")
        if self.cooling_coefficient <= 0:
            raise ValueError("cooling_coefficient 必须为正数")
        if self.lower_control_bound_kw < 0:
            raise ValueError("冷却功率下限不得为负数")
        if self.lower_control_bound_kw >= self.upper_control_bound_kw:
            raise ValueError("冷却功率上限必须大于下限")


_HVAC_PROVENANCE_SOURCE_KINDS = frozenset(
    {"literature", "project_assumption", "synthetic_benchmark"}
)
_HVAC_2R2C_PARAMETER_NAMES = (
    "air_wall_thermal_resistance_celsius_per_kw",
    "wall_outdoor_thermal_resistance_celsius_per_kw",
    "air_thermal_capacitance_kj_per_celsius",
    "wall_thermal_capacitance_kj_per_celsius",
    "cooling_coefficient",
    "ambient_temperature_celsius",
    "initial_air_temperature_celsius",
    "initial_wall_temperature_celsius",
    "lower_control_bound_kw",
    "upper_control_bound_kw",
)


@dataclass(frozen=True, slots=True)
class HvacParameterProvenance:
    """记录一个 HVAC 物理或场景参数从原始来源到配置单位的换算。"""

    parameter_name: str
    source_kind: str
    reference: str
    source_version: str
    original_value: float
    original_unit: str
    configured_value: float
    conversion_note: str

    def __post_init__(self) -> None:
        for name in (
            "parameter_name",
            "source_kind",
            "reference",
            "source_version",
            "original_unit",
            "conversion_note",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} 必须是非空字符串")
        if self.source_kind not in _HVAC_PROVENANCE_SOURCE_KINDS:
            raise ValueError(
                "source_kind 必须为 literature、project_assumption 或 synthetic_benchmark"
            )
        for name in ("original_value", "configured_value"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
                raise ValueError(f"{name} 必须是有限实数")


@dataclass(frozen=True, slots=True)
class Hvac2R2CModelContract:
    """冻结二阶 2R2C 冷却模型、二状态初值、执行器范围和参数来源。"""

    air_wall_thermal_resistance_celsius_per_kw: float
    wall_outdoor_thermal_resistance_celsius_per_kw: float
    air_thermal_capacitance_kj_per_celsius: float
    wall_thermal_capacitance_kj_per_celsius: float
    cooling_coefficient: float
    ambient_temperature_celsius: float
    initial_air_temperature_celsius: float
    initial_wall_temperature_celsius: float
    lower_control_bound_kw: float
    upper_control_bound_kw: float
    parameter_provenance: tuple[HvacParameterProvenance, ...]

    def __post_init__(self) -> None:
        for name in _HVAC_2R2C_PARAMETER_NAMES:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
                raise ValueError(f"{name} 必须是有限实数")
        for name in (
            "air_wall_thermal_resistance_celsius_per_kw",
            "wall_outdoor_thermal_resistance_celsius_per_kw",
            "air_thermal_capacitance_kj_per_celsius",
            "wall_thermal_capacitance_kj_per_celsius",
            "cooling_coefficient",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} 必须为正数")
        if self.lower_control_bound_kw < 0:
            raise ValueError("冷却功率下限不得为负数")
        if self.lower_control_bound_kw >= self.upper_control_bound_kw:
            raise ValueError("冷却功率上限必须大于下限")
        if not isinstance(self.parameter_provenance, tuple) or any(
            not isinstance(item, HvacParameterProvenance) for item in self.parameter_provenance
        ):
            raise TypeError("parameter_provenance 必须是 HvacParameterProvenance 元组")

        provenance_by_name = {item.parameter_name: item for item in self.parameter_provenance}
        if len(provenance_by_name) != len(self.parameter_provenance) or set(
            provenance_by_name
        ) != set(_HVAC_2R2C_PARAMETER_NAMES):
            raise ValueError("2R2C provenance 必须与全部配置参数一一对应且不得重复")
        for name in _HVAC_2R2C_PARAMETER_NAMES:
            if provenance_by_name[name].configured_value != getattr(self, name):
                raise ValueError(f"{name} 的 provenance configured_value 与配置值不一致")


HvacPlantModelContract = HvacModelContract | Hvac2R2CModelContract


@dataclass(frozen=True, slots=True)
class HvacReferenceSegment:
    """表示左闭右开的恒温参考区间 ``[start_seconds, end_seconds)``。"""

    start_seconds: int
    end_seconds: int
    target_temperature_celsius: float

    def __post_init__(self) -> None:
        if self.start_seconds < 0 or self.end_seconds <= self.start_seconds:
            raise ValueError("参考区间必须满足 0 <= start_seconds < end_seconds")
        if not isfinite(self.target_temperature_celsius):
            raise ValueError("target_temperature_celsius 必须是有限实数")


@dataclass(frozen=True, slots=True)
class HvacScenarioContract:
    """HVAC 配置、时序、模型、参考和通用结果通道之间的唯一契约。"""

    timing: HvacTimingContract
    model: HvacPlantModelContract
    reference_segments: tuple[HvacReferenceSegment, ...]
    endpoint_reference_celsius: float
    metadata: ScenarioMetadata

    def __post_init__(self) -> None:
        if not self.reference_segments:
            raise ValueError("HVAC reference 至少需要一个区间")
        if self.reference_segments[0].start_seconds != 0:
            raise ValueError("第一个 HVAC reference 区间必须从 0 s 开始")
        for previous, current in zip(self.reference_segments, self.reference_segments[1:]):
            if previous.end_seconds != current.start_seconds:
                raise ValueError("HVAC reference 区间必须连续且不能重叠")
        if self.reference_segments[-1].end_seconds != self.timing.horizon_seconds:
            raise ValueError("最后一个 HVAC reference 区间必须在 horizon_seconds 结束")
        if (
            self.endpoint_reference_celsius
            != self.reference_segments[-1].target_temperature_celsius
        ):
            raise ValueError("endpoint reference 必须等于最后一个区间目标")
        if not isfinite(self.endpoint_reference_celsius):
            raise ValueError("endpoint_reference_celsius 必须是有限实数")
        if self.metadata.name != "hvac":
            raise ValueError("HVAC 场景 metadata.name 必须为 hvac")


def load_hvac_scenario_contract(
    path: str | Path,
    *,
    config_source: bytes | None = None,
) -> HvacScenarioContract:
    """读取并严格校验 ``scenario.name: hvac`` 的 YAML 配置，不执行任何控制计算。"""
    config_path = Path(path)
    if config_source is not None and not isinstance(config_source, bytes):
        raise TypeError("config_source 必须是 bytes 或 None")
    try:
        source = config_path.read_bytes() if config_source is None else config_source
    except OSError as error:
        raise ValueError(f"无法读取 HVAC 配置文件：{config_path}") from error
    loaded = yaml.safe_load(source.decode("utf-8"))
    if not isinstance(loaded, Mapping):
        raise TypeError("HVAC 配置根节点必须是映射")

    scenario = _mapping(loaded, "scenario")
    if _string(scenario, "name") != "hvac":
        raise ValueError("scenario.name 必须为 hvac")
    hvac = _mapping(scenario, "hvac")

    timing_data = _mapping(hvac, "timing")
    timing = HvacTimingContract(
        sampling_period_seconds=_integer(timing_data, "sampling_period_seconds"),
        horizon_seconds=_integer(timing_data, "horizon_seconds"),
        sample_count=_integer(timing_data, "sample_count"),
        terminal_sample_included=_boolean(timing_data, "terminal_sample_included"),
        update_order=_string(timing_data, "update_order"),
        output_log_time_index=_string(timing_data, "output_log_time_index"),
    )
    model = _parse_model(_mapping(hvac, "model"))
    reference_segments, endpoint_reference = _parse_reference(_mapping(hvac, "reference"))
    metadata = _parse_metadata(_mapping(hvac, "channels"))
    _validate_signal_adapter(_mapping(hvac, "signal_adapter"))

    return HvacScenarioContract(
        timing=timing,
        model=model,
        reference_segments=reference_segments,
        endpoint_reference_celsius=endpoint_reference,
        metadata=metadata,
    )


def _parse_model(model: ConfigMapping) -> HvacPlantModelContract:
    """只在 HVAC 层按显式 kind 分派模型，未知类型不得猜测或降级。"""
    kind = _string(model, "kind")
    if kind == "first_order_rc_cooling":
        return _parse_first_order_model(model)
    if kind == "second_order_2r2c_cooling":
        return _parse_2r2c_model(model)
    raise ValueError("model.kind 必须为 first_order_rc_cooling 或 second_order_2r2c_cooling")


def _validate_control(model: ConfigMapping) -> ConfigMapping:
    """校验两种 HVAC plant 共用的热功率单位、正方向与 control 映射。"""
    control = _mapping(model, "control")
    if _string(control, "unit") != "kW_thermal_cooling":
        raise ValueError("HVAC control.unit 必须为 kW_thermal_cooling")
    if _string(control, "positive_direction") != "cooling":
        raise ValueError("HVAC 正控制量必须约定为 cooling")
    return control


def _parse_first_order_model(model: ConfigMapping) -> HvacModelContract:
    """保持既有一阶 RC 配置语义和离散化标识不变。"""
    if _string(model, "discretization") != "zero_order_hold":
        raise ValueError("model.discretization 必须为 zero_order_hold")
    control = _validate_control(model)

    return HvacModelContract(
        thermal_resistance_celsius_per_kw=_number(model, "thermal_resistance_celsius_per_kw"),
        thermal_capacitance_kj_per_celsius=_number(model, "thermal_capacitance_kj_per_celsius"),
        cooling_coefficient=_number(model, "cooling_coefficient"),
        ambient_temperature_celsius=_number(model, "ambient_temperature_celsius"),
        initial_temperature_celsius=_number(model, "initial_temperature_celsius"),
        lower_control_bound_kw=_number(control, "lower_bound_kw"),
        upper_control_bound_kw=_number(control, "upper_bound_kw"),
    )


def _parse_2r2c_model(model: ConfigMapping) -> Hvac2R2CModelContract:
    """解析无内部热源的 2R2C 连续模型及 exact-ZOH 配置。"""
    if _string(model, "continuous_model_version") != "hvac_2r2c_no_internal_gains_v1":
        raise ValueError("continuous_model_version 必须为 hvac_2r2c_no_internal_gains_v1")
    if _string(model, "discretization") != "exact_zero_order_hold":
        raise ValueError("2R2C model.discretization 必须为 exact_zero_order_hold")
    control = _validate_control(model)
    provenance = _parse_parameter_provenance(model)
    return Hvac2R2CModelContract(
        air_wall_thermal_resistance_celsius_per_kw=_number(
            model, "air_wall_thermal_resistance_celsius_per_kw"
        ),
        wall_outdoor_thermal_resistance_celsius_per_kw=_number(
            model, "wall_outdoor_thermal_resistance_celsius_per_kw"
        ),
        air_thermal_capacitance_kj_per_celsius=_number(
            model, "air_thermal_capacitance_kj_per_celsius"
        ),
        wall_thermal_capacitance_kj_per_celsius=_number(
            model, "wall_thermal_capacitance_kj_per_celsius"
        ),
        cooling_coefficient=_number(model, "cooling_coefficient"),
        ambient_temperature_celsius=_number(model, "ambient_temperature_celsius"),
        initial_air_temperature_celsius=_number(model, "initial_air_temperature_celsius"),
        initial_wall_temperature_celsius=_number(model, "initial_wall_temperature_celsius"),
        lower_control_bound_kw=_number(control, "lower_bound_kw"),
        upper_control_bound_kw=_number(control, "upper_bound_kw"),
        parameter_provenance=provenance,
    )


def _parse_parameter_provenance(
    model: ConfigMapping,
) -> tuple[HvacParameterProvenance, ...]:
    """把 YAML 来源列表提升为可审计契约，而不是把来源仅留在注释中。"""
    raw_provenance = model.get("parameter_provenance")
    if not isinstance(raw_provenance, list):
        raise TypeError("parameter_provenance 必须是列表")
    return tuple(
        HvacParameterProvenance(
            parameter_name=_string(item_mapping, "parameter_name"),
            source_kind=_string(item_mapping, "source_kind"),
            reference=_string(item_mapping, "reference"),
            source_version=_string(item_mapping, "source_version"),
            original_value=_number(item_mapping, "original_value"),
            original_unit=_string(item_mapping, "original_unit"),
            configured_value=_number(item_mapping, "configured_value"),
            conversion_note=_string(item_mapping, "conversion_note"),
        )
        for item_mapping in (_item_mapping(item, "parameter provenance") for item in raw_provenance)
    )


def _parse_reference(reference: ConfigMapping) -> tuple[tuple[HvacReferenceSegment, ...], float]:
    """校验 reference 的单位、分段边界和 10800 s 的明确端点值。"""
    if _string(reference, "unit") != "degC":
        raise ValueError("HVAC reference.unit 必须为 degC")
    raw_segments = reference.get("segments")
    if not isinstance(raw_segments, list):
        raise TypeError("reference.segments 必须为列表")
    segments = tuple(
        HvacReferenceSegment(
            start_seconds=_integer(_item_mapping(item, "reference segment"), "start_seconds"),
            end_seconds=_integer(_item_mapping(item, "reference segment"), "end_seconds"),
            target_temperature_celsius=_number(
                _item_mapping(item, "reference segment"), "target_temperature_celsius"
            ),
        )
        for item in raw_segments
    )
    return segments, _number(reference, "endpoint_value_celsius")


def _parse_metadata(channels: ConfigMapping) -> ScenarioMetadata:
    """将 HVAC 的标量温度/冷却功率通道映射到通用结果元数据。"""
    return ScenarioMetadata(
        name="hvac",
        reference=_channel_metadata(_mapping(channels, "reference"), "degC"),
        output=_channel_metadata(_mapping(channels, "output"), "degC"),
        control=_channel_metadata(_mapping(channels, "control"), "kW_thermal_cooling"),
    )


def _validate_signal_adapter(adapter: ConfigMapping) -> None:
    """冻结 HVAC 的 ``v = reference - temperature`` 语义，但不在此实现 adapter。"""
    if _string(adapter, "kind") != "reference_minus_temperature":
        raise ValueError("HVAC signal_adapter.kind 必须为 reference_minus_temperature")
    if _string(adapter, "output_unit") != "degC":
        raise ValueError("HVAC signal_adapter.output_unit 必须为 degC")
    if _string(adapter, "controller_input_unit") != "degC":
        raise ValueError("HVAC signal_adapter.controller_input_unit 必须为 degC")


def _channel_metadata(channel: ConfigMapping, expected_unit: str) -> ChannelMetadata:
    """确保当前 HVAC SISO 场景以一个有单位的通道接入通用结果模型。"""
    names = _string_tuple(channel, "names")
    units = _string_tuple(channel, "units")
    if len(names) != 1 or units != (expected_unit,):
        raise ValueError(f"HVAC channel 必须恰有一个单位为 {expected_unit} 的通道")
    return ChannelMetadata(names=names, units=units)


def _mapping(source: ConfigMapping, key: str) -> ConfigMapping:
    """取得必填映射节点，避免缺失或错误类型在后续计算中静默传播。"""
    return _item_mapping(source.get(key), key)


def _item_mapping(value: Any, name: str) -> ConfigMapping:
    """验证 YAML 节点是字符串键的映射。"""
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} 必须是映射")
    return value


def _string(source: ConfigMapping, key: str) -> str:
    """读取非空字符串配置项。"""
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} 必须是非空字符串")
    return value


def _string_tuple(source: ConfigMapping, key: str) -> tuple[str, ...]:
    """读取非空字符串列表，并转换为不可变元组供契约安全持有。"""
    value = source.get(key)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise ValueError(f"{key} 必须是非空字符串列表")
    return tuple(value)


def _integer(source: ConfigMapping, key: str) -> int:
    """读取不接受布尔值的整数秒数或样本数。"""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise TypeError(f"{key} 必须是整数")
    return int(value)


def _boolean(source: ConfigMapping, key: str) -> bool:
    """读取显式布尔配置，避免字符串形式的真假值造成歧义。"""
    value = source.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"{key} 必须是布尔值")
    return value


def _number(source: ConfigMapping, key: str) -> float:
    """读取有限实数，拒绝布尔值、字符串和 NaN/无穷大。"""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
        raise ValueError(f"{key} 必须是有限实数")
    return float(value)
