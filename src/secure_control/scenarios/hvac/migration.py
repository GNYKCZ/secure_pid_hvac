"""HVAC reference 迁移的明文 PID 门禁、可审计选择记录与基线身份。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from hashlib import sha256
from math import isfinite
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

import numpy as np
import yaml

from secure_control.core import ControllerSpec

from .baseline import (
    HvacControlQualityContract,
    HvacPidValidationResult,
    validate_hvac_pid_design,
)
from .contract import Hvac2R2CModelContract, HvacScenarioContract, load_hvac_scenario_contract
from .pid import HvacPidDesign
from .tuning import (
    HvacPidTuningContract,
    HvacPidTuningResult,
    _load_hvac_pid_config_inputs,
    _revalidate_pid_config_inputs,
    tune_hvac_pid,
)

_METHOD = "validate_current_then_conditionally_tune_v1"
_IDENTITY_SCHEME = "hvac_baseline_identity_v1"


@dataclass(frozen=True, slots=True)
class HvacPidSelectionRecord:
    """冻结 current-design 门禁与可选 exhaustive tuning 的实际决策。"""

    method: Literal["validate_current_then_conditionally_tune_v1"]
    source_pid_filename: str
    source_pid_sha256: str
    pid_reused: bool
    old_design: HvacPidDesign
    final_design: HvacPidDesign
    current_validation: HvacPidValidationResult
    tuning_executed: bool
    search_space_candidate_count: int
    evaluated_candidate_count: int
    feasible_candidate_count: int | None
    selected_objective: tuple[float, ...] | None
    rejection_counts: Mapping[str, int]
    quality_contract_sha256: str

    def __post_init__(self) -> None:
        """拒绝不自洽 reuse/tuning 组合并冻结拒绝计数。"""
        if self.method != _METHOD:
            raise ValueError(f"PID selection method 必须为 {_METHOD}")
        _safe_filename(self.source_pid_filename, "source_pid_filename")
        for name in ("source_pid_sha256", "quality_contract_sha256"):
            _require_hash(getattr(self, name), name, 64)
        if type(self.pid_reused) is not bool or type(self.tuning_executed) is not bool:
            raise TypeError("pid_reused/tuning_executed 必须是 bool")
        counts = (
            self.search_space_candidate_count,
            self.evaluated_candidate_count,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("PID selection candidate count 必须是非负整数")
        if self.search_space_candidate_count <= 0:
            raise ValueError("search_space_candidate_count 必须为正数")
        if self.feasible_candidate_count is not None and (
            type(self.feasible_candidate_count) is not int or self.feasible_candidate_count < 0
        ):
            raise ValueError("feasible_candidate_count 必须是非负整数或 null")
        copied = {str(key): int(value) for key, value in self.rejection_counts.items()}
        if any(value < 0 for value in copied.values()):
            raise ValueError("rejection_counts 不得为负数")
        object.__setattr__(self, "rejection_counts", MappingProxyType(copied))
        if self.pid_reused:
            if (
                not self.current_validation.passed
                or self.old_design != self.final_design
                or self.tuning_executed
                or self.evaluated_candidate_count != 0
                or self.feasible_candidate_count is not None
                or self.selected_objective is not None
                or copied
            ):
                raise ValueError("PID reuse selection record 不自洽")
        elif (
            self.current_validation.passed
            or not self.tuning_executed
            or self.evaluated_candidate_count != self.search_space_candidate_count
            or self.feasible_candidate_count is None
            or self.selected_objective is None
        ):
            raise ValueError("PID tuning selection record 不自洽")


@dataclass(frozen=True, slots=True)
class HvacPidBaselineResolution:
    """保存迁移后最终 PID、质量契约、选择记录与 lineage。"""

    design: HvacPidDesign
    tuning_contract: HvacPidTuningContract
    quality_contract: HvacControlQualityContract
    selection: HvacPidSelectionRecord
    tuning_result: HvacPidTuningResult | None
    start_commit: str
    supersedes_baseline: str

    def __post_init__(self) -> None:
        """确保 resolution 与 selection 的最终设计和 tuning 状态一致。"""
        _require_hash(self.start_commit, "start_commit", 40)
        _require_hash(self.supersedes_baseline, "supersedes_baseline", 64)
        if self.design != self.selection.final_design:
            raise ValueError("resolution design 与 selection final design 不一致")
        if (self.tuning_result is not None) != self.selection.tuning_executed:
            raise ValueError("resolution tuning result 与 selection 状态不一致")


@dataclass(frozen=True, slots=True)
class HvacBaselineIdentity:
    """保存跨运行稳定的新 HVAC baseline 内容身份与迁移 lineage。"""

    scheme: Literal["hvac_baseline_identity_v1"]
    baseline_id: str
    source_hashes: Mapping[str, str]
    quality_contract_sha256: str
    selection_record_sha256: str
    controller_spec_sha256: str
    finite_horizon_certificate_sha256: str
    supersedes_baseline: str
    start_commit: str

    def __post_init__(self) -> None:
        """复制并冻结来源 hash，拒绝格式不合法的身份记录。"""
        if self.scheme != _IDENTITY_SCHEME:
            raise ValueError(f"baseline identity scheme 必须为 {_IDENTITY_SCHEME}")
        copied = {str(key): str(value) for key, value in self.source_hashes.items()}
        if set(copied) != {"wrapper", "baseline", "scenario"}:
            raise ValueError("baseline identity 必须绑定 wrapper/baseline/scenario")
        for name, value in copied.items():
            _require_hash(value, f"source_hashes.{name}", 64)
        object.__setattr__(self, "source_hashes", MappingProxyType(copied))
        for name in (
            "baseline_id",
            "quality_contract_sha256",
            "selection_record_sha256",
            "controller_spec_sha256",
            "finite_horizon_certificate_sha256",
            "supersedes_baseline",
        ):
            _require_hash(getattr(self, name), name, 64)
        _require_hash(self.start_commit, "start_commit", 40)


def canonical_hvac_mapping_sha256(value: Mapping[str, object]) -> str:
    """以 UTF-8/sorted-key/compact JSON 计算 HVAC 派生结构的稳定摘要。"""
    if not isinstance(value, Mapping):
        raise TypeError("canonical HVAC hash 输入必须是 mapping")
    payload = _canonical_value(value, ())
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def canonical_hvac_source_sha256(source: bytes) -> str:
    """规范化 CRLF/CR 为 LF 后计算配置来源摘要，保证跨平台一致。"""
    if not isinstance(source, bytes):
        raise TypeError("source 必须是 bytes")
    return sha256(source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


def load_hvac_pid_baseline_resolution(
    path: str | Path,
    plant_contract: HvacScenarioContract,
) -> HvacPidBaselineResolution:
    """先验证旧 PID，再按声明仅在失败时调用原 deterministic tuner。"""
    if not isinstance(plant_contract, HvacScenarioContract) or not isinstance(
        plant_contract.model, Hvac2R2CModelContract
    ):
        raise TypeError("plant_contract 必须是 2R2C HvacScenarioContract")
    current = _load_hvac_pid_config_inputs(path, plant_contract)
    migration = _mapping(current.loaded, "migration")
    if set(migration) != {
        "schema_version",
        "method",
        "start_commit",
        "supersedes_baseline",
        "source_pid_config",
        "source_pid_sha256",
        "quality_contract_sha256",
        "selection",
    }:
        raise ValueError("PID migration schema 字段无效")
    if _integer(migration, "schema_version") != 1 or _string(migration, "method") != _METHOD:
        raise ValueError("PID migration schema/method 无效")
    start_commit = _string(migration, "start_commit")
    supersedes = _string(migration, "supersedes_baseline")
    _require_hash(start_commit, "start_commit", 40)
    _require_hash(supersedes, "supersedes_baseline", 64)

    source_name = _string(migration, "source_pid_config")
    _safe_filename(source_name, "source_pid_config")
    source_path = current.config_path.parent / source_name
    try:
        source_bytes = source_path.read_bytes()
        source_loaded = yaml.safe_load(source_bytes.decode("utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"无法读取 migration source PID：{source_path}") from error
    if canonical_hvac_source_sha256(source_bytes) != _string(migration, "source_pid_sha256"):
        raise ValueError("migration source PID SHA-256 不一致")
    if not isinstance(source_loaded, Mapping):
        raise TypeError("migration source PID 根节点必须是映射")
    source_plant_name = _string(source_loaded, "plant_config")
    _safe_filename(source_plant_name, "source plant_config")
    source_contract = load_hvac_scenario_contract(source_path.parent / source_plant_name)
    source_inputs = _load_hvac_pid_config_inputs(source_path, source_contract)
    if current.tuning != source_inputs.tuning:
        raise ValueError("migration fallback tuning 必须与旧 PID source 完全一致")

    quality_hash = canonical_hvac_mapping_sha256(asdict(current.quality))
    if quality_hash != _string(migration, "quality_contract_sha256"):
        raise ValueError("quality contract SHA-256 与重算结果不一致")
    validation = validate_hvac_pid_design(plant_contract, source_inputs.design, current.quality)
    tuning_result = None
    if validation.passed:
        final_design = source_inputs.design
    else:
        tuning_result = tune_hvac_pid(plant_contract, current.tuning, current.quality)
        final_design = tuning_result.selected_design
    if current.design != final_design:
        raise ValueError("配置 final gains 与条件式 PID 选择结果不一致")

    selection = _selection_record(
        _mapping(migration, "selection"),
        source_name=source_name,
        source_hash=_string(migration, "source_pid_sha256"),
        old_design=source_inputs.design,
        final_design=final_design,
        validation=validation,
        tuning=current.tuning,
        tuning_result=tuning_result,
        quality_hash=quality_hash,
    )
    _revalidate_pid_config_inputs(current)
    _revalidate_pid_config_inputs(source_inputs)
    if source_path.read_bytes() != source_bytes:
        raise ValueError("migration source PID 在解析期间发生变化")
    return HvacPidBaselineResolution(
        final_design,
        current.tuning,
        current.quality,
        selection,
        tuning_result,
        start_commit,
        supersedes,
    )


def build_hvac_baseline_identity(
    *,
    source_hashes: Mapping[str, str],
    quality_contract: HvacControlQualityContract,
    selection: HvacPidSelectionRecord,
    controller_spec: ControllerSpec,
    safety_certificate: object,
    supersedes_baseline: str,
    start_commit: str,
) -> HvacBaselineIdentity:
    """从配置、选择、控制器和证书内容构造与 seed/run 无关的 baseline ID。"""
    source_copy = {str(key): str(value) for key, value in source_hashes.items()}
    quality_hash = canonical_hvac_mapping_sha256(asdict(quality_contract))
    if quality_hash != selection.quality_contract_sha256:
        raise ValueError("baseline identity 的 quality contract 与 PID selection 不一致")
    selection_hash = canonical_hvac_mapping_sha256(_selection_payload(selection))
    controller_hash = canonical_hvac_mapping_sha256(_controller_payload(controller_spec))
    selected_controller_hash = canonical_hvac_mapping_sha256(
        _controller_payload(selection.final_design.to_controller_spec())
    )
    if controller_hash != selected_controller_hash:
        raise ValueError("baseline identity 的 ControllerSpec 与 PID selection 不一致")
    certificate_hash = canonical_hvac_mapping_sha256(_dataclass_mapping(safety_certificate))
    material = {
        "scheme": _IDENTITY_SCHEME,
        "source_hashes": source_copy,
        "quality_contract_sha256": quality_hash,
        "selection_record_sha256": selection_hash,
        "controller_spec_sha256": controller_hash,
        "finite_horizon_certificate_sha256": certificate_hash,
    }
    baseline_id = canonical_hvac_mapping_sha256(material)
    return HvacBaselineIdentity(
        _IDENTITY_SCHEME,
        baseline_id,
        source_copy,
        quality_hash,
        selection_hash,
        controller_hash,
        certificate_hash,
        supersedes_baseline,
        start_commit,
    )


def selection_record_payload(value: HvacPidSelectionRecord) -> dict[str, object]:
    """返回可写入 effective config 的 JSON-safe 选择记录副本。"""
    if not isinstance(value, HvacPidSelectionRecord):
        raise TypeError("value 必须是 HvacPidSelectionRecord")
    return _selection_payload(value)


def baseline_identity_payload(value: HvacBaselineIdentity) -> dict[str, object]:
    """返回可写入 artifact 的 JSON-safe baseline 身份与 lineage 副本。"""
    if not isinstance(value, HvacBaselineIdentity):
        raise TypeError("value 必须是 HvacBaselineIdentity")
    return {
        "scheme": value.scheme,
        "baseline_id": value.baseline_id,
        "source_hashes": dict(value.source_hashes),
        "quality_contract_sha256": value.quality_contract_sha256,
        "selection_record_sha256": value.selection_record_sha256,
        "controller_spec_sha256": value.controller_spec_sha256,
        "finite_horizon_certificate_sha256": value.finite_horizon_certificate_sha256,
        "supersedes_baseline": value.supersedes_baseline,
        "start_commit": value.start_commit,
    }


def _selection_record(
    declared: Mapping[str, Any],
    *,
    source_name: str,
    source_hash: str,
    old_design: HvacPidDesign,
    final_design: HvacPidDesign,
    validation: HvacPidValidationResult,
    tuning: HvacPidTuningContract,
    tuning_result: HvacPidTuningResult | None,
    quality_hash: str,
) -> HvacPidSelectionRecord:
    """构造实际 selection record，并与 YAML 声明逐字段严格核对。"""
    expected_keys = {
        "pid_reused",
        "old_gains",
        "final_gains",
        "current_gain_validation",
        "current_gain_rejection_reasons",
        "tuning_executed",
        "search_space_candidate_count",
        "evaluated_candidate_count",
        "feasible_candidate_count",
        "selected_objective",
        "rejection_counts",
    }
    if set(declared) != expected_keys:
        raise ValueError("PID selection 声明字段无效")
    pid_reused = tuning_result is None
    record = HvacPidSelectionRecord(
        _METHOD,
        source_name,
        source_hash,
        pid_reused,
        old_design,
        final_design,
        validation,
        not pid_reused,
        tuning.candidate_count,
        0 if pid_reused else tuning_result.evaluated_candidate_count,
        None if pid_reused else tuning_result.feasible_candidate_count,
        None if pid_reused else tuning_result.selected_objective,
        {} if pid_reused else tuning_result.rejection_counts,
        quality_hash,
    )
    expected = _selection_payload(record)
    declared_normalized = _canonical_value(declared, ())
    if not isinstance(declared_normalized, dict):
        raise TypeError("PID selection 声明必须可规范化为 mapping")
    expected_declared = _canonical_value({key: expected[key] for key in expected_keys}, ())
    for name in ("old_gains", "final_gains"):
        if declared_normalized[name] != expected[name]:
            raise ValueError(f"PID selection {name} 与重算结果不一致")
    if declared_normalized != expected_declared:
        raise ValueError("PID selection 声明与 plaintext gate/conditional tuning 重算结果不一致")
    return record


def _selection_payload(value: HvacPidSelectionRecord) -> dict[str, object]:
    """按冻结字段生成 selection 的 canonical/快照共同载荷。"""
    metrics = asdict(value.current_validation.metrics)
    return {
        "method": value.method,
        "source_pid_filename": value.source_pid_filename,
        "source_pid_sha256": value.source_pid_sha256,
        "pid_reused": value.pid_reused,
        "old_gains": _gains(value.old_design),
        "final_gains": _gains(value.final_design),
        "current_gain_validation": metrics,
        "current_gain_rejection_reasons": list(value.current_validation.rejection_reasons),
        "tuning_executed": value.tuning_executed,
        "search_space_candidate_count": value.search_space_candidate_count,
        "evaluated_candidate_count": value.evaluated_candidate_count,
        "feasible_candidate_count": value.feasible_candidate_count,
        "selected_objective": (
            None if value.selected_objective is None else list(value.selected_objective)
        ),
        "rejection_counts": dict(value.rejection_counts),
        "quality_contract_sha256": value.quality_contract_sha256,
    }


def _gains(value: HvacPidDesign) -> dict[str, float]:
    """只序列化 PID 选择所需的三个 gains，避免重复混入 tracking 字段。"""
    return {
        "proportional_gain_kw_per_celsius": value.proportional_gain_kw_per_celsius,
        "integral_gain_kw_per_celsius_second": value.integral_gain_kw_per_celsius_second,
        "derivative_gain_kw_second_per_celsius": value.derivative_gain_kw_second_per_celsius,
    }


def _controller_payload(value: ControllerSpec) -> dict[str, object]:
    """无损保存通用 ControllerSpec 的矩阵、初态和 scale metadata。"""
    if not isinstance(value, ControllerSpec):
        raise TypeError("controller_spec 必须是 ControllerSpec")
    return {
        "A": np.asarray(value.A).tolist(),
        "B": np.asarray(value.B).tolist(),
        "C": np.asarray(value.C).tolist(),
        "D": np.asarray(value.D).tolist(),
        "x0": np.asarray(value.x0).tolist(),
        "scale_metadata": (None if value.scale_metadata is None else asdict(value.scale_metadata)),
    }


def _dataclass_mapping(value: object) -> Mapping[str, object]:
    """只接受 dataclass 证书并转为独立 mapping。"""
    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError("safety_certificate 必须是 dataclass 实例")
    result = asdict(value)
    if not isinstance(result, dict):
        raise TypeError("safety_certificate 无法转换为 mapping")
    return result


def _canonical_value(value: object, path: tuple[str, ...]) -> object:
    """递归拒绝非 JSON-safe、非有限及运行特定 identity 字段。"""
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical HVAC mapping 的键必须是字符串")
            if key in {"test_seed", "secure_material_test_seed", "run_id", "baseline_id"}:
                raise ValueError(f"canonical HVAC identity 不得包含运行特定字段 {key}")
            result[key] = _canonical_value(item, (*path, key))
        return result
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item, path) for item in value]
    if value is None or type(value) in {bool, int, str}:
        if isinstance(value, str) and Path(value).is_absolute():
            raise ValueError("canonical HVAC identity 不得包含绝对路径")
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("canonical HVAC identity 不得包含 NaN/Inf")
        return value
    raise TypeError(f"canonical HVAC identity 含不支持的类型：{type(value).__name__}")


def _mapping(source: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """严格读取必填 mapping。"""
    value = source.get(key)
    if not isinstance(value, Mapping) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{key} 必须是字符串键 mapping")
    return value


def _string(source: Mapping[str, Any], key: str) -> str:
    """读取非空字符串。"""
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} 必须是非空字符串")
    return value


def _integer(source: Mapping[str, Any], key: str) -> int:
    """读取不接受 bool 的整数。"""
    value = source.get(key)
    if type(value) is not int:
        raise TypeError(f"{key} 必须是整数")
    return value


def _safe_filename(value: str, name: str) -> None:
    """拒绝绝对路径和目录逃逸，只允许同目录配置文件名。"""
    if not value or Path(value).name != value or value in {".", ".."}:
        raise ValueError(f"{name} 必须是安全的同目录文件名")


def _require_hash(value: object, name: str, length: int) -> None:
    """验证小写十六进制 SHA/commit 文本。"""
    if (
        not isinstance(value, str)
        or len(value) != length
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} 必须是 {length} 位小写十六进制字符串")
