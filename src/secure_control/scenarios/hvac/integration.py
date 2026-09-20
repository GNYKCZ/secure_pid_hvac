"""HVAC 双闭环装配、有限时域范围证书和场景指标。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from hashlib import sha256
from math import isfinite
from numbers import Integral
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import (
    FixedPointContext,
    PocklingtonCertificate,
    PocklingtonFactorEvidence,
    PrimeModulusEvidence,
    PrimeVerificationError,
    verify_prime_modulus,
)
from secure_control.execution import (
    PlaintextStateSpaceRuntime,
    SecureStateSpaceRuntime,
    SecureTraceCollector,
    SecureTracePolicy,
)
from secure_control.protocol import ControllerRangeContract
from secure_control.simulation import (
    ScenarioMetadata,
    SimulationBranch,
    SimulationPlan,
    SimulationResult,
    run,
)

from .adapter import HvacSignalAdapter
from .baseline import (
    HvacComparisonMetrics,
    HvacControlQualityContract,
    HvacSegmentMetric,
    _legacy_segment_metrics,
    evaluate_hvac_comparison_metrics,
)
from .contract import Hvac2R2CModelContract, HvacModelContract, load_hvac_scenario_contract
from .migration import (
    HvacBaselineIdentity,
    HvacPidBaselineResolution,
    HvacPidRedesignRecord,
    HvacVerifiedBaselinePredecessor,
    baseline_identity_payload,
    build_hvac_baseline_identity,
    canonical_hvac_source_sha256,
    load_hvac_pid_baseline_resolution,
    load_hvac_pid_redesign_resolution,
    selection_record_payload,
)
from .pid import load_hvac_pid_design
from .plant import build_hvac_2r2c_state_space, build_hvac_plant
from .tuning import (
    HvacPidTuningContract,
    HvacPidTuningResult,
    load_hvac_pid_tuning_contract,
    tune_hvac_pid,
)

_MAX_WRAPPER_YAML_BYTES = 1 << 20
_MAX_WRAPPER_YAML_DEPTH = 128
_MAX_WRAPPER_YAML_NODES = 4096
_MAX_POCKLINGTON_PARSE_DEPTH = 32
_MAX_POCKLINGTON_PARSE_NODES = 256
_MAX_POCKLINGTON_INTEGER_BITS = 4096
_MAX_BASELINE_LINEAGE_DEPTH = 8


class _BoundedSafeLoader(yaml.SafeLoader):
    """在构造 Python 对象前限制 YAML 大小、组合节点和语法嵌套深度。"""

    def __init__(self, stream: str) -> None:
        self._composition_depth = 0
        self._composition_nodes = 0
        super().__init__(stream)

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        """逐节点施加预算，alias 引用也计入总工作量。"""
        if self._composition_depth >= _MAX_WRAPPER_YAML_DEPTH:
            raise PrimeVerificationError(
                "resource_limit_exceeded", "HVAC YAML 嵌套深度超过资源限制。"
            )
        self._composition_nodes += 1
        if self._composition_nodes > _MAX_WRAPPER_YAML_NODES:
            raise PrimeVerificationError(
                "resource_limit_exceeded", "HVAC YAML 节点数超过资源限制。"
            )
        self._composition_depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self._composition_depth -= 1


@dataclass(slots=True)
class _EvidenceParseBudget:
    """在场景映射转换为 crypto 类型前限制证书树和 YAML alias 环。"""

    nodes: int = 0
    active_mapping_ids: set[int] | None = None

    def __post_init__(self) -> None:
        if self.active_mapping_ids is None:
            self.active_mapping_ids = set()


def _load_bounded_wrapper_yaml(source: bytes) -> Any:
    """以受限 SafeLoader 读取 wrapper，资源异常保留稳定 reason code。"""
    if len(source) > _MAX_WRAPPER_YAML_BYTES:
        raise PrimeVerificationError("resource_limit_exceeded", "HVAC wrapper YAML 超过资源限制。")
    try:
        return yaml.load(source.decode("utf-8"), Loader=_BoundedSafeLoader)
    except (MemoryError, OverflowError, RecursionError, ValueError) as error:
        raise PrimeVerificationError(
            "resource_limit_exceeded", "HVAC wrapper YAML 解析超过资源限制。"
        ) from error


@dataclass(frozen=True, slots=True)
class HvacSafetyCertificate:
    """记录 180 步物理、编码 payload 与 accumulator 的先验范围。"""

    horizon_steps: int
    plant_state_names: tuple[str, ...]
    plant_state_bounds_celsius: tuple[tuple[float, float], ...]
    controller_input_bounds_celsius: tuple[float, float]
    controller_state_names: tuple[str, ...]
    controller_state_bounds: tuple[tuple[float, float], ...]
    raw_control_bounds_kw: tuple[float, float]
    applied_control_bounds_kw: tuple[float, float]
    input_payload_bounds: tuple[int, ...]
    state_payload_bounds: tuple[int, ...]
    maximum_state_accumulator_bounds: tuple[int, ...]
    maximum_output_accumulator_bounds: tuple[int, ...]
    centered_modulus_limit: int
    state_truncation_bits: int

    @property
    def temperature_bounds_celsius(self) -> tuple[float, float]:
        """兼容一阶调用方，返回可观测空气温度范围。"""
        return self.plant_state_bounds_celsius[0]

    @property
    def input_abs_bound_celsius(self) -> float:
        """兼容旧接口，返回 controller input 的最大绝对界。"""
        return max(abs(value) for value in self.controller_input_bounds_celsius)

    @property
    def input_payload_bound(self) -> int:
        """兼容旧 SISO 接口，返回唯一 input payload 上界。"""
        return self.input_payload_bounds[0]


@dataclass(frozen=True, slots=True)
class HvacComparison:
    """通用八字段结果、完整 HVAC 指标与有限时域范围证书。"""

    result: SimulationResult
    comparison_metrics: HvacComparisonMetrics | None
    safety_certificate: HvacSafetyCertificate
    legacy_segment_metrics_ideal: tuple[HvacSegmentMetric, ...] = ()
    legacy_segment_metrics_secure: tuple[HvacSegmentMetric, ...] = ()

    @property
    def segment_metrics_ideal(self) -> tuple[HvacSegmentMetric, ...]:
        """兼容旧接口并优先返回完整 ideal 区段指标。"""
        if self.comparison_metrics is not None:
            return self.comparison_metrics.ideal.segments
        return self.legacy_segment_metrics_ideal

    @property
    def segment_metrics_secure(self) -> tuple[HvacSegmentMetric, ...]:
        """兼容旧接口并优先返回完整 secure 区段指标。"""
        if self.comparison_metrics is not None:
            return self.comparison_metrics.secure.segments
        return self.legacy_segment_metrics_secure


def _safe_lineage_member(parent: Path, value: object, name: str) -> Path:
    """只接受同目录普通非链接文件，避免 lineage 路径改变 source authority。"""
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise ValueError(f"{name} 必须是同目录安全文件名")
    candidate = parent / value
    if (
        not candidate.is_file()
        or candidate.is_symlink()
        or any(item.is_symlink() for item in candidate.parents)
    ):
        raise ValueError(f"{name} 必须是存在的普通非链接文件")
    return candidate.resolve()


def _snapshot_hvac_config_chain(wrapper_path: Path) -> tuple[tuple[str, Path, bytes], ...]:
    """读取 redesign 前驱的 wrapper/PID/scenario bytes，供构造后和调参后复验。"""
    try:
        wrapper_source = wrapper_path.read_bytes()
        wrapper = _load_bounded_wrapper_yaml(wrapper_source)
    except (OSError, yaml.YAMLError) as error:
        raise ValueError("无法读取 redesign predecessor wrapper") from error
    if not isinstance(wrapper, Mapping):
        raise TypeError("redesign predecessor wrapper 根节点必须是映射")
    baseline_path = _safe_lineage_member(
        wrapper_path.parent, wrapper.get("baseline_config"), "source baseline_config"
    )
    try:
        baseline_source = baseline_path.read_bytes()
        baseline = yaml.safe_load(baseline_source.decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("无法读取 redesign predecessor PID baseline") from error
    if not isinstance(baseline, Mapping):
        raise TypeError("redesign predecessor PID baseline 根节点必须是映射")
    scenario_path = _safe_lineage_member(
        baseline_path.parent, baseline.get("plant_config"), "source plant_config"
    )
    try:
        scenario_source = scenario_path.read_bytes()
    except OSError as error:
        raise ValueError("无法读取 redesign predecessor scenario") from error
    return (
        ("wrapper", wrapper_path, wrapper_source),
        ("baseline", baseline_path, baseline_source),
        ("scenario", scenario_path, scenario_source),
    )


class HvacScenario:
    """以冻结 HVAC/PID 配置装配两支独立闭环并交给通用 runner。"""

    scenario_version = "1"

    def __init__(
        self,
        config_path: str | Path,
        *,
        test_seed: int | None = None,
        trace_policy: SecureTracePolicy | None = None,
        trace_collector: SecureTraceCollector | None = None,
        _lineage_paths: frozenset[Path] | None = None,
        _lineage_depth: int = 0,
    ) -> None:
        """读取 wrapper/PID/plant 配置并在创建安全资源前完成全部校验。"""
        path = Path(config_path)
        canonical_path = path.resolve()
        visited = frozenset() if _lineage_paths is None else _lineage_paths
        if canonical_path in visited:
            raise ValueError("HVAC baseline lineage 存在 cycle")
        if _lineage_depth > _MAX_BASELINE_LINEAGE_DEPTH:
            raise ValueError("HVAC baseline lineage 超出最大深度")
        lineage_paths = visited | {canonical_path}
        try:
            wrapper_source = path.read_bytes()
            loaded = _load_bounded_wrapper_yaml(wrapper_source)
        except (OSError, yaml.YAMLError) as error:
            raise ValueError(f"无法读取 HVAC 双闭环配置：{path}") from error
        if not isinstance(loaded, Mapping):
            raise TypeError("HVAC 双闭环配置根节点必须是映射。")
        selector = loaded.get("scenario")
        if not isinstance(selector, Mapping) or selector.get("name") != "hvac":
            raise ValueError("HVAC 双闭环外壳 scenario.name 必须为 hvac。")
        baseline_name = loaded.get("baseline_config")
        if not isinstance(baseline_name, str) or not baseline_name.strip():
            raise TypeError("baseline_config 必须是非空路径字符串。")
        baseline_path = path.parent / baseline_name
        try:
            baseline_source = baseline_path.read_bytes()
        except OSError as error:
            raise ValueError(f"无法读取 HVAC PID 基线配置：{baseline_path}") from error
        baseline_hash_declared = "baseline_sha256" in loaded
        expected_baseline_hash = loaded.get("baseline_sha256")
        if baseline_hash_declared:
            if not isinstance(expected_baseline_hash, str) or not expected_baseline_hash.strip():
                raise TypeError("wrapper 的 baseline_sha256 必须是非空字符串。")
            # 信任锚来自已读取的 wrapper，不能由尚未验证的 baseline 内容决定是否启用。
            if canonical_hvac_source_sha256(baseline_source) != expected_baseline_hash:
                raise ValueError("wrapper 的 PID baseline SHA-256 不一致。")
        try:
            baseline_loaded = yaml.safe_load(baseline_source.decode("utf-8"))
        except yaml.YAMLError as error:
            raise ValueError(f"无法读取 HVAC PID 基线配置：{baseline_path}") from error
        if not isinstance(baseline_loaded, Mapping):
            raise TypeError("HVAC PID 基线配置根节点必须是映射。")
        has_migration = "migration" in baseline_loaded
        has_redesign = "baseline_creation" in baseline_loaded
        if has_migration and has_redesign:
            raise ValueError("PID baseline 不得同时声明 migration 与 baseline_creation。")
        if (has_migration or has_redesign) and not baseline_hash_declared:
            raise TypeError("正式 baseline wrapper 的 baseline_sha256 必须是非空字符串。")
        security = loaded.get("security")
        if not isinstance(security, Mapping):
            raise TypeError("security 必须是映射。")
        if test_seed is not None and (
            isinstance(test_seed, bool) or not isinstance(test_seed, int)
        ):
            raise TypeError("test_seed 必须是整数或 None。")
        if (trace_policy is None) != (trace_collector is None):
            raise ValueError("trace_policy 与 trace_collector 必须同时提供或同时省略。")

        self._plant_source: bytes | None = None
        self._plant_filename: str | None = None
        self._quality_contract: HvacControlQualityContract | None = None
        self._tuning_contract: HvacPidTuningContract | None = None
        self._tuning_result: HvacPidTuningResult | None = None
        self._baseline_resolution: HvacPidBaselineResolution | None = None
        self._baseline_identity: HvacBaselineIdentity | None = None
        plant_path: Path | None = None
        predecessor: HvacVerifiedBaselinePredecessor | None = None
        plant_name = baseline_loaded.get("plant_config")
        if plant_name is None:
            self._contract = load_hvac_scenario_contract(baseline_path)
            if isinstance(self._contract.model, Hvac2R2CModelContract):
                raise ValueError(
                    "2R2C 双闭环必须通过 Issue #42 PID baseline 的 plant_config 引用 plant-only 配置。"
                )
            self._design = load_hvac_pid_design(baseline_path, self._contract)
        else:
            if not isinstance(plant_name, str) or not plant_name.strip():
                raise TypeError("plant_config 必须是非空路径字符串。")
            plant_path = baseline_path.parent / plant_name
            try:
                self._plant_source = plant_path.read_bytes()
            except OSError as error:
                raise ValueError(f"无法读取 HVAC plant 配置：{plant_path}") from error
            self._plant_filename = plant_path.name
            self._contract = load_hvac_scenario_contract(plant_path)
            if has_migration:
                resolution = load_hvac_pid_baseline_resolution(baseline_path, self._contract)
                self._baseline_resolution = resolution
                self._design = resolution.design
                self._tuning_contract = resolution.tuning_contract
                self._quality_contract = resolution.quality_contract
                self._tuning_result = resolution.tuning_result
            elif has_redesign:
                creation = baseline_loaded.get("baseline_creation")
                if not isinstance(creation, Mapping):
                    raise TypeError("baseline_creation 必须是映射。")
                predecessor_path = _safe_lineage_member(
                    baseline_path.parent,
                    creation.get("source_wrapper_config"),
                    "source_wrapper_config",
                )
                predecessor_snapshots = _snapshot_hvac_config_chain(predecessor_path)
                predecessor_scenario = HvacScenario(
                    predecessor_path,
                    _lineage_paths=lineage_paths,
                    _lineage_depth=_lineage_depth + 1,
                )
                if predecessor_scenario.baseline_identity is None:
                    raise ValueError("主动 redesign predecessor 必须具有正式 baseline identity")
                predecessor = HvacVerifiedBaselinePredecessor(
                    predecessor_path,
                    predecessor_scenario.baseline_identity,
                    predecessor_scenario._design,
                    predecessor_snapshots,
                )
                predecessor.revalidate()
                resolution = load_hvac_pid_redesign_resolution(
                    baseline_path,
                    self._contract,
                    predecessor,
                    config_source=baseline_source,
                )
                self._baseline_resolution = resolution
                self._design = resolution.design
                self._tuning_contract = resolution.tuning_contract
                self._quality_contract = resolution.quality_contract
                self._tuning_result = resolution.tuning_result
            else:
                (
                    self._design,
                    self._tuning_contract,
                    self._quality_contract,
                ) = load_hvac_pid_tuning_contract(baseline_path, self._contract)
                self._tuning_result = tune_hvac_pid(
                    self._contract, self._tuning_contract, self._quality_contract
                )
            if plant_path.read_bytes() != self._plant_source:
                raise ValueError("HVAC plant 配置在解析期间发生变化。")
        if path.read_bytes() != wrapper_source or baseline_path.read_bytes() != baseline_source:
            raise ValueError("HVAC 配置在解析期间发生变化，拒绝生成不可信快照。")

        self._wrapper_source_hash = sha256(wrapper_source).hexdigest()
        self._baseline_source_hash = sha256(baseline_source).hexdigest()
        self._plant_source_hash = (
            None if self._plant_source is None else sha256(self._plant_source).hexdigest()
        )
        self._wrapper_filename = path.name
        self._baseline_filename = baseline_path.name
        self._fixed_point = FixedPointContext(
            _positive_integer(security, "modulus"),
            integer_bits=_positive_integer(security, "integer_bits"),
            fractional_bits=_positive_integer(security, "fractional_bits"),
        )
        self._modulus_evidence = _parse_modulus_evidence(security.get("modulus_evidence"))
        self._modulus_verification = verify_prime_modulus(
            self._fixed_point.modulus, self._modulus_evidence
        )
        self._security_parameter = _positive_integer(security, "security_parameter")
        self._horizon_steps = _positive_integer(security, "horizon_steps")
        self._test_seed = test_seed
        self._trace_policy = trace_policy
        self._trace_collector = trace_collector
        if self._contract.timing.terminal_sample_included:
            raise ValueError("当前双闭环仅支持 terminal_sample_included=false。")
        if self._horizon_steps != self._contract.timing.sample_count:
            raise ValueError("horizon_steps 必须等于 HVAC sample_count。")
        self._required_safety_certificate = self._derive_safety_certificate()
        self.safety_certificate = self._required_safety_certificate
        if self._baseline_resolution is not None:
            if self._plant_source is None or plant_path is None:
                raise RuntimeError("正式 baseline 缺少 scenario source")
            if (
                path.read_bytes() != wrapper_source
                or baseline_path.read_bytes() != baseline_source
                or plant_path.read_bytes() != self._plant_source
            ):
                raise ValueError("HVAC 配置在解析期间发生变化，拒绝生成不可信身份。")
            if predecessor is not None:
                predecessor.revalidate()
            self._baseline_identity = build_hvac_baseline_identity(
                source_hashes={
                    "wrapper": canonical_hvac_source_sha256(wrapper_source),
                    "baseline": canonical_hvac_source_sha256(baseline_source),
                    "scenario": canonical_hvac_source_sha256(self._plant_source),
                },
                quality_contract=self._baseline_resolution.quality_contract,
                selection=self._baseline_resolution.selection,
                controller_spec=self._design.to_controller_spec(),
                safety_certificate=self.safety_certificate,
                supersedes_baseline=self._baseline_resolution.supersedes_baseline,
                start_commit=self._baseline_resolution.start_commit,
            )

    @property
    def metadata(self) -> ScenarioMetadata:
        """返回已解析的通道元数据，不创建安全 session。"""
        return self._contract.metadata

    @property
    def baseline_identity(self) -> HvacBaselineIdentity | None:
        """返回正式 creation 基线身份；历史配置为兼容旧接口返回 ``None``。"""
        return self._baseline_identity

    @property
    def controller_dimensions(self) -> tuple[int, int, int]:
        """返回 ``(state, input, output)`` 维数，不创建安全 session。"""
        spec = self._design.to_controller_spec()
        return spec.state_dimension, spec.input_dimension, spec.output_dimension

    def effective_config_snapshot(self) -> dict[str, Any]:
        """快照实际参与装配的三源配置、调参、品质和范围证书。"""
        self._validate_safety_certificate()
        contract = self._contract
        sources: dict[str, Any] = {
            "wrapper": {"filename": self._wrapper_filename, "sha256": self._wrapper_source_hash},
            "baseline": {
                "filename": self._baseline_filename,
                "sha256": self._baseline_source_hash,
            },
        }
        if self._plant_filename is not None:
            sources["plant"] = {
                "filename": self._plant_filename,
                "sha256": self._plant_source_hash,
            }
        model_kind = (
            "second_order_2r2c_cooling"
            if isinstance(contract.model, Hvac2R2CModelContract)
            else "first_order_rc_cooling"
        )
        snapshot: dict[str, Any] = {
            "scenario": {"name": "hvac", "version": self.scenario_version},
            "sources": sources,
            "wrapper": {
                "baseline_config": self._baseline_filename,
                "security": {
                    "modulus": self._fixed_point.modulus,
                    "integer_bits": self._fixed_point.integer_bits,
                    "fractional_bits": self._fixed_point.fractional_bits,
                    "security_parameter": self._security_parameter,
                    "horizon_steps": self._horizon_steps,
                },
            },
            "hvac": {
                "timing": asdict(contract.timing),
                "model": asdict(contract.model),
                "model_semantics": {
                    "kind": model_kind,
                    "discretization": (
                        "exact_zero_order_hold"
                        if isinstance(contract.model, Hvac2R2CModelContract)
                        else "zero_order_hold"
                    ),
                    "positive_control": "cooling",
                    "control_unit": "kW_thermal_cooling",
                },
                "reference_segments": [asdict(item) for item in contract.reference_segments],
                "endpoint_reference_celsius": contract.endpoint_reference_celsius,
                "channels": {
                    "reference": asdict(contract.metadata.reference),
                    "output": asdict(contract.metadata.output),
                    "control": asdict(contract.metadata.control),
                },
                "signal_adapter": {
                    "kind": "reference_minus_temperature",
                    "output_unit": "degC",
                    "controller_input_unit": "degC",
                },
                "pid": asdict(self._design),
                "pid_strategies": {
                    "kind": "positional_pid_error_derivative",
                    "derivative_filter": "none",
                    "anti_windup": "disabled",
                    "output_saturation": "scenario_before_plant",
                },
            },
            "execution": {
                "secure_material_test_seed": self._test_seed,
                "secure_material_randomness": (
                    "deterministic_test" if self._test_seed is not None else "secure_random"
                ),
            },
            "modulus_verification": {
                "modulus": str(self._modulus_verification.modulus),
                "bit_length": self._modulus_verification.bit_length,
                "method": self._modulus_verification.method,
                "status": self._modulus_verification.status,
                "source": self._modulus_verification.source,
                "source_version": self._modulus_verification.source_version,
                "certificate_id": self._modulus_verification.certificate_id,
                "certificate_sha256": self._modulus_verification.certificate_sha256,
            },
            "finite_horizon_certificate": asdict(self.safety_certificate),
        }
        if self._tuning_result is not None and self._tuning_contract is not None:
            snapshot["hvac"]["tuning"] = {
                "algorithm": self._tuning_contract.algorithm,
                "proportional": asdict(self._tuning_contract.proportional),
                "integral": asdict(self._tuning_contract.integral),
                "derivative": asdict(self._tuning_contract.derivative),
                "objective_order": self._tuning_contract.objective_order,
                "tie_break_order": self._tuning_contract.tie_break_order,
                "evaluated_candidate_count": self._tuning_result.evaluated_candidate_count,
                "feasible_candidate_count": self._tuning_result.feasible_candidate_count,
                "rejection_counts": dict(self._tuning_result.rejection_counts),
                "selected_objective": self._tuning_result.selected_objective,
            }
            snapshot["hvac"]["quality"] = asdict(self._quality_contract)
        if self._baseline_resolution is not None:
            resolution = self._baseline_resolution
            selection = resolution.selection
            snapshot["hvac"]["tuning"] = {
                "algorithm": resolution.tuning_contract.algorithm,
                "proportional": asdict(resolution.tuning_contract.proportional),
                "integral": asdict(resolution.tuning_contract.integral),
                "derivative": asdict(resolution.tuning_contract.derivative),
                "objective_order": resolution.tuning_contract.objective_order,
                "tie_break_order": resolution.tuning_contract.tie_break_order,
                "search_space_candidate_count": selection.search_space_candidate_count,
                "executed": selection.tuning_executed,
                "evaluated_candidate_count": selection.evaluated_candidate_count,
                "feasible_candidate_count": selection.feasible_candidate_count,
                "rejection_counts": dict(selection.rejection_counts),
                "selected_objective": selection.selected_objective,
            }
            snapshot["hvac"]["quality"] = asdict(resolution.quality_contract)
            provenance_name = (
                "pid_redesign" if isinstance(selection, HvacPidRedesignRecord) else "pid_selection"
            )
            snapshot["hvac"][provenance_name] = selection_record_payload(selection)
            if self._baseline_identity is None:
                raise RuntimeError("正式 baseline identity 尚未构造")
            snapshot["baseline_identity"] = baseline_identity_payload(self._baseline_identity)
        return snapshot

    def build_plan(self) -> SimulationPlan:
        """以范围证书构造独立 plant/adapter/runtime 和安全会话。"""
        self._validate_safety_certificate()
        plain_spec, secure_spec = self._controller_specs()
        range_contract = ControllerRangeContract(
            state_payload_bounds=self.safety_certificate.state_payload_bounds,
            input_payload_bounds=self.safety_certificate.input_payload_bounds,
            horizon_steps=self._horizon_steps,
        )
        contract = self._contract
        ideal = SimulationBranch(
            build_hvac_plant(contract),
            HvacSignalAdapter(contract),
            PlaintextStateSpaceRuntime(plain_spec),
        )
        secure = SimulationBranch(
            build_hvac_plant(contract),
            HvacSignalAdapter(contract),
            SecureStateSpaceRuntime(
                secure_spec,
                self._fixed_point,
                range_contract,
                security_parameter=self._security_parameter,
                modulus_evidence=self._modulus_evidence,
                test_seed=self._test_seed,
                trace_policy=self._trace_policy,
                trace_collector=self._trace_collector,
            ),
        )
        return SimulationPlan(
            metadata=contract.metadata,
            sample_times=np.array(contract.timing.sample_times_seconds, dtype=float),
            ideal=ideal,
            secure=secure,
        )

    def metrics(self, result: SimulationResult) -> HvacComparison:
        """纯粹从正式八字段结果核对物理界并计算 HVAC 指标。"""
        self._validate_safety_certificate()
        air_low, air_high = self.safety_certificate.plant_state_bounds_celsius[0]
        for name in ("output_ideal", "output_secure"):
            output = getattr(result, name)
            if not np.all((air_low - 1e-10 <= output) & (output <= air_high + 1e-10)):
                raise ValueError(f"{name} 超出事前证明的 HVAC air temperature 范围。")
        low, high = self.safety_certificate.applied_control_bounds_kw
        for name in ("control_ideal", "control_secure"):
            applied = getattr(result, name)
            if not np.all((low <= applied) & (applied <= high)):
                raise ValueError(f"{name} 超出 HVAC actuator 范围。")
        if self._quality_contract is not None:
            metrics = evaluate_hvac_comparison_metrics(
                result, self._contract, self._quality_contract
            )
            return HvacComparison(result, metrics, self.safety_certificate)
        ideal = _legacy_segment_metrics(
            self._contract, self._design, result.output_ideal, result.control_ideal
        )
        secure = _legacy_segment_metrics(
            self._contract, self._design, result.output_secure, result.control_secure
        )
        return HvacComparison(result, None, self.safety_certificate, ideal, secure)

    def metrics_snapshot(self, result: SimulationResult) -> dict[str, Any]:
        """返回可写入扫描工件的 HVAC 指标快照，不暴露内部 plant 状态。"""
        comparison = self.metrics(result)
        if comparison.comparison_metrics is not None:
            return asdict(comparison.comparison_metrics)
        return {
            "legacy_segment_metrics_ideal": [
                asdict(item) for item in comparison.legacy_segment_metrics_ideal
            ],
            "legacy_segment_metrics_secure": [
                asdict(item) for item in comparison.legacy_segment_metrics_secure
            ],
        }

    def _controller_specs(self) -> tuple[ControllerSpec, ControllerSpec]:
        """返回语义相同的明文 spec 与带冻结 scale ledger 的安全 spec。"""
        plain = self._design.to_controller_spec()
        ell = self._fixed_point.fractional_bits
        secure = ControllerSpec(
            A=plain.A,
            B=plain.B,
            C=plain.C,
            D=plain.D,
            x0=plain.x0,
            scale_metadata=ControllerScaleMetadata(
                state=ell, input=ell, output=2 * ell, A=0, B=0, C=ell, D=ell
            ),
        )
        return plain, secure

    def _derive_safety_certificate(self) -> HvacSafetyCertificate:
        """按 exact plant 和 PID 仿射区间传播建立 180 步先验证书。"""
        plant_names, plant_bounds_by_step = self._plant_interval_bounds()
        references = tuple(
            next(
                segment.target_temperature_celsius
                for segment in self._contract.reference_segments
                if segment.start_seconds <= time < segment.end_seconds
            )
            for time in self._contract.timing.sample_times_seconds
        )
        input_bounds_by_step = tuple(
            (reference - bounds[0][1], reference - bounds[0][0])
            for reference, bounds in zip(references, plant_bounds_by_step[:-1])
        )
        input_low = min(item[0] for item in input_bounds_by_step)
        input_high = max(item[1] for item in input_bounds_by_step)
        plain_spec, secure_spec = self._controller_specs()
        state_intervals = [(float(value), float(value)) for value in plain_spec.x0]
        state_global = list(state_intervals)
        raw_low = float("inf")
        raw_high = float("-inf")
        for input_interval in input_bounds_by_step:
            output_interval = _affine_interval(
                plain_spec.C, state_intervals, plain_spec.D, (input_interval,)
            )[0]
            raw_low = min(raw_low, output_interval[0])
            raw_high = max(raw_high, output_interval[1])
            state_intervals = _affine_interval(
                plain_spec.A, state_intervals, plain_spec.B, (input_interval,)
            )
            state_global = [
                (min(old[0], new[0]), max(old[1], new[1]))
                for old, new in zip(state_global, state_intervals)
            ]
        plant_global = tuple(
            (
                min(step[index][0] for step in plant_bounds_by_step),
                max(step[index][1] for step in plant_bounds_by_step),
            )
            for index in range(len(plant_names))
        )
        if not all(
            isfinite(value) for bounds in (*plant_global, *state_global) for value in bounds
        ) or not all(isfinite(value) for value in (input_low, input_high, raw_low, raw_high)):
            raise FloatingPointError("HVAC finite-horizon 区间传播产生非有限值")

        input_payload_bound = _exact_scaled_upper_bound(
            max(abs(input_low), abs(input_high)), self._fixed_point.scale
        )
        if input_payload_bound > self._fixed_point.maximum_payload:
            raise ValueError("HVAC input payload bound 超出 fixed-point 可表示范围")
        zero_scale = FixedPointContext(
            self._fixed_point.modulus,
            integer_bits=self._fixed_point.integer_bits,
            fractional_bits=0,
        )
        encoded = {
            "A": np.asarray(zero_scale.encode(secure_spec.A), dtype=object),
            "B": np.asarray(zero_scale.encode(secure_spec.B), dtype=object),
            "C": np.asarray(self._fixed_point.encode(secure_spec.C), dtype=object),
            "D": np.asarray(self._fixed_point.encode(secure_spec.D), dtype=object),
            "x0": np.asarray(self._fixed_point.encode(secure_spec.x0), dtype=object),
        }
        current = [abs(int(value)) for value in encoded["x0"]]
        maximum_state = current.copy()
        maximum_state_accumulator = [0] * len(current)
        maximum_output_accumulator = [0] * secure_spec.output_dimension
        for _ in range(self._horizon_steps):
            output_raw = _integer_row_bounds(
                encoded["C"], current, encoded["D"], [input_payload_bound]
            )
            state_raw = _integer_row_bounds(
                encoded["A"], current, encoded["B"], [input_payload_bound]
            )
            maximum_output_accumulator = [
                max(old, new) for old, new in zip(maximum_output_accumulator, output_raw)
            ]
            maximum_state_accumulator = [
                max(old, new) for old, new in zip(maximum_state_accumulator, state_raw)
            ]
            current = state_raw
            maximum_state = [max(old, new) for old, new in zip(maximum_state, current)]
        centered_limit = (self._fixed_point.modulus - 1) // 2
        if any(value > self._fixed_point.maximum_payload for value in maximum_state):
            raise ValueError("controller state payload bound 超出 fixed-point 可表示范围")
        if any(
            value > centered_limit
            for value in (*maximum_state_accumulator, *maximum_output_accumulator)
        ):
            raise ValueError("controller accumulator 超出 centered Z_q 范围")
        return HvacSafetyCertificate(
            self._horizon_steps,
            plant_names,
            plant_global,
            (input_low, input_high),
            ("integral_error", "previous_error"),
            tuple(state_global),
            (raw_low, raw_high),
            (
                self._contract.model.lower_control_bound_kw,
                self._contract.model.upper_control_bound_kw,
            ),
            (input_payload_bound,),
            tuple(maximum_state),
            tuple(maximum_state_accumulator),
            tuple(maximum_output_accumulator),
            centered_limit,
            0,
        )

    def _validate_safety_certificate(self) -> None:
        """拒绝任何小于先验传播结果的物理或编码范围声明。"""
        certificate = self.safety_certificate
        required = self._required_safety_certificate
        if not isinstance(certificate, HvacSafetyCertificate):
            raise TypeError("safety_certificate 必须是 HvacSafetyCertificate")
        if (
            certificate.horizon_steps != required.horizon_steps
            or certificate.plant_state_names != required.plant_state_names
            or certificate.controller_state_names != required.controller_state_names
            or certificate.state_truncation_bits != required.state_truncation_bits
        ):
            raise ValueError("HVAC certificate 的 horizon、state 名称或 Trunc 语义不一致")
        _require_enclosing_bounds(
            "plant_state_bounds_celsius",
            certificate.plant_state_bounds_celsius,
            required.plant_state_bounds_celsius,
        )
        _require_enclosing_bounds(
            "controller_input_bounds_celsius",
            (certificate.controller_input_bounds_celsius,),
            (required.controller_input_bounds_celsius,),
        )
        _require_enclosing_bounds(
            "controller_state_bounds",
            certificate.controller_state_bounds,
            required.controller_state_bounds,
        )
        _require_enclosing_bounds(
            "raw_control_bounds_kw",
            (certificate.raw_control_bounds_kw,),
            (required.raw_control_bounds_kw,),
        )
        _require_enclosing_bounds(
            "applied_control_bounds_kw",
            (certificate.applied_control_bounds_kw,),
            (required.applied_control_bounds_kw,),
        )
        for name in (
            "input_payload_bounds",
            "state_payload_bounds",
            "maximum_state_accumulator_bounds",
            "maximum_output_accumulator_bounds",
        ):
            claimed = getattr(certificate, name)
            minimum = getattr(required, name)
            if len(claimed) != len(minimum) or any(
                value < required_value for value, required_value in zip(claimed, minimum)
            ):
                raise ValueError(f"HVAC certificate 的 {name} 小于先验所需范围")
        expected_centered_limit = (self._fixed_point.modulus - 1) // 2
        if certificate.centered_modulus_limit != expected_centered_limit:
            raise ValueError("HVAC certificate 的 centered modulus limit 与 fixed-point 配置不一致")
        if any(
            value > certificate.centered_modulus_limit
            for value in (
                *certificate.maximum_state_accumulator_bounds,
                *certificate.maximum_output_accumulator_bounds,
            )
        ):
            raise ValueError("HVAC certificate 的 accumulator 超出 centered modulus limit")

    def _plant_interval_bounds(
        self,
    ) -> tuple[tuple[str, ...], tuple[tuple[tuple[float, float], ...], ...]]:
        """返回 k=0..horizon 的 plant state 区间，不读取任何闭环轨迹。"""
        model = self._contract.model
        if isinstance(model, HvacModelContract):
            equilibrium = lambda control: (
                model.ambient_temperature_celsius
                - model.cooling_coefficient * model.thermal_resistance_celsius_per_kw * control
            )
            bounds = (
                min(model.initial_temperature_celsius, equilibrium(model.upper_control_bound_kw)),
                max(model.initial_temperature_celsius, equilibrium(model.lower_control_bound_kw)),
            )
            return ("air_temperature",), tuple((bounds,) for _ in range(self._horizon_steps + 1))
        if not isinstance(model, Hvac2R2CModelContract):
            raise TypeError("未知 HVAC model contract")
        matrices = build_hvac_2r2c_state_space(model, self._contract.timing.sampling_period_seconds)
        current = (
            (model.initial_air_temperature_celsius, model.initial_air_temperature_celsius),
            (model.initial_wall_temperature_celsius, model.initial_wall_temperature_celsius),
        )
        steps = [current]
        control = ((model.lower_control_bound_kw, model.upper_control_bound_kw),)
        ambient = ((model.ambient_temperature_celsius, model.ambient_temperature_celsius),)
        for _ in range(self._horizon_steps):
            current = tuple(
                _affine_interval(
                    matrices.A_p, current, matrices.B_p, control, matrices.E_p, ambient
                )
            )
            steps.append(current)
        return ("air_temperature", "wall_temperature"), tuple(steps)


def _affine_interval(
    first: np.ndarray,
    first_intervals: list[tuple[float, float]] | tuple[tuple[float, float], ...],
    second: np.ndarray,
    second_intervals: tuple[tuple[float, float], ...],
    third: np.ndarray | None = None,
    third_intervals: tuple[tuple[float, float], ...] = (),
) -> list[tuple[float, float]]:
    """以系数符号精确传播矩阵仿射表达式的盒区间。"""
    matrices = ((first, first_intervals), (second, second_intervals))
    if third is not None:
        matrices += ((third, third_intervals),)
    result: list[tuple[float, float]] = []
    for row in range(first.shape[0]):
        lower = 0.0
        upper = 0.0
        for matrix, intervals in matrices:
            for column, interval in enumerate(intervals):
                coefficient = float(matrix[row, column])
                products = (coefficient * interval[0], coefficient * interval[1])
                lower += min(products)
                upper += max(products)
        result.append((lower, upper))
    return result


def _require_enclosing_bounds(
    name: str,
    claimed: tuple[tuple[float, float], ...],
    required: tuple[tuple[float, float], ...],
) -> None:
    """验证公开盒区间逐维包含先验传播结果，不接受反转或非有限边界。"""
    if len(claimed) != len(required):
        raise ValueError(f"HVAC certificate 的 {name} 维数不一致")
    for interval, minimum in zip(claimed, required):
        if (
            len(interval) != 2
            or not all(isfinite(value) for value in interval)
            or interval[0] > minimum[0]
            or interval[1] < minimum[1]
        ):
            raise ValueError(f"HVAC certificate 的 {name} 小于先验所需范围")


def _integer_row_bounds(
    first: np.ndarray,
    first_bounds: list[int],
    second: np.ndarray,
    second_bounds: list[int],
) -> list[int]:
    """用 Python int 计算编码矩阵每行的三角不等式 accumulator 界。"""
    return [
        sum(abs(int(first[row, column])) * first_bounds[column] for column in range(first.shape[1]))
        + sum(
            abs(int(second[row, column])) * second_bounds[column]
            for column in range(second.shape[1])
        )
        for row in range(first.shape[0])
    ]


def _positive_integer(source: Mapping[str, Any], name: str) -> int:
    """读取安全配置正整数并拒绝 bool。"""
    value = source.get(name)
    if isinstance(value, bool) or not isinstance(value, Integral) or value <= 0:
        raise ValueError(f"security.{name} 必须是正整数。")
    return int(value)


def _parse_modulus_evidence(value: Any) -> PrimeModulusEvidence | None:
    """把 HVAC YAML 的可选公开证据映射为领域无关、深度冻结的 crypto 类型。"""
    if value is None:
        return None
    evidence = _exact_mapping(
        value,
        "security.modulus_evidence",
        {
            "method",
            "source",
            "source_version",
            "certificate_id",
            "certificate_sha256",
            "certificate",
        },
    )
    return PrimeModulusEvidence(
        method=evidence["method"],
        source=evidence["source"],
        source_version=evidence["source_version"],
        certificate_id=evidence["certificate_id"],
        certificate_sha256=evidence["certificate_sha256"],
        certificate=_parse_pocklington_certificate(
            evidence["certificate"],
            "security.modulus_evidence.certificate",
            depth=0,
            budget=_EvidenceParseBudget(),
        ),
    )


def _parse_pocklington_certificate(
    value: Any,
    path: str,
    *,
    depth: int,
    budget: _EvidenceParseBudget,
) -> PocklingtonCertificate:
    """在共享资源预算内解析证书；数论条件仍只由 crypto verifier 判断。"""
    if depth > _MAX_POCKLINGTON_PARSE_DEPTH:
        raise PrimeVerificationError(
            "resource_limit_exceeded", "Pocklington YAML 证书深度超过资源限制。"
        )
    certificate = _exact_mapping(value, path, {"candidate", "factors"})
    factors = certificate["factors"]
    if not isinstance(factors, list) or not factors:
        raise TypeError(f"{path}.factors 必须是非空列表。")
    candidate = certificate["candidate"]
    if (
        isinstance(candidate, Integral)
        and not isinstance(candidate, bool)
        and int(candidate).bit_length() > _MAX_POCKLINGTON_INTEGER_BITS
    ):
        raise PrimeVerificationError(
            "resource_limit_exceeded", "Pocklington YAML candidate 超过资源限制。"
        )
    budget.nodes += 1 + len(factors)
    if budget.nodes > _MAX_POCKLINGTON_PARSE_NODES:
        raise PrimeVerificationError("resource_limit_exceeded", "Pocklington YAML 证书节点过多。")
    assert budget.active_mapping_ids is not None
    mapping_id = id(certificate)
    if mapping_id in budget.active_mapping_ids:
        raise PrimeVerificationError(
            "resource_limit_exceeded", "Pocklington YAML 证书存在 alias 循环。"
        )
    budget.active_mapping_ids.add(mapping_id)
    try:
        parsed: list[PocklingtonFactorEvidence] = []
        for index, item in enumerate(factors):
            factor_path = f"{path}.factors[{index}]"
            factor = _exact_mapping(
                item,
                factor_path,
                {"prime", "exponent", "witness", "certificate"},
                optional={"certificate"},
            )
            nested = factor.get("certificate")
            parsed.append(
                PocklingtonFactorEvidence(
                    prime=factor["prime"],
                    exponent=factor["exponent"],
                    witness=factor["witness"],
                    certificate=(
                        None
                        if nested is None
                        else _parse_pocklington_certificate(
                            nested,
                            f"{factor_path}.certificate",
                            depth=depth + 1,
                            budget=budget,
                        )
                    ),
                )
            )
        return PocklingtonCertificate(candidate=candidate, factors=tuple(parsed))
    finally:
        budget.active_mapping_ids.remove(mapping_id)


def _exact_mapping(
    value: Any,
    path: str,
    required: set[str],
    *,
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    """拒绝证据 schema 的缺失和未知字段，避免拼写错误被静默忽略。"""
    if not isinstance(value, Mapping):
        raise TypeError(f"{path} 必须是映射。")
    optional = set() if optional is None else optional
    missing = required - optional - set(value)
    unknown = set(value) - required
    if missing or unknown:
        raise ValueError(f"{path} 字段不匹配：missing={sorted(missing)}, unknown={sorted(unknown)}")
    return value


def _exact_scaled_upper_bound(value: float, scale: int) -> int:
    """以 binary64 的精确有理数计算 ``ceil(value * scale) + 1``。"""
    if not isfinite(value) or value < 0.0 or scale <= 0:
        raise ValueError("范围值必须有限非负，scale 必须为正整数")
    numerator, denominator = value.as_integer_ratio()
    scaled_ceiling = -(-(numerator * scale) // denominator)
    return scaled_ceiling + 1


def run_hvac_dual_loop(config_path: str | Path, *, test_seed: int | None = None) -> HvacComparison:
    """装配并运行 180 步 HVAC 双闭环，返回结果、指标和证书。"""
    scenario = HvacScenario(config_path, test_seed=test_seed)
    return scenario.metrics(run(scenario))
