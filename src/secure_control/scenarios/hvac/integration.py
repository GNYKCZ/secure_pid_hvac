"""HVAC 双闭环装配、有限时间物理输入证书和场景指标。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from hashlib import sha256
from math import ceil, isfinite
from numbers import Integral
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import PlaintextStateSpaceRuntime, SecureStateSpaceRuntime
from secure_control.protocol import ControllerRangeContract
from secure_control.simulation import (
    ScenarioMetadata,
    SimulationBranch,
    SimulationPlan,
    SimulationResult,
    run,
)

from .adapter import HvacSignalAdapter
from .baseline import HvacSegmentMetric, _segment_metrics
from .contract import Hvac2R2CModelContract, load_hvac_scenario_contract
from .pid import load_hvac_pid_design
from .plant import HvacPlant


@dataclass(frozen=True, slots=True)
class HvacSafetyCertificate:
    """记录本配置/时域下事前推出的 plant、input 与编码 state 公开范围。"""

    temperature_bounds_celsius: tuple[float, float]
    input_abs_bound_celsius: float
    input_payload_bound: int
    state_payload_bounds: tuple[int, int]
    horizon_steps: int


@dataclass(frozen=True, slots=True)
class HvacComparison:
    """通用八字段结果及仅属于 HVAC 场景的两支区段指标和范围证书。"""

    result: SimulationResult
    segment_metrics_ideal: tuple[HvacSegmentMetric, ...]
    segment_metrics_secure: tuple[HvacSegmentMetric, ...]
    safety_certificate: HvacSafetyCertificate


class HvacScenario:
    """以现有 HVAC/PID 配置装配两支独立闭环，交给通用 runner 执行。"""

    scenario_version = "1"

    def __init__(self, config_path: str | Path, *, test_seed: int | None = None) -> None:
        """只读取双闭环配置及其引用的基线；build_plan 才创建运行时。"""
        path = Path(config_path)
        try:
            wrapper_source = path.read_bytes()
            loaded = yaml.safe_load(wrapper_source.decode("utf-8"))
        except OSError as error:
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
        security = loaded.get("security")
        if not isinstance(security, Mapping):
            raise TypeError("security 必须是映射。")
        if test_seed is not None and (
            isinstance(test_seed, bool) or not isinstance(test_seed, int)
        ):
            raise TypeError("test_seed 必须是整数或 None。")

        self._contract = load_hvac_scenario_contract(baseline_path)
        if isinstance(self._contract.model, Hvac2R2CModelContract):
            # 该模型类型本身合法，但不属于当前一阶双闭环入口允许的配置值。
            raise ValueError(  # noqa: TRY004
                "当前 HvacScenario 的双闭环范围证书仅支持一阶 RC；"
                "2R2C PID 与双闭环接入属于 Issue #42。"
            )
        self._design = load_hvac_pid_design(baseline_path, self._contract)
        # 两个旧 loader 会再次读取基线；若解析期间文件变化，来源 hash 便不能代表实际配置。
        if path.read_bytes() != wrapper_source or baseline_path.read_bytes() != baseline_source:
            raise ValueError("HVAC 配置在解析期间发生变化，拒绝生成不可信快照。")
        self._wrapper_source_hash = sha256(wrapper_source).hexdigest()
        self._baseline_source_hash = sha256(baseline_source).hexdigest()
        self._wrapper_filename = path.name
        self._baseline_filename = baseline_path.name
        self._fixed_point = FixedPointContext(
            _positive_integer(security, "modulus"),
            integer_bits=_positive_integer(security, "integer_bits"),
            fractional_bits=_positive_integer(security, "fractional_bits"),
        )
        self._security_parameter = _positive_integer(security, "security_parameter")
        self._horizon_steps = _positive_integer(security, "horizon_steps")
        self._test_seed = test_seed
        if self._contract.timing.terminal_sample_included:
            raise ValueError("当前双闭环仅支持 terminal_sample_included=false。")
        if self._horizon_steps != self._contract.timing.sample_count:
            raise ValueError("horizon_steps 必须等于 HVAC sample_count。")
        self.safety_certificate = self._derive_safety_certificate()

    @property
    def metadata(self) -> ScenarioMetadata:
        """直接返回已解析的通道元数据，不为产物读取再创建安全 session。"""
        return self._contract.metadata

    def effective_config_snapshot(self) -> dict[str, Any]:
        """只快照已校验且实际参与装配的值、执行 seed 和两个源文件摘要。

        路径仅保留文件名而非机器绝对路径；固定策略字段是旧配置 loader 已强制
        验证的语义，不把任意未知 YAML 字段误称为生效控制参数。
        """
        contract = self._contract
        return {
            "scenario": {"name": "hvac", "version": self.scenario_version},
            "sources": {
                "wrapper": {
                    "filename": self._wrapper_filename,
                    "sha256": self._wrapper_source_hash,
                },
                "baseline": {
                    "filename": self._baseline_filename,
                    "sha256": self._baseline_source_hash,
                },
            },
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
                    "kind": "first_order_rc_cooling",
                    "discretization": "zero_order_hold",
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
            "finite_horizon_certificate": asdict(self.safety_certificate),
        }

    def build_plan(self) -> SimulationPlan:
        """先由场景推物理界，再由 Client 离线证明编码控制器界，成功后返回双支计划。"""
        design = self._design
        contract = self._contract
        plain_spec = design.to_controller_spec()
        ell = self._fixed_point.fractional_bits
        secure_spec = ControllerSpec(
            A=plain_spec.A,
            B=plain_spec.B,
            C=plain_spec.C,
            D=plain_spec.D,
            x0=plain_spec.x0,
            scale_metadata=ControllerScaleMetadata(
                state=ell, input=ell, output=2 * ell, A=0, B=0, C=ell, D=ell
            ),
        )
        range_contract = ControllerRangeContract(
            state_payload_bounds=self.safety_certificate.state_payload_bounds,
            input_payload_bounds=(self.safety_certificate.input_payload_bound,),
            horizon_steps=self._horizon_steps,
        )
        # 两支只共享不可变配置值；plant、adapter、runtime 和安全 session 均重新构造。
        ideal = SimulationBranch(
            HvacPlant(contract), HvacSignalAdapter(contract), PlaintextStateSpaceRuntime(plain_spec)
        )
        secure = SimulationBranch(
            HvacPlant(contract),
            HvacSignalAdapter(contract),
            SecureStateSpaceRuntime(
                secure_spec,
                self._fixed_point,
                range_contract,
                security_parameter=self._security_parameter,
                test_seed=self._test_seed,
            ),
        )
        return SimulationPlan(
            metadata=contract.metadata,
            sample_times=np.array(contract.timing.sample_times_seconds, dtype=float),
            ideal=ideal,
            secure=secure,
        )

    def metrics(self, result: SimulationResult) -> HvacComparison:
        """从已运行的八字段结果计算场景指标，且核对每支物理范围。"""
        low, high = self.safety_certificate.temperature_bounds_celsius
        for name in ("output_ideal", "output_secure"):
            output = getattr(result, name)
            if not np.all((low - 1e-10 <= output) & (output <= high + 1e-10)):
                raise ValueError(f"{name} 超出事前证明的 HVAC plant 温度范围。")
        model = self._contract.model
        for name in ("control_ideal", "control_secure"):
            applied = getattr(result, name)
            if not np.all(
                (model.lower_control_bound_kw <= applied)
                & (applied <= model.upper_control_bound_kw)
            ):
                raise ValueError(f"{name} 超出 HVAC actuator 范围。")
        return HvacComparison(
            result,
            _segment_metrics(self._contract, self._design, result.output_ideal),
            _segment_metrics(self._contract, self._design, result.output_secure),
            self.safety_certificate,
        )

    def _derive_safety_certificate(self) -> HvacSafetyCertificate:
        """由 RC 凸组合及 actuator 界事前推出温度和 |r-T| 界，不读取仿真轨迹。

        ZOH 温度递推可写成 ``T_next=aT+(1-a)(T_ambient-eta R u)``，其中
        ``0<a<1`` 且 ``u`` 在配置区间内；初温与两个极端平衡温度的包络因此
        对全部步数不变。reference 的极端值再给出 controller input 的绝对界。
        """
        model = self._contract.model
        cooling_equilibrium = lambda control: (
            model.ambient_temperature_celsius
            - model.cooling_coefficient * model.thermal_resistance_celsius_per_kw * control
        )
        low = min(
            model.initial_temperature_celsius,
            cooling_equilibrium(model.upper_control_bound_kw),
        )
        high = max(
            model.initial_temperature_celsius,
            cooling_equilibrium(model.lower_control_bound_kw),
        )
        reference_values = [
            segment.target_temperature_celsius for segment in self._contract.reference_segments
        ]
        input_abs_bound = max(
            abs(reference - temperature)
            for reference in reference_values
            for temperature in (low, high)
        )
        if not all(isfinite(value) for value in (low, high, input_abs_bound)):
            raise ValueError("HVAC 物理范围证明产生非有限值。")
        # 论文编码 floor(x*2^ell+1/2)；额外一 payload 覆盖边界取整。
        input_payload_bound = ceil(input_abs_bound * self._fixed_point.scale + 1)
        if input_payload_bound > self._fixed_point.maximum_payload:
            raise ValueError("HVAC input payload bound 超出 fixed-point 可表示范围。")
        initial = self._design.to_controller_spec().x0
        initial_payload = np.asarray(self._fixed_point.encode(initial), dtype=object)
        integral_bound = abs(int(initial_payload[0])) + (
            self._horizon_steps * self._design.sample_period_seconds * input_payload_bound
        )
        previous_bound = max(abs(int(initial_payload[1])), input_payload_bound)
        return HvacSafetyCertificate(
            (low, high),
            input_abs_bound,
            input_payload_bound,
            (integral_bound, previous_bound),
            self._horizon_steps,
        )


def _positive_integer(source: Mapping[str, Any], name: str) -> int:
    """读取配置整数并拒绝 bool/零值，防止安全参数被静默解释。"""
    value = source.get(name)
    if isinstance(value, bool) or not isinstance(value, Integral) or value <= 0:
        raise ValueError(f"security.{name} 必须是正整数。")
    return int(value)


def run_hvac_dual_loop(config_path: str | Path, *, test_seed: int | None = None) -> HvacComparison:
    """从场景 CLI/config 装配并运行 180 步双闭环，返回无持久化的结果和证书。"""
    scenario = HvacScenario(config_path, test_seed=test_seed)
    return scenario.metrics(run(scenario))
