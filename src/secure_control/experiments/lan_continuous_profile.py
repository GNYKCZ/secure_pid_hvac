"""连续 Client 场景的唯一分派与小型已预检装配记录。"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext, PrimeModulusEvidence
from secure_control.execution.lan_config import _load_yaml
from secure_control.protocol import ControllerRangeContract
from secure_control.scenarios.cart_pole.secure_experiment import (
    SCENARIO_VERSION as CART_POLE_VERSION,
)
from secure_control.scenarios.cart_pole.secure_experiment import (
    CartPoleSecureExperiment,
)
from secure_control.scenarios.paper_pid.secure_experiment import (
    SCENARIO_VERSION as PAPER_VERSION,
)
from secure_control.scenarios.paper_pid.secure_experiment import (
    assemble_paper_pid_plan,
    paper_pid_numeric_contract,
    validate_paper_pid_baseline,
)
from secure_control.scenarios.quadruple_tank.plant import build_quadruple_tank_state_space
from secure_control.scenarios.quadruple_tank.secure_experiment import (
    SCENARIO_VERSION as TANK_VERSION,
)
from secure_control.scenarios.quadruple_tank.secure_experiment import (
    assemble_quadruple_tank_plan,
    validate_quadruple_tank_result,
)
from secure_control.simulation import SimulationPlan, SimulationResult

from .artifacts import ExperimentRecord
from .cart_pole_evidence import load_verified_cart_pole_run, write_cart_pole_evidence
from .cart_pole_lan_profile import load_cart_pole_lan_profile
from .lan_profile import load_paper_pid_lan_profile
from .quadruple_tank_lan_profile import load_quadruple_tank_lan_profile


@dataclass(frozen=True, slots=True)
class PreparedLanExperiment:
    """通用 Client 只消费这些已预检契约和场景拥有的验证回调。"""

    scenario_name: str
    scenario_version: str
    sample_count: int
    ell: int
    expected_state_truncation_bits: int
    q: int
    security_parameter: int
    evidence: PrimeModulusEvidence | None
    spec: ControllerSpec
    context: FixedPointContext
    contract: ControllerRangeContract
    output_root: Path
    control_channel: int
    claim_level: str
    effective_config: dict[str, object]
    build_plan: Callable[[object], SimulationPlan]
    validate_result: Callable[[SimulationResult], None]
    recheck_sources: Callable[[], None]
    write_scenario_evidence: Callable[[ExperimentRecord, Path], tuple[str, ...]] | None = None
    verify_scenario_run: Callable[[Path], None] | None = None


def _paper(path: str | Path) -> PreparedLanExperiment:
    profile = load_paper_pid_lan_profile(path)
    spec, context, contract = paper_pid_numeric_contract(
        fractional_bits=profile.ell, parameter_bits=profile.parameter_bits,
        runtime_payload_bits=profile.runtime_payload_bits, modulus=profile.q,
        sample_count=profile.sample_count,
        measurement_absolute_bound=profile.measurement_absolute_bound,
    )

    def recheck() -> None:
        for source, digest in ((profile.path, profile.digest),
                               (profile.baseline_path, profile.baseline_digest)):
            if sha256(source.read_bytes()).hexdigest() != digest:
                raise ValueError("paper PID profile 或基线在运行期间变化。")
        if (profile.definition_path is not None
                and sha256(profile.definition_path.read_bytes()).hexdigest()
                != profile.definition_digest):
            raise ValueError("Fig3 冻结定义在运行期间变化。")

    effective = {
        "scenario": {"name": "paper_pid_fig3", "version": PAPER_VERSION},
        "fractional_bits": profile.ell, "paper_parameter_bits": profile.parameter_bits,
        "runtime_payload_bits": profile.runtime_payload_bits,
        "security_parameter": profile.security_parameter, "q": profile.q,
        "sample_count": profile.sample_count,
        "range": {"mode": "finite_horizon", "steps": profile.sample_count,
                  "measurement_absolute_bound": profile.measurement_absolute_bound},
        "reference_used": False, "raw_equals_applied": True,
        "claim_level": profile.claim_level,
        "profile_sha256": profile.digest,
        "prime_source_sha256": profile.prime_digest,
        "frozen_definition_sha256": profile.definition_digest,
        "definition": profile.definition,
        "baseline_source_sha256": profile.baseline_digest,
        "baseline_plant": profile.baseline_config["plant"],
        "controller_spec": {
            name: getattr(spec, name).tolist() for name in ("A", "B", "C", "D", "x0")
        },
    }
    return PreparedLanExperiment(
        "paper_pid_fig3", PAPER_VERSION, profile.sample_count, profile.ell, profile.ell,
        profile.q, profile.security_parameter, profile.evidence, spec, context, contract,
        profile.output_root, profile.control_channel, profile.claim_level, effective,
        lambda secure: assemble_paper_pid_plan(spec, secure, profile.sample_count),
        lambda result: validate_paper_pid_baseline(
            result, profile.baseline_config, profile.sample_count,
            profile.measurement_absolute_bound,
        ), recheck,
    )


def _tank(path: str | Path) -> PreparedLanExperiment:
    profile = load_quadruple_tank_lan_profile(path)
    state_space = build_quadruple_tank_state_space(profile.plant)

    effective = {
        "scenario": {"name": "quadruple_tank", "version": TANK_VERSION},
        "fractional_bits": profile.ell, "paper_parameter_bits": profile.parameter_bits,
        "runtime_payload_bits": profile.runtime_payload_bits,
        "security_parameter": profile.security_parameter, "q": profile.q,
        "sample_count": profile.sample_count,
        "range": {"mode": "finite_horizon", "steps": profile.sample_count,
                  "measurement_absolute_bounds_v": list(profile.measurement_absolute_bounds_v),
                  "proof": profile.proof},
        "reference_used": False, "raw_equals_applied": True,
        "claim_level": profile.claim_level,
        "profile_sha256": profile.digest,
        "prime_source_sha256": profile.prime_digest,
        "plant_source_sha256": profile.plant_digest,
        "observer_source_sha256": profile.observer_digest,
        "plant_contract": asdict(profile.plant),
        "plant_state_space": {name: getattr(state_space, name).tolist()
                              for name in ("F", "G", "C", "A_p", "B_p", "C_p", "D_p")},
        "controller_spec": {name: getattr(profile.spec, name).tolist()
                            for name in ("A", "B", "C", "D", "x0")},
    }
    return PreparedLanExperiment(
        "quadruple_tank", TANK_VERSION, profile.sample_count, profile.ell, profile.ell,
        profile.q, profile.security_parameter, profile.evidence, profile.spec,
        profile.context, profile.contract, profile.output_root, profile.control_channel,
        profile.claim_level, effective,
        lambda secure: assemble_quadruple_tank_plan(profile.spec, profile.plant, secure,
                                                    profile.sample_count),
        lambda result: validate_quadruple_tank_result(
            result, profile.spec, profile.plant, profile.sample_count,
            profile.measurement_absolute_bounds_v,
        ), profile.recheck_sources,
    )


def _cart_pole(path: str | Path) -> PreparedLanExperiment:
    """#91 的唯一 plant/controller/adapter 来源仅在 Client 场景层装配。"""
    profile = load_cart_pole_lan_profile(path)
    scenario = CartPoleSecureExperiment(profile.plant, profile.balance, profile.spec)

    def verify_run(run_dir: Path) -> None:
        """发布后必须经 canonical 与场景双重 reader 才能返回 complete。"""
        load_verified_cart_pole_run(run_dir)

    effective = {
        "scenario": {"name": "cart_pole", "version": CART_POLE_VERSION},
        "fractional_bits": profile.ell, "paper_parameter_bits": profile.parameter_bits,
        "runtime_payload_bits": profile.runtime_payload_bits,
        "security_parameter": profile.security_parameter, "q": profile.q,
        "sample_count": profile.balance.horizon_steps,
        "range": {"mode": "finite_horizon", "steps": profile.balance.horizon_steps,
                  "proof": profile.proof},
        "reference_used": True, "raw_equals_applied": False,
        "claim_level": "cart-pole-near-upright-simulation",
        "profile_sha256": profile.digest,
        "prime_source_sha256": profile.prime_digest,
        "plant_source_sha256": profile.plant_digest,
        "balance_source_sha256": profile.balance_digest,
        "plant_contract": asdict(profile.plant),
        "balance_config": asdict(profile.balance),
        "controller_spec": {name: getattr(profile.spec, name).tolist()
                            for name in ("A", "B", "C", "D", "x0")},
    }
    return PreparedLanExperiment(
        "cart_pole", CART_POLE_VERSION, profile.balance.horizon_steps,
        profile.ell, profile.ell, profile.q, profile.security_parameter,
        profile.evidence, profile.spec, profile.context, profile.contract,
        profile.output_root, 0, "cart-pole-near-upright-simulation", effective,
        scenario.build_plan, scenario.validate_result, profile.recheck_sources,
        lambda record, stage: write_cart_pole_evidence(record, stage, scenario),
        verify_run,
    )


def load_prepared_lan_experiment(path: str | Path) -> PreparedLanExperiment:
    """唯一显式分派；未知场景在网络建立之前失败。"""
    scenario = _load_yaml(Path(path).resolve()).get("scenario")
    if scenario == "paper_pid_fig3":
        return _paper(path)
    if scenario == "quadruple_tank":
        return _tank(path)
    if scenario == "cart_pole":
        return _cart_pole(path)
    raise ValueError("连续 LAN 实验场景无效。")
