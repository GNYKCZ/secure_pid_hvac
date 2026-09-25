"""Client 连续 LAN 的共享素数预检与 Paper PID profile。"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from secure_control.crypto import PrimeModulusEvidence, verify_prime_modulus
from secure_control.execution.lan_config import _fields, _load_yaml, _relative
from secure_control.scenarios.paper_pid.baseline import run_paper_pid_baseline
from secure_control.scenarios.paper_pid.secure_experiment import paper_pid_numeric_contract

from .paper_pid_sources import load_baseline_config, parse_prime_certificate

_FROZEN_DEFINITION_SHA256 = "16b635276927e4a14977ff7ac2d7baa67885fc3244017589fb2a638b5c6de39a"


@dataclass(frozen=True, slots=True)
class PaperPidLanProfile:
    """实验选择与公开数值上下文；密钥和拓扑留在角色配置。"""

    path: Path
    digest: str
    definition_digest: str | None
    definition_path: Path | None
    definition: dict[str, Any] | None
    baseline_config: dict[str, Any]
    baseline_path: Path
    baseline_digest: str
    prime_digest: str
    sample_count: int
    ell: int
    parameter_bits: int
    runtime_payload_bits: int
    security_parameter: int
    q: int
    evidence: PrimeModulusEvidence | None
    measurement_absolute_bound: int
    control_channel: int
    output_root: Path
    claim_level: str


def _integer(value: object, name: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} 必须是 >= {minimum} 的整数。")
    return value


def _load_prime(path: Path) -> tuple[int, PrimeModulusEvidence | None, str]:
    """两种 Client 场景共用唯一素数证书解析和验证。"""
    prime = _load_yaml(path)
    _fields(prime, {"modulus", "evidence"})
    q = _integer(prime["modulus"], "q", minimum=3)
    raw_evidence = prime["evidence"]
    if raw_evidence is None:
        evidence = None
    else:
        _fields(raw_evidence, {"method", "source", "source_version",
                               "certificate_id", "certificate_sha256", "certificate"})
        evidence = PrimeModulusEvidence(
            raw_evidence["method"], raw_evidence["source"],
            raw_evidence["source_version"], raw_evidence["certificate_id"],
            raw_evidence["certificate_sha256"],
            parse_prime_certificate(raw_evidence["certificate"]),
        )
    verify_prime_modulus(q, evidence)
    return q, evidence, sha256(path.read_bytes()).hexdigest()


def load_paper_pid_lan_profile(path: str | Path) -> PaperPidLanProfile:
    """严格解析并验证 q、证书、位宽和 finite horizon，早于任何网络连接。"""
    source = Path(path).resolve()
    profile = _load_yaml(source)
    source_fields = {"frozen_definition", "baseline_source"} & set(profile)
    if len(source_fields) != 1:
        raise ValueError("须且只能选择 baseline_source 或 frozen_definition。")
    _fields(profile, {"schema_version", "scenario", "sample_count", "numeric", "range",
                      "plot", "output_root"} | source_fields)
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise ValueError("实验 profile schema_version 无效。")
    if profile["scenario"] != "paper_pid_fig3":
        raise ValueError("目前只支持 paper_pid_fig3 场景。")
    count = _integer(profile["sample_count"], "sample_count", minimum=1)
    numeric = profile["numeric"]
    _fields(numeric, {"ell", "k", "runtime_payload_bits", "lambda", "prime_source"})
    ell = _integer(numeric["ell"], "ell", minimum=1)
    parameter_bits = _integer(numeric["k"], "k", minimum=ell + 1)
    runtime_bits = _integer(numeric["runtime_payload_bits"], "runtime_payload_bits",
                            minimum=parameter_bits)
    security = _integer(numeric["lambda"], "lambda", minimum=1)
    limits = profile["range"]
    _fields(limits, {"measurement_absolute_bound"})
    bound = _integer(limits["measurement_absolute_bound"],
                     "measurement_absolute_bound", minimum=1)
    plot = profile["plot"]
    _fields(plot, {"control_channel"})
    channel = _integer(plot["control_channel"], "control_channel", minimum=0)
    if channel != 0:
        raise ValueError("paper PID 只有控制通道 0。")
    prime_path = _relative(source, numeric["prime_source"])
    q, evidence, prime_digest = _load_prime(prime_path)
    if q.bit_length() - security - 2 <= ell:
        raise ValueError("q、lambda、ell 不满足 Protocol 2 的 κ>ell。")
    # 用场景唯一的 state/input 界公式与标准 Client 校验器复核完整 horizon。
    spec, context, contract = paper_pid_numeric_contract(
        fractional_bits=ell, parameter_bits=parameter_bits,
        runtime_payload_bits=runtime_bits, modulus=q, sample_count=count,
        measurement_absolute_bound=bound,
    )
    from secure_control.crypto import TwoPartySharing
    from secure_control.protocol import Client

    Client(context, TwoPartySharing(q), security_parameter=security,
           modulus_evidence=evidence).distribute_controller(spec, contract)
    definition_path = None
    definition_digest = None
    definition = None
    frozen = False
    if "frozen_definition" in source_fields:
        # 兼容旧 LAN 结果的冻结声明；日常运行仅依赖自身的基线来源。
        from .paper_pid_fig3 import load_definition

        definition_path = _relative(source, profile["frozen_definition"])
        definition, baseline_config, frozen_q, frozen_evidence = load_definition(definition_path)
        definition_digest = sha256(definition_path.read_bytes()).hexdigest()
        baseline_path = definition_path.parent / definition["baseline_config"]
        baseline_digest = definition["baseline_sha256"]
        frozen = (definition_digest == _FROZEN_DEFINITION_SHA256
                  and count == definition["sample_count"]
                  and ell in definition["fractional_bits"]
                  and parameter_bits == ell + definition["paper_parameter_headroom_bits"]
                  and runtime_bits == ell + definition["runtime_payload_headroom_bits"]
                  and security == definition["security_parameter"]
                  and bound == definition["measurement_absolute_bound"]
                  and q == frozen_q and evidence == frozen_evidence
                  and sha256(prime_path.read_bytes()).hexdigest() == definition["prime_sha256"])
    else:
        baseline_path = _relative(source, profile["baseline_source"])
        baseline_config, baseline_digest = load_baseline_config(baseline_path)
    baseline = run_paper_pid_baseline(
        alpha=baseline_config["plant"]["alpha"],
        sample_period_seconds=baseline_config["plant"]["sample_period_seconds"],
        plant_initial_state=baseline_config["plant"]["initial_state"],
        sample_count=count,
    )
    if max(abs(float(value)) for value in baseline.rows[:, 6]) > bound:
        raise ValueError("已知明文 plant 测量超出 profile 的先验界。")
    root = _relative(source, profile["output_root"])
    return PaperPidLanProfile(
        source, sha256(source.read_bytes()).hexdigest(),
        definition_digest, definition_path, definition, baseline_config,
        baseline_path, baseline_digest,
        prime_digest, count, ell, parameter_bits,
        runtime_bits, security, q, evidence, bound, channel, root,
        "paper-inspired-frozen-parameter-point" if frozen else "user-exploration",
    )
