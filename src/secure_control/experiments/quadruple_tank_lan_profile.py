"""四水箱 Client profile：严格来源、素数和闭环范围预检。"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext, PrimeModulusEvidence, TwoPartySharing
from secure_control.execution.lan_config import _fields, _load_yaml, _relative
from secure_control.protocol import Client, ControllerRangeContract
from secure_control.scenarios.quadruple_tank.contract import (
    QuadrupleTankContract,
    load_quadruple_tank_contract,
)
from secure_control.scenarios.quadruple_tank.observer import load_quadruple_tank_observer_spec
from secure_control.scenarios.quadruple_tank.secure_experiment import (
    quadruple_tank_numeric_contract,
)

from .lan_profile import _integer, _load_prime

_CANONICAL_PLANT_SHA256 = "e48ea5edb55c2512c3bf1f11ed1ea46e7d2ac4f5841b875c6d27fba1273ff236"
_CANONICAL_OBSERVER_SHA256 = "b227ad5e9740109c7ee03300eed07f20f2d77a0c273b163ba9a0275f35bcb533"


@dataclass(frozen=True, slots=True)
class QuadrupleTankLanProfile:
    """已预检的场景数值和来源；P1/P2 不读取此 Client 文件。"""

    path: Path
    digest: str
    plant_path: Path
    plant_digest: str
    observer_path: Path
    observer_digest: str
    prime_path: Path
    prime_digest: str
    plant: QuadrupleTankContract
    spec: ControllerSpec
    context: FixedPointContext
    contract: ControllerRangeContract
    proof: dict[str, object]
    sample_count: int
    ell: int
    parameter_bits: int
    runtime_payload_bits: int
    security_parameter: int
    q: int
    evidence: PrimeModulusEvidence | None
    measurement_absolute_bounds_v: tuple[int, int]
    control_channel: int
    output_root: Path
    claim_level: str

    def recheck_sources(self) -> None:
        """联网运行后再核对所有公开输入，拒绝期间漂移。"""
        for path, digest in ((self.path, self.digest),
                             (self.plant_path, self.plant_digest),
                             (self.observer_path, self.observer_digest),
                             (self.prime_path, self.prime_digest)):
            if sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("四水箱 profile 或来源在运行期间变化。")


def load_quadruple_tank_lan_profile(path: str | Path) -> QuadrupleTankLanProfile:
    """在任何拨号之前验证配置、两路测量包络和编码有限时域。"""
    source = Path(path).resolve()
    profile = _load_yaml(source)
    _fields(profile, {"schema_version", "scenario", "plant_source", "observer_source",
                      "sample_count", "numeric", "range", "plot", "output_root"})
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise ValueError("四水箱 profile schema_version 无效。")
    if profile["scenario"] != "quadruple_tank":
        raise ValueError("四水箱 profile 场景无效。")
    count = _integer(profile["sample_count"], "sample_count", minimum=1)
    numeric = profile["numeric"]
    _fields(numeric, {"ell", "k", "runtime_payload_bits", "lambda", "prime_source"})
    ell = _integer(numeric["ell"], "ell", minimum=1)
    parameter_bits = _integer(numeric["k"], "k", minimum=ell + 1)
    runtime_bits = _integer(numeric["runtime_payload_bits"], "runtime_payload_bits",
                            minimum=parameter_bits)
    security = _integer(numeric["lambda"], "lambda", minimum=1)
    limits = profile["range"]
    _fields(limits, {"measurement_absolute_bounds_v"})
    values = limits["measurement_absolute_bounds_v"]
    if not isinstance(values, list) or len(values) != 2:
        raise ValueError("四水箱必须声明两路测量界。")
    bounds = tuple(_integer(value, "measurement_absolute_bounds_v", minimum=1)
                   for value in values)
    plot = profile["plot"]
    _fields(plot, {"control_channel"})
    channel = _integer(plot["control_channel"], "control_channel", minimum=0)
    if channel not in (0, 1):
        raise ValueError("四水箱控制通道只能是 0 或 1。")
    plant_path = _relative(source, profile["plant_source"])
    observer_path = _relative(source, profile["observer_source"])
    prime_path = _relative(source, numeric["prime_source"])
    plant = load_quadruple_tank_contract(plant_path)
    spec = load_quadruple_tank_observer_spec(observer_path)
    q, evidence, prime_digest = _load_prime(prime_path)
    if q.bit_length() - security - 2 <= ell:
        raise ValueError("q、lambda、ell 不满足 Protocol 2 的 κ>ell。")
    context, contract, proof = quadruple_tank_numeric_contract(
        spec, plant, fractional_bits=ell, parameter_bits=parameter_bits,
        runtime_payload_bits=runtime_bits, modulus=q, sample_count=count,
        measurement_absolute_bounds_v=bounds,
    )
    Client(context, TwoPartySharing(q), security_parameter=security,
           modulus_evidence=evidence).distribute_controller(spec, contract)
    plant_digest = sha256(plant_path.read_bytes()).hexdigest()
    observer_digest = sha256(observer_path.read_bytes()).hexdigest()
    claim = ("paper-parameter-derived-linear-simulation"
             if (plant_digest == _CANONICAL_PLANT_SHA256
                 and observer_digest == _CANONICAL_OBSERVER_SHA256)
             else "user-exploration")
    return QuadrupleTankLanProfile(
        source, sha256(source.read_bytes()).hexdigest(), plant_path,
        plant_digest, observer_path, observer_digest, prime_path, prime_digest,
        plant, spec, context, contract, proof, count, ell, parameter_bits,
        runtime_bits, security, q, evidence, bounds, channel,
        _relative(source, profile["output_root"]), claim,
    )
