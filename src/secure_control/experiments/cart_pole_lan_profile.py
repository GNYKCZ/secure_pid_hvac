"""倒立摆 Client profile：单一物理/控制来源和拨号前数值预检。"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext, PrimeModulusEvidence, TwoPartySharing
from secure_control.execution.lan_config import _fields, _load_yaml, _relative
from secure_control.protocol import Client, ControllerRangeContract
from secure_control.scenarios.cart_pole.contract import CartPoleContract, load_cart_pole_contract
from secure_control.scenarios.cart_pole.controller import (
    CartPoleBalanceConfig,
    build_cart_pole_controller_spec,
    load_cart_pole_balance_config,
)
from secure_control.scenarios.cart_pole.secure_experiment import cart_pole_numeric_contract

from .lan_profile import _integer, _load_prime


@dataclass(frozen=True, slots=True)
class CartPoleLanProfile:
    """Client 持有的来源、数值证明与控制器；P1/P2 不读取场景配置。"""

    path: Path
    digest: str
    plant_path: Path
    plant_digest: str
    balance_path: Path
    balance_digest: str
    prime_path: Path
    prime_digest: str
    plant: CartPoleContract
    balance: CartPoleBalanceConfig
    spec: ControllerSpec
    context: FixedPointContext
    contract: ControllerRangeContract
    proof: dict[str, object]
    ell: int
    parameter_bits: int
    runtime_payload_bits: int
    security_parameter: int
    q: int
    evidence: PrimeModulusEvidence | None
    output_root: Path

    def recheck_sources(self) -> None:
        """发布之前逐一重读来源 bytes，拒绝运行期间被修改的配置。"""
        for path, digest in (
            (self.path, self.digest), (self.plant_path, self.plant_digest),
            (self.balance_path, self.balance_digest), (self.prime_path, self.prime_digest),
        ):
            if sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("倒立摆 profile 或来源在运行期间变化。")


def load_cart_pole_lan_profile(path: str | Path) -> CartPoleLanProfile:
    """严格读取小型 Client profile 并在联网前验证初态、编码和公开素数。"""
    source = Path(path).resolve()
    profile = _load_yaml(source)
    _fields(profile, {"schema_version", "scenario", "plant_source", "balance_source",
                      "numeric", "output_root"})
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise ValueError("倒立摆 profile schema_version 无效。")
    if profile["scenario"] != "cart_pole":
        raise ValueError("倒立摆 profile 场景无效。")
    numeric = profile["numeric"]
    _fields(numeric, {"ell", "k", "runtime_payload_bits", "lambda", "prime_source"})
    ell = _integer(numeric["ell"], "ell", minimum=1)
    parameter_bits = _integer(numeric["k"], "k", minimum=ell + 1)
    runtime_bits = _integer(numeric["runtime_payload_bits"], "runtime_payload_bits",
                            minimum=parameter_bits)
    security = _integer(numeric["lambda"], "lambda", minimum=1)
    plant_path = _relative(source, profile["plant_source"])
    balance_path = _relative(source, profile["balance_source"])
    prime_path = _relative(source, numeric["prime_source"])
    plant = load_cart_pole_contract(plant_path)
    balance = load_cart_pole_balance_config(balance_path, plant)
    if balance.horizon_steps > 1000:
        raise ValueError("倒立摆 LAN 运行超过 1000 步上限。")
    if np.any(np.abs(plant.initial_state) > np.asarray(balance.safe_abs)):
        raise ValueError("倒立摆初态超出四维安全工作域。")
    spec = build_cart_pole_controller_spec(plant, balance)
    q, evidence, prime_digest = _load_prime(prime_path)
    if q.bit_length() - security - 2 <= ell:
        raise ValueError("q、lambda、ell 不满足 Protocol 2 的 κ>ell。")
    context, contract, proof = cart_pole_numeric_contract(
        spec, balance, fractional_bits=ell, parameter_bits=parameter_bits,
        runtime_payload_bits=runtime_bits, modulus=q,
    )
    proof["force_limit_n"] = plant.max_applied_force_n
    Client(context, TwoPartySharing(q), security_parameter=security,
           modulus_evidence=evidence).distribute_controller(spec, contract)
    return CartPoleLanProfile(
        source, sha256(source.read_bytes()).hexdigest(), plant_path,
        sha256(plant_path.read_bytes()).hexdigest(), balance_path,
        sha256(balance_path.read_bytes()).hexdigest(), prime_path, prime_digest,
        plant, balance, spec, context, contract, proof, ell, parameter_bits,
        runtime_bits, security, q, evidence, _relative(source, profile["output_root"]),
    )
