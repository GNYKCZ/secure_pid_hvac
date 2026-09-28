"""#103 安全起摆的固定门计划与全输入盒精确有理算术界。"""

from __future__ import annotations

from fractions import Fraction
from math import factorial

from secure_control.crypto.primes import PrimeModulusEvidence
from secure_control.protocol.arithmetic import (
    ScalarCertificate,
    ScalarGate,
    ScalarProgram,
    certify_scalar_program,
)

from .contract import CartPoleContract
from .controller import CartPoleBalanceConfig
from .swing_up import CartPoleSwingUpConfig

_PI_UPPER = Fraction(22, 7)


def build_swing_up_program(
    plant: CartPoleContract, config: CartPoleSwingUpConfig,
) -> ScalarProgram:
    """从现有物理和增益 owner 编译 #102 能量律，不把参数数值写进通用协议。"""
    if not isinstance(plant, CartPoleContract) or not isinstance(config, CartPoleSwingUpConfig):
        raise TypeError("安全起摆必须使用已验证的场景配置")
    constants: list[tuple[str, Fraction]] = []
    gates: list[ScalarGate] = []

    def constant(name: str, value: Fraction) -> str:
        constants.append((name, value))
        return name

    def gate(name: str, operation: str, left: str, right: str) -> str:
        gates.append(ScalarGate(name, operation, left, right))
        return name

    def number(value: float) -> Fraction:
        return Fraction.from_float(value)

    zero = constant("zero", Fraction(0))
    z = gate("beta_squared", "multiply", "beta", "beta")
    for kind in ("sin", "cos"):
        degree = 21 if kind == "sin" else 20
        horner = constant(f"{kind}_coefficient_10", Fraction(1, factorial(degree)))
        for index in range(9, -1, -1):
            product = gate(f"{kind}_horner_multiply_{index}", "multiply", horner, z)
            coefficient = constant(
                f"{kind}_coefficient_{index}",
                Fraction((-1) ** index, factorial(2 * index + (1 if kind == "sin" else 0))),
            )
            horner = gate(
                "cos_value" if kind == "cos" and index == 0 else f"{kind}_horner_add_{index}",
                "add", product, coefficient,
            )
        if kind == "sin":
            gate("sin_value", "multiply", "beta", horner)

    mass_cart = number(plant.cart_mass_kg)
    mass_pole = number(plant.pole_mass_kg)
    length = number(plant.com_length_m)
    inertia = number(plant.pole_inertia_kg_m2)
    gravity = number(plant.gravity_m_per_s2)
    h = mass_pole * length
    j = inertia + h * length
    hg = h * gravity
    omega_squared = gate("omega_squared", "multiply", "omega", "omega")
    kinetic = gate("kinetic", "multiply",
                   constant("half_inertia", j / 2), omega_squared)
    potential = gate("potential", "multiply",
                     constant("gravity_energy", hg), "cos_value")
    energy = gate("energy", "add", kinetic, potential)
    error = gate("energy_error", "subtract", energy,
                 constant("upright_energy", hg))
    error_omega = gate("error_omega", "multiply", error, "omega")
    error_omega_cos = gate("error_omega_cos", "multiply", error_omega, "cos_value")
    energy_accel = gate("energy_accel", "multiply",
                        constant("energy_gain", number(config.energy_gain_m_per_j_s)),
                        error_omega_cos)
    position_accel = gate("position_accel", "multiply",
                          constant("position_gain", number(config.cart_position_gain_per_s2)),
                          "p")
    velocity_accel = gate("velocity_accel", "multiply",
                          constant("velocity_gain", number(config.cart_velocity_gain_per_s)),
                          "v")
    accel = gate("accel", "subtract",
                 gate("accel_before_velocity", "subtract",
                      gate("accel_before_position", "subtract", zero, energy_accel),
                      position_accel),
                 velocity_accel)
    cos_squared = gate("cos_squared", "multiply", "cos_value", "cos_value")
    coupling = gate("coupling", "multiply",
                    constant("coupling_coefficient", h * h / j), cos_squared)
    effective_mass = gate("effective_mass", "subtract",
                          constant("total_mass", mass_cart + mass_pole), coupling)
    inertial_force = gate("inertial_force", "multiply", effective_mass, accel)
    friction_force = gate("friction_force", "multiply",
                          constant("friction", number(plant.cart_friction_n_s_per_m)), "v")
    pole_kinetic = gate("pole_kinetic", "multiply",
                        constant("pole_moment", h), omega_squared)
    pole_force = gate("pole_force", "multiply", pole_kinetic, "sin_value")
    sin_cos = gate("sin_cos", "multiply", "sin_value", "cos_value")
    gravity_force = gate("gravity_force", "multiply",
                         constant("gravity_coupling", h * h * gravity / j), sin_cos)
    raw = gate("raw_force", "subtract",
               gate("raw_before_gravity", "add",
                    gate("raw_before_pole", "add", inertial_force, friction_force),
                    pole_force), gravity_force)
    return ScalarProgram(
        ("p", "v", "beta", "omega"), tuple(constants), tuple(gates), raw,
    )


def certify_swing_up_arithmetic(
    plant: CartPoleContract, balance: CartPoleBalanceConfig,
    config: CartPoleSwingUpConfig, *,
    modulus: int, fractional_bits: int = 80, security_parameter: int = 80,
    modulus_evidence: PrimeModulusEvidence | None = None,
) -> tuple[ScalarProgram, ScalarCertificate]:
    """证明固定 38 门的全盒整数范围和 raw 力近似误差。

    解析事实：|sin β|、|cos β|≤1；在 |β|≤π<22/7 上，
    21 阶 sin、20 阶 cos Taylor 多项式的余项分别不超过
    (22/7)^23/23! 和 (22/7)^22/22!。泛型证书再逐门传播输入编码、
    系数编码及每次 Protocol 2 至多两格的保守舍入误差。
    """
    if fractional_bits != 80 or security_parameter != 80:
        raise ValueError("#103 安全起摆只接受已批准的 ℓ=80、λ=80 profile")
    config.validate(plant, balance)
    program = build_swing_up_program(plant, config)
    certificate = certify_scalar_program(
        program,
        {
            "p": Fraction.from_float(plant.track_center_limit_m),
            "v": Fraction.from_float(config.max_cart_speed_m_per_s),
            "beta": _PI_UPPER,
            "omega": Fraction.from_float(config.max_pole_speed_rad_per_s),
        },
        modulus=modulus,
        fractional_bits=fractional_bits,
        security_parameter=security_parameter,
        modulus_evidence=modulus_evidence,
        semantic_enclosures={
            "sin_value": (Fraction(1), _PI_UPPER**23 / factorial(23)),
            "cos_value": (Fraction(1), _PI_UPPER**22 / factorial(22)),
        },
    )
    return program, certificate
