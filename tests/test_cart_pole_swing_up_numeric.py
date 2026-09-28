"""#103 安全起摆固定门计划的独立整数 oracle 与范围负例。"""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from math import nextafter, pi
from pathlib import Path
from queue import Queue
from threading import Thread

import pytest

from secure_control.crypto.fixed_point import FixedPointContext
from secure_control.experiments.lan_profile import _load_prime
from secure_control.protocol.arithmetic import (
    ScalarPartyExecutor,
    ScalarProgram,
    prepare_scalar_round,
)
from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
from secure_control.scenarios.cart_pole.swing_up import (
    energy_shaping_force,
    load_cart_pole_swing_up_config,
)
from secure_control.scenarios.cart_pole.swing_up_numeric import certify_swing_up_arithmetic

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def setup():
    design = load_cart_pole_observer_design(ROOT / "configs/cart_pole_observer.yaml")
    swing = load_cart_pole_swing_up_config(
        ROOT / "configs/cart_pole_swing_up.yaml", design.plant, design.balance,
    )
    prime, evidence, _ = _load_prime(ROOT / "configs/shared_prime_256_pocklington.yaml")
    return design, swing, prime, evidence


def _integer_oracle(program, modulus: int, values: tuple[float, ...]) -> float:
    """独立按门次序计算普通整数，逐乘法用论文 floor(m/S+1/2)。"""
    context = FixedPointContext(modulus, 174, 80)
    scale = context.scale
    nodes = {name: int(context.encode(value)) for name, value in
             zip(program.inputs, values, strict=True)}
    nodes.update({name: int(context.encode(value)) for name, value in program.constants})
    for gate in program.gates:
        left, right = nodes[gate.left], nodes[gate.right]
        if gate.operation == "multiply":
            nodes[gate.name] = (2 * left * right + scale) // (2 * scale)
        elif gate.operation == "add":
            nodes[gate.name] = left + right
        else:
            nodes[gate.name] = left - right
    return nodes[program.output] / scale


def test_all_box_integer_certificate_and_gate_resource_count(setup):
    design, swing, modulus, evidence = setup
    program, proof = certify_swing_up_arithmetic(
        design.plant, design.balance, swing, modulus=modulus,
        modulus_evidence=evidence,
    )
    assert program.multiplication_count == proof.multiplication_count == 38
    assert len({gate.name for gate in program.gates}) == len(program.gates)
    assert len(proof.multiplication_bounds) == 38
    assert {name for name, _ in proof.multiplication_bounds} == {
        gate.name for gate in program.gates if gate.operation == "multiply"
    }
    assert all(bound < (1 << (proof.kappa - 1)) for _, bound in proof.multiplication_bounds)
    assert proof.max_pretrunc_abs < (1 << (proof.kappa - 1))
    assert proof.max_pretrunc_abs < modulus // 2
    assert proof.kappa == 174
    assert proof.bound("raw_force").ideal_abs < 438
    assert proof.bound("raw_force").error_abs < Fraction(5, 10**8)
    assert proof.max_pretrunc_gate == "energy_accel"


@pytest.mark.parametrize(
    "values",
    [
        (0., 0., -pi, 0.),
        (.5, 3., pi - 1e-12, 15.),
        (-.5, -3., -pi + 1e-12, -15.),
        (.2, -.4, .31, 1.7),
        (-.1, .8, -1.45, -4.2),
    ],
)
def test_integer_gate_oracle_matches_canonical_energy_law(setup, values):
    design, swing, modulus, evidence = setup
    program, proof = certify_swing_up_arithmetic(
        design.plant, design.balance, swing, modulus=modulus,
        modulus_evidence=evidence,
    )
    integer = _integer_oracle(program, modulus, values)
    p, v, beta, omega = values
    ideal = energy_shaping_force(design.plant, swing, (p, v, beta, omega))
    assert abs(integer - ideal) < float(proof.bound("raw_force").error_abs) + 1e-12


def test_parameter_owner_rederives_secret_values_without_changing_public_topology(setup):
    design, swing, modulus, evidence = setup
    original, _ = certify_swing_up_arithmetic(
        design.plant, design.balance, swing, modulus=modulus,
        modulus_evidence=evidence,
    )
    changed, _ = certify_swing_up_arithmetic(
        design.plant, design.balance, replace(swing, energy_gain_m_per_j_s=9.),
        modulus=modulus, modulus_evidence=evidence,
    )
    assert original.topology_sha256() == changed.topology_sha256()
    assert dict(original.constants)["energy_gain"] == Fraction(8)
    assert dict(changed.constants)["energy_gain"] == Fraction(9)
    assert _integer_oracle(original, modulus, (0., 0., .4, 2.)) != _integer_oracle(
        changed, modulus, (0., 0., .4, 2.),
    )


def test_wrong_precision_and_unprovable_box_reject_before_material_creation(setup):
    design, swing, modulus, evidence = setup
    with pytest.raises(ValueError, match="ℓ=80"):
        certify_swing_up_arithmetic(
            design.plant, design.balance, swing, modulus=modulus, fractional_bits=32,
            modulus_evidence=evidence,
        )
    with pytest.raises(ValueError, match="κ>ℓ"):
        certify_swing_up_arithmetic(
            design.plant, design.balance, swing, modulus=257,
        )
    with pytest.raises(ValueError, match="输入盒|乘积"):
        certify_swing_up_arithmetic(
            design.plant, design.balance,
            replace(swing, max_pole_speed_rad_per_s=1e10), modulus=modulus,
            modulus_evidence=evidence,
        )


def test_two_party_gate_executor_consumes_fresh_material_without_parameter_plaintext(setup):
    design, swing, modulus, evidence = setup
    program, proof = certify_swing_up_arithmetic(
        design.plant, design.balance, swing, modulus=modulus,
        modulus_evidence=evidence,
    )
    values = {"p": .2, "v": -.4, "beta": .31, "omega": 1.7}
    materials = prepare_scalar_round(
        program, values, proof, modulus=modulus, modulus_evidence=evidence,
        round_id="issue103-test-round", step=0,
    )
    # 单方只有公开拓扑及自己的数值份额；物理/增益常量的明文不交给 executor。
    public = ScalarProgram(
        program.inputs,
        tuple((name, Fraction(0)) for name, _ in program.constants),
        program.gates, program.output,
    )
    channels = (Queue(), Queue())

    class Peer:
        def __init__(self, party):
            self.party = party

        def _send(self, kind, resource, values=()):
            channels[1 - self.party].put((kind, resource, values))

        def _receive(self, kind, resource):
            actual = channels[self.party].get(timeout=10)
            assert actual[:2] == (kind, resource)
            return actual[2]

        def exchange_product(self, resource, d, e):
            self._send("product", resource, (d, e))
            return self._receive("product", resource)

        def send_truncation(self, resource, masked):
            self._send("trunc", resource, masked)

        def receive_truncation(self, resource):
            return self._receive("trunc", resource)

        def complete_gate(self, resource):
            self._send("complete", resource)
            self._receive("complete", resource)

    executors = [
        ScalarPartyExecutor(
            public, materials[party], modulus=modulus, fractional_bits=80,
            security_parameter=80, modulus_evidence=evidence,
        ) for party in (0, 1)
    ]
    outputs = [None, None]
    errors = []

    def run(party):
        try:
            outputs[party] = executors[party].evaluate(Peer(party))
        except (AssertionError, TypeError, ValueError, RuntimeError, TimeoutError) as error:
            errors.append(error)

    threads = [Thread(target=run, args=(party,)) for party in (0, 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert not errors
    assert all(executor.consumed == 38 for executor in executors)
    context = FixedPointContext(modulus, 174, 80)
    decoded = context.decode_residue((outputs[0] + outputs[1]) % modulus)
    expected = energy_shaping_force(
        design.plant, swing, (values["p"], values["v"], values["beta"], values["omega"]),
    )
    assert abs(decoded - expected) < float(proof.bound("raw_force").error_abs) + 1e-12
    with pytest.raises(RuntimeError, match="不得重试"):
        executors[0].evaluate(Peer(0))


def test_client_rejects_real_input_just_outside_box_before_minting_material(setup):
    design, swing, modulus, evidence = setup
    program, proof = certify_swing_up_arithmetic(
        design.plant, design.balance, swing, modulus=modulus,
        modulus_evidence=evidence,
    )
    with pytest.raises(ValueError, match="p 越出"):
        prepare_scalar_round(
            program, {"p": nextafter(.5, 1.), "v": 0., "beta": 0., "omega": 0.},
            proof, modulus=modulus, modulus_evidence=evidence,
            round_id="out-of-box", step=0,
        )
