"""场景无关的固定标量算术门计划与保守定点范围证书。"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from math import isfinite
from numbers import Real
from typing import Literal, Protocol

from secure_control.crypto.beaver import (
    BeaverMultiplier,
    BeaverTripleShare,
    MaskedDifferenceShare,
    _TripleLifecycle,
)
from secure_control.crypto.fixed_point import FixedPointContext
from secure_control.crypto.primes import PrimeModulusEvidence, verify_prime_modulus
from secure_control.crypto.secret_sharing import AdditiveShare, TwoPartySharing
from secure_control.crypto.truncation import (
    MaskedTruncationShare,
    P2MaskedMessage,
    SecureTruncation,
    TruncationAuxiliaryShare,
    _MaskLifecycle,
)

ScalarOperation = Literal["add", "subtract", "multiply"]


@dataclass(frozen=True, slots=True)
class ScalarGate:
    """公开拓扑中的一项二元操作；乘法门各消耗一组 triple 和 Trunc。"""

    name: str
    operation: ScalarOperation
    left: str
    right: str


@dataclass(frozen=True, slots=True)
class ScalarProgram:
    """输入/常量名称与门次序固定，常量数值只由 Client 分享。"""

    inputs: tuple[str, ...]
    constants: tuple[tuple[str, Fraction], ...]
    gates: tuple[ScalarGate, ...]
    output: str

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for name in self.inputs:
            if not name or name in seen:
                raise ValueError("标量程序输入名称必须非空且唯一")
            seen.add(name)
        for name, value in self.constants:
            if not name or name in seen or not isinstance(value, Fraction):
                raise ValueError("标量程序常量名称或精确数值无效")
            seen.add(name)
        for gate in self.gates:
            if (not gate.name or gate.name in seen
                    or gate.operation not in {"add", "subtract", "multiply"}
                    or gate.left not in seen or gate.right not in seen):
                raise ValueError("标量程序门必须按无环拓扑次序引用已有节点")
            seen.add(gate.name)
        if self.output not in seen:
            raise ValueError("标量程序输出节点不存在")

    @property
    def multiplication_count(self) -> int:
        return sum(gate.operation == "multiply" for gate in self.gates)

    def topology_sha256(self) -> str:
        """仅散列公开连线，不把可字典猜测的秘密参数摘要给单方。"""
        payload = {
            "inputs": self.inputs,
            "constants": tuple(name for name, _ in self.constants),
            "gates": tuple((g.name, g.operation, g.left, g.right) for g in self.gates),
            "output": self.output,
        }
        return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ScalarLayerPlan:
    """仅由公开拓扑派生的乘法依赖层；材料仍保持原门次序。"""

    program_sha256: str
    layers: tuple[tuple[str, ...], ...]


def build_scalar_layer_plan(program: ScalarProgram) -> ScalarLayerPlan:
    """加减不增加通信深度，乘法增加一层，同层按原拓扑次序。"""
    if not isinstance(program, ScalarProgram):
        raise TypeError("标量层计划需要已验证程序")
    depth = {name: 0 for name in program.inputs}
    depth.update({name: 0 for name, _ in program.constants})
    layers: list[list[str]] = []
    for gate in program.gates:
        level = max(depth[gate.left], depth[gate.right])
        if gate.operation == "multiply":
            level += 1
            while len(layers) < level:
                layers.append([])
            layers[level - 1].append(gate.name)
        depth[gate.name] = level
    if any(not layer for layer in layers):
        raise ValueError("标量程序的乘法层不能有空隙")
    return ScalarLayerPlan(program.topology_sha256(), tuple(tuple(x) for x in layers))


@dataclass(frozen=True, slots=True)
class ScalarBound:
    """目标实数、执行误差及实际编码 payload 的公开绝对上界。"""

    ideal_abs: Fraction
    error_abs: Fraction
    payload_abs: int


@dataclass(frozen=True, slots=True)
class ScalarCertificate:
    """逐门整数证明；语义包络的数学依据由场景调用者负责。"""

    program_sha256: str
    fractional_bits: int
    kappa: int
    bounds: tuple[tuple[str, ScalarBound], ...]
    multiplication_bounds: tuple[tuple[str, int], ...]
    max_pretrunc_abs: int
    max_pretrunc_gate: str
    multiplication_count: int

    def bound(self, name: str) -> ScalarBound:
        return dict(self.bounds)[name]


def _ceil(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def certify_scalar_program(
    program: ScalarProgram, input_abs: Mapping[str, Fraction], *,
    modulus: int, fractional_bits: int, security_parameter: int,
    modulus_evidence: PrimeModulusEvidence | None = None,
    semantic_enclosures: Mapping[str, tuple[Fraction, Fraction]] | None = None,
) -> ScalarCertificate:
    """按每门最坏舍入两格、中心模界和 Protocol 2 的 Z<κ> 界证明。

    semantic_enclosures 中的 (目标绝对界, 多项式近似误差) 必须由调用者
    对具体程序另行证明；这里仅将其保守传播，不把采样结果当数学证书。
    """
    if not isinstance(program, ScalarProgram) or set(input_abs) != set(program.inputs):
        raise ValueError("程序与输入盒不匹配")
    if (type(fractional_bits) is not int or fractional_bits < 1
            or type(security_parameter) is not int or security_parameter < 1):
        raise ValueError("标量程序精度参数无效")
    verify_prime_modulus(modulus, modulus_evidence)
    kappa = modulus.bit_length() - security_parameter - 2
    if kappa <= fractional_bits:
        raise ValueError("Protocol 2 要求 κ>ℓ")
    context = FixedPointContext(modulus, kappa, fractional_bits)
    scale = context.scale
    max_message = (1 << (kappa - 1)) - 1
    centered_limit = (modulus - 1) // 2
    enclosures = {} if semantic_enclosures is None else dict(semantic_enclosures)
    if not set(enclosures).issubset({gate.name for gate in program.gates}):
        raise ValueError("语义包络必须对应程序门")
    bounds: dict[str, ScalarBound] = {}
    for name in program.inputs:
        limit = input_abs[name]
        if not isinstance(limit, Fraction) or limit < 0:
            raise ValueError("输入盒必须给非负精确有理界")
        payload = _ceil(limit * scale) + 1
        if payload > context.maximum_payload or payload > centered_limit:
            raise ValueError(f"{name} 的输入盒越出有符号 payload/中心模界")
        bounds[name] = ScalarBound(limit, Fraction(1, 2 * scale), payload)
    for name, value in program.constants:
        encoded = int(context.encode(value))
        bounds[name] = ScalarBound(abs(value), Fraction(1, 2 * scale), abs(encoded))
    max_pretrunc = 0
    max_gate = ""
    multiplication_bounds: list[tuple[str, int]] = []
    for gate in program.gates:
        left, right = bounds[gate.left], bounds[gate.right]
        if gate.operation == "multiply":
            pretrunc = left.payload_abs * right.payload_abs
            if pretrunc > max_message or pretrunc > centered_limit:
                raise ValueError(f"{gate.name} 的乘积超出 Protocol 2/中心模界")
            if pretrunc > max_pretrunc:
                max_pretrunc, max_gate = pretrunc, gate.name
            multiplication_bounds.append((gate.name, pretrunc))
            bound = ScalarBound(
                left.ideal_abs * right.ideal_abs,
                left.ideal_abs * right.error_abs
                + right.ideal_abs * left.error_abs
                + left.error_abs * right.error_abs
                + Fraction(2, scale),
                _ceil(Fraction(pretrunc, scale)) + 2,
            )
        else:
            bound = ScalarBound(
                left.ideal_abs + right.ideal_abs,
                left.error_abs + right.error_abs,
                left.payload_abs + right.payload_abs,
            )
        if gate.name in enclosures:
            ideal_abs, extra_error = enclosures[gate.name]
            if (not isinstance(ideal_abs, Fraction) or ideal_abs < 0
                    or not isinstance(extra_error, Fraction) or extra_error < 0):
                raise ValueError("语义包络必须为非负精确有理数")
            error = bound.error_abs + extra_error
            bound = ScalarBound(ideal_abs, error, _ceil(scale * (ideal_abs + error)) + 1)
        if bound.payload_abs > context.maximum_payload or bound.payload_abs > centered_limit:
            raise ValueError(f"{gate.name} 的输出越出有符号 payload/中心模界")
        bounds[gate.name] = bound
    return ScalarCertificate(
        program.topology_sha256(), fractional_bits, kappa,
        tuple(bounds.items()), tuple(multiplication_bounds),
        max_pretrunc, max_gate, program.multiplication_count,
    )


@dataclass(frozen=True, slots=True)
class ScalarGateMaterial:
    """单方持有一门的一次性 triple 与 Protocol 2 mask 份额。"""

    gate: str
    resource_id: str
    a: int
    b: int
    c: int
    r: int
    r_prime: int


@dataclass(frozen=True, slots=True)
class ScalarPartyMaterial:
    """一次公开 round 的单方输入、常量与 38 门材料。"""

    party: int
    round_id: str
    step: int
    program_sha256: str
    values: tuple[tuple[str, int], ...]
    gates: tuple[ScalarGateMaterial, ...]


def prepare_scalar_round(
    program: ScalarProgram, values: Mapping[str, float], certificate: ScalarCertificate,
    *, modulus: int, modulus_evidence: PrimeModulusEvidence | None,
    round_id: str, step: int,
) -> tuple[ScalarPartyMaterial, ScalarPartyMaterial]:
    """Client 每轮新鲜分享所有数值和每门材料；证书/输入先查再消耗随机量。"""
    if (program.topology_sha256() != certificate.program_sha256
            or set(values) != set(program.inputs)
            or not round_id or type(step) is not int or step < 0):
        raise ValueError("标量 round 身份或输入不匹配")
    context = FixedPointContext(modulus, certificate.kappa, certificate.fractional_bits)
    bounds = dict(certificate.bounds)
    encoded: list[tuple[str, int]] = []
    for name in program.inputs:
        value = values[name]
        if (isinstance(value, bool) or not isinstance(value, Real)
                or not isfinite(float(value))
                or abs(Fraction.from_float(float(value))) > bounds[name].ideal_abs):
            raise ValueError(f"{name} 越出已认证输入盒")
        payload = int(context.encode(value))
        if abs(payload) > bounds[name].payload_abs:
            raise ValueError(f"{name} 越出已认证输入盒")
        encoded.append((name, payload))
    encoded.extend((name, int(context.encode(value))) for name, value in program.constants)
    sharing = TwoPartySharing(modulus)
    multiplier = BeaverMultiplier(sharing)
    truncation = SecureTruncation(
        sharing, certificate.fractional_bits, modulus.bit_length() - certificate.kappa - 2,
        modulus_evidence,
    )
    party_values: list[list[tuple[str, int]]] = [[], []]
    party_gates: list[list[ScalarGateMaterial]] = [[], []]
    for name, payload in encoded:
        pair = sharing.share(payload)
        for party in (0, 1):
            party_values[party].append((name, int(pair[party].value)))
    for gate in program.gates:
        if gate.operation != "multiply":
            continue
        pair = multiplier.create_triple()
        masks = truncation.create_auxiliary()
        for party in (0, 1):
            triple, mask = pair[party], masks[party]
            party_gates[party].append(ScalarGateMaterial(
                gate.name, f"{round_id}:{gate.name}",
                int(triple.a.value), int(triple.b.value), int(triple.c.value),
                int(mask.r.value), int(mask.r_prime.value),
            ))
    return tuple(
        ScalarPartyMaterial(party, round_id, step, certificate.program_sha256,
                            tuple(party_values[party]), tuple(party_gates[party]))
        for party in (0, 1)
    )


class ScalarPeerPort(Protocol):
    """只交换掩蔽值和完成屏障；不接收对方输入或参数份额。"""

    def exchange_product(
        self, resource_id: str, d: int, e: int,
    ) -> tuple[int, int]: ...

    def send_truncation(self, resource_id: str, masked: int) -> None: ...

    def receive_truncation(self, resource_id: str) -> int: ...

    def complete_gate(self, resource_id: str) -> None: ...


class ScalarBatchPeerPort(Protocol):
    """按公开层交换遮蔽值，下一层须等待双方整层完成屏障。"""

    def exchange_layer_products(
        self, layer_index: int, resource_ids: tuple[str, ...],
        values: tuple[tuple[int, int], ...],
    ) -> tuple[tuple[int, int], ...]: ...

    def send_layer_truncations(
        self, layer_index: int, resource_ids: tuple[str, ...], values: tuple[int, ...],
    ) -> None: ...

    def receive_layer_truncations(
        self, layer_index: int, resource_ids: tuple[str, ...],
    ) -> tuple[int, ...]: ...

    def complete_layer(self, layer_index: int, resource_ids: tuple[str, ...]) -> None: ...


@dataclass(frozen=True, slots=True)
class _PendingProduct:
    lifecycle: _TripleLifecycle
    triple: BeaverTripleShare
    masked: MaskedDifferenceShare


@dataclass(frozen=True, slots=True)
class _PendingTruncation:
    product: AdditiveShare
    mask: TruncationAuxiliaryShare
    masked: MaskedTruncationShare
    lifecycle: _MaskLifecycle
    product_lifecycle: _TripleLifecycle


class ScalarPartyExecutor:
    """单方按固定拓扑执行分享算术，拒绝材料重复或错序。"""

    def __init__(
        self, program: ScalarProgram, material: ScalarPartyMaterial, *,
        modulus: int, fractional_bits: int, security_parameter: int,
        modulus_evidence: PrimeModulusEvidence | None,
    ) -> None:
        if (material.party not in (0, 1)
                or material.program_sha256 != program.topology_sha256()
                or tuple(name for name, _ in material.values)
                != (*program.inputs, *(name for name, _ in program.constants))
                or tuple(item.gate for item in material.gates)
                != tuple(gate.name for gate in program.gates if gate.operation == "multiply")
                or len({item.resource_id for item in material.gates}) != len(material.gates)
                or any(item.resource_id != f"{material.round_id}:{item.gate}"
                       for item in material.gates)):
            raise ValueError("单方标量材料与固定程序不匹配")
        self.program = program
        self.material = material
        self.sharing = TwoPartySharing(modulus)
        self.multiplier = BeaverMultiplier(self.sharing)
        self.truncation = SecureTruncation(
            self.sharing, fractional_bits, security_parameter, modulus_evidence,
        )
        self._done = False
        self.consumed = 0
        for _, share in material.values:
            self._checked_residue(share)
        for item in material.gates:
            for share in (item.a, item.b, item.c, item.r, item.r_prime):
                self._checked_residue(share)

    def _checked_residue(self, value: int) -> int:
        if type(value) is not int or not 0 <= value < self.sharing.modulus:
            raise ValueError("单方材料必须是 canonical residue")
        return value

    def _prepare_product(
        self, left: AdditiveShare, right: AdditiveShare, item: ScalarGateMaterial,
    ) -> _PendingProduct:
        lifecycle = _TripleLifecycle(self.multiplier)
        triple = BeaverTripleShare(
            AdditiveShare(item.a), AdditiveShare(item.b), AdditiveShare(item.c),
            self.material.party, lifecycle,
        )
        return _PendingProduct(lifecycle, triple,
                               self.multiplier.mask_inputs(left, right, triple))

    def _finish_product(
        self, pending: _PendingProduct, d: int, e: int,
        item: ScalarGateMaterial,
    ) -> _PendingTruncation:
        other = 1 - self.material.party
        pending.lifecycle.claim_masking(other)
        rebound = MaskedDifferenceShare(
            AdditiveShare(self._checked_residue(d)),
            AdditiveShare(self._checked_residue(e)), other, pending.lifecycle,
        )
        opened = self.multiplier.open_masked_differences(pending.masked, rebound)
        product = self.multiplier.finish(pending.triple, opened)
        lifecycle = _MaskLifecycle(self.truncation)
        mask = TruncationAuxiliaryShare(
            AdditiveShare(item.r), AdditiveShare(item.r_prime),
            self.material.party, lifecycle,
        )
        return _PendingTruncation(
            product, mask, self.truncation.mask_input(product, mask), lifecycle,
            pending.lifecycle,
        )

    def _p2_truncation_message(self, pending: _PendingTruncation) -> int:
        pending.lifecycle.claim_mask(0)
        outgoing = self.truncation.p2_send_masked(pending.masked)
        return int(outgoing.value.value)

    def _finish_truncation(self, pending: _PendingTruncation, incoming: int | None) -> AdditiveShare:
        if self.material.party == 0:
            if incoming is None:
                raise ValueError("P1 截断消息缺失")
            pending.lifecycle.claim_mask(1)
            pending.lifecycle.claim_p2_send()
            centered = self.truncation.p1_reconstruct_masked(
                pending.masked,
                P2MaskedMessage(AdditiveShare(self._checked_residue(incoming)),
                                pending.lifecycle),
            )
            return self.truncation.finish_p1(pending.product, pending.mask, centered)
        if incoming is not None:
            raise ValueError("P2 不接收截断消息")
        pending.lifecycle.claim_p1_reconstruction()
        return self.truncation.finish_p2(pending.product, pending.mask)

    def _complete_gate(self, pending: _PendingTruncation) -> None:
        other = 1 - self.material.party
        pending.product_lifecycle.claim_finish(other)
        pending.lifecycle.claim_finish(other)
        self.consumed += 1

    def evaluate(self, peer: ScalarPeerPort) -> int:
        """每门完成双向遮蔽、P2→P1 截断与双完成屏障后才继续。"""
        if self._done:
            raise RuntimeError("同一标量 round 不得重试或重复消费材料")
        self._done = True
        nodes = {name: AdditiveShare(value) for name, value in self.material.values}
        materials = iter(self.material.gates)
        for gate in self.program.gates:
            left, right = nodes[gate.left], nodes[gate.right]
            if gate.operation == "add":
                nodes[gate.name] = self.sharing.add(left, right)
                continue
            if gate.operation == "subtract":
                nodes[gate.name] = self.sharing.subtract(left, right)
                continue
            item = next(materials)
            pending = self._prepare_product(left, right, item)
            d, e = peer.exchange_product(
                item.resource_id, int(pending.masked.d.value), int(pending.masked.e.value),
            )
            truncation = self._finish_product(pending, d, e, item)
            if self.material.party == 0:
                result = self._finish_truncation(
                    truncation, peer.receive_truncation(item.resource_id),
                )
            else:
                peer.send_truncation(item.resource_id,
                                     self._p2_truncation_message(truncation))
                result = self._finish_truncation(truncation, None)
            peer.complete_gate(item.resource_id)
            self._complete_gate(truncation)
            nodes[gate.name] = result
        return int(nodes[self.program.output].value)

    def evaluate_batch(self, peer: ScalarBatchPeerPort) -> int:
        """独立乘法同层交换，每门仍按原资源单独 Beaver 和 Trunc。"""
        if self._done:
            raise RuntimeError("同一标量 round 不得重试或重复消费材料")
        self._done = True
        plan = build_scalar_layer_plan(self.program)
        nodes = {name: AdditiveShare(value) for name, value in self.material.values}
        gates = {gate.name: gate for gate in self.program.gates}
        materials = {item.gate: item for item in self.material.gates}

        def local_closure() -> None:
            for gate in self.program.gates:
                if gate.operation == "multiply" or gate.name in nodes:
                    continue
                if gate.left not in nodes or gate.right not in nodes:
                    continue
                left, right = nodes[gate.left], nodes[gate.right]
                nodes[gate.name] = (self.sharing.add(left, right)
                                    if gate.operation == "add"
                                    else self.sharing.subtract(left, right))

        for layer_index, layer in enumerate(plan.layers):
            local_closure()
            items = tuple(materials[name] for name in layer)
            ids = tuple(item.resource_id for item in items)
            pending = tuple(self._prepare_product(nodes[gates[name].left],
                                                  nodes[gates[name].right], item)
                            for name, item in zip(layer, items, strict=True))
            outgoing = tuple((int(item.masked.d.value), int(item.masked.e.value))
                             for item in pending)
            incoming = peer.exchange_layer_products(layer_index, ids, outgoing)
            if len(incoming) != len(layer) or any(
                not isinstance(pair, tuple) or len(pair) != 2
                for pair in incoming
            ):
                raise ValueError("乘法层批次 shape 与公开计划不匹配")
            # 整层先验证完毕，不能在一个坏值之前消费有效前缀。
            for pair in incoming:
                self._checked_residue(pair[0])
                self._checked_residue(pair[1])
            truncations = tuple(self._finish_product(started, pair[0], pair[1], item)
                                for started, pair, item in zip(pending, incoming, items,
                                                               strict=True))
            if self.material.party == 0:
                received = peer.receive_layer_truncations(layer_index, ids)
                if len(received) != len(layer):
                    raise ValueError("截断层批次缺项")
                for value in received:
                    self._checked_residue(value)
                results = tuple(self._finish_truncation(item, value)
                                for item, value in zip(truncations, received, strict=True))
            else:
                values = tuple(self._p2_truncation_message(item) for item in truncations)
                peer.send_layer_truncations(layer_index, ids, values)
                results = tuple(self._finish_truncation(item, None)
                                for item in truncations)
            peer.complete_layer(layer_index, ids)
            for name, item, value in zip(layer, truncations, results, strict=True):
                self._complete_gate(item)
                nodes[name] = value
        local_closure()
        if self.program.output not in nodes or self.consumed != len(materials):
            raise ValueError("标量层计划未完成全部公开门")
        return int(nodes[self.program.output].value)
