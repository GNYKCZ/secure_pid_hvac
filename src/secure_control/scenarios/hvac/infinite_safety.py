"""装配固定参考、局部未饱和的 2R2C 量化闭环无限时域安全证书。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from secure_control.core import (
    ControllerScaleMetadata,
    ControllerSpec,
    EllipsoidalInvariantWitness,
    InvariantVerificationReport,
    LinearSafetyConstraint,
    RationalBox,
    RationalValue,
    RobustAffineInvariantProblem,
    invariant_certificate_sha256,
    verify_ellipsoidal_invariant,
)
from secure_control.crypto import (
    FixedPointContext,
    PrimeModulusEvidence,
    PrimeModulusVerification,
    verify_prime_modulus,
)
from secure_control.protocol import (
    ClosedLoopAffineComposition,
    ClosedLoopRangeEvidence,
    ControllerLayout,
    ControllerRangeContract,
    ControllerScaleLedger,
    closed_loop_composition_sha256,
    controller_payload_fingerprint,
)

from .contract import Hvac2R2CModelContract, load_hvac_scenario_contract
from .integration import _parse_modulus_evidence
from .plant import build_hvac_2r2c_state_space
from .stability import HvacClosedLoopStabilityReport, analyze_hvac_closed_loop_stability
from .tuning import load_hvac_pid_tuning_contract

_MAX_CONFIG_BYTES = 1 << 20


@dataclass(frozen=True, slots=True)
class HvacInfiniteSafetyProfile:
    """保存单个 ``ell`` 的控制器、闭环证据及来源指纹。"""

    fractional_bits: int
    integer_bits: int
    security_parameter: int
    kappa: int
    fixed_point: FixedPointContext
    controller: ControllerSpec
    range_contract: ControllerRangeContract
    invariant_report: InvariantVerificationReport
    prime_verification: PrimeModulusVerification
    modulus_evidence: PrimeModulusEvidence
    model_sha256: str
    float_hex_snapshot: tuple[str, ...]
    state_accumulator_bounds: tuple[int, ...]
    output_accumulator_bounds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class HvacInfiniteSafetyBundle:
    """保存四个冻结精度点和共同的适用假设及声明边界。"""

    scenario_id: str
    profiles: tuple[HvacInfiniteSafetyProfile, ...]
    source_hashes: tuple[tuple[str, str], ...]
    stability_report: HvacClosedLoopStabilityReport
    stability_report_sha256: str
    assumptions: tuple[str, ...]
    claim_boundary: str


def load_hvac_infinite_safety_bundle(
    config_path: str | Path,
) -> HvacInfiniteSafetyBundle:
    """严格读取 #38 配置，重建二进制浮点模型并精确复验四个证书。"""
    path = Path(config_path).resolve()
    try:
        source = path.read_bytes()
    except OSError as error:
        raise ValueError("无法读取 HVAC 无限时域安全配置") from error
    if len(source) > _MAX_CONFIG_BYTES:
        raise ValueError("HVAC 无限时域安全配置超过大小限制")
    try:
        loaded = yaml.safe_load(source.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("HVAC 无限时域安全配置不是有效 UTF-8 YAML") from error
    if not isinstance(loaded, Mapping):
        raise TypeError("HVAC 无限时域安全配置根节点必须是映射")
    required = {
        "schema_version",
        "scenario_id",
        "sources",
        "upstream_stability",
        "fixed_assumptions",
        "security",
        "witnesses",
        "claim_boundary",
    }
    if set(loaded) != required or loaded["schema_version"] != 1:
        raise ValueError("HVAC 无限时域安全配置字段或 schema_version 无效")
    scenario_id = _nonempty_string(loaded["scenario_id"], "scenario_id")
    claim_boundary = _nonempty_string(loaded["claim_boundary"], "claim_boundary")
    source_paths, source_hashes = _validated_sources(path.parent, loaded["sources"])

    stability_source = _mapping(loaded["upstream_stability"], "upstream_stability")
    if set(stability_source) != {
        "references_celsius",
        "boundary_tolerance",
        "report_sha256",
    }:
        raise ValueError("upstream_stability 字段无效")
    stability_references = tuple(
        _fraction(value, "upstream_stability.references_celsius")
        for value in stability_source["references_celsius"]
    )
    if stability_references != (Fraction(15), Fraction(20), Fraction(25)):
        raise ValueError("#37 stability references 必须冻结为 15/20/25°C")
    boundary_tolerance = _fraction(
        stability_source["boundary_tolerance"],
        "upstream_stability.boundary_tolerance",
    )
    if boundary_tolerance != Fraction(1, 1_000_000_000):
        raise ValueError("#37 boundary tolerance 必须冻结为 1e-9")
    raw_stability_report = analyze_hvac_closed_loop_stability(
        source_paths["plant"],
        source_paths["pid"],
        references_celsius=tuple(float(value) for value in stability_references),
        boundary_tolerance=float(boundary_tolerance),
    )
    if (
        raw_stability_report.schur.status != "stable"
        or any(item.applicability != "applicable" for item in raw_stability_report.equilibria)
        or raw_stability_report.plant_source_sha256
        != sha256(source_paths["plant"].read_bytes()).hexdigest()
        or raw_stability_report.pid_source_sha256
        != sha256(source_paths["pid"].read_bytes()).hexdigest()
    ):
        raise ValueError("#37 完整 stability report 与 #38 来源或适用性不一致")
    # #37 报告原始哈希忠实记录本地文件字节；#38 的长期内容身份改用已验证的规范文本
    # 哈希，避免 Windows CRLF 与 POSIX LF 让同一 Git 内容得到不同证书。
    stability_report = replace(
        raw_stability_report,
        plant_source_sha256=source_hashes["plant"],
        pid_source_sha256=source_hashes["pid"],
    )
    stability_payload = json.dumps(
        asdict(stability_report),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    stability_report_sha256 = sha256(stability_payload).hexdigest()
    if stability_report_sha256 != _nonempty_string(
        stability_source["report_sha256"], "upstream_stability.report_sha256"
    ):
        raise ValueError("#37 完整 stability report SHA-256 不匹配")

    contract = load_hvac_scenario_contract(source_paths["plant"])
    if not isinstance(contract.model, Hvac2R2CModelContract):
        raise TypeError("无限时域 HVAC 证书只接受冻结 2R2C plant")
    design, _, _ = load_hvac_pid_tuning_contract(source_paths["pid"], contract)
    plant = build_hvac_2r2c_state_space(contract.model, contract.timing.sampling_period_seconds)
    base_controller = design.to_controller_spec()

    assumptions = _mapping(loaded["fixed_assumptions"], "fixed_assumptions")
    expected_assumptions = {
        "reference_celsius",
        "ambient_celsius",
        "continues_forever",
        "strictly_unsaturated",
        "actuator_lower_kw",
        "actuator_upper_kw",
        "controller_input_abs_bound_celsius",
        "controller_state_abs_bounds",
        "air_temperature_bounds_celsius",
        "wall_temperature_bounds_celsius",
        "initial_half_width",
        "actuation_decode_abs_error_kw",
        "plant_roundoff_abs_error_celsius",
        "state_truncation_abs_error",
    }
    if set(assumptions) != expected_assumptions:
        raise ValueError("fixed_assumptions 字段无效")
    reference = _fraction(assumptions["reference_celsius"], "reference_celsius")
    ambient = _fraction(assumptions["ambient_celsius"], "ambient_celsius")
    if assumptions.get("continues_forever") is not True:
        raise ValueError("continues_forever 必须明确为 true")
    if assumptions.get("strictly_unsaturated") is not True:
        raise ValueError("strictly_unsaturated 必须明确为 true")
    if reference != 25 or ambient != 30:
        raise ValueError("#38 冻结工作点必须是 reference=25°C、ambient=30°C")
    if Fraction.from_float(contract.model.ambient_temperature_celsius) != ambient:
        raise ValueError("配置 ambient 与冻结 plant 不一致")

    security = _mapping(loaded["security"], "security")
    if set(security) != {
        "fractional_bits",
        "integer_headroom_bits",
        "security_parameter",
    }:
        raise ValueError("security 字段无效")
    fractional_bits = _integer_tuple(security["fractional_bits"], "fractional_bits")
    if fractional_bits != (32, 40, 48, 56):
        raise ValueError("#38 只接受已验证扫描的 ell=32/40/48/56")
    headroom = _positive_integer(security["integer_headroom_bits"], "integer_headroom_bits")
    security_parameter = _positive_integer(security["security_parameter"], "security_parameter")
    if headroom != 28 or security_parameter != 80:
        raise ValueError("#38 的 k 与 lambda 必须沿用已验证扫描")
    plant_roundoff = tuple(
        _fraction(value, "plant_roundoff_abs_error_celsius")
        for value in assumptions["plant_roundoff_abs_error_celsius"]
    )
    if plant_roundoff != (Fraction(0), Fraction(0)):
        raise ValueError("当前冻结模型只接受显式为零的 plant roundoff 假设")
    if _fraction(assumptions["state_truncation_abs_error"], "state_truncation_abs_error") != 0:
        raise ValueError("整数 A/B 路径的 state Trunc 误差必须为零")
    if _fraction(assumptions["actuator_lower_kw"], "actuator_lower_kw") != Fraction.from_float(
        contract.model.lower_control_bound_kw
    ) or _fraction(assumptions["actuator_upper_kw"], "actuator_upper_kw") != Fraction.from_float(
        contract.model.upper_control_bound_kw
    ):
        raise ValueError("证书 actuator bounds 与冻结 plant 不一致")

    prime_loaded = yaml.safe_load(source_paths["prime"].read_text(encoding="utf-8"))
    prime_mapping = _mapping(prime_loaded, "prime source")
    if set(prime_mapping) != {"modulus", "evidence"}:
        raise ValueError("prime source 字段无效")
    modulus = _positive_integer(prime_mapping["modulus"], "modulus")
    modulus_evidence = _parse_modulus_evidence(prime_mapping["evidence"])
    prime_verification = verify_prime_modulus(modulus, modulus_evidence)
    if modulus.bit_length() != 256:
        raise ValueError("#38 只接受冻结的 256-bit 素数")
    expected_kappa = modulus.bit_length() - security_parameter - 2

    witnesses = _mapping(loaded["witnesses"], "witnesses")
    if set(witnesses) != {str(ell) for ell in fractional_bits}:
        raise ValueError("witnesses 必须逐项覆盖 ell=32/40/48/56")
    profiles = tuple(
        _build_profile(
            ell,
            ell + headroom,
            security_parameter,
            expected_kappa,
            modulus,
            prime_verification,
            modulus_evidence,
            plant,
            base_controller,
            reference,
            ambient,
            assumptions,
            _mapping(witnesses[str(ell)], f"witnesses.{ell}"),
        )
        for ell in fractional_bits
    )
    for name, source_path in source_paths.items():
        current_hash = sha256(source_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if current_hash != source_hashes[name]:
            raise ValueError(f"sources.{name} 在证书装配期间发生变化")
    if path.read_bytes() != source:
        raise ValueError("HVAC 无限时域安全配置在解析期间发生变化")
    return HvacInfiniteSafetyBundle(
        scenario_id,
        profiles,
        tuple(sorted(source_hashes.items())),
        stability_report,
        stability_report_sha256,
        (
            "reference 固定为 25°C 且从证书初态起无限持续",
            "ambient 固定为 30°C，2R2C plant 与 PID 来源哈希保持不变",
            "控制始终严格位于 0–12 kW，因而不进入 saturation 切换",
            "输入编码误差不超过半 LSB；整数 A/B 路径的 state Trunc 误差为零",
            "actuation decode 误差受配置界约束，plant binary64 roundoff 在模型中声明为零",
        ),
        claim_boundary,
    )


def _build_profile(
    ell: int,
    integer_bits: int,
    security_parameter: int,
    kappa: int,
    modulus: int,
    prime_verification: PrimeModulusVerification,
    modulus_evidence: PrimeModulusEvidence,
    plant,
    base_controller: ControllerSpec,
    reference: Fraction,
    ambient: Fraction,
    assumptions: Mapping[str, Any],
    template: Mapping[str, Any],
) -> HvacInfiniteSafetyProfile:
    """从实际编码矩阵装配一个精度点，不使用名义连续 PID 系数代替。"""
    fixed_point = FixedPointContext(modulus, integer_bits, ell)
    zero_scale = FixedPointContext(modulus, integer_bits, 0)
    encoded_a = np.asarray(zero_scale.encode(base_controller.A), dtype=object)
    encoded_b = np.asarray(zero_scale.encode(base_controller.B), dtype=object)
    encoded_c = np.asarray(fixed_point.encode(base_controller.C), dtype=object)
    encoded_d = np.asarray(fixed_point.encode(base_controller.D), dtype=object)
    a = _payload_matrix(encoded_a, 0)
    b = _payload_matrix(encoded_b, 0)
    c = _payload_matrix(encoded_c, ell)
    d = _payload_matrix(encoded_d, ell)
    ap = _float_matrix(plant.A_p)
    bp = _float_matrix(plant.B_p)
    ep = _float_matrix(plant.E_p)
    cp = _float_matrix(plant.C_p)

    transition = (
        (a[0][0], a[0][1], -b[0][0] * cp[0][0], -b[0][0] * cp[0][1]),
        (a[1][0], a[1][1], -b[1][0] * cp[0][0], -b[1][0] * cp[0][1]),
        (
            bp[0][0] * c[0][0],
            bp[0][0] * c[0][1],
            ap[0][0] - bp[0][0] * d[0][0] * cp[0][0],
            ap[0][1] - bp[0][0] * d[0][0] * cp[0][1],
        ),
        (
            bp[1][0] * c[0][0],
            bp[1][0] * c[0][1],
            ap[1][0] - bp[1][0] * d[0][0] * cp[0][0],
            ap[1][1] - bp[1][0] * d[0][0] * cp[0][1],
        ),
    )
    affine = (
        b[0][0] * reference,
        b[1][0] * reference,
        bp[0][0] * d[0][0] * reference + ep[0][0] * ambient,
        bp[1][0] * d[0][0] * reference + ep[1][0] * ambient,
    )
    equilibrium = _solve_linear(_identity_minus(transition), affine)
    input_error = Fraction(1, 1 << (ell + 1))
    decode_error = _fraction(
        assumptions["actuation_decode_abs_error_kw"],
        "actuation_decode_abs_error_kw",
    )
    if decode_error < Fraction(1, 1 << 48):
        raise ValueError("actuation decode 误差界小于冻结实现的保守上界")
    disturbance = (
        (b[0][0], Fraction(0)),
        (b[1][0], Fraction(0)),
        (bp[0][0] * d[0][0], bp[0][0]),
        (bp[1][0] * d[0][0], bp[1][0]),
    )
    disturbance_bounds = (input_error, decode_error)

    state_abs = tuple(
        _fraction(value, "controller_state_abs_bounds")
        for value in assumptions["controller_state_abs_bounds"]
    )
    if len(state_abs) != 2 or any(value <= 0 for value in state_abs):
        raise ValueError("controller_state_abs_bounds 必须是两个正有理数")
    input_abs = _fraction(
        assumptions["controller_input_abs_bound_celsius"],
        "controller_input_abs_bound_celsius",
    )
    if input_abs <= 0:
        raise ValueError("controller_input_abs_bound_celsius 必须为正")
    state_payload_bounds = tuple(_ceil(value * (1 << ell)) for value in state_abs)
    input_payload_bounds = (_ceil(input_abs * (1 << ell)),)
    lower_control = _fraction(assumptions["actuator_lower_kw"], "actuator_lower_kw")
    upper_control = _fraction(assumptions["actuator_upper_kw"], "actuator_upper_kw")
    air_bounds = tuple(
        _fraction(value, "air_temperature_bounds_celsius")
        for value in assumptions["air_temperature_bounds_celsius"]
    )
    wall_bounds = tuple(
        _fraction(value, "wall_temperature_bounds_celsius")
        for value in assumptions["wall_temperature_bounds_celsius"]
    )
    if (
        len(air_bounds) != 2
        or len(wall_bounds) != 2
        or air_bounds[0] >= air_bounds[1]
        or wall_bounds[0] >= wall_bounds[1]
    ):
        raise ValueError("air/wall temperature bounds 必须是严格递增的有理数对")
    raw_row = (c[0][0], c[0][1], -d[0][0], Fraction(0))
    raw_offset = d[0][0] * reference
    raw_disturbance = (d[0][0], Fraction(1))
    zero_disturbance = (Fraction(0), Fraction(0))
    constraints = (
        _constraint(
            "controller_state_payload[0]",
            (1, 0, 0, 0),
            0,
            zero_disturbance,
            -state_abs[0],
            state_abs[0],
        ),
        _constraint(
            "controller_state_payload[1]",
            (0, 1, 0, 0),
            0,
            zero_disturbance,
            -state_abs[1],
            state_abs[1],
        ),
        _constraint(
            "controller_input_payload[0]",
            (0, 0, -1, 0),
            reference,
            (1, 0),
            -input_abs,
            input_abs,
        ),
        _constraint("air_temperature", (0, 0, 1, 0), 0, zero_disturbance, *air_bounds),
        _constraint("wall_temperature", (0, 0, 0, 1), 0, zero_disturbance, *wall_bounds),
        _constraint(
            "raw_control_kw",
            raw_row,
            raw_offset,
            raw_disturbance,
            lower_control,
            upper_control,
            strict=True,
        ),
        _constraint(
            "applied_control_kw",
            raw_row,
            raw_offset,
            raw_disturbance,
            lower_control,
            upper_control,
            strict=True,
        ),
    )
    initial_half_width = _fraction(assumptions["initial_half_width"], "initial_half_width")
    if initial_half_width <= 0:
        raise ValueError("initial_half_width 必须为正")
    initial_set = RationalBox(
        tuple(_rational(value - initial_half_width) for value in equilibrium),
        tuple(_rational(value + initial_half_width) for value in equilibrium),
    )
    problem = RobustAffineInvariantProblem(
        _rational_matrix(transition),
        tuple(_rational(value) for value in affine),
        _rational_matrix(disturbance),
        tuple(_rational(value) for value in disturbance_bounds),
        initial_set,
        constraints,
        ("integral_error", "previous_error", "air_temperature", "wall_temperature"),
    )
    witness = EllipsoidalInvariantWitness(
        tuple(_rational(value) for value in equilibrium),
        _shape_matrix(template),
        _rational(_fraction(template["contraction_bound"], "contraction_bound")),
        tuple(
            _rational(_fraction(value, "disturbance_norm_bounds"))
            for value in template["disturbance_norm_bounds"]
        ),
        _rational(_fraction(template["radius"], "radius")),
        tuple(
            _rational(_fraction(value, "constraint_dual_norm_bounds"))
            for value in template["constraint_dual_norm_bounds"]
        ),
    )
    report = verify_ellipsoidal_invariant(problem, witness)
    if report.status != "certified":
        raise ValueError("HVAC 无限时域证书精确复验失败：" + ",".join(report.reason_codes))

    controller = ControllerSpec(
        A=np.asarray([[float(value) for value in row] for row in a], dtype=float),
        B=np.asarray([[float(value) for value in row] for row in b], dtype=float),
        C=np.asarray([[float(value) for value in row] for row in c], dtype=float),
        D=np.asarray([[float(value) for value in row] for row in d], dtype=float),
        x0=np.asarray([float(equilibrium[0]), float(equilibrium[1])], dtype=float),
        scale_metadata=ControllerScaleMetadata(
            state=ell, input=ell, output=2 * ell, A=0, B=0, C=ell, D=ell
        ),
    )
    if not np.array_equal(
        np.asarray(fixed_point.encode(controller.C), dtype=object), encoded_c
    ) or not np.array_equal(np.asarray(fixed_point.encode(controller.D), dtype=object), encoded_d):
        raise ValueError("量化 C/D 无法经 ControllerSpec 浮点表示稳定往返")
    layout = ControllerLayout(
        2,
        1,
        1,
        ControllerScaleLedger(ell, ell, 0, 0, ell, ell, ell, 0, 2 * ell, 2 * ell),
    )
    payloads = {
        "A": encoded_a,
        "B": encoded_b,
        "C": encoded_c,
        "D": encoded_d,
        "x0": np.asarray(fixed_point.encode(controller.x0), dtype=object),
    }
    fingerprint = controller_payload_fingerprint(payloads, layout)
    state_accumulator_bounds = tuple(
        sum(
            abs(int(encoded_a[row, column])) * state_payload_bounds[column]
            for column in range(encoded_a.shape[1])
        )
        + sum(
            abs(int(encoded_b[row, column])) * input_payload_bounds[column]
            for column in range(encoded_b.shape[1])
        )
        for row in range(encoded_a.shape[0])
    )
    output_accumulator_bounds = tuple(
        sum(
            abs(int(encoded_c[row, column])) * state_payload_bounds[column]
            for column in range(encoded_c.shape[1])
        )
        + sum(
            abs(int(encoded_d[row, column])) * input_payload_bounds[column]
            for column in range(encoded_d.shape[1])
        )
        for row in range(encoded_c.shape[0])
    )
    centered_limit = (modulus - 1) // 2
    if any(
        value > centered_limit for value in (*state_accumulator_bounds, *output_accumulator_bounds)
    ):
        raise ValueError("#38 编码 accumulator 超出 centered Z_q")
    # 公开组合记录只描述通用仿射关系：v=r-Cp*xp+w0，xp+=Ap*xp+Ep*Ta+Bp*u+Bp*w1。
    # Client 将把已安装的 A/B/C/D 代入该记录，精确重建 problem，避免证书与控制器脱节。
    composition = ClosedLoopAffineComposition(
        controller_state_indices=(0, 1),
        external_state_indices=(2, 3),
        input_state_matrix=_rational_matrix(((0, 0, -cp[0][0], -cp[0][1]),)),
        input_affine=(_rational(reference),),
        input_disturbance_matrix=_rational_matrix(((1, 0),)),
        external_transition=_rational_matrix(
            (
                (0, 0, ap[0][0], ap[0][1]),
                (0, 0, ap[1][0], ap[1][1]),
            )
        ),
        external_affine=(
            _rational(ep[0][0] * ambient),
            _rational(ep[1][0] * ambient),
        ),
        external_disturbance_matrix=_rational_matrix(((0, bp[0][0]), (0, bp[1][0]))),
        output_injection=_rational_matrix(((bp[0][0],), (bp[1][0],))),
    )
    evidence = ClosedLoopRangeEvidence(
        problem,
        witness,
        invariant_certificate_sha256(problem, witness),
        fingerprint,
        (0, 1),
        state_payload_bounds,
        input_payload_bounds,
        composition,
        closed_loop_composition_sha256(composition),
    )
    range_contract = ControllerRangeContract(
        state_payload_bounds,
        input_payload_bounds,
        closed_loop_evidence=evidence,
    )
    snapshot = {
        "transition": _fraction_payload(transition),
        "affine": _fraction_payload(affine),
        "disturbance": _fraction_payload(disturbance),
        "ell": ell,
    }
    model_sha256 = sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    float_hex = tuple(
        float(value).hex()
        for matrix in (plant.A_p, plant.B_p, plant.E_p, plant.C_p)
        for value in matrix.flat
    )
    return HvacInfiniteSafetyProfile(
        ell,
        integer_bits,
        security_parameter,
        kappa,
        fixed_point,
        controller,
        range_contract,
        report,
        prime_verification,
        modulus_evidence,
        model_sha256,
        float_hex,
        state_accumulator_bounds,
        output_accumulator_bounds,
    )


def _validated_sources(base: Path, value: Any):
    """复验 plant/PID/sweep/prime 四个规范文本哈希。"""
    sources = _mapping(value, "sources")
    if set(sources) != {"plant", "pid", "sweep", "prime"}:
        raise ValueError("sources 必须冻结 plant/pid/sweep/prime")
    paths: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    for name, raw in sources.items():
        item = _mapping(raw, f"sources.{name}")
        if set(item) != {"path", "sha256"}:
            raise ValueError(f"sources.{name} 字段无效")
        source_path = (base / _nonempty_string(item["path"], f"sources.{name}.path")).resolve()
        if source_path.parent != base.resolve():
            raise ValueError("source 路径不得逃逸配置目录")
        expected = _nonempty_string(item["sha256"], f"sources.{name}.sha256")
        actual = sha256(source_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if actual != expected:
            raise ValueError(f"sources.{name} SHA-256 不匹配")
        paths[name] = source_path
        hashes[name] = actual
    return paths, hashes


def _shape_matrix(template: Mapping[str, Any]):
    """从共同分母和整数分子读取对称有理 Lyapunov 矩阵。"""
    required = {
        "shape_denominator",
        "shape_numerators",
        "contraction_bound",
        "disturbance_norm_bounds",
        "radius",
        "constraint_dual_norm_bounds",
    }
    if set(template) != required:
        raise ValueError("witness 字段无效")
    denominator = _positive_integer(template["shape_denominator"], "shape_denominator")
    rows = template["shape_numerators"]
    if (
        not isinstance(rows, list)
        or len(rows) != 4
        or any(not isinstance(row, list) or len(row) != 4 for row in rows)
    ):
        raise ValueError("shape_numerators 必须是 4x4 整数矩阵")
    return tuple(
        tuple(_rational(Fraction(_integer(value, "shape numerator"), denominator)) for value in row)
        for row in rows
    )


def _constraint(name, row, offset, disturbance, lower, upper, strict=False):
    return LinearSafetyConstraint(
        name,
        tuple(_rational(Fraction(value)) for value in row),
        _rational(Fraction(offset)),
        tuple(_rational(Fraction(value)) for value in disturbance),
        _rational(Fraction(lower)),
        _rational(Fraction(upper)),
        strict,
    )


def _payload_matrix(payload: np.ndarray, bits: int):
    scale = 1 << bits
    return tuple(
        tuple(Fraction(int(payload[row, column]), scale) for column in range(payload.shape[1]))
        for row in range(payload.shape[0])
    )


def _float_matrix(matrix: np.ndarray):
    return tuple(tuple(Fraction.from_float(float(value)) for value in row) for row in matrix)


def _identity_minus(matrix):
    return tuple(
        tuple(Fraction(int(row == column)) - matrix[row][column] for column in range(len(matrix)))
        for row in range(len(matrix))
    )


def _solve_linear(matrix, vector):
    """用精确 Gauss-Jordan 消元求唯一平衡点。"""
    size = len(vector)
    work = [list(matrix[row]) + [vector[row]] for row in range(size)]
    for column in range(size):
        pivot = next((row for row in range(column, size) if work[row][column]), None)
        if pivot is None:
            raise ValueError("闭环平衡方程奇异")
        work[column], work[pivot] = work[pivot], work[column]
        divisor = work[column][column]
        work[column] = [value / divisor for value in work[column]]
        for row in range(size):
            if row == column:
                continue
            factor = work[row][column]
            work[row] = [a - factor * b for a, b in zip(work[row], work[column])]
    return tuple(row[-1] for row in work)


def _rational(value: Fraction) -> RationalValue:
    return RationalValue(value.numerator, value.denominator)


def _rational_matrix(matrix):
    return tuple(tuple(_rational(value) for value in row) for row in matrix)


def _fraction_payload(value):
    if isinstance(value, Fraction):
        return [value.numerator, value.denominator]
    return [_fraction_payload(item) for item in value]


def _fraction(value: Any, name: str) -> Fraction:
    if isinstance(value, bool):
        raise TypeError(f"{name} 必须是有理数")
    try:
        result = Fraction(value)
    except (TypeError, ValueError, ZeroDivisionError) as error:
        raise ValueError(f"{name} 必须是有理数字符串或整数") from error
    return result


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{name} 必须是字符串键映射")
    return value


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{name} 必须是非空字符串")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} 必须是整数")
    return value


def _positive_integer(value: Any, name: str) -> int:
    result = _integer(value, name)
    if result <= 0:
        raise ValueError(f"{name} 必须是正整数")
    return result


def _integer_tuple(value: Any, name: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise TypeError(f"{name} 必须是非空整数数组")
    return tuple(_positive_integer(item, name) for item in value)


def _ceil(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)
