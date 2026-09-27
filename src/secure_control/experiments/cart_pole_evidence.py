"""倒立摆正式侧证据：在 canonical artifact 上重放模型与控制语义。"""

from __future__ import annotations

import json
from dataclasses import asdict
from fractions import Fraction
from math import isfinite
from pathlib import Path

import numpy as np
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure

from secure_control.crypto import (
    FixedPointContext,
    PrimeModulusEvidence,
    TwoPartySharing,
)
from secure_control.protocol import Client
from secure_control.protocol.messages import _PROTOCOL3_TERM_ORDER
from secure_control.scenarios.cart_pole.adapter import MeasurementSample, _disturbance_plan
from secure_control.scenarios.cart_pole.contract import CartPoleContract
from secure_control.scenarios.cart_pole.controller import (
    CartPoleBalanceConfig,
    build_cart_pole_controller_spec,
)
from secure_control.scenarios.cart_pole.experiment import BalanceMonitor
from secure_control.scenarios.cart_pole.interactive import PULSE_FORCE_N, PULSE_PHASE
from secure_control.scenarios.cart_pole.observer import (
    CartPoleObserverConfig,
    build_cart_pole_observer_design,
)
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_experiment import (
    CartPoleObserverSecureExperiment,
    CartPoleSecureExperiment,
    cart_pole_observer_numeric_contract,
)

from .artifacts import ExperimentRecord, _digest, _read_json, load_artifacts
from .paper_pid_sources import parse_prime_certificate

EVIDENCE_NAME = "cart_pole_evidence.json"
MOTION_NAME = "cart_pole_motion.png"
MOTION_MANIFEST_NAME = "cart_pole_motion_plot.json"
DISTURBANCE_POLICY = {
    "kind": "horizontal_cart_force_pulse", "force_n": PULSE_FORCE_N,
    "duration_steps": 1, "phase": PULSE_PHASE,
}


def _numeric_array(value: object, shape: tuple[int, ...]) -> np.ndarray:
    """保留 JSON 数值类型，避免 bool 在 NumPy 转换时变成 0/1。"""
    def matches(items: object, dimensions: tuple[int, ...]) -> bool:
        if not isinstance(items, list) or len(items) != dimensions[0]:
            return False
        if len(dimensions) == 1:
            return all(type(item) in (int, float) for item in items)
        return all(matches(item, dimensions[1:]) for item in items)

    if not matches(value, shape):
        raise ValueError("倒立摆证据数值数组 shape 或类型无效。")
    array = np.asarray(value, dtype=np.float64)
    if not np.isfinite(array).all():
        raise ValueError("倒立摆证据数值数组必须有限。")
    return array


def _clean_certificate(value: object) -> dict:
    """将 JSON 证书中 dataclass 的 None 子证书恢复为原解析器的省略字段。"""
    if not isinstance(value, dict) or set(value) != {"candidate", "factors"}:
        raise ValueError("倒立摆素数证书无效。")
    factors = []
    for entry in value["factors"]:
        if not isinstance(entry, dict) or set(entry) != {
            "prime", "exponent", "witness", "certificate"
        }:
            raise ValueError("倒立摆素数因子证据无效。")
        item = {name: entry[name] for name in ("prime", "exponent", "witness")}
        if entry["certificate"] is not None:
            item["certificate"] = _clean_certificate(entry["certificate"])
        factors.append(item)
    return {"candidate": value["candidate"], "factors": factors}


def _observer_prime_evidence(value: object) -> PrimeModulusEvidence | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "method", "source", "source_version", "certificate_id", "certificate_sha256",
        "certificate",
    }:
        raise ValueError("倒立摆公开素数证据字段无效。")
    return PrimeModulusEvidence(
        value["method"], value["source"], value["source_version"],
        value["certificate_id"], value["certificate_sha256"],
        parse_prime_certificate(_clean_certificate(value["certificate"])),
    )


def _json_normal(value: object) -> object:
    """与正式 JSON 相同地规范 tuple/list，以便严格对照重派生记录。"""
    return json.loads(json.dumps(value, allow_nan=False))


def _verify_observer_resources(record: ExperimentRecord, spec, context, contract) -> None:
    """重新运行 canonical 数值预检并核对每轮双提交资源身份和实耗。"""
    config, provenance = record.effective_config, record.provenance
    client = Client(
        context, TwoPartySharing(config["q"]),
        security_parameter=config["security_parameter"],
        modulus_evidence=_observer_prime_evidence(config.get("prime_evidence")),
    )
    distribution = client.distribute_controller(spec, contract)
    proof = config["range"]["proof"]
    if (proof.get("range_verification") != _json_normal(asdict(client.range_verification))
            or provenance.get("range_verification")
            != _json_normal(asdict(client.range_verification))
            or provenance.get("prime_verification")
            != _json_normal(asdict(client.truncation.modulus_verification))
            or provenance.get("scale_ledger")
            != _json_normal(asdict(distribution.p1.layout.scale_ledger))):
        raise ValueError("倒立摆动态范围、素数或尺度证据与重新预检不符。")
    n = contract.horizon_steps
    elapsed = provenance.get("wall_elapsed_ms")
    if type(elapsed) not in (int, float) or not isfinite(elapsed) or elapsed <= 0:
        raise ValueError("倒立摆动态墙钟耗时字段无效。")
    layout = distribution.p1.layout
    state, inputs, outputs = (layout.state_dimension, layout.input_dimension,
                              layout.output_dimension)
    shapes = {"A": (state, state), "B": (state, inputs),
              "C": (outputs, state), "D": (outputs, inputs)}
    products = sum(rows * cols for rows, cols in shapes.values())
    truncations = layout.state_dimension if layout.scale_ledger.state_truncation_bits else 0
    confirmed = provenance.get("confirmed_steps")
    rounds = provenance.get("round_ledger")
    if (type(n) is not int or not isinstance(confirmed, list) or len(confirmed) != n
            or not isinstance(rounds, list) or len(rounds) != n
            or provenance.get("resource_counts") != {
                "products_consumed": products * n,
                "truncations_consumed": truncations * n,
            } or truncations == 0):
        raise ValueError("倒立摆动态资源实耗或轮次长度无效。")
    seen = set()
    for step, (count, round_record) in enumerate(zip(confirmed, rounds, strict=True)):
        if count != {"step": step, "status": "double_committed",
                     "products": products, "truncations": truncations}:
            raise ValueError("倒立摆动态逐步双提交实耗不符。")
        if not isinstance(round_record, dict) or set(round_record) != {
            "step", "round_id", "product_resource_ids", "truncation_resource_ids"
        } or type(round_record["step"]) is not int or round_record["step"] != step:
            raise ValueError("倒立摆动态轮次身份无效。")
        round_id = round_record["round_id"]
        if not isinstance(round_id, str) or not round_id or round_id in seen:
            raise ValueError("倒立摆动态轮次身份重复或为空。")
        seen.add(round_id)
        expected_products = [f"{round_id}:{term}[{row},{column}]"
                             for term in _PROTOCOL3_TERM_ORDER
                             for row in range(shapes[term][0])
                             for column in range(shapes[term][1])]
        expected_truncations = [f"{round_id}:state[{row}]" for row in range(truncations)]
        if (round_record["product_resource_ids"] != expected_products
                or round_record["truncation_resource_ids"] != expected_truncations):
            raise ValueError("倒立摆动态资源身份或顺序不符。")


def _verify_observer_evidence(record: ExperimentRecord, payload: dict) -> None:
    """重建动态设计、编码范围与公开物理前缀；秘密估计只用包络核验。"""
    config = record.effective_config
    if config.get("controller_mode") != "observer_two_measurement":
        raise ValueError("倒立摆动态控制器模式无效。")
    plant = CartPoleContract(**config["plant_contract"])
    balance = CartPoleBalanceConfig(**config["balance_config"])
    balance.validate_plant(plant)
    design = build_cart_pole_observer_design(
        plant, balance, CartPoleObserverConfig(**config["observer_config"])
    )
    snapshot = config.get("observer_design")
    if not isinstance(snapshot, dict) or {k: v for k, v in snapshot.items()
                                            if k != "source_snapshots"} != {
        k: v for k, v in _json_normal(design.to_snapshot()).items()
        if k != "source_snapshots"
    }:
        raise ValueError("倒立摆动态设计快照与三源参数不符。")
    sources = snapshot.get("source_snapshots")
    if (not isinstance(sources, list) or len(sources) != 3
            or {item.get("role"): item.get("sha256") for item in sources
                if isinstance(item, dict)} != {
                    "observer": config.get("observer_source_sha256"),
                    "plant": config.get("plant_source_sha256"),
                    "balance": config.get("balance_source_sha256"),
                }):
        raise ValueError("倒立摆动态三源身份快照不符。")
    # 摘要仅关联来源身份；快照中的原始 YAML 也必须与重建设计的参数一致。
    by_role = {item["role"]: item for item in sources}
    for role, parameters in (
        ("plant", config["plant_contract"]), ("balance", config["balance_config"]),
        ("observer", config["observer_config"]),
    ):
        source = by_role[role]
        if (set(source) != {"role", "filename", "sha256", "yaml"}
                or not isinstance(source["filename"], str) or not source["filename"]
                or not isinstance(source["sha256"], str) or len(source["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in source["sha256"])):
            raise ValueError("倒立摆动态三源快照字段无效。")
        original = source["yaml"]
        expected = {"schema_version": 1, "scenario": "cart_pole", **parameters}
        if role == "observer" and isinstance(original, dict):
            for field, dependency in (("plant_source", "plant"), ("balance_source", "balance")):
                reference = original.get(field)
                if (not isinstance(reference, str)
                        or Path(reference).name != by_role[dependency]["filename"]):
                    raise ValueError("倒立摆动态来源引用不符。")
                expected[field] = reference
        if original != _json_normal(expected):
            raise ValueError("倒立摆动态来源 YAML 与有效参数不符。")
    initial = config["initialization"]
    first = MeasurementSample(**initial["first_measurement"])
    truth0 = CartPolePlant(plant).output()
    if (first.sample_id != 0 or first.time_s != 0
            or first.p_m != truth0[0] or first.theta_rad != truth0[2]):
        raise ValueError("倒立摆动态首样本不是物理初态的两测量。")
    initialization = design.initialize(first, tuple(initial["velocity_seed"]))
    if initial != {
        "first_measurement": _json_normal(asdict(first)),
        "branch": initialization.branch, "theta_star": initialization.theta_star,
        "velocity_seed": list(initialization.velocity_seed),
        "initial_error_abs": list(initialization.initial_error_abs),
        "y_abs": list(initialization.y_abs),
    }:
        raise ValueError("倒立摆动态首测量、chart 或 seed 快照不符。")
    local0 = truth0.copy()
    local0[2] -= initialization.theta_star
    if (np.any(np.abs(local0) > np.asarray(balance.safe_abs))
            or np.any(np.abs(local0 - initialization.spec.x0)
                      > np.asarray(initialization.initial_error_abs))):
        raise ValueError("倒立摆动态初态不满足公开工作域/估计前提。")
    spec = initialization.spec
    if config.get("controller_spec") != {
        name: getattr(spec, name).tolist() for name in ("A", "B", "C", "D", "x0")
    }:
        raise ValueError("倒立摆动态控制器与设计不符。")
    context, contract, expected_proof = cart_pole_observer_numeric_contract(
        initialization, balance.horizon_steps,
        fractional_bits=config["fractional_bits"],
        parameter_bits=config["paper_parameter_bits"],
        runtime_payload_bits=config["runtime_payload_bits"], modulus=config["q"],
    )
    proof = config["range"]["proof"]
    if (config["range"].get("mode") != "finite_horizon"
            or config["range"].get("steps") != balance.horizon_steps
            or not isinstance(proof, dict)
            or {key: value for key, value in proof.items() if key != "range_verification"}
            != expected_proof):
        raise ValueError("倒立摆动态编码范围证明字段不符。")
    _verify_observer_resources(record, spec, context, contract)
    n = balance.horizon_steps
    if (payload.get("schema_version") != 3 or payload.get("run_id") != record.run_id
            or payload.get("sample_count") != n
            or payload.get("sample_period_s") != plant.sample_period_s
            or payload.get("terminal_time_s") != n * plant.sample_period_s
            or payload.get("state_units") != list(record.metadata.output.units)
            or payload.get("force_unit") != "N"
            or payload.get("raw_error") != "ideal - secure"
            or record.result.time.size != n):
        raise ValueError("倒立摆动态正式证据身份/单位/长度无效。")
    times = np.arange(n + 1) * plant.sample_period_s
    np.testing.assert_array_equal(_numeric_array(payload.get("time_s"), (n + 1,)), times)
    np.testing.assert_array_equal(record.result.time, times[:-1])
    expected_reference = np.tile(np.asarray(balance.target_state), (n + 1, 1))
    expected_reference[:, 2] += initialization.theta_star
    np.testing.assert_array_equal(_numeric_array(payload.get("reference"), (n + 1, 4)),
                                  expected_reference)
    np.testing.assert_array_equal(record.result.reference, expected_reference[:-1])
    disturbances = _disturbance_plan(config.get("disturbances"), n)
    expected_events = [{"step": step, "force_n": force, "duration_steps": 1,
                        "phase": "after_controller_commit_before_plant_step"}
                       for step, force in disturbances]
    if payload.get("events") != expected_events or set(payload.get("branches", {})) != {
        "ideal", "secure"
    }:
        raise ValueError("倒立摆动态事件或双支记录无效。")
    raw_by_branch = {}
    encoded = {name: np.asarray(context.encode(getattr(spec, name)), dtype=object)
               for name in ("A", "B", "C", "D", "x0")}
    scale = context.scale
    transition = [[Fraction(int(value), scale) for value in row] for row in encoded["A"]]
    input_matrix = [[Fraction(int(value), scale) for value in row] for row in encoded["B"]]
    ideal_estimate_record = None
    for name in ("ideal", "secure"):
        branch = payload["branches"][name]
        keys = {"observations", "measurements", "local_measurements", "raw_force_n",
                "applied_force_n", "disturbance_force_n", "requested_disturbance_n",
                "total_force_n", "force_dispositions", "statuses", "stable_counts"}
        if name == "ideal":
            keys.add("ideal_estimates")
        if not isinstance(branch, dict) or set(branch) != keys:
            raise ValueError("倒立摆动态分支字段无效。")
        observations = _numeric_array(branch["observations"], (n + 1, 4))
        measurements = _numeric_array(branch["measurements"], (n + 1, 2))
        local = _numeric_array(branch["local_measurements"], (n + 1, 2))
        raw = _numeric_array(branch["raw_force_n"], (n,))
        applied = _numeric_array(branch["applied_force_n"], (n,))
        actual = _numeric_array(branch["disturbance_force_n"], (n,))
        requested = _numeric_array(branch["requested_disturbance_n"], (n,))
        total = _numeric_array(branch["total_force_n"], (n,))
        statuses, counts = branch["statuses"], branch["stable_counts"]
        dispositions = branch["force_dispositions"]
        if (not isinstance(statuses, list) or len(statuses) != n + 1
                or not isinstance(counts, list) or len(counts) != n + 1
                or any(type(value) is not int or value < 0 for value in counts)
                or not isinstance(dispositions, list) or len(dispositions) != n):
            raise ValueError("倒立摆动态监督/执行状态长度无效。")
        np.testing.assert_array_equal(measurements, observations[:, [0, 2]])
        np.testing.assert_array_equal(local[:, 0], measurements[:, 0])
        np.testing.assert_allclose(local[:, 1], measurements[:, 1]
                                   - initialization.theta_star, rtol=0, atol=1e-14)
        if np.any(np.abs(local) > np.asarray(initialization.y_abs)):
            raise ValueError("倒立摆动态两测量超出固定 chart 工作域。")
        np.testing.assert_array_equal(getattr(record.result, f"output_{name}"), observations[:-1])
        np.testing.assert_array_equal(getattr(record.result, f"control_{name}")[:, 0], applied)
        np.testing.assert_array_equal(raw, applied)
        if np.any(np.abs(raw) > plant.max_applied_force_n):
            raise ValueError("倒立摆动态 raw 超出非饱和契约。")
        physical = CartPolePlant(plant)
        monitor = BalanceMonitor(balance)
        ideal_state = np.asarray(spec.x0).copy()
        ideal_estimates = (_numeric_array(branch["ideal_estimates"], (n + 1, 4))
                           if name == "ideal" else None)
        if ideal_estimates is not None:
            ideal_estimate_record = ideal_estimates
        nominal = [Fraction(int(value)) for value in encoded["x0"]]
        power = [[Fraction(int(row == col)) for col in range(4)] for row in range(4)]
        error = [Fraction(0) for _ in range(4)]
        for step in range(n + 1):
            np.testing.assert_allclose(physical.output(), observations[step], rtol=0, atol=1e-12)
            truth_local = observations[step].copy()
            truth_local[2] -= initialization.theta_star
            if (monitor.observe(truth_local) != statuses[step]
                    or monitor.stable_count != counts[step]):
                raise ValueError("倒立摆动态监督状态与物理轨迹不符。")
            if step == n:
                if ideal_estimates is not None:
                    np.testing.assert_array_equal(ideal_estimates[step], ideal_state)
                if statuses[step] != "stable":
                    raise ValueError("倒立摆动态终点未稳定。")
                break
            v = local[step]
            if name == "ideal":
                np.testing.assert_array_equal(ideal_estimates[step], ideal_state)
                expected_raw = float((spec.C @ ideal_state + spec.D @ v)[0])
                ideal_state = spec.A @ ideal_state + spec.B @ v
                if not np.isclose(raw[step], expected_raw, atol=1e-12, rtol=0):
                    raise ValueError("倒立摆动态理想控制递推不符。")
            else:
                v_payload = [int(value) for value in np.asarray(context.encode(v)).flat]
                numerator = (sum(int(encoded["C"][0, col]) * nominal[col]
                                 for col in range(4))
                             + sum(int(encoded["D"][0, col]) * v_payload[col]
                                   for col in range(2)))
                center = float(numerator / (scale * scale))
                radius = float(sum(abs(int(encoded["C"][0, col])) * error[col]
                                   for col in range(4)) / (scale * scale))
                if abs(raw[step] - center) > radius + 1e-12:
                    raise ValueError("倒立摆动态安全 raw 超出独立定点算术包络。")
                nominal = [sum(transition[row][col] * nominal[col] for col in range(4))
                           + sum(input_matrix[row][col] * v_payload[col] for col in range(2))
                           for row in range(4)]
                error = [error[row] + sum(abs(power[row][col]) * Fraction(3, 2)
                                          for col in range(4)) for row in range(4)]
                power = [[sum(power[row][mid] * transition[mid][col] for mid in range(4))
                          for col in range(4)] for row in range(4)]
            expected_requested = dict(disturbances).get(step, 0.)
            expected_actual = (expected_requested if abs(raw[step] + expected_requested)
                               <= plant.max_applied_force_n else 0.)
            expected_disposition = ("accepted" if expected_actual == expected_requested
                                    else "rejected_total_force_limit")
            if (requested[step] != expected_requested or actual[step] != expected_actual
                    or dispositions[step] != expected_disposition
                    or total[step] != applied[step] + actual[step]
                    or abs(total[step]) > plant.max_applied_force_n):
                raise ValueError("倒立摆动态力、扰动或执行回执不符。")
            physical.step(np.array([total[step]]))
        raw_by_branch[name] = raw
    np.testing.assert_array_equal(_numeric_array(payload.get("raw_force_error_n"), (n,)),
                                  raw_by_branch["ideal"] - raw_by_branch["secure"])
    ideal_truth = _numeric_array(payload["branches"]["ideal"]["observations"], (n + 1, 4))
    ideal_truth[:, 2] -= initialization.theta_star
    metrics = {
        "ideal_estimation_error_max_abs_si": np.max(
            np.abs(ideal_truth - ideal_estimate_record), axis=0
        ).tolist(),
        "branch_state_difference_max_abs_si": np.max(
            np.abs(record.result.output_error), axis=0
        ).tolist(),
        "raw_force_difference_max_abs_n": float(np.max(np.abs(
            raw_by_branch["ideal"] - raw_by_branch["secure"]
        ))),
        "secure_raw_peak_abs_n": float(np.max(np.abs(raw_by_branch["secure"]))),
    }
    if payload.get("metrics") != metrics:
        raise ValueError("倒立摆动态估计/算术/物理指标与已验证轨迹不符。")


def verify_cart_pole_evidence(record: object, run_dir: Path) -> None:
    """从正式 CSV 和物理配置重放两支，核对 raw→applied 与 N+1 状态。"""
    if not isinstance(record, ExperimentRecord) or record.metadata.name != "cart_pole":
        raise ValueError("倒立摆证据需要已验证的场景记录。")
    payload = json.loads((run_dir / EVIDENCE_NAME).read_text(encoding="utf-8"),
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    if not isinstance(payload, dict):
        raise TypeError("倒立摆证据必须是 JSON 对象。")
    config = record.effective_config
    if config.get("scenario") == {"name": "cart_pole", "version": "4"}:
        _verify_observer_evidence(record, payload)
        return
    plant_contract = CartPoleContract(**config["plant_contract"])
    balance = CartPoleBalanceConfig(**config["balance_config"])
    spec = build_cart_pole_controller_spec(plant_contract, balance)
    if config.get("controller_spec") != {
        name: getattr(spec, name).tolist() for name in ("A", "B", "C", "D", "x0")
    }:
        raise ValueError("倒立摆控制器与物理/平衡来源不一致。")
    context = FixedPointContext(config["q"], config["runtime_payload_bits"],
                                config["fractional_bits"])
    encoded_d = np.asarray(context.encode(spec.D), dtype=object).reshape(4)
    n = balance.horizon_steps
    scenario = config.get("scenario")
    version = scenario.get("version") if isinstance(scenario, dict) else None
    if version == "1":
        if payload.get("schema_version") != 1 or any(
            name in payload for name in ("disturbance_force_n", "events")
        ):
            raise ValueError("无扰倒立摆证据版本不一致。")
        disturbance = np.zeros(n, dtype=np.float64)
    elif version == "2":
        if (config.get("disturbance_policy") != DISTURBANCE_POLICY
                or type(payload.get("schema_version")) is not int
                or payload["schema_version"] != 2):
            raise ValueError("有扰倒立摆证据版本或策略不一致。")
        disturbance = _numeric_array(payload.get("disturbance_force_n"), (n,))
        if any(force not in (-PULSE_FORCE_N, 0.0, PULSE_FORCE_N)
               for force in disturbance):
            raise ValueError("倒立摆外力仅允许单步 ±1 N 脉冲。")
        events = payload.get("events")
        expected_events = [
            {"step": index, "force_n": float(force), "duration_steps": 1,
             "phase": PULSE_PHASE}
            for index, force in enumerate(disturbance) if force != 0
        ]
        if (not isinstance(events, list) or len(events) != len(expected_events)
                or any(not isinstance(event, dict) or set(event) != set(expected)
                       or type(event["step"]) is not int
                       or type(event["duration_steps"]) is not int
                       or type(event["force_n"]) not in (int, float)
                       or event != expected
                       for event, expected in zip(events, expected_events, strict=True))):
            raise ValueError("倒立摆事件表与逐步外力不一致。")
    else:
        raise ValueError("倒立摆场景版本无效。")
    evidence_time = _numeric_array(payload.get("time_s"), (n + 1,))
    evidence_reference = _numeric_array(payload.get("reference"), (n + 1, 4))
    if (type(payload.get("schema_version")) is not int
            or payload.get("run_id") != record.run_id
            or type(payload.get("sample_count")) is not int or payload["sample_count"] != n
            or record.result.time.size != n
            or type(payload.get("sample_period_s")) not in (int, float)
            or payload.get("sample_period_s") != plant_contract.sample_period_s
            or type(payload.get("terminal_time_s")) not in (int, float)
            or payload.get("terminal_time_s") != n * plant_contract.sample_period_s
            or evidence_time.tolist() != (np.arange(n + 1)
                                          * plant_contract.sample_period_s).tolist()
            or evidence_reference.tolist() != [list(balance.target_state) for _ in range(n + 1)]
            or payload.get("state_units") != list(record.metadata.output.units)
            or payload.get("force_unit") != "N" or payload.get("raw_error") != "ideal - secure"
            or not isinstance(payload.get("branches"), dict)
            or set(payload["branches"]) != {"ideal", "secure"}):
        raise ValueError("倒立摆证据身份、单位或步数无效。")
    expected_times = np.arange(n) * plant_contract.sample_period_s
    np.testing.assert_allclose(record.result.time, expected_times, rtol=0, atol=1e-14)
    np.testing.assert_allclose(record.result.reference,
                               evidence_reference[:n], rtol=0, atol=0)
    raw_by_branch = {}
    for name in ("ideal", "secure"):
        branch = payload["branches"][name]
        if not isinstance(branch, dict) or set(branch) != {
            "observations", "raw_force_n", "statuses", "stable_counts"
        }:
            raise ValueError("倒立摆分支证据字段无效。")
        observations = _numeric_array(branch["observations"], (n + 1, 4))
        raw = _numeric_array(branch["raw_force_n"], (n,))
        statuses = branch["statuses"]
        counts = branch["stable_counts"]
        if (not isinstance(statuses, list) or len(statuses) != n + 1
                or not isinstance(counts, list) or len(counts) != n + 1
                or any(type(value) is not int or value < 0 for value in counts)):
            raise ValueError("倒立摆证据 shape 或有限性无效。")
        outputs = getattr(record.result, f"output_{name}")
        applied = getattr(record.result, f"control_{name}")[:, 0]
        np.testing.assert_allclose(observations[:n], outputs, rtol=0, atol=0)
        np.testing.assert_allclose(np.clip(raw, -plant_contract.max_applied_force_n,
                                           plant_contract.max_applied_force_n),
                                   applied, rtol=0, atol=0)
        # 静态零维 LQR 的 raw 力可从已验证观测和公开 D 独立重算。
        # 安全支没有 state Trunc；累加器是 2ell 尺度的中心化精确整数。
        for index in range(n):
            v = outputs[index] - np.asarray(balance.target_state)
            if name == "ideal":
                expected_raw = float((spec.D @ v)[0])
            else:
                encoded_v = np.asarray(context.encode(v), dtype=object)
                accumulator = sum(int(gain) * int(value)
                                  for gain, value in zip(encoded_d, encoded_v, strict=True))
                if abs(accumulator) > (context.modulus - 1) // 2:
                    raise ValueError("倒立摆运行时输出模数回绕。")
                expected_raw = accumulator / (context.scale * context.scale)
            if not np.isclose(raw[index], expected_raw, rtol=0, atol=1e-12):
                raise ValueError("倒立摆 raw 力与控制器/观测不一致。")
        plant = CartPolePlant(plant_contract)
        monitor = BalanceMonitor(balance)
        for index in range(n + 1):
            np.testing.assert_allclose(plant.output(), observations[index], rtol=0, atol=1e-12)
            status = monitor.observe(observations[index])
            if status != statuses[index] or monitor.stable_count != counts[index]:
                raise ValueError("倒立摆稳定判定或连续计数无效。")
            if index < n:
                total = applied[index] + disturbance[index]
                if abs(total) > plant_contract.max_applied_force_n:
                    raise ValueError("倒立摆外力与控制器合力超出物理输入界。")
                plant.step(np.array([total], dtype=np.float64))
        if statuses[-1] != "stable":
            raise ValueError("倒立摆终点尚未稳定。")
        raw_by_branch[name] = raw
    raw_error = _numeric_array(payload.get("raw_force_error_n"), (n,))
    np.testing.assert_allclose(raw_error, raw_by_branch["ideal"] - raw_by_branch["secure"],
                               rtol=0, atol=0)
    np.testing.assert_allclose(record.result.control_error,
                               record.result.control_ideal - record.result.control_secure,
                               rtol=0, atol=0)


def write_cart_pole_evidence(record: object, stage: Path,
                             experiment: CartPoleSecureExperiment | CartPoleObserverSecureExperiment,
                             disturbances: tuple[float, ...] | None = None) -> tuple[str, ...]:
    """在正式 staging 写场景证据并于原子发布前进行语义重放。"""
    payload = experiment.evidence(record.run_id, record.result)
    if isinstance(experiment, CartPoleObserverSecureExperiment):
        (stage / EVIDENCE_NAME).write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        verify_cart_pole_evidence(record, stage)
        _write_motion_plot(record, payload, stage)
        _verify_motion_plot(record, stage)
        return (EVIDENCE_NAME, MOTION_NAME, MOTION_MANIFEST_NAME)
    if disturbances is not None:
        if len(disturbances) != payload["sample_count"]:
            raise ValueError("倒立摆逐步外力记录不完整。")
        payload["schema_version"] = 2
        payload["disturbance_force_n"] = list(disturbances)
        payload["events"] = [
            {"step": step, "force_n": float(force), "duration_steps": 1,
             "phase": PULSE_PHASE}
            for step, force in enumerate(disturbances) if force != 0
        ]
    (stage / EVIDENCE_NAME).write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    verify_cart_pole_evidence(record, stage)
    if disturbances is None:
        return (EVIDENCE_NAME,)
    _write_motion_plot(record, payload, stage)
    _verify_motion_plot(record, stage)
    return (EVIDENCE_NAME, MOTION_NAME, MOTION_MANIFEST_NAME)


def _motion_axes(title):
    """只创建场景运动画布；有限与长结果的 renderer 共享单位/布局。"""
    figure = Figure(figsize=(9, 6), layout="constrained")
    FigureCanvasAgg(figure)
    axes = figure.subplots(2, 1, sharex=True)
    figure.suptitle(title)
    return figure, axes


def plot_motion_overview(series, events, stable, title):
    """消费已验证、有界实际点；用固定 artist 数量表示分桶事件/稳定标记。"""
    figure, axes = _motion_axes(title)
    for axis, signal, label in zip(axes, ("p", "theta"), ("Position (m)", "Angle (rad)"),
                                   strict=True):
        for branch, color in (("ideal", "tab:blue"), ("secure", "tab:orange")):
            points = series[f"{signal}_{branch}"]
            axis.plot([p[1] for p in points], [p[2] for p in points], label=branch, color=color,
                      marker="." if len(points) == 1 else None)
        if events:
            low, high = axis.get_ylim()
            axis.vlines([p[0] for p in events], low, high, colors="tab:red", alpha=.3,
                        label="applied disturbances (bucket markers)")
        axis.set_ylabel(label)
        axis.grid(True, alpha=.3)
        axis.legend()
    if stable:
        axes[0].scatter([p[0] for p in stable], [p[1] for p in stable], s=5,
                        label="secure stable observations (bucket markers)")
    axes[1].set_xlabel("Simulation time (s) · bucket overview; raw values in playback")
    if len(series["p_secure"]) == 1:
        axes[0].text(.5, .9, "Initial observation; no control intervals", ha="center",
                     transform=axes[0].transAxes)
    return figure


def _write_motion_plot(record: ExperimentRecord, payload: dict[str, object], stage: Path) -> None:
    """仅从本次正式轨迹与已重放的侧证据画位置、摆角和事件。"""
    figure, axes = _motion_axes(f"Cart-pole motion · {record.run_id}")
    times = np.asarray(payload["time_s"])
    for name, color in (("ideal", "tab:blue"), ("secure", "tab:orange")):
        values = np.asarray(payload["branches"][name]["observations"])
        axes[0].plot(times, values[:, 0], color=color, label=f"{name} p")
        axes[1].plot(times, values[:, 2], color=color, label=f"{name} theta")
        stable = np.asarray(payload["branches"][name]["statuses"]) == "stable"
        axes[0].plot(times[stable], values[stable, 0], ".", color=color,
                     markersize=3, label=f"{name} stable observations")
    for axis, ylabel in zip(axes, ("Cart position p (m)", "Pole angle theta (rad)"),
                            strict=True):
        axis.axhline(0, color="black", linestyle="--", linewidth=.7, label="target 0")
        for event in payload["events"]:
            axis.axvline(times[event["step"]], color="tab:red", alpha=.35)
        axis.set_ylabel(ylabel)
        axis.grid(True, alpha=.3)
        axis.legend()
    axes[1].set_xlabel("Simulation time (s); red lines: applied disturbance")
    try:
        figure.savefig(stage / MOTION_NAME, dpi=160, format="png")
    finally:
        figure.clear()
    manifest = {
        "run_id": record.run_id,
        "sample_count": int(record.result.time.size),
        "trajectory_sha256": _digest(stage / "trajectory.csv"),
        "evidence_sha256": _digest(stage / EVIDENCE_NAME),
        "figure_sha256": _digest(stage / MOTION_NAME),
    }
    (stage / MOTION_MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _verify_motion_plot(record: ExperimentRecord, run_dir: Path) -> None:
    manifest = _read_json(run_dir / MOTION_MANIFEST_NAME)
    if manifest != {
        "run_id": record.run_id,
        "sample_count": int(record.result.time.size),
        "trajectory_sha256": _digest(run_dir / "trajectory.csv"),
        "evidence_sha256": _digest(run_dir / EVIDENCE_NAME),
        "figure_sha256": _digest(run_dir / MOTION_NAME),
    }:
        raise ValueError("倒立摆运动图与正式证据来源不一致。")


def load_verified_cart_pole_run(run_dir: str | Path) -> tuple[object, dict[str, object]]:
    """先用 canonical v1 reader 校验 hash，再校验倒立摆场景语义。"""
    path = Path(run_dir)
    record = load_artifacts(path)
    derived = _read_json(path / "metadata.json").get("derived_files_sha256")
    if not isinstance(derived, dict) or EVIDENCE_NAME not in derived:
        raise ValueError("倒立摆侧证据未列入正式产物摘要清单。")
    if derived[EVIDENCE_NAME] != _digest(path / EVIDENCE_NAME):
        raise ValueError("倒立摆侧证据摘要与正式产物清单不一致。")
    verify_cart_pole_evidence(record, path)
    if record.effective_config["scenario"]["version"] in ("2", "4"):
        if not {MOTION_NAME, MOTION_MANIFEST_NAME} <= derived.keys():
            raise ValueError("倒立摆运动图未列入正式产物摘要清单。")
        _verify_motion_plot(record, path)
    return record, json.loads((path / EVIDENCE_NAME).read_text(encoding="utf-8"))
