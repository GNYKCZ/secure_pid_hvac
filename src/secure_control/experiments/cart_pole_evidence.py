"""倒立摆正式侧证据：在 canonical artifact 上重放模型与控制语义。"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from secure_control.crypto import FixedPointContext
from secure_control.scenarios.cart_pole.contract import CartPoleContract
from secure_control.scenarios.cart_pole.controller import (
    CartPoleBalanceConfig,
    build_cart_pole_controller_spec,
)
from secure_control.scenarios.cart_pole.experiment import BalanceMonitor
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_experiment import CartPoleSecureExperiment

from .artifacts import ExperimentRecord, load_artifacts

EVIDENCE_NAME = "cart_pole_evidence.json"

def verify_cart_pole_evidence(record: object, run_dir: Path) -> None:
    """从正式 CSV 和物理配置重放两支，核对 raw→applied 与 N+1 状态。"""
    if not isinstance(record, ExperimentRecord) or record.metadata.name != "cart_pole":
        raise ValueError("倒立摆证据需要已验证的场景记录。")
    payload = json.loads((run_dir / EVIDENCE_NAME).read_text(encoding="utf-8"),
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    config = record.effective_config
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
    if (payload.get("schema_version") != 1 or payload.get("run_id") != record.run_id
            or payload.get("sample_count") != n or record.result.time.size != n
            or payload.get("sample_period_s") != plant_contract.sample_period_s
            or payload.get("terminal_time_s") != n * plant_contract.sample_period_s
            or payload.get("time_s") != (np.arange(n + 1)
                                         * plant_contract.sample_period_s).tolist()
            or payload.get("reference") != [list(balance.target_state) for _ in range(n + 1)]
            or payload.get("state_units") != list(record.metadata.output.units)
            or payload.get("force_unit") != "N" or payload.get("raw_error") != "ideal - secure"
            or not isinstance(payload.get("branches"), dict)
            or set(payload["branches"]) != {"ideal", "secure"}):
        raise ValueError("倒立摆证据身份、单位或步数无效。")
    expected_times = np.arange(n) * plant_contract.sample_period_s
    np.testing.assert_allclose(record.result.time, expected_times, rtol=0, atol=1e-14)
    np.testing.assert_allclose(record.result.reference,
                               np.asarray(payload["reference"])[:n], rtol=0, atol=0)
    raw_by_branch = {}
    for name in ("ideal", "secure"):
        branch = payload["branches"][name]
        if not isinstance(branch, dict) or set(branch) != {
            "observations", "raw_force_n", "statuses", "stable_counts"
        }:
            raise ValueError("倒立摆分支证据字段无效。")
        observations = np.asarray(branch["observations"], dtype=np.float64)
        raw = np.asarray(branch["raw_force_n"], dtype=np.float64)
        statuses = branch["statuses"]
        counts = branch["stable_counts"]
        if (observations.shape != (n + 1, 4) or raw.shape != (n,)
                or not np.isfinite(observations).all() or not np.isfinite(raw).all()
                or not isinstance(statuses, list) or len(statuses) != n + 1
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
                plant.step(np.array([applied[index]], dtype=np.float64))
        if statuses[-1] != "stable":
            raise ValueError("倒立摆终点尚未稳定。")
        raw_by_branch[name] = raw
    raw_error = np.asarray(payload.get("raw_force_error_n"), dtype=np.float64)
    if raw_error.shape != (n,):
        raise ValueError("倒立摆 raw force error shape 无效。")
    np.testing.assert_allclose(raw_error, raw_by_branch["ideal"] - raw_by_branch["secure"],
                               rtol=0, atol=0)
    np.testing.assert_allclose(record.result.control_error,
                               record.result.control_ideal - record.result.control_secure,
                               rtol=0, atol=0)


def write_cart_pole_evidence(record: object, stage: Path,
                             experiment: CartPoleSecureExperiment) -> tuple[str, ...]:
    """在正式 staging 写场景证据并于原子发布前进行语义重放。"""
    payload = experiment.evidence(record.run_id, record.result)
    (stage / EVIDENCE_NAME).write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    verify_cart_pole_evidence(record, stage)
    return (EVIDENCE_NAME,)


def load_verified_cart_pole_run(run_dir: str | Path) -> tuple[object, dict[str, object]]:
    """先用 canonical v1 reader 校验 hash，再校验倒立摆场景语义。"""
    path = Path(run_dir)
    record = load_artifacts(path)
    verify_cart_pole_evidence(record, path)
    return record, json.loads((path / EVIDENCE_NAME).read_text(encoding="utf-8"))
