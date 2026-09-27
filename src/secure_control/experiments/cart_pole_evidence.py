"""倒立摆正式侧证据：在 canonical artifact 上重放模型与控制语义。"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure

from secure_control.crypto import FixedPointContext
from secure_control.scenarios.cart_pole.contract import CartPoleContract
from secure_control.scenarios.cart_pole.controller import (
    CartPoleBalanceConfig,
    build_cart_pole_controller_spec,
)
from secure_control.scenarios.cart_pole.experiment import BalanceMonitor
from secure_control.scenarios.cart_pole.interactive import PULSE_FORCE_N, PULSE_PHASE
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_experiment import CartPoleSecureExperiment

from .artifacts import ExperimentRecord, _digest, _read_json, load_artifacts

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


def verify_cart_pole_evidence(record: object, run_dir: Path) -> None:
    """从正式 CSV 和物理配置重放两支，核对 raw→applied 与 N+1 状态。"""
    if not isinstance(record, ExperimentRecord) or record.metadata.name != "cart_pole":
        raise ValueError("倒立摆证据需要已验证的场景记录。")
    payload = json.loads((run_dir / EVIDENCE_NAME).read_text(encoding="utf-8"),
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    if not isinstance(payload, dict):
        raise TypeError("倒立摆证据必须是 JSON 对象。")
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
                             experiment: CartPoleSecureExperiment,
                             disturbances: tuple[float, ...] | None = None) -> tuple[str, ...]:
    """在正式 staging 写场景证据并于原子发布前进行语义重放。"""
    payload = experiment.evidence(record.run_id, record.result)
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
    if record.effective_config["scenario"]["version"] == "2":
        if not {MOTION_NAME, MOTION_MANIFEST_NAME} <= derived.keys():
            raise ValueError("倒立摆运动图未列入正式产物摘要清单。")
        _verify_motion_plot(record, path)
    return record, json.loads((path / EVIDENCE_NAME).read_text(encoding="utf-8"))
