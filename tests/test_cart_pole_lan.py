"""#92：倒立摆 LAN profile、范围证明、正式场景证据和三进程闭环。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from math import pi
from pathlib import Path

import numpy as np
import pytest
import yaml
from matplotlib.figure import Figure
from test_cart_pole_balance import _independent_run
from test_cart_pole_observer import oracle_closed_loop
from test_lan_continuous import _finish, _plain_deployment, _run
from test_lan_continuous import deployment as _tls_deployment

from secure_control.crypto import TwoPartySharing
from secure_control.experiments.artifacts import load_artifacts, write_artifacts
from secure_control.experiments.cart_pole_evidence import (
    EVIDENCE_NAME,
    MOTION_MANIFEST_NAME,
    load_verified_cart_pole_run,
    verify_cart_pole_evidence,
    write_cart_pole_evidence,
)
from secure_control.experiments.cart_pole_lan_profile import load_cart_pole_lan_profile
from secure_control.experiments.lan_continuous_profile import load_prepared_lan_experiment
from secure_control.protocol import Client
from secure_control.protocol.roles import _bounded_input_reachability
from secure_control.scenarios.cart_pole.adapter import MeasurementSample
from secure_control.scenarios.cart_pole.observer import build_cart_pole_observer_design
from secure_control.scenarios.cart_pole.secure_experiment import (
    CartPoleObserverSecureExperiment,
    CartPoleSecureExperiment,
    cart_pole_numeric_contract,
)
from secure_control.simulation import compare_closed_loops

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "configs" / "cart_pole_lan.example.yaml"
OBSERVER_PROFILE = ROOT / "configs" / "cart_pole_observer_lan.example.yaml"
# ell=32 时每步四路编码及 D 量化的力误差上界约 4.51e-9 N；
# 400 步原点线性化响应包络约 3.27e-9（最大状态分量）/4.95e-8 N。
# 对非线性代表轨迹留余量，且保留 #91 明文 oracle 原有 3e-8 门限。
IDEAL_ORACLE_ATOL = 3e-8
SECURE_STATE_ATOL = 4e-8
SECURE_FORCE_ATOL = 9e-8
PAIR_STATE_ATOL = 1e-8
PAIR_FORCE_ATOL = 6e-8


class _QuantizedLqrRuntime:
    """仅供证据单元测试独立计算静态 2ell 输出，不模拟网络协议。"""

    def __init__(self, profile) -> None:
        self.context = profile.context
        self.d = np.asarray(self.context.encode(profile.spec.D), dtype=object).reshape(4)

    def step(self, value: np.ndarray) -> np.ndarray:
        encoded = np.asarray(self.context.encode(value), dtype=object)
        total = sum(int(gain) * int(item)
                    for gain, item in zip(self.d, encoded, strict=True))
        return np.array([total / (self.context.scale * self.context.scale)])


def _profile_for(paths: dict[str, Path]) -> Path:
    """只在测试临时配置内选择倒立摆，P1/P2 仍用通用角色入口。"""
    profile = paths["Client"].parent / "cart-profile.yaml"
    data = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    data["plant_source"] = str(ROOT / "configs" / "cart_pole_plant.yaml")
    data["balance_source"] = str(ROOT / "configs" / "cart_pole_balance.yaml")
    data["numeric"]["prime_source"] = str(
        ROOT / "configs" / "shared_prime_256_pocklington.yaml"
    )
    data["output_root"] = str(profile.parent / "runs")
    profile.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    client = paths["Client"]
    client.write_text(client.read_text(encoding="utf-8").replace(
        "experiment: paper_pid_lan.example.yaml", f"experiment: {profile}"
    ), encoding="utf-8")
    return profile


def _observer_profile_for(paths: dict[str, Path], *, horizon: int = 60,
                          initial_state: tuple[float, ...] = (0, 0, .005, 0),
                          disturbances: tuple[tuple[int, float], ...] = ()) -> Path:
    """有限动态集成测试沿用三份角色配置，仅换 Client 的场景来源。"""
    root = paths["Client"].parent
    plant = yaml.safe_load((ROOT / "configs" / "cart_pole_plant.yaml").read_text(
        encoding="utf-8"
    ))
    plant["initial_state"] = list(initial_state)
    plant_path = root / "observer-plant.yaml"
    plant_path.write_text(yaml.safe_dump(plant), encoding="utf-8")
    balance = yaml.safe_load((ROOT / "configs" / "cart_pole_balance.yaml").read_text(
        encoding="utf-8"
    ))
    balance["horizon_steps"] = horizon
    balance_path = root / "observer-balance.yaml"
    balance_path.write_text(yaml.safe_dump(balance), encoding="utf-8")
    observer = yaml.safe_load((ROOT / "configs" / "cart_pole_observer.yaml").read_text(
        encoding="utf-8"
    ))
    observer.update({"plant_source": str(plant_path), "balance_source": str(balance_path)})
    observer_path = root / "observer.yaml"
    observer_path.write_text(yaml.safe_dump(observer), encoding="utf-8")
    profile = yaml.safe_load(OBSERVER_PROFILE.read_text(encoding="utf-8"))
    profile["observer_source"] = str(observer_path)
    profile["numeric"]["prime_source"] = str(
        ROOT / "configs" / "shared_prime_256_pocklington.yaml"
    )
    profile["output_root"] = str(root / "observer-runs")
    profile["disturbances"] = [list(event) for event in disturbances]
    profile_path = root / "observer-profile.yaml"
    profile_path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    client = paths["Client"]
    client.write_text(client.read_text(encoding="utf-8").replace(
        f"controller: {ROOT / 'tests' / 'fixtures' / 'legacy_hvac' / 'hvac_dual_loop.yaml'}",
        f"experiment: {profile_path}",
    ).replace(
        "experiment: paper_pid_lan.example.yaml", f"experiment: {profile_path}"
    ), encoding="utf-8")
    return profile_path


@pytest.fixture(scope="module")
def observer_verified_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """复用一份真实非零chart三进程产物，类型篡改逐案恢复原字节。"""
    paths = _plain_deployment(tmp_path_factory.mktemp("observer-evidence"))
    _observer_profile_for(paths, initial_state=(0, 0, 2 * pi + .005, 0))
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, result, errors = _finish(_run("Client", paths["Client"]), 600)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 60) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        run_dir = Path(result["run_dir"])
        load_verified_cart_pole_run(run_dir)
        return run_dir
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


@pytest.mark.parametrize("filename,keys", [
    (EVIDENCE_NAME, ("schema_version",)),
    (EVIDENCE_NAME, ("sample_count",)),
    ("metadata.json", ("provenance", "confirmed_steps", 0, "step")),
    ("metadata.json", ("provenance", "confirmed_steps", 0, "products")),
    ("metadata.json", ("provenance", "resource_counts", "truncations_consumed")),
    ("metadata.json", ("provenance", "scale_ledger", "state_truncation_bits")),
    ("config.json", ("observer_design", "source_snapshots", 0, "yaml", "schema_version")),
    ("config.json", ("observer_design", "source_snapshots", 1, "yaml", "schema_version")),
    ("config.json", ("observer_design", "source_snapshots", 2, "yaml", "schema_version")),
    ("config.json", ("observer_design", "contract_version")),
    ("config.json", ("observer_design", "pole_placement", "maxiter")),
    ("config.json", ("initialization", "branch")),
    ("config.json", ("sample_count",)),
    ("config.json", ("range", "steps")),
    ("config.json", ("range", "proof", "horizon_steps")),
    ("config.json", ("range", "proof", "step_bounds", 0, "step")),
    ("config.json", ("range", "proof", "initial_payload", 0)),
    ("config.json", ("range", "proof", "input_payload_bounds", 0)),
    (MOTION_MANIFEST_NAME, ("sample_count",)),
])
def test_observer_reader_rejects_equal_noninteger_fields(
    observer_verified_run: Path, filename: str, keys: tuple,
) -> None:
    """RV-001：刷新全部摘要后，数值相等的bool/float仍须被正式入口拒绝。"""
    run_dir = observer_verified_run
    originals = {name: (run_dir / name).read_bytes() for name in (
        "metadata.json", "config.json", EVIDENCE_NAME, MOTION_MANIFEST_NAME,
    )}
    for kind in (float, bool):
        documents = {name: json.loads(blob) for name, blob in originals.items()}
        parent = documents[filename]
        for key in keys[:-1]:
            parent = parent[key]
        value = parent[keys[-1]]
        assert type(value) is int
        replacement = kind(value)
        if replacement != value:
            continue  # bool只在0/1处数值相等，其余字段用float覆盖。
        parent[keys[-1]] = replacement
        try:
            for name in ("config.json", EVIDENCE_NAME):
                (run_dir / name).write_text(json.dumps(documents[name]), encoding="utf-8")
            motion = documents[MOTION_MANIFEST_NAME]
            motion["evidence_sha256"] = sha256((run_dir / EVIDENCE_NAME).read_bytes()).hexdigest()
            (run_dir / MOTION_MANIFEST_NAME).write_text(json.dumps(motion), encoding="utf-8")
            manifest = documents["metadata.json"]
            manifest["files_sha256"]["config.json"] = sha256(
                (run_dir / "config.json").read_bytes()
            ).hexdigest()
            for name in (EVIDENCE_NAME, MOTION_MANIFEST_NAME):
                manifest["derived_files_sha256"][name] = sha256((run_dir / name).read_bytes()).hexdigest()
            (run_dir / "metadata.json").write_text(json.dumps(manifest), encoding="utf-8")
            with pytest.raises((ValueError, TypeError)):
                load_verified_cart_pole_run(run_dir)
        finally:
            for name, blob in originals.items():
                (run_dir / name).write_bytes(blob)
        load_verified_cart_pole_run(run_dir)


def _capture_motion_artists(record, payload, run_dir: Path,
                            monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """核对正式renderer实际artist；保留原PNG/manifest，不引入另一套绘图。"""
    from secure_control.experiments import cart_pole_evidence

    paths = (run_dir / cart_pole_evidence.MOTION_NAME, run_dir / MOTION_MANIFEST_NAME)
    originals = {path: path.read_bytes() for path in paths}
    axes_data = []
    original_save = Figure.savefig

    def capture(figure, *args, **kwargs):
        for axis in figure.axes:
            axes_data.append({
                "lines": [(line.get_label(), list(line.get_xdata()), list(line.get_ydata()))
                          for line in axis.lines],
                "ylim": axis.get_ylim(), "xlabel": axis.get_xlabel(),
            })
        return original_save(figure, *args, **kwargs)

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(Figure, "savefig", capture)
            cart_pole_evidence._write_motion_plot(record, payload, run_dir)
    finally:
        for path, blob in originals.items():
            path.write_bytes(blob)
    return axes_data


@pytest.mark.parametrize("theta_star", [0., 2 * pi, -4 * pi])
def test_observer_motion_targets_use_saved_reference(
    observer_verified_run: Path, theta_star: float, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RV-002：连续角曲线和目标在同一chart，零线不压缩整圈transient。"""
    record, payload = load_verified_cart_pole_run(observer_verified_run)
    payload = deepcopy(payload)
    shift = theta_star - payload["reference"][0][2]
    for row in payload["reference"]:
        row[2] += shift
    for branch in payload["branches"].values():
        for row in branch["observations"]:
            row[2] += shift
    axes = _capture_motion_artists(record, payload, observer_verified_run, monkeypatch)
    for axis, index in ((axes[0], 0), (axes[1], 2)):
        target = next((line for line in axis["lines"] if line[0].startswith("target")), None)
        assert target is not None
        np.testing.assert_array_equal(target[2],
                                      [payload["reference"][0][index]] * len(target[2]))
        if index == 2 and theta_star != 0:
            assert target[0] != "target 0"
    assert axes[1]["ylim"][1] - axes[1]["ylim"][0] < .02


@pytest.mark.parametrize("ideal,secure", [(0., 0.), (1., 1.), (1., 0.), (0., -1.)])
def test_observer_motion_marks_actual_disturbance_by_branch(
    observer_verified_run: Path, ideal: float, secure: float, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RV-003：展示层消费实际外力；相同请求不能冒充两支相同执行结果。"""
    record, payload = load_verified_cart_pole_run(observer_verified_run)
    payload = deepcopy(payload)
    payload["events"] = [{"step": 0, "force_n": 1., "duration_steps": 1}]
    for name, force in (("ideal", ideal), ("secure", secure)):
        branch = payload["branches"][name]
        branch["disturbance_force_n"][0] = force
        branch["force_dispositions"][0] = ("accepted" if force else "rejected_total_force_limit")
    axes = _capture_motion_artists(record, payload, observer_verified_run, monkeypatch)
    for axis in axes:
        verticals = [line for line in axis["lines"]
                     if len(line[1]) == 2 and line[1][0] == line[1][1]]
        assert {line[0] for line in verticals} == {
            f"{name} applied disturbance" for name, force in (("ideal", ideal), ("secure", secure))
            if force != 0
        }
        for name, force in (("ideal", ideal), ("secure", secure)):
            markers = [line for line in axis["lines"] if line[0] == f"{name} applied disturbance"]
            assert len(markers) == int(force != 0)
            if markers:
                assert markers[0][1] == [payload["time_s"][0]] * 2
        assert "red lines" not in axis["xlabel"]


def test_observer_profile_and_plaintext_scene_are_dynamic() -> None:
    """真实配置的首样本直接决定4×2 spec，双支无网络仍按两测量闭环。"""
    profile = load_cart_pole_lan_profile(OBSERVER_PROFILE)
    assert (profile.spec.state_dimension, profile.spec.input_dimension) == (4, 2)
    assert profile.contract.horizon_steps == 400
    assert profile.proof["range_verification"]["state_accumulator_bounds"][0] > 0
    scene = CartPoleObserverSecureExperiment(
        profile.observer_design, profile.observer_initialization
    )
    from secure_control.execution import PlaintextStateSpaceRuntime

    plan = scene.build_plan(PlaintextStateSpaceRuntime(profile.spec))
    result = scene.execute_plan(plan)
    scene.validate_result(result)
    assert scene.records["secure"]["statuses"][-1] == "stable"
    assert len(scene.records["secure"]["measurements"]) == 401
    assert np.max(np.abs(result.control_error)) == 0


@pytest.mark.parametrize("theta,disturbance", [
    (-.08726646259971647, ((200, -1.),)),
    (2 * pi + .08726646259971647, ((200, 1.),)),
])
def test_observer_scene_keeps_fixed_angle_branch_and_disturbance(
    theta: float, disturbance: tuple[tuple[int, float], ...]
) -> None:
    """负角和整圈角都沿首测量chart运行，未知外力只进入物理适配器。"""
    profile = load_cart_pole_lan_profile(OBSERVER_PROFILE)
    design = build_cart_pole_observer_design(
        replace(profile.plant, initial_state=(0, 0, theta, 0)),
        profile.balance, profile.observer_design.config,
    )
    initialization = design.initialize(MeasurementSample(0, 0., 0., theta))
    scene = CartPoleObserverSecureExperiment(design, initialization, disturbance)
    from secure_control.execution import PlaintextStateSpaceRuntime

    plan = scene.build_plan(PlaintextStateSpaceRuntime(initialization.spec))
    result = scene.execute_plan(plan)
    scene.validate_result(result)
    assert scene.records["secure"]["statuses"][-1] == "stable"
    assert scene.records["secure"]["requested_disturbance_n"][200] == disturbance[0][1]
    assert result.reference[0, 2] == initialization.theta_star
    assert np.max(np.abs(result.control_error)) == 0


def test_observer_profile_source_drift_and_runtime_failure(tmp_path: Path) -> None:
    """新 profile 来源变化在联网前拒绝；raw 越界/超时不产生成功结果。"""
    paths = _plain_deployment(tmp_path)
    path = _observer_profile_for(paths)
    profile = load_cart_pole_lan_profile(path)
    with path.open("a", encoding="utf-8") as target:
        target.write("\n# changed after preflight\n")
    with pytest.raises(ValueError, match="来源"):
        profile.recheck_sources()
    scene = CartPoleObserverSecureExperiment(
        profile.observer_design, profile.observer_initialization
    )

    class BadRuntime:
        def __init__(self, error: Exception | None = None) -> None:
            self.error = error

        def step(self, _value):
            if self.error is not None:
                raise self.error
            return np.array([11.])

    plan = scene.build_plan(BadRuntime())
    with pytest.raises(ValueError, match="saturation_outside_contract"):
        scene.execute_plan(plan)
    np.testing.assert_array_equal(plan.secure.plant.state, profile.plant.initial_state)
    assert scene.records == {}
    scene = CartPoleObserverSecureExperiment(
        profile.observer_design, profile.observer_initialization
    )
    with pytest.raises(TimeoutError):
        scene.execute_plan(scene.build_plan(BadRuntime(TimeoutError("injected"))))
    assert scene.records == {}


@pytest.mark.parametrize("field,value", [("k", 33), ("runtime_payload_bits", 39),
                                         ("lambda", 224)])
def test_observer_numeric_profile_rejects_insufficient_widths(
    tmp_path: Path, field: str, value: int,
) -> None:
    """参数、状态payload与Protocol2 κ各自有独立门禁，不借raw力限幅掩盖。"""
    path = _observer_profile_for(_plain_deployment(tmp_path), horizon=400)
    profile = yaml.safe_load(path.read_text(encoding="utf-8"))
    profile["numeric"][field] = value
    path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    with pytest.raises(ValueError):
        load_cart_pole_lan_profile(path)


def test_bounded_input_reachability_uses_encoded_block_contraction() -> None:
    """#109：持续界复核实际编码矩阵，保留块幂抵消并拒绝不足的状态界。"""
    nilpotent = {"A": np.array([[1, 1], [-1, -1]], dtype=object),
                 "B": np.zeros((2, 1), dtype=object),
                 "x0": np.array([1, 0], dtype=object)}
    with pytest.raises(ValueError, match="不收缩"):
        _bounded_input_reachability(nilpotent, (0,), 0, 1)
    assert _bounded_input_reachability(nilpotent, (0,), 0, 2) == (2, 1)

    profile = load_cart_pole_lan_profile(OBSERVER_PROFILE)
    encoded = {name: np.asarray(profile.context.encode(getattr(profile.spec, name)), dtype=object)
               for name in ("A", "B", "C", "D", "x0")}
    bounds = _bounded_input_reachability(encoded, profile.contract.input_payload_bounds,
                                         profile.ell, 22)
    assert len(bounds) == 4 and all(0 < value <= profile.context.maximum_payload
                                    for value in bounds)
    contract = replace(profile.contract, state_payload_bounds=bounds, horizon_steps=None,
                       reachability_block_steps=22)
    client = Client(profile.context, TwoPartySharing(profile.q),
                    security_parameter=profile.security_parameter,
                    modulus_evidence=profile.evidence)
    client.distribute_controller(profile.spec, contract)
    assert client.range_verification.proof_mode == "bounded_input_reachability"
    with pytest.raises(ValueError, match="未覆盖"):
        client.distribute_controller(profile.spec, replace(
            contract, state_payload_bounds=(bounds[0] - 1, *bounds[1:])
        ))


def test_observer_cli_fault_reports_attempted_vs_physical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """协议已提交但raw越界时公开attempt=1、物理前缀=0，不称complete。"""
    from secure_control.execution.lan_config import load_lan_config
    from secure_control.experiments import lan_runner

    paths = _plain_deployment(tmp_path)
    _observer_profile_for(paths)

    class AttemptedRuntime:
        def __init__(self, *_args) -> None:
            self.confirmed_steps = []
            self.resource_counts = {"products_consumed": 0, "truncations_consumed": 0}

        def step(self, _value):
            self.confirmed_steps.append({"step": 0, "status": "double_committed",
                                         "products": 30, "truncations": 4})
            self.resource_counts = {"products_consumed": 30, "truncations_consumed": 4}
            return np.array([11.])

        def close(self) -> None:
            pass

    monkeypatch.setattr(lan_runner, "LanContinuousRuntime", AttemptedRuntime)
    with pytest.raises(ValueError, match="saturation_outside_contract") as failure:
        lan_runner.run_client_continuous(load_lan_config(paths["Client"], "Client"))
    assert failure.value._public_lan_progress == {
        "protocol_double_committed_count": 1, "physically_confirmed_count": 0,
        "resource_counts": {"products_consumed": 30, "truncations_consumed": 4},
        "uncertain": False,
    }
    lan_runner._failure("Client", 4, "identity_or_protocol", failure.value)
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "failed" and report["progress"] == (
        failure.value._public_lan_progress
    )


def test_observer_three_process_finite_resources_and_reader(tmp_path: Path) -> None:
    """真实三PID递推60步，逐轮消费30 triple/4 Trunc 并正式读回。"""
    paths = _plain_deployment(tmp_path)
    _observer_profile_for(paths)
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, result, errors = _finish(_run("Client", paths["Client"]), 600)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 600) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert result["resource_counts"] == {
            "products_consumed": 60 * 30, "truncations_consumed": 60 * 4,
        }
        record, sidecar = load_verified_cart_pole_run(result["run_dir"])
        assert len(record.provenance["round_ledger"]) == 60
        assert len({item["round_id"] for item in record.provenance["round_ledger"]}) == 60
        assert sidecar["branches"]["secure"]["statuses"][-1] == "stable"
        assert Path(result["figure_path"]).is_file()
        from copy import deepcopy

        altered = deepcopy(record)
        altered.effective_config["observer_design"]["source_snapshots"][1]["yaml"][
            "sample_period_s"
        ] *= 2
        with pytest.raises(ValueError, match="来源 YAML"):
            verify_cart_pole_evidence(altered, Path(result["run_dir"]))
        altered = deepcopy(record)
        altered.provenance["round_ledger"][1]["round_id"] = altered.provenance[
            "round_ledger"
        ][0]["round_id"]
        with pytest.raises(ValueError, match="轮次身份"):
            verify_cart_pole_evidence(altered, Path(result["run_dir"]))
        altered = deepcopy(record)
        altered.effective_config["controller_spec"]["B"][0][0] += 1e-4
        with pytest.raises(ValueError, match="控制器"):
            verify_cart_pole_evidence(altered, Path(result["run_dir"]))
        altered = deepcopy(record)
        altered.effective_config["range"]["proof"]["step_bounds"][3][
            "state_payload_bounds"
        ][0] += 1
        with pytest.raises(ValueError, match="范围证明"):
            verify_cart_pole_evidence(altered, Path(result["run_dir"]))
        altered = deepcopy(record)
        altered.provenance["resource_counts"]["truncations_consumed"] -= 1
        with pytest.raises(ValueError, match="资源实耗"):
            verify_cart_pole_evidence(altered, Path(result["run_dir"]))
        sidecar_path = Path(result["run_dir"]) / EVIDENCE_NAME
        original = sidecar_path.read_text(encoding="utf-8")
        run_dir = Path(result["run_dir"])
        manifest_path = run_dir / "metadata.json"
        motion_path = run_dir / MOTION_MANIFEST_NAME
        original_manifest = manifest_path.read_text(encoding="utf-8")
        original_motion = motion_path.read_text(encoding="utf-8")
        try:
            changed = deepcopy(sidecar)
            changed["branches"]["secure"]["measurements"][3][0] += .001
            sidecar_path.write_text(json.dumps(changed), encoding="utf-8")
            with pytest.raises((ValueError, AssertionError)):
                verify_cart_pole_evidence(record, Path(result["run_dir"]))
            # 即使篡改者刷新了所有相关文件摘要，独立语义重放仍拒绝测量错位。
            manifest = json.loads(original_manifest)
            motion = json.loads(original_motion)
            motion["evidence_sha256"] = sha256(sidecar_path.read_bytes()).hexdigest()
            motion_path.write_text(json.dumps(motion), encoding="utf-8")
            manifest["derived_files_sha256"][EVIDENCE_NAME] = motion["evidence_sha256"]
            manifest["derived_files_sha256"][MOTION_MANIFEST_NAME] = sha256(
                motion_path.read_bytes()
            ).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with pytest.raises((ValueError, AssertionError)):
                load_verified_cart_pole_run(run_dir)
        finally:
            sidecar_path.write_text(original, encoding="utf-8")
            manifest_path.write_text(original_manifest, encoding="utf-8")
            motion_path.write_text(original_motion, encoding="utf-8")
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_observer_three_process_400_steps_disturbance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """正式400步5°+1N扰动仍非饱和成功，资源从plan/实耗派生。"""
    paths = _plain_deployment(tmp_path)
    _observer_profile_for(
        paths, horizon=400, initial_state=(0, 0, .08726646259971647, 0),
        disturbances=((200, 1.),),
    )
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, result, errors = _finish(_run("Client", paths["Client"]), 1200)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 1200) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        record, evidence = load_verified_cart_pole_run(result["run_dir"])
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert result["resource_counts"] == {
            "products_consumed": 400 * 30, "truncations_consumed": 400 * 4,
        }
        assert len(record.provenance["round_ledger"]) == 400
        assert evidence["branches"]["secure"]["statuses"][-1] == "stable"
        assert evidence["branches"]["secure"]["requested_disturbance_n"][200] == 1.
        oracle_state, _, oracle_force, statuses, counts = oracle_closed_loop(
            (0, 0, .08726646259971647, 0), (0, 0), 1,
        )
        for name in ("ideal", "secure"):
            np.testing.assert_allclose(evidence["branches"][name]["observations"],
                                       oracle_state, rtol=0, atol=3e-8)
            np.testing.assert_allclose(evidence["branches"][name]["raw_force_n"],
                                       oracle_force, rtol=0, atol=1e-7)
            assert evidence["branches"][name]["statuses"] == statuses
            assert evidence["branches"][name]["stable_counts"] == counts
        assert np.max(np.abs(record.result.output_error)) < 3e-8
        assert np.max(np.abs(evidence["raw_force_error_n"])) < 1e-7
        axes = _capture_motion_artists(record, evidence, Path(result["run_dir"]), monkeypatch)
        for name in ("ideal", "secure"):
            marker = next(line for line in axes[1]["lines"]
                          if line[0] == f"{name} applied disturbance")
            assert marker[1] == [4., 4.]
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_observer_rejected_pulse_is_not_plotted_as_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RV-003：真实400步合法拒绝外扰仍成功，正式图不能宣称施加该脉冲。"""
    paths = _plain_deployment(tmp_path)
    _observer_profile_for(paths, horizon=400,
                          initial_state=(0, 0, .08726646259971647, 0),
                          disturbances=((0, -1.),))
    plant_path = tmp_path / "observer-plant.yaml"
    plant = yaml.safe_load(plant_path.read_text(encoding="utf-8"))
    plant["max_applied_force_n"] = 2.440242909979021
    plant_path.write_text(yaml.safe_dump(plant), encoding="utf-8")
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, result, errors = _finish(_run("Client", paths["Client"]), 1200)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 60) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        run_dir = Path(result["run_dir"])
        record, evidence = load_verified_cart_pole_run(run_dir)
        for branch in evidence["branches"].values():
            assert branch["requested_disturbance_n"][0] == -1.
            assert branch["disturbance_force_n"][0] == 0.
            assert branch["force_dispositions"][0] == "rejected_total_force_limit"
            assert branch["statuses"][-1] == "stable"
        axes = _capture_motion_artists(record, evidence, run_dir, monkeypatch)
        for axis in axes:
            assert not any(len(line[1]) == 2 and line[1][0] == line[1][1]
                           for line in axis["lines"])
        # 同一正式拒绝run的step0/duration也须严格整数。
        original = (run_dir / EVIDENCE_NAME).read_bytes()
        for field in ("step", "duration_steps"):
            changed = deepcopy(evidence)
            changed["events"][0][field] = float(changed["events"][0][field])
            try:
                (run_dir / EVIDENCE_NAME).write_text(json.dumps(changed), encoding="utf-8")
                with pytest.raises(ValueError, match="事件"):
                    verify_cart_pole_evidence(record, run_dir)
            finally:
                (run_dir / EVIDENCE_NAME).write_bytes(original)
        load_verified_cart_pole_run(run_dir)
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_observer_three_process_mutual_tls(tmp_path: Path) -> None:
    """动态控制器沿原mTLS角色链路完成有限会话与正式读回。"""
    paths = _tls_deployment.__wrapped__(tmp_path)
    _observer_profile_for(paths)
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, result, errors = _finish(_run("Client", paths["Client"]), 600)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 600) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert result["transport"] == "mutual_tls" and result["tls_version"] == "TLSv1.3"
        assert all(item[1]["tls_version"] == "TLSv1.3" for item in outcomes)
        load_verified_cart_pole_run(result["run_dir"])
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_profile_and_exact_static_lqr_bounds() -> None:
    """四路编码端点、零维 state、2ell 模输出和 400 步资源均由数据推得。"""
    profile = load_cart_pole_lan_profile(PROFILE)
    assert profile.contract.state_payload_bounds == ()
    assert profile.contract.horizon_steps == 400
    assert profile.q.bit_length() - profile.security_parameter - 2 > profile.ell
    scale = 1 << profile.ell
    for limit, bound in zip(profile.balance.safe_abs,
                            profile.contract.input_payload_bounds, strict=True):
        assert bound >= max(abs(int(np.floor(-limit * scale + .5))),
                            abs(int(np.floor(limit * scale + .5))))
    encoded = np.asarray(profile.context.encode(profile.spec.D), dtype=object).reshape(4)
    assert profile.proof["output_accumulator_absolute_bound"] == sum(
        abs(int(value)) * bound for value, bound in
        zip(encoded, profile.contract.input_payload_bounds, strict=True)
    )
    assert profile.proof["output_accumulator_absolute_bound"] < (profile.q - 1) // 2
    assert profile.proof["output_fractional_bits"] == 64
    assert profile.proof["force_limit_n"] == profile.plant.max_applied_force_n
    assert profile.context.from_residue(profile.context.to_residue(-123)) == -123
    assert profile.context.decode(-123 * scale, fractional_bits=64) == pytest.approx(
        -123 / scale
    )


@pytest.mark.parametrize("change", [
    lambda data: data["numeric"].update({"k": 32}),
    lambda data: data["numeric"].update({"runtime_payload_bits": 39}),
    lambda data: data["numeric"].update({"lambda": 230}),
    lambda data: data.update({"plant_source": "missing.yaml"}),
    lambda data: data.update({"sample_count": 400}),
])
def test_invalid_profile_fails_before_network(tmp_path: Path, change) -> None:
    data = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    data["plant_source"] = str(ROOT / "configs" / "cart_pole_plant.yaml")
    data["balance_source"] = str(ROOT / "configs" / "cart_pole_balance.yaml")
    data["numeric"]["prime_source"] = str(
        ROOT / "configs" / "shared_prime_256_pocklington.yaml"
    )
    change(data)
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises((ValueError, TypeError, OSError)):
        load_cart_pole_lan_profile(path)


def test_domain_and_horizon_guard() -> None:
    profile = load_cart_pole_lan_profile(PROFILE)
    with pytest.raises(ValueError):
        cart_pole_numeric_contract(
            profile.spec, replace(profile.balance, horizon_steps=1001),
            fractional_bits=32, parameter_bits=40,
            runtime_payload_bits=46, modulus=profile.q,
        )
    with pytest.raises(ValueError, match="payload"):
        cart_pole_numeric_contract(
            profile.spec, replace(profile.balance, safe_abs=(.45, .6, .2, 1e8)),
            fractional_bits=32,
            parameter_bits=40, runtime_payload_bits=40, modulus=profile.q,
        )
    experiment = CartPoleSecureExperiment(profile.plant, profile.balance, profile.spec)
    with pytest.raises(ValueError, match="工作域"):
        experiment.secure_adapter.controller_input(
            np.zeros(4), np.array([0, 0, .25, 0]),
        )
    assert experiment.secure_adapter.raw_forces == []
    client = Client(profile.context, TwoPartySharing(profile.q),
                    security_parameter=profile.security_parameter,
                    modulus_evidence=profile.evidence)
    distribution = client.distribute_controller(profile.spec, profile.contract)
    with pytest.raises(ValueError):
        client.prepare_online(distribution, np.array([.5, 0, 0, 0]), step=0)
    assert client.prepare_online(distribution, np.zeros(4), step=0).step == 0


def test_source_drift_and_initial_domain_fail_preflight(tmp_path: Path) -> None:
    """文件变化与越界初态在下一次联网前被拒绝。"""
    data = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    plant = yaml.safe_load((ROOT / "configs" / "cart_pole_plant.yaml").read_text(
        encoding="utf-8"
    ))
    plant_path = tmp_path / "plant.yaml"
    plant_path.write_text(yaml.safe_dump(plant), encoding="utf-8")
    data["plant_source"] = str(plant_path)
    data["balance_source"] = str(ROOT / "configs" / "cart_pole_balance.yaml")
    data["numeric"]["prime_source"] = str(
        ROOT / "configs" / "shared_prime_256_pocklington.yaml"
    )
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    profile = load_cart_pole_lan_profile(profile_path)
    plant["initial_state"] = [0, 0, .25, 0]
    plant_path.write_text(yaml.safe_dump(plant), encoding="utf-8")
    with pytest.raises(ValueError):
        profile.recheck_sources()
    with pytest.raises(ValueError, match="初态"):
        load_cart_pole_lan_profile(profile_path)


def test_plaintext_oracle_and_verified_sidecar(tmp_path: Path) -> None:
    """两支可变对象独立；逐点匹配 #91 DOP853，发布后重放 N+1 判定。"""
    profile = load_cart_pole_lan_profile(PROFILE)
    experiment = CartPoleSecureExperiment(profile.plant, profile.balance, profile.spec)
    plan = experiment.build_plan(_QuantizedLqrRuntime(profile))
    assert plan.ideal.plant is not plan.secure.plant
    assert plan.ideal.adapter is not plan.secure.adapter
    result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
    experiment.validate_result(result)
    states, raw, applied, statuses, counts = _independent_run(profile.plant.initial_state)
    for name in ("ideal", "secure"):
        state_atol = IDEAL_ORACLE_ATOL if name == "ideal" else SECURE_STATE_ATOL
        force_atol = IDEAL_ORACLE_ATOL if name == "ideal" else SECURE_FORCE_ATOL
        np.testing.assert_allclose(getattr(result, f"output_{name}"), states[:-1],
                                   rtol=0, atol=state_atol)
        np.testing.assert_allclose(getattr(result, f"control_{name}")[:, 0], applied,
                                   rtol=0, atol=force_atol)
        adapter = getattr(experiment, f"{name}_adapter")
        np.testing.assert_allclose(adapter.raw_forces, raw, rtol=0, atol=force_atol)
        np.testing.assert_allclose(adapter.observations, states, rtol=0, atol=state_atol)
        assert adapter.statuses == statuses
        assert adapter.stable_counts == counts
    assert np.max(np.abs(result.output_secure - result.output_ideal)) < PAIR_STATE_ATOL
    assert np.max(np.abs(result.control_secure - result.control_ideal)) < PAIR_FORCE_ATOL
    provenance = {"scenario_name": "cart_pole", "scenario_version": "1", "schema_version": 1}
    prepared = load_prepared_lan_experiment(PROFILE)
    artifact = write_artifacts(
        result, plan.metadata, prepared.effective_config, provenance,
        output_root=tmp_path / "runs",
        derived_writer=lambda record, stage: write_cart_pole_evidence(record, stage,
                                                                       experiment),
    )
    record, sidecar = load_verified_cart_pole_run(artifact.run_dir)
    assert record.run_id == artifact.run_id
    assert sidecar["branches"]["secure"]["statuses"][-1] == "stable"
    assert len(sidecar["time_s"]) == 401
    assert len(sidecar["branches"]["secure"]["raw_force_n"]) == 400
    original = (artifact.run_dir / EVIDENCE_NAME).read_text(encoding="utf-8")
    for mutate in (
        lambda data: data.update({"run_id": "wrong"}),
        lambda data: data["branches"]["secure"]["raw_force_n"].__setitem__(0, 100),
        lambda data: data["branches"]["secure"]["stable_counts"].__setitem__(-1, 0),
        lambda data: data["branches"]["secure"]["observations"].__setitem__(-1,
                                                                                 [0, 0, 0, 0]),
    ):
        data = json.loads(original)
        mutate(data)
        (artifact.run_dir / EVIDENCE_NAME).write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises((ValueError, AssertionError)):
            verify_cart_pole_evidence(record, artifact.run_dir)
    (artifact.run_dir / EVIDENCE_NAME).write_text(original, encoding="utf-8")
    load_verified_cart_pole_run(artifact.run_dir)

    manifest_path = artifact.run_dir / "metadata.json"
    original_manifest = manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(original_manifest)
    del manifest["derived_files_sha256"][EVIDENCE_NAME]
    if not manifest["derived_files_sha256"]:
        del manifest["derived_files_sha256"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    load_artifacts(artifact.run_dir)
    with pytest.raises(ValueError):
        load_verified_cart_pole_run(artifact.run_dir)
    manifest_path.write_text(original_manifest, encoding="utf-8")

    (artifact.run_dir / EVIDENCE_NAME).write_text(original + " ", encoding="utf-8")
    with pytest.raises(ValueError):
        load_verified_cart_pole_run(artifact.run_dir)
    (artifact.run_dir / EVIDENCE_NAME).write_text(original, encoding="utf-8")

    for mutate in (
        lambda data: data.update({"schema_version": True}),
        lambda data: data.update({"schema_version": 1.0}),
        lambda data: data.update({"sample_count": True}),
        lambda data: data.update({"sample_count": 400.0}),
        lambda data: data["branches"]["ideal"]["observations"][0].__setitem__(0, False),
    ):
        data = json.loads(original)
        mutate(data)
        (artifact.run_dir / EVIDENCE_NAME).write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises((ValueError, AssertionError)):
            verify_cart_pole_evidence(record, artifact.run_dir)
    (artifact.run_dir / EVIDENCE_NAME).write_text(original, encoding="utf-8")
    load_verified_cart_pole_run(artifact.run_dir)


def test_three_independent_processes_400_steps(tmp_path: Path) -> None:
    """真实 P1/P2/Client 进程运行 400 区间并检查双提交、1600/0 实耗。"""
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    # 无监听方时 Client 失败且未发布；随后真正启动新三进程会话。
    missing_code, missing, _ = _finish(_run("Client", paths["Client"]), 20)
    assert missing_code != 0 and missing["status"] == "failed"
    assert not list((tmp_path / "runs").glob("*/metadata.json"))
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        client = _run("Client", paths["Client"])
        code, result, errors = _finish(client, 600)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 600) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert result["status"] == "complete" and result["sample_count"] == 400
        assert result["resource_counts"] == {
            "products_consumed": 1600, "truncations_consumed": 0,
        }
        record, sidecar = load_verified_cart_pole_run(result["run_dir"])
        assert len(record.provenance["confirmed_steps"]) == 400
        assert all(item == {"step": index, "status": "double_committed",
                            "products": 4, "truncations": 0}
                   for index, item in enumerate(record.provenance["confirmed_steps"]))
        assert sidecar["branches"]["ideal"]["statuses"][-1] == "stable"
        assert sidecar["branches"]["secure"]["statuses"][-1] == "stable"
        states, raw, applied, statuses, counts = _independent_run(
            (0, 0, 0.08726646259971647, 0)
        )
        for name in ("ideal", "secure"):
            state_atol = IDEAL_ORACLE_ATOL if name == "ideal" else SECURE_STATE_ATOL
            force_atol = IDEAL_ORACLE_ATOL if name == "ideal" else SECURE_FORCE_ATOL
            np.testing.assert_allclose(getattr(record.result, f"output_{name}"),
                                       states[:-1], rtol=0, atol=state_atol)
            np.testing.assert_allclose(getattr(record.result, f"control_{name}")[:, 0],
                                       applied, rtol=0, atol=force_atol)
            branch = sidecar["branches"][name]
            np.testing.assert_allclose(branch["raw_force_n"], raw, rtol=0, atol=force_atol)
            np.testing.assert_allclose(branch["observations"], states, rtol=0,
                                       atol=state_atol)
            assert branch["statuses"] == statuses and branch["stable_counts"] == counts
        assert np.max(np.abs(record.result.output_secure - record.result.output_ideal)) < PAIR_STATE_ATOL
        assert np.max(np.abs(record.result.control_secure - record.result.control_ideal)) < PAIR_FORCE_ATOL
        assert Path(result["figure_path"]).is_file()
        assert all(item[1]["steps_committed"] == 400 for item in outcomes)
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_time_limit_has_no_success_artifact(tmp_path: Path) -> None:
    """十步可全部双提交，但未达到 51 次观测，Client 不发布 complete。"""
    paths = _plain_deployment(tmp_path)
    profile_path = _profile_for(paths)
    data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    balance = yaml.safe_load((ROOT / "configs" / "cart_pole_balance.yaml").read_text(
        encoding="utf-8"
    ))
    balance["horizon_steps"] = 10
    balance_path = tmp_path / "short-balance.yaml"
    balance_path.write_text(yaml.safe_dump(balance), encoding="utf-8")
    data["balance_source"] = str(balance_path)
    profile_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, result, _ = _finish(_run("Client", paths["Client"]), 60)
        assert code != 0 and result["status"] == "failed"
        assert not list((tmp_path / "runs").glob("*/metadata.json"))
        assert not list((tmp_path / "runs").glob("*/control.png"))
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


_SECOND_ROUND_DISCONNECT = r"""
import sys
from pathlib import Path
import secure_control.execution.lan_runtime as lan
from secure_control.experiments.lan_runner import cli

capture = Path(sys.argv[1])
original = lan._party_reply
def reply(sock, request, payload, timeout, **kwargs):
    if (request.operation == 'endpoint' and request.step == 1
            and getattr(request.payload, 'operation', None) == 'stage_batch'):
        capture.write_text(request.session_id, encoding='utf-8')
        sock.close()
        raise RuntimeError('injected second-round disconnect')
    return original(sock, request, payload, timeout, **kwargs)
lan._party_reply = reply
sys.argv = ['secure-control', 'p1', '--config', sys.argv[2]]
cli()
"""


def test_second_round_disconnect_then_new_session(tmp_path: Path) -> None:
    """提交不确定时无 success artifact；新进程/新 session 可重新完成。"""
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    for path in paths.values():
        path.write_text(path.read_text(encoding="utf-8").replace(
            "step: 30", "step: 3"
        ).replace("idle: 30", "idle: 3"), encoding="utf-8")
    captured = tmp_path / "failed-session.txt"
    p1 = subprocess.Popen(
        [sys.executable, "-c", _SECOND_ROUND_DISCONNECT, str(captured), str(paths["P1"])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p2 = _run("P2", paths["P2"])
    try:
        time.sleep(.5)
        code, failed, _ = _finish(_run("Client", paths["Client"]), 30)
        assert code != 0 and failed["status"] == "failed"
        p1_output, p1_errors = p1.communicate(timeout=10)
        assert captured.is_file() and captured.read_text(encoding="utf-8"), (
            failed, p1_output, p1_errors,
        )
        assert not list((tmp_path / "runs").glob("*/metadata.json"))
    finally:
        for party in (p1, p2):
            if party.poll() is None:
                party.kill()
            party.communicate()
    fresh = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(.5)
        code, success, errors = _finish(_run("Client", paths["Client"]), 600)
        assert code == 0, (success, errors)
        assert success["session_id"] != captured.read_text(encoding="utf-8")
        assert all(_finish(party, 30)[0] == 0 for party in fresh)
        load_verified_cart_pole_run(success["run_dir"])
    finally:
        for party in fresh:
            if party.poll() is None:
                party.kill()
            party.communicate()
