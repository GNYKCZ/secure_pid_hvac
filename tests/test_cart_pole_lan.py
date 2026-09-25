"""#92：倒立摆 LAN profile、范围证明、正式场景证据和三进程闭环。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest
import yaml
from test_cart_pole_balance import _independent_run
from test_lan_continuous import _finish, _plain_deployment, _run

from secure_control.crypto import TwoPartySharing
from secure_control.experiments.artifacts import write_artifacts
from secure_control.experiments.cart_pole_evidence import (
    EVIDENCE_NAME,
    load_verified_cart_pole_run,
    verify_cart_pole_evidence,
    write_cart_pole_evidence,
)
from secure_control.experiments.cart_pole_lan_profile import load_cart_pole_lan_profile
from secure_control.experiments.lan_continuous_profile import load_prepared_lan_experiment
from secure_control.protocol import Client
from secure_control.scenarios.cart_pole.secure_experiment import (
    CartPoleSecureExperiment,
    cart_pole_numeric_contract,
)
from secure_control.simulation import compare_closed_loops

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "configs" / "cart_pole_lan.example.yaml"
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
            and getattr(request.payload, 'operation', None) == 'stage_output'):
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
