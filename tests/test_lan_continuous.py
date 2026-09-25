"""#86：同一 mTLS 会话跨轮、严格 profile 与正式图发布回归。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest
import yaml
from test_lan_single_step import ROOT, _finish, _free_ports, _run
from test_lan_single_step import deployment as _base_deployment

from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import LanContinuousRuntime
from secure_control.execution.localhost_codec import (
    LanContinuousSetupPayload,
    LanHelloPayload,
    decode_wire_value,
    encode_wire_value,
)
from secure_control.experiments.artifacts import load_artifacts, write_artifacts
from secure_control.experiments.lan_profile import load_paper_pid_lan_profile
from secure_control.experiments.plotting import plot_control_triptych, redraw_control_triptych
from secure_control.experiments.quadruple_tank_lan_profile import load_quadruple_tank_lan_profile
from secure_control.scenarios.paper_pid.plant import PaperPidCascadePlant
from secure_control.scenarios.paper_pid.secure_experiment import (
    build_paper_pid_plan,
    paper_pid_numeric_contract,
)
from secure_control.simulation import compare_closed_loops


@pytest.fixture
def deployment(tmp_path: Path) -> dict[str, Path]:
    """复用 #68 的独立角色证书和随机端口准备。"""
    return _base_deployment.__wrapped__(tmp_path)


def _continuous_config(paths: dict[str, Path], count: int, ell: int = 32) -> Path:
    definition = yaml.safe_load((ROOT / "configs" / "paper_pid_fig3_sweep.yaml").read_text(
        encoding="utf-8"
    ))
    profile = paths["Client"].parent / "experiment.yaml"
    data = {
        "schema_version": 1, "scenario": "paper_pid_fig3", "sample_count": count,
        "numeric": {
            "ell": ell, "k": ell + definition["paper_parameter_headroom_bits"],
            "runtime_payload_bits": ell + definition["runtime_payload_headroom_bits"],
            "lambda": definition["security_parameter"],
            "prime_source": str(ROOT / "configs" / "shared_prime_256_pocklington.yaml"),
        },
        "range": {"measurement_absolute_bound": definition["measurement_absolute_bound"]},
        "plot": {"control_channel": 0},
        "frozen_definition": str(ROOT / "configs" / "paper_pid_fig3_sweep.yaml"),
        "output_root": str(profile.parent / "runs"),
    }
    profile.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    role = paths["Client"]
    role.write_text(role.read_text(encoding="utf-8").replace(
        f"controller: {ROOT / 'tests' / 'fixtures' / 'legacy_hvac' / 'hvac_dual_loop.yaml'}",
        f"experiment: {profile}",
    ).replace("experiment: paper_pid_lan.example.yaml",
              f"experiment: {profile}"), encoding="utf-8")
    return profile


def _nested_keys(value: object) -> list[str]:
    if isinstance(value, dict):
        return [str(key) for key in value] + [
            item for child in value.values() for item in _nested_keys(child)
        ]
    if isinstance(value, list):
        return [item for child in value for item in _nested_keys(child)]
    return []


def _run_module(role: str, config: Path) -> subprocess.Popen[str]:
    """以 VS Code launch.json 所用模块入口启动真实独立进程。"""
    return subprocess.Popen(
        [sys.executable, "-m", "secure_control.experiments.lan_runner",
         role.lower(), "--config", str(config)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _plain_deployment(tmp_path: Path) -> dict[str, Path]:
    """无证书文件的随机端口实验配置，验证三份直接运行脚本。"""
    ports = _free_ports()
    topology = ROOT / "configs" / "local-deployment.example.yaml"
    content = topology.read_text(encoding="utf-8")
    for old, new in zip((34401, 34402, 34403), ports, strict=True):
        content = content.replace(f"port: {old}", f"port: {new}")
    topology_path = tmp_path / "topology.yaml"
    topology_path.write_text(content, encoding="utf-8")
    paths = {}
    for role, name in (("P1", "lab-p1.example.yaml"), ("P2", "lab-p2.example.yaml"),
                       ("Client", "lab-client-continuous.example.yaml")):
        role_content = (ROOT / "configs" / name).read_text(encoding="utf-8")
        role_content = role_content.replace("topology: local-deployment.example.yaml",
                                            f"topology: {topology_path}")
        path = tmp_path / name
        path.write_text(role_content, encoding="utf-8")
        paths[role] = path
    return paths


def _tank_profile(paths: dict[str, Path], count: int, ell: int = 32,
                  channel: int = 1) -> Path:
    """只改 Client profile；P1/P2 沿用与 PID 相同的场景无关入口。"""
    profile = paths["Client"].parent / "tank-experiment.yaml"
    data = yaml.safe_load((ROOT / "configs" / "quadruple_tank_lan.example.yaml").read_text(
        encoding="utf-8"
    ))
    data["sample_count"] = count
    data["numeric"].update({"ell": ell, "k": ell + 8, "runtime_payload_bits": ell + 14})
    data["numeric"]["prime_source"] = str(ROOT / "configs" /
                                            "shared_prime_256_pocklington.yaml")
    data["plant_source"] = str(ROOT / "configs" / "quadruple_tank_plant.yaml")
    data["observer_source"] = str(ROOT / "configs" / "quadruple_tank_observer.yaml")
    data["plot"]["control_channel"] = channel
    data["output_root"] = str(profile.parent / "tank-runs")
    profile.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    role = paths["Client"]
    role.write_text(role.read_text(encoding="utf-8").replace(
        "experiment: paper_pid_lan.example.yaml", f"experiment: {profile}"
    ), encoding="utf-8")
    return profile


def test_quadruple_tank_three_process_short_session_and_selected_redraw(tmp_path: Path) -> None:
    """真实三进程 MIMO 每步消耗 36 triple/4 Trunc，通道 1 重绘保持选择。"""
    paths = _plain_deployment(tmp_path)
    _tank_profile(paths, 3)
    parties = [_run(role, paths[role]) for role in ("P1", "P2")]
    try:
        time.sleep(0.5)
        client = _run("Client", paths["Client"])
        code, result, errors = _finish(client, 100)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 100) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert result["scenario"] == "quadruple_tank"
        assert result["resource_counts"] == {"products_consumed": 108,
                                               "truncations_consumed": 12}
        record = load_artifacts(result["run_dir"])
        assert record.result.control_error.shape == (3, 2)
        assert record.provenance["confirmed_steps"] == [
            {"step": index, "status": "double_committed", "products": 36,
             "truncations": 4} for index in range(3)
        ]
        assert record.provenance["scale_ledger"]["state_truncation_bits"] == 32
        assert np.array_equal(record.result.control_error,
                              record.result.control_ideal - record.result.control_secure)
        selected = json.loads((Path(result["run_dir"]) / "control_plot.json").read_text(
            encoding="utf-8"
        ))
        assert selected["control_channel"] == 1
        redrawn = redraw_control_triptych(result["run_dir"], tmp_path / "redrawn.png")
        assert redrawn.read_bytes() == (Path(result["run_dir"]) / "control.png").read_bytes()
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


@pytest.mark.parametrize("change", [
    lambda data: data["range"].update({"measurement_absolute_bounds_v": [4, 256]}),
    lambda data: data["numeric"].update({"k": 32}),
    lambda data: data["numeric"].update({"runtime_payload_bits": 40}),
    lambda data: data["numeric"].update({"lambda": 230}),
    lambda data: data["plot"].update({"control_channel": 2}),
    lambda data: data.update({"observer_source": "missing.yaml"}),
])
def test_tank_bad_profile_fails_before_network(tmp_path: Path, change) -> None:
    paths = _plain_deployment(tmp_path)
    profile = _tank_profile(paths, 3)
    data = yaml.safe_load(profile.read_text(encoding="utf-8"))
    change(data)
    profile.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises((ValueError, TypeError, OSError)):
        load_quadruple_tank_lan_profile(profile)


def test_direct_python_files_run_three_role_lab_without_certificates(tmp_path: Path) -> None:
    """三个独立 Python 文件各启动一角，Client 发布三步真实图。"""
    paths = _plain_deployment(tmp_path)
    profile = _continuous_config(paths, 3, ell=33)
    data = yaml.safe_load(profile.read_text(encoding="utf-8"))
    data["baseline_source"] = str(ROOT / "configs" / "paper_pid_cascade_zoh.yaml")
    del data["frozen_definition"]
    profile.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert not list(tmp_path.glob("*.pem"))
    parties = [subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / f"run_continuous_{role.lower()}.py"),
         str(paths[role])], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    ) for role in ("P1", "P2")]
    try:
        time.sleep(0.5)
        client = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / "run_continuous_client.py"),
             str(paths["Client"])], cwd=ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        code, result, errors = _finish(client, 100)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 100) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert "Client 配置检查通过" in errors
        assert "Client 与 P1 的协议连接已建立" in errors
        assert "Client 与 P2 的协议连接已建立" in errors
        assert "三方已就绪" in errors and "Client 运行完成" in errors
        assert "P1 已启动" in outcomes[0][2] and "P1 运行完成" in outcomes[0][2]
        assert "P2 已启动" in outcomes[1][2] and "P2 运行完成" in outcomes[1][2]
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert all(item[1]["steps_committed"] == 3 for item in outcomes)
        assert all(item[1]["transport"] == "insecure_tcp" and
                   item[1]["tls_version"] is None for item in outcomes)
        assert result["transport"] == "insecure_tcp" and result["tls_version"] is None
        assert result["ell"] == 33
        assert result["claim_level"] == "user-exploration"
        run_dir = Path(result["run_dir"])
        record = load_artifacts(run_dir)
        assert record.result.time.size == 3
        assert Path(result["figure_path"]).is_file()
        assert record.provenance["transport"] == "insecure_tcp"
        assert record.effective_config["definition"] is None
        assert "unauthenticated plaintext" in record.provenance["security_boundary"]
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_plain_transport_must_be_explicit_and_must_not_ignore_tls(tmp_path: Path) -> None:
    paths = _plain_deployment(tmp_path)
    role = paths["P1"]
    content = role.read_text(encoding="utf-8")
    role.write_text(content.replace("transport: insecure_tcp\n", ""), encoding="utf-8")
    with pytest.raises(ValueError):
        load_lan_config(role, "P1")
    role.write_text(content + "tls:\n  ca: ignored.pem\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_lan_config(role, "P1")


def test_default_lab_configs_need_no_certificate_files() -> None:
    for role, name in (("P1", "lab-p1.example.yaml"), ("P2", "lab-p2.example.yaml"),
                       ("Client", "lab-client-continuous.example.yaml")):
        config = load_lan_config(ROOT / "configs" / name, role)
        assert config.transport == "insecure_tcp"
        assert (config.ca, config.certificate, config.private_key) == (None, None, None)


def test_continuous_setup_codec_keeps_prime_evidence(deployment: dict[str, Path]) -> None:
    profile = load_paper_pid_lan_profile(_continuous_config(deployment, 3))
    setup = LanContinuousSetupPayload(
        profile.q, profile.runtime_payload_bits, profile.ell,
        profile.security_parameter, (1, 1), (1,), 3, profile.evidence,
    )
    assert decode_wire_value(encode_wire_value(setup)) == setup
    assert decode_wire_value(encode_wire_value(LanHelloPayload(
        "a" * 64, "b" * 64, "lan-continuous-v1"
    ))).mode == "lan-continuous-v1"


def test_client_profile_can_use_paper_pid_baseline_without_fig3_definition(
    deployment: dict[str, Path],
) -> None:
    """日常三角色实验不必依赖 Fig3 四点冻结定义。"""
    path = _continuous_config(deployment, 3, ell=33)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data.pop("frozen_definition")
    data["baseline_source"] = str(ROOT / "configs" / "paper_pid_cascade_zoh.yaml")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    profile = load_paper_pid_lan_profile(path)
    assert profile.ell == 33
    assert profile.claim_level == "user-exploration"


@pytest.mark.parametrize("replacement", ["ell: 0", "k: 32", "lambda: 250",
                                           "sample_count: 0", "measurement_absolute_bound: 1"])
def test_bad_profile_rejected_before_network(
    deployment: dict[str, Path], replacement: str
) -> None:
    profile = _continuous_config(deployment, 3)
    content = profile.read_text(encoding="utf-8")
    if replacement.startswith("ell"):
        content = content.replace("ell: 32", replacement)
    elif replacement.startswith("k"):
        content = content.replace("k: 40", replacement)
    elif replacement.startswith("lambda"):
        content = content.replace("lambda: 80", replacement)
    elif replacement.startswith("measurement"):
        content = content.replace("measurement_absolute_bound: 128", replacement)
    else:
        content = content.replace("sample_count: 3", replacement)
    profile.write_text(content, encoding="utf-8")
    with pytest.raises((ValueError, TypeError)):
        load_paper_pid_lan_profile(profile)


def test_profile_duplicate_and_wrong_prime_rejected(deployment: dict[str, Path]) -> None:
    profile = _continuous_config(deployment, 3)
    with profile.open("a", encoding="utf-8") as target:
        target.write("sample_count: 4\n")
    with pytest.raises(ValueError, match="重复"):
        load_paper_pid_lan_profile(profile)
    profile = _continuous_config(deployment, 3)
    prime = ROOT / "configs" / "shared_prime_256_pocklington.yaml"
    bad_prime = profile.parent / "bad_prime.yaml"
    content = prime.read_text(encoding="utf-8")
    source = load_paper_pid_lan_profile(profile)
    bad_prime.write_text(content.replace(str(source.q), str(source.q + 2), 1), encoding="utf-8")
    profile.write_text(profile.read_text(encoding="utf-8").replace(
        str(prime), str(bad_prime)
    ), encoding="utf-8")
    with pytest.raises((ValueError, TypeError)):
        load_paper_pid_lan_profile(profile)


def test_bad_shared_prime_certificate_rejected_before_network(deployment: dict[str, Path]) -> None:
    """证书损坏必须在 Client 配置预检阶段失败。"""
    profile = _continuous_config(deployment, 3)
    prime = ROOT / "configs" / "shared_prime_256_pocklington.yaml"
    damaged = profile.parent / "damaged_prime.yaml"
    damaged.write_text(prime.read_text(encoding="utf-8").replace(
        "aa15ad45266d1c1bffee97cb2626ba4940ffbc8c3472045e92696c196a06dc3b",
        "ba15ad45266d1c1bffee97cb2626ba4940ffbc8c3472045e92696c196a06dc3b", 1
    ), encoding="utf-8")
    profile.write_text(profile.read_text(encoding="utf-8").replace(
        str(prime), str(damaged)
    ), encoding="utf-8")
    with pytest.raises((ValueError, TypeError)):
        load_paper_pid_lan_profile(profile)
    assert not (profile.parent / "runs").exists()


@pytest.mark.parametrize(("count", "ell"), [(3, 32), (51, 32), (51, 40)])
def test_three_independent_continuous_roles_publish_one_verified_run(
    deployment: dict[str, Path], count: int, ell: int
) -> None:
    profile = _continuous_config(deployment, count, ell)
    parties = [_run_module(role, deployment[role]) for role in ("P1", "P2")]
    try:
        time.sleep(0.5)
        client = _run_module("Client", deployment["Client"])
        code, result, errors = _finish(client, 100)
        assert code == 0, (result, errors)
        outcomes = [_finish(party, 100) for party in parties]
        assert all(item[0] == 0 for item in outcomes), outcomes
        assert len({result["pid"], *(item[1]["pid"] for item in outcomes)}) == 3
        assert all(item[1]["steps_committed"] == count for item in outcomes)
        assert all(item[1]["tls_version"] == "TLSv1.3" for item in outcomes)
        assert all(item[1]["profile_sha256"] == result["topology_sha256"]
                   for item in outcomes)
        assert result["resource_counts"] == {
            "products_consumed": 9 * count, "truncations_consumed": 2 * count,
        }
        run_dir = Path(result["run_dir"])
        record = load_artifacts(run_dir)
        assert Path(result["figure_path"]) == (run_dir / "control.png").resolve()
        assert result["scenario"] == "paper_pid_fig3"
        assert result["ell"] == ell
        assert result["claim_level"] == record.effective_config["claim_level"]
        if count == 51:
            assert result["claim_level"] == "paper-inspired-frozen-parameter-point"
        assert record.result.time.size == count
        assert record.effective_config["fractional_bits"] == ell
        assert record.provenance["session_id"] == result["session_id"]
        assert record.provenance["topology_sha256"] == result["topology_sha256"]
        public_keys = _nested_keys(result) + _nested_keys(record.effective_config)
        public_keys += _nested_keys(record.provenance)
        public_keys += [key for item in outcomes for key in _nested_keys(item[1])]
        assert not any(secret in key.lower() for key in public_keys
                       for secret in ("share", "triple", "mask", "nonce", "private_key", "combined"))
        assert [item["step"] for item in record.provenance["confirmed_steps"]] == list(range(count))
        assert all(item["products"] == 9 and item["truncations"] == 2
                   for item in record.provenance["confirmed_steps"])
        assert (run_dir / "control.png").is_file()
        plot = json.loads((run_dir / "control_plot.json").read_text(encoding="utf-8"))
        assert plot["shared_control_y_scale"] is True
        assert plot["sample_count"] == count
        assert record.effective_config["profile_sha256"] == load_paper_pid_lan_profile(profile).digest
        if count == 51:
            # 两次安全随机性可不同；用 #70 预先冻结的 epsilon 和 plant 增益给出界。
            frozen_root = ROOT / "results" / "paper_pid_fig3"
            frozen_manifest = json.loads((frozen_root / "manifest.json").read_text(encoding="utf-8"))
            frozen_id = next(item["run_id"] for item in frozen_manifest["runs"]
                             if item["ell"] == ell)
            frozen = load_artifacts(frozen_root / frozen_id)
            np.testing.assert_array_equal(record.result.time, frozen.result.time)
            np.testing.assert_array_equal(record.result.control_ideal,
                                          frozen.result.control_ideal)
            epsilon = frozen_manifest["definition"]["epsilon"]
            control_bound = 2 * epsilon
            assert np.max(np.abs(record.result.control_secure
                                 - frozen.result.control_secure)) < control_bound
            matrices = PaperPidCascadePlant(0.2, 0.1, np.full(4, 100.0)).state_space
            impulse = np.array(matrices.B_p[:, 0], copy=True)
            gain = 0.0
            for _ in range(count - 1):
                gain += abs(float((matrices.C_p @ impulse)[0]))
                impulse = matrices.A_p @ impulse
            assert np.max(np.abs(record.result.output_secure
                                 - frozen.result.output_secure)) <= control_bound * gain + 1e-12
            if ell == 32:
                point = load_paper_pid_lan_profile(profile)
                local_plan, local_runtime, _ = build_paper_pid_plan(
                    fractional_bits=ell, modulus=point.q, modulus_evidence=point.evidence,
                    security_parameter=point.security_parameter, sample_count=count,
                    measurement_absolute_bound=point.measurement_absolute_bound,
                    runtime_payload_headroom_bits=14, test_seed=70, backend="localhost",
                )
                try:
                    local = compare_closed_loops(local_plan.ideal, local_plan.secure,
                                                 local_plan.sample_times)
                finally:
                    local_runtime.close()
                np.testing.assert_array_equal(record.result.time, local.time)
                assert np.max(np.abs(record.result.control_secure
                                     - local.control_secure)) < control_bound
                assert np.max(np.abs(record.result.output_secure
                                     - local.output_secure)) <= control_bound * gain + 1e-12
        figure = plot_control_triptych(record, 0)
        np.testing.assert_array_equal(figure.axes[0].lines[0].get_ydata(),
                                      record.result.control_ideal[:, 0])
        np.testing.assert_array_equal(figure.axes[1].lines[0].get_ydata(),
                                      record.result.control_secure[:, 0])
        np.testing.assert_array_equal(figure.axes[2].lines[0].get_ydata(),
                                      record.result.control_error[:, 0])
        assert figure.axes[0].get_ylim() == figure.axes[1].get_ylim()
        np.testing.assert_array_equal(figure.axes[0].get_yticks(), figure.axes[1].get_yticks())
        np.testing.assert_array_equal(figure.axes[0].lines[0].get_xdata(), record.result.time)
        np.testing.assert_array_equal(figure.axes[1].lines[0].get_xdata(), record.result.time)
        figure.clear()
        if count == 3:
            redrawn = redraw_control_triptych(run_dir, profile.parent / "redrawn.png")
            assert redrawn.is_file()
            assert redrawn.read_bytes() == (run_dir / "control.png").read_bytes()

            # 重启全部角色后，不能续用上一组 share/session 或已发布 run ID。
            again = [_run(role, deployment[role]) for role in ("P1", "P2")]
            try:
                time.sleep(0.5)
                second = _run("Client", deployment["Client"])
                second_code, second_result, second_error = _finish(second, 30)
                assert second_code == 0, (second_result, second_error)
                assert second_result["session_id"] != result["session_id"]
                assert second_result["run_id"] != result["run_id"]
                assert all(_finish(party, 30)[0] == 0 for party in again)
            finally:
                for party in again:
                    if party.poll() is None:
                        party.kill()
                    party.communicate()

            def fail_render(_record, _stage):
                raise RuntimeError("render failed")

            with pytest.raises(RuntimeError, match="render failed"):
                write_artifacts(record.result, record.metadata, record.effective_config,
                                record.provenance, output_root=profile.parent / "failed-runs",
                                derived_writer=fail_render)
            assert list((profile.parent / "failed-runs").iterdir()) == []
            with (run_dir / "control.png").open("ab") as target:
                target.write(b"tampered")
            with pytest.raises(ValueError, match="摘要"):
                load_artifacts(run_dir)
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_shared_prime_and_frozen_compatibility_bytes() -> None:
    """公开证据的日常名称不能使旧 raw SHA 或 HVAC LF 摘要漂移。"""
    shared = (ROOT / "configs" / "shared_prime_256_pocklington.yaml").read_bytes()
    legacy = (ROOT / "configs" / "hvac_2r2c_sweep_prime.yaml").read_bytes()
    fixture = (ROOT / "tests" / "fixtures" / "legacy_hvac" / "hvac_2r2c_sweep_prime.yaml").read_bytes()
    definition = (ROOT / "configs" / "paper_pid_fig3_sweep.yaml").read_bytes()
    assert shared == legacy == fixture
    assert sha256(shared).hexdigest() == (
        "b8c5e9e779d945cfc19d0662b641cd1084acadd0907cc6b4e64ee4076455111b"
    )
    assert sha256(shared.replace(b"\r\n", b"\n")).hexdigest() == (
        "b317a7db4f14fbf77258102d6b09766dc3b5f495252c1e29ed3ae315cb98340c"
    )
    assert sha256(definition).hexdigest() == (
        "16b635276927e4a14977ff7ac2d7baa67885fc3244017589fb2a638b5c6de39a"
    )


_LOST_SECOND_COMMIT = r"""
import sys
import secure_control.execution.lan_runtime as lan
from secure_control.experiments.lan_runner import cli
original = lan._party_reply
def reply(sock, request, payload, timeout, **kwargs):
    if request.operation == 'endpoint' and request.step == 1 and getattr(request.payload, 'operation', None) == 'commit':
        sock.close()
        raise RuntimeError('injected second-step commit ack loss')
    return original(sock, request, payload, timeout, **kwargs)
lan._party_reply = reply
sys.argv = ['secure-control', *sys.argv[1:]]
cli()
"""

_STALE_SECOND_ONLINE = r"""
import sys
import secure_control.execution.lan_runtime as lan
from secure_control.experiments.lan_runner import cli
original = lan._request
def request(sock, role, sequence, operation, session, timeout, payload=None, round_id=None, step=None, **kwargs):
    if role == 'P1' and operation == 'online' and step == 1:
        step = 0
    return original(sock, role, sequence, operation, session, timeout, payload, round_id, step, **kwargs)
lan._request = request
sys.argv = ['secure-control', *sys.argv[1:]]
cli()
"""


def test_second_round_commit_ack_loss_has_no_success_run(deployment: dict[str, Path]) -> None:
    profile = _continuous_config(deployment, 3)
    p1 = _run("P1", deployment["P1"])
    p2 = subprocess.Popen(
        [sys.executable, "-c", _LOST_SECOND_COMMIT, "p2", "--config", str(deployment["P2"])],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        time.sleep(0.5)
        client = _run("Client", deployment["Client"])
        code, result, _ = _finish(client, 30)
        assert code != 0 and result["status"] == "failed"
        assert not (profile.parent / "runs").exists()
        assert _finish(p2, 30)[0] != 0
        assert _finish(p1, 30)[0] != 0
    finally:
        for party in (p1, p2):
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_second_round_stale_step_rejected(deployment: dict[str, Path]) -> None:
    profile = _continuous_config(deployment, 3)
    parties = [_run(role, deployment[role]) for role in ("P1", "P2")]
    try:
        time.sleep(0.5)
        client = subprocess.Popen(
            [sys.executable, "-c", _STALE_SECOND_ONLINE, "client", "--config",
             str(deployment["Client"])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        code, result, _ = _finish(client, 30)
        assert code != 0 and result["status"] == "failed"
        assert not (profile.parent / "runs").exists()
        assert all(_finish(party, 30)[0] != 0 for party in parties)
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()


def test_measurement_out_of_range_invalidates_session(deployment: dict[str, Path]) -> None:
    profile = load_paper_pid_lan_profile(_continuous_config(deployment, 3))
    spec, context, contract = paper_pid_numeric_contract(
        fractional_bits=profile.ell, parameter_bits=profile.parameter_bits,
        runtime_payload_bits=profile.runtime_payload_bits, modulus=profile.q,
        sample_count=profile.sample_count,
        measurement_absolute_bound=profile.measurement_absolute_bound,
    )
    parties = [_run(role, deployment[role]) for role in ("P1", "P2")]
    try:
        time.sleep(0.5)
        runtime = LanContinuousRuntime(
            load_lan_config(deployment["Client"], "Client"), spec, context, contract,
            profile.security_parameter, profile.evidence,
        )
        try:
            with pytest.raises(ValueError, match="input_payload_bounds"):
                runtime.step(np.array([129.0]))
            with pytest.raises(RuntimeError, match="已失败"):
                runtime.step(np.array([100.0]))
        finally:
            runtime.close()
        assert all(_finish(party, 30)[0] != 0 for party in parties)
    finally:
        for party in parties:
            if party.poll() is None:
                party.kill()
            party.communicate()
