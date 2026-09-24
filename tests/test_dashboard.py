"""A08 本机只读服务、正式回放和真实三角色同次产物验证。"""

from __future__ import annotations

import http.client
import json
import time
from pathlib import Path

import numpy as np
import pytest

import secure_control.experiments.paper_pid_fig3 as paper_fig3
from secure_control.experiments.artifacts import load_artifacts, write_artifacts
from secure_control.experiments.dashboard import run_live_hvac, run_live_paper
from secure_control.experiments.dashboard_server import DashboardServer, DashboardState
from secure_control.experiments.paper_pid_fig3 import (
    _run_point,
    load_definition,
    render_saved_sweep,
)
from secure_control.experiments.telemetry_replay import replay_events
from secure_control.scenarios.paper_pid.baseline import run_paper_pid_baseline
from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult
from secure_control.simulation.telemetry import (
    BoundedPublisher,
    TelemetrySession,
    public_event_dict,
)

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "results/paper_pid_fig3"


def _request(server: DashboardServer, method: str, path: str, *, host: str | None = None):
    """只访问当前测试启动的 loopback 端口。"""
    port = int(server.url.split(":")[-1].strip("/"))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    connection.request(method, path, headers={"Host": host or f"127.0.0.1:{port}"})
    response = connection.getresponse()
    content = response.read()
    status = response.status
    headers = dict(response.getheaders())
    connection.close()
    return status, headers, content


def test_saved_paper_sweep_replays_both_raw_control_curves_at_every_step() -> None:
    """四个已发布 run 的 u/û 与 canonical reader 逐值同源，非误差替身。"""
    manifest = render_saved_sweep(PAPER)
    state = DashboardState()
    for entry in manifest["runs"]:
        state.register_run(PAPER / entry["run_id"])
    server = DashboardServer(state, port=0)
    server.start()
    try:
        status, _, body = _request(server, "GET", "/api/status")
        assert status == 200
        runs = json.loads(body)["runs"]
        assert len(runs) == 4
        assert all(item["backend"] == "single_process" for item in runs)
        assert all(item["reference_used"] is False for item in runs)
        assert all(item["raw_equals_applied"] is True for item in runs)
        for entry in manifest["runs"]:
            run_id = entry["run_id"]
            record = load_artifacts(PAPER / run_id)
            status, headers, body = _request(server, "GET", f"/api/runs/{run_id}/events")
            assert status == 200
            assert headers["Content-Type"] == "text/event-stream; charset=utf-8"
            events = [
                json.loads(line.removeprefix("data: "))
                for line in body.decode("utf-8").splitlines()
                if line.startswith("data: ")
            ]
            assert len(events) == 53
            assert events[0]["channels"]["reference"]["names"] == ["unused_zero"]
            assert events[0]["channels"]["control"]["units"] == ["paper_unit_unspecified"]
            for step, sample in enumerate(events[1:-1]):
                assert sample["step"] == step
                assert sample["time_s"] == float(record.result.time[step])
                assert sample["control_ideal"] == record.result.control_ideal[step].tolist()
                assert sample["control_secure"] == record.result.control_secure[step].tolist()
                assert sample["control_error"] == record.result.control_error[step].tolist()
                assert sample["roles"]["P1"] == {"state": "unknown", "source": "unavailable"}
                assert sample["latency_ms"]["controller_round"] is None
    finally:
        server.close()


def test_http_rejects_nonlocal_host_control_methods_paths_and_unlisted_run() -> None:
    """浏览器既不能注入文件路径，也没有参数、协议或重试端点。"""
    state = DashboardState()
    server = DashboardServer(state, port=0)
    server.start()
    try:
        status, headers, body = _request(server, "GET", "/")
        assert status == 200 and b"Client" in body
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert "Access-Control-Allow-Origin" not in headers
        assert _request(server, "GET", "/app.js")[0] == 200
        assert _request(server, "GET", "/style.css")[0] == 200
        assert _request(server, "GET", "/api/status", host="evil.example")[0] == 400
        assert _request(server, "POST", "/api/start")[0] == 405
        assert _request(server, "GET", "/api/start")[0] == 404
        assert _request(server, "GET", "/api/status?path=C:/secret")[0] == 404
        assert _request(server, "GET", "/../../private")[0] == 404
        assert (
            _request(server, "GET", "/api/runs/20260101T000000000000Z-000000000000/events")[0]
            == 404
        )
    finally:
        server.close()


def test_vector_channels_keep_names_units_and_values_in_verified_replay(tmp_path: Path) -> None:
    """混合单位的双通道结果不被折成标量，也不推造 reference/output 共轴。"""
    metadata = ScenarioMetadata(
        "toy",
        ChannelMetadata(("target_temperature", "voltage"), ("degC", "V")),
        ChannelMetadata(("air_temperature", "current"), ("degC", "A")),
        ChannelMetadata(("cooling_power", "charge"), ("kW", "A")),
    )
    reference = np.array([[20.0, 5.0], [21.0, 6.0]])
    output_ideal = np.array([[19.0, 3.0], [20.0, 4.0]])
    output_secure = output_ideal - 1.0
    control_ideal = np.array([[1.0, 2.0], [3.0, 4.0]])
    control_secure = control_ideal - 0.5
    result = SimulationResult(
        time=np.array([0.0, 1.0]),
        reference=reference,
        output_ideal=output_ideal,
        output_secure=output_secure,
        control_ideal=control_ideal,
        control_secure=control_secure,
        control_error=control_ideal - control_secure,
        output_error=output_ideal - output_secure,
    )
    artifact = write_artifacts(
        result,
        metadata,
        {"scenario": {"name": "toy", "version": "1"}},
        {"scenario_name": "toy", "scenario_version": "1", "schema_version": 1},
        output_root=tmp_path / "runs",
    )
    state = DashboardState()
    state.register_run(artifact.run_dir)
    server = DashboardServer(state, port=0)
    server.start()
    try:
        status, _, body = _request(server, "GET", f"/api/runs/{artifact.run_id}/events")
        assert status == 200
        events = [
            json.loads(line.removeprefix("data: "))
            for line in body.decode("utf-8").splitlines()
            if line.startswith("data: ")
        ]
        assert events[0]["channels"]["reference"] == {
            "names": ["target_temperature", "voltage"],
            "units": ["degC", "V"],
        }
        assert events[0]["channels"]["output"] == {
            "names": ["air_temperature", "current"],
            "units": ["degC", "A"],
        }
        assert events[1]["reference"] == [20.0, 5.0]
        assert events[2]["control_secure"] == [2.5, 3.5]
    finally:
        server.close()


def test_sse_connection_limit_and_disconnect_cleanup() -> None:
    """慢 SSE 占用的线程有上限，断线后订阅与连接槽可再次使用。"""
    state = DashboardState(max_subscribers=1)
    server = DashboardServer(state, port=0)
    server.start()
    port = int(server.url.split(":")[-1].strip("/"))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/api/events")
        response = connection.getresponse()
        assert response.status == 200
        assert _request(server, "GET", "/api/events")[0] == 503
        response.close()
        connection.close()
        deadline = time.monotonic() + 5
        while state.status()["subscribers"] and time.monotonic() < deadline:
            time.sleep(0.05)
        assert state.status()["subscribers"] == 0
        assert state.acquire_stream()
        state.release_stream()
    finally:
        connection.close()
        server.close()


def test_live_paper_same_session_verified_result_and_slow_subscriber(tmp_path: Path) -> None:
    """真实 localhost 运行的直播、资源和正式回放同源；慢页面可丢帧。"""
    state = DashboardState()
    slow = state.subscribe()
    assert slow is not None
    live_events = []

    def consume(event):
        state.publish(event)
        live_events.append(public_event_dict(event))

    publisher = BoundedPublisher(consume, capacity=8)
    state.publisher = publisher
    session = TelemetrySession(publisher)
    started = time.monotonic()
    try:
        run_id = run_live_paper(
            ROOT / "configs/paper_pid_fig3_sweep.yaml",
            ell=32,
            output_root=tmp_path / "paper",
            test_seed=70,
            state=state,
            telemetry=session,
        )
        # 终态可以滞后于正式写入；派发线程不得阻塞控制。
        deadline = time.monotonic() + 5
        while state.status()["publication"] != "verified" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert time.monotonic() - started < 40
        assert state.status()["publication"] == "verified"
        assert state.status()["runs"][0]["live_session_id"] == session.session_id
        record = load_artifacts(tmp_path / "paper" / run_id)
        assert record.provenance["public_telemetry_session_id"] == session.session_id
        assert record.provenance["resource_counts"] == {
            "products_consumed": 459,
            "truncations_consumed": 102,
        }
        assert record.result.time.shape == (51,)
        assert record.result.time[0] == 0 and record.result.time[-1] == 5
        deadline = time.monotonic() + 5
        while (
            not any(event["kind"] == "session_ended" for event in live_events)
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert live_events[0]["roles"]["P1"]["source"] == "session_topology"
        assert live_events[-1]["kind"] == "session_ended"
        for sample in (event for event in live_events if event["kind"] == "sample"):
            step = sample["step"]
            assert sample["time_s"] == float(record.result.time[step])
            for field in (
                "reference",
                "output_ideal",
                "output_secure",
                "control_ideal",
                "control_secure",
                "control_error",
                "output_error",
            ):
                assert sample[field] == getattr(record.result, field)[step].tolist()
        replay = replay_events(tmp_path / "paper" / run_id)
        assert len(replay) == 53
        for step, event in enumerate(replay[1:-1]):
            sample = public_event_dict(event)
            assert sample["control_secure"] == record.result.control_secure[step].tolist()
            assert sample["control_ideal"] == record.result.control_ideal[step].tolist()
        assert slow.dropped_samples > 0
        state.unsubscribe(slow)  # 模拟关闭页面；后续无 Dashboard 的真实三角色基线。
        definition, baseline_config, q, evidence = load_definition(
            ROOT / "configs/paper_pid_fig3_sweep.yaml"
        )
        baseline = run_paper_pid_baseline(
            alpha=baseline_config["plant"]["alpha"],
            sample_period_seconds=baseline_config["plant"]["sample_period_seconds"],
            plant_initial_state=baseline_config["plant"]["initial_state"],
            sample_count=definition["sample_count"],
        )
        no_dashboard = _run_point(
            definition,
            baseline,
            q,
            evidence,
            32,
            output_root=tmp_path / "without_dashboard",
            test_seed=70,
            backend="localhost",
        )
        for field in (
            "time",
            "reference",
            "output_ideal",
            "output_secure",
            "control_ideal",
            "control_secure",
            "control_error",
            "output_error",
        ):
            np.testing.assert_array_equal(
                getattr(record.result, field), getattr(no_dashboard.result, field)
            )
        assert record.provenance["resource_counts"] == no_dashboard.provenance["resource_counts"]
    finally:
        state.unsubscribe(slow)
        publisher.close()


def test_live_hvac_replay_matches_same_real_localhost_result(tmp_path: Path) -> None:
    """180 点 HVAC 的通道、时间与八字段由同一次三角色运行发布。"""
    state = DashboardState()
    publisher = BoundedPublisher(state.publish, capacity=16)
    state.publisher = publisher
    session = TelemetrySession(publisher)
    try:
        run_id = run_live_hvac(
            ROOT / "configs/hvac_2r2c_dual_loop_25_20_15.yaml",
            output_root=tmp_path / "hvac",
            test_seed=42,
            state=state,
            telemetry=session,
        )
        record = load_artifacts(tmp_path / "hvac" / run_id)
        assert record.provenance["backend"] == "localhost"
        assert record.provenance["public_telemetry_session_id"] == session.session_id
        assert record.result.time.size == 180
        assert record.result.time[0] == 0 and record.result.time[-1] == 10740
        replay = replay_events(tmp_path / "hvac" / run_id)
        header = public_event_dict(replay[0])
        assert header["channels"]["reference"]["names"] == ["target_temperature"]
        assert header["channels"]["output"]["units"] == ["degC"]
        assert header["channels"]["control"]["units"] == ["kW_thermal_cooling"]
        for step, event in enumerate(replay[1:-1]):
            sample = public_event_dict(event)
            for field in (
                "reference",
                "output_ideal",
                "output_secure",
                "control_ideal",
                "control_secure",
                "control_error",
                "output_error",
            ):
                assert sample[field] == getattr(record.result, field)[step].tolist()
    finally:
        publisher.close()


def test_failed_publication_never_offers_replay_even_if_end_dispatch_is_late(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A07 completed 仅是控制完成；writer 故障必须保持正式回放不可用。"""
    state = DashboardState()
    publisher = BoundedPublisher(state.publish, capacity=8)
    state.publisher = publisher
    session = TelemetrySession(publisher)

    def fail_writer(*args, **kwargs):
        raise OSError("private path sentinel")

    monkeypatch.setattr(paper_fig3, "write_artifacts", fail_writer)
    try:
        with pytest.raises(OSError):
            run_live_paper(
                ROOT / "configs/paper_pid_fig3_sweep.yaml",
                ell=32,
                output_root=tmp_path / "failed",
                test_seed=70,
                state=state,
                telemetry=session,
            )
        deadline = time.monotonic() + 5
        while state.status()["session_id"] is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert state.status()["publication"] == "unavailable"
        assert state.status()["runs"] == []
        assert not (tmp_path / "failed").exists()
    finally:
        publisher.close()
