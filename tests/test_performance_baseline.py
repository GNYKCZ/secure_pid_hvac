"""共同基线的独立小数组统计与计划边界，不启动网络或系统采集。"""

import pytest


def test_unknown_environment_rejected_before_ledger_or_collect(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import secure_control.experiments.performance_baseline as baseline
    import secure_control.experiments.tail_diagnostic_runner as runner
    from secure_control.execution.lan_config import load_lan_config
    paths = ["configs/lab-p1-cart-pole-demo.example.yaml", "configs/lab-p2-cart-pole-demo.example.yaml"]
    configs = [load_lan_config(p, r) for p, r in zip(paths, ("P1", "P2"), strict=True)]
    plan = {"index": 0, "condition": "L", "configurations": {c.role: runner._config_identity(c) for c in configs}}
    monkeypatch.setattr(baseline, "authorize_baseline", lambda *a, **kw: None)
    monkeypatch.setattr(baseline.subprocess, "check_output", lambda args, **kw: "" if "status" in args else "a"*40)
    monkeypatch.setattr(baseline.shutil, "disk_usage", lambda p: SimpleNamespace(free=10*1024**3))
    monkeypatch.setattr(baseline, "baseline_environment", lambda c: {"verified": False})
    monkeypatch.setattr(runner, "ROOT", tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("must reject before ledger/native/spawn")
    monkeypatch.setattr(runner, "_write_new", forbidden)
    monkeypatch.setattr(runner, "_collect_host", forbidden)
    with pytest.raises(ValueError, match="环境"):
        baseline._run_baseline_host_approved(plan, {"authorization_url": "test"}, "pair", config_paths=paths,
                                            output=tmp_path / "run", expected_head="a"*40)


def pair_package_fixture(root, fault=None):
    import hashlib
    import json

    from secure_control.experiments.baseline_package import publish_package, read_package
    from secure_control.experiments.native_tail_capture import (
        B_RECEIVE_RESOURCES,
        CALIBRATION_RESOURCES,
        plan_digest,
    )
    root.mkdir()
    plan = {"index": 1, "condition": "F", "source_head": "a"*40,
            "hosts": {"pair": B_RECEIVE_RESOURCES, "client": CALIBRATION_RESOURCES}}
    env = {"verified": True, "routes": [1], "cpu_topology": [1], "process_count": 2}
    owner = {"status": "saved", "stop_returncode": 0, "background_unchanged": True,
             "elapsed_s": 50., "etl_bytes": 3, "native_buffer_bytes_at_stop": 8192,
             "nonpaged_sessions_at_stop": True, "native_buffer_budget_exceeded": False,
             "resource_budget_exceeded": False,
             "final_sessions": [{"clock": 1, "events_lost": 0, "buffers_lost": 0,
                                 "buffer_kb": 4, "buffers": 1}] * 2}
    roles = [{"role": r, "pid": k+10, "status": "closed",
              "outcome": {"status": "closed", "steps_committed": 2000,
                          "final_receipt": {"cumulative_committed_count": 2000}}}
             for k, r in enumerate(("P1", "P2"))]
    if fault == "count":
        roles[0]["outcome"]["steps_committed"] = 0
    if fault == "native_partial":
        owner["status"] = "partial"
    group = {"roles": roles, "stop_reason": None, "forced_cleanup": [],
             "exitcodes": [1, 1] if fault == "exit" else [0, 0], "native": owner, "wall_s": 55.}
    files = {"plan.json": plan, "P1.json": roles[0], "P2.json": roles[1]}
    if fault != "missing_owner":
        files["native-owner.json"] = owner
    for name, value in files.items():
        (root / name).write_text(json.dumps(value))
    if fault != "missing_etl":
        (root / "native.etl").write_bytes(b"etl")
    manifest = {"side": "pair", "source_head": "a"*40, "index": 1, "condition": "F",
        "plan_sha256": plan_digest(plan), "functional_complete": True, "capture_complete": True,
        "environment_before": env, "environment_after": env, "group": group,
        "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}}
    (root / "manifest.json").write_text(json.dumps(manifest))
    target = root.parent / (root.name + ".zip")
    publish_package(root, target, {"side": "pair", "index": 1})
    return read_package(target, {"side": "pair", "index": 1})[0], plan


@pytest.mark.parametrize("fault", ["count", "exit", "native_partial", "missing_owner", "missing_etl"])
def test_real_pair_package_validation_rejects_underlying_failures(tmp_path, fault):
    from secure_control.experiments.performance_baseline import validate_manual_result
    records, plan = pair_package_fixture(tmp_path / fault, fault)
    with pytest.raises(ValueError):
        validate_manual_result(records, plan, "pair", [])


def test_real_pair_package_validation_accepts_complete_evidence(tmp_path):
    from secure_control.experiments.performance_baseline import validate_manual_result
    records, plan = pair_package_fixture(tmp_path / "valid")
    assert validate_manual_result(records, plan, "pair", [])["functional_complete"]


def test_formal_prepare_cli_loads_all_definitions(tmp_path):
    import json
    import subprocess
    import sys

    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"source_head": "a" * 40,
        "configurations": {r: {} for r in ("Client", "P1", "P2")},
        "outputs": [{"client": f"A{k}", "pair": f"B{k}"} for k in range(8)]}))
    result = subprocess.run([sys.executable, "-m", "secure_control.experiments.performance_baseline",
                             "prepare", str(spec), str(tmp_path / "plans")],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert len(list((tmp_path / "plans").glob("run-*.json"))) == 8

from secure_control.execution.cycle_timing import StepTimingObservation
from secure_control.experiments.live_timing import (
    LiveTimingCollector,
    export_timing,
    load_timing_report,
)
from secure_control.experiments.performance_baseline import (
    BaselineBatch,
    authorize_baseline,
    baseline_metrics,
    baseline_plan,
    coordinate_batch,
    environments_match,
    prepare_run_plans,
    run_baseline_host,
    verify_baseline_numbers,
)


def test_formal_run_rejects_missing_online_coordinator_before_any_io(tmp_path):
    with pytest.raises(RuntimeError, match="online coordinator unavailable"):
        run_baseline_host({}, {}, "client", config_paths=[], output=tmp_path / "new",
                          expected_head="a" * 40)
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("answer,elapsed,error", [("", 0., ValueError), ("no", 0., ValueError),
                                               ("yes", 1081., TimeoutError)])
def test_manual_confirmation_still_rejects_decline_and_expired_wait(tmp_path, answer, elapsed, error):
    import json

    import secure_control.experiments.performance_baseline as baseline
    spec = {"source_head": "a" * 40,
            "configurations": {r: {} for r in ("Client", "P1", "P2")},
            "outputs": [{"client": str(tmp_path / f"A{k}"), "pair": str(tmp_path / f"B{k}")}
                        for k in range(8)]}
    baseline.prepare_manual(spec, tmp_path / "A", "client", [], tmp_path / "approvals")
    clock = [0.]

    def read(_):
        clock[0] = elapsed
        return answer

    def forbidden(*args, **kwargs):
        raise AssertionError("rejected confirmation must not execute a run")
    with pytest.raises(error):
        baseline.run_manual(tmp_path / "A", read=read, now=lambda: clock[0], runner=forbidden)
    state = json.loads((tmp_path / "A/state.json").read_text())
    assert state["stop"] is True and state["pending"] is None and state["next_index"] == 0


@pytest.mark.parametrize("confirmation", ["YES", "yes", " Yes "])
def test_manual_one_group_packages_and_imports_then_requires_next_confirmation(tmp_path, monkeypatch, confirmation):
    import json

    import secure_control.experiments.performance_baseline as baseline
    from secure_control.experiments.native_tail_capture import plan_digest
    spec = {"source_head": "a" * 40,
            "configurations": {r: {} for r in ("Client", "P1", "P2")},
            "outputs": [{"client": str(tmp_path / f"A{k}"), "pair": str(tmp_path / f"B{k}")}
                        for k in range(8)]}
    approvals = tmp_path / "approvals"
    approvals.mkdir()
    baseline.prepare_manual(spec, tmp_path / "A", "client", [], approvals)
    baseline.prepare_manual(spec, tmp_path / "B", "pair", [], approvals)
    bundle = json.loads((tmp_path / "A/bundle.json").read_text())
    plan = bundle["plans"][0]
    approval = {"schema": "baseline-manual-authorization-v1", "purpose": baseline.MANUAL_PURPOSE,
                "source_head": "a" * 40, "attempts": 1, "plan_sha256": plan_digest(plan),
                "authorization_url": "https://github.com/GNYKCZ/secure_pid_hvac/issues/166#issuecomment-2"}
    (approvals / "approval-0.json").write_text(json.dumps(approval))
    calls = []

    def runner(plan, approval, side, *, output, **kwargs):
        import hashlib
        baseline.authorize_baseline(approval, plan, side=side, output=output, head="a" * 40)
        calls.append(side)
        output.mkdir()
        (output / "plan.json").write_text(json.dumps(plan))
        (output / "manifest.json").write_text(json.dumps({"environment_before": {
            "verified": True, "routes": [], "cpu_topology": [], "process_count": 2},
            "files": {"plan.json": hashlib.sha256((output / "plan.json").read_bytes()).hexdigest()}}))

    # 编排测试隔离纯结果校验；独立数值/环境反例由前述oracle用例覆盖。
    monkeypatch.setattr(baseline, "validate_manual_result", lambda records, *args: records["manifest.json"])
    baseline.run_manual(tmp_path / "B", read=lambda _: confirmation, now=lambda: 0., runner=runner)
    source = next((tmp_path / "B/outbox").glob("*.zip"))
    state_before = (tmp_path / "B/state.json").read_bytes()
    assert baseline.repack_manual(tmp_path / "B", 0) == str(source)
    assert (tmp_path / "B/state.json").read_bytes() == state_before
    (tmp_path / "A/inbox" / source.name).write_bytes(source.read_bytes())
    answers = iter([confirmation, "", "NO"])
    with pytest.raises(ValueError, match="未确认"):
        baseline.run_manual(tmp_path / "A", read=lambda _: next(answers), now=lambda: 0., runner=runner)
    assert calls == ["pair", "client"]
    state = json.loads((tmp_path / "A/state.json").read_text())
    assert state["next_index"] == 1 and state["stop"]
    with pytest.raises(ValueError):
        baseline.run_manual(tmp_path / "A", runner=runner)
    assert calls == ["pair", "client"]


def test_package_rejects_traversal_and_wrong_identity(tmp_path):
    import json
    import zipfile

    from secure_control.experiments.baseline_package import publish_package, read_package
    source = tmp_path / "source"
    source.mkdir()
    (source / "manifest.json").write_text(json.dumps({"files": {}}))
    target = tmp_path / "ok.zip"
    publish_package(source, target, {"side": "pair"})
    with pytest.raises(ValueError, match="身份"):
        read_package(target, {"side": "client"})
    with zipfile.ZipFile(tmp_path / "bad.zip", "w") as archive:
        archive.writestr("../escape", "bad")
    with pytest.raises(ValueError):
        read_package(tmp_path / "bad.zip", {})


def test_numeric_oracle_accepts_encoded_first_step_and_rejects_wrong_output(tmp_path):
    from types import SimpleNamespace

    import numpy as np

    from secure_control.crypto import TwoPartySharing
    from secure_control.execution.lan_config import load_lan_config
    from secure_control.execution.lan_runtime import _public_reachability_digest
    from secure_control.execution.localhost_codec import LanSegmentedSetupV2Payload
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.protocol import Client
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession
    config = load_lan_config("configs/lab-client-cart-pole-demo.example.yaml", "Client")
    prepared = load_segmented_experiment(config.experiment_config, 400, InteractiveSession())
    context = prepared.context
    client = Client(context, TwoPartySharing(context.modulus),
                    security_parameter=prepared.security_parameter, modulus_evidence=prepared.evidence)
    encoded = {k: context.encode(getattr(prepared.spec, k)) for k in ("A", "B", "C", "D", "x0")}
    layout = client._layout_from_spec(prepared.spec)
    verification = client._validate_range_contract(encoded, layout, prepared.contract)
    setup = LanSegmentedSetupV2Payload(context.modulus, context.integer_bits, context.fractional_bits,
        prepared.security_parameter, prepared.contract.state_payload_bounds,
        prepared.contract.input_payload_bounds, prepared.contract.reachability_block_steps, 400,
        "a" * 64, _public_reachability_digest(prepared.contract, verification), prepared.evidence)
    value = prepared.scene.controller_input()
    # 手工首步整数点积；不调用待测replay生成expected。
    raw = float((encoded["C"] @ encoded["x0"] + encoded["D"] @ context.encode(value))[0]) / context.scale**2
    snapshot = prepared.scene.advance(0, np.array([raw]))
    record = SimpleNamespace(protocol=SimpleNamespace(global_step=0, raw_control=(raw,)), snapshot=snapshot)
    assert verify_baseline_numbers(prepared, config, [record], np.array([value]), setup)["verified"]
    wrong = SimpleNamespace(protocol=SimpleNamespace(global_step=0, raw_control=(raw+100,)), snapshot=snapshot)
    with pytest.raises(ValueError):
        verify_baseline_numbers(prepared, config, [wrong], np.array([value]), setup)
    with pytest.raises(ValueError):
        verify_baseline_numbers(prepared, config, [record], np.array([value])+1, setup)
    # 固定2000步纯本地物理/整数oracle生成完整Client包；不运行秘密协议或网络。
    import hashlib
    import json
    from dataclasses import asdict

    from secure_control.execution.localhost_codec import encode_wire_value
    from secure_control.experiments.baseline_package import publish_package, read_package
    from secure_control.experiments.native_tail_capture import plan_digest
    from secure_control.experiments.performance_baseline import validate_manual_result
    pair_records, plan = pair_package_fixture(tmp_path / "pair")
    assert validate_manual_result(pair_records, plan, "pair", [])
    numeric_rows = [record]
    input_rows = [value.copy()]
    nominal = encoded["x0"]
    for k in range(2000):
        if k:
            value = prepared.scene.controller_input()
            raw = float((encoded["C"] @ nominal + encoded["D"] @ context.encode(value))[0]) / context.scale**2
            snapshot = prepared.scene.advance(k, np.array([raw]))
            numeric_rows.append(SimpleNamespace(protocol=SimpleNamespace(global_step=k, raw_control=(raw,)),
                                                snapshot=snapshot))
            input_rows.append(value.copy())
        accumulators = encoded["A"] @ nominal + encoded["B"] @ context.encode(value)
        nominal = np.array([(int(x)+context.scale//2)//context.scale for x in accumulators], dtype=object)
    collector = LiveTimingCollector("samples", sample_limit=2000)
    for k in range(2000):
        start = 1_000_000_000+k*20_000_000
        collector.record(StepTimingObservation(attempt_seq=k, global_step=k, segment_index=k//400,
            actual_sample_start_ns=start, control_applied_ns=start+1_000_000,
            work_completed_ns=start+2_000_000, status="confirmed"))
    report = collector.report()
    report.update(metadata={"timing_mode": "non_realtime_demo"}, control_outcome={}, export={})
    numerical = {"inputs": np.array(input_rows).tolist(), "setup": json.loads(encode_wire_value(setup)),
        "records": [{"global_step": r.protocol.global_step, "raw_control": r.protocol.raw_control,
                     "snapshot": asdict(r.snapshot)} for r in numeric_rows]}
    role = {"role": "Client", "status": "stopped", "timing": report, "numerical_evidence": numerical,
            "outcome": {"status": "stopped", "confirmed_step_count": 2000, "protocol_committed_count": 2000}}
    source = tmp_path / "client"
    source.mkdir()
    owner = pair_records["native-owner.json"]
    values = {"plan.json": plan, "Client.json": role, "metrics.json": baseline_metrics(report),
              "native-owner.json": owner}
    for name, item in values.items():
        (source / name).write_text(json.dumps(item))
    (source / "native.etl").write_bytes(b"etl")
    manifest = {**pair_records["manifest.json"], "side": "client",
        "plan_sha256": plan_digest(plan), "group": {"roles": [role], "exitcodes": [0],
        "stop_reason": None, "forced_cleanup": [], "native": owner},
        "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()}}
    (source / "manifest.json").write_text(json.dumps(manifest))
    archive = tmp_path / "client.zip"
    publish_package(source, archive, {"side": "client", "index": 1})
    records, _ = read_package(archive, {"side": "client", "index": 1})
    assert validate_manual_result(records, plan, "client", ["configs/lab-client-cart-pole-demo.example.yaml"])


@pytest.mark.parametrize("field,value", [("routes", ["ethernet"]), ("cpu_topology", ["other"]),
                                         ("process_count", 51), ("verified", False)])
def test_environment_drift_or_unknown_is_not_comparable(field, value):
    baseline = {"verified": True, "routes": ["wifi"], "cpu_topology": ["core0"], "process_count": 50}
    assert environments_match(baseline, baseline)
    assert not environments_match(baseline, {**baseline, field: value})
    assert not environments_match({}, {})


def test_manual_coordinator_preserves_failure_and_does_not_start_next(tmp_path):
    import json

    from secure_control.experiments.native_tail_capture import plan_digest
    plans = prepare_run_plans({"source_head": "a" * 40,
        "configurations": {r: {} for r in ("Client", "P1", "P2")},
        "outputs": [{"client": f"A{k}", "pair": f"B{k}"} for k in range(8)]})
    paths = []
    for side in ("client", "pair"):
        path = tmp_path / f"{side}.json"
        path.write_text(json.dumps({"side": side, "index": 0,
            "plan_sha256": plan_digest(plans[0]), "functional_complete": False,
            "capture_complete": True, "environment_unchanged": True,
            "environment_before": {"os": side}}), encoding="utf8")
        paths.append(str(path))
    answers = iter(paths)
    coordinate_batch(plans, tmp_path / "coord", read=lambda _: next(answers), now=lambda: 0.)
    result = json.loads((tmp_path / "coord/batch.json").read_text())
    assert result["stop_reason"] == "functional_failure" and not result["complete"]
    assert not (tmp_path / "coord/reservation-1.json").exists()


def test_authorization_rejects_old_purpose_changed_condition_and_boolean_attempts(tmp_path):
    from secure_control.experiments.native_tail_capture import plan_digest
    paths = [{"client": str(tmp_path / f"A{k}"), "pair": str(tmp_path / f"B{k}")}
             for k in range(8)]
    spec = {"source_head": "a" * 40, "configurations": {r: {} for r in ("Client", "P1", "P2")},
            "outputs": paths}
    plan = prepare_run_plans(spec)[0]
    approval = {"schema": "baseline-authorization-v1", "purpose": "capture-overhead-baseline-v1",
                "source_head": "a" * 40, "attempts": 1, "plan_sha256": plan_digest(plan),
                "authorization_url": "https://github.com/GNYKCZ/secure_pid_hvac/issues/166#issuecomment-1"}
    authorize_baseline(approval, plan, side="client", output=paths[0]["client"], head="a" * 40)
    for key, value in (("attempts", True), ("purpose", "control-slow-step-v1")):
        changed = {**approval, key: value}
        with pytest.raises(PermissionError):
            authorize_baseline(changed, plan, side="client", output=paths[0]["client"], head="a" * 40)


def test_batch_no_retry_first_capture_failure_and_remaining_budget():
    clock = [0.]
    batch = BaselineBatch(now=lambda: clock[0])
    assert batch.reserve(0) == "L"
    with pytest.raises(ValueError):
        batch.reserve(0)
    batch.finish(functional_complete=True, capture_complete=False, environment_unchanged=True)
    assert batch.reserve(1) == "F"
    result = batch.finish(functional_complete=True, capture_complete=False, environment_unchanged=True)
    assert result["stop_reason"] == "capture_failure"
    with pytest.raises(ValueError):
        batch.reserve(2)
    clock[0] = 0
    batch = BaselineBatch(now=lambda: clock[0])
    clock[0] = 1081
    with pytest.raises(TimeoutError):
        batch.reserve(0)
    assert batch.pending is None and batch.next_index == 0


@pytest.mark.parametrize("functional,environment,reason", [
    (False, True, "functional_failure"), (True, False, "environment_drift")])
def test_batch_stops_on_failure_or_drift(functional, environment, reason):
    batch = BaselineBatch(now=lambda: 0.)
    batch.reserve(0)
    assert batch.finish(functional_complete=functional, capture_complete=True,
                        environment_unchanged=environment)["stop_reason"] == reason
    with pytest.raises(ValueError):
        batch.reserve(1)


def test_plan_freezes_alternating_blocks_and_distinct_outputs():
    paths = [{"client": f"A/{k}", "pair": f"B/{k}"} for k in range(8)]
    plan = baseline_plan("a" * 40, {r: {} for r in ("Client", "P1", "P2")}, paths)
    assert [r["condition"] for r in plan["runs"]] == list("LFFLFLLF")
    assert plan["authorization_required"] is True
    assert plan["observation"]["tail_recorder"] is False
    paths[-1] = paths[0]
    with pytest.raises(ValueError):
        baseline_plan("a" * 40, {r: {} for r in ("Client", "P1", "P2")}, paths)


def test_small_array_oracle_preserves_budget_and_maintenance_semantics(tmp_path):
    collector = LiveTimingCollector("samples", sample_limit=5)
    for k, work in enumerate((10, 21, 22, 20, 23)):
        start = 1_000_000_000 + k * 40_000_000
        collector.record(StepTimingObservation(
            attempt_seq=k, global_step=k, segment_index=k // 3,
            actual_sample_start_ns=start, control_applied_ns=start + 5_000_000,
            work_completed_ns=start + work * 1_000_000, status="confirmed",
            sample_interval_ns=40_000_000 if k else None,
            phase_durations_ns={"single_exchange": 3_000_000,
                                **({"maintenance_advance": 9_000_000} if k == 1 else {})}))
    path = tmp_path / "timing.json"
    export_timing(collector, path, {"timing_mode": "non_realtime_demo"}, {"status": "stopped"})
    report = load_timing_report(path)
    result = baseline_metrics(report)
    assert result["work"]["above_20ms"] == 3
    assert result["work"]["above_20ms_fraction"] == .6
    assert result["work"]["p50_ns"] == 21_000_000
    assert result["work"]["p99_ns"] == 23_000_000
    assert result["longest_consecutive_budget_exceedance"] == 2
    assert result["following_two_steps_work"]["count"] == 2
    assert result["maintenance_boundary_work"]["max_ns"] == 21_000_000
    assert result["work_exit_to_next_sample"]["max_ns"] == 30_000_000
    assert result["deadline_miss"] is None
    report["metadata"]["timing_mode"] = "absolute"
    with pytest.raises(ValueError):
        baseline_metrics(report)
