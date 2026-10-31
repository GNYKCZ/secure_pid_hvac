"""共同基线的独立小数组统计与计划边界，不启动网络或系统采集。"""

import pytest

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
    prepare_run_plans,
)


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
