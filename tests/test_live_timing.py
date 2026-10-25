"""#132：独立整数时间线、全程统计和有界性能报告契约。"""

from dataclasses import replace

import pytest

from secure_control.execution.cycle_timing import StepTimingObservation
from secure_control.experiments.live_timing import LiveTimingCollector


def observation(k=0, work=15_000_000, **kwargs):
    """手写时刻差作 oracle，不通过被测统计计算期望。"""
    start = 1_000_000_000 + k * 30_000_000
    return StepTimingObservation(
        attempt_seq=k,
        global_step=k,
        segment_index=k // 3,
        actual_sample_start_ns=start,
        control_applied_ns=start + 5_000_000,
        work_completed_ns=start + work,
        sample_interval_ns=30_000_000 if k else None,
        status="confirmed",
        **kwargs,
    )


def test_exact_statistics_bins_failure_correction_and_raw_capacity():
    collector = LiveTimingCollector("samples", sample_limit=2)
    for k, work in enumerate((15_000_000, 20_000_000, 20_000_001, 1_100_000_000)):
        collector.record(observation(k, work))
    result = collector.report()
    metric = result["metrics"]["work_elapsed_ns"]
    assert (metric["count"], metric["sum_ns"], metric["min_ns"], metric["max_ns"]) == (
        4,
        1_155_000_001,
        15_000_000,
        1_100_000_000,
    )
    assert metric["above_15ms"] == 3 and metric["above_20ms"] == 2
    assert metric["quantiles"]["p99"] == {"lower_ns": 1_000_000_000, "upper_ns": None}
    assert result["raw"]["captured"] == 2 and result["raw"]["omitted"] == 2
    assert not result["raw"]["complete"] and result["observations"] == 4
    collector.correct_last(
        replace(
            observation(3, 1_100_000_000),
            status="miss_after_apply",
            work_completed_ns=None,
            failure_phase="CYCLE_OBSERVATION",
            terminal_elapsed_ns=1_100_000_001,
        )
    )
    result = collector.report()
    assert result["observations"] == 4 and result["status_counts"]["confirmed"] == 3
    assert result["metrics"]["work_elapsed_ns"]["count"] == 3
    assert result["metrics"]["work_elapsed_ns"]["max_ns"] == 20_000_001
    assert result["metrics"]["control_latency_ns"]["count"] == 4
    assert result["first_failure"]["global_step"] == 3
    assert collector.buffer_bytes <= 8 * 1024 * 1024


def test_zero_endpoint_validation_and_observer_failure_are_explicit():
    collector = LiveTimingCollector()
    assert collector.report()["metrics"]["work_elapsed_ns"]["quantiles"]["p50"] is None
    with pytest.raises(ValueError):
        observation(work=-1)
    collector.record(observation())
    collector.record(replace(observation(1), phase_durations_ns={"input": -1}))
    result = collector.report()
    assert result["statistics_complete"] is False and result["observation_error"] == "ValueError"
    assert result["observations"] == 1


def test_single_exchange_is_distinct_and_legacy_report_metric_set_remains_readable(tmp_path):
    from secure_control.experiments.live_timing import (
        export_timing,
        load_timing_report,
        validate_timing_report,
    )

    collector = LiveTimingCollector("samples", sample_limit=1)
    collector.record(observation(phase_durations_ns={"single_exchange": 4_000_000,
                                                    "reconstruct": 200_000}))
    report = collector.report()
    assert report["raw"]["samples"][0]["phase_durations_ns"] == {
        "single_exchange": 4_000_000, "reconstruct": 200_000}
    assert report["metrics"]["stage"]["count"] == report["metrics"]["commit"]["count"] == 0
    assert report["metrics"]["single_exchange"]["sum_ns"] == 4_000_000
    target = tmp_path/'new.json'
    export_timing(collector, target, {}, {"status": "stopped"})
    assert load_timing_report(target)["metrics"]["single_exchange"]["count"] == 1
    legacy = LiveTimingCollector("samples", sample_limit=1)
    legacy.record(observation())
    old_target = tmp_path/'old.json'
    export_timing(legacy, old_target, {}, {"status": "stopped"})
    old = load_timing_report(old_target)
    del old["metrics"]["single_exchange"]
    assert validate_timing_report(old) is old


@pytest.mark.parametrize("count", [0, 1, 256, 257, 10001])
def test_full_range_oracle_and_fixed_storage(count):
    """仅驱动公开整数汇总器，不启动控制器/网络/worker，不属于控制性能长测。"""
    import math

    collector = LiveTimingCollector("samples", sample_limit=10_000)
    storage = (len(collector.raw), len(collector.recent), collector.buffer_bytes)
    values = [((k * 37) % 400) * 100_000 for k in range(count)]
    for k, value in enumerate(values):
        collector.record(
            replace(
                observation(k, max(value, 5_000_000)),
                control_applied_ns=1_000_000_000 + k * 30_000_000,
                work_completed_ns=1_000_000_000 + k * 30_000_000 + value,
            )
        )
    result = collector.report()
    metric = result["metrics"]["work_elapsed_ns"]
    assert (len(collector.raw), len(collector.recent), collector.buffer_bytes) == storage
    assert metric["count"] == count and metric["sum_ns"] == sum(values)
    assert metric["max_ns"] == (max(values) if values else None)
    assert metric["above_15ms"] == sum(v > 15_000_000 for v in values)
    assert metric["above_20ms"] == sum(v > 20_000_000 for v in values)
    assert len(result["recent"]) == min(256, count)
    assert len(result["slowest"]) == min(8, count)
    assert result["raw"]["captured"] == min(count, 10000)
    for key, p in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
        interval = metric["quantiles"][key]
        if count:
            expected = sorted(values)[math.ceil(p * count) - 1]
            assert interval["lower_ns"] <= expected < interval["upper_ns"]
        else:
            assert interval is None


def test_output_preflight_atomic_export_and_report_tampering(tmp_path, monkeypatch):
    import json

    from secure_control.experiments import live_timing as timing

    for options in (
        {"mode": "summary", "supported": False},
        {"mode": "summary", "supported": True, "sample_limit": 1},
        {"mode": "samples", "supported": True, "sample_limit": True},
        {"mode": "off", "supported": True, "output": tmp_path / "off.json"},
    ):
        with pytest.raises(ValueError):
            timing.performance_options(**options)
    formal = tmp_path / "formal"
    (formal / "nested").mkdir(parents=True)
    (formal / "run.json").write_text("{}")
    with pytest.raises(ValueError):
        timing.performance_options(
            "summary", supported=True, output=formal / "nested" / "report.json"
        )
    collector = LiveTimingCollector("samples", sample_limit=2)
    collector.record(observation())
    target = tmp_path / "report.json"
    result = timing.export_timing(
        collector, target, {"local_git": {"head": "a" * 40}}, {"status": "stopped"}
    )
    assert result["export"]["status"] == "saved"
    report = timing.load_timing_report(target)
    assert report["metrics"]["work_elapsed_ns"]["mean_ns"] == 15_000_000
    original = target.read_bytes()
    assert (
        timing.export_timing(collector, target, {}, {"status": "stopped"})["export"]["status"]
        == "failed"
    )
    assert target.read_bytes() == original and not list(tmp_path.glob("*.partial"))
    for change in (
        lambda r: r.update(format_version=2),
        lambda r: r["raw"].update(omitted=1),
        lambda r: r["recent"][0].update(work_elapsed_ns=0),
        lambda r: r["metrics"]["work_elapsed_ns"]["histogram"]["counts"].__setitem__(150, 2),
    ):
        bad = json.loads(original)
        change(bad)
        with pytest.raises(ValueError):
            timing.validate_timing_report(bad)

    def failed(*args, **kwargs):
        raise OSError("test disk failure")

    monkeypatch.setattr(timing.os, "link", failed)
    result = timing.export_timing(collector, tmp_path / "failed.json", {}, {"status": "stopped"})
    assert result["export"]["status"] == "failed" and not (tmp_path / "failed.json").exists()


def test_snapshot_copy_throttle_and_callback_failure_rollback(monkeypatch):
    from secure_control.experiments import live_timing as timing

    now, snapshots = [0], []
    monkeypatch.setattr(timing, "perf_counter_ns", lambda: now[0])
    collector = LiveTimingCollector(on_snapshot=snapshots.append)
    for k in range(257):
        collector.record(observation(k))
    assert len(snapshots) == 1 and collector.count == 257
    now[0] = 100_000_000
    collector.publish()
    assert len(snapshots[-1]["trend"]) == 256 and snapshots[-1]["latest"]["global_step"] == 256
    snapshots[-1]["latest"]["status"] = "tampered"
    assert collector.report()["recent"][-1]["status"] == "confirmed"

    def failed(_view):
        raise RuntimeError("test UI failure")

    broken = LiveTimingCollector(on_snapshot=failed)
    broken.record(observation())
    report = broken.report()
    assert not report["statistics_complete"] and report["observations"] == 0
    assert all(m["count"] == 0 for m in report["metrics"].values())
    views = []
    now[0] = 0

    def slow_first(view):
        views.append(view)
        if len(views) == 1:
            now[0] += 200_000_000

    corrected = LiveTimingCollector(on_snapshot=slow_first)
    corrected.record(observation())
    corrected.correct_last(
        replace(observation(), status="miss_after_apply", work_completed_ns=None)
    )
    corrected.publish(force=True)
    assert len(views) == 3
    assert views[1]["observations"] == 1 and views[1]["latest"]["status"] == "miss_after_apply"
    assert all(v["latest"] is None or v["latest"]["attempt_seq"] < v["observations"] for v in views)
    assert views[2]["latest"]["status"] == "miss_after_apply"
    assert corrected.report()["metrics"]["work_elapsed_ns"]["count"] == 0
