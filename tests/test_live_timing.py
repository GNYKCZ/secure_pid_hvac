"""#132：独立整数时间线、全程统计和有界性能报告契约。"""

from dataclasses import replace
from pathlib import Path

import pytest

from secure_control.execution.cycle_timing import StepTimingObservation
from secure_control.experiments.live_timing import LiveTimingCollector


@pytest.mark.parametrize('client_io', ['blocking-v1', 'ready-v1'])
@pytest.mark.parametrize('non_realtime', [False,True])
def test_timing_metadata_records_local_io_strategy_without_changing_wire(client_io,non_realtime):
    from types import SimpleNamespace

    from secure_control.experiments.communication_benchmark import _config, _ports
    from secure_control.experiments.live_timing import timing_metadata
    profile = 'control-dynamic-matrix-preauthorized-v2'
    config = replace(_config('Client', _ports()), wire_profile=profile, client_io=client_io)
    prepared = SimpleNamespace(scene=SimpleNamespace(period=.02), segment_capacity=2,
                               effective_config={'public': 'fixture'})
    metadata = timing_metadata(config, prepared, non_realtime=non_realtime, mode='summary')
    assert metadata['client_io'] == client_io and metadata['wire_profile'] == profile
    assert metadata['topology_digest'] == config.topology.digest
    assert metadata['peer_head'] == metadata['peer_network'] == 'unknown'
    assert metadata['timing_mode']==('non_realtime_demo' if non_realtime else 'absolute')


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
    old['format_version'] = 1
    for name in ('lateness_ns','cycle_remaining_ns','cycle_overrun_ns'):
        del old['metrics'][name]
    for row in (*old['raw']['samples'],*old['recent'],*old['slowest']):
        row.pop('cycle_remaining_ns',None)
        row.pop('cycle_overrun_ns',None)
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
        lambda r: r.update(format_version=3),
        lambda r: r['metrics'].pop('cycle_remaining_ns'),
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


@pytest.mark.parametrize('offset,work,remaining,overrun', [
    (200_000,5_000_000,14_800_000,0),
    (100_000,19_900_000,0,0),
    (0,20_000_001,0,1),
    (-100_000,5_000_000,15_100_000,0),
])
def test_v2_integer_cycle_derivatives_have_exact_boundary_semantics(offset,work,remaining,overrun):
    from secure_control.experiments.live_timing import CYCLE_METRICS

    scheduled = 1_000_000_000-offset
    row = observation(work=work,scheduled_start_ns=scheduled,deadline_ns=scheduled+20_000_000)
    collector = LiveTimingCollector('samples',sample_limit=1)
    collector.record(row)
    report = collector.report()
    sample = report['raw']['samples'][0]
    assert report['format_version'] == 2
    assert [sample[k] for k in CYCLE_METRICS] == [max(0,offset),remaining,overrun]
    for key,expected in zip(CYCLE_METRICS,(max(0,offset),remaining,overrun),strict=True):
        assert report['metrics'][key]['sum_ns'] == expected
        assert report['metrics'][key]['missing_count'] == 0
        assert 'histogram' not in report['metrics'][key]


def test_v2_missing_endpoints_demo_and_correction_do_not_invent_cycle_margin():
    from secure_control.experiments.live_timing import CYCLE_METRICS

    collector = LiveTimingCollector('samples',sample_limit=4)
    collector.record(observation())  # 演示虽有完整工作，也没有计划或周期余量。
    scheduled=1_030_000_000
    success=observation(1,scheduled_start_ns=scheduled-200_000,deadline_ns=scheduled+19_800_000)
    collector.record(success)
    assert collector.report()['metrics']['cycle_remaining_ns']['count'] == 1
    collector.correct_last(replace(success,status='miss_after_apply',work_completed_ns=None))
    collector.record(StepTimingObservation(2,2,0,status='miss_before_apply',
        scheduled_start_ns=1_060_000_000,deadline_ns=1_080_000_000))
    report=collector.report()
    assert report['metrics']['lateness_ns']['sum_ns']==200_000
    assert report['metrics']['lateness_ns']['missing_count']==2
    assert report['status_counts']['confirmed']==1 and report['observations']==3
    for key in CYCLE_METRICS[1:]:
        assert report['metrics'][key]['count']==0 and report['metrics'][key]['missing_count']==3
        assert all(r[key] is None for r in report['recent'])


def test_v2_cycle_margin_uses_final_observation_stamp_and_rolls_back_error():
    from secure_control.experiments.live_timing import CYCLE_METRICS

    ticks=iter((1_000_000_000,1_021_000_000))
    collector=LiveTimingCollector('samples',sample_limit=1)
    collector.completion_clock=lambda:next(ticks)
    collector.record(observation(work=5_000_000,scheduled_start_ns=1_000_000_000,deadline_ns=1_020_000_000))
    sample=collector.report()['recent'][0]
    assert sample['work_elapsed_ns']==21_000_000 and sample['cycle_overrun_ns']==1_000_000
    assert sample['observation_ns']==21_000_000
    broken=LiveTimingCollector(on_snapshot=lambda _:(_ for _ in ()).throw(RuntimeError()))
    broken.record(observation(scheduled_start_ns=999_000_000,deadline_ns=1_019_000_000))
    report=broken.report()
    assert not report['statistics_complete'] and report['observations']==0
    assert all(report['metrics'][k]['count']==0 for k in CYCLE_METRICS)


def test_v2_strict_reader_rejects_forged_values_and_v1_remains_unmodified(tmp_path):
    import copy

    from secure_control.experiments.live_timing import (
        CYCLE_METRICS,
        export_timing,
        load_timing_report,
        validate_timing_report,
    )

    collector=LiveTimingCollector('samples',sample_limit=2)
    collector.record(observation(scheduled_start_ns=999_800_000,deadline_ns=1_019_800_000))
    path=tmp_path/'v2.json'
    assert export_timing(collector,path,{'timing_mode':'absolute'},{'status':'stopped'})['export']['status']=='saved'
    original=load_timing_report(path)
    for change in (
        lambda r:r['raw']['samples'][0].update(cycle_remaining_ns=0),
        lambda r:r['recent'][0].update(cycle_overrun_ns=False),
        lambda r:r['slowest'][0].update(cycle_remaining_ns=None),
        lambda r:r['metrics']['lateness_ns'].update(missing_count=1),
        lambda r:r['metrics']['cycle_remaining_ns'].update(sum_ns=3,mean_ns=3,min_ns=3,max_ns=3),
        lambda r:r['metrics'].pop('single_exchange'),
        lambda r:r['raw']['samples'][0].update(unknown_field=0),
        lambda r:r.update(format_version=True),
        lambda r:r.update(format_version=99),
        lambda r:r['metrics']['cycle_overrun_ns'].update(sum_ns=2**63),
        lambda r:r.update(observation_error='ValueError',statistics_complete=True),
        lambda r:r['metrics']['cycle_overrun_ns'].update(mean_ns=False),
    ):
        bad=copy.deepcopy(original)
        change(bad)
        with pytest.raises(ValueError):
            validate_timing_report(bad)
    legacy=copy.deepcopy(original)
    legacy['format_version']=1
    for key in CYCLE_METRICS:del legacy['metrics'][key]
    del legacy['metrics']['single_exchange']
    for row in (*legacy['raw']['samples'],*legacy['recent'],*legacy['slowest']):
        del row['cycle_remaining_ns'],row['cycle_overrun_ns']
    before=copy.deepcopy(legacy)
    assert validate_timing_report(legacy) is legacy and legacy==before
    invalid_v2=copy.deepcopy(legacy)
    invalid_v2['format_version']=2
    with pytest.raises(ValueError):
        validate_timing_report(invalid_v2)  # 不能仅把旧version2非法断言删除。
    for path in (Path(__file__).resolve().parents[1]/'results/lan_continuous/performance').glob('*.json'):
        # 真正历史v1文件只读，不能只测试由新报告退化的合成fixture。
        if path.name in ('80fa6ce41b2f4032ac16ab992634a358.json','4aa7664d3db745c2921a9b08c6b41d04.json'):
            report=load_timing_report(path)
            assert report['format_version']==1


def test_v2_null_cycle_metrics_constant_capacity_and_overflow():
    from secure_control.experiments.live_timing import CYCLE_METRICS

    collector=LiveTimingCollector('samples',sample_limit=10_000)
    initial=(collector.buffer_bytes,len(collector.raw),len(collector.recent))
    for k in range(257):collector.record(observation(k))
    assert (collector.buffer_bytes,len(collector.raw),len(collector.recent))==initial
    assert collector.buffer_bytes<=8*1024*1024
    assert len(collector.report()['recent'])==256 and len(collector.report()['slowest'])==8
    assert all(collector.report()['metrics'][key]['missing_count']==257 for key in CYCLE_METRICS)
    broken=LiveTimingCollector()
    broken.metrics['lateness_ns'].total=2**63-1
    broken.record(observation(scheduled_start_ns=999_999_999,deadline_ns=1_019_999_999))
    assert broken.report()['observation_error']=='ValueError'
