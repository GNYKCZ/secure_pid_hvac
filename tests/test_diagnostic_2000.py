"""2000窗口独立容量/身份/跨段/监督oracle，绝不启动2000控制或原生试采。"""
import copy
import os
from types import SimpleNamespace

import pytest

from secure_control.execution.diagnostic_limits import artifact_limits, limits_for
from secure_control.execution.tail_diagnostics import DiagnosticContext, TailRecorder
from secure_control.experiments.tail_diagnostic_analysis import _decode, analyze_records


@pytest.mark.parametrize('window',[400,2000])
def test_fixed_window_memory_and_round_boundary(tmp_path,window):
    limits=limits_for(window)
    context=DiagnosticContext('window-test','domain',str(tmp_path),'a'*40,os.getpid(),window=window)
    recorder=TailRecorder(context,'Client',stream_map=True).start()
    try:
        recorder.bind_protocol('run','session','epoch')
        recorder.bind_round(limits.identities-1,'last-material')
        recorder.control_step(limits.window-1)
        recorder.emit('sample',0)
        recorder.emit('work',1)
        assert recorder.buffer_bytes+len(recorder.streams.buffer)<=limits.memory_limit
        if window==2000:
            assert recorder.buffer_bytes==4849600
            assert len(recorder.streams.buffer)==327680
            assert recorder.buffer_bytes*4+len(recorder.streams.buffer)==19726080
        else:
            assert recorder.buffer_bytes==983040 and len(recorder.streams.buffer)==65536
        report=recorder.finish('stopped')
        assert str(limits.identities-1) in report['rounds']
        assert artifact_limits(report)==limits and _decode(report)['complete']
        assert ('limits' in report) is (window==2000)
        assert 'window' not in report['context']
    finally:
        if not recorder._finished:
            recorder.finish('failed')


@pytest.mark.parametrize('fault',['step','material','schema','declared_limits','v1_extension','capacity'])
def test_versioned_limits_never_silently_widen(tmp_path,fault):
    ctx=DiagnosticContext('bounds','domain',str(tmp_path),'a'*40,1,window=2000)
    recorder=TailRecorder(ctx,'P1').start()
    recorder.control_step(1999)
    record=recorder.finish('closed')
    if fault=='step': record['events'][0][2]=2000
    if fault=='material': record['events'][0][3]=2016
    if fault=='schema': record['schema']='control-tail-diagnostic-v3'
    if fault=='declared_limits': record['limits']['window']=2001
    if fault=='v1_extension': record['schema']='control-tail-diagnostic-v1'
    if fault=='capacity': record['event_capacity']=61441
    with pytest.raises(ValueError): _decode(record)


def test_v2_overflow_is_partial_without_increasing_capacity(tmp_path):
    recorder=TailRecorder(DiagnosticContext('overflow','domain',str(tmp_path),'a'*40,1,window=2000),
        'worker',event_capacity=1,gc_capacity=1).start()
    recorder.bind_round(2015,'valid-last')
    recorder.bind_round(2016,'invalid')
    recorder.emit('worker_generate',0,material=2015)
    record=recorder.finish('closed')
    assert not record['diagnostic_complete'] and record['lost_events']>0
    assert '2016' not in record['rounds'] and len(record['events'])<=2


def test_v1_and_v2_cannot_be_mixed_and_five_segment_ranges_are_explicit():
    from test_tail_diagnostics import fixture_records
    records,domains=fixture_records(dual=True)
    limits=limits_for(2000)
    for record in records:
        record.update(schema=limits.trace_schema,limits=limits.payload())
        record['buffer_bytes']=(record['event_capacity']+record['gc_capacity'])*64+limits.identity_bytes
    result=analyze_records(records,clock_domains=domains,expected_steps=range(2000),targets=())
    assert not result['diagnostic_complete']
    assert [(s['start'],s['end']) for s in result['segments']]==[
        (0,399),(400,799),(800,1199),(1200,1599),(1600,1999)]
    changed=copy.deepcopy(records)
    changed[0]['schema']='control-tail-diagnostic-v1'
    changed[0].pop('limits')
    with pytest.raises(ValueError,match='窗口混配'):
        analyze_records(changed,clock_domains=domains,expected_steps=range(2))


def test_partial_samples_without_observed_steps_remain_unknown():
    from test_tail_diagnostics import fixture_records
    records,domains=fixture_records()
    for record in records:
        record.update(events=[],event_count=0,gc_count=0)
    samples=[{'global_step':0,'round_id':'round0','actual_sample_start_ns':100,
        'control_applied_ns':199,'work_completed_ns':200,'work_elapsed_ns':100,'control_latency_ns':99}]
    result=analyze_records(records,clock_domains=domains,samples=samples,partial=True)
    assert not result['diagnostic_complete'] and not result['all_work_steps']
    assert result['work_groups']['unknown']['count']==1
    assert result['work_groups']['final_stop']['count']==0


@pytest.mark.parametrize('window',[400,2000])
@pytest.mark.parametrize('case',[
    'undeclared_prefix','declared_prefix','declared_last_no_stop','failed_stop',
    'completed_stop','undeclared_stop','early_normal_stop','unpaired_stop',
    'wrong_thread_stop','stop_before_work',
])
def test_rv006_final_stop_requires_actual_successful_stop_evidence(window,case):
    from test_tail_diagnostics import fixture_records, recount

    from secure_control.execution.tail_diagnostics import PHASES
    records,domains=fixture_records()
    if window==2000:
        limits=limits_for(window)
        for record in records:
            record.update(schema=limits.trace_schema,limits=limits.payload())
            record['buffer_bytes']=(record['event_capacity']+record['gc_capacity'])*64+limits.identity_bytes
    client=records[0]
    client['status']='failed' if case=='failed_stop' else 'stopped'
    has_stop=case not in ('undeclared_prefix','declared_prefix','declared_last_no_stop')
    if has_stop:
        thread=client['main_thread_id']+(1 if case=='wrong_thread_stop' else 0)
        for edge,wall in ((0,310 if case=='stop_before_work' else 330),(1,340)):
            if case=='unpaired_stop' and edge==1:
                continue
            client['events'].append([0,2*PHASES['stop']+edge,1,-1,wall,0,thread,0])
        recount(client)
    expected=(None if case in ('undeclared_prefix','undeclared_stop') else
              range(3) if case in ('declared_prefix','early_normal_stop') else range(2))
    samples=[{'global_step':1,'round_id':'round1','actual_sample_start_ns':300,
        'control_applied_ns':319,'work_completed_ns':320,'work_elapsed_ns':20,
        'control_latency_ns':19,'status':'confirmed','phase_durations_ns':{'maintenance':0}}]
    result=analyze_records(records,clock_domains=domains,samples=samples,expected_steps=expected,partial=True)
    final=case in ('completed_stop','undeclared_stop','early_normal_stop')
    groups=result['work_groups']
    assert groups['final_stop']['count']==int(final)
    assert groups['ordinary']['count']==int(not final)
    assert sum(group['count'] for group in groups.values())==result['work_distribution']['count']==1
    assert groups['final_stop' if final else 'ordinary']['mean_ns']==20
    assert result['work_distribution']['mean_ns']==20


def test_rv006_maintenance_boundary_prefix_is_not_final_stop():
    from test_tail_diagnostics import fixture_records, recount
    records,domains=fixture_records()
    limits=limits_for(2000)
    for record in records:
        record.update(schema=limits.trace_schema,limits=limits.payload())
        record['buffer_bytes']=(record['event_capacity']+record['gc_capacity'])*64+limits.identity_bytes
        record['rounds']['399']=record['rounds'].pop('1')
        for row in record['events']:
            if row[2]==1: row[2]=399
            if row[3]==1: row[3]=399
        recount(record)
    samples=[{'global_step':399,'round_id':'round1','actual_sample_start_ns':300,
        'control_applied_ns':319,'work_completed_ns':320,'work_elapsed_ns':20,
        'control_latency_ns':19,'status':'confirmed',
        'phase_durations_ns':{'maintenance':5,'maintenance_advance':5}}]
    result=analyze_records(records,clock_domains=domains,samples=samples,expected_steps=range(800),partial=True)
    assert result['work_groups']['continuing_maintenance']['count']==1
    assert result['work_groups']['final_stop']['count']==0
    assert sum(group['count'] for group in result['work_groups'].values())==1
    assert not result['diagnostic_complete']


def test_explicit_2000_attempt_callbacks_four_continuations_and_no_2001(tmp_path,monkeypatch):
    from secure_control.execution.lan_config import load_lan_config
    from secure_control.experiments import lan_continuous_profile, lan_runner, live_timing
    from secure_control.experiments import tail_diagnostic_runner as runner
    config=load_lan_config(runner.ROOT/'configs/lab-client-cart-pole-demo.example.yaml','Client')
    monkeypatch.setattr(lan_continuous_profile,'load_segmented_experiment',
        lambda path,segment,session:SimpleNamespace(scene=SimpleNamespace(period=.02),segment=segment))
    monkeypatch.setattr(live_timing,'timing_metadata',lambda *a,**kw:{})
    monkeypatch.setattr(runner.subprocess,'check_output',lambda *a,**kw:'a'*40)
    maintenance=[]
    def fake_original(config,prepared,**kwargs):
        assert prepared.segment==400
        for step in range(2000):
            assert not kwargs['control'].stop_requested
            kwargs['before_sample']()
            kwargs['on_step'](SimpleNamespace(protocol=SimpleNamespace(global_step=step)))
            if (step+1)%400==0 and not kwargs['control'].stop_requested:
                maintenance.append(step)
        assert kwargs['control'].stop_requested
        return {'status':'stopped'}
    monkeypatch.setattr(lan_runner,'_run_prepared_segmented',fake_original)
    ctx=DiagnosticContext('callbacks','domain',str(tmp_path),'a'*40,1,window=2000)
    result=[]
    runner._configured_child(config,ctx,SimpleNamespace(put=result.append),
        SimpleNamespace(is_set=lambda:False,set=lambda:None),runner.time.perf_counter()+240,
        2000,SimpleNamespace(value=0.))
    assert result[0]['attempt_callbacks']==2000 and result[0]['status']=='stopped'
    assert maintenance==[399,799,1199,1599]


def test_2000_requires_explicit_window_and_native_preparation_before_any_launch(tmp_path):
    from secure_control.experiments.tail_diagnostic_runner import run_host, run_local
    with pytest.raises(ValueError): run_local(tmp_path/'local',expected_head='a'*40,software_review='https://r',steps=2000)
    with pytest.raises(ValueError): run_host('client',tmp_path/'old',diagnostic_id='test',expected_head='a'*40,
        software_review='https://r',config_paths=[],steps=2000)
    with pytest.raises(ValueError,match='实测封锁'):
        run_host('client',tmp_path/'new',diagnostic_id='test',expected_head='a'*40,
            software_review='https://r',config_paths=[],steps=2000,window=2000,stream_map=True)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('side',['client','pair'])
def test_pending_runtime_gate_precedes_config_ledger_and_native_launch(tmp_path,monkeypatch,side):
    from secure_control.experiments import tail_diagnostic_runner as runner
    def forbidden(*args,**kwargs):
        pytest.fail('blocked runtime must not inspect git, reserve ledger or launch')
    monkeypatch.setattr(runner.subprocess,'check_output',forbidden)
    monkeypatch.setattr(runner,'_write_new',forbidden)
    monkeypatch.setattr(runner,'_collect_host',forbidden)
    with pytest.raises(ValueError,match='实测封锁'):
        runner.run_host(side,tmp_path/'no-output',diagnostic_id='d17-blocked',
            expected_head='a'*40,software_review='https://example.test/review',config_paths=[],
            steps=2000,window=2000,stream_map=side=='client',native_plan={'source_head':'a'*40} if side=='client' else None)
    assert not list(tmp_path.iterdir())


def test_v2_stream_capacity_and_last_step_do_not_extend_v1():
    from test_client_stream_map import Socket

    from secure_control.execution.client_stream_map import ClientStreamMap
    owner=ClientStreamMap(window=2000)
    raw=[Socket(),Socket()]
    sockets=[owner.register(s) for s in raw]
    owner.begin(sockets,[1,1],1999)
    for source,sock in zip(raw,sockets,strict=True):
        sock.send(b'\0\0\0\1!')
        source.input=[b'\0\0\0\1!']
        sock.recv(5)
    report=owner.report()
    assert report['complete'] and [r[0] for r in report['rows']]==[3998,3999]
    assert artifact_limits(report,stream=True)==limits_for(2000)
    owner.begin(sockets,[1,1],2000)
    assert not owner.report()['complete']
    with pytest.raises(ValueError): limits_for(True)


@pytest.mark.parametrize('boundary',['activity','wall'])
def test_2000_host_fakeclock_90_and_240_cleanup_only_owned(monkeypatch,boundary):
    from secure_control.experiments import tail_diagnostic_runner as runner
    clock=[0.]
    started=[]
    activity=SimpleNamespace(value=1. if boundary=='activity' else 0.)
    class Process:
        pid=44
        exitcode=None
        def __init__(self,**kw): pass
        def start(self): started.append(self.pid)
        def join(self,timeout): pass
        def is_alive(self): return self.exitcode is None
        def terminate(self): self.exitcode=-1
    class Queue:
        def get(self,timeout):
            clock[0]=91 if boundary=='activity' else 237
            raise runner.queue.Empty
        def close(self): pass
        def cancel_join_thread(self): pass
    spawn=SimpleNamespace(Process=Process,Queue=Queue,Value=lambda *a:activity,
        Event=lambda:SimpleNamespace(set=lambda:None))
    cleared=[]
    def cleanup(ps,deadline,**kw):
        cleared.extend(p.pid for p in ps)
        assert deadline==239
        for p in ps: p.terminate()
        return [{'pid':p.pid} for p in ps]
    monkeypatch.setattr(runner,'_clear_owned',cleanup)
    result=runner._collect_host([SimpleNamespace(role='P1')],SimpleNamespace(window=2000),2000,
        _mp=SimpleNamespace(get_context=lambda _:spawn),_now=lambda:clock[0])
    assert result['stop_reason']==('activity_limit' if boundary=='activity' else 'wall_limit')
    assert cleared==started==[44] and result['wall_s']<=240
