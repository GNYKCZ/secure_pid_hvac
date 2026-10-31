"""D12：独立时间线、GC交集和不同主机域不能伪造统一时间轴。"""
import copy
import gc
import json
import os
import subprocess
import sys
from dataclasses import replace
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest

from secure_control.execution.tail_diagnostics import (
    PHASES,
    SCHEMA,
    DiagnosticContext,
    TailRecorder,
    current,
)
from secure_control.experiments.tail_diagnostic_analysis import analyze_records, gc_intersections


def context(tmp_path):
    return DiagnosticContext('diagnostic-test', 'domain-A', str(tmp_path), 'a'*40, 10)


def test_party_receive_record_buffer_is_decodable_and_strictly_bounded(tmp_path):
    from secure_control.experiments.tail_diagnostic_analysis import _decode
    ctx=replace(context(tmp_path),window=2000,transport='insecure_tcp')
    recorder=TailRecorder(ctx,'P1',party_receive_map=True)
    record=recorder.finish('stopped')
    assert record['buffer_bytes']==5_504_960
    _decode(record)
    for delta in (-1,1,655360):
        bad=copy.deepcopy(record);bad['buffer_bytes']+=delta
        with pytest.raises(ValueError):_decode(bad)
    for role in ('Client','worker'):
        bad=copy.deepcopy(record);bad['role']=role
        with pytest.raises(ValueError):_decode(bad)


@pytest.mark.parametrize('fault',[None,'input','run','derived','target','policy','memory'])
def test_recovery_links_only_unchanged_same_run_sources(tmp_path,monkeypatch,fault):
    import hashlib

    from secure_control.experiments import tail_calibration as c
    from secure_control.experiments import tail_diagnostic_analysis as a
    from secure_control.experiments import windows_tail_analysis as w
    record=TailRecorder(context(tmp_path),'Client').finish('stopped')
    view={'errors':['event budget exceeded'],'complete':False,'source_head':'a'*40,
          'diagnostic_id':'run','target_pid':record['pid'],'target_tid':record['main_thread_id']}
    def save(name,value):
        raw=value if isinstance(value,bytes) else json.dumps(value).encode()
        (tmp_path/name).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()
    hashes={n:save(n,v) for n,v in [('native-a.etl',b'fake'),('control-native-events.json',[]),
            ('control-native-view.json',view),('Client.stream.json',{})]}
    m={'side':'client','source_head':'a'*40,'diagnostic_id':'run',
       'native_evidence':{'status':'read','files':hashes},
       'files':[{'path':'Client.json','sha256':save('Client.json',record)}],
       'control_samples':[{'actual_sample_start_ns':30,'work_completed_ns':60}]}
    save('manifest.json',m);manifest=tmp_path/'manifest.json'
    source_hashes=a._recovery_inputs(manifest)[2]
    out=tmp_path/'recovered';out.mkdir()
    request={'manifest':str(manifest),'source_sha256':source_hashes,
             'analysis_head':'b'*40,'limits':a.RECOVERY_LIMITS}
    (out/'request.json').write_text(json.dumps(request),encoding='utf8')
    monkeypatch.setattr(w,'read_control_recovery_etl',lambda *args,**kw:{
        'events':[],'scan_complete':True,'complete':True,'schedule_window_complete':True,
        'target_pid':record['pid'],'target_tid':record['main_thread_id'],
        'maximum_events':5000000,'recovery_policy':'control-etl-recovery-v1'})
    monkeypatch.setattr(c,'_peak_memory',lambda:a.RECOVERY_LIMITS['peak_memory_bytes']+1 if fault=='memory' else 1)
    a._recover_control_worker(out)
    if fault=='input':(tmp_path/'native-a.etl').write_bytes(b'changed')
    receipt=json.loads((out/'receipt.json').read_text(encoding='utf8'))
    if fault=='run':receipt['source_sha256']['manifest.json']='wrong'
    if fault=='policy':receipt['limits']={}
    if fault in ('derived','target'):
        p=out/('events.json' if fault=='derived' else 'view.json')
        if fault=='derived':p.write_text('[1]',encoding='utf8')
        else:
            v=json.loads(p.read_text());v['target_pid']+=1;p.write_text(json.dumps(v))
            receipt['files']['view.json']=hashlib.sha256(p.read_bytes()).hexdigest()
    (out/'receipt.json').write_text(json.dumps(receipt),encoding='utf8')
    if fault in (None,'memory'):
        result,_=a._load_control_recovery(out/'receipt.json',manifest)
        assert result['complete']==(fault is None)
    else:
        with pytest.raises(ValueError):a._load_control_recovery(out/'receipt.json',manifest)


def test_recovery_watchdog_has_no_retry_or_session_commands(tmp_path,monkeypatch):
    from secure_control.experiments import tail_diagnostic_analysis as a
    monkeypatch.setattr(a,'_recovery_inputs',lambda _:({}, {}, {'input':'hash'}))
    monkeypatch.setattr(a.subprocess,'check_output',lambda *args,**kw:'a'*40)
    calls=[]
    def timeout(args,**kw):
        calls.append((args,kw))
        raise subprocess.TimeoutExpired(args,kw['timeout'])
    monkeypatch.setattr(a.subprocess,'run',timeout)
    output=tmp_path/'bounded'
    with pytest.raises(subprocess.TimeoutExpired):
        a.recover_control_etl(tmp_path/'manifest.json',output,expected_head='a'*40)
    assert len(calls)==1 and calls[0][1]['timeout']==120
    assert calls[0][0][1]=='-c' and 'wpr' not in calls[0][0]
    assert json.loads((output/'failure.json').read_text())['retry'] is False
    with pytest.raises(FileExistsError):
        a.recover_control_etl(tmp_path/'manifest.json',output,expected_head='a'*40)
    assert len(calls)==1


def test_recorder_default_off_bounded_overflow_and_no_secret_payload(tmp_path):
    assert current() is None
    original = list(gc.callbacks)
    recorder = TailRecorder(context(tmp_path), 'Client', event_capacity=2, gc_capacity=2)
    assert recorder.buffer_bytes <= 1024*1024
    recorder.start()
    with pytest.raises(TypeError):
        recorder.emit('sample',0,0,payload='secret-sentinel')
    recorder.emit('sample', 0, 0)
    recorder.emit('work', 1, 0)
    report = recorder.finish('stopped')
    assert current() is None and gc.callbacks == original
    assert report['lost_events'] > 0 and report['first_lost_sequence'] is not None
    assert not report['diagnostic_complete'] and len(report['events']) <= 2
    assert 'share' not in repr(report) and 'seed' not in repr(report)
    assert 'secret-sentinel' not in repr(report)


def test_gc_callback_install_restore_and_observer_failure_are_isolated(tmp_path):
    first = lambda *args: None
    second = lambda *args: None
    gc.callbacks.append(first)
    recorder = TailRecorder(context(tmp_path), 'Client')
    try:
        recorder.start()
        with pytest.raises(RuntimeError):
            TailRecorder(context(tmp_path), 'P1').start()
        gc.callbacks.append(second)
        recorder._gc_callback('start', {'generation': True})
        report = recorder.finish('failed')
        assert not report['diagnostic_complete']
        assert gc.callbacks[-2:] == [first, second]
        assert current() is None
    finally:
        gc.callbacks[:] = [v for v in gc.callbacks if v is not first and v is not second]


def test_gc_clipping_does_not_count_stop_gc_as_control_coverage():
    # 原RV003反例：停止期GC比运行期长，不能拿它充运行窗口覆盖。
    events = [{'start_ns':5,'end_ns':15,'thread_id':1,'generation':0},
              {'start_ns':45,'end_ns':60,'thread_id':1,'generation':1},
              {'start_ns':101,'end_ns':200,'thread_id':1,'generation':2}]
    result = gc_intersections(events, 10, 50)
    assert result['overlap_ns'] == 10 and result['complete']
    assert [v['overlap_ns'] for v in result['events']] == [5, 5]
    broken = gc_intersections([{'start_ns':20,'end_ns':None,'thread_id':1,'generation':0}],10,50)
    assert not broken['complete'] and broken['overlap_ns'] == 0


def test_gc_overlap_union_does_not_double_count_parallel_events():
    result = gc_intersections([{'start_ns':10,'end_ns':30,'thread_id':1,'generation':0},
                              {'start_ns':20,'end_ns':40,'thread_id':2,'generation':1}],0,50)
    assert result['overlap_ns'] == 30


def test_round_identity_slots_and_clock_source_are_strict(tmp_path):
    recorder = TailRecorder(context(tmp_path), 'worker')
    recorder.start()
    recorder.bind_protocol('run','session','epoch')
    recorder.bind_round(415,'round415')
    recorder.bind_round(415,'different')
    report = recorder.finish('stopped')
    assert not report['diagnostic_complete']
    assert report['rounds']['415'] == 'round415'
    assert report['clock']['wall']['implementation']
    assert report['clock']['cpu']['resolution'] > 0


def test_context_cannot_request_an_unbounded_or_invalid_buffer(tmp_path):
    with pytest.raises(ValueError):
        TailRecorder(context(tmp_path),'Client',event_capacity=999999)
    with pytest.raises(ValueError):
        TailRecorder(replace(context(tmp_path), diagnostic_id=''), 'Client')


def test_gc_capacity_missing_endpoint_and_export_failure_preserve_callbacks(tmp_path):
    original = list(gc.callbacks)
    rec = TailRecorder(context(tmp_path),'Client',gc_capacity=2).start()
    rec._gc_callback('start',{'generation':0})
    rec._gc_callback('stop',{'generation':0})
    rec._gc_callback('start',{'generation':1})
    report = rec.finish('stopped')
    assert report['lost_events'] and not report['diagnostic_complete']
    assert gc.callbacks == original
    existing = tmp_path/'Client.json'
    existing.write_text('preserved',encoding='utf8')
    rec = TailRecorder(context(tmp_path),'Client').start()
    rec._gc_callback('start',{'generation':2})
    assert not rec.save('stopped')['diagnostic_complete']
    assert existing.read_text(encoding='utf8') == 'preserved' and current() is None
    assert gc.callbacks == original


def test_observation_clock_failure_does_not_escape_or_leave_a_partial_event(tmp_path,monkeypatch):
    import secure_control.execution.tail_diagnostics as tail
    rec = TailRecorder(context(tmp_path),'Client').start()
    def broken():
        raise OSError('observer clock')
    with monkeypatch.context() as patch:
        patch.setattr(tail.time,'thread_time_ns',broken)
        rec.emit('sample',0,0)
    report = rec.finish('stopped')
    assert not report['diagnostic_complete'] and report['observation_error'] == 'OSError'
    assert all(row[6] > 0 for row in report['events']) and current() is None


def test_protocol_optional_callback_failure_is_not_a_protocol_operation():
    from secure_control.protocol.coordinator import _observe_boundary
    errors = []
    class BrokenObserver:
        def __call__(self,*args):
            raise OSError('observation only')
        def observation_failed(self,error):
            errors.append(type(error).__name__)
    _observe_boundary(BrokenObserver(),'matrix',0,1)
    assert errors == ['OSError']


def test_real_stop_count_is_400_and_slow_labels_do_not_terminate(monkeypatch):
    from secure_control.experiments import tail_diagnostic_runner as runner
    stopped = []
    control = SimpleNamespace(request_stop=lambda:stopped.append(True))
    event = SimpleNamespace(is_set=lambda:False)
    monkeypatch.setattr(runner.time,'perf_counter',lambda:10.)
    for confirmed in (102,285,290,399):
        runner._request_stop(control,event,30,confirmed,400)
    assert not stopped
    runner._request_stop(control,event,30,400,400)
    assert len(stopped) == 1
    runner._request_stop(control,SimpleNamespace(is_set=lambda:True),30,0,400)
    runner._request_stop(control,event,9,0,400)
    assert len(stopped) == 3


def test_parent_deadline_reaps_only_owned_processes_without_real_spawn(monkeypatch):
    import queue

    from secure_control.experiments import tail_diagnostic_runner as runner
    now, killed, processes = [0.], [], []
    class Process:
        def __init__(self, **kwargs):
            self.pid, self.exitcode, self.alive = 1000+len(processes),None,True
            processes.append(self)
        def start(self):
            now[0] += 1
        def join(self, timeout):
            now[0] += timeout
        def is_alive(self):
            return self.alive
        def terminate(self):
            self.alive, self.exitcode = False,-1
    class Results:
        def get(self,timeout):
            now[0] += timeout
            raise queue.Empty
        def close(self):
            return None
        def cancel_join_thread(self):
            return None
    spawn = SimpleNamespace(Queue=Results,Event=lambda:SimpleNamespace(set=lambda:None),Process=Process)
    def kill(command, **kwargs):
        assert command[0] == 'taskkill' and kwargs['timeout'] == 1.
        killed.append(int(command[2]))
        now[0] += 1
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(runner.subprocess,'run',kill)
    group = runner._collect_group((1,2,3),None,400,
        _mp=SimpleNamespace(get_context=lambda kind:spawn),_now=lambda:now[0])
    assert group['wall_s'] <= 30 and killed == [1000,1001,1002]
    assert group['owned_pids'] == killed and group['forced_cleanup']
    assert all(not p.is_alive() for p in processes)


@pytest.mark.parametrize('drop', [None,'request_send','work'])
def test_analyze_cli_accepts_synthetic_two_domains_and_rejects_forced_single_axis(tmp_path,drop):
    records,domains = fixture_records(dual=True)
    if drop:
        client = records[0]
        client['events'] = [r for r in client['events'] if r[1]//2 != PHASES[drop]]
        recount(client)
    import hashlib
    files = []
    for record in records:
        path = tmp_path/f'{record["role"]}.json'
        path.write_text(json.dumps(record),encoding='utf8')
        files.append({'path':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'schema':SCHEMA,'diagnostic_id':'same','source_head':'a'*40,
                                    'diagnostic_complete':True,'expected_step_count':2,'files':files,
                                    'clock_domains':domains}),encoding='utf8')
    script = Path(__file__).resolve().parents[1]/'scripts/run_control_tail_diagnostic.py'
    command = [sys.executable,str(script),'analyze',str(manifest),'--output',str(tmp_path/'analysis.json')]
    result = subprocess.run(command,capture_output=True,text=True,check=False)
    assert result.returncode == 0,result.stderr
    data = json.loads((tmp_path/'analysis.json').read_text(encoding='utf8'))
    assert data['diagnostic_complete'] is (drop is None)
    assert len(set(data['clock_axes'].values())) == 2
    if drop:
        assert data['missing_evidence']
    result = subprocess.run(command+['--same-host'],capture_output=True,text=True,check=False)
    assert result.returncode != 0


def fixture_records(*, gc_event=True, dual=False, auxiliary=False, future=False):
    """手写绝对时刻oracle；异域B故意差一亿ns，同hostname不意味着同域。"""
    roles = ('Client','P1','P2','worker')
    pids = {'Client':101,'P1':102,'P2':103,'worker':104}
    records = []
    for role in roles:
        domain = 'B' if dual and role in ('P1','P2') else 'A'
        shift = 100_000_000 if domain == 'B' else 0
        thread = pids[role]*10
        data = {'schema':SCHEMA,'context':{'diagnostic_id':'same','source_head':'a'*40,
            'clock_domain_id':domain,'launcher_pid':10 if domain == 'A' else 20},
            'role':role,'pid':pids[role],'parent_pid':101 if role == 'worker' else 10 if domain == 'A' else 20,
            'main_thread_id':thread,'hostname':'identical-hostname','clock':{'wall':{'monotonic':True,'implementation':'QPC','resolution':1e-7},
            'cpu':{'monotonic':True,'implementation':'quantized CPU','resolution':.015625}},
            'protocol':['run','session','epoch'],'rounds':{'0':'round0','1':'round1'},
            'buffer_bytes':983040,'event_capacity':12288,'gc_capacity':2048,
            'lost_events':0,'diagnostic_complete':True,'events':[]}
        def event(phase,edge,wall,step=0,material=-1,thread_id=thread,aux=0,_data=data,_shift=shift):
            _data['events'].append([0,2*PHASES[phase]+edge,step,material,wall+_shift,0,thread_id,aux])
        if role == 'Client':
            event('sample',0,100)
            event('exchange',0,105)
            event('exchange',1,197)
            event('work',1,200)
            event('sample',0,300,1)
            event('exchange',0,301,1)
            event('exchange',1,319,1)
            event('work',1,320,1)
            for step,base in ((0,100),(1,300)):
                for phase in ('material_claim','material_bind'):
                    event(phase,0,base,step,step)
                    event(phase,1,base+1,step,step)
                event('request_send',0,base+1,step,aux=0)
                event('request_send',1,base+2,step,aux=0)
                event('request_send',0,base+3,step,aux=1)
                event('request_send',1,base+4,step,aux=1)
                for phase,offset in (('reply_read',94 if step == 0 else 16),
                                     ('reply_frame',95 if step == 0 else 17),
                                     ('commit_fact',96 if step == 0 else 18)):
                    for party in (0,1):
                        event(phase,0,base+offset,step,aux=party)
                for phase in ('double_commit','output_checked','applied'):
                    event(phase,0,base+(97 if step == 0 else 19),step)
        elif role == 'P1':
            event('matrix',0,115)
            event('suffix',0,120)
            event('suffix',1,180)
            event('matrix',1,185)
        elif role == 'P2':
            event('matrix',0,110)
            event('matrix',1,190)
            if gc_event:
                tid = thread+1 if auxiliary else thread
                aux = 4*PHASES['prefix' if future else 'matrix']
                data['events'].extend([[0,900,0,1 if future else -1,130+shift,0,tid,aux],
                                       [0,901,0,1 if future else -1,170+shift,0,tid,aux]])
        else:
            event('worker_generate',0,1,-1,0)
            event('worker_generate',1,50,-1,0)
            event('worker_ipc',0,50,-1,0)
            event('worker_ipc',1,55,-1,0)
            event('worker_generate',0,210,-1,1)
            event('worker_generate',1,250,-1,1)
            event('worker_ipc',0,250,-1,1)
            event('worker_ipc',1,255,-1,1)
        if role in ('P1','P2'):
            for phase,left,right in (('request_receive',101,105),('restore',105,109),
                ('truncation',190,191),('ready',191,192),('commit',192,193),('final_send',193,194)):
                event(phase,0,left)
                event(phase,1,right)
            if role == 'P2':
                event('suffix',0,175)
                event('suffix',1,180)
            for phase,left,right in (('request_receive',301,305),('restore',305,306),
                ('matrix',306,312),('suffix',307,310),('truncation',312,313),
                ('ready',313,314),('commit',314,315),('final_send',315,316)):
                event(phase,0,left,1)
                event(phase,1,right,1)
        if role in ('P1','P2'):
            event('stage',0,191)
            event('stage',0,313,1)
        data['events'].sort(key=lambda r:r[4])
        for seq,row in enumerate(data['events']):
            row[0] = seq
        data['gc_count'] = sum(row[1] in (900,901) for row in data['events'])
        data['event_count'] = len(data['events'])-data['gc_count']
        records.append(data)
    domains = {}
    for domain in {r['context']['clock_domain_id'] for r in records}:
        members = {r['role']:{'pid':r['pid']} for r in records if r['context']['clock_domain_id'] == domain}
        domains[domain] = {'local_spawn_verified':True,'launcher_pid':10 if domain == 'A' else 20,
                          'members':members,'wall_clock':records[0]['clock']['wall']}
    return records,domains


def test_known_slow_party_and_gc_contributor_without_double_count():
    records,domains = fixture_records()
    result = analyze_records(records,expected_steps=range(2),clock_domains=domains,targets=(0,))
    step = result['steps'][0]
    assert result['diagnostic_complete']
    assert step['located_phase'] == {'role':'P2','phase':'matrix'}
    assert step['evidence_level'] == 'Contributor observed' and not step['fixable_mechanism_confirmed']
    assert step['gc_overlap_union_by_domain_ns'] == {'A':40}
    assert step['normal_neighbor_step'] == 1 and step['normal_neighbor_work_ns'] == 20
    p1 = next(r for r in step['timeline_by_domain']['A'] if r['role']=='P1' and r['phase']=='matrix')
    assert p1['wall_ns'] == 70 and p1['exclusive_wall_ns'] == 10


def recount(record):
    """独立删改oracle后修正格式计数，确保负例只测试语义而不是坏格式。"""
    record['events'].sort(key=lambda r:r[4])
    for index,row in enumerate(record['events']):
        row[0] = index
    record['gc_count'] = sum(r[1] in (900,901) for r in record['events'])
    record['event_count'] = len(record['events'])-record['gc_count']


@pytest.mark.parametrize('critical', [False,True])
@pytest.mark.parametrize('reverse', [False,True])
def test_slack_gc_cannot_replace_slow_party_or_depend_on_record_order(critical,reverse):
    records,domains = fixture_records(gc_event=critical)
    p1 = records[1]
    # P1 11.6–11.7ms GC被12–18ms等待余量吸收；P2 17.5ms才进入suffix。
    # 可选P2 13–17ms GC期间P1已经等待它，用作有依赖关系的正例。
    p1['events'].extend([[0,900,0,-1,116,0,p1['main_thread_id'],4*PHASES['matrix']],
                         [0,901,0,-1,117,0,p1['main_thread_id'],4*PHASES['matrix']]])
    for record in records:
        for row in record['events']:
            row[4] *= 100_000
        recount(record)
    if reverse:
        records.reverse()
    result = analyze_records(records,clock_domains=domains,expected_steps=range(2),targets=(0,))
    step = result['steps'][0]
    assert result['diagnostic_complete'] and step['work_ns'] == 10_000_000
    assert step['located_phase'] == {'role':'P2','phase':'matrix'}
    assert step['evidence_level'] == ('Contributor observed' if critical else 'Located')
    assert {r['role'] for r in step['gc_dependency_contributions']} == ({'P2'} if critical else set())
    assert any(r['role']=='P1' for r in step['gc'])


@pytest.mark.parametrize('samples_present', [False,True])
@pytest.mark.parametrize('drop', ['request_send','material_claim','material_bind','stage','one_work','all_work','entire_step'])
def test_complete_event_groups_or_whole_steps_cannot_disappear(drop,samples_present):
    records,domains = fixture_records()
    for record in records:
        if drop == 'entire_step':
            record['events'] = [r for r in record['events'] if r[2] != 1 and r[3] != 1]
        elif drop in ('one_work','all_work') and record['role']=='Client':
            record['events'] = [r for r in record['events'] if not
                (r[1]//2 in (PHASES['sample'],PHASES['work']) and (drop=='all_work' or r[2]==1))]
        elif drop == 'stage' and record['role'] in ('P1','P2'):
            record['events'] = [r for r in record['events'] if r[1]//2 != PHASES['stage']]
        elif drop not in ('one_work','all_work','stage','entire_step') and record['role']=='Client':
            record['events'] = [r for r in record['events'] if r[1]//2 != PHASES[drop]]
        recount(record)
    samples = [{'global_step':s,'round_id':f'round{s}','actual_sample_start_ns':a,
        'control_applied_ns':b-1,'work_completed_ns':b,'work_elapsed_ns':b-a,'control_latency_ns':b-1-a}
        for s,a,b in ((0,100,200),(1,300,320))] if samples_present else []
    result = analyze_records(records,clock_domains=domains,samples=samples,expected_steps=range(2))
    assert not result['diagnostic_complete'] and result['missing_evidence']


def test_undeclared_control_range_cannot_prove_complete_recording():
    records,domains = fixture_records()
    result = analyze_records(records,clock_domains=domains)
    assert not result['diagnostic_complete'] and 'not declared' in result['missing_evidence'][0]


@pytest.mark.parametrize('auxiliary,future', [(True,False),(False,True)])
def test_auxiliary_or_next_material_gc_is_not_claimed_as_current_control_pause(auxiliary,future):
    records,domains = fixture_records(auxiliary=auxiliary,future=future)
    step = analyze_records(records,expected_steps=range(2),clock_domains=domains,targets=(0,))['steps'][0]
    assert step['evidence_level'] == 'Located'
    assert step['gc'] and not step['fixable_mechanism_confirmed']


def test_cpu_zero_is_not_network_proof_and_dual_host_cannot_be_forced_to_one_axis():
    records,domains = fixture_records(gc_event=False,dual=True)
    result = analyze_records(records,expected_steps=range(2),clock_domains=domains,targets=(0,))
    assert result['clock_axes'] == {'Client':'A','P1':'B','P2':'B','worker':'A'}
    assert set(result['steps'][0]['timeline_by_domain']) == {'A','B'}
    assert result['steps'][0]['evidence_level'] == 'Located'
    for row in result['steps'][0]['timeline_by_domain']['B']:
        assert 'client_work_overlap_ns' not in row
        assert 'zero does not identify network' in row['cpu_note']
    with pytest.raises(ValueError,match='不同clock'):
        analyze_records(records,expected_steps=range(2),clock_domains=domains,same_host=True)
    with pytest.raises(ValueError,match='spawn证明'):
        analyze_records(fixture_records()[0],same_host=True,expected_steps=range(2))


@pytest.mark.parametrize('fault',['session','round','step_bool','duplicate_seq','overflow','missing_end','missing_gc_end'])
def test_incomplete_or_wrong_identity_is_rejected_or_marked_without_invented_endpoints(fault):
    records,domains = fixture_records()
    changed = copy.deepcopy(records)
    if fault=='session':
        changed[1]['protocol'][1] = 'other'
    elif fault=='round':
        changed[1]['rounds']['0'] = 'other'
    elif fault=='step_bool':
        changed[1]['events'][0][2] = True
    elif fault=='duplicate_seq':
        changed[1]['events'][1][0] = changed[1]['events'][0][0]
    elif fault=='overflow':
        changed[1]['diagnostic_complete'] = False
    elif fault=='missing_end':
        changed[1]['events'].pop()
    else:
        changed[2]['events'] = [r for r in changed[2]['events'] if r[1] != 901]
    for record in changed:
        record['gc_count'] = sum(row[1] in (900,901) for row in record['events'])
        record['event_count'] = len(record['events'])-record['gc_count']
    if fault in ('session','round','step_bool','duplicate_seq'):
        with pytest.raises(ValueError):
            analyze_records(changed,expected_steps=range(2),clock_domains=domains)
    else:
        result = analyze_records(changed,expected_steps=range(2),clock_domains=domains,targets=(0,))
        assert not result['diagnostic_complete']
        assert result['steps'][0]['evidence_level'] != 'Contributor observed'


@pytest.mark.parametrize('fault', [None,'lost_sample','missing_phase','wrong_round',
                                   'missing_send','missing_claim','missing_stage','missing_work'])
def test_launcher_separates_control_success_from_incomplete_observation(tmp_path,monkeypatch,fault):
    from dataclasses import asdict

    from secure_control.experiments import tail_diagnostic_runner as runner

    def synthetic_group(ports,ctx,steps):
        records,_ = fixture_records()
        for record in records:
            record['context'] = asdict(ctx)
            if record['role'] != 'worker':
                record['parent_pid'] = os.getpid()
            if fault == 'missing_phase' and record['role'] == 'P2':
                record['events'] = [r for r in record['events'] if r[1] not in (2*PHASES['matrix'],2*PHASES['matrix']+1)]
                for seq,row in enumerate(record['events']):
                    row[0] = seq
                record['event_count'] = len(record['events'])-record['gc_count']
            phase = {'missing_send':'request_send','missing_claim':'material_claim',
                     'missing_stage':'stage','missing_work':'work'}.get(fault)
            if phase and (record['role']=='Client' or phase=='stage' and record['role']=='P2'):
                record['events'] = [r for r in record['events'] if r[1]//2 != PHASES[phase]]
                recount(record)
            (Path(ctx.output_directory)/f"{record['role']}.json").write_text(json.dumps(record),encoding='utf8')
        samples = [{'global_step':step,'round_id':f'round{step}','status':'confirmed',
            'actual_sample_start_ns':begin,'control_applied_ns':end-1,'work_completed_ns':end,
            'work_elapsed_ns':end-begin,'control_latency_ns':end-1-begin}
            for step,begin,end in ((0,100,200),(1,300,320))]
        if fault == 'lost_sample':
            samples.pop()
        elif fault == 'wrong_round':
            samples[0]['round_id'] = 'wrong-round'
        reports = [{'role':r['role'],'pid':r['pid'],'status':'stopped'} for r in records if r['role'] != 'worker']
        reports[0].update(outcome={'confirmed_step_count':2,'protocol_committed_count':2,
            'material_summary':{'worker_exited':True,'cleanup_failed':False,'worker':{'pid':104}}},
            timing={'raw':{'samples':samples}})
        return {'wall_s':.1,'roles':reports,'forced_cleanup':[],
                'owned_pids':[101,102,103],'exitcodes':[0,0,0]}

    monkeypatch.setattr(runner,'_collect_group',synthetic_group)
    head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=runner.ROOT,text=True).strip()
    manifest = runner.run_local(tmp_path/'synthetic',expected_head=head,
                                software_review='https://software-test.invalid',steps=2)
    assert manifest['functional_complete']
    assert manifest['diagnostic_complete'] is (fault is None)
    assert manifest['timing_complete'] is (fault != 'lost_sample')
    if fault == 'wrong_round':
        assert manifest['export_errors'] == [{'role':'analysis','error_type':'ValueError'}]


@pytest.mark.integration
def test_short_local_original_roles_and_worker_export_and_same_analyzer(tmp_path):
    from secure_control.experiments.tail_diagnostic_analysis import analyze_manifests
    from secure_control.experiments.tail_diagnostic_runner import run_local
    root = Path(__file__).resolve().parents[1]
    head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    output = tmp_path/'short-software-test'
    manifest = run_local(output,expected_head=head,software_review='https://software-test.invalid',steps=2)
    assert manifest['functional_complete'],manifest['group']
    assert manifest['diagnostic_complete'],manifest
    result = analyze_manifests([output/'manifest.json'],same_host=True)
    assert result['diagnostic_complete'] and result['all_work_steps'] == [0,1]
    assert len(set(result['clock_axes'].values())) == 1
    assert len(manifest['files']) == 4 and sum(json.loads((output/e['path']).read_text(encoding='utf8'))['buffer_bytes'] for e in manifest['files']) <= 4*1024*1024
    with pytest.raises(FileExistsError):
        run_local(output,expected_head=head,software_review='https://software-test.invalid',steps=2)


def _observed_party(config,ports,queue,fault,profile,*,diagnostic_context):
    """测试层包装原短会话服务器；生产角色不含故障开关。"""
    from test_preauthorized_matrix import _party
    recorder = TailRecorder(diagnostic_context,config.role).start()
    try:
        _party(config,ports,queue,fault,profile)
    finally:
        recorder.save('closed' if fault is None else 'failed')


@pytest.mark.integration
@pytest.mark.parametrize('fault',[None,'bad_output','late_after_commit','partial_send','ready_missing'])
def test_observation_preserves_existing_independent_output_oracle_and_failure_semantics(tmp_path,monkeypatch,fault):
    import test_preauthorized_matrix as original
    source = subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    context = DiagnosticContext('short-observed', 'test-domain', str(tmp_path), source, os.getpid())
    monkeypatch.setattr(original,'_party',partial(_observed_party,diagnostic_context=context))
    callbacks = list(gc.callbacks)
    recorder = TailRecorder(context,'Client').start()
    try:
        original.test_real_short_sessions_single_exchange_and_failure_accounting(
            monkeypatch,2,fault,original.PREAUTHORIZED_PROFILE_V2,'ready-v1')
    finally:
        saved = recorder.save('stopped' if fault is None else 'failed')
    assert saved['status'] == 'saved' and current() is None and gc.callbacks == callbacks
    assert {p.name for p in tmp_path.glob('*.json')} == {'Client.json','P1.json','P2.json','worker.json'}


@pytest.mark.parametrize('side,control_plan',[('client',False),('pair',False),('pair',True)])
@pytest.mark.parametrize('failure',[False,True])
def test_two_host_freezes_actual_config_reserves_id_and_keeps_partial(tmp_path,monkeypatch,side,failure,control_plan):
    """纯装配oracle，不启动双机或本机替代实验；同ID换目录仍被账本拒绝。"""
    from dataclasses import asdict

    from secure_control.experiments import tail_diagnostic_runner as runner
    root = runner.ROOT
    monkeypatch.setattr(runner,'ROOT',tmp_path)
    monkeypatch.setattr(runner.subprocess,'check_output',lambda args,**kw:
        'a'*40 if 'rev-parse' in args else '')
    records,_ = fixture_records(dual=True)
    wanted = {'Client','worker'} if side=='client' else {'P1','P2'}
    subset = [r for r in records if r['role'] in wanted]
    configs = [root/'configs'/f'lab-{r}-cart-pole-demo.example.yaml'
               for r in (['client'] if side=='client' else ['p1','p2'])]

    def collect(loaded,ctx,steps,*,wall_started,**extra):
        assert extra.get('control_file',False)==control_plan
        assert [c.role for c in loaded] == (['Client'] if side=='client' else ['P1','P2'])
        assert all(c.topology.p1_peer.host=='192.168.31.116' for c in loaded)
        reports = []
        for record in subset:
            record['context'] = asdict(ctx)
            if record['role']!='worker':
                record['parent_pid'] = os.getpid()
            if failure:
                record['diagnostic_complete'] = False
                record['status'] = 'failed'
            (Path(ctx.output_directory)/f"{record['role']}.json").write_text(json.dumps(record),encoding='utf8')
            if record['role']!='worker':
                reports.append({'role':record['role'],'pid':record['pid'],
                    'status':'failed' if failure else 'stopped'})
        if side=='client':
            samples = [{'global_step':s,'round_id':f'round{s}','status':'confirmed',
                'actual_sample_start_ns':a,'control_applied_ns':b-1,'work_completed_ns':b,
                'work_elapsed_ns':b-a,'control_latency_ns':b-1-a} for s,a,b in ((0,100,200),(1,300,320))]
            reports[0].update(timing={'raw':{'samples':samples}},outcome={
                'confirmed_step_count':2,'protocol_committed_count':2,
                'material_summary':{'worker_exited':True,'cleanup_failed':False,'worker':{'pid':104}}})
        return {'wall_s':.1,'roles':reports,'forced_cleanup':[],
            'owned_pids':[r['pid'] for r in reports],'exitcodes':[0]*len(reports),
            'members':{r['role']:{'pid':r['pid']} for r in reports},
            'stop_reason':'first_functional_failure' if failure else None,'activity_elapsed_s':.1}

    monkeypatch.setattr(runner,'_collect_host',collect)
    kwargs = {'diagnostic_id':'one-session','expected_head':'a'*40,
        'software_review':'https://software-test.invalid','config_paths':configs,'steps':2}
    if control_plan:
        from secure_control.experiments import native_tail_capture, tail_calibration
        monkeypatch.setattr(native_tail_capture,'authorize_control',lambda *a,**kw:None)
        monkeypatch.setattr(tail_calibration,'_source_clean',lambda:True)
        kwargs.update(window=2000,steps=2000,authorization={},native_plan={
            'schema':'native-calibration-preparation-v1','purpose':'control-slow-step-v1',
            'source_head':'a'*40,'software_review':kwargs['software_review']})
    manifest = runner.run_host(side,tmp_path/'first',**kwargs)
    assert manifest['diagnostic_complete'] is (not failure)
    assert manifest['mode']=='non_realtime_diagnostic' and not manifest['strict_qualification']
    assert manifest['clock_domains'][manifest['plan']['clock_domain_id']]['local_spawn_verified']
    ledger = json.loads((tmp_path/f'results/tail_diagnostics/session-one-session-{side}.ledger.json').read_text())
    assert ledger['two_host_2000' if control_plan else 'one_two_host']==0
    assert ledger['status']==('partial' if failure else 'complete')
    with pytest.raises(FileExistsError):
        runner.run_host(side,tmp_path/'different',**kwargs)
    assert not (tmp_path/'different').exists()
    # ZIP/checkout换行不同不能消耗唯一实测后才发现伪版本冲突；真实代码改变仍拒绝。
    text = tmp_path/'source.py'
    text.write_bytes(b'value = 1\r\n')
    digest = runner._common_sha(text)
    original = runner._sha(text)
    text.write_bytes(b'value = 1\n')
    assert runner._common_sha(text)==digest and runner._sha(text)!=original
    text.write_bytes(b'value = 2\n')
    assert runner._common_sha(text)!=digest
    binary = tmp_path/'raw.bin'
    binary.write_bytes(b'\r\n')
    assert runner._common_sha(binary)==runner._sha(binary)


@pytest.mark.parametrize('reason',['wall_limit','activity_limit','first_functional_failure','child_exit'])
def test_two_host_supervision_fake_clock_no_retry_and_only_owned_pid_cleanup(monkeypatch,reason):
    """监督期限用假时钟驱动；不等待180秒、不运行实际业务进程。"""
    from secure_control.experiments import tail_diagnostic_runner as runner
    clock = [0.]
    killed, started = [], []
    activity = SimpleNamespace(value=0.)
    class Process:
        def __init__(self,**kwargs):
            self.pid = 100+len(started)
            self.exitcode = None
        def start(self):
            started.append(self.pid)
        def join(self,timeout):
            pass
        def is_alive(self):
            return self.exitcode is None
        def terminate(self):
            self.exitcode = -1
    class Queue:
        def get(self,timeout):
            if reason=='first_functional_failure':
                return {'role':'P1','status':'failed'}
            clock[0] = 177 if reason=='wall_limit' else 31
            if reason=='activity_limit':
                activity.value = 1
            elif reason=='child_exit':
                processes[0].exitcode = 4
            raise runner.queue.Empty
        def close(self):
            pass
        def cancel_join_thread(self):
            pass
    processes = []
    def make_process(**kwargs):
        p = Process(**kwargs)
        processes.append(p)
        return p
    spawn = SimpleNamespace(Queue=Queue,Event=lambda:SimpleNamespace(set=lambda:None),
        Value=lambda *args:activity,Process=make_process)
    def kill(args,**kwargs):
        killed.append(args)
        return SimpleNamespace(returncode=0)
    original = runner._clear_owned
    monkeypatch.setattr(runner,'_clear_owned',lambda ps,d,**kw:original(ps,d,_now=lambda:clock[0],_run=kill))
    group = runner._collect_host([SimpleNamespace(role='P1'),SimpleNamespace(role='P2')],None,400,
        _mp=SimpleNamespace(get_context=lambda _:spawn),_now=lambda:clock[0])
    assert group['stop_reason']==reason and len(started)==2
    assert {int(args[2]) for args in killed} <= set(started)
    assert all(args[0]=='taskkill' and args[-2:]==['/T','/F'] for args in killed)
    assert group['wall_s']<=180
    if reason=='wall_limit':
        def fail_start(**kwargs):
            raise OSError('spawn failed')
        spawn.Process = fail_start
        partial = runner._collect_host([SimpleNamespace(role='Client')],None,400,
            _mp=SimpleNamespace(get_context=lambda _:spawn),_now=lambda:clock[0])
        assert partial['stop_reason']=='launcher_failure' and partial['launcher_error']=='OSError'
        assert partial['owned_pids']==[] and not partial['roles']


def test_configured_client_attempt_400_stops_without_401_and_first_failure_no_retry(tmp_path,monkeypatch):
    """原runner替身只驱动真实装配回调；成功400次与首失败均只调用一次runner。"""
    from secure_control.execution.lan_config import load_lan_config
    from secure_control.experiments import lan_continuous_profile, lan_runner, live_timing
    from secure_control.experiments import tail_diagnostic_runner as runner
    config = load_lan_config(runner.ROOT/'configs/lab-client-cart-pole-demo.example.yaml','Client')
    monkeypatch.setattr(lan_continuous_profile,'load_segmented_experiment',
        lambda *args:SimpleNamespace(scene=SimpleNamespace(period=.02)))
    monkeypatch.setattr(live_timing,'timing_metadata',lambda *args,**kw:{})
    ctx = replace(context(tmp_path),launcher_pid=os.getpid())
    real_check = runner.subprocess.check_output
    monkeypatch.setattr(runner.subprocess,'check_output',lambda *args,**kw:'a'*40)
    calls = []
    def original(config,prepared,**kwargs):
        calls.append(1)
        for step in range(400):
            assert not kwargs['control'].stop_requested
            kwargs['before_sample']()
            kwargs['on_step'](SimpleNamespace(protocol=SimpleNamespace(global_step=step)))
        assert kwargs['control'].stop_requested
        return {'status':'stopped'}
    monkeypatch.setattr(lan_runner,'_run_prepared_segmented',original)
    reports = []
    stop = SimpleNamespace(is_set=lambda:False,set=lambda:None)
    runner._configured_child(config,ctx,SimpleNamespace(put=reports.append),stop,
        runner.time.perf_counter()+100,400,SimpleNamespace(value=0.))
    assert calls==[1] and reports[0]['attempt_callbacks']==400
    assert reports[0]['status']=='stopped'
    # 下一次只用另一个临时导出目录；这是软件失败替身，不是第二组控制实验。
    def fail(*args,**kwargs):
        calls.append(1)
        kwargs['before_sample']()
        raise ConnectionError('test')
    monkeypatch.setattr(lan_runner,'_run_prepared_segmented',fail)
    failed_output = tmp_path/'failure'
    failed_output.mkdir()
    runner._configured_child(config,replace(ctx,output_directory=str(failed_output)),
        SimpleNamespace(put=reports.append),stop,runner.time.perf_counter()+100,400,
        SimpleNamespace(value=0.))
    assert calls==[1,1] and reports[-1]['status']=='failed'
    assert reports[-1]['error_type']=='ConnectionError'
    monkeypatch.setattr(runner.subprocess,'check_output',real_check)


def two_host_manifests(tmp_path):
    """独立构造A/B时钟相差一亿ns的原始事件，不从分析输出反推expected。"""
    import hashlib
    records,domains = fixture_records(dual=True)
    paths = []
    for side,wanted,domain in (('client',{'Client','worker'},'A'),('pair',{'P1','P2'},'B')):
        output = tmp_path/side
        output.mkdir()
        files = []
        for record in records:
            if record['role'] not in wanted:
                continue
            record['context']['topology_digest'] = 'topology'
            raw = json.dumps(record).encode()
            path = output/f"{record['role']}.json"
            path.write_bytes(raw)
            files.append({'path':path.name,'sha256':hashlib.sha256(raw).hexdigest()})
        plan = {'side':side,'source_head':'a'*40,'diagnostic_id':'same','maximum_steps':2,
            'mode':'non_realtime_diagnostic','clock_domain_id':domain,'topology_digest':'topology',
            'common_source_sha256':{'src/example.py':'1'*64},'software_review':'https://review.invalid',
            'profile':'control-dynamic-matrix-preauthorized-v2',
            'configurations':[{'role':r,'wire_profile':'control-dynamic-matrix-preauthorized-v2',
                'transport':'insecure_tcp','topology_digest':'topology'} for r in sorted(wanted-{'worker'})]}
        manifest = {'schema':SCHEMA,'source_head':'a'*40,'diagnostic_id':'same','side':side,
            'diagnostic_complete':True,'functional_complete':True,'expected_step_count':2,
            'files':files,'clock_domains':{domain:domains[domain]},'control_samples':[],
            'plan':plan,'plan_sha256':hashlib.sha256(json.dumps(plan,ensure_ascii=False,
                allow_nan=False,separators=(',',':')).encode()).hexdigest(),'group':{}}
        path = output/'manifest.json'
        path.write_text(json.dumps(manifest),encoding='utf8')
        paths.append(path)
    return paths


def test_two_host_analysis_top_eight_neighbors_points_and_local_gc_dependencies(tmp_path):
    from secure_control.experiments.tail_diagnostic_analysis import analyze_manifests
    paths = two_host_manifests(tmp_path)
    report = analyze_manifests(paths)
    assert report['diagnostic_complete'] and report['mode']=='non_realtime_diagnostic'
    assert report['clock_axes']=={'Client':'A','worker':'A','P1':'B','P2':'B'}
    assert report['work_distribution']['mean_ns']==60
    assert [r['global_step'] for r in report['steps']]==[0,1]
    step = report['steps'][0]
    assert {e['role'] for e in step['server_local_gc_dependencies']}=={'P2'}
    assert step['client_points'] and step['normal_neighbor_step']==1
    assert all('client_work_overlap_ns' not in r for r in step['timeline_by_domain']['B'])
    assert all('client_window_comparable' not in e or not e['client_window_comparable']
               for e in step['server_local_gc_dependencies'])
    assert not step['fixable_mechanism_confirmed']
    with pytest.raises(ValueError,match='不同clock'):
        analyze_manifests(paths,same_host=True)


@pytest.mark.parametrize('fault',['head','topology','source','role','session','round','plan_hash','domain'])
def test_two_host_analysis_rejects_mixed_evidence(tmp_path,fault):
    import hashlib

    from secure_control.experiments.tail_diagnostic_analysis import analyze_manifests
    paths = two_host_manifests(tmp_path)
    m = json.loads(paths[1].read_text())
    if fault=='head':
        m['source_head'] = 'b'*40
    elif fault=='topology':
        m['plan']['topology_digest'] = 'other'
    elif fault=='source':
        m['plan']['common_source_sha256']['src/example.py']='2'*64
    elif fault=='role':
        m['side']='client'
        m['plan']['side']='client'
    elif fault=='domain':
        m['plan']['clock_domain_id']='A'
    elif fault in ('session','round'):
        entry = m['files'][0]
        p = paths[1].parent/entry['path']
        record = json.loads(p.read_text())
        if fault=='session':
            record['protocol'][1]='other'
        else:
            record['rounds']['0']='other'
        raw = json.dumps(record).encode()
        p.write_bytes(raw)
        entry['sha256'] = hashlib.sha256(raw).hexdigest()
    if fault!='plan_hash':
        m['plan_sha256']=hashlib.sha256(json.dumps(m['plan'],ensure_ascii=False,
            allow_nan=False,separators=(',',':')).encode()).hexdigest()
    else:
        m['plan']['maximum_steps']=1
    paths[1].write_text(json.dumps(m))
    with pytest.raises(ValueError):
        analyze_manifests(paths)


@pytest.mark.parametrize('fault',['missing_file','missing_manifest','unfinished','no_files'])
def test_two_host_partial_never_becomes_complete_or_invents_endpoints(tmp_path,fault):
    import hashlib

    from secure_control.experiments.tail_diagnostic_analysis import analyze_manifests
    paths = two_host_manifests(tmp_path)
    if fault=='missing_manifest':
        paths=paths[:1]
    elif fault=='missing_file':
        (paths[1].parent/'P1.json').unlink()
    elif fault=='no_files':
        for p in paths:
            m=json.loads(p.read_text())
            m['files']=[]
            m['diagnostic_complete']=False
            p.write_text(json.dumps(m))
    else:
        m=json.loads(paths[0].read_text())
        entry=next(e for e in m['files'] if e['path']=='Client.json')
        p=paths[0].parent/'Client.json'
        r=json.loads(p.read_text())
        r['events']=[row for row in r['events'] if not (row[2]==1 and row[1]==PHASES['exchange']*2+1)]
        r['diagnostic_complete']=False
        recount(r)
        raw=json.dumps(r).encode()
        p.write_bytes(raw)
        entry['sha256']=hashlib.sha256(raw).hexdigest()
        m['diagnostic_complete']=False
        paths[0].write_text(json.dumps(m))
    result=analyze_manifests(paths,partial=True)
    assert not result['diagnostic_complete']
    if fault=='unfinished':
        assert result['unfinished_spans']['Client'][0]['phase']=='exchange'
    assert all(not s['fixable_mechanism_confirmed'] for s in result['steps'])


@pytest.mark.parametrize('prepared',[False,True])
@pytest.mark.parametrize('failure_phase',['SAMPLE_START','INPUT','ROUND_IN_FLIGHT'])
@pytest.mark.parametrize('identity',[None,'round1','wrong-round'])
def test_rv003_partial_failure_round_unknown_preserves_prefix(tmp_path,prepared,failure_phase,identity):
    """失败行属于Client事实；worker预生成身份不能替Client补造本步事务。"""
    import hashlib

    from secure_control.experiments.tail_diagnostic_analysis import analyze_manifests
    paths = two_host_manifests(tmp_path)
    for path in paths:
        manifest = json.loads(path.read_text())
        manifest['diagnostic_complete'] = False
        manifest['functional_complete'] = False
        for entry in manifest['files']:
            role_path = path.parent/entry['path']
            record = json.loads(role_path.read_text())
            # 第0步完整；第1步仅Client可能采样，或已发送但未完成，没有work端点。
            if record['role']=='Client':
                record['events'] = [r for r in record['events'] if r[2]!=1 or
                    failure_phase!='SAMPLE_START' and r[1]==PHASES['sample']*2 or
                    failure_phase=='ROUND_IN_FLIGHT' and r[1]==PHASES['exchange']*2]
                record['rounds'].pop('1',None)
            elif record['role'] in ('P1','P2'):
                record['events'] = [r for r in record['events'] if r[2]!=1]
                record['rounds'].pop('1',None)
            elif not prepared:
                record['rounds'].pop('1',None)
                record['events'] = [r for r in record['events'] if r[3]!=1]
            if record['role']=='Client' and identity=='round1':
                record['rounds']['1']='round1'
            record['diagnostic_complete']=False
            recount(record)
            raw=json.dumps(record).encode()
            role_path.write_bytes(raw)
            entry['sha256']=hashlib.sha256(raw).hexdigest()
        if manifest['side']=='client':
            manifest['control_samples']=[
                {'global_step':0,'round_id':'round0','status':'confirmed',
                 'actual_sample_start_ns':100,'control_applied_ns':199,'work_completed_ns':200,
                 'control_latency_ns':99,'work_elapsed_ns':100},
                {'global_step':1,'round_id':identity,'status':'failed','failure_phase':failure_phase,
                 'actual_sample_start_ns':None if failure_phase=='SAMPLE_START' else 300,
                 'control_applied_ns':None,'work_completed_ns':None,
                 'control_latency_ns':None,'work_elapsed_ns':None}]
        path.write_text(json.dumps(manifest))
    if identity=='wrong-round':
        with pytest.raises(ValueError,match='身份'):
            analyze_manifests(paths,partial=True)
        return
    result=analyze_manifests(paths,partial=True)
    assert not result['diagnostic_complete'] and result['all_work_steps']==[0]
    assert result['work_distribution']['count']==1 and result['work_distribution']['mean_ns']==100
    failure=result['failure_samples'][0]
    assert failure['round_id']==identity and failure['work_completed_ns'] is None
    assert failure['control_applied_ns'] is None and failure['failure_phase']==failure_phase
    if identity is None:
        assert result['unknown_sample_round_steps']==[1]
        with pytest.raises(ValueError,match='身份'):
            analyze_manifests(paths)
    assert all(not s['fixable_mechanism_confirmed'] for s in result['steps'])


@pytest.mark.parametrize('values,slow,selected',[
    ([20_000_000,20_000_001,1,30_000_000,1],[1,3],[0,1,2,3,4]),
    ([20_000_000,1],[],[]),([21_000_000],[0],[0])])
def test_control_slow_threshold_and_nearest_normal_neighbors(values,slow,selected):
    from secure_control.experiments.tail_diagnostic_analysis import select_slow_steps
    found,chosen,neighbors=select_slow_steps([{'global_step':i,'work_elapsed_ns':v} for i,v in enumerate(values)])
    assert found==slow and chosen==selected
    if len(values)==1:assert neighbors[0]=={'before':None,'after':None}


@pytest.mark.parametrize('fault',[None,'calibration','purpose','plan','steps','path','config','resource','url'])
def test_control_approval_does_not_reuse_calibration_or_other_run(tmp_path,fault):
    from secure_control.experiments.native_tail_capture import (
        CALIBRATION_RESOURCES,
        authorize_control,
        plan_digest,
    )
    plan={'schema':'native-calibration-preparation-v1','purpose':'control-slow-step-v1',
        'source_selection_audit_version':2,'source_head':'a'*40,'control_steps':2000,
        'pair_wait_s':45,'pair_business_s':55,'pair_total_s':100,
        'control_configurations':{'Client':{'role':'Client','identity':'frozen'}},**CALIBRATION_RESOURCES}
    approval={'schema':'native-control-authorization-v1','purpose':'control-slow-step-v1',
        'source_head':'a'*40,'plan_sha256':plan_digest(plan),'diagnostic_id':'run','attempts':1,
        'steps':2000,'client_output':str(tmp_path/'A'),
        'authorization_url':'https://github.com/GNYKCZ/secure_pid_hvac/issues/153#issuecomment-9999999999'}
    configs=[{'role':'Client','identity':'frozen'}]
    if fault=='calibration':approval['schema']='native-calibration-authorization-v1'
    if fault=='purpose':approval['purpose']='public-echo'
    if fault=='plan':approval['plan_sha256']='b'*64
    if fault=='steps':approval['steps']=True
    if fault=='path':approval['client_output']=str(tmp_path/'other')
    if fault=='config':configs[0]['identity']='changed'
    if fault=='resource':plan['active_window_s']=100
    if fault=='url':approval['authorization_url']=None
    if fault:
        with pytest.raises(PermissionError):authorize_control(approval,plan,side='client',output=tmp_path/'A',
            head='a'*40,diagnostic_id='run',configurations=configs)
    else:assert authorize_control(approval,plan,side='client',output=tmp_path/'A',head='a'*40,
        diagnostic_id='run',configurations=configs)==approval


@pytest.mark.parametrize('business',[False,True])
@pytest.mark.parametrize('b_boundary',[False,True])
def test_control_pair_wait_and_business_deadlines_without_spawn(monkeypatch,business,b_boundary,tmp_path):
    import queue

    from secure_control.experiments import tail_diagnostic_runner as runner
    clock=[0.];activity=SimpleNamespace(value=0.);children=[];order=[]
    class Native:
        def __init__(self):
            self.started=None;self.capture_deadline=110.;self.output=tmp_path/'native-b.etl';self.report={}
        def begin(self):self.started=clock[0];order.append('native')
        def finish(self):order.append('stop');return {'status':'saved'}
    class Process:
        def __init__(self,**kwargs):
            self.pid=100+len(children);self.exitcode=None;children.append(self)
            assert kwargs['args'][-1] is True
        def start(self):order.append('spawn')
    class Queue:
        def get(self,timeout):
            clock[0]+=1
            if business and clock[0]>=(44 if b_boundary else 20) and not activity.value:
                activity.value=44 if b_boundary else 20
            raise queue.Empty
        def close(self):pass
        def cancel_join_thread(self):pass
    spawn=SimpleNamespace(Queue=Queue,Value=lambda *a:activity,
        Event=lambda:SimpleNamespace(set=lambda:None),Process=Process)
    monkeypatch.setattr(runner,'_clear_owned',lambda *a,**kw:[])
    extra={'b_receive_boundary':True,'native':Native()} if b_boundary else {}
    result=runner._collect_host([SimpleNamespace(role='P1'),SimpleNamespace(role='P2')],None,2000,
        control_file=True,_mp=SimpleNamespace(get_context=lambda _:spawn),_now=lambda:clock[0],**extra)
    assert result['stop_reason']=='control_wait_or_business_limit'
    assert clock[0]==((99 if b_boundary else 75) if business else 45)
    assert result['owned_pids']==[100,101]
    if b_boundary:assert order==['native','spawn','spawn','stop']


def test_control_party_reuses_first_request_hook_once_without_network(tmp_path,monkeypatch):
    from contextlib import nullcontext

    from secure_control.execution import lan_runtime
    from secure_control.experiments import tail_diagnostic_runner as runner
    activity=SimpleNamespace(value=0.,get_lock=lambda:nullcontext())
    events=[];reports=[]
    class Recorder:
        def __init__(self,*a,**kw):pass
        def start(self):return self
        def emit(self,*a,**kw):events.append(a)
        def save(self,status):return {'status':status}
    monkeypatch.setattr(runner,'TailRecorder',Recorder)
    monkeypatch.setattr(runner.subprocess,'check_output',lambda *a,**kw:'a'*40)
    def party(*a,**kw):
        # 当前安装的recorder由构造保存，直接驱动原有观察点。
        recorder[0].emit('request_receive',0)
        first=activity.value
        recorder[0].emit('request_receive',0)
        assert first>0 and activity.value==first
        return {'status':'closed'}
    recorder=[]
    def factory(*a,**kw):
        r=Recorder();recorder.append(r);return r
    monkeypatch.setattr(runner,'TailRecorder',factory)
    monkeypatch.setattr(lan_runtime,'run_party_single_step',party)
    runner._configured_child(SimpleNamespace(role='P1'),context(tmp_path),
        SimpleNamespace(put=reports.append),SimpleNamespace(set=lambda:None),100,2000,
        activity=activity,control_file=True)
    assert reports[0]['status']=='closed' and len(events)==2


@pytest.mark.parametrize('purpose',['control-slow-step-v1','control-b-receive-boundary-v1'])
def test_control_missing_approval_fails_before_ledger_or_native(tmp_path,monkeypatch,purpose):
    from secure_control.experiments import tail_calibration
    from secure_control.experiments import tail_diagnostic_runner as runner
    monkeypatch.setattr(tail_calibration,'_source_clean',lambda:True)
    head=__import__('subprocess').check_output(['git','rev-parse','HEAD'],cwd=runner.ROOT,text=True).strip()
    with pytest.raises(PermissionError):runner.run_host('client',tmp_path/'new',diagnostic_id='noapproval',
        expected_head=head,software_review='https://example.test/review',
        config_paths=[runner.ROOT/'configs/lab-client-cart-pole-demo.example.yaml'],steps=2000,
        stream_map=True,window=2000,native_plan={'purpose':purpose,
            'source_head':head,'software_review':'https://example.test/review'})
    assert not (tmp_path/'new').exists()


@pytest.mark.parametrize('fault',[None,'hash','identity','residence_only','residence_quality'])
def test_slow_table_native_hash_identity_and_clipped_thread_evidence(tmp_path,monkeypatch,fault):
    """只测试新离线拼接边界；角色解码/跨机身份由已有分析器独立覆盖。"""
    import hashlib

    from secure_control.experiments import tail_diagnostic_analysis as a
    from secure_control.experiments.windows_tail_analysis import PROCESS, THREAD
    monkeypatch.setattr(a,'analyze_manifests',lambda *args,**kw:{'diagnostic_complete':True})
    ctx={'diagnostic_id':'x','source_head':'a'*40,'clock_domain_id':'A'}
    client={'role':'Client','pid':1,'main_thread_id':2,'context':ctx}
    decoded={'spans':[{'global_step':0,'phase':'request_send','aux':0,'start_ns':30,'end_ns':40}],
        'points':[{'global_step':0,'phase':'reply_read','aux':0,'wall_ns':90}]}
    monkeypatch.setattr(a,'_decode',lambda _:decoded)
    raw=json.dumps(client).encode();(tmp_path/'Client.json').write_bytes(raw)
    rows=[{'provider':PROCESS,'opcode':1,'time_ns':1,'values':{'ProcessId':1,'UniqueProcessKey':1}},
        {'provider':THREAD,'opcode':1,'time_ns':2,'values':{'TThreadId':2,'ProcessId':1}},
        {'provider':THREAD,'opcode':36,'time_ns':20,'cpu':0,'event_index':1,'values':{'NewThreadId':2,'OldThreadId':0,'OldThreadState':1}},
        {'provider':THREAD,'opcode':36,'time_ns':60,'cpu':0,'event_index':2,'values':{'NewThreadId':0,'OldThreadId':2,'OldThreadState':5}},
        {'provider':THREAD,'opcode':50,'time_ns':70,'cpu':0,'event_index':3,'values':{'TThreadId':2}},
        {'provider':THREAD,'opcode':36,'time_ns':80,'cpu':0,'event_index':4,'values':{'NewThreadId':2,'OldThreadId':0,'OldThreadState':1}},
        {'provider':THREAD,'opcode':36,'time_ns':105,'cpu':0,'event_index':5,'values':{'NewThreadId':0,'OldThreadId':2,'OldThreadState':5}},
        {'provider':THREAD,'opcode':2,'time_ns':110,'values':{'TThreadId':2,'ProcessId':1}},
        {'provider':PROCESS,'opcode':2,'time_ns':115,'values':{'ProcessId':1}}]
    (tmp_path/'native-a.etl').write_bytes(b'fake offline input')
    etlhash=hashlib.sha256((tmp_path/'native-a.etl').read_bytes()).hexdigest()
    view={'purpose':'control-slow-step-v1','source_head':'a'*40,'diagnostic_id':'bad' if fault=='identity' else 'x',
        'target_pid':1,'target_tid':2,'complete':True,'schedule_window_complete':True,'etl_sha256':etlhash,
        'window_replay':{'anchor':{'time':20}}}
    view.update(header={'events_lost':0,'buffers_lost':0},errors=[],target_critical_gaps=0,
        cpu_chain_mismatches=0,target_window_ns=[30,100])
    if fault in ('residence_only','residence_quality'):
        view['schedule_window_complete']=False
        rows[3]['values']['OldThreadState']=3
        rows[4]['time_ns']=59  # Ready先于out；不能把此事件用作CPU边界。
        rows[3],rows[4]=rows[4],rows[3]
    if fault=='residence_quality':view['cpu_chain_mismatches']=1
    files={'control-native-view.json':view,'control-native-events.json':rows,'Client.stream.json':{'context':ctx,'rows':[]}}
    for name,value in files.items():(tmp_path/name).write_text(json.dumps(value),encoding='utf8')
    hashes={name:hashlib.sha256((tmp_path/name).read_bytes()).hexdigest() for name in (*files,'native-a.etl')}
    manifest={'side':'client','files':[{'path':'Client.json','sha256':hashlib.sha256(raw).hexdigest()}],
        'control_samples':[{'global_step':0,'round_id':'r0','actual_sample_start_ns':30,
            'work_completed_ns':100,'work_elapsed_ns':21_000_000}],
        'native_evidence':{'status':'read','files':hashes}}
    p=tmp_path/'manifest.json';p.write_text(json.dumps(manifest),encoding='utf8')
    if fault=='hash':(tmp_path/'native-a.etl').write_bytes(b'changed')
    if fault in ('hash','identity'):
        with pytest.raises(ValueError):a.analyze_slow_control([p])
        return
    result=a.analyze_slow_control([p]);wait=result['rows'][0]['parties'][0]['A_wait_analysis']
    assert wait['send_complete_to_first_read_ns']==50
    if fault in ('residence_only','residence_quality'):
        assert wait['ready_observed_ns'] is None and wait['running_observed_ns'] is None
        assert not result['rows'][0]['thread_intervals_verified']
        assert wait['residency_verified']==(fault=='residence_only')
        assert wait['running_residency_ns']==(30 if fault=='residence_only' else None)
        assert wait['not_running_ns']==(20 if fault=='residence_only' else None)
        assert wait['unknown_ns']==(0 if fault=='residence_only' else 50)
        assert result['original_schedule_window_complete'] is False
        return
    assert wait['ready_observed_ns']==10 and wait['running_observed_ns']==30
    assert wait['other_scheduler_states_ns']==10
    assert result['rows'][0]['parties'][0]['tcp_component_complete_ns'] is None
    assert result['rows'][0]['parties'][0]['cross_host_difference_ns'] is None


@pytest.mark.parametrize('native_status',[None,'partial','saved'])
def test_control_client_still_requires_its_actual_native_save(tmp_path,monkeypatch,native_status):
    from dataclasses import asdict

    from secure_control.experiments import native_tail_capture as n
    from secure_control.experiments import tail_calibration as c
    from secure_control.experiments import tail_diagnostic_runner as r
    root=r.ROOT;monkeypatch.setattr(r,'ROOT',tmp_path)
    monkeypatch.setattr(r.subprocess,'check_output',lambda args,**kw:'a'*40 if 'rev-parse' in args else '')
    monkeypatch.setattr(c,'_source_clean',lambda:True)
    monkeypatch.setattr(n,'authorize_control',lambda *a,**kw:None)
    class Capture:
        def __init__(self,plan,output,**kw):self.report={'status':native_status}
        def preflight(self):return {'mock':True}
    monkeypatch.setattr(n,'NativeCapture',Capture)
    from secure_control.experiments import windows_tail_analysis as w
    monkeypatch.setattr(w,'read_calibration_etl',lambda *a,**kw:{'events':[],'complete':True,'schedule_window_complete':True})
    monkeypatch.setattr(c,'_peak_memory',lambda:1)
    records,_=fixture_records(dual=True);records=[x for x in records if x['role'] in ('Client','worker')]
    def collect(configs,ctx,steps,**kw):
        out=Path(ctx.output_directory)
        for record in records:
            record['context']=asdict(ctx)
            if record['role']=='Client':record['parent_pid']=os.getpid()
            (out/(record['role']+'.json')).write_text(json.dumps(record),encoding='utf8')
        (out/'native-a.etl').write_bytes(b'mock');(out/'Client.stream.json').write_text('{}',encoding='utf8')
        samples=[{'global_step':i,'round_id':str(i),'status':'confirmed','actual_sample_start_ns':i*1000+1,
            'work_completed_ns':i*1000+101,'work_elapsed_ns':100} for i in range(2000)]
        group={'wall_s':1.,'forced_cleanup':[],'stop_reason':None,'exitcodes':[0],
            'owned_pids':[101],'members':{'Client':{'pid':101}},'activity_elapsed_s':1.,
            'roles':[{'role':'Client','pid':101,'status':'closed','timing':{'raw':{'samples':samples}},
                'outcome':{'confirmed_step_count':2000,'protocol_committed_count':2000,
                    'material_summary':{'worker_exited':True,'cleanup_failed':False,'worker':{'pid':104}}}}]}
        if native_status is not None:group['native']={'status':native_status}
        return group
    monkeypatch.setattr(r,'_collect_host',collect)
    manifest=r.run_host('client',tmp_path/'A',diagnostic_id='owner-save',expected_head='a'*40,
        software_review='https://review.test',config_paths=[root/'configs/lab-client-cart-pole-demo.example.yaml'],
        window=2000,steps=2000,stream_map=True,authorization={},native_plan={
            'purpose':'control-slow-step-v1','source_head':'a'*40,'software_review':'https://review.test'})
    assert manifest['functional_complete'] and manifest['native_evidence']['status']=='read'
    assert manifest['diagnostic_complete']==(native_status=='saved')


@pytest.mark.parametrize('fault',[None,'hash','identity','range'])
def test_b_request_consumer_binds_files_and_keeps_local_clocks_separate(tmp_path,monkeypatch,fault):
    import copy
    import hashlib

    from test_tail_calibration import addr, party_request_evidence

    from secure_control.experiments import tail_diagnostic_analysis as a
    from secure_control.experiments.windows_tail_analysis import TCPIP
    monkeypatch.setattr(a,'analyze_manifests',lambda *args,**kwargs:{'diagnostic_complete':False})
    monkeypatch.setattr(a,'_decode',lambda record:{'spans':[], 'points':[]})
    paths=[];records={};hashes={}
    for side in ('client','pair'):
        directory=tmp_path/side;directory.mkdir();files=[]
        for role,pid,tid in ([('Client',11,12)] if side=='client' else [('P1',1,2),('P2',3,4)]):
            record={'role':role,'pid':pid,'main_thread_id':tid,'protocol':['run','session','epoch'],
                'context':{'diagnostic_id':'run','source_head':'a'*40,'clock_domain_id':'A' if side=='client' else 'B'}}
            records[role]=record
            raw=json.dumps(record).encode();(directory/(role+'.json')).write_bytes(raw)
            hashes[role]=hashlib.sha256(raw).hexdigest();files.append({'path':role+'.json','sha256':hashes[role]})
        manifest={'side':side,'files':files,'source_head':'a'*40,'diagnostic_id':'run','control_samples':[]}
        def artifact(name,value,directory=directory):
            raw=value if isinstance(value,bytes) else json.dumps(value).encode()
            (directory/name).write_bytes(raw);return hashlib.sha256(raw).hexdigest()
        if side=='client':
            manifest['control_samples']=[{'global_step':0,'work_elapsed_ns':21_000_001,
                'actual_sample_start_ns':10**12,'work_completed_ns':10**12+21_000_001}]
            etlhash=artifact('native-a.etl',b'mock A')
            view={'complete':False,'purpose':'control-slow-step-v1','source_head':'a'*40,
                'diagnostic_id':'run','target_pid':11,'target_tid':12,'etl_sha256':etlhash}
            stream={'complete':False,'context':records['Client']['context'],'rows':[
                [0,11 if fault=='range' else 10,8,18,10,4,18,0],[1,10,8,18,10,4,18,0]]}
            ah={'native-a.etl':etlhash,'control-native-view.json':artifact('control-native-view.json',view),
                'control-native-events.json':artifact('control-native-events.json',[]),
                'Client.stream.json':artifact('Client.stream.json',stream)}
            manifest['native_evidence']={'status':'read','files':ah}
        else:
            trace,s1=party_request_evidence();s2=copy.deepcopy(s1)
            s2.update(role='P2');s2['connection'].update(pid=3,thread_id=4,local=['10.0.0.1',101])
            extra=copy.deepcopy(trace['events'])
            for row in extra:
                if row['values'].get('ProcessId')==1:row['values']['ProcessId']=3
                if 'Tcb' in row['values']:row['values']['Tcb']=10
                if row.get('id')==1017:row['values']['LocalAddress']=addr('10.0.0.1',101)
                if 'event_index' in row:row['event_index']+=100
            assert sum(row.get('id')==1017 and row['provider']==TCPIP for row in extra)==1
            trace['events'].extend(extra)
            events=trace.pop('events');etlhash=artifact('native-b.etl',b'mock B')
            trace.update(purpose='control-b-receive-boundary-v1',source_head='a'*40,
                diagnostic_id='run',etl_sha256=etlhash,targets=[[1,2],[3,4]])
            bh={'native-b.etl':etlhash,'request-native-events.json':artifact('request-native-events.json',events),
                'request-native-view.json':artifact('request-native-view.json',trace)}
            for role,s in [('P1',s1),('P2',s2)]:
                s.update(context=records[role]['context'],role_file_sha256=hashes[role])
                if fault=='identity' and role=='P1':s['connection']['pid']=3
                bh[role+'.receive.json']=artifact(role+'.receive.json',s)
            manifest['b_request_evidence']={'status':'read','files':bh}
            if fault=='hash':(directory/'native-b.etl').write_bytes(b'changed')
        path=directory/'manifest.json';path.write_text(json.dumps(manifest),encoding='utf8');paths.append(path)
    if fault in ('hash','identity'):
        with pytest.raises(ValueError):a.analyze_slow_control(paths)
        return
    result=a.analyze_slow_control(paths);parties=result['rows'][0]['parties']
    assert parties[0]['B_receive_analysis']['verified']==(fault is None)
    assert parties[1]['B_receive_analysis']['first_component_to_first_recv_ns']==5
    assert parties[1]['B_receive_analysis']['first_component_ns']==80  # B域，不减10**12的A域时刻。
    assert parties[1]['cross_host_difference_ns'] is None
    assert not result['diagnostic_complete']
