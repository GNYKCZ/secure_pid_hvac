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
