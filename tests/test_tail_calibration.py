"""File候选及公开校准的纯软件门禁；无socket连接、WPR或新实验。"""
import copy
import hashlib
import json
import struct
from pathlib import Path

import pytest
from test_native_tail_capture import Backend, schemas
from test_windows_tail_analysis import MockAPI

from secure_control.experiments import tail_calibration as c
from secure_control.experiments.native_tail_capture import plan_digest, prepare_native
from secure_control.experiments.windows_tail_analysis import (
    PROCESS,
    TCPIP,
    THREAD,
    _read_etl,
    read_calibration_etl,
)


def test_public_wire_oracle_and_setup_maintenance_offsets():
    expected=struct.pack('!I',58)+b'D20C'+hashlib.sha256(b'run').digest()[:16]+struct.pack('!BIB',0,0,0)+bytes(32)
    assert c._frame('run',0,0)==expected
    assert c._frame('run',1,50)[29]==2  # header4+magic4+ID16+conn1+seq4
    assert len(c._frame('run',0,1))!=len(c._frame('run',0,2))
    for args in [('bad space',0,0),('run',True,0),('run',0,False),('run',2,1),('run',0,512)]:
        with pytest.raises(ValueError):c._frame(*args)


@pytest.fixture
def authorization(tmp_path,monkeypatch):
    monkeypatch.setattr(c,'_head',lambda:'a'*40)
    monkeypatch.setattr(c,'_source_clean',lambda:True)
    profile=Path(__file__).parents[1]/'configs/control-tail-calibration.wprp'
    plan=prepare_native(profile,_schemas=schemas(),_backend=Backend(),_file_candidate=True)
    plan['source_head']='a'*40
    plan['topology_sha256']='c'*64
    approval={'schema':'native-calibration-authorization-v1','plan_sha256':plan_digest(plan),
        'source_head':'a'*40,'calibration_id':'test-public','attempts':1,'active_window_s':55,
        'client_output':str(tmp_path/'A'),'pair_output':str(tmp_path/'B'),
        'authorization_url':'https://github.com/GNYKCZ/secure_pid_hvac/issues/153#issuecomment-9999999999'}
    return plan,approval


@pytest.mark.parametrize('fault',[None,'old_url','old_issue','plan','head','bool','duration','output','id','dirty'])
def test_new_authorization_binds_sha_plan_output_and_single_attempt(authorization,fault,monkeypatch):
    plan,approval=authorization
    if fault=='old_url':approval['authorization_url']='https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6471238272'
    if fault=='old_issue':approval['authorization_url']='https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-9999999999'
    if fault=='plan':plan['active_window_s']=56
    if fault=='head':approval['source_head']='b'*40
    if fault=='bool':approval['attempts']=True
    if fault=='duration':approval['active_window_s']=55.0
    if fault=='output':approval['client_output']+='-other'
    if fault=='id':approval['calibration_id']='../other'
    if fault=='dirty':monkeypatch.setattr(c,'_source_clean',lambda:False)
    output=Path(approval['pair_output']).with_name('A')
    if fault:
        with pytest.raises(PermissionError):c.authorize(approval,plan,side='client',output=output,expected_head='a'*40)
    else:assert c.authorize(approval,plan,side='client',output=output,expected_head='a'*40)=='test-public'


def test_missing_approval_refuses_before_directory_network_or_native(tmp_path,monkeypatch):
    monkeypatch.setattr(c,'_config_addresses',lambda *a:pytest.fail('must reject before config/network'))
    with pytest.raises(PermissionError):
        c.run_calibration('client',tmp_path/'never',plan={},approval={},config_paths=[],expected_head='a'*40)
    assert not (tmp_path/'never').exists()


def test_actual_enable_failure_consumes_attempt_and_never_spawns_public_client(authorization,monkeypatch):
    from types import SimpleNamespace
    plan,approval=authorization;calls=[]
    monkeypatch.setattr(c,'_config_addresses',lambda *a:([('10.0.0.2',200),('10.0.0.2',201)],'c'*64))
    class FailedNative:
        def __init__(self,*a,**kw):self.report={'status':'not_started'}
        def begin(self):calls.append('enable');raise ValueError('missing actual enable')
        def finish(self):calls.append('finish');return {'status':'cancelled'}
    monkeypatch.setattr(c,'NativeCapture',FailedNative)
    def context():
        return SimpleNamespace(Queue=lambda:SimpleNamespace(close=lambda:None,join_thread=lambda:None),
            Event=lambda:SimpleNamespace(set=lambda:None),
            Process=lambda **kw:pytest.fail('must not start traffic without actual enable'))
    monkeypatch.setattr(c.mp,'get_context',lambda *a:context())
    result=c.run_calibration('client',approval['client_output'],plan=plan,approval=approval,
                            config_paths=['unused'],expected_head='a'*40)
    assert result['calibration_complete'] is False and calls==['enable','finish']
    assert (Path(approval['client_output'])/'ledger.json').exists()
    with pytest.raises(FileExistsError):
        c.run_calibration('client',approval['client_output'],plan=plan,approval=approval,
                          config_paths=['unused'],expected_head='a'*40)


@pytest.mark.parametrize('unkillable',[False,True])
def test_returned_frame_prefix_survives_late_child_exit_and_unknown_exit_is_explicit(authorization,monkeypatch,unkillable):
    from types import SimpleNamespace
    plan,approval=authorization;prefix=[[0,0,62,0,0,1,2,3,4]]
    monkeypatch.setattr(c,'_config_addresses',lambda *a:([('10.0.0.2',200),('10.0.0.2',201)],'c'*64))
    class Native:
        def __init__(self,*a,**kw):self.report={'status':'recording'}
        def begin(self):self.capture_deadline=c.time.perf_counter()+55
        def finish(self):return {'status':'saved'}
    monkeypatch.setattr(c,'NativeCapture',Native)
    class Child:
        pid=1234
        def __init__(self,**kw):self.alive=True
        def start(self):pass
        def join(self,timeout):pass
        def is_alive(self):return self.alive
        def terminate(self):self.alive=unkillable
        @property
        def exitcode(self):return None if self.alive else -15
    q=SimpleNamespace(get=lambda **kw:{'status':'closed','frames':prefix},close=lambda:None,join_thread=lambda:None)
    ctx=SimpleNamespace(Queue=lambda:q,Event=lambda:SimpleNamespace(set=lambda:None),Process=Child)
    monkeypatch.setattr(c.mp,'get_context',lambda *a:ctx)
    result=c.run_calibration('client',approval['client_output'],plan=plan,approval=approval,
                            config_paths=['unused'],expected_head='a'*40)
    assert result['calibration_complete'] is False
    report=json.loads((Path(approval['client_output'])/'client.json').read_text(encoding='utf8'))
    assert report['frames']==prefix and report['child_pid']==1234 and report['child_exited']==(not unkillable)
    assert report['status']==('child_alive_manual_attention' if unkillable else 'failed')


@pytest.mark.parametrize('tcp_usable,peak',[(True,1000000),(False,1000000),(True,600*1024*1024)])
def test_client_summary_projects_calibrated_tcp_and_memory_but_waits_for_peer(authorization,monkeypatch,tcp_usable,peak):
    from types import SimpleNamespace
    plan,approval=authorization
    monkeypatch.setattr(c,'_config_addresses',lambda *a:([('10.0.0.2',200),('10.0.0.2',201)],'c'*64))
    class Native:
        def __init__(self,plan,path,**kw):self.path=path;self.report={'status':'recording'}
        def begin(self):self.path.write_bytes(b'mock');self.capture_deadline=c.time.perf_counter()+55
        def finish(self):return {'status':'saved'}
    monkeypatch.setattr(c,'NativeCapture',Native)
    report={'status':'closed','pid':1234,'tid':9,'frames':[],
            'window_start_ns':1,'window_end_ns':41_000_000_001}
    q=SimpleNamespace(get=lambda **kw:report,close=lambda:None,join_thread=lambda:None)
    child=SimpleNamespace(pid=1234,exitcode=0,start=lambda:None,join=lambda t:None,is_alive=lambda:False)
    ctx=SimpleNamespace(Queue=lambda:q,Event=lambda:SimpleNamespace(set=lambda:None),Process=lambda **kw:child)
    monkeypatch.setattr(c.mp,'get_context',lambda *a:ctx)
    monkeypatch.setattr(c,'read_calibration_etl',lambda *a,**kw:{'events':[],'schedule_window_complete':True,
                                                            'tcp_usable':False,'complete':True})
    monkeypatch.setattr(c,'calibration_tcp',lambda *a:{'usable':tcp_usable})
    monkeypatch.setattr(c,'_peak_memory',lambda:peak)
    result=c.run_calibration('client',approval['client_output'],plan=plan,approval=approval,
                            config_paths=['unused'],expected_head='a'*40)
    assert result['tcp_usable']==tcp_usable
    assert result['local_checks_complete']==(tcp_usable and peak<=512*1024*1024)
    assert not result['calibration_complete'] and 'NOT RUN' in result['peer_verification']


class CalibrationAPI(MockAPI):
    """手写生命周期/切换序列，期望由显式状态不变量确定。"""
    def __init__(self,rows):
        super().__init__(None);self.rows=rows
    def process(self,handle):
        for row in self.rows:self.callback(row)
    def descriptor(self,row):return row['provider'],row['id'],row['version'],row['opcode']
    def event(self,row):return copy.deepcopy(row)
    def header(self):
        return {**super().header(),'frequency':1_000_000_000}


def row(provider,opcode,stamp,**values):
    return {'provider':provider,'id':0,'version':5 if opcode==36 else 3,'opcode':opcode,
            'ticks':stamp,'cpu':0,'values':values}


def timeline():
    return [row(PROCESS,1,10,ProcessId=1,UniqueProcessKey=55),
        row(THREAD,1,20,ProcessId=1,TThreadId=2),
        row(THREAD,36,25,NewThreadId=2,OldThreadId=0,OldThreadState=1),
        row(THREAD,36,35,NewThreadId=0,OldThreadId=2,OldThreadState=5),
        row(THREAD,50,45,TThreadId=2),
        row(THREAD,36,50,NewThreadId=2,OldThreadId=0,OldThreadState=1),
        row(THREAD,36,65,NewThreadId=0,OldThreadId=2,OldThreadState=5),
        row(THREAD,2,70,ProcessId=1,TThreadId=2),row(PROCESS,2,80,ProcessId=1)]


@pytest.mark.parametrize('fault',[None,'start','middle','end','reuse','cpu','unsupported','budget'])
def test_target_window_needs_lifetime_internal_switches_and_untruncated_read(tmp_path,fault):
    rows=timeline();path=tmp_path/'metadata.etl';path.write_bytes(b'mock')
    if fault=='start':rows.pop(1)
    if fault=='middle':rows.pop(3)
    if fault=='end':rows.pop(-2)
    if fault=='reuse':rows.insert(7,row(THREAD,1,69,ProcessId=1,TThreadId=2))
    if fault=='cpu':rows[5]['values']['OldThreadId']=99
    if fault=='unsupported':
        class Broken(CalibrationAPI):
            def event(self,row):
                return {'unsupported':(THREAD,0,6,36)} if row['opcode']==36 else super().event(row)
        api=Broken(rows)
    else:api=CalibrationAPI(rows)
    result=(_read_etl(path,maximum_events=5,_api=api,target=(1,2,[30,60])) if fault=='budget'
            else read_calibration_etl(path,pid=1,tid=2,window_ns=[30,60],_api=api))
    assert result['schedule_window_complete']==(fault is None)
    assert result['tcp_usable'] is False
    if fault=='budget':assert 'event budget exceeded' in result['errors']


def test_target_retention_and_filtering_are_distinct_from_total_count(tmp_path):
    path=tmp_path/'metadata.etl';path.write_bytes(b'mock')
    rows=(row(THREAD,50,i,TThreadId=99) for i in range(100001))
    result=read_calibration_etl(path,pid=1,tid=2,window_ns=[1,2],_api=CalibrationAPI(rows))
    assert result['event_count']==100001 and result['retained_event_count']==0
    rows=(row(THREAD,50,i,TThreadId=2) for i in range(100001))
    result=read_calibration_etl(path,pid=1,tid=2,window_ns=[1,2],_api=CalibrationAPI(rows))
    assert result['retained_event_count']==100000 and 'retention budget exceeded' in result['errors']
    assert not result['complete'] and not result['schedule_window_complete']


def addr(ip,port):
    return (b'\x02\x00'+struct.pack('!H',port)+bytes(map(int,ip.split('.')))+bytes(8)).hex()


@pytest.mark.parametrize('fault',[None,'missing','direction','pid','gap','reuse','prefix','partial','end_sequence'])
def test_public_flow_connection_direction_wrap_retransmission_and_missing_evidence(fault):
    application={'pid':1,'connections':[{'local':['10.0.0.1',100+i],'remote':['10.0.0.2',200+i],
                                      'rx_bytes':110} for i in (0,1)]}
    rows=[]
    for i in (0,1):
        rows.append({'provider':TCPIP,'id':1033,'time_ns':10,'values':{'ProcessId':1,'Tcb':i,
            'LocalAddress':addr('10.0.0.1',100+i),'RemoteAddress':addr('10.0.0.2',200+i)}})
        for j,(seq,length) in enumerate(((2**32-16,50),(34,60),(2**32-16,50))):
            rows.append({'provider':TCPIP,'id':1074,'time_ns':20+j,'event_index':len(rows),
                         'values':{'Tcb':i,'SeqNo':seq,'NumBytes':length}})
    if fault=='missing':rows=[]
    if fault=='direction':application['connections'][0]['local'],application['connections'][0]['remote']=application['connections'][0]['remote'],application['connections'][0]['local']
    if fault=='pid':application['pid']=9
    if fault=='gap':rows[2]['values']['SeqNo']=40
    if fault=='reuse':
        other=copy.deepcopy(rows[0]);other['values']['Tcb']=99;rows.insert(1,other)
    if fault=='prefix':rows.pop(0)
    if fault=='end_sequence':rows[2]['values']['SeqNo']=44  # 变长帧可证伪将末序号当起点。
    trace={'events':rows,'complete':fault!='partial','schedule_window_complete':True}
    result=c.calibration_tcp(trace,application)
    assert result['usable']==(fault is None)
    assert result['socket_readable']=='unknown'


@pytest.mark.parametrize('fault',[None,'float_attempt','float_peer','bool_frame'])
def test_pair_manifest_hash_and_identity_are_required_before_two_host_pass(tmp_path,fault):
    a=tmp_path/'A';b=tmp_path/'B';a.mkdir();b.mkdir()
    common={'calibration_id':'x','source_head':'a'*40,'plan_sha256':'b'*64,
            'authorization_url':'new-approval','topology':'t','attempts':1}
    c._save(a/'ledger.json',{**common,'side':'client'})
    c._save(b/'ledger.json',{**common,'side':'pair','attempts':1.0 if fault=='float_attempt' else 1})
    frames=[]
    for i in (0,1):
        offset=0
        for seq in (0,1):
            size=len(c._frame('x',i,seq));frames.append([i,seq,size,offset,offset,1,2,3,4]);offset+=size
    if fault=='bool_frame':frames[0][0]=False
    c._save(a/'client.json',{'status':'closed','frames':frames})
    c._save(b/'pair.json',{'status':'closed','frame_counts':[2.0,2] if fault=='float_peer' else [2,2]})
    c._save(a/'native-owner.json',{'status':'saved','resource_authorization':'new-approval'})
    (a/'native-a.etl').write_bytes(b'mock')
    c._save(a/'native-view.json',{'local_checks_complete':True,'source_head':'a'*40,'plan_sha256':'b'*64,
                                'etl_sha256':hashlib.sha256(b'mock').hexdigest()})
    c._manifest(a);c._manifest(b)
    if fault:
        with pytest.raises(ValueError):c.analyze_calibration(a,b)
        return
    assert c.analyze_calibration(a,b)['calibration_complete']
    (b/'pair.json').write_text('{}')
    with pytest.raises(ValueError,match='hash'):c.analyze_calibration(a,b)


@pytest.mark.parametrize('wait_s',[0,20])
@pytest.mark.parametrize('fault',[None,'bad_content','truncated','oversized'])
def test_public_pair_codec_with_in_memory_peers_always_closes_owned_sockets(monkeypatch,fault,wait_s):
    clock=[0.]; business_started=[False]
    monkeypatch.setattr(c.time,'monotonic',lambda:clock[0])
    receive=c._receive
    monkeypatch.setattr(c,'_receive',lambda sock,deadline:receive(sock,deadline,_now=lambda:clock[0]))
    class Peer:
        def __init__(self,connection):
            self.data=bytearray(c._frame('run',connection,0)+c._frame('run',connection,1))
            self.sent=bytearray();self.closed=False
            if connection==1 and fault=='bad_content':self.data[10]^=1
            if connection==1 and fault=='truncated':self.data=self.data[:6]
            if connection==1 and fault=='oversized':self.data[:4]=struct.pack('!I',257)
        def settimeout(self,value):assert 0<value<=3
        def recv(self,n,flags=0):
            if flags:return bytes(self.data[:1])
            n=min(n,3);part=bytes(self.data[:n]);del self.data[:n];return part
        def sendall(self,data):self.sent.extend(data)
        def close(self):self.closed=True
    peers=[Peer(0),Peer(1)];listeners=[]
    class Listener:
        def __init__(self):self.index=len(listeners);listeners.append(self);self.closed=False
        def bind(self,address):assert address==('10.0.0.2',200+self.index)
        def listen(self,n):assert n==1
        def setblocking(self,value):assert value is False
        def accept(self):
            if self.index==0:clock[0]+=wait_s
            return peers[self.index],('10.0.0.1',100+self.index)
        def close(self):self.closed=True
    monkeypatch.setattr(c.socket,'socket',lambda *args:Listener())
    def ready(readers,*args):
        if readers and isinstance(readers[0],Peer) and not business_started[0]:
            clock[0]+=41;business_started[0]=True
        return list(readers),[],[]
    monkeypatch.setattr(c.select,'select',ready)
    if fault:
        with pytest.raises((ValueError,EOFError)):c._pair([('10.0.0.2',200),('10.0.0.2',201)],'run')
    else:
        assert c._pair([('10.0.0.2',200),('10.0.0.2',201)],'run')['frame_counts']==[2,2]
        assert all(bytes(p.sent)==c._frame('run',i,0)+c._frame('run',i,1) for i,p in enumerate(peers))
    assert all(p.closed for p in peers+listeners)


@pytest.mark.parametrize('fault',[None,'bad_echo','stop','send'])
def test_public_client_forty_second_window_offsets_and_first_failure_without_real_traffic(monkeypatch,fault):
    from types import SimpleNamespace
    clock=[0.];peers=[];reports=[]
    class Peer:
        def __init__(self,address):self.address=address;self.data=bytearray();self.closed=False
        def getsockname(self):return '10.0.0.1',100+len(peers)
        def getpeername(self):return self.address
        def settimeout(self,value):assert 0<value<=3
        def sendall(self,value):
            if fault=='send':raise OSError('first send failed')
            self.data.extend(value)
            if fault=='bad_echo':self.data[-1]^=1
        def recv(self,n):
            n=min(n,3);value=bytes(self.data[:n]);del self.data[:n];return value
        def close(self):self.closed=True
    def connect(address,timeout):
        assert timeout==3
        peer=Peer(address);peers.append(peer);return peer
    monkeypatch.setattr(c.socket,'create_connection',connect)
    monkeypatch.setattr(c.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(c.time,'perf_counter_ns',lambda:int(clock[0]*1e9))
    monkeypatch.setattr(c.time,'sleep',lambda _s:clock.__setitem__(0,clock[0]+20.5))
    receive=c._receive
    monkeypatch.setattr(c,'_receive',lambda sock,deadline:receive(sock,deadline,_now=lambda:clock[0]))
    c._client_worker([('10.0.0.2',200),('10.0.0.2',201)],'run',SimpleNamespace(put=reports.append),
                     SimpleNamespace(is_set=lambda:fault=='stop'))
    report=reports[0]
    assert report['status']==('closed' if fault is None else 'failed')
    assert all(p.closed for p in peers)
    if fault is None:
        assert report['window_end_ns']-report['window_start_ns']==41_000_000_000
        assert len(report['frames'])==4
        assert report['frames'][2][3:5]==[len(c._frame('run',0,0))]*2
    else:assert len(report['frames'])==0


@pytest.mark.parametrize('side', ['client', 'pair'])
def test_real_lan_config_adapts_dial_and_bind_addresses(tmp_path, side):
    """真实配置加载边界必须转成socket地址，B用bind、A用host。"""
    root = Path(__file__).parents[1] / 'configs'
    topology = tmp_path / 'topology.yaml'
    topology.write_text((root / 'lab-cart-pole-demo-deployment.example.yaml').read_text(
        encoding='utf8').replace('bind: 192.168.31.116', 'bind: 192.168.31.117'), encoding='utf8')
    roles = ('client',) if side == 'client' else ('p1', 'p2')
    paths = []
    for role in roles:
        path = tmp_path / (role + '.yaml')
        path.write_text((root / f'lab-{role}-cart-pole-demo.example.yaml').read_text(
            encoding='utf8').replace('topology: lab-cart-pole-demo-deployment.example.yaml',
                                    'topology: ' + topology.as_posix()).replace(
                'experiment: cart_pole_observer_lan.example.yaml',
                'experiment: ' + (root / 'cart_pole_observer_lan.example.yaml').as_posix()), encoding='utf8')
        paths.append(path)
    addresses, digest = c._config_addresses(paths, side)
    expected = '192.168.31.116' if side == 'client' else '192.168.31.117'
    assert addresses == ((expected, 34401), (expected, 34402))
    assert len(digest) == 64


@pytest.mark.parametrize('fault',[None,'inside','reuse','not_terminal','no_window'])
def test_post_end_terminal_switch_is_evidence_not_window_gap(fault):
    """原ETL的end后terminal out只在已证明窗口外单生命周期时不污染。"""
    from secure_control.experiments.windows_tail_analysis import normalize_schedule
    rows=timeline()
    rows.append(row(THREAD,36,85,NewThreadId=99,OldThreadId=2,OldThreadState=4))
    if fault=='not_terminal':rows[-1]['values']['OldThreadState']=5
    if fault=='reuse':rows.insert(-1,row(THREAD,1,82,ProcessId=1,TThreadId=2))
    for r in rows:r['time_ns']=r['ticks']
    trace={'events':rows,'complete':True,'target_tid':2,'target_window_ns':[30,90 if fault=='inside' else 60]}
    if fault=='no_window':trace.pop('target_window_ns')
    result=normalize_schedule(trace)
    if fault in ('inside','not_terminal','no_window'):
        assert not result['complete']
    elif fault is None:
        assert result['complete'] and len(result['terminal_boundary_events'])==1
    else:
        assert not result.get('terminal_boundary_events')


@pytest.mark.parametrize('fault',[None,'no_anchor','inside_ready','inside_unknown','double_cpu','wrong_cpu','reuse','missing_end','lost'])
def test_window_anchor_preserves_prefix_conflicts_and_rejects_internal_gaps(tmp_path,fault):
    """前缀running-ready冲突不能污染明确锚定的窗口，窗口内和驻留错误仍拒绝。"""
    rows=timeline()
    rows.insert(3,row(THREAD,50,27,TThreadId=2))  # 前缀running-ready冲突。
    if fault=='no_anchor':window=[15,60]
    else:window=[52,60]
    if fault=='inside_ready':rows.insert(7,row(THREAD,50,55,TThreadId=2))
    if fault=='inside_unknown':rows[4]['values']['OldThreadState']=3;window=[30,60]
    if fault=='double_cpu':
        extra=row(THREAD,36,53,NewThreadId=2,OldThreadId=0,OldThreadState=1);extra['cpu']=1;rows.insert(7,extra)
    if fault=='wrong_cpu':rows[4]['cpu']=1
    if fault=='reuse':rows.insert(-2,row(THREAD,1,68,ProcessId=1,TThreadId=2))
    if fault=='missing_end':rows.pop(-2)
    class API(CalibrationAPI):
        def header(self):return {**super().header(),'events_lost':int(fault=='lost')}
    path=tmp_path/'window.etl';path.write_bytes(b'mock')
    if fault=='lost':
        with pytest.raises(ValueError):read_calibration_etl(path,pid=1,tid=2,window_ns=window,_api=API(rows))
        return
    result=read_calibration_etl(path,pid=1,tid=2,window_ns=window,_api=API(rows))
    assert result['schedule_window_complete']==(fault is None)
    if fault is None:
        assert result['lifetime_replay']['state']=='unknown'
        assert result['window_replay']['anchor']['time']==50
        assert result['window_replay']['state']=='running'
        assert result['lifetime_replay']['issues']


@pytest.mark.parametrize('fault',[None,'retransmit','plus_n','minus_n','hole','future_fill','unsolicited','tie',
    'reuse','endpoint','no_birth','lost','epoch','protocol','prefix_missing','late_frame','outside_extra','end_before_checkpoint','data_after_end'])
def test_control_setup_anchor_is_independent_of_nonzero_control_offsets(fault):
    from secure_control.experiments.windows_tail_analysis import (
        control_frame_coverage,
        control_tcp_anchor,
    )
    start=2**32-4
    conn={'epoch':0,'pid':1,'registered_ns':15,'local':['10.0.0.1',100],'remote':['10.0.0.2',200],
        'setup_checkpoint':{'epoch':0,'operation':'lan_setup','sequence':2,
          'contract':'validated-setup-reply-then-offline-request-v1','received_bytes':10,'sent_bytes':12,
          'checkpoint_ns':50,'next_send_enter_ns':60}}
    sidecar={'complete':True,'connections':[conn,{**conn,'epoch':1}],
        'context':{'diagnostic_id':'run','source_head':'a'*40},'protocol':['run','session','epoch'],
        'rows':[[0,20,12,32,10,4,18,0]]}
    birth={'provider':TCPIP,'id':1033,'time_ns':10,'event_index':0,'values':{'ProcessId':1,'Tcb':9,
        'LocalAddress':addr('10.0.0.1',100),'RemoteAddress':addr('10.0.0.2',200)}}
    def packet(seq,size,t,index):return {'provider':TCPIP,'id':1074,'time_ns':t,'event_index':index,
        'values':{'Tcb':9,'SeqNo':seq%2**32,'NumBytes':size}}
    rows=[birth,packet(start,6,20,1),packet(start+6,4,26,2),packet(start+10,8,80,3)]
    if fault=='retransmit':rows.insert(3,packet(start+6,4,30,4))
    if fault=='plus_n':conn['setup_checkpoint']['received_bytes']=11
    if fault=='minus_n':conn['setup_checkpoint']['received_bytes']=9
    if fault=='hole':rows[2]['values']['SeqNo']+=1
    if fault=='future_fill':rows[2]['time_ns']=55
    if fault=='unsolicited':rows.insert(3,packet(start+10,1,55,4))
    if fault=='tie':rows[2]['time_ns']=50
    if fault=='reuse':rows.insert(1,{**birth,'event_index':5})
    if fault=='endpoint':birth['values']['LocalAddress']=addr('10.0.0.9',100)
    if fault=='no_birth':rows.pop(0)
    if fault=='epoch':conn['setup_checkpoint']['epoch']=1
    if fault=='protocol':sidecar['protocol']=None
    if fault=='prefix_missing':rows.pop(1)
    if fault=='late_frame':rows[-1]['time_ns']=91
    if fault=='outside_extra':rows.append(packet(start+18,1,110,4))
    if fault in ('end_before_checkpoint','data_after_end'):
        rows.insert(3,{**birth,'id':1043,'time_ns':40 if fault=='end_before_checkpoint' else 75,'event_index':6})
    rows.extend([{'provider':PROCESS,'opcode':1,'time_ns':5,'values':{'ProcessId':1}},
                 {'provider':PROCESS,'opcode':2,'time_ns':120,'values':{'ProcessId':1}}])
    trace={'complete':fault!='lost','target_pid':1,'target_window_ns':[70,100],'events':rows}
    anchor=control_tcp_anchor(trace,sidecar,0)
    if fault not in (None,'retransmit','late_frame','outside_extra','data_after_end'):
        assert not anchor['verified'];return
    assert anchor['verified'] and anchor['sequence_at_application_offset_zero']==start
    coverage=control_frame_coverage(trace,sidecar,0,anchor,85,90)
    assert coverage['complete_at']==(None if fault in ('late_frame','data_after_end') else 80)
    if fault=='outside_extra':assert coverage['outside_business_events_unknown']==[4]



def test_target_tcp_data_before_binding_callback_is_retained_without_renumbering(tmp_path):
    path=tmp_path/'late-binding.etl';path.write_bytes(b'mock')
    data=row(TCPIP,0,26,Tcb=999,NumBytes=10,SeqNo=100);data['id']=1074
    birth=row(TCPIP,0,24,Tcb=999,ProcessId=1,LocalAddress=addr('10.0.0.1',100),RemoteAddress=addr('10.0.0.2',200));birth['id']=1033
    rows=timeline();rows[3:3]=[data,birth]  # 回调顺序不能充当关联证据。
    result=read_calibration_etl(path,pid=1,tid=2,window_ns=[30,60],_api=CalibrationAPI(rows))
    tcp=[r for r in result['events'] if r['provider']==TCPIP]
    assert [r['id'] for r in tcp]==[1074,1033]
    assert tcp[0]['values']['Tcb']==tcp[1]['values']['Tcb']
    assert [r['event_index'] for r in tcp]==[4,5]
