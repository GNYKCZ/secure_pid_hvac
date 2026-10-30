"""合成原始事件/时钟和mock离线API；不采集ETW或运行控制。"""
import ctypes
import os
import struct
import uuid
from types import SimpleNamespace

import pytest

from secure_control.experiments.windows_tail_analysis import (
    PROCESS,
    TCPIP,
    THREAD,
    _cswitch_v5,
    _fields,
    _native,
    byte_coverage,
    correlate_frame,
    normalize_schedule,
    qpc_ns,
    read_etl,
    scheduling,
)


@pytest.mark.skipif(os.name!='nt',reason='只读本机TDH schema，不是ETL采集')
@pytest.mark.parametrize('version',[0,1])
@pytest.mark.parametrize('width',[4,8])
def test_actual_tdh_schema_decodes_hand_encoded_event(version,width):
    api=_native()
    event=api.record_type()
    event.header.size=80
    event.header.flags=0x20 if width==4 else 0x40
    event.header.provider.data[:]=uuid.UUID(TCPIP).bytes_le
    event.header.desc.id=1074
    event.header.desc.version=version
    values=[0x1234,120,0xfffffff0]+([2] if version else [])
    raw=struct.pack('<'+('I' if width==4 else 'Q')+'II'+('I' if version else ''),*values)
    buffer=ctypes.create_string_buffer(raw)
    event.user=ctypes.cast(buffer,ctypes.c_void_p)
    event.length=len(raw)
    result=api.event(ctypes.pointer(event))
    assert result['values']==dict(zip(['Tcb','NumBytes','SeqNo']+(['NumPkt'] if version else []),values,strict=True))
    # descriptor之外的版本不套相邻schema；未触碰业务buffer内容。
    event.header.desc.version=99
    assert 'unsupported' in api.event(ctypes.pointer(event))


def e(kind,time,**kw):
    return dict(kind=kind,time=time,pid=1,tid=2,life='born-1',**kw)


def test_ready_late_running_wait_is_hand_computed():
    events=[e('start',0),e('ready',10),e('in',44),e('out',50,next='waiting')]
    assert scheduling({'events':events,'complete':True},1,2,'born-1')=={'state':'waiting','ready_waits':[34]}


def test_thread_already_running_does_not_invent_ready_delay():
    assert scheduling({'events':[e('start',0),e('in',5)],'complete':True},1,2,'born-1')=={'state':'running','ready_waits':[]}


@pytest.mark.parametrize('fault',[None,'lost','chain','gap','missing_end','reuse','cpu',
    'duplicate_in','missing_out','time','window','identity','missing_anchor','missing_right_boundary',
    'self_switch','cross_cpu_overlap','backward_migration','unknown_descriptor','event_order',
    'migration','zero_migration','self_continuous','self_wrong_cpu'])
def test_cpu_residence_uses_switch_pairs_without_inventing_ready(fault):
    """显式时间线oracle：窗口[10,50)，CPU驻留10..20和40..50共20，未驻留20。"""
    from secure_control.experiments.windows_tail_analysis import cpu_residence
    def raw(provider,opcode,time,index,**values):
        return {'provider':provider,'opcode':opcode,'time_ns':time,'event_index':index,
            'cpu':0,'values':values}
    rows=[raw(PROCESS,1,0,1,ProcessId=1,UniqueProcessKey=7),
        raw(THREAD,1,1,2,ProcessId=1,TThreadId=2),
        raw(THREAD,36,5,3,NewThreadId=2,OldThreadId=0,OldThreadState=1),
        raw(THREAD,50,19,4,TThreadId=2),  # 跨CPU Ready先于切出，不能污染CPU驻留。
        raw(THREAD,36,20,5,NewThreadId=0,OldThreadId=2,OldThreadState=3),
        raw(THREAD,36,40,6,NewThreadId=2,OldThreadId=0,OldThreadState=7),
        raw(THREAD,36,55,7,NewThreadId=0,OldThreadId=2,OldThreadState=2),
        raw(THREAD,2,60,8,TThreadId=2,ProcessId=1),raw(PROCESS,2,65,9,ProcessId=1)]
    trace={'complete':True,'header':{'events_lost':0,'buffers_lost':0},'errors':[],
        'cpu_chain_mismatches':0,'target_critical_gaps':0,'target_pid':1,'target_tid':2,
        'target_window_ns':[10,50],'events':rows}
    if fault=='lost':trace['header']['events_lost']=1
    if fault=='chain':trace['cpu_chain_mismatches']=1
    if fault=='gap':trace['target_critical_gaps']=1
    if fault=='missing_end':rows.pop(-2)
    if fault=='reuse':rows.insert(-1,raw(THREAD,1,62,10,ProcessId=1,TThreadId=2))
    if fault=='cpu':rows[4]['cpu']=1
    if fault=='duplicate_in':rows[4]['values'].update(NewThreadId=2,OldThreadId=0)
    if fault=='missing_out':rows.pop(4)
    if fault=='time':rows[4]['time_ns']=4
    if fault=='window':trace['target_window_ns']=[0,50]
    if fault=='identity':trace['target_pid']=3
    if fault=='missing_anchor':rows.pop(2)
    if fault=='missing_right_boundary':rows.pop(6)
    if fault=='self_switch':rows[4]['values']['NewThreadId']=2
    if fault=='cross_cpu_overlap':rows.insert(4,{**rows[2],'cpu':1,'time_ns':19})
    if fault=='backward_migration':rows[5]['time_ns']=20;rows[4],rows[5]=rows[5],rows[4]
    if fault=='unknown_descriptor':trace['complete']=False
    if fault=='event_order':rows[4]['event_index']=3
    if fault in ('migration','zero_migration'):
        rows[5]['cpu']=rows[6]['cpu']=1
    if fault=='zero_migration':rows[5]['time_ns']=20
    if fault in ('self_continuous','self_wrong_cpu'):
        for row in rows[3:]:row['event_index']+=1
        self_row=raw(THREAD,36,15,4,NewThreadId=2,OldThreadId=2,OldThreadState=2)
        if fault=='self_wrong_cpu':self_row['cpu']=1
        rows.insert(3,self_row)
    result=cpu_residence(trace)
    if fault not in (None,'migration','zero_migration','self_continuous'):
        assert result['verified'] is False and not result['intervals'];return
    assert result['verified'] is True
    if fault=='self_continuous':
        assert result['continuous_self_switches']==[{'event_index':4,'time_ns':15,'cpu':0}]
        assert sum(r['end_ns']-r['start_ns'] for r in result['intervals'] if r['state']=='not_running')==20
        return
    assert [(r['state'],r['start_ns'],r['end_ns']) for r in result['intervals']]==(
        [('running',10,20),('running',20,50)] if fault=='zero_migration' else
        [('running',10,20),('not_running',20,40),('running',40,50)])
    assert result['ready_state']=='unknown'
    assert normalize_schedule(trace)['complete']


@pytest.mark.parametrize('fault',['missing_start','reuse','lost','backward','ready_while_running'])
def test_scheduler_unknown_when_lifecycle_or_events_missing(fault):
    events=[e('start',0),e('ready',10),e('in',44)]
    lost=0
    if fault=='missing_start': events.pop(0)
    if fault=='reuse': events.extend([e('end',45),{**e('start',46),'life':'born-2'}])
    if fault=='lost': lost=1
    if fault=='backward': events[-1]['time']=9
    if fault=='ready_while_running': events.append(e('ready',45))
    assert scheduling({'events':events,'complete':True},1,2,'born-1',lost=lost)=={'state':'unknown','ready_waits':[]}


def test_circular_suffix_with_zero_loss_cannot_prove_schedule_or_tcp_coverage():
    """环形保留末段时lost可为零；命令保存成功并不补回首窗口或线程start。"""
    retained = {'events':[{'provider':THREAD,'opcode':50,'time_ns':30,
                           'values':{'TThreadId':2}}], 'complete':True}
    normalized = normalize_schedule(retained)
    assert not normalized['complete'] and normalized['unassociated_events']==1
    assert scheduling(normalized,1,2,'born-1',lost=0)=={'state':'unknown','ready_waits':[]}
    assert byte_coverage([],FLOW,1000,100,trusted=True,lost=0)=={
        'boundary':'unknown','complete_at':None,'socket_readable':'unknown'}


FLOW=('epoch1','B','A',34401,12345,'receive','TCPIP1074')


@pytest.mark.parametrize('version',[0,1])
@pytest.mark.skipif(os.name!='nt',reason='Windows TDH metadata only')
def test_accept_1017_uses_actual_tdh_manifest_with_constructed_payload(version):
    api=_native();event=api.record_type();event.header.size=80;event.header.flags=0x40
    event.header.provider.data[:]=uuid.UUID(TCPIP).bytes_le
    event.header.desc.id=1017;event.header.desc.version=version
    local=bytes.fromhex('02008661c0a81f740000000000000000')
    remote=bytes.fromhex('0200c778c0a81ffd0000000000000000')
    raw=struct.pack('<I16sI16sIIIQ'+('Q' if version else ''),16,local,16,remote,0,41,0,0x1234,
        *([98765] if version else []))
    buffer=ctypes.create_string_buffer(raw);event.user=ctypes.cast(buffer,ctypes.c_void_p);event.length=len(raw)
    decoded=api.event(ctypes.pointer(event))
    assert decoded['values']=={'Tcb':0x1234,'LocalAddress':local.hex(),'RemoteAddress':remote.hex(),
        'ProcessId':41,**({'ProcessStartKey':98765} if version else {})}
    assert decoded['schema_sha256']
    assert _fields((TCPIP,1017,2,0)) is None


def packet(seq,length,time,identity,flow=FLOW,**kw):
    return dict(seq=seq,length=length,time=time,packet=identity,flow=flow,**kw)


@pytest.mark.parametrize('case',['ordered','out_of_order','retransmit','appearance','coalesced','wrap','ack'])
def test_tcp_coverage_is_not_socket_readiness(case):
    events=[packet(1000,50,10,'a'),packet(1050,50,20,'b')]
    anchor,end=1000,20
    if case=='out_of_order': events=[packet(1050,50,10,'b'),packet(1000,50,20,'a')]
    if case=='retransmit': events.insert(1,packet(1000,50,15,'retry'))
    if case=='appearance': events.insert(1,packet(1000,50,15,'a'))
    if case=='coalesced': events=[packet(950,200,10,'coalesced')]; end=10
    if case=='wrap': anchor=0xfffffff0; events=[packet(anchor,16,10,'a'),packet(0,84,20,'b')]
    if case=='ack': events.insert(1,packet(1050,0,15,'ack'))
    assert byte_coverage(events,FLOW,anchor,100,trusted=True)=={
        'boundary':'selected-component byte coverage','complete_at':end,'socket_readable':'unknown'}


@pytest.mark.parametrize('fault',['missing','mixed_flow','reconnect','component','no_anchor','no_length',
                                 'not_trusted','lost','half_wrap','syn','conflicting_packet'])
def test_no_false_full_reply(fault):
    events=[packet(1000,50,10,'a'),packet(1050,50,20,'b')]
    anchor,length,trusted,lost=1000,100,True,0
    if fault=='missing': events.pop()
    if fault in ('mixed_flow','reconnect','component'):
        flow=list(FLOW); flow[{'mixed_flow':3,'reconnect':0,'component':6}[fault]]='other'
        events[-1]['flow']=tuple(flow)
    if fault=='no_anchor': anchor=None
    if fault=='no_length': length=None
    if fault=='not_trusted': trusted=False
    if fault=='lost': lost=1
    if fault=='half_wrap': events[0]['seq']=(1000+2**31)%2**32
    if fault=='syn': events[0]['syn']=True
    if fault=='conflicting_packet': events[-1]['packet']='a'
    assert byte_coverage(events,FLOW,anchor,length,trusted=trusted,lost=lost)=={
        'boundary':'unknown','complete_at':None,'socket_readable':'unknown'}


@pytest.mark.parametrize('clock',[None,2,3,'UTC','relative'])
def test_qpc_domain_not_guessed(clock):
    with pytest.raises(ValueError): qpc_ns(100,10000000,clock)


def test_qpc_integer_conversion_and_loss():
    assert qpc_ns(123456789,10000000,1)==12345678900
    assert qpc_ns(1,3000000,1)==333
    with pytest.raises(ValueError): qpc_ns(1,10000000,1,1)


def test_cswitch_v5_matches_signed_microsoft_traceevent_3_1_21_oracle():
    """原01 ETL前两条v5；expected来自独立官方DLL，不能由本解析生成。"""
    raw = bytes.fromhex('f01b0000000000000f000200000c020901000000b1db398b02000000')
    assert _cswitch_v5(raw,8)=={'NewThreadId':7152,'OldThreadId':0,'OldThreadState':2}
    raw = bytes.fromhex('00000000f01b0000000f0000066105045e0e000093b9010008000000')
    assert _cswitch_v5(raw,8)=={'NewThreadId':0,'OldThreadId':7152,'OldThreadState':5}


@pytest.mark.parametrize('length,width',[(0,8),(24,8),(27,8),(29,8),(28,4),(28,True)])
def test_cswitch_v5_refuses_unverified_shape_or_architecture(length,width):
    with pytest.raises(ValueError): _cswitch_v5(bytes(length),width)


@pytest.mark.skipif(os.name!='nt',reason='本机离线ABI；不创建会话')
def test_native_cswitch_v5_descriptor_cpu_and_unknown_version_do_not_use_header_tid():
    api=_native();event=api.record_type()
    event.header.size=80;event.header.flags=0x350;event.buffer=9
    event.header.tid=0xffffffff
    event.header.provider.data[:]=uuid.UUID(THREAD).bytes_le
    event.header.desc.id=0;event.header.desc.version=5;event.header.desc.opcode=36
    raw=ctypes.create_string_buffer(bytes.fromhex('f01b0000000000000f000200000c020901000000b1db398b02000000'))
    event.user=ctypes.cast(raw,ctypes.c_void_p);event.length=28
    decoded=api.event(ctypes.pointer(event))
    assert decoded['values']=={'NewThreadId':7152,'OldThreadId':0,'OldThreadState':2}
    assert decoded['cpu']==9 and decoded['tid']==0xffffffff
    event.header.desc.version=6;event.user=None
    assert api.event(ctypes.pointer(event))=={'unsupported':(THREAD,0,6,36)}
    event.header.desc.version=5
    with pytest.raises(ValueError):api.event(ctypes.pointer(event))


class MockAPI:
    """只在内存调用callback，绝无OpenTrace真实会话。"""

    def __init__(self,fault):
        self.fault=fault
        self.closed=[]

    def open(self,path,callback):
        self.callback=callback
        assert path.suffix=='.etl'
        return 123

    def header(self):
        return {'clock':2 if self.fault=='clock' else 1,'frequency':10000000,
            'pointer_size':16 if self.fault=='width' else 8,'end':0 if self.fault=='partial' else 1,
            'mode':0x100 if self.fault=='realtime' else 0,
            'events_lost':1 if self.fault=='loss' else 0,'buffers_lost':0}

    def process(self,handle):
        if self.fault=='process': raise OSError('test')
        for _ in range(3): self.callback(None)

    def event(self,pointer):
        if self.fault=='callback': raise ValueError('test')
        if self.fault=='unsupported': return {'unsupported':('unknown',1,0,0)}
        return {'provider':TCPIP,'id':1074,'version':0,'opcode':0,'pid':1,'tid':2,
                'ticks':100,'pointer_size':8,'values':{'Tcb':0xdeadbeef,'NumBytes':10,'SeqNo':1000}}

    def close(self,handle): self.closed.append(handle)


@pytest.mark.skipif(os.name!='nt',reason='Windows x64 ctypes ABI oracle')
def test_native_offline_unicode_path_abi_mode_and_handle_lifetime(tmp_path,monkeypatch):
    # 官方evntcons.h：REAL_TIME=0x100、RAW_TIMESTAMP=0x1000、EVENT_RECORD=0x10000000。
    # 官方x64布局的偏移为独立oracle，不从被测结构生成expected。
    original=ctypes.WinDLL
    seen={}
    class Function:
        def __init__(self,call): self.call=call
        def __call__(self,*args): return self.call(*args)
    def open_trace(pointer):
        log=pointer._obj
        typ=type(log)
        assert ctypes.sizeof(log)==448
        assert {k:getattr(typ,k).offset for k in ('filename','logger','process_mode','header','callback','context')}=={
            'filename':0,'logger':8,'process_mode':28,'header':120,'callback':424,'context':440}
        assert ctypes.sizeof(log.header)==280
        assert type(log.header).frequency.offset==256 and type(log.header).clock.offset==272
        seen.update(path=log.filename,log=log)
        if log.process_mode!=0x10001000 or log.logger is not None:
            ctypes.set_last_error(123)
            return 2**64-1
        log.header.clock=1;log.header.frequency=10000000;log.header.pointer_size=8;log.header.end=1
        return 2**40+123
    def process(handle,count,*args):
        assert handle._obj.value==2**40+123 and count==1
        assert seen['log'].filename==str(path.resolve())
        return 0
    closed=[]
    fake=SimpleNamespace(OpenTraceW=Function(open_trace),ProcessTrace=Function(process),
        CloseTrace=Function(lambda handle:closed.append(handle) or 0))
    monkeypatch.setattr(ctypes,'WinDLL',lambda name,**kw:fake if name=='advapi32' else original(name,**kw))
    path=tmp_path/'\u6d4b\u8bd5 space.etl'
    path.write_bytes(b'mock only, not a real ETL')
    api=_native()
    assert ctypes.sizeof(api.record_type)==112 and api.record_type.user.offset==96
    result=read_etl(path,_api=api)
    assert result['event_count']==0 and closed==[2**40+123]
    assert seen['path']==str(path.resolve())


@pytest.mark.parametrize('total,limit,exceeded',[
    (100001,100000,True),(100001,300000,False),(300000,300000,False),(300001,300000,True),
])
def test_explicit_300k_cap_counts_all_events_including_unsupported(tmp_path,total,limit,exceeded):
    class API(MockAPI):
        def process(self,handle):
            for i in range(total): self.callback(i)
        def event(self,index):
            return {'unsupported':('other metadata',1,0,0)} if index else super().event(index)
    api=API(None)
    path=tmp_path/'counted.etl';path.write_bytes(b'mock')
    trace=read_etl(path,maximum_events=limit,_api=api)
    assert trace['event_count']==total and len(trace['events'])==1
    assert trace['unsupported_counts'][0]['count']==min(total,limit)-1
    assert ('event budget exceeded' in trace['errors']) is exceeded
    assert trace['other_unsupported_count']==min(total,limit)-1
    assert not trace['complete'] and api.closed==[123]


@pytest.mark.parametrize('limit',[True,0,300001])
def test_cap_refuses_unbounded_calls_before_open(tmp_path,limit):
    path=tmp_path/'mock.etl';path.write_bytes(b'mock')
    class API:
        def open(self,*args): pytest.fail('must reject before native open')
    with pytest.raises(ValueError,match='budget'): read_etl(path,maximum_events=limit,_api=API())


@pytest.mark.skipif(os.name!='nt',reason='实际本机TDH仅用于合成线程v3事件')
@pytest.mark.parametrize('opcode',[1,2])
def test_thread_v3_required_lifetime_fields_are_tdh_checked(opcode):
    api=_native();event=api.record_type()
    event.header.size=80;event.header.flags=0x140
    event.header.provider.data[:]=uuid.UUID(THREAD).bytes_le
    event.header.desc.version=3;event.header.desc.opcode=opcode
    data=ctypes.create_string_buffer(struct.pack('<II7QI4B',11,22,*([0]*12)))
    event.user=ctypes.cast(data,ctypes.c_void_p);event.length=len(data)-1
    result=api.event(ctypes.pointer(event))
    assert result['values']=={'ProcessId':11,'TThreadId':22}
    # 实际CSwitch v5本机TDH无schema，不能从v2/v3套布局猜测。
    assert _fields((THREAD,0,5,36)) is None


def test_default_budget_stays_100k_and_descriptor_counts_mark_critical_gaps(tmp_path):
    class API(MockAPI):
        def event(self,index): return {'unsupported':(THREAD,0,5,36)}
    path=tmp_path/'mock.etl';path.write_bytes(b'mock')
    trace=read_etl(path,_api=API(None))
    assert trace['maximum_events']==100000 and trace['event_count']==3
    assert trace['critical_unsupported_count']==3 and trace['other_unsupported_count']==0
    assert trace['descriptor_counts']==trace['unsupported_counts']


def test_descriptor_count_after_budget_and_empty_input_do_not_claim_complete(tmp_path):
    class API(MockAPI):
        def descriptor(self,pointer): return (TCPIP,1074,0,0)
    path=tmp_path/'empty.etl';path.touch()
    api=API(None)
    with pytest.raises(ValueError,match='boundary'): read_etl(path,_api=api)
    assert not api.closed
    path.write_bytes(b'mock')
    trace=read_etl(path,_api=api,maximum_events=1)
    assert trace['event_count']==trace['descriptor_counts'][0]['count']==3
    assert len(trace['events'])==1 and trace['events'][0]['event_index']==1 and not trace['complete']


def test_open_failure_never_closes_unallocated_handle_and_truncated_decode_stays_partial(tmp_path):
    path=tmp_path/'truncated.etl';path.write_bytes(b'\x00')
    class API(MockAPI):
        def open(self,path,callback): raise OSError(13,'mock truncated input')
    api=API(None)
    with pytest.raises(OSError): read_etl(path,_api=api)
    assert not api.closed
    broken=MockAPI('callback')
    trace=read_etl(path,_api=broken)
    assert trace['decode_errors']=={'ValueError':3} and not trace['complete']
    assert broken.closed==[123]


@pytest.mark.parametrize('fault',[None,'clock','width','loss','partial','realtime','process','callback','unsupported','budget'])
def test_offline_lifecycle_bounded_errors_and_close(tmp_path,fault):
    path=tmp_path/'synthetic.etl'
    path.write_bytes(b'synthetic placeholder; mock API only')
    api=MockAPI(fault)
    if fault in ('clock','width','loss','partial','realtime','process'):
        with pytest.raises((ValueError,OSError)): read_etl(path,_api=api)
    else:
        result=read_etl(path,_api=api,maximum_events=1 if fault=='budget' else 100)
        assert result['complete'] is (fault is None)
        assert len(result['events'])<=1 if fault=='budget' else len(result['events'])<=3
        if fault is None:
            assert result['events'][0]['values']['Tcb']==0
            assert result['events'][0]['time_ns']==10000
            assert 'deadbeef' not in str(result)
    assert api.closed==[123]


def test_raw_schedule_normalization_requires_process_and_thread_start():
    def raw(provider,opcode,time,values):
        return {'provider':provider,'opcode':opcode,'time_ns':time,'values':values}
    trace={'complete':True,'events':[
        raw(PROCESS,1,0,{'ProcessId':1,'UniqueProcessKey':7}),
        raw(THREAD,1,1,{'ProcessId':1,'TThreadId':2}),
        raw(THREAD,50,10,{'TThreadId':2}),
        raw(THREAD,36,44,{'NewThreadId':2,'OldThreadId':0,'OldThreadState':5}),
    ]}
    normalized=normalize_schedule(trace)
    life=normalized['events'][0]['life']
    assert scheduling(normalized,1,2,life)['ready_waits']==[34]
    trace['events'].pop(0)
    missing=normalize_schedule(trace)
    assert missing['events']==[] and not missing['complete'] and missing['unassociated_events']>0
    assert _fields((THREAD,0,3,50)) is None


def test_frame_offset_anchor_and_unknown_boundary():
    connection={'epoch':0,'local':['A',123],'remote':['B',34401]}
    sidecar={'complete':True,'context':{'diagnostic_id':'run','source_head':'a'*40},
        'protocol':['protocol','session','epoch'],'connections':[connection],
        'rows':[[0,7,5,12,6,4,14,0]]}
    assert correlate_frame(sidecar,0,[])['boundary']=='unknown'
    anchor={'verified':True,'diagnostic_id':'run','source_head':'a'*40,'protocol':sidecar['protocol'],
        'connection':connection,'semantic_boundary':'TCPIP1074 verified data sequence',
        'evidence':'synthetic hand oracle only','sequence_at_application_offset_zero':1000,'flow':FLOW}
    result=correlate_frame(sidecar,0,[packet(1006,8,20,'frame')],anchor)
    assert result['complete_at']==20 and result['socket_readable']=='unknown'
    anchor['diagnostic_id']='old-run'
    assert correlate_frame(sidecar,0,[],anchor)['boundary']=='unknown'


@pytest.mark.parametrize('complete',[True,False])
def test_rv004_normalized_completeness_reaches_scheduling(complete):
    def raw(provider,opcode,time,values):
        return {'provider':provider,'opcode':opcode,'time_ns':time,'values':values}
    trace={'complete':complete,'events':[
        raw(PROCESS,1,0,{'ProcessId':1,'UniqueProcessKey':7}),
        raw(THREAD,1,1,{'ProcessId':1,'TThreadId':2}),
        raw(THREAD,50,10,{'TThreadId':2}),
        raw(THREAD,36,44,{'NewThreadId':2,'OldThreadId':0,'OldThreadState':5})]}
    evidence=normalize_schedule(trace)
    life=evidence['events'][0]['life']
    assert len(evidence['events'])==3  # 不完整原始证据仍保留供审计。
    result=scheduling(evidence,1,2,life)
    assert result==({'state':'running','ready_waits':[34]} if complete else
                    {'state':'unknown','ready_waits':[]})
    assert scheduling(evidence['events'],1,2,life)=={'state':'unknown','ready_waits':[]}


@pytest.mark.parametrize('after',[False,True])
@pytest.mark.parametrize('fault',['identity','time','unrelated','legal_duplicate','retransmit'])
def test_rv005_formal_frame_consumer_validates_after_first_coverage(after,fault):
    connection={'epoch':0,'local':['A',123],'remote':['B',34401]}
    sidecar={'complete':True,'context':{'diagnostic_id':'run','source_head':'a'*40},
        'protocol':['protocol','session','epoch'],'connections':[connection],
        'rows':[[0,7,5,12,6,4,14,0]]}
    anchor={'verified':True,'diagnostic_id':'run','source_head':'a'*40,'protocol':sidecar['protocol'],
        'connection':connection,'semantic_boundary':'TCPIP1074 verified data sequence',
        'evidence':'synthetic oracle','sequence_at_application_offset_zero':1000,'flow':FLOW}
    events=[packet(1006,8 if after else 4,20,'same')]
    if fault=='identity': events.append(packet(1010,4,21,'same'))
    if fault=='time': events.append(packet(1010,4,19,'other'))
    if fault=='unrelated':
        events.append(packet(9999,1,19,'same',flow=('other',*FLOW[1:])))
        if not after: events.append(packet(1010,4,22,'remaining'))
    if fault=='legal_duplicate':
        events.append(packet(1006,8 if after else 4,21,'same'))
        if not after: events.append(packet(1010,4,22,'remaining'))
    if fault=='retransmit': events.append(packet(1006,8,22,'retry'))
    result=correlate_frame(sidecar,0,events,anchor)
    if fault in ('identity','time'):
        assert result['complete_at'] is None and result['boundary']=='unknown'
    else:
        assert result['complete_at']==(20 if after else 22)
    assert result['socket_readable']=='unknown'


@pytest.mark.parametrize('fault',[None,'unsupported','callback'])
def test_rv004_mock_reader_through_normalizer_and_scheduling(tmp_path,fault):
    """使用真实reader返回对象贯穿消费者，缺标记不能由调用方手动补lost修饰。"""
    def raw(provider,opcode,time,values):
        return {'provider':provider,'id':0,'version':2,'opcode':opcode,'ticks':time,
                'pointer_size':8,'pid':1,'tid':2,'values':values}
    class API(MockAPI):
        def __init__(self):
            super().__init__(fault)
            self.rows=[raw(PROCESS,1,0,{'ProcessId':1,'UniqueProcessKey':7}),
                raw(THREAD,1,1,{'ProcessId':1,'TThreadId':2}),
                raw(THREAD,50,10,{'TThreadId':2}),
                raw(THREAD,36,44,{'NewThreadId':2,'OldThreadId':0,'OldThreadState':5})]
        def header(self):
            return {**super().header(),'frequency':1000000000}
        def process(self,handle):
            for index in range(4+(fault is not None)):
                self.callback(index)
        def event(self,index):
            if index<4:
                return self.rows[index]
            if fault=='callback':
                raise ValueError('synthetic decode error')
            return {'unsupported':('unknown',1,0,0)}
    path=tmp_path/'mock-only.etl'
    path.write_bytes(b'not an actual ETL; mock API fixture')
    api=API()
    trace=read_etl(path,_api=api)
    assert trace['complete'] is (fault is None) and api.closed==[123]
    evidence=normalize_schedule(trace)
    life=evidence['events'][0]['life']
    assert scheduling(evidence,1,2,life)==({'state':'running','ready_waits':[34]} if fault is None
                                          else {'state':'unknown','ready_waits':[]})
