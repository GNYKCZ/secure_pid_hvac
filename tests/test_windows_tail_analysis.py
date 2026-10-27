"""合成原始事件/时钟和mock离线API；不采集ETW或运行控制。"""
import ctypes
import os
import struct
import uuid

import pytest

from secure_control.experiments.windows_tail_analysis import (
    PROCESS,
    TCPIP,
    THREAD,
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
    assert scheduling(events,1,2,'born-1')=={'state':'waiting','ready_waits':[34]}


def test_thread_already_running_does_not_invent_ready_delay():
    assert scheduling([e('start',0),e('in',5)],1,2,'born-1')=={'state':'running','ready_waits':[]}


@pytest.mark.parametrize('fault',['missing_start','reuse','lost','backward','ready_while_running'])
def test_scheduler_unknown_when_lifecycle_or_events_missing(fault):
    events=[e('start',0),e('ready',10),e('in',44)]
    lost=0
    if fault=='missing_start': events.pop(0)
    if fault=='reuse': events.extend([e('end',45),{**e('start',46),'life':'born-2'}])
    if fault=='lost': lost=1
    if fault=='backward': events[-1]['time']=9
    if fault=='ready_while_running': events.append(e('ready',45))
    assert scheduling(events,1,2,'born-1',lost=lost)=={'state':'unknown','ready_waits':[]}


FLOW=('epoch1','B','A',34401,12345,'receive','TCPIP1074')


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
    assert scheduling(normalized['events'],1,2,life)['ready_waits']==[34]
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
