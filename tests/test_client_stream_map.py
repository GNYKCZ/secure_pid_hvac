"""默认关闭与公开流偏移的手算oracle；不启动任何新控制/采集会话。"""
import hashlib
import json
import struct
from pathlib import Path

import pytest

from secure_control.execution.client_stream_map import ClientStreamMap
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.tail_diagnostics import DiagnosticContext, TailRecorder
from secure_control.experiments.windows_tail_analysis import read_stream_link


class Socket:
    """有限手写IO序列；地址查询次数独立计数。"""

    def __init__(self):
        self.address_queries = 0
        self.sizes = []
        self.input = []

    def getsockname(self):
        self.address_queries += 1
        return ('192.0.2.1',12345)

    def getpeername(self):
        self.address_queries += 1
        return ('192.0.2.2',34401)

    def send(self,data):
        size = self.sizes.pop(0) if self.sizes else len(data)
        if isinstance(size,Exception):
            raise size
        return size

    def recv(self,*args):
        value = self.input.pop(0)
        if isinstance(value,Exception):
            raise value
        if args and len(value)>args[0]:
            self.input.insert(0,value[args[0]:])
            value=value[:args[0]]
        return value

    def gettimeout(self):
        return 5.

    def settimeout(self,value):
        self.timeout=value


def test_party_receive_counts_all_frames_and_only_validates_explicit_identity(monkeypatch):
    from secure_control.execution import client_stream_map as m
    ticks=iter(range(100,10000,10));monkeypatch.setattr(m.time,'perf_counter_ns',lambda:next(ticks))
    owner=m.PartyReceiveMap();raw=Socket();sock=owner.register(raw)
    raw.input=[b'\0\0\0\1h',b'\0\0',b'\0\3abc']
    sock.recv(100)  # hello，未绑定
    sock.recv(100);sock.recv(100)  # setup长度头分片，5+7字节累计
    owner.validate(sock,2,'lan_setup');sock.send(b'reply')
    raw.input=[TimeoutError(),b'\0',b'\0\0\2xy']
    with pytest.raises(TimeoutError):sock.recv(100)
    sock.recv(100);sock.recv(100)
    assert owner.report()['rows'][-1][7:]==[-1,-1,0]
    owner.validate(sock,4,'online_permit',0)
    report=owner.report();assert report['complete'] and report['buffer_bytes']<=1024*1024
    assert [r[1:4] for r in report['rows']]==[[0,1,5],[5,3,12],[12,2,18]]
    assert report['rows'][0][9]==0 and report['rows'][2][7:]==[0,4,2]
    assert report['rows'][2][4:7]==[200,210,230]
    assert report['connection']['setup_checkpoint']['received_bytes']==12
    assert 'abc' not in json.dumps(report) and 'xy' not in json.dumps(report)


@pytest.mark.parametrize('fault',['peek','thread','bypass','capacity','partial_eof','duplicate','setup_pipeline'])
def test_party_receive_observation_failures_preserve_business_bytes(monkeypatch,fault):
    from secure_control.execution import client_stream_map as m
    owner=m.PartyReceiveMap();raw=Socket();sock=owner.register(raw)
    frame=b'\0\0\0\1x';raw.input=[frame]
    if fault=='thread':monkeypatch.setattr(m.threading,'get_native_id',lambda:-1)
    if fault=='capacity':owner.capacity=0
    if fault=='bypass':getattr(sock,'recv_into',None)
    if fault=='partial_eof':raw.input=[b'\0',b''];sock.recv(10)
    data=sock.recv(100,1) if fault=='peek' else sock.recv(100)
    if fault not in ('partial_eof',):assert data==frame
    if fault=='duplicate':owner.validate(sock,2,'lan_setup');owner.validate(sock,2,'lan_setup')
    if fault=='setup_pipeline':
        raw.input=[frame+b'\0'];sock.recv(100);owner.validate(sock,2,'lan_setup')
    assert not owner.report()['complete'] and owner.error is not None


def test_party_receive_coalesced_frames_share_call_times_without_byte_arrival_guess(monkeypatch):
    from secure_control.execution import client_stream_map as m
    ticks=iter([1,10,20]);monkeypatch.setattr(m.time,'perf_counter_ns',lambda:next(ticks))
    owner=m.PartyReceiveMap();raw=Socket();sock=owner.register(raw)
    raw.input=[b'\0\0\0\1a\0\0\0\2bc'];sock.recv(100)
    rows=owner.report()['rows']
    assert [r[1:4] for r in rows]==[[0,1,5],[5,2,11]]
    assert [r[4:7] for r in rows]==[[10,20,20],[10,20,20]]


@pytest.mark.parametrize('valid',[False,True])
def test_party_setup_checkpoint_is_only_called_after_request_identity_checks(monkeypatch,valid):
    from types import SimpleNamespace

    from secure_control.execution import client_stream_map as m
    from secure_control.execution import lan_runtime as runtime
    owner=m.PartyReceiveMap();raw=Socket();sock=owner.register(raw)
    raw.input=[b'\0\0\0\1s'];sock.recv(100)
    request=SimpleNamespace(kind='request',sender='Client',recipient='P1',sequence=2 if valid else 3,
        operation='lan_setup',session_id='session',round_id=None,step=None,resource_id=None)
    monkeypatch.setattr(runtime,'receive_envelope',lambda *args,**kwargs:request)
    monkeypatch.setattr(runtime.tail_diagnostics,'current',lambda:SimpleNamespace(party_receives=owner))
    if not valid:
        with pytest.raises(ValueError):runtime._party_receive(sock,'P1',2,'lan_setup','session',5)
        assert owner.checkpoint is None and owner.report()['rows'][0][9]==0
    else:
        assert runtime._party_receive(sock,'P1',2,'lan_setup','session',5) is request
        assert owner.checkpoint['received_bytes']==5


def test_default_off_no_new_buffer_or_address_query(monkeypatch,tmp_path):
    from secure_control.execution import lan_transport
    ctx = DiagnosticContext('off','domain',str(tmp_path),'a'*40,1)
    recorder = TailRecorder(ctx,'Client').start()
    try:
        assert recorder.streams is None and recorder.buffer_bytes==983040
        config = load_lan_config(Path(__file__).parents[1]/'configs/lab-client-cart-pole-demo.example.yaml','Client')
        raw = Socket()
        monkeypatch.setattr(lan_transport,'_resolve',lambda *a:[])
        monkeypatch.setattr(lan_transport,'_dial',lambda *a:raw)
        assert lan_transport.connect_role(config.topology.p1_client,config,'P1',10) is raw
        assert raw.address_queries==0
    finally:
        recorder.finish('stopped')


def sockets():
    owner = ClientStreamMap()
    raw = [Socket(),Socket()]
    wrapped = [owner.register(s) for s in raw]
    return owner,raw,wrapped


def test_setup_then_split_control_and_stop_exact_offsets_no_body():
    owner,raw,wrapped = sockets()
    for sock,source in zip(wrapped,raw,strict=True):
        sock.send(b'\0\0\0\3abc')  # setup7字节
        source.input = [b'\0\0',b'\0\2',b'xy']  # setup6字节，长度头分片
        for _ in range(3):
            sock.recv(10)
    owner.begin(wrapped,[3,3],0)
    for sock,source in zip(wrapped,raw,strict=True):
        source.sizes=[2,BlockingIOError(),5]
        assert sock.send(b'\0\0\0\3abc')==2
        with pytest.raises(BlockingIOError):
            sock.send(b'\0\3abc')
        sock.send(b'\0\3abc')
        source.input=[b'\0',b'\0\0',b'\4',b'no',b'pe']
        for _ in range(5):
            sock.recv(10)
        sock.send(b'\0\0\0\1!')  # stop5字节，不改变已完成控制row
    report=owner.report()
    assert report['complete'] and report['buffer_bytes']==65536
    assert report['rows']==[[0,7,7,14,6,4,14,0],[1,7,7,14,6,4,14,0]]
    assert [(r['sent_bytes'],r['received_bytes']) for r in report['connections']]==[(19,14),(19,14)]
    assert all(s.address_queries==2 for s in raw)
    assert all(secret not in json.dumps(report) for secret in ('abc','nope','xy'))


@pytest.mark.parametrize('fault',['eof','error','partial','overflow','reconnect','invalid_header','capacity'])
def test_partial_unknown_cannot_become_complete(fault):
    owner,raw,wrapped=sockets()
    owner.begin(wrapped,[1,1],0)
    for sock in wrapped:
        sock.send(b'\0\0\0\1!')
    if fault=='overflow':
        wrapped[0].sent=2**63-1
        wrapped[0].send(b'x')
    elif fault=='reconnect':
        assert owner.register(Socket()).__class__ is Socket
    elif fault=='capacity':
        owner.count=800
        owner.begin(wrapped,[1,1],1)
    else:
        raw[0].input = [b'' if fault=='eof' else ConnectionError() if fault=='error' else
                       b'\0\0\0\0' if fault=='invalid_header' else b'\0\0\0\5x']
        if fault=='error':
            with pytest.raises(ConnectionError): wrapped[0].recv(10)
        else:
            wrapped[0].recv(10)
    assert not owner.report()['complete']


def test_parser_covers_coalesced_setup_and_refuses_midframe_anchor():
    owner,raw,wrapped=sockets()
    raw[0].input=[b'\0\0\0\1a\0\0\0\2bc',b'\0']
    wrapped[0].recv(100)
    assert wrapped[0].received==11
    wrapped[0].recv(100)
    owner.begin(wrapped,[1,1],0)
    assert not owner.report()['complete'] and owner.error


def test_original_dual_frame_transport_uses_single_counter_owner(tmp_path,monkeypatch):
    from secure_control.execution import localhost_transport
    from secure_control.execution.localhost_transport import _exchange_two_frames, deadline_after
    monkeypatch.setattr(localhost_transport.select,'select',lambda r,w,e,t:(r,w,[]))
    ctx=DiagnosticContext('exchange','domain',str(tmp_path),'a'*40,1)
    recorder=TailRecorder(ctx,'Client',stream_map=True).start()
    try:
        raw=[Socket(),Socket()]
        wrapped=[recorder.streams.register(s) for s in raw]
        recorder.control_step(0)
        recorder.bind_round(0,'round0')
        for s in raw:
            s.input=[b'\0\0',b'\0\4',b'ab',BlockingIOError(),b'cd']
        replies=[]
        _exchange_two_frames(wrapped,[b'one',b'two'],deadline=deadline_after(5),limit=100,
            on_request=lambda *a:None,on_reply=lambda p,data:replies.append((p,data)),observer=recorder)
        report=recorder.streams.report()
        assert replies==[(0,b'abcd'),(1,b'abcd')]
        assert report['complete'] and report['rows']==[[0,0,7,7,0,4,8,0],[1,0,7,7,0,4,8,0]]
        assert all(s.timeout==5. for s in raw)
    finally:
        recorder.finish('stopped')


def link_fixture(tmp_path):
    ctx=DiagnosticContext('stream','domain',str(tmp_path),'a'*40,1)
    recorder=TailRecorder(ctx,'Client',stream_map=True).start()
    recorder.bind_protocol('run','session','epoch')
    recorder.bind_round(0,'round0')
    owner=recorder.streams
    raw=[Socket(),Socket()]
    wrapped=[owner.register(s) for s in raw]
    owner.begin(wrapped,[1,1],0)
    for sock,source in zip(wrapped,raw,strict=True):
        sock.send(b'\0\0\0\1!')
        source.input=[b'\0\0\0\1!']
        sock.recv(5)
    result=recorder.save('stopped')
    assert result['status']=='saved' and recorder.buffer_bytes+len(owner.buffer)==1024*1024
    manifest={'schema':'control-tail-diagnostic-v1','diagnostic_id':'stream','source_head':'a'*40,'diagnostic_complete':True,
              'files':[{'path':'Client.json','sha256':hashlib.sha256((tmp_path/'Client.json').read_bytes()).hexdigest()}]}
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    link={'schema':'client-stream-map-link-v1','manifest':'manifest.json','sidecar':'Client.stream.json',
          'manifest_sha256':hashlib.sha256((tmp_path/'manifest.json').read_bytes()).hexdigest(),
          'sidecar_sha256':hashlib.sha256((tmp_path/'Client.stream.json').read_bytes()).hexdigest()}
    (tmp_path/'stream-link.json').write_text(json.dumps(link))
    return link


@pytest.mark.parametrize('fault',[None,'hash','round','row_bool','endpoint','protocol','path'])
def test_explicit_sidecar_is_independent_and_tamper_checked(tmp_path,fault):
    link=link_fixture(tmp_path)
    if fault=='path':
        link['sidecar']='../outside.json'
        (tmp_path/'stream-link.json').write_text(json.dumps(link))
    elif fault:
        path=tmp_path/'Client.stream.json'
        data=json.loads(path.read_text())
        if fault=='round': data['rows'][0][0]=4
        if fault=='row_bool': data['rows'][0][1]=True
        if fault=='endpoint': data['rows'][0][6]=100
        if fault=='protocol': data['protocol'][0]='other'
        path.write_text(json.dumps(data))
        if fault!='hash':
            link['sidecar_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            (tmp_path/'stream-link.json').write_text(json.dumps(link))
    if fault:
        with pytest.raises((ValueError,FileNotFoundError)):
            read_stream_link(tmp_path/'stream-link.json')
    else:
        sidecar=read_stream_link(tmp_path/'stream-link.json')
        assert sidecar['complete'] and sidecar['rows'][0]==[0,0,5,5,0,1,5,0]
        old=json.loads((tmp_path/'Client.json').read_text())
        assert old['schema']=='control-tail-diagnostic-v1' and 'streams' not in old
        assert struct.calcsize('!8q')*800<=65536


@pytest.mark.parametrize('fault',[None,'partial','duplicate','peek','concurrent'])
def test_setup_checkpoint_is_fixed_validated_boundary_and_next_existing_send(monkeypatch,fault):
    from secure_control.execution import client_stream_map as m
    mapper=ClientStreamMap();raw=Socket();raw.input=[struct.pack('!I',6)+b'setup!']
    sock=mapper.register(raw);sock.send(b'query')
    if fault=='concurrent':monkeypatch.setattr(m.threading,'get_native_id',lambda:sock.thread+1)
    data=sock.recv(100,2) if fault=='peek' else sock.recv(5 if fault=='partial' else 100)
    assert data
    mapper.setup_checkpoint(sock)
    if fault=='duplicate':mapper.setup_checkpoint(sock)
    if fault:
        assert mapper.error is not None;return
    cp=dict(sock.checkpoint)
    assert cp['received_bytes']==10 and cp['next_send_enter_ns'] is None
    assert raw.address_queries==2
    assert sock.send(b'next request')==12
    assert sock.checkpoint['checkpoint_ns']<=sock.checkpoint['next_send_enter_ns']
    first=sock.checkpoint['next_send_enter_ns'];sock.send(b'part2')
    assert sock.checkpoint['next_send_enter_ns']==first
