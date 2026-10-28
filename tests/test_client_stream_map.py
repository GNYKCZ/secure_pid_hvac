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
