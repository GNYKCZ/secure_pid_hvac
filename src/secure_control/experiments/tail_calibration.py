"""显式、单次、公开流量校准；无plant/密码协议，普通演示不导入或启动本入口。"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import multiprocessing as mp
import os
import queue
import re
import select
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from .native_tail_capture import NativeCapture, plan_digest
from .windows_tail_analysis import TCPIP, byte_coverage, read_calibration_etl


def _frame(identity, connection, sequence):
    """长度变化的公开模式可检验SeqNo是否为数据起点，不把恒长流量的巧合当语义证据。"""
    if (not isinstance(identity,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',identity)
            or type(connection) is not int or connection not in (0,1)
            or type(sequence) is not int or not 0<=sequence<512):
        raise ValueError('public frame identity')
    kind = 0 if sequence==0 else 2 if sequence%50==0 else 1
    size = (32 if kind==0 else 96 if kind==2 else 64)+sequence%13
    payload = b'D20C'+hashlib.sha256(identity.encode()).digest()[:16]
    payload += struct.pack('!BIB',connection,sequence,kind)+bytes([sequence%251])*size
    return struct.pack('!I',len(payload))+payload


def _receive(sock, deadline, *, _now=time.monotonic):
    """共享总截止，先有界头再读payload；首字节时刻不是内核到达时刻。"""
    def exact(size):
        result = bytearray()
        first = None
        while len(result)<size:
            remaining = deadline-_now()
            if remaining<=0:
                raise TimeoutError('calibration receive deadline')
            sock.settimeout(min(3.,remaining))
            part = sock.recv(size-len(result))
            if not part:
                raise EOFError('calibration peer closed')
            if first is None:first=time.perf_counter_ns()
            result.extend(part)
        return bytes(result),first
    header,first = exact(4)
    size = struct.unpack('!I',header)[0]
    if not 26<=size<=256:
        raise ValueError('public frame length')
    body,_ = exact(size)
    return header+body,first


def _save(path, value):
    """所有JSON合计有界，停止后独占写入；异常文件不覆盖，也不宣称保存完整。"""
    path=Path(path)
    used=sum(p.stat().st_size for p in path.parent.glob('*.json'))
    with path.open('x',encoding='utf8') as stream:
        for chunk in json.JSONEncoder(ensure_ascii=True,allow_nan=False,separators=(',',':')).iterencode(value):
            used += len(chunk)
            if used>32*1024*1024:
                raise ValueError('calibration JSON output budget')
            stream.write(chunk)


def _head():
    return subprocess.check_output(['git','rev-parse','HEAD'],
        cwd=Path(__file__).resolve().parents[3],text=True).strip()


def _source_clean():
    """只拒绝待运行源码/候选profile脏改动，保留用户部署与工作流修改。"""
    return not subprocess.check_output(['git','status','--porcelain','--','src','scripts',
        'configs/control-tail-calibration.wprp'],cwd=Path(__file__).resolve().parents[3],text=True).strip()


def _peak_memory():
    """离线进程实际峰值工作集；是事后目标核对，非OS硬内存配额。"""
    import ctypes as ct
    class Memory(ct.Structure):
        _fields_=[('size',ct.c_uint32),('faults',ct.c_uint32)]+[(n,ct.c_size_t) for n in (
            'peak','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
    value=Memory();value.size=ct.sizeof(value)
    api=ct.WinDLL('psapi').GetProcessMemoryInfo
    api.argtypes=[ct.c_void_p,ct.c_void_p,ct.c_uint32];api.restype=ct.c_int
    if not api(ct.c_void_p(-1),ct.byref(value),ct.sizeof(value)):
        raise OSError('process peak memory unavailable')
    return value.peak


def _manifest(output):
    """两端结果绑定原件摘要；复制后仍能拒绝误配/意外篡改，非远端身份认证。"""
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in output.glob('*.json')}
    _save(output/'manifest.json',{'schema':'native-calibration-manifest-v1','files':files})


def _bound(directory, name):
    directory=Path(directory)
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf8'))
    path=directory/name
    if manifest.get('schema')!='native-calibration-manifest-v1' or path.stat().st_size>32*1024*1024:
        raise ValueError('calibration manifest/size')
    raw=path.read_bytes()
    if manifest['files'].get(name)!=hashlib.sha256(raw).hexdigest():
        raise ValueError('calibration artifact hash')
    return json.loads(raw)


def analyze_calibration(client_directory, pair_directory):
    """离线核实双端同一次公开流量；只通过A本地检查不能宣称双机校准完成。"""
    a=_bound(client_directory,'ledger.json');b=_bound(pair_directory,'ledger.json')
    for key in ('calibration_id','source_head','plan_sha256','authorization_url','topology'):
        if a.get(key)!=b.get(key):raise ValueError('calibration peer identity mismatch')
    if (a.get('side')!='client' or b.get('side')!='pair'
            or any(type(v.get('attempts')) is not int or v['attempts']!=1 for v in (a,b))):
        raise ValueError('calibration ledger roles/count')
    client=_bound(client_directory,'client.json');pair=_bound(pair_directory,'pair.json')
    view=_bound(client_directory,'native-view.json');owner=_bound(client_directory,'native-owner.json')
    etl=Path(client_directory)/'native-a.etl'
    if not etl.is_file() or etl.stat().st_size>128*1024*1024 or hashlib.sha256(etl.read_bytes()).hexdigest()!=view['etl_sha256']:
        raise ValueError('calibration ETL changed')
    frames=client.get('frames')
    if not isinstance(frames,list) or len(frames)>1024:
        raise ValueError('calibration frame list')
    counts,offsets=[0,0],[0,0]
    for row in frames:
        if (not isinstance(row,list) or len(row)!=9 or any(type(v) is not int or v<0 for v in row)
                or row[0] not in (0,1)):
            raise ValueError('calibration frame schema')
        i=row[0]
        if (row[1]!=counts[i] or row[2]!=len(_frame(a['calibration_id'],i,row[1]))
                or row[3]!=offsets[i] or row[4]!=offsets[i] or not row[5]<=row[6]<=row[7]<=row[8]):
            raise ValueError('calibration frame sequence/offset/time')
        counts[i]+=1;offsets[i]+=row[2]
    peer_counts=pair.get('frame_counts')
    if (not isinstance(peer_counts,list) or len(peer_counts)!=2
            or any(type(v) is not int or v<0 for v in peer_counts)):
        raise ValueError('calibration peer count schema')
    passed=(client.get('status')==pair.get('status')=='closed' and owner.get('status')=='saved'
            and pair.get('frame_counts')==counts and min(counts)>1
            and view.get('local_checks_complete') is True and view.get('source_head')==a['source_head']
            and view.get('plan_sha256')==a['plan_sha256']
            and owner.get('resource_authorization')==a['authorization_url'])
    return {'schema':'native-calibration-result-v1','calibration_complete':passed,
            'source_head':a['source_head'],'calibration_id':a['calibration_id'],
            'scope':'public two-host calibration only; formal control/performance NOT RUN',
            'socket_readable':'unknown','frame_counts':counts}


def authorize(approval, plan, *, side, output, expected_head):
    """本轮新批准绑定计划/版本/ID/两端路径，旧实验许可不能复用；不替用户生成批准。"""
    url=approval.get('authorization_url')
    identity=approval.get('calibration_id')
    if (approval.get('schema')!='native-calibration-authorization-v1'
            or plan.get('schema')!='native-calibration-preparation-v1'
            or approval.get('plan_sha256')!=plan_digest(plan)
            or approval.get('source_head')!=expected_head or plan.get('source_head')!=expected_head
            or expected_head!=_head()
            or not _source_clean()
            or not isinstance(plan.get('topology_sha256'),str)
            or not re.fullmatch(r'[0-9a-f]{64}',plan['topology_sha256'])
            or type(approval.get('attempts')) is not int or approval['attempts']!=1
            or type(approval.get('active_window_s')) is not int or approval['active_window_s']!=55
            or not isinstance(url,str) or not re.fullmatch(
                r'https://github.com/GNYKCZ/secure_pid_hvac/issues/153#issuecomment-[0-9]+',url)
            or url.endswith(('6471238272','6470834346','6462410802'))
            or not isinstance(identity,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',identity)
            or side not in ('client','pair')
            or not isinstance(approval.get(side+'_output'),str)
            or Path(approval[side+'_output']).resolve()!=Path(output).resolve()):
        raise PermissionError('new calibration authorization does not bind this exact run')
    return identity


def _config_addresses(paths, side):
    from secure_control.execution.lan_config import load_lan_config
    roles = ('Client',) if side=='client' else ('P1','P2')
    if len(paths)!=len(roles):raise ValueError('calibration config count')
    configs=[load_lan_config(p,r) for p,r in zip(paths,roles,strict=True)]
    if (any(c.transport!='insecure_tcp' for c in configs)
            or len({c.topology.digest for c in configs})!=1):
        raise ValueError('calibration requires matched explicit insecure TCP topology')
    topology=configs[0].topology
    return (topology.p1_client,topology.p2_client),topology.digest


def _client_worker(addresses, identity, results, stop):
    """主线程在native启动后由spawn创建，公开字节在原连接上累计全部setup/维护偏移。"""
    sockets=[]
    report={'status':'failed','pid':os.getpid(),'tid':threading.get_native_id(),
            'frames':[],'connections':[]}
    deadline=time.monotonic()+50
    try:
        for address in addresses:
            sock=socket.create_connection(address,timeout=3)
            sockets.append(sock)
            report['connections'].append({'local':list(sock.getsockname()),'remote':list(sock.getpeername()),
                                          'tx_bytes':0,'rx_bytes':0})
        started=time.monotonic();report['window_start_ns']=time.perf_counter_ns()
        for sequence in range(512):
            if stop.is_set():raise TimeoutError('calibration parent deadline')
            if sequence and time.monotonic()-started>=41:break
            for connection,sock in enumerate(sockets):
                value=_frame(identity,connection,sequence)
                sock.settimeout(min(3.,max(.001,deadline-time.monotonic())))
                before=time.perf_counter_ns();sock.sendall(value);sent=time.perf_counter_ns()
                reply,first=_receive(sock,deadline)
                received=time.perf_counter_ns()
                if reply!=value:raise ValueError('public echo content/identity')
                counters=report['connections'][connection]
                report['frames'].append([connection,sequence,len(value),counters['tx_bytes'],
                    counters['rx_bytes'],before,sent,first,received])
                counters['tx_bytes']+=len(value);counters['rx_bytes']+=len(value)
            time.sleep(.2)
        report['window_end_ns']=time.perf_counter_ns()
        if report['window_end_ns']-report['window_start_ns']<40_000_000_000:
            raise ValueError('calibration application window shorter than 40 seconds')
        report['status']='closed'
    except Exception as error:  # noqa: BLE001 - 子进程只返回失败类型，不能伪造完整报告。
        report['error_type']=type(error).__name__
    finally:
        for sock in sockets:sock.close()
        results.put(report)


def _pair(addresses, identity):
    """B端单进程两个监听；只回显指定公开帧，无native/no controller/no worker。"""
    listeners=[];peers={};counts=[0,0];deadline=time.monotonic()+55
    try:
        for address in addresses:
            listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            listeners.append(listener);listener.bind(address);listener.listen(1);listener.setblocking(False)
        for connection,listener in enumerate(listeners):
            ready,_,_=select.select([listener],[],[],max(0,deadline-time.monotonic()))
            if not ready:raise TimeoutError('calibration accept deadline')
            sock,_=listener.accept();peers[sock]=connection
        while peers:
            if time.monotonic()>=deadline:raise TimeoutError('calibration pair deadline')
            ready,_,_=select.select(list(peers),[],[],min(1.,deadline-time.monotonic()))
            for sock in ready:
                connection=peers[sock]
                # MSG_PEEK仅区分正常全连接关闭；中途EOF仍由完整帧读取拒绝。
                if not sock.recv(1,socket.MSG_PEEK):
                    sock.close();del peers[sock];continue
                value,_=_receive(sock,deadline)
                if value!=_frame(identity,connection,counts[connection]):
                    raise ValueError('public frame mismatch')
                sock.settimeout(min(3.,max(.001,deadline-time.monotonic())))
                sock.sendall(value);counts[connection]+=1
        if min(counts)<2:raise ValueError('insufficient calibration frames')
        return {'status':'closed','frame_counts':counts,'pid':os.getpid(),
                'tid':threading.get_native_id()}
    finally:
        for sock in (*peers,*listeners):sock.close()


def run_calibration(side, output, *, plan, approval, config_paths, expected_head):
    """唯一显式运行入口：批准及新目录账本先于监听/native，首错停止且不重试。"""
    output=Path(output).resolve()
    identity=authorize(approval,plan,side=side,output=output,expected_head=expected_head)
    addresses,topology=_config_addresses(config_paths,side)
    if plan['topology_sha256']!=topology:
        raise PermissionError('calibration topology changed since approved preparation')
    # B端只有公开回显。拒绝同机校准冒充两机观测；配置应为已核实的真实设备字面量地址。
    if any(ipaddress.ip_address(a[0]).is_loopback or ipaddress.ip_address(a[0]).is_unspecified for a in addresses):
        raise ValueError('calibration requires explicit two-host addresses')
    output.mkdir(exist_ok=False)
    _save(output/'ledger.json',{'schema':'native-calibration-attempt-v1','attempts':1,
        'calibration_id':identity,'source_head':expected_head,'side':side,'plan_sha256':plan_digest(plan),
        'authorization_url':approval['authorization_url'],'topology':topology})
    if side=='pair':
        try:report=_pair(addresses,identity)
        except Exception as error:  # noqa: BLE001 - 保留首错，不补跑。
            report={'status':'failed','error_type':type(error).__name__}
        _save(output/'pair.json',report)
        _manifest(output)
        return report
    native=NativeCapture(plan,output/'native-a.etl',authorization=approval)
    context=mp.get_context('spawn');results=context.Queue();stop=context.Event();process=None
    report={'status':'failed'}
    try:
        native.begin()
        _save(output/'native-start.json',native.report)
        process=context.Process(target=_client_worker,args=(addresses,identity,results,stop))
        process.start()
        while time.perf_counter()<native.capture_deadline:
            try:
                report=results.get(timeout=min(.5,max(.001,native.capture_deadline-time.perf_counter())))
                break
            except queue.Empty:
                if not process.is_alive():break
        stop.set();process.join(1)
        if process.is_alive():
            process.terminate();process.join(1);report.update(status='failed',error_type='ChildDeadline')
        if process.exitcode!=0:report['status']='failed'
    except Exception as error:  # noqa: BLE001 - native/子进程失败也必须进入本owner收尾。
        report.update(status='failed',error_type=type(error).__name__)
    finally:
        stop.set()
        if process is not None and process.is_alive():
            process.terminate();process.join(1)
        if process is not None:
            report.update(child_pid=process.pid,child_exited=not process.is_alive())
            if process.is_alive():report['status']='child_alive_manual_attention'
        native_report=native.finish()
        results.close();results.join_thread()
        _save(output/'native-owner.json',native_report)
    _save(output/'client.json',report)
    if report['status']=='closed' and native_report['status']=='saved':
        trace=read_calibration_etl(output/'native-a.etl',pid=report['pid'],tid=report['tid'],
            window_ns=[report['window_start_ns'],report['window_end_ns']])
        tcp=calibration_tcp(trace,report)
        summary={k:v for k,v in trace.items() if k!='events'}
        summary.update(tcp=tcp,tcp_usable=tcp['usable'],calibration_complete=False,
            local_checks_complete=trace['schedule_window_complete'] and tcp['usable'],
            peer_verification='NOT RUN; copy both manifests and use calibrate-analyze',
            source_head=expected_head,plan_sha256=plan_digest(plan),
            etl_sha256=hashlib.sha256((output/'native-a.etl').read_bytes()).hexdigest())
        # 有界元数据保留用于后续独立复核；超过输出上限则抛错，不宣称完整保存。
        _save(output/'target-events.json',trace['events'])
        peak=_peak_memory()
        summary.update(process_peak_working_set_bytes=peak,memory_target_met=peak<=512*1024*1024,
            local_checks_complete=summary['local_checks_complete'] and peak<=512*1024*1024)
        _save(output/'native-view.json',summary)
        _manifest(output)
        return summary
    _manifest(output)
    return {'calibration_complete':False,'client_status':report['status'],'native_status':native_report['status']}


def _sockaddr(value):
    """只识别已知sockaddr形状；TDH字段存在不等于任意字节都是可信地址。"""
    try:
        raw=bytes.fromhex(value);family=int.from_bytes(raw[:2],'little')
        if len(raw)==16 and family==2:address=ipaddress.IPv4Address(raw[4:8])
        elif len(raw)==28 and family==23:
            address=ipaddress.IPv6Address(raw[8:24]);address=address.ipv4_mapped or address
        else:return None
        return str(address),int.from_bytes(raw[2:4],'big')
    except (TypeError,ValueError):return None


def calibration_tcp(trace, application):
    """校准两条B→A公开全流；不声称物理到包或socket readable，不跨机减时钟。"""
    unknown={'usable':False,'boundary':'unknown','socket_readable':'unknown'}
    if not trace.get('complete') or not trace.get('schedule_window_complete'):
        return unknown
    bindings={};flow_events={0:[],1:[]};first_bind={};flow_tcbs={}
    for row in trace['events']:
        if row['provider']!=TCPIP:continue
        v=row['values']
        if row['id']!=1074:
            local,remote=_sockaddr(v.get('LocalAddress')),_sockaddr(v.get('RemoteAddress'))
            if v.get('ProcessId',v.get('Pid'))!=application['pid']:continue
            for i,connection in enumerate(application['connections']):
                if local==tuple(connection['local']) and remote==tuple(connection['remote']):
                    if v['Tcb'] in bindings and bindings[v['Tcb']]!=i:return unknown
                    if i in flow_tcbs and flow_tcbs[i]!=v['Tcb']:return unknown
                    flow_tcbs[i]=v['Tcb']
                    bindings[v['Tcb']]=i;first_bind.setdefault(i,row['time_ns'])
        elif v.get('NumBytes',0)>0:
            i=bindings.get(v['Tcb'])
            if i is not None:
                flow_events[i].append({'seq':v['SeqNo'],'length':v['NumBytes'],'time':row['time_ns'],
                    'packet':row['event_index'],'flow':('calibration','B','A',i,0,'receive','TCPIP1074')})
    anchors=[]
    for i in (0,1):
        events=flow_events[i]
        if not events or first_bind[i]>events[0]['time']:return unknown
        anchor=events[0]['seq'];length=application['connections'][i]['rx_bytes']
        # 初始公开连接在启用后创建，B不发送其他字节；完整流包括setup/维护全部字节。
        result=byte_coverage(events,events[0]['flow'],anchor,length,trusted=True)
        if result['complete_at'] is None:return unknown
        # 收到的组件区间不得越过公开总长度，且聚合/重传不重复增加公开字节。
        if any((e['seq']-anchor)%2**32+e['length']>length for e in events):return unknown
        anchors.append({'connection':i,'sequence_at_application_offset_zero':anchor,
            'public_bytes':length,'coverage':result})
    return {'usable':True,'boundary':'TCPIP1074 received-data sequence calibrated against full public echo',
            'socket_readable':'unknown','anchors':anchors,
            'scope':'two new connections, B-to-A; no claim about remote receive or production streams'}
