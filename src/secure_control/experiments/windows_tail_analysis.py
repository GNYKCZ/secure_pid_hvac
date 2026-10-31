"""Windows离线ETL窄适配与公开流关联；不提供启动或控制系统会话的API。"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from pathlib import Path

from secure_control.execution.diagnostic_limits import artifact_limits

TCPIP = '2f07e2ee-15db-40f1-90ef-9d7ba282188a'
THREAD = '3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c'
PROCESS = '3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c'
CSWITCH_V5_SOURCE = ('https://github.com/microsoft/perfview/blob/'
    '4b14fe0c8c6101cb3c1c6bfed2e317a9d29f68ee/src/TraceEvent/Parsers/KernelTraceEventParser.cs')


def _cswitch_v5(raw, width):
    """独立TraceEvent 3.1.21逐条核验的x64/v5/28字节前缀；不接受邻版本回退。"""
    if type(width) is not int or width!=8 or len(raw)!=28:
        raise ValueError('unverified CSwitch v5 shape/architecture')
    # Microsoft CSwitchTraceData：新/旧TID在0/4，旧状态在14；header TID可为-1。
    return {'NewThreadId':int.from_bytes(raw[:4],'little'),
        'OldThreadId':int.from_bytes(raw[4:8],'little'),'OldThreadState':raw[14]}


def qpc_ns(ticks, frequency, clock, lost=0):
    """仅原始QPC转整数ns；UTC/相对显示值不可与应用端点相减。"""
    if (clock != 1 or type(frequency) is not int or frequency <= 0
            or type(ticks) is not int or ticks < 0 or lost):
        raise ValueError('unknown clock or lost events')
    return ticks*1_000_000_000//frequency


def scheduling(evidence, pid, tid, lifetime, *, lost=0):
    """规范化生命周期事件的Ready→Running；无法证明前缀时不制造排队时间。"""
    # 完整性必须与事件一起传递；裸events列表已经丢失来源状态，不能默认为可靠。
    if (not isinstance(evidence,dict) or evidence.get('complete') is not True
            or not isinstance(evidence.get('events'),list)):
        return {'state':'unknown','ready_waits':[]}
    events = evidence['events']
    starts = [e for e in events if e['kind']=='start' and e['pid']==pid and e['tid']==tid]
    if lost or len(starts)!=1 or starts[0]['life']!=lifetime:
        return {'state':'unknown','ready_waits':[]}
    active, state, ready, previous = False, 'unknown', None, -1
    waits = []
    for e in events:
        if e['time'] < previous:
            return {'state':'unknown','ready_waits':[]}
        previous = e['time']
        if e['tid'] != tid:
            continue
        if e.get('pid')!=pid or e.get('life')!=lifetime:
            return {'state':'unknown','ready_waits':[]}
        kind = e['kind']
        if kind == 'start':
            active, state = True, 'unknown'
        elif not active:
            return {'state':'unknown','ready_waits':[]}
        elif kind == 'end':
            active, state, ready = False, 'ended', None
        elif kind == 'ready':
            if state == 'running' or ready is not None:
                return {'state':'unknown','ready_waits':[]}
            state, ready = 'ready', e['time']
        elif kind == 'in':
            if state=='running':
                return {'state':'unknown','ready_waits':[]}
            if ready is not None:
                waits.append(e['time']-ready)
            state, ready = 'running', None
        elif kind == 'out':
            if state != 'running':
                return {'state':'unknown','ready_waits':[]}
            state = e['next']
            ready = e['time'] if state == 'ready' else None
        else:
            return {'state':'unknown','ready_waits':[]}
    return {'state':state,'ready_waits':waits}



def _schedule_issues(events):
    """线性记录严格状态规则的异常位置；保留前缀证据，不把未知区间计零。"""
    state,ready,issues = 'unknown',False,[]
    for e in events:
        kind,reason=e['kind'],None
        if kind=='start':state,ready='unknown',False
        elif kind=='ready':
            if state=='running' or ready:reason='ready while running/already ready'
            state,ready='ready',True
        elif kind=='in':
            if state=='running':reason='duplicate in'
            state,ready='running',False
        elif kind=='out':
            if state!='running':reason='out while not running'
            if e['next'] not in ('ready','waiting'):reason='unknown switch-out state'
            state,ready=e['next'],e['next']=='ready'
        elif kind=='end':state,ready='ended',False
        if reason:issues.append({'reason':reason,'event':e})
    return issues


def _window_schedule(evidence,pid,tid,window):
    """唯一生命周期及CPU驻留证明后，以窗前明确切入锚定；不改变通用重放规则。"""
    events=[e for e in evidence['events'] if e['tid']==tid]
    starts=[e for e in events if e['kind']=='start']
    ends=[e for e in events if e['kind']=='end']
    lifetime={'state':'unknown','issues':_schedule_issues(events)}
    result={'state':'unknown','range_ns':list(window),'anchor':None,'reason':'lifetime/quality unavailable'}
    if (not evidence['complete'] or len(starts)!=1 or len(ends)!=1
            or starts[0]['pid']!=pid or not starts[0]['time']<=window[0]<window[1]<=ends[0]['time']):
        return lifetime,result
    life=starts[0]['life']
    lifetime.update(scheduling(evidence,pid,tid,life),range_ns=[starts[0]['time'],ends[0]['time']])
    # 所有目标切换都核对驻留，前缀语义异常不能掩盖跨CPU双重运行或缺失切出。
    cpu,previous=None,-1
    for e in events:
        if e['pid']!=pid or e['life']!=life or e['time']<previous:
            result['reason']='identity/order gap';return lifetime,result
        previous=e['time']
        if e['kind'] in ('in','out'):
            value=e.get('cpu')
            if type(value) is not int or value<0:
                result['reason']='CPU unavailable';return lifetime,result
            if e['kind']=='in':
                if cpu is not None:
                    result['reason']='overlapping CPU residence';return lifetime,result
                cpu=value
            else:
                if cpu!=value:
                    result['reason']='unmatched CPU switch-out';return lifetime,result
                cpu=None
    anchors=[(i,e) for i,e in enumerate(events) if e['kind']=='in' and e['time']<=window[0]]
    if not anchors:
        result['reason']='no pre-window switch-in';return lifetime,result
    index,anchor=anchors[-1]
    fragment=[e for e in events[index:] if e['time']<=window[1]]
    result.update(anchor=anchor,issues=_schedule_issues(fragment))
    if result['issues']:
        result['reason']='strict window replay conflict';return lifetime,result
    # 使用真实生命周期start及明确in初始化；不借助窗内较晚事件跳过窗口开头。
    replay=scheduling({**evidence,'events':[starts[0],*fragment]},pid,tid,life)
    result.update(replay,reason='verified' if replay['state']!='unknown' else 'unknown window state')
    return lifetime,result


def cpu_residence(trace):
    """只证明目标线程的CPU驻留，不把Ready顺序或切出状态解释成网络/GIL等待。"""
    unknown={'verified':False,'intervals':[],'ready_state':'unknown'}
    header=trace.get('header',{})
    if (trace.get('complete') is not True or trace.get('errors')
            or header.get('events_lost')!=0 or header.get('buffers_lost')!=0
            or trace.get('target_critical_gaps')!=0 or trace.get('cpu_chain_mismatches')!=0):
        return {**unknown,'reason':'trace quality unavailable'}
    pid,tid,window=(trace.get(k) for k in ('target_pid','target_tid','target_window_ns'))
    if (type(pid) is not int or type(tid) is not int or not isinstance(window,(list,tuple))
            or len(window)!=2 or any(type(t) is not int for t in window) or not window[0]<window[1]):
        return {**unknown,'reason':'target identity/window unavailable'}
    normalized=normalize_schedule(trace)
    events=normalized['events']
    starts=[e for e in events if e['kind']=='start']
    ends=[e for e in events if e['kind']=='end']
    process_starts=[r for r in trace['events'] if r['provider']==PROCESS
        and r['opcode']==1 and r['values'].get('ProcessId')==pid]
    process_ends=[r for r in trace['events'] if r['provider']==PROCESS
        and r['opcode']==2 and r['values'].get('ProcessId')==pid]
    thread_starts=[r for r in trace['events'] if r['provider']==THREAD
        and r['opcode']==1 and r['values'].get('TThreadId')==tid]
    thread_ends=[r for r in trace['events'] if r['provider']==THREAD
        and r['opcode']==2 and r['values'].get('TThreadId')==tid]
    if (not normalized['complete'] or len(starts)!=1 or len(ends)!=1
            or len(thread_starts)!=1 or len(thread_ends)!=1
            or len(process_starts)!=1 or len(process_ends)!=1
            or not process_starts[0]['time_ns']<=starts[0]['time']<=window[0]
                <window[1]<=ends[0]['time']<=process_ends[0]['time_ns']):
        return {**unknown,'reason':'unique enclosing lifetime unavailable'}
    life=starts[0]['life'];on=None;previous=-1;previous_index=-1;switches=[]
    raw_switches=[r for r in trace['events'] if r['provider']==THREAD and r['opcode']==36
        and tid in (r['values']['NewThreadId'],r['values']['OldThreadId'])]
    indices=[r.get('event_index') for r in raw_switches]
    if any(type(i) is not int or i<0 for i in indices) or len(set(indices))!=len(indices):
        return {**unknown,'reason':'switch event identity unavailable'}
    self_switches=[r for r in raw_switches if r['values']['NewThreadId']==r['values']['OldThreadId']]
    self_indices={r['event_index'] for r in self_switches}
    for e in events:
        if e['pid']!=pid or e['tid']!=tid or e['life']!=life or e['time']<previous:
            return {**unknown,'reason':'lifetime identity/order conflict'}
        previous=e['time']
        if e['kind'] not in ('in','out'):continue
        cpu=e.get('cpu')
        if type(cpu) is not int or not 0<=cpu<4096:
            return {**unknown,'reason':'CPU unavailable'}
        index=e.get('event_index')
        # 同一原始自切换的out/in必须同CPU同刻且先匹配当前驻留；零时区间不计离CPU。
        self_in=(index in self_indices and e['kind']=='in' and switches
            and switches[-1]['kind']=='out' and switches[-1]['event_index']==index
            and switches[-1]['time']==e['time'] and switches[-1]['cpu']==cpu)
        if type(index) is not int or index<previous_index or index==previous_index and not self_in:
            return {**unknown,'reason':'switch event order unavailable'}
        previous_index=index
        if e['kind']=='in':
            if on is not None:return {**unknown,'reason':'overlapping CPU residence'}
            on=cpu
        else:
            if on!=cpu:return {**unknown,'reason':'unmatched CPU switch-out'}
            on=None
        switches.append(e)
    anchors=[i for i,e in enumerate(switches) if e['time']<=window[0]]
    if not anchors:return {**unknown,'reason':'no pre-window CPU boundary'}
    index=anchors[-1];anchor=switches[index];intervals=[]
    # 只依据实际in/out边界，Ready和OldThreadState原始值保留在严格重放中。
    for i in range(index,len(switches)-1):
        event=switches[i];following=switches[i+1]
        left,right=max(window[0],event['time']),min(window[1],following['time'])
        if left<right:
            intervals.append({'state':'running' if event['kind']=='in' else 'not_running',
                'start_ns':left,'end_ns':right,'cpu':event['cpu'] if event['kind']=='in' else None,
                'life':life,
                'start_event_index':event.get('event_index'),'end_event_index':following.get('event_index')})
        if following['time']>=window[1]:break
    if sum(r['end_ns']-r['start_ns'] for r in intervals)!=window[1]-window[0]:
        return {**unknown,'reason':'CPU residence does not cover window'}
    return {'verified':True,'intervals':intervals,'ready_state':'unknown',
        'reason':'paired CPU switch boundaries; Ready/GIL/socket state not inferred',
        'range_ns':list(window),'anchor_event_index':anchor.get('event_index'),
        'continuous_self_switches':[{'event_index':r['event_index'],'time_ns':r['time_ns'],
            'cpu':r['cpu']} for r in self_switches],
        'terminal_boundary_events':normalized['terminal_boundary_events']}


def byte_coverage(events, flow, anchor, length, *, trusted=False, lost=0):
    """指定系统事件边界的连续TCP数据区间；seq/长度均须外部可信锚点。"""
    unknown = {'boundary':'unknown','complete_at':None,'socket_readable':'unknown'}
    if (not trusted or lost or type(anchor) is not int or not 0<=anchor<2**32
            or type(length) is not int or not 0<length<2**31
            or not isinstance(flow,tuple) or len(flow)!=7):
        return unknown
    ranges, seen, previous, first_complete = [], {}, -1, None
    for e in events:
        if e['flow'] != flow:
            continue
        if e['time'] < previous:
            return unknown
        previous = e['time']
        size, seq = e['length'], e['seq']
        if (type(seq) is not int or not 0<=seq<2**32 or type(size) is not int
                or not 0<=size<2**31 or e.get('syn') or e.get('fin')):
            return unknown
        identity, value = e['packet'], (seq,size)
        if identity in seen:
            if seen[identity] != value:
                return unknown
            continue
        seen[identity] = value
        if not size:
            continue
        offset = (seq-anchor)%2**32
        if offset == 2**31:
            return unknown
        if offset > 2**31:
            offset -= 2**32
        left, right = max(0,offset), min(length,offset+size)
        if left < right:
            ranges.append((left,right))
        edge = 0
        for left,right in sorted(ranges):
            if left > edge:
                break
            edge = max(edge,right)
        if edge >= length and first_complete is None:
            first_complete = e['time']
        # 首次覆盖时刻不等于证据校验结束；同流后续身份冲突/倒序仍会使本结果未知。
    return unknown if first_complete is None else {
        'boundary':'selected-component byte coverage','complete_at':first_complete,
        'socket_readable':'unknown'}


def read_stream_link(path):
    """显式sidecar链接核对旧manifest和角色文件hash，拒绝篡改/越界/未知格式。"""
    path = Path(path).resolve()
    link = json.loads(path.read_text(encoding='utf8'))
    if link.get('schema') != 'client-stream-map-link-v1':
        raise ValueError('unknown stream link')
    def load(name, digest):
        target = (path.parent/name).resolve()
        if target.parent != path.parent or target.stat().st_size > 16*1024*1024:
            raise ValueError('stream artifact boundary')
        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('stream artifact hash')
        return json.loads(raw)
    manifest = load(link['manifest'],link['manifest_sha256'])
    sidecar = load(link['sidecar'],link['sidecar_sha256'])
    role = load('Client.json',sidecar['role_file_sha256'])
    limits = artifact_limits(sidecar,stream=True)
    if artifact_limits(manifest) != limits or artifact_limits(role) != limits:
        raise ValueError('stream/trace窗口不一致')
    if not any(e.get('path')=='Client.json' and e.get('sha256')==sidecar['role_file_sha256']
               for e in manifest.get('files',[])):
        raise ValueError('role hash not bound by original manifest')
    if (sidecar.get('buffer_bytes') != limits.stream_bytes
            or len(sidecar.get('rows',[])) > limits.frame_rows or len(sidecar.get('connections',[])) > 2
            or sidecar.get('context') != role.get('context') or sidecar.get('protocol') != role.get('protocol')
            or manifest.get('diagnostic_id') != sidecar['context']['diagnostic_id']
            or manifest.get('source_head') != sidecar['context']['source_head']):
        raise ValueError('stream identities/capacity')
    identities, complete = set(), sidecar.get('complete') is True
    connections = sidecar['connections']
    for index,connection in enumerate(connections):
        if (connection.get('epoch')!=index or type(connection.get('epoch')) is not int
                or any(type(connection.get(k)) is not int or not 0<=connection[k]<2**63
                       for k in ('sent_bytes','received_bytes','pid','thread_id'))):
            raise ValueError('connection counters/epoch')
    previous = {}
    for row in sidecar['rows']:
        if (not isinstance(row,list) or len(row)!=8 or any(type(v) is not int for v in row)
                or not 0 <= row[0] < limits.frame_rows or row[0] in identities):
            raise ValueError('stream frame identity')
        identities.add(row[0])
        step, connection = divmod(row[0],2)
        if (connection >= len(connections) or connections[connection]['epoch'] != connection
                or row[1] < 0 or row[2] <= 4 or row[4] < 0 or row[7] != 0
                or str(step) not in role['rounds']):
            raise ValueError('stream frame range/round')
        if row[3] not in (-1,row[1]+row[2]) or row[6] != -1 and (row[5]<=0 or row[6]!=row[4]+4+row[5]):
            raise ValueError('stream frame endpoints')
        if (row[3]>connections[connection]['sent_bytes'] or row[6]>connections[connection]['received_bytes']
                or row[5]<-1 or row[5]==0 or row[5]>=2**32
                or connection in previous and (row[1]<previous[connection][0] or row[4]<previous[connection][1])):
            raise ValueError('stream overlapping/outside counters')
        previous[connection] = (row[1]+row[2],row[6] if row[6]>=0 else row[4])
        complete = complete and row[3]>=0 and row[6]>=0 and row[5]>0
    sidecar['complete'] = complete and manifest.get('diagnostic_complete') is True
    return sidecar


def _native():
    """仅Windows x64绑定离线读取API；模块import不加载Windows DLL。"""
    if os.name != 'nt':
        raise OSError('Windows offline ETL only')
    import ctypes as c
    if c.sizeof(c.c_void_p) != 8:
        raise OSError('offline ABI requires x64 consumer')
    u32, u16, u8, u64 = c.c_uint32,c.c_uint16,c.c_ubyte,c.c_uint64
    class Guid(c.Structure):
        _fields_ = [('data',u8*16)]
    class Desc(c.Structure):
        _fields_ = [('id',u16),('version',u8),('channel',u8),('level',u8),('opcode',u8),('task',u16),('keyword',u64)]
    class Header(c.Structure):
        _fields_ = [('size',u16),('type',u16),('flags',u16),('property',u16),('tid',u32),('pid',u32),
            ('stamp',c.c_int64),('provider',Guid),('desc',Desc),('cpu',u64),('activity',Guid)]
    class Record(c.Structure):
        _fields_ = [('header',Header),('buffer',u32),('ext_count',u16),('length',u16),
                    ('ext',c.c_void_p),('user',c.c_void_p),('context',c.c_void_p)]
    class TraceHeader(c.Structure):
        _fields_ = [('buffer_size',u32),('version',u32),('provider_version',u32),('processors',u32),
            ('end',c.c_int64),('resolution',u32),('max_file',u32),('mode',u32),('written',u32),
            ('start_buffers',u32),('pointer_size',u32),('events_lost',u32),('cpu_mhz',u32),
            ('logger_name',c.c_void_p),('file_name',c.c_void_p),('timezone',u8*172),
            ('boot',c.c_int64),('frequency',c.c_int64),('start',c.c_int64),('clock',u32),('buffers_lost',u32)]
    callback_type = c.WINFUNCTYPE(None,c.POINTER(Record))
    class Logfile(c.Structure):
        _fields_ = [('filename',c.c_wchar_p),('logger',c.c_wchar_p),('current',c.c_int64),
            ('buffers_read',u32),('process_mode',u32),('current_event',u64*11),('header',TraceHeader),
            ('buffer_callback',c.c_void_p),('buffer_size',u32),('filled',u32),('events_lost',u32),
            ('callback',callback_type),('kernel',u32),('context',c.c_void_p)]
    if (c.sizeof(Record),c.sizeof(TraceHeader),c.sizeof(Logfile)) != (112,280,448):
        raise OSError('unexpected ETW ABI')
    advapi, tdh = c.WinDLL('advapi32',use_last_error=True),c.WinDLL('tdh',use_last_error=True)
    advapi.OpenTraceW.argtypes, advapi.OpenTraceW.restype = [c.POINTER(Logfile)],u64
    advapi.ProcessTrace.argtypes, advapi.ProcessTrace.restype = [c.POINTER(u64),u32,c.c_void_p,c.c_void_p],u32
    advapi.CloseTrace.argtypes, advapi.CloseTrace.restype = [u64],u32
    tdh.TdhGetEventInformation.argtypes = [c.POINTER(Record),u32,c.c_void_p,c.c_void_p,c.POINTER(u32)]
    tdh.TdhGetEventInformation.restype = u32
    class Property(c.Structure):
        _fields_ = [('name',u64),('index',u32),('reserved',u32)]
    tdh.TdhGetPropertySize.argtypes = [c.POINTER(Record),u32,c.c_void_p,u32,c.POINTER(Property),c.POINTER(u32)]
    tdh.TdhGetPropertySize.restype = u32
    tdh.TdhGetProperty.argtypes = [c.POINTER(Record),u32,c.c_void_p,u32,c.POINTER(Property),u32,c.c_void_p]
    tdh.TdhGetProperty.restype = u32

    class Native:
        """OpenTrace只提供文件名且RAW_TIMESTAMP|EVENT_RECORD，绝无实时session名。"""

        record_type = Record

        def open(self, path, handler):
            self.log = Logfile()
            self.stop_requested = False
            self.filename = c.create_unicode_buffer(str(path))
            self.log.filename = c.cast(self.filename,c.c_wchar_p)
            # evntcons.h：0x100是REAL_TIME，离线文件必须排除；回调需EVENT_RECORD。
            self.log.process_mode = 0x1000|0x10000000
            self.callback = callback_type(handler)
            self.log.callback = self.callback
            # 官方BufferCallback允许离线取消；只在预算耗尽后停在缓冲边界，不关闭活会话。
            buffer_type = c.WINFUNCTYPE(u32,c.POINTER(Logfile))
            self.buffer_callback = buffer_type(lambda _log: int(not self.stop_requested))
            self.log.buffer_callback = c.cast(self.buffer_callback,c.c_void_p)
            handle = advapi.OpenTraceW(c.byref(self.log))
            if handle == 2**64-1:
                raise OSError(c.get_last_error(),'OpenTrace failed')
            return handle

        def header(self):
            h = self.log.header
            return {'clock':h.clock,'frequency':h.frequency,'pointer_size':h.pointer_size,
                'events_lost':h.events_lost+self.log.events_lost,'buffers_lost':h.buffers_lost,
                'end':h.end,'mode':h.mode}

        def process(self, handle):
            value = u64(handle)
            status = advapi.ProcessTrace(c.byref(value),1,None,None)
            if status and not (status==1223 and self.stop_requested):
                raise OSError(status,'ProcessTrace failed')
            return status

        def stop_processing(self):
            """请求在下一缓冲边界停止离线遍历，后续不能声称完整文件已读。"""
            self.stop_requested = True

        def close(self,handle):
            if advapi.CloseTrace(handle):
                raise OSError('CloseTrace failed')

        def descriptor(self,pointer):
            """只读固定事件头用于完整遍历计数；未知事件不读取UserData。"""
            import uuid
            h = pointer.contents.header
            return (str(uuid.UUID(bytes_le=bytes(h.provider.data))),h.desc.id,h.desc.version,h.desc.opcode)

        def event(self,pointer):
            import uuid
            h = pointer.contents.header
            guid = str(uuid.UUID(bytes_le=bytes(h.provider.data)))
            key = (guid,h.desc.id,h.desc.version,h.desc.opcode)
            if key==(THREAD,0,5,36):
                import platform
                width = {0x20:4,0x40:8}.get(h.flags&0x60)
                if (platform.machine().lower() not in ('amd64','x86_64')
                        or width!=8 or pointer.contents.length!=28 or not pointer.contents.user):
                    raise ValueError('unverified CSwitch v5 architecture/length')
                values = _cswitch_v5(c.string_at(pointer.contents.user,28),width)
                return {'provider':guid,'id':0,'version':5,'opcode':36,'pid':h.pid,'tid':h.tid,
                    'ticks':h.stamp,'pointer_size':width,'values':values,
                    'cpu':pointer.contents.buffer & (0xffff if h.flags&0x200 else 0xff),
                    'schema_source':CSWITCH_V5_SOURCE,
                    'schema_sha256':hashlib.sha256(b'cswitch-v5-x64-size28-u32@0-u32@4-u8@14').hexdigest()}
            required = _fields(key)
            if required is None:
                return {'unsupported':key}
            width = {0x20:4,0x40:8}.get(h.flags&0x60)
            if width is None:
                raise ValueError('event pointer width unknown')
            size = u32()
            status = tdh.TdhGetEventInformation(pointer,0,None,None,c.byref(size))
            if status != 122 or not 112 <= size.value <= 65536:
                raise ValueError('unsupported event schema')
            data = c.create_string_buffer(size.value)
            if tdh.TdhGetEventInformation(pointer,0,None,data,c.byref(size)):
                raise ValueError('schema read failed')
            raw = data.raw[:size.value]
            count = struct.unpack_from('<I',raw,100)[0]
            if count>256 or 112+24*count>len(raw):
                raise ValueError('schema properties boundary')
            found = {}
            for i in range(count):
                flags,offset,typ = struct.unpack_from('<IIH',raw,112+24*i)
                if offset%2 or not 112 <= offset < len(raw):
                    raise ValueError('schema string boundary')
                end = offset
                while end+2<=len(raw) and raw[end:end+2]!=b'\0\0':
                    end += 2
                if end+2>len(raw):
                    raise ValueError('schema string terminator')
                name = raw[offset:end].decode('utf-16le')
                if name in required:
                    if name in found or typ not in required[name] or flags not in ((0,2) if typ==14 else (0,)):
                        raise ValueError('unsupported field layout')
                    found[name] = typ
                if name.lower() in ('payload','userdata','packetdata'):
                    raise ValueError('payload event not allowed')
            if set(found)!=set(required):
                raise ValueError('required fields absent')
            values = {}
            for name,typ in found.items():
                name_buffer = c.create_unicode_buffer(name)
                prop = Property(c.cast(name_buffer,c.c_void_p).value,0xffffffff,0)
                size = u32()
                if tdh.TdhGetPropertySize(pointer,0,None,1,c.byref(prop),c.byref(size)):
                    raise ValueError('property size failed')
                expected = size.value if typ==14 else {3:1,4:1,8:4,10:8,16:width}[typ]
                if size.value!=expected or not 1 <= expected <= 128:
                    raise ValueError('property width mismatch')
                data = c.create_string_buffer(expected)
                if tdh.TdhGetProperty(pointer,0,None,1,c.byref(prop),expected,data):
                    raise ValueError('property decode failed')
                values[name] = data.raw.hex() if typ==14 else int.from_bytes(data.raw,'little',signed=typ==3)
            return {'provider':guid,'id':h.desc.id,'version':h.desc.version,'opcode':h.desc.opcode,
                'pid':h.pid,'tid':h.tid,'ticks':h.stamp,'pointer_size':width,'values':values,
                'cpu':pointer.contents.buffer & (0xffff if h.flags&0x200 else 0xff),
                'schema_sha256':hashlib.sha256(raw).hexdigest()}
    return Native()


def _fields(key):
    """版本窄白名单；没有证明的字段/版本不从邻近schema猜测。"""
    guid,event,version,opcode = key
    if guid==TCPIP and event==1074 and version in (0,1):
        return {'Tcb':(16,),'NumBytes':(8,),'SeqNo':(8,),**({'NumPkt':(8,)} if version else {})}
    versions = {1017:(0,1),1033:(0,1),1038:(0,1),1040:(0,1),1043:(0,1,2),1300:(0,1,2,3)}
    if guid==TCPIP and event in versions and version in versions[event]:
        return {'Tcb':(16,),'LocalAddress':(14,),'RemoteAddress':(14,),
            'Pid' if event==1300 else 'ProcessId':(8,),
            **({'Status':(8,)} if event==1017 else {}),
            **({'ProcessStartKey':(10,)} if version else {})}
    if guid==THREAD:
        if opcode in (1,2) and version in (2,3):
            return {'ProcessId':(8,),'TThreadId':(8,)}
        if opcode==50 and version==2:
            return {'TThreadId':(8,)}
        if opcode==36 and version in (2,3):
            return {'NewThreadId':(8,),'OldThreadId':(8,),'OldThreadState':(3,)}
    # Process schema在实际ETL中必须通过TDH字段检查；unsupported不提供归因。
    if guid==PROCESS and opcode in (1,2) and version in (2,3,4):
        return {'ProcessId':(8,),'UniqueProcessKey':(16,)}
    return None


def tcp_source_schemas(*, accept=False):
    """只读全部本机TCPIP manifest descriptor，审计指定事件源，无provider启用。"""
    import ctypes as c
    import uuid
    api = _native()
    record = api.record_type()
    guid = record.header.provider
    guid.data[:] = uuid.UUID(TCPIP).bytes_le
    desc_type = type(record.header.desc)
    dll = c.WinDLL('tdh')
    enum = dll.TdhEnumerateManifestProviderEvents
    enum.argtypes = [c.c_void_p,c.c_void_p,c.POINTER(c.c_uint32)]
    enum.restype = c.c_uint32
    info = dll.TdhGetManifestEventInformation
    info.argtypes = [c.c_void_p,c.c_void_p,c.c_void_p,c.POINTER(c.c_uint32)]
    info.restype = c.c_uint32
    def query(fn,*args):
        size = c.c_uint32()
        if fn(*args,None,c.byref(size))!=122 or not 8<=size.value<=1024*1024:
            raise ValueError('source schema unavailable')
        buffer = c.create_string_buffer(size.value)
        if fn(*args,buffer,c.byref(size)):
            raise ValueError('source schema query failed')
        return buffer.raw[:size.value]
    data = query(enum,c.byref(guid))
    count = struct.unpack_from('<I',data)[0]
    if count>4096 or len(data)!=8+count*16:
        raise ValueError('source descriptor bounds')
    rows = []
    for index in range(count):
        desc = desc_type.from_buffer_copy(data[8+index*16:24+index*16])
        if desc.id not in ((1017,1033,1038,1040,1043,1074,1300) if accept else (1033,1038,1040,1043,1074,1300)):
            continue
        raw = query(info,c.byref(guid),c.byref(desc))
        if len(raw)<112:
            raise ValueError('source schema header')
        properties = struct.unpack_from('<I',raw,100)[0]
        if properties>128 or 112+properties*24>len(raw):
            raise ValueError('source schema property bounds')
        fields = []
        for prop in range(properties):
            flags,offset,typ = struct.unpack_from('<IIH',raw,112+24*prop)
            if offset%2 or not 112<=offset<len(raw):
                raise ValueError('source name offset')
            end = offset
            while end+2<=len(raw) and raw[end:end+2]!=b'\0\0':
                end += 2
            if end+2>len(raw):
                raise ValueError('source name unterminated')
            fields.append({'name':raw[offset:end].decode('utf-16le'),'type':typ,'flags':flags})
        rows.append({'id':desc.id,'version':desc.version,'fields':fields,
            'provider':TCPIP,'level':desc.level,'keyword':desc.keyword,
            'schema_sha256':hashlib.sha256(raw).hexdigest()})
    return rows


def read_etl(path, *, maximum_events=100000, _api=None):
    """默认10万、显式最高30万；数所有遍历事件，未知描述符不降格成完整证据。"""
    return _read_etl(path,maximum_events=maximum_events,_api=_api)


def read_calibration_etl(path, *, pid, tid, window_ns, _api=None):
    """File校准专用有界视图；总遍历与保留上限分离，不改变旧读取入口预算。"""
    if (any(type(v) is not int or v<=0 for v in (pid,tid))
            or not isinstance(window_ns,(tuple,list)) or len(window_ns)!=2
            or any(type(v) is not int or v<0 for v in window_ns)
            or window_ns[0]>=window_ns[1] or window_ns[1]-window_ns[0]>55_000_000_000):
        raise ValueError('calibration target/window')
    return _read_etl(path,maximum_events=2500000,_api=_api,target=(pid,tid,window_ns))


def read_control_recovery_etl(path, *, pid, tid, window_ns, _api=None):
    """显式离线恢复预算；旧入口2.5M不变，不能用于新采集。"""
    if (any(type(v) is not int or v<=0 for v in (pid,tid))
            or not isinstance(window_ns,(tuple,list)) or len(window_ns)!=2
            or any(type(v) is not int or v<0 for v in window_ns)
            or not 0<window_ns[1]-window_ns[0]<=55_000_000_000):
        raise ValueError('recovery target/window')
    return _read_etl(path,maximum_events=5000000,_api=_api,
                     target=(pid,tid,window_ns),_recovery=True)


def read_party_requests_etl(path, *, targets, _api=None):
    """B单会话只解码一次，保留两个实际Party的生命周期和TCP元数据。"""
    if (not isinstance(targets,(list,tuple)) or len(targets)!=2
            or any(len(t)!=2 or any(type(v) is not int or v<=0 for v in t) for t in targets)
            or len({t[0] for t in targets})!=2 or len({t[1] for t in targets})!=2):
        raise ValueError('two unique Party PID/TID targets required')
    return _read_etl(path,maximum_events=2500000,_api=_api,targets=targets)


def _read_etl(path, *, maximum_events, _api=None, target=None, targets=None,
              _recovery=False, _now=time.monotonic):
    """两种固定预算共用唯一遍历；目标筛选不跳过descriptor/错误/截断计数。"""
    path = Path(path).resolve()
    targeted=target is not None or targets is not None
    pids={t[0] for t in targets} if targets else {target[0]} if target else set()
    tids={t[1] for t in targets} if targets else {target[1]} if target else set()
    if path.suffix.lower()!='.etl' or not path.is_file() or not 0<path.stat().st_size<=(128 if targeted else 64)*1024*1024:
        raise ValueError('ETL file boundary')
    if _recovery and (target is None or targets is not None):raise ValueError('recovery requires one control target')
    if type(maximum_events) is not int or not 1 <= maximum_events <= (5000000 if _recovery else 2500000 if targeted else 300000):
        raise ValueError('event budget')
    api = _api if _api is not None else _native()
    rows, errors, keys, count = [], [], {}, 0
    descriptors, unsupported, decode_errors = {}, {}, {}
    exhausted = False
    timed_out=False
    started=_now()
    retention_exhausted, filtered, critical_gaps = False, 0, 0
    target_tcbs = set()
    cpu_running, cpu_chain_mismatches = {}, 0
    def tally(mapping,key):
        # 不允许坏文件用无限descriptor/错误类别增长计数器；超界仍令证据不完整。
        if key not in mapping and len(mapping)>=4096:
            raise ValueError('descriptor capacity')
        mapping[key] = mapping.get(key,0)+1
    def callback(pointer):
        nonlocal count, exhausted, timed_out, retention_exhausted, filtered, critical_gaps, cpu_chain_mismatches
        count += 1
        try:
            descriptor = api.descriptor(pointer) if hasattr(api,'descriptor') else None
            if descriptor is not None:
                tally(descriptors,descriptor)
            if count>maximum_events or _recovery and _now()-started>=120:
                exhausted = exhausted or count>maximum_events
                timed_out = timed_out or _recovery and _now()-started>=120
                if hasattr(api,'stop_processing'):api.stop_processing()
                return
            row = api.event(pointer)
            if descriptor is None:
                descriptor = tuple(row['unsupported']) if 'unsupported' in row else (
                    row['provider'],row['id'],row['version'],row['opcode'])
                tally(descriptors,descriptor)
            if 'unsupported' in row:
                tally(unsupported,tuple(row['unsupported']))
                key = tuple(row['unsupported'])
                selected = (key[0]==TCPIP or key[0]==THREAD and key[3] in (1,2,36,50)
                            or key[0]==PROCESS and key[3] in (1,2))
                critical_gaps += int(selected)
                if (not targeted or selected) and 'unsupported event present' not in errors:
                    errors.append('unsupported event present')
                return
            if targeted:
                v = row['values']
                keep = False
                if row['provider']==THREAD:
                    if row['opcode']==36:
                        cpu=row.get('cpu')
                        if type(cpu) is not int or not 0<=cpu<4096:
                            raise ValueError('switch CPU unavailable/outside calibration scope')
                        if cpu in cpu_running and cpu_running[cpu]!=v['OldThreadId']:
                            cpu_chain_mismatches += 1
                        cpu_running[cpu]=v['NewThreadId']
                    keep = (bool(tids & {v.get('NewThreadId'),v.get('OldThreadId')}) if row['opcode']==36
                            else v.get('TThreadId') in tids)
                elif row['provider']==PROCESS:
                    keep = v.get('ProcessId') in pids
                elif row['provider']==TCPIP:
                    if v.get('ProcessId',v.get('Pid')) in pids:
                        if len(target_tcbs)>=64 and v['Tcb'] not in target_tcbs:
                            raise ValueError('target connection capacity')
                        target_tcbs.add(v['Tcb'])
                    # 先有界保留元数据再关联，避免跨CPU绑定行晚于数据行导致丢前缀。
                    keep = True
                if not keep:
                    filtered += 1
                    return
                if len(rows)>=100000:
                    retention_exhausted = True
                    return
            # 内核TCB/进程地址只作内部映射，以本次顺序ID输出，不导出原地址。
            for field in ('Tcb','UniqueProcessKey'):
                if field in row['values']:
                    key = (field,row['values'][field])
                    if key not in keys:
                        if len(keys)>=4096:
                            raise ValueError('identity capacity')
                        keys[key] = len(keys)
                    row['values'][field] = keys[key]
            row['event_index'] = count  # 原文件遍历序号，未知事件的空位不重新编号。
            rows.append(row)
        except Exception as error:  # noqa: BLE001 - 不允许异常跨native callback。
            kind = type(error).__name__
            decode_errors[kind] = decode_errors.get(kind,0)+1
            if kind not in errors:
                errors.append(kind)
    handle = api.open(path,callback)
    header = None
    try:
        header = api.header()
        qpc_ns(0,header['frequency'],header['clock'],header['events_lost']+header['buffers_lost'])
        # TRACE_LOGFILE_HEADER跨WOW布局未用真实ETL验证，窄适配保守拒绝32位文件头。
        if header['pointer_size'] != 8 or not header['end'] or header['mode']&0x100:
            raise ValueError('unfinished or realtime trace header')
        process_status=api.process(handle)
        header = api.header()
        qpc_ns(0,header['frequency'],header['clock'],header['events_lost']+header['buffers_lost'])
    finally:
        api.close(handle)
    if exhausted:
        errors.append('event budget exceeded')
    if timed_out:errors.append('recovery time budget exceeded')
    if _recovery and process_status not in (None,0):
        errors.append('processing cancelled')
    if retention_exhausted:
        errors.append('retention budget exceeded')
    if cpu_chain_mismatches:
        errors.append('CPU switch chain gap')
    if targeted:
        identifiers={keys.get(('Tcb',tcb)) for tcb in target_tcbs}
        selected=[r for r in rows if r['provider']!=TCPIP or r['values'].get('Tcb') in identifiers]
        filtered += len(rows)-len(selected)
        rows=selected
    for row in rows:
        row['time_ns'] = qpc_ns(row['ticks'],header['frequency'],header['clock'])
    def summaries(mapping):
        return [{'provider':k[0],'id':k[1],'version':k[2],'opcode':k[3],'count':v}
                for k,v in sorted(mapping.items())]
    result = {'header':header,'events':rows,'event_count':count,'errors':errors,
        'maximum_events':maximum_events,'retained_event_count':len(rows),
        'descriptor_counts':summaries(descriptors),'unsupported_counts':summaries(unsupported),
        'critical_unsupported_count':sum(v for k,v in unsupported.items() if k[0] in (PROCESS,THREAD,TCPIP)),
        'other_unsupported_count':sum(v for k,v in unsupported.items() if k[0] not in (PROCESS,THREAD,TCPIP)),
        'decode_errors':decode_errors,
        'complete':not errors,'network_semantics':'unverified; event presence is not socket readability',
        'real_event_schema_validation':'performed per descriptor; runtime SeqNo semantic validation still required'}
    if targets:
        result.update(schema='native-party-request-view-v1',targets=[list(t) for t in targets],
            target_critical_gaps=critical_gaps,cpu_chain_mismatches=cpu_chain_mismatches,
            retention_limit=100000,filtered_event_count=filtered)
    if target is not None:
        pid,tid,window = target
        starts = [r for r in rows if r['provider']==THREAD and r['opcode']==1
                  and r['values'].get('ProcessId')==pid and r['values'].get('TThreadId')==tid
                  and r['time_ns']<=window[0]]
        ends = [r for r in rows if r['provider']==THREAD and r['opcode']==2
                and r['values'].get('TThreadId')==tid and r['time_ns']>=window[1]]
        process_starts = [r for r in rows if r['provider']==PROCESS and r['opcode']==1
                          and r['values'].get('ProcessId')==pid and r['time_ns']<=window[0]]
        # 生命周期夹住完整应用窗口，并核查内部ready/in/out序列；不以包络或lost0单独判完整。
        normalized = normalize_schedule({**result,'target_tid':tid,'target_window_ns':list(window)})
        lifetime_replay,window_replay = _window_schedule(normalized,pid,tid,window)
        result.update(schema='native-calibration-view-v1',target_pid=pid,target_tid=tid,
            target_window_ns=list(window),filtered_event_count=filtered,retention_limit=100000,
            target_connection_count=len(target_tcbs),target_critical_gaps=critical_gaps,
            cpu_chain_mismatches=cpu_chain_mismatches,
            schedule_window_complete=(not errors and len(starts)==len(ends)==len(process_starts)==1
                                      and window_replay['state']!='unknown'),
            lifetime_replay=lifetime_replay,window_replay=window_replay,
            source_payload='excluded; target TCP metadata only',
            tcp_usable=False)  # byte/SeqNo校准仍须独立应用流锚点，事件出现不自动设为可用。
    if _recovery:
        result.update(recovery_policy='control-etl-recovery-v1',scan_complete=not errors,
                      scan_elapsed_s=_now()-started)
    return result


def normalize_schedule(trace):
    """仅完整进程/线程生命周期可关联nativeID；不推测事件头PID是被唤醒线程。"""
    processes, threads, events = {}, {}, []
    unassociated = 0
    ended, terminal_boundaries, start_counts = {}, [], {}
    window = trace.get('target_window_ns')
    for row in trace['events']:
        if row['provider']==THREAD and row['opcode']==1:
            tid = row['values']['TThreadId']
            start_counts[tid] = start_counts.get(tid,0)+1
    for row in trace['events']:
        value, stamp = row['values'], row['time_ns']
        if row['provider']==PROCESS:
            pid = value['ProcessId']
            if row['opcode']==1:
                processes[pid] = (value['UniqueProcessKey'],stamp)
            elif row['opcode']==2:
                processes.pop(pid,None)
                for tid in [tid for tid,data in threads.items() if data[0]==pid]:
                    owner,life = threads[tid]
                    events.append({'kind':'end','time':stamp,'pid':owner,'tid':tid,'life':life})
                    threads.pop(tid)
        elif row['provider']==THREAD:
            opcode = row['opcode']
            row_index = row.get('event_index')
            row_cpu = row.get('cpu')
            def emit(kind,tid,_stamp=stamp,_index=row_index,_cpu=row_cpu,terminal=False,**extra):
                nonlocal unassociated
                if trace.get('target_tid') is not None and tid!=trace['target_tid']:
                    return
                if tid in threads:
                    pid, life = threads[tid]
                    events.append({'kind':kind,'time':_stamp,'pid':pid,'tid':tid,'life':life,'cpu':_cpu,'event_index':_index,**extra})
                elif tid:
                    # 仅明确结束后、窗口外、未复用TID的终止切出可单独保存；不隐藏窗口内未知。
                    boundary = ended.get(tid)
                    if (kind=='out' and terminal and boundary and start_counts.get(tid)==1
                            and isinstance(window,(list,tuple)) and len(window)==2
                            and window[1]<boundary[2]<_stamp):
                        terminal_boundaries.append({'tid':tid,'pid':boundary[0],'life':boundary[1],
                            'thread_end':boundary[2],'time':_stamp,'event_index':_index})
                    else:
                        unassociated += 1
            if opcode==1:
                tid,pid = value['TThreadId'],value['ProcessId']
                if pid in processes:
                    if tid in threads:
                        emit('end',tid)
                    threads[tid] = (pid,(processes[pid],stamp))
                    emit('start',tid)
                else:
                    unassociated += 1
            elif opcode==2:
                tid = value['TThreadId']
                if tid in threads:
                    owner,life = threads[tid]
                    ended[tid] = (owner,life,stamp)
                emit('end',value['TThreadId'])
                threads.pop(value['TThreadId'],None)
            elif opcode==50:
                emit('ready',value['TThreadId'])
            elif opcode==36:
                state = {1:'ready',5:'waiting'}.get(value['OldThreadState'],'unknown')
                emit('out',value['OldThreadId'],next=state,old_thread_state=value['OldThreadState'],terminal=value['OldThreadState']==4)
                emit('in',value['NewThreadId'])
    return {'events':events,'complete':trace['complete'] and not unassociated,
        'unassociated_events':unassociated,'terminal_boundary_events':terminal_boundaries,
        'scope':'missing lifetime remains unassociated; Running does not identify Python recv/GIL'}


def correlate_frame(sidecar, identity, events, anchor=None):
    """外部可信连接/seq锚点显式输入；不足时不把首个普通step当TCP偏移零。"""
    unknown = {'boundary':'unknown','complete_at':None,'socket_readable':'unknown'}
    if not sidecar.get('complete') or not anchor or not anchor.get('verified'):
        return unknown
    rows = [row for row in sidecar['rows'] if row[0]==identity]
    connection = identity%2
    if len(rows)!=1 or connection>=len(sidecar['connections']):
        return unknown
    context = sidecar['context']
    if (anchor.get('diagnostic_id') != context['diagnostic_id']
            or anchor.get('source_head') != context['source_head']
            or anchor.get('protocol') != sidecar['protocol']
            or anchor.get('connection') != sidecar['connections'][connection]
            or anchor.get('semantic_boundary') != 'TCPIP1074 verified data sequence'
            or not anchor.get('evidence')):
        return unknown
    row = rows[0]
    start = anchor.get('sequence_at_application_offset_zero')
    if type(start) is not int or not 0<=start<2**32 or row[5]<=0 or row[6]<0:
        return unknown
    # 正常握手/setup/停止均已累计，只有同一连接全流零点可以加应用偏移。
    result = byte_coverage(events,anchor.get('flow'),(start+row[4])%2**32,4+row[5],
        trusted=True,lost=anchor.get('lost',0))
    return {**result,'anchor_evidence':anchor['evidence'],
            'note':'caller-supplied verified anchor; software does not establish TCP/socket readiness semantics'}


def control_tcp_anchor(trace, sidecar, connection):
    """以已验证setup静止边界的独立字节N证明本次流零点，不用普通控制帧反推。"""
    from .tail_calibration import _sockaddr
    def unknown(reason):return {'verified':False,'reason':reason}
    if not trace.get('complete') or not sidecar.get('complete'):
        return unknown('file or stream incomplete')
    party_request=sidecar.get('schema')=='party-receive-map-v1'
    if party_request:
        if connection!=0 or sidecar.get('role') not in ('P1','P2') or not sidecar.get('connection'):
            return unknown('Party connection identity unavailable')
        conn=sidecar['connection']
    else:
        if connection not in (0,1) or len(sidecar.get('connections',[]))!=2:
            return unknown('connection identity unavailable')
        conn=sidecar['connections'][connection]
    cp=conn.get('setup_checkpoint')
    if (conn.get('epoch')!=connection or conn.get('pid')!=trace.get('target_pid') or not cp
            or cp.get('operation')!='lan_setup' or cp.get('sequence')!=2
            or cp.get('contract')!=('validated-setup-request-before-reply-v1' if party_request else 'validated-setup-reply-then-offline-request-v1')
            or cp.get('epoch')!=connection):return unknown('setup checkpoint missing/wrong epoch')
    n,stamp,next_send=(cp.get(k) for k in ('received_bytes','checkpoint_ns',
        'reply_send_enter_ns' if party_request else 'next_send_enter_ns'))
    if (any(type(v) is not int for v in (n,stamp,next_send)) or not 0<n<2**31
            or not conn['registered_ns']<stamp<next_send):return unknown('checkpoint bounds ambiguous')
    if not isinstance(sidecar.get('protocol'),(tuple,list)) or len(sidecar['protocol'])!=3 or any(not isinstance(v,str) or not v for v in sidecar['protocol']):
        return unknown('public protocol identity missing')
    rows=[r for r in trace['events'] if r['provider']==TCPIP]
    births=[r for r in rows if r['id']==(1017 if party_request else 1033)
        and (not party_request or r['values'].get('Status')==0) and r['values'].get('ProcessId')==conn['pid']
        and _sockaddr(r['values'].get('LocalAddress'))==tuple(conn['local'])
        and _sockaddr(r['values'].get('RemoteAddress'))==tuple(conn['remote'])]
    if len(births)!=1:return unknown('unique connect-completed event unavailable')
    birth=births[0];tcb=birth['values']['Tcb']
    starts=[r['time_ns'] for r in trace['events'] if r['provider']==PROCESS and r['opcode']==1 and r['values'].get('ProcessId')==conn['pid']]
    process_ends=[r['time_ns'] for r in trace['events'] if r['provider']==PROCESS and r['opcode']==2 and r['values'].get('ProcessId')==conn['pid']]
    if len(starts)!=1 or len(process_ends)!=1 or not starts[0]<=birth['time_ns']<stamp<process_ends[0]:
        return unknown('unique process lifetime unavailable')
    if sum(r['id'] in (1017,1033) and r['values'].get('Tcb')==tcb for r in rows)!=1:
        return unknown('TCB reused')
    metadata=[r for r in rows if r['id']!=1074 and r['values'].get('Tcb')==tcb]
    if any(_sockaddr(r['values'].get('LocalAddress'))!=tuple(conn['local'])
           or _sockaddr(r['values'].get('RemoteAddress'))!=tuple(conn['remote'])
           or r['values'].get('ProcessId',r['values'].get('Pid')) not in (0,conn['pid']) for r in metadata):
        return unknown('connection lifecycle identity conflict')
    observed=[r for r in rows if r['id']==1074 and r['values']['Tcb']==tcb and r['values']['NumBytes']>0]
    if any(r['time_ns']==birth['time_ns'] for r in observed):return unknown('connect timestamp tie')
    early=[r for r in observed if r['time_ns']<birth['time_ns']]
    if any(r['time_ns']<starts[0] for r in early):return unknown('pre-connect event outside process lifetime')
    # 1033是连接完成，并非TCB创建；早到事件不能用于证明应用字节或提前覆盖。
    # 仅用完成后的独立完整setup前缀锚定，再验证早到区间全部被该前缀包容。
    data=[r for r in observed if r['time_ns']>birth['time_ns']]
    if any(r['time_ns'] in (stamp,next_send) for r in data):return unknown('checkpoint timestamp tie')
    prefix=[r for r in data if r['time_ns']<stamp]
    if not prefix:return unknown('setup prefix absent')
    candidates=[]
    for start in {r['values']['SeqNo'] for r in prefix}:
        ranges=sorted(((r['values']['SeqNo']-start)%2**32,
                       (r['values']['SeqNo']-start)%2**32+r['values']['NumBytes']) for r in prefix)
        end=0
        for left,right in ranges:
            if left>end or right>n:break
            end=max(end,right)
        else:
            if end==n:candidates.append(start)
    if len(candidates)!=1:return unknown('prefix union is not uniquely exactly N bytes')
    start=candidates[0]
    if any((r['values']['SeqNo']-start)%2**32+r['values']['NumBytes']>n for r in early):
        return unknown('pre-connect range not contained in independent prefix')
    redundant=[]
    for r in early:
        left=(r['values']['SeqNo']-start)%2**32;right=left+r['values']['NumBytes']
        redundant.append({'classification':'pre_connect_observation_redundant',
            'event_index':r['event_index'],'time_ns':r['time_ns'],
            'seq':r['values']['SeqNo'],'length':r['values']['NumBytes'],
            'post_prefix_witness_indices':[p['event_index'] for p in prefix
                if max(left,(p['values']['SeqNo']-start)%2**32)
                    <min(right,(p['values']['SeqNo']-start)%2**32+p['values']['NumBytes'])]})
    if any((r['values']['SeqNo']-start)%2**32+r['values']['NumBytes']>n
           for r in data if stamp<r['time_ns']<next_send):
        return unknown('unsolicited prefix growth before next request')
    ends=[*process_ends,*[r['time_ns'] for r in metadata if r['id'] in (1040,1043)]]
    end_ns=min(ends) if ends else None
    if end_ns is not None and end_ns<=next_send:return unknown('connection ended before setup boundary')
    flow=(('control','Client',sidecar['role'],0,0,'receive','TCPIP1074') if party_request else
        ('control','P'+str(connection+1),'Client',connection,0,'receive','TCPIP1074'))
    return {'verified':True,'sequence_at_application_offset_zero':start,'flow':flow,
        'diagnostic_id':sidecar['context']['diagnostic_id'],'source_head':sidecar['context']['source_head'],
        'protocol':sidecar['protocol'],'connection':conn,'semantic_boundary':'TCPIP1074 verified data sequence',
        'evidence':{'checkpoint':cp,'birth_event_index':birth['event_index'],
            'prefix_event_indices':[r['event_index'] for r in prefix],'prefix_union_bytes':n,'connection_end_ns':end_ns,
            'pre_connect_events_unknown':[r['event_index'] for r in early],
            'pre_connect_observations':redundant,'prefix_policy':'post-connect-independent-v1'},
        'packets':[{'seq':r['values']['SeqNo'],'length':r['values']['NumBytes'],'time':r['time_ns'],
                    'packet':r['event_index'],'flow':flow} for r in data]}


def party_request_coverage(trace, sidecar, row, anchor):
    """仅B同机分段；首字节和整帧组件覆盖分开，不能把部分首读伪装整帧已到。"""
    unknown={'verified':False,'socket_readable':'unknown'}
    if not anchor.get('verified'):return {**unknown,'reason':anchor.get('reason')}
    cp=sidecar['connection']['setup_checkpoint']
    if (len(row)!=10 or any(type(v) is not int for v in row) or row[9]!=2 or row[7]<0
            or row[2]<=0 or row[3]!=row[1]+4+row[2] or row[1]<cp['received_bytes']
            or not cp['reply_send_enter_ns']<row[4]<=row[5]<=row[6]):
        return {**unknown,'reason':'validated request frame/read bounds unavailable'}
    start=anchor['sequence_at_application_offset_zero'];packets=anchor['packets']
    end=anchor['evidence']['connection_end_ns']
    if row[6]>=end:return {**unknown,'reason':'request read outside connection lifetime'}
    for p in packets:
        offset=(p['seq']-start)%2**32
        if offset>=2**31:return {**unknown,'reason':'sequence unwrap ambiguous'}
        if p['time']>=end and max(offset,row[1])<min(offset+p['length'],row[3]):
            return {**unknown,'reason':'request bytes overlap ended connection'}
    first=byte_coverage(packets,anchor['flow'],(start+row[1])%2**32,1,trusted=True)
    full=byte_coverage(packets,anchor['flow'],(start+row[1])%2**32,4+row[2],trusted=True)
    a,b=first['complete_at'],full['complete_at']
    if a is None or b is None or a>row[5] or b>row[6]:
        return {**unknown,'reason':'component coverage/read ordering unavailable'}
    return {'verified':True,'socket_readable':'unknown','first_component_ns':a,'full_component_ns':b,
        'recv_enter_ns':row[4],'first_positive_return_ns':row[5],'frame_complete_ns':row[6],
        'first_component_to_first_recv_ns':row[5]-a,'full_component_to_frame_ns':row[6]-b,
        'full_component_to_first_recv_ns':row[5]-b if row[5]>=b else None,
        'recv_enter_after_first_component_ns':max(0,row[4]-a),
        'first_recv_precedes_full_coverage':row[5]<b,
        'component_event_indices':[p['packet'] for p in packets
            if max((p['seq']-start)%2**32,row[1])<min((p['seq']-start)%2**32+p['length'],row[3])],
        'anchor_evidence':anchor['evidence'],
        'note':'B local TCP component to recv return only; not NIC, socket readability or GIL proof'}


def control_frame_coverage(trace, sidecar, identity, anchor, first_read_ns, frame_ns):
    """只使用内部独立锚点，逐回复验证；窗外额外字节保留unknown，不猜FIN。"""
    unknown={'boundary':'unknown','complete_at':None,'socket_readable':'unknown'}
    if not anchor.get('verified'):return {**unknown,'reason':anchor.get('reason')}
    if type(first_read_ns) is not int or type(frame_ns) is not int or first_read_ns>frame_ns:
        return {**unknown,'reason':'application read bounds unavailable'}
    rows=[r for r in sidecar['rows'] if r[0]==identity]
    if len(rows)!=1 or len(rows[0])!=8 or any(type(v) is not int for v in rows[0]) or rows[0][4]<anchor['evidence']['checkpoint']['received_bytes'] or rows[0][5]<=0 or rows[0][6]!=rows[0][4]+4+rows[0][5] or rows[0][3]!=rows[0][1]+rows[0][2]:
        return {**unknown,'reason':'control frame is not after independent setup prefix'}
    if first_read_ns<=anchor['evidence']['checkpoint']['next_send_enter_ns']:
        return {**unknown,'reason':'control read precedes next request boundary'}
    packets=anchor['packets']
    if any((p['seq']-anchor['sequence_at_application_offset_zero'])%2**32>=2**31 for p in packets):
        return {**unknown,'reason':'sequence unwrap ambiguous'}
    end_ns=anchor['evidence'].get('connection_end_ns')
    if end_ns is not None:
        target_start=rows[0][4];target_end=rows[0][6]
        for p in packets:
            offset=(p['seq']-anchor['sequence_at_application_offset_zero'])%2**32
            if p['time']>=end_ns and max(offset,target_start)<min(offset+p['length'],target_end):
                return {**unknown,'reason':'target bytes overlap ended connection'}
    result=correlate_frame(sidecar,identity,packets,anchor)
    if result['complete_at'] is not None and result['complete_at']>frame_ns:
        return {**unknown,'reason':'component coverage occurs after application frame read'}
    result['outside_business_events_unknown']=[p['packet'] for p in packets if p['time']>trace['target_window_ns'][1]]
    return result
