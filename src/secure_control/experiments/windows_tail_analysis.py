"""Windows离线ETL窄适配与公开流关联；不提供启动或控制系统会话的API。"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

TCPIP = '2f07e2ee-15db-40f1-90ef-9d7ba282188a'
THREAD = '3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c'
PROCESS = '3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c'


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
    if not any(e.get('path')=='Client.json' and e.get('sha256')==sidecar['role_file_sha256']
               for e in manifest.get('files',[])):
        raise ValueError('role hash not bound by original manifest')
    if (sidecar.get('schema') != 'client-stream-map-v1' or sidecar.get('buffer_bytes') != 65536
            or len(sidecar.get('rows',[])) > 800 or len(sidecar.get('connections',[])) > 2
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
                or not 0 <= row[0] < 800 or row[0] in identities):
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
            self.log.filename = str(path)
            self.log.process_mode = 0x1000|0x100
            self.callback = callback_type(handler)
            self.log.callback = self.callback
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
            if status:
                raise OSError(status,'ProcessTrace failed')

        def close(self,handle):
            if advapi.CloseTrace(handle):
                raise OSError('CloseTrace failed')

        def event(self,pointer):
            import uuid
            h = pointer.contents.header
            guid = str(uuid.UUID(bytes_le=bytes(h.provider.data)))
            key = (guid,h.desc.id,h.desc.version,h.desc.opcode)
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
                'schema_sha256':hashlib.sha256(raw).hexdigest()}
    return Native()


def _fields(key):
    """版本窄白名单；没有证明的字段/版本不从邻近schema猜测。"""
    guid,event,version,opcode = key
    if guid==TCPIP and event==1074 and version in (0,1):
        return {'Tcb':(16,),'NumBytes':(8,),'SeqNo':(8,),**({'NumPkt':(8,)} if version else {})}
    if guid==TCPIP and event in (1033,1300) and version in (0,1):
        return {'Tcb':(16,),'LocalAddress':(14,),'RemoteAddress':(14,),
            'ProcessId' if event==1033 else 'Pid':(8,),
            **({'ProcessStartKey':(10,)} if version else {})}
    if guid==THREAD:
        if opcode in (1,2) and version==2:
            return {'ProcessId':(8,),'TThreadId':(8,)}
        if opcode==50 and version==2:
            return {'TThreadId':(8,)}
        if opcode==36 and version in (2,3):
            return {'NewThreadId':(8,),'OldThreadId':(8,),'OldThreadState':(3,)}
    # Process schema在实际ETL中必须通过TDH字段检查；unsupported不提供归因。
    if guid==PROCESS and opcode in (1,2) and version in (2,3,4):
        return {'ProcessId':(8,),'UniqueProcessKey':(16,)}
    return None


def read_etl(path, *, maximum_events=100000, _api=None):
    """有界离线文件读取；mock可验证finally资源清理，不构成真实ETL验证。"""
    path = Path(path).resolve()
    if path.suffix.lower()!='.etl' or not path.is_file() or path.stat().st_size>64*1024*1024:
        raise ValueError('ETL file boundary')
    if type(maximum_events) is not int or not 1 <= maximum_events <= 100000:
        raise ValueError('event budget')
    api = _api if _api is not None else _native()
    rows, errors, keys, count = [], [], {}, 0
    exhausted = False
    def callback(pointer):
        nonlocal count, exhausted
        count += 1
        if count>maximum_events:
            exhausted = True
            return
        try:
            row = api.event(pointer)
            if 'unsupported' in row:
                if 'unsupported event present' not in errors:
                    errors.append('unsupported event present')
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
            rows.append(row)
        except Exception as error:  # noqa: BLE001 - 不允许异常跨native callback。
            kind = type(error).__name__
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
        api.process(handle)
        header = api.header()
        qpc_ns(0,header['frequency'],header['clock'],header['events_lost']+header['buffers_lost'])
    finally:
        api.close(handle)
    if exhausted:
        errors.append('event budget exceeded')
    for row in rows:
        row['time_ns'] = qpc_ns(row['ticks'],header['frequency'],header['clock'])
    return {'header':header,'events':rows,'event_count':count,'errors':errors,
        'complete':not errors,'network_semantics':'unverified; event presence is not socket readability',
        'real_event_schema_validation':'performed per descriptor; runtime SeqNo semantic validation still required'}


def normalize_schedule(trace):
    """仅完整进程/线程生命周期可关联nativeID；不推测事件头PID是被唤醒线程。"""
    processes, threads, events = {}, {}, []
    unassociated = 0
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
            def emit(kind,tid,_stamp=stamp,**extra):
                nonlocal unassociated
                if tid in threads:
                    pid, life = threads[tid]
                    events.append({'kind':kind,'time':_stamp,'pid':pid,'tid':tid,'life':life,**extra})
                elif tid:
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
                emit('end',value['TThreadId'])
                threads.pop(value['TThreadId'],None)
            elif opcode==50:
                emit('ready',value['TThreadId'])
            elif opcode==36:
                state = {1:'ready',5:'waiting'}.get(value['OldThreadState'],'unknown')
                emit('out',value['OldThreadId'],next=state)
                emit('in',value['NewThreadId'])
    return {'events':events,'complete':trace['complete'] and not unassociated,
        'unassociated_events':unassociated,
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
