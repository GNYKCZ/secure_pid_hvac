"""显式安装的进程本地数字观察；不拥有网络、授权、秘密或控制循环。"""
from __future__ import annotations

import gc
import hashlib
import json
import os
import platform
import re
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .diagnostic_limits import limits_for

SCHEMA = 'control-tail-diagnostic-v1'
PHASES = {name: i+1 for i, name in enumerate((
    'startup', 'control', 'stop', 'cleanup', 'sample', 'work', 'material_claim',
    'material_bind', 'request_send', 'reply_read', 'reply_frame', 'commit_fact',
    'double_commit', 'output_checked', 'applied', 'request_receive', 'restore',
    'matrix', 'suffix', 'truncation', 'stage', 'ready', 'commit', 'final_send',
    'seed', 'prefix', 'prefix_peer', 'worker_generate', 'worker_ipc', 'exchange',
))}
SPAN_PHASES = frozenset(('startup', 'control', 'stop', 'cleanup', 'material_claim',
    'material_bind', 'request_send', 'request_receive', 'restore', 'matrix', 'suffix',
    'truncation', 'ready', 'commit', 'final_send', 'seed', 'prefix', 'prefix_peer',
    'worker_generate', 'worker_ipc', 'exchange'))
_ROW = struct.Struct('!8q')
_IDENTITY = struct.Struct('!H128s')
_active = None


@dataclass(frozen=True, slots=True)
class DiagnosticContext:
    """仅由显式launcher传递的公开上下文；同域标签本身不是同机证明。"""

    diagnostic_id: str
    clock_domain_id: str
    output_directory: str
    source_head: str
    launcher_pid: int
    client_io: str = 'ready-v1'
    transport: str = 'insecure_tcp'
    topology_digest: str = ''
    experiment_sha256: str = ''
    source_dirty: bool = True
    window: int = 400


def context_payload(context):
    """v1原上下文不扩字段；window由v2文件limits声明并传播到原worker。"""
    value = asdict(context)
    value.pop('window')
    return value


def current():
    """默认None，不分配缓冲或安装GC回调；已有辅助线程共享当前进程观察器。"""
    return _active


def _clock(name):
    info = time.get_clock_info(name)
    return {'implementation':info.implementation, 'resolution':info.resolution,
            'monotonic':info.monotonic, 'adjustable':info.adjustable}


class TailRecorder:
    """每进程≤1MiB预分配数字/身份缓冲；热路径不生成事件dict、JSON或写盘。"""

    def __init__(self, context: DiagnosticContext, role: str, *, event_capacity=None, gc_capacity=None, stream_map=False, party_receive_map=False):
        self.limits = limits_for(context.window)
        event_capacity = self.limits.events if event_capacity is None else event_capacity
        gc_capacity = self.limits.gc_events if gc_capacity is None else gc_capacity
        if _active is not None:
            raise RuntimeError('每进程只允许一个活动诊断会话。')
        if (not isinstance(context, DiagnosticContext) or role not in ('Client','P1','P2','worker')
                or any(type(v) is not str or not 0 < len(v) <= 256
                       for v in (context.diagnostic_id, context.clock_domain_id, context.source_head))
                or type(context.launcher_pid) is not int or context.launcher_pid <= 0
                or re.fullmatch(r'[0-9a-f]{40}',context.source_head) is None
                or type(event_capacity) is not int or not 1 <= event_capacity <= self.limits.events
                or type(gc_capacity) is not int or not 1 <= gc_capacity <= self.limits.gc_events):
            raise ValueError('诊断身份/角色/固定容量无效。')
        self.context, self.role = context, role
        if type(stream_map) is not bool or stream_map and (role != 'Client' or context.transport != 'insecure_tcp'):
            raise ValueError('流映射只支持显式Client明文诊断')
        self.streams = None
        self.party_receives=None
        if type(party_receive_map) is not bool:raise ValueError('Party观察开关必须为bool')
        if party_receive_map:
            if role not in ('P1','P2') or context.window!=2000 or context.transport!='insecure_tcp':
                raise ValueError('Party接收观察只支持显式2000步明文诊断')
            from .client_stream_map import PartyReceiveMap
            self.party_receives=PartyReceiveMap()
        if stream_map:
            from .client_stream_map import ClientStreamMap
            self.streams = ClientStreamMap(window=context.window)
        self.event_capacity, self.gc_capacity = event_capacity, gc_capacity
        self._events = bytearray(event_capacity*_ROW.size)
        self._gc_events = bytearray(gc_capacity*_ROW.size)
        self._identities = bytearray(self.limits.identity_bytes)
        self.buffer_bytes = len(self._events)+len(self._gc_events)+len(self._identities)
        if self.party_receives is not None:self.buffer_bytes+=len(self.party_receives.buffer)
        if self.buffer_bytes>self.limits.memory_limit:raise ValueError('diagnostic memory budget')
        self._count = self._gc_count = self._sequence = self.lost_events = 0
        self.first_lost_sequence = None
        self.error_type = None
        self._control_step, self._phase = -1, 0
        self._phase_stack = []
        self._local = threading.local()
        self._installed = self._finished = False
        self._control_started = self._stop_started = self._cleanup_started = False
        self._protocol = None
        self._original_callbacks = ()
        self._callback = self._gc_callback
        self.main_thread_id = threading.get_native_id()
        self.clock = {'wall':_clock('perf_counter'), 'cpu':_clock('thread_time')}
        self.gc_before = {'enabled':gc.isenabled(), 'threshold':gc.get_threshold()}

    def observation_failed(self, error):
        """观察失败独立标记，不抛入原业务或允许重试。"""
        self.error_type = self.error_type or type(error).__name__

    def start(self):
        """安装一次；保留所有原回调，不改变GC enabled/阈值/collect行为。"""
        global _active
        if _active is not None or self._installed or self._finished:
            raise RuntimeError('每进程只允许一个活动诊断会话。')
        if len(gc.callbacks) > 64:
            raise RuntimeError('原GC回调数超出诊断元数据预算')
        self._original_callbacks = tuple(gc.callbacks)
        _active, self._installed = self, True
        gc.callbacks.append(self._callback)
        self.emit('startup', 0)
        return self

    def _append(self, code, step, material, aux, *, collecting=False, wall_ns=None):
        sequence = self._sequence
        self._sequence += 1
        index, capacity = ((self._gc_count, self.gc_capacity) if collecting else
                           (self._count, self.event_capacity))
        if index >= capacity:
            self.lost_events += 1
            if self.first_lost_sequence is None:
                self.first_lost_sequence = sequence
            return
        wall = time.perf_counter_ns() if wall_ns is None else wall_ns
        cpu, native = time.thread_time_ns(), threading.get_native_id()
        _ROW.pack_into(self._gc_events if collecting else self._events, index*_ROW.size,
            sequence, code, step, material, wall, cpu, native, aux)
        if collecting:
            self._gc_count += 1
        else:
            self._count += 1

    def emit(self, phase, edge=0, step=None, material=None, aux=0, *, wall_ns=None):
        """固定枚举边界；None端点保留未知，aux只接受公开整数码。"""
        try:
            if not self._installed:
                return
            code = PHASES[phase]
            if type(edge) is not int or edge not in (0,1) or type(aux) is not int:
                raise ValueError('诊断事件码错误')
            global_step = self._control_step if step is None else step
            material_step = getattr(self._local, 'material_step', -1) if material is None else material
            if (type(global_step) is not int or not -1 <= global_step < self.limits.window
                    or type(material_step) is not int or not -1 <= material_step < self.limits.identities):
                raise ValueError('诊断步骤超出固定窗口')
            if material_step >= 0:
                self._local.material_step = material_step
            if threading.get_native_id() == self.main_thread_id and phase in SPAN_PHASES:
                if edge == 0:
                    if len(self._phase_stack) >= 16:
                        raise ValueError('诊断阶段嵌套超出固定上限')
                    self._phase_stack.append(code)
                else:
                    for index in range(len(self._phase_stack)-1,-1,-1):
                        if self._phase_stack[index] == code:
                            del self._phase_stack[index]
                            break
                self._phase = self._phase_stack[-1] if self._phase_stack else 0
            if wall_ns is not None and (type(wall_ns) is not int or wall_ns < 0):
                raise ValueError('公开端点不是非负整数ns')
            self._append(2*code+edge, global_step, material_step, aux, wall_ns=wall_ns)
            if edge == 1 and material_step >= 0:
                self._local.material_step = -1
        except Exception as error:  # noqa: BLE001 - 诊断不能改变业务授权/失败语义。
            self.observation_failed(error)

    def __call__(self, phase, edge, step=None, material=None, aux=0):
        """protocol层只调用此可选callable，不反向依赖execution。"""
        self.emit(phase, edge, step, material, aux)

    def material_context(self, step=-1):
        """已有辅助线程的目标材料步；不覆盖控制线程当前步快照。"""
        self._local.material_step = step

    def control_step(self, step):
        """原控制owner显式更新快照，不从辅助线程推断当前控制步。"""
        if type(step) is not int or not 0 <= step < self.limits.window:
            self.observation_failed(ValueError())
            return
        self._control_step = step
        self.begin_control()

    def begin_control(self):
        """原startup清理之后才开始运行窗口；不主动collect。"""
        if not self._control_started:
            self.emit('startup',1)
            self.emit('control',0)
            self._control_started = True

    def stop_control(self):
        """停止GC与运行窗口分开，禁止停止期GC充作运行覆盖。"""
        if not self._stop_started:
            if self._control_started:
                self.emit('control',1)
            else:
                self.emit('startup',1)
            self.emit('stop',0)
            self._stop_started = True

    def begin_cleanup(self):
        """保留原停止/清理分界；不关闭业务资源。"""
        self.stop_control()
        if not self._cleanup_started:
            self.emit('stop',1)
            self.emit('cleanup',0)
            self._cleanup_started = True

    def bind_protocol(self, run_id, session_id, epoch):
        """只接收已有公开协议身份；一进程不混入另一session。"""
        try:
            values = (run_id, session_id, epoch)
            if any(type(v) is not str or not 0 < len(v) <= 128 for v in values):
                raise ValueError('公开协议身份无效')
            if self._protocol is not None and self._protocol != values:
                raise ValueError('诊断混入不同协议session')
            self._protocol = values
        except Exception as error:  # noqa: BLE001 - 仅令证据不完整。
            self.observation_failed(error)

    def bind_round(self, step, round_id):
        """416个固定槽存公开round，不复制秘密或每事件重复身份字符串。"""
        try:
            if type(step) is not int or not 0 <= step < self.limits.identities or type(round_id) is not str:
                raise ValueError('round索引错误')
            encoded = round_id.encode('ascii')
            if not 0 < len(encoded) <= 128:
                raise ValueError('round身份过长')
            offset = step*_IDENTITY.size
            size, previous = _IDENTITY.unpack_from(self._identities, offset)
            if size and previous[:size] != encoded:
                raise ValueError('同一材料/控制步出现不同round')
            _IDENTITY.pack_into(self._identities, offset, len(encoded), encoded)
        except Exception as error:  # noqa: BLE001 - 不影响材料或控制状态。
            self.observation_failed(error)

    def _gc_callback(self, phase, info):
        try:
            generation = info['generation']
            if type(generation) is not int or generation not in (0,1,2) or phase not in ('start','stop'):
                raise ValueError('GC事件无效')
            self._append(900 if phase == 'start' else 901, self._control_step,
                getattr(self._local, 'material_step', -1), self._phase*4+generation, collecting=True)
        except BaseException as error:  # noqa: BLE001 - GC回调不抛出/打印观察异常。
            self.observation_failed(error)

    def finish(self, status):
        """结束后才展开JSON结构；移除自己的回调，保留别人新增/原有回调。"""
        global _active
        if self._finished:
            raise RuntimeError('诊断已结束，不能重复导出')
        self.begin_cleanup()
        self.emit('cleanup',1)
        gc.callbacks[:] = [v for v in gc.callbacks if v is not self._callback]
        remaining_original = [v for v in gc.callbacks if any(v is original for original in self._original_callbacks)]
        callbacks_restored = len(remaining_original) == len(self._original_callbacks) and all(
            left is right for left,right in zip(remaining_original,self._original_callbacks,strict=True))
        self._installed, self._finished = False, True
        if _active is self:
            _active = None
        rows = [list(_ROW.unpack_from(buffer, i*_ROW.size))
                for buffer,count in ((self._events,self._count),(self._gc_events,self._gc_count))
                for i in range(count)]
        rows.sort(key=lambda row:row[0])
        rounds = {}
        for step in range(self.limits.identities):
            size, value = _IDENTITY.unpack_from(self._identities, step*_IDENTITY.size)
            if size:
                rounds[str(step)] = value[:size].decode('ascii')
        gc_after = {'enabled':gc.isenabled(),'threshold':gc.get_threshold()}
        pending_gc, gc_balanced = set(), True
        for row in rows:
            if row[1] in (900,901):
                key = (row[6], row[7] % 4)
                if row[1] == 900:
                    gc_balanced = gc_balanced and key not in pending_gc
                    pending_gc.add(key)
                elif key not in pending_gc:
                    gc_balanced = False
                else:
                    pending_gc.remove(key)
        gc_balanced = gc_balanced and not pending_gc
        return {'schema':self.limits.trace_schema,
            **({'limits':self.limits.payload()} if self.limits.window!=400 else {}),
            'context':context_payload(self.context), 'role':self.role,
            'pid':os.getpid(),'parent_pid':os.getppid(),'main_thread_id':self.main_thread_id,
            'hostname':socket.gethostname(),'python':platform.python_version(),'platform':platform.platform(),
            'clock':self.clock,'gc_before':self.gc_before,'gc_after':gc_after,
            'callbacks_restored':callbacks_restored,'protocol':self._protocol,'rounds':rounds,
            'buffer_bytes':self.buffer_bytes,'event_capacity':self.event_capacity,'gc_capacity':self.gc_capacity,
            'event_count':self._count,'gc_count':self._gc_count,'lost_events':self.lost_events,
            'first_lost_sequence':self.first_lost_sequence,'observation_error':self.error_type,
            'gc_events_complete':gc_balanced,
            'diagnostic_complete':not self.lost_events and self.error_type is None and callbacks_restored and gc_balanced and status in ('stopped','closed'),
            'status':status,'events':rows}

    def save(self, status):
        """独立角色文件拒覆盖；保存失败只报告诊断失败，不替业务制造成功。"""
        try:
            report = self.finish(status)
            path = Path(self.context.output_directory)/f'{self.role}.json'
            with path.open('x', encoding='utf8') as stream:
                json.dump(report,stream,ensure_ascii=False,allow_nan=False,separators=(',',':'))
            if self.streams is not None:
                sidecar = self.streams.report()
                sidecar.update(context=context_payload(self.context),protocol=self._protocol,
                    role_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    complete=sidecar['complete'] and report['diagnostic_complete'])
                with path.with_name('Client.stream.json').open('x',encoding='utf8') as stream:
                    json.dump(sidecar,stream,ensure_ascii=False,allow_nan=False,separators=(',',':'))
            if self.party_receives is not None:
                sidecar=self.party_receives.report()
                sidecar.update(context=context_payload(self.context),protocol=self._protocol,role=self.role,
                    role_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    complete=sidecar['complete'] and report['diagnostic_complete'])
                with path.with_name(self.role+'.receive.json').open('x',encoding='utf8') as stream:
                    json.dump(sidecar,stream,ensure_ascii=False,allow_nan=False,separators=(',',':'))
            return {'status':'saved','path':path.name,'diagnostic_complete':report['diagnostic_complete']}
        except Exception as error:  # noqa: BLE001 - 独立导出状态，不覆盖原控制失败。
            self.observation_failed(error)
            return {'status':'failed','error_type':type(error).__name__,'diagnostic_complete':False}
