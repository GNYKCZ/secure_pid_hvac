"""专项WPR元数据准备与有界自有会话生命周期；默认入口绝不启用。"""
from __future__ import annotations

import ctypes
import hashlib
import shutil
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from uuid import uuid4

from secure_control.execution.diagnostic_limits import limits_for
from secure_control.experiments.windows_tail_analysis import tcp_source_schemas

_IDS = {1033,1038,1040,1043,1074,1300}
_SCALARS = {'Tcb':16,'NumBytes':8,'SeqNo':8,'NumPkt':8,'LocalAddressLength':8,
    'RemoteAddressLength':8,'Status':8,'ProcessId':8,'Compartment':8,'ProcessStartKey':10,
    'State':8,'Pid':8,'Inspect':13,'SendTrackerEnabled':8,'RcvBufSet':8}


def profile_contract(path, schemas):
    """静态审计profile与本机全部被选版本字段，禁止宽关键字/raw内容旁路。"""
    path = Path(path).resolve()
    if path.stat().st_size>65536:
        raise ValueError('profile size')
    root = ET.fromstring(path.read_bytes())
    providers = root.findall('.//EventProvider')
    profiles = root.findall('.//Profile')
    if (len(providers)!=1 or len(profiles)!=1
            or providers[0].get('Name')!='2f07e2ee-15db-40f1-90ef-9d7ba282188a'
            or profiles[0].get('Name')!='D17' or profiles[0].get('LoggingMode')!='Memory'
            or any('Stack' in e.tag or e.tag in ('CaptureStateOnStart','CaptureStateOnSave') for e in root.iter())):
        raise ValueError('unexpected capture provider/profile')
    filters = providers[0].find('EventFilters')
    if (filters is None or filters.get('FilterIn')!='true'
            or {int(e.get('Value')) for e in filters} != _IDS
            or len(filters)!=len(_IDS)):
        raise ValueError('source event-ID filter required')
    keywords = providers[0].findall('./Keywords/Keyword')
    system = root.findall('./Profiles/SystemProvider')
    if (len(keywords)!=1 or keywords[0].get('Value')!='0x600000484' or len(system)!=1
            or {e.get('Value') for e in system[0].findall('./Keywords/Keyword')}
               != {'ProcessThread','CSwitch','ReadyThread'}):
        raise ValueError('unexpected keyword scope')
    collectors = root.findall('.//SystemCollector')+root.findall('.//EventCollector')
    if (len(collectors)!=2 or sorted((int(e.find('BufferSize').get('Value')),
             int(e.find('Buffers').get('Value'))) for e in collectors) != [(64,64),(64,128)]):
        raise ValueError('native buffer budget')
    seen = set()
    for row in schemas:
        if row['id'] not in _IDS:
            raise ValueError('unselected source schema')
        seen.add(row['id'])
        required = {'Tcb','NumBytes','SeqNo'} if row['id']==1074 else {
            'Tcb','LocalAddress','RemoteAddress','Pid' if row['id']==1300 else 'ProcessId'}
        if not required <= {f['name'] for f in row['fields']}:
            raise ValueError('required source metadata absent')
        for field in row['fields']:
            name,typ,flags = field['name'],field['type'],field['flags']
            if name in ('LocalAddress','RemoteAddress'):
                if typ!=14 or flags!=2:
                    raise ValueError('address schema changed')
            elif name not in _SCALARS or _SCALARS[name]!=typ or flags:
                raise ValueError('source field not audited; no payload fallback')
    if seen != _IDS:
        raise ValueError('selected event schemas incomplete')
    return {'profile':str(path),'profile_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'event_ids':sorted(_IDS),'source_schemas':schemas,'native_buffer_bytes':12*1024*1024,
        'source_payload':'excluded by ID allowlist and actual registered field audit',
        'runtime_semantics':'SeqNo/version/QPC/loss and stream anchors require actual single-group validation'}


def _sessions():
    """QueryAllTraces只读快照：只用于冲突、GUID归属与实际缓冲上限核验。"""
    if ctypes.sizeof(ctypes.c_void_p)!=8:
        raise OSError('native session query requires x64')
    api = ctypes.WinDLL('advapi32')
    query = api.QueryAllTracesW
    query.argtypes = [ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)]
    query.restype = ctypes.c_uint32
    buffers = [ctypes.create_string_buffer(4216) for _ in range(64)]
    for buffer in buffers:
        struct.pack_into('<I',buffer,0,len(buffer))
        struct.pack_into('<II',buffer,112,2168,120)
    pointers = (ctypes.c_void_p*len(buffers))(*[ctypes.addressof(b) for b in buffers])
    count = ctypes.c_uint32()
    if query(pointers,len(buffers),ctypes.byref(count)) or count.value>len(buffers):
        raise ValueError('session snapshot unavailable')
    rows = []
    for buffer in buffers[:count.value]:
        raw = buffer.raw
        offset = struct.unpack_from('<I',raw,116)[0]
        if offset%2 or not 120<=offset<len(raw):
            raise ValueError('session name boundary')
        end = offset
        while end+2<=len(raw) and raw[end:end+2]!=b'\0\0':
            end += 2
        if end+2>len(raw):
            raise ValueError('session name terminator')
        rows.append({'name':raw[offset:end].decode('utf-16le'),'guid':raw[24:40].hex(),
            'buffer_kb':struct.unpack_from('<I',raw,48)[0],
            'buffers':struct.unpack_from('<I',raw,80)[0],
            'events_lost':struct.unpack_from('<I',raw,88)[0],
            'buffers_lost':struct.unpack_from('<I',raw,96)[0],
            'clock':struct.unpack_from('<I',raw,40)[0]})
    return rows


class WprBackend:
    """仅明确用户启动专项才调用start；所有命令显式唯一instancename，无全局cancel。"""

    def __init__(self):
        self.executable = shutil.which('wpr')
        if self.executable is None:
            raise OSError('WPR unavailable')

    def sessions(self):
        """只读系统会话，不解析语言相关的WPR状态文本。"""
        return _sessions()

    def run(self,args,timeout):
        """有界调用自带WPR，不安装工具、不启用其他命令。"""
        return subprocess.run([self.executable,*args],capture_output=True,timeout=timeout,check=False)


def prepare_native(profile, *, _schemas=None, _backend=None):
    """软件阶段唯一入口：TDH/会话查询及-profiledetails，不start/stop任何会话。"""
    schemas = tcp_source_schemas() if _schemas is None else _schemas
    plan = profile_contract(profile,schemas)
    backend = WprBackend() if _backend is None else _backend
    if any(r['name'].startswith('WPR_') or r['name']=='NT Kernel Logger' for r in backend.sessions()):
        raise ValueError('existing recording conflict; do not cancel it')
    result = backend.run(['-profiledetails',plan['profile']+'!D17'],10)
    if result.returncode:
        raise ValueError('WPR rejected custom profile')
    return {**plan,'schema':'native-tail-preparation-v1','window':2000,
        'profiledetails_sha256':hashlib.sha256(result.stdout).hexdigest(),
        'prepared_not_captured':True,'real_capture_verified':False,
        'minimum_free_bytes':1024**3,'etl_limit_bytes':64*1024*1024,
        'disk_budget_bytes':256*1024*1024,'native_window_s':limits_for(2000).native_s}


class NativeCapture:
    """唯一专项的会话owner；不由日常Client自动实例化，无重试或后台常驻服务。"""

    def __init__(self,plan,output,*,_backend=None,_now=time.perf_counter):
        self.plan,self.output = plan,Path(output).resolve()
        self.backend = WprBackend() if _backend is None else _backend
        self.now = _now
        self.instance = 'D17_'+uuid4().hex
        self.owned = None
        self.started = None
        self.report = {'status':'not_started','instance':self.instance}

    def begin(self):
        """ledger已扣减后才运行；启动前再次核验profile/hash/冲突与磁盘。"""
        if self.started is not None or self.output.exists():
            raise ValueError('native capture cannot restart/overwrite')
        if (self.plan.get('schema')!='native-tail-preparation-v1'
                or self.plan.get('window')!=2000
                or hashlib.sha256(Path(self.plan['profile']).read_bytes()).hexdigest()!=self.plan['profile_sha256']):
            raise ValueError('native plan/profile mismatch')
        profile_contract(self.plan['profile'],self.plan['source_schemas'])
        if any(self.plan.get(k)!=v for k,v in {'minimum_free_bytes':1024**3,
                'etl_limit_bytes':64*1024*1024,'disk_budget_bytes':256*1024*1024,
                'native_window_s':limits_for(2000).native_s,'native_buffer_bytes':12*1024*1024}.items()):
            raise ValueError('native resource limits changed')
        if shutil.disk_usage(self.output.parent).free < self.plan['minimum_free_bytes']:
            raise ValueError('native disk reserve')
        before = self.backend.sessions()
        if any(r['name'].startswith('WPR_') or r['name']=='NT Kernel Logger' for r in before):
            raise ValueError('native session conflict')
        self.started = self.now()
        self.capture_deadline = self.started+limits_for(2000).native_s-10
        # start超时也可能已经创建自身会话，不能在finally中被误认成从未启动。
        self.owned = []
        try:
            result = self.backend.run(['-start',self.plan['profile']+'!D17','-instancename',self.instance],10)
        except Exception:
            self.finish(cancel=True)
            raise
        if result.returncode:
            self.report['status'] = 'start_failed'
            self.finish(cancel=True)
            raise ValueError('native start failed; no retry')
        # 自己成功创建的唯一instance才允许finally关闭，绝不全局stop/cancel。
        self.owned = []
        try:
            rows = self.backend.sessions()
            own = [r for r in rows if self.instance in r['name']]
            if (len(own)!=2 or any(r['clock']!=1 for r in own)
                    or sum(r['buffer_kb']*r['buffers']*1024 for r in own)>12*1024*1024):
                raise ValueError('native ownership/clock/buffer proof unavailable')
            self.owned = own
            self.report.update(status='recording',sessions=own)
        except Exception:
            self.finish(cancel=True)
            raise

    def finish(self,*,cancel=False):
        """只停止自己成功创建且GUID仍吻合的会话；冲突时不关闭他人会话。"""
        if self.owned is None:
            return self.report
        try:
            rows = self.backend.sessions()
        except Exception as error:  # noqa: BLE001 - 无法证明GUID时不停止可能变更归属的会话。
            self.report.update(status='ownership_unavailable_manual_attention',error_type=type(error).__name__)
            if self.owned:
                self.owned = None
                return self.report
            # start返回前未知GUID，仅允许撤销本次随机instance的部分启动。
            rows = []
            cancel = True
        current = [r for r in rows if self.instance in r['name']]
        expected = {(r['name'],r['guid']) for r in self.owned}
        if self.owned and {(r['name'],r['guid']) for r in current}!=expected:
            self.report['status'] = 'ownership_changed_manual_attention'
            self.owned = None
            return self.report
        args = ['-cancel'] if cancel else ['-stop',str(self.output),'-skipPdbGen']
        remaining = limits_for(2000).native_s-(self.now()-self.started)
        if remaining<=0:
            self.report['status'] = 'deadline_exceeded_manual_attention'
            self.owned = None
            return self.report
        try:
            result = self.backend.run([*args,'-instancename',self.instance],min(10,remaining))
        except Exception as error:  # noqa: BLE001 - 不以失败后的自动重跑掩盖未知会话状态。
            self.report.update(status='stop_failed_manual_attention',error_type=type(error).__name__)
            self.owned = None
            return self.report
        self.owned = None
        elapsed = self.now()-self.started
        valid = (not result.returncode and elapsed<=limits_for(2000).native_s
                 and not any(r['events_lost'] or r['buffers_lost'] for r in current))
        if not cancel:
            files = list(self.output.parent.glob('*.etl'))
            valid = (valid and self.output.is_file() and self.output.stat().st_size<=64*1024*1024
                     and sum(p.stat().st_size for p in files)<=256*1024*1024)
        self.report.update(status='cancelled' if cancel and valid else 'saved' if valid else 'partial',
            elapsed_s=elapsed,stop_returncode=result.returncode,final_sessions=current)
        return self.report
