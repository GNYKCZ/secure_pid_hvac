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
from secure_control.experiments.windows_tail_analysis import TCPIP, tcp_source_schemas

_IDS = {1033,1038,1040,1043,1074,1300}
_SCALARS = {'Tcb':16,'NumBytes':8,'SeqNo':8,'NumPkt':8,'LocalAddressLength':8,
    'RemoteAddressLength':8,'Status':8,'ProcessId':8,'Compartment':8,'ProcessStartKey':10,
    'State':8,'Pid':8,'Inspect':13,'SendTrackerEnabled':8,'RcvBufSet':8}
AUTHORIZATION = 'https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6462410802'
CALIBRATION_RESOURCES = {'minimum_free_bytes':2*1024**3,'etl_limit_bytes':128*1024*1024,
    'disk_budget_bytes':384*1024*1024,'native_window_s':100,'active_window_s':55,
    'native_buffer_bytes':12*1024*1024}


def plan_digest(plan):
    """批准记录绑定完整只读计划；不包含批准记录自身，不能用旧计划扩大预算。"""
    import json
    return hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _exceptions_for(plan):
    if plan.get('schema')=='native-calibration-preparation-v1':
        return {'design':'https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6471238272',
            'requested_not_approved':True,'os_abnormal_stop_hard_guarantee':False,
            'temporary_disk_hard_quota':False,'temporary_peak_verified':False}
    return resource_exceptions()


def resource_exceptions():
    """本次用户批准的两项固定例外，不提供通用force/ignore开关。"""
    return {'authorization':AUTHORIZATION,'native_stop_target_s':100,
        'os_abnormal_stop_hard_guarantee':False,'temporary_disk_target_bytes':256*1024*1024,
        'temporary_disk_hard_quota':False,'temporary_peak_verified':False}


def profile_contract(path, schemas, *, file_candidate=False):
    """静态审计profile与本机全部被选版本字段，禁止宽关键字/raw内容旁路。"""
    path = Path(path).resolve()
    if path.stat().st_size>65536:
        raise ValueError('profile size')
    root = ET.fromstring(path.read_bytes())
    providers = root.findall('.//EventProvider')
    profiles = root.findall('.//Profile')
    if (len(providers)!=1 or len(profiles)!=1
            or providers[0].get('Name')!=TCPIP or providers[0].get('Level')!='5'
            or profiles[0].get('Name')!=('D20' if file_candidate else 'D17')
            or profiles[0].get('LoggingMode')!=('File' if file_candidate else 'Memory')
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
    seen, descriptors = set(), set()
    for row in schemas:
        # 字段白名单并不能证明该版本会被当前level/keyword选中。
        # 只核验实际TDH descriptor，不根据事件缺失猜测或扩大keyword。
        if (type(row['id']) is not int or row['id'] not in _IDS
                or row.get('provider')!=TCPIP
                or type(row['version']) is not int or not 0<=row['version']<=255
                or type(row.get('level')) is not int or not 0<=row['level']<=5
                or type(row.get('keyword')) is not int or not 0<=row['keyword']<2**64
                or row['keyword'] and not row['keyword'] & 0x600000484):
            raise ValueError('unselected source descriptor')
        identity = (row['id'],row['version'])
        if identity in descriptors:
            raise ValueError('duplicate source descriptor')
        descriptors.add(identity)
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
        'source_selection_audit_version':1,
        'source_payload':'excluded by ID allowlist and actual registered field audit',
        'runtime_semantics':('NOT RUN: actual TCP target-flow/SeqNo anchors, first-to-last scheduling coverage, '
            'thread lifetime, actual CSwitch version, QPC/loss and resource validation required; '
            'Memory is circular: lost=0 does not prove full-window retention')}


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
            # Microsoft TraceEventSession 3.1.21读取同一HistoricalContext作为session ID。
            'logger_id':struct.unpack_from('<Q',raw,8)[0],
            'buffer_kb':struct.unpack_from('<I',raw,48)[0],
            'buffers':struct.unpack_from('<I',raw,80)[0],
            'events_lost':struct.unpack_from('<I',raw,88)[0],
            'buffers_lost':struct.unpack_from('<I',raw,96)[0],
            'clock':struct.unpack_from('<I',raw,40)[0]})
    return rows


def _provider_enables():
    """EnumerateTraceGuidsEx仅查询TCPIP实际enable信息，不注册或启用provider。"""
    import uuid
    api = ctypes.WinDLL('advapi32').EnumerateTraceGuidsEx
    api.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,
                    ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)]
    api.restype = ctypes.c_uint32
    guid = ctypes.create_string_buffer(uuid.UUID(TCPIP).bytes_le)
    needed = ctypes.c_uint32()
    status = api(1,guid,16,None,0,ctypes.byref(needed))
    if status==1168:
        return []
    if status!=122 or not 8<=needed.value<=1024*1024:
        raise ValueError('TCPIP enable query unavailable')
    data = ctypes.create_string_buffer(needed.value)
    if api(1,guid,16,data,len(data),ctypes.byref(needed)):
        raise ValueError('TCPIP enable query failed')
    return _decode_provider_enables(data.raw)


def _decode_provider_enables(raw):
    """窄解析官方TRACE_GUID_INFO/INSTANCE_INFO/ENABLE_INFO，有界且拒绝截断。"""
    if len(raw)<8:
        raise ValueError('enable header')
    count = struct.unpack_from('<I',raw)[0]
    if count>256:
        raise ValueError('enable instance capacity')
    offset,rows = 8,[]
    for index in range(count):
        if offset+16>len(raw):
            raise ValueError('enable instance boundary')
        next_offset,n,pid,flags = struct.unpack_from('<IIII',raw,offset)
        if n>256 or offset+16+n*32>len(raw):
            raise ValueError('enable rows boundary')
        for i in range(n):
            enabled,level,_,logger,prop,_,any_key,all_key = struct.unpack_from('<IBBHIIQQ',raw,offset+16+i*32)
            rows.append({'logger_id':logger,'enabled':enabled,'level':level,
                         'match_any':any_key,'match_all':all_key,'enable_property':prop,
                         'provider_pid':pid,'instance_flags':flags})
        if len(rows)>4096:
            raise ValueError('enable row capacity')
        if index<count-1:
            if next_offset<16+n*32 or offset+next_offset>=len(raw):
                raise ValueError('enable next boundary')
            offset += next_offset
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

    def is_admin(self):
        """只读核对当前令牌；不弹提权窗口或变更权限。"""
        return bool(ctypes.WinDLL('shell32').IsUserAnAdmin())

    def source_schemas(self):
        """开始前重查实际字段，不能信任过期计划自报。"""
        return tcp_source_schemas()

    def provider_enables(self):
        """只读实际provider→logger ID关联，区别于TDH注册清单。"""
        return _provider_enables()

    def run(self,args,timeout):
        """有界调用自带WPR，不安装工具、不启用其他命令。"""
        return subprocess.run([self.executable,*args],capture_output=True,timeout=timeout,check=False)


def prepare_native(profile, *, _schemas=None, _backend=None, _file_candidate=False):
    """软件阶段唯一入口：TDH/会话查询及-profiledetails，不start/stop任何会话。"""
    schemas = tcp_source_schemas() if _schemas is None else _schemas
    plan = profile_contract(profile,schemas,file_candidate=_file_candidate)
    backend = WprBackend() if _backend is None else _backend
    if any(r['name'].startswith('WPR_') or r['name']=='NT Kernel Logger' for r in backend.sessions()):
        raise ValueError('existing recording conflict; do not cancel it')
    name = 'D20' if _file_candidate else 'D17'
    result = backend.run(['-profiledetails',plan['profile']+'!'+name],10)
    if result.returncode:
        raise ValueError('WPR rejected custom profile')
    result = {**plan,'schema':'native-tail-preparation-v1','window':2000,
        'profiledetails_sha256':hashlib.sha256(result.stdout).hexdigest(),
        'prepared_not_captured':True,'real_capture_verified':False,
        'resource_exceptions':resource_exceptions(),
        'minimum_free_bytes':1024**3,'etl_limit_bytes':64*1024*1024,
        'disk_budget_bytes':256*1024*1024,'native_window_s':limits_for(2000).native_s}
    if _file_candidate:
        result.update(schema='native-calibration-preparation-v1',window=55,profile_name=name,
                      logging_mode='File',**CALIBRATION_RESOURCES)
        result['resource_exceptions'] = _exceptions_for(result)
        result['runtime_semantics'] = ('File calibration candidate; runtime enable/target flow, '
            'full lifecycle/coverage and measured resources require one separately authorized run')
    return result


class NativeCapture:
    """唯一专项的会话owner；不由日常Client自动实例化，无重试或后台常驻服务。"""

    def __init__(self,plan,output,*,_backend=None,_now=time.perf_counter,authorization=None):
        self.plan,self.output = plan,Path(output).resolve()
        self.backend = WprBackend() if _backend is None else _backend
        self.now = _now
        self.authorization = authorization
        self.file_candidate = plan.get('schema')=='native-calibration-preparation-v1'
        self.instance = ('D20_' if self.file_candidate else 'D17_')+uuid4().hex
        self.owned = None
        self.started = None
        self.report = {'status':'not_started','instance':self.instance,
            'resource_exceptions':_exceptions_for(plan),
            'manual_recovery':{'status':['wpr','-status','-instancename',self.instance],
                'query_sessions':['uv','run','python','-c',
                    ("import json,sys; from secure_control.experiments.native_tail_capture import _sessions; "
                     "print(json.dumps([r for r in _sessions() if sys.argv[1] in r['name']],indent=2))"),self.instance],
                'save':['wpr','-stop',str(self.output.with_name('native-a-manual.etl')),
                        '-skipPdbGen','-instancename',self.instance],
                'condition':'先核对本instance及sessions的GUID；归属变化或无法确认时不要停止；无全局cancel'}}

    def preflight(self):
        """只读启动前核验；入口在账本前执行，begin还会重查以发现竞态。"""
        if self.started is not None or self.output.exists():
            raise ValueError('native capture cannot restart/overwrite')
        profile = Path(self.plan['profile']).resolve()
        name = 'control-tail-calibration.wprp' if self.file_candidate else 'control-tail-native-2000.wprp'
        if (self.plan.get('schema')!=('native-calibration-preparation-v1' if self.file_candidate else 'native-tail-preparation-v1')
                or type(self.plan.get('source_selection_audit_version')) is not int
                or self.plan['source_selection_audit_version']!=1
                or self.plan.get('window')!=(55 if self.file_candidate else 2000)
                or profile != Path(__file__).resolve().parents[3]/'configs'/name
                or hashlib.sha256(profile.read_bytes()).hexdigest()!=self.plan['profile_sha256']
                or self.plan.get('resource_exceptions')!=_exceptions_for(self.plan)
                or self.file_candidate and (self.plan.get('profile_name')!='D20' or self.plan.get('logging_mode')!='File')):
            raise ValueError('native plan/profile mismatch')
        if not self.backend.is_admin():
            raise PermissionError('A原生诊断需要管理员PowerShell；未启动采集')
        actual_schemas = self.backend.source_schemas()
        profile_contract(profile,actual_schemas,file_candidate=self.file_candidate)
        if actual_schemas != self.plan['source_schemas']:
            raise ValueError('native source schemas changed since preparation')
        resources = CALIBRATION_RESOURCES if self.file_candidate else {'minimum_free_bytes':1024**3,
                'etl_limit_bytes':64*1024*1024,'disk_budget_bytes':256*1024*1024,
                'native_window_s':limits_for(2000).native_s,'native_buffer_bytes':12*1024*1024}
        if any(type(self.plan.get(k)) is not int or self.plan[k]!=v for k,v in resources.items()):
            raise ValueError('native resource limits changed')
        parent = self.output.parent
        while not parent.exists():
            parent = parent.parent
        if shutil.disk_usage(parent).free < self.plan['minimum_free_bytes']:
            raise ValueError('native disk reserve')
        before = self.backend.sessions()
        if any(r['name'].startswith('WPR_') or r['name']=='NT Kernel Logger' for r in before):
            raise ValueError('native session conflict')
        return {'administrator':True,'profile_sha256':self.plan['profile_sha256'],
                'resource_exceptions':_exceptions_for(self.plan),'source_schemas_rechecked':True}

    def begin(self):
        """ledger已扣减后才运行；仍核验profile/hash/权限/冲突与磁盘。"""
        self.report['preflight'] = self.preflight()
        if self.file_candidate:
            approval = self.authorization
            if (not isinstance(approval,dict) or approval.get('schema')!='native-calibration-authorization-v1'
                    or approval.get('plan_sha256')!=plan_digest(self.plan)
                    or not isinstance(approval.get('authorization_url'),str)
                    or not approval['authorization_url'].startswith('https://github.com/GNYKCZ/secure_pid_hvac/issues/153#issuecomment-')
                    or approval['authorization_url'] in (AUTHORIZATION,_exceptions_for(self.plan)['design'])):
                raise PermissionError('File calibration requires a new plan-bound user authorization')
        self.started = self.now()
        self.capture_deadline = self.started+(55 if self.file_candidate else limits_for(2000).native_s-10)
        # start超时也可能已经创建自身会话，不能在finally中被误认成从未启动。
        self.owned = []
        try:
            result = self.backend.run(['-start',self.plan['profile']+('!D20' if self.file_candidate else '!D17'),
                *(['-filemode'] if self.file_candidate else []),'-instancename',self.instance],10)
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
            if self.file_candidate:
                ids = {r.get('logger_id') for r in own}
                if any(type(v) is not int or not 0<=v<65536 for v in ids):
                    raise ValueError('logger ID proof unavailable')
                enables = [r for r in self.backend.provider_enables() if r['logger_id'] in ids]
                self.report['tcpip_runtime_enables'] = enables
                self.report['resource_authorization'] = self.authorization['authorization_url']
                if not enables or any(r['enabled']!=1 or r['level']!=5
                        or r['match_any']!=0x600000484 or r['match_all'] for r in enables):
                    raise ValueError('own TCPIP provider enable proof failed; no traffic launched')
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
        native_bytes = sum(r['buffer_kb']*r['buffers']*1024 for r in current)
        self.report.update(native_buffer_bytes_at_stop=native_bytes,
            native_buffer_budget_exceeded=native_bytes>self.plan['native_buffer_bytes'])
        valid = (not result.returncode and elapsed<=limits_for(2000).native_s
                 and not any(r['events_lost'] or r['buffers_lost'] or r['clock']!=1 for r in current)
                 and native_bytes<=self.plan['native_buffer_bytes'])
        try:
            remaining_sessions = [r for r in self.backend.sessions() if self.instance in r['name']]
        except Exception as error:  # noqa: BLE001 - 命令退出不等于ETW已停。
            self.report.update(status='stop_unverified_manual_attention',error_type=type(error).__name__)
            return self.report
        if result.returncode or remaining_sessions:
            self.report.update(status='stop_unverified_manual_attention',
                stop_returncode=result.returncode,remaining_sessions=remaining_sessions)
            return self.report
        exceeded = False
        if not cancel:
            # 可观察的本目录包括非ETL产物；merge外部临时峰值仍未知，不冒称硬配额。
            directory_bytes = sum(p.stat().st_size for p in self.output.parent.rglob('*') if p.is_file())
            etl_bytes = self.output.stat().st_size if self.output.is_file() else None
            exceeded = (directory_bytes>self.plan['disk_budget_bytes']
                        or etl_bytes is not None and etl_bytes>self.plan['etl_limit_bytes'])
            self.report.update(output_directory_bytes=directory_bytes,etl_bytes=etl_bytes,
                resource_budget_exceeded=exceeded,temporary_peak_verified=False)
            valid = valid and etl_bytes is not None and not exceeded
        self.report.update(status='cancelled' if cancel and valid else 'saved' if valid else 'partial',
            elapsed_s=elapsed,stop_returncode=result.returncode,final_sessions=current)
        return self.report
