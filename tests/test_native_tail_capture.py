"""只读profile核验及mock自有会话生命周期，禁止真实WPR启动。"""
import copy
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from secure_control.experiments.native_tail_capture import (
    NativeCapture,
    prepare_native,
    profile_contract,
)

PROFILE=Path(__file__).parents[1]/'configs/control-tail-native-2000.wprp'


def schemas():
    """手写允许字段oracle，不能代替本机TDH实际字段核验。"""
    result=[]
    for event in (1033,1038,1040,1043,1074,1300):
        names=[('Tcb',16,0),('NumBytes',8,0),('SeqNo',8,0)] if event==1074 else [
            ('Tcb',16,0),('LocalAddress',14,2),('RemoteAddress',14,2),
            ('Pid' if event==1300 else 'ProcessId',8,0)]
        result.append({'id':event,'version':0,
            'provider':'2f07e2ee-15db-40f1-90ef-9d7ba282188a','level':4,
            'keyword':0x200000000 if event==1074 else 0x400000084,
            'fields':[{'name':n,'type':t,'flags':f} for n,t,f in names]})
    return result


class Backend:
    """模拟本次唯一instance，命令列表可审计，没有subprocess调用。"""

    def __init__(self,fault=None):
        self.fault=fault
        self.commands=[]
        self.instance=None
        self.live=False
        self.changed=False

    def is_admin(self):
        return self.fault!='not_admin'

    def provider_enables(self):
        return []

    def source_schemas(self):
        result=schemas()
        if self.fault=='schema_change': result[0]['version']=8
        return result

    def sessions(self):
        if self.fault=='conflict':
            return [{'name':'WPR_other_user'}]
        if not self.live:
            return []
        if self.fault=='query':
            raise OSError('mock query failure')
        return [{'name':'WPR_'+self.instance+'_system','guid':'changed' if self.changed else 'a',
            'clock':2 if self.fault=='clock' else 1,'buffer_kb':64,
            'buffers':129 if self.fault=='buffers' else 128,'events_lost':0,'buffers_lost':0},
            {'name':'WPR_'+self.instance+'_events','guid':'b','clock':1,'buffer_kb':64,
             'buffers':64,'events_lost':1 if self.fault=='loss' else 0,'buffers_lost':0}]

    def run(self,args,timeout):
        self.commands.append(args)
        assert timeout<=10
        if args[0]=='-start':
            self.instance=args[-1]
            self.live=True
            if self.fault=='start_timeout':
                raise subprocess.TimeoutExpired('mock-wpr',10)
            return SimpleNamespace(returncode=1 if self.fault=='start' else 0,stdout=b'')
        if args[0]=='-stop':
            if self.fault=='stop_timeout':
                raise subprocess.TimeoutExpired('mock-wpr',10)
            Path(args[1]).write_bytes(b'mock-only ETL output')
            self.live=self.fault=='stop_still_live'
        if args[0]=='-cancel': self.live=False
        return SimpleNamespace(returncode=0,stdout=b'profile parsed; fake-only')


def test_preparation_never_issues_start_stop_or_cancel():
    backend=Backend()
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=backend)
    assert [a[0] for a in backend.commands]==['-profiledetails']
    assert plan['native_buffer_bytes']==12582912 and plan['window']==2000
    assert plan['prepared_not_captured'] and not plan['real_capture_verified']
    assert plan['source_selection_audit_version']==1
    assert 'Memory is circular: lost=0' in plan['runtime_semantics']


@pytest.mark.parametrize('field,value', [('provider','wrong'),('level',6),('level',True),
    ('keyword',1<<40),('keyword',False),('keyword',-1),('keyword',1<<64),
    ('version',False),('version',256),('id',1033.0)])
def test_registered_descriptor_must_match_selected_provider_level_and_keyword(field,value):
    rows=schemas()
    rows[0][field]=value
    with pytest.raises(ValueError,match='source descriptor'):
        profile_contract(PROFILE,rows)


def test_old_field_only_plan_and_duplicate_descriptor_are_not_selection_evidence(tmp_path):
    rows=schemas()
    del rows[0]['keyword']
    with pytest.raises(ValueError): profile_contract(PROFILE,rows)
    rows=schemas()
    rows.append(copy.deepcopy(rows[0]))
    with pytest.raises(ValueError,match='duplicate'): profile_contract(PROFILE,rows)
    profile=tmp_path/'wrong-level.wprp'
    profile.write_text(PROFILE.read_text().replace('Level="5"','Level="3"'))
    with pytest.raises(ValueError): profile_contract(profile,schemas())


@pytest.mark.parametrize('fault',['payload','field_type','missing_event','missing_fields','unselected_id','profile_filter','profile_buffer'])
def test_source_or_profile_expansion_is_rejected(tmp_path,fault):
    rows=schemas()
    profile=PROFILE
    if fault=='payload': rows[0]['fields'].append({'name':'Payload','type':14,'flags':2})
    if fault=='field_type': rows[0]['fields'][0]['type']=14
    if fault=='missing_event': rows.pop()
    if fault=='missing_fields': rows[0]['fields']=[]
    if fault=='unselected_id': rows[0]['id']=160
    if fault.startswith('profile_'):
        profile=tmp_path/'bad.wprp'
        source=PROFILE.read_text()
        source=source.replace('FilterIn="true"','FilterIn="false"') if fault=='profile_filter' else source.replace('Value="128"','Value="129"')
        profile.write_text(source)
    with pytest.raises(ValueError): profile_contract(profile,rows)


@pytest.mark.parametrize('fault',[None,'conflict','buffers','clock','start','loss','owner'])
def test_owned_native_session_fake_lifecycle_and_exact_limits(tmp_path,monkeypatch,fault):
    import secure_control.experiments.native_tail_capture as module
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=Backend())
    backend=Backend(fault)
    clock=[0.]
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:SimpleNamespace(free=2*1024**3))
    capture=NativeCapture(plan,tmp_path/'native-a.etl',_backend=backend,_now=lambda:clock[0])
    if fault in ('conflict','buffers','clock','start'):
        with pytest.raises(ValueError): capture.begin()
        if fault=='conflict': assert not backend.commands
        else:
            assert not backend.live
            assert backend.commands[-1][0]=='-cancel'
        return
    capture.begin()
    assert capture.capture_deadline==90
    clock[0]=99
    if fault=='owner': backend.changed=True
    report=capture.finish()
    assert report['status']==('ownership_changed_manual_attention' if fault=='owner' else 'partial' if fault=='loss' else 'saved')
    assert all(args[-2]=='-instancename' and args[-1]==capture.instance for args in backend.commands)
    if fault=='owner': assert [args[0] for args in backend.commands]==['-start']
    else: assert not backend.live


def test_native_deadline_partial_not_retried_and_plan_cannot_expand_budget(tmp_path,monkeypatch):
    import secure_control.experiments.native_tail_capture as module
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=Backend())
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:SimpleNamespace(free=2*1024**3))
    clock=[0.]
    backend=Backend()
    capture=NativeCapture(plan,tmp_path/'native.etl',_backend=backend,_now=lambda:clock[0])
    capture.begin()
    clock[0]=101
    assert capture.finish()['status']=='deadline_exceeded_manual_attention'
    assert capture.finish()['status']=='deadline_exceeded_manual_attention'
    assert [args[0] for args in backend.commands]==['-start']
    bad=copy.deepcopy(plan)
    bad['native_window_s']=1000
    with pytest.raises(ValueError): NativeCapture(bad,tmp_path/'bad.etl',_backend=Backend()).begin()


@pytest.mark.parametrize('fault',['start_timeout','query','stop_timeout'])
def test_native_exception_paths_do_not_hide_session_state(tmp_path,monkeypatch,fault):
    import secure_control.experiments.native_tail_capture as module
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=Backend())
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:SimpleNamespace(free=2*1024**3))
    backend=Backend(fault)
    capture=NativeCapture(plan,tmp_path/'native.etl',_backend=backend,_now=lambda:0.)
    if fault in ('start_timeout','query'):
        with pytest.raises((OSError,subprocess.TimeoutExpired)):
            capture.begin()
        assert not backend.live
        assert [a[0] for a in backend.commands]==['-start','-cancel']
    else:
        capture.begin()
        assert capture.finish()['status']=='stop_failed_manual_attention'
        assert backend.live  # 未知状态如实呈现，绝不宣称已成功清退。
        assert [a[0] for a in backend.commands]==['-start','-stop']


@pytest.mark.parametrize('fault',['not_admin','schema_change','space','profile_path','approval','conflict',
                                 'old_audit','bool_audit','float_audit'])
def test_native_preflight_rejects_other_conditions_despite_resource_exceptions(tmp_path,monkeypatch,fault):
    import secure_control.experiments.native_tail_capture as module
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=Backend())
    backend=Backend(fault)
    if fault=='profile_path':
        profile=tmp_path/'copied.wprp'
        profile.write_bytes(PROFILE.read_bytes())
        plan['profile']=str(profile)
    if fault=='approval': plan['resource_exceptions']['temporary_disk_hard_quota']=True
    if fault=='old_audit': plan.pop('source_selection_audit_version')
    if fault=='bool_audit': plan['source_selection_audit_version']=True
    if fault=='float_audit': plan['source_selection_audit_version']=1.0
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:SimpleNamespace(free=0 if fault=='space' else 2*1024**3))
    capture=NativeCapture(plan,tmp_path/'not-created'/'native.etl',_backend=backend)
    with pytest.raises((PermissionError,ValueError)):
        capture.preflight()
    assert not backend.commands and not backend.live and not capture.output.parent.exists()


@pytest.mark.parametrize('kind',['etl','directory','still_live','buffer_growth'])
def test_native_stop_budget_and_actual_session_state_are_not_command_exit(tmp_path,monkeypatch,kind):
    import secure_control.experiments.native_tail_capture as module
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:SimpleNamespace(free=2*1024**3))
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=Backend())
    backend=Backend('stop_still_live' if kind=='still_live' else None)
    original=backend.run
    def run(args,timeout):
        result=original(args,timeout)
        if args[0]=='-stop' and kind in ('etl','directory'):
            file=Path(args[1]) if kind=='etl' else tmp_path/'merge-temporary.bin'
            with file.open('wb') as stream:
                stream.truncate((65 if kind=='etl' else 257)*1024*1024)
        return result
    backend.run=run
    capture=NativeCapture(plan,tmp_path/'native.etl',_backend=backend,_now=lambda:0.)
    capture.begin()
    if kind=='buffer_growth':
        snapshot=backend.sessions
        def grown():
            rows=snapshot()
            if rows:rows[0]['buffers']=129
            return rows
        backend.sessions=grown
    report=capture.finish()
    if kind=='still_live':
        assert report['status']=='stop_unverified_manual_attention' and backend.live
    elif kind=='buffer_growth':
        assert report['status']=='partial' and report['native_buffer_budget_exceeded']
    else:
        assert report['status']=='partial' and report['resource_budget_exceeded']
        assert (tmp_path/'native.etl').exists() and not report['temporary_peak_verified']
    assert report['resource_exceptions']['authorization']==module.AUTHORIZATION
    assert report['manual_recovery']['status'][-1]==capture.instance


@pytest.mark.parametrize('fault',[None,'mixed','no_approval','old_approval','wrong_enable','missing_enable','pre_enable','pre_legacy','paged','missing_mode','mode_at_stop','old_audit','old_profile','budget'])
def test_file_calibration_is_separate_plan_and_checks_own_actual_provider(tmp_path,monkeypatch,fault):
    from secure_control.experiments import native_tail_capture as m
    profile=PROFILE.with_name('control-tail-calibration.wprp')
    plan=prepare_native(profile,_schemas=schemas(),_backend=Backend(),_file_candidate=True)
    assert plan['schema']=='native-calibration-preparation-v1' and plan['logging_mode']=='File'
    assert plan['etl_limit_bytes']==128*1024*1024
    class FileBackend(Backend):
        stopping=False
        def run(self,args,timeout):
            if args[0]=='-stop':self.stopping=True
            return super().run(args,timeout)
        def sessions(self):
            rows=super().sessions()
            for i,row in enumerate(rows):
                row['logger_id']=100+i
                row['log_file_mode']=0x01000001 if fault=='paged' or fault=='mode_at_stop' and self.stopping else 1
                if fault=='missing_mode':row.pop('log_file_mode')
            return rows
        def provider_enables(self):
            rows = [] if fault=='missing_enable' else [{'logger_id':101,'enabled':1,'provider_pid':0,
                'level':4 if fault=='wrong_enable' else 5,'match_any':0x600000484,'match_all':0,
                'instance_flags':2 if fault=='pre_enable' else 3 if fault=='pre_legacy' else 0}]
            if fault=='mixed':rows.append({**rows[0],'instance_flags':2})
            return rows
    backend=FileBackend()
    approval={'schema':'native-calibration-authorization-v1','plan_sha256':m.plan_digest(plan),
              'authorization_url':'https://github.com/GNYKCZ/secure_pid_hvac/issues/153#issuecomment-9999999999'}
    if fault=='no_approval': approval=None
    if fault=='old_approval': approval['authorization_url']=m.AUTHORIZATION
    if fault=='old_audit':plan['source_selection_audit_version']=1
    if fault=='old_profile': plan['profile']=str(PROFILE.resolve())
    if fault=='budget': plan['etl_limit_bytes']+=1
    monkeypatch.setattr(m.shutil,'disk_usage',lambda path:SimpleNamespace(free=3*1024**3))
    capture=NativeCapture(plan,tmp_path/'candidate.etl',_backend=backend,_now=lambda:0.,authorization=approval)
    if fault and fault not in ('mixed','mode_at_stop'):
        with pytest.raises((PermissionError,ValueError)):capture.begin()
        if fault in ('wrong_enable','missing_enable','pre_enable','pre_legacy','paged','missing_mode'):
            assert [a[0] for a in backend.commands]==['-start','-cancel']
        else: assert not backend.commands
        return
    capture.begin()
    assert capture.capture_deadline==55 and backend.commands[0][1].endswith('!D20')
    if fault=='mode_at_stop':backend.stopping=True
    assert (capture.finish()['status']=='saved')==(fault!='mode_at_stop')
    with pytest.raises(ValueError):profile_contract(profile,schemas())


def test_enable_snapshot_decoder_preserves_logger_mask_and_rejects_truncation():
    import struct

    from secure_control.experiments.native_tail_capture import _decode_provider_enables
    raw=struct.pack('<II',1,0)+struct.pack('<IIII',0,1,0,2)+struct.pack('<IBBHIIQQ',1,5,0,42,0,0,0x600000484,0)
    rows=_decode_provider_enables(raw)
    assert rows[0]['logger_id']==42 and rows[0]['match_any']==0x600000484 and rows[0]['enabled']==1
    for n in (0,4,8,23,len(raw)-1):
        with pytest.raises(ValueError):_decode_provider_enables(raw[:n])


@pytest.mark.parametrize('value',[None,'false'])
def test_file_profile_requires_nonpaged_buffers(tmp_path,value):
    """内核TCPIP不能写分页会话；遗漏属性不能通过只读契约。"""
    profile=PROFILE.with_name('control-tail-calibration.wprp')
    import xml.etree.ElementTree as ET
    root=ET.fromstring(profile.read_bytes());provider=root.find('./Profiles/EventProvider')
    provider.attrib.pop('NonPagedMemory',None)
    if value is not None:provider.set('NonPagedMemory',value)
    path=tmp_path/'paged.wprp';ET.ElementTree(root).write(path)
    with pytest.raises(ValueError):profile_contract(path,schemas(),file_candidate=True)


def test_session_query_reads_actual_log_file_mode_at_sdk_offset(monkeypatch):
    """独立手写EVENT_TRACE_PROPERTIES布局，核对模式来自64字节处。"""
    import ctypes as ct
    import struct

    from secure_control.experiments import native_tail_capture as m
    class Query:
        def __call__(self,pointers,capacity,count):
            raw=bytearray(4216)
            struct.pack_into('<I',raw,116,120)
            struct.pack_into('<I',raw,64,0x01000001)
            raw[120:130]='test'.encode('utf-16le')+b'\0\0'
            ct.memmove(pointers[0],bytes(raw),len(raw))
            ct.cast(count,ct.POINTER(ct.c_uint32))[0]=1
            return 0
    monkeypatch.setattr(m.ctypes,'WinDLL',lambda _:SimpleNamespace(QueryAllTracesW=Query()))
    assert m._sessions()[0]['log_file_mode']==0x01000001


def test_prepare_file_snapshot_is_observation_not_own_enable_proof():
    """其他会话已注册只是准备快照，仍须begin重新核验自己的会话。"""
    backend=Backend()
    plan=prepare_native(PROFILE.with_name('control-tail-calibration.wprp'),
        _schemas=schemas(),_backend=backend,_file_candidate=True)
    assert plan['source_selection_audit_version']==2
    assert plan['native_nonpaged_buffer_bytes']==12*1024*1024
    assert plan['provider_snapshot_at_prepare']['enabled_instances']==[]
    assert plan['provider_snapshot_at_prepare']['qpc_ns']>0
    assert 'not own-session' in plan['provider_snapshot_at_prepare']['scope']
    assert [a[0] for a in backend.commands]==['-profiledetails']
