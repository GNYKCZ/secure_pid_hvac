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
        result.append({'id':event,'version':0,'fields':[{'name':n,'type':t,'flags':f} for n,t,f in names]})
    return result


class Backend:
    """模拟本次唯一instance，命令列表可审计，没有subprocess调用。"""

    def __init__(self,fault=None):
        self.fault=fault
        self.commands=[]
        self.instance=None
        self.live=False
        self.changed=False

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
            self.live=False
        if args[0]=='-cancel': self.live=False
        return SimpleNamespace(returncode=0,stdout=b'profile parsed; fake-only')


def test_preparation_never_issues_start_stop_or_cancel():
    backend=Backend()
    plan=prepare_native(PROFILE,_schemas=schemas(),_backend=backend)
    assert [a[0] for a in backend.commands]==['-profiledetails']
    assert plan['native_buffer_bytes']==12582912 and plan['window']==2000
    assert plan['prepared_not_captured'] and not plan['real_capture_verified']


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
