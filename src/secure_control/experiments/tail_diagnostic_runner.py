"""一次有界本机诊断装配；调用原角色/runner和原worker，不复制控制循环。"""
from __future__ import annotations

import gc
import hashlib
import json
import multiprocessing as mp
import os
import platform
import queue
import re
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from secure_control.execution.diagnostic_limits import limits_for
from secure_control.execution.tail_diagnostics import SCHEMA, DiagnosticContext, TailRecorder

PROFILE = 'control-dynamic-matrix-preauthorized-v2'
ROOT = Path(__file__).resolve().parents[3]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _common_sha(path):
    """跨Windows checkout只容忍源码文本的CRLF/LF差异；本机保护仍校验原字节。"""
    path = Path(path)
    data = path.read_bytes()
    if path.suffix in ('.py','.toml','.lock'):
        data = data.replace(b'\r\n',b'\n')
    return hashlib.sha256(data).hexdigest()


def _write_new(path, value):
    with Path(path).open('x',encoding='utf8') as stream:
        json.dump(value,stream,ensure_ascii=False,allow_nan=False,separators=(',',':'))


def _request_stop(control, stop, deadline, completed, maximum):
    """真实确认数限步；慢标签不参与停止，sample容量不参与判断。"""
    if completed >= maximum or stop.is_set() or time.perf_counter() >= deadline:
        control.request_stop()


def _role_child(role, ports, context, results, stop, deadline, steps):
    from secure_control.experiments.communication_benchmark import _config
    config = replace(_config(role,ports),wire_profile=PROFILE,startup_timeout=20.,
                     step_timeout=2.,idle_timeout=10.,shutdown_timeout=2.)
    if role == 'Client':
        config = replace(config,client_io='ready-v1')
    _configured_child(config,context,results,stop,deadline,steps)


def _configured_child(config, context, results, stop, deadline, steps, activity=None, stream_map=False, control_file=False, b_receive_boundary=False):
    """仅装配原角色；两机模式保留加载的配置和原业务循环。"""
    role = config.role
    limits = limits_for(context.window)
    recorder = TailRecorder(context,role,stream_map=stream_map and role == 'Client',
        **({'party_receive_map':True} if b_receive_boundary and role in ('P1','P2') else {})).start()
    if control_file and role in ('P1','P2'):
        # 复用已有首请求观察点，只报告一次业务起点，不修改协议或增加网络流量。
        emit = recorder.emit
        observed = [False]
        def first_request(phase,*args,**kwargs):
            if phase=='request_receive' and not observed[0]:
                observed[0]=True
                with activity.get_lock():
                    if not activity.value:activity.value=time.perf_counter()
            return emit(phase,*args,**kwargs)
        recorder.emit=first_request

    result = {'role':role,'pid':os.getpid(),'parent_pid':os.getppid(),'status':'failed'}
    try:
        if activity is not None:
            actual = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
            if actual != context.source_head:
                raise ValueError('子进程源码HEAD变更')
        if role == 'Client':
            from secure_control.execution.lan_runtime import RunControl
            from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
            from secure_control.experiments.lan_runner import _run_prepared_segmented
            from secure_control.experiments.live_timing import LiveTimingCollector, timing_metadata
            from secure_control.scenarios.cart_pole.interactive import InteractiveSession
            session, control = InteractiveSession(),RunControl()
            prepared = load_segmented_experiment(config.experiment_config,limits.segment_steps,session)
            if activity is not None and prepared.scene.period != .02:
                raise ValueError('双机诊断保持20ms模型周期')
            collector = LiveTimingCollector('samples',sample_limit=steps)
            metadata = timing_metadata(config,prepared,non_realtime=True,mode='samples')
            attempts = 0

            def before_sample():
                nonlocal attempts
                if activity is not None and activity.value == 0:
                    activity.value = time.perf_counter()
                limit = min(deadline,activity.value+(55 if control_file else limits.activity_s)) if activity is not None else deadline
                if activity is not None and (attempts >= steps or stop.is_set() or time.perf_counter() >= limit):
                    raise TimeoutError('诊断活动/attempt边界停止')
                _request_stop(control,stop,limit,attempts,steps)
                attempts += 1

            def on_step(record):
                _request_stop(control,stop,deadline,record.protocol.global_step+1,steps)

            outcome = _run_prepared_segmented(config,prepared,control=control,session=session,
                on_step=on_step,before_sample=before_sample,non_realtime=True,
                timing_observer=collector,material_slots=16)
            result.update(status=outcome.get('status'),outcome=outcome,
                          timing=collector.report(),metadata=metadata,attempt_callbacks=attempts)
        else:
            from secure_control.execution.lan_runtime import run_party_single_step
            outcome = run_party_single_step(config,batch=True,wire_profile=PROFILE)
            result.update(status=outcome.get('status'),outcome=outcome)
        if result['status'] not in ('stopped','closed'):
            stop.set()
    except Exception as error:  # noqa: BLE001 - 仅导出类别，不输出秘密/异常文本。
        result['error_type'] = type(error).__name__
        stop.set()
    finally:
        result['diagnostic_export'] = recorder.save(result['status'])
        results.put(result)


def _collect_group(ports, context, steps, *, _mp=mp, _now=time.perf_counter):
    """24秒父收集与自身PID树清退；实际>30秒/强退不标成功。"""
    started = _now()
    processes = []
    reports, forced = [], []
    spawn = _mp.get_context('spawn')
    results,stop = spawn.Queue(),spawn.Event()
    try:
        for role in ('P1','P2','Client'):
            if _now()-started >= 24:
                break
            process = spawn.Process(target=_role_child,args=(role,ports,context,results,stop,started+24,steps))
            processes.append(process)
            process.start()
        while len(reports) < len(processes):
            remaining = started+24-_now()
            if remaining <= 0:
                break
            try:
                result = results.get(timeout=remaining)
            except queue.Empty:
                break
            reports.append(result)
            if result.get('status') not in ('stopped','closed'):
                stop.set()
    finally:
        stop.set()
        for process in processes:
            if process.pid is None:
                continue
            process.join(timeout=max(0,min(.25,started+25-_now())))
            if process.is_alive():
                try:
                    killed = subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],
                                            capture_output=True,timeout=1.,check=False)
                    forced.append({'pid':process.pid,'returncode':killed.returncode})
                except (OSError,subprocess.TimeoutExpired) as error:
                    forced.append({'pid':process.pid,'error_type':type(error).__name__})
                if process.is_alive():
                    process.terminate()
                process.join(.25)
        results.close()
        results.cancel_join_thread()
    return {'wall_s':_now()-started,'roles':reports,'forced_cleanup':forced,
            'owned_pids':[p.pid for p in processes],
            'exitcodes':[p.exitcode for p in processes]}


def run_local(output, *, expected_head, software_review, steps=400):
    """显式local命令才启动唯一一组；输出目录/账本/文件均拒覆盖。"""
    if type(steps) is not int or not 1 <= steps <= 400:
        raise ValueError('诊断最多400确认步骤')
    if type(software_review) is not str or not software_review.startswith('https://'):
        raise ValueError('需要当前源码的独立软件审查链接')
    head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if head != expected_head:
        raise ValueError('源码HEAD与冻结计划不符')
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('诊断产物目录已经存在，不能重跑/覆盖')
    if not gc.isenabled() or gc.get_threshold() != (700,10,10):
        raise ValueError('本机诊断保持正常GC及原阈值')
    from secure_control.experiments.communication_benchmark import _config, _ports
    ports = _ports()
    config = _config('Client',ports)
    diagnostic_id,domain = uuid4().hex,uuid4().hex
    dirty = bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip())
    context = DiagnosticContext(diagnostic_id,domain,str(output),head,os.getpid(),
        topology_digest=config.topology.digest,experiment_sha256=_sha(config.experiment_config),source_dirty=dirty)
    paths = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard',
        'src','scripts','configs','pyproject.toml','uv.lock'],cwd=ROOT,text=True).splitlines()
    frozen = {p:_sha(ROOT/p) for p in paths}
    output.mkdir(parents=True,exist_ok=False)
    plan = {'schema':SCHEMA,'diagnostic_id':diagnostic_id,'source_head':head,'source_sha256':frozen,
        'software_review':software_review,'maximum_steps':steps,'group_wall_limit_s':30,
        'segment_steps':400,'material_slots':16,'mode':'non_realtime_demo',
        'profile':PROFILE,'client_io':'ready-v1','ports':ports,'slow_label_ns':5_000_000,
        'scope':'localhost diagnostic only; no performance qualification; no retry'}
    _write_new(output/'plan.json',plan)
    ledger = {'schema':SCHEMA,'diagnostic_id':diagnostic_id,'remaining':0,'status':'reserved',
              'maximum_steps':steps,'maximum_wall_s':30,'plan_sha256':_sha(output/'plan.json')}
    _write_new(output/'ledger.json',ledger)  # 任何角色启动前持久扣减，失败不恢复。
    group = _collect_group(ports,context,steps)
    client = next((r for r in group['roles'] if r['role'] == 'Client'),{})
    samples = client.get('timing',{}).get('raw',{}).get('samples',[])
    material = client.get('outcome',{}).get('material_summary',{})
    functional = (group['wall_s'] <= 30 and not group['forced_cleanup']
        and len(group['roles']) == 3 and group['exitcodes'] == [0,0,0]
        and all(r['status'] in ('stopped','closed') for r in group['roles'])
        and client.get('outcome',{}).get('confirmed_step_count') == steps
        and client.get('outcome',{}).get('protocol_committed_count') == steps
        and material.get('worker_exited') is True and material.get('cleanup_failed') is False)
    timing_complete = (len(samples) == steps and all(s.get('status') == 'confirmed' for s in samples)
                       and [s.get('global_step') for s in samples] == list(range(steps)))
    files, records, errors = [], {}, []
    for role in ('Client','P1','P2','worker'):
        path = output/f'{role}.json'
        try:
            record = json.loads(path.read_text(encoding='utf8'))
            records[role] = record
            files.append({'path':path.name,'sha256':_sha(path)})
        except (OSError,ValueError) as error:
            errors.append({'role':role,'error_type':type(error).__name__})
    members = {r['role']:{'pid':r['pid']} for r in group['roles']}
    worker_pid = (material.get('worker') or {}).get('pid')
    if worker_pid is not None:
        members['worker'] = {'pid':worker_pid}
    verified = (set(records) == set(members) == {'Client','P1','P2','worker'}
        and {r['pid'] for r in group['roles']} == set(group['owned_pids'])
        and all(records[r]['pid'] == m['pid'] for r,m in members.items())
        and records['worker']['parent_pid'] == records['Client']['pid']
        and all(records[r]['parent_pid'] == os.getpid() for r in ('Client','P1','P2'))
        and all(records[r]['clock']['wall'] == records['Client']['clock']['wall'] for r in records))
    source_unchanged = all(_sha(ROOT/p) == sha for p,sha in frozen.items())
    complete = functional and timing_complete and verified and not errors and source_unchanged and all(
        r.get('diagnostic_complete') is True for r in records.values())
    manifest = {'schema':SCHEMA,'diagnostic_id':diagnostic_id,'source_head':head,
        'diagnostic_complete':complete,'functional_complete':functional,'expected_step_count':steps,'clock_domains':{
            domain:{'local_spawn_verified':verified,'launcher_pid':os.getpid(),'members':members,
                    'wall_clock':records.get('Client',{}).get('clock',{}).get('wall')}},
        'files':files,'control_samples':samples,'group':group,'export_errors':errors,
        'source_unchanged':source_unchanged,'last_step_semantics':f'{steps-1} is final stop, not continuing segment maintenance',
        'observation_warning':'diagnostic changes allocation/GC timing; do not compare its durations to uninstrumented D11'}
    # 原控制结果与证据完整性分开；使用同一个离线分析器核验阶段覆盖，避免双套规则。
    from secure_control.experiments.tail_diagnostic_analysis import analyze_records
    try:
        validation = analyze_records(list(records.values()),clock_domains=manifest['clock_domains'],
                                     samples=samples,same_host=True,targets=(),expected_steps=range(steps))
        complete = complete and validation['diagnostic_complete']
    except Exception as error:  # noqa: BLE001 - 观察数据失败只降低证据等级，保留原控制结果。
        errors.append({'role':'analysis','error_type':type(error).__name__})
        complete = False
    manifest.update(diagnostic_complete=complete,timing_complete=timing_complete)
    _write_new(output/'manifest.json',manifest)
    ledger.update(status='complete' if complete else 'failed_or_incomplete',
                  functional_complete=functional,diagnostic_complete=complete,
                  wall_s=group['wall_s'],manifest_sha256=_sha(output/'manifest.json'))
    (output/'ledger.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2),encoding='utf8')
    return manifest


def _clear_owned(processes, deadline, *, _now=time.perf_counter, _run=subprocess.run,
                 _grace_s=.1, _details=None):
    """只处理自有PID；共享有界正常退出宽限，强退尝试与实际退出事实分别保留。"""
    forced = []
    began = _now()
    # 所有成员共用一个宽限，仍预留一秒用于强退；不延长调用者给出的截止。
    grace_deadline = min(began+_grace_s, max(began,deadline-1.))
    for process in processes:
        if process.pid is None:
            continue
        detail = {'pid':process.pid,'force_attempted':False,'terminate_issued':False}
        process.join(timeout=max(0,grace_deadline-_now()))
        if not process.is_alive():
            detail.update(exitcode=process.exitcode,alive_after=False,
                          natural_exit_verified=process.exitcode==0)
            if _details is not None:_details.append(detail)
            continue
        remaining = deadline-_now()
        if remaining<=0:
            detail.update(exitcode=process.exitcode,alive_after=True,natural_exit_verified=False,
                          cleanup_incomplete=True)
            forced.append({'pid':process.pid,'cleanup_incomplete':True,'reason':'deadline_exhausted'})
            if _details is not None:_details.append(detail)
            continue
        detail['force_attempted']=True
        try:
            killed = _run(['taskkill','/PID',str(process.pid),'/T','/F'],
                          capture_output=True,timeout=min(.5,remaining),check=False)
            detail['taskkill_returncode']=killed.returncode
            forced.append({'pid':process.pid,'returncode':killed.returncode})
        except (OSError,subprocess.TimeoutExpired) as error:
            detail['taskkill_error_type']=type(error).__name__
            forced.append({'pid':process.pid,'error_type':type(error).__name__})
        if process.is_alive() and _now()<deadline:
            process.terminate()
            detail['terminate_issued']=True
        process.join(timeout=max(0,min(.1,deadline-_now())))
        detail.update(exitcode=process.exitcode,alive_after=process.is_alive(),
                      natural_exit_verified=False)
        detail['cleanup_incomplete']=detail['alive_after'] or detail['exitcode'] is None
        if _details is not None:_details.append(detail)
    return forced


def _collect_host(configs, context, steps, *, wall_started=None, stream_map=False, native=None, control_file=False, b_receive_boundary=False, _mp=mp, _now=time.perf_counter, _child=None, _baseline=False):
    """按声明窗口监督实际成员；无跨机时钟或额外连接。"""
    started = _now() if wall_started is None else wall_started
    limits = limits_for(context.window if context is not None else 400)
    run_deadline = started+(110 if b_receive_boundary and configs[0].role!='Client' else 100 if control_file else limits.wall_s-3)
    if _baseline:
        run_deadline = started+(110 if configs[0].role != 'Client' else 90)
    spawn = _mp.get_context('spawn')
    results, stop, activity = spawn.Queue(), spawn.Event(), spawn.Value('d',0.)
    processes, reports, reason, launcher_error = [], [], None, None
    native_report = None
    try:
        if native is not None:
            native.begin()
            (native.output.parent/'native-owner.json').write_text(
                json.dumps(native.report,ensure_ascii=False,indent=2),encoding='utf8')
        for config in configs:
            if _now() >= run_deadline:
                reason = 'wall_limit'
                break
            process = spawn.Process(target=_configured_child if _child is None else _child,
                args=(config,context,results,stop,run_deadline,steps,activity,stream_map,
                      *([True,True] if b_receive_boundary else [True] if control_file else [])))
            processes.append(process)
            process.start()
        while len(reports) < len(processes):
            now = _now()
            if b_receive_boundary and native is not None and configs[0].role!='Client' and activity.value:
                native.capture_deadline=min(native.capture_deadline,activity.value+55)
            if control_file and configs[0].role!='Client' and (
                    not activity.value and now>=started+45 or activity.value and now>=activity.value+55):
                reason='control_wait_or_business_limit';break
            if native is not None and now>=native.capture_deadline:
                reason = 'native_window_limit'
                break
            if now >= run_deadline or activity.value and now >= activity.value+(55 if control_file else limits.activity_s):
                reason = 'wall_limit' if now >= run_deadline else 'activity_limit'
                break
            try:
                report = results.get(timeout=min(.1,max(.001,run_deadline-now)))
            except queue.Empty:
                if any(p.exitcode is not None and p.exitcode != 0 for p in processes):
                    reason = 'child_exit'
                    break
                continue
            reports.append(report)
            if report.get('status') not in ('stopped','closed'):
                reason = 'first_functional_failure'
                break
    except KeyboardInterrupt:
        reason, launcher_error = 'user_interrupted', 'KeyboardInterrupt'
    except Exception as error:  # noqa: BLE001 - 启动失败也冻结partial，不重试或丢弃已用账本。
        reason, launcher_error = 'launcher_failure', type(error).__name__
    finally:
        stop.set()
        cleanup_deadline = started+limits.wall_s-1
        if _baseline:
            cleanup_deadline = started+(120 if configs[0].role != 'Client' else 100)
        if native is not None and native.started is not None:
            # 原生窗口包含退出时间，不能让业务清退一直占用240秒总预算。
            cleanup_deadline = min(cleanup_deadline,native.capture_deadline)
        cleanup_details = []
        forced = _clear_owned(processes,cleanup_deadline,_now=_now,
            _grace_s=1. if reason is None and len(reports)==len(processes) else .1,
            _details=cleanup_details)
        if native is not None:
            try:
                native_report = native.finish()
            except Exception as error:  # noqa: BLE001 - 保留业务退出和本次采集故障，不重启会话。
                native_report = {'status':'partial','error_type':type(error).__name__}
        results.close()
        results.cancel_join_thread()
    return {'wall_s':_now()-started,'roles':reports,'forced_cleanup':forced,
        'cleanup_details':cleanup_details,
        'owned_pids':[p.pid for p in processes],'exitcodes':[p.exitcode for p in processes],
        'members':{c.role:{'pid':p.pid} for c,p in zip(configs,processes,strict=False)},
        'stop_reason':reason,'launcher_error':launcher_error,'activity_start':activity.value or None,
        **({'native':native_report} if native is not None else {}),
        'activity_elapsed_s':None if not activity.value else _now()-activity.value}


def _config_identity(config):
    """只冻结公开配置语义，私钥和秘密内容不进入诊断。"""
    return {'role':config.role,'topology_digest':config.topology.digest,
        'transport':config.transport,'wire_profile':config.wire_profile,'client_io':config.client_io,
        'experiment_sha256':None if config.experiment_config is None else _sha(config.experiment_config),
        'timeouts':{name:getattr(config,name+'_timeout') for name in ('startup','step','idle','shutdown')}}


def run_host(side, output, *, diagnostic_id, expected_head, software_review, config_paths, steps=400, stream_map=False, window=400, native_plan=None, authorization=None):
    """显式两机一次采集；同ID本端账本拒绝换目录重跑，原local入口保持。"""
    wall_started = time.perf_counter()
    limits = limits_for(window)
    from secure_control.execution.lan_config import load_lan_config
    if type(stream_map) is not bool or stream_map and side != 'client':
        raise ValueError('流映射只可显式用于A端')
    b_receive_boundary=bool(native_plan and native_plan.get('purpose')=='control-b-receive-boundary-v1')
    control_file = bool(native_plan and native_plan.get('purpose')=='control-slow-step-v1') or b_receive_boundary
    if authorization is not None and not control_file:
        raise PermissionError('control approval requires control-purpose plan')
    if native_plan is not None and (window!=2000 or side!='client' and not control_file):
        raise ValueError('原生专项只支持显式A端2000窗口')
    if window!=400 and side=='client' and (not stream_map or native_plan is None):
        raise ValueError('2000步专项须同时具备公开stream map和经审查原生准备计划')
    if side not in ('client','pair') or type(steps) is not int or not 1 <= steps <= limits.window:
        raise ValueError('诊断端或attempt上限无效')
    if not isinstance(diagnostic_id,str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',diagnostic_id) is None:
        raise ValueError('诊断ID只能使用1至64个字母数字下划线或短横线')
    if type(software_review) is not str or not software_review.startswith('https://'):
        raise ValueError('需要当前源码独立软件审查链接')
    head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if head != expected_head:
        raise ValueError('源码HEAD与计划不符')
    if native_plan is not None and native_plan.get('source_head')!=head:
        raise ValueError('原生准备head与本机不一致')
    roles = ('Client',) if side == 'client' else ('P1','P2')
    if len(config_paths) != len(roles):
        raise ValueError('本端配置数量不符')
    configs = [load_lan_config(p,r) for p,r in zip(config_paths,roles,strict=True)]
    if (len({c.topology.digest for c in configs}) != 1
            or any(c.transport != 'insecure_tcp' or c.wire_profile != PROFILE for c in configs)
            or side == 'client' and (configs[0].client_io != 'ready-v1' or configs[0].experiment_config is None)):
        raise ValueError('两机诊断必须为匹配的无证书preauthorized-v2/Client ready-v1配置')
    if not gc.isenabled() or gc.get_threshold() != (700,10,10):
        raise ValueError('诊断保持正常GC及原阈值')
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('输出目录已存在，不能重跑')
    if control_file:
        from secure_control.experiments.native_tail_capture import authorize_control, plan_digest
        from secure_control.experiments.tail_calibration import _source_clean
        if steps!=2000 or not _source_clean():raise ValueError('control source/steps changed')
        if native_plan.get('software_review')!=software_review:raise ValueError('control review changed')
        if b_receive_boundary:
            from secure_control.experiments.native_tail_capture import authorize_receive
            authorize_receive(authorization,native_plan,side=side,output=output,head=head,
                diagnostic_id=diagnostic_id,configurations=[_config_identity(c) for c in configs])
        else:
            authorize_control(authorization,native_plan,side=side,output=output,head=head,
                diagnostic_id=diagnostic_id,configurations=[_config_identity(c) for c in configs])
    native = None
    native_preflight = None
    exceptions = {}
    if window==2000:
        from secure_control.experiments.native_tail_capture import (
            NativeCapture,
            resource_exceptions,
        )
        if control_file:
            from secure_control.experiments.native_tail_capture import _exceptions_for
            exceptions = _exceptions_for(native_plan['hosts'][side] if b_receive_boundary else native_plan)
        else:exceptions = resource_exceptions()
        if side=='client' or b_receive_boundary:
            node=native_plan['hosts'][side] if b_receive_boundary else native_plan
            native = NativeCapture(node,output/('native-a.etl' if side=='client' else 'native-b.etl'),
                **({'authorization':authorization} if control_file else {}),
                **({'authorization_plan':native_plan,'side':side} if b_receive_boundary else {}))
            native_preflight = native.preflight()  # 只读；管理员/profile/source/空间/冲突均在账本与子进程前拒绝。
    paths = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard',
        'src','scripts','configs','pyproject.toml','uv.lock'],cwd=ROOT,text=True).splitlines()
    frozen = {p:_sha(ROOT/p) for p in paths}
    dirty = bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip())
    context = DiagnosticContext(diagnostic_id,uuid4().hex,str(output),head,os.getpid(),
        topology_digest=configs[0].topology.digest,source_dirty=dirty,
        experiment_sha256=_sha(configs[0].experiment_config) if side == 'client' else '',window=window)
    identities = [_config_identity(c) for c in configs]
    # 共享源码摘要不含机器部署配置；角色配置通过公开语义摘要单独核验。
    common = {p:_common_sha(ROOT/p) for p in frozen if not p.startswith('configs/')}
    version = {'schema':limits.trace_schema,
        **({'limits':limits.payload()} if window!=400 else {})}
    plan = {**version,'diagnostic_id':diagnostic_id,'source_head':head,'side':side,
        **({'resource_exceptions':exceptions} if exceptions else {}),
        **({'native_preparation':native_plan,'native_preflight':native_preflight} if native is not None else {}),
        'stream_map':stream_map,
        **({'control_plan_sha256':plan_digest(native_plan),
            'control_authorization':authorization} if control_file else {}),
        'source_sha256':frozen,'common_source_sha256':common,'software_review':software_review,
        'common_source_hash_mode':'sha256: CRLF to LF for .py/.toml/.lock; raw bytes otherwise',
        'source_dirty':dirty,'configurations':identities,'maximum_steps':steps,
        'group_wall_limit_s':120 if b_receive_boundary and side=='pair' else 100 if control_file else limits.wall_s,'activity_limit_s':55 if control_file else limits.activity_s,'segment_steps':limits.segment_steps,'material_slots':16,
        'mode':'non_realtime_diagnostic','profile':PROFILE,'client_io':'ready-v1',
        'topology_digest':configs[0].topology.digest,'python':platform.python_version(),
        'platform':platform.platform(),'launcher_pid':os.getpid(),'clock_domain_id':context.clock_domain_id,
        'scope':'one user-started two-host group; no retry; no realtime qualification'}
    ledger = {**version,'diagnostic_id':diagnostic_id,'side':side,
        'two_host_2000' if window!=400 else 'one_two_host':0,
        'status':'reserved','output':str(output),'maximum_steps':steps,'maximum_wall_s':120 if b_receive_boundary and side=='pair' else 100 if control_file else limits.wall_s}
    ledger_root = ROOT/'results'/'tail_diagnostics'
    ledger_root.mkdir(parents=True,exist_ok=True)
    ledger_path = ledger_root/f'session-{diagnostic_id}-{side}.ledger.json'
    _write_new(ledger_path,ledger)  # 本端永久扣减；B没有连上也不恢复。
    output.mkdir(parents=True,exist_ok=False)
    _write_new(output/'plan.json',plan)
    _write_new(output/'ledger.json',ledger)
    extra = {'stream_map':True} if stream_map else {}
    if control_file:extra['control_file']=True
    if b_receive_boundary:extra['b_receive_boundary']=True
    if native is not None:
        # 首个provider之前留下唯一instance与精确恢复命令，父进程异常时仍可找到。
        _write_new(output/'native-owner.json',native.report)
        extra['native'] = native
    group = _collect_host(configs,context,steps,wall_started=wall_started,**extra)
    if native is not None:
        (output/'native-owner.json').write_text(json.dumps(native.report,ensure_ascii=False,indent=2),encoding='utf8')
    records, files, errors = {}, [], []
    expected_roles = (*roles,'worker') if side == 'client' else roles
    for role in expected_roles:
        path = output/f'{role}.json'
        try:
            records[role] = json.loads(path.read_text(encoding='utf8'))
            files.append({'path':path.name,'sha256':_sha(path)})
        except (OSError,ValueError) as error:
            errors.append({'role':role,'error_type':type(error).__name__})
    client = next((r for r in group['roles'] if r['role']=='Client'),{})
    material = client.get('outcome',{}).get('material_summary',{})
    members = dict(group['members'])
    if side == 'client' and (material.get('worker') or {}).get('pid') is not None:
        members['worker'] = {'pid':material['worker']['pid']}
    wall_clock = next(iter(records.values()),{}).get('clock',{}).get('wall')
    verified = (set(records) == set(members) == set(expected_roles)
        and {m['pid'] for r,m in members.items() if r != 'worker'} == set(group['owned_pids'])
        and all(r['pid'] == members[role]['pid'] and r['parent_pid'] ==
            (members['Client']['pid'] if role == 'worker' else os.getpid())
            and r['context']['clock_domain_id'] == context.clock_domain_id
            and r['clock']['wall'] == wall_clock for role,r in records.items()))
    try:
        unchanged = all(_sha(ROOT/p) == sha for p,sha in frozen.items())
    except OSError:
        unchanged = False
    functional = (not group['forced_cleanup'] and group['stop_reason'] is None and group['wall_s'] <= limits.wall_s
        and len(group['roles']) == len(roles) and all(code == 0 for code in group['exitcodes'])
        and all(r['status'] in ('stopped','closed') for r in group['roles']))
    if b_receive_boundary:functional=functional and group['wall_s']<=(120 if side=='pair' else 100)
    samples = client.get('timing',{}).get('raw',{}).get('samples',[])
    if side == 'client':
        functional = (functional and client.get('outcome',{}).get('confirmed_step_count') == steps
            and client.get('outcome',{}).get('protocol_committed_count') == steps
            and material.get('worker_exited') is True and material.get('cleanup_failed') is False
            and group['activity_elapsed_s'] is not None and group['activity_elapsed_s'] <= limits.activity_s
            and len(samples) == steps and all(s.get('status') == 'confirmed' for s in samples))
    complete = functional and verified and unchanged and not errors and all(
        r.get('diagnostic_complete') is True for r in records.values())
    if native is not None:
        # 只有实际持有采集owner的A端需要native.saved，B仅携带同计划作批准绑定。
        complete = complete and group.get('native',{}).get('status')=='saved'
    manifest = {**version,'diagnostic_id':diagnostic_id,'source_head':head,'side':side,
        **({'resource_exceptions':exceptions} if exceptions else {}),
        'diagnostic_complete':complete,'functional_complete':functional,'expected_step_count':steps,
        'mode':'non_realtime_diagnostic','clock_domains':{context.clock_domain_id:{
            'local_spawn_verified':verified,'launcher_pid':os.getpid(),'members':members,'wall_clock':wall_clock}},
        'files':files,'control_samples':samples,'group':group,'export_errors':errors,'source_unchanged':unchanged,
        'plan_sha256':_sha(output/'plan.json'),'plan':plan,'strict_qualification':False,
        'last_step_semantics':f'{steps-1} is final stop; no continuing segment maintenance',
        'observation_warning':'diagnostic changes allocation/GC; cross-host absolute ns cannot be subtracted'}
    if control_file and side=='client':
        # 停止后唯一有界读取；失败保留原件，并将缺证据写入manifest，不补跑。
        try:
            from secure_control.experiments.tail_calibration import _peak_memory, _save
            from secure_control.experiments.windows_tail_analysis import read_calibration_etl
            record=records['Client']
            trace=read_calibration_etl(output/'native-a.etl',pid=record['pid'],tid=record['main_thread_id'],
                window_ns=[samples[0]['actual_sample_start_ns'],samples[-1]['work_completed_ns']])
            _save(output/'control-native-events.json',trace['events'])
            view={k:v for k,v in trace.items() if k!='events'}
            view.update(purpose='control-slow-step-v1',source_head=head,diagnostic_id=diagnostic_id,
                etl_sha256=_sha(output/'native-a.etl'),process_peak_working_set_bytes=_peak_memory())
            view['memory_target_met']=view['process_peak_working_set_bytes']<=512*1024*1024
            if not view['memory_target_met'] or not view.get('complete') or not view.get('schedule_window_complete'):
                manifest['diagnostic_complete']=False
            _save(output/'control-native-view.json',view)
            manifest['native_evidence']={'status':'read','files':{n:_sha(output/n) for n in
                ('native-a.etl','control-native-events.json','control-native-view.json','Client.stream.json')}}
        except Exception as error:  # noqa: BLE001 - 只读失败不篡改已完成控制结果。
            manifest['native_evidence']={'status':'partial','error_type':type(error).__name__}
            manifest['diagnostic_complete']=False
    if b_receive_boundary and side=='pair':
        try:
            from secure_control.experiments.tail_calibration import _peak_memory, _save
            from secure_control.experiments.windows_tail_analysis import read_party_requests_etl
            receive_maps={r:json.loads((output/(r+'.receive.json')).read_text(encoding='utf8')) for r in roles}
            if any(not s.get('complete') or s['role_file_sha256']!=_sha(output/(r+'.json')) for r,s in receive_maps.items()):
                raise ValueError('Party receive map incomplete')
            if any(sorted(row[7] for row in s['rows'] if row[9]==2)!=list(range(steps)) for s in receive_maps.values()):
                raise ValueError('Party validated request coverage incomplete')
            trace=read_party_requests_etl(output/'native-b.etl',targets=[(records[r]['pid'],records[r]['main_thread_id']) for r in roles])
            _save(output/'request-native-events.json',trace['events'])
            view={k:v for k,v in trace.items() if k!='events'}
            view.update(purpose='control-b-receive-boundary-v1',source_head=head,diagnostic_id=diagnostic_id,
                etl_sha256=_sha(output/'native-b.etl'),process_peak_working_set_bytes=_peak_memory())
            view['memory_target_met']=view['process_peak_working_set_bytes']<=512*1024*1024
            _save(output/'request-native-view.json',view)
            if not view['memory_target_met'] or not trace.get('complete'):manifest['diagnostic_complete']=False
            manifest['b_request_evidence']={'status':'read','files':{n:_sha(output/n) for n in
                ('native-b.etl','request-native-events.json','request-native-view.json','P1.receive.json','P2.receive.json')}}
        except Exception as error:  # noqa: BLE001 - 新观测失败保留功能结果、原件与单次扣额。
            manifest['b_request_evidence']={'status':'partial','error_type':type(error).__name__}
            manifest['diagnostic_complete']=False
    _write_new(output/'manifest.json',manifest)
    if stream_map:
        # 独立链接不扩展旧v1 manifest/事件schema；sidecar丢失不伪造成功。
        sidecar = output/'Client.stream.json'
        _write_new(output/'stream-link.json',{'schema':'client-stream-map-link-v1',
            'manifest':'manifest.json','manifest_sha256':_sha(output/'manifest.json'),
            'sidecar':'Client.stream.json','sidecar_sha256':_sha(sidecar) if sidecar.is_file() else None})
    ledger.update(status='complete' if manifest['diagnostic_complete'] else 'partial',manifest_sha256=_sha(output/'manifest.json'),
                  functional_complete=functional,diagnostic_complete=manifest['diagnostic_complete'],wall_s=group['wall_s'])
    for path in (ledger_path,output/'ledger.json'):
        path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2),encoding='utf8')
    return manifest
