"""一次有界本机诊断装配；调用原角色/runner和原worker，不复制控制循环。"""
from __future__ import annotations

import gc
import hashlib
import json
import multiprocessing as mp
import os
import queue
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from secure_control.execution.tail_diagnostics import SCHEMA, DiagnosticContext, TailRecorder

PROFILE = 'control-dynamic-matrix-preauthorized-v2'
ROOT = Path(__file__).resolve().parents[3]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_new(path, value):
    with Path(path).open('x',encoding='utf8') as stream:
        json.dump(value,stream,ensure_ascii=False,allow_nan=False,separators=(',',':'))


def _request_stop(control, stop, deadline, completed, maximum):
    """真实确认数限步；慢标签不参与停止，sample容量不参与判断。"""
    if completed >= maximum or stop.is_set() or time.perf_counter() >= deadline:
        control.request_stop()


def _role_child(role, ports, context, results, stop, deadline, steps):
    recorder = TailRecorder(context,role).start()
    result = {'role':role,'pid':os.getpid(),'parent_pid':os.getppid(),'status':'failed'}
    try:
        from secure_control.experiments.communication_benchmark import _config
        config = replace(_config(role,ports),wire_profile=PROFILE,startup_timeout=20.,
                         step_timeout=2.,idle_timeout=10.,shutdown_timeout=2.)
        if role == 'Client':
            config = replace(config,client_io='ready-v1')
            from secure_control.execution.lan_runtime import RunControl
            from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
            from secure_control.experiments.lan_runner import _run_prepared_segmented
            from secure_control.experiments.live_timing import LiveTimingCollector, timing_metadata
            from secure_control.scenarios.cart_pole.interactive import InteractiveSession
            session, control = InteractiveSession(),RunControl()
            prepared = load_segmented_experiment(config.experiment_config,400,session)
            collector = LiveTimingCollector('samples',sample_limit=steps)
            metadata = timing_metadata(config,prepared,non_realtime=True,mode='samples')

            def before_sample():
                _request_stop(control,stop,deadline,0,steps)

            def on_step(record):
                _request_stop(control,stop,deadline,record.protocol.global_step+1,steps)

            outcome = _run_prepared_segmented(config,prepared,control=control,session=session,
                on_step=on_step,before_sample=before_sample,non_realtime=True,
                timing_observer=collector,material_slots=16)
            result.update(status=outcome.get('status'),outcome=outcome,
                          timing=collector.report(),metadata=metadata)
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
        'diagnostic_complete':complete,'functional_complete':functional,'clock_domains':{
            domain:{'local_spawn_verified':verified,'launcher_pid':os.getpid(),'members':members,
                    'wall_clock':records.get('Client',{}).get('clock',{}).get('wall')}},
        'files':files,'control_samples':samples,'group':group,'export_errors':errors,
        'source_unchanged':source_unchanged,'last_step_semantics':f'{steps-1} is final stop, not continuing segment maintenance',
        'observation_warning':'diagnostic changes allocation/GC timing; do not compare its durations to uninstrumented D11'}
    # 原控制结果与证据完整性分开；使用同一个离线分析器核验阶段覆盖，避免双套规则。
    from secure_control.experiments.tail_diagnostic_analysis import analyze_records
    try:
        validation = analyze_records(list(records.values()),clock_domains=manifest['clock_domains'],
                                     samples=samples,same_host=True,targets=())
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
