"""只读公开诊断；同机求交、异域分轴，不从相关性或CPU零值猜测系统根因。"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

from secure_control.execution.diagnostic_limits import artifact_limits
from secure_control.execution.tail_diagnostics import PHASES, SPAN_PHASES

_NAMES = {v:k for k,v in PHASES.items()}


def _union(intervals):
    total, right = 0, None
    for start,end in sorted(intervals):
        total += max(0, end-max(start, right if right is not None else start))
        right = max(end, right if right is not None else end)
    return total


def _distribution(values):
    """保留全分母的工作时长摘要；维护分类由实际计时字段决定。"""
    work = sorted(values)
    return {'count':len(work),'mean_ns':sum(work)/len(work) if work else None,
        'max_ns':max(work,default=None),'above_20ms':sum(v>20_000_000 for v in work),
        'quantiles_ns':{label:work[math.ceil(len(work)*p)-1] if work else None
                        for label,p in (('p50',.5),('p95',.95),('p99',.99))}}


def gc_intersections(events, start_ns, end_ns):
    """只计真实控制窗口内交集；缺端点不造零时长，重叠区间不重复收费。"""
    if type(start_ns) is not int or type(end_ns) is not int or start_ns > end_ns:
        raise ValueError('真实运行窗口无效')
    clipped, intervals, complete = [], [], True
    for event in events:
        start, end = event['start_ns'], event['end_ns']
        if start is None or end is None:
            complete = False
            continue
        if type(start) is not int or type(end) is not int or start > end:
            raise ValueError('GC端点无效')
        left,right = max(start,start_ns),min(end,end_ns)
        if left < right:
            clipped.append({**event,'overlap_ns':right-left,'clipped_start_ns':left,'clipped_end_ns':right})
            intervals.append((left,right))
    return {'events':clipped,'overlap_ns':_union(intervals),'complete':complete}


def _decode(record):
    limits = artifact_limits(record)
    if record.get('role') not in ('Client','P1','P2','worker'):
        raise ValueError('不支持的角色/诊断schema')
    if type(record.get('buffer_bytes')) is not int or not 0 < record['buffer_bytes'] <= limits.memory_limit:
        raise ValueError('诊断缓冲越界')
    if any(type(record.get(k)) is not int or record[k] <= 0 for k in ('pid','parent_pid','main_thread_id')):
        raise ValueError('进程/线程必须是严格正整数')
    events = record.get('events')
    if not isinstance(events,list) or len(events) > limits.events+limits.gc_events:
        raise ValueError('事件容量无效')
    for field,maximum in (('event_capacity',limits.events),('gc_capacity',limits.gc_events)):
        if type(record.get(field)) is not int or not 1 <= record[field] <= maximum:
            raise ValueError('记录容量字段错误')
    for field,capacity in (('event_count',record['event_capacity']),('gc_count',record['gc_capacity'])):
        if type(record.get(field)) is not int or not 0 <= record[field] <= capacity:
            raise ValueError('记录数量字段错误')
    if (record['event_count']+record['gc_count'] != len(events)
            or record['buffer_bytes'] != (record['event_capacity']+record['gc_capacity'])*64+limits.identity_bytes
            or type(record.get('lost_events')) is not int or record['lost_events'] < 0):
        raise ValueError('缓冲长度/数量/丢失不一致')
    spans, points, gcs, open_spans, open_gc = [], [], [], {}, {}
    previous = -1
    complete = record.get('diagnostic_complete') is True and record.get('lost_events',0) == 0
    for row in events:
        if not isinstance(row,list) or len(row) != 8 or any(type(v) is not int for v in row):
            raise ValueError('事件必须为严格8整数行')
        sequence,code,step,material,wall,cpu,thread,aux = row
        if sequence <= previous or wall < 0 or cpu < 0 or thread <= 0 or not -1 <= step < limits.window or not -1 <= material < limits.identities:
            raise ValueError('事件序号/端点/线程/身份无效')
        previous = sequence
        if code in (900,901):
            generation = aux % 4
            if generation not in (0,1,2) or aux//4 not in (0,*_NAMES):
                raise ValueError('GC代数无效')
            key = (thread,generation)
            event = {'start_ns':None,'end_ns':wall,'thread_id':thread,'generation':generation,
                     'global_step':None if step == -1 else step,'material_step':None if material == -1 else material,
                     'control_phase':_NAMES.get(aux//4)}
            if code == 900:
                if key in open_gc:
                    complete = False
                open_gc[key] = {**event,'start_ns':wall,'end_ns':None}
            else:
                start = open_gc.pop(key,None)
                if start is None:
                    complete = False
                gcs.append({**(start or event),'end_ns':wall})
            continue
        phase,edge = _NAMES.get(code//2),code % 2
        if phase is None:
            raise ValueError('未知事件枚举')
        event = {'phase':phase,'global_step':None if step == -1 else step,
            'material_step':None if material == -1 else material,'wall_ns':wall,'cpu_ns':cpu,
            'thread_id':thread,'aux':aux}
        if phase not in SPAN_PHASES:
            if edge != int(phase == 'work'):
                raise ValueError('单点事件的边界码无效')
            points.append(event)
            continue
        key = (thread,phase,aux)
        if edge == 0:
            if key in open_spans:
                complete = False
            open_spans[key] = event
        else:
            start = open_spans.pop(key,None)
            if start is None:
                complete = False
                continue
            if wall < start['wall_ns'] or cpu < start['cpu_ns']:
                raise ValueError('时钟倒退')
            if start['global_step'] is not None and event['global_step'] is not None and start['global_step'] != event['global_step'] and phase not in ('control','stop','cleanup','startup'):
                raise ValueError('同一span跨控制身份')
            spans.append({'phase':phase,'global_step':event['global_step'] if start['global_step'] is None else start['global_step'],
                'material_step':event['material_step'] if start['material_step'] is None else start['material_step'],
                'thread_id':thread,'aux':aux,'start_ns':start['wall_ns'],'end_ns':wall,
                'wall_ns':wall-start['wall_ns'],'cpu_ns':cpu-start['cpu_ns']})
    if open_spans or open_gc:
        complete = False
    gcs.extend(open_gc.values())
    return {'spans':spans,'points':points,'gc':gcs,'complete':complete,
            'open_span_count':len(open_spans),'open_gc_count':len(open_gc),
            'unfinished_spans':list(open_spans.values())}


def _axes(records, domains, same_host):
    ids = {r['context']['clock_domain_id'] for r in records}
    if same_host and len(ids) != 1:
        raise ValueError('不能将不同clock domain强行放在同一轴')
    axes = {}
    for record in records:
        context = record['context']
        domain = context['clock_domain_id']
        proof = domains.get(domain)
        wall_clock = record['clock']['wall']
        if (not isinstance(wall_clock,dict) or type(wall_clock.get('implementation')) is not str or not wall_clock['implementation']
                or isinstance(wall_clock.get('resolution'),bool)
                or not isinstance(wall_clock.get('resolution'),(int,float))
                or not math.isfinite(wall_clock['resolution']) or wall_clock['resolution'] <= 0):
            raise ValueError('时钟实现/分辨率未知')
        verified = (isinstance(proof,dict) and proof.get('local_spawn_verified') is True
                    and type(proof.get('launcher_pid')) is int
                    and proof['launcher_pid'] == context['launcher_pid'])
        if verified:
            members = proof.get('members',{})
            if not isinstance(members,dict) or len({m.get('pid') for m in members.values()}) != len(members):
                raise ValueError('同机spawn成员PID重复')
            own = members.get(record['role'],{})
            expected_parent = (members.get('Client',{}).get('pid') if record['role'] == 'worker'
                               else proof['launcher_pid'])
            if (type(own.get('pid')) is not int or own['pid'] != record['pid']
                    or record['parent_pid'] != expected_parent
                    or record['clock']['wall'] != proof.get('wall_clock')
                    or record['clock']['wall'].get('monotonic') is not True):
                raise ValueError('同机spawn/时钟证明与角色不一致')
        if same_host and not verified:
            raise ValueError('没有实际本机spawn证明，不能仅凭hostname或标签合轴')
        axes[record['role']] = domain if verified else f'{domain}:unverified:{record["pid"]}'
    return axes


def analyze_records(records, *, clock_domains=None, samples=(), same_host=False, targets=(285,290), slow_ns=5_000_000, expected_steps=None, detail_neighbors=False, partial=False):
    """同一分析入口处理本机或合成/未来双机数据；不启动任何控制或网络。"""
    if not records or len(records) > 4 or len({r['role'] for r in records}) != len(records):
        raise ValueError('角色重复或记录数量无效')
    limits = artifact_limits(records[0])
    if any(artifact_limits(r) != limits for r in records):
        raise ValueError('诊断窗口混配')
    contexts = [r['context'] for r in records]
    if any(type(c.get('source_head')) is not str or re.fullmatch(r'[0-9a-f]{40}',c['source_head']) is None
           or type(c.get('diagnostic_id')) is not str or not c['diagnostic_id'] for c in contexts):
        raise ValueError('诊断ID或源码SHA错误')
    if len({c['diagnostic_id'] for c in contexts}) != 1 or len({c['source_head'] for c in contexts}) != 1:
        raise ValueError('不能混入不同诊断或源码')
    protocols = {tuple(r['protocol']) for r in records if r.get('protocol') is not None}
    if len(protocols) > 1 or any(len(p) != 3 or any(type(v) is not str or not 0 < len(v) <= 128 for v in p) for p in protocols):
        raise ValueError('run/session/epoch不一致')
    rounds = {}
    for record in records:
        for step,identity in record['rounds'].items():
            if not step.isdigit() or not 0 <= int(step) < limits.identities or type(identity) is not str:
                raise ValueError('round关联错误')
            if step in rounds and rounds[step] != identity:
                raise ValueError('同一控制/材料步的round身份不一致')
            rounds[step] = identity
    decoded = {r['role']:_decode(r) for r in records}
    axes = _axes(records,clock_domains or {},same_host)
    complete = (len(records) == 4 and all(r.get('protocol') is not None for r in records)
                and all(v['complete'] for v in decoded.values())
                and all(axes[r['role']] == r['context']['clock_domain_id'] for r in records))
    missing = []
    observed_steps = {row[2] for r in records if r['role'] != 'worker' for row in r['events']
                      if row[2] >= 0 and row[1]//2 not in
                      (PHASES['startup'],PHASES['control'],PHASES['stop'],PHASES['cleanup'])}
    if expected_steps is not None:
        if (not isinstance(expected_steps,(list,tuple,range)) or not expected_steps
                or any(type(s) is not int or not 0 <= s < limits.window for s in expected_steps)
                or list(expected_steps) != list(range(len(expected_steps)))):
            raise ValueError('声明的控制步骤范围无效')
        required_steps = set(expected_steps)
        if not observed_steps <= required_steps:
            missing.append('observed control step outside declared range')
    else:
        # 未声明范围的离线旧产物只可推导已观察范围，不能证明全程没有整步丢失。
        required_steps = set(range(max(observed_steps)+1)) if observed_steps else set()
        missing.append('expected control step range not declared')
    by_step, sample_points = {}, {}
    for point in decoded.get('Client',{}).get('points',[]):
        step = point['global_step']
        if point['phase'] == 'sample':
            if step in sample_points:
                raise ValueError('同一控制步重复采样事件')
            sample_points[step] = point['wall_ns']
        elif point['phase'] == 'work' and step in sample_points:
            by_step[step] = (sample_points[step],point['wall_ns'])
    work_points = [p['global_step'] for p in decoded.get('Client',{}).get('points',[]) if p['phase'] == 'work']
    if (not required_steps or set(by_step) != required_steps or set(sample_points) != required_steps
            or sorted(work_points) != sorted(required_steps)):
        missing.append('Client sample/work pairs do not cover declared control steps')
    sample_ids, unknown_round_steps = [], []
    for sample in samples:
        step = sample['global_step']
        if type(step) is not int or not 0 <= step < limits.window:
            raise ValueError('原工作样本身份错误')
        # 输入/采样失败可能早于runtime.step，而worker已预生成同槽round。
        # 只保留显式partial的未完成失败行；绝不从材料身份填造Client已尝试事务。
        unknown_failure = (partial and sample.get('round_id') is None
            and sample.get('status') in ('failed','uncertain','cancelled','stopped_before_commit','miss_before_apply')
            and all(sample.get(k) is None for k in
                    ('control_applied_ns','work_completed_ns','control_latency_ns','work_elapsed_ns')))
        if unknown_failure:
            unknown_round_steps.append(step)
            missing.append(f'Client step {step}: failure round identity unknown')
            complete = False
        elif sample.get('round_id') is None or sample['round_id'] != rounds.get(str(step)):
            raise ValueError('原工作样本身份错误')
        sample_ids.append(step)
        if sample.get('work_completed_ns') is not None:
            begin,applied,finish = (sample.get(k) for k in ('actual_sample_start_ns','control_applied_ns','work_completed_ns'))
            if (any(type(v) is not int for v in (begin,applied,finish)) or not begin <= applied <= finish
                    or sample.get('work_elapsed_ns') != finish-begin
                    or sample.get('control_latency_ns') != applied-begin):
                raise ValueError('原工作样本端点差错误')
        if step not in by_step or sample.get('work_completed_ns') is None or sample.get('actual_sample_start_ns') is None:
            complete = False
        elif (sample['actual_sample_start_ns'] > by_step[step][0] or
              sample['work_completed_ns'] < by_step[step][1]):
            # 钩子在既有端点内，不能把观察事件搬到工作区间外制造归因。
            raise ValueError('诊断工作端点不在原始控制端点内')
    if samples and sorted(sample_ids) != sorted(required_steps):
        missing.append('original samples do not cover declared control steps exactly once')
    for step in sorted(required_steps):
        for record in records:
            if str(step) not in record['rounds']:
                missing.append(f"{record['role']} step {step}: missing own round identity")
        for role in ('P1','P2'):
            spans = decoded.get(role,{}).get('spans',[])
            if any(not any(s['global_step'] == step and s['phase'] == phase for s in spans)
                   for phase in ('request_receive','restore','matrix','suffix','truncation','ready','commit','final_send')):
                complete = False
                missing.append(f'{role} step {step}: missing required server span')
            if not any(p['global_step'] == step and p['phase'] == 'stage' for p in decoded.get(role,{}).get('points',[])):
                missing.append(f'{role} step {step}: missing stage')
        for phase in ('worker_generate','worker_ipc'):
            if not any(s['material_step'] == step and s['phase'] == phase for s in decoded.get('worker',{}).get('spans',[])):
                complete = False
                missing.append(f'worker material {step}: missing {phase}')
        points = decoded.get('Client',{}).get('points',[])
        spans = decoded.get('Client',{}).get('spans',[])
        for phase in ('material_claim','material_bind','exchange'):
            if not any(s['global_step'] == step and s['phase'] == phase for s in spans):
                missing.append(f'Client step {step}: missing {phase}')
        for party in (0,1):
            if not any(s['global_step'] == step and s['phase'] == 'request_send' and s['aux'] == party for s in spans):
                missing.append(f'Client step {step}: missing request_send P{party+1}')
        for phase in ('reply_read','reply_frame','commit_fact'):
            for party in (0,1):
                if not any(p['global_step'] == step and p['phase'] == phase and p['aux'] == party for p in points):
                    complete = False
                    missing.append(f'Client step {step}: missing {phase} P{party+1}')
        for phase in ('double_commit','output_checked','applied'):
            if not any(p['global_step'] == step and p['phase'] == phase for p in points):
                complete = False
                missing.append(f'Client step {step}: missing {phase}')
    complete = complete and not missing
    chosen = {s for s in targets if s in by_step}
    if by_step:
        chosen.add(max(by_step,key=lambda s:by_step[s][1]-by_step[s][0]))
        chosen.update(s for s,(start,end) in by_step.items() if end-start > slow_ns)
    if detail_neighbors:
        original_work = {s['global_step']:s['work_elapsed_ns'] for s in samples
                         if s.get('work_elapsed_ns') is not None}
        ranked_work = {s:original_work.get(s,b-a) for s,(a,b) in by_step.items()}
        chosen.update(s for s,v in ranked_work.items() if v > slow_ns)
        chosen.update(sorted(ranked_work,key=ranked_work.get,reverse=True)[:8])
        for step in tuple(chosen):
            chosen.update(s for s in (step-1,step+1) if s in by_step)
    result = []
    for step in sorted(chosen):
        start,end = by_step[step]
        timeline, gc_rows, domains = [], [], {}
        client_axis = axes['Client']
        for record in records:
            role, axis = record['role'],axes[record['role']]
            data = decoded[role]
            # 同域才允许与Client窗口相交；异域仅列其本地步骤边界。
            own = [s for s in data['spans'] if s['global_step'] == step or s['material_step'] == step]
            online = [s for s in own if s['global_step'] == step and s['phase'] in
                      ('material_bind','material_claim','exchange','restore','matrix','suffix','truncation','ready','commit','final_send')]
            windows = ((start,end) if axis == client_axis else
                       (min(s['start_ns'] for s in online),max(s['end_ns'] for s in online)) if online else None)
            domains.setdefault(axis,[])
            for span in own:
                children = [s for s in data['spans'] if s['thread_id'] == span['thread_id']
                    and s['phase'] not in ('startup','control','stop','cleanup')
                    and span['start_ns'] <= s['start_ns'] <= s['end_ns'] <= span['end_ns']
                    and s['wall_ns'] < span['wall_ns']]
                row = {**span,'role':role,'clock_domain_id':axis,
                       'exclusive_wall_ns':span['wall_ns']-_union([(s['start_ns'],s['end_ns']) for s in children]),
                       'cpu_note':'thread CPU may be quantized; zero does not identify network wait'}
                if axis == client_axis:
                    row['client_work_overlap_ns'] = max(0,min(end,span['end_ns'])-max(start,span['start_ns']))
                    child_overlap = [(max(start,s['start_ns']),min(end,s['end_ns'])) for s in children
                                     if max(start,s['start_ns']) < min(end,s['end_ns'])]
                    row['exclusive_client_work_overlap_ns'] = row['client_work_overlap_ns']-_union(child_overlap)
                timeline.append(row)
                domains[axis].append(row)
            if windows is not None:
                gc_data = gc_intersections(data['gc'],*windows)
                for event in gc_data['events']:
                    gc_rows.append({**event,'role':role,'clock_domain_id':axis,
                        'on_control_thread':event['thread_id'] == record['main_thread_id'],
                        'current_online_phase':event['control_phase'] in
                            ('material_bind','material_claim','exchange','restore','matrix','suffix','truncation','ready','commit','final_send'),
                        'client_window_comparable':axis == client_axis})
        local_spans = [r for r in timeline if r['phase'] in ('material_bind','material_claim',
            'restore','matrix','suffix','truncation','ready','commit','final_send')]
        location = max(local_spans,key=lambda r:(r.get('exclusive_client_work_overlap_ns',r['exclusive_wall_ns']),
                                               r['role'],r['phase']),default=None)
        overlap_candidates = [e for e in gc_rows if e['role'] != 'worker' and e['on_control_thread']
                        and e['current_online_phase'] and e['global_step'] == step
                        and e['material_step'] in (None,step) and e['overlap_ns'] > 0]
        # GC局部重叠不等于阻塞链贡献。仅确认慢方矩阵GC期间另一方已经等其suffix，
        # 且慢方在GC结束后才进入该交换的同域可核验子集；未知链路保守留作重叠事实。
        contribution = []
        for event in overlap_candidates:
            if (location is None or event['role'] != location['role'] or location['phase'] != 'matrix'
                    or event['control_phase'] != 'matrix' or not event['client_window_comparable']):
                continue
            if not location['start_ns'] <= event['start_ns'] < event['end_ns'] <= location['end_ns']:
                continue
            peer = 'P2' if event['role'] == 'P1' else 'P1' if event['role'] == 'P2' else None
            own_suffix = [s for s in timeline if s['role'] == event['role'] and s['phase'] == 'suffix']
            waits = [s for s in timeline if s['role'] == peer and s['phase'] == 'suffix'
                     and s['clock_domain_id'] == event['clock_domain_id']]
            if any(w['start_ns'] <= event['start_ns'] < event['end_ns'] <= s['start_ns'] <= w['end_ns']
                   for s in own_suffix for w in waits):
                contribution.append(event)
        level = ('Contributor observed' if complete and contribution else
                 'Located' if location is not None else 'Unresolved system/link wait')
        neighbors = [s for s,(a,b) in by_step.items() if s != step and b-a <= slow_ns]
        neighbor = min(neighbors,key=lambda s:(abs(s-step),s)) if neighbors else None
        result.append({'global_step':step,'work_ns':end-start,'clock_domain_id':client_axis,
            'normal_neighbor_step':neighbor,'normal_neighbor_work_ns':None if neighbor is None else by_step[neighbor][1]-by_step[neighbor][0],
            'evidence_level':level,'located_phase':(None if location is None else {'role':location['role'],'phase':location['phase']}),
            'gc_dependency_contributions':contribution if complete else [],
            'fixable_mechanism_confirmed':False,'gc':gc_rows,'timeline_by_domain':domains,
            'gc_overlap_union_by_domain_ns':{axis:_union([(e['clipped_start_ns'],e['clipped_end_ns'])
                for e in gc_rows if e['clock_domain_id'] == axis]) for axis in domains},
            'unknown':'GC overlap is not a complete root-cause proof; scheduling/network attribution needs additional evidence; nested/parallel spans are not summed'})
        if detail_neighbors:
            # 仅B本地域核对双方依赖；不要求B时钟与Client可比较。
            dependency = []
            for event in gc_rows:
                if (not event['on_control_thread'] or event['control_phase'] != 'matrix'
                        or event['global_step'] != step or event['material_step'] not in (None,step)):
                    continue
                peer = {'P1':'P2','P2':'P1'}.get(event['role'])
                own = [s for s in timeline if s['role']==event['role'] and s['phase']=='suffix']
                waits = [s for s in timeline if s['role']==peer and s['phase']=='suffix'
                         and s['clock_domain_id']==event['clock_domain_id']]
                matrix = [s for s in timeline if s['role']==event['role'] and s['phase']=='matrix']
                if any(m['start_ns'] <= event['start_ns'] < event['end_ns'] <= m['end_ns']
                       and w['start_ns'] <= event['start_ns'] < event['end_ns'] <= s['start_ns'] <= w['end_ns']
                       for m in matrix for s in own for w in waits):
                    dependency.append(event)
            result[-1]['server_local_gc_dependencies'] = dependency if complete else []
            result[-1]['client_points'] = [p for p in decoded.get('Client',{}).get('points',[])
                                           if p['global_step']==step]
            result[-1]['original_work_ns'] = original_work.get(step)
            result[-1]['related_preparation_by_domain'] = {
                axes[r['role']]+':'+r['role']:[s for s in decoded[r['role']]['spans']
                    if s['phase'] in ('seed','prefix','prefix_peer') and
                    (s['global_step'] in (step-1,step) or s['material_step'] in (step,step+1)
                     or s['global_step'] is None and s['material_step'] is None)] for r in records}
    work = sorted(s['work_elapsed_ns'] for s in samples if s.get('work_elapsed_ns') is not None) if samples else sorted(b-a for a,b in by_step.values())
    distribution = {**_distribution(work),
        'scope':('original completed Client work samples' if samples else 'diagnostic sample/work pairs')+
                '; failures listed separately; not pure network latency'}
    expected_maintenance = [s for s in sorted(required_steps) if s+1<len(required_steps)
                            and (s+1)%limits.segment_steps==0]
    maintenance = [s['global_step'] for s in samples
                   if s.get('phase_durations_ns',{}).get('maintenance',0)>0]
    client = next((r for r in records if r['role']=='Client'),{})
    stop_spans = [s for s in decoded.get('Client',{}).get('spans',[])
                  if s['phase']=='stop' and s['thread_id']==client.get('main_thread_id')]
    final_step = None
    # 预定范围和观察前缀都不是停止事实。finish在失败时也补stop事件，故必须同时
    # 有成功状态、完整配对、主线程身份和末次已完成工作之后的真实停止边界。
    if client.get('status')=='stopped' and decoded.get('Client',{}).get('complete') and len(stop_spans)==1:
        stop = stop_spans[0]
        step = stop['global_step']
        if (step in by_step and step==max(observed_steps,default=None)
                and by_step[step][1]<=stop['start_ns']
                and any(s['global_step']==step and s.get('status')=='confirmed'
                        and s.get('work_elapsed_ns') is not None for s in samples)):
            final_step = step
    def groups(rows):
        # 缺计时字段不能按索引猜维护；final_stop是成功停止前末次工作，不是停止耗时。
        groups = {'ordinary':[],'continuing_maintenance':[],'final_stop':[],'unknown':[]}
        for row in rows:
            value = row.get('work_elapsed_ns')
            if value is None:
                continue
            step = row['global_step']
            phase = row.get('phase_durations_ns',{})
            group = ('final_stop' if step==final_step else
                'continuing_maintenance' if step in expected_maintenance and step in maintenance else
                'ordinary' if 'maintenance' in phase and phase['maintenance']==0 else 'unknown')
            groups[group].append(value)
        return {name:_distribution(values) for name,values in groups.items()}
    return {'schema':limits.trace_schema,
        **({'limits':limits.payload()} if limits.window!=400 else {}),
        'diagnostic_id':contexts[0]['diagnostic_id'],'source_head':contexts[0]['source_head'],
        'diagnostic_complete':complete,'clock_axes':axes,'steps':result,'missing_evidence':missing,
        'all_work_steps':sorted(by_step),'incomplete_roles':[k for k,v in decoded.items() if not v['complete']],
        'requested_steps_unavailable':[s for s in targets if s not in by_step],
        'work_distribution':distribution,
        'unfinished_spans':{r:d['unfinished_spans'] for r,d in decoded.items()},
        'failure_samples':[s for s in samples if s.get('status') != 'confirmed'],
        'segments':[{'start':start,'end':min(start+limits.segment_steps,limits.window)-1,
            'completed_steps':[s for s in sorted(by_step) if start<=s<start+limits.segment_steps],
            'work_distribution':_distribution(s['work_elapsed_ns'] for s in samples
                if start<=s['global_step']<start+limits.segment_steps and s.get('work_elapsed_ns') is not None)}
            for start in range(0,limits.window,limits.segment_steps)],
        'expected_maintenance_steps':expected_maintenance,
        'observed_maintenance_steps':maintenance,'work_groups':groups(samples),
        'unknown_sample_round_steps':unknown_round_steps,
        'scope':'diagnostic observation only; not a performance comparison or strict realtime qualification'}


def analyze_manifests(paths, *, same_host=False, partial=False):
    """核对各角色文件hash后读入；目录组合不提供跨主机时钟同步。"""
    records, domains, samples, manifests_complete, expected = [], {}, [], True, None
    loaded, file_errors = [], []
    for name in paths:
        path = Path(name)
        manifest = json.loads(path.read_text(encoding='utf8'))
        limits = artifact_limits(manifest)
        if loaded and limits != artifact_limits(loaded[0]):
            raise ValueError('manifest窗口版本不一致')
        loaded.append(manifest)
        manifests_complete = manifests_complete and manifest.get('diagnostic_complete') is True
        count = manifest.get('expected_step_count')
        if type(count) is not int or not 1 <= count <= limits.window:
            manifests_complete = False
        elif expected is not None and expected != count:
            raise ValueError('manifest声明的控制范围不一致')
        else:
            expected = count
        for entry in manifest['files']:
            target = (path.parent/entry['path']).resolve()
            if target.parent != path.parent.resolve():
                raise ValueError('角色文件路径越出产物目录')
            try:
                raw = target.read_bytes()
            except FileNotFoundError:
                if not partial:
                    raise
                file_errors.append({'path':entry['path'],'error_type':'FileNotFoundError'})
                manifests_complete = False
                continue
            if hashlib.sha256(raw).hexdigest() != entry['sha256']:
                raise ValueError('角色文件hash不符')
            record = json.loads(raw)
            if artifact_limits(record) != limits:
                raise ValueError('manifest与角色窗口版本不一致')
            if (record['context']['diagnostic_id'] != manifest.get('diagnostic_id')
                    or record['context']['source_head'] != manifest.get('source_head')):
                raise ValueError('manifest与角色身份/SHA不符')
            if manifest.get('side') in ('client','pair'):
                allowed = {'Client','worker'} if manifest['side']=='client' else {'P1','P2'}
                if (record['role'] not in allowed or entry['path'] != record['role']+'.json'
                        or record['context']['clock_domain_id'] != manifest.get('plan',{}).get('clock_domain_id')):
                    raise ValueError('角色文件与本端计划/时钟域不符')
            records.append(record)
        for key,value in manifest.get('clock_domains',{}).items():
            if key in domains and domains[key] != value:
                raise ValueError('clock domain证明冲突')
            domains[key] = value
        samples.extend(manifest.get('control_samples',[]))
    identities = {(m.get('diagnostic_id'),m.get('source_head')) for m in loaded}
    if len(identities) != 1:
        raise ValueError('manifest诊断ID/源码不一致')
    two_host = any(m.get('side') in ('client','pair') for m in loaded)
    if two_host:
        if len(loaded) > 2 or len({m.get('side') for m in loaded}) != len(loaded):
            raise ValueError('两机manifest角色重复')
        if {m.get('side') for m in loaded} != {'client','pair'}:
            manifests_complete = False
        common, topology, review = set(), set(), set()
        for m in loaded:
            plan = m.get('plan',{})
            if (plan.get('side') != m['side'] or plan.get('source_head') != m['source_head']
                    or plan.get('diagnostic_id') != m['diagnostic_id']
                    or plan.get('maximum_steps') != m.get('expected_step_count')
                    or plan.get('mode') != 'non_realtime_diagnostic'):
                raise ValueError('两机计划与manifest不符')
            encoded = json.dumps(plan,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf8')
            if hashlib.sha256(encoded).hexdigest() != m.get('plan_sha256'):
                raise ValueError('两机计划hash不符')
            common.add(json.dumps(plan['common_source_sha256'],sort_keys=True))
            topology.add(plan['topology_digest'])
            review.add(plan['software_review'])
            allowed = {'Client','worker'} if m['side']=='client' else {'P1','P2'}
            member_roles = {r['role'] for r in records if r['context']['clock_domain_id']==plan['clock_domain_id']}
            if not member_roles <= allowed:
                raise ValueError('两机角色与本地成员不符')
            if member_roles != allowed:
                manifests_complete = False
            for r in records:
                if r['role'] not in allowed:
                    continue
                if r['context'].get('topology_digest') != plan['topology_digest']:
                    raise ValueError('角色拓扑与冻结计划不符')
            expected_roles = {'Client'} if m['side']=='client' else {'P1','P2'}
            configs = plan['configurations']
            if ({c['role'] for c in configs} != expected_roles or len(configs)!=len(expected_roles)
                    or any(c['wire_profile'] != plan['profile'] or c['transport'] != 'insecure_tcp'
                           or c['topology_digest'] != plan['topology_digest'] for c in configs)):
                raise ValueError('配置/协议与两机计划不符')
        if len(common)!=1 or len(topology)!=1 or len(review)!=1:
            raise ValueError('两机源码内容/拓扑/审查版本不一致')
        if len({m['plan']['clock_domain_id'] for m in loaded}) != len(loaded):
            raise ValueError('两机必须使用独立时钟域')
    if not records:
        if not partial:
            raise ValueError('没有角色记录')
        return {'schema':limits.trace_schema,
            **({'limits':limits.payload()} if limits.window!=400 else {}),
            'diagnostic_complete':False,'steps':[],
            'missing_evidence':['no role records'],'file_errors':file_errors,'manifests':loaded,
            'scope':'partial diagnostic; no clock/latency conclusion'}
    result = analyze_records(records,clock_domains=domains,samples=samples,same_host=same_host,
                             expected_steps=None if expected is None else range(expected),
                             targets=() if two_host else (285,290),
                             slow_ns=20_000_000 if two_host else 5_000_000,detail_neighbors=two_host,
                             partial=partial)
    result['diagnostic_complete'] = result['diagnostic_complete'] and manifests_complete
    result['file_errors'] = file_errors
    if two_host:
        result['mode'] = 'non_realtime_diagnostic'
        result['manifests_complete'] = manifests_complete
        result['functional_outcomes'] = [{'side':m['side'],'functional_complete':m['functional_complete'],
                                        'group':m['group']} for m in loaded]
    return result


def select_slow_steps(samples, threshold_ns=20_000_000):
    """严格work>20ms，并加入前后最近正常步；没有慢步不得自动重跑。"""
    work={s['global_step']:s['work_elapsed_ns'] for s in samples
          if type(s.get('work_elapsed_ns')) is int and s['work_elapsed_ns']>=0}
    slow={k for k,v in work.items() if v>threshold_ns};selected=set(slow);neighbors={}
    for step in sorted(slow):
        normal=[k for k,v in work.items() if v<=threshold_ns]
        before=max((k for k in normal if k<step),default=None)
        after=min((k for k in normal if k>step),default=None)
        neighbors[step]={'before':before,'after':after}
        selected.update(k for k in (before,after) if k is not None)
    return sorted(slow),sorted(selected),neighbors


def analyze_slow_control(paths):
    """只读逐慢步证据，不跨主机减QPC；缺独立TCP零点时仍输出应用及调度。"""
    from secure_control.experiments.windows_tail_analysis import normalize_schedule
    validated=analyze_manifests(paths,partial=True)
    manifests=[(Path(p),json.loads(Path(p).read_text(encoding='utf8'))) for p in paths]
    control_plans=[m.get('plan',{}).get('control_plan_sha256') for _,m in manifests]
    if any(control_plans):
        if len(manifests)!=2 or len(set(control_plans))!=1:
            raise ValueError('control-purpose plan mismatch between peers')
        approvals=[m['plan'].get('control_authorization') for _,m in manifests]
        if approvals[0]!=approvals[1] or not isinstance(approvals[0],dict):
            raise ValueError('control-purpose approval mismatch between peers')
    records={};sources={};samples=[];client_dir=None;client_manifest=None
    for path,m in manifests:
        samples.extend(m.get('control_samples',[]))
        for entry in m['files']:
            p=path.parent/entry['path']
            if p.is_file():
                r=json.loads(p.read_text(encoding='utf8'));records[r['role']]=r
                sources[r['role']]=entry['sha256']
        if m.get('side')=='client':client_dir=path.parent;client_manifest=m
    decoded={r:_decode(v) for r,v in records.items()}
    slow,chosen,neighbors=select_slow_steps(samples)
    native=None;stream=None;native_reason='missing hash-bound control-native evidence';native_hashes={}
    if client_dir is not None:
        evidence=client_manifest.get('native_evidence',{})
        if evidence.get('status')=='read':
            native_hashes=evidence['files']
            if set(native_hashes)!={'native-a.etl','control-native-events.json','control-native-view.json','Client.stream.json'}:
                raise ValueError('control native artifact set incomplete')
            for name,digest in native_hashes.items():
                p=(client_dir/name).resolve()
                if p.parent!=client_dir.resolve() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
                    raise ValueError('control native artifact identity/hash changed')
            native=json.loads((client_dir/'control-native-view.json').read_text(encoding='utf8'))
            stream=json.loads((client_dir/'Client.stream.json').read_text(encoding='utf8'))
            native['events']=json.loads((client_dir/'control-native-events.json').read_text(encoding='utf8'))
            client=records['Client']
            if (native.get('etl_sha256')!=native_hashes['native-a.etl']
                    or native.get('purpose')!='control-slow-step-v1'
                    or native.get('source_head')!=client['context']['source_head']
                    or native.get('diagnostic_id')!=client['context']['diagnostic_id']
                    or native['target_pid']!=client['pid'] or native['target_tid']!=client['main_thread_id']
                    or stream['context']['diagnostic_id']!=client['context']['diagnostic_id']
                    or stream['context']['source_head']!=client['context']['source_head']):
                raise ValueError('control native/stream target mismatch')
            native_reason='independent SeqNo/application-offset-zero anchor unavailable for this connection'
    normalized=(normalize_schedule({**native,'target_tid':native['target_tid']}) if native else None)
    results=[]
    for step in chosen:
        sample=next(s for s in samples if s['global_step']==step)
        start,end=sample['actual_sample_start_ns'],sample['work_completed_ns']
        intervals=[]
        if native and native.get('schedule_window_complete') is True:
            anchor=native['window_replay']['anchor'];state='unknown';previous=anchor['time']
            for e in normalized['events']:
                if e['time']<anchor['time']:continue
                left,right=max(start,previous),min(end,e['time'])
                if left<right and state in ('running','ready'):
                    intervals.append({'state':state,'start_ns':left,'end_ns':right,
                        'boundary_event_index':e.get('event_index')})
                if e['kind']=='in':state='running'
                elif e['kind']=='out':state=e['next']
                elif e['kind']=='ready':state='ready'
                elif e['kind']=='end':state='ended'
                previous=e['time']
                if previous>end:break
        parties=[]
        for party,role in enumerate(('P1','P2')):
            client=decoded.get('Client',{})
            send=[s for s in client.get('spans',[]) if s['global_step']==step
                  and s['phase']=='request_send' and s['aux']==party]
            points={name:next((p['wall_ns'] for p in client.get('points',[])
                if p['global_step']==step and p['phase']==name and p['aux']==party),None)
                for name in ('reply_read','reply_frame')}
            server=[s for s in decoded.get(role,{}).get('spans',[]) if s['global_step']==step]
            mapping=[r for r in (stream or {}).get('rows',[]) if r[0]==step*2+party]
            wait=None
            first=points['reply_read']
            if len(send)==1 and first is not None and first>=send[0]['end_ns']:
                lo,hi=send[0]['end_ns'],first
                ready_ns=_union([(max(lo,r['start_ns']),min(hi,r['end_ns'])) for r in intervals
                    if r['state']=='ready' and max(lo,r['start_ns'])<min(hi,r['end_ns'])])
                running_ns=_union([(max(lo,r['start_ns']),min(hi,r['end_ns'])) for r in intervals
                    if r['state']=='running' and max(lo,r['start_ns'])<min(hi,r['end_ns'])])
                verified=bool(native and native.get('schedule_window_complete'))
                wait={'send_complete_to_first_read_ns':hi-lo,
                    'ready_observed_ns':ready_ns if verified else None,
                    'running_observed_ns':running_ns if verified else None,
                    'other_scheduler_states_ns':hi-lo-ready_ns-running_ns if verified else None,
                    'before_component_coverage_ns':None,'after_component_coverage_ns':None,
                    'note':'scheduler occupancy only; waiting is not proof of network delay'}
            parties.append({'role':role,'A_wait_analysis':wait,'A_request_send_spans':send,'A_reply_points_ns':points,
                'A_reply_stream_row':mapping[0] if len(mapping)==1 else None,
                'tcp_component_complete_ns':None,'tcp_unknown_reason':native_reason,
                'B_local_spans':server,'B_clock_domain_id':records.get(role,{}).get('context',{}).get('clock_domain_id'),
                'cross_host_difference_ns':None})
        results.append({'diagnostic_id':(client_manifest or {}).get('diagnostic_id'),
            'source_head':(client_manifest or {}).get('source_head'),'global_step':step,'kind':'slow' if step in slow else 'normal_neighbor',
            'round_id':sample.get('round_id'),'work_ns':sample['work_elapsed_ns'],
            'A_clock_domain_id':records.get('Client',{}).get('context',{}).get('clock_domain_id'),
            'A_exchange_spans':[s for s in decoded.get('Client',{}).get('spans',[]) if s['global_step']==step and s['phase']=='exchange'],
            'thread_intervals':intervals,'thread_intervals_verified':bool(native and native.get('schedule_window_complete')),
            'parties':parties,'cause':'unresolved; observations do not establish socket readability or GIL availability'})
    return {'schema':'control-slow-step-analysis-v1','status':'observed' if slow else 'not_reproduced' if validated['diagnostic_complete'] else 'incomplete_no_slow_observed',
        'threshold_ns':20_000_000,'slow_steps':slow,'normal_neighbors':neighbors,'rows':results,
        'diagnostic_complete':validated['diagnostic_complete'],'role_sha256':sources,
        'native_sha256':native_hashes,'socket_readable':'unknown','retry':False}
