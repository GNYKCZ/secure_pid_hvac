"""显式一次本机采集或只读多域分析；普通演示入口不启用诊断。"""
import argparse
import json
from pathlib import Path


def main():
    """薄命令行入口；采集、控制循环、离线分析分别由原owner负责。"""
    parser = argparse.ArgumentParser(description='有界控制尾部诊断（不是性能资格测试）')
    modes = parser.add_subparsers(dest='mode',required=True)
    local = modes.add_parser('local',help='明确运行一个ready-v1本机组')
    local.add_argument('output',type=Path)
    local.add_argument('--expected-head',required=True)
    local.add_argument('--software-review',required=True)
    local.add_argument('--steps',type=int,default=400)
    for side in ('client','pair'):
        host = modes.add_parser(side,help='A端Client+worker' if side == 'client' else 'B端P1/P2（先启动）')
        host.add_argument('output',type=Path)
        host.add_argument('--diagnostic-id',required=True)
        host.add_argument('--expected-head',required=True)
        host.add_argument('--software-review',required=True)
        host.add_argument('--authorization',type=Path)
        host.add_argument('--steps',type=int,default=400)
        host.add_argument('--window',type=int,choices=(400,2000),default=400,help='显式版本窗口，旧默认400保持')
        if side == 'client':
            host.add_argument('--stream-map',action='store_true',help='显式公开帧区间sidecar；不启动系统跟踪')
            host.add_argument('--native-plan',type=Path,help='仅2000专项：用户明确执行时才启动计划中的自有WPR会话')
            host.add_argument('--config',type=Path,default=Path('configs/lab-client-cart-pole-demo.example.yaml'))
        else:
            host.add_argument('--native-plan',type=Path)
            host.add_argument('--p1-config',type=Path,default=Path('configs/lab-p1-cart-pole-demo.example.yaml'))
            host.add_argument('--p2-config',type=Path,default=Path('configs/lab-p2-cart-pole-demo.example.yaml'))
    prepare = modes.add_parser('prepare-native',help='只读核查profile/source/session，写计划，不启动采集/控制')
    prepare.add_argument('output',type=Path)
    prepare.add_argument('--expected-head',required=True)
    file_prepare=modes.add_parser('prepare-file-calibration',help='只读准备显式File校准计划，不采集/发流量')
    file_prepare.add_argument('output',type=Path)
    file_prepare.add_argument('--expected-head',required=True)
    file_prepare.add_argument('--config',type=Path,required=True,help='只读绑定Client拓扑摘要，不联网')
    control_prepare=modes.add_parser('prepare-control-file',help='只读准备原控制File计划，不运行')
    control_prepare.add_argument('output',type=Path)
    control_prepare.add_argument('--expected-head',required=True)
    control_prepare.add_argument('--software-review',required=True)
    for role in ('client','p1','p2'):
        control_prepare.add_argument('--'+role+'-config',type=Path,default=Path('configs/lab-'+role+'-cart-pole-demo.example.yaml'))
    b_prepare=modes.add_parser('prepare-b-receive-file',help='B只读核验接受连接源，不采集')
    b_prepare.add_argument('output',type=Path)
    b_prepare.add_argument('--expected-head',required=True)
    b_prepare.add_argument('--software-review',required=True)
    for role in ('p1','p2'):
        b_prepare.add_argument('--'+role+'-config',type=Path,default=Path('configs/lab-'+role+'-cart-pole-demo.example.yaml'))
    combine=modes.add_parser('combine-b-receive-plans',help='只读组合两机独立节点计划')
    combine.add_argument('client_plan',type=Path)
    combine.add_argument('pair_plan',type=Path)
    combine.add_argument('output',type=Path)
    combine.add_argument('--diagnostic-id',required=True)
    for side in ('client','pair'):
        calibration=modes.add_parser('calibrate-'+side,help='需新的计划绑定用户批准；一次公开流量，不运行控制')
        calibration.add_argument('output',type=Path)
        calibration.add_argument('--expected-head',required=True)
        calibration.add_argument('--plan',type=Path,required=True)
        calibration.add_argument('--authorization',type=Path,required=True)
        if side=='client':
            calibration.add_argument('--config',type=Path,required=True)
        else:
            calibration.add_argument('--p1-config',type=Path,required=True)
            calibration.add_argument('--p2-config',type=Path,required=True)
    comparison=modes.add_parser('calibrate-analyze',help='只读核实已复制的同组两端原件')
    comparison.add_argument('client_directory',type=Path)
    comparison.add_argument('pair_directory',type=Path)
    comparison.add_argument('--output',type=Path,required=True)
    control_analysis=modes.add_parser('analyze-control',help='只读逐work>20ms及正常邻步证据表')
    control_analysis.add_argument('manifests',type=Path,nargs='+')
    control_analysis.add_argument('--output',type=Path,required=True)
    control_analysis.add_argument('--a-recovery',type=Path,help='显式链接独立离线恢复receipt，不修改原manifest')
    recovery=modes.add_parser('recover-control',help='只读已有A ETL，一次5M/120s离线恢复，不启动采集')
    recovery.add_argument('manifest',type=Path)
    recovery.add_argument('output',type=Path)
    recovery.add_argument('--expected-head',required=True)
    analyze = modes.add_parser('analyze',help='只读角色manifest，不运行控制')
    analyze.add_argument('manifests',type=Path,nargs='+')
    analyze.add_argument('--output',type=Path,required=True)
    analyze.add_argument('--same-host',action='store_true',help='没有实际同机spawn证明时拒绝合轴')
    analyze.add_argument('--partial',action='store_true',help='保留失败前缀/缺角色；不升级为完整证据')
    args = parser.parse_args()
    if args.mode=='combine-b-receive-plans':
        from secure_control.experiments.native_tail_capture import combine_receive_plans
        result=combine_receive_plans(json.loads(args.client_plan.read_text(encoding='utf8')),
            json.loads(args.pair_plan.read_text(encoding='utf8')),args.diagnostic_id)
        with args.output.open('x',encoding='utf8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2)
        print('Combined preparation only; no capture started.')
    elif args.mode in ('prepare-native','prepare-file-calibration','prepare-control-file','prepare-b-receive-file'):
        import subprocess

        from secure_control.experiments.native_tail_capture import prepare_native
        from secure_control.experiments.tail_diagnostic_runner import ROOT
        head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        if head!=args.expected_head:
            parser.error('准备计划head不一致')
        file_candidate=args.mode!='prepare-native'
        b_receive=args.mode=='prepare-b-receive-file'
        result = prepare_native(ROOT/('configs/control-tail-b-receive.wprp' if b_receive else
            'configs/control-tail-calibration.wprp' if file_candidate else 'configs/control-tail-native-2000.wprp'),
            _file_candidate=file_candidate,**({'_b_receive':True} if b_receive else {}))
        if args.mode in ('prepare-control-file','prepare-b-receive-file'):
            from secure_control.execution.lan_config import load_lan_config
            from secure_control.experiments.tail_diagnostic_runner import _config_identity
            configs=[load_lan_config(getattr(args,r.lower()+'_config'),r) for r in (('P1','P2') if b_receive else ('Client','P1','P2'))]
            if len({c.topology.digest for c in configs})!=1:parser.error('拓扑不一致')
            result.update(purpose='control-b-receive-boundary-v1' if b_receive else 'control-slow-step-v1',control_steps=2000,software_review=args.software_review,
                control_configurations={c.role:_config_identity(c) for c in configs},
                topology_sha256=configs[0].topology.digest,pair_wait_s=45,pair_business_s=55,pair_total_s=100)
            if b_receive:result['pair_total_s']=120
        elif file_candidate:
            from secure_control.experiments.tail_calibration import _config_addresses
            _,result['topology_sha256']=_config_addresses([args.config],'client')
        result['source_head'] = head
        with args.output.open('x',encoding='utf8') as stream:
            json.dump(result,stream,ensure_ascii=False,indent=2)
        print('仅准备计划已保存；尚未启动任何系统或控制采集。')
    elif args.mode in ('calibrate-client','calibrate-pair'):
        from secure_control.experiments.tail_calibration import run_calibration
        side=args.mode.removeprefix('calibrate-')
        paths=[args.config] if side=='client' else [args.p1_config,args.p2_config]
        result=run_calibration(side,args.output,plan=json.loads(args.plan.read_text(encoding='utf8')),
            approval=json.loads(args.authorization.read_text(encoding='utf8')),config_paths=paths,
            expected_head=args.expected_head)
        print(json.dumps({k:v for k,v in result.items() if k not in ('events','tcp')},ensure_ascii=False))
        if result.get('status')!='closed' and result.get('local_checks_complete') is not True:
            raise SystemExit(2)
    elif args.mode=='calibrate-analyze':
        from secure_control.experiments.tail_calibration import _save, analyze_calibration
        result=analyze_calibration(args.client_directory,args.pair_directory)
        _save(args.output,result)
        print(json.dumps(result,ensure_ascii=False))
        if not result['calibration_complete']:raise SystemExit(2)
    elif args.mode=='recover-control':
        from secure_control.experiments.tail_diagnostic_analysis import recover_control_etl
        result=recover_control_etl(args.manifest,args.output,expected_head=args.expected_head)
        print(json.dumps({'status':result['status'],'receipt':str(args.output/'receipt.json')}))
    elif args.mode=='analyze-control':
        from secure_control.experiments.tail_diagnostic_analysis import analyze_slow_control
        result=analyze_slow_control(args.manifests,a_recovery=args.a_recovery)
        with args.output.open('x',encoding='utf8') as stream:json.dump(result,stream,indent=2)
        print(json.dumps({'status':result['status'],'slow_steps':result['slow_steps']}))
    elif args.mode == 'local':
        from secure_control.experiments.tail_diagnostic_runner import run_local
        result = run_local(args.output,expected_head=args.expected_head,
                           software_review=args.software_review,steps=args.steps)
        print(json.dumps({'diagnostic_complete':result['diagnostic_complete'],
                          'functional_complete':result['functional_complete'],
                          'manifest':str(args.output/'manifest.json')},ensure_ascii=False))
    elif args.mode in ('client','pair'):
        from secure_control.experiments.tail_diagnostic_runner import run_host
        paths = [args.config] if args.mode == 'client' else [args.p1_config,args.p2_config]
        result = run_host(args.mode,args.output,diagnostic_id=args.diagnostic_id,
            expected_head=args.expected_head,software_review=args.software_review,
            config_paths=paths,steps=args.steps,**({'window':args.window} if args.window!=400 else {}),
            **({'stream_map':True} if args.mode=='client' and args.stream_map else {}),
            **({'native_plan':json.loads(args.native_plan.read_text(encoding='utf8'))}
               if args.native_plan else {}),
            **({'authorization':json.loads(args.authorization.read_text(encoding='utf8'))}
               if args.authorization else {}))
        print(json.dumps({'diagnostic_complete':result['diagnostic_complete'],
            'functional_complete':result['functional_complete'],
            'manifest':str(args.output/'manifest.json')},ensure_ascii=False))
    else:
        from secure_control.experiments.tail_diagnostic_analysis import analyze_manifests
        result = analyze_manifests(args.manifests,same_host=args.same_host,partial=args.partial)
        with args.output.open('x',encoding='utf8') as stream:
            json.dump(result,stream,ensure_ascii=False,indent=2,allow_nan=False)
        print(json.dumps({'diagnostic_complete':result['diagnostic_complete'],
                          'steps':[r['global_step'] for r in result['steps']],
                          'output':str(args.output)},ensure_ascii=False))


if __name__ == '__main__':
    main()
