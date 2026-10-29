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
        host.add_argument('--steps',type=int,default=400)
        host.add_argument('--window',type=int,choices=(400,2000),default=400,help='显式版本窗口，旧默认400保持')
        if side == 'client':
            host.add_argument('--stream-map',action='store_true',help='显式公开帧区间sidecar；不启动系统跟踪')
            host.add_argument('--native-plan',type=Path,help='仅2000专项：用户明确执行时才启动计划中的自有WPR会话')
            host.add_argument('--config',type=Path,default=Path('configs/lab-client-cart-pole-demo.example.yaml'))
        else:
            host.add_argument('--p1-config',type=Path,default=Path('configs/lab-p1-cart-pole-demo.example.yaml'))
            host.add_argument('--p2-config',type=Path,default=Path('configs/lab-p2-cart-pole-demo.example.yaml'))
    prepare = modes.add_parser('prepare-native',help='只读核查profile/source/session，写计划，不启动采集/控制')
    prepare.add_argument('output',type=Path)
    prepare.add_argument('--expected-head',required=True)
    file_prepare=modes.add_parser('prepare-file-calibration',help='只读准备显式File校准计划，不采集/发流量')
    file_prepare.add_argument('output',type=Path)
    file_prepare.add_argument('--expected-head',required=True)
    file_prepare.add_argument('--config',type=Path,required=True,help='只读绑定Client拓扑摘要，不联网')
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
    analyze = modes.add_parser('analyze',help='只读角色manifest，不运行控制')
    analyze.add_argument('manifests',type=Path,nargs='+')
    analyze.add_argument('--output',type=Path,required=True)
    analyze.add_argument('--same-host',action='store_true',help='没有实际同机spawn证明时拒绝合轴')
    analyze.add_argument('--partial',action='store_true',help='保留失败前缀/缺角色；不升级为完整证据')
    args = parser.parse_args()
    if args.mode in ('prepare-native','prepare-file-calibration'):
        import subprocess

        from secure_control.experiments.native_tail_capture import prepare_native
        from secure_control.experiments.tail_diagnostic_runner import ROOT
        head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        if head!=args.expected_head:
            parser.error('准备计划head不一致')
        file_candidate=args.mode=='prepare-file-calibration'
        result = prepare_native(ROOT/('configs/control-tail-calibration.wprp' if file_candidate
                                      else 'configs/control-tail-native-2000.wprp'),_file_candidate=file_candidate)
        if file_candidate:
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
               if args.mode=='client' and args.native_plan else {}))
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
