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
        if side == 'client':
            host.add_argument('--stream-map',action='store_true',help='显式公开帧区间sidecar；不启动系统跟踪')
            host.add_argument('--config',type=Path,default=Path('configs/lab-client-cart-pole-demo.example.yaml'))
        else:
            host.add_argument('--p1-config',type=Path,default=Path('configs/lab-p1-cart-pole-demo.example.yaml'))
            host.add_argument('--p2-config',type=Path,default=Path('configs/lab-p2-cart-pole-demo.example.yaml'))
    analyze = modes.add_parser('analyze',help='只读角色manifest，不运行控制')
    analyze.add_argument('manifests',type=Path,nargs='+')
    analyze.add_argument('--output',type=Path,required=True)
    analyze.add_argument('--same-host',action='store_true',help='没有实际同机spawn证明时拒绝合轴')
    analyze.add_argument('--partial',action='store_true',help='保留失败前缀/缺角色；不升级为完整证据')
    args = parser.parse_args()
    if args.mode == 'local':
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
            config_paths=paths,steps=args.steps,**({'stream_map':True} if args.mode=='client' and args.stream_map else {}))
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
