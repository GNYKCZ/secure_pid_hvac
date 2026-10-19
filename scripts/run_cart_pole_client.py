"""直接运行倒立摆动画 Client；可选第一个参数为角色配置路径。"""

import argparse
import json
import signal
import sys
from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="倒立摆 Client：默认持续动画与停止保存")
    parser.add_argument("config", nargs="?", type=Path,
                        default=Path(__file__).resolve().parents[1]
                        / "configs/lab-client-cart-pole.example.yaml")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--headless-continuous", action="store_true")
    modes.add_argument("--finite", action="store_true")
    modes.add_argument("--full-route", choices=("plaintext", "secure"))
    modes.add_argument("--full-gui-route", choices=("plaintext", "secure"))
    parser.add_argument("--segment-steps", type=int, default=400)
    parser.add_argument("--preload-steps", type=int, default=0,
                        help="动态v2有限预送窗口，1..1000；耗尽后正常停止")
    parser.add_argument("--preload-execution", choices=("staged", "fused"), default="fused")
    parser.add_argument("--recording", choices=("light", "full"),
                        help="仅动态持续：默认light不保存完整轨迹；full可靠留证并支持回放")
    parser.add_argument("--non-realtime", action="store_true",
                        help="仅动态持续light：无周期截止的非实时仿真，模型步长保持不变")
    parser.add_argument("--full-output", type=Path)
    parser.add_argument("--full-non-realtime", action="store_true",
                        help="安全完整路线的显式非实时诊断；没有20ms资格")
    parser.add_argument("--swing-config", type=Path,
                        default=Path(__file__).resolve().parents[1]
                        / "configs/cart_pole_swing_up.yaml")
    parser.add_argument("--observer-config", type=Path,
                        default=Path(__file__).resolve().parents[1]
                        / "configs/cart_pole_observer.yaml")
    parser.add_argument("--prime-config", type=Path,
                        default=Path(__file__).resolve().parents[1]
                        / "configs/shared_prime_256_pocklington.yaml")
    args = parser.parse_args()
    # 在创建窗口/连接/供料前拒绝不兼容模式，不能悄悄忽略 wire 或 full 请求。
    if args.non_realtime or not (args.full_route == "plaintext" or args.full_gui_route == "plaintext"):
        from secure_control.execution.lan_config import load_lan_config
        from secure_control.execution.localhost_codec import _COMPACT_PROFILE_V2

        selected = load_lan_config(args.config, "Client")
        if args.non_realtime or selected.wire_profile == _COMPACT_PROFILE_V2:
            if args.finite or args.full_route or args.full_gui_route:
                parser.error("compact-v2 / --non-realtime 仅支持动态持续light，不支持finite或完整路线")
            from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
            from secure_control.experiments.lan_runner import validate_segmented_mode
            from secure_control.scenarios.cart_pole.interactive import InteractiveSession

            try:
                prepared = load_segmented_experiment(selected.experiment_config, args.segment_steps,
                                                     InteractiveSession())
                validate_segmented_mode(selected, prepared, non_realtime=args.non_realtime,
                                        recording_mode=args.recording, preload_steps=args.preload_steps)
            except (ValueError, TypeError) as error:
                parser.error(str(error))
    if args.recording is not None and (args.finite or args.full_route or args.full_gui_route):
        parser.error("--recording 只支持动态observer持续入口")
    if args.full_non_realtime and args.full_route != "secure" and args.full_gui_route != "secure":
        parser.error("--full-non-realtime 只支持安全完整路线诊断")
    if (not 0 <= args.preload_steps <= 1000 or args.preload_steps and (
            args.finite or args.full_route or args.full_gui_route)):
        parser.error("--preload-steps 只支持动态v2持续入口，范围1..1000")
    if args.full_gui_route:
        if args.full_output is None:
            parser.error("--full-gui-route 需要 --full-output 指定新结果目录")
        from secure_control.scenarios.cart_pole.gui import run_full_window

        run_full_window(
            args.config, route=args.full_gui_route, observer_path=args.observer_config,
            swing_path=args.swing_config, prime_path=args.prime_config,
            output=args.full_output, segment_steps=args.segment_steps,
            realtime=not args.full_non_realtime,
        )
        sys.exit(0)
    if args.full_route:
        from secure_control.execution.lan_config import load_lan_config
        from secure_control.experiments.cart_pole_full_evidence import (
            write_cart_pole_full_run,
            write_cart_pole_plaintext_full_run,
        )
        from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
        from secure_control.scenarios.cart_pole.swing_up import load_cart_pole_swing_up_config
        from secure_control.scenarios.cart_pole.swing_up_experiment import (
            run_plaintext_full_experiment,
        )

        if args.full_output is None:
            parser.error("--full-route 需要 --full-output 指定新结果目录")
        design = load_cart_pole_observer_design(args.observer_config)
        swing = load_cart_pole_swing_up_config(
            args.swing_config, design.plant, design.balance,
        )
        if args.full_route == "plaintext":
            physical = run_plaintext_full_experiment(
                design.plant, design.balance, swing, design,
            )
            target = write_cart_pole_plaintext_full_run(physical, args.full_output)
        else:
            from secure_control.experiments.lan_profile import _load_prime
            from secure_control.scenarios.cart_pole.secure_full_experiment import (
                run_secure_full_experiment,
            )

            modulus, evidence, _ = _load_prime(args.prime_config)
            client = load_lan_config(args.config, "Client")
            result = run_secure_full_experiment(
                design.plant, design.balance, swing, design, client,
                modulus=modulus, modulus_evidence=evidence,
                segment_capacity=args.segment_steps,
                realtime=not args.full_non_realtime,
            )
            sealed = any(c["physical_end"] > 0 for e in result.epoch_events for c in e["closed_segments"])
            target = write_cart_pole_full_run(result, args.full_output) if sealed else None
        timing = ({} if args.full_route == "plaintext" else {
            "timing_mode": "non_realtime_diagnostic" if args.full_non_realtime else "absolute",
            "cycle_failure": result.cycle_failure,
            "cycle_attempts": len(result.cycles),
            "physically_confirmed_count": result.physically_confirmed_count,
            "evidence_state": "published_verified_prefix" if target else "no_sealed_prefix",
        })
        print(json.dumps({"route": args.full_route, "run_dir": str(target) if target else None,
                          "completed_steps": (physical.completed_steps
                                              if args.full_route == "plaintext" else
                                              result.physical.completed_steps),
                          "termination": (physical.termination
                                          if args.full_route == "plaintext" else
                                          result.physical.termination),
                          "goal_met": (physical.goal_met
                                       if args.full_route == "plaintext" else
                                       result.physical.goal_met), **timing},
                         ensure_ascii=False))
        sys.exit(0 if (physical.goal_met if args.full_route == "plaintext"
                       else result.physical.goal_met) else 1)
    if args.headless_continuous:
        from secure_control.execution.lan_config import load_lan_config
        from secure_control.execution.lan_runtime import RunControl
        from secure_control.experiments.cart_pole_lan_profile import load_cart_pole_lan_profile
        from secure_control.experiments.cart_pole_segmented_evidence import run_cart_pole_segmented
        from secure_control.experiments.lan_runner import run_client_segmented
        from secure_control.scenarios.cart_pole.interactive import InteractiveSession

        control = RunControl()
        config = load_lan_config(args.config, "Client")
        if config.experiment_config is None:
            raise ValueError("缺少倒立摆 Client profile。")
        dynamic = load_cart_pole_lan_profile(config.experiment_config).observer_design is not None
        if args.preload_steps and not dynamic:
            parser.error("--preload-steps 需要动态observer配置")
        if args.recording is not None and not dynamic:
            parser.error("--recording 需要动态observer配置")
        # Ctrl+C 仅提交正常停止意图，不抛 KeyboardInterrupt 截断协议 I/O。
        previous = signal.signal(signal.SIGINT, lambda *_args: control.request_stop())
        try:
            result = (run_cart_pole_segmented(
                config, segment_steps=args.segment_steps, control=control,
                session=InteractiveSession(),
                preload_steps=args.preload_steps, preload_execution=args.preload_execution,
                recording_mode=args.recording,
                **({"non_realtime": True} if args.non_realtime else {}),
            ) if dynamic else run_client_segmented(
                config, segment_steps=args.segment_steps, control=control,
            ))
            print(json.dumps(result, ensure_ascii=False))
        finally:
            signal.signal(signal.SIGINT, previous)
        sys.exit(0 if result["status"] in ("stopped", "complete") else 1)
    # 其他场景和 P1/P2 从不导入 Tk；只有专用入口创建窗口。
    from secure_control.scenarios.cart_pole.gui import run_window

    run_window(args.config, segment_steps=args.segment_steps,
               mode="finite" if args.finite else "segmented",
               preload_steps=args.preload_steps, preload_execution=args.preload_execution,
               recording_mode=args.recording,
               **({"non_realtime": True} if args.non_realtime else {}))
