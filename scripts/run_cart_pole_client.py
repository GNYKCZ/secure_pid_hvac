"""直接运行倒立摆动画 Client；可选第一个参数为角色配置路径。"""

import argparse
import json
import signal
import sys
from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="倒立摆 Client：有限动画或持续后端")
    parser.add_argument("config", nargs="?", type=Path,
                        default=Path(__file__).resolve().parents[1]
                        / "configs/lab-client-cart-pole.example.yaml")
    parser.add_argument("--headless-continuous", action="store_true")
    parser.add_argument("--segment-steps", type=int, default=400)
    args = parser.parse_args()
    if args.headless_continuous:
        from secure_control.execution.lan_config import load_lan_config
        from secure_control.execution.lan_runtime import RunControl
        from secure_control.experiments.lan_runner import run_client_segmented

        control = RunControl()
        # Ctrl+C 仅提交正常停止意图，不抛 KeyboardInterrupt 截断协议 I/O。
        previous = signal.signal(signal.SIGINT, lambda *_args: control.request_stop())
        try:
            result = run_client_segmented(
                load_lan_config(args.config, "Client"),
                segment_steps=args.segment_steps, control=control,
            )
            print(json.dumps(result, ensure_ascii=False))
        finally:
            signal.signal(signal.SIGINT, previous)
        sys.exit(0 if result["status"] == "stopped" else 1)
    # 其他场景和 P1/P2 从不导入 Tk；只有专用入口创建窗口。
    from secure_control.scenarios.cart_pole.gui import run_window

    run_window(args.config)
