"""直接运行倒立摆动画 Client；可选第一个参数为角色配置路径。"""

import sys
from pathlib import Path

if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("只接受一个可选的 Client 角色配置路径。")
    config = (Path(sys.argv[1]) if len(sys.argv) == 2 else
              Path(__file__).resolve().parents[1] / "configs/lab-client-cart-pole.example.yaml")
    # 其他场景和 P1/P2 从不导入 Tk；只有专用入口创建窗口。
    from secure_control.scenarios.cart_pole.gui import run_window

    run_window(config)
