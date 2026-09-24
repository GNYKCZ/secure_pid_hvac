"""直接运行 P2 实验角色；可选的第一个参数为角色配置路径。"""

import sys
from pathlib import Path

from secure_control.experiments.lan_runner import cli

if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("只接受一个可选的角色配置路径。")
    config = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else (Path(__file__).resolve().parents[1] / "configs/lab-p2.example.yaml")
    )
    sys.argv = [sys.argv[0], "p2", "--config", str(config)]
    cli()
