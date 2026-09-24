"""直接运行 Client 实验角色并发布图；可选的第一个参数为角色配置路径。"""

import sys
from pathlib import Path

from secure_control.experiments.lan_runner import cli

if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("只接受一个可选的角色配置路径。")
    config = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else (Path(__file__).resolve().parents[1] / "configs/lab-client-continuous.example.yaml")
    )
    sys.argv = [sys.argv[0], "client", "--config", str(config)]
    cli()
