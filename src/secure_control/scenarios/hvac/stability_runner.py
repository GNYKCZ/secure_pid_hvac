"""将冻结 2R2C HVAC 局部闭环稳定性报告输出为标准 JSON。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from .stability import analyze_hvac_closed_loop_stability


def main(argv: Sequence[str] | None = None) -> int:
    """解析两个配置路径并输出报告；所有数学逻辑均委托给分析模块。"""
    parser = argparse.ArgumentParser(description="分析 2R2C HVAC 局部未饱和闭环稳定性")
    parser.add_argument("plant_config", type=Path, help="2R2C plant YAML 路径")
    parser.add_argument("pid_config", type=Path, help="2R2C PID baseline YAML 路径")
    parser.add_argument(
        "--boundary-tolerance",
        type=float,
        default=1e-9,
        help="单位圆分类灰区半宽",
    )
    arguments = parser.parse_args(argv)
    report = analyze_hvac_closed_loop_stability(
        arguments.plant_config,
        arguments.pid_config,
        boundary_tolerance=arguments.boundary_tolerance,
    )
    print(json.dumps(asdict(report), ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":  # pragma: no cover - 由 CLI 手工入口覆盖。
    raise SystemExit(main())
