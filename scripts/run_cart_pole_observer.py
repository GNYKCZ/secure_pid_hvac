"""两测量动态倒立摆的有限明文入口；不启动安全协议、网络或动画。"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml

from secure_control.experiments.provenance import _git_provenance
from secure_control.scenarios.cart_pole import (
    load_cart_pole_observer_design,
    run_observer_balance_experiment,
    write_observer_balance_report,
)
from secure_control.scenarios.cart_pole.contract import _UniqueKeyLoader


def main() -> int:
    """统一加载三源、编译、运行及保存；失败/不稳定/保存失败均exit=1。"""
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="倒立摆两测量动态明文基线（理想真值监督）")
    parser.add_argument("config", nargs="?", type=Path,
                        default=project / "configs/cart_pole_observer.yaml")
    parser.add_argument("--disturbance", action="append", metavar="STEP:FORCE_N")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        design = load_cart_pole_observer_design(args.config)
        sources = json.loads(design.source_snapshots_json)
        root = yaml.load(args.config.read_bytes(), Loader=_UniqueKeyLoader)
        source_paths = {"observer": args.config, "plant": args.config.parent / root["plant_source"],
                        "balance": args.config.parent / root["balance_source"]}
        def verify_sources() -> None:
            """来源摘要覆盖统一编译期间至报告保存前，不把后改源冒充本次参数。"""
            if any(hashlib.sha256(source_paths[item["role"]].read_bytes()).hexdigest() != item["sha256"]
                   for item in sources):
                raise ValueError("运行期间配置来源发生变化，不发布报告")

        verify_sources()
        disturbances = []
        for token in args.disturbance or ():
            step, force = token.split(":")
            disturbances.append((int(step), float(force)))
        provenance = {"code_version": _git_provenance(project), "python_version": platform.python_version()}
        result = run_observer_balance_experiment(design, disturbances=tuple(disturbances))
        verify_sources()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        output = args.output or project / "results/diagnostics" / f"cart-pole-observer-{stamp}-{uuid4().hex}.json"
        write_observer_balance_report(result, output, provenance=provenance)
        print(json.dumps({"status": result.termination, "goal_met": result.goal_met,
                          "report": str(output.resolve()), "summary": result.to_report()["summary"],
                          "failure_reason": result.failure_reason}, ensure_ascii=False, allow_nan=False))
        return 0 if result.goal_met else 1
    except (OSError, TypeError, ValueError, FloatingPointError, OverflowError,
            RuntimeError, UserWarning, yaml.YAMLError) as error:
        print(json.dumps({"status": "failed", "goal_met": False,
                          "category": type(error).__name__, "reason": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
