"""确定性明文起摆研究入口；独立于三角色 LAN/GUI，输出原始 JSON 与摘要。"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml

from secure_control.experiments.provenance import _git_provenance
from secure_control.scenarios.cart_pole.contract import _UniqueKeyLoader, load_cart_pole_contract
from secure_control.scenarios.cart_pole.controller import load_cart_pole_balance_config
from secure_control.scenarios.cart_pole.observer import load_cart_pole_observer_design
from secure_control.scenarios.cart_pole.swing_up import load_cart_pole_swing_up_config
from secure_control.scenarios.cart_pole.swing_up_experiment import (
    run_plaintext_full_experiment,
    run_swing_up_experiment,
    write_swing_up_report,
)


def main() -> int:
    """显式选择启动方向/单区间外力；配置和保存失败均不能返回成功。"""
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="倒立摆明文起摆可行性；没有安全计算或 GUI")
    parser.add_argument("config", nargs="?", type=Path,
                        default=project / "configs/cart_pole_swing_up.yaml")
    parser.add_argument("--direction", type=int, choices=(-1, 1))
    parser.add_argument("--route", choices=("legacy_static", "plaintext_full"),
                        default="legacy_static")
    parser.add_argument("--observer", type=Path,
                        default=project / "configs/cart_pole_observer.yaml")
    parser.add_argument("--disturbance", action="append", metavar="STEP:FORCE_N")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        root = yaml.load(args.config.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
        if not isinstance(root, dict):
            raise TypeError("起摆配置必须是映射")
        for name in ("plant_source", "balance_source"):
            if not isinstance(root.get(name), str) or not root[name].strip():
                raise ValueError(f"{name} 必须是非空路径")
        sources = {"swing_up": args.config, "plant": args.config.parent / root["plant_source"],
                   "balance": args.config.parent / root["balance_source"]}
        if args.route == "plaintext_full":
            sources["observer"] = args.observer
        # 运行前冻结源字节，运行后再核对；报告不能把后来变化的配置冒充本次来源。
        source_bytes = {name: path.read_bytes() for name, path in sources.items()}
        plant = load_cart_pole_contract(sources["plant"])
        balance = load_cart_pole_balance_config(sources["balance"], plant)
        config = load_cart_pole_swing_up_config(args.config, plant, balance)
        if args.direction is not None:
            config = replace(config, kick_direction=args.direction)
        if args.disturbance is not None:
            events = []
            for event in args.disturbance:
                step, force = event.split(":")
                events.append((int(step), float(force)))
            config = replace(config, disturbances=tuple(events))
        provenance = {
            "code_version": _git_provenance(project), "python_version": platform.python_version(),
            "source_snapshots": [{"role": name, "filename": sources[name].name,
                                  "sha256": hashlib.sha256(blob).hexdigest(),
                                  "yaml": yaml.load(blob, Loader=_UniqueKeyLoader)}
                                 for name, blob in source_bytes.items()],
        }
        if args.route == "plaintext_full":
            observer = load_cart_pole_observer_design(args.observer)
            if observer.plant != plant or observer.balance != balance:
                raise ValueError("observer来源与起摆物理/平衡来源不一致")
            result = run_plaintext_full_experiment(plant, balance, config, observer)
        else:
            result = run_swing_up_experiment(plant, balance, config)
        if any(path.read_bytes() != source_bytes[name] for name, path in sources.items()):
            raise ValueError("运行期间配置来源发生变化，不发布研究报告")
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        label = "cart-pole-swing-up" if args.route == "legacy_static" else "cart-pole-plaintext-full"
        output = args.output or project / "results/diagnostics" / f"{label}-{stamp}-{uuid4().hex}.json"
        write_swing_up_report(result, output, provenance=provenance)
        print(json.dumps({"status": result.termination, "goal_met": result.goal_met,
                          "report": str(output.resolve()),
                          "summary": result.to_report()["summary"],
                          "transitions": result.to_report()["transitions"],
                          "failure_reason": result.failure_reason}, ensure_ascii=False, allow_nan=False))
        return 0 if result.goal_met else 1
    except (OSError, TypeError, ValueError, FloatingPointError, OverflowError, yaml.YAMLError) as error:
        print(json.dumps({"status": "failed", "goal_met": False,
                          "category": type(error).__name__, "reason": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
