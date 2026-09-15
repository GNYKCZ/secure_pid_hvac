"""HVAC 双闭环的场景级可重复 CLI；通用 simulation.runner 不选择场景。"""

from __future__ import annotations

import argparse
import json

import numpy as np

from .integration import run_hvac_dual_loop


def main() -> None:
    """读取场景配置并输出实际计算的摘要，不保存 #13 的正式结果文件。"""
    parser = argparse.ArgumentParser(description="Run the HVAC ideal/secure dual closed loop")
    parser.add_argument("--config", required=True, help="HVAC dual-loop YAML path")
    parser.add_argument(
        "--seed", type=int, default=None, help="test-only deterministic material seed"
    )
    args = parser.parse_args()
    comparison = run_hvac_dual_loop(args.config, test_seed=args.seed)
    result = comparison.result
    certificate = comparison.safety_certificate
    summary = {
        "sample_count": int(result.time.size),
        "maximum_applied_control_error_kw": float(np.max(np.abs(result.control_error))),
        "maximum_output_error_celsius": float(np.max(np.abs(result.output_error))),
        "tail_mae_ideal_celsius": [
            metric.tail_mae_celsius for metric in comparison.segment_metrics_ideal
        ],
        "tail_mae_secure_celsius": [
            metric.tail_mae_celsius for metric in comparison.segment_metrics_secure
        ],
        "finite_horizon_steps": certificate.horizon_steps,
        "temperature_bounds_celsius": certificate.temperature_bounds_celsius,
        "input_payload_bound": certificate.input_payload_bound,
        "state_payload_bounds": certificate.state_payload_bounds,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
