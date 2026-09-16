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
    summary: dict[str, object] = {
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
        "plant_state_names": certificate.plant_state_names,
        "plant_state_bounds_celsius": certificate.plant_state_bounds_celsius,
        "controller_input_bounds_celsius": certificate.controller_input_bounds_celsius,
        "input_payload_bounds": certificate.input_payload_bounds,
        "state_payload_bounds": certificate.state_payload_bounds,
        "maximum_state_accumulator_bounds": certificate.maximum_state_accumulator_bounds,
        "maximum_output_accumulator_bounds": certificate.maximum_output_accumulator_bounds,
        "state_truncation_bits": certificate.state_truncation_bits,
    }
    if comparison.comparison_metrics is not None:
        metrics = comparison.comparison_metrics
        summary["quality_passed"] = metrics.passed
        summary["comparison"] = {
            "max_control_error_kw": metrics.max_control_error_kw,
            "mean_control_error_kw": metrics.mean_control_error_kw,
            "rms_control_error_kw": metrics.rms_control_error_kw,
            "max_temperature_error_celsius": metrics.max_temperature_error_celsius,
            "mean_temperature_error_celsius": metrics.mean_temperature_error_celsius,
            "rms_temperature_error_celsius": metrics.rms_temperature_error_celsius,
        }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
