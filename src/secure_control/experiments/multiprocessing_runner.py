"""比较单进程与 spawn 三进程安全 HVAC 执行结果。"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
from pathlib import Path
from typing import Any

import numpy as np

from secure_control.execution import MultiprocessingSecureStateSpaceRuntime
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation.engine import compare_closed_loops


def run_multiprocessing_comparison(
    config_path: str | Path, *, test_seed: int | None = None
) -> dict[str, Any]:
    """运行同一 HVAC 配置的两个安全后端并返回公开比较摘要。"""
    local_scenario = HvacScenario(config_path, test_seed=test_seed)
    local_plan = local_scenario.build_plan()
    local_result = compare_closed_loops(
        local_plan.ideal,
        local_plan.secure,
        local_plan.sample_times,
    )
    process_scenario = HvacScenario(
        config_path,
        test_seed=test_seed,
        secure_runtime_builder=MultiprocessingSecureStateSpaceRuntime,
    )
    plan = process_scenario.build_plan()
    runtime = plan.secure.runtime
    if not isinstance(runtime, MultiprocessingSecureStateSpaceRuntime):
        raise TypeError("多进程场景未构造预期 runtime。")
    try:
        process_result = compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
        topology = runtime.topology
        return {
            "start_method": topology.start_method,
            "parent_pid": topology.parent_pid,
            "role_pids": {item.role: item.pid for item in topology.roles},
            "sample_count": int(process_result.time.size),
            "maximum_control_difference": float(
                np.max(np.abs(local_result.control_secure - process_result.control_secure))
            ),
            "maximum_output_difference": float(
                np.max(np.abs(local_result.output_secure - process_result.output_secure))
            ),
            "resource_counts": runtime.resource_counts,
            "cleanup": "closed",
            "security_boundary": (
                "Client owns plaintext and reconstruction; P1/P2 retain only their local shares"
            ),
        }
    finally:
        runtime.close()


def main() -> None:
    """从命令行运行比较并仅输出不含秘密份额的 JSON 摘要。"""
    parser = argparse.ArgumentParser(description="Compare local and spawn secure HVAC execution")
    parser.add_argument("--config", required=True, help="HVAC wrapper YAML")
    parser.add_argument("--seed", type=int, default=None, help="test-only material seed")
    args = parser.parse_args()
    print(
        json.dumps(
            run_multiprocessing_comparison(args.config, test_seed=args.seed),
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    mp.freeze_support()
    main()
