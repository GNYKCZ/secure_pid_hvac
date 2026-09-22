"""比较 Issue #16 spawn backend 与 localhost TCP backend 的安全 HVAC 结果。"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
from pathlib import Path
from typing import Any

import numpy as np

from secure_control.execution import (
    LocalhostSecureStateSpaceRuntime,
    MultiprocessingSecureStateSpaceRuntime,
)
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation.engine import compare_closed_loops


def run_localhost_comparison(
    config_path: str | Path, *, test_seed: int | None = None
) -> dict[str, Any]:
    """以同一配置和 seed 比较两个隔离 backend，并返回不含秘密的摘要。"""
    process_scenario = HvacScenario(
        config_path,
        test_seed=test_seed,
        secure_runtime_builder=MultiprocessingSecureStateSpaceRuntime,
    )
    process_plan = process_scenario.build_plan()
    process_runtime = process_plan.secure.runtime
    if not isinstance(process_runtime, MultiprocessingSecureStateSpaceRuntime):
        raise TypeError("#16 对照场景未构造预期 multiprocessing runtime。")

    localhost_runtime: LocalhostSecureStateSpaceRuntime | None = None
    try:
        localhost_scenario = HvacScenario(
            config_path,
            test_seed=test_seed,
            secure_runtime_builder=LocalhostSecureStateSpaceRuntime,
        )
        localhost_plan = localhost_scenario.build_plan()
        candidate = localhost_plan.secure.runtime
        if not isinstance(candidate, LocalhostSecureStateSpaceRuntime):
            raise TypeError("localhost 场景未构造预期 runtime。")
        localhost_runtime = candidate
        process_result = compare_closed_loops(
            process_plan.ideal,
            process_plan.secure,
            process_plan.sample_times,
        )
        localhost_result = compare_closed_loops(
            localhost_plan.ideal,
            localhost_plan.secure,
            localhost_plan.sample_times,
        )
        topology = localhost_runtime.topology
        return {
            "host": topology.host,
            "port": topology.port,
            "role_pids": {item.role: item.pid for item in topology.roles},
            "sample_count": int(localhost_result.time.size),
            "maximum_control_difference": float(
                np.max(np.abs(process_result.control_secure - localhost_result.control_secure))
            ),
            "maximum_output_difference": float(
                np.max(np.abs(process_result.output_secure - localhost_result.output_secure))
            ),
            "resource_counts": localhost_runtime.resource_counts,
            "resource_counts_match_issue16": (
                localhost_runtime.resource_counts == process_runtime.resource_counts
            ),
            "cleanup": "closed",
            "security_boundary": (
                "loopback transport simulation only; no TLS, authentication, or "
                "production security claim"
            ),
        }
    finally:
        if localhost_runtime is not None:
            localhost_runtime.close()
        process_runtime.close()


def main() -> None:
    """从命令行运行比较并仅输出不含 share 的 JSON 摘要。"""
    parser = argparse.ArgumentParser(description="Compare Issue #16 and localhost execution")
    parser.add_argument("--config", required=True, help="HVAC wrapper YAML")
    parser.add_argument("--seed", type=int, default=None, help="test-only material seed")
    args = parser.parse_args()
    print(
        json.dumps(
            run_localhost_comparison(args.config, test_seed=args.seed),
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    mp.freeze_support()
    main()
