"""A08 Client 本机只读 Dashboard 的显式 HVAC、paper PID 和 verified 回放入口。"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import threading
from pathlib import Path

import numpy as np

from secure_control.execution import LocalhostSecureStateSpaceRuntime
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.scenarios.paper_pid.baseline import run_paper_pid_baseline
from secure_control.simulation.engine import compare_closed_loops
from secure_control.simulation.telemetry import (
    BoundedPublisher,
    TelemetrySession,
    observe_roles,
)

from .artifacts import SCHEMA_VERSION, load_artifacts, write_artifacts
from .dashboard_server import DashboardServer, DashboardState
from .paper_pid_fig3 import (
    PRECISIONS,
    _run_point,
    load_definition,
    render_saved_sweep,
)
from .provenance import collect_provenance


def run_live_hvac(
    config: str | Path,
    *,
    output_root: str | Path,
    test_seed: int | None,
    state: DashboardState,
    telemetry: TelemetrySession,
) -> str:
    """同一 localhost 结果既发布 A07 样本又写正式八字段，不重跑控制。"""
    scenario = HvacScenario(
        config, test_seed=test_seed, secure_runtime_builder=LocalhostSecureStateSpaceRuntime
    )
    plan = scenario.build_plan()
    runtime = plan.secure.runtime
    if not isinstance(runtime, LocalhostSecureStateSpaceRuntime):
        raise TypeError("Dashboard HVAC 必须使用本机三角色 runtime")
    try:
        telemetry.roles = observe_roles(runtime.topology)
        result = compare_closed_loops(
            plan.ideal, plan.secure, plan.sample_times, telemetry=telemetry
        )
        scenario.metrics(result)
        provenance = collect_provenance(
            scenario_name=scenario.metadata.name,
            scenario_version=scenario.scenario_version,
            schema_version=SCHEMA_VERSION,
            test_seed=test_seed,
        )
        provenance.update(
            {
                "backend": "localhost",
                "resource_counts": runtime.resource_counts,
                "public_telemetry_session_id": telemetry.session_id,
                "security_boundary": "loopback diagnostic; no deployment security claim",
            }
        )
        artifact = write_artifacts(
            result,
            scenario.metadata,
            scenario.effective_config_snapshot(),
            provenance,
            output_root=output_root,
        )
        # writer 自带 staging 复验；发布后再次经公开 reader 核对身份才开放 URL。
        record = load_artifacts(artifact.run_dir)
        if record.run_id != artifact.run_id or not np.array_equal(
            record.result.control_secure, result.control_secure
        ):
            raise ValueError("正式 run 读回与本次 Client 结果不一致")
        return state.register_run(artifact.run_dir, live_session_id=telemetry.session_id)
    except Exception:
        state.publication_failed()
        raise
    finally:
        runtime.close()


def run_live_paper(
    config: str | Path,
    *,
    ell: int,
    output_root: str | Path,
    test_seed: int,
    state: DashboardState,
    telemetry: TelemetrySession,
) -> str:
    """复用 #70 的单精度核验/发布，不把一次 live 冒称四点 Fig.3 扫描。"""
    try:
        definition, baseline_config, q, evidence = load_definition(config)
        baseline = run_paper_pid_baseline(
            alpha=baseline_config["plant"]["alpha"],
            sample_period_seconds=baseline_config["plant"]["sample_period_seconds"],
            plant_initial_state=baseline_config["plant"]["initial_state"],
            sample_count=definition["sample_count"],
        )
        record = _run_point(
            definition,
            baseline,
            q,
            evidence,
            ell,
            output_root=output_root,
            test_seed=test_seed,
            backend="localhost",
            telemetry=telemetry,
        )
        return state.register_run(
            Path(output_root) / record.run_id, live_session_id=telemetry.session_id
        )
    except Exception:
        state.publication_failed()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Client-only read-only control Dashboard")
    parser.add_argument("--port", type=int, default=8765, help="loopback HTTP port")
    parser.add_argument("--start-immediately", action="store_true")
    parser.add_argument(
        "--hold-seconds",
        type=float,
        default=None,
        help="CLI demo only: stop after this many seconds following the run",
    )
    sub = parser.add_subparsers(dest="mode", required=True)
    hvac = sub.add_parser("live-hvac")
    hvac.add_argument("--config", default="configs/hvac_2r2c_dual_loop_25_20_15.yaml")
    hvac.add_argument("--output-root", default="results/diagnostics/dashboard_hvac")
    hvac.add_argument("--seed", type=int, default=None)
    paper = sub.add_parser("live-paper")
    paper.add_argument("--config", default="configs/paper_pid_fig3_sweep.yaml")
    paper.add_argument("--output-root", default="results/diagnostics/dashboard_paper")
    paper.add_argument("--seed", type=int, default=70)
    paper.add_argument("--ell", type=int, choices=PRECISIONS, required=True)
    replay = sub.add_parser("replay-run")
    replay.add_argument("--run-dir", required=True)
    sweep = sub.add_parser("replay-paper-sweep")
    sweep.add_argument("--sweep-dir", default="results/paper_pid_fig3")
    return parser


def main(argv: list[str] | None = None) -> int:
    """URL/CLI 显式确定输入；页面没有运行、重试或路径写入 API。"""
    args = _parser().parse_args(argv)
    if args.port < 0 or args.port > 65535:
        raise ValueError("port 必须在 0..65535")
    if args.hold_seconds is not None and args.hold_seconds < 0:
        raise ValueError("hold-seconds 不能为负")
    state = DashboardState()
    try:
        if args.mode == "replay-run":
            state.register_run(args.run_dir)
        elif args.mode == "replay-paper-sweep":
            manifest = render_saved_sweep(args.sweep_dir)
            for entry in manifest["runs"]:
                state.register_run(Path(args.sweep_dir) / entry["run_id"])
    except Exception:  # noqa: BLE001 - CLI 不输出 reader 的本地路径和异常对象。
        print("正式结果未通过验证；页面未启动。", flush=True)
        return 1
    server = DashboardServer(state, port=args.port)
    server.start()
    print(f"Dashboard: {server.url}", flush=True)
    publisher: BoundedPublisher | None = None
    try:
        if args.mode.startswith("live-"):
            if not args.start_immediately:
                input("按 Enter 开始一次控制运行；页面只读。")
            publisher = BoundedPublisher(state.publish)
            state.publisher = publisher
            telemetry = TelemetrySession(publisher)
            try:
                if args.mode == "live-hvac":
                    run_id = run_live_hvac(
                        args.config,
                        output_root=args.output_root,
                        test_seed=args.seed,
                        state=state,
                        telemetry=telemetry,
                    )
                else:
                    run_id = run_live_paper(
                        args.config,
                        ell=args.ell,
                        output_root=args.output_root,
                        test_seed=args.seed,
                        state=state,
                        telemetry=telemetry,
                    )
                print(f"Verified replay run: {run_id}", flush=True)
            except Exception:  # noqa: BLE001 - CLI 禁止将底层异常文本泄漏到公开输出。
                # 公开 CLI 不打印异常文本、私有路径或诊断对象。
                state.publication_failed()
                print("控制或正式结果验证失败；回放不可用。", flush=True)
                return 1
        print("只读页面继续运行；Ctrl+C 退出。", flush=True)
        threading.Event().wait(args.hold_seconds)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        if publisher is not None:
            publisher.close()
        server.close()
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
