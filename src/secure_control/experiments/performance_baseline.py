"""采集扰动对照的计划与离线指标；不拥有协议、材料或系统采集会话。"""

from __future__ import annotations

import json
import math
import os
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path
from time import monotonic
from types import SimpleNamespace

from secure_control.experiments.live_timing import validate_timing_report

PURPOSE = "capture-overhead-baseline-v1"
MANUAL_PURPOSE = "capture-overhead-manual-v1"
CONDITIONS = ("L", "F", "F", "L", "F", "L", "L", "F")


def environments_match(left, right):
    """缺测不当作相等；进程数自然变化也保守记漂移，不据此认定因果。"""
    required = ("routes", "cpu_topology", "process_count")
    return (left.get("verified") is True and right.get("verified") is True
            and all(left.get(k) is not None and right.get(k) is not None for k in required)
            and left == right)


def verify_baseline_numbers(prepared, config, records, inputs, setup):
    """退出后复用既有物理重放/encoded Trunc包络，不从实测输出生成expected。"""
    from dataclasses import asdict

    import numpy as np

    from secure_control.execution.localhost_codec import encode_wire_value
    from secure_control.experiments.cart_pole_segmented_evidence import (
        _DynamicDefinition,
        _DynamicReplay,
    )

    definition = _DynamicDefinition({"definition": prepared.effective_config,
        "setup": json.loads(encode_wire_value(setup)),
        "topology_sha256": config.topology.digest, "transport": config.transport,
        "channels": asdict(prepared.metadata)})
    rows = []
    for index, record in enumerate(records):
        if record is None or record.protocol.global_step != index:
            raise ValueError("数值记录缺步、重复或身份错位。")
        snapshot = json.loads(json.dumps(record.snapshot if isinstance(record.snapshot, dict)
                                        else asdict(record.snapshot), allow_nan=False))
        if not np.array_equal(inputs[index], snapshot["local_measurement"]):
            raise ValueError("实际分享输入与独立物理测量不一致。")
        rows.append({"snapshot": snapshot, "protocol": {"raw_control": record.protocol.raw_control}})
    replay = _DynamicReplay(definition)
    replay.convert({"steps": rows}, "baseline", 0, lambda: None)
    return {"verified": True, "steps": replay.step,
            "oracle": "cart_pole_segmented_evidence.DynamicReplay encoded Trunc envelope + physical replay"}


def authorize_baseline(approval, plan, *, side, output, head):
    """新用途逐组批准绑定完整计划，旧control批准不能用于对照运行。"""
    from secure_control.experiments.native_tail_capture import plan_digest
    index = plan.get("index")
    manual = plan.get("purpose") == MANUAL_PURPOSE
    if (not isinstance(approval, dict) or plan.get("schema") != "baseline-run-plan-v1"
            or plan.get("purpose") not in (PURPOSE, MANUAL_PURPOSE) or plan.get("source_head") != head
            or type(index) is not int or not 0 <= index < 8
            or plan.get("condition") != CONDITIONS[index]
            or side not in ("client", "pair")
            or approval.get("schema") != ("baseline-manual-authorization-v1" if manual else "baseline-authorization-v1")
            or approval.get("purpose") != plan["purpose"] or approval.get("source_head") != head
            or approval.get("plan_sha256") != plan_digest(plan)
            or type(approval.get("attempts")) is not int or approval["attempts"] != 1
            or type(plan.get("steps")) is not int or plan["steps"] != 2000
            or str(Path(output).resolve()) != plan.get("outputs", {}).get(side)
            or not re.fullmatch(r"https://github.com/GNYKCZ/secure_pid_hvac/issues/166#issuecomment-[0-9]+",
                                str(approval.get("authorization_url", "")))):
        raise PermissionError("需要本组新用途、准确计划绑定的运行批准。")
    batch = plan.get("batch", {})
    canonical = baseline_plan(head, batch.get("configurations"), batch.get("outputs"))
    if (batch.get("plan") != canonical or plan.get("configurations") != canonical["configurations"]
            or plan.get("outputs") != canonical["runs"][index]["outputs"]):
        raise PermissionError("批次配置、顺序或路径发生变化。")


def baseline_environment(configs=()):
    """只读公开环境摘要；不枚举进程内容，不改变后台会话。"""
    result = {"os": platform.platform(), "python": platform.python_version(),
              "cpu_logical_count": os.cpu_count(), "machine": platform.machine()}
    result.update(cpu_topology=None, process_count=None, routes=None, verified=False)
    try:
        import ipaddress
        targets = sorted({str(ipaddress.ip_address(endpoint.host)) for config in configs
                          for endpoint in (config.topology.p1_client, config.topology.p2_client,
                                           config.topology.p1_peer)})
        if not targets:
            raise ValueError("缺少实际路由目标。")
        if os.name == "nt":
            script = (
                "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
                "$targets=ConvertFrom-Json $env:BASELINE_TARGETS;"
                "$routes=@(foreach($target in $targets){"
                "$r=Find-NetRoute -RemoteIPAddress $target;"
                "[pscustomobject]@{target=$target;selection=@($r | Select-Object "
                "InterfaceIndex,InterfaceAlias,IPAddress,NextHop,DestinationPrefix)}});"
                "[pscustomobject]@{cpu_topology=@(Get-CimInstance Win32_Processor | "
                "Select-Object DeviceID,NumberOfCores,NumberOfLogicalProcessors);"
                "process_count=@(Get-Process).Count;routes=$routes}|ConvertTo-Json -Depth 6 -Compress")
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                                        "-Command", script], capture_output=True, timeout=10,
                                       env={**os.environ, "BASELINE_TARGETS": json.dumps(targets)},
                                       check=True)
            facts = json.loads(completed.stdout.decode("utf-8-sig"))
        else:
            cpu = []
            for path in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/topology")):
                cpu.append({"cpu": path.parent.name,
                            "package": (path / "physical_package_id").read_text().strip(),
                            "core": (path / "core_id").read_text().strip()})
            routes = []
            for target in targets:
                raw = subprocess.check_output(["ip", "-j", "route", "get", target], timeout=5)
                routes.append({"target": target, "selection": json.loads(raw)})
            facts = {"cpu_topology": cpu, "process_count": sum(p.name.isdigit() for p in Path("/proc").iterdir()),
                     "routes": routes}
        if (not facts.get("cpu_topology") or not facts.get("routes")
                or type(facts.get("process_count")) is not int or facts["process_count"] < 1):
            raise ValueError("环境事实不完整。")
        result.update(facts, verified=True)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result["verification_error"] = type(error).__name__
    if os.name == "nt":
        from secure_control.experiments.native_tail_capture import _session_snapshot, _sessions
        result["background_sessions"] = _session_snapshot(_sessions())["stable"]
    else:
        result["background_sessions"] = None
    return result


def run_baseline_host(plan, approval, side, *, config_paths, output, expected_head):
    """显式运行一组的一端，唯一账本先扣额；无自动重试或旧诊断门禁降级。"""
    # RV-002：当前部署尚未提供在线共享邮箱，静态批准绝不能单独启动。
    # 在新在线握手实现与复审通过前显式阻断；不把离线ticket当动态授权。
    raise RuntimeError("baseline online coordinator unavailable: shared mailbox deployment required")


def _run_baseline_host_approved(plan, approval, side, *, config_paths, output, expected_head):
    """保留待在线门禁接入的装配；不是正式运行入口，不提供CLI降级开关。"""
    from secure_control.execution.lan_config import load_lan_config
    from secure_control.experiments.native_tail_capture import NativeCapture, plan_digest
    from secure_control.experiments.tail_diagnostic_runner import (
        ROOT,
        _collect_host,
        _config_identity,
        _sha,
        _write_new,
    )
    started = time.perf_counter()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    output = Path(output).resolve()
    authorize_baseline(approval, plan, side=side, output=output, head=head)
    if head != expected_head or subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip():
        raise ValueError("运行需要计划对应的干净源码。")
    roles = ("Client",) if side == "client" else ("P1", "P2")
    if len(config_paths) != len(roles):
        raise ValueError("角色配置数量不符。")
    configs = [load_lan_config(p, r) for p, r in zip(config_paths, roles, strict=True)]
    for config in configs:
        if (_config_identity(config) != plan.get("configurations", {}).get(config.role)
                or config.transport != "insecure_tcp"
                or config.wire_profile != "control-dynamic-matrix-preauthorized-v2"
                or config.role == "Client" and config.client_io != "ready-v1"):
            raise ValueError("角色、拓扑或公开配置与计划不符。")
    if output.exists():
        raise FileExistsError(output)
    parent = output.parent
    while not parent.exists():
        parent = parent.parent
    if shutil.disk_usage(parent).free < 4 * 1024**3:
        raise ValueError("磁盘余量不足4GiB。")
    environment = baseline_environment(configs)
    native = None
    if plan["condition"] == "F":
        node = plan.get("hosts", {}).get(side, {})
        if node.get("source_head") != head:
            raise ValueError("采集节点版本不符。")
        if os.name != "nt":
            raise ValueError("此平台没有获批原生采集能力，不能将F降级为L。")
        native = NativeCapture(node, output / "native.etl", authorization=approval,
                               authorization_plan=plan, side=side)
        native.preflight()
    ledger_root = ROOT / "results" / "tail_diagnostics"
    ledger_root.mkdir(parents=True, exist_ok=True)
    # 摘要绑定路径但不足以防换路径重跑，所以永久账本使用批准URL与组号。
    import hashlib
    identity = hashlib.sha256(approval["authorization_url"].encode()).hexdigest()
    ledger = ledger_root / f"baseline-{identity}-{plan['index']}-{side}.json"
    _write_new(ledger, {"status": "reserved", "plan_sha256": plan_digest(plan)})
    output.mkdir(parents=True, exist_ok=False)
    _write_new(output / "plan.json", plan)
    group = _collect_host(configs, SimpleNamespace(window=2000), 2000,
                          wall_started=started, control_file=True, b_receive_boundary=True,
                          native=native, _child=baseline_child, _baseline=True)
    if native is not None:
        (output / "native-owner.json").write_text(json.dumps(native.report), encoding="utf-8")
    after = baseline_environment(configs)
    reports = group["roles"]
    functional = (len(reports) == len(roles) and not group["stop_reason"]
                  and not group["forced_cleanup"] and all(
                      r["status"] in ("stopped", "closed") for r in reports))
    for report in reports:
        _write_new(output / (report["role"] + ".json"), report)
        if report["role"] == "Client":
            outcome = report.get("outcome", {})
            functional = functional and outcome.get("confirmed_step_count") == 2000
            functional = functional and outcome.get("protocol_committed_count") == 2000
            functional = functional and report.get("numerical_validation", {}).get("verified") is True
            try:
                metrics = baseline_metrics(report["timing"])
                _write_new(output / "metrics.json", metrics)
            except (KeyError, ValueError) as error:
                functional = False
                _write_new(output / "metrics-failure.json", {"error_type": type(error).__name__})
    result = {"schema": "baseline-host-result-v1", "source_head": head,
              "plan_sha256": plan_digest(plan), "side": side,
              "index": plan["index"], "condition": plan["condition"],
              "functional_complete": functional, "environment_before": environment,
              "environment_after": after, "environment_unchanged": environments_match(environment, after),
              "capture_complete": native is None or group.get("native", {}).get("status") == "saved",
              "artifact_bytes": sum(p.stat().st_size for p in output.iterdir() if p.is_file()),
              "group": group, "files": {p.name: _sha(p) for p in output.iterdir() if p.is_file()}}
    _write_new(output / "manifest.json", result)
    return result


def prepare_run_plans(spec):
    """从人工协调的批次规格生成八份只读计划；不启动角色或采集。"""
    batch = baseline_plan(spec["source_head"], spec["configurations"], spec["outputs"])
    return [{"schema": "baseline-run-plan-v1", "purpose": PURPOSE,
             "source_head": spec["source_head"], "steps": 2000,
             "index": run["index"], "condition": run["condition"],
             "outputs": run["outputs"], "configurations": spec["configurations"],
             "hosts": spec.get("hosts", {}),
             "batch": {"configurations": spec["configurations"], "outputs": spec["outputs"],
                       "plan": batch}} for run in batch["runs"]]


def coordinate_batch(plans, output, *, read=input, now=monotonic):
    """人工协调端保持单一单调时钟；每组读回两端manifest再放行下一组。"""
    from secure_control.experiments.native_tail_capture import plan_digest
    from secure_control.experiments.tail_diagnostic_runner import _write_new

    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    if len(plans) != 8 or [p.get("condition") for p in plans] != list(CONDITIONS):
        raise ValueError("需要完整八组计划。")
    batch = BaselineBatch(now=now)
    reference = {}
    artifact_bytes = 0
    try:
        for index, plan in enumerate(plans):
            condition = batch.reserve(index)
            _write_new(output / f"reservation-{index}.json", {
                "index": index, "condition": condition, "plan_sha256": plan_digest(plan),
                "elapsed_s": now() - batch.started, "remaining_s": 1200 - (now() - batch.started)})
            print(f"Run {index} {condition}: start B then A with this exact plan; copy both manifests back.")
            manifests = []
            for side in ("client", "pair"):
                path = Path(read(f"Run {index} {side} copied manifest path: "))
                item = json.loads(path.read_text(encoding="utf-8-sig"))
                if (item.get("side") != side or item.get("index") != index
                        or item.get("plan_sha256") != plan_digest(plan)):
                    raise ValueError("回执与本组不符。")
                manifests.append(item)
                reference.setdefault(side, item["environment_before"])
                size = item.get("artifact_bytes", 0)
                if type(size) is not int or size < 0:
                    raise ValueError("无效产物字节计数。")
                artifact_bytes += size
                if artifact_bytes > 2 * 1024**3:
                    raise ValueError("批次产物目标超出2GiB，停止未启动项。")
            receipt = batch.finish(
                functional_complete=all(m.get("functional_complete") is True for m in manifests),
                capture_complete=all(m.get("capture_complete") is True for m in manifests),
                environment_unchanged=all(m.get("environment_unchanged") is True and
                    environments_match(m["environment_before"], reference[m["side"]]) for m in manifests))
            _write_new(output / f"receipt-{index}.json", receipt)
            if batch.stop_reason:
                break
    except (Exception, KeyboardInterrupt) as error:
        batch.stop_reason = type(error).__name__
        raise
    finally:
        _write_new(output / "batch.json", {"receipts": batch.receipts,
            "elapsed_s": now() - batch.started, "stop_reason": batch.stop_reason,
            "complete": len(batch.receipts) == 8 and batch.stop_reason is None,
            "scope": "manual coordination; waiting and cleanup included; no automatic rerun"})


def cli():
    """正式对照入口：准备和分析不运行控制；run必须显式绑定新批准。"""
    import argparse

    from secure_control.experiments.tail_diagnostic_runner import _write_new

    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    prepare = modes.add_parser("prepare")
    prepare.add_argument("spec", type=Path)
    prepare.add_argument("output", type=Path)
    run = modes.add_parser("run")
    run.add_argument("side", choices=("client", "pair"))
    run.add_argument("plan", type=Path)
    run.add_argument("authorization", type=Path)
    run.add_argument("output", type=Path)
    run.add_argument("--expected-head", required=True)
    run.add_argument("--config", type=Path, action="append", required=True)
    analyze = modes.add_parser("metrics")
    analyze.add_argument("report", type=Path)
    analyze.add_argument("output", type=Path)
    coordinate = modes.add_parser("coordinate")
    coordinate.add_argument("plans", type=Path)
    coordinate.add_argument("output", type=Path)
    setup = modes.add_parser("manual-prepare")
    setup.add_argument("spec", type=Path)
    setup.add_argument("output", type=Path)
    setup.add_argument("--side", choices=("client", "pair"), required=True)
    setup.add_argument("--config", type=Path, action="append", required=True)
    setup.add_argument("--approvals", type=Path, required=True)
    manual = modes.add_parser("manual")
    manual.add_argument("bundle", type=Path)
    repack = modes.add_parser("repack")
    repack.add_argument("bundle", type=Path)
    repack.add_argument("--index", type=int, required=True)
    args = parser.parse_args()
    if args.mode == "manual-prepare":
        prepare_manual(json.loads(args.spec.read_text(encoding="utf-8-sig")), args.output,
                       args.side, args.config, args.approvals)
    elif args.mode == "repack":
        print(repack_manual(args.bundle, args.index))
    elif args.mode == "manual":
        run_manual(args.bundle)
    elif args.mode == "prepare":
        plans = prepare_run_plans(json.loads(args.spec.read_text(encoding="utf-8-sig")))
        args.output.mkdir(parents=True, exist_ok=False)
        for plan in plans:
            _write_new(args.output / f"run-{plan['index']}.json", plan)
        print("Preparation only; no run started.")
    elif args.mode == "coordinate":
        coordinate_batch([json.loads((args.plans / f"run-{k}.json").read_text(encoding="utf-8-sig"))
                          for k in range(8)], args.output)
    elif args.mode == "metrics":
        _write_new(args.output, baseline_metrics(json.loads(args.report.read_text(encoding="utf-8-sig"))))
    else:
        result = run_baseline_host(json.loads(args.plan.read_text(encoding="utf-8-sig")),
                                   json.loads(args.authorization.read_text(encoding="utf-8-sig")),
                                   args.side, config_paths=args.config, output=args.output,
                                   expected_head=args.expected_head)
        print(json.dumps({k: result[k] for k in (
            "functional_complete", "capture_complete", "environment_unchanged")}))
        if not all(result[k] for k in ("functional_complete", "capture_complete", "environment_unchanged")):
            raise SystemExit(2)


def baseline_child(config, context, results, stop, deadline, steps, activity=None, *unused):
    """两条件唯一业务装配；不启用详细诊断、GC回调或逐步写盘。"""
    from secure_control.execution.lan_runtime import RunControl, run_party_single_step
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.experiments.lan_runner import _run_prepared_segmented
    from secure_control.experiments.live_timing import LiveTimingCollector, timing_metadata
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    result = {"role": config.role, "pid": os.getpid(), "status": "failed"}
    cpu = time.process_time_ns()
    try:
        if config.role == "Client":
            session, control = InteractiveSession(), RunControl()
            prepared = load_segmented_experiment(config.experiment_config, 400, session)
            if prepared.scene.period != .02:
                raise ValueError("共同基线固定20ms模型周期。")
            collector = LiveTimingCollector("samples", sample_limit=steps)
            metadata = timing_metadata(config, prepared, non_realtime=True, mode="samples")
            attempts = 0
            import numpy as np
            records = [None] * steps
            public_setup = []
            inputs = np.empty((steps, prepared.spec.input_dimension), dtype=float)
            original_input = prepared.scene.controller_input

            def observed_input():
                value = original_input()
                inputs[attempts-1] = value
                return value

            prepared.scene.controller_input = observed_input

            def before_sample():
                nonlocal attempts
                if not activity.value:
                    activity.value = time.perf_counter()
                if (attempts >= steps or stop.is_set() or time.perf_counter() >=
                        min(deadline, activity.value + 55)):
                    raise TimeoutError("共同基线活动边界停止。")
                attempts += 1

            def on_step(record):
                records[record.protocol.global_step] = record
                if record.protocol.global_step + 1 >= steps:
                    control.request_stop()

            outcome = _run_prepared_segmented(
                config, prepared, control=control, session=session, before_sample=before_sample,
                on_step=on_step, on_start=lambda state, setup: public_setup.append(setup),
                non_realtime=True, timing_observer=collector, material_slots=16)
            report = collector.report()
            report.update(metadata=metadata, control_outcome=outcome,
                          export={"status": "in_memory", "path": None})
            result.update(status=outcome["status"], outcome=outcome, timing=report)
            result["numerical_validation"] = verify_baseline_numbers(prepared, config, records, inputs, public_setup[0])
            from dataclasses import asdict

            from secure_control.execution.localhost_codec import encode_wire_value
            result["numerical_evidence"] = {
                "inputs": inputs.tolist(), "setup": json.loads(encode_wire_value(public_setup[0])),
                "records": [{"global_step": r.protocol.global_step,
                             "raw_control": r.protocol.raw_control, "snapshot": asdict(r.snapshot)}
                            for r in records]}
        else:
            def on_activity():
                with activity.get_lock():
                    if not activity.value:
                        activity.value = time.perf_counter()

            outcome = run_party_single_step(config, batch=True,
                                           wire_profile="control-dynamic-matrix-preauthorized-v2",
                                           on_activity=on_activity)
            result.update(status=outcome["status"], outcome=outcome)
    except Exception as error:  # noqa: BLE001 - 不导出控制/密码材料异常文本
        result["status"] = "failed"
        result["error_type"] = type(error).__name__
        stop.set()
    finally:
        result["process_cpu_ns"] = time.process_time_ns() - cpu
        results.put(result)


class BaselineBatch:
    """人工双端协调的单机批次门禁；一次领取，首错停止，不代替运行批准。"""

    def __init__(self, *, now=monotonic):
        self.now = now
        self.started = now()
        self.next_index = 0
        self.pending = None
        self.stop_reason = None
        self.receipts = []

    def reserve(self, index):
        """首次启动命令前调用；剩余不足完整120秒组预算即不启动。"""
        if (type(index) is not int or index != self.next_index or index >= 8
                or self.pending is not None or self.stop_reason is not None):
            raise ValueError("批次顺序、未结算组或停止状态不允许启动。")
        elapsed = self.now() - self.started
        if elapsed < 0 or elapsed + 120 > 1200:
            self.stop_reason = "insufficient_batch_budget"
            raise TimeoutError("批次剩余额度不足，未启动该组。")
        self.pending = index
        return CONDITIONS[index]

    def finish(self, *, functional_complete, capture_complete, environment_unchanged):
        """只接收两端核验后的事实；失败样本保留且无补跑路径。"""
        if self.pending is None or any(type(v) is not bool for v in (
                functional_complete, capture_complete, environment_unchanged)):
            raise ValueError("需要已领取组及明确的两端核验结果。")
        index = self.pending
        reason = ("functional_failure" if not functional_complete else
                  "capture_failure" if CONDITIONS[index] == "F" and not capture_complete else
                  "environment_drift" if not environment_unchanged else
                  "batch_wall_limit" if self.now() - self.started > 1200 else None)
        self.receipts.append({"index": index, "condition": CONDITIONS[index],
                              "comparable": reason is None, "stop_reason": reason})
        self.pending = None
        self.next_index += 1
        self.stop_reason = reason
        return dict(self.receipts[-1])


def baseline_plan(source_head, configurations, outputs):
    """冻结两块交替顺序及逐端路径；此对象本身不授权运行。"""
    if (not isinstance(source_head, str) or len(source_head) != 40
            or any(c not in "0123456789abcdef" for c in source_head)):
        raise ValueError("需要完整源码SHA。")
    if (not isinstance(configurations, dict) or set(configurations) != {"Client", "P1", "P2"}
            or not isinstance(outputs, list) or len(outputs) != 8):
        raise ValueError("需要三角色配置和八组两端新路径。")
    paths = []
    for item in outputs:
        if (not isinstance(item, dict) or set(item) != {"client", "pair"}
                or any(not isinstance(p, str) or not p for p in item.values())):
            raise ValueError("每组必须包含两端路径。")
        paths.extend(item.values())
    if len(set(paths)) != 16:
        raise ValueError("两端输出路径必须互异。")
    return {
        "schema": "performance-baseline-plan-v1", "purpose": PURPOSE,
        "source_head": source_head, "configurations": configurations,
        "runs": [{"index": k, "block": k // 4, "condition": condition,
                  "outputs": dict(outputs[k]), "steps": 2000}
                 for k, condition in enumerate(CONDITIONS)],
        "observation": {"collector": "LiveTimingCollector", "mode": "samples",
                        "capacity": 2000, "tail_recorder": False, "stream_map": False,
                        "timing_mode": "non_realtime_demo", "material_slots": 16,
                        "segment_steps": 400},
        "limits": {"batch_wall_s": 1200, "client_wall_s": 100, "pair_wall_s": 120,
                   "business_s": 55, "pair_wait_s": 45, "cleanup_s": 10,
                   "minimum_free_bytes": 4 * 1024**3, "artifacts_bytes": 2 * 1024**3,
                   "offline_wall_s": 600},
        "authorization_required": True,
        "scope": "capture overhead only; no TCP attribution or realtime qualification",
    }


def _distribution(values):
    """离线按nearest-rank精确统计；空集合明确为缺测，不当作零。"""
    ordered = sorted(values)
    count = len(ordered)
    return {"count": count, "above_20ms": sum(v > 20_000_000 for v in ordered),
            "above_20ms_fraction": sum(v > 20_000_000 for v in ordered) / count if count else None,
            **{name: ordered[math.ceil(count * q) - 1] if count else None
               for name, q in (("p50_ns", .5), ("p95_ns", .95), ("p99_ns", .99))},
            "max_ns": ordered[-1] if count else None}


def baseline_metrics(report):
    """仅消费共同计时原件，预算超出与真实deadline事实分开报告。"""
    validate_timing_report(report)
    rows = report["raw"]["samples"]
    if (not report["raw"]["complete"] or not report["statistics_complete"]
            or report["metadata"].get("timing_mode") != "non_realtime_demo"):
        raise ValueError("需要完整共同非实时计时样本。")
    if any(r["scheduled_start_ns"] is not None or r["deadline_ns"] is not None for r in rows):
        raise ValueError("非实时基线不能混入绝对截止工况。")
    consecutive = longest = 0
    gaps, work, control, exchange, intervals = [], [], [], [], []
    boundary, following = [], []
    boundary_indices = set()
    for k, row in enumerate(rows):
        elapsed = row["work_elapsed_ns"]
        if elapsed is not None:
            work.append(elapsed)
        consecutive = consecutive + 1 if elapsed is not None and elapsed > 20_000_000 else 0
        longest = max(longest, consecutive)
        if row["control_latency_ns"] is not None:
            control.append(row["control_latency_ns"])
        phases = row["phase_durations_ns"]
        if "single_exchange" in phases:
            exchange.append(phases["single_exchange"])
        if row["sample_interval_ns"] is not None:
            intervals.append(row["sample_interval_ns"])
        if "maintenance_advance" in phases:
            boundary_indices.add(k)
            boundary.append(elapsed)
        if k and rows[k-1]["work_completed_ns"] is not None and row["actual_sample_start_ns"] is not None:
            gap = row["actual_sample_start_ns"] - rows[k-1]["work_completed_ns"]
            if gap < 0:
                raise ValueError("相邻工作端点顺序不一致。")
            gaps.append(gap)
        if (k-1 in boundary_indices or k-2 in boundary_indices) and elapsed is not None:
            following.append(elapsed)
    return {"work": _distribution(work), "input_to_output": _distribution(control),
            "exchange": _distribution(exchange), "sample_interval": _distribution(intervals),
            "work_exit_to_next_sample": _distribution(gaps),
            "maintenance_boundary_work": _distribution([v for v in boundary if v is not None]),
            "following_two_steps_work": _distribution(following),
            "longest_consecutive_budget_exceedance": longest,
            "status_counts": report["status_counts"],
            "deadline_miss": None, "absolute_lateness_ns": None,
            "not_applicable_reason": "relative pacing has no absolute schedule/deadline"}


def prepare_manual(spec, output, side, configs, approvals):
    """一次生成本机薄入口与冻结计划引用；准备不产生运行授权。"""
    from secure_control.experiments.native_tail_capture import plan_digest
    from secure_control.experiments.tail_diagnostic_runner import ROOT, _write_new

    plans = prepare_run_plans(spec)
    for plan in plans:
        plan["purpose"] = MANUAL_PURPOSE
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in ("inbox", "outbox"):
        (output / name).mkdir()
    bundle = {"schema": "baseline-manual-bundle-v1", "side": side,
              "batch_id": plan_digest(plans), "repo": str(ROOT), "plans": plans,
              "configs": [str(Path(p).resolve()) for p in configs],
              "approvals": str(Path(approvals).resolve())}
    _write_new(output / "bundle.json", bundle)
    (output / "start-baseline.ps1").write_text(
        "$ErrorActionPreference='Stop'\n"
        "$bundle=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'bundle.json') | ConvertFrom-Json\n"
        "Set-Location -LiteralPath $bundle.repo\n"
        "uv run python -m secure_control.experiments.performance_baseline manual $PSScriptRoot\n"
        "if ($LASTEXITCODE -ne 0) { throw 'Baseline STOP; preserve results; do not retry.' }\n",
        encoding="utf-8")


def validate_manual_result(records, plan, side, configs):
    """包完整性之外重核角色事实；Client以保存输入重跑独立数值oracle。"""
    from secure_control.execution.lan_config import load_lan_config
    from secure_control.execution.localhost_codec import decode_wire_value
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.experiments.native_tail_capture import plan_digest
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    manifest = records["manifest.json"]
    if (records["plan.json"] != plan or manifest.get("side") != side
            or manifest.get("plan_sha256") != plan_digest(plan)
            or manifest.get("functional_complete") is not True or manifest.get("capture_complete") is not True
            or not environments_match(manifest["environment_before"], manifest["environment_after"])
            or manifest["group"].get("stop_reason") or manifest["group"].get("forced_cleanup")):
        raise ValueError("两端功能、采集、清理或环境未通过。")
    for role in (("Client",) if side == "client" else ("P1", "P2")):
        if records[role + ".json"].get("status") not in ("stopped", "closed"):
            raise ValueError("角色终态未通过。")
    if side == "client":
        client = records["Client.json"]
        if any(type(client["outcome"].get(k)) is not int or client["outcome"][k] != 2000
               for k in ("confirmed_step_count", "protocol_committed_count")):
            raise ValueError("Client提交/确认计数不足。")
        baseline_metrics(client["timing"])
        evidence = client["numerical_evidence"]
        if len(evidence["records"]) != 2000 or len(evidence["inputs"]) != 2000:
            raise ValueError("数值记录容量或完整性不符。")
        config = load_lan_config(configs[0], "Client")
        prepared = load_segmented_experiment(config.experiment_config, 400, InteractiveSession())
        rows = [SimpleNamespace(protocol=SimpleNamespace(global_step=r["global_step"],
                raw_control=r["raw_control"]), snapshot=r["snapshot"]) for r in evidence["records"]]
        verify_baseline_numbers(prepared, config, rows, evidence["inputs"],
                                decode_wire_value(json.dumps(evidence["setup"]).encode()))
    return manifest


def repack_manual(bundle_path, index):
    """幂等重打包已有原件，不恢复运行额度或推进人工组号。"""
    from secure_control.experiments.baseline_package import publish_package, read_package
    root = Path(bundle_path).resolve()
    bundle = json.loads((root / "bundle.json").read_text(encoding="utf-8-sig"))
    if type(index) is not int or not 0 <= index < 8:
        raise ValueError("重打包组号无效。")
    side = bundle["side"]
    identity = {"batch_id": bundle["batch_id"], "index": index, "side": side}
    target = root / "outbox" / f"baseline-{bundle['batch_id'][:12]}-{index:02}-{side}.zip"
    if target.exists():
        read_package(target, identity)
    else:
        source = Path(bundle["plans"][index]["outputs"][side])
        if not (source / "manifest.json").is_file():
            raise ValueError("原件没有完整manifest，只能保留失败现场。")
        publish_package(source, target, identity)
    return str(target)


def run_manual(bundle_path, *, read=input, now=monotonic, runner=None):
    """A常驻计时、B逐组确认；跨端顺序归人工，本地次数及失败STOP由程序执行。"""
    from secure_control.experiments.baseline_package import publish_package, read_package
    from secure_control.experiments.tail_diagnostic_runner import _write_new

    root = Path(bundle_path).resolve()
    bundle = json.loads((root / "bundle.json").read_text(encoding="utf-8-sig"))
    side, plans = bundle["side"], bundle["plans"]
    if (bundle.get("schema") != "baseline-manual-bundle-v1" or side not in ("client", "pair")
            or len(plans) != 8 or any(type(p.get("index")) is not int or p["index"] != k
                                    for k, p in enumerate(plans))):
        raise ValueError("人工启动包schema或顺序无效。")
    state_path = root / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {
        "batch_id": bundle["batch_id"], "next_index": 0, "pending": None, "stop": False}
    if (type(state.get("next_index")) is not int or not 0 <= state["next_index"] <= 8
            or type(state.get("stop")) is not bool
            or state.get("batch_id") != bundle["batch_id"] or state.get("pending") is not None
            or state.get("stop") or side == "client" and state_path.exists()):
        raise ValueError("本机STOP、未完成attempt或A计时会话已退出，不能重启续额。")
    lock = root / "active.lock"
    with lock.open("x") as stream:
        stream.write(str(os.getpid()))
    started, total_bytes, references = now(), 0, {}

    def save():
        temporary = root / "state.partial"
        temporary.write_text(json.dumps(state), encoding="utf-8")
        os.replace(temporary, state_path)

    try:
        save()
        while state["next_index"] < 8:
            index = state["next_index"]
            plan = plans[index]
            if plan.get("purpose") != MANUAL_PURPOSE or plan.get("index") != index:
                raise ValueError("需要新manual用途及顺序计划。")
            print(f"Batch {bundle['batch_id'][:12]} group {index+1}/8 {plan['condition']} {side}")
            if side == "client" and now()-started+120 > 1200:
                raise TimeoutError("人工批次剩余时间不足，不启动下一组。")
            answer = read("A: start B, then type YES; B: confirm A allowed matching group, type YES: ")
            if answer != "YES" or side == "client" and now()-started+120 > 1200:
                raise ValueError("未确认或人工等待超额，停止。")
            approval = json.loads((Path(bundle["approvals"]) / f"approval-{index}.json").read_text(encoding="utf-8-sig"))
            state["pending"] = index
            save()  # 永久预留早于任何native或控制；失败不恢复。
            execute = _run_baseline_host_approved if runner is None else runner
            output = Path(plan["outputs"][side])
            execute(plan, approval, side, config_paths=bundle["configs"], output=output,
                    expected_head=plan["source_head"])
            identity = {"batch_id": bundle["batch_id"], "index": index, "side": side}
            package = root / "outbox" / f"baseline-{bundle['batch_id'][:12]}-{index:02}-{side}.zip"
            publish_package(output, package, identity)
            own, size = read_package(package, identity)
            manifest = validate_manual_result(own, plan, side, bundle["configs"])
            total_bytes += size + package.stat().st_size
            if side == "client":
                read("Copy B ZIP into inbox, then press Enter: ")
                peer_identity = {**identity, "side": "pair"}
                peer_name = package.name.replace("-client.zip", "-pair.zip")
                peer_path = root / "inbox" / peer_name
                peer, peer_size = read_package(peer_path, peer_identity)
                other = validate_manual_result(peer, plan, "pair", bundle["configs"])
                total_bytes += peer_size + peer_path.stat().st_size
                for name, item in (("client", manifest), ("pair", other)):
                    references.setdefault(name, item["environment_before"])
                    if not environments_match(item["environment_before"], references[name]):
                        raise ValueError("跨组环境漂移，停止。")
                if total_bytes > 2 * 1024**3 or now()-started > 1200:
                    raise ValueError("批次资源或人工时间目标超额。")
            state.update(pending=None, next_index=index+1)
            save()
            print("Local result verified; next group requires A permission and human confirmation.")
            if side == "pair":
                break
    except BaseException:
        state["stop"] = True
        save()
        raise
    finally:
        _write_new(root / f"session-{time.time_ns()}.json", {
            "state": state, "elapsed_s": now()-started, "artifact_bytes": total_bytes,
            "local_enforcement": True, "coordination": "manual",
            "cross_host_automatic_stop": None, "global_hard_deadline": None})
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    cli()
