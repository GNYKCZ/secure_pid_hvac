"""固定网络场景的有界编排/额度与公开证据；控制循环和秘密材料仍归原后端。"""

from __future__ import annotations

import copy
import gc
import hashlib
import json
import os
import platform
import re
import ssl
import subprocess
import sys
import time
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from secure_control.execution.lan_config import LanEndpoint, LanTopology
from secure_control.execution.localhost_codec import (
    _COMPACT_PROFILE,
    _COMPACT_PROFILE_V2,
    _COMPACT_PROFILE_V3,
    _COMPACT_PROFILES,
)

from . import communication_benchmark as benchmark
from ._network_emulator import SEED, NetworkRelay, models

ROOT = Path(__file__).resolve().parents[3]
PROFILES = ("N0", "N1", "N2", "N3")
EXTRA_SOURCE = ("src/secure_control/experiments/network_benchmark.py",
                "src/secure_control/crypto/beaver.py", "src/secure_control/crypto/truncation.py",
                "src/secure_control/experiments/_network_emulator.py", "src/secure_control/experiments/_network_wait_win32.py",
                "src/secure_control/execution/lan_config.py",
                "configs/cart_pole_plant.yaml", "configs/cart_pole_balance.yaml",
                "configs/shared_prime_256_pocklington.yaml", "pyproject.toml", "uv.lock")
COMMENT = re.compile(r"https://github\.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-[0-9]+\Z")
V2_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6231537918"
V2_CLOSED_HISTORY = "ae524efc8bc7f8495ea511406a62410afdeb98a6761716ed2fe5610f5058aa2c"
V2_PORTS = (55121, 55122, 55123)
V2_CERTIFICATE_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6231986263"
V2_CERTIFICATE_FIELDS = ("certificate_change_authorization_url", "previous_public_certificate_sha256",
                         "previous_conditions_sha256", "public_certificate_validity", "certificate_change_reason")
CLOSURE_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6235872603"
CLOSURE_HISTORY = "da18c50ed0e175257b7c058943dd2ff3c470669573672179c16d1e47b59e18c4"
EVENT_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6245910420"
EVENT_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6245981263"
EVENT_HISTORY = "cc6b6a46b009fbebc32700e32ac65e348f3f10c474e6f219f2a39ecb0785c3b4"
EVENT_STRATEGY = "win32-event-wait-v1"
EVENT_FIELDS = ("wait_strategy", "wait_design_url", "wait_authorization_url", "closed_seven_history_sha256")
REPAIR_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6251910122"
REPAIR_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6251961861"
REPAIR_HISTORY = "5e28dad8b899e1653f0c165ef5661027ac1f9d9fd684bc2ec2ac64a3ef3dc99c"
REPAIR_NATIVE_HISTORY = "f429510fb22e70ea865b10dd084581e56199bf087cc81c44ed071ed7ebc6e120"
STAGED_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6284803981"
STAGED_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6284903029"
STAGED_HISTORY = "08805f3aa8e0149771f05d7519c51f8801345e9c47f24a86d9848eb447a14852"
STAGED_NATIVE_HISTORY = "61dcefa48b1314ca1d86e9ab039dc3f214ab0c746ced453090557d26c3b079be"
STAGED_STAGES = (("T1", "N0", _COMPACT_PROFILE_V2), ("T2", "N0", _COMPACT_PROFILE_V3),
                 ("T3", "N2", _COMPACT_PROFILE_V3))
LOCAL_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6289274852"
LOCAL_HISTORY = "b9a468b68413d80e2c1daaa4ac9ce6700d555bb9c7717fee00563c951909d2d7"
LOCAL_NATIVE_HISTORY = "61f4826e58ff45d91417fb72024dd8c43f5a6d51bed7d7829650306f62705cb7"
LOCAL_STAGES = (("U1", "N0", _COMPACT_PROFILE_V2), ("U2", "N0", _COMPACT_PROFILE_V3))
V1_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6307818461"
V1_HISTORY = "32bda5b0e9b350164dcb8f972edc02f2724fe3b7e167222b50c9f12f807e6a22"
V1_NATIVE_HISTORY = "ba432f89d849b8a3cbcb39b20943e6b3653df83046be0d3a7d1d655c042d41a8"
V1_CONTROL_HEAD = "44472725f908ef5c8a9a610a689b037bb38ee36f"
V1_REVIEW = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6291716161"
V1_RAW_SHA256 = ["7bf31dcc9ec8b703edee022f6414c8dd7b6be212fd330b4c35024d7f89f0975b",
                 "9d5007dfa94652a4367533f02b66dce2a81c508d303fec0fefea650536968c5a"]
V1_SOURCE_FILES = ("src/secure_control/experiments/network_benchmark.py",
                   "src/secure_control/experiments/lan_runner.py")
W_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6308806798"
W_HISTORY = "55b2fda1991b4ba65cd67fb7ec87addc0b865bb8f14289b10c71eb49cc403902"
W_NATIVE_HISTORY = "08374e2f98cc0381ff855bb5b3ac0dd3a03aa0a46508b366efd6b898fe686b93"
W_BASE_HEAD = "45a60abe5e2547326ac152d9280cd133b662b72d"
W_SOURCE_FILES = (*V1_SOURCE_FILES, "src/secure_control/experiments/_network_emulator.py",
                  "src/secure_control/experiments/_network_wait_win32.py")
W_TRACE_INSTANCE = "Issue120W1"
W_TRACE_KEYWORDS = {"ProcessThread", "CSwitch", "ReadyThread", "ThreadPriority", "CpuConfig", "Interrupt", "DPC"}
SC_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6333274397"
SC_HISTORY = "e1e6ebdc02516f43624ec5c82a3de1db30a5873a6ea686b6e65843a2866fec56"
SC_NATIVE_HISTORY = "b0f927d5e368a97a8e16b3de4d9eb7898ad6e3edb413f56a40ab020876b43a0d"
SC_MAIN = "767c2a14c7cb9b9d86c221d464aafd4cf60c87d6"
SC_CONTROL = "2b1c40a46e92be939a2a52cd800fc5e15185c1f0"
SC_SCALAR = "src/secure_control/crypto/secret_sharing.py"
SC_VARIABLE_FILES = (SC_SCALAR, "tests/test_secret_sharing.py")
SC_SUPPORT_FILES = ("src/secure_control/experiments/network_benchmark.py",
                    "src/secure_control/experiments/lan_runner.py",
                    "tests/test_network_benchmark.py", "docs/network_performance.md")

# #128的共同测量支持H可以在无矩阵模块的完整A版本上导入。
MATRIX_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/128#issuecomment-6338813023"
MATRIX_DESIGN = "https://github.com/GNYKCZ/secure_pid_hvac/issues/128#issuecomment-6338770182"
MATRIX_MAIN = "32fbb11224ad4e48588e041583288d5bac1be896"
MATRIX_WIRE = "control-dynamic-matrix-v1"
MATRIX_SCOPE = "issue128-matrix-comparison-v1"
MATRIX_MODULE = "src/secure_control/crypto/matrix_beaver.py"
MATRIX_VARIABLE_FILES = (MATRIX_MODULE, "src/secure_control/protocol/messages.py",
    "src/secure_control/protocol/roles.py", "src/secure_control/protocol/coordinator.py",
    *(f"src/secure_control/execution/{name}.py" for name in
      ("localhost_codec", "_localhost_peer", "_localhost_workers", "_material_worker", "lan_runtime")),
    "tests/test_matrix_beaver.py")
MATRIX_SUPPORT_FILES = (*SC_SUPPORT_FILES, "src/secure_control/experiments/communication_benchmark.py")
MATRIX_COMMENT = re.compile(r"https://github\.com/GNYKCZ/secure_pid_hvac/issues/128#issuecomment-[0-9]+\Z")


def matrix_source():
    """本Issue覆盖全部核心源码/运行配置/依赖；缺失矩阵模块在A显式记null。"""
    files = subprocess.check_output(["git", "ls-files", "src/secure_control", "configs", "scripts",
                                     "pyproject.toml", "uv.lock"], cwd=ROOT, text=True).splitlines()
    # 四份交互部署配置不参与本机固定实验，仍由Work独立做字节前后保护。
    excluded = {"configs/"+n for n in ("lab-client-cart-pole.example.yaml", "lab-p1.example.yaml",
                                     "lab-p2.example.yaml", "local-deployment.example.yaml")}
    files = sorted((set(files) | {MATRIX_MODULE}) - excluded)
    return (subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() if (ROOT/name).is_file() else None
             for name in files})


def matrix_process_binding(m):
    """每个spawn角色从自己的完整解释器核实际源及已导入包路径。"""
    if matrix_source() != (m["head"], m["source_sha256"]):
        raise ValueError("角色实际源与冻结完整版本不同")
    source_root = (ROOT/"src").resolve()
    for name, module in tuple(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if name.startswith("secure_control") and path is not None and not Path(path).resolve().is_relative_to(source_root):
            raise ValueError("角色从冻结仓库外导入核心")
    return {"head":m["head"], "source_sha256_digest":digest(m["source_sha256"])}


class _MatrixBoundOutput:
    """共同H只给原worker终报附加实际来源，不改变材料或控制消息。"""

    def __init__(self, output, manifest):
        self.output, self.manifest = output, manifest

    def send_bytes(self, data):
        if data[:1] == b"R":
            report = json.loads(data[1:])
            try:
                report["source_binding"] = matrix_process_binding(self.manifest)
            except (OSError, ValueError, RuntimeError) as error:
                report["error_type"] = type(error).__name__
            data = b"R"+json.dumps(report, separators=(",", ":"), allow_nan=False).encode()
            if len(data) > 16*1024:
                raise ValueError("工人来源终报超过原预算")
        self.output.send_bytes(data)

    def close(self):
        self.output.close()


def _matrix_worker_job(manifest, spec, credit, output):
    from secure_control.execution._material_worker import _worker_main
    matrix_process_binding(manifest)
    _worker_main(spec, credit, _MatrixBoundOutput(output, manifest))


@contextmanager
def _matrix_worker_binding(manifest):
    from functools import partial

    from secure_control.execution import _material_worker
    with patch.object(_material_worker, "_worker_main", partial(_matrix_worker_job, manifest)):
        yield


def _matrix_manifest_valid(m):
    if not isinstance(m, dict) or m.get("comparison_stage") not in ("M128-P0", "M128-A", "M128-B"):
        return False
    stage = m["comparison_stage"]
    versions = m.get("matrix_versions")
    if (not isinstance(versions, dict) or set(versions) != {"A", "B"}
            or any(type(v) is not dict or set(v) != {"head", "source_sha256"}
                   or re.fullmatch(r"[0-9a-f]{40}", str(v.get("head"))) is None
                   or type(v.get("source_sha256")) is not dict for v in versions.values())):
        return False
    a, b = versions["A"], versions["B"]
    sources = a["source_sha256"]
    if (a["head"] == b["head"] or sources.keys() != b["source_sha256"].keys()
            or sources.get(MATRIX_MODULE, "missing") is not None
            or not isinstance(b["source_sha256"].get(MATRIX_MODULE), str)
            or any(value != b["source_sha256"][name] for name, value in sources.items()
                   if name not in MATRIX_VARIABLE_FILES)):
        return False
    version = versions["A" if stage == "M128-A" else "B"]
    return (m.get("scope") == MATRIX_SCOPE and m.get("authorization_url") == MATRIX_AUTHORIZATION
        and m.get("comparison_design_url") == MATRIX_DESIGN
        and (m.get("head"), m.get("source_sha256")) == (version["head"], version["source_sha256"])
        and m.get("software_pass") is True and m.get("readback_exact") is True
        and isinstance(m.get("review_url"), str) and MATRIX_COMMENT.fullmatch(m["review_url"]) is not None
        and m.get("review_heads") == [a["head"], b["head"]]
        and (m.get("profile"), m.get("phase")) == ("N0", "candidate")
        and m.get("wire_profile") == (_COMPACT_PROFILE_V3 if stage == "M128-A" else MATRIX_WIRE)
        and all(type(m.get(k)) is int and m[k] == v for k, v in {
            "call": ("M128-P0", "M128-A", "M128-B").index(stage)+1,
            "maximum_calls": 3, "total_maximum_attempts": 2000,
            "maximum_attempts": 0 if stage == "M128-P0" else 1000}.items())
        and m.get("ports") == list(V2_PORTS)
        and m.get("budget_path") == str((ROOT/".tmp/issue128-performance-budget.json").resolve())
        and m.get("native_ledger_path") == str((ROOT/".tmp/issue128-native-invocations.json").resolve())
        and m.get("certificate_directory") == str((ROOT/".tmp/issue128-matrix-certs").resolve())
        and m.get("environment") == {"platform": platform.platform(), "python": sys.version.split()[0],
                                     "openssl": ssl.OPENSSL_VERSION})


def _require_matrix_versions(m):
    if not _matrix_manifest_valid(m):
        raise ValueError("#128缺少完整A/B版本及独审")
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT)
    a, b = (m["matrix_versions"][name]["head"] for name in ("A", "B"))
    common = set(git("diff", "--name-only", MATRIX_MAIN, a).decode().splitlines())
    variable = set(git("diff", "--name-only", a, b).decode().splitlines())
    if (not common or not common <= set(MATRIX_SUPPORT_FILES) or MATRIX_MODULE not in variable
            or not variable <= set(MATRIX_VARIABLE_FILES)
            or git("merge-base", a, b).decode().strip() != a):
        raise ValueError("#128 A必须为main+H，B仅增加矩阵实现")
    for name in ("beaver", "truncation", "secret_sharing"):
        path = f"src/secure_control/crypto/{name}.py"
        if any(git("show", f"{head}:{path}") != git("show", f"{MATRIX_MAIN}:{path}") for head in (a, b)):
            raise ValueError("P0旧标量原语必须与main字节相同")


def _require_matrix_certificates(m, configs=None):
    directory = Path(m["certificate_directory"])
    if (certificate_validity(directory) != m.get("public_certificate_validity")
            or {n: hashlib.sha256((directory/n).read_bytes()).hexdigest()
                for n in ("ca.pem", "client.pem", "p1.pem", "p2.pem")} != m.get("public_certificate_sha256")):
        raise ValueError("#128证书来源/规格/余期不符，不自动续证")
    if configs is not None and configs != role_configs(directory, V2_PORTS, "N0"):
        raise ValueError("#128只能复用固定N0 mutual TLS配置")


def require_matrix_candidate(m, wire_profile, configs=None):
    if (not _matrix_manifest_valid(m) or m["comparison_stage"] == "M128-P0"
            or wire_profile != m["wire_profile"] or matrix_source() != (m["head"], m["source_sha256"])):
        raise ValueError("#128运行来源或编码未获本次独审")
    _require_matrix_versions(m)
    _require_matrix_certificates(m, configs)


def _matrix_previous(entry):
    raw = Path(entry["output"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry.get("raw_sha256") or entry.get("sample_pass") is not True:
        raise ValueError("#128前项原件缺失/变化/未通过")
    return json.loads(raw)


def _next_matrix_call(entries, profile, phase, head, sources, m):
    if (not _matrix_manifest_valid(m) or type(entries) is not list or len(entries) >= 3
            or m["call"] != len(entries)+1 or (profile, phase, head, sources) !=
               (m["profile"], m["phase"], m["head"], m["source_sha256"])):
        raise ValueError("#128独立三次scope已耗尽或阶段/来源不符")
    _require_matrix_versions(m)
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf-8"))["entries"]
    keys = ("call", "head", "source_sha256", "comparison_stage", "authorization_url", "maximum_attempts",
            "profile", "phase", "wire_profile", "output")
    if (type(rows) is not list or len(rows) != len(entries)+1
            or any(row.get("completed") is not True or row.get("native_exit") != 0 for row in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or type(rows[-1].get("started_utc")) is not str
            or any(rows[-1].get(k) != m.get(k) for k in keys)):
        raise ValueError("#128缺少唯一真实START或前项正常原生退出")
    for i, entry in enumerate(entries):
        if (not _matrix_manifest_valid(entry) or entry.get("finished") is not True
                or entry["comparison_stage"] != ("M128-P0", "M128-A")[i]
                or any(rows[i].get(k) != entry.get(k) for k in keys)
                or rows[i].get("raw_sha256") != entry.get("raw_sha256")
                or any(entry.get(k) != m.get(k) for k in
                    ("matrix_versions", "review_heads", "review_url", "environment",
                     "public_certificate_sha256", "public_certificate_validity"))):
            raise ValueError("#128前项失败/在途/条件不一致，禁止下一项")
        previous = _matrix_previous(entry)
        if i == 0:
            if not _matrix_cost_pass(previous):
                raise ValueError("P0结构/功能不完整")
        elif not _assemble_matrix(previous, entry).get("network_sample_pass"):
            raise ValueError("A未完整1000零超期，禁止B")
    return m["maximum_attempts"]


def _assemble_matrix(result, manifest):
    """保留完整尝试/失败，矩阵计数独立；复用原周期/身份/资源门禁。"""
    matrix = manifest["comparison_stage"] == "M128-B"
    schema = "matrix-dynamic-evidence-v1" if matrix else "matrix-comparison-scalar-evidence-v1"
    expected_schema = "matrix-dynamic-evidence-v1" if matrix else "cycle-qualification-v1"
    incoming_schema = result.get("schema")
    complete = False
    try:
        complete = (incoming_schema in (expected_schema, schema)
            and benchmark._compact_sample_pass(result, result.get("material_comparison") or {},
                                              result.get("network_history") or {}, target_steps=1000))
    except (KeyError, TypeError, ValueError, IndexError):
        pass
    wire = manifest["wire_profile"]
    material = result.get("material_summary") or {}
    sample = bool(_matrix_manifest_valid(manifest) and result.get("status") == "stopped" and complete
        and result.get("code_sha") == manifest["head"] and result.get("source_sha256") == manifest["source_sha256"]
        and result.get("network_source_integrity_failed") is not True and _tls_pass(result)
        and (result.get("network_history") or {}).get("finite_sample_pass") is True
        and result.get("wire_profile") == wire and material.get("encoding_profile") == wire
        and (material.get("worker") or {}).get("encoding_profile") == wire
        and (material.get("worker") or {}).get("source_binding") ==
            {"head":manifest["head"], "source_sha256_digest":digest(manifest["source_sha256"])}
        and all(p.get("source_binding") ==
            {"head":manifest["head"], "source_sha256_digest":digest(manifest["source_sha256"])}
            for p in result.get("party_outcomes", []))
        and all(p.get("wire_profile") == wire for p in result.get("party_outcomes", []))
        and _staged_frames_pass(result, _COMPACT_PROFILE_V3))
    result.update(schema=schema, arithmetic_profile="matrix-beaver-v1" if matrix else "scalar-beaver-v1",
        network_manifest=manifest, network_manifest_sha256=digest(manifest), network_sample_pass=sample,
        network_dynamic_qualification_pass=False, local_dynamic_qualification_pass=False, qualification_pass=False,
        stage_pass=False, worker_long_run_gate_pass=False, candidate_gate_pass=False, server_gc_candidate_gate_pass=False,
        eligible_for_candidate=False, qualification_allowed=False, comparison_only=True, diagnostic=True)
    if not sample and result.get("status") == "stopped":
        result.update(status="failed", failure_category="MatrixEvidenceIncomplete", failed_phase="MATRIX_REPORT")
    return result


def _run_matrix_network(*, profile, phase, certs, ports, ledger, approval, output, wire_profile):
    manifest = json.loads(Path(approval).read_text(encoding="utf-8"))
    head, sources = matrix_source()
    output = Path(output).resolve()
    if (not _matrix_manifest_valid(manifest) or output.exists() or str(output) != manifest.get("output")
            or (head, sources) != (manifest["head"], manifest["source_sha256"])
            or (profile, phase, wire_profile, list(ports)) !=
               (manifest["profile"], manifest["phase"], manifest["wire_profile"], manifest["ports"])
            or str(Path(ledger).resolve()) != manifest["budget_path"]
            or str(Path(certs).resolve()) != manifest["certificate_directory"]
            or not gc.isenabled() or gc.get_threshold() != (700,10,10)
            or gc.get_freeze_count() or gc.get_debug() or gc.callbacks):
        raise ValueError("#128正式入口不符，未启动角色")
    _require_matrix_certificates(manifest)
    with RunBudget(ledger) as budget:
        steps = _next_matrix_call(budget.entries, profile, phase, head, sources, manifest)
        entry = manifest | {"started_utc": datetime.now(UTC).isoformat(), "finished": False, "sample_pass": False}
        budget.entries.append(entry)
        budget._save()
        result = {}
        with output.open("x", encoding="utf-8") as stream:
            try:
                if manifest["comparison_stage"] == "M128-P0":
                    result = _matrix_local_cost(manifest)
                else:
                    with _matrix_worker_binding(manifest):
                        result = benchmark.run_network_observation(configs=role_configs(certs, ports, "N0"), steps=steps,
                            wire_profile=wire_profile, candidate_manifest=manifest)
                if matrix_source() != (head, sources):
                    result["network_source_integrity_failed"] = True
            except Exception as error:  # noqa: BLE001 - 不暴露秘密/异常内容，失败占项保留
                result.update(status="failed", failure_category=type(error).__name__, failed_phase="MATRIX_RUN_OR_CLEANUP")
            result.update(code_sha=head, source_sha256=sources)
            if manifest["comparison_stage"] == "M128-P0":
                result.update(network_sample_pass=bool(_matrix_cost_pass(result)
                    and result.get("network_source_integrity_failed") is not True), network_manifest=manifest,
                    network_dynamic_qualification_pass=False)
            else:
                result = _assemble_matrix(result, manifest)
                if manifest["comparison_stage"] == "M128-B":
                    result["network_progress_goal_pass"] = bool(result["network_sample_pass"]
                        and _staged_gain(_matrix_previous(budget.entries[1]), result))
                    result["observed_5ms_headroom"] = bool(result["network_sample_pass"]
                        and max(r["cycle_completed_ns"]-r["scheduled_start_ns"] for r in result["cycles"]) <= 15000000)
            export_started = time.perf_counter_ns()
            json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        export_ns = time.perf_counter_ns()-export_started
        budget.finish(result, hashlib.sha256(output.read_bytes()).hexdigest())
        if manifest["comparison_stage"] == "M128-P0":
            budget.entries[-1]["primitive_pairs"] = len(result.get("pairs", []))
            budget._save()
    result["network_export_ns"] = export_ns
    return result


def _matrix_cost_pass(result):
    """只检查局部功能/结构/全样本；局部时延绝不替代完整周期收益门禁。"""
    phases = {"prepare_random_share", "encode_numeric_material", "restore_numeric_material", "multiply", "truncate_and_oracle"}
    if (result.get("schema") != "matrix-primitive-cost-v1" or result.get("functional_pass") is not True
            or result.get("status") != "stopped" or len(result.get("pairs", [])) != 18):
        return False
    try:
        for index, pair in enumerate(result["pairs"]):
            order = ["scalar", "matrix"] if index % 2 == 0 else ["matrix", "scalar"]
            if (type(pair["index"]) is not int or pair["index"] != index or pair["warmup"] is not (index<2)
                    or pair["order"] != order or len(pair["samples"]) != 2):
                return False
            for kind, sample in zip(order, pair["samples"], strict=True):
                elements = 49 if kind == "matrix" else 98
                if (sample["kind"] != kind or sample["functional_pass"] is not True
                        or sample["material_elements_per_party"] != elements
                        or sample["material_bytes_both_parties"] != elements*32*2
                        or sample["mask_elements_per_direction"] != (36 if kind == "matrix" else 60)
                        or any(set(sample[k]) != phases or any(type(v) is not int or v < 0 for v in sample[k].values())
                               for k in ("wall_ns", "cpu_ns"))
                        or any(type(sample[k]) is not int or sample[k] < sum(sample[p].values())
                               for k,p in (("total_wall_ns","wall_ns"),("total_cpu_ns","cpu_ns")))):
                    return False
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _matrix_primitive_sample(kind, prepared):
    """P0仅测共同裸数值codec和原语，两方本地调用；不模拟IPC或完整控制周期。"""
    import numpy as np

    from secure_control.crypto import (
        AdditiveShare,
        BeaverMultiplier,
        SecureTruncation,
        TwoPartySharing,
    )
    from secure_control.crypto.beaver import BeaverTripleShare, _TripleLifecycle
    from secure_control.crypto.matrix_beaver import MatrixBeaverMultiplier, MatrixTripleShare
    from secure_control.crypto.truncation import TruncationAuxiliaryShare, _MaskLifecycle

    q, ell = prepared.context.modulus, prepared.context.fractional_bits
    sharing = TwoPartySharing(q)
    spec = prepared.spec
    matrix = np.asarray(prepared.context.encode_to_residue(np.block([[spec.A, spec.B], [spec.C, spec.D]])), dtype=object)
    vector = np.asarray(prepared.context.encode_to_residue(np.concatenate((spec.x0, np.zeros(2)))) , dtype=object).reshape(6, 1)
    expected = [sum(int(matrix[i,j])*int(vector[j,0]) for j in range(6)) % q for i in range(5)]
    phases, cpu_phases = {}, {}
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    total_wall, total_cpu = wall, cpu
    def mark(name):
        nonlocal wall, cpu
        next_wall, next_cpu = time.perf_counter_ns(), time.process_time_ns()
        phases[name], cpu_phases[name] = next_wall-wall, next_cpu-cpu
        wall, cpu = next_wall, next_cpu
    owner = MatrixBeaverMultiplier(sharing) if kind == "matrix" else BeaverMultiplier(sharing)
    trunc = SecureTruncation(sharing, ell, prepared.security_parameter, prepared.evidence)
    left, right = sharing.share(matrix), sharing.share(vector)
    triples = [owner.create_triple(5, 6)] if kind == "matrix" else [owner.create_triple() for _ in range(30)]
    auxiliaries = [trunc.create_auxiliary() for _ in range(4)]
    mark("prepare_random_share")
    def flattened(party):
        values = []
        for pair in triples:
            t = pair[party]
            for share in ((t.u, t.v, t.w) if kind == "matrix" else (t.a, t.b, t.c)):
                values.extend(int(v) for v in np.asarray(share.value, dtype=object).flat)
        for pair in auxiliaries:
            values.extend((pair[party].r.value, pair[party].r_prime.value))
        return values
    width = (q.bit_length()+7)//8
    encoded = [b"".join(v.to_bytes(width, "big") for v in flattened(p)) for p in (0, 1)]
    mark("encode_numeric_material")
    del triples, auxiliaries  # 未mask的源DTO不再可领取；恢复值仅用于本次局部原语。
    numbers = [[int.from_bytes(data[i:i+width], "big") for i in range(0, len(data), width)] for data in encoded]
    owner = MatrixBeaverMultiplier(sharing) if kind == "matrix" else BeaverMultiplier(sharing)
    trunc = SecureTruncation(sharing, ell, prepared.security_parameter, prepared.evidence)
    triples = []
    for index in range(1 if kind == "matrix" else 30):
        life = _TripleLifecycle(owner)
        if kind == "matrix":
            pair = tuple(MatrixTripleShare(AdditiveShare(np.array(numbers[p][:30],dtype=object).reshape(5,6)),
                AdditiveShare(np.array(numbers[p][30:36],dtype=object).reshape(6,1)),
                AdditiveShare(np.array(numbers[p][36:41],dtype=object).reshape(5,1)), p, 5, 6, life) for p in (0,1))
        else:
            pair = tuple(BeaverTripleShare(*(AdditiveShare(v) for v in numbers[p][3*index:3*index+3]), p, life)
                         for p in (0,1))
        triples.append(pair)
    base = 41 if kind == "matrix" else 90
    auxiliaries = []
    for row in range(4):
        life = _MaskLifecycle(trunc)
        auxiliaries.append(tuple(TruncationAuxiliaryShare(*(AdditiveShare(v) for v in
            numbers[p][base+2*row:base+2*row+2]), p, life) for p in (0,1)))
    mark("restore_numeric_material")
    if kind == "matrix":
        masks = [owner.mask_inputs(left[p], right[p], triples[0][p]) for p in (0,1)]
        mask_elements = sum(np.asarray(v.value).size for v in (masks[0].e,masks[0].f))
        opened = owner.open_masked_differences(*masks)
        product = [owner.finish(triples[0][p], opened) for p in (0,1)]
    else:
        mask_elements = 0
        values = [[0]*5 for _ in (0,1)]
        for index, pair in enumerate(triples):
            row, col = divmod(index, 6)
            masks = [owner.mask_inputs(AdditiveShare(int(left[p].value[row,col])),
                AdditiveShare(int(right[p].value[col,0])), pair[p]) for p in (0,1)]
            mask_elements += sum(np.asarray(v.value).size for v in (masks[0].d,masks[0].e))
            opened = owner.open_masked_differences(*masks)
            for p in (0,1):
                values[p][row] = (values[p][row]+owner.finish(pair[p], opened).value) % q
        product = [AdditiveShare(np.array(v,dtype=object).reshape(5,1)) for v in values]
    mark("multiply")
    reconstructed = sharing.reconstruct(*product).reshape(5).tolist()
    valid = reconstructed == expected
    for row, pair in enumerate(auxiliaries):
        inputs = [AdditiveShare(int(product[p].value[row,0])) for p in (0,1)]
        masked = [trunc.mask_input(inputs[p], pair[p]) for p in (0,1)]
        opened = trunc.p1_reconstruct_masked(masked[0], trunc.p2_send_masked(masked[1]))
        output = sharing.reconstruct(trunc.finish_p1(inputs[0], pair[0], opened), trunc.finish_p2(inputs[1], pair[1]))
        centered = expected[row] if expected[row] <= q//2 else expected[row]-q
        rounded = trunc.paper_round_divide(centered)
        output = output if output <= q//2 else output-q
        valid = valid and abs(output-rounded) <= 1
    mark("truncate_and_oracle")
    elements = 49 if kind == "matrix" else 98
    valid = valid and all(len(data) == elements*width for data in encoded)
    valid = valid and mask_elements == (36 if kind == "matrix" else 60)
    return {"kind":kind, "wall_ns":phases, "cpu_ns":cpu_phases,
        "total_wall_ns":time.perf_counter_ns()-total_wall, "total_cpu_ns":time.process_time_ns()-total_cpu,
        "material_elements_per_party":elements, "material_bytes_both_parties":sum(map(len,encoded)),
        "mask_elements_per_direction":int(mask_elements), "functional_pass":bool(valid)}


def _matrix_local_cost(manifest):
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    from .lan_continuous_profile import load_segmented_experiment
    prepared = load_segmented_experiment(benchmark._config("Client", V2_PORTS).experiment_config,
                                         400, InteractiveSession())
    pairs = []
    for index in range(18):
        order = ("scalar", "matrix") if index % 2 == 0 else ("matrix", "scalar")
        row = {"index":index, "warmup":index<2, "order":list(order), "samples":[]}
        pairs.append(row)
        for kind in order:
            try:
                sample = _matrix_primitive_sample(kind, prepared)
            except Exception as error:  # noqa: BLE001 - 保存先前全部样本且不暴露数值秘密
                sample = {"kind":kind, "functional_pass":False, "error_type":type(error).__name__}
            row["samples"].append(sample)
            if sample["functional_pass"] is not True:
                return {"schema":"matrix-primitive-cost-v1", "status":"failed", "functional_pass":False, "pairs":pairs}
    return {"schema":"matrix-primitive-cost-v1", "status":"stopped", "functional_pass":True, "pairs":pairs,
            "cycles":[], "scope":"local primitives and common numeric material codec; not full cycle/IPC/network",
            "matrix_versions":manifest["matrix_versions"], "warmup_pairs":2, "formal_pairs":16}


def sc_source():
    """只扩展本批新来源，不回填历史记录或改变旧批次指纹算法。"""
    head, fingerprints = source()
    return head, fingerprints | {SC_SCALAR: hashlib.sha256((ROOT/SC_SCALAR).read_bytes()).hexdigest()}


def _sc_manifest_valid(m):
    if not isinstance(m, dict) or m.get("comparison_stage") not in ("SC-A", "SC-B"):
        return False
    index = int(m["comparison_stage"] == "SC-B")
    versions = m.get("sc_versions")
    if (not isinstance(versions, dict) or set(versions) != {"SC-A", "SC-B"}
            or any(not isinstance(v, dict) or set(v) != {"head", "source_sha256"}
                or not isinstance(v["head"], str) or not re.fullmatch(r"[0-9a-f]{40}", v["head"])
                or not isinstance(v["source_sha256"], dict) or SC_SCALAR not in v["source_sha256"]
                for v in versions.values())):
        return False
    a, b = versions["SC-A"], versions["SC-B"]
    if (a["head"] == b["head"] or set(a["source_sha256"]) != set(b["source_sha256"])
            or a["source_sha256"][SC_SCALAR] == b["source_sha256"][SC_SCALAR]
            or any(value != b["source_sha256"][key] for key, value in a["source_sha256"].items() if key != SC_SCALAR)
            or (m.get("head"), m.get("source_sha256")) != (versions[m["comparison_stage"]]["head"], versions[m["comparison_stage"]]["source_sha256"])
            or m.get("sc_review_heads") != [a["head"], b["head"]]):
        return False
    common = m | {"authorization_url": LOCAL_DESIGN, "comparison_design_url": LOCAL_DESIGN,
        "closed_history_sha256": LOCAL_HISTORY, "closed_native_history_sha256": LOCAL_NATIVE_HISTORY,
        "comparison_stage": "U1" if index == 0 else "U2", "wire_profile": _COMPACT_PROFILE_V2 if index == 0 else _COMPACT_PROFILE_V3,
        "call": 12+index, "maximum_calls": 13, "total_maximum_attempts": 13000,
        "certificate_directory": str((ROOT/".tmp/issue120-stage-authorized-certs").resolve())}
    return (m.get("authorization_url") == SC_DESIGN and m.get("comparison_design_url") == SC_DESIGN
        and m.get("closed_history_sha256") == SC_HISTORY and m.get("closed_native_history_sha256") == SC_NATIVE_HISTORY
        and (m.get("profile"), m.get("phase"), m.get("wire_profile")) == ("N0", "candidate", _COMPACT_PROFILE_V3)
        and m.get("certificate_directory") == str((ROOT/".tmp/issue120-wait-diagnostic-certs").resolve())
        and m.get("budget_path") == str((ROOT/".tmp/issue120-network-budget.json").resolve())
        and not any(k in m for k in ("system_trace", "wait_diagnostic", "first_model_failure_stop"))
        and all(type(m.get(k)) is int and m[k] == value for k, value in {
            "call":16+index, "maximum_calls":17, "total_maximum_attempts":17000,
            "batch_maximum_calls":2, "batch_maximum_attempts":2000}.items())
        and _local_manifest_valid(common))


def _require_sc_versions(m):
    """核两个完整提交仅有SC变量；共同H不夹带控制改动，不执行checkout。"""
    if not _sc_manifest_valid(m):
        raise ValueError("缺少SC两版本精确映射及独审来源。")
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT)
    a, b = (m["sc_versions"][stage]["head"] for stage in ("SC-A", "SC-B"))
    def changed(first, second):
        return set(git("diff", "--name-only", first, second).decode("utf8").splitlines())
    if (changed(a, b) != set(SC_VARIABLE_FILES)
            or not changed(SC_MAIN, a) or not changed(SC_CONTROL, b)
            or not changed(SC_MAIN, a) <= set(SC_SUPPORT_FILES)
            or changed(SC_MAIN, a) != changed(SC_CONTROL, b)
            or any(git("show", f"{a}:{path}") != git("show", f"{SC_MAIN}:{path}")
                   or git("show", f"{b}:{path}") != git("show", f"{SC_CONTROL}:{path}") for path in SC_VARIABLE_FILES)
            or any(git("show", f"{a}:{path}") != git("show", f"{b}:{path}") for path in SC_SUPPORT_FILES)):
        raise ValueError("SC两版本或共同H不一致，禁止混入其他生产变化。")


def _next_sc_call(entries, profile, phase, head, sources, m):
    if (not _sc_manifest_valid(m) or type(entries) is not list or len(entries) not in (15,16)
            or digest(entries[:15]) != SC_HISTORY or any(e.get("finished") is not True for e in entries)
            or m["call"] != len(entries)+1
            or (profile, phase, head, sources) != (m["profile"], m["phase"], m["head"], m["source_sha256"])):
        raise ValueError("SC许可/15项历史/顺序/来源或额度不符。")
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf8"))["entries"]
    keys = ("call", "head", "source_sha256", "conditions_sha256", "comparison_stage", "authorization_url",
            "maximum_attempts", "profile", "phase", "wire_profile")
    if (type(rows) is not list or len(rows) != len(entries)+1 or digest(rows[:15]) != SC_NATIVE_HISTORY
            or any(row.get("completed") is not True for row in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or not isinstance(rows[-1].get("started_utc"), str)
            or any(rows[-1].get(k) != m.get(k) for k in keys)):
        raise ValueError("SC原生历史或唯一当前START不符。")
    fixed = ("certificate_directory", "public_certificate_sha256", "public_certificate_validity", "conditions_sha256")
    if any(m.get(k) != entries[14].get(k) for k in fixed):
        raise ValueError("SC必须复用W1原证/条件，不含续证许可。")
    _require_sc_versions(m)
    if len(entries) == 16:
        first = entries[15]
        if (first.get("comparison_stage") != "SC-A" or not _sc_manifest_valid(first)
                or rows[15].get("native_exit") != 0 or any(rows[15].get(k) != first.get(k) for k in keys)
                or any(first.get(k) != m.get(k) for k in (*fixed, "sc_versions", "sc_review_heads", "review_url"))):
            raise ValueError("SC-B缺少同批SC-A正常原生退出。")
        _comparison_result(first, _sc_manifest_valid)
    return 1000


def _require_sc_certificates(m, configs=None):
    _require_local_certificates(m, configs)


def require_sc_candidate(m, configs=None):
    if not _sc_manifest_valid(m):
        raise ValueError("SC仅允许本次N0/v3两版本比较。")
    head, sources = sc_source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or sources != m["source_sha256"] or len(entries) != m["call"]
            or not lock.is_file() or lock.read_text(encoding="utf8").strip() != str(os.getpid())):
        raise ValueError("SC来源/当前占项/进程锁不符。")
    _next_sc_call(entries[:-1], m["profile"], m["phase"], head, sources, m)
    if entries[-1].get("finished") is not False or any(entries[-1].get(k) != value for k, value in m.items()
            if k not in ("command", "started_utc", "scope")):
        raise ValueError("SC当前在途记录不符。")
    _require_sc_certificates(m, configs)


def _w_manifest_valid(m):
    """本批W1诊断/W2有证据修复复核，不复活旧许可或另开跟踪。"""
    if not isinstance(m, dict) or m.get("comparison_stage") not in ("W1", "W2"):
        return False
    second = m["comparison_stage"] == "W2"
    common = {k: v for k, v in m.items() if k not in V2_CERTIFICATE_FIELDS}
    common.update(authorization_url=V1_DESIGN, comparison_design_url=V1_DESIGN,
        closed_history_sha256=V1_HISTORY, closed_native_history_sha256=V1_NATIVE_HISTORY,
        comparison_stage="V1", call=14, maximum_calls=14, total_maximum_attempts=14000,
        batch_maximum_calls=1, batch_maximum_attempts=1000,
        certificate_directory=str((ROOT/".tmp/issue120-stage-authorized-certs").resolve()),
        public_certificate_validity={}, comparison_review_url=V1_REVIEW, comparison_raw_sha256=V1_RAW_SHA256)
    return (m.get("authorization_url") == W_DESIGN and m.get("comparison_design_url") == W_DESIGN
        and m.get("closed_history_sha256") == W_HISTORY and m.get("closed_native_history_sha256") == W_NATIVE_HISTORY
        and m.get("wait_diagnostic") is (not second) and m.get("system_trace") is (not second)
        and m.get("first_model_failure_stop") is True
        and all(type(m.get(k)) is int and m[k] == v for k,v in {
            "call": 16 if second else 15, "maximum_calls": 16, "total_maximum_attempts": 16000,
            "batch_maximum_calls": 2, "batch_maximum_attempts": 2000}.items())
        and m.get("certificate_directory") in {str((ROOT/".tmp"/name).resolve())
                for name in ("issue120-stage-authorized-certs", "issue120-wait-diagnostic-certs")}
        and isinstance(m.get("public_certificate_validity"), dict)
        and not any(k in m for k in V2_CERTIFICATE_FIELDS if k != "public_certificate_validity")
        and _v1_manifest_valid(common))


def _next_w_call(entries, profile, phase, head, sources, m):
    """保留14项含失败的历史；W2额外要求原件/可复核区间/修复与独审。"""
    if (not _w_manifest_valid(m) or type(entries) is not list or len(entries) not in (14,15)
            or digest(entries[:14]) != W_HISTORY or m["call"] != len(entries)+1
            or any(e.get("finished") is not True for e in entries)
            or (profile,phase,head,sources) != (m["profile"],m["phase"],m["head"],m["source_sha256"])):
        raise ValueError("W批次许可/14项历史/来源/顺序或额度不符。")
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf8"))["entries"]
    keys = ("call","head","source_sha256","conditions_sha256","comparison_stage","authorization_url",
            "maximum_attempts","profile","phase","wire_profile")
    if (type(rows) is not list or len(rows) != len(entries)+1 or digest(rows[:14]) != W_NATIVE_HISTORY
            or any(r.get("completed") is not True for r in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or not isinstance(rows[-1].get("started_utc"),str)
            or any(rows[-1].get(k) != m.get(k) for k in keys)):
        raise ValueError("W批次原生历史/当前START不符。")
    previous = entries[13]
    frozen = previous["source_sha256"]
    if (previous["head"] != W_BASE_HEAD or head == W_BASE_HEAD or set(sources) != set(frozen)
            or any(sources[k] != value for k,value in frozen.items() if k not in W_SOURCE_FILES)):
        raise ValueError("W批次控制/材料/transport来源必须冻结。")
    # 换证只在W1前一次，旧公开指纹/条件必须可追溯，不读取私钥。
    if m.get("certificate_directory") == previous.get("certificate_directory"):
        if any(m.get(k) != previous.get(k) for k in ("public_certificate_sha256","public_certificate_validity","conditions_sha256")):
            raise ValueError("复用原证必须保持原指纹/条件。")
    elif (m.get("certificate_preparation_url") != W_DESIGN
            or m.get("certificate_preparation_reason") != "insufficient_validity_before_W1"
            or m.get("prior_public_certificate_sha256") != previous.get("public_certificate_sha256")
            or m.get("prior_conditions_sha256") != previous.get("conditions_sha256")
            or digest({"ports":m["ports"],"environment":m["environment"],
                "public_certificate_sha256":m["prior_public_certificate_sha256"],"seed":SEED}) != previous["conditions_sha256"]):
        raise ValueError("W1一次证书准备依据不符。")
    if len(entries) == 15:
        first = entries[-1]
        if (not _w_manifest_valid(first) or first["comparison_stage"] != "W1"
                or any(first.get(k) != m.get(k) for k in ("certificate_directory","public_certificate_sha256",
                    "public_certificate_validity","conditions_sha256")) or head == first["head"]
                or all(sources.get(k) == first.get("source_sha256",{}).get(k) for k in W_SOURCE_FILES[2:])
                or any(rows[-2].get(k) != first.get(k) for k in keys)
                or type(rows[-2].get("native_exit")) is not int
                or not COMMENT.fullmatch(m.get("diagnosis_review_url",""))
                or not COMMENT.fullmatch(m.get("fix_evidence_url",""))):
            raise ValueError("W2需要同链W1、真实退出、新修复head和独审。")
        raw = Path(first["output"]).read_bytes()
        cause = Path(m["cause_path"]).read_bytes()
        if (hashlib.sha256(raw).hexdigest() != first.get("raw_sha256")
                or m.get("predecessor_raw_sha256") != first.get("raw_sha256")
                or hashlib.sha256(cause).hexdigest() != m.get("cause_sha256")):
            raise ValueError("W2缺少精确原件/原因证据。")
        evidence = json.loads(cause)
        r = json.loads(raw)
        if (evidence.get("version") != 1 or evidence.get("branch") not in ("relative_preparation","handle_preparation","dispatch_work")
                or evidence.get("raw_sha256") != first["raw_sha256"] or evidence.get("head") != first["head"]
                or evidence.get("review_url") != m["diagnosis_review_url"]
                or type(evidence.get("start_ns")) is not int or type(evidence.get("end_ns")) is not int
                or evidence["end_ns"]-evidence["start_ns"] <= 1000000
                or evidence.get("trace_lost_events") != 0 or evidence.get("clock_mapping_verified") is not True
                or any(r.get("network_manifest",{}).get(k) != first.get(k) for k in keys)
                or (r.get("system_trace") or {}).get("saved") is not True
                or evidence.get("etl_sha256") != (r.get("system_trace") or {}).get("etl_sha256")
                or not isinstance(evidence.get("etl_sha256"),str)
                or not re.fullmatch(r"[0-9a-f]{64}",evidence["etl_sha256"])
                or not isinstance(evidence.get("excerpt_sha256"),str)
                or not re.fullmatch(r"[0-9a-f]{64}",evidence["excerpt_sha256"])
                or not (r.get("network_relay") or {}).get("wait_diagnostic",{}).get("first_anomaly")):
            raise ValueError("W2未有可复核内部原因区间/映射/独审，不接受root_cause布尔。")
    return 1000


def _require_w_certificates(m, configs=None):
    """只读当前同链公开证书及原N2拓扑；不在owner内生成证书。"""
    _require_v1_certificates(m, configs)


def require_w_candidate(m, configs=None):
    """正式/共享/实际循环共用本批锁、唯一START和原子占项。"""
    if not _w_manifest_valid(m):
        raise ValueError("缺少W批次精确许可。")
    head,sources = source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or sources != m["source_sha256"] or len(entries) != m["call"]
            or not lock.is_file() or lock.read_text(encoding="utf8").strip() != str(os.getpid())):
        raise ValueError("W批次当前来源/锁/占项不符。")
    _next_w_call(entries[:-1],m["profile"],m["phase"],head,sources,m)
    if entries[-1].get("finished") is not False or any(entries[-1].get(k) != value for k,value in m.items()
            if k not in ("command","started_utc","scope")):
        raise ValueError("W批次在途记录不符。")
    _require_w_certificates(m,configs)


class _WaitTrace:
    """仅W1一次任务具名WPR会话；启动不确定也保留claim，核实终止后释放归属。"""

    def __init__(self, manifest):
        self.manifest = manifest
        self.owned = False
        self.deadline_ns = time.perf_counter_ns()+85000000000
        self.report = {"version":1,"instance":W_TRACE_INSTANCE,"started":False,"saved":False,"commands":[]}

    @staticmethod
    def validate_profile(m):
        """只读校验32MiB内存环与最小事件集，禁止stack/sample/网络等宽泛配置。"""
        path = ROOT/".tmp/issue120-w1.wprp"
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != m.get("trace_profile_sha256"):
            raise ValueError("WPR任务profile摘要不符。")
        root = ElementTree.fromstring(data)
        profiles = root.findall("./Profiles/Profile")
        if (len(profiles) != 1 or profiles[0].get("LoggingMode") != "Memory"
                or profiles[0].get("Name") != W_TRACE_INSTANCE
                or [x.attrib for x in root.findall("./Profiles/SystemCollector/BufferSize")] != [{"Value":"256"}]
                or [x.attrib for x in root.findall("./Profiles/SystemCollector/Buffers")] != [{"Value":"128"}]
                or {x.get("Value") for x in root.findall("./Profiles/SystemProvider/Keywords/Keyword")} != W_TRACE_KEYWORDS
                or root.findall(".//Stacks") or root.findall(".//EventProvider")
                or m.get("trace_instance") != W_TRACE_INSTANCE or m.get("trace_max_seconds") != 90):
            raise ValueError("WPR必须为本任务固定32MiB及最小系统事件，禁止重型记录。")
        return path

    def _command(self, args, timeout):
        start = time.perf_counter_ns()
        remaining = (self.deadline_ns-start)/1000000000
        if remaining <= 0:
            raise TimeoutError("WPR本任务清理总时限已到，停止自动推进。")
        fact = {"command":["wpr",*args],"native_exit":None,"start_qpc_ns":start}
        try:
            result = subprocess.run(["wpr",*args],capture_output=True,text=True,
                                    timeout=min(timeout,remaining),check=False)
            fact["native_exit"] = result.returncode
        except BaseException as error:
            fact["error_type"] = type(error).__name__
            raise
        finally:
            fact["end_qpc_ns"] = time.perf_counter_ns()
            self.report["commands"].append(fact)
        if result.returncode:
            raise RuntimeError("本任务WPR命令失败；不重采。")
        return result.stdout

    def _confirm_stopped(self):
        """只核本任务具名会话；保存失败后最多一次cancel，确认停止才释放归属。"""
        try:
            status = self._command(["-status","-instancename",W_TRACE_INSTANCE],3)
            if "WPR is not recording" not in status:
                self.report["cancel_attempted"] = True
                self._command(["-cancel","-instancename",W_TRACE_INSTANCE],5)
                status = self._command(["-status","-instancename",W_TRACE_INSTANCE],3)
            if "WPR is not recording" not in status:
                raise RuntimeError("任务WPR尚在记录，禁止继续。")
            self.owned = False
            self.report["stopped_confirmed"] = True
        except BaseException as error:
            self.report.update(stopped_confirmed=False,cleanup_error_type=type(error).__name__)
            raise

    @classmethod
    def recover_owned(cls, manifest, *, deadline_ns=None):
        """原生外层所有退出都核持久claim；无本任务claim则不碰任何会话。"""
        path = ROOT/".tmp/issue120-w1-trace-claim.json"
        if not path.exists():
            return {"not_started":True,"stopped_confirmed":True}
        claim = json.loads(path.read_text(encoding="utf8"))
        if (claim.get("instance") != W_TRACE_INSTANCE or any(claim.get(k) != manifest.get(k)
                for k in ("head","call","trace_profile_sha256"))
                or type(claim.get("owner_pid")) is not int or type(claim.get("claim_qpc_ns")) is not int):
            raise ValueError("本任务跟踪归属凭据不匹配，不接管未知会话。")
        owner = cls(manifest)
        owner.deadline_ns = min(owner.deadline_ns,claim["claim_qpc_ns"]+85000000000,
                                deadline_ns if deadline_ns is not None else owner.deadline_ns)
        owner.owned = True
        try:
            owner._confirm_stopped()
        except BaseException as error:  # noqa: BLE001 - 保留未释放归属及明确失败，原生退出不被覆盖。
            owner.report["recovery_error_type"] = type(error).__name__
        finally:
            owner.report["ownership_released"] = not owner.owned
        return owner.report

    def __enter__(self):
        path = self.validate_profile(self.manifest)
        if (ROOT/".tmp/issue120-w1.etl").exists():
            raise ValueError("任务ETL已存在，禁止启动第二次记录。")
        if "WPR is not recording" not in self._command(["-status"],3):
            raise RuntimeError("存在非本任务WPR会话，不接管或cancel。")
        if "WPR is not recording" not in self._command(["-status","-instancename",W_TRACE_INSTANCE],3):
            raise RuntimeError("同名任务实例已存在，不接管。")
        # 两次只读确认无会话后，先独占登记这一次start尝试。超时也保留明确归属供外层收尾。
        claim = {k:self.manifest.get(k) for k in ("head","call","trace_profile_sha256")}
        claim.update(instance=W_TRACE_INSTANCE,owner_pid=os.getpid(),claim_qpc_ns=time.perf_counter_ns())
        with (ROOT/".tmp/issue120-w1-trace-claim.json").open("x",encoding="utf8") as stream:
            json.dump(claim,stream);stream.flush();os.fsync(stream.fileno())
        self.owned = True
        self.report["start_attempted"] = True
        try:
            self._command(["-start",str(path)+"!"+W_TRACE_INSTANCE,"-instancename",W_TRACE_INSTANCE],10)
            self.report["started"] = True
        except BaseException as error:
            self.report["start_error_type"] = type(error).__name__
            try:
                self._confirm_stopped()
            except BaseException as cleanup_error:  # noqa: BLE001 - 不覆盖首start错误，保留尚未释放归属。
                self.report["start_cleanup_error_type"] = type(cleanup_error).__name__
            raise
        return self

    def __exit__(self, *_):
        if self.owned:
            first_error = None
            try:
                path = ROOT/".tmp/issue120-w1.etl"
                if path.exists():
                    path = ROOT/f".tmp/issue120-w1-conflict-{os.getpid()}.etl"
                    self.report["stop_path_conflict"] = True
                    if path.exists():
                        raise RuntimeError("任务ETL及冲突保存路径均已存在。")
                self._command(["-stop",str(path),"-skipPdbGen","-instancename",W_TRACE_INSTANCE],10)
                self.report.update(saved=True,etl_path=str(path),etl_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                   etl_bytes=path.stat().st_size)
            except BaseException as error:  # noqa: BLE001 - 清理阶段保留首错，仍尝试确认本任务停止。
                self.report["stop_error_type"] = type(error).__name__
                first_error = error
            try:
                self._confirm_stopped()
            except BaseException as error:  # noqa: BLE001 - 状态不确定不能释放归属或覆盖首保存错误。
                first_error = first_error or error
            self.report["ownership_released"] = not self.owned
            if first_error is not None:
                raise first_error


def _v1_manifest_valid(m):
    """新批准仅一个N2/V1；沿用公共形状检查，不复活T/U或换证例外。"""
    if not isinstance(m, dict):
        return False
    common = {k: v for k, v in m.items() if k not in ("comparison_review_url", "comparison_raw_sha256")}
    common.update(authorization_url=LOCAL_DESIGN, comparison_design_url=LOCAL_DESIGN,
        closed_history_sha256=LOCAL_HISTORY, closed_native_history_sha256=LOCAL_NATIVE_HISTORY,
        comparison_stage="U2", profile="N0", call=13, maximum_calls=13, total_maximum_attempts=13000,
        batch_maximum_calls=2, batch_maximum_attempts=2000)
    return (m.get("authorization_url") == V1_DESIGN and m.get("comparison_design_url") == V1_DESIGN
        and m.get("closed_history_sha256") == V1_HISTORY
        and m.get("closed_native_history_sha256") == V1_NATIVE_HISTORY
        and m.get("comparison_stage") == "V1" and m.get("profile") == "N2"
        and m.get("control_head") == V1_CONTROL_HEAD and m.get("comparison_review_url") == V1_REVIEW
        and m.get("comparison_raw_sha256") == V1_RAW_SHA256
        and all(type(m.get(k)) is int and m[k] == v for k, v in {
            "call": 14, "maximum_calls": 14, "total_maximum_attempts": 14000,
            "batch_maximum_calls": 1, "batch_maximum_attempts": 1000}.items())
        and m.get("models") == {k: asdict(v) for k, v in models("N2").items()}
        and m.get("topology") == asdict(role_configs(
            ROOT/".tmp/issue120-stage-authorized-certs", V2_PORTS, "N2")[0].topology)
        and _local_manifest_valid(common))


def _next_v1_call(entries, profile, phase, head, sources, m):
    """唯一第14项；旧13对象/原生退出保留，重算同源U前件并冻结控制来源。"""
    if (not _v1_manifest_valid(m) or type(entries) is not list or len(entries) != 13
            or digest(entries) != V1_HISTORY or any(e.get("finished") is not True for e in entries)
            or (profile, phase, head, sources) != (m["profile"], m["phase"], m["head"], m["source_sha256"])):
        raise ValueError("V1精确许可/13项历史/来源或唯一额度不符。")
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf-8"))["entries"]
    keys = ("call", "head", "source_sha256", "conditions_sha256", "comparison_stage",
            "authorization_url", "maximum_attempts", "profile", "phase", "wire_profile")
    if (type(rows) is not list or len(rows) != 14 or digest(rows[:13]) != V1_NATIVE_HISTORY
            or any(r.get("completed") is not True for r in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or not isinstance(rows[-1].get("started_utc"), str)
            or any(rows[-1].get(k) != m.get(k) for k in keys)):
        raise ValueError("V1缺少精确native历史或当前唯一START。")
    old_sources = entries[12].get("source_sha256")
    if (entries[12].get("head") != V1_CONTROL_HEAD or head == V1_CONTROL_HEAD
            or not isinstance(old_sources, dict) or set(sources) != set(old_sources)
            or sources.get(V1_SOURCE_FILES[0]) == old_sources.get(V1_SOURCE_FILES[0])
            or any(sources[k] != v for k, v in old_sources.items() if k not in V1_SOURCE_FILES)):
        raise ValueError("V1只允许已审入口/退出路由变化，控制/relay等来源必须冻结。")
    originals = []
    fixed = ("certificate_directory", "public_certificate_sha256", "public_certificate_validity", "conditions_sha256")
    for entry, native, raw_sha in zip(entries[11:13], rows[11:13], V1_RAW_SHA256, strict=True):
        if (entry.get("head") != V1_CONTROL_HEAD or entry.get("source_sha256") != old_sources
                or entry.get("raw_sha256") != raw_sha or native.get("native_exit") != 0
                or any(native.get(k) != entry.get(k) for k in keys)
                or any(entry.get(k) != m.get(k) for k in fixed)):
            raise ValueError("V1需要已审U1/U2精确原件、真实正常退出及同套条件/证书。")
        originals.append(_comparison_result(entry, _local_manifest_valid))
    if not _staged_gain(*originals):
        raise ValueError("V1前置U1/U2未达到原10%收益，不能只信通过标志。")
    return 1000


def _require_v1_certificates(m, configs=None):
    """只读同套证书；实际必须走N2中继拓扑，禁止N0占位。"""
    if configs is not None and configs != role_configs(m["certificate_directory"], V2_PORTS, "N2"):
        raise ValueError("V1实际拓扑必须等于原N2六向TLS配置。")
    _require_local_certificates(m)


def require_v1_candidate(m, configs=None):
    """正式CLI、共享入口及实际循环共用当前来源、锁与第14项核验。"""
    if not _v1_manifest_valid(m):
        raise ValueError("缺少V1唯一N2许可。")
    head, sources = source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or sources != m["source_sha256"] or len(entries) != 14
            or not lock.is_file() or lock.read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("V1缺少当前来源/进程锁/唯一占项。")
    _next_v1_call(entries[:-1], m["profile"], m["phase"], head, sources, m)
    if entries[-1].get("finished") is not False or any(entries[-1].get(k) != v for k, v in m.items()
            if k not in ("command", "started_utc", "scope")):
        raise ValueError("V1在途占项与manifest不符。")
    _require_v1_certificates(m, configs)


def _v1_relay_pass(relay):
    """绑定原N2报告身份/模型资源字段；模型公式与误差判断仍由原relay负责。"""
    from ._network_emulator import MODEL_TOLERANCE_NS, QUEUE_LIMIT, READ_LIMIT

    directions = relay.get("directions")
    return (relay.get("profile") == "N2" and relay.get("seed") == SEED
        and relay.get("read_block_limit") == READ_LIMIT and relay.get("queue_limit_per_direction") == QUEUE_LIMIT
        and relay.get("model_tolerance_ns") == MODEL_TOLERANCE_NS
        and isinstance(directions, dict) and set(directions) == set(models("N2"))
        and all(isinstance(r, dict) and all(type(r.get(k)) is int and r[k] > 0
                for k in ("received_bytes", "sent_bytes")) for r in directions.values()))


def _local_manifest_valid(m):
    """仅本次局部摘要优化的两个直连阶段，不恢复旧 T3 或换证许可。"""
    if not isinstance(m, dict):
        return False
    index = next((i for i, row in enumerate(LOCAL_STAGES) if row == (
        m.get("comparison_stage"), m.get("profile"), m.get("wire_profile"))), None)
    if index is None:
        return False
    common = m | {"authorization_url": STAGED_AUTHORIZATION, "comparison_design_url": STAGED_DESIGN,
        "closed_history_sha256": STAGED_HISTORY, "closed_native_history_sha256": STAGED_NATIVE_HISTORY,
        "comparison_stage": "T1" if index == 0 else "T2", "call": 10+index,
        "maximum_calls": 12, "total_maximum_attempts": 12000,
        "batch_maximum_calls": 3, "batch_maximum_attempts": 3000}
    return (m.get("authorization_url") == LOCAL_DESIGN and m.get("comparison_design_url") == LOCAL_DESIGN
        and m.get("closed_history_sha256") == LOCAL_HISTORY
        and m.get("closed_native_history_sha256") == LOCAL_NATIVE_HISTORY
        and all(type(m.get(k)) is int and m[k] == v for k, v in {
            "call": 12+index, "maximum_calls": 13, "total_maximum_attempts": 13000,
            "batch_maximum_calls": 2, "batch_maximum_attempts": 2000}.items())
        and not any(k in m for k in (*[key for key in V2_CERTIFICATE_FIELDS if key != "public_certificate_validity"],
                                    "comparison_review_url", "comparison_raw_sha256"))
        and isinstance(m.get("public_certificate_validity"), dict)
        and _staged_manifest_valid(common))


def _next_local_call(entries, profile, phase, head, sources, m):
    """保留旧十一对象及 exit5；只要求本批 U1 成功成为 U2 前件。"""
    if (not _local_manifest_valid(m) or type(entries) is not list or len(entries) not in (11, 12)
            or digest(entries[:11]) != LOCAL_HISTORY or m["call"] != len(entries)+1
            or (profile, phase, head, sources) != (m["profile"], m["phase"], m["head"], m["source_sha256"])
            or any(entry.get("finished") is not True for entry in entries)
            or [(e.get("comparison_stage"), e.get("profile"), e.get("wire_profile"))
                for e in entries[11:]] != list(LOCAL_STAGES[:len(entries)-11])):
        raise ValueError("局部比较许可/十一项历史/顺序/来源或额度不符。")
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf-8"))["entries"]
    keys = ("call", "head", "source_sha256", "conditions_sha256", "comparison_stage",
            "authorization_url", "maximum_attempts", "profile", "phase", "wire_profile")
    if (type(rows) is not list or len(rows) != len(entries)+1 or digest(rows[:11]) != LOCAL_NATIVE_HISTORY
            or any(row.get("completed") is not True for row in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or not isinstance(rows[-1].get("started_utc"), str)
            or any(rows[-1].get(k) != m.get(k) for k in keys)):
        raise ValueError("局部比较 native 历史/当前 START 不符。")
    fixed = ("certificate_directory", "public_certificate_sha256", "public_certificate_validity", "conditions_sha256")
    if any(m.get(k) != entries[10].get(k) for k in fixed):
        raise ValueError("局部比较必须复用已存在的同套证书/环境条件，不含换证授权。")
    if len(entries) == 11 and (head == entries[10].get("head") or sources == entries[10].get("source_sha256")):
        raise ValueError("U1必须使用局部优化后新审查的来源，不能重跑旧T1/T2。")
    if len(entries) == 12:
        previous, native = entries[-1], rows[-2]
        if (not _local_manifest_valid(previous) or native.get("native_exit") != 0
                or any(native.get(k) != previous.get(k) for k in keys)
                or any(previous.get(k) != m.get(k) for k in (*fixed, "head", "source_sha256"))):
            raise ValueError("U2必须与已正常退出的U1同源同条件。")
        _comparison_result(previous, _local_manifest_valid)
    return 1000


def _require_local_certificates(m, configs=None):
    """只读现有公开证书预检，不产生、替换或借用上一批换证例外。"""
    directory = Path(m["certificate_directory"])
    if (certificate_validity(directory) != m["public_certificate_validity"]
            or any(hashlib.sha256((directory/name).read_bytes()).hexdigest() != sha
                   for name, sha in m["public_certificate_sha256"].items())
            or configs is not None and configs != role_configs(directory, V2_PORTS, "N0")):
        raise ValueError("局部比较证书/有效期/固定直连拓扑不匹配；不得自动换证。")


def require_local_candidate(m, configs=None):
    """CLI/共享/实际循环共同核对新的有限占项，未占项不能旁路运行。"""
    if not _local_manifest_valid(m):
        raise ValueError("缺少局部比较 U1/U2 的精确许可。")
    head, sources = source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or sources != m["source_sha256"] or len(entries) != m["call"]
            or not lock.is_file() or lock.read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("局部比较缺少当前来源/进程锁/占项。")
    _next_local_call(entries[:-1], m["profile"], m["phase"], head, sources, m)
    if entries[-1].get("finished") is not False or any(entries[-1].get(k) != v for k, v in m.items()
            if k not in ("command", "started_utc", "topology", "models", "scope")):
        raise ValueError("局部比较在途占项与 manifest 不符。")
    _require_local_certificates(m, configs)


def _staged_manifest_valid(m):
    """本批次只允许同源 T1/T2/T3 各一次，不复活旧复验或长期资格。"""
    if not isinstance(m, dict):
        return False
    stage = next((i for i, item in enumerate(STAGED_STAGES) if item == (
        m.get("comparison_stage"), m.get("profile"), m.get("wire_profile"))), None)
    if stage is None:
        return False
    # 仅复用公共形状检查，旧许可自身的阶段、历史及证书例外判断不变。
    common = {k: v for k, v in m.items() if k not in V2_CERTIFICATE_FIELDS}
    common.update(wire_profile=_COMPACT_PROFILE_V2, authorization_url=V2_AUTHORIZATION,
        closed_history_sha256=V2_CLOSED_HISTORY, profile="N2", phase="candidate", call=6,
        maximum_calls=6, maximum_attempts=1000, total_maximum_attempts=6000,
        continuation_maximum_calls=1, continuation_maximum_attempts=1000,
        eligible_for_candidate=True, qualification_allowed=False)
    return (m.get("authorization_url") == STAGED_AUTHORIZATION
        and m.get("comparison_design_url") == STAGED_DESIGN
        and m.get("closed_history_sha256") == STAGED_HISTORY
        and m.get("closed_native_history_sha256") == STAGED_NATIVE_HISTORY
        and m.get("phase") == "candidate" and m.get("software_pass") is True
        and m.get("readback_exact") is True and m.get("qualification_allowed") is False
        and all(type(m.get(k)) is int and m[k] == v for k, v in {
            "call": 10+stage, "maximum_calls": 12, "maximum_attempts": 1000,
            "total_maximum_attempts": 12000, "batch_maximum_calls": 3,
            "batch_maximum_attempts": 3000}.items())
        and m.get("wait_strategy") == EVENT_STRATEGY
        and m.get("certificate_directory") == str((ROOT/".tmp/issue120-stage-authorized-certs").resolve())
        and m.get("native_ledger_path") == str((ROOT/".tmp/issue120-network-invocations.json").resolve())
        and not any(k in m for k in ("closure_stage", "continuation_stage"))
        and _v2_candidate_manifest_valid(common))


def _staged_result(entry):
    """读取完整原件并重算全部旧门禁；不信任账本预填的通过标志。"""
    return _comparison_result(entry, _staged_manifest_valid)


def _comparison_result(entry, valid_manifest):
    """同一完整原件读取/门禁算法；由具体批次决定许可，不复制证据真相。"""
    data = Path(entry["output"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry.get("raw_sha256"):
        raise ValueError("比较阶段前件原件摘要不匹配。")
    result = json.loads(data)
    manifest = result.get("network_manifest") or {}
    if (not valid_manifest(manifest) or any(manifest.get(k) != entry.get(k) for k in (
            "comparison_stage", "head", "source_sha256", "conditions_sha256", "call"))
            or result.get("code_sha") != entry["head"]
            or result.get("source_sha256") != entry["source_sha256"]):
        raise ValueError("比较阶段前件原件来源不匹配。")
    checked = assemble(copy.deepcopy(result), profile=entry["profile"], phase="candidate",
                       manifest=manifest, relay=result.get("network_relay") or {})
    if checked.get("network_sample_pass") is not True:
        raise ValueError("比较阶段前件未完整通过；剩余额度停止。")
    return result


def _staged_gain(baseline, candidate):
    """从完整周期端点计算固定 10% 中位数收益；整数插值避免预填分位。"""
    def values(result):
        rows = result.get("cycles", [])
        if len(rows) != 1000 or any(not isinstance(row, dict) or type(row.get(k)) is not int for row in rows for k in (
                "scheduled_start_ns", "cycle_completed_ns")):
            raise ValueError("比较需要完整1000周期。")
        times = sorted(row["cycle_completed_ns"]-row["scheduled_start_ns"] for row in rows)
        if min(times) < 0:
            raise ValueError("周期端点倒置。")
        return times
    def percentile(times, percent):
        index, remainder = divmod((len(times)-1)*percent, 100)
        return times[index]*(100-remainder)+times[min(index+1, len(times)-1)]*remainder
    first, second = values(baseline), values(candidate)
    return (10*percentile(second, 50) <= 9*percentile(first, 50)
            and percentile(second, 99) <= percentile(first, 99) and max(second) <= 20000000)


def _staged_frames_pass(result, wire_profile):
    """分开核真实轮发送与维护记账：Party 的 advance 回执计入下一轮之前。"""
    normal = 11 if wire_profile == _COMPACT_PROFILE_V3 else 15
    rows, parties, cycles = result.get("steps", []), result.get("party_outcomes", []), result.get("cycles", [])
    if len(rows) != 1000 or len(parties) != 2 or len(cycles) != 1000:
        return False
    def count(sent):
        if not isinstance(sent, dict) or any(not isinstance(row, dict) or type(row.get("frames")) is not int or row["frames"] < 0
                                             for row in sent.values()):
            raise ValueError("发送帧计数不完整。")
        return sum(row["frames"] for row in sent.values())
    try:
        for step, row in enumerate(rows):
            # Client 暂存/提交共4帧；维护另在 CycleTiming 的实际计数中保留。
            if count(row["sent"]) != 4:
                return False
            role_frames = 0
            for party in parties:
                item = party["steps"][step]
                if item["step"] != step:
                    return False
                role_frames += count(item["sent"])
            if role_frames+4 != normal+(2 if step in (400, 800) else 0):
                return False
            sent = cycles[step]["public_frame_counts"]
            if (not isinstance(sent, dict) or any(type(value) is not int or value < 0 for value in sent.values())
                    or sum(sent.values()) != 4+(2 if step in (399, 799) else 0)):
                return False
    except (KeyError, TypeError, ValueError, IndexError):
        return False
    return True


def _next_staged_call(entries, profile, phase, head, sources, m):
    """原九对象保持逐字语义；任何已启动失败、改源或前件不足封闭后续。"""
    if (not _staged_manifest_valid(m) or type(entries) is not list or not 9 <= len(entries) <= 11
            or digest(entries[:9]) != STAGED_HISTORY or m["call"] != len(entries)+1
            or (profile, phase, head, sources) != (m["profile"], m["phase"], m["head"], m["source_sha256"])
            or any(entry.get("finished") is not True for entry in entries)
            or [(entry.get("comparison_stage"), entry.get("profile"), entry.get("wire_profile"))
                for entry in entries[9:]] != list(STAGED_STAGES[:len(entries)-9])):
        raise ValueError("比较阶段许可/九项历史/来源/顺序或额度不符。")
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf-8"))["entries"]
    keys = ("call", "head", "source_sha256", "conditions_sha256", "comparison_stage",
            "authorization_url", "maximum_attempts", "profile", "phase", "wire_profile")
    if m.get("previous_public_certificate_sha256") != entries[8].get("public_certificate_sha256"):
        raise ValueError("比较阶段换证必须保留固定第九项的公开指纹。")
    if (type(rows) is not list or len(rows) != len(entries)+1
            or digest(rows[:9]) != STAGED_NATIVE_HISTORY
            or any(row.get("completed") is not True for row in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or not isinstance(rows[-1].get("started_utc"), str)
            or any(rows[-1].get(k) != m.get(k) for k in keys)):
        raise ValueError("比较阶段 native 历史/当前 START 不符。")
    originals = []
    for entry, native in zip(entries[9:], rows[9:-1], strict=True):
        if (not _staged_manifest_valid(entry) or native.get("native_exit") != 0
                or any(native.get(k) != entry.get(k) for k in keys)
                or any(entry.get(k) != m.get(k) for k in (
                    "head", "source_sha256", "conditions_sha256", "certificate_directory",
                    "public_certificate_sha256", "public_certificate_validity"))):
            raise ValueError("比较阶段必须同源、同条件且前件真实退出成功。")
        originals.append(_staged_result(entry))
    if len(originals) == 2 and (
            not _staged_gain(*originals)
            or not isinstance(m.get("comparison_review_url"), str)
            or not COMMENT.fullmatch(m["comparison_review_url"])
            or m.get("comparison_raw_sha256") != [entry["raw_sha256"] for entry in entries[9:]]):
        raise ValueError("T3需要完整收益门槛及两份精确原件的独立审计。")
    return 1000


def _require_staged_certificates(m, configs=None):
    """仅 T1 前一次同规格换证；三阶段共用，原公开证书和私钥均不覆盖。"""
    directory = Path(m["certificate_directory"])
    old = ROOT/".tmp/issue120-network-closure-certs"
    if (m.get("certificate_change_authorization_url") != STAGED_AUTHORIZATION
            or m.get("certificate_change_reason") != "insufficient_validity_before_T1"
            or certificate_validity(directory) != m.get("public_certificate_validity")
            or any(hashlib.sha256((directory/name).read_bytes()).hexdigest() != sha
                   for name, sha in m["public_certificate_sha256"].items())
            or not isinstance(m.get("previous_public_certificate_sha256"), dict)
            or set(m["previous_public_certificate_sha256"]) != set(m["public_certificate_sha256"])
            or any(hashlib.sha256((old/name).read_bytes()).hexdigest() != sha
                   for name, sha in m["previous_public_certificate_sha256"].items())
            or not any(ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(old/name))["notAfter"])
                       - datetime.now(UTC).timestamp() < 3600 for name in m["public_certificate_sha256"])
            or configs is not None and configs != role_configs(directory, V2_PORTS, m["profile"])):
        raise ValueError("比较阶段证书/有效期/拓扑或一次必要换证依据不符。")


def require_staged_candidate(m, configs=None):
    """共享入口与实际循环都核当前锁、来源及占项；私有入口也不能追加调用。"""
    if not _staged_manifest_valid(m):
        raise ValueError("缺少本批 T1/T2/T3 精确许可。")
    head, sources = source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or sources != m["source_sha256"] or len(entries) != m["call"]
            or not lock.is_file() or lock.read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("比较阶段缺少当前来源/进程锁/占项。")
    _next_staged_call(entries[:-1], m["profile"], m["phase"], head, sources, m)
    if entries[-1].get("finished") is not False or any(entries[-1].get(k) != v for k, v in m.items()
            if k not in ("command", "started_utc", "topology", "models", "scope")):
        raise ValueError("比较阶段在途占项与 manifest 不符。")
    _require_staged_certificates(m, configs)


def require_network_candidate(m, wire_profile, configs=None):
    """只按明确批次路由许可；不能把 v3 放入旧 R1/Q1 的能力集合。"""
    if isinstance(m, dict) and m.get("authorization_url") == MATRIX_AUTHORIZATION:
        require_matrix_candidate(m, wire_profile, configs)
        return
    if isinstance(m, dict) and m.get("authorization_url") == SC_DESIGN:
        if m.get("wire_profile") != wire_profile:
            raise ValueError("SC实际编码不符。")
        require_sc_candidate(m, configs)
        return
    if isinstance(m, dict) and m.get("authorization_url") == W_DESIGN:
        if m.get("wire_profile") != wire_profile:
            raise ValueError("W批次编码与实际入口不符。")
        require_w_candidate(m,configs)
        return
    if isinstance(m, dict) and m.get("authorization_url") == V1_DESIGN:
        if m.get("wire_profile") != wire_profile:
            raise ValueError("V1编码与实际入口不匹配。")
        require_v1_candidate(m, configs)
        return
    if isinstance(m, dict) and m.get("authorization_url") == LOCAL_DESIGN:
        if m.get("wire_profile") != wire_profile:
            raise ValueError("局部比较编码与实际入口不匹配。")
        require_local_candidate(m, configs)
        return
    if wire_profile == _COMPACT_PROFILE_V3 or isinstance(m, dict) and m.get("authorization_url") == STAGED_AUTHORIZATION:
        if not isinstance(m, dict) or m.get("wire_profile") != wire_profile:
            raise ValueError("比较阶段编码与实际入口不符。")
        require_staged_candidate(m, configs)
    else:
        require_v2_candidate(m, configs)


def _repair_manifest_valid(m):
    """第19批仅两个具体新阶段；旧B/C及布尔冒充整数均不能借用。"""
    if not isinstance(m, dict):
        return False
    qualification = m.get("continuation_stage") == "repair_qualification"
    legacy = {k:v for k,v in m.items() if k not in V2_CERTIFICATE_FIELDS}
    legacy.update(authorization_url=V2_AUTHORIZATION,closed_history_sha256=V2_CLOSED_HISTORY,
        phase="candidate",call=6,maximum_calls=6,maximum_attempts=1000,total_maximum_attempts=6000,
        continuation_maximum_calls=1,continuation_maximum_attempts=1000,
        eligible_for_candidate=True,qualification_allowed=False)
    return (m.get("authorization_url") == REPAIR_AUTHORIZATION
        and m.get("continuation_design_url") == REPAIR_DESIGN
        and m.get("continuation_stage") in ("repair_recheck","repair_qualification")
        and "closure_stage" not in m and m.get("closed_history_sha256") == REPAIR_HISTORY
        and m.get("closed_native_history_sha256") == REPAIR_NATIVE_HISTORY
        and m.get("wait_strategy") == EVENT_STRATEGY
        and m.get("phase") == ("qualification" if qualification else "candidate")
        and all(type(m.get(k)) is int and m[k] == v for k,v in {
            "call":10 if qualification else 9,"maximum_calls":10,"total_maximum_attempts":19000,
            "maximum_attempts":10000 if qualification else 1000,
            "continuation_maximum_calls":2,"continuation_maximum_attempts":11000}.items())
        and m.get("eligible_for_candidate") is (not qualification)
        and m.get("qualification_allowed") is qualification
        and m.get("software_pass") is True and m.get("readback_exact") is True
        and m.get("native_ledger_path") == str((ROOT/".tmp/issue120-network-invocations.json").resolve())
        and isinstance(m.get("certificate_directory"),str)
        and m.get("certificate_directory") in {str((ROOT/".tmp"/name).resolve()) for name in
            ("issue120-network-closure-certs","issue120-network-repair-certs")}
        and isinstance(m.get("source_sha256"),dict)
        and "src/secure_control/experiments/_network_wait_win32.py" in m["source_sha256"]
        and _v2_candidate_manifest_valid(legacy))


def _repair_native(entries, m):
    """native只记实际CLI事实；canonical核固定历史及当前START，不赋予旁路许可。"""
    rows = json.loads(Path(m["native_ledger_path"]).read_text(encoding="utf-8"))["entries"]
    if (type(rows) is not list or len(rows) != len(entries)+1
            or digest(rows[:8]) != REPAIR_NATIVE_HISTORY
            or any(r.get("completed") is not True for r in rows[:-1])
            or rows[-1].get("completed") is not False or rows[-1].get("native_exit") is not None
            or not isinstance(rows[-1].get("started_utc"),str)
            or any(rows[-1].get(k) != m.get(k) for k in ("call","head","source_sha256","conditions_sha256",
                "continuation_stage","authorization_url","maximum_attempts","profile","phase"))):
        raise ValueError("修复复验native历史/当前START或完成状态不符，不允许重跑。")
    if len(entries) == 9 and (rows[8].get("native_exit") != 0
            or any(rows[8].get(k) != entries[8].get(k) for k in ("call","head","source_sha256",
                "conditions_sha256","continuation_stage","authorization_url","maximum_attempts","profile","phase"))):
        raise ValueError("资格前件native必须是同一复验的实际成功退出。")


def _next_repair_call(entries, profile, phase, head, sources, m):
    """只追加call9复验/call10资格；原八项失败与未用步数保持封闭。"""
    if (not _repair_manifest_valid(m) or type(entries) is not list or len(entries) not in (8,9)
            or digest(entries[:8]) != REPAIR_HISTORY or any(e.get("finished") is not True for e in entries)
            or m["call"] != len(entries)+1 or (profile,phase,head,sources) != (m["profile"],m["phase"],m["head"],m["source_sha256"])
            or sum(e["maximum_attempts"] for e in entries)+m["maximum_attempts"] > 19000):
        raise ValueError("修复复验许可/八项历史/来源/阶段或额度不符。")
    previous = entries[-1]
    if (m.get("predecessor_raw_sha256") != previous.get("raw_sha256")
            or m.get("predecessor_readback_exact") is not True
            or not isinstance(m.get("predecessor_review_url"),str)
            or not COMMENT.fullmatch(m["predecessor_review_url"])):
        raise ValueError("修复复验缺少精确前件原件和独立审计。")
    _repair_native(entries,m)
    goal = _closure_predecessor(previous)
    if len(entries) == 8:
        if (m["continuation_stage"] != "repair_recheck" or goal
                or head == previous["head"] or sources == previous["source_sha256"]
                or m.get("previous_conditions_sha256") != previous["conditions_sha256"]
                or m.get("previous_public_certificate_sha256") != previous["public_certificate_sha256"]
                or digest({"ports":m["ports"],"environment":m["environment"],
                    "public_certificate_sha256":m["previous_public_certificate_sha256"],"seed":SEED}) != previous["conditions_sha256"]):
            raise ValueError("R1必须绑定旧B失败及同一环境/端口/seed，使用新已审来源。")
        same = all(m.get(k)==previous.get(k) for k in ("conditions_sha256","certificate_directory",
            "public_certificate_sha256","public_certificate_validity"))
        if not same and (m["certificate_directory"] != str((ROOT/".tmp/issue120-network-repair-certs").resolve())
                or m.get("certificate_change_authorization_url") != REPAIR_AUTHORIZATION
                or m.get("certificate_change_reason") != "insufficient_validity_before_R1"):
            raise ValueError("R1只允许原条件或明确一次必要换证例外。")
    elif (m["continuation_stage"] != "repair_qualification" or not goal
            or not _repair_manifest_valid(previous) or previous.get("continuation_stage") != "repair_recheck"
            or previous["head"] != head or previous["source_sha256"] != sources or previous["maximum_attempts"] != 1000
            or any(m.get(k) != previous.get(k) for k in ("conditions_sha256","certificate_directory",
                "public_certificate_sha256","public_certificate_validity",*V2_CERTIFICATE_FIELDS))):
        raise ValueError("Q1只允许同源/同条件、完整且18/16通过并独立审计的R1。")
    return m["maximum_attempts"]


def _require_repair_certificates(m, configs=None):
    """离线核证；仅R1前原证不足一小时可使用同规格新目录，Q1不得换套。"""
    directory = Path(m["certificate_directory"])
    if (certificate_validity(directory) != m.get("public_certificate_validity")
            or any(hashlib.sha256((directory/name).read_bytes()).hexdigest() != sha
                   for name,sha in m["public_certificate_sha256"].items())
            or configs is not None and configs != role_configs(directory,V2_PORTS,"N2")):
        raise ValueError("修复复验证书/有效期/角色配置与冻结不符。")
    original = ROOT/".tmp/issue120-network-closure-certs"
    if directory.resolve() != original.resolve():
        now = datetime.now(UTC).timestamp()
        if (m.get("certificate_change_authorization_url") != REPAIR_AUTHORIZATION
                or m.get("certificate_change_reason") != "insufficient_validity_before_R1"
                or not any(ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(original/name))['notAfter'])-now < 3600
                           for name in m["public_certificate_sha256"])
                or any(hashlib.sha256((original/name).read_bytes()).hexdigest() != sha
                       for name,sha in m["previous_public_certificate_sha256"].items())):
            raise ValueError("R1新证只能来自本批准的一次必要准备，旧证必须保持。")


def _require_repair(m, configs=None):
    """共享与实际循环复用唯一canonical占项和native事实，不靠外层wrapper放行。"""
    head,sources = source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or sources != m["source_sha256"] or len(entries) != m["call"]
            or not lock.is_file() or lock.read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("修复复验共享入口缺当前来源/进程锁/占项。")
    _next_repair_call(entries[:-1],m["profile"],m["phase"],head,sources,m)
    if entries[-1].get("finished") is not False or any(entries[-1].get(k) != value for k,value in m.items()
            if k not in ("command","started_utc","topology","models","scope")):
        raise ValueError("修复复验在途占项与manifest不符。")
    _require_repair_certificates(m,configs)


def _event_manifest_valid(m):
    """只接受具体已批准的B/C与新增来源，不接受任意strategy或新A。"""
    return (m.get("wait_strategy") == EVENT_STRATEGY and m.get("wait_design_url") == EVENT_DESIGN
        and m.get("wait_authorization_url") == EVENT_AUTHORIZATION
        and m.get("closed_seven_history_sha256") == EVENT_HISTORY
        and (m.get("closure_stage"), m.get("call")) in (("B", 8), ("C", 9))
        and isinstance(m.get("source_sha256"), dict)
        and "src/secure_control/experiments/_network_wait_win32.py" in (m.get("source_sha256") or {}))


def _closure_manifest_valid(m):
    """第15次A/B/C的共同公开许可形状；实际历史/前置原件由同一owner核验。"""
    if not isinstance(m, dict):
        return False
    stage = m.get("closure_stage")
    steps = 10000 if stage == "C" else 1000
    # 复用已有来源/环境/GC/证书/总账路径检查，旧许可自身的语义保持不变。
    legacy = {k: v for k, v in m.items() if k not in V2_CERTIFICATE_FIELDS}
    legacy.update(authorization_url=V2_AUTHORIZATION, closed_history_sha256=V2_CLOSED_HISTORY,
        profile="N2", phase="candidate", call=6, maximum_calls=6, maximum_attempts=1000,
        total_maximum_attempts=6000, continuation_maximum_calls=1, continuation_maximum_attempts=1000,
        eligible_for_candidate=True, qualification_allowed=False)
    return (stage in ("A", "B", "C") and m.get("authorization_url") == CLOSURE_AUTHORIZATION
        and (not any(k in m for k in EVENT_FIELDS) or _event_manifest_valid(m))
        and m.get("closed_history_sha256") == CLOSURE_HISTORY
        and m.get("profile") == "N2" and m.get("phase") == ("qualification" if stage == "C" else "candidate")
        and all(type(m.get(k)) is int and m[k] == v for k, v in {
            "maximum_calls": 9, "maximum_attempts": steps, "total_maximum_attempts": 18000,
            "continuation_maximum_calls": 3, "continuation_maximum_attempts": 12000}.items())
        and type(m.get("call")) is int and m["call"] in ({7} if stage == "A" else {8} if stage == "B" else {8, 9})
        and m.get("eligible_for_candidate") is (stage != "C") and m.get("qualification_allowed") is (stage == "C")
        and m.get("software_pass") is True and m.get("readback_exact") is True
        and isinstance(m.get("certificate_directory"), str)
        and m["certificate_directory"] in {str((ROOT/".tmp"/name).resolve())
            for name in ("issue120-compact-v2-certs", "issue120-network-closure-certs")}
        and _v2_candidate_manifest_valid(legacy))


def _closure_cpu_pass(relay, *, native=False):
    """只核已记录CPU服务区间；不是全OS进程或纯控制CPU。"""
    p = relay.get("wait_policy") or {}
    normal = {"version": 2 if native else 1, "max_poll_episode_ns": 0 if native else 500000,
              "cpu_window_ns": 100000000, "cpu_limit_percent": 50}
    if (any(type(p.get(k)) is not int or p[k] != v for k, v in normal.items())
            or p.get("strategy") != (EVENT_STRATEGY if native else "bounded-near-due-v1")
            or (p.get("guard_ns") is not None if native else type(p.get("guard_ns")) is not int or p["guard_ns"] != 500000)
            or p.get("lifecycle_complete") is not True
            or p.get("first_cpu_limit_window") is not None or p.get("cpu_sample_error_type") is not None
            or type(p.get("cpu_complete_windows")) is not int or p["cpu_complete_windows"] < 1):
        return False
    if native and (p.get("active_poll") is not False
            or any(type(p.get(k)) is not int or p[k] != 0 for k in ("poll_episodes", "poll_wall_ns", "max_poll_wall_ns", "handles_open"))
            or type(p.get("handle_high_water")) is not int or not 1 <= p["handle_high_water"] <= 16
            or type(p.get("native_wait_calls")) is not int or p["native_wait_calls"] < 1
            or any(type(p.get(k)) is not int or p[k] < 0 for k in
                ("network_notifications", "last_wait_started_ns", "last_wait_returned_ns", "last_wait_target_ns"))
            or p["last_wait_returned_ns"] < p["last_wait_started_ns"]):
        return False
    for row in (p.get("peak_cpu_window"), p.get("tail_cpu_window")):
        if (not isinstance(row, dict) or any(type(row.get(k)) is not int or row[k] < 0 for k in
                ("start_qpc_ns", "end_qpc_ns", "cpu_delta_ns", "wall_delta_ns"))
                or row["end_qpc_ns"]-row["start_qpc_ns"] != row["wall_delta_ns"]
                or row.get("complete_window") is not (row["wall_delta_ns"] >= 100000000)
                or row["complete_window"] and 2*row["cpu_delta_ns"] > row["wall_delta_ns"]):
            return False
    return True


def _closure_goal(result):
    """从全部完整周期重算18/16目标，不相信预填分位或goal布尔。"""
    rows = result.get("cycles", [])
    if not rows or any(type(r.get(k)) is not int for r in rows for k in
                       ("scheduled_start_ns", "cycle_completed_ns")):
        return False
    values = sorted(r["cycle_completed_ns"]-r["scheduled_start_ns"] for r in rows)
    index, remainder = divmod((len(values)-1)*99, 100)
    p99_times_100 = values[index]*(100-remainder) + values[min(index+1, len(values)-1)]*remainder
    return min(values) >= 0 and max(values) <= 18000000 and p99_times_100 <= 16000000*100


def _closure_predecessor(entry):
    """原件hash、来源和完整门禁重算；返回真实有限样本及进步门禁。"""
    data = Path(entry["output"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry.get("raw_sha256"):
        raise ValueError("闭环前置原件hash不符。")
    result = json.loads(data)
    manifest = result.get("network_manifest") or {}
    if (manifest.get("authorization_url") not in (CLOSURE_AUTHORIZATION,REPAIR_AUTHORIZATION)
            or manifest.get("head") != entry["head"] or manifest.get("source_sha256") != entry["source_sha256"]
            or result.get("code_sha") != entry["head"] or result.get("source_sha256") != entry["source_sha256"]
            or manifest.get("conditions_sha256") != entry["conditions_sha256"]):
        raise ValueError("闭环前置原件来源/条件不符。")
    checked = assemble(copy.deepcopy(result), profile="N2", phase=entry["phase"], manifest=manifest,
                       relay=result.get("network_relay") or {})
    return checked["network_sample_pass"] and _closure_goal(result)


def _next_closure_call(entries, profile, phase, head, sources, m):
    """A→可选单一patch的B→同源C；失败启动占项，不复活旧六项许可。"""
    if (not _closure_manifest_valid(m) or profile != m["profile"] or phase != m["phase"]
            or head != m["head"] or sources != m["source_sha256"]
            or type(entries) is not list or not 6 <= len(entries) <= 8
            or digest(entries[:6]) != CLOSURE_HISTORY or m["call"] != len(entries)+1
            or any(e.get("finished") is not True for e in entries)):
        raise ValueError("闭环许可/来源/六项历史/顺序或在途状态不符。")
    current = entries[6:]
    if ([e.get("closure_stage") for e in current] not in ([], ["A"], ["A", "B"])
            or any(e.get("authorization_url") != CLOSURE_AUTHORIZATION for e in current)
            or sum(e["maximum_attempts"] for e in current)+m["maximum_attempts"] > 12000):
        raise ValueError("闭环阶段结束或预算耗尽。")
    stage = m["closure_stage"]
    if len(entries) >= 7 and digest(entries[:7]) == EVENT_HISTORY and not _event_manifest_valid(m):
        raise ValueError("固定A之后只允许本次已批准事件候选，不能回退旧B许可。")
    if _event_manifest_valid(m):
        return _next_event_call(entries, m, head, sources)
    if not current:
        if stage != "A" or head == entries[-1]["head"] or sources == entries[-1]["source_sha256"]:
            raise ValueError("新闭环必须先唯一A，不能从旧来源开始。")
        old = entries[-1]
        if (m.get("previous_conditions_sha256") != old["conditions_sha256"]
                or m.get("previous_public_certificate_sha256") != old.get("public_certificate_sha256")
                or digest({"ports": m["ports"], "environment": m["environment"],
                    "public_certificate_sha256": m["previous_public_certificate_sha256"], "seed": SEED})
                    != old["conditions_sha256"]):
            raise ValueError("A仅可保留旧环境/端口/seed并按批准准备证书。")
    else:
        a, previous = current[0], current[-1]
        if (stage == "A" or m["conditions_sha256"] != a["conditions_sha256"]
                or any(m.get(k) != a.get(k) for k in ("certificate_directory", "public_certificate_sha256",
                    "public_certificate_validity", "previous_conditions_sha256", "previous_public_certificate_sha256"))
                or m.get("predecessor_raw_sha256") != previous.get("raw_sha256")
                or not isinstance(m.get("predecessor_review_url"), str) or not COMMENT.fullmatch(m["predecessor_review_url"])
                or m.get("predecessor_readback_exact") is not True):
            raise ValueError("B/C须绑定前置原件/独立审计及A同一套条件。")
        goal = _closure_predecessor(previous)
        if stage == "B":
            if (len(current) != 1 or goal or head == previous["head"] or sources == previous["source_sha256"]
                    or not isinstance(m.get("patch_evidence_url"), str) or not COMMENT.fullmatch(m["patch_evidence_url"])):
                raise ValueError("B仅限A不足且有一项新已审证据patch。")
        elif (not goal or previous["head"] != head or previous["source_sha256"] != sources
                or previous["maximum_attempts"] != 1000):
            raise ValueError("C需要同head/指纹完整有效且达到18/16的1000原件。")
    return m["maximum_attempts"]


def _next_event_call(entries, m, head, sources):
    """原七项绝不改写；B前证书例外只属于具体新批准，C严格绑定B。"""
    if len(entries) not in (7, 8) or digest(entries[:7]) != EVENT_HISTORY:
        raise ValueError("事件候选必须延续固定七项，不重跑A。")
    previous, a = entries[-1], entries[6]
    if (m.get("predecessor_raw_sha256") != previous.get("raw_sha256")
            or m.get("predecessor_readback_exact") is not True
            or not isinstance(m.get("predecessor_review_url"), str) or not COMMENT.fullmatch(m["predecessor_review_url"])):
        raise ValueError("事件候选缺精确前件原件/独立审计。")
    goal = _closure_predecessor(previous)
    if m["closure_stage"] == "B":
        if (len(entries) != 7 or goal or head == previous["head"] or sources == previous["source_sha256"]
                or m.get("patch_evidence_url") != EVENT_DESIGN
                or m.get("previous_conditions_sha256") != a["conditions_sha256"]
                or m.get("previous_public_certificate_sha256") != a["public_certificate_sha256"]
                or digest({"ports": m["ports"], "environment": m["environment"],
                    "public_certificate_sha256": m["previous_public_certificate_sha256"], "seed": SEED}) != a["conditions_sha256"]):
            raise ValueError("B只允许本批准候选及原条件或明确证书例外。")
        same = all(m.get(k) == a.get(k) for k in
            ("conditions_sha256", "certificate_directory", "public_certificate_sha256", "public_certificate_validity"))
        if not same and (m["certificate_directory"] != str((ROOT/".tmp/issue120-network-closure-certs").resolve())
                or m.get("certificate_change_authorization_url") != EVENT_AUTHORIZATION
                or m.get("certificate_change_reason") != "insufficient_validity_before_B"):
            raise ValueError("B换证缺少具体一次例外，不能改变其他条件。")
    elif (len(entries) != 8 or not goal or not _event_manifest_valid(previous)
            or previous.get("closure_stage") != "B" or previous["head"] != head or previous["source_sha256"] != sources
            or previous["maximum_attempts"] != 1000 or any(m.get(k) != previous.get(k) for k in
                ("conditions_sha256", "certificate_directory", "public_certificate_sha256", "public_certificate_validity",
                 "previous_conditions_sha256", "previous_public_certificate_sha256", "certificate_change_authorization_url",
                 "certificate_change_reason", *EVENT_FIELDS))):
        raise ValueError("事件C须绑定同源/同条件、完整有效且18/16通过的唯一B。")
    return m["maximum_attempts"]


def _require_closure_certificates(m, configs=None):
    """每次离线核证；只有具体批准的A前或事件B前一次准备例外。"""
    directory = Path(m["certificate_directory"])
    if (certificate_validity(directory) != m.get("public_certificate_validity")
            or any(hashlib.sha256((directory/name).read_bytes()).hexdigest() != sha
                   for name, sha in m["public_certificate_sha256"].items())
            or configs is not None and configs != role_configs(directory, V2_PORTS, "N2")):
        raise ValueError("闭环证书/有效期/三角色配置不符合冻结。")
    original = ROOT/".tmp/issue120-compact-v2-certs"
    if directory.resolve() != original.resolve():
        # 新目录只允许设计明确的一次准备，不可把仍有效旧证换掉做条件搜索。
        now = datetime.now(UTC).timestamp()
        insufficient = any(ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(original/name))["notAfter"])-now < 3600
                           for name in m["public_certificate_sha256"])
        expected = "insufficient_validity_before_B" if _event_manifest_valid(m) else "insufficient_validity_before_A"
        if (not insufficient or m.get("certificate_change_reason") != expected
                or _event_manifest_valid(m) and m.get("certificate_change_authorization_url") != EVENT_AUTHORIZATION
                or any(hashlib.sha256((original/name).read_bytes()).hexdigest() != sha
                       for name, sha in m["previous_public_certificate_sha256"].items())):
            raise ValueError("仅允许原证书余期不足且与本阶段具体批准相符的换证。")


def _require_closure(m, configs=None):
    """共享/实际循环与wrapper共用同一历史/条件/前件事实，不靠CLI单独拦截。"""
    head, fingerprints = source()
    ledger = Path(m["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    lock = ledger.with_suffix(ledger.suffix+".lock")
    if (head != m["head"] or fingerprints != m["source_sha256"] or len(entries) != m["call"]
            or not lock.is_file() or lock.read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("闭环共享入口来源/锁/占项不符。")
    _next_closure_call(entries[:-1], m["profile"], m["phase"], head, fingerprints, m)
    entry = entries[-1]
    if (entry.get("finished") is not False or any(entry.get(k) != value for k, value in m.items()
            if k not in ("command", "started_utc", "topology", "models", "scope"))):
        raise ValueError("闭环manifest与本次在途占项不一致。")
    _require_closure_certificates(m, configs)


def certificate_validity(directory, *, now=None):
    """离线核验原生成器的四份公开证书；不读私钥、不连接TLS、不修改信任。"""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC) if now is None else now
    certificates = {name: x509.load_pem_x509_certificate((Path(directory)/name).read_bytes())
                    for name in ("ca.pem", "client.pem", "p1.pem", "p2.pem")}
    ca = certificates["ca.pem"]
    validity = {}
    for name, cert in certificates.items():
        key = cert.public_key()
        is_ca = name == "ca.pem"
        expected = "LAN local test CA" if is_ca else name[:-4]+".secure-control.test"
        if (not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537
                or cert.signature_hash_algorithm.name != "sha256"
                or cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, expected)])
                or cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                    != x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None)
                or (cert.not_valid_after_utc-cert.not_valid_before_utc).total_seconds() != 25*3600
                or now < cert.not_valid_before_utc or (cert.not_valid_after_utc-now).total_seconds() < 3600):
            raise ValueError("测试证书身份/规格/有效期不符合本次条件，启动前须至少余一小时。")
        cert.verify_directly_issued_by(ca)
        if not is_ca and (
                cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    != x509.SubjectAlternativeName([x509.DNSName(expected)])
                or set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
                    != {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH}):
            raise ValueError("角色证书SAN/用途不符合原TLS身份。")
        validity[name] = {"not_before": cert.not_valid_before_utc.isoformat(),
                          "not_after": cert.not_valid_after_utc.isoformat()}
    return validity


def _v2_certificate_change_valid(manifest):
    """证书例外只改变公开证书输入；旧摘要随后必须与原历史相等。"""
    if not any(k in manifest for k in V2_CERTIFICATE_FIELDS):
        return True
    previous = manifest.get("previous_public_certificate_sha256")
    current = manifest.get("public_certificate_sha256")
    validity = manifest.get("public_certificate_validity")
    if (manifest.get("certificate_change_authorization_url") != V2_CERTIFICATE_AUTHORIZATION
            or manifest.get("certificate_change_reason") != "expired_test_certificates"
            or not isinstance(previous, dict) or not isinstance(current, dict)
            or set(previous) != {"ca.pem", "client.pem", "p1.pem", "p2.pem"}
            or set(current) != set(previous) or not isinstance(validity, dict) or set(validity) != set(previous)
            or any(not isinstance(v, str) or re.fullmatch(r"[0-9a-f]{64}", v) is None
                   or v == current[k] for k, v in previous.items())
            or manifest.get("previous_conditions_sha256") != digest({"ports": manifest.get("ports"),
                "environment": manifest.get("environment"), "public_certificate_sha256": previous, "seed": SEED})):
        return False
    try:
        for row in validity.values():
            if set(row) != {"not_before", "not_after"}:
                return False
            start, end = (datetime.fromisoformat(row[k]) for k in ("not_before", "not_after"))
            if start.utcoffset() != UTC.utcoffset(start) or end.utcoffset() != UTC.utcoffset(end) or end <= start:
                return False
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def _require_v2_conditions(manifest, history):
    """共同入口把候选条件锚定到原五项；精确证书例外不能夹带其他变化。"""
    previous = (manifest.get("previous_conditions_sha256") if any(k in manifest for k in V2_CERTIFICATE_FIELDS)
                else manifest.get("conditions_sha256"))
    if (not _v2_certificate_change_valid(manifest) or len(history) != 5
            or digest(history) != V2_CLOSED_HISTORY
            or any(e.get("conditions_sha256") != previous for e in history)):
        raise ValueError("v2候选与原五项冻结条件不符，或缺少精确证书变更依据。")


def digest(value):
    """只对公开结构作规范摘要，不接触TLS私钥或秘密计算载荷。"""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def source():
    """来源锁同时覆盖实际新实验和原后端，不能复用旧裸TCP运行的SHA。"""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    return head, benchmark._source_fingerprints(EXTRA_SOURCE)


def validate_cli(args):
    """网络参数独占入口，不允许旧profile/任意步数或安全参数搭配绕过门禁。"""
    if (args.case != "cycle" or args.mode != "batch" or args.steps is not None
            or args.delay_ms != 0 or args.segment_steps not in (None, 400) or args.material_slots != 16
            or args.preload_steps != 0 or args.preload_execution != "fused" or args.recording not in (None, "light")
            or args.tcp_nodelay != "default" or args.commit_policy != "default" or args.role_config is not None
            or args.gc_trial_policy is not None or args.material_candidate is not None
            or any(getattr(args, name) for name in ("diagnostic", "timeout_trace", "worker_timeout_diagnostic",
                "worker_long_run", "worker_wait_diagnostic", "server_gc_candidate", "stage_wait_diagnostic",
                "compact_history_candidate", "qpc_stage_receive_candidate", "qpc_dynamic_qualification", "fixed_proof_cache"))
            or args.network_profile not in PROFILES or args.network_phase not in ("discovery", "recheck", "qualification", "candidate")
            or any(getattr(args, name) is None for name in ("network_certs", "network_ports", "network_ledger", "network_approval"))
            or args.network_repair_note is not None and args.network_phase != "recheck"):
        raise ValueError("网络实验参数必须独占、固定场景/阶段/正常GC/原动态资源；不能设置任意steps。")
    wire = getattr(args, "network_wire_profile", None)
    authorization = getattr(args, "network_authorization", None)
    if authorization == MATRIX_AUTHORIZATION:
        if ((args.network_profile, args.network_phase) != ("N0", "candidate")
                or wire not in (_COMPACT_PROFILE_V3, MATRIX_WIRE)
                or args.network_repair_note is not None or args.network_ports != "55121,55122,55123"):
            raise ValueError("#128只允许已审A/B、N0和固定端口")
        return V2_PORTS
    local = authorization == LOCAL_DESIGN
    w_batch = authorization == W_DESIGN
    v1 = authorization == V1_DESIGN or w_batch
    sc = authorization == SC_DESIGN
    staged = authorization == STAGED_AUTHORIZATION or local or v1 or sc
    if v1 and (args.network_profile != "N2" or wire != _COMPACT_PROFILE_V3):
        raise ValueError("V1仅允许N2/compact-v3。")
    if sc and (args.network_profile != "N0" or wire != _COMPACT_PROFILE_V3):
        raise ValueError("SC仅N0/v3。")
    if local and args.network_profile != "N0":
        raise ValueError("局部比较仅允许 N0 直连。")
    if staged and (wire not in (_COMPACT_PROFILE_V2, _COMPACT_PROFILE_V3)
            or args.network_profile not in ("N0", "N2") or args.network_phase != "candidate"):
        raise ValueError("本批比较仅开放 N0/N2 的有限 candidate。")
    if not staged and (wire is None and (authorization is not None or args.network_phase == "candidate")
            or wire is not None and (wire not in _COMPACT_PROFILES or args.network_profile != "N2"
                or wire == _COMPACT_PROFILE_V3
                or args.network_phase not in ({"candidate"} if wire == _COMPACT_PROFILE_V2
                    and authorization not in (CLOSURE_AUTHORIZATION,REPAIR_AUTHORIZATION) else {"candidate", "qualification"})
                or not isinstance(authorization, str) or not COMMENT.fullmatch(authorization)
                or wire == _COMPACT_PROFILE_V2 and authorization not in (V2_AUTHORIZATION, CLOSURE_AUTHORIZATION,REPAIR_AUTHORIZATION))):
        raise ValueError("紧凑候选须匹配批准和N2阶段；v2仅本次candidate。")
    try:
        ports = tuple(int(p) for p in args.network_ports.split(","))
    except (ValueError, AttributeError) as error:
        raise ValueError("网络端口应为三个逗号分隔的整数。") from error
    if len(ports) != 3 or len(set(ports)) != 3 or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("网络端口必须固定且互异。")
    if (wire == _COMPACT_PROFILE_V2 or staged) and ports != V2_PORTS:
        raise ValueError("v2必须保留原三个端口。")
    return ports


def role_configs(certs, ports, profile):
    """复用现有bind/host分离，三角色使用同一拓扑且端到端TLS。"""
    if (profile not in PROFILES or type(ports) is not tuple or len(ports) != 3
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports) or len(set(ports)) != 3):
        raise ValueError("网络场景和三个固定端口不合法。")
    certs = Path(certs).resolve()
    base = benchmark._config("Client", ports)
    bind = "127.0.0.1" if profile == "N0" else "127.0.0.2"
    endpoints = tuple(LanEndpoint(bind, "127.0.0.1", port) for port in ports)
    public = {"version": 1, "identities": base.topology.identities,
              **{k: asdict(v) for k, v in zip(("p1_client", "p2_client", "p1_peer"), endpoints, strict=True)}}
    topology = LanTopology(base.topology.identities, *endpoints, digest(public))
    return tuple(replace(benchmark._config(role, ports), topology=topology, transport="mutual_tls",
        ca=certs/"ca.pem", certificate=certs/f"{role.lower()}.pem", private_key=certs/f"{role.lower()}.key")
        for role in ("Client", "P1", "P2"))


def next_call(entries, profile, phase, head, sources, repair_note=None):
    """纯状态转移：四定位、一次针对性复核、一次N2资格；启动失败同样占项。"""
    if profile not in PROFILES or phase not in ("discovery", "recheck", "qualification"):
        raise ValueError("非法网络阶段。")
    if type(entries) is not list or any(not isinstance(e, dict) or e.get("profile") not in PROFILES
            or e.get("phase") not in ("discovery", "recheck", "qualification")
            or type(e.get("maximum_attempts")) is not int
            or e["maximum_attempts"] != (10000 if e["phase"] == "qualification" else 1000)
            for e in entries):
        raise ValueError("额度历史结构或步数不匹配。")
    if (len(entries) >= 6 or any(not e.get("finished") for e in entries)
            or any(e["phase"] == "qualification" for e in entries)
            or any(e["phase"] == "recheck" and not e.get("sample_pass") for e in entries)):
        raise ValueError("网络闭环已结束、在途或额度耗尽。")
    if entries and phase != "recheck" and (entries[-1]["head"] != head or entries[-1]["source_sha256"] != sources):
        raise ValueError("当前SHA/源改变后只允许已审修复的唯一复核。")
    discovery = [e for e in entries if e["phase"] == "discovery"]
    rechecks = [e for e in entries if e["phase"] == "recheck"]
    unexpected = next((e for e in discovery if e["profile"] != "N3" and not e.get("sample_pass")
        and not any(r.get("sample_pass") and r["profile"] == e["profile"] and r["head"] == head
                    and r["source_sha256"] == sources for r in rechecks)), None)
    if phase == "discovery":
        if len(discovery) >= 4 or profile != PROFILES[len(discovery)]:
            raise ValueError("定位场景必须按N0/N1/N2/N3各执行一次。")
        if unexpected is not None and not any(r.get("sample_pass") and r["profile"] == unexpected["profile"]
                and r["head"] == head and r["source_sha256"] == sources for r in rechecks):
            raise ValueError("意外失败后暂停其他定位，不能旁路追加。")
        if profile == "N3" and not any(e["profile"] == "N2" and e.get("sample_pass") and e["head"] == head
                and e["source_sha256"] == sources for e in entries):
            raise ValueError("N3需要当前候选N2完整成功。")
        steps = 1000
    elif phase == "recheck":
        failed = unexpected or (discovery[-1] if discovery and discovery[-1]["profile"] == "N3"
                                and not discovery[-1].get("sample_pass") else None)
        required = "N2" if failed is not None and failed["profile"] == "N3" else failed["profile"] if failed else None
        if (rechecks or failed is None or profile != required or head == failed["head"] or sources == failed["source_sha256"]
                or not isinstance(repair_note, str) or not COMMENT.fullmatch(repair_note)):
            raise ValueError("只允许已公布证据并提交修复后的唯一同条件复核。")
        steps = 1000
    else:
        if [e["profile"] for e in discovery] != list(PROFILES) or profile != "N2" or not any(e["profile"] == "N2" and e.get("sample_pass")
                and e["head"] == head and e["source_sha256"] == sources and e["maximum_attempts"] == 1000 for e in entries):
            raise ValueError("最终资格需要当前SHA/源指纹下N2完整1000成功证据。")
        steps = 10000
    if sum(e["maximum_attempts"] for e in entries)+steps > 15000:
        raise ValueError("网络尝试总预算超过15000。")
    return steps


def _next_compact_call(entries, profile, phase, head, sources, continuation):
    """在同一已停止账本追加一次人工续接；旧循环与失败记录不可重置。"""
    if isinstance(continuation, dict) and continuation.get("authorization_url") == SC_DESIGN:
        return _next_sc_call(entries, profile, phase, head, sources, continuation)
    if isinstance(continuation, dict) and continuation.get("authorization_url") == W_DESIGN:
        return _next_w_call(entries,profile,phase,head,sources,continuation)
    if isinstance(continuation, dict) and continuation.get("authorization_url") == V1_DESIGN:
        return _next_v1_call(entries, profile, phase, head, sources, continuation)
    if isinstance(continuation, dict) and continuation.get("authorization_url") == LOCAL_DESIGN:
        return _next_local_call(entries, profile, phase, head, sources, continuation)
    if isinstance(continuation, dict) and continuation.get("authorization_url") == STAGED_AUTHORIZATION:
        return _next_staged_call(entries, profile, phase, head, sources, continuation)
    if isinstance(continuation, dict) and continuation.get("authorization_url") == REPAIR_AUTHORIZATION:
        return _next_repair_call(entries,profile,phase,head,sources,continuation)
    if isinstance(continuation, dict) and continuation.get("authorization_url") == CLOSURE_AUTHORIZATION:
        return _next_closure_call(entries, profile, phase, head, sources, continuation)
    if isinstance(continuation, dict) and continuation.get("wire_profile") == _COMPACT_PROFILE_V2:
        if (type(entries) is not list or len(entries) != 5
                or continuation.get("authorization_url") != V2_AUTHORIZATION
                or continuation.get("closed_history_sha256") != V2_CLOSED_HISTORY
                or digest(entries) != V2_CLOSED_HISTORY or profile != "N2" or phase != "candidate"
                or any(not isinstance(e, dict) or e.get("finished") is not True
                       or type(e.get("maximum_attempts")) is not int or e["maximum_attempts"] != 1000 for e in entries)
                or entries[-1].get("wire_profile") != _COMPACT_PROFILE
                or entries[-1].get("phase") != "candidate" or entries[-1].get("profile") != "N2"
                or entries[-1].get("sample_pass") is not False
                or head == entries[-1].get("head") or sources == entries[-1].get("source_sha256")):
            raise ValueError("v2仅允许保留原五项历史后的唯一第六项N2/candidate/1000。")
        return 1000
    if (type(entries) is not list or not isinstance(continuation, dict)
            or continuation.get("wire_profile") != _COMPACT_PROFILE
            or not COMMENT.fullmatch(continuation.get("authorization_url", ""))
            or profile != "N2" or phase not in {"candidate", "qualification"}):
        raise ValueError("紧凑候选续接身份或阶段无效。")
    prefix = [e for e in entries if "authorization_url" not in e]
    current = entries[len(prefix):]
    if (not prefix or entries != prefix + current
            or any("authorization_url" not in e for e in current)
            or digest(prefix) != continuation.get("closed_history_sha256")
            or any(e.get("finished") is not True for e in prefix)
            or not any(e.get("phase") == "recheck" and e.get("sample_pass") is False for e in prefix)
            or any(e.get("authorization_url") != continuation["authorization_url"]
                   or e.get("wire_profile") != _COMPACT_PROFILE for e in current)
            or len(entries) >= 6 or len(current) >= 2 or any(e.get("finished") is not True for e in current)):
        raise ValueError("续接必须保留原已停止历史；在途或耗尽不能重跑。")
    if not current:
        if phase != "candidate" or head == prefix[-1].get("head") or sources == prefix[-1].get("source_sha256"):
            raise ValueError("新候选必须先以新已审来源执行唯一1000步。")
        if sum(e.get("maximum_attempts", 15000) for e in entries) + 1000 > 15000:
            raise ValueError("候选续接不得突破原总账上限。")
        return 1000
    previous = current[0]
    if (phase != "qualification" or previous.get("phase") != "candidate"
            or previous.get("maximum_attempts") != 1000 or previous.get("sample_pass") is not True
            or previous.get("head") != head or previous.get("source_sha256") != sources):
        raise ValueError("只有同一来源的候选完整成功后才能执行唯一10000步。")
    if sum(e.get("maximum_attempts", 15000) for e in entries) + 10000 > 15000:
        raise ValueError("候选续接不得突破原总账上限。")
    return 10000


def _v2_candidate_manifest_valid(manifest):
    """本次有限样本的公开来源/许可绑定；不是长期资格或新认证系统。"""
    if not isinstance(manifest, dict):
        return False
    if manifest.get("authorization_url") == REPAIR_AUTHORIZATION:
        return _repair_manifest_valid(manifest)
    if manifest.get("authorization_url") == CLOSURE_AUTHORIZATION:
        return _closure_manifest_valid(manifest)
    m = manifest
    certificates = m.get("public_certificate_sha256")
    sources = m.get("source_sha256")
    environment = m.get("environment")
    return (m.get("wire_profile") == _COMPACT_PROFILE_V2
        and m.get("authorization_url") == V2_AUTHORIZATION and m.get("closed_history_sha256") == V2_CLOSED_HISTORY
        and m.get("profile") == "N2" and m.get("phase") == "candidate"
        and m.get("eligible_for_candidate") is True and m.get("qualification_allowed") is False
        and all(type(m.get(k)) is int and m[k] == v for k, v in {
            "call": 6, "maximum_calls": 6, "maximum_attempts": 1000, "total_maximum_attempts": 6000,
            "continuation_maximum_calls": 1, "continuation_maximum_attempts": 1000}.items())
        and m.get("ports") == list(V2_PORTS)
        and isinstance(m.get("head"), str) and re.fullmatch(r"[0-9a-f]{40}", m["head"]) is not None
        and isinstance(sources, dict) and bool(sources)
        and all(isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for k, v in sources.items())
        and isinstance(environment, dict) and set(environment) == {"platform", "python", "openssl"}
        and isinstance(certificates, dict) and set(certificates) == {"ca.pem", "client.pem", "p1.pem", "p2.pem"}
        and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in certificates.values())
        and isinstance(m.get("review_url"), str) and COMMENT.fullmatch(m["review_url"]) is not None
        and m.get("gc") == {"enabled": True, "threshold": [700, 10, 10], "freeze_count": 0, "debug": 0}
        and m.get("budget_path") == str((ROOT / ".tmp/issue120-network-budget.json").resolve())
        and m.get("conditions_sha256") == digest({"ports": list(V2_PORTS), "environment": environment,
            "public_certificate_sha256": certificates, "seed": SEED}) and m.get("seed") == SEED
        and _v2_certificate_change_valid(m))


def require_v2_candidate(manifest, configs=None):
    """共享/实际循环都核对当前来源及获准的在途占项，不能私有入口旁路。"""
    if not _v2_candidate_manifest_valid(manifest):
        raise ValueError("v2缺少本次已审N2阶段/步数的完整绑定。")
    if manifest.get("authorization_url") == REPAIR_AUTHORIZATION:
        _require_repair(manifest,configs)
        return
    if manifest.get("authorization_url") == CLOSURE_AUTHORIZATION:
        _require_closure(manifest, configs)
        return
    head, fingerprints = source()
    ledger = Path(manifest["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    if (head != manifest["head"] or fingerprints != manifest["source_sha256"] or len(entries) != 6
            or ledger.with_suffix(ledger.suffix + ".lock").read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("v2来源或原账本占项不匹配。")
    _next_compact_call(entries[:5], "N2", "candidate", head, fingerprints, manifest)
    _require_v2_conditions(manifest, entries[:5])
    entry = entries[-1]
    if (entry.get("finished") is not False or any(entry.get(k) != manifest[k] for k in (
            "call", "profile", "phase", "head", "source_sha256", "wire_profile", "authorization_url",
            "closed_history_sha256", "maximum_attempts", "conditions_sha256"))
            or any(entry.get(k) != manifest.get(k) for k in V2_CERTIFICATE_FIELDS)
            or "certificate_change_authorization_url" in manifest
                and entry.get("public_certificate_sha256") != manifest["public_certificate_sha256"]):
        raise ValueError("v2第六项不是本次未完成的唯一占项。")
    if configs is not None:
        if (type(configs) is not tuple or len(configs) != 3
                or tuple(c.role for c in configs) != ("Client", "P1", "P2")
                or any(c.transport != "mutual_tls" or c.topology != configs[0].topology for c in configs)):
            raise ValueError("v2必须使用原三角色TLS配置。")
        topology = configs[0].topology
        endpoints = (topology.p1_client, topology.p2_client, topology.p1_peer)
        if (tuple(e.port for e in endpoints) != V2_PORTS
                or any(e.bind != "127.0.0.2" or e.host != "127.0.0.1" for e in endpoints)
                or any(hashlib.sha256(c.ca.read_bytes()).hexdigest() != manifest["public_certificate_sha256"]["ca.pem"]
                       or hashlib.sha256(c.certificate.read_bytes()).hexdigest()
                       != manifest["public_certificate_sha256"][c.role.lower()+".pem"] for c in configs)):
            raise ValueError("v2拓扑/公开证书不符合原N2条件。")
        if "certificate_change_authorization_url" in manifest:
            directories = {c.certificate.parent.resolve() for c in configs}
            expected = (ROOT/".tmp/issue120-compact-v2-certs").resolve()
            if (directories != {expected} or any(c.ca.resolve() != expected/"ca.pem" for c in configs)
                    or certificate_validity(next(iter(directories))) != manifest["public_certificate_validity"]):
                raise ValueError("新公开证书的离线核验与冻结有效期不符。")


class RunBudget:
    """磁盘独占锁和启动前持久占项；崩溃在途记录不被自动重跑覆盖。"""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = self.path.with_suffix(self.path.suffix+".lock")
        self.entries = []
        self.owned = False

    def __enter__(self):
        descriptor = os.open(self.lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.owned = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(str(os.getpid()))
        try:
            if self.path.exists():
                value = json.loads(self.path.read_text(encoding="utf-8"))
                if value.get("schema") != "network-call-budget-v1" or type(value.get("entries")) is not list:
                    raise ValueError("额度记录schema不匹配。")
                self.entries = value["entries"]
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _save(self):
        temporary = self.path.with_suffix(self.path.suffix+".writing")
        with temporary.open("x", encoding="utf-8") as stream:
            repair = any(e.get("authorization_url") == REPAIR_AUTHORIZATION for e in self.entries)
            closure = any(e.get("authorization_url") == CLOSURE_AUTHORIZATION for e in self.entries)
            staged = any(e.get("authorization_url") == STAGED_AUTHORIZATION for e in self.entries)
            local = any(e.get("authorization_url") == LOCAL_DESIGN for e in self.entries)
            v1 = any(e.get("authorization_url") == V1_DESIGN for e in self.entries)
            w_batch = any(e.get("authorization_url") == W_DESIGN for e in self.entries)
            sc = any(e.get("authorization_url") == SC_DESIGN for e in self.entries)
            matrix = bool(self.entries) and all(e.get("authorization_url") == MATRIX_AUTHORIZATION for e in self.entries)
            json.dump({"schema": "network-call-budget-v1", "maximum_calls": 3 if matrix else 17 if sc else 16 if w_batch else 14 if v1 else 13 if local else 12 if staged else 10 if repair else 9 if closure else 6,
                       "maximum_attempts": 2000 if matrix else 17000 if sc else 16000 if w_batch else 14000 if v1 else 13000 if local else 12000 if staged else 19000 if repair else 18000 if closure else 15000,
                       "entries": self.entries}, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    def reserve(self, profile, phase, head, sources, output, repair_note=None, conditions_sha256=None,
                *, continuation=None):
        steps = (_next_compact_call(self.entries, profile, phase, head, sources, continuation)
                 if continuation is not None else next_call(self.entries, profile, phase, head, sources, repair_note))
        self.entries.append({"call": len(self.entries)+1, "profile": profile, "phase": phase,
            "head": head, "source_sha256": sources, "maximum_attempts": steps,
            "output": str(Path(output).resolve()), "started_utc": datetime.now(UTC).isoformat(),
            "finished": False, "sample_pass": False, "repair_note": repair_note,
            "conditions_sha256": conditions_sha256})
        if continuation is not None:
            fields = continuation
            if continuation.get("authorization_url") in (CLOSURE_AUTHORIZATION,REPAIR_AUTHORIZATION,STAGED_AUTHORIZATION,LOCAL_DESIGN,V1_DESIGN,W_DESIGN,SC_DESIGN):
                owned = {"output", "started_utc", "finished", "sample_pass", "actual_attempts", "raw_sha256",
                         "failure_category", "ended_utc", "repair_note"}
                fields = {k: v for k, v in continuation.items() if k not in owned}
            self.entries[-1].update(fields)
        self._save()
        return steps

    def finish(self, result, sha):
        self.entries[-1].update(finished=True, actual_attempts=len(result.get("cycles", [])),
            sample_pass=result.get("network_sample_pass") is True, raw_sha256=sha,
            failure_category=result.get("failure_category"), ended_utc=datetime.now(UTC).isoformat())
        self._save()

    def __exit__(self, *_args):
        if self.owned:
            self.lock.unlink()
            self.owned = False


def _tls_pass(result):
    observations = [result.get("network_tls", {})]
    observations.extend(p.get("network_tls", {}) for p in result.get("party_outcomes", []))
    wanted = {(role, f"{peer.lower()}.secure-control.test") for role in ("Client", "P1", "P2")
              for peer in ("Client", "P1", "P2") if role != peer}
    links = [link for row in observations for link in row.get("links", [])]
    return (len(observations) == 3 and all(row.get("restored") is True for row in observations)
        and len(links) == 6 and {(link.get("role"), link.get("peer_identity")) for link in links} == wanted
        and all(link.get("version") == "TLSv1.3" and link.get("tcp_nodelay") == 1
                and link.get("peer_san") in ([["DNS", link["peer_identity"]]], [("DNS", link["peer_identity"])])
                for link in links))


def assemble(result, *, profile, phase, manifest, relay):
    """有限样本与最终资格严格分开，保留原失败、周期及旧资格false语义。"""
    if str(result.get("schema", "")).startswith("matrix-"):
        raise ValueError("矩阵证据需要#128显式reader，不能解释为旧网络结果")
    result.update(schema="network-cycle-v1", network_profile=profile, network_phase=phase,
                  network_manifest=manifest, network_manifest_sha256=digest(manifest), network_relay=relay)
    target = 10000 if phase == "qualification" else 1000
    try:
        complete = benchmark._compact_sample_pass(result, result.get("material_comparison") or {},
            result.get("network_history") or {}, target_steps=target)
    except (KeyError, TypeError, ValueError, IndexError):
        complete = False
    wire_profile = manifest.get("wire_profile")
    repair = manifest.get("authorization_url") == REPAIR_AUTHORIZATION
    closure = manifest.get("authorization_url") in (CLOSURE_AUTHORIZATION,REPAIR_AUTHORIZATION)
    compact = wire_profile in _COMPACT_PROFILES
    local = manifest.get("authorization_url") == LOCAL_DESIGN
    w_batch = manifest.get("authorization_url") == W_DESIGN
    v1 = manifest.get("authorization_url") == V1_DESIGN or w_batch
    sc = manifest.get("authorization_url") == SC_DESIGN
    staged = manifest.get("authorization_url") == STAGED_AUTHORIZATION or local or v1 or sc
    material = result.get("material_summary") or {}
    wire_valid = (wire_profile is None and result.get("wire_profile") is None) or compact and (result.get("wire_profile") == wire_profile
        and material.get("encoding_profile") == wire_profile
        and (material.get("worker") or {}).get("encoding_profile") == wire_profile
        and len(result.get("party_outcomes", [])) == 2
        and all(row.get("wire_profile") == wire_profile for row in result["party_outcomes"]))
    sample = (result.get("status") == "stopped" and result.get("requested_steps") == target
        and (((_sc_manifest_valid(manifest) if sc else _w_manifest_valid(manifest) if w_batch else _v1_manifest_valid(manifest) if v1 else _local_manifest_valid(manifest) if local else _staged_manifest_valid(manifest))
              and (profile, phase) == (manifest["profile"], manifest["phase"])
              and result.get("code_sha") == manifest["head"]
              and result.get("source_sha256") == manifest["source_sha256"]
              and result.get("network_source_integrity_failed") is not True) if staged else
             (wire_profile != _COMPACT_PROFILE_V3 and (wire_profile != _COMPACT_PROFILE_V2 or profile == "N2" and (phase == "candidate" or closure and phase == "qualification")
             and _v2_candidate_manifest_valid(manifest) and result.get("code_sha") == manifest["head"]
             and result.get("source_sha256") == manifest["source_sha256"]
             and result.get("network_source_integrity_failed") is not True)))
        and complete and wire_valid and (result.get("network_history") or {}).get("finite_sample_pass") is True and _tls_pass(result)
        and relay.get("model_valid") is True and relay.get("process_exited") is True
        and (not v1 or _v1_relay_pass(relay))
        and (not w_batch or relay.get("first_model_failure_stop") is True
             and (manifest["comparison_stage"] != "W1" or (result.get("system_trace") or {}).get("saved") is True))
        and not relay.get("forced_termination") and (not closure or _closure_cpu_pass(relay,
            native=_repair_manifest_valid(manifest) if repair else _event_manifest_valid(manifest)))
        and (not staged or _staged_frames_pass(result, wire_profile)
             and (profile == "N0" or _closure_cpu_pass(relay, native=True))))
    result.update(network_sample_pass=bool(sample),
        network_dynamic_qualification_pass=bool(sample and (wire_profile != _COMPACT_PROFILE_V2 or closure)
                                                and profile == "N2" and phase == "qualification"),
        local_dynamic_qualification_pass=False, qualification_pass=False, stage_pass=False,
        worker_long_run_gate_pass=False, candidate_gate_pass=False, server_gc_candidate_gate_pass=False,
        comparison_only=True, diagnostic=True)
    if wire_profile == _COMPACT_PROFILE_V2 or staged:
        result.update(eligible_for_candidate=False, qualification_allowed=False)
    if closure:
        result["network_progress_goal_pass"] = bool(sample and _closure_goal(result))
    if staged:
        result["network_progress_goal_pass"] = (bool(sample and _closure_goal(result))
            if manifest["comparison_stage"] in ("T3", "V1", "W1", "W2") else None)
    if not sample and result.get("status") == "stopped":
        result.update(status="failed", failure_category="NetworkEvidenceOrModel", failed_phase="NETWORK_REPORT")
    return result


def run_network_benchmark(*, profile, phase, certs, ports, ledger, approval, output, repair_note=None,
                          wire_profile=None, authorization=None):
    """唯一新网络性能入口；校验审查来源和额度后才启动角色/转发器。"""
    if authorization == MATRIX_AUTHORIZATION:
        if repair_note is not None:
            raise ValueError("#128性能阶段不接受源码修复/补跑")
        return _run_matrix_network(profile=profile, phase=phase, certs=certs, ports=ports,
                                   ledger=ledger, approval=approval, output=output, wire_profile=wire_profile)
    head, fingerprints = sc_source() if authorization == SC_DESIGN else source()
    approval = json.loads(Path(approval).read_text(encoding="utf-8"))
    environment = {"platform": platform.platform(), "python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION}
    if (approval.get("head") != head or approval.get("source_sha256") != fingerprints
            or approval.get("software_pass") is not True or approval.get("readback_exact") is not True
            or approval.get("ports") != list(ports) or approval.get("environment") != environment
            or not COMMENT.fullmatch(approval.get("review_url", ""))):
        raise ValueError("缺少当前head/源指纹对应的独立软件审查放行。")
    continuation = None
    repair = wire_profile == _COMPACT_PROFILE_V2 and authorization == REPAIR_AUTHORIZATION
    closure = wire_profile == _COMPACT_PROFILE_V2 and authorization in (CLOSURE_AUTHORIZATION,REPAIR_AUTHORIZATION)
    local = authorization == LOCAL_DESIGN
    w_batch = authorization == W_DESIGN
    v1 = authorization == V1_DESIGN or w_batch
    sc = authorization == SC_DESIGN
    staged = authorization == STAGED_AUTHORIZATION or local or v1 or sc
    if wire_profile is not None:
        if (wire_profile not in _COMPACT_PROFILES or approval.get("wire_profile") != wire_profile
                or not isinstance(authorization, str) or not COMMENT.fullmatch(authorization)
                or approval.get("authorization_url") != authorization
                or not isinstance(approval.get("closed_history_sha256"), str)):
            raise ValueError("缺少绑定本候选编码、人工批准和旧历史的独立审查放行。")
        continuation = {"wire_profile": wire_profile, "authorization_url": authorization,
                        "closed_history_sha256": approval["closed_history_sha256"]}
        if staged:
            if (not (_sc_manifest_valid(approval) if sc else _w_manifest_valid(approval) if w_batch else _v1_manifest_valid(approval) if v1 else _local_manifest_valid(approval) if local else _staged_manifest_valid(approval))
                    or (profile, phase) != (approval["profile"], approval["phase"])
                    or ports != V2_PORTS or str(Path(ledger).resolve()) != approval["budget_path"]
                    or str(Path(certs).resolve()) != approval["certificate_directory"]):
                raise ValueError("缺少本批比较阶段的精确许可。")
            continuation = dict(approval)
        elif wire_profile == _COMPACT_PROFILE_V3:
            raise ValueError("compact-v3 仅允许本批 T2/T3。")
        elif closure:
            if (not (_repair_manifest_valid(approval) if repair else _closure_manifest_valid(approval))
                    or profile != approval["profile"] or phase != approval["phase"]
                    or ports != V2_PORTS or str(Path(ledger).resolve()) != approval["budget_path"]
                    or str(Path(certs).resolve()) != approval["certificate_directory"]):
                raise ValueError("缺少本次A/B/C的精确许可。")
            continuation = dict(approval)
        elif wire_profile == _COMPACT_PROFILE_V2 and (
                profile != "N2" or phase != "candidate" or authorization != V2_AUTHORIZATION
                or approval["closed_history_sha256"] != V2_CLOSED_HISTORY
                or ports != V2_PORTS or Path(ledger).resolve() != (ROOT / ".tmp/issue120-network-budget.json").resolve()
                or approval.get("phase") != "candidate" or approval.get("eligible_for_candidate") is not True
                or approval.get("qualification_allowed") is not False
                or type(approval.get("continuation_maximum_calls")) is not int or approval["continuation_maximum_calls"] != 1
                or type(approval.get("continuation_maximum_attempts")) is not int or approval["continuation_maximum_attempts"] != 1000):
            raise ValueError("v2仅开放本次原账本上的一次1000候选，不允许长期资格。")
    elif authorization is not None or phase == "candidate":
        raise ValueError("候选续接必须显式指定编码 profile 与批准。")
    output = Path(output)
    if output.exists():
        raise ValueError("本轮输出已存在，不允许覆盖或重跑。")
    # 只开新文件，控制窗口中不写JSON；异常/启动失败仍使用已经持久占用的调用项。
    with RunBudget(ledger) as budget:
        conditions = digest({"ports": list(ports), "environment": environment,
            "public_certificate_sha256": approval.get("public_certificate_sha256"), "seed": SEED})
        if staged:
            if approval["conditions_sha256"] != conditions:
                raise ValueError("比较阶段条件摘要不符。")
            if sc:
                _next_sc_call(budget.entries, profile, phase, head, fingerprints, approval)
                _require_sc_certificates(approval)
            elif w_batch:
                _next_w_call(budget.entries,profile,phase,head,fingerprints,approval)
                _require_w_certificates(approval)
                if approval["system_trace"]:
                    _WaitTrace.validate_profile(approval)
            elif v1:
                _next_v1_call(budget.entries, profile, phase, head, fingerprints, approval)
                _require_v1_certificates(approval)
            elif local:
                _next_local_call(budget.entries, profile, phase, head, fingerprints, approval)
                _require_local_certificates(approval)
            else:
                _next_staged_call(budget.entries, profile, phase, head, fingerprints, approval)
                _require_staged_certificates(approval)
        elif closure:
            if approval["conditions_sha256"] != conditions:
                raise ValueError("闭环预声明条件摘要不符。")
            if repair:
                _next_repair_call(budget.entries,profile,phase,head,fingerprints,approval)
                _require_repair_certificates(approval)
            else:
                _next_closure_call(budget.entries, profile, phase, head, fingerprints, approval)
                _require_closure_certificates(approval)
        elif wire_profile == _COMPACT_PROFILE_V2:
            if approval.get("conditions_sha256") != conditions:
                raise ValueError("v2预声明新条件摘要不匹配。")
            condition_record = approval | {"ports": list(ports), "environment": environment,
                                           "seed": SEED, "conditions_sha256": conditions}
            _require_v2_conditions(condition_record, budget.entries)
            _next_compact_call(budget.entries, profile, phase, head, fingerprints, continuation)
            if "certificate_change_authorization_url" in approval:
                if (Path(certs).resolve() != (ROOT/".tmp/issue120-compact-v2-certs").resolve()
                        or certificate_validity(certs) != approval["public_certificate_validity"]):
                    raise ValueError("新公开证书有效期不符合预声明。")
                if any(hashlib.sha256((Path(certs)/name).read_bytes()).hexdigest() != value
                       for name, value in approval["public_certificate_sha256"].items()):
                    raise ValueError("新公开证书指纹不符合预声明。")
                continuation.update({k: approval[k] for k in (*V2_CERTIFICATE_FIELDS, "public_certificate_sha256")})
        elif budget.entries and budget.entries[0].get("conditions_sha256") != conditions:
            raise ValueError("同一闭环的端口/环境/证书/公开seed不能改变。")
        if phase == "qualification" and not closure:
            candidates = [e for e in budget.entries if e["profile"] == "N2" and e.get("sample_pass")
                          and e["head"] == head and e["source_sha256"] == fingerprints
                          and (continuation is None or e.get("authorization_url") == authorization)]
            if (approval.get("qualification_allowed") is not True or not candidates
                    or approval.get("n2_result_sha256") != candidates[-1].get("raw_sha256")):
                raise ValueError("最终资格尚未由当前N2结果和独立审查放行。")
            if hashlib.sha256(Path(candidates[-1]["output"]).read_bytes()).hexdigest() != candidates[-1]["raw_sha256"]:
                raise ValueError("当前候选的N2原件已变化。")
        steps = budget.reserve(profile, phase, head, fingerprints, output, repair_note, conditions,
                               continuation=continuation)
        result, relay, trace = {}, None, None
        manifest = {"profile": profile, "phase": phase, "head": head, "source_sha256": fingerprints,
            "command": list(sys.argv), "seed": SEED, "maximum_attempts": steps,
            "call": budget.entries[-1]["call"], "maximum_calls": 6, "total_maximum_attempts": 15000,
            "models": {name: asdict(model) for name, model in models(profile).items()}, "ports": list(ports),
            "environment": environment,
            "gc": {"enabled": gc.isenabled(), "threshold": list(gc.get_threshold()),
                   "freeze_count": gc.get_freeze_count(), "debug": gc.get_debug()},
            "review_url": approval["review_url"], "started_utc": budget.entries[-1]["started_utc"],
            "conditions_sha256": conditions,
            "scope": "single computer; opaque read-block propagation/rate model; not measured WiFi, packets or hardware"}
        if continuation is not None:
            v2 = wire_profile == _COMPACT_PROFILE_V2
            if closure or staged:
                manifest.update(continuation)
            else:
                manifest.update(continuation, continuation_maximum_calls=1 if v2 else 2,
                            continuation_maximum_attempts=1000 if v2 else 11000)
            if v2 and not closure and not staged:
                manifest.update(total_maximum_attempts=6000, eligible_for_candidate=True,
                                qualification_allowed=False, budget_path=str(Path(ledger).resolve()))
        with output.open("x", encoding="utf-8") as stream:
            try:
                configs = role_configs(certs, ports, profile)
                manifest["topology"] = asdict(configs[0].topology)
                manifest["public_certificate_sha256"] = {name: hashlib.sha256((Path(certs)/name).read_bytes()).hexdigest()
                    for name in ("ca.pem", "client.pem", "p1.pem", "p2.pem")}
                if manifest["public_certificate_sha256"] != approval.get("public_certificate_sha256"):
                    raise ValueError("公开证书指纹不符合预声明。")
                trace = _WaitTrace(manifest) if w_batch and manifest["system_trace"] else None
                relay = NetworkRelay(profile, tuple(("127.0.0.1", port, "127.0.0.2") for port in ports),
                    **({"wait_strategy": EVENT_STRATEGY} if _event_manifest_valid(manifest)
                        or _repair_manifest_valid(manifest) or staged else {}),
                    **({"wait_diagnostic":manifest["wait_diagnostic"],"fail_first_model":True} if w_batch else {})) if profile != "N0" else None
                with (trace if trace is not None else nullcontext()), (relay if relay is not None else nullcontext()):
                    result = benchmark.run_network_observation(configs=configs, steps=steps,
                        **({"wire_profile": wire_profile} if wire_profile is not None else {}),
                        **({"candidate_manifest": manifest} if wire_profile in (_COMPACT_PROFILE_V2, _COMPACT_PROFILE_V3) else {}))
                final_head, final_fingerprints = sc_source() if sc else source()
                if final_head != head or final_fingerprints != fingerprints:
                    result["network_source_integrity_failed"] = True
                    if result.get("status") == "stopped":
                        result.update(status="failed", failure_category="NetworkSourceChanged", failed_phase="SOURCE_CHECK")
            except Exception as error:  # noqa: BLE001 - 只公开错误类别，保留原可得结果/失败字段。
                if result:
                    result["network_orchestration_error_type"] = type(error).__name__
                    if result.get("status") == "stopped":
                        result.update(status="failed", failure_category=type(error).__name__, failed_phase="NETWORK_CLEANUP")
                else:
                    result = {"status": "failed", "failure_category": type(error).__name__,
                              "failed_phase": "NETWORK_STARTUP_OR_EXPORT", "cycles": [], "steps": [],
                              "cycle_timing": benchmark._timing([]), "requested_steps": steps}
            relay_report = relay.report if relay is not None else {"model_valid": True, "process_exited": True,
                "forced_termination": False, "scope": "N0 direct TLS, no relay process or injected delay"}
            if trace is not None:
                result["system_trace"] = trace.report
            result.update(code_sha=head, source_sha256=fingerprints)
            result = assemble(result, profile=profile, phase=phase, manifest=manifest, relay=relay_report or {})
            if staged and manifest["comparison_stage"] in ("T2", "U2", "SC-B"):
                result["network_progress_goal_pass"] = bool(result["network_sample_pass"]
                    and _staged_gain(_comparison_result(budget.entries[15], _sc_manifest_valid) if sc else
                        _comparison_result(budget.entries[11], _local_manifest_valid) if local else _staged_result(budget.entries[9]), result))
                if result["network_sample_pass"] and not result["network_progress_goal_pass"]:
                    result["comparison_stop_reason"] = "wall_clock_gain_insufficient"
            result.update(network_budget={"call": budget.entries[-1]["call"], "reserved_attempts": steps,
                              "calls_spent": len(budget.entries),
                              "attempts_reserved": sum(e["maximum_attempts"] for e in budget.entries),
                              "startup_failure_consumes_call": True})
            export_started = time.perf_counter_ns()
            json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        export_ns = time.perf_counter_ns()-export_started
        budget.finish(result, hashlib.sha256(output.read_bytes()).hexdigest())
    result["network_export_ns"] = export_ns  # 原始文件之外，CLI日志单列退出后编码/写盘。
    return result
