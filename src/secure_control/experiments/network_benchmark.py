"""固定网络场景的有界编排/额度与公开证据；控制循环和秘密材料仍归原后端。"""

from __future__ import annotations

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
from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

from secure_control.execution.lan_config import LanEndpoint, LanTopology
from secure_control.execution.localhost_codec import (
    _COMPACT_PROFILE,
    _COMPACT_PROFILE_V2,
    _COMPACT_PROFILES,
)

from . import communication_benchmark as benchmark
from ._network_emulator import SEED, NetworkRelay, models

ROOT = Path(__file__).resolve().parents[3]
PROFILES = ("N0", "N1", "N2", "N3")
EXTRA_SOURCE = ("src/secure_control/experiments/network_benchmark.py",
                "src/secure_control/experiments/_network_emulator.py", "src/secure_control/execution/lan_config.py",
                "configs/cart_pole_plant.yaml", "configs/cart_pole_balance.yaml",
                "configs/shared_prime_256_pocklington.yaml", "pyproject.toml", "uv.lock")
COMMENT = re.compile(r"https://github\.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-[0-9]+\Z")
V2_AUTHORIZATION = "https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6231537918"
V2_CLOSED_HISTORY = "ae524efc8bc7f8495ea511406a62410afdeb98a6761716ed2fe5610f5058aa2c"
V2_PORTS = (55121, 55122, 55123)


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
    if (wire is None and (authorization is not None or args.network_phase == "candidate")
            or wire is not None and (wire not in _COMPACT_PROFILES or args.network_profile != "N2"
                or args.network_phase not in ({"candidate"} if wire == _COMPACT_PROFILE_V2 else {"candidate", "qualification"})
                or not isinstance(authorization, str) or not COMMENT.fullmatch(authorization)
                or wire == _COMPACT_PROFILE_V2 and authorization != V2_AUTHORIZATION)):
        raise ValueError("紧凑候选须匹配批准和N2阶段；v2仅本次candidate。")
    try:
        ports = tuple(int(p) for p in args.network_ports.split(","))
    except (ValueError, AttributeError) as error:
        raise ValueError("网络端口应为三个逗号分隔的整数。") from error
    if len(ports) != 3 or len(set(ports)) != 3 or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("网络端口必须固定且互异。")
    if wire == _COMPACT_PROFILE_V2 and ports != V2_PORTS:
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
            "public_certificate_sha256": certificates, "seed": SEED}) and m.get("seed") == SEED)


def require_v2_candidate(manifest, configs=None):
    """共享/实际循环都核对当前来源和原账本的已占第六项，不能私有入口旁路。"""
    if not _v2_candidate_manifest_valid(manifest):
        raise ValueError("v2缺少本次已审N2/candidate/1000的完整绑定。")
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
    head, fingerprints = source()
    ledger = Path(manifest["budget_path"])
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    if (head != manifest["head"] or fingerprints != manifest["source_sha256"] or len(entries) != 6
            or ledger.with_suffix(ledger.suffix + ".lock").read_text(encoding="utf-8").strip() != str(os.getpid())):
        raise ValueError("v2来源或原账本占项不匹配。")
    _next_compact_call(entries[:5], "N2", "candidate", head, fingerprints, manifest)
    entry = entries[-1]
    if (entry.get("finished") is not False or any(entry.get(k) != manifest[k] for k in (
            "call", "profile", "phase", "head", "source_sha256", "wire_profile", "authorization_url",
            "closed_history_sha256", "maximum_attempts", "conditions_sha256"))):
        raise ValueError("v2第六项不是本次未完成的唯一占项。")


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
            json.dump({"schema": "network-call-budget-v1", "maximum_calls": 6, "maximum_attempts": 15000,
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
            self.entries[-1].update(continuation)
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
    result.update(schema="network-cycle-v1", network_profile=profile, network_phase=phase,
                  network_manifest=manifest, network_manifest_sha256=digest(manifest), network_relay=relay)
    target = 10000 if phase == "qualification" else 1000
    try:
        complete = benchmark._compact_sample_pass(result, result.get("material_comparison") or {},
            result.get("network_history") or {}, target_steps=target)
    except (KeyError, TypeError, ValueError, IndexError):
        complete = False
    wire_profile = manifest.get("wire_profile")
    compact = wire_profile in _COMPACT_PROFILES
    material = result.get("material_summary") or {}
    wire_valid = (wire_profile is None and result.get("wire_profile") is None) or compact and (result.get("wire_profile") == wire_profile
        and material.get("encoding_profile") == wire_profile
        and (material.get("worker") or {}).get("encoding_profile") == wire_profile
        and len(result.get("party_outcomes", [])) == 2
        and all(row.get("wire_profile") == wire_profile for row in result["party_outcomes"]))
    sample = (result.get("status") == "stopped" and result.get("requested_steps") == target
        and (wire_profile != _COMPACT_PROFILE_V2 or profile == "N2" and phase == "candidate"
             and _v2_candidate_manifest_valid(manifest) and result.get("code_sha") == manifest["head"]
             and result.get("source_sha256") == manifest["source_sha256"]
             and result.get("network_source_integrity_failed") is not True)
        and complete and wire_valid and (result.get("network_history") or {}).get("finite_sample_pass") is True and _tls_pass(result)
        and relay.get("model_valid") is True and relay.get("process_exited") is True
        and not relay.get("forced_termination"))
    result.update(network_sample_pass=bool(sample),
        network_dynamic_qualification_pass=bool(sample and wire_profile != _COMPACT_PROFILE_V2
                                                and profile == "N2" and phase == "qualification"),
        local_dynamic_qualification_pass=False, qualification_pass=False, stage_pass=False,
        worker_long_run_gate_pass=False, candidate_gate_pass=False, server_gc_candidate_gate_pass=False,
        comparison_only=True, diagnostic=True)
    if wire_profile == _COMPACT_PROFILE_V2:
        result.update(eligible_for_candidate=False, qualification_allowed=False)
    if not sample and result.get("status") == "stopped":
        result.update(status="failed", failure_category="NetworkEvidenceOrModel", failed_phase="NETWORK_REPORT")
    return result


def run_network_benchmark(*, profile, phase, certs, ports, ledger, approval, output, repair_note=None,
                          wire_profile=None, authorization=None):
    """唯一新网络性能入口；校验审查来源和额度后才启动角色/转发器。"""
    head, fingerprints = source()
    approval = json.loads(Path(approval).read_text(encoding="utf-8"))
    environment = {"platform": platform.platform(), "python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION}
    if (approval.get("head") != head or approval.get("source_sha256") != fingerprints
            or approval.get("software_pass") is not True or approval.get("readback_exact") is not True
            or approval.get("ports") != list(ports) or approval.get("environment") != environment
            or not COMMENT.fullmatch(approval.get("review_url", ""))):
        raise ValueError("缺少当前head/源指纹对应的独立软件审查放行。")
    continuation = None
    if wire_profile is not None:
        if (wire_profile not in _COMPACT_PROFILES or approval.get("wire_profile") != wire_profile
                or not isinstance(authorization, str) or not COMMENT.fullmatch(authorization)
                or approval.get("authorization_url") != authorization
                or not isinstance(approval.get("closed_history_sha256"), str)):
            raise ValueError("缺少绑定本候选编码、人工批准和旧历史的独立审查放行。")
        continuation = {"wire_profile": wire_profile, "authorization_url": authorization,
                        "closed_history_sha256": approval["closed_history_sha256"]}
        if wire_profile == _COMPACT_PROFILE_V2 and (
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
        if budget.entries and budget.entries[0].get("conditions_sha256") != conditions:
            raise ValueError("同一闭环的端口/环境/证书/公开seed不能改变。")
        if phase == "qualification":
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
        result, relay = {}, None
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
            manifest.update(continuation, continuation_maximum_calls=1 if v2 else 2,
                            continuation_maximum_attempts=1000 if v2 else 11000)
            if v2:
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
                relay = NetworkRelay(profile, tuple(("127.0.0.1", port, "127.0.0.2") for port in ports)) if profile != "N0" else None
                with relay if relay is not None else nullcontext():
                    result = benchmark.run_network_observation(configs=configs, steps=steps,
                        **({"wire_profile": wire_profile} if wire_profile is not None else {}),
                        **({"candidate_manifest": manifest} if wire_profile == _COMPACT_PROFILE_V2 else {}))
                final_head, final_fingerprints = source()
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
            result.update(code_sha=head, source_sha256=fingerprints)
            result = assemble(result, profile=profile, phase=phase, manifest=manifest, relay=relay_report or {})
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
