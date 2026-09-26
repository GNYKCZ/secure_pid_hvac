"""#101：已确认段的有界暂存、连续对照、完整聚合 reader 与 guarded 发布。"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType

import numpy as np

from secure_control.crypto import TwoPartySharing
from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.execution.lan_runtime import RunControl
from secure_control.execution.localhost_codec import (
    LanContinuousSetupPayload,
    LanSegmentedHelloPayload,
    SegmentEndPayload,
    SegmentEndReceipt,
    decode_wire_value,
    encode_wire_value,
)
from secure_control.protocol import Client
from secure_control.scenarios.cart_pole.adapter import CartPoleAdapter
from secure_control.scenarios.cart_pole.contract import CartPoleContract
from secure_control.scenarios.cart_pole.controller import (
    CartPoleBalanceConfig,
    build_cart_pole_controller_spec,
)
from secure_control.scenarios.cart_pole.experiment import BalanceMonitor
from secure_control.scenarios.cart_pole.interactive import PULSE_PHASE, InteractiveSession
from secure_control.scenarios.cart_pole.plant import CartPolePlant
from secure_control.scenarios.cart_pole.secure_experiment import cart_pole_numeric_contract
from secure_control.simulation import SimulationResult

from .artifacts import _RUN_ID_PATTERN, _new_run_id, _owned_stage, load_artifacts, write_artifacts
from .cart_pole_evidence import DISTURBANCE_POLICY, _numeric_array, plot_motion_overview
from .lan_continuous_profile import PreparedSegmentedExperiment, load_segmented_experiment
from .lan_runner import _run_prepared_segmented
from .plotting import OVERVIEW_BUCKETS, BoundedOverview, _control_axes

FORMAT = "cart_pole_segmented_run"
SEGMENT_LIMIT = 8 * 1024 * 1024
INDEX_LINE_LIMIT = 64 * 1024
HEADER_LIMIT = 256 * 1024
EVIDENCE = "cart_pole_segment_evidence.json"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SESSION = re.compile(r"controller-[0-9a-f]{32}\Z")
_ROUND = re.compile(r"round-[0-9a-f]{32}\Z")


def _bytes(value: object) -> bytes:
    """固定 UTF-8/LF 及 key 顺序，entry hash 不包含自身，避免循环摘要。"""
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _same(actual, expected) -> None:
    """规范 JSON 比较同时拒绝 bool 冒充整数；元组只在文件边界变为列表。"""
    if _bytes(actual) != _bytes(expected):
        raise ValueError("分段证据字段或语义不一致。")


def _close(actual, expected) -> None:
    """有限 binary64 重放容差；失败保持 reader 的 ValueError 契约。"""
    if np.shape(actual) != np.shape(expected) or not np.allclose(
            actual, expected, rtol=0, atol=1e-12):
        raise ValueError("连续数值证据不一致。")


def _keys(value, keys) -> None:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("分段证据字段集合无效。")


def _int(value, minimum=0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError("分段整数字段无效。")
    return value


def _decode(raw: bytes) -> dict:
    """拒绝重复 key、非对象及非标准浮点；调用方在读取前限制长度。"""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("重复 JSON key。")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    if not isinstance(value, dict):
        raise TypeError("需要 JSON 对象。")
    return value


def _path(root: Path, relative: str, *, directory=False, limit=SEGMENT_LIMIT) -> Path:
    """只信任 root 内逐级普通路径；不先 resolve 再隐藏 symlink/逃逸事实。"""
    if (not isinstance(relative, str) or not relative or "\\" in relative
            or Path(relative).is_absolute() or any(p in ("", ".", "..")
                                                  for p in relative.split("/"))):
        raise ValueError("分段路径无效。")
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise ValueError("不接受 symlink 产物。")
    if root.resolve() not in path.resolve().parents:
        raise ValueError("产物路径逃逸。")
    if directory:
        if not path.is_dir():
            raise ValueError("缺少分段目录。")
    elif not path.is_file() or path.stat().st_size > limit:
        raise ValueError("缺少文件或文件超出有界大小。")
    return path


def _read(path: Path, limit=SEGMENT_LIMIT) -> dict:
    size = path.stat().st_size
    if size > limit:
        raise ValueError("JSON 超过有界大小。")
    with path.open("rb") as source:
        # 小段按实际大小分配；仍多读一字节检测增长，不为每个小 JSON 预留 8 MiB。
        raw = source.read(size + 1)
        if len(raw) != size:
            raise ValueError("JSON 在读取期间变化。")
    return _decode(raw)


def _hash(path: Path, check: Callable[[], None] = lambda: None) -> str:
    """所有聚合文件使用固定 block 哈希，不把 O(N) 索引装入内存。"""
    digest = sha256()
    with path.open("rb") as source:
        while block := source.read(64 * 1024):
            check()
            digest.update(block)
    return digest.hexdigest()


def _write(path: Path, value, limit=SEGMENT_LIMIT) -> None:
    raw = _bytes(value)
    if len(raw) > limit:
        raise ValueError("分段记录超过有界大小。")
    with path.open("xb") as output:
        output.write(raw)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _members(folder, expected):
    """固定文件集合逐项匹配；额外内容立即拒绝，不 collect 任意目录列表。"""
    remaining = set(expected)
    with os.scandir(folder) as children:
        for child in children:
            if child.name not in remaining:
                raise ValueError("存在未声明的产物内容。")
            remaining.remove(child.name)
    if remaining:
        raise ValueError("缺少声明的产物内容。")


@contextmanager
def _identities():
    """跨段唯一性使用临时磁盘索引，固定 4 MiB cache；不保留全 run 的 set。"""
    with tempfile.TemporaryDirectory(prefix="cart-pole-identities-") as folder:
        connection = sqlite3.connect(Path(folder) / "ids.sqlite")
        try:
            connection.execute("PRAGMA cache_size=-4096")
            connection.execute("PRAGMA temp_store=FILE")
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("CREATE TABLE ids(kind TEXT, id TEXT, PRIMARY KEY(kind,id))")
            yield connection
        finally:
            connection.close()


def _identity(db, kind, value) -> None:
    if not isinstance(value, str):
        raise TypeError("协议身份类型无效。")
    try:
        db.execute("INSERT INTO ids VALUES (?,?)", (kind, value))
    except sqlite3.IntegrityError as error:
        raise ValueError("跨段协议身份重复。") from error


class _Definition:
    """从单一冻结公开定义复核场景、范围/prime/ledger，不重新生成秘密材料。"""

    def __init__(self, config):
        _keys(config, {"definition", "setup", "topology_sha256", "transport", "channels"})
        self.config = config
        self.effective = effective = config["definition"]
        _keys(effective, {"scenario", "fractional_bits", "paper_parameter_bits",
                          "runtime_payload_bits", "security_parameter", "q", "sample_count",
                          "range", "reference_used", "raw_equals_applied", "claim_level",
                          "profile_sha256", "prime_source_sha256", "plant_source_sha256",
                          "balance_source_sha256", "plant_contract", "balance_config",
                          "controller_spec", "mode", "segment_capacity", "segment_range",
                          "disturbance_policy", "modulus_evidence"})
        if (effective.get("scenario") != {"name": "cart_pole", "version": "3"}
                or effective.get("mode") != "segmented"
                or config["transport"] not in ("insecure_tcp", "mutual_tls")
                or not _HEX.fullmatch(config["topology_sha256"])):
            raise ValueError("场景/传输/版本无效。")
        self.capacity = _int(effective["segment_capacity"], 1)
        if self.capacity > 1000:
            raise ValueError("段容量超过范围。")
        self.plant = CartPoleContract(**effective["plant_contract"])
        self.balance = CartPoleBalanceConfig(**effective["balance_config"])
        for name in ("fractional_bits", "paper_parameter_bits", "runtime_payload_bits",
                     "security_parameter", "q", "sample_count"):
            _int(effective[name], 1)
        for name in ("profile_sha256", "prime_source_sha256", "plant_source_sha256",
                     "balance_source_sha256"):
            if not isinstance(effective[name], str) or not _HEX.fullmatch(effective[name]):
                raise ValueError("冻结来源摘要无效。")
        _same([effective["sample_count"], effective["reference_used"],
               effective["raw_equals_applied"], effective["claim_level"]],
              [self.balance.horizon_steps, True, False, "cart-pole-near-upright-simulation"])
        self.spec = build_cart_pole_controller_spec(self.plant, self.balance)
        _same(effective["controller_spec"],
              {name: getattr(self.spec, name).tolist() for name in ("A", "B", "C", "D", "x0")})
        _same(effective["disturbance_policy"], DISTURBANCE_POLICY)
        self.context, self.contract, proof = cart_pole_numeric_contract(
            self.spec, replace(self.balance, horizon_steps=self.capacity),
            fractional_bits=effective["fractional_bits"],
            parameter_bits=effective["paper_parameter_bits"],
            runtime_payload_bits=effective["runtime_payload_bits"], modulus=effective["q"],
        )
        _same(effective["segment_range"], {"contract": asdict(self.contract), "proof": proof})
        _, _, finite_proof = cart_pole_numeric_contract(
            self.spec, self.balance, fractional_bits=effective["fractional_bits"],
            parameter_bits=effective["paper_parameter_bits"],
            runtime_payload_bits=effective["runtime_payload_bits"], modulus=effective["q"],
        )
        finite_proof["force_limit_n"] = self.plant.max_applied_force_n
        _same(effective["range"], {"mode": "finite_horizon", "steps": self.balance.horizon_steps,
                                  "proof": finite_proof})
        self.setup = decode_wire_value(_bytes(config["setup"]))
        if not isinstance(self.setup, LanContinuousSetupPayload):
            raise TypeError("需要有限 setup。")
        _same(asdict(self.setup), asdict(LanContinuousSetupPayload(
            self.context.modulus, self.context.integer_bits, self.context.fractional_bits,
            effective["security_parameter"], (), self.contract.input_payload_bounds,
            self.capacity, self.setup.modulus_evidence,
        )))
        _same(effective["modulus_evidence"],
              asdict(self.setup.modulus_evidence) if self.setup.modulus_evidence else None)
        # 构造 Client 只做 canonical 数学/素数校验；不 distribute 或 prepare_online。
        client = Client(self.context, TwoPartySharing(self.context.modulus),
                        security_parameter=effective["security_parameter"],
                        modulus_evidence=self.setup.modulus_evidence)
        layout = client._layout_from_spec(self.spec)
        self.ledger = asdict(layout.scale_ledger)
        payloads = {name: np.asarray(self.context.encode(getattr(self.spec, name)), dtype=object)
                    for name in ("A", "B", "C", "D", "x0")}
        self.range = asdict(client._validate_range_contract(payloads, layout, self.contract))
        self.prime = asdict(client.truncation.modulus_verification)
        self.adapter = CartPoleAdapter(self.plant, self.balance)
        _same(config["channels"], asdict(self.adapter.metadata))
        self.products = sum(getattr(self.spec, name).size for name in ("A", "B", "C", "D"))


def _protocol(data, definition, db, index, start, previous, run_id):
    """核对原双回执及逐步能力/资源路由；计数不信任自报 root。"""
    _keys(data, {"protocol", "steps"})
    protocol = data["protocol"]
    _keys(protocol, {"hello", "session_id", "steps", "receipts", "setup",
                     "connection_seconds", "scale_ledger", "range_verification",
                     "modulus_verification"})
    hello = protocol["hello"]
    parsed = LanSegmentedHelloPayload(**hello)
    _same(hello, asdict(LanSegmentedHelloPayload(
        definition.config["topology_sha256"], parsed.nonce, run_id, index, start, previous,
    )))
    session = protocol["session_id"]
    if not isinstance(session, str) or not _SESSION.fullmatch(session):
        raise ValueError("session 身份无效。")
    _identity(db, "session", session)
    _same(protocol["setup"], asdict(definition.setup))
    _same(protocol["scale_ledger"], definition.ledger)
    _same(protocol["range_verification"], definition.range)
    _same(protocol["modulus_verification"], definition.prime)
    seconds = protocol["connection_seconds"]
    if type(seconds) not in (int, float) or not np.isfinite(seconds) or seconds < 0:
        raise ValueError("连接耗时无效。")
    steps = data["steps"]
    if not isinstance(steps, list) or len(steps) > definition.capacity:
        raise ValueError("段步骤数超界。")
    if not isinstance(protocol["steps"], list) or len(protocol["steps"]) != len(steps):
        raise ValueError("能力/快照行数不一致。")
    for local, item in enumerate(steps):
        _keys(item, {"protocol", "snapshot", "double_committed", "physically_confirmed"})
        if item["double_committed"] is not True or item["physically_confirmed"] is not True:
            raise ValueError("不能发布未确认步骤。")
        step = item["protocol"]
        _keys(step, {"run_id", "segment_index", "session_id", "round_id", "local_step",
                     "global_step", "raw_control", "products", "truncations", "resource_ids"})
        round_id = step["round_id"]
        if not isinstance(round_id, str) or not _ROUND.fullmatch(round_id):
            raise ValueError("round 身份无效。")
        _identity(db, "round", round_id)
        _same(step, {"run_id": run_id, "segment_index": index, "session_id": session,
                     "round_id": round_id, "local_step": local, "global_step": start + local,
                     "raw_control": step["raw_control"], "products": definition.products,
                     "truncations": 0,
                     "resource_ids": [f"{round_id}:D[0,{j}]"
                                      for j in range(definition.spec.input_dimension)]})
        _same(step, protocol["steps"][local])
        _numeric_array(step["raw_control"], (1,))
        for identity in step["resource_ids"]:
            _identity(db, "resource", identity)
    receipts = protocol["receipts"]
    if not isinstance(receipts, list) or len(receipts) != 2:
        raise ValueError("缺少双方结束回执。")
    action = receipts[0]["end"]["action"]
    if action not in ("continue", "stop") or (action == "continue"
                                                and len(steps) != definition.capacity):
        raise ValueError("只有满段能继续。")
    end = SegmentEndPayload(run_id, index, start, len(steps), start + len(steps),
                            steps[-1]["protocol"]["round_id"] if steps else None, action)
    for party, receipt in zip(("P1", "P2"), receipts, strict=True):
        _same(receipt, asdict(SegmentEndReceipt(party, session, end, start + len(steps),
                                              len(steps) * definition.products, 0)))
    db.commit()
    return action, session, start + len(steps)


class _Replay:
    """唯一 root 初态初始化两套独立可变状态；monitor 只在真正新观测时更新。"""

    def __init__(self, definition):
        self.definition = definition
        self.plants = {name: CartPolePlant(definition.plant) for name in ("ideal", "secure")}
        self.adapters = {name: CartPoleAdapter(definition.plant, definition.balance)
                         for name in self.plants}
        self.monitors = {name: BalanceMonitor(definition.balance) for name in self.plants}
        self.ideal = PlaintextStateSpaceRuntime(definition.spec)
        self.step = 0
        for name in self.plants:
            if self.monitors[name].observe(self.plants[name].output()) == "failed":
                raise ValueError("初态越域。")

    def convert(self, data, parent, index, check):
        """逐区间重放并返回 ≤L 行八字段/侧证据；不生成安全材料或重新观察边界。"""
        definition = self.definition
        ts = definition.plant.sample_period_s
        target = np.asarray(definition.balance.target_state)
        branches = {name: {"observations": [plant.output().tolist()], "raw_force_n": [],
                           "statuses": [self.monitors[name].status],
                           "stable_counts": [self.monitors[name].stable_count]}
                    for name, plant in self.plants.items()}
        before = self.step
        applied = {name: [] for name in self.plants}
        disturbances = []
        for item in data["steps"]:
            check()
            g = self.step
            snap = item["snapshot"]
            _keys(snap, {"t_before_s", "t_after_s", "observation_before", "observation_after",
                         "target", "raw_force_n", "applied_force_n", "disturbance_force_n",
                         "observed_status", "stable_count"})
            t0, t1 = g * ts, (g + 1) * ts
            if not np.isfinite(t1) or t1 <= t0:
                raise ValueError("仿真时间不能有限且可区分地表示。")
            _same([snap["t_before_s"], snap["t_after_s"], snap["target"]],
                  [t0, t1, target.tolist()])
            _close(_numeric_array(snap["observation_before"], (4,)),
                   self.plants["secure"].output())
            d = snap["disturbance_force_n"]
            if type(d) not in (int, float) or d not in (-1., 0., 1.):
                raise ValueError("实际外力无效。")
            disturbances.append(float(d))
            for name, plant in self.plants.items():
                v = self.adapters[name].controller_input(target, plant.output())
                if name == "ideal":
                    raw = float(self.ideal.step(v)[0])
                else:
                    # 独立 Python 整数点积；先验证 input 界，再以 2ell 解码未截断输出。
                    encoded_v = [int(x) for x in definition.context.encode(v)]
                    if any(abs(x) > bound for x, bound in
                           zip(encoded_v, definition.contract.input_payload_bounds, strict=True)):
                        raise ValueError("重放输入超出段证明。")
                    encoded_d = [int(x) for x in definition.context.encode(definition.spec.D)[0]]
                    value = sum(a * b for a, b in zip(encoded_d, encoded_v, strict=True))
                    if abs(value) > (definition.context.modulus - 1) // 2:
                        raise ValueError("输出模数回绕。")
                    raw = value / definition.context.scale**2
                    _same(item["protocol"]["raw_control"], [snap["raw_force_n"]])
                    if type(snap["raw_force_n"]) not in (int, float) or not np.isclose(
                            snap["raw_force_n"], raw, rtol=0, atol=1e-12):
                        raise ValueError("安全 raw 与原观测/定点控制器不一致。")
                force = float(self.adapters[name].apply_control(np.array([raw]))[0])
                if abs(force + d) > definition.plant.max_applied_force_n:
                    raise ValueError("对照合力越界；不裁剪外力补图。")
                output = plant.step(np.array([force + d]))
                monitor = self.monitors[name]
                if monitor.observe(output) == "failed":
                    raise ValueError("重放物理状态越界。")
                branch = branches[name]
                branch["raw_force_n"].append(raw)
                branch["observations"].append(output.tolist())
                branch["statuses"].append(monitor.status)
                branch["stable_counts"].append(monitor.stable_count)
                applied[name].append([force])
                if name == "secure":
                    _close(_numeric_array(snap["observation_after"], (4,)), output)
                    _same([snap["applied_force_n"], snap["observed_status"], snap["stable_count"]],
                          [force, monitor.status, monitor.stable_count])
            self.step += 1
        n = self.step - before
        evidence = {
            "schema_version": 3, "scope": "segment_fragment", "artifact_run_id": parent,
            "segment_index": index, "global_start": before, "global_end": self.step,
            "branches": branches, "disturbance_force_n": disturbances,
            "events": [{"step": before + j, "force_n": d, "duration_steps": 1,
                        "phase": PULSE_PHASE} for j, d in enumerate(disturbances) if d],
        }
        result = None
        if n:
            u0, u1 = np.array(applied["ideal"]), np.array(applied["secure"])
            y0 = np.asarray(branches["ideal"]["observations"][:-1])
            y1 = np.asarray(branches["secure"]["observations"][:-1])
            result = SimulationResult(np.arange(before, self.step) * ts,
                                      np.tile(target, (n, 1)), y0, y1, u0, u1, u0-u1, y0-y1)
        return result, evidence


def _entries(root, manifest, check):
    """索引逐行读取，entry/摘要链及实际目录同时核验，不构造全索引列表。"""
    index_path = _path(root, "segments.jsonl", limit=float("inf"))
    if _hash(index_path, check) != manifest["index_sha256"]:
        raise ValueError("聚合索引摘要不一致。")
    previous = None
    count = start = 0
    with index_path.open("rb") as source:
        while raw := source.readline(INDEX_LINE_LIMIT + 1):
            check()
            if len(raw) > INDEX_LINE_LIMIT:
                raise ValueError("索引行过长。")
            item = _decode(raw)
            _keys(item, {"index", "global_start", "global_end", "protocol_sha256",
                         "chunk", "prev_sha256", "sha256"})
            if raw != _bytes(item):
                raise ValueError("索引不是规范 UTF-8/LF。")
            digest = item["sha256"]
            payload = {key: value for key, value in item.items() if key != "sha256"}
            if digest != sha256(_bytes(payload)).hexdigest() or item["prev_sha256"] != previous:
                raise ValueError("索引摘要链无效。")
            if (_int(item["index"]) != count or _int(item["global_start"]) != start
                    or not start <= _int(item["global_end"]) <= start + manifest["capacity"]):
                raise ValueError("缺段、重叠或顺序错误。")
            folder = _path(root, f"segments/{count}", directory=True)
            protocol = _path(folder, "protocol.json")
            if _hash(protocol, check) != item["protocol_sha256"]:
                raise ValueError("协议段摘要不一致。")
            chunk = item["chunk"]
            expected_names = {"protocol.json"}
            if item["global_end"] > start:
                _keys(chunk, {"name", "files"})
                if not isinstance(chunk["name"], str) or not _RUN_ID_PATTERN.fullmatch(chunk["name"]):
                    raise ValueError("数据块名称无效。")
                _keys(chunk["files"], {"trajectory.csv", "metadata.json", "config.json", EVIDENCE})
                block = _path(folder, chunk["name"], directory=True)
                _members(block, chunk["files"])
                for name, digest in chunk["files"].items():
                    if _hash(_path(block, name), check) != digest:
                        raise ValueError("数据块摘要无效。")
                expected_names.add(chunk["name"])
            elif chunk is not None:
                raise ValueError("零步段不能伪造控制行。")
            _members(folder, expected_names)
            yield item
            count += 1
            start = item["global_end"]
            previous = item["sha256"]
    if count != manifest["segment_count"] or start != manifest["N"] or previous != manifest["tail"]:
        raise ValueError("索引末尾与根计数不一致。")
    folders = _path(root, "segments", directory=True)
    seen = 0
    with os.scandir(folders) as children:
        for path in children:
            if (not path.name.isdecimal() or str(int(path.name)) != path.name
                    or not 0 <= int(path.name) < count or path.is_symlink()
                    or not path.is_dir(follow_symlinks=False)):
                raise ValueError("额外未声明段或目录。")
            seen += 1
    if seen != count:
        raise ValueError("段目录数量不一致。")


def _fragment_config(config, parent, entry):
    return {**config, "scope": "segment_fragment", "parent_run_id": parent,
            "segment_index": entry["index"], "global_start": entry["global_start"],
            "global_end": entry["global_end"],
            "sample_count": entry["global_end"] - entry["global_start"]}


def _load_chunk(root, entry):
    folder = _path(root, f"segments/{entry['index']}", directory=True)
    protocol = _read(_path(folder, "protocol.json"))
    if entry["chunk"] is None:
        return protocol, None, None
    block = _path(folder, entry["chunk"]["name"], directory=True)
    # canonical reader 保持旧语义；先检查新文件的严格 JSON 和段行数，
    # 避免异常文件让其有限 rows 列表膨胀到超过当前段容量。
    metadata = _read(_path(block, "metadata.json"))
    _keys(metadata, {"schema_version", "run_id", "created_at_utc", "success", "sample_count",
                     "scenario", "channels", "channel_counts", "columns", "files_sha256",
                     "provenance", "derived_files_sha256"})
    _keys(metadata["derived_files_sha256"], {EVIDENCE})
    _read(_path(block, "config.json"))
    n = entry["global_end"] - entry["global_start"]
    with _path(block, "trajectory.csv").open("r", encoding="utf-8", newline="") as source:
        rows = csv.reader(source)
        next(rows, None)
        count = 0
        for _row in rows:
            count += 1
            if count > n:
                raise ValueError("数据块行数超过已确认段前缀。")
    if count != n:
        raise ValueError("数据块缺少已确认行。")
    return protocol, load_artifacts(block), _read(_path(block, EVIDENCE))


def _header(root, check, *, allow_staging=False, plots=True):
    """完整根与 fragment/hidden staging 明确分离；固定大小头不信任自报 N。"""
    if not root.is_dir() or root.is_symlink() or (root.name.startswith(".incomplete-")
                                               and not allow_staging):
        raise ValueError("需要正式聚合目录。")
    manifest = _read(_path(root, "run.json", limit=HEADER_LIMIT), HEADER_LIMIT)
    _keys(manifest, {"format", "format_version", "status", "artifact_run_id", "backend_run_id",
                     "N", "capacity", "segment_count", "tail", "termination", "config_sha256",
                     "index_sha256", "plots_sha256"})
    if (manifest["format"] != FORMAT or type(manifest["format_version"]) is not int
            or manifest["format_version"] != 1 or manifest["status"] != "complete"
            or not _RUN_ID_PATTERN.fullmatch(manifest["artifact_run_id"])
            or not _HEX.fullmatch(manifest["backend_run_id"])
            or root.name != ((".incomplete-" if allow_staging else "")
                             + manifest["artifact_run_id"])):
        raise ValueError("聚合格式、状态或身份无效。")
    _int(manifest["N"])
    _int(manifest["segment_count"], 1)
    capacity = _int(manifest["capacity"], 1)
    if capacity > 1000:
        raise ValueError("根容量超界。")
    config_file = _path(root, "config.json", limit=HEADER_LIMIT)
    if _hash(config_file, check) != manifest["config_sha256"]:
        raise ValueError("根配置摘要不一致。")
    config = _read(config_file, HEADER_LIMIT)
    expected = {"run.json", "config.json", "segments.jsonl", "segments"}
    if plots:
        expected |= {"plots.json", "control.png", "cart_pole_motion.png"}
        plot_file = _path(root, "plots.json", limit=HEADER_LIMIT)
        if _hash(plot_file, check) != manifest["plots_sha256"]:
            raise ValueError("概要图清单摘要无效。")
        plot = _read(plot_file, HEADER_LIMIT)
        _keys(plot, {"format_version", "artifact_run_id", "N", "config_sha256",
                     "index_sha256", "algorithm", "buckets", "point_counts", "figures"})
        _same({key: plot[key] for key in ("format_version", "artifact_run_id", "N",
                                         "config_sha256", "index_sha256", "algorithm", "buckets")},
              {"format_version": 1, "artifact_run_id": manifest["artifact_run_id"],
               "N": manifest["N"], "config_sha256": manifest["config_sha256"],
               "index_sha256": manifest["index_sha256"],
               "algorithm": "first-last-min-max-v1", "buckets": OVERVIEW_BUCKETS})
        _keys(plot["point_counts"], {"u_ideal", "u_secure", "u_error", "p_ideal", "p_secure",
                                     "theta_ideal", "theta_secure", "events", "stable"})
        if any(_int(count) > 4*OVERVIEW_BUCKETS+2 for count in plot["point_counts"].values()):
            raise ValueError("概要图点数超界。")
        if any(plot["point_counts"][name] > OVERVIEW_BUCKETS for name in ("events", "stable")):
            raise ValueError("事件/稳定状态桶数超界。")
        _keys(plot["figures"], {"control.png", "cart_pole_motion.png"})
        for name, digest in plot["figures"].items():
            if _hash(_path(root, name), check) != digest:
                raise ValueError("概要图摘要无效。")
    _members(root, expected)
    return manifest, config


def _verify(root, check, *, allow_staging=False, plots=True):
    manifest, config = _header(root, check, allow_staging=allow_staging, plots=plots)
    definition = _Definition(config)
    if manifest["capacity"] != definition.capacity:
        raise ValueError("根与配置段容量不一致。")
    replay = _Replay(definition)
    previous = None
    last = None
    with _identities() as db:
        for entry in _entries(root, manifest, check):
            check()
            data, record, evidence = _load_chunk(root, entry)
            action, previous, end = _protocol(data, definition, db, entry["index"],
                                              replay.step, previous, manifest["backend_run_id"])
            if action != ("stop" if entry["index"] == manifest["segment_count"]-1 else "continue"):
                raise ValueError("只能最后一段正常 stop。")
            expected, expected_evidence = replay.convert(data, manifest["artifact_run_id"],
                                                         entry["index"], check)
            if end != entry["global_end"]:
                raise ValueError("协议前缀与索引不一致。")
            if expected is not None:
                _same(record.effective_config,
                      _fragment_config(definition.effective, manifest["artifact_run_id"], entry))
                _same(asdict(record.metadata), config["channels"])
                _same(record.provenance, {"scenario_name": "cart_pole", "scenario_version": "3",
                                          "schema_version": 1, "backend": "lan_segmented_fragment"})
                _same(evidence, {**expected_evidence, "run_id": record.run_id})
                for name in SimulationResult.__dataclass_fields__:
                    _close(getattr(record.result, name), getattr(expected, name))
            last = data["protocol"]
    n = replay.step
    monitor = replay.monitors["secure"]
    _same(manifest["termination"], {
        "status": "stopped", "stop_reason": "user_requested", "confirmed_step_count": n,
        "protocol_committed_count": n, "next_global_step": n,
        "terminal_time_s": n * definition.plant.sample_period_s,
        "observed_status": monitor.status, "stable_count": monitor.stable_count,
        "resource_counts": {"products_consumed": definition.products*n, "truncations_consumed": 0},
        "final_receipts": last["receipts"],
    })
    return manifest, config


@dataclass(frozen=True, slots=True)
class VerifiedSegmentedRun:
    """完整验证后的固定头和磁盘访问句柄；每次 seek 重核摘要，至多缓存两块。"""

    path: Path
    _manifest: dict
    _config: dict
    _fingerprint: str
    _cache: OrderedDict

    @property
    def metadata(self) -> Mapping:
        """只读聚合 metadata；不暴露所有索引或全 N 数组。"""
        return _freeze(self._manifest)

    def _fresh(self, check):
        if _hash(_path(self.path, "run.json", limit=HEADER_LIMIT), check) != self._fingerprint:
            raise ValueError("正式根在打开后被修改。")
        manifest, config = _header(self.path, check)
        _same(manifest, self._manifest)
        _same(config, self._config)

    def iter_segments(self, *, check=lambda: None) -> Iterator[tuple]:
        """流式重核索引和文件后读当前块；调用方不得为绘图全量收集。"""
        self._fresh(check)
        for entry in _entries(self.path, self._manifest, check):
            # 即使缓存命中仍先核过当前文件摘要；缓存不作为永久可信标记。
            value = self._chunk(entry)
            data, record, evidence = value
            if record is not None:
                record = replace(record, effective_config=_freeze(record.effective_config),
                                 provenance=_freeze(record.provenance))
            yield _freeze(entry), record, _freeze(evidence), _freeze(data)

    def _chunk(self, entry):
        """只缓存被选中的块；调用方必须先完成当前索引/文件摘要核对。"""
        key = entry["index"]
        value = self._cache.pop(key, None)
        if value is None:
            value = _load_chunk(self.path, entry)
        self._cache[key] = value
        if len(self._cache) > 2:
            self._cache.popitem(last=False)
        return value

    def observation_at(self, k: int, *, check=lambda: None) -> Mapping:
        """观测索引 0…N，k>0 的施力归属 g=k−1；段边界优先取前块末态。"""
        if type(k) is not int or not 0 <= k <= self._manifest["N"]:
            raise ValueError("回放观测索引越界。")
        self._fresh(check)
        for entry in _entries(self.path, self._manifest, check):
            if entry["global_start"] <= k <= entry["global_end"]:
                _data, record, evidence = self._chunk(entry)
                if record is None:
                    definition = _Definition(self._config)
                    initial = _Replay(definition)
                    return _freeze({"step": k, "time_s": k*definition.plant.sample_period_s,
                                    "state": list(definition.plant.initial_state),
                                    "ideal_state": list(definition.plant.initial_state),
                                    "status": initial.monitors["secure"].status,
                                    "stable_count": initial.monitors["secure"].stable_count,
                                    "applied_force_n": None, "disturbance_force_n": None,
                                    "control_error_n": None})
                local = k - entry["global_start"]
                secure, ideal = evidence["branches"]["secure"], evidence["branches"]["ideal"]
                return _freeze({"step": k, "time_s": k*self._config["definition"]
                                ["plant_contract"]["sample_period_s"],
                                "state": secure["observations"][local],
                                "ideal_state": ideal["observations"][local],
                                "status": secure["statuses"][local],
                                "stable_count": secure["stable_counts"][local],
                                "applied_force_n": (float(record.result.control_secure[local-1, 0])
                                                    if local else None),
                                "disturbance_force_n": (evidence["disturbance_force_n"][local-1]
                                                        if local else None),
                                "control_error_n": (float(record.result.control_error[local-1, 0])
                                                    if local else None)})
        raise ValueError("缺少请求观测。")


def open_verified_cart_pole_segmented_run(path: str | Path, *, check=lambda: None
                                         ) -> VerifiedSegmentedRun:
    """公开入口必须先完整流式验证；片段/hidden staging 不具有完整运行语义。"""
    root = Path(path)
    manifest, config = _verify(root, check)
    return VerifiedSegmentedRun(root, manifest, config, _hash(root / "run.json", check), OrderedDict())


def _segment_overview(source, check, staging):
    """只读取已验证块，不在渲染时执行 controller 或 plant。"""
    names = ("u_ideal", "u_secure", "u_error", "p_ideal", "p_secure",
             "theta_ideal", "theta_secure")
    n = source._manifest["N"]
    series = {name: BoundedOverview(n) for name in names}
    events, stable = {}, {}
    if staging:
        def chunks():
            for entry in _entries(source.path, source._manifest, check):
                _data, record, evidence = _load_chunk(source.path, entry)
                yield _freeze(entry), record, _freeze(evidence), None
        iterator = chunks()
    else:
        iterator = source.iter_segments(check=check)
    period = source._config["definition"]["plant_contract"]["sample_period_s"]
    if n == 0:
        initial = source._config["definition"]["plant_contract"]["initial_state"]
        for name in names[3:]:
            series[name].add(0, 0., initial[0 if name.startswith("p_") else 2])
    for entry, record, evidence, _data in iterator:
        check()
        if record is None:
            continue
        result = record.result
        for j, time in enumerate(result.time):
            check()
            g = entry["global_start"] + j
            for name, value in (("u_ideal", result.control_ideal[j, 0]),
                                ("u_secure", result.control_secure[j, 0]),
                                ("u_error", result.control_error[j, 0])):
                series[name].add(g, float(time), float(value))
            bucket = min(OVERVIEW_BUCKETS-1, g*OVERVIEW_BUCKETS // max(1, n))
            if evidence["disturbance_force_n"][j]:
                events.setdefault(bucket, (g*period, evidence["disturbance_force_n"][j]))
        for j in range(len(result.time)+1):
            if j == 0 and entry["index"]:
                continue
            g = entry["global_start"] + j
            for branch in ("ideal", "secure"):
                values = evidence["branches"][branch]["observations"][j]
                series[f"p_{branch}"].add(g, g*period, values[0])
                series[f"theta_{branch}"].add(g, g*period, values[2])
            if evidence["branches"]["secure"]["statuses"][j] == "stable":
                bucket = min(OVERVIEW_BUCKETS-1, g*OVERVIEW_BUCKETS // max(1, n))
                stable.setdefault(bucket, (g*period, evidence["branches"]["secure"]
                                          ["observations"][j][0]))
    return {key: item.points() for key, item in series.items()}, list(events.values()), list(stable.values())


def _overview_control(series, title, n):
    figure, axes = _control_axes(title)
    for axis, key, color in zip(axes, ("u_ideal", "u_secure", "u_error"),
                                ("tab:blue", "tab:orange", "tab:red"), strict=True):
        points = series[key]
        axis.plot([p[1] for p in points], [p[2] for p in points], color=color, label=key)
        axis.set_ylabel("Ideal - secure force (N)" if key == "u_error" else "Applied force (N)")
        axis.grid(True, alpha=.3)
        axis.legend()
        if not n:
            axis.text(.5, .5, "No control intervals executed", ha="center", transform=axis.transAxes)
    axes[2].axhline(0, color="gray", linewidth=.7)
    axes[2].set_xlabel("Simulation time (s) · bucket overview; raw values in playback")
    return figure


def write_segmented_overview(source, stage: Path, *, check=lambda: None, staging=False):
    """完整源的有界概要和来源清单；两张 mandatory 图任一失败阻止完整发布。"""
    series, events, stable = _segment_overview(source, check, staging)
    manifest = source._manifest
    status = manifest["termination"]["observed_status"]
    title = (f"{manifest['artifact_run_id']} · N={manifest['N']} · bucket overview\n"
             f"User stopped · observed {status}")
    figures = {"control.png": _overview_control(series, title, manifest["N"]),
               "cart_pole_motion.png": plot_motion_overview(series, events, stable, title)}
    try:
        for name, figure in figures.items():
            check()
            figure.savefig(stage / name, dpi=160, format="png")
            check()
    finally:
        for figure in figures.values():
            figure.clear()
    payload = {"format_version": 1, "artifact_run_id": manifest["artifact_run_id"],
               "N": manifest["N"], "config_sha256": manifest["config_sha256"],
               "index_sha256": manifest["index_sha256"], "algorithm": "first-last-min-max-v1",
               "buckets": OVERVIEW_BUCKETS,
               "point_counts": {**{key: len(value) for key, value in series.items()},
                                "events": len(events), "stable": len(stable)},
               "figures": {name: _hash(stage / name, check) for name in figures}}
    (stage / "plots.json").write_bytes(_bytes(payload))


def redraw_segmented_control(run_dir, output_path):
    """通过完整新 reader 重绘概要；不恢复协议或更改已发布源。"""
    source = open_verified_cart_pole_segmented_run(run_dir)
    series, _events, _stable = _segment_overview(source, lambda: None, False)
    figure = _overview_control(series, f"{source.metadata['artifact_run_id']} · verified overview",
                               source.metadata["N"])
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        figure.savefig(target, dpi=160, format="png")
    finally:
        figure.clear()
    return target


class _Spool:
    """运行期间唯一 owned hidden root，只做当前段可靠写入，停止后才重放和绘图。"""

    def __init__(self, prepared, config, session, phase):
        self.prepared, self.session, self.phase = prepared, session, phase
        self.root = prepared.output_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.run_id = _new_run_id()
        self.stage = self.root / (".incomplete-" + self.run_id)
        self.final = self.root / self.run_id
        if os.path.lexists(self.final):
            raise FileExistsError("不覆盖已有结果。")
        self.count = self.end = 0
        self.backend_id = None
        self.published = False
        setup = LanContinuousSetupPayload(
            prepared.context.modulus, prepared.context.integer_bits,
            prepared.context.fractional_bits, prepared.security_parameter,
            (), prepared.contract.input_payload_bounds, prepared.contract.horizon_steps,
            prepared.evidence,
        )
        self.config = {"definition": prepared.effective_config,
                       "setup": _decode(encode_wire_value(setup)),
                       "topology_sha256": config.topology.digest, "transport": config.transport,
                       "channels": asdict(prepared.metadata)}
        self.stage.mkdir()
        self.identity = self.stage.stat(follow_symlinks=False).st_ino

    def check(self):
        if self.session.cancelled.is_set():
            raise RuntimeError("结果处理已取消。")
        self.prepared.recheck_sources()

    def cleanup(self):
        if not self.published and _owned_stage(self.stage, self.root, self.identity):
            shutil.rmtree(self.stage)

    def record(self, segment):
        """可靠段出口：任何序列化/磁盘错误抛回唯一后端，不能丢段后伪成功。"""
        self.check()
        data = asdict(segment)
        hello = data["protocol"]["hello"]
        if hello["segment_index"] != self.count or hello["global_start"] != self.end:
            raise ValueError("暂存段前缀不一致。")
        if self.backend_id is None:
            self.backend_id = hello["run_id"]
        if hello["run_id"] != self.backend_id:
            raise ValueError("暂存 run 身份变化。")
        _write(self.stage / f"spool-{self.count}.json", data)
        self.end += len(data["steps"])
        self.count += 1

    def publish(self, stopped):
        """只接受真正 stopped；重放、图、reader 全部成功后由原 guard 发布。"""
        self.check()
        if (stopped.get("status") != "stopped" or stopped["run_id"] != self.backend_id
                or stopped["confirmed_step_count"] != self.end
                or stopped["protocol_committed_count"] != self.end or self.count < 1):
            raise ValueError("后端停止结果与暂存前缀不一致。")
        self.phase("BACKEND_STOPPED")
        definition = _Definition(self.config)
        replay = _Replay(definition)
        self.phase("REPLAYING")
        (self.stage / "segments").mkdir()
        _write(self.stage / "config.json", self.config, HEADER_LIMIT)
        previous = tail = None
        last = None
        with _identities() as db, (self.stage / "segments.jsonl").open("xb") as index_file:
            for i in range(self.count):
                self.check()
                spool_path = self.stage / f"spool-{i}.json"
                data = _read(spool_path)
                start = replay.step
                action, previous, end = _protocol(data, definition, db, i, start, previous,
                                                  self.backend_id)
                if action != ("stop" if i == self.count-1 else "continue"):
                    raise ValueError("暂存结束 action 无效。")
                result, evidence = replay.convert(data, self.run_id, i, self.check)
                folder = self.stage / "segments" / str(i)
                folder.mkdir()
                _write(folder / "protocol.json", data)
                entry = {"index": i, "global_start": start, "global_end": end,
                         "protocol_sha256": _hash(folder / "protocol.json", self.check),
                         "chunk": None, "prev_sha256": tail}
                if result is not None:
                    def derived(record, stage, evidence=evidence):
                        self.check()
                        _write(stage / EVIDENCE, {**evidence, "run_id": record.run_id})
                        return (EVIDENCE,)
                    artifact = write_artifacts(
                        result, self.prepared.metadata,
                        _fragment_config(definition.effective, self.run_id, entry),
                        {"scenario_name": "cart_pole", "scenario_version": "3",
                         "schema_version": 1, "backend": "lan_segmented_fragment"},
                        output_root=folder, derived_writer=derived,
                    )
                    entry["chunk"] = {"name": artifact.run_id,
                                      "files": {name: _hash(artifact.run_dir / name, self.check)
                                                for name in ("trajectory.csv", "metadata.json",
                                                             "config.json", EVIDENCE)}}
                tail = sha256(_bytes(entry)).hexdigest()
                entry["sha256"] = tail
                raw = _bytes(entry)
                if len(raw) > INDEX_LINE_LIMIT:
                    raise ValueError("索引行超过上限。")
                index_file.write(raw)
                last = data["protocol"]
                spool_path.unlink()
        _same(stopped["final_segment"], last)
        terminal = {key: stopped[key] for key in (
            "status", "stop_reason", "confirmed_step_count", "protocol_committed_count",
            "next_global_step", "terminal_time_s", "observed_status", "stable_count", "resource_counts")}
        terminal["final_receipts"] = last["receipts"]
        manifest = {"format": FORMAT, "format_version": 1, "status": "complete",
                    "artifact_run_id": self.run_id, "backend_run_id": self.backend_id,
                    "N": self.end, "capacity": definition.capacity, "segment_count": self.count,
                    "tail": tail, "termination": terminal,
                    "config_sha256": _hash(self.stage / "config.json", self.check),
                    "index_sha256": _hash(self.stage / "segments.jsonl", self.check),
                    "plots_sha256": None}
        _write(self.stage / "run.json", manifest, HEADER_LIMIT)
        self.phase("VERIFYING")
        _verify(self.stage, self.check, allow_staging=True, plots=False)
        # 绘图读取刚完整校验过的源，不在 Matplotlib 内隐藏执行控制/plant。
        self.phase("PLOTTING")
        source = VerifiedSegmentedRun(self.stage, manifest, self.config,
                                      _hash(self.stage / "run.json"), OrderedDict())
        write_segmented_overview(source, self.stage, check=self.check, staging=True)
        manifest["plots_sha256"] = _hash(self.stage / "plots.json", self.check)
        (self.stage / "run.json").write_bytes(_bytes(manifest))
        self.phase("VERIFYING")
        _verify(self.stage, self.check, allow_staging=True)
        self.check()
        self.phase("PUBLISHING")
        self.check()
        with self.session.publication_guard():
            if os.path.lexists(self.final):
                raise FileExistsError("不覆盖已有完整结果。")
            os.rename(self.stage, self.final)
            self.published = True
        self.phase("COMPLETE")
        return {"status": "complete", "run_dir": str(self.final),
                "confirmed_step_count": self.end, "backend": stopped,
                "figure_paths": [str(self.final / name)
                                 for name in ("control.png", "cart_pole_motion.png")]}


def run_cart_pole_segmented(config, *, control: RunControl, session: InteractiveSession,
                           segment_steps=400, prepared: PreparedSegmentedExperiment | None = None,
                           on_step=None, phase=None) -> dict:
    """Client 专用发布协调；安全循环只有一份，后端失败不会进入成功出版。"""
    if not isinstance(control, RunControl) or not isinstance(session, InteractiveSession):
        raise TypeError("持续发布需要原 RunControl/InteractiveSession。")
    if config.experiment_config is None:
        raise ValueError("持续发布缺少 experiment profile。")
    if prepared is None:
        prepared = load_segmented_experiment(config.experiment_config, segment_steps, session)
    elif (prepared.scene.session is not session
          or prepared.contract.horizon_steps != segment_steps):
        raise ValueError("必须消费同一次持续装配与队列。")
    phase = phase if phase is not None else lambda _: None
    transaction = _Spool(prepared, config, session, phase)
    try:
        stopped = _run_prepared_segmented(config, prepared, control=control, session=session,
                                          on_step=on_step, on_segment=transaction.record, phase=phase)
        if stopped["status"] != "stopped":
            return stopped
        return transaction.publish(stopped)
    finally:
        transaction.cleanup()
