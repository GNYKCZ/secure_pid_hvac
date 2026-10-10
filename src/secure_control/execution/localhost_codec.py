"""localhost transport 的固定版本 JSON schema 与无损 bigint/share codec。"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import asdict, dataclass
from fractions import Fraction
from math import isfinite, prod
from numbers import Integral
from typing import Any, Literal

import numpy as np

from secure_control.crypto import (
    AdditiveShare,
    PocklingtonCertificate,
    PocklingtonFactorEvidence,
    PrimeModulusEvidence,
    PrimeModulusVerification,
)
from secure_control.protocol import ControllerRangeVerification, ControllerScaleLedger
from secure_control.protocol.arithmetic import (
    ScalarGate,
    ScalarGateMaterial,
    ScalarPartyMaterial,
    ScalarProgram,
)
from secure_control.protocol.messages import (
    ControllerLayout,
    ControllerShare,
    ControlShareMessage,
    InputShareMessage,
    P2TruncationPayload,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyResources,
    PreloadedResourceManifest,
    PreloadReceipt,
    ProductMaskPayload,
    ProductResourceMaterial,
    Protocol3BatchPayload,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
    ResourceMetadata,
    StepResourcePlan,
    TruncationMaskPayload,
    TruncationResourceMaterial,
)

SCHEMA_VERSION = 3
_ROLES = {"Supervisor", "Client", "P1", "P2"}
_KINDS = {"hello", "ready", "request", "reply", "error", "shutdown"}
_OPERATIONS = {
    "hello",
    "ready",
    "offline",
    "online",
    "preload_init",
    "preload_block",
    "preload_seal",
    "activate",
    "activate_stage",
    "lan_hello",
    "lan_ready",
    "lan_setup",
    "segment_end",
    "segment_begin",
    "step",
    "endpoint",
    "peer_product",
    "peer_truncation",
    "peer_batch",
    "shutdown",
}
_CANONICAL_INTEGER = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_MAX_INTEGER_DIGITS = 100_000
_MAX_ARRAY_ITEMS = 1_000_000
_MAX_JSON_DEPTH = 32
_RANGE_PROOF_MODES = {
    "finite_horizon",
    "closed_loop_invariant",
    "independent_input_invariant",
    "bounded_input_reachability",
}
_PRIME_VERIFICATION_METHODS = {
    "deterministic_miller_rabin_64_v1",
    "pocklington_v1",
}

WireRole = Literal["Supervisor", "Client", "P1", "P2"]
WireKind = Literal["hello", "ready", "request", "reply", "error", "shutdown"]


class LocalhostCodecError(ValueError):
    """wire JSON、字段集合、类型或资源预算不满足固定 schema。"""


@dataclass(frozen=True, slots=True)
class HelloPayload:
    """启动连接的角色、PID 与一次性防串线 nonce。"""

    nonce: str
    pid: int


@dataclass(frozen=True, slots=True)
class ReadyPayload:
    """角色 ready 摘要；只有 Client 携带公开验证结果。"""

    pid: int
    scale_ledger: ControllerScaleLedger | None = None
    range_verification: ControllerRangeVerification | None = None
    modulus_verification: PrimeModulusVerification | None = None


@dataclass(frozen=True, slots=True)
class RemoteErrorPayload:
    """不含 traceback、frame 或 share 的受限远端错误。"""

    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class LanHelloPayload:
    """mTLS 建立后对 LAN 模式、拓扑和新鲜 session nonce 再绑定。"""

    profile_sha256: str
    nonce: str
    mode: Literal["lan-single-step-v1", "lan-continuous-v1", "lan-scalar-v3"] = "lan-single-step-v1"


@dataclass(frozen=True, slots=True)
class BatchHelloPayload:
    """新能力显式包裹原 hello；旧 wire 字段集合不改变。"""

    base: HelloPayload | LanHelloPayload | LanSegmentedHelloPayload
    capability: Literal["control-batch-v1"] = "control-batch-v1"

    def __post_init__(self) -> None:
        if self.capability != "control-batch-v1" or not isinstance(
            self.base, (HelloPayload, LanHelloPayload, LanSegmentedHelloPayload)
        ):
            raise LocalhostCodecError("批量 hello 能力或原模式无效")


@dataclass(frozen=True, slots=True)
class LanSetupPayload:
    """离线分享前传给单方的公开数值上下文，不含 controller 或随机材料。"""

    modulus: int
    integer_bits: int
    fractional_bits: int
    security_parameter: int
    state_payload_bounds: tuple[int, ...]
    input_payload_bounds: tuple[int, ...]
    horizon_steps: int


@dataclass(frozen=True, slots=True)
class PreloadedHelloPayload:
    """显式预送能力包装；旧角色必须拒绝未知类型，不静默降级。"""

    base: BatchHelloPayload
    count: int
    stage_mode: Literal["staged", "fused"]
    version: Literal["control-preloaded-v1"] = "control-preloaded-v1"

    def __post_init__(self):
        if (not isinstance(self.base, BatchHelloPayload)
                or not isinstance(self.base.base, LanSegmentedHelloPayload)
                or self.base.base.mode != "lan-segmented-v2"
                or type(self.count) is not int or not 1 <= self.count <= 1000
                or self.stage_mode not in {"staged", "fused"}
                or self.version != "control-preloaded-v1"):
            raise LocalhostCodecError("预送 hello 能力、模式或容量无效")


@dataclass(frozen=True, slots=True)
class PreloadedInitPayload:
    """完整公开清单及其规范摘要；不以摘要代替认证信道。"""

    manifest: PreloadedResourceManifest
    manifest_sha256: str

    def __post_init__(self):
        if (not isinstance(self.manifest, PreloadedResourceManifest)
                or self.manifest.sha256() != self.manifest_sha256):
            raise LocalhostCodecError("预送公开清单摘要不匹配")


@dataclass(frozen=True, slots=True)
class PreloadedBlock:
    """启动期有界原始定宽数值块；JSON 信封仅以规范base64承载这些字节。"""

    receipt: PreloadReceipt
    values: bytes

    def __post_init__(self):
        if (not isinstance(self.receipt, PreloadReceipt) or self.receipt.phase != "block"
                or type(self.values) is not bytes or not 0 < len(self.values) <= 128 * 1024):
            raise LocalhostCodecError("预送块字节、长度或摘要无效")


@dataclass(frozen=True, slots=True)
class PreloadedReadyPayload:
    """完整有限窗口安装屏障；双方均确认后 Client 才启动正式控制。"""

    manifest_sha256: str
    count: int

    def __post_init__(self):
        _required_sha256(self.manifest_sha256, "manifest_sha256")
        if type(self.count) is not int or not 1 <= self.count <= 1000:
            raise LocalhostCodecError("预送就绪数量无效")


@dataclass(frozen=True, slots=True)
class PreloadedInputPayload:
    """只发送当前测量的本方输入和已经确认的清单引用。"""

    manifest_sha256: str
    input_message: InputShareMessage
    slot_index: int
    plan_sha256: str

    def __post_init__(self):
        _required_sha256(self.manifest_sha256, "manifest_sha256")
        _required_sha256(self.plan_sha256, "plan_sha256")
        _require_nonnegative_integer(self.slot_index, "slot_index")
        if (not isinstance(self.input_message, InputShareMessage) or self.slot_index >= 1000
                or self.slot_index != self.input_message.step):
            raise LocalhostCodecError("预送激活必须携带本次输入份额")


@dataclass(frozen=True, slots=True)
class LanSegmentedHelloPayload:
    """新模式独立的段链身份；旧 hello 的字段集合保持不变。"""

    profile_sha256: str
    nonce: str
    run_id: str
    segment_index: int
    global_start: int
    previous_session_id: str | None
    mode: Literal["lan-segmented-v1", "lan-segmented-v2", "lan-full-v3"] = "lan-segmented-v1"

    def __post_init__(self) -> None:
        _required_sha256(self.profile_sha256, "profile_sha256")
        _required_sha256(self.nonce, "nonce")
        _text(self.run_id, "run_id")
        _require_nonnegative_integer(self.segment_index, "segment_index")
        _require_nonnegative_integer(self.global_start, "global_start")
        _require_optional_identity(self.previous_session_id, "previous_session_id")
        if self.mode not in {"lan-segmented-v1", "lan-segmented-v2", "lan-full-v3"}:
            raise LocalhostCodecError("分段 hello 模式错误。")


@dataclass(frozen=True, slots=True)
class SegmentEndPayload:
    """仅步边界可发送的连续前缀结束声明，角色必须独立核对。"""

    run_id: str
    segment_index: int
    global_start: int
    confirmed_count: int
    global_end_exclusive: int
    last_round_id: str | None
    action: Literal["continue", "stop", "switch"]

    def __post_init__(self) -> None:
        _text(self.run_id, "run_id")
        for name in ("segment_index", "global_start", "confirmed_count", "global_end_exclusive"):
            _require_nonnegative_integer(getattr(self, name), name)
        _require_optional_identity(self.last_round_id, "last_round_id")
        if (self.action not in {"continue", "stop", "switch"}
                or self.global_end_exclusive != self.global_start + self.confirmed_count
                or (self.last_round_id is None) != (self.confirmed_count == 0)):
            raise LocalhostCodecError("段结束前缀或末轮无效。")


@dataclass(frozen=True, slots=True)
class SegmentEndReceipt:
    """本方实际提交、资源消费与段链尾；不含任何秘密份额。"""

    role: Literal["P1", "P2"]
    session_id: str
    end: SegmentEndPayload
    cumulative_committed_count: int
    products: int
    truncations: int

    def __post_init__(self) -> None:
        if self.role not in {"P1", "P2"} or not isinstance(self.end, SegmentEndPayload):
            raise LocalhostCodecError("段结束回执角色或类型错误。")
        _text(self.session_id, "session_id")
        for name in ("cumulative_committed_count", "products", "truncations"):
            _require_nonnegative_integer(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class SegmentBeginPayload:
    """v2 同会话下一段的公开屏障，不包含秘密状态或新离线分享。"""

    run_id: str
    segment_index: int
    global_start: int
    controller_epoch: str
    previous_round_id: str | None

    def __post_init__(self) -> None:
        _text(self.run_id, "run_id")
        _require_nonnegative_integer(self.segment_index, "segment_index")
        _require_nonnegative_integer(self.global_start, "global_start")
        _required_sha256(self.controller_epoch, "controller_epoch")
        _require_optional_identity(self.previous_round_id, "previous_round_id")


@dataclass(frozen=True, slots=True)
class LanContinuousSetupPayload:
    """连续模式公开数值 setup；证书不含任何单方秘密。"""

    modulus: int
    integer_bits: int
    fractional_bits: int
    security_parameter: int
    state_payload_bounds: tuple[int, ...]
    input_payload_bounds: tuple[int, ...]
    horizon_steps: int
    modulus_evidence: PrimeModulusEvidence | None


@dataclass(frozen=True, slots=True)
class LanSegmentedSetupV2Payload:
    """公开且无限时域的 v2 setup；block 不是段容量或有限 horizon。"""

    modulus: int
    integer_bits: int
    fractional_bits: int
    security_parameter: int
    state_payload_bounds: tuple[int, ...]
    input_payload_bounds: tuple[int, ...]
    reachability_block_steps: int
    segment_capacity: int
    controller_epoch: str
    proof_sha256: str
    modulus_evidence: PrimeModulusEvidence | None

    def __post_init__(self) -> None:
        if not 1 <= self.segment_capacity <= 1000:
            raise LocalhostCodecError("v2 segment_capacity 超出范围")
        if not 1 <= self.reachability_block_steps <= 128:
            raise LocalhostCodecError("v2 reachability block 超出范围")
        _required_sha256(self.controller_epoch, "controller_epoch")
        _required_sha256(self.proof_sha256, "proof_sha256")


@dataclass(frozen=True, slots=True)
class ClientStepResult:
    """双角色均确认提交后返回给父进程的公开单步结果。"""

    output: np.ndarray[Any, Any]
    round_id: str
    step: int
    products: int
    truncations: int

    def __post_init__(self) -> None:
        if not isinstance(self.output, np.ndarray) or self.output.ndim != 1:
            raise ValueError("Client 输出必须是一维数组。")
        if self.output.dtype.kind != "f" or not np.isfinite(self.output).all():
            raise ValueError("Client 输出必须是有限浮点数组。")
        _text(self.round_id, "round_id")
        _require_nonnegative_integer(self.step, "step")
        _require_nonnegative_integer(self.products, "products")
        _require_nonnegative_integer(self.truncations, "truncations")


@dataclass(frozen=True, slots=True)
class PartyStageResult:
    """仅在 Client 私有通道返回的单方暂存回执和输出 share。"""

    receipt: Protocol3StageReceipt
    share: ControlShareMessage

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, Protocol3StageReceipt) or not isinstance(
            self.share, ControlShareMessage
        ):
            raise TypeError("暂存结果必须包含回执与控制份额。")
        if (
            self.receipt.party,
            self.receipt.session_id,
            self.receipt.round_id,
            self.receipt.step,
        ) != (self.share.sender, self.share.session_id, self.share.round_id, self.share.step):
            raise ValueError("暂存回执与控制份额 identity 不匹配。")


WirePayload = (
    HelloPayload
    | ReadyPayload
    | RemoteErrorPayload
    | np.ndarray[Any, Any]
    | StepResourcePlan
    | Protocol3EndpointCommand
    | ProductMaskPayload
    | Protocol3BatchPayload
    | TruncationMaskPayload
    | P2TruncationPayload
    | Protocol3StageReceipt
    | PartyOfflineMaterial
    | PartyOnlineMaterial
    | ControlShareMessage
    | ClientStepResult
    | PartyStageResult
    | LanHelloPayload
    | BatchHelloPayload
    | LanSetupPayload
    | LanContinuousSetupPayload
    | LanSegmentedSetupV2Payload
    | LanSegmentedHelloPayload
    | SegmentBeginPayload
    | SegmentEndPayload
    | SegmentEndReceipt
    | PreloadedResourceManifest
    | PreloadedHelloPayload
    | PreloadedBlock
    | PreloadedInitPayload
    | PreloadReceipt
    | PreloadedReadyPayload
    | PreloadedInputPayload
    | None
)


@dataclass(frozen=True, slots=True)
class WireEnvelope:
    """固定版本、有方向、单调 sequence 和完整协议 identity 的 wire 信封。"""

    schema_version: int
    kind: WireKind
    sender: WireRole
    recipient: WireRole
    sequence: int
    operation: str
    session_id: str | None
    round_id: str | None
    step: int | None
    resource_id: str | None
    payload: WirePayload = None

    def __post_init__(self) -> None:
        if _integer(self.schema_version, "schema_version") != SCHEMA_VERSION:
            raise LocalhostCodecError("不支持的 localhost schema version。")
        if self.kind not in _KINDS or self.sender not in _ROLES or self.recipient not in _ROLES:
            raise LocalhostCodecError("wire kind 或角色非法。")
        if self.sender == self.recipient:
            raise LocalhostCodecError("wire sender 与 recipient 不能相同。")
        _require_nonnegative_integer(self.sequence, "sequence")
        if self.operation not in _OPERATIONS:
            raise LocalhostCodecError("未知 localhost operation。")
        _require_optional_identity(self.session_id, "session_id")
        _require_optional_identity(self.round_id, "round_id")
        _require_optional_identity(self.resource_id, "resource_id")
        if self.step is not None:
            _require_nonnegative_integer(self.step, "step")
        _validate_payload_contract(self)


def encode_envelope(message: WireEnvelope) -> bytes:
    """将合法信封编码为字段顺序稳定、禁止 NaN 的 UTF-8 JSON。"""
    if not isinstance(message, WireEnvelope):
        raise TypeError("message 必须是 WireEnvelope。")
    payload = {
        "schema_version": message.schema_version,
        "kind": message.kind,
        "sender": message.sender,
        "recipient": message.recipient,
        "sequence": message.sequence,
        "operation": message.operation,
        "session_id": message.session_id,
        "round_id": message.round_id,
        "step": message.step,
        "resource_id": message.resource_id,
        "payload": _encode_value(message.payload),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def decode_envelope(payload: bytes) -> WireEnvelope:
    """严格解析一条 wire 信封，拒绝重复/未知/缺失字段与非规范 payload。"""
    value = _load_json(payload)
    mapping = _mapping(value, "WireEnvelope")
    _exact_fields(
        mapping,
        {
            "schema_version",
            "kind",
            "sender",
            "recipient",
            "sequence",
            "operation",
            "session_id",
            "round_id",
            "step",
            "resource_id",
            "payload",
        },
        "WireEnvelope",
    )
    try:
        return WireEnvelope(
            mapping["schema_version"],
            mapping["kind"],
            mapping["sender"],
            mapping["recipient"],
            mapping["sequence"],
            mapping["operation"],
            mapping["session_id"],
            mapping["round_id"],
            mapping["step"],
            mapping["resource_id"],
            _decode_value(mapping["payload"]),
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, LocalhostCodecError):
            raise
        raise LocalhostCodecError(f"WireEnvelope 字段非法：{error}") from error


def encode_wire_value(value: object) -> bytes:
    """为 codec 单元测试和固定 wire union 编码一个受支持值。"""
    return json.dumps(
        _encode_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def decode_wire_value(payload: bytes) -> object:
    """解码一个受支持值；不接受任意 Python object 或动态类型名。"""
    return _decode_value(_load_json(payload))


def _preloaded_values_size(plan: StepResourcePlan, modulus: int) -> int:
    """固定公开计划的无损数值长度；分配和生成之前即可计算。"""
    if not isinstance(plan, StepResourcePlan) or type(modulus) is not int or modulus < 3:
        raise ValueError("预送计划或模数无效")
    size = ((modulus.bit_length() + 7) // 8) * (3 * plan.triple_count + 2 * plan.truncation_count)
    if not 0 < size <= 512 * 1024:
        raise ValueError("单轮预送数值超出编码预算")
    return size


def _encode_preloaded_values(resources: PartyResources, modulus: int) -> bytes:
    """仅编码本方原材料数值；不传送 owner、lifecycle 或未来输入。"""
    if not isinstance(resources, PartyResources):
        raise TypeError("预送只接受单方资源")
    plan = resources.plan
    size = _preloaded_values_size(plan, modulus)
    if (type(resources.recipient) is not int or resources.recipient not in (0, 1)
            or tuple(item.metadata for item in resources.product_resources) != plan.product_resources
            or tuple(item.metadata for item in resources.state_truncation_resources)
            != plan.state_truncation_resources):
        raise ValueError("预送资源角色或顺序不匹配")
    width = (modulus.bit_length() + 7) // 8
    values = []
    for item in resources.product_resources:
        if type(item.owner) is not int or item.owner != resources.recipient:
            raise ValueError("预送资源角色不匹配")
        values.extend((item.triple.a, item.triple.b, item.triple.c))
    for item in resources.state_truncation_resources:
        if type(item.owner) is not int or item.owner != resources.recipient:
            raise ValueError("预送资源角色不匹配")
        values.extend((item.truncation.r, item.truncation.r_prime))
    encoded = []
    for share in values:
        value = share.value
        if type(value) is not int or not 0 <= value < modulus:
            raise ValueError("预送数值必须是 canonical scalar residue")
        encoded.append(value.to_bytes(width, "big"))
    result = b"".join(encoded)
    if len(result) != size:
        raise ValueError("预送数值长度错误")
    return result


def _decode_preloaded_values(data: bytes, inp: InputShareMessage,
                             plan: StepResourcePlan, modulus: int) -> PartyOnlineMaterial:
    """领取当前轮后才重建单方 DTO，原 protocol recovery 继续拥有生命周期。"""
    if type(data) is not bytes or len(data) != _preloaded_values_size(plan, modulus):
        raise ValueError("预送数值长度错误")
    if not isinstance(inp, InputShareMessage) or type(inp.recipient) is not int or inp.recipient not in (0, 1):
        raise ValueError("预送输入角色无效")
    width = (modulus.bit_length() + 7) // 8
    values = []
    for offset in range(0, len(data), width):
        value = int.from_bytes(data[offset:offset + width], "big")
        if value >= modulus:
            raise ValueError("预送数值必须是 canonical residue")
        values.append(AdditiveShare(value))
    iterator = iter(values)
    return PartyOnlineMaterial(
        inp, plan,
        tuple(ProductResourceMaterial(inp.recipient, item, next(iterator), next(iterator),
                                      next(iterator)) for item in plan.product_resources),
        tuple(TruncationResourceMaterial(inp.recipient, item, next(iterator), next(iterator))
              for item in plan.state_truncation_resources),
    )


def _encode_value(value: object) -> object:
    if isinstance(value, PreloadedHelloPayload):
        return {"type": "preloaded_hello", "base": _encode_value(value.base),
                "count": value.count, "stage_mode": value.stage_mode, "version": value.version}
    if isinstance(value, PreloadedResourceManifest):
        fields = asdict(value)
        fields.update(layout=_encode_value(value.layout), modulus=_decimal(value.modulus))
        return {"type": "preloaded_manifest", **fields, "derived": value.derived()}
    if isinstance(value, PreloadedBlock):
        return {"type": "preloaded_block", "receipt": _encode_value(value.receipt),
                "values": base64.b64encode(value.values).decode("ascii")}
    if isinstance(value, PreloadedInitPayload):
        return {"type": "preloaded_init", "manifest": _encode_value(value.manifest),
                "manifest_sha256": value.manifest_sha256}
    if isinstance(value, PreloadReceipt):
        return {"type": "preload_receipt", **asdict(value)}
    if isinstance(value, PreloadedReadyPayload):
        return {"type": "preloaded_ready", **asdict(value)}
    if isinstance(value, PreloadedInputPayload):
        return {"type": "preloaded_input", "manifest_sha256": value.manifest_sha256,
                "input_message": _encode_value(value.input_message), "slot_index": value.slot_index,
                "plan_sha256": value.plan_sha256}
    if value is None:
        return {"type": "none"}
    if isinstance(value, bool):
        raise TypeError("wire payload 不接受裸 bool。")
    if isinstance(value, Integral):
        return {"type": "bigint", "decimal": str(int(value))}
    if isinstance(value, HelloPayload):
        return {"type": "hello", "nonce": value.nonce, "pid": value.pid}
    if isinstance(value, ReadyPayload):
        return {
            "type": "ready",
            "pid": value.pid,
            "scale_ledger": _encode_value(value.scale_ledger),
            "range_verification": _encode_value(value.range_verification),
            "modulus_verification": _encode_value(value.modulus_verification),
        }
    if isinstance(value, RemoteErrorPayload):
        return {"type": "remote_error", "error_type": value.error_type, "message": value.message}
    if isinstance(value, LanHelloPayload):
        return {
            "type": "lan_hello",
            "profile_sha256": value.profile_sha256,
            "nonce": value.nonce,
            "mode": value.mode,
        }
    if isinstance(value, BatchHelloPayload):
        return {"type": "batch_hello", "capability": value.capability,
                "base": _encode_value(value.base)}
    if isinstance(value, LanSegmentedHelloPayload):
        return {"type": "lan_segmented_hello", **asdict(value)}
    if isinstance(value, SegmentEndPayload):
        return {"type": "segment_end", **asdict(value)}
    if isinstance(value, SegmentEndReceipt):
        return {"type": "segment_end_receipt", **asdict(value), "end": _encode_value(value.end)}
    if isinstance(value, SegmentBeginPayload):
        return {"type": "segment_begin", **asdict(value)}
    if isinstance(value, LanSetupPayload):
        return {
            "type": "lan_setup",
            "modulus": _decimal(value.modulus),
            "integer_bits": value.integer_bits,
            "fractional_bits": value.fractional_bits,
            "security_parameter": value.security_parameter,
            "state_payload_bounds": list(value.state_payload_bounds),
            "input_payload_bounds": list(value.input_payload_bounds),
            "horizon_steps": value.horizon_steps,
        }
    if isinstance(value, LanContinuousSetupPayload):
        return {
            "type": "lan_continuous_setup",
            "modulus": _decimal(value.modulus),
            "integer_bits": value.integer_bits,
            "fractional_bits": value.fractional_bits,
            "security_parameter": value.security_parameter,
            "state_payload_bounds": list(value.state_payload_bounds),
            "input_payload_bounds": list(value.input_payload_bounds),
            "horizon_steps": value.horizon_steps,
            "modulus_evidence": _encode_prime_evidence(value.modulus_evidence),
        }
    if isinstance(value, LanSegmentedSetupV2Payload):
        return {
            "type": "lan_segmented_setup_v2",
            "modulus": _decimal(value.modulus),
            "integer_bits": value.integer_bits,
            "fractional_bits": value.fractional_bits,
            "security_parameter": value.security_parameter,
            "state_payload_bounds": list(value.state_payload_bounds),
            "input_payload_bounds": list(value.input_payload_bounds),
            "reachability_block_steps": value.reachability_block_steps,
            "segment_capacity": value.segment_capacity,
            "controller_epoch": value.controller_epoch,
            "proof_sha256": value.proof_sha256,
            "modulus_evidence": _encode_prime_evidence(value.modulus_evidence),
        }
    if isinstance(value, ClientStepResult):
        return {
            "type": "client_step_result",
            "output": _encode_value(value.output),
            "round_id": value.round_id,
            "step": value.step,
            "products": value.products,
            "truncations": value.truncations,
        }
    if isinstance(value, PartyStageResult):
        return {
            "type": "party_stage_result",
            "receipt": _encode_value(value.receipt),
            "share": _encode_value(value.share),
        }
    if isinstance(value, np.ndarray):
        array = np.asarray(value)
        if array.dtype.kind in "iu":
            return _encode_integer_value(array)
        if array.dtype.kind != "f" or not np.isfinite(array.astype(float)).all():
            raise TypeError("wire float_array 必须只含有限实数。")
        return {
            "type": "float_array",
            "shape": list(array.shape),
            "values": [float(item) for item in array.flat],
        }
    if isinstance(value, AdditiveShare):
        return {"type": "share", "value": _encode_integer_value(value.value)}
    if isinstance(value, ControllerScaleLedger):
        return {
            "type": "scale_ledger",
            **{name: getattr(value, name) for name in value.__dataclass_fields__},
        }
    if isinstance(value, ControllerRangeVerification):
        return {
            "type": "range_verification",
            "proof_mode": value.proof_mode,
            "certificate_sha256": value.certificate_sha256,
            "state_accumulator_bounds": list(value.state_accumulator_bounds),
            "output_accumulator_bounds": list(value.output_accumulator_bounds),
            "centered_modulus_limit": _decimal(value.centered_modulus_limit),
            "maximum_truncation_message": _decimal(value.maximum_truncation_message),
        }
    if isinstance(value, PrimeModulusVerification):
        return {
            "type": "modulus_verification",
            "modulus": _decimal(value.modulus),
            "bit_length": value.bit_length,
            "method": value.method,
            "status": value.status,
            "source": value.source,
            "source_version": value.source_version,
            "certificate_id": value.certificate_id,
            "certificate_sha256": value.certificate_sha256,
        }
    if isinstance(value, ControllerLayout):
        return {
            "type": "controller_layout",
            "state_dimension": value.state_dimension,
            "input_dimension": value.input_dimension,
            "output_dimension": value.output_dimension,
            "scale_ledger": _encode_value(value.scale_ledger),
        }
    if isinstance(value, ControllerShare):
        return {
            "type": "controller_share",
            **{name: _encode_value(getattr(value, name)) for name in ("A", "B", "C", "D")},
        }
    if isinstance(value, PartyOfflineMaterial):
        return {
            "type": "party_offline_material",
            "recipient": value.recipient,
            "session_id": value.session_id,
            "controller": _encode_value(value.controller),
            "initial_state": _encode_value(value.initial_state),
            "layout": _encode_value(value.layout),
        }
    if isinstance(value, InputShareMessage):
        return {
            "type": "input_share",
            "recipient": value.recipient,
            "session_id": value.session_id,
            "round_id": value.round_id,
            "step": value.step,
            "value": _encode_value(value.value),
        }
    if isinstance(value, ResourceMetadata):
        return {
            "type": "resource_metadata",
            "resource_id": value.resource_id,
            "session_id": value.session_id,
            "round_id": value.round_id,
            "step": value.step,
            "kind": value.kind,
            "term": value.term,
            "index": list(value.index),
            "shape": list(value.shape),
            "left_fractional_bits": value.left_fractional_bits,
            "right_fractional_bits": value.right_fractional_bits,
            "output_fractional_bits": value.output_fractional_bits,
        }
    if isinstance(value, StepResourcePlan):
        return {
            "type": "step_resource_plan",
            "session_id": value.session_id,
            "round_id": value.round_id,
            "step": value.step,
            "state_shape": list(value.state_shape),
            "input_shape": list(value.input_shape),
            "output_shape": list(value.output_shape),
            "scale_ledger": _encode_value(value.scale_ledger),
            "product_resources": [_encode_value(item) for item in value.product_resources],
            "state_truncation_resources": [
                _encode_value(item) for item in value.state_truncation_resources
            ],
        }
    if isinstance(value, ProductResourceMaterial):
        return {
            "type": "product_resource_material",
            "owner": value.owner,
            "metadata": _encode_value(value.metadata),
            "a": _encode_value(value.a),
            "b": _encode_value(value.b),
            "c": _encode_value(value.c),
        }
    if isinstance(value, TruncationResourceMaterial):
        return {
            "type": "truncation_resource_material",
            "owner": value.owner,
            "metadata": _encode_value(value.metadata),
            "r": _encode_value(value.r),
            "r_prime": _encode_value(value.r_prime),
        }
    if isinstance(value, PartyOnlineMaterial):
        return {
            "type": "party_online_material",
            "input_message": _encode_value(value.input_message),
            "plan": _encode_value(value.plan),
            "product_resources": [_encode_value(item) for item in value.product_resources],
            "state_truncation_resources": [
                _encode_value(item) for item in value.state_truncation_resources
            ],
        }
    if isinstance(value, ProductMaskPayload):
        return {
            "type": "product_mask",
            "d": _encode_value(value.d),
            "e": _encode_value(value.e),
            "party": value.party,
        }
    if isinstance(value, Protocol3BatchPayload):
        return {
            "type": "protocol3_batch", "version": value.version,
            "phase": value.phase, "plan_sha256": value.plan_sha256,
            "run_id": value.run_id, "epoch_id": value.epoch_id,
            "physical_step": value.physical_step, "batch_index": value.batch_index,
            "resource_ids": list(value.resource_ids),
            "products": [_encode_value(item) for item in value.products],
            "truncations": [_encode_value(item) for item in value.truncations],
        }
    if isinstance(value, TruncationMaskPayload):
        return {
            "type": "truncation_mask",
            "value": _encode_value(value.value),
            "party": value.party,
        }
    if isinstance(value, P2TruncationPayload):
        return {"type": "p2_truncation", "value": _encode_value(value.value)}
    if isinstance(value, Protocol3StageReceipt):
        return {
            "type": "stage_receipt",
            "party": value.party,
            "session_id": value.session_id,
            "round_id": value.round_id,
            "step": value.step,
            "products": value.products,
            "truncations": value.truncations,
        }
    if isinstance(value, Protocol3EndpointCommand):
        return {
            "type": "endpoint_command",
            "operation": value.operation,
            "metadata": _encode_value(value.metadata),
            "product_mask": _encode_value(value.product_mask),
            "truncation_mask": _encode_value(value.truncation_mask),
            "p2_truncation": _encode_value(value.p2_truncation),
        }
    if isinstance(value, ControlShareMessage):
        return {
            "type": "control_share",
            "sender": value.sender,
            "session_id": value.session_id,
            "round_id": value.round_id,
            "step": value.step,
            "fractional_bits": value.fractional_bits,
            "value": _encode_value(value.value),
        }
    raise TypeError(f"不支持的 localhost wire payload：{type(value).__name__}")


def _encode_prime_certificate(value: PocklingtonCertificate) -> dict[str, object]:
    """证书整数用规范十进制字符串编码，避免 JSON 数值精度损失。"""
    return {"candidate": _decimal(value.candidate), "factors": [
        {"prime": _decimal(item.prime), "exponent": item.exponent,
         "witness": _decimal(item.witness),
         "certificate": _encode_prime_certificate(item.certificate)
         if item.certificate is not None else None}
        for item in value.factors
    ]}


def _encode_prime_evidence(value: PrimeModulusEvidence | None) -> object:
    if value is None:
        return None
    return {"method": value.method, "source": value.source,
            "source_version": value.source_version,
            "certificate_id": value.certificate_id,
            "certificate_sha256": value.certificate_sha256,
            "certificate": _encode_prime_certificate(value.certificate)}


def _decode_prime_certificate(value: object) -> PocklingtonCertificate:
    item = _mapping(value, "prime certificate")
    _exact_fields(item, {"candidate", "factors"}, "prime certificate")
    factors = item["factors"]
    if not isinstance(factors, list) or not factors or len(factors) > 1024:
        raise LocalhostCodecError("prime factors 数量非法。")
    decoded = []
    for factor in factors:
        entry = _mapping(factor, "prime factor")
        _exact_fields(entry, {"prime", "exponent", "witness", "certificate"}, "prime factor")
        child = entry["certificate"]
        decoded.append(PocklingtonFactorEvidence(
            _positive_decimal(entry["prime"], "prime"),
            _positive(entry["exponent"], "exponent"),
            _nonnegative_decimal(entry["witness"], "witness"),
            _decode_prime_certificate(child) if child is not None else None,
        ))
    return PocklingtonCertificate(_positive_decimal(item["candidate"], "candidate"),
                                  tuple(decoded))


def _decode_prime_evidence(value: object) -> PrimeModulusEvidence | None:
    if value is None:
        return None
    item = _mapping(value, "prime evidence")
    _exact_fields(item, {"method", "source", "source_version", "certificate_id",
                         "certificate_sha256", "certificate"}, "prime evidence")
    return PrimeModulusEvidence(
        _text(item["method"], "method"), _text(item["source"], "source"),
        _text(item["source_version"], "source_version"),
        _text(item["certificate_id"], "certificate_id"),
        _required_sha256(item["certificate_sha256"], "certificate_sha256"),
        _decode_prime_certificate(item["certificate"]),
    )


def _decode_value(value: object) -> object:
    mapping = _mapping(value, "wire value")
    kind = mapping.get("type")
    if not isinstance(kind, str):
        raise LocalhostCodecError("wire value 缺少字符串 type。")
    if kind == "preloaded_hello":
        _exact_fields(mapping, {"type", "base", "count", "stage_mode", "version"}, kind)
        return PreloadedHelloPayload(_typed(mapping["base"], BatchHelloPayload),
                                      mapping["count"], mapping["stage_mode"], mapping["version"])
    if kind == "preloaded_manifest":
        _exact_fields(mapping, {"type", "derived", *PreloadedResourceManifest.__dataclass_fields__}, kind)
        fields = {name: mapping[name] for name in PreloadedResourceManifest.__dataclass_fields__}
        fields["layout"] = _typed(mapping["layout"], ControllerLayout)
        fields["modulus"] = _positive_decimal(mapping["modulus"], "modulus")
        if not isinstance(mapping["round_ids"], list):
            raise LocalhostCodecError("预送round列表无效")
        fields["round_ids"] = tuple(mapping["round_ids"])
        manifest = PreloadedResourceManifest(**fields)
        derived = _mapping(mapping["derived"], "derived")
        if (derived != manifest.derived() or any(type(v) is not int for v in derived.values())):
            raise LocalhostCodecError("预送公开派生数量、宽度或长度不匹配")
        return manifest
    if kind == "preloaded_init":
        _exact_fields(mapping, {"type", "manifest", "manifest_sha256"}, kind)
        return PreloadedInitPayload(_typed(mapping["manifest"], PreloadedResourceManifest),
                                   mapping["manifest_sha256"])
    if kind in {"preload_receipt", "preloaded_ready"}:
        cls = PreloadReceipt if kind == "preload_receipt" else PreloadedReadyPayload
        _exact_fields(mapping, {"type", *cls.__dataclass_fields__}, kind)
        return cls(**{name: mapping[name] for name in cls.__dataclass_fields__})
    if kind == "preloaded_block":
        _exact_fields(mapping, {"type", "receipt", "values"}, kind)
        text = _text(mapping["values"], "values", maximum=4 * ((128 * 1024 + 2) // 3))
        try:
            data = base64.b64decode(text, validate=True)
        except (ValueError, binascii.Error) as error:
            raise LocalhostCodecError("预送base64无效") from error
        if base64.b64encode(data).decode("ascii") != text:
            raise LocalhostCodecError("预送base64非规范")
        return PreloadedBlock(_typed(mapping["receipt"], PreloadReceipt), data)
    if kind == "preloaded_input":
        _exact_fields(mapping, {"type", "manifest_sha256", "input_message", "slot_index",
                                "plan_sha256"}, kind)
        return PreloadedInputPayload(mapping["manifest_sha256"],
                                      _typed(mapping["input_message"], InputShareMessage),
                                      mapping["slot_index"], mapping["plan_sha256"])
    if kind == "none":
        _exact_fields(mapping, {"type"}, kind)
        return None
    if kind == "bigint":
        _exact_fields(mapping, {"type", "decimal"}, kind)
        return _parse_decimal(mapping["decimal"])
    if kind == "bigint_array":
        return _decode_integer_value(mapping)
    if kind == "hello":
        _exact_fields(mapping, {"type", "nonce", "pid"}, kind)
        return HelloPayload(_text(mapping["nonce"], "nonce"), _positive(mapping["pid"], "pid"))
    if kind == "ready":
        _exact_fields(
            mapping,
            {"type", "pid", "scale_ledger", "range_verification", "modulus_verification"},
            kind,
        )
        return ReadyPayload(
            _positive(mapping["pid"], "pid"),
            _optional_typed(mapping["scale_ledger"], ControllerScaleLedger),
            _optional_typed(mapping["range_verification"], ControllerRangeVerification),
            _optional_typed(mapping["modulus_verification"], PrimeModulusVerification),
        )
    if kind == "remote_error":
        _exact_fields(mapping, {"type", "error_type", "message"}, kind)
        return RemoteErrorPayload(
            _text(mapping["error_type"], "error_type", maximum=128),
            _text(mapping["message"], "message", maximum=1024),
        )
    if kind == "lan_hello":
        _exact_fields(mapping, {"type", "profile_sha256", "nonce", "mode"}, kind)
        mode = _text(mapping["mode"], "mode")
        if mode not in {"lan-single-step-v1", "lan-continuous-v1", "lan-scalar-v3"}:
            raise LocalhostCodecError("不支持的 LAN 模式。")
        return LanHelloPayload(
            _required_sha256(mapping["profile_sha256"], "profile_sha256"),
            _required_sha256(mapping["nonce"], "nonce"),
            mode,
        )
    if kind == "batch_hello":
        _exact_fields(mapping, {"type", "capability", "base"}, kind)
        base = _decode_value(mapping["base"])
        return BatchHelloPayload(base, _text(mapping["capability"], "capability"))
    if kind in {"lan_segmented_hello", "segment_end", "segment_end_receipt",
                "segment_begin"}:
        cls = {"lan_segmented_hello": LanSegmentedHelloPayload,
               "segment_end": SegmentEndPayload, "segment_end_receipt": SegmentEndReceipt,
               "segment_begin": SegmentBeginPayload}[kind]
        _exact_fields(mapping, {"type", *cls.__dataclass_fields__}, kind)
        fields = {name: mapping[name] for name in cls.__dataclass_fields__}
        if cls is SegmentEndReceipt:
            fields["end"] = _typed(mapping["end"], SegmentEndPayload)
        return cls(**fields)
    if kind == "lan_setup":
        _exact_fields(
            mapping,
            {
                "type",
                "modulus",
                "integer_bits",
                "fractional_bits",
                "security_parameter",
                "state_payload_bounds",
                "input_payload_bounds",
                "horizon_steps",
            },
            kind,
        )
        return LanSetupPayload(
            _positive_decimal(mapping["modulus"], "modulus"),
            _positive(mapping["integer_bits"], "integer_bits"),
            _nonnegative(mapping["fractional_bits"], "fractional_bits"),
            _positive(mapping["security_parameter"], "security_parameter"),
            _integer_tuple(
                mapping["state_payload_bounds"], "state_payload_bounds", nonnegative=True
            ),
            _integer_tuple(
                mapping["input_payload_bounds"], "input_payload_bounds", nonnegative=True
            ),
            _positive(mapping["horizon_steps"], "horizon_steps"),
        )
    if kind == "lan_continuous_setup":
        _exact_fields(mapping, {
            "type", "modulus", "integer_bits", "fractional_bits", "security_parameter",
            "state_payload_bounds", "input_payload_bounds", "horizon_steps", "modulus_evidence",
        }, kind)
        return LanContinuousSetupPayload(
            _positive_decimal(mapping["modulus"], "modulus"),
            _positive(mapping["integer_bits"], "integer_bits"),
            _nonnegative(mapping["fractional_bits"], "fractional_bits"),
            _positive(mapping["security_parameter"], "security_parameter"),
            _integer_tuple(mapping["state_payload_bounds"], "state_payload_bounds", nonnegative=True),
            _integer_tuple(mapping["input_payload_bounds"], "input_payload_bounds", nonnegative=True),
            _positive(mapping["horizon_steps"], "horizon_steps"),
            _decode_prime_evidence(mapping["modulus_evidence"]),
        )
    if kind == "lan_segmented_setup_v2":
        _exact_fields(mapping, {"type", *LanSegmentedSetupV2Payload.__dataclass_fields__}, kind)
        return LanSegmentedSetupV2Payload(
            _positive_decimal(mapping["modulus"], "modulus"),
            _positive(mapping["integer_bits"], "integer_bits"),
            _nonnegative(mapping["fractional_bits"], "fractional_bits"),
            _positive(mapping["security_parameter"], "security_parameter"),
            _integer_tuple(mapping["state_payload_bounds"], "state_payload_bounds", nonnegative=True),
            _integer_tuple(mapping["input_payload_bounds"], "input_payload_bounds", nonnegative=True),
            _positive(mapping["reachability_block_steps"], "reachability_block_steps"),
            _positive(mapping["segment_capacity"], "segment_capacity"),
            _required_sha256(mapping["controller_epoch"], "controller_epoch"),
            _required_sha256(mapping["proof_sha256"], "proof_sha256"),
            _decode_prime_evidence(mapping["modulus_evidence"]),
        )
    if kind == "client_step_result":
        _exact_fields(
            mapping, {"type", "output", "round_id", "step", "products", "truncations"}, kind
        )
        return ClientStepResult(
            _typed(mapping["output"], np.ndarray),
            _text(mapping["round_id"], "round_id"),
            _nonnegative(mapping["step"], "step"),
            _nonnegative(mapping["products"], "products"),
            _nonnegative(mapping["truncations"], "truncations"),
        )
    if kind == "party_stage_result":
        _exact_fields(mapping, {"type", "receipt", "share"}, kind)
        return PartyStageResult(
            _typed(mapping["receipt"], Protocol3StageReceipt),
            _typed(mapping["share"], ControlShareMessage),
        )
    if kind == "float_array":
        _exact_fields(mapping, {"type", "shape", "values"}, kind)
        return _decode_float_array(mapping["shape"], mapping["values"])
    if kind == "share":
        _exact_fields(mapping, {"type", "value"}, kind)
        return AdditiveShare(_decode_integer_value(mapping["value"]))
    if kind == "scale_ledger":
        names = set(ControllerScaleLedger.__dataclass_fields__)
        _exact_fields(mapping, {"type", *names}, kind)
        return ControllerScaleLedger(**{name: _nonnegative(mapping[name], name) for name in names})
    if kind == "range_verification":
        fields = {
            "type",
            "proof_mode",
            "certificate_sha256",
            "state_accumulator_bounds",
            "output_accumulator_bounds",
            "centered_modulus_limit",
            "maximum_truncation_message",
        }
        _exact_fields(mapping, fields, kind)
        proof_mode = _text(mapping["proof_mode"], "proof_mode")
        if proof_mode not in _RANGE_PROOF_MODES:
            raise LocalhostCodecError("proof_mode 不属于固定枚举。")
        return ControllerRangeVerification(
            proof_mode,
            _optional_sha256(mapping["certificate_sha256"], "certificate_sha256"),
            _integer_tuple(
                mapping["state_accumulator_bounds"],
                "state_accumulator_bounds",
                nonnegative=True,
            ),
            _integer_tuple(
                mapping["output_accumulator_bounds"],
                "output_accumulator_bounds",
                nonnegative=True,
            ),
            _positive_decimal(mapping["centered_modulus_limit"], "centered_modulus_limit"),
            _nonnegative_decimal(
                mapping["maximum_truncation_message"], "maximum_truncation_message"
            ),
        )
    if kind == "modulus_verification":
        fields = {
            "type",
            "modulus",
            "bit_length",
            "method",
            "status",
            "source",
            "source_version",
            "certificate_id",
            "certificate_sha256",
        }
        _exact_fields(mapping, fields, kind)
        method = _text(mapping["method"], "method")
        status = _text(mapping["status"], "status")
        if method not in _PRIME_VERIFICATION_METHODS or status != "verified":
            raise LocalhostCodecError("模数验证 method 或 status 不属于固定枚举。")
        modulus = _positive_decimal(mapping["modulus"], "modulus")
        bit_length = _positive(mapping["bit_length"], "bit_length")
        if bit_length != modulus.bit_length():
            raise LocalhostCodecError("modulus bit_length 与数值不匹配。")
        return PrimeModulusVerification(
            modulus,
            bit_length,
            method,
            status,
            _text(mapping["source"], "source"),
            _text(mapping["source_version"], "source_version"),
            _optional_text(mapping["certificate_id"], "certificate_id"),
            _optional_sha256(mapping["certificate_sha256"], "certificate_sha256"),
        )
    if kind == "controller_layout":
        _exact_fields(
            mapping,
            {"type", "state_dimension", "input_dimension", "output_dimension", "scale_ledger"},
            kind,
        )
        return ControllerLayout(
            _nonnegative(mapping["state_dimension"], "state_dimension"),
            _positive(mapping["input_dimension"], "input_dimension"),
            _positive(mapping["output_dimension"], "output_dimension"),
            _typed(mapping["scale_ledger"], ControllerScaleLedger),
        )
    if kind == "controller_share":
        _exact_fields(mapping, {"type", "A", "B", "C", "D"}, kind)
        return ControllerShare(
            *(_typed(mapping[name], AdditiveShare) for name in ("A", "B", "C", "D"))
        )
    if kind == "party_offline_material":
        _exact_fields(
            mapping,
            {"type", "recipient", "session_id", "controller", "initial_state", "layout"},
            kind,
        )
        return PartyOfflineMaterial(
            _party(mapping["recipient"]),
            _text(mapping["session_id"], "session_id"),
            _typed(mapping["controller"], ControllerShare),
            _typed(mapping["initial_state"], AdditiveShare),
            _typed(mapping["layout"], ControllerLayout),
        )
    if kind == "input_share":
        _exact_fields(
            mapping,
            {"type", "recipient", "session_id", "round_id", "step", "value"},
            kind,
        )
        return InputShareMessage(
            _party(mapping["recipient"]),
            _text(mapping["session_id"], "session_id"),
            _text(mapping["round_id"], "round_id"),
            _nonnegative(mapping["step"], "step"),
            _typed(mapping["value"], AdditiveShare),
        )
    if kind == "resource_metadata":
        fields = {
            "type",
            "resource_id",
            "session_id",
            "round_id",
            "step",
            "kind",
            "term",
            "index",
            "shape",
            "left_fractional_bits",
            "right_fractional_bits",
            "output_fractional_bits",
        }
        _exact_fields(mapping, fields, kind)
        right = mapping["right_fractional_bits"]
        return ResourceMetadata(
            _text(mapping["resource_id"], "resource_id"),
            _text(mapping["session_id"], "session_id"),
            _text(mapping["round_id"], "round_id"),
            _nonnegative(mapping["step"], "step"),
            _text(mapping["kind"], "kind"),
            _text(mapping["term"], "term"),
            _integer_tuple(mapping["index"], "index", nonnegative=True),
            _integer_tuple(mapping["shape"], "shape", nonnegative=True),
            _nonnegative(mapping["left_fractional_bits"], "left_fractional_bits"),
            None if right is None else _nonnegative(right, "right_fractional_bits"),
            _nonnegative(mapping["output_fractional_bits"], "output_fractional_bits"),
        )
    if kind == "step_resource_plan":
        fields = {
            "type",
            "session_id",
            "round_id",
            "step",
            "state_shape",
            "input_shape",
            "output_shape",
            "scale_ledger",
            "product_resources",
            "state_truncation_resources",
        }
        _exact_fields(mapping, fields, kind)
        return StepResourcePlan(
            _text(mapping["session_id"], "session_id"),
            _text(mapping["round_id"], "round_id"),
            _nonnegative(mapping["step"], "step"),
            _shape1(mapping["state_shape"], "state_shape"),
            _shape1(mapping["input_shape"], "input_shape"),
            _shape1(mapping["output_shape"], "output_shape"),
            _typed(mapping["scale_ledger"], ControllerScaleLedger),
            _typed_tuple(mapping["product_resources"], ResourceMetadata),
            _typed_tuple(mapping["state_truncation_resources"], ResourceMetadata),
        )
    if kind == "product_resource_material":
        _exact_fields(mapping, {"type", "owner", "metadata", "a", "b", "c"}, kind)
        return ProductResourceMaterial(
            _party(mapping["owner"]),
            _typed(mapping["metadata"], ResourceMetadata),
            _typed(mapping["a"], AdditiveShare),
            _typed(mapping["b"], AdditiveShare),
            _typed(mapping["c"], AdditiveShare),
        )
    if kind == "truncation_resource_material":
        _exact_fields(mapping, {"type", "owner", "metadata", "r", "r_prime"}, kind)
        return TruncationResourceMaterial(
            _party(mapping["owner"]),
            _typed(mapping["metadata"], ResourceMetadata),
            _typed(mapping["r"], AdditiveShare),
            _typed(mapping["r_prime"], AdditiveShare),
        )
    if kind == "party_online_material":
        _exact_fields(
            mapping,
            {"type", "input_message", "plan", "product_resources", "state_truncation_resources"},
            kind,
        )
        return PartyOnlineMaterial(
            _typed(mapping["input_message"], InputShareMessage),
            _typed(mapping["plan"], StepResourcePlan),
            _typed_tuple(mapping["product_resources"], ProductResourceMaterial),
            _typed_tuple(mapping["state_truncation_resources"], TruncationResourceMaterial),
        )
    if kind == "product_mask":
        _exact_fields(mapping, {"type", "d", "e", "party"}, kind)
        return ProductMaskPayload(
            _typed(mapping["d"], AdditiveShare),
            _typed(mapping["e"], AdditiveShare),
            _party(mapping["party"]),
        )
    if kind == "protocol3_batch":
        _exact_fields(mapping, {"type", "version", "phase", "plan_sha256", "run_id",
                                "epoch_id", "physical_step", "batch_index", "resource_ids",
                                "products", "truncations"}, kind)
        ids = mapping["resource_ids"]
        if not isinstance(ids, list) or len(ids) > 1_000_000:
            raise LocalhostCodecError("批次资源列表无效")
        return Protocol3BatchPayload(
            _text(mapping["phase"], "phase"),
            _required_sha256(mapping["plan_sha256"], "plan_sha256"),
            _optional_text(mapping["run_id"], "run_id"),
            _text(mapping["epoch_id"], "epoch_id"),
            None if mapping["physical_step"] is None else
            _nonnegative(mapping["physical_step"], "physical_step"),
            _nonnegative(mapping["batch_index"], "batch_index"),
            tuple(_text(item, "resource_id") for item in ids),
            _typed_tuple(mapping["products"], ProductMaskPayload),
            _typed_tuple(mapping["truncations"], P2TruncationPayload),
            _text(mapping["version"], "version"),
        )
    if kind == "truncation_mask":
        _exact_fields(mapping, {"type", "value", "party"}, kind)
        return TruncationMaskPayload(
            _typed(mapping["value"], AdditiveShare), _party(mapping["party"])
        )
    if kind == "p2_truncation":
        _exact_fields(mapping, {"type", "value"}, kind)
        return P2TruncationPayload(_typed(mapping["value"], AdditiveShare))
    if kind == "stage_receipt":
        _exact_fields(
            mapping,
            {"type", "party", "session_id", "round_id", "step", "products", "truncations"},
            kind,
        )
        return Protocol3StageReceipt(
            _party(mapping["party"]),
            _text(mapping["session_id"], "session_id"),
            _text(mapping["round_id"], "round_id"),
            _nonnegative(mapping["step"], "step"),
            _nonnegative(mapping["products"], "products"),
            _nonnegative(mapping["truncations"], "truncations"),
        )
    if kind == "endpoint_command":
        _exact_fields(
            mapping,
            {"type", "operation", "metadata", "product_mask", "truncation_mask", "p2_truncation"},
            kind,
        )
        return Protocol3EndpointCommand(
            _text(mapping["operation"], "operation"),
            _optional_typed(mapping["metadata"], ResourceMetadata),
            _optional_typed(mapping["product_mask"], ProductMaskPayload),
            _optional_typed(mapping["truncation_mask"], TruncationMaskPayload),
            _optional_typed(mapping["p2_truncation"], P2TruncationPayload),
        )
    if kind == "control_share":
        _exact_fields(
            mapping,
            {"type", "sender", "session_id", "round_id", "step", "fractional_bits", "value"},
            kind,
        )
        return ControlShareMessage(
            _party(mapping["sender"]),
            _text(mapping["session_id"], "session_id"),
            _text(mapping["round_id"], "round_id"),
            _nonnegative(mapping["step"], "step"),
            _nonnegative(mapping["fractional_bits"], "fractional_bits"),
            _typed(mapping["value"], AdditiveShare),
        )
    raise LocalhostCodecError(f"未知 wire value type：{kind}")


def _validate_payload_contract(message: WireEnvelope) -> None:
    key = (message.kind, message.operation)
    payload = message.payload
    direction = (message.sender, message.recipient)
    to_supervisor = {("Client", "Supervisor"), ("P1", "Supervisor"), ("P2", "Supervisor")}
    to_party = {("Client", "P1"), ("Client", "P2")}
    to_client = {("P1", "Client"), ("P2", "Client")}
    peer = {("P1", "P2"), ("P2", "P1")}
    allowed: dict[tuple[str, str], set[tuple[str, str]]] = {
        ("hello", "hello"): to_supervisor | to_party | peer,
        ("ready", "ready"): to_supervisor,
        ("error", "ready"): to_supervisor,
        ("hello", "lan_hello"): to_party | to_client | peer,
        ("request", "lan_ready"): to_party,
        ("reply", "lan_ready"): to_client,
        ("error", "lan_ready"): to_client,
        ("request", "lan_setup"): to_party,
        ("reply", "lan_setup"): to_client,
        ("error", "lan_setup"): to_client,
        ("request", "segment_end"): to_party,
        ("reply", "segment_end"): to_client,
        ("error", "segment_end"): to_client,
        ("request", "segment_begin"): to_party,
        ("reply", "segment_begin"): to_client,
        ("error", "segment_begin"): to_client,
        ("request", "step"): {("Supervisor", "Client")},
        ("reply", "step"): {("Client", "Supervisor")},
        ("error", "step"): {("Client", "Supervisor")},
        ("request", "offline"): to_party,
        ("reply", "offline"): to_client,
        ("error", "offline"): to_client,
        ("request", "online"): to_party,
        ("reply", "online"): to_client,
        ("error", "online"): to_client,
        ("request", "endpoint"): to_party,
        ("reply", "endpoint"): to_client,
        ("error", "endpoint"): to_client,
        ("request", "peer_product"): peer,
        ("request", "peer_truncation"): {("P2", "P1")},
        ("request", "peer_batch"): peer,
        ("shutdown", "shutdown"): {("Supervisor", "Client")} | to_party,
        ("reply", "shutdown"): {("Client", "Supervisor")} | to_client,
        ("error", "shutdown"): {("Client", "Supervisor")} | to_client,
    }
    for operation in ("preload_init", "preload_block", "preload_seal", "activate", "activate_stage"):
        allowed[("request", operation)] = to_party
        allowed[("reply", operation)] = to_client
        allowed[("error", operation)] = to_client
    if direction not in allowed.get(key, set()):
        raise LocalhostCodecError("wire kind/operation 与角色方向组合非法。")
    if message.operation == "peer_product" and (
        message.kind != "request" or {message.sender, message.recipient} != {"P1", "P2"}
    ):
        raise LocalhostCodecError("Protocol 1 peer 消息必须在 P1 与 P2 之间请求发送。")
    if message.operation == "peer_truncation" and (
        message.kind != "request" or (message.sender, message.recipient) != ("P2", "P1")
    ):
        raise LocalhostCodecError("Protocol 2 peer 消息必须由 P2 发送给 P1。")
    expected: tuple[type[object], ...] | None
    if key == ("hello", "hello"):
        expected = (HelloPayload, BatchHelloPayload)
    elif key == ("hello", "lan_hello"):
        expected = (LanHelloPayload, LanSegmentedHelloPayload, BatchHelloPayload,
                    PreloadedHelloPayload)
    elif key == ("ready", "ready"):
        expected = (ReadyPayload,)
    elif message.kind == "error":
        expected = (RemoteErrorPayload,)
    elif message.operation == "preload_init":
        expected = (PreloadedInitPayload,) if message.kind == "request" else (PreloadReceipt,)
    elif message.operation == "preload_block":
        expected = (PreloadedBlock,) if message.kind == "request" else (PreloadReceipt,)
    elif message.operation == "preload_seal":
        expected = (PreloadedReadyPayload,) if message.kind == "request" else (PreloadReceipt,)
    elif message.operation in {"activate", "activate_stage"}:
        expected = ((PreloadedInputPayload,) if message.kind == "request" else
                    (PartyStageResult,) if message.operation == "activate_stage" else (type(None),))
    elif key == ("request", "step"):
        expected = (np.ndarray,)
    elif key == ("reply", "step"):
        expected = (ClientStepResult,)
    elif key == ("request", "endpoint"):
        expected = (Protocol3EndpointCommand,)
    elif key == ("reply", "endpoint"):
        expected = (PartyStageResult, type(None))
    elif key == ("request", "peer_product"):
        expected = (ProductMaskPayload,)
    elif key == ("request", "peer_truncation"):
        expected = (P2TruncationPayload,)
    elif key == ("request", "peer_batch"):
        expected = (Protocol3BatchPayload,)
    elif key == ("request", "offline"):
        expected = (PartyOfflineMaterial,)
    elif key == ("request", "lan_setup"):
        expected = (LanSetupPayload, LanContinuousSetupPayload, LanSegmentedSetupV2Payload)
    elif message.operation == "segment_begin" and message.kind in {"request", "reply"}:
        expected = (SegmentBeginPayload,)
    elif key == ("request", "segment_end"):
        expected = (SegmentEndPayload,)
    elif key == ("reply", "segment_end"):
        expected = (SegmentEndReceipt,)
    elif key == ("request", "online"):
        expected = (PartyOnlineMaterial,)
    elif (
        key
        in {
            ("request", "lan_ready"),
            ("reply", "lan_ready"),
            ("reply", "lan_setup"),
            ("reply", "offline"),
            ("reply", "online"),
            ("reply", "shutdown"),
        }
        or message.kind == "shutdown"
    ):
        expected = (type(None),)
    else:
        expected = None
    if expected is None or not isinstance(payload, expected):
        raise LocalhostCodecError("wire kind/operation 与 payload 类型组合非法。")
    if isinstance(payload, BatchHelloPayload) and (
        message.operation == "hello" and not isinstance(payload.base, HelloPayload)
        or message.operation == "lan_hello" and not isinstance(
            payload.base, (LanHelloPayload, LanSegmentedHelloPayload)
        )
    ):
        raise LocalhostCodecError("批量 hello 与原握手模式不匹配")
    if (message.operation == "peer_batch" and isinstance(payload, Protocol3BatchPayload)
            and (message.round_id is None or message.step is None
                 or message.resource_id is not None
                 or payload.phase == "truncation" and direction != ("P2", "P1")
                 or payload.batch_index != {"product": 0, "product_complete": 1,
                                            "truncation": 2, "state_complete": 3}[payload.phase])):
        raise LocalhostCodecError("Protocol 3 批次方向、阶段或身份非法")
    if message.operation in {"segment_end", "segment_begin", "preload_init", "preload_seal"} and (
        message.session_id is None or message.round_id is not None
        or message.step is not None or message.resource_id is not None
        or (isinstance(payload, SegmentEndReceipt)
            and (payload.role != message.sender or payload.session_id != message.session_id))
    ):
        raise LocalhostCodecError("段结束回执身份不符或携带 round identity。")
    if message.operation == "endpoint" and isinstance(payload, Protocol3EndpointCommand):
        expected_resource = payload.metadata.resource_id if payload.metadata is not None else None
        if message.resource_id != expected_resource:
            raise LocalhostCodecError("endpoint envelope 与 command resource identity 不匹配。")
    if (
        message.operation == "step"
        and isinstance(payload, ClientStepResult)
        and (payload.step != message.step or message.round_id is not None)
    ):
        raise LocalhostCodecError("Client 单步结果与信封 step 不匹配。")
    if (
        message.operation in {"endpoint", "activate", "activate_stage"}
        and isinstance(payload, PartyStageResult)
        and (
            direction[0] not in {"P1", "P2"}
            or payload.receipt.party != (0 if direction[0] == "P1" else 1)
        )
    ):
        raise LocalhostCodecError("暂存结果的角色不匹配。")
    if (
        message.operation in {"endpoint", "activate", "activate_stage"}
        and isinstance(payload, PartyStageResult)
        and (
            (payload.receipt.session_id, payload.receipt.round_id, payload.receipt.step)
            != (message.session_id, message.round_id, message.step)
            or message.resource_id is not None
        )
    ):
        raise LocalhostCodecError("暂存结果与信封 round identity 不匹配。")
    if message.operation in {"activate", "activate_stage"} and isinstance(payload, PreloadedInputPayload):
        inp = payload.input_message
        if (message.session_id, message.round_id, message.step, message.resource_id) != (
            inp.session_id, inp.round_id, inp.step, None,
        ) or inp.recipient != (0 if message.recipient == "P1" else 1):
            raise LocalhostCodecError("激活信封与本次输入身份不匹配")
    if isinstance(payload, PreloadedInitPayload) and message.session_id != payload.manifest.session_id:
        raise LocalhostCodecError("预送manifest与信封session不匹配")
    if isinstance(payload, PreloadReceipt) and message.kind == "reply" and (
        payload.party != (0 if message.sender == "P1" else 1)
        or message.operation != "preload_" + payload.phase
        or message.step != payload.first_step
    ):
        raise LocalhostCodecError("预送回执与信封角色、阶段或区间不匹配")
    if message.operation == "preload_block" and (
        message.session_id is None or message.round_id is not None or message.resource_id is not None
        or isinstance(payload, PreloadedBlock) and (
            message.step != payload.receipt.first_step
            or payload.receipt.party != (0 if message.recipient == "P1" else 1))
    ):
        raise LocalhostCodecError("预送块信封身份不匹配")


def _load_json(payload: bytes) -> object:
    if not isinstance(payload, bytes):
        raise TypeError("JSON payload 必须是 bytes。")

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise LocalhostCodecError(f"JSON 字段重复：{key}")
            result[key] = value
        return result

    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=lambda token: _raise_constant(token),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalhostCodecError("wire payload 不是合法 UTF-8 JSON。") from error
    _check_json_budget(value, 0)
    return value


def _raise_constant(token: str) -> object:
    raise LocalhostCodecError(f"JSON 不允许常量：{token}")


def _check_json_budget(value: object, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise LocalhostCodecError("JSON 嵌套深度超过上限。")
    if isinstance(value, dict):
        if len(value) > 64:
            raise LocalhostCodecError("JSON object 字段数超过上限。")
        for item in value.values():
            _check_json_budget(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > _MAX_ARRAY_ITEMS:
            raise LocalhostCodecError("JSON array 元素数超过上限。")
        for item in value:
            _check_json_budget(item, depth + 1)


def _encode_integer_value(value: object) -> object:
    array = np.asarray(value, dtype=object)
    if array.ndim == 0:
        return {"type": "bigint", "decimal": _decimal(array.item())}
    if array.size > _MAX_ARRAY_ITEMS:
        raise LocalhostCodecError("bigint_array 元素数超过上限。")
    return {
        "type": "bigint_array",
        "shape": list(array.shape),
        "values": [_decimal(item) for item in array.flat],
    }


def _decode_integer_value(value: object) -> int | np.ndarray:
    mapping = _mapping(value, "integer value")
    kind = mapping.get("type")
    if kind == "bigint":
        _exact_fields(mapping, {"type", "decimal"}, "bigint")
        return _parse_decimal(mapping["decimal"])
    if kind != "bigint_array":
        raise LocalhostCodecError("share value 必须是 bigint 或 bigint_array。")
    _exact_fields(mapping, {"type", "shape", "values"}, "bigint_array")
    shape = _shape(mapping["shape"], "shape")
    values = mapping["values"]
    if not isinstance(values, list) or len(values) != prod(shape):
        raise LocalhostCodecError("bigint_array shape 与 values 数量不匹配。")
    result = np.empty(shape, dtype=object)
    for index, item in zip(np.ndindex(shape), values, strict=True):
        result[index] = _parse_decimal(item)
    return result


def _decode_float_array(shape_value: object, values_value: object) -> np.ndarray:
    shape = _shape(shape_value, "shape")
    if not isinstance(values_value, list) or len(values_value) != prod(shape):
        raise LocalhostCodecError("float_array shape 与 values 数量不匹配。")
    values: list[float] = []
    for item in values_value:
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not isfinite(float(item))
        ):
            raise LocalhostCodecError("float_array 只允许有限实数。")
        values.append(float(item))
    return np.asarray(values, dtype=float).reshape(shape)


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LocalhostCodecError(f"{name} 必须是 JSON object。")
    return value


def _exact_fields(mapping: dict[str, object], fields: set[str], name: str) -> None:
    if set(mapping) != fields:
        raise LocalhostCodecError(f"{name} 字段集合不匹配。")


def _typed(value: object, expected: type[Any]) -> Any:
    decoded = _decode_value(value)
    if not isinstance(decoded, expected):
        raise LocalhostCodecError(f"wire value 必须解码为 {expected.__name__}。")
    return decoded


def _optional_typed(value: object, expected: type[Any]) -> Any:
    decoded = _decode_value(value)
    if decoded is not None and not isinstance(decoded, expected):
        raise LocalhostCodecError(f"wire value 必须解码为 {expected.__name__} 或 None。")
    return decoded


def _typed_tuple(value: object, expected: type[Any]) -> tuple[Any, ...]:
    if not isinstance(value, list) or len(value) > _MAX_ARRAY_ITEMS:
        raise LocalhostCodecError("wire tuple 必须是有界 JSON array。")
    return tuple(_typed(item, expected) for item in value)


def _decimal(value: object) -> str:
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)):
        raise TypeError("bigint 必须是整数。")
    return str(int(value))


def _parse_decimal(value: object) -> int:
    if not isinstance(value, str) or len(value) > _MAX_INTEGER_DIGITS:
        raise LocalhostCodecError("bigint decimal 必须是有界字符串。")
    if _CANONICAL_INTEGER.fullmatch(value) is None:
        raise LocalhostCodecError("bigint decimal 不是规范整数。")
    return int(value)


def _nonnegative_decimal(value: object, name: str) -> int:
    integer = _parse_decimal(value)
    if integer < 0:
        raise LocalhostCodecError(f"{name} 必须是非负整数。")
    return integer


def _positive_decimal(value: object, name: str) -> int:
    integer = _parse_decimal(value)
    if integer <= 0:
        raise LocalhostCodecError(f"{name} 必须是正整数。")
    return integer


def _shape(value: object, name: str) -> tuple[int, ...]:
    shape = _integer_tuple(value, name, nonnegative=True)
    if len(shape) > 8 or prod(shape) > _MAX_ARRAY_ITEMS:
        raise LocalhostCodecError(f"{name} 超过维度或元素预算。")
    return shape


def _shape1(value: object, name: str) -> tuple[int]:
    shape = _shape(value, name)
    if len(shape) != 1:
        raise LocalhostCodecError(f"{name} 必须是一维 shape。")
    return shape  # type: ignore[return-value]


def _integer_tuple(value: object, name: str, *, nonnegative: bool = False) -> tuple[int, ...]:
    if not isinstance(value, list) or len(value) > _MAX_ARRAY_ITEMS:
        raise LocalhostCodecError(f"{name} 必须是有界整数 array。")
    result: list[int] = []
    for item in value:
        integer = _nonnegative(item, name) if nonnegative else _integer(item, name)
        result.append(integer)
    return tuple(result)


def _party(value: object) -> Literal[0, 1]:
    integer = _nonnegative(value, "party")
    if integer not in {0, 1}:
        raise LocalhostCodecError("party 必须是 0 或 1。")
    return integer  # type: ignore[return-value]


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LocalhostCodecError(f"{name} 必须是整数。")
    return value


def _nonnegative(value: object, name: str) -> int:
    integer = _integer(value, name)
    if integer < 0:
        raise LocalhostCodecError(f"{name} 必须是非负整数。")
    return integer


def _positive(value: object, name: str) -> int:
    integer = _integer(value, name)
    if integer <= 0:
        raise LocalhostCodecError(f"{name} 必须是正整数。")
    return integer


def _text(value: object, name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise LocalhostCodecError(f"{name} 必须是长度 1..{maximum} 的字符串。")
    return value


def _optional_text(value: object, name: str) -> str | None:
    return None if value is None else _text(value, name)


def _optional_sha256(value: object, name: str) -> str | None:
    if value is None:
        return None
    digest = _text(value, name, maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise LocalhostCodecError(f"{name} 必须是 64 位小写十六进制字符串。")
    return digest


def _required_sha256(value: object, name: str) -> str:
    digest = _optional_sha256(value, name)
    if digest is None:
        raise LocalhostCodecError(f"{name} 必须是 SHA-256 摘要。")
    return digest


def _require_nonnegative_integer(value: object, name: str) -> None:
    _nonnegative(value, name)


def _require_optional_identity(value: object, name: str) -> None:
    if value is not None:
        _text(value, name)


@dataclass(frozen=True, slots=True)
class ScalarSetupV3:
    """固定算术拓扑及已认证素数的公开配置；常量数值从不出现于 setup。"""

    program: ScalarProgram
    modulus: int
    fractional_bits: int
    security_parameter: int
    modulus_evidence: PrimeModulusEvidence | None


@dataclass(frozen=True, slots=True)
class ScalarStageV3:
    """单方已算完一轮的输出份额与实际消费数。"""

    output_share: int
    products: int
    truncations: int


@dataclass(frozen=True, slots=True)
class ScalarLayerPayloadV1:
    """v3 会话内的新层帧；仅含公开门身份与原协议遮蔽整数。"""

    phase: Literal["product", "truncation", "complete"]
    program_sha256: str
    layer_index: int
    resource_ids: tuple[str, ...]
    values: tuple[tuple[int, ...], ...] = ()
    version: Literal["control-batch-v1"] = "control-batch-v1"

    def __post_init__(self) -> None:
        width = {"product": 2, "truncation": 1, "complete": 0}.get(self.phase)
        if (width is None or self.version != "control-batch-v1"
                or type(self.layer_index) is not int or self.layer_index < 0
                or not isinstance(self.program_sha256, str)
                or len(self.program_sha256) != 64
                or not isinstance(self.resource_ids, tuple)
                or len(self.resource_ids) > 256
                or any(not isinstance(item, str) or not item for item in self.resource_ids)
                or len(set(self.resource_ids)) != len(self.resource_ids)
                or not isinstance(self.values, tuple)
                or len(self.values) != (0 if width == 0 else len(self.resource_ids))
                or any(not isinstance(row, tuple) or len(row) != width
                       or any(type(value) is not int or value < 0 for value in row)
                       for row in self.values)):
            raise LocalhostCodecError("标量层批次 shape、身份或整数无效")


@dataclass(frozen=True, slots=True)
class ScalarFrameV3:
    """v3 算术消息统一绑定角色、run、epoch、session 与物理/局部步。"""

    sender: Literal["Client", "P1", "P2"]
    recipient: Literal["Client", "P1", "P2"]
    run_id: str
    epoch_id: str
    session_id: str
    physical_step: int
    local_step: int
    round_id: str | None
    resource_id: str | None
    operation: str
    payload: object


_SCALAR_OPERATIONS = {
    "setup", "ready", "material", "compute", "result", "commit", "committed",
    "end", "ended", "peer_product", "peer_truncation", "peer_complete", "peer_layer",
}


def encode_scalar_frame_v3(frame: ScalarFrameV3) -> bytes:
    """严格编码 v3 消息；大整数一律十进制字符串，绝不使用 pickle。"""
    if not isinstance(frame, ScalarFrameV3):
        raise TypeError("v3 frame 类型无效")
    _validate_scalar_frame_v3(frame)
    payload = frame.payload
    if isinstance(payload, ScalarSetupV3):
        body: object = {
            "program": {
                "inputs": list(payload.program.inputs),
                "constants": [name for name, _ in payload.program.constants],
                "gates": [[g.name, g.operation, g.left, g.right] for g in payload.program.gates],
                "output": payload.program.output,
            },
            "modulus": _decimal(payload.modulus),
            "fractional_bits": payload.fractional_bits,
            "security_parameter": payload.security_parameter,
            "modulus_evidence": _encode_prime_evidence(payload.modulus_evidence),
        }
    elif isinstance(payload, ScalarPartyMaterial):
        body = {
            "party": payload.party,
            "round_id": payload.round_id,
            "step": payload.step,
            "program_sha256": payload.program_sha256,
            "values": [[name, _decimal(value)] for name, value in payload.values],
            "gates": [
                [gate.gate, gate.resource_id, *(_decimal(value) for value in
                 (gate.a, gate.b, gate.c, gate.r, gate.r_prime))]
                for gate in payload.gates
            ],
        }
    elif isinstance(payload, ScalarStageV3):
        body = {"output_share": _decimal(payload.output_share),
                "products": payload.products, "truncations": payload.truncations}
    elif isinstance(payload, ScalarLayerPayloadV1):
        body = {"version": payload.version, "phase": payload.phase,
                "program_sha256": payload.program_sha256,
                "layer_index": payload.layer_index,
                "resource_ids": list(payload.resource_ids),
                "values": [[_decimal(value) for value in row] for row in payload.values]}
    elif isinstance(payload, tuple):
        body = [_decimal(value) for value in payload]
    elif isinstance(payload, int):
        body = _decimal(payload)
    else:
        body = payload
    content = {
        "schema": "scalar-v3",
        "sender": frame.sender,
        "recipient": frame.recipient,
        "run_id": frame.run_id,
        "epoch_id": frame.epoch_id,
        "session_id": frame.session_id,
        "physical_step": frame.physical_step,
        "local_step": frame.local_step,
        "round_id": frame.round_id,
        "resource_id": frame.resource_id,
        "operation": frame.operation,
        "payload": body,
    }
    return json.dumps(content, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def decode_scalar_frame_v3(encoded: bytes) -> ScalarFrameV3:
    """白名单解析 v3，拒绝多余字段、非规范整数和伪造角色方向。"""
    mapping = _mapping(_load_json(encoded), "scalar-v3 frame")
    _exact_fields(mapping, {"schema", "sender", "recipient", "run_id", "epoch_id",
                            "session_id", "physical_step", "local_step", "round_id",
                            "resource_id", "operation", "payload"}, "scalar-v3 frame")
    if mapping["schema"] != "scalar-v3":
        raise LocalhostCodecError("v3 schema 错误")
    operation = _text(mapping["operation"], "operation")
    raw = mapping["payload"]
    if operation == "setup":
        setup = _mapping(raw, "setup")
        _exact_fields(setup, {"program", "modulus", "fractional_bits",
                              "security_parameter", "modulus_evidence"}, "scalar setup")
        public = _mapping(setup["program"], "program")
        _exact_fields(public, {"inputs", "constants", "gates", "output"}, "scalar program")
        if not isinstance(public["inputs"], list) or not isinstance(public["constants"], list):
            raise LocalhostCodecError("v3 程序输入/常量列表无效")
        if not isinstance(public["gates"], list) or len(public["gates"]) > 256:
            raise LocalhostCodecError("v3 门列表无效")
        gates = []
        for item in public["gates"]:
            if not isinstance(item, list) or len(item) != 4:
                raise LocalhostCodecError("v3 门字段无效")
            gates.append(ScalarGate(*(_text(value, "gate") for value in item)))
        program = ScalarProgram(
            tuple(_text(value, "input") for value in public["inputs"]),
            tuple((_text(value, "constant"), Fraction(0)) for value in public["constants"]),
            tuple(gates), _text(public["output"], "output"),
        )
        payload: object = ScalarSetupV3(
            program, _parse_decimal(setup["modulus"]),
            _positive(setup["fractional_bits"], "fractional_bits"),
            _positive(setup["security_parameter"], "security_parameter"),
            _decode_prime_evidence(setup["modulus_evidence"]),
        )
    elif operation == "material":
        material = _mapping(raw, "material")
        _exact_fields(material, {"party", "round_id", "step", "program_sha256",
                                 "values", "gates"}, "scalar material")
        if (not isinstance(material["values"], list) or len(material["values"]) > 256
                or not isinstance(material["gates"], list) or len(material["gates"]) > 256):
            raise LocalhostCodecError("v3 材料列表无效")
        values = []
        for item in material["values"]:
            if not isinstance(item, list) or len(item) != 2:
                raise LocalhostCodecError("v3 数值份额字段无效")
            values.append((_text(item[0], "value name"), _parse_decimal(item[1])))
        resources = []
        for item in material["gates"]:
            if not isinstance(item, list) or len(item) != 7:
                raise LocalhostCodecError("v3 门材料字段无效")
            resources.append(ScalarGateMaterial(
                _text(item[0], "gate"), _text(item[1], "resource_id"),
                *(_parse_decimal(value) for value in item[2:]),
            ))
        payload = ScalarPartyMaterial(
            _party(material["party"]), _text(material["round_id"], "round_id"),
            _nonnegative(material["step"], "step"),
            _required_sha256(material["program_sha256"], "program_sha256"),
            tuple(values), tuple(resources),
        )
    elif operation == "result":
        result = _mapping(raw, "result")
        _exact_fields(result, {"output_share", "products", "truncations"}, "scalar result")
        payload = ScalarStageV3(
            _parse_decimal(result["output_share"]),
            _nonnegative(result["products"], "products"),
            _nonnegative(result["truncations"], "truncations"),
        )
    elif operation == "peer_product":
        if not isinstance(raw, list) or len(raw) != 2:
            raise LocalhostCodecError("v3 peer_product 需两个份额")
        payload = tuple(_parse_decimal(value) for value in raw)
    elif operation == "peer_truncation":
        payload = _parse_decimal(raw)
    elif operation == "peer_layer":
        layer = _mapping(raw, "peer_layer")
        _exact_fields(layer, {"version", "phase", "program_sha256", "layer_index",
                              "resource_ids", "values"}, "peer_layer")
        ids = layer["resource_ids"]
        values = layer["values"]
        if not isinstance(ids, list) or not isinstance(values, list):
            raise LocalhostCodecError("标量层列表无效")
        payload = ScalarLayerPayloadV1(
            _text(layer["phase"], "phase"),
            _required_sha256(layer["program_sha256"], "program_sha256"),
            _nonnegative(layer["layer_index"], "layer_index"),
            tuple(_text(item, "resource_id") for item in ids),
            tuple(tuple(_parse_decimal(value) for value in row)
                  for row in values if isinstance(row, list)),
            _text(layer["version"], "version"),
        )
        if len(payload.values) != len(values):
            raise LocalhostCodecError("标量层数值行类型无效")
    elif operation in {"committed", "ended"}:
        payload = _nonnegative(_parse_decimal(raw), operation)
    elif operation == "end":
        if raw not in {"stop", "switch"}:
            raise LocalhostCodecError("v3 end action 无效")
        payload = raw
    elif operation in {"ready", "compute", "commit", "peer_complete"}:
        if raw is not None:
            raise LocalhostCodecError("v3 空消息不得带 payload")
        payload = None
    else:
        raise LocalhostCodecError("未知 v3 operation")
    frame = ScalarFrameV3(
        _text(mapping["sender"], "sender"), _text(mapping["recipient"], "recipient"),
        _text(mapping["run_id"], "run_id"), _text(mapping["epoch_id"], "epoch_id"),
        _text(mapping["session_id"], "session_id"),
        _nonnegative(mapping["physical_step"], "physical_step"),
        _nonnegative(mapping["local_step"], "local_step"),
        _optional_text(mapping["round_id"], "round_id"),
        _optional_text(mapping["resource_id"], "resource_id"),
        operation, payload,
    )
    _validate_scalar_frame_v3(frame)
    return frame


def _validate_scalar_frame_v3(frame: ScalarFrameV3) -> None:
    """统一检查角色方向、身份字段和操作所需的 payload。"""
    if frame.operation not in _SCALAR_OPERATIONS:
        raise LocalhostCodecError("未知 v3 operation")
    for name in ("run_id", "epoch_id", "session_id"):
        _text(getattr(frame, name), name)
    if (type(frame.physical_step) is not int or frame.physical_step < 0
            or type(frame.local_step) is not int or frame.local_step < 0):
        raise LocalhostCodecError("v3 步号无效")
    party = {"P1", "P2"}
    client_to_party = {"setup", "material", "compute", "commit", "end"}
    party_to_client = {"ready", "result", "committed", "ended"}
    peer = {"peer_product", "peer_complete", "peer_layer"}
    if not (
        (frame.operation in client_to_party and frame.sender == "Client"
         and frame.recipient in party)
        or (frame.operation in party_to_client and frame.sender in party
            and frame.recipient == "Client")
        or (frame.operation in peer and frame.sender in party
            and frame.recipient in party and frame.sender != frame.recipient)
        or (frame.operation == "peer_truncation" and
            (frame.sender, frame.recipient) == ("P2", "P1"))
    ):
        raise LocalhostCodecError("v3 操作与角色方向不符")
    need_round = frame.operation not in {"setup", "end", "ended"}
    need_resource = frame.operation.startswith("peer_")
    if (need_round != (frame.round_id is not None)
            or need_resource != (frame.resource_id is not None)):
        raise LocalhostCodecError("v3 round/resource 身份不符")
    expected = {
        "setup": ScalarSetupV3, "material": ScalarPartyMaterial,
        "result": ScalarStageV3, "peer_product": tuple,
        "peer_truncation": int, "peer_layer": ScalarLayerPayloadV1,
        "committed": int, "ended": int, "end": str,
    }
    required = expected.get(frame.operation, type(None))
    if not isinstance(frame.payload, required):
        raise LocalhostCodecError("v3 payload 类型与操作不符")
    if frame.operation == "peer_layer" and (
        frame.resource_id != f"layer:{frame.payload.layer_index}"
        or frame.payload.phase == "truncation"
        and (frame.sender, frame.recipient) != ("P2", "P1")
    ):
        raise LocalhostCodecError("v3 标量层方向或身份无效")
