"""localhost transport 的固定版本 JSON schema 与无损 bigint/share codec。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from math import isfinite, prod
from numbers import Integral
from typing import Any, Literal

import numpy as np

from secure_control.crypto import AdditiveShare, PrimeModulusVerification
from secure_control.protocol import ControllerRangeVerification, ControllerScaleLedger
from secure_control.protocol.messages import (
    ControllerLayout,
    ControllerShare,
    ControlShareMessage,
    InputShareMessage,
    P2TruncationPayload,
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    ProductMaskPayload,
    ProductResourceMaterial,
    Protocol3EndpointCommand,
    Protocol3StageReceipt,
    ResourceMetadata,
    StepResourcePlan,
    TruncationMaskPayload,
    TruncationResourceMaterial,
)

SCHEMA_VERSION = 1
_ROLES = {"Supervisor", "Client", "P1", "P2"}
_KINDS = {"hello", "ready", "request", "reply", "error", "shutdown"}
_OPERATIONS = {
    "hello",
    "ready",
    "offline",
    "online",
    "prepare",
    "begin",
    "endpoint",
    "reconstruct",
    "control_share",
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


WirePayload = (
    HelloPayload
    | ReadyPayload
    | RemoteErrorPayload
    | np.ndarray[Any, Any]
    | StepResourcePlan
    | Protocol3EndpointCommand
    | ProductMaskPayload
    | TruncationMaskPayload
    | P2TruncationPayload
    | Protocol3StageReceipt
    | PartyOfflineMaterial
    | PartyOnlineMaterial
    | ControlShareMessage
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


def _encode_value(value: object) -> object:
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


def _decode_value(value: object) -> object:
    mapping = _mapping(value, "wire value")
    kind = mapping.get("type")
    if not isinstance(kind, str):
        raise LocalhostCodecError("wire value 缺少字符串 type。")
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
    expected: tuple[type[object], ...] | None
    if key == ("hello", "hello"):
        expected = (HelloPayload,)
    elif key == ("ready", "ready"):
        expected = (ReadyPayload,)
    elif message.kind == "error":
        expected = (RemoteErrorPayload,)
    elif key == ("request", "prepare"):
        expected = (np.ndarray,)
    elif key == ("reply", "prepare"):
        expected = (StepResourcePlan,)
    elif key == ("request", "endpoint"):
        expected = (Protocol3EndpointCommand,)
    elif key == ("reply", "endpoint"):
        expected = (
            ProductMaskPayload,
            TruncationMaskPayload,
            P2TruncationPayload,
            Protocol3StageReceipt,
            type(None),
        )
    elif key == ("reply", "reconstruct"):
        expected = (np.ndarray,)
    elif key == ("request", "offline"):
        expected = (PartyOfflineMaterial,)
    elif key == ("request", "online"):
        expected = (PartyOnlineMaterial,)
    elif key == ("request", "control_share"):
        expected = (ControlShareMessage,)
    elif message.operation in {"begin", "reconstruct", "shutdown"}:
        expected = (type(None),)
    else:
        expected = None
    if expected is None or not isinstance(payload, expected):
        raise LocalhostCodecError("wire kind/operation 与 payload 类型组合非法。")
    if message.operation == "endpoint" and isinstance(payload, Protocol3EndpointCommand):
        expected_resource = payload.metadata.resource_id if payload.metadata is not None else None
        if message.resource_id != expected_resource:
            raise LocalhostCodecError("endpoint envelope 与 command resource identity 不匹配。")


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


def _require_nonnegative_integer(value: object, name: str) -> None:
    _nonnegative(value, name)


def _require_optional_identity(value: object, name: str) -> None:
    if value is not None:
        _text(value, name)
