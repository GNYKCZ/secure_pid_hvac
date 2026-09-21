"""Windows ``spawn`` 进程中的 Client/P1/P2 私有执行入口。"""

from __future__ import annotations

import os
import random
import traceback
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, Literal

from secure_control.core import ControllerSpec
from secure_control.crypto import (
    FixedPointContext,
    PrimeModulusEvidence,
    TwoPartySharing,
)
from secure_control.protocol import P1, P2, Client, ControllerRangeContract
from secure_control.protocol.coordinator import LocalProtocol3PartyEndpoint
from secure_control.protocol.messages import (
    OnlineRound,
    P2TruncationPayload,
    PartyOnlineRound,
    ProductMaskPayload,
    ResourceMetadata,
    TruncationMaskPayload,
)

_PROTOCOL_VERSION = 1


@dataclass(frozen=True, slots=True)
class IpcEnvelope:
    """父进程与角色进程之间的固定版本请求/响应信封。"""

    protocol_version: int
    request_id: int
    role: Literal["Client", "P1", "P2"]
    operation: str
    session_id: str | None
    round_id: str | None
    step: int | None
    payload: Any = None
    error_type: str | None = None
    error_message: str | None = None
    error_traceback: str | None = None


def _reply(request: IpcEnvelope, payload: Any = None) -> IpcEnvelope:
    return IpcEnvelope(
        _PROTOCOL_VERSION,
        request.request_id,
        request.role,
        request.operation,
        request.session_id,
        request.round_id,
        request.step,
        payload,
    )


def _error(request: IpcEnvelope, error: BaseException) -> IpcEnvelope:
    return IpcEnvelope(
        _PROTOCOL_VERSION,
        request.request_id,
        request.role,
        request.operation,
        request.session_id,
        request.round_id,
        request.step,
        error_type=type(error).__name__,
        error_message=str(error),
        error_traceback=traceback.format_exc(),
    )


def _validate_request(request: object, role: str) -> IpcEnvelope:
    if not isinstance(request, IpcEnvelope):
        raise TypeError("IPC 请求必须使用 IpcEnvelope。")
    if request.protocol_version != _PROTOCOL_VERSION or request.role != role:
        raise ValueError("IPC 协议版本或目标角色不匹配。")
    return request


def client_worker(
    control: Connection,
    p1_channel: Connection,
    p2_channel: Connection,
    spec: ControllerSpec,
    fixed_point: FixedPointContext,
    range_contract: ControllerRangeContract,
    security_parameter: int,
    modulus_evidence: PrimeModulusEvidence | None,
    test_seed: int | None,
) -> None:
    """运行唯一 Client；明文 controller/input 与最终重构不离开此进程。"""
    current: OnlineRound | None = None
    try:
        sharing = TwoPartySharing(fixed_point.modulus)
        client = Client(
            fixed_point,
            sharing,
            security_parameter=security_parameter,
            modulus_evidence=modulus_evidence,
        )
        material_rng = random.Random(test_seed) if test_seed is not None else None
        distribution = client.distribute_controller(spec, range_contract, rng=material_rng)
        p1_channel.send(distribution.p1)
        p2_channel.send(distribution.p2)
        control.send(
            IpcEnvelope(
                _PROTOCOL_VERSION,
                0,
                "Client",
                "ready",
                distribution.session_id,
                None,
                None,
                {
                    "pid": os.getpid(),
                    "scale_ledger": distribution.p1.layout.scale_ledger,
                    "range_verification": client.range_verification,
                    "modulus_verification": client.truncation.modulus_verification,
                },
            )
        )
        while True:
            request = _validate_request(control.recv(), "Client")
            try:
                if request.session_id != distribution.session_id:
                    raise ValueError("Client 请求的 session identity 不匹配。")
                if request.operation == "shutdown":
                    control.send(_reply(request, {"pid": os.getpid()}))
                    return
                if request.operation == "prepare":
                    if current is not None:
                        raise RuntimeError("前一 round 尚未结束。")
                    if request.round_id is not None:
                        raise ValueError("prepare 请求不得预先指定 round identity。")
                    current = client.prepare_online(
                        distribution,
                        request.payload,
                        step=request.step if request.step is not None else -1,
                        rng=material_rng,
                    )
                    # 先开放父进程发送 begin，再写可能超过 Pipe 缓冲区的在线材料；
                    # 角色只有收到 begin 后才读取材料，反向顺序会形成循环等待。
                    control.send(_reply(request, current.p1_resources.plan))
                    p1_channel.send(PartyOnlineRound(current.p1_input, current.p1_resources))
                    p2_channel.send(PartyOnlineRound(current.p2_input, current.p2_resources))
                    continue
                if request.operation == "reconstruct":
                    if current is None:
                        raise RuntimeError("没有可重构的当前 round。")
                    if (request.round_id, request.step) != (current.round_id, current.step):
                        raise ValueError("reconstruct 请求的 round 或 step identity 不匹配。")
                    first = p1_channel.recv()
                    second = p2_channel.recv()
                    output = client.reconstruct_control(first, second)
                    current = None
                    control.send(_reply(request, output))
                    continue
                if request.operation == "abort":
                    if current is not None:
                        client.abort_round(current)
                        current = None
                    control.send(_reply(request))
                    continue
                raise ValueError(f"Client 不支持操作：{request.operation}")
            except Exception as error:  # noqa: BLE001 - IPC 边界必须回传任意工作进程错误
                control.send(_error(request, error))
    except Exception as error:  # noqa: BLE001 - 启动失败必须结构化通知父进程
        try:
            control.send(
                IpcEnvelope(
                    _PROTOCOL_VERSION,
                    0,
                    "Client",
                    "startup",
                    None,
                    None,
                    None,
                    error_type=type(error).__name__,
                    error_message=str(error),
                    error_traceback=traceback.format_exc(),
                )
            )
        except (BrokenPipeError, EOFError, OSError):
            return
    finally:
        control.close()
        p1_channel.close()
        p2_channel.close()


def role_worker(
    party: int,
    control: Connection,
    client_channel: Connection,
) -> None:
    """运行一个 Server 角色；任何时候都只持有本方 share。"""
    role_name: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
    endpoint: LocalProtocol3PartyEndpoint | None = None
    try:
        offline = client_channel.recv()
        role: P1 | P2 = P1(offline) if party == 0 else P2(offline)
        control.send(
            IpcEnvelope(
                _PROTOCOL_VERSION,
                0,
                role_name,
                "ready",
                role.session_id,
                None,
                None,
                {"pid": os.getpid()},
            )
        )
        while True:
            request = _validate_request(control.recv(), role_name)
            try:
                if request.session_id != role.session_id:
                    raise ValueError(f"{role_name} 请求的 session identity 不匹配。")
                if request.operation == "shutdown":
                    control.send(_reply(request, {"pid": os.getpid()}))
                    return
                if request.operation == "begin":
                    if endpoint is not None:
                        raise RuntimeError("前一 round 尚未提交。")
                    payload = client_channel.recv()
                    if not isinstance(payload, PartyOnlineRound):
                        raise TypeError("Server 在线消息类型错误。")
                    plan = payload.resources.plan
                    if (request.round_id, request.step) != (plan.round_id, plan.step):
                        raise ValueError("begin 请求与在线材料的 round 或 step identity 不匹配。")
                    endpoint = LocalProtocol3PartyEndpoint(
                        role,
                        payload,
                        client_channel.send,
                    )
                    control.send(_reply(request))
                    continue
                if endpoint is None:
                    raise RuntimeError("当前没有已开始的 Protocol 3 round。")
                if (request.round_id, request.step) != (
                    endpoint.plan.round_id,
                    endpoint.plan.step,
                ):
                    raise ValueError("角色请求的 round 或 step identity 不匹配。")
                result = _dispatch_endpoint(endpoint, request.operation, request.payload)
                if request.operation == "commit":
                    endpoint = None
                control.send(_reply(request, result))
                if request.operation in {
                    "mask_product",
                    "finish_product",
                    "complete_product",
                    "finish_products",
                    "mask_truncation",
                    "p2_truncation_message",
                    "finish_truncation_p1",
                    "finish_truncation_p2",
                    "complete_truncation",
                    "stage_output",
                    "commit",
                }:
                    continue
                raise ValueError(f"{role_name} 不支持操作：{request.operation}")
            except Exception as error:  # noqa: BLE001 - IPC 边界必须回传任意工作进程错误
                control.send(_error(request, error))
    except Exception as error:  # noqa: BLE001 - 启动失败必须结构化通知父进程
        try:
            control.send(
                IpcEnvelope(
                    _PROTOCOL_VERSION,
                    0,
                    role_name,
                    "startup",
                    None,
                    None,
                    None,
                    error_type=type(error).__name__,
                    error_message=str(error),
                    error_traceback=traceback.format_exc(),
                )
            )
        except (BrokenPipeError, EOFError, OSError):
            return
    finally:
        control.close()
        client_channel.close()


def _dispatch_endpoint(endpoint: LocalProtocol3PartyEndpoint, operation: str, payload: Any) -> Any:
    """把单个已验证 IPC 操作映射到 protocol-owned endpoint，不编排操作顺序。"""
    if operation == "mask_product" and isinstance(payload, ResourceMetadata):
        return endpoint.mask_product(payload)
    if operation == "finish_product" and _payload_types(
        payload, ResourceMetadata, ProductMaskPayload
    ):
        endpoint.finish_product(payload[0], payload[1])
        return None
    if operation == "complete_product" and isinstance(payload, ResourceMetadata):
        endpoint.complete_product(payload)
        return None
    if operation == "finish_products" and payload is None:
        endpoint.finish_products()
        return None
    if operation == "mask_truncation" and isinstance(payload, ResourceMetadata):
        return endpoint.mask_truncation(payload)
    if operation == "p2_truncation_message" and _payload_types(
        payload, ResourceMetadata, TruncationMaskPayload
    ):
        return endpoint.p2_truncation_message(payload[0], payload[1])
    if operation == "finish_truncation_p1" and _payload_types(
        payload,
        ResourceMetadata,
        TruncationMaskPayload,
        P2TruncationPayload,
    ):
        endpoint.finish_truncation_p1(payload[0], payload[1], payload[2])
        return None
    if operation == "finish_truncation_p2" and isinstance(payload, ResourceMetadata):
        endpoint.finish_truncation_p2(payload)
        return None
    if operation == "complete_truncation" and isinstance(payload, ResourceMetadata):
        endpoint.complete_truncation(payload)
        return None
    if operation == "stage_output" and payload is None:
        return endpoint.stage_output()
    if operation == "commit" and payload is None:
        endpoint.commit()
        return None
    raise ValueError(f"Protocol 3 endpoint 不支持操作或 payload 类型错误：{operation}")


def _payload_types(payload: Any, *types: type[object]) -> bool:
    return (
        isinstance(payload, tuple)
        and len(payload) == len(types)
        and all(isinstance(value, expected) for value, expected in zip(payload, types, strict=True))
    )
