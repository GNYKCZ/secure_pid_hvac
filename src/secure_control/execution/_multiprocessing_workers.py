"""Windows ``spawn`` 进程中的 Client/P1/P2 私有执行入口。"""

from __future__ import annotations

import os
import random
import traceback
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, Literal

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import (
    AdditiveShare,
    FixedPointContext,
    MaskedDifferenceShare,
    P2MaskedMessage,
    PrimeModulusEvidence,
    TwoPartySharing,
)
from secure_control.protocol import P1, P2, Client, ControllerRangeContract
from secure_control.protocol.messages import (
    _PROTOCOL3_TERM_ORDER,
    ControlShareMessage,
    InputShareMessage,
    OnlineRound,
    PartyResources,
    StepResourcePlan,
)
from secure_control.protocol.roles import _Server, _vector_from_scalars

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


@dataclass(frozen=True, slots=True)
class RoundPartyPayload:
    """Client 通过私有 Pipe 交给单个 Server 的本方在线材料。"""

    input_message: InputShareMessage
    resources: PartyResources


@dataclass(frozen=True, slots=True)
class PeerEnvelope:
    """P1/P2 私有 Pipe 上绑定 round 与资源身份的消息。"""

    protocol_version: int
    sender: int
    operation: str
    session_id: str
    round_id: str
    step: int
    resource_id: str
    payload: Any


@dataclass(frozen=True, slots=True)
class ProductMaskPayload:
    """不携带对象身份的单方 Beaver 遮蔽差值传输表示。"""

    d: AdditiveShare
    e: AdditiveShare
    party: int


@dataclass(frozen=True, slots=True)
class TruncationMaskPayload:
    """不携带对象身份的单方截断遮蔽份额传输表示。"""

    value: AdditiveShare
    party: int


@dataclass(frozen=True, slots=True)
class P2TruncationPayload:
    """P2 发给 P1 的截断消息传输表示，不跨进程传递 lifecycle。"""

    value: AdditiveShare


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
                    p1_channel.send(RoundPartyPayload(current.p1_input, current.p1_resources))
                    p2_channel.send(RoundPartyPayload(current.p2_input, current.p2_resources))
                    control.send(_reply(request, current.p1_resources.plan))
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
    peer_channel: Connection,
) -> None:
    """运行一个 Server 角色；任何时候都只持有本方 share。"""
    role_name: Literal["P1", "P2"] = "P1" if party == 0 else "P2"
    staged_state: AdditiveShare | None = None
    staged_identity: tuple[str, int] | None = None
    try:
        offline = client_channel.recv()
        role: _Server = P1(offline) if party == 0 else P2(offline)
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
                if request.operation == "execute":
                    if staged_state is not None:
                        raise RuntimeError("前一 round 尚未提交。")
                    payload = client_channel.recv()
                    if not isinstance(payload, RoundPartyPayload):
                        raise TypeError("Server 在线消息类型错误。")
                    plan = payload.resources.plan
                    if (request.round_id, request.step) != (plan.round_id, plan.step):
                        raise ValueError("execute 请求与在线材料的 round 或 step identity 不匹配。")
                    output, staged_state, counts = _execute_role_round(role, payload, peer_channel)
                    staged_identity = (plan.round_id, plan.step)
                    client_channel.send(output)
                    control.send(_reply(request, counts))
                    continue
                if request.operation == "commit":
                    if staged_state is None or staged_identity is None:
                        raise RuntimeError("没有待提交的 state。")
                    if (request.round_id, request.step) != staged_identity:
                        raise ValueError("commit 请求的 round 或 step identity 不匹配。")
                    role.commit_state(staged_state)
                    staged_state = None
                    staged_identity = None
                    control.send(_reply(request))
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
        peer_channel.close()


def _execute_role_round(
    role: _Server,
    payload: RoundPartyPayload,
    peer: Connection,
) -> tuple[ControlShareMessage, AdditiveShare, dict[str, int]]:
    resources = payload.resources
    plan = resources.plan
    party = resources.recipient
    other = 1 - party
    if (
        party not in {0, 1}
        or len(resources.product_resources) != len(plan.product_resources)
        or len(resources.state_truncation_resources) != len(plan.state_truncation_resources)
    ):
        raise ValueError("Server 在线资源数量或角色路由不匹配。")
    if role.session_id != plan.session_id:
        raise ValueError("Server 与资源计划不属于同一 session。")
    input_share = role.input_share(
        payload.input_message,
        session_id=plan.session_id,
        round_id=plan.round_id,
        step=plan.step,
    )
    sums = _empty_term_sums(role)
    sharing: TwoPartySharing | None = None
    for resource, expected in zip(resources.product_resources, plan.product_resources, strict=True):
        if resource.metadata != expected or resource.owner != party:
            raise ValueError("乘法资源与公开计划不匹配。")
        multiplier = resource.triple._lifecycle.owner
        sharing = multiplier.sharing
        term = expected.term
        row, column = expected.index
        right = (
            role.state_value(column)
            if term in {"A", "C"}
            else role.input_value(input_share, column)
        )
        masked = role.start_product(
            multiplier,
            role.matrix_value(term, row, column),
            right,
            resource,
        )
        _send_peer(
            peer,
            party,
            "product_mask",
            expected.resource_id,
            plan,
            ProductMaskPayload(masked.d, masked.e, party),
        )
        remote = _recv_peer(peer, other, "product_mask", expected.resource_id, plan)
        if not isinstance(remote, ProductMaskPayload) or remote.party != other:
            raise TypeError("对端 Beaver 遮蔽消息类型或角色错误。")
        lifecycle = masked._lifecycle
        lifecycle.claim_masking(other)
        rebound = MaskedDifferenceShare(remote.d, remote.e, remote.party, lifecycle)
        opened = multiplier.open_masked_differences(masked, rebound)
        product = role.finish_product(multiplier, resource, opened)
        lifecycle.claim_finish(other)
        resource._lifecycle.claim(other)
        resource._lifecycle.complete()
        sums[(term, row)] = role.add(sharing, sums[(term, row)], product)
    if sharing is None:  # ControllerSpec 保证 D 至少包含一个标量乘法。
        raise RuntimeError("资源计划缺少必须存在的 D 项乘法。")
    c_state = _term_vector(sums, "C", role.layout.output_dimension)
    d_input = _term_vector(sums, "D", role.layout.output_dimension)
    output = role.add(sharing, c_state, d_input)
    a_state = _term_vector(sums, "A", role.layout.state_dimension)
    b_input = _term_vector(sums, "B", role.layout.state_dimension)
    raw_state = role.add(sharing, a_state, b_input)
    next_state = _truncate_state(role, raw_state, resources, peer)
    message = ControlShareMessage(
        party,
        plan.session_id,
        plan.round_id,
        plan.step,
        role.layout.scale_ledger.output,
        output,
    )
    return (
        message,
        next_state,
        {
            "products": len(resources.product_resources),
            "truncations": len(resources.state_truncation_resources),
        },
    )


def _empty_term_sums(role: _Server) -> dict[tuple[str, int], AdditiveShare]:
    rows = {
        "C": role.layout.output_dimension,
        "D": role.layout.output_dimension,
        "A": role.layout.state_dimension,
        "B": role.layout.state_dimension,
    }
    return {
        (term, row): AdditiveShare(0) for term in _PROTOCOL3_TERM_ORDER for row in range(rows[term])
    }


def _term_vector(sums: dict[tuple[str, int], AdditiveShare], term: str, rows: int) -> AdditiveShare:
    return _vector_from_scalars([sums[(term, row)] for row in range(rows)])


def _truncate_state(
    role: _Server,
    raw_state: AdditiveShare,
    resources: PartyResources,
    peer: Connection,
) -> AdditiveShare:
    plan = resources.plan
    party = resources.recipient
    other = 1 - party
    if not resources.state_truncation_resources:
        return raw_state
    values: list[AdditiveShare] = []
    for row, resource in enumerate(resources.state_truncation_resources):
        expected = plan.state_truncation_resources[row]
        if resource.metadata != expected or resource.owner != party:
            raise ValueError("截断资源与公开计划不匹配。")
        truncation = resource.truncation._lifecycle.owner
        raw_value = np.asarray(raw_state.value, dtype=object)[row]
        raw = AdditiveShare(raw_value.item() if isinstance(raw_value, np.generic) else raw_value)
        masked = role.mask_truncation(truncation, raw, resource)
        _send_peer(
            peer,
            party,
            "truncation_mask",
            expected.resource_id,
            plan,
            TruncationMaskPayload(masked.value, party),
        )
        remote = _recv_peer(peer, other, "truncation_mask", expected.resource_id, plan)
        if not isinstance(remote, TruncationMaskPayload) or remote.party != other:
            raise TypeError("对端截断遮蔽消息类型或角色错误。")
        lifecycle = masked._lifecycle
        lifecycle.claim_mask(other)
        if party == 1:
            p2_message = truncation.p2_send_masked(masked)
            _send_peer(
                peer,
                party,
                "p2_truncation",
                expected.resource_id,
                plan,
                P2TruncationPayload(p2_message.value),
            )
            _recv_peer(peer, other, "p1_truncation_ack", expected.resource_id, plan)
            lifecycle.claim_p1_reconstruction()
            value = role.finish_truncation_p2(truncation, raw, resource)
            lifecycle.claim_finish(0)
        else:
            remote_message = _recv_peer(peer, other, "p2_truncation", expected.resource_id, plan)
            if not isinstance(remote_message, P2TruncationPayload):
                raise TypeError("P2 截断消息类型错误。")
            lifecycle.claim_p2_send()
            rebound = P2MaskedMessage(remote_message.value, lifecycle)
            masked_value = truncation.p1_reconstruct_masked(masked, rebound)
            value = role.finish_truncation_p1(truncation, raw, resource, masked_value)
            _send_peer(peer, party, "p1_truncation_ack", expected.resource_id, plan, True)
            lifecycle.claim_finish(1)
        resource._lifecycle.claim(other)
        resource._lifecycle.complete()
        values.append(value)
    return _vector_from_scalars(values)


def _send_peer(
    channel: Connection,
    sender: int,
    operation: str,
    resource_id: str,
    plan: StepResourcePlan,
    payload: Any,
) -> None:
    channel.send(
        PeerEnvelope(
            _PROTOCOL_VERSION,
            sender,
            operation,
            plan.session_id,
            plan.round_id,
            plan.step,
            resource_id,
            payload,
        )
    )


def _recv_peer(
    channel: Connection,
    sender: int,
    operation: str,
    resource_id: str,
    plan: StepResourcePlan,
) -> Any:
    message = channel.recv()
    if not isinstance(message, PeerEnvelope) or (
        message.protocol_version,
        message.sender,
        message.operation,
        message.session_id,
        message.round_id,
        message.step,
        message.resource_id,
    ) != (
        _PROTOCOL_VERSION,
        sender,
        operation,
        plan.session_id,
        plan.round_id,
        plan.step,
        resource_id,
    ):
        raise ValueError("P1/P2 消息的版本、路由或资源身份不匹配。")
    return message.payload
