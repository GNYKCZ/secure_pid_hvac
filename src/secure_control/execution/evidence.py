"""安全运行时的领域无关、默认关闭诊断证据契约。"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from numbers import Integral
from typing import Literal

from secure_control.protocol.evidence import (
    CombinedShareStepAudit,
    IntegerVectorEvidence,
    ProtocolReconstructionEvidence,
)


@dataclass(frozen=True, slots=True)
class SecureTracePolicy:
    """声明固定诊断 step 及 combined-share 的显式离线授权。"""

    selected_step: int
    allow_combined_share_diagnostic: bool = False
    diagnostic_rng_mode: Literal["reproducibility_only"] = "reproducibility_only"

    def __post_init__(self) -> None:
        """拒绝负 step、truthy 非布尔开关和生产随机性伪装成诊断随机性。"""
        if (
            isinstance(self.selected_step, bool)
            or not isinstance(self.selected_step, Integral)
            or self.selected_step < 0
        ):
            raise ValueError("selected_step 必须是非负整数。")
        if type(self.allow_combined_share_diagnostic) is not bool:
            raise TypeError("allow_combined_share_diagnostic 必须是 bool。")
        if self.diagnostic_rng_mode != "reproducibility_only":
            raise ValueError("诊断 evidence 只允许 reproducibility_only 随机模式。")
        object.__setattr__(self, "selected_step", int(self.selected_step))


@dataclass(frozen=True, slots=True)
class ProtocolResourceSnapshot:
    """保存真实创建、消费和失败废弃的 Protocol 1/2 累计计数。"""

    triples_created: int
    triples_consumed: int
    triples_aborted: int
    truncations_created: int
    truncations_consumed: int
    truncations_aborted: int

    def __post_init__(self) -> None:
        """资源累计计数只能是非负整数，且完成/废弃不能超过创建数。"""
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, Integral) or value < 0:
                raise ValueError(f"{name} 必须是非负整数。")
            object.__setattr__(self, name, int(value))
        if self.triples_consumed + self.triples_aborted > self.triples_created:
            raise ValueError("triple 的消费/废弃总数不能超过创建数。")
        if self.truncations_consumed + self.truncations_aborted > self.truncations_created:
            raise ValueError("truncation 的消费/废弃总数不能超过创建数。")


@dataclass(frozen=True, slots=True)
class ResourceOperationCounts:
    """从真实 StepResourcePlan 聚合 A/B/C/D 乘法和 state 截断数量。"""

    A: int
    B: int
    C: int
    D: int
    state_truncation: int

    @property
    def protocol1_triples(self) -> int:
        """返回四个通用矩阵项实际计划的标量乘法总数。"""
        return self.A + self.B + self.C + self.D


@dataclass(frozen=True, slots=True)
class StateTransitionEvidence:
    """记录同一 round 的更新前 state、累加器及提交后 state。"""

    state_before: IntegerVectorEvidence
    controller_input: IntegerVectorEvidence
    state_accumulator: IntegerVectorEvidence
    state_after: IntegerVectorEvidence
    truncation_bits: int
    equation_verified: bool


@dataclass(frozen=True, slots=True)
class SecureStepTrace:
    """保存一次成功安全控制步的 sanitized 执行证据。"""

    step: int
    session_id_sha256: str
    round_id_sha256: str
    controller_input: IntegerVectorEvidence
    raw_control: IntegerVectorEvidence
    decoded_raw_control: tuple[float, ...]
    resources_before: ProtocolResourceSnapshot
    resources_after: ProtocolResourceSnapshot
    operations: ResourceOperationCounts
    resource_id_sha256: tuple[str, ...]
    state_transition: StateTransitionEvidence | None


class SecureTraceCollector:
    """仅在内存中按 step 收集不可变 trace，并隔离选定 share 审计对象。"""

    def __init__(self) -> None:
        """建立空 collector；未启用 runtime policy 时不会收到任何数据。"""
        self._traces: list[SecureStepTrace] = []
        self._selected_share_audit: CombinedShareStepAudit | None = None

    def append(
        self,
        trace: SecureStepTrace,
        share_audit: CombinedShareStepAudit | None = None,
    ) -> None:
        """原子追加下一步 trace；selected audit 只允许设置一次。"""
        if not isinstance(trace, SecureStepTrace):
            raise TypeError("trace 必须是 SecureStepTrace。")
        if trace.step != len(self._traces):
            raise ValueError("trace step 必须从 0 开始严格连续。")
        if share_audit is not None:
            if not isinstance(share_audit, CombinedShareStepAudit):
                raise TypeError("share_audit 类型无效。")
            if share_audit.step != trace.step or self._selected_share_audit is not None:
                raise ValueError("combined-share audit 必须绑定当前 step 且只能保存一次。")
        self._traces.append(trace)
        if share_audit is not None:
            self._selected_share_audit = share_audit

    def traces(self) -> tuple[SecureStepTrace, ...]:
        """返回 collector 当前内容的不可变 tuple 快照。"""
        return tuple(self._traces)

    def selected_share_audit(self) -> CombinedShareStepAudit | None:
        """返回显式授权的本地 share 审计；普通公开导出不得调用该方法。"""
        return self._selected_share_audit

    def reset(self) -> None:
        """在 runtime 成功 reset 到新 session 后清空旧 session 证据。"""
        self._traces.clear()
        self._selected_share_audit = None


def build_secure_step_trace(
    evidence: ProtocolReconstructionEvidence,
    resources_before: ProtocolResourceSnapshot,
    resources_after: ProtocolResourceSnapshot,
    *,
    include_state: bool,
) -> SecureStepTrace:
    """把 Client 重构事实和真实资源生命周期转换为 sanitized runtime trace。"""
    if not isinstance(evidence, ProtocolReconstructionEvidence):
        raise TypeError("evidence 必须是 ProtocolReconstructionEvidence。")
    if not isinstance(resources_before, ProtocolResourceSnapshot) or not isinstance(
        resources_after, ProtocolResourceSnapshot
    ):
        raise TypeError("资源快照类型无效。")
    before_values = tuple(
        getattr(resources_before, name) for name in resources_before.__dataclass_fields__
    )
    after_values = tuple(
        getattr(resources_after, name) for name in resources_after.__dataclass_fields__
    )
    if any(after < before for before, after in zip(before_values, after_values, strict=True)):
        raise ValueError("资源累计计数不得倒退。")
    terms = Counter(item.term for item in evidence.plan.product_resources)
    operations = ResourceOperationCounts(
        A=terms.get("A", 0),
        B=terms.get("B", 0),
        C=terms.get("C", 0),
        D=terms.get("D", 0),
        state_truncation=len(evidence.plan.state_truncation_resources),
    )
    if operations.protocol1_triples != evidence.plan.triple_count:
        raise ValueError("资源计划的 A/B/C/D 分解与 triple 总数不一致。")
    state = None
    if include_state:
        if (
            evidence.state_before is None
            or evidence.state_accumulator is None
            or evidence.state_after is None
            or evidence.state_equation_verified is not True
        ):
            raise ValueError("选定 step 缺少完整且已验证的 controller state evidence。")
        state = StateTransitionEvidence(
            evidence.state_before,
            evidence.controller_input,
            evidence.state_accumulator,
            evidence.state_after,
            evidence.state_truncation_bits,
            True,
        )
    resource_ids = tuple(
        item.resource_id
        for item in (*evidence.plan.product_resources, *evidence.plan.state_truncation_resources)
    )
    return SecureStepTrace(
        step=evidence.step,
        session_id_sha256=_identifier_digest("session", evidence.session_id),
        round_id_sha256=_identifier_digest("round", evidence.round_id),
        controller_input=evidence.controller_input,
        raw_control=evidence.raw_control,
        decoded_raw_control=evidence.decoded_raw_control,
        resources_before=resources_before,
        resources_after=resources_after,
        operations=operations,
        resource_id_sha256=tuple(_identifier_digest("resource", item) for item in resource_ids),
        state_transition=state,
    )


def _identifier_digest(kind: str, value: str) -> str:
    """以域分离 SHA-256 关联身份，不把原始 session/round/resource ID 写入报告。"""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{kind} identity 不能为空。")
    return sha256(f"secure_control.evidence.{kind}.v1\0{value}".encode()).hexdigest()
