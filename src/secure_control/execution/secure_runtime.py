"""封装 Client/P1/P2 协议的通用安全状态空间控制器运行时。"""

from __future__ import annotations

import random
from typing import Any

import numpy as np
from numpy.typing import NDArray

from secure_control.core import ControllerSpec
from secure_control.crypto import (
    AdditiveShare,
    FixedPointContext,
    PrimeModulusEvidence,
    PrimeModulusVerification,
    TwoPartySharing,
)
from secure_control.protocol import (
    P1,
    P2,
    Client,
    ControllerRangeContract,
    ControllerRangeVerification,
    ControllerScaleLedger,
    OfflineDistribution,
    SingleProcessCoordinator,
)
from secure_control.protocol.messages import OnlineRound

from ._inputs import normalize_step_input
from .evidence import (
    ProtocolResourceSnapshot,
    SecureTraceCollector,
    SecureTracePolicy,
    build_secure_step_trace,
)

Array = NDArray[Any]
Session = tuple[
    Client,
    P1,
    P2,
    OfflineDistribution,
    SingleProcessCoordinator,
    random.Random | None,
]


class SecureStateSpaceRuntime:
    """以与明文 runtime 相同的 ``step/reset`` 接口执行通用安全控制器。

    runtime 私有持有一个 Client、两方 Server 角色和当前单进程 coordinator。上层只提交
    通用 controller input 并获得 ``(p,)`` control，不接触 share、Beaver、Trunc 或角色对象。
    每步严格先以更新前 state 计算 ``u(k)``，完整成功后才推进 step；任何协议或重构失败
    都会恢复两方 state share，并关闭失败 round 的 Client capability。
    """

    def __init__(
        self,
        spec: ControllerSpec,
        fixed_point: FixedPointContext,
        range_contract: ControllerRangeContract,
        *,
        security_parameter: int,
        modulus_evidence: PrimeModulusEvidence | None = None,
        test_seed: int | None = None,
        trace_policy: SecureTracePolicy | None = None,
        trace_collector: SecureTraceCollector | None = None,
    ) -> None:
        """验证公共配置并建立一个独立、不可与其他实例混用的协议 session。

        ``test_seed`` 仅用于 transcript 相互隔离的确定性测试；传入 ``None`` 时，参数分享和
        每轮材料沿用 crypto 层的安全随机源。该参数不会用于 session/round identity。
        """
        if not isinstance(spec, ControllerSpec):
            raise TypeError("spec 必须是 ControllerSpec。")
        if not isinstance(fixed_point, FixedPointContext):
            raise TypeError("fixed_point 必须是 FixedPointContext。")
        if not isinstance(range_contract, ControllerRangeContract):
            raise TypeError("range_contract 必须是 ControllerRangeContract。")
        if modulus_evidence is not None and not isinstance(modulus_evidence, PrimeModulusEvidence):
            raise TypeError("modulus_evidence 必须是 PrimeModulusEvidence 或 None。")
        if test_seed is not None and (
            isinstance(test_seed, bool) or not isinstance(test_seed, int)
        ):
            raise TypeError("test_seed 必须是整数或 None。")
        if (trace_policy is None) != (trace_collector is None):
            raise ValueError("trace_policy 与 trace_collector 必须同时提供或同时省略。")
        if trace_policy is not None and not isinstance(trace_policy, SecureTracePolicy):
            raise TypeError("trace_policy 必须是 SecureTracePolicy 或 None。")
        if trace_collector is not None and not isinstance(trace_collector, SecureTraceCollector):
            raise TypeError("trace_collector 必须是 SecureTraceCollector 或 None。")
        if trace_policy is not None and test_seed is None:
            raise ValueError("诊断 trace 必须使用显式 deterministic test_seed。")

        self._spec = spec
        self._fixed_point = fixed_point
        self._range_contract = range_contract
        self._security_parameter = security_parameter
        self._modulus_evidence = modulus_evidence
        self._test_seed = test_seed
        self._trace_policy = trace_policy
        self._trace_collector = trace_collector
        self._install_session(self._build_session())

    @property
    def spec(self) -> ControllerSpec:
        """返回运行时使用的不可变、场景无关控制器规格。"""
        return self._spec

    @property
    def scale_ledger(self) -> ControllerScaleLedger:
        """返回当前 session 的只读公开尺度账本。"""
        return self._distribution.p1.layout.scale_ledger

    @property
    def modulus_verification(self) -> PrimeModulusVerification:
        """返回当前 Client 对公开模数完成的不可变验证摘要。"""
        return self._client.truncation.modulus_verification

    @property
    def range_verification(self) -> ControllerRangeVerification:
        """返回当前 session 在分享前完成的不可变范围验证摘要。"""
        return self._client.range_verification

    def step(self, v: Array | float) -> np.ndarray:
        """执行一个事务式安全控制步，并返回长度为 ``p`` 的有限浮点向量。

        合法输入表示与 ``PlaintextStateSpaceRuntime`` 一致。只有协议执行、Client 输出重构
        和有限值检查全部成功后才递增内部 step；失败 round 的资源不复用，state 与 step
        保持在调用前状态，以便调用方修正输入后继续运行。
        """
        input_vector = normalize_step_input(v, self._spec.input_dimension)
        first_state = self._copy_share(self._p1.state_share)
        second_state = self._copy_share(self._p2.state_share)
        online: OnlineRound | None = None
        resources_before = self._resource_snapshot() if self._trace_policy is not None else None
        resources_finalized = False
        capability_open = False
        try:
            online = self._client.prepare_online(
                self._distribution,
                input_vector,
                step=self._step_index,
                rng=self._material_rng,
            )
            capability_open = True
            self._account_created_resources(online)
            if self._trace_policy is None:
                output_shares = self._coordinator.execute(self._p1, self._p2, online)
                output = self._client.reconstruct_control(*output_shares)
                capability_open = False
            else:
                output_shares, snapshot = self._coordinator.execute_with_evidence(
                    self._p1, self._p2, online
                )
                selected = self._step_index == self._trace_policy.selected_step
                output, evidence = self._client.reconstruct_control_with_evidence(
                    *output_shares,
                    snapshot,
                    include_state=selected,
                    include_combined_share_audit=(
                        selected and self._trace_policy.allow_combined_share_diagnostic
                    ),
                )
                capability_open = False
            self._account_finalized_resources(online)
            resources_finalized = True
            if not np.isfinite(output).all():
                raise FloatingPointError("安全控制输出包含 NaN 或无穷大")
            if self._trace_policy is not None:
                if resources_before is None:
                    raise RuntimeError("诊断 trace 缺少执行前资源快照。")
                resources_after = self._resource_snapshot()
                trace = build_secure_step_trace(
                    evidence,
                    resources_before,
                    resources_after,
                    include_state=selected,
                )
                if self._trace_collector is None:
                    raise RuntimeError("诊断 trace collector 不可用。")
                self._trace_collector.append(trace, evidence.combined_share_audit)
        except Exception:
            # coordinator 可能在两方依次提交 state 之间失败，或 Client 可能在提交后重构失败；
            # 使用调用前的本地 share 快照回滚，不在 execution 层重构 controller state。
            self._p1.commit_state(first_state)
            self._p2.commit_state(second_state)
            if online is not None and capability_open:
                self._client.abort_round(online)
            if online is not None and not resources_finalized:
                self._account_finalized_resources(online)
            raise

        self._step_index += 1
        return np.array(output, dtype=float, copy=True)

    def reset(self) -> None:
        """原子建立新协议 session，并恢复 x0、step 与确定性测试材料序列。

        新 session 完整建立后才替换旧对象；若验证或离线分发失败，旧 session 仍可继续使用。
        reset 不重构或公开旧 state，也不会把旧 round capability 或资源带入新 session。
        """
        session = self._build_session()
        self._install_session(session)
        if self._trace_collector is not None:
            self._trace_collector.reset()

    def _build_session(self) -> Session:
        """在局部变量中完整建立新 Client、Servers 与 coordinator，支持原子 reset。"""
        sharing = TwoPartySharing(self._fixed_point.modulus)
        client = Client(
            self._fixed_point,
            sharing,
            security_parameter=self._security_parameter,
            modulus_evidence=self._modulus_evidence,
        )
        material_rng = random.Random(self._test_seed) if self._test_seed is not None else None
        distribution = client.distribute_controller(
            self._spec,
            self._range_contract,
            rng=material_rng,
        )
        p1, p2 = P1(distribution.p1), P2(distribution.p2)
        coordinator = SingleProcessCoordinator(sharing, client.multiplier, client.truncation)
        return client, p1, p2, distribution, coordinator, material_rng

    def _install_session(self, session: Session) -> None:
        """一次替换完整 session，并把公开时间索引恢复为零。"""
        (
            self._client,
            self._p1,
            self._p2,
            self._distribution,
            self._coordinator,
            self._material_rng,
        ) = session
        self._step_index = 0
        if self._trace_policy is not None:
            self._resource_totals = {
                "triples_created": 0,
                "triples_consumed": 0,
                "triples_aborted": 0,
                "truncations_created": 0,
                "truncations_consumed": 0,
                "truncations_aborted": 0,
            }

    def _account_created_resources(self, online: OnlineRound) -> None:
        """按真实 OnlineRound 中已创建的材料数量更新诊断累计值。"""
        if self._trace_policy is None:
            return
        self._resource_totals["triples_created"] += len(online.p1_resources.product_resources)
        self._resource_totals["truncations_created"] += len(
            online.p1_resources.state_truncation_resources
        )

    def _account_finalized_resources(self, online: OnlineRound) -> None:
        """从共享 lifecycle 的最终状态读取真实消费/废弃数，不能用理论常量代替。"""
        if self._trace_policy is None:
            return
        for prefix, resources in (
            ("triples", online.p1_resources.product_resources),
            ("truncations", online.p1_resources.state_truncation_resources),
        ):
            self._resource_totals[f"{prefix}_consumed"] += sum(
                item._lifecycle.status == "consumed" for item in resources
            )
            self._resource_totals[f"{prefix}_aborted"] += sum(
                item._lifecycle.status == "aborted" for item in resources
            )

    def _resource_snapshot(self) -> ProtocolResourceSnapshot:
        """仅在显式 trace 模式下返回真实诊断资源累计快照。"""
        if self._trace_policy is None:
            raise RuntimeError("默认关闭的 runtime 不提供诊断资源快照。")
        return ProtocolResourceSnapshot(**self._resource_totals)

    @staticmethod
    def _copy_share(share: AdditiveShare) -> AdditiveShare:
        """复制单方 state share，供失败回滚使用；该操作不接触另一方份额。"""
        return AdditiveShare(np.array(share.value, dtype=object, copy=True))
