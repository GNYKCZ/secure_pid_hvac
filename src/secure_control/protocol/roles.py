"""Client、P1 与 P2 的领域无关本地角色状态和操作。"""

from __future__ import annotations

import random
from dataclasses import dataclass
from numbers import Integral
from typing import Any

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import (
    AdditiveShare,
    BeaverMultiplier,
    FixedPointContext,
    MaskedDifferenceShare,
    MaskedTruncationShare,
    P1MaskedValue,
    PublicMaskedDifferences,
    SecureTruncation,
    TwoPartySharing,
)

from .messages import (
    ControllerLayout,
    ControllerShare,
    ControlShareMessage,
    InputShareMessage,
    OfflineControllerMessage,
    OfflineDistribution,
    OnlineRound,
    PartyIndex,
    PartyResources,
    ResourceMetadata,
    ScalarResourceShare,
    StepResourcePlan,
    _ResourceLifecycle,
)


def _require_step(step: int) -> int:
    """验证公开时间索引，避免 bool 或负数进入资源标识。"""
    if isinstance(step, bool) or not isinstance(step, Integral) or step < 0:
        raise ValueError("step 必须是非负整数。")
    return int(step)


def _scalar_from_array(share: AdditiveShare, index: tuple[int, ...]) -> AdditiveShare:
    """从本地向量或矩阵份额中取一个标量，不复制也不组合其他参与方的份额。"""
    values = np.asarray(share.value, dtype=object)
    value = values[index]
    return AdditiveShare(value.item() if isinstance(value, np.generic) else value)


def _vector_from_scalars(values: list[AdditiveShare]) -> AdditiveShare:
    """将同一参与方的一组标量结果组装为 object 向量，保留任意精度 residue。"""
    result = np.empty(len(values), dtype=object)
    for index, value in enumerate(values):
        scalar = np.asarray(value.value, dtype=object)
        if scalar.ndim != 0:
            raise TypeError("控制器内部标量计算意外收到数组份额。")
        result[index] = scalar.item()
    return AdditiveShare(result)


class Client:
    """持有明文控制器和输入的编码/分发边界，不向任一 Server 发送两份 share。"""

    def __init__(
        self,
        fixed_point: FixedPointContext,
        sharing: TwoPartySharing,
        *,
        security_parameter: int,
    ) -> None:
        """建立 Client 的定点、共享和一次性预处理材料生成器。"""
        if fixed_point.modulus != sharing.modulus:
            raise ValueError("FixedPointContext 与 TwoPartySharing 必须使用相同 modulus。")
        self.fixed_point = fixed_point
        self.sharing = sharing
        self.multiplier = BeaverMultiplier(sharing)
        self.truncation = SecureTruncation(
            sharing,
            ell=fixed_point.fractional_bits,
            security_parameter=security_parameter,
        )

    def distribute_controller(
        self, spec: ControllerSpec, *, rng: random.Random | None = None
    ) -> OfflineDistribution:
        """编码并分别分发通用 ``A/B/C/D/x0``，每条消息仅有接收方的一份 share。"""
        if not isinstance(spec, ControllerSpec):
            raise TypeError("spec 必须是 ControllerSpec，不能是场景领域对象。")
        layout = self._layout_from_spec(spec)
        encoded = {
            name: self.fixed_point.encode_to_residue(getattr(spec, name))
            for name in ("A", "B", "C", "D", "x0")
        }
        shared = {name: self.sharing.share(value, rng=rng) for name, value in encoded.items()}
        first = ControllerShare(shared["A"][0], shared["B"][0], shared["C"][0], shared["D"][0])
        second = ControllerShare(shared["A"][1], shared["B"][1], shared["C"][1], shared["D"][1])
        return OfflineDistribution(
            OfflineControllerMessage(0, first, shared["x0"][0], layout),
            OfflineControllerMessage(1, second, shared["x0"][1], layout),
        )

    def prepare_online(
        self,
        distribution: OfflineDistribution,
        v: Any,
        *,
        step: int,
        rng: random.Random | None = None,
    ) -> OnlineRound:
        """分享本轮通用输入 ``v``，并按矩阵 shape/scale 创建不复用的本地资源包。"""
        if not isinstance(distribution, OfflineDistribution):
            raise TypeError("distribution 必须来自 Client.distribute_controller。")
        step = _require_step(step)
        layout = self._matching_layout(distribution)
        input_values = self._normalize_input(v, layout)
        input_shares = self.sharing.share(self.fixed_point.encode_to_residue(input_values), rng=rng)
        plan = self._resource_plan(layout, step)
        first_resources: list[ScalarResourceShare] = []
        second_resources: list[ScalarResourceShare] = []
        for metadata in plan.resources:
            triple = self.multiplier.create_triple(rng=rng)
            truncation = self.truncation.create_auxiliary(rng=rng)
            lifecycle = _ResourceLifecycle()
            first_resources.append(
                ScalarResourceShare(0, metadata, triple[0], truncation[0], lifecycle)
            )
            second_resources.append(
                ScalarResourceShare(1, metadata, triple[1], truncation[1], lifecycle)
            )
        return OnlineRound(
            step,
            InputShareMessage(0, step, input_shares[0]),
            InputShareMessage(1, step, input_shares[1]),
            PartyResources(0, plan, tuple(first_resources)),
            PartyResources(1, plan, tuple(second_resources)),
        )

    def reconstruct_control(
        self, first: ControlShareMessage, second: ControlShareMessage
    ) -> np.ndarray:
        """仅在 Client 边界重构并解码 control shares，Server 从不调用此方法。"""
        if not isinstance(first, ControlShareMessage) or not isinstance(
            second, ControlShareMessage
        ):
            raise TypeError("控制输出必须是两条 ControlShareMessage。")
        if (first.sender, second.sender) != (0, 1) or first.step != second.step:
            raise ValueError("控制输出必须按同一 step 的 P1、P2 顺序提供。")
        decoded = self.fixed_point.decode_residue(
            self.sharing.reconstruct(first.value, second.value)
        )
        return np.asarray(decoded)

    def _layout_from_spec(self, spec: ControllerSpec) -> ControllerLayout:
        """检查当前标量截断实现可承载的统一尺度，并提取公开矩阵维度。"""
        scale = self.fixed_point.fractional_bits
        if spec.scale_metadata is not None:
            metadata = spec.scale_metadata
            scales = (
                metadata.state,
                metadata.input,
                metadata.output,
                metadata.A,
                metadata.B,
                metadata.C,
                metadata.D,
            )
            if any(value != scale for value in scales):
                raise ValueError(
                    "当前 Protocol 3 标量路径只支持 A/B/C/D/x0/v/u 使用相同 fractional bits。"
                )
        return ControllerLayout(
            spec.state_dimension,
            spec.input_dimension,
            spec.output_dimension,
            scale,
        )

    def _matching_layout(self, distribution: OfflineDistribution) -> ControllerLayout:
        """确认两条 Client 离线消息来自同一个公开控制器布局。"""
        if distribution.p1.recipient != 0 or distribution.p2.recipient != 1:
            raise ValueError("离线消息的角色路由不正确。")
        if distribution.p1.layout != distribution.p2.layout:
            raise ValueError("两条离线消息必须具有相同 controller layout。")
        return distribution.p1.layout

    def _normalize_input(self, value: Any, layout: ControllerLayout) -> np.ndarray:
        """将单输入标量或长度为 m 的扁平向量规范化为公开约定的 ``(m,)`` shape。"""
        array = np.asarray(value, dtype=object)
        if array.ndim == 0 and layout.input_dimension == 1:
            array = array.reshape(1)
        if array.shape != (layout.input_dimension,):
            raise ValueError(f"v 必须具有 shape ({layout.input_dimension},)。")
        return array

    def _resource_plan(self, layout: ControllerLayout, step: int) -> StepResourcePlan:
        """按 C/D/A/B 计算顺序为每个矩阵元素分配独立 triple 和 mask。"""
        shapes = {
            "A": (layout.state_dimension, layout.state_dimension),
            "B": (layout.state_dimension, layout.input_dimension),
            "C": (layout.output_dimension, layout.state_dimension),
            "D": (layout.output_dimension, layout.input_dimension),
        }
        resources: list[ResourceMetadata] = []
        # 先输出后状态更新，保持 u(k) 使用 x(k) 而非 x(k+1) 的时间索引语义。
        for term in ("C", "D", "A", "B"):
            rows, columns = shapes[term]
            for row in range(rows):
                for column in range(columns):
                    resource_id = f"step-{step}:{term}[{row},{column}]"
                    resources.append(
                        ResourceMetadata(
                            resource_id,
                            step,
                            term,  # type: ignore[arg-type]
                            (row, column),
                            shapes[term],
                            layout.fractional_bits,
                        )
                    )
        return StepResourcePlan(
            step,
            (layout.state_dimension,),
            (layout.input_dimension,),
            (layout.output_dimension,),
            layout.fractional_bits,
            tuple(resources),
        )


@dataclass(slots=True)
class _Server:
    """P1/P2 共享的本地操作；实例只保存本方参数份额和本方 state share。"""

    _party: PartyIndex
    _controller: ControllerShare
    _state: AdditiveShare
    _layout: ControllerLayout

    @property
    def controller_share(self) -> ControllerShare:
        """返回本方的参数 share 容器，不暴露另一方参数。"""
        return self._controller

    @property
    def state_share(self) -> AdditiveShare:
        """返回本方当前 controller state share，而不是 state plaintext。"""
        return self._state

    @property
    def layout(self) -> ControllerLayout:
        """返回控制器公开维度与定点尺度。"""
        return self._layout

    def input_share(self, message: InputShareMessage, *, step: int) -> AdditiveShare:
        """接收本方 input share，并拒绝另一个角色、旧 step 或两份 share 容器。"""
        if not isinstance(message, InputShareMessage):
            raise TypeError("Server 只能接收单条 InputShareMessage。")
        if message.recipient != self._party or message.step != step:
            raise ValueError("输入消息的接收方或 step 与当前协议轮次不匹配。")
        values = np.asarray(message.value.value, dtype=object)
        if values.shape != (self._layout.input_dimension,):
            raise ValueError("输入 share 的 shape 与 controller input dimension 不匹配。")
        return message.value

    def matrix_value(self, term: str, row: int, column: int) -> AdditiveShare:
        """读取本方某个公开索引的参数份额；矩阵名仅限通用 A/B/C/D。"""
        if term not in {"A", "B", "C", "D"}:
            raise ValueError("矩阵项必须是通用 A、B、C 或 D。")
        return _scalar_from_array(getattr(self._controller, term), (row, column))

    def state_value(self, index: int) -> AdditiveShare:
        """读取本方当前状态向量的一项，不重构状态。"""
        return _scalar_from_array(self._state, (index,))

    def input_value(self, input_share: AdditiveShare, index: int) -> AdditiveShare:
        """读取本方当前输入向量的一项，不接触对方输入份额。"""
        return _scalar_from_array(input_share, (index,))

    def start_product(
        self,
        multiplier: BeaverMultiplier,
        left: AdditiveShare,
        right: AdditiveShare,
        resource: ScalarResourceShare,
    ) -> MaskedDifferenceShare:
        """以本地 operand/triple share 生成 Beaver 遮蔽差值，不能传入明文操作数。"""
        self._validate_resource(resource)
        resource._lifecycle.claim(self._party)
        return multiplier.mask_inputs(left, right, resource.triple)

    def finish_product(
        self,
        multiplier: BeaverMultiplier,
        resource: ScalarResourceShare,
        opened: PublicMaskedDifferences,
    ) -> AdditiveShare:
        """使用公开 d/e 和本方 triple share 完成乘法输出 share。"""
        self._validate_resource(resource)
        return multiplier.finish(resource.triple, opened)

    def mask_truncation(
        self,
        truncation: SecureTruncation,
        product: AdditiveShare,
        resource: ScalarResourceShare,
    ) -> MaskedTruncationShare:
        """用本方随机 mask 遮蔽双尺度乘积，准备 Protocol 2 的唯一消息流。"""
        self._validate_resource(resource)
        return truncation.mask_input(product, resource.truncation)

    def finish_truncation_p1(
        self,
        truncation: SecureTruncation,
        product: AdditiveShare,
        resource: ScalarResourceShare,
        masked_value: P1MaskedValue,
    ) -> AdditiveShare:
        """仅 P1 使用收到的 P2 masked message 完成 Protocol 2 本地输出。"""
        self._validate_resource(resource)
        if self._party != 0:
            raise ValueError("只有 P1 可以完成 Protocol 2 的 P1 分支。")
        return truncation.finish_p1(product, resource.truncation, masked_value)

    def finish_truncation_p2(
        self,
        truncation: SecureTruncation,
        product: AdditiveShare,
        resource: ScalarResourceShare,
    ) -> AdditiveShare:
        """仅 P2 在不接收 P1 消息的条件下完成 Protocol 2 本地输出。"""
        self._validate_resource(resource)
        if self._party != 1:
            raise ValueError("只有 P2 可以完成 Protocol 2 的 P2 分支。")
        return truncation.finish_p2(product, resource.truncation)

    def add(
        self, sharing: TwoPartySharing, left: AdditiveShare, right: AdditiveShare
    ) -> AdditiveShare:
        """执行本方的线性 share 加法；线性项不消耗 Beaver 或 Trunc 资源。"""
        return sharing.add(left, right)

    def commit_state(self, state: AdditiveShare) -> None:
        """在整轮成功后原子替换本方 state share，失败轮次不会调用本方法。"""
        values = np.asarray(state.value, dtype=object)
        if values.shape != (self._layout.state_dimension,):
            raise ValueError("下一状态 share 的 shape 与 controller state dimension 不匹配。")
        self._state = state

    def _validate_resource(self, resource: ScalarResourceShare) -> None:
        """确认资源仅属于当前角色，并且 triple/mask 的角色标签也一致。"""
        if not isinstance(resource, ScalarResourceShare) or resource.owner != self._party:
            raise ValueError("Server 只能使用 Client 分发给本方的一份协议资源。")
        if (
            resource.triple.party_index != self._party
            or resource.truncation.party_index != self._party
        ):
            raise ValueError("资源内部的 triple 或 truncation share 角色不一致。")


class P1(_Server):
    """协议第一方；仅持有 P1 参数、状态、输入和辅助随机量 shares。"""

    def __init__(self, message: OfflineControllerMessage) -> None:
        """从 Client 的单条 P1 离线消息初始化，不接受完整控制器或 P2 数据。"""
        if not isinstance(message, OfflineControllerMessage) or message.recipient != 0:
            raise ValueError("P1 必须由一条发送给 P1 的 OfflineControllerMessage 初始化。")
        super().__init__(0, message.controller, message.initial_state, message.layout)


class P2(_Server):
    """协议第二方；仅持有 P2 参数、状态、输入和辅助随机量 shares。"""

    def __init__(self, message: OfflineControllerMessage) -> None:
        """从 Client 的单条 P2 离线消息初始化，不接受完整控制器或 P1 数据。"""
        if not isinstance(message, OfflineControllerMessage) or message.recipient != 1:
            raise ValueError("P2 必须由一条发送给 P2 的 OfflineControllerMessage 初始化。")
        super().__init__(1, message.controller, message.initial_state, message.layout)
