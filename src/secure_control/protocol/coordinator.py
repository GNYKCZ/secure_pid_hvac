"""单进程下的 Client/P1/P2 消息协调，不向 Server 提供明文或完整 state。"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from secure_control.crypto import AdditiveShare, BeaverMultiplier, SecureTruncation, TwoPartySharing

from .messages import (
    ControlShareMessage,
    MaskedExchangeMessage,
    OnlineRound,
    OpenedMaskedMessage,
    ScalarResourceShare,
    TruncationMaskedMessage,
)
from .roles import P1, P2, _Server, _vector_from_scalars


class SingleProcessCoordinator:
    """协调本地消息投递和公开 masked 值；其输出始终是两条 control share 消息。

    该类只是当前的 transport/协调选择。它可以临时配对 P1/P2 的 Beaver 遮蔽差值，
    因而得到协议允许公开的 ``d/e``，但从不重构 controller parameter、state、input
    或 control output；这些明文仅由 Client 的显式边界方法重构。
    """

    def __init__(
        self,
        sharing: TwoPartySharing,
        multiplier: BeaverMultiplier,
        truncation: SecureTruncation,
    ) -> None:
        """绑定同一 ``Z_q`` 下的既有算术原语，不保存 Client 或任何明文控制器。"""
        if not isinstance(sharing, TwoPartySharing):
            raise TypeError("sharing 必须是 TwoPartySharing。")
        if multiplier.sharing is not sharing or truncation.sharing is not sharing:
            raise ValueError("协调器与所有算术原语必须共享同一个 TwoPartySharing 实例。")
        self._sharing = sharing
        self._multiplier = multiplier
        self._truncation = truncation

    def execute(
        self, p1: P1, p2: P2, online: OnlineRound
    ) -> tuple[ControlShareMessage, ControlShareMessage]:
        """执行一轮通用 ``u=Cx+Dv``、``x_next=Ax+Bv`` 并只返回输出份额。

        输出矩阵项先于状态矩阵项执行，所以使用的始终是本轮开始时的 ``x(k)``。
        任意校验、资源或算术失败都会废弃该轮尚未完成的预处理材料，且不会提交新状态。
        """
        try:
            self._validate_round(p1, p2, online)
            first_input = p1.input_share(online.p1_input, step=online.step)
            second_input = p2.input_share(online.p2_input, step=online.step)
            resources = iter(zip(online.p1_resources.resources, online.p2_resources.resources))

            # 输出先计算，确保严格对应离散控制器定义中的 x(k)。
            c_state = self._matrix_vector("C", p1, p2, p1.state_value, p2.state_value, resources)
            d_input = self._matrix_vector(
                "D",
                p1,
                p2,
                lambda index: p1.input_value(first_input, index),
                lambda index: p2.input_value(second_input, index),
                resources,
            )
            output = self._add_vectors(p1, p2, c_state, d_input)

            # 直到所有输出项成功后才组装下一状态；commit 在最后一次性发生。
            a_state = self._matrix_vector("A", p1, p2, p1.state_value, p2.state_value, resources)
            b_input = self._matrix_vector(
                "B",
                p1,
                p2,
                lambda index: p1.input_value(first_input, index),
                lambda index: p2.input_value(second_input, index),
                resources,
            )
            next_state = self._add_vectors(p1, p2, a_state, b_input)
            if next(resources, None) is not None:
                raise ValueError("本轮资源计划包含未被消费的矩阵项。")
            p1.commit_state(next_state[0])
            p2.commit_state(next_state[1])
            return (
                ControlShareMessage(0, online.step, output[0]),
                ControlShareMessage(1, online.step, output[1]),
            )
        except Exception:
            self._abort_round(online)
            raise

    def _matrix_vector(
        self,
        term: str,
        p1: P1,
        p2: P2,
        first_right: Callable[[int], AdditiveShare],
        second_right: Callable[[int], AdditiveShare],
        resources: Iterator[tuple[ScalarResourceShare, ScalarResourceShare]],
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """以逐标量 Protocol 1+2 实现一个通用共享矩阵/向量积。"""
        rows, columns = self._term_shape(term, p1)
        first_values: list[AdditiveShare] = []
        second_values: list[AdditiveShare] = []
        for row in range(rows):
            first_sum = AdditiveShare(0)
            second_sum = AdditiveShare(0)
            for column in range(columns):
                first_resource, second_resource = next(resources)
                self._validate_resource_pair(first_resource, second_resource, term, (row, column))
                product = self._scalar_product(
                    p1.matrix_value(term, row, column),
                    first_right(column),
                    p2.matrix_value(term, row, column),
                    second_right(column),
                    p1,
                    p2,
                    first_resource,
                    second_resource,
                )
                first_sum = p1.add(self._sharing, first_sum, product[0])
                second_sum = p2.add(self._sharing, second_sum, product[1])
            first_values.append(first_sum)
            second_values.append(second_sum)
        return _vector_from_scalars(first_values), _vector_from_scalars(second_values)

    def _scalar_product(
        self,
        first_left: AdditiveShare,
        first_right: AdditiveShare,
        second_left: AdditiveShare,
        second_right: AdditiveShare,
        p1: P1,
        p2: P2,
        first_resource: ScalarResourceShare,
        second_resource: ScalarResourceShare,
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """执行一个标量乘法与截断，并显式建模两类允许的 masked-value 消息。"""
        first_masked = p1.start_product(self._multiplier, first_left, first_right, first_resource)
        second_masked = p2.start_product(
            self._multiplier, second_left, second_right, second_resource
        )
        # 两条相反方向消息只带 d_i/e_i；原始 operand shares 从未进入消息对象。
        to_p2 = MaskedExchangeMessage(
            0,
            1,
            first_resource.metadata.step,
            first_resource.metadata.resource_id,
            first_masked,
        )
        to_p1 = MaskedExchangeMessage(
            1,
            0,
            second_resource.metadata.step,
            second_resource.metadata.resource_id,
            second_masked,
        )
        opened = self._multiplier.open_masked_differences(to_p2.value, to_p1.value)
        opened_message = OpenedMaskedMessage(
            (0, 1),
            first_resource.metadata.step,
            first_resource.metadata.resource_id,
            opened,
        )
        first_product = p1.finish_product(self._multiplier, first_resource, opened_message.value)
        second_product = p2.finish_product(self._multiplier, second_resource, opened_message.value)

        first_truncated = p1.mask_truncation(self._truncation, first_product, first_resource)
        second_truncated = p2.mask_truncation(self._truncation, second_product, second_resource)
        p2_message = self._truncation.p2_send_masked(second_truncated)
        truncation_message = TruncationMaskedMessage(
            1,
            0,
            first_resource.metadata.step,
            first_resource.metadata.resource_id,
            p2_message,
        )
        p1_masked_value = self._truncation.p1_reconstruct_masked(
            first_truncated, truncation_message.value
        )
        first_result = p1.finish_truncation_p1(
            self._truncation, first_product, first_resource, p1_masked_value
        )
        second_result = p2.finish_truncation_p2(self._truncation, second_product, second_resource)
        first_resource._lifecycle.complete()
        return first_result, second_result

    def _add_vectors(
        self,
        p1: _Server,
        p2: _Server,
        left: tuple[AdditiveShare, AdditiveShare],
        right: tuple[AdditiveShare, AdditiveShare],
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """逐项线性相加两个同 shape 的本地向量 share，不建立明文向量。"""
        first_values = []
        second_values = []
        first_left, second_left = left
        first_right, second_right = right
        first_array = first_left.value
        second_array = second_left.value
        if len(first_array) != len(first_right.value) or len(second_array) != len(
            second_right.value
        ):
            raise ValueError("待相加的共享向量必须同形。")
        for index in range(len(first_array)):
            first_values.append(
                p1.add(
                    self._sharing,
                    AdditiveShare(first_array[index]),
                    AdditiveShare(first_right.value[index]),
                )
            )
            second_values.append(
                p2.add(
                    self._sharing,
                    AdditiveShare(second_array[index]),
                    AdditiveShare(second_right.value[index]),
                )
            )
        return _vector_from_scalars(first_values), _vector_from_scalars(second_values)

    def _term_shape(self, term: str, server: _Server) -> tuple[int, int]:
        """从公开 layout 返回通用矩阵 shape，拒绝任何场景特定矩阵名称。"""
        layout = server.layout
        shapes = {
            "A": (layout.state_dimension, layout.state_dimension),
            "B": (layout.state_dimension, layout.input_dimension),
            "C": (layout.output_dimension, layout.state_dimension),
            "D": (layout.output_dimension, layout.input_dimension),
        }
        try:
            return shapes[term]
        except KeyError as error:
            raise ValueError("矩阵项必须是通用 A、B、C 或 D。") from error

    def _validate_round(self, p1: P1, p2: P2, online: OnlineRound) -> None:
        """在触碰 state 前验证角色、shape、step、尺度和资源配对，失败时可整体废弃。"""
        if not isinstance(p1, P1) or not isinstance(p2, P2) or not isinstance(online, OnlineRound):
            raise TypeError("execute 需要 P1、P2 与 Client 准备的 OnlineRound。")
        if p1.layout != p2.layout:
            raise ValueError("P1 与 P2 必须安装相同 controller layout。")
        if online.step != online.p1_input.step or online.step != online.p2_input.step:
            raise ValueError("在线输入消息的 step 与 OnlineRound 不一致。")
        if online.p1_resources.recipient != 0 or online.p2_resources.recipient != 1:
            raise ValueError("在线资源包的角色路由不正确。")
        if online.p1_resources.plan != online.p2_resources.plan:
            raise ValueError("P1 与 P2 必须使用同一个资源计划。")
        plan = online.p1_resources.plan
        expected_shapes = (
            (p1.layout.state_dimension,),
            (p1.layout.input_dimension,),
            (p1.layout.output_dimension,),
        )
        if (plan.state_shape, plan.input_shape, plan.output_shape) != expected_shapes:
            raise ValueError("资源计划的公开 shape 与已安装 controller 不匹配。")
        if plan.step != online.step or plan.fractional_bits != p1.layout.fractional_bits:
            raise ValueError("资源计划的 step 或 fractional bits 与 controller 不匹配。")
        if (
            len(online.p1_resources.resources) != plan.resource_count
            or len(online.p2_resources.resources) != plan.resource_count
        ):
            raise ValueError("在线资源包数量与矩阵项资源计划不匹配。")
        for first, second, metadata in zip(
            online.p1_resources.resources,
            online.p2_resources.resources,
            plan.resources,
            strict=True,
        ):
            if (
                first.owner != 0
                or second.owner != 1
                or first.metadata != metadata
                or second.metadata != metadata
                or first._lifecycle is not second._lifecycle
                or first._lifecycle.status != "prepared"
            ):
                raise ValueError("在线资源必须成对、同元数据且尚未使用。")

    def _validate_resource_pair(
        self,
        first: ScalarResourceShare,
        second: ScalarResourceShare,
        term: str,
        index: tuple[int, int],
    ) -> None:
        """确认迭代到的两份资源正好属于当前矩阵元素，杜绝跨项复用。"""
        if (
            first.owner != 0
            or second.owner != 1
            or first.metadata != second.metadata
            or first._lifecycle is not second._lifecycle
            or first.metadata.term != term
            or first.metadata.index != index
            or first._lifecycle.status != "prepared"
        ):
            raise ValueError("矩阵项不能使用错配、已消费或已废弃的协议资源。")

    def _abort_round(self, online: OnlineRound) -> None:
        """在任意失败路径废弃本轮所有未完成资源，防止下一次调用重放残留材料。"""
        if not isinstance(online, OnlineRound):
            return
        for resource in (*online.p1_resources.resources, *online.p2_resources.resources):
            resource._lifecycle.abort()
