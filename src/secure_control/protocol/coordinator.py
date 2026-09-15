"""单进程下的 Protocol 3 消息协调，不向 Server 提供明文或完整 state。"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from secure_control.crypto import AdditiveShare, BeaverMultiplier, SecureTruncation, TwoPartySharing

from .messages import (
    ControlShareMessage,
    MaskedExchangeMessage,
    OnlineRound,
    OpenedMaskedMessage,
    ProductResourceShare,
    StateTruncationResourceShare,
    TruncationMaskedMessage,
)
from .roles import P1, P2, _Server, _vector_from_scalars


class SingleProcessCoordinator:
    """协调本地消息投递与公开 masked 值；输出始终是同一 round 的双尺度 control shares。

    该类只是当前 transport/协调选择。它只能暂态配对 Beaver 遮蔽差值而得到允许公开
    的 ``d/e``，从不重构参数、state、input 或 control output；明文重构仅在 Client
    的显式边界发生。
    """

    def __init__(
        self, sharing: TwoPartySharing, multiplier: BeaverMultiplier, truncation: SecureTruncation
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
        """按 Protocol 3 执行 ``u=Cx+Dv`` 与 ``x_next=Trunc(Ax+Bv)``。

        所有标量乘积先保持 ``2^(2ell)`` 尺度并完成行内加法；只有聚合 state 行使用一
        对 Trunc 随机量。输出不截断，保持双尺度直到 Client 解码。任意失败均废弃本轮
        未完成资源且不提交新 state。
        """
        try:
            self._validate_round(p1, p2, online)
            first_input = p1.input_share(
                online.p1_input,
                session_id=online.session_id,
                round_id=online.round_id,
                step=online.step,
            )
            second_input = p2.input_share(
                online.p2_input,
                session_id=online.session_id,
                round_id=online.round_id,
                step=online.step,
            )
            products = iter(
                zip(online.p1_resources.product_resources, online.p2_resources.product_resources)
            )

            c_state = self._matrix_vector_products(
                "C", p1, p2, p1.state_value, p2.state_value, products
            )
            d_input = self._matrix_vector_products(
                "D",
                p1,
                p2,
                lambda index: p1.input_value(first_input, index),
                lambda index: p2.input_value(second_input, index),
                products,
            )
            output = self._add_vectors(p1, p2, c_state, d_input)

            a_state = self._matrix_vector_products(
                "A", p1, p2, p1.state_value, p2.state_value, products
            )
            b_input = self._matrix_vector_products(
                "B",
                p1,
                p2,
                lambda index: p1.input_value(first_input, index),
                lambda index: p2.input_value(second_input, index),
                products,
            )
            raw_next_state = self._add_vectors(p1, p2, a_state, b_input)
            if next(products, None) is not None:
                raise ValueError("本轮乘法资源计划包含未被消费的矩阵项。")
            next_state = self._truncate_state_rows(p1, p2, raw_next_state, online)
            p1.commit_state(next_state[0])
            p2.commit_state(next_state[1])
            return (
                ControlShareMessage(
                    0,
                    online.session_id,
                    online.round_id,
                    online.step,
                    2 * p1.layout.fractional_bits,
                    output[0],
                ),
                ControlShareMessage(
                    1,
                    online.session_id,
                    online.round_id,
                    online.step,
                    2 * p2.layout.fractional_bits,
                    output[1],
                ),
            )
        except Exception:
            self._abort_round(online)
            raise

    def _matrix_vector_products(
        self,
        term: str,
        p1: P1,
        p2: P2,
        first_right: Callable[[int], AdditiveShare],
        second_right: Callable[[int], AdditiveShare],
        products: Iterator[tuple[ProductResourceShare, ProductResourceShare]],
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """以逐标量 Beaver 乘法形成双尺度矩阵/向量积，绝不在此处截断。"""
        rows, columns = self._term_shape(term, p1)
        first_values: list[AdditiveShare] = []
        second_values: list[AdditiveShare] = []
        for row in range(rows):
            first_sum = AdditiveShare(0)
            second_sum = AdditiveShare(0)
            for column in range(columns):
                first_resource, second_resource = next(products)
                self._validate_product_pair(first_resource, second_resource, term, (row, column))
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
        first_resource: ProductResourceShare,
        second_resource: ProductResourceShare,
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """执行一个双尺度 Beaver 乘法，并模拟绑定 session/round 的双向遮蔽消息。"""
        first_masked = p1.start_product(self._multiplier, first_left, first_right, first_resource)
        second_masked = p2.start_product(
            self._multiplier, second_left, second_right, second_resource
        )
        metadata = first_resource.metadata
        to_p2 = MaskedExchangeMessage(
            0,
            1,
            metadata.session_id,
            metadata.round_id,
            metadata.step,
            metadata.resource_id,
            first_masked,
        )
        to_p1 = MaskedExchangeMessage(
            1,
            0,
            metadata.session_id,
            metadata.round_id,
            metadata.step,
            metadata.resource_id,
            second_masked,
        )
        opened = self._multiplier.open_masked_differences(to_p2.value, to_p1.value)
        opened_message = OpenedMaskedMessage(
            (0, 1),
            metadata.session_id,
            metadata.round_id,
            metadata.step,
            metadata.resource_id,
            opened,
        )
        first_product = p1.finish_product(self._multiplier, first_resource, opened_message.value)
        second_product = p2.finish_product(self._multiplier, second_resource, opened_message.value)
        first_resource._lifecycle.complete()
        return first_product, second_product

    def _truncate_state_rows(
        self,
        p1: P1,
        p2: P2,
        raw_state: tuple[AdditiveShare, AdditiveShare],
        online: OnlineRound,
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """对每个聚合 state 行恰好调用一次 Protocol 2，并保持单个 ``w`` 误差语义。"""
        first_values: list[AdditiveShare] = []
        second_values: list[AdditiveShare] = []
        for row, (first_resource, second_resource) in enumerate(
            zip(
                online.p1_resources.state_truncation_resources,
                online.p2_resources.state_truncation_resources,
                strict=True,
            )
        ):
            self._validate_truncation_pair(first_resource, second_resource, row)
            first_raw = AdditiveShare(raw_state[0].value[row])
            second_raw = AdditiveShare(raw_state[1].value[row])
            first_masked = p1.mask_truncation(self._truncation, first_raw, first_resource)
            second_masked = p2.mask_truncation(self._truncation, second_raw, second_resource)
            p2_message = self._truncation.p2_send_masked(second_masked)
            metadata = first_resource.metadata
            message = TruncationMaskedMessage(
                1,
                0,
                metadata.session_id,
                metadata.round_id,
                metadata.step,
                metadata.resource_id,
                p2_message,
            )
            first_masked_value = self._truncation.p1_reconstruct_masked(first_masked, message.value)
            first_values.append(
                p1.finish_truncation_p1(
                    self._truncation, first_raw, first_resource, first_masked_value
                )
            )
            second_values.append(
                p2.finish_truncation_p2(self._truncation, second_raw, second_resource)
            )
            first_resource._lifecycle.complete()
        return _vector_from_scalars(first_values), _vector_from_scalars(second_values)

    def _add_vectors(
        self,
        p1: _Server,
        p2: _Server,
        left: tuple[AdditiveShare, AdditiveShare],
        right: tuple[AdditiveShare, AdditiveShare],
    ) -> tuple[AdditiveShare, AdditiveShare]:
        """逐项线性相加同 shape 的两组本地向量 share，不建立明文向量。"""
        first_left, second_left = left
        first_right, second_right = right
        if len(first_left.value) != len(first_right.value) or len(second_left.value) != len(
            second_right.value
        ):
            raise ValueError("待相加的共享向量必须同形。")
        first_values = [
            p1.add(
                self._sharing,
                AdditiveShare(first_left.value[index]),
                AdditiveShare(first_right.value[index]),
            )
            for index in range(len(first_left.value))
        ]
        second_values = [
            p2.add(
                self._sharing,
                AdditiveShare(second_left.value[index]),
                AdditiveShare(second_right.value[index]),
            )
            for index in range(len(second_left.value))
        ]
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
        """在资源 claim 前验证角色、session、round、shape、scale 及两方资源配对。"""
        if not isinstance(p1, P1) or not isinstance(p2, P2) or not isinstance(online, OnlineRound):
            raise TypeError("execute 需要 P1、P2 与 Client 准备的 OnlineRound。")
        if (
            p1.layout != p2.layout
            or p1.session_id != p2.session_id
            or p1.session_id != online.session_id
        ):
            raise ValueError("P1、P2 与 OnlineRound 必须绑定同一 controller session。")
        if any(
            (message.session_id, message.round_id, message.step)
            != (online.session_id, online.round_id, online.step)
            for message in (online.p1_input, online.p2_input)
        ):
            raise ValueError("在线输入必须绑定同一 session、round 与 step。")
        if (
            online.p1_resources.recipient != 0
            or online.p2_resources.recipient != 1
            or online.p1_resources.plan != online.p2_resources.plan
        ):
            raise ValueError("在线资源包的角色路由或资源计划不一致。")
        plan = online.p1_resources.plan
        if (plan.session_id, plan.round_id, plan.step) != (
            online.session_id,
            online.round_id,
            online.step,
        ):
            raise ValueError("资源计划必须绑定当前 session、round 与 step。")
        if (plan.state_shape, plan.input_shape, plan.output_shape) != (
            (p1.layout.state_dimension,),
            (p1.layout.input_dimension,),
            (p1.layout.output_dimension,),
        ) or plan.fractional_bits != p1.layout.fractional_bits:
            raise ValueError("资源计划的公开 shape 或 fractional bits 与控制器不匹配。")
        self._validate_resource_collection(
            online.p1_resources.product_resources,
            online.p2_resources.product_resources,
            plan.product_resources,
        )
        self._validate_resource_collection(
            online.p1_resources.state_truncation_resources,
            online.p2_resources.state_truncation_resources,
            plan.state_truncation_resources,
        )

    def _validate_resource_collection(
        self, first: tuple[object, ...], second: tuple[object, ...], metadata: tuple[object, ...]
    ) -> None:
        """确认两方资源按同一 metadata 一一配对且全部仍处于 prepared 状态。"""
        if len(first) != len(metadata) or len(second) != len(metadata):
            raise ValueError("在线资源数量与资源计划不匹配。")
        for first_item, second_item, expected in zip(first, second, metadata, strict=True):
            if (
                (getattr(first_item, "owner", None), getattr(second_item, "owner", None)) != (0, 1)
                or getattr(first_item, "metadata", None) != expected
                or getattr(second_item, "metadata", None) != expected
                or getattr(first_item, "_lifecycle", None)
                is not getattr(second_item, "_lifecycle", None)
                or getattr(first_item, "_lifecycle", None).status != "prepared"
            ):
                raise ValueError("在线资源必须成对、同元数据且尚未使用。")

    def _validate_product_pair(
        self,
        first: ProductResourceShare,
        second: ProductResourceShare,
        term: str,
        index: tuple[int, int],
    ) -> None:
        """确认当前 triple pair 正好属于指定矩阵元素并保持 ``ell→2ell`` 尺度。"""
        metadata = first.metadata
        if (
            first.owner != 0
            or second.owner != 1
            or metadata != second.metadata
            or first._lifecycle is not second._lifecycle
            or metadata.kind != "multiplication"
            or metadata.term != term
            or metadata.index != index
            or (metadata.input_fractional_bits, metadata.output_fractional_bits)
            != (self._truncation.ell, 2 * self._truncation.ell)
            or first._lifecycle.status != "prepared"
        ):
            raise ValueError("矩阵项不能使用错配、错误尺度或已消费的乘法资源。")

    def _validate_truncation_pair(
        self, first: StateTruncationResourceShare, second: StateTruncationResourceShare, row: int
    ) -> None:
        """确认截断资源只对应聚合 state 第 row 行，并恢复 ``2ell→ell`` 尺度。"""
        metadata = first.metadata
        if (
            first.owner != 0
            or second.owner != 1
            or metadata != second.metadata
            or first._lifecycle is not second._lifecycle
            or metadata.kind != "state_truncation"
            or metadata.term != "state"
            or metadata.index != (row,)
            or (metadata.input_fractional_bits, metadata.output_fractional_bits)
            != (2 * self._truncation.ell, self._truncation.ell)
            or first._lifecycle.status != "prepared"
        ):
            raise ValueError("state 行不能使用错配、错误尺度或已消费的截断资源。")

    def _abort_round(self, online: OnlineRound) -> None:
        """在任意失败路径废弃本轮全部未完成 triples/masks，阻止残留材料重放。"""
        if not isinstance(online, OnlineRound):
            return
        resources = (
            *online.p1_resources.product_resources,
            *online.p2_resources.product_resources,
            *online.p1_resources.state_truncation_resources,
            *online.p2_resources.state_truncation_resources,
        )
        for resource in resources:
            resource._lifecycle.abort()
