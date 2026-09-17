"""Client、P1 与 P2 的领域无关本地角色状态和操作。"""

from __future__ import annotations

import hashlib
import math
import random
import secrets
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
    PrimeModulusEvidence,
    PublicMaskedDifferences,
    SecureTruncation,
    TwoPartySharing,
)

from .messages import (
    ControllerLayout,
    ControllerRangeContract,
    ControllerScaleLedger,
    ControllerShare,
    ControlShareMessage,
    InputShareMessage,
    OfflineControllerMessage,
    OfflineDistribution,
    OnlineRound,
    PartyIndex,
    PartyResources,
    ProductResourceShare,
    ResourceMetadata,
    StateTruncationResourceShare,
    StepResourcePlan,
    _ResourceLifecycle,
)


def _require_step(step: int) -> int:
    """验证公开时间索引，避免 bool 或负数进入 round 和资源标识。"""
    if isinstance(step, bool) or not isinstance(step, Integral) or step < 0:
        raise ValueError("step 必须是非负整数。")
    return int(step)


def _scalar_from_array(share: AdditiveShare, index: tuple[int, ...]) -> AdditiveShare:
    """从本地向量或矩阵份额中取标量，不组合另一方份额。"""
    values = np.asarray(share.value, dtype=object)
    value = values[index]
    return AdditiveShare(value.item() if isinstance(value, np.generic) else value)


def _vector_from_scalars(values: list[AdditiveShare]) -> AdditiveShare:
    """将同一参与方的标量结果组装为 object 向量，保留任意精度 residue。"""
    result = np.empty(len(values), dtype=object)
    for index, value in enumerate(values):
        scalar = np.asarray(value.value, dtype=object)
        if scalar.ndim != 0:
            raise TypeError("控制器内部标量计算意外收到数组份额。")
        result[index] = scalar.item()
    return AdditiveShare(result)


class Client:
    """持有明文控制器/输入的编码与范围证明边界，不向任一 Server 发送两份 share。"""

    def __init__(
        self,
        fixed_point: FixedPointContext,
        sharing: TwoPartySharing,
        *,
        security_parameter: int,
        modulus_evidence: PrimeModulusEvidence | None = None,
    ) -> None:
        """建立 Client，并把公开模数证据交给唯一的 Protocol 2 验证入口。"""
        if fixed_point.modulus != sharing.modulus:
            raise ValueError("FixedPointContext 与 TwoPartySharing 必须使用相同 modulus。")
        self.fixed_point = fixed_point
        self.sharing = sharing
        self.multiplier = BeaverMultiplier(sharing)
        self.truncation = SecureTruncation(
            sharing,
            ell=fixed_point.fractional_bits,
            security_parameter=security_parameter,
            modulus_evidence=modulus_evidence,
        )
        # 身份不从可重放的离线/在线材料 RNG 派生；Client 以此登记其签发能力。
        self._issued_sessions: set[str] = set()
        self._issued_rounds: dict[tuple[str, str, int], ControllerLayout] = {}
        # 测试 RNG 每次 online 预处理都分配不同域，避免重新播种导致辅助材料复用。
        self._test_material_epoch = 0

    def distribute_controller(
        self,
        spec: ControllerSpec,
        range_contract: ControllerRangeContract,
        *,
        rng: random.Random | None = None,
    ) -> OfflineDistribution:
        """验证公开范围后，编码并按同一不可混淆 session 分发 ``A/B/C/D/x0``。"""
        if not isinstance(spec, ControllerSpec):
            raise TypeError("spec 必须是 ControllerSpec，不能是场景领域对象。")
        if not isinstance(range_contract, ControllerRangeContract):
            raise TypeError("range_contract 必须是 ControllerRangeContract。")
        layout = self._layout_from_spec(spec)
        range_contract.validate_layout(layout)
        if spec.scale_metadata is not None:
            self._validate_zero_scale_fields(spec, layout.scale_ledger)
        field_scales = {
            "A": layout.scale_ledger.A,
            "B": layout.scale_ledger.B,
            "C": layout.scale_ledger.C,
            "D": layout.scale_ledger.D,
            "x0": layout.scale_ledger.state,
        }
        payloads = {
            name: np.asarray(
                self._fixed_point_at_scale(field_scales[name]).encode(getattr(spec, name)),
                dtype=object,
            )
            for name in ("A", "B", "C", "D", "x0")
        }
        self._validate_range_contract(payloads, layout, range_contract)
        shares = {
            name: self.sharing.share(self.fixed_point.to_residue(value), rng=rng)
            for name, value in payloads.items()
        }
        session_id = self._identifier("controller")
        self._issued_sessions.add(session_id)
        first = ControllerShare(shares["A"][0], shares["B"][0], shares["C"][0], shares["D"][0])
        second = ControllerShare(shares["A"][1], shares["B"][1], shares["C"][1], shares["D"][1])
        first_message = OfflineControllerMessage(
            0, session_id, first, shares["x0"][0], layout, range_contract
        )
        second_message = OfflineControllerMessage(
            1, session_id, second, shares["x0"][1], layout, range_contract
        )
        return OfflineDistribution(session_id, range_contract, first_message, second_message)

    def prepare_online(
        self,
        distribution: OfflineDistribution,
        v: Any,
        *,
        step: int,
        rng: random.Random | None = None,
    ) -> OnlineRound:
        """验证 input payload 范围，并创建绑定 session/round 的 triples 与 state masks。"""
        layout = self._distribution_layout(distribution)
        if distribution.session_id not in self._issued_sessions:
            raise ValueError("离线分发不属于当前 Client 签发的 controller session。")
        step = _require_step(step)
        horizon = distribution.range_contract.horizon_steps
        if horizon is not None and step >= horizon:
            raise ValueError("step 超出已证明的 finite horizon，不能创建在线资源。")
        input_values = self._normalize_input(v, layout)
        input_payload = np.asarray(
            self._fixed_point_at_scale(layout.scale_ledger.input).encode(input_values), dtype=object
        )
        self._validate_input_bound(input_payload, distribution.range_contract)
        round_id = self._identifier("round")
        identity = (distribution.session_id, round_id, step)
        if identity in self._issued_rounds:
            raise ValueError("同一 controller session 内的 round_id 不能复用。")
        material_rng = self._online_material_rng(rng)
        input_shares = self.sharing.share(
            self.fixed_point.to_residue(input_payload), rng=material_rng
        )
        plan = self._resource_plan(layout, distribution.session_id, round_id, step)
        first_products: list[ProductResourceShare] = []
        second_products: list[ProductResourceShare] = []
        for metadata in plan.product_resources:
            triple = self.multiplier.create_triple(rng=material_rng)
            lifecycle = _ResourceLifecycle()
            first_products.append(ProductResourceShare(0, metadata, triple[0], lifecycle))
            second_products.append(ProductResourceShare(1, metadata, triple[1], lifecycle))
        first_truncations: list[StateTruncationResourceShare] = []
        second_truncations: list[StateTruncationResourceShare] = []
        for metadata in plan.state_truncation_resources:
            auxiliary = self.truncation.create_auxiliary(rng=material_rng)
            lifecycle = _ResourceLifecycle()
            first_truncations.append(
                StateTruncationResourceShare(0, metadata, auxiliary[0], lifecycle)
            )
            second_truncations.append(
                StateTruncationResourceShare(1, metadata, auxiliary[1], lifecycle)
            )
        online = OnlineRound(
            distribution.session_id,
            round_id,
            step,
            InputShareMessage(0, distribution.session_id, round_id, step, input_shares[0]),
            InputShareMessage(1, distribution.session_id, round_id, step, input_shares[1]),
            PartyResources(0, plan, tuple(first_products), tuple(first_truncations)),
            PartyResources(1, plan, tuple(second_products), tuple(second_truncations)),
        )
        # 只有整轮 input 与资源全部准备成功后才签发输出 capability。
        self._issued_rounds[identity] = layout
        return online

    def reconstruct_control(
        self, first: ControlShareMessage, second: ControlShareMessage
    ) -> np.ndarray:
        """在 Client 边界对已签发 round 的正确 shape/ledger scale control shares 重构一次。"""
        if not isinstance(first, ControlShareMessage) or not isinstance(
            second, ControlShareMessage
        ):
            raise TypeError("控制输出必须是两条 ControlShareMessage。")
        if (
            (first.sender, second.sender) != (0, 1)
            or first.session_id != second.session_id
            or first.round_id != second.round_id
            or first.step != second.step
            or first.fractional_bits != second.fractional_bits
        ):
            raise ValueError("控制输出必须是同一 session/round、同尺度的 P1、P2 shares。")
        identity = (first.session_id, first.round_id, first.step)
        layout = self._issued_rounds.get(identity)
        if layout is None:
            raise ValueError("控制输出不属于当前 Client 签发的 round，或该 round 已完成重构。")
        if first.fractional_bits != layout.scale_ledger.output:
            raise ValueError("控制输出 fractional bits 与当前 round 的 scale ledger 不一致。")
        expected_shape = (layout.output_dimension,)
        if (
            np.asarray(first.value.value, dtype=object).shape != expected_shape
            or np.asarray(second.value.value, dtype=object).shape != expected_shape
        ):
            raise ValueError(f"控制输出 share 必须具有 output dimension shape {expected_shape}。")
        signed = np.asarray(
            self.fixed_point.from_residue(self.sharing.reconstruct(first.value, second.value)),
            dtype=object,
        )
        result = np.empty(signed.shape, dtype=float)
        scale = 1 << first.fractional_bits
        for index in np.ndindex(signed.shape):
            value = int(signed[index]) / scale
            if not math.isfinite(value):
                raise ValueError("ledger scale control output 无法安全解码为有限浮点数。")
            result[index] = value
        # 成功解码后关闭 capability，防止上层误把同一 round 的 control 重复应用。
        del self._issued_rounds[identity]
        return result

    def abort_round(self, online: OnlineRound) -> None:
        """关闭当前 Client 已签发但未成功重构的 round capability。

        该操作不接收、更不重构任何 share。执行阶段失败时资源由 coordinator 永久废弃；
        输出重构失败时资源已经消费，因此这里只负责阻止失败输出被再次应用。
        """
        if not isinstance(online, OnlineRound):
            raise TypeError("online 必须是 Client.prepare_online 返回的 OnlineRound。")
        identity = (online.session_id, online.round_id, online.step)
        if online.session_id not in self._issued_sessions or identity not in self._issued_rounds:
            raise ValueError("只能关闭当前 Client 尚未完成的 round capability。")
        del self._issued_rounds[identity]

    def _layout_from_spec(self, spec: ControllerSpec) -> ControllerLayout:
        """由 metadata 建立首版支持的尺度账本，并提取公开 controller 维度。"""
        scale = self.fixed_point.fractional_bits
        metadata = spec.scale_metadata
        if metadata is None:
            state = input_scale = A = B = C = D = scale
            output = 2 * scale
        else:
            if metadata.state != scale or metadata.input != scale:
                raise ValueError(
                    "首版协议要求 state/input scale 等于 FixedPointContext 的基础 ell。"
                )
            state, input_scale = metadata.state, metadata.input
            A, B, C, D, output = metadata.A, metadata.B, metadata.C, metadata.D, metadata.output
        state_accumulator = A + state
        output_accumulator = C + state
        ledger = ControllerScaleLedger(
            state,
            input_scale,
            A,
            B,
            C,
            D,
            state_accumulator,
            state_accumulator - state if state_accumulator >= state else -1,
            output_accumulator,
            output,
        )
        return ControllerLayout(
            spec.state_dimension, spec.input_dimension, spec.output_dimension, ledger
        )

    def _fixed_point_at_scale(self, fractional_bits: int) -> FixedPointContext:
        """复用相同 q/payload 位宽，只改变字段编码所需的公开 fractional bits。"""
        return FixedPointContext(
            self.fixed_point.modulus,
            integer_bits=self.fixed_point.integer_bits,
            fractional_bits=fractional_bits,
        )

    def _validate_zero_scale_fields(
        self, spec: ControllerSpec, ledger: ControllerScaleLedger
    ) -> None:
        """拒绝把非整数值声明为零分数位，避免论文取整静默改变控制器。"""
        scales = {
            "A": ledger.A,
            "B": ledger.B,
            "C": ledger.C,
            "D": ledger.D,
            "x0": ledger.state,
        }
        for name, scale in scales.items():
            if scale != 0:
                continue
            for value in np.asarray(getattr(spec, name), dtype=object).flat:
                if not isinstance(value, Integral) and value != int(value):
                    raise ValueError(f"{name} 声明为零 fractional bits 时必须只包含数学整数。")

    def _distribution_layout(self, distribution: OfflineDistribution) -> ControllerLayout:
        """验证两条离线消息由同一次 Client 分发产生，拒绝同 shape 的跨 session 拼接。"""
        if not isinstance(distribution, OfflineDistribution):
            raise TypeError("distribution 必须来自 Client.distribute_controller。")
        first, second = distribution.p1, distribution.p2
        if (
            first.recipient != 0
            or second.recipient != 1
            or first.session_id != distribution.session_id
            or second.session_id != distribution.session_id
            or first.layout != second.layout
            or first.range_contract != distribution.range_contract
            or second.range_contract != distribution.range_contract
        ):
            raise ValueError("离线分发的角色、session、layout 或范围契约不一致。")
        distribution.range_contract.validate_layout(first.layout)
        return first.layout

    def _normalize_input(self, value: Any, layout: ControllerLayout) -> np.ndarray:
        """将单输入标量或长度为 m 的扁平向量规范化为 ``(m,)`` shape。"""
        array = np.asarray(value, dtype=object)
        if array.ndim == 0 and layout.input_dimension == 1:
            array = array.reshape(1)
        if array.shape != (layout.input_dimension,):
            raise ValueError(f"v 必须具有 shape ({layout.input_dimension},)。")
        return array

    def _validate_range_contract(
        self,
        payloads: dict[str, np.ndarray],
        layout: ControllerLayout,
        contract: ControllerRangeContract,
    ) -> None:
        """证明有界输入下 state 递推保持 Protocol 2 与 centered ``Z_q`` 的前置条件。"""
        state_bounds = contract.state_payload_bounds
        input_bounds = contract.input_payload_bounds
        if any(value > self.fixed_point.maximum_payload for value in state_bounds):
            raise ValueError(
                "state_payload_bounds 不能超出 FixedPointContext 的可表示 payload 范围。"
            )
        if any(value > self.fixed_point.maximum_payload for value in input_bounds):
            raise ValueError(
                "input_payload_bounds 不能超出 FixedPointContext 的可表示 payload 范围。"
            )
        for index, value in enumerate(payloads["x0"]):
            if abs(int(value)) > state_bounds[index]:
                raise ValueError("x0 payload 超出公开 state_payload_bounds。")

        if contract.horizon_steps is not None:
            self._validate_finite_horizon(payloads, layout, contract)
            return

        state_raw_bounds = self._row_bounds(
            payloads["A"], state_bounds, payloads["B"], input_bounds
        )
        ledger = layout.scale_ledger
        maximum_truncation_message = self.truncation.maximum_message
        centered_limit = (self.sharing.modulus - 1) // 2
        for index, raw_bound in enumerate(state_raw_bounds):
            if ledger.state_truncation_bits:
                if raw_bound > maximum_truncation_message:
                    raise ValueError("state 聚合乘积超出 Protocol 2 的 Z<kappa> 范围。")
                # Protocol 2 paper rounding 后还可能有 w∈{-1,0,1}，不变集需预留 1。
                truncation_scale = 1 << ledger.state_truncation_bits
                next_bound = (raw_bound + truncation_scale - 1) // truncation_scale + 1
            else:
                if raw_bound > centered_limit:
                    raise ValueError("无需 Trunc 的 state 聚合乘积可能越出 centered Z_q 范围。")
                next_bound = raw_bound
            if next_bound > state_bounds[index]:
                raise ValueError("state_payload_bounds 不是给定输入范围下的不变安全范围。")

        output_raw_bounds = self._row_bounds(
            payloads["C"], state_bounds, payloads["D"], input_bounds
        )
        if any(value > centered_limit for value in output_raw_bounds):
            raise ValueError("control output 聚合乘积可能越出 centered Z_q 范围。")
        if len(state_raw_bounds) != layout.state_dimension:
            raise AssertionError("state 范围验证的行数与 controller layout 不一致。")

    def _validate_finite_horizon(
        self,
        payloads: dict[str, np.ndarray],
        layout: ControllerLayout,
        contract: ControllerRangeContract,
    ) -> None:
        """以 Python 精确整数从编码 x0 逐步证明有限 horizon 的范围前提。

        ``s_k`` 是各 state payload 的公开绝对上界。每个可执行 k 先用 ``s_k``
        检查更新前输出，再检查 state accumulator 与 Trunc 前提，推得 ``s_(k+1)``；
        终点 state 也须在声明界内，但不虚构终点的额外 controller step。
        """
        current = [abs(int(value)) for value in payloads["x0"]]
        input_bounds = contract.input_payload_bounds
        state_bounds = contract.state_payload_bounds
        ledger = layout.scale_ledger
        centered_limit = (self.sharing.modulus - 1) // 2
        maximum_truncation_message = self.truncation.maximum_message
        assert contract.horizon_steps is not None

        for step in range(contract.horizon_steps):
            output_raw_bounds = self._row_bounds(
                payloads["C"], tuple(current), payloads["D"], input_bounds
            )
            if any(value > centered_limit for value in output_raw_bounds):
                raise ValueError(f"finite horizon 第 {step} 步 output 超出 centered Z_q 范围。")

            state_raw_bounds = self._row_bounds(
                payloads["A"], tuple(current), payloads["B"], input_bounds
            )
            next_bounds: list[int] = []
            for raw_bound in state_raw_bounds:
                if ledger.state_truncation_bits:
                    if raw_bound > maximum_truncation_message:
                        raise ValueError(
                            f"finite horizon 第 {step} 步 state 超出 Protocol 2 的 Z<kappa> 范围。"
                        )
                    truncation_scale = 1 << ledger.state_truncation_bits
                    # Protocol 2 的 rounding 与 w∈{-1,0,1} 需要额外保留 1 payload。
                    next_bound = (raw_bound + truncation_scale - 1) // truncation_scale + 1
                else:
                    if raw_bound > centered_limit:
                        raise ValueError(
                            f"finite horizon 第 {step} 步 state 超出 centered Z_q 范围。"
                        )
                    next_bound = raw_bound
                next_bounds.append(next_bound)
            if any(value > bound for value, bound in zip(next_bounds, state_bounds)):
                raise ValueError(
                    f"finite horizon 第 {step + 1} 步 state 超出 state_payload_bounds。"
                )
            current = next_bounds

    def _validate_input_bound(self, payload: np.ndarray, contract: ControllerRangeContract) -> None:
        """在 Client 分享前检查每个实际 input payload 未超出公开范围。"""
        for index, value in enumerate(payload):
            if abs(int(value)) > contract.input_payload_bounds[index]:
                raise ValueError("v payload 超出公开 input_payload_bounds。")

    def _row_bounds(
        self,
        first: np.ndarray,
        first_bounds: tuple[int, ...],
        second: np.ndarray,
        second_bounds: tuple[int, ...],
    ) -> list[int]:
        """以三角不等式计算每行 ledger accumulator 的公开绝对上界，不读取 shares。"""
        bounds: list[int] = []
        for row in range(first.shape[0]):
            bound = sum(
                abs(int(first[row, column])) * first_bounds[column]
                for column in range(first.shape[1])
            )
            bound += sum(
                abs(int(second[row, column])) * second_bounds[column]
                for column in range(second.shape[1])
            )
            bounds.append(bound)
        return bounds

    def _resource_plan(
        self, layout: ControllerLayout, session_id: str, round_id: str, step: int
    ) -> StepResourcePlan:
        """按 ledger 分配所有乘法 triple，以及零份或逐 state 行一份 Trunc mask。"""
        shapes = {
            "A": (layout.state_dimension, layout.state_dimension),
            "B": (layout.state_dimension, layout.input_dimension),
            "C": (layout.output_dimension, layout.state_dimension),
            "D": (layout.output_dimension, layout.input_dimension),
        }
        products: list[ResourceMetadata] = []
        ledger = layout.scale_ledger
        for term in ("C", "D", "A", "B"):
            rows, columns = shapes[term]
            right_scale = ledger.state if term in {"A", "C"} else ledger.input
            left_scale = getattr(ledger, term)
            for row in range(rows):
                for column in range(columns):
                    products.append(
                        ResourceMetadata(
                            f"{round_id}:{term}[{row},{column}]",
                            session_id,
                            round_id,
                            step,
                            "multiplication",
                            term,  # type: ignore[arg-type]
                            (row, column),
                            shapes[term],
                            left_scale,
                            right_scale,
                            left_scale + right_scale,
                        )
                    )
        truncations = (
            tuple(
                ResourceMetadata(
                    f"{round_id}:state[{row}]",
                    session_id,
                    round_id,
                    step,
                    "state_truncation",
                    "state",
                    (row,),
                    (layout.state_dimension,),
                    ledger.state_accumulator,
                    None,
                    ledger.state,
                )
                for row in range(layout.state_dimension)
            )
            if ledger.state_truncation_bits
            else ()
        )
        return StepResourcePlan(
            session_id,
            round_id,
            step,
            (layout.state_dimension,),
            (layout.input_dimension,),
            (layout.output_dimension,),
            ledger,
            tuple(products),
            truncations,
        )

    def _identifier(self, prefix: str) -> str:
        """从独立安全随机源生成身份，避免固定材料 seed 造成 session/round 碰撞。"""
        return f"{prefix}-{secrets.token_hex(16)}"

    def _online_material_rng(self, rng: random.Random | None) -> random.Random | None:
        """为每轮测试材料作确定性域分离，避免相同 seed 重播时复用 Beaver/Trunc 随机量。

        未传入 ``rng`` 或显式传入 ``SystemRandom`` 时，沿用各 crypto primitive 的安全随机源。
        只有普通可重放测试 RNG 会先取固定宽度种子，再与此 Client 的单调 epoch 哈希；不同
        Client 的首轮仍可复现，同一 Client 的后续 round 则必定进入不同随机域。
        """
        if rng is None or isinstance(rng, random.SystemRandom):
            return rng
        source_seed = rng.getrandbits(256).to_bytes(32, "big")
        epoch = self._test_material_epoch
        self._test_material_epoch += 1
        domain = epoch.to_bytes(16, "big")
        seed = hashlib.sha256(b"secure_control.protocol.online_material.v1" + domain + source_seed)
        return random.Random(int.from_bytes(seed.digest(), "big"))


@dataclass(slots=True)
class _Server:
    """P1/P2 共享的本地操作；实例只保存本方参数/state shares 与所属 controller session。"""

    _party: PartyIndex
    _session_id: str
    _controller: ControllerShare
    _state: AdditiveShare
    _layout: ControllerLayout

    @property
    def controller_share(self) -> ControllerShare:
        """返回本方参数 share 容器，不暴露另一方参数。"""
        return self._controller

    @property
    def state_share(self) -> AdditiveShare:
        """返回本方当前 controller state share，而不是 state plaintext。"""
        return self._state

    @property
    def layout(self) -> ControllerLayout:
        """返回控制器公开维度与定点尺度。"""
        return self._layout

    @property
    def session_id(self) -> str:
        """返回当前安装控制器的不可混淆公开 session identity。"""
        return self._session_id

    def input_share(
        self, message: InputShareMessage, *, session_id: str, round_id: str, step: int
    ) -> AdditiveShare:
        """接收本方同一 session/round 的 input share，拒绝两份 share 或错序消息。"""
        if not isinstance(message, InputShareMessage):
            raise TypeError("Server 只能接收单条 InputShareMessage。")
        if (
            message.recipient != self._party
            or message.session_id != session_id
            or message.round_id != round_id
            or message.step != step
        ):
            raise ValueError("输入消息的角色、session、round 或 step 与当前协议不匹配。")
        values = np.asarray(message.value.value, dtype=object)
        if values.shape != (self._layout.input_dimension,):
            raise ValueError("输入 share 的 shape 与 controller input dimension 不匹配。")
        return message.value

    def matrix_value(self, term: str, row: int, column: int) -> AdditiveShare:
        """读取本方公开索引的 A/B/C/D 参数份额，不重构参数。"""
        if term not in {"A", "B", "C", "D"}:
            raise ValueError("矩阵项必须是通用 A、B、C 或 D。")
        return _scalar_from_array(getattr(self._controller, term), (row, column))

    def state_value(self, index: int) -> AdditiveShare:
        """读取本方当前状态向量的一项，不重构 state。"""
        return _scalar_from_array(self._state, (index,))

    def input_value(self, input_share: AdditiveShare, index: int) -> AdditiveShare:
        """读取本方当前输入向量的一项，不接触对方 input share。"""
        return _scalar_from_array(input_share, (index,))

    def start_product(
        self,
        multiplier: BeaverMultiplier,
        left: AdditiveShare,
        right: AdditiveShare,
        resource: ProductResourceShare,
    ) -> MaskedDifferenceShare:
        """以本地 operands/triple share 生成 Beaver 遮蔽差值，乘积保持 ledger 结果尺度。"""
        self._validate_product_resource(resource)
        resource._lifecycle.claim(self._party)
        return multiplier.mask_inputs(left, right, resource.triple)

    def finish_product(
        self,
        multiplier: BeaverMultiplier,
        resource: ProductResourceShare,
        opened: PublicMaskedDifferences,
    ) -> AdditiveShare:
        """使用公开 d/e 和本方 triple share 完成 ledger 结果尺度的乘法 share。"""
        self._validate_product_resource(resource)
        return multiplier.finish(resource.triple, opened)

    def mask_truncation(
        self,
        truncation: SecureTruncation,
        value: AdditiveShare,
        resource: StateTruncationResourceShare,
    ) -> MaskedTruncationShare:
        """仅对聚合 state 行执行 Protocol 2 遮蔽，不对单个矩阵乘积截断。"""
        self._validate_truncation_resource(resource)
        resource._lifecycle.claim(self._party)
        return truncation.mask_input(value, resource.truncation)

    def finish_truncation_p1(
        self,
        truncation: SecureTruncation,
        value: AdditiveShare,
        resource: StateTruncationResourceShare,
        masked_value: P1MaskedValue,
    ) -> AdditiveShare:
        """仅 P1 使用 P2 masked message 完成该 state 行的一次截断。"""
        self._validate_truncation_resource(resource)
        if self._party != 0:
            raise ValueError("只有 P1 可以完成 Protocol 2 的 P1 分支。")
        return truncation.finish_p1(value, resource.truncation, masked_value)

    def finish_truncation_p2(
        self,
        truncation: SecureTruncation,
        value: AdditiveShare,
        resource: StateTruncationResourceShare,
    ) -> AdditiveShare:
        """仅 P2 在不接收 P1 消息的条件下完成该 state 行的一次截断。"""
        self._validate_truncation_resource(resource)
        if self._party != 1:
            raise ValueError("只有 P2 可以完成 Protocol 2 的 P2 分支。")
        return truncation.finish_p2(value, resource.truncation)

    def add(
        self, sharing: TwoPartySharing, left: AdditiveShare, right: AdditiveShare
    ) -> AdditiveShare:
        """执行本方线性 share 加法；该操作不消耗 Beaver 或 Trunc 资源。"""
        return sharing.add(left, right)

    def commit_state(self, state: AdditiveShare) -> None:
        """只在完整 round 成功后原子替换本方 state share。"""
        values = np.asarray(state.value, dtype=object)
        if values.shape != (self._layout.state_dimension,):
            raise ValueError("下一状态 share 的 shape 与 controller state dimension 不匹配。")
        self._state = state

    def _validate_product_resource(self, resource: ProductResourceShare) -> None:
        """确认 triple 只属于当前角色、矩阵乘法 metadata 与资源尺度正确。"""
        if not isinstance(resource, ProductResourceShare) or resource.owner != self._party:
            raise ValueError("Server 只能使用 Client 分发给本方的一份乘法资源。")
        if resource.triple.party_index != self._party or resource.metadata.kind != "multiplication":
            raise ValueError("乘法资源的角色或 metadata 不一致。")

    def _validate_truncation_resource(self, resource: StateTruncationResourceShare) -> None:
        """确认 mask 只属于当前角色，并且仅声明用于聚合后的 state 行。"""
        if not isinstance(resource, StateTruncationResourceShare) or resource.owner != self._party:
            raise ValueError("Server 只能使用 Client 分发给本方的一份 state 截断资源。")
        if (
            resource.truncation.party_index != self._party
            or resource.metadata.kind != "state_truncation"
        ):
            raise ValueError("截断资源的角色或 metadata 不一致。")


class P1(_Server):
    """协议第一方；仅持有 P1 参数、state、input 和辅助随机量 shares。"""

    def __init__(self, message: OfflineControllerMessage) -> None:
        """由单条 P1 离线消息初始化，不接受完整控制器或 P2 数据。"""
        if not isinstance(message, OfflineControllerMessage) or message.recipient != 0:
            raise ValueError("P1 必须由一条发送给 P1 的 OfflineControllerMessage 初始化。")
        super().__init__(
            0, message.session_id, message.controller, message.initial_state, message.layout
        )


class P2(_Server):
    """协议第二方；仅持有 P2 参数、state、input 和辅助随机量 shares。"""

    def __init__(self, message: OfflineControllerMessage) -> None:
        """由单条 P2 离线消息初始化，不接受完整控制器或 P1 数据。"""
        if not isinstance(message, OfflineControllerMessage) or message.recipient != 1:
            raise ValueError("P2 必须由一条发送给 P2 的 OfflineControllerMessage 初始化。")
        super().__init__(
            1, message.session_id, message.controller, message.initial_state, message.layout
        )
