"""倒立摆连续 LAN 的有限范围证明、双支装配及场景证据。"""

from __future__ import annotations

from math import inf, nextafter

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.protocol import ControllerRangeContract
from secure_control.simulation import SimulationBranch, SimulationPlan, SimulationResult

from .adapter import CartPoleAdapter, _finite_vector
from .contract import CartPoleContract
from .controller import CartPoleBalanceConfig
from .experiment import BalanceMonitor
from .plant import CartPolePlant

SCENARIO_VERSION = "1"


def cart_pole_numeric_contract(
    spec: ControllerSpec, config: CartPoleBalanceConfig, *, fractional_bits: int,
    parameter_bits: int, runtime_payload_bits: int, modulus: int,
) -> tuple[FixedPointContext, ControllerRangeContract, dict[str, object]]:
    """按四维工作域证明静态 LQR 的编码输入及未回绕输出，限于 N≤1000。"""
    if (spec.state_dimension != 0 or spec.input_dimension != 4 or spec.output_dimension != 1
            or type(fractional_bits) is not int or type(parameter_bits) is not int
            or type(runtime_payload_bits) is not int
            or not runtime_payload_bits >= parameter_bits > fractional_bits >= 1
            or not 1 <= config.horizon_steps <= 1000):
        raise ValueError("倒立摆控制器维度、数值位宽或有限步数无效。")
    parameter_context = FixedPointContext(modulus, parameter_bits, fractional_bits)
    for name in ("A", "B", "C", "D", "x0"):
        parameter_context.encode(getattr(spec, name))
    context = FixedPointContext(modulus, runtime_payload_bits, fractional_bits)
    encoded_d = np.asarray(context.encode(spec.D), dtype=object).reshape(4)
    # 下一浮点数包络包含端点乘法的舍入；实际输入仍由 Client.prepare_online 再查一次。
    bounds = tuple(max(abs(int(context.encode(-nextafter(limit, inf)))),
                       abs(int(context.encode(nextafter(limit, inf)))))
                   for limit in config.safe_abs)
    if any(bound > context.maximum_payload for bound in bounds):
        raise ValueError("倒立摆观测工作域超过动态输入 payload 位宽。")
    output_bound = sum(abs(int(gain)) * bound
                       for gain, bound in zip(encoded_d, bounds, strict=True))
    if output_bound > (modulus - 1) // 2:
        raise ValueError("倒立摆 2ell 尺度输出可能在 Z_q 回绕。")
    contract = ControllerRangeContract((), bounds, horizon_steps=config.horizon_steps)
    proof = {
        "state_payload_bounds": [], "input_payload_bounds": list(bounds),
        "encoded_D": [int(value) for value in encoded_d],
        "output_accumulator_absolute_bound": output_bound,
        "centered_modulus_limit": (modulus - 1) // 2,
        "output_fractional_bits": 2 * fractional_bits,
    }
    return context, contract, proof


class MonitoredCartPoleAdapter(CartPoleAdapter):
    """在分享之前门禁更新前观测，并单独保存 raw 力与判定。"""

    def __init__(self, plant: CartPoleContract, config: CartPoleBalanceConfig) -> None:
        super().__init__(plant, config)
        self.monitor = BalanceMonitor(config)
        self.observations: list[list[float]] = []
        self.statuses: list[str] = []
        self.stable_counts: list[int] = []
        self.raw_forces: list[float] = []

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """原场景 v=y−r 之前拒绝越域，确保该步不会产生 share。"""
        measured = _finite_vector(output, 4, "output")
        status = self.monitor.observe(measured)
        if status == "failed":
            raise ValueError(f"倒立摆观测离开工作域：{self.monitor.failure_reason}")
        self.observations.append(measured.tolist())
        self.statuses.append(status)
        self.stable_counts.append(self.monitor.stable_count)
        return super().controller_input(reference, measured)

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        """保存有限 raw 力，再由 #91 唯一执行器实现进行裁剪。"""
        raw = _finite_vector(raw_control, 1, "raw_control")
        applied = super().apply_control(raw)
        self.raw_forces.append(float(raw[0]))
        return applied

    def observe_terminal(self, output: np.ndarray) -> None:
        """第 N 次 plant.step 之后只观测，不再调用控制协议。"""
        measured = _finite_vector(output, 4, "terminal output")
        status = self.monitor.observe(measured)
        self.observations.append(measured.tolist())
        self.statuses.append(status)
        self.stable_counts.append(self.monitor.stable_count)
        if status != "stable":
            raise ValueError(f"倒立摆终点未稳定：{status}")


class CartPoleSecureExperiment:
    """拥有两套可变 plant/adapter；通用 runner 仅消费 plan 与验证方法。"""

    def __init__(self, plant: CartPoleContract, balance: CartPoleBalanceConfig,
                 spec: ControllerSpec) -> None:
        self.plant_contract = plant
        self.balance = balance
        self.spec = spec
        self.ideal_plant = CartPolePlant(plant)
        self.secure_plant = CartPolePlant(plant)
        self.ideal_adapter = MonitoredCartPoleAdapter(plant, balance)
        self.secure_adapter = MonitoredCartPoleAdapter(plant, balance)

    def build_plan(self, secure: object) -> SimulationPlan:
        """同一物理配置和初态，分别建 plant、adapter、runtime。"""
        return SimulationPlan(
            self.ideal_adapter.metadata,
            np.arange(self.balance.horizon_steps, dtype=np.float64)
            * self.plant_contract.sample_period_s,
            SimulationBranch(self.ideal_plant, self.ideal_adapter,
                             PlaintextStateSpaceRuntime(self.spec)),
            SimulationBranch(self.secure_plant, self.secure_adapter, secure),
        )

    def validate_result(self, result: SimulationResult) -> None:
        """N 行更新前轨迹后检查两支末端观测、完整记录和执行器口径。"""
        n = self.balance.horizon_steps
        for adapter, plant, outputs, applied in (
            (self.ideal_adapter, self.ideal_plant, result.output_ideal, result.control_ideal),
            (self.secure_adapter, self.secure_plant, result.output_secure, result.control_secure),
        ):
            if (len(adapter.observations) != n or len(adapter.raw_forces) != n
                    or len(adapter.statuses) != n or len(adapter.stable_counts) != n):
                raise ValueError("倒立摆逐步场景记录不完整。")
            np.testing.assert_allclose(adapter.observations, outputs, rtol=0, atol=0)
            np.testing.assert_allclose(
                np.clip(adapter.raw_forces, -self.plant_contract.max_applied_force_n,
                        self.plant_contract.max_applied_force_n), applied[:, 0], rtol=0, atol=0,
            )
            adapter.observe_terminal(plant.output())

    def evidence(self, run_id: str, result: SimulationResult) -> dict[str, object]:
        """N 行 raw/applied 配对与 N+1 判定属于场景，不改变八字段 schema。"""
        branches = {}
        for name, adapter in (("ideal", self.ideal_adapter), ("secure", self.secure_adapter)):
            branches[name] = {
                "observations": adapter.observations,
                "raw_force_n": adapter.raw_forces,
                "statuses": adapter.statuses,
                "stable_counts": adapter.stable_counts,
            }
        return {
            "schema_version": 1, "run_id": run_id, "sample_count": self.balance.horizon_steps,
            "sample_period_s": self.plant_contract.sample_period_s,
            "time_s": (np.arange(self.balance.horizon_steps + 1)
                       * self.plant_contract.sample_period_s).tolist(),
            "reference": [list(self.balance.target_state)
                          for _ in range(self.balance.horizon_steps + 1)],
            "state_units": list(self.ideal_adapter.metadata.output.units),
            "force_unit": "N", "raw_error": "ideal - secure",
            "raw_force_error_n": (np.asarray(self.ideal_adapter.raw_forces)
                                  - np.asarray(self.secure_adapter.raw_forces)).tolist(),
            "terminal_time_s": self.balance.horizon_steps * self.plant_contract.sample_period_s,
            "branches": branches,
        }
