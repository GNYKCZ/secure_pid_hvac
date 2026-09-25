"""四水箱连续闭环的场景装配、明文预言机与有限时域范围证明。"""

from __future__ import annotations

from math import ceil, inf, isfinite, nextafter

import numpy as np

from secure_control.core import ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.protocol import ControllerRangeContract
from secure_control.simulation import SimulationBranch, SimulationPlan, SimulationResult

from .adapter import QuadrupleTankAdapter
from .contract import QuadrupleTankContract
from .plant import QuadrupleTankPlant, build_quadruple_tank_state_space

SCENARIO_VERSION = "1"


def _up(value: float) -> float:
    """对 binary64 运算向外取整；任何非有限包络均使预检失败。"""
    result = nextafter(value, inf)
    if not isfinite(result):
        raise ValueError("四水箱闭环包络不再有限。")
    return result


def _positive_matvec(matrix: np.ndarray, vector: list[float]) -> list[float]:
    """逐项乘加向外取整，涵盖 NumPy 矩阵乘法的 binary64 舍入。"""
    output = []
    for row in matrix:
        total = 0.0
        for coefficient, bound in zip(row, vector, strict=True):
            total = _up(total + _up(abs(float(coefficient)) * bound))
        output.append(total)
    return output


def _sum_bounds(first: list[float], second: list[float]) -> list[float]:
    return [_up(left + right) for left, right in zip(first, second, strict=True)]


def _encoded(spec: ControllerSpec, context: FixedPointContext) -> dict[str, np.ndarray]:
    return {name: np.asarray(context.encode(getattr(spec, name)), dtype=object)
            for name in ("A", "B", "C", "D", "x0")}


def _integer_rows(first: np.ndarray, first_bounds: list[int],
                  second: np.ndarray, second_bounds: list[int]) -> list[int]:
    return [
        sum(abs(int(value)) * first_bounds[column] for column, value in enumerate(row))
        + sum(abs(int(value)) * second_bounds[column]
              for column, value in enumerate(second[row_index]))
        for row_index, row in enumerate(first)
    ]


def quadruple_tank_numeric_contract(
    spec: ControllerSpec, plant: QuadrupleTankContract, *, fractional_bits: int,
    parameter_bits: int, runtime_payload_bits: int, modulus: int, sample_count: int,
    measurement_absolute_bounds_v: tuple[int, int],
) -> tuple[FixedPointContext, ControllerRangeContract, dict[str, object]]:
    """独立证明两支闭环的测量界，再以精确整数证明编码 state/input 界。"""
    if (type(sample_count) is not int or not 1 <= sample_count <= 1000
            or type(fractional_bits) is not int or type(parameter_bits) is not int
            or type(runtime_payload_bits) is not int
            or not runtime_payload_bits >= parameter_bits > fractional_bits >= 1
            or len(measurement_absolute_bounds_v) != 2
            or any(type(value) is not int or value <= 0
                   for value in measurement_absolute_bounds_v)):
        raise ValueError("四水箱精度、样本数或两路测量界无效。")
    parameter_context = FixedPointContext(modulus, parameter_bits, fractional_bits)
    _encoded(spec, parameter_context)
    context = FixedPointContext(modulus, runtime_payload_bits, fractional_bits)
    payload = _encoded(spec, context)
    scale = context.scale
    state_space = build_quadruple_tank_state_space(plant)
    plant_bounds = [abs(value) for value in plant.initial_state_deviation_cm]
    ideal_state = [abs(float(value)) for value in spec.x0]
    secure_state = [abs(int(value)) for value in payload["x0"]]
    measured_max = [0.0, 0.0]
    payload_measured_max = [0, 0]
    for step in range(sample_count):
        measured = _positive_matvec(state_space.C_p, plant_bounds)
        input_payload = [ceil(_up(_up(_up(value * scale) + 0.5)))
                         for value in measured]
        measured_max = [max(old, new) for old, new in zip(measured_max, measured)]
        payload_measured_max = [max(old, new) for old, new in
                                zip(payload_measured_max, input_payload)]
        for index, (bound, declared) in enumerate(zip(measured, measurement_absolute_bounds_v)):
            if bound > declared or input_payload[index] > declared * scale:
                raise ValueError(f"闭环第 {step} 步 y{index + 1} 超出声明测量界。")
        secure_output_raw = _integer_rows(payload["C"], secure_state,
                                          payload["D"], input_payload)
        secure_control = [_up(float(value / (scale * scale))) for value in secure_output_raw]
        ideal_control = _sum_bounds(_positive_matvec(spec.C, ideal_state),
                                    _positive_matvec(spec.D, measured))
        control = [max(first, second) for first, second in
                   zip(secure_control, ideal_control)]
        plant_bounds = _sum_bounds(_positive_matvec(state_space.A_p, plant_bounds),
                                    _positive_matvec(state_space.B_p, control))
        ideal_state = _sum_bounds(_positive_matvec(spec.A, ideal_state),
                                  _positive_matvec(spec.B, measured))
        raw = _integer_rows(payload["A"], secure_state, payload["B"], input_payload)
        secure_state = [(value + scale - 1) // scale + 1 for value in raw]
    input_bounds = [value * scale for value in measurement_absolute_bounds_v]
    current = [abs(int(value)) for value in payload["x0"]]
    maximum_state = current.copy()
    for _ in range(sample_count):
        raw = _integer_rows(payload["A"], current, payload["B"], input_bounds)
        current = [(value + scale - 1) // scale + 1 for value in raw]
        maximum_state = [max(old, new) for old, new in zip(maximum_state, current)]
    contract = ControllerRangeContract(tuple(maximum_state), tuple(input_bounds),
                                       horizon_steps=sample_count)
    proof = {
        "measurement_envelope_v": measured_max,
        "measurement_payload_envelope": payload_measured_max,
        "state_payload_bounds": maximum_state,
        "input_payload_bounds": input_bounds,
        "plant_rounding": "binary64 individual nonnegative products and sums rounded outward",
        "controller_truncation_error_payload": 1,
    }
    return context, contract, proof


def assemble_quadruple_tank_plan(
    spec: ControllerSpec, plant: QuadrupleTankContract, secure: object, sample_count: int,
) -> SimulationPlan:
    """为理想和安全支分别构建 plant、adapter、runtime；样本为更新前状态。"""
    ideal_adapter = QuadrupleTankAdapter()
    secure_adapter = QuadrupleTankAdapter()
    return SimulationPlan(
        ideal_adapter.metadata,
        np.arange(sample_count, dtype=float) * plant.sample_period_seconds,
        SimulationBranch(QuadrupleTankPlant(plant), ideal_adapter,
                         PlaintextStateSpaceRuntime(spec)),
        SimulationBranch(QuadrupleTankPlant(plant), secure_adapter, secure),
    )


def quadruple_tank_ideal_oracle(spec: ControllerSpec, plant: QuadrupleTankContract,
                               sample_count: int) -> tuple[np.ndarray, np.ndarray]:
    """用独立的 8×8 Φ 幂验证明文闭环，不调用生产仿真引擎。"""
    m = build_quadruple_tank_state_space(plant)
    phi = np.block([[m.A_p + m.B_p @ spec.D @ m.C_p, m.B_p @ spec.C],
                    [spec.B @ m.C_p, spec.A]])
    initial = np.concatenate((plant.initial_state_deviation_cm, spec.x0))
    outputs, controls = [], []
    for step in range(sample_count):
        state = np.linalg.matrix_power(phi, step) @ initial
        y = m.C_p @ state[:4]
        outputs.append(y)
        controls.append(spec.C @ state[4:] + spec.D @ y)
    return np.asarray(outputs), np.asarray(controls)


def validate_quadruple_tank_result(
    result: SimulationResult, spec: ControllerSpec, plant: QuadrupleTankContract,
    sample_count: int, measurement_absolute_bounds_v: tuple[int, int],
) -> None:
    """场景侧以独立 Φ 基线和已证明的两路界核对运行结果。"""
    expected_y, expected_u = quadruple_tank_ideal_oracle(spec, plant, sample_count)
    np.testing.assert_allclose(result.output_ideal, expected_y, rtol=1e-11, atol=1e-10)
    np.testing.assert_allclose(result.control_ideal, expected_u, rtol=1e-11, atol=1e-10)
    bounds = np.asarray(measurement_absolute_bounds_v)
    if (np.any(np.abs(result.output_ideal) > bounds)
            or np.any(np.abs(result.output_secure) > bounds)):
        raise ValueError("四水箱 plant y 超出先验证明的两路测量界。")
