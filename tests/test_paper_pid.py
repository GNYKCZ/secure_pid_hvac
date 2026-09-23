"""论文 §VII PID 矩阵、独立差分式及明文时序的回归测试。"""

from __future__ import annotations

import numpy as np
import pytest

from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.scenarios.paper_pid import PaperPidDesign, paper_sec_vii_controller_spec


def _difference_outputs(
    inputs: tuple[float, ...], *, kp: float, ki: float, kd: float, nd: int, ts: float
) -> list[float]:
    """独立按并联 PID 的 I/d 差分式计算，不读取或执行 ControllerSpec。"""
    integral = derivative = previous_input = 0.0
    outputs = []
    for current_input in inputs:
        derivative = (1 - nd) * derivative + (nd * kd / ts) * (
            current_input - previous_input
        )
        outputs.append(kp * current_input + integral + derivative)
        integral += ki * ts * current_input
        previous_input = current_input
    return outputs


def test_paper_printed_controller_matrices_and_zero_initial_state() -> None:
    """§VII 给出的印刷矩阵与零初态逐项锁定，不用反推 gains 替代来源。"""
    spec = paper_sec_vii_controller_spec()

    np.testing.assert_array_equal(spec.A, [[1.0, 0.0], [1.0, 0.0]])
    np.testing.assert_array_equal(spec.B, [[1.0], [0.0]])
    np.testing.assert_array_equal(spec.C, [[2.7368927, -2.96540833]])
    np.testing.assert_array_equal(spec.D, [[-5.01071167]])
    np.testing.assert_array_equal(spec.x0, [0.0, 0.0])
    assert (spec.state_dimension, spec.input_dimension, spec.output_dimension) == (2, 1, 1)


def test_paper_printed_instance_matches_independent_difference_equation() -> None:
    """印刷系数反推的 gains 仅作 oracle，逐步核对 k=0 和正负/零输入。"""
    spec = paper_sec_vii_controller_spec()
    runtime = PlaintextStateSpaceRuntime(spec)
    # 这里的 1.5 是独立测试输入，不把论文 plant 初态的 100 误当成 y(0)。
    inputs = (1.5, 0.0, -3.0, 2.5, 2.5, 0.0)
    expected = _difference_outputs(
        inputs,
        kp=-2.04530334,
        ki=-2.2851563,
        kd=-0.296540833,
        nd=1,
        ts=0.1,
    )
    observed = []
    for index, value in enumerate(inputs):
        before = runtime.state
        control = runtime.step(np.array([value]))
        assert control.shape == (1,)
        if index == 0:
            np.testing.assert_array_equal(before, [0.0, 0.0])
            assert control[0] == pytest.approx(-7.516067505)
        np.testing.assert_allclose(
            runtime.state, spec.A @ before + spec.B[:, 0] * value, rtol=1e-12, atol=1e-10
        )
        observed.append(control[0])
    np.testing.assert_allclose(observed, expected, rtol=1e-12, atol=1e-10)
    runtime.reset()
    np.testing.assert_array_equal(runtime.state, spec.x0)
    np.testing.assert_array_equal(runtime.step(inputs[0]), np.array([observed[0]]))


@pytest.mark.parametrize("nd", [1, 2, 3])
def test_parameterized_pid_matches_independent_filtered_difference_equation(nd: int) -> None:
    """Nd≠1 也应遵循论文滤波差分式；有限步等价不声称闭环稳定。"""
    design = PaperPidDesign(1.25, -0.5, 0.125, nd, 0.2)
    spec = design.to_controller_spec()
    np.testing.assert_array_equal(spec.A, [[2 - nd, nd - 1], [1, 0]])
    np.testing.assert_array_equal(spec.B, [[1], [0]])
    np.testing.assert_allclose(
        spec.C,
        [[-0.1 - nd * nd * 0.125 / 0.2, (nd - 1) * -0.1 + nd * nd * 0.125 / 0.2]],
    )
    np.testing.assert_allclose(spec.D, [[1.25 + nd * 0.125 / 0.2]])

    inputs = (0.0, 2.0, -1.0, 0.5, 0.0, -2.0)
    oracle = _difference_outputs(inputs, kp=1.25, ki=-0.5, kd=0.125, nd=nd, ts=0.2)
    runtime = PlaintextStateSpaceRuntime(spec)
    actual = [runtime.step(value)[0] for value in inputs]
    np.testing.assert_allclose(actual, oracle, rtol=1e-12, atol=1e-10)


def test_nonzero_initial_state_uses_previous_state_for_output() -> None:
    """任意 x0 使用论文的状态坐标，u(0) 先于 x(1) 更新。"""
    spec = PaperPidDesign(1.0, 0.5, -0.2, 2, 0.1, (3.0, -4.0)).to_controller_spec()
    runtime = PlaintextStateSpaceRuntime(spec)
    before = runtime.state
    control = runtime.step(np.array([[2.0]]))

    np.testing.assert_allclose(control, spec.C @ before + spec.D[:, 0] * 2.0)
    np.testing.assert_allclose(runtime.state, spec.A @ before + spec.B[:, 0] * 2.0)
    assert not np.allclose(control, spec.C @ runtime.state + spec.D[:, 0] * 2.0)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"derivative_filter_parameter": 0}, "正整数"),
        ({"derivative_filter_parameter": 1.0}, "正整数"),
        ({"derivative_filter_parameter": True}, "正整数"),
        ({"sample_period_seconds": 0.0}, "正的有限"),
        ({"sample_period_seconds": np.inf}, "正的有限"),
        ({"proportional_gain": np.nan}, "有限实数"),
        ({"initial_state": (1.0,)}, "initial_state"),
        ({"initial_state": (0.0, np.inf)}, "initial_state"),
    ],
)
def test_invalid_pid_parameters_fail_before_runtime(changes: dict, message: str) -> None:
    """输入参数不符时拒绝构造，不能静默改变数学/shape 语义。"""
    values = {
        "proportional_gain": 1.0,
        "integral_gain": 0.5,
        "derivative_gain": -0.2,
        "derivative_filter_parameter": 1,
        "sample_period_seconds": 0.1,
    }
    values.update(changes)
    with pytest.raises(ValueError, match=message):
        PaperPidDesign(**values)


def test_paper_pid_runtime_rejects_wrong_input_shape_without_state_update() -> None:
    """SISO 的单步行向量与多输入不得借 NumPy 广播混入状态。"""
    runtime = PlaintextStateSpaceRuntime(paper_sec_vii_controller_spec())
    with pytest.raises(ValueError, match="shape"):
        runtime.step(np.array([1.0, 2.0]))
    np.testing.assert_array_equal(runtime.state, [0.0, 0.0])
    with pytest.raises(ValueError, match="列向量"):
        runtime.step(np.array([[1.0, 2.0]]))
    np.testing.assert_array_equal(runtime.state, [0.0, 0.0])
