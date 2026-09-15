"""通用明文状态空间运行时的数值与边界测试。"""

import numpy as np
import pytest

from secure_control.core import ControllerSpec
from secure_control.execution import ControllerRuntime, PlaintextStateSpaceRuntime


def test_step_uses_current_state_before_state_update() -> None:
    """用独立手算值验证 u(k) 先于 x_c(k+1) 计算。"""
    runtime = PlaintextStateSpaceRuntime(
        ControllerSpec(
            A=np.array([[2.0]]),
            B=np.array([[3.0]]),
            C=np.array([[5.0]]),
            D=np.array([[7.0]]),
            x0=np.array([11.0]),
        )
    )

    # 第一步：u=5*11+7*13=146，x_next=2*11+3*13=61。
    assert np.array_equal(runtime.step(13.0), np.array([146.0]))
    assert np.array_equal(runtime.state, np.array([61.0]))
    # 第二步必须使用第一步写入的 61，而非初始状态 11。
    assert np.array_equal(runtime.step(17.0), np.array([424.0]))


def test_vector_input_and_output_follow_matrix_shapes() -> None:
    """验证多输入、多输出控制器不会依赖 NumPy 广播。"""
    runtime = PlaintextStateSpaceRuntime(
        ControllerSpec(
            A=np.array([[1.0, 2.0], [0.0, 1.0]]),
            B=np.eye(2),
            C=np.array([[1.0, 0.0], [0.0, 2.0]]),
            D=np.zeros((2, 2)),
            x0=np.array([1.0, -1.0]),
        )
    )

    assert np.array_equal(runtime.step(np.array([3.0, 4.0])), np.array([1.0, -2.0]))
    assert np.array_equal(runtime.state, np.array([2.0, 3.0]))


def test_column_vector_input_matches_flat_vector_input() -> None:
    """论文常用的单步列向量应与扁平数组表示具有相同的控制语义。"""
    spec = ControllerSpec(
        A=np.array([[1.0, 2.0], [0.0, 1.0]]),
        B=np.eye(2),
        C=np.array([[1.0, 0.0], [0.0, 2.0]]),
        D=np.zeros((2, 2)),
        x0=np.array([1.0, -1.0]),
    )
    flat_runtime = PlaintextStateSpaceRuntime(spec)
    column_runtime = PlaintextStateSpaceRuntime(spec)

    # 仅归一化表示形式，不改变 m=2 控制器的矩阵乘法和状态更新语义。
    assert np.array_equal(flat_runtime.step(np.array([3.0, 4.0])), np.array([1.0, -2.0]))
    assert np.array_equal(column_runtime.step(np.array([[3.0], [4.0]])), np.array([1.0, -2.0]))
    assert np.array_equal(column_runtime.state, flat_runtime.state)


def test_static_state_feedback_has_no_internal_state() -> None:
    """零维 controller state 时，运行时只执行 D @ v。"""
    runtime = PlaintextStateSpaceRuntime(
        ControllerSpec(
            A=np.empty((0, 0)),
            B=np.empty((0, 2)),
            C=np.empty((1, 0)),
            D=np.array([[-1.5, -0.25]]),
            x0=np.empty(0),
        )
    )

    assert np.array_equal(runtime.step(np.array([2.0, -4.0])), np.array([-2.0]))
    assert runtime.state.shape == (0,)


def test_reset_and_runtime_instances_do_not_share_state() -> None:
    """reset 必须恢复 x0，两个 runtime 的内部 state 必须相互隔离。"""
    spec = ControllerSpec(
        A=np.array([[1.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[0.0]]),
        x0=np.array([2.0]),
    )
    first = PlaintextStateSpaceRuntime(spec)
    second = PlaintextStateSpaceRuntime(spec)

    first.step(3.0)
    assert np.array_equal(first.state, np.array([5.0]))
    assert np.array_equal(second.state, np.array([2.0]))
    first.reset()
    assert np.array_equal(first.state, np.array([2.0]))


@pytest.mark.parametrize(
    ("value", "exception", "message"),
    [
        (np.array([[1.0, 2.0]]), ValueError, "列向量"),
        (np.array([1.0, 2.0]), ValueError, "shape"),
        (np.array([np.nan]), FloatingPointError, "NaN"),
        ("not-a-number", TypeError, "实数"),
    ],
)
def test_invalid_inputs_fail_without_state_mutation(
    value: object, exception: type[Exception], message: str
) -> None:
    """非法输入必须明确失败，且不能造成半步状态更新。"""
    runtime = PlaintextStateSpaceRuntime(
        ControllerSpec(
            A=np.array([[1.0]]),
            B=np.array([[1.0]]),
            C=np.array([[1.0]]),
            D=np.array([[0.0]]),
            x0=np.array([5.0]),
        )
    )

    with pytest.raises(exception, match=message):
        runtime.step(value)  # type: ignore[arg-type]
    assert np.array_equal(runtime.state, np.array([5.0]))


def test_integer_controller_preserves_fractional_input_without_truncation() -> None:
    """整数矩阵也应按实数输入计算，不能通过隐式类型转换截断小数。"""
    runtime = PlaintextStateSpaceRuntime(
        ControllerSpec(
            A=np.array([[1]], dtype=np.int64),
            B=np.array([[1]], dtype=np.int64),
            C=np.array([[0]], dtype=np.int64),
            D=np.array([[0]], dtype=np.int64),
            x0=np.array([0], dtype=np.int64),
        )
    )

    np.testing.assert_array_equal(runtime.step(1.5), np.array([0.0]))
    np.testing.assert_array_equal(runtime.state, np.array([1.5]))
    runtime.reset()
    np.testing.assert_array_equal(runtime.state, np.array([0], dtype=np.int64))
    # 原先已接受的整数输入继续保持整数结果与状态 dtype，不因新增小数路径被改写。
    np.testing.assert_array_equal(runtime.step(2), np.array([0], dtype=np.int64))
    assert runtime.state.dtype == np.dtype("int64")


def test_runtime_implements_shared_execution_protocol() -> None:
    """明文运行时必须满足 future secure runtime 共享的结构化接口。"""
    runtime = PlaintextStateSpaceRuntime(
        ControllerSpec(
            A=np.array([[1.0]]),
            B=np.array([[0.0]]),
            C=np.array([[1.0]]),
            D=np.array([[0.0]]),
            x0=np.array([0.0]),
        )
    )

    assert isinstance(runtime, ControllerRuntime)
