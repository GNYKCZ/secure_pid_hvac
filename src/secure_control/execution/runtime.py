"""通用明文离散状态空间控制器运行时。"""

from __future__ import annotations

from typing import Any

import numpy as np
from numpy.typing import NDArray

from secure_control.core import ControllerSpec

Array = NDArray[Any]


class PlaintextStateSpaceRuntime:
    """执行一个通用离散状态空间控制器。

    给定 ``ControllerSpec`` 中的 ``A/B/C/D/x0``，本类在每次 ``step(v)`` 中
    严格按下列顺序计算：先使用当前 ``x_c(k)`` 得到 ``u(k)``，再计算
    ``x_c(k+1)``。返回值始终是一维 NumPy 数组；单通道控制量的形状为 ``(1,)``。

    本类只处理明文数值矩阵，不编码定点数、不执行模运算，也不包含任何场景逻辑。
    """

    def __init__(self, spec: ControllerSpec) -> None:
        """以不可变 ControllerSpec 创建独立的可变运行时状态。

        ``ControllerSpec`` 可以描述未来安全计算所需的 object dtype，但本明文运行时
        只接受 NumPy 原生实数 dtype，避免在没有明确定义运算语义时把 Python 大整数
        或其他对象隐式带入矩阵运算。
        """
        if spec.A.dtype.kind not in "iuf":
            raise TypeError("明文运行时只接受整数或浮点数 dtype 的 ControllerSpec")

        self._spec = spec
        self._dtype = spec.A.dtype
        # 必须复制 x0：同一个 ControllerSpec 可用于多个运行时，彼此的状态不能共享。
        self._state = np.array(spec.x0, dtype=self._dtype, copy=True)

    @property
    def spec(self) -> ControllerSpec:
        """返回运行时使用的不可变控制器规格。"""
        return self._spec

    @property
    def state(self) -> Array:
        """返回当前 controller state 的只读快照，避免调用方修改内部状态。"""
        snapshot = self._state.copy()
        snapshot.setflags(write=False)
        return snapshot

    def reset(self) -> None:
        """将内部状态恢复为 ControllerSpec 的 ``x0`` 副本。"""
        self._state = np.array(self._spec.x0, dtype=self._dtype, copy=True)

    def step(self, v: Array | float) -> Array:
        """计算一个控制步并返回 ``u(k)``。

        ``v`` 可以是单输入控制器的标量、一维向量 ``(m,)``，或论文矩阵表示中常用的
        单步列向量 ``(m, 1)``，其中 ``m`` 为输入维数。运行时会将允许的向量表示统一为
        内部一维数组；返回控制量始终为 ``(p,)``。行向量和批量二维数组没有明确的单步
        语义，必须拒绝，避免 NumPy 广播在不报错的情况下改变矩阵乘法的物理含义。
        """
        input_vector = self._coerce_input(v)

        try:
            with np.errstate(over="raise", invalid="raise"):
                # u(k) 必须读取更新前的 x_c(k)，因此不能先写回 next_state。
                control = self._spec.C @ self._state + self._spec.D @ input_vector
                next_state = self._spec.A @ self._state + self._spec.B @ input_vector
        except FloatingPointError as error:
            raise FloatingPointError("状态空间矩阵计算产生了无效或溢出结果") from error

        self._require_finite("控制输出", control)
        self._require_finite("下一控制器状态", next_state)

        # 两个结果均通过检查后才改变状态；失败时保留上一个有效状态，便于重试或诊断。
        self._state = np.array(next_state, dtype=self._dtype, copy=True)
        return np.array(control, dtype=self._dtype, copy=True)

    def _coerce_input(self, value: Array | float) -> Array:
        """验证单步输入，并将允许的列向量归一化为一维数组。"""
        input_vector = np.asarray(value)
        if input_vector.ndim == 0:
            input_vector = input_vector.reshape(1)
        elif input_vector.ndim == 2 and input_vector.shape == (
            self._spec.input_dimension,
            1,
        ):
            # 数学上的列向量仅是一个时间步的 m 个输入分量；归一化后保持矩阵运算语义不变。
            input_vector = input_vector.reshape(self._spec.input_dimension)
        elif input_vector.ndim != 1:
            raise ValueError(
                "controller input 必须是标量、一维向量或形状为 "
                f"({self._spec.input_dimension}, 1) 的列向量"
            )
        if input_vector.shape != (self._spec.input_dimension,):
            raise ValueError(
                "controller input shape 必须为 "
                f"({self._spec.input_dimension},)，实际为 {input_vector.shape}"
            )
        if input_vector.dtype.kind not in "iuf":
            raise TypeError("controller input 必须包含实数数值")
        self._require_finite("controller input", input_vector)

        # 对整数控制器拒绝带小数的输入，避免 astype 静默截断而产生错误控制量。
        if (
            self._dtype.kind in "iu"
            and input_vector.dtype.kind == "f"
            and not np.equal(input_vector, np.trunc(input_vector)).all()
        ):
            raise ValueError("整数 dtype 的 ControllerSpec 不接受含小数的输入")
        converted = np.array(input_vector, dtype=self._dtype, copy=True)
        self._require_finite("转换后的 controller input", converted)
        return converted

    @staticmethod
    def _require_finite(name: str, value: Array) -> None:
        """确保运行时输入、中间结果和输出不含 NaN 或无穷大。"""
        if not np.isfinite(value).all():
            raise FloatingPointError(f"{name} 包含 NaN 或无穷大")
