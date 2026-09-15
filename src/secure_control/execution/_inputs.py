"""明文与安全 controller runtime 共用的单步输入规范化。"""

from __future__ import annotations

from typing import Any

import numpy as np
from numpy.typing import NDArray

Array = NDArray[Any]


def normalize_step_input(value: Array | float, input_dimension: int) -> Array:
    """验证实数、有限值和单步 shape，并统一为 ``(m,)`` 的独立数组。

    只允许单输入标量、扁平向量 ``(m,)`` 或列向量 ``(m, 1)``。行向量与批量二维
    输入没有统一的单步时间语义，因此在进入明文矩阵运算或安全分享前共同拒绝。
    """
    input_vector = np.asarray(value)
    if input_vector.ndim == 0:
        input_vector = input_vector.reshape(1)
    elif input_vector.ndim == 2 and input_vector.shape == (input_dimension, 1):
        input_vector = input_vector.reshape(input_dimension)
    elif input_vector.ndim != 1:
        raise ValueError(
            f"controller input 必须是标量、一维向量或形状为 ({input_dimension}, 1) 的列向量"
        )
    if input_vector.shape != (input_dimension,):
        raise ValueError(
            f"controller input shape 必须为 ({input_dimension},)，实际为 {input_vector.shape}"
        )
    if input_vector.dtype.kind not in "iuf":
        raise TypeError("controller input 必须包含实数数值")
    if not np.isfinite(input_vector).all():
        raise FloatingPointError("controller input 包含 NaN 或无穷大")
    return np.array(input_vector, copy=True)
