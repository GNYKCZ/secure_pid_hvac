"""明文与安全执行层共用的控制器运行时契约。"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from numpy.typing import NDArray

Array = NDArray[Any]


@runtime_checkable
class ControllerRuntime(Protocol):
    """供领域无关仿真引擎消费的最小控制器运行接口。"""

    def step(self, v: Array) -> Array:
        """推进一个离散控制步，并返回当前控制输出向量。"""
        ...

    def reset(self) -> None:
        """将运行时恢复到构造时配置的初始状态。"""
        ...
