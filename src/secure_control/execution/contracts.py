"""Controller runtime contract shared by plaintext and secure execution."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from numpy.typing import NDArray

Array = NDArray[Any]


@runtime_checkable
class ControllerRuntime(Protocol):
    """Minimal execution interface consumed by a simulation engine."""

    def step(self, v: Array) -> Array:
        """Advance one controller step and return the control output."""
        ...

    def reset(self) -> None:
        """Restore the runtime to its configured initial state."""
        ...
