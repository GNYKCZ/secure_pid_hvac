"""Generic discrete state-space controller specification."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Integral, Real
from typing import Any

import numpy as np
from numpy.typing import NDArray

Array = NDArray[Any]


def _readonly_numeric_array(name: str, value: Array) -> Array:
    array = np.array(value, copy=True)
    if array.dtype.kind not in "iufO":
        raise TypeError(f"{name} must contain real numeric values")
    if array.dtype.kind == "O":
        for item in array.flat:
            if isinstance(item, bool) or not isinstance(item, Real):
                raise TypeError(f"{name} object arrays must contain only real numeric values")
            if not isinstance(item, Integral) and not isfinite(float(item)):
                raise ValueError(f"{name} must contain only finite values")
    elif not np.isfinite(array).all():
        raise ValueError(f"{name} must contain only finite values")
    array.setflags(write=False)
    return array


@dataclass(frozen=True, slots=True)
class ControllerSpec:
    """Immutable shape and scale contract for a discrete state-space controller.

    The contract represents ``x_next = A @ x + B @ v`` and
    ``u = C @ x + D @ v``. It contains no execution algorithm or
    scenario-specific controller design parameters.
    """

    A: Array
    B: Array
    C: Array
    D: Array
    x0: Array
    fractional_bits: int | None = None

    def __post_init__(self) -> None:
        for name in ("A", "B", "C", "D", "x0"):
            object.__setattr__(self, name, _readonly_numeric_array(name, getattr(self, name)))

        if self.A.ndim != 2 or self.A.shape[0] == 0 or self.A.shape[0] != self.A.shape[1]:
            raise ValueError("A must be a non-empty square matrix")
        if self.B.ndim != 2 or self.B.shape[0] != self.A.shape[0] or self.B.shape[1] == 0:
            raise ValueError("B must have shape (state_dimension, input_dimension)")
        if self.C.ndim != 2 or self.C.shape[1] != self.A.shape[0] or self.C.shape[0] == 0:
            raise ValueError("C must have shape (output_dimension, state_dimension)")
        if self.D.ndim != 2 or self.D.shape != (self.C.shape[0], self.B.shape[1]):
            raise ValueError("D must have shape (output_dimension, input_dimension)")
        if self.x0.ndim != 1 or self.x0.shape != (self.A.shape[0],):
            raise ValueError("x0 must have shape (state_dimension,)")

        dtypes = {array.dtype for array in (self.A, self.B, self.C, self.D, self.x0)}
        if len(dtypes) != 1:
            raise TypeError("A, B, C, D, and x0 must use the same dtype")

        if self.fractional_bits is not None and (
            isinstance(self.fractional_bits, bool)
            or not isinstance(self.fractional_bits, Integral)
            or self.fractional_bits < 0
        ):
            raise ValueError("fractional_bits must be a non-negative integer or None")

    @property
    def state_dimension(self) -> int:
        """Number of controller state channels."""
        return self.A.shape[0]

    @property
    def input_dimension(self) -> int:
        """Number of controller input channels."""
        return self.B.shape[1]

    @property
    def output_dimension(self) -> int:
        """Number of controller output channels."""
        return self.C.shape[0]
