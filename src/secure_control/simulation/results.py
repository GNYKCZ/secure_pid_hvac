"""Generic result data for comparing two controller executions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from numpy.typing import NDArray

Array = NDArray[Any]


def _readonly_signal(name: str, value: Array, sample_count: int) -> Array:
    signal = np.array(value, copy=True)
    if signal.ndim == 1:
        signal = signal[:, np.newaxis]
    if signal.ndim != 2 or signal.shape[0] != sample_count or signal.shape[1] == 0:
        raise ValueError(f"{name} must have shape (sample_count, channel_count)")
    if signal.dtype.kind not in "iuf" or not np.isfinite(signal).all():
        raise ValueError(f"{name} must contain finite real numeric values")
    signal.setflags(write=False)
    return signal


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """Scenario-independent ideal-versus-secure trajectories."""

    time: Array
    reference: Array
    output_ideal: Array
    output_secure: Array
    control_ideal: Array
    control_secure: Array
    control_error: Array
    output_error: Array

    def __post_init__(self) -> None:
        time = np.array(self.time, copy=True)
        if time.ndim != 1 or time.size == 0:
            raise ValueError("time must be a non-empty one-dimensional array")
        if time.dtype.kind not in "iuf" or not np.isfinite(time).all():
            raise ValueError("time must contain finite real numeric values")
        time.setflags(write=False)
        object.__setattr__(self, "time", time)

        for name in (
            "reference",
            "output_ideal",
            "output_secure",
            "control_ideal",
            "control_secure",
            "control_error",
            "output_error",
        ):
            object.__setattr__(
                self,
                name,
                _readonly_signal(name, getattr(self, name), sample_count=time.size),
            )

        if not (self.output_ideal.shape == self.output_secure.shape == self.output_error.shape):
            raise ValueError("ideal, secure, and error output shapes must match")
        if not (self.control_ideal.shape == self.control_secure.shape == self.control_error.shape):
            raise ValueError("ideal, secure, and error control shapes must match")
