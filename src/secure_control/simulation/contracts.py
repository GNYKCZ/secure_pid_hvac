"""Structural contracts used by a scenario-independent simulation engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from numpy.typing import NDArray

Array = NDArray[Any]


@dataclass(frozen=True, slots=True)
class ChannelMetadata:
    """Names and units supplied by a scenario for one signal vector."""

    names: tuple[str, ...]
    units: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.names or len(self.names) != len(self.units):
            raise ValueError("channel names and units must be non-empty and have equal length")
        if any(not value.strip() for value in (*self.names, *self.units)):
            raise ValueError("channel names and units must not be blank")


@dataclass(frozen=True, slots=True)
class ScenarioMetadata:
    """Scenario identity and display metadata without domain-specific fields."""

    name: str
    reference: ChannelMetadata
    output: ChannelMetadata
    control: ChannelMetadata

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("scenario name must not be blank")


@runtime_checkable
class Plant(Protocol):
    """Minimal plant interface required by a future simulation engine."""

    def output(self) -> Array:
        """Return the current observable output vector."""
        ...

    def step(self, control: Array) -> Array:
        """Advance one plant step and return its next observable output."""
        ...


@runtime_checkable
class ScenarioAdapter(Protocol):
    """Scenario-owned reference and controller-input mapping contract."""

    metadata: ScenarioMetadata

    def reference_at(self, time: float) -> Array:
        """Return the scenario reference vector for a simulation time."""
        ...

    def controller_input(self, reference: Array, output: Array) -> Array:
        """Map reference and plant output to the controller input vector."""
        ...
