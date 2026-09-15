"""Structural contracts used by a scenario-independent simulation engine."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Protocol, runtime_checkable

import numpy as np
from numpy.typing import NDArray

from secure_control.execution import ControllerRuntime

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

    def apply_control(self, raw_control: Array) -> Array:
        """由场景决定 actuator 施加语义，返回实际送给 plant 的控制向量。"""
        ...


@dataclass(frozen=True, slots=True)
class SimulationBranch:
    """组合一支独立闭环的 plant、adapter 与通用 controller runtime。"""

    plant: Plant
    adapter: ScenarioAdapter
    runtime: ControllerRuntime


@dataclass(frozen=True, slots=True)
class SimulationPlan:
    """场景事前建立的双支运行计划，持有相同的不可变时间网格与通道约定。"""

    metadata: ScenarioMetadata
    sample_times: Array
    ideal: SimulationBranch
    secure: SimulationBranch

    def __post_init__(self) -> None:
        """在进入引擎前固定时间网格，拒绝非实数、非有限或非递增时刻。"""
        if not isinstance(self.metadata, ScenarioMetadata):
            raise TypeError("metadata 必须是 ScenarioMetadata。")
        if not isinstance(self.ideal, SimulationBranch) or not isinstance(
            self.secure, SimulationBranch
        ):
            raise TypeError("ideal/secure 必须是 SimulationBranch。")
        times = np.asarray(self.sample_times)
        if times.ndim != 1 or times.size == 0:
            raise ValueError("sample_times 必须是非空一维时间数组。")
        if times.dtype.kind not in "iuf":
            raise TypeError("sample_times 必须包含实数。")
        if not np.isfinite(times).all():
            raise FloatingPointError("sample_times 包含 NaN 或无穷大。")
        if any(later <= earlier for earlier, later in pairwise(times)):
            raise ValueError("sample_times 必须严格递增。")
        snapshot = np.array(times, copy=True)
        snapshot.setflags(write=False)
        object.__setattr__(self, "sample_times", snapshot)


@runtime_checkable
class Scenario(Protocol):
    """场景在执行前构造双支计划；通用 runner 不负责具体领域装配。"""

    def build_plan(self) -> SimulationPlan:
        """返回已完成场景配置和范围证明的通用运行计划。"""
        ...
