"""Scenario-independent simulation contracts and result data."""

from secure_control.simulation.contracts import (
    ChannelMetadata,
    Plant,
    Scenario,
    ScenarioAdapter,
    ScenarioMetadata,
    SimulationBranch,
    SimulationPlan,
)
from secure_control.simulation.engine import compare_closed_loops, simulate_branch
from secure_control.simulation.results import SimulationResult
from secure_control.simulation.runner import run

__all__ = [
    "ChannelMetadata",
    "Plant",
    "Scenario",
    "ScenarioAdapter",
    "ScenarioMetadata",
    "SimulationBranch",
    "SimulationPlan",
    "SimulationResult",
    "compare_closed_loops",
    "run",
    "simulate_branch",
]
