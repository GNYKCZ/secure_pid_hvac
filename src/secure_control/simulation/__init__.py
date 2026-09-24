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
from secure_control.simulation.engine import (
    compare_closed_loops,
    run_secure_branch,
    simulate_branch,
)
from secure_control.simulation.results import SimulationResult
from secure_control.simulation.runner import run
from secure_control.simulation.telemetry import (
    BoundedPublisher,
    EventReceiver,
    Sample,
    SessionEnded,
    SessionFault,
    SessionStarted,
    TelemetrySession,
    public_event_json,
)

__all__ = [
    "BoundedPublisher",
    "ChannelMetadata",
    "EventReceiver",
    "Plant",
    "Sample",
    "Scenario",
    "ScenarioAdapter",
    "ScenarioMetadata",
    "SessionEnded",
    "SessionFault",
    "SessionStarted",
    "SimulationBranch",
    "SimulationPlan",
    "SimulationResult",
    "TelemetrySession",
    "compare_closed_loops",
    "public_event_json",
    "run",
    "run_secure_branch",
    "simulate_branch",
]
