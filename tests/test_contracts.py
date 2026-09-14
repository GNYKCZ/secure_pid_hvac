"""Contract tests for the scenario-independent architecture baseline."""

from dataclasses import FrozenInstanceError

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.execution import ControllerRuntime
from secure_control.simulation import (
    ChannelMetadata,
    Plant,
    ScenarioAdapter,
    ScenarioMetadata,
    SimulationResult,
)


def make_controller_spec() -> ControllerSpec:
    """Return a small, domain-neutral controller contract fixture."""
    return ControllerSpec(
        A=np.array([[1.0, 0.5], [0.0, 1.0]]),
        B=np.array([[0.0], [1.0]]),
        C=np.array([[1.0, 0.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0, 0.0]),
    )


def test_controller_spec_validates_dimensions_and_is_immutable() -> None:
    spec = make_controller_spec()

    assert (spec.state_dimension, spec.input_dimension, spec.output_dimension) == (2, 1, 1)
    with pytest.raises(ValueError, match="read-only"):
        spec.A[0, 0] = 2.0
    with pytest.raises(FrozenInstanceError):
        spec.scale_metadata = None  # type: ignore[misc]


def test_controller_spec_rejects_incompatible_shapes() -> None:
    with pytest.raises(ValueError, match="D must have shape"):
        ControllerSpec(
            A=np.eye(2),
            B=np.ones((2, 1)),
            C=np.ones((1, 2)),
            D=np.ones((2, 1)),
            x0=np.zeros(2),
        )


def test_controller_spec_accepts_large_integer_objects_but_rejects_non_finite_values() -> None:
    large = 1 << 200
    spec = ControllerSpec(
        A=np.array([[large]], dtype=object),
        B=np.array([[large]], dtype=object),
        C=np.array([[large]], dtype=object),
        D=np.array([[large]], dtype=object),
        x0=np.array([large], dtype=object),
        scale_metadata=ControllerScaleMetadata(
            state=32,
            input=16,
            output=16,
            A=0,
            B=0,
            C=16,
            D=16,
        ),
    )

    assert spec.A[0, 0] == large
    with pytest.raises(ValueError, match="finite"):
        ControllerSpec(
            A=np.array([[np.nan]], dtype=object),
            B=np.array([[0.0]], dtype=object),
            C=np.array([[0.0]], dtype=object),
            D=np.array([[0.0]], dtype=object),
            x0=np.array([0.0], dtype=object),
        )


def test_controller_spec_supports_static_state_feedback() -> None:
    spec = ControllerSpec(
        A=np.empty((0, 0)),
        B=np.empty((0, 2)),
        C=np.empty((1, 0)),
        D=np.array([[-1.5, -0.25]]),
        x0=np.empty(0),
    )

    assert (spec.state_dimension, spec.input_dimension, spec.output_dimension) == (0, 2, 1)
    assert np.array_equal(spec.D, np.array([[-1.5, -0.25]]))


def test_controller_scale_metadata_is_per_signal_and_matrix() -> None:
    metadata = ControllerScaleMetadata(state=0, input=4, output=7, A=0, B=2, C=7, D=3)

    assert metadata.state == 0
    assert metadata.B == 2
    with pytest.raises(ValueError, match="non-negative"):
        ControllerScaleMetadata(D=-1)


def test_runtime_and_scenario_contracts_are_structural() -> None:
    class RuntimeFixture:
        def step(self, v: np.ndarray) -> np.ndarray:
            return v.copy()

        def reset(self) -> None:
            return None

    class PlantFixture:
        def output(self) -> np.ndarray:
            return np.zeros(2)

        def step(self, control: np.ndarray) -> np.ndarray:
            return control.copy()

    class ScenarioFixture:
        metadata = ScenarioMetadata(
            name="neutral_fixture",
            reference=ChannelMetadata(("target",), ("unit",)),
            output=ChannelMetadata(("first", "second"), ("unit", "unit")),
            control=ChannelMetadata(("actuation",), ("unit",)),
        )

        def reference_at(self, time: float) -> np.ndarray:
            return np.array([time])

        def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
            return np.concatenate((reference, output))

    assert isinstance(RuntimeFixture(), ControllerRuntime)
    assert isinstance(PlantFixture(), Plant)
    assert isinstance(ScenarioFixture(), ScenarioAdapter)


def test_simulation_result_supports_vector_outputs() -> None:
    result = SimulationResult(
        time=np.array([0.0, 1.0]),
        reference=np.array([[1.0], [2.0]]),
        output_ideal=np.array([[1.0, 2.0], [3.0, 4.0]]),
        output_secure=np.array([[1.1, 2.1], [3.1, 4.1]]),
        control_ideal=np.array([0.5, 0.6]),
        control_secure=np.array([0.4, 0.7]),
        control_error=np.array([0.1, 0.1]),
        output_error=np.full((2, 2), 0.1),
    )

    assert result.output_ideal.shape == (2, 2)
    assert result.control_ideal.shape == (2, 1)
    with pytest.raises(ValueError, match="read-only"):
        result.output_ideal[0, 0] = 0.0


def test_simulation_result_rejects_mismatched_channels() -> None:
    with pytest.raises(ValueError, match="output shapes must match"):
        SimulationResult(
            time=np.array([0.0]),
            reference=np.array([0.0]),
            output_ideal=np.array([[0.0, 0.0]]),
            output_secure=np.array([0.0]),
            control_ideal=np.array([0.0]),
            control_secure=np.array([0.0]),
            control_error=np.array([0.0]),
            output_error=np.array([0.0]),
        )
