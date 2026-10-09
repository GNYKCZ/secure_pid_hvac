"""Contract tests for the scenario-independent architecture baseline."""

from dataclasses import FrozenInstanceError

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec


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
