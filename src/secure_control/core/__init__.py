"""Stable, scenario-independent control data contracts."""

from secure_control.core.controller import ControllerScaleMetadata, ControllerSpec
from secure_control.core.stability import (
    EigenvalueDiagnostic,
    SchurStabilityReport,
    SchurStatus,
    check_discrete_schur_stability,
)

__all__ = [
    "ControllerScaleMetadata",
    "ControllerSpec",
    "EigenvalueDiagnostic",
    "SchurStabilityReport",
    "SchurStatus",
    "check_discrete_schur_stability",
]
