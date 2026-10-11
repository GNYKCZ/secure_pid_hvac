"""场景选择、可验证结果产物、公开 provenance 与定点精度扫描。"""

from typing import TYPE_CHECKING

from .evidence_artifacts import EvidenceArtifacts, VerifiedEvidenceData
from .exact_grid import ExactGridControlRow, derive_exact_grid_row, paper_round_fraction
from .exact_grid_artifacts import ExactGridArtifacts, VerifiedExactGridData
from .sweep import (
    BaselineSourceRequest,
    PrecisionPreflightReport,
    PrecisionSweepDefinition,
    ProtocolCostReport,
    RangeMargin,
    ResolvedBaselineSource,
    ResolvedPrecisionSweepPlan,
    ReusablePrecisionSweepDefinition,
    SweepArtifacts,
    SweepPointDefinition,
    SweepRunRecord,
    SweepRunStatus,
    load_precision_sweep_definition,
    materialize_point_config,
)
from .sweep_metrics import ErrorMetrics, aggregate_error_metrics, compute_error_metrics

if TYPE_CHECKING:
    from .evidence_reporting import EvidenceReportArtifacts, EvidenceReportProfile


def __getattr__(name):
    """保留报告公开导出；只有真正使用报告时才加载其绘图依赖。"""
    if name in {"EvidenceReportArtifacts", "EvidenceReportProfile"}:
        from . import evidence_reporting
        value = getattr(evidence_reporting, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(__all__))


__all__ = [
    "BaselineSourceRequest",
    "ErrorMetrics",
    "EvidenceArtifacts",
    "EvidenceReportArtifacts",
    "EvidenceReportProfile",
    "ExactGridArtifacts",
    "ExactGridControlRow",
    "PrecisionPreflightReport",
    "PrecisionSweepDefinition",
    "ProtocolCostReport",
    "RangeMargin",
    "ResolvedBaselineSource",
    "ResolvedPrecisionSweepPlan",
    "ReusablePrecisionSweepDefinition",
    "SweepArtifacts",
    "SweepPointDefinition",
    "SweepRunRecord",
    "SweepRunStatus",
    "VerifiedEvidenceData",
    "VerifiedExactGridData",
    "aggregate_error_metrics",
    "compute_error_metrics",
    "derive_exact_grid_row",
    "load_precision_sweep_definition",
    "materialize_point_config",
    "paper_round_fraction",
]
