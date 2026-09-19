"""HVAC 场景组件：配置契约、plant、reference 和信号适配。"""

from .adapter import HvacSignalAdapter
from .baseline import (
    HvacBranchMetrics,
    HvacComparisonMetrics,
    HvacControlQualityContract,
    HvacPlaintextBaseline,
    HvacSegmentMetric,
    HvacSegmentQualityContract,
    evaluate_hvac_branch_metrics,
    evaluate_hvac_comparison_metrics,
    run_plaintext_hvac_baseline,
)
from .contract import (
    Hvac2R2CModelContract,
    HvacParameterProvenance,
    HvacPlantModelContract,
    HvacScenarioContract,
    load_hvac_scenario_contract,
)
from .infinite_safety import (
    HvacInfiniteSafetyBundle,
    HvacInfiniteSafetyProfile,
    load_hvac_infinite_safety_bundle,
)
from .pid import HvacPidDesign, load_hvac_pid_design
from .plant import (
    Hvac2R2CPlant,
    Hvac2R2CStateSpace,
    HvacPlant,
    build_hvac_2r2c_state_space,
    build_hvac_plant,
)
from .reference import HvacStepReference
from .stability import (
    ApplicabilityStatus,
    HvacClosedLoopStabilityReport,
    HvacEquilibriumReport,
    analyze_hvac_closed_loop_stability,
    build_hvac_closed_loop_matrix,
)
from .tuning import (
    HvacGainSearchAxis,
    HvacPidTuningContract,
    HvacPidTuningResult,
    HvacTuningInfeasibleError,
    load_hvac_pid_tuning_contract,
    tune_hvac_pid,
)

__all__ = [
    "ApplicabilityStatus",
    "Hvac2R2CModelContract",
    "Hvac2R2CPlant",
    "Hvac2R2CStateSpace",
    "HvacBranchMetrics",
    "HvacClosedLoopStabilityReport",
    "HvacComparisonMetrics",
    "HvacControlQualityContract",
    "HvacEquilibriumReport",
    "HvacGainSearchAxis",
    "HvacInfiniteSafetyBundle",
    "HvacInfiniteSafetyProfile",
    "HvacParameterProvenance",
    "HvacPidDesign",
    "HvacPidTuningContract",
    "HvacPidTuningResult",
    "HvacPlaintextBaseline",
    "HvacPlant",
    "HvacPlantModelContract",
    "HvacScenarioContract",
    "HvacSegmentMetric",
    "HvacSegmentQualityContract",
    "HvacSignalAdapter",
    "HvacStepReference",
    "HvacTuningInfeasibleError",
    "analyze_hvac_closed_loop_stability",
    "build_hvac_2r2c_state_space",
    "build_hvac_closed_loop_matrix",
    "build_hvac_plant",
    "evaluate_hvac_branch_metrics",
    "evaluate_hvac_comparison_metrics",
    "load_hvac_infinite_safety_bundle",
    "load_hvac_pid_design",
    "load_hvac_pid_tuning_contract",
    "load_hvac_scenario_contract",
    "run_plaintext_hvac_baseline",
    "tune_hvac_pid",
]
