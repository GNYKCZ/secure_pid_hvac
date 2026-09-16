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
from .pid import HvacPidDesign, load_hvac_pid_design
from .plant import (
    Hvac2R2CPlant,
    Hvac2R2CStateSpace,
    HvacPlant,
    build_hvac_2r2c_state_space,
    build_hvac_plant,
)
from .reference import HvacStepReference
from .tuning import (
    HvacGainSearchAxis,
    HvacPidTuningContract,
    HvacPidTuningResult,
    HvacTuningInfeasibleError,
    load_hvac_pid_tuning_contract,
    tune_hvac_pid,
)

__all__ = [
    "Hvac2R2CModelContract",
    "Hvac2R2CPlant",
    "Hvac2R2CStateSpace",
    "HvacBranchMetrics",
    "HvacComparisonMetrics",
    "HvacControlQualityContract",
    "HvacGainSearchAxis",
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
    "build_hvac_2r2c_state_space",
    "build_hvac_plant",
    "evaluate_hvac_branch_metrics",
    "evaluate_hvac_comparison_metrics",
    "load_hvac_pid_design",
    "load_hvac_pid_tuning_contract",
    "load_hvac_scenario_contract",
    "run_plaintext_hvac_baseline",
    "tune_hvac_pid",
]
