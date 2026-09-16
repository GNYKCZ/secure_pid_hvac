"""HVAC 场景组件：配置契约、plant、reference 和信号适配。"""

from .adapter import HvacSignalAdapter
from .baseline import HvacPlaintextBaseline, HvacSegmentMetric, run_plaintext_hvac_baseline
from .contract import (
    Hvac2R2CModelContract,
    HvacParameterProvenance,
    HvacPlantModelContract,
    HvacScenarioContract,
    load_hvac_scenario_contract,
)
from .pid import HvacPidDesign, load_hvac_pid_design
from .plant import Hvac2R2CPlant, Hvac2R2CStateSpace, HvacPlant, build_hvac_2r2c_state_space
from .reference import HvacStepReference

__all__ = [
    "Hvac2R2CModelContract",
    "Hvac2R2CPlant",
    "Hvac2R2CStateSpace",
    "HvacParameterProvenance",
    "HvacPidDesign",
    "HvacPlaintextBaseline",
    "HvacPlant",
    "HvacPlantModelContract",
    "HvacScenarioContract",
    "HvacSegmentMetric",
    "HvacSignalAdapter",
    "HvacStepReference",
    "build_hvac_2r2c_state_space",
    "load_hvac_pid_design",
    "load_hvac_scenario_contract",
    "run_plaintext_hvac_baseline",
]
