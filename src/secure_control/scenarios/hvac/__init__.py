"""HVAC 场景组件：配置契约、plant、reference 和信号适配。"""

from .adapter import HvacSignalAdapter
from .baseline import HvacPlaintextBaseline, HvacSegmentMetric, run_plaintext_hvac_baseline
from .contract import HvacScenarioContract, load_hvac_scenario_contract
from .pid import HvacPidDesign, load_hvac_pid_design
from .plant import HvacPlant
from .reference import HvacStepReference

__all__ = [
    "HvacPidDesign",
    "HvacPlaintextBaseline",
    "HvacPlant",
    "HvacScenarioContract",
    "HvacSegmentMetric",
    "HvacSignalAdapter",
    "HvacStepReference",
    "load_hvac_pid_design",
    "load_hvac_scenario_contract",
    "run_plaintext_hvac_baseline",
]
