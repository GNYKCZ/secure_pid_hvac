"""HVAC 场景的配置契约；不包含 plant、reference 或 PID 的运行时实现。"""

from .contract import HvacScenarioContract, load_hvac_scenario_contract

__all__ = ["HvacScenarioContract", "load_hvac_scenario_contract"]
