"""不负责领域装配的通用场景运行入口。"""

from __future__ import annotations

from .contracts import Scenario, SimulationPlan
from .engine import compare_closed_loops
from .results import SimulationResult


def run(scenario: Scenario) -> SimulationResult:
    """取得场景事前构造/证明的计划，再交给领域无关引擎执行。"""
    if not isinstance(scenario, Scenario):
        raise TypeError("scenario 必须提供 build_plan()。")
    plan = scenario.build_plan()
    if not isinstance(plan, SimulationPlan):
        raise TypeError("scenario.build_plan() 必须返回 SimulationPlan。")
    if (
        plan.ideal.adapter.metadata != plan.metadata
        or plan.secure.adapter.metadata != plan.metadata
    ):
        raise ValueError("场景计划 metadata 与两支 adapter 的 channel metadata 不一致。")
    return compare_closed_loops(plan.ideal, plan.secure, plan.sample_times)
