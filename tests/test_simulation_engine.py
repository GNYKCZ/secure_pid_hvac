"""领域无关 runner/engine 的 toy 标量、向量、时序与隔离回归。"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pytest

from secure_control.core import ControllerSpec
from secure_control.execution import PlaintextStateSpaceRuntime
from secure_control.simulation import (
    ChannelMetadata,
    ScenarioMetadata,
    SimulationBranch,
    SimulationPlan,
    SimulationResult,
    run,
    simulate_branch,
)


class ToyPlant:
    """以向量加法更新可观测状态，不含任何具体场景概念。"""

    def __init__(self, initial: np.ndarray, events: list[str] | None = None) -> None:
        """为一支闭环复制初态和独立的可选调用记录。"""
        self.state = np.array(initial, dtype=float, copy=True)
        self.events = events

    def output(self) -> np.ndarray:
        """返回本轮更新前的可观测向量。"""
        if self.events is not None:
            self.events.append("output")
        return self.state.copy()

    def step(self, control: np.ndarray) -> np.ndarray:
        """仅用本支控制输入推进状态。"""
        if self.events is not None:
            self.events.append("plant.step")
        self.state += control
        return self.state.copy()


class ToyAdapter:
    """为 toy 场景提供通用通道、reference、v 映射和恒等 actuator。"""

    def __init__(self, channels: int, events: list[str] | None = None) -> None:
        """创建单支 adapter，通道数可为标量或向量。"""
        names = tuple(f"channel_{index}" for index in range(channels))
        channel = ChannelMetadata(names, ("unit",) * channels)
        self.metadata = ScenarioMetadata("toy", channel, channel, channel)
        self._reference = np.arange(1, channels + 1, dtype=float)
        self.events = events

    def reference_at(self, time: float) -> np.ndarray:
        """返回与时间网格同值的参考，便于比较两支是否对齐。"""
        if self.events is not None:
            self.events.append("reference")
        return self._reference.copy()

    def controller_input(self, reference: np.ndarray, output: np.ndarray) -> np.ndarray:
        """toy 场景自己决定 v 的构造，引擎只调用 hook。"""
        if self.events is not None:
            self.events.append("controller_input")
        return reference - output

    def apply_control(self, raw_control: np.ndarray) -> np.ndarray:
        """toy actuator 不裁剪，仍显式经过通用 hook。"""
        if self.events is not None:
            self.events.append("apply_control")
        return raw_control.copy()


class ToyRuntime:
    """以透传控制记录 step 次序，用于单支调用顺序测试。"""

    def __init__(self, events: list[str]) -> None:
        """持有本支调用记录，不读另一支任何状态。"""
        self.events = events

    def step(self, value: np.ndarray) -> np.ndarray:
        """返回本轮输入作为 raw control。"""
        self.events.append("runtime.step")
        return value.copy()

    def reset(self) -> None:
        """toy runtime 无内部状态，但满足共享接口。"""


@dataclass(frozen=True)
class ToyScenario:
    """使用相同 plan/runner API 装配两支独立 toy 闭环。"""

    channels: int

    def build_plan(self) -> SimulationPlan:
        """返回同值通道与时间网格，但不复用可变 plant/adapter/runtime。"""
        adapter_ideal = ToyAdapter(self.channels)
        adapter_secure = ToyAdapter(self.channels)
        dimension = self.channels
        spec = ControllerSpec(
            A=np.empty((0, 0)),
            B=np.empty((0, dimension)),
            C=np.empty((dimension, 0)),
            D=np.eye(dimension),
            x0=np.empty(0),
        )
        return SimulationPlan(
            metadata=adapter_ideal.metadata,
            sample_times=np.array([0.0, 1.0, 2.0]),
            ideal=SimulationBranch(
                ToyPlant(np.zeros(dimension)), adapter_ideal, PlaintextStateSpaceRuntime(spec)
            ),
            secure=SimulationBranch(
                ToyPlant(np.full(dimension, 0.5)),
                adapter_secure,
                PlaintextStateSpaceRuntime(spec),
            ),
        )


@pytest.mark.parametrize("channels", [1, 2])
def test_toy_scalar_and_vector_use_same_runner_with_signed_errors(channels: int) -> None:
    """不改引擎即运行标量/向量场景，且误差逐时刻、逐通道为 ideal-secure。"""
    result = run(ToyScenario(channels))

    assert result.time.shape == (3,)
    for name in (
        "reference",
        "output_ideal",
        "output_secure",
        "control_ideal",
        "control_secure",
        "control_error",
        "output_error",
    ):
        assert getattr(result, name).shape == (3, channels)
    np.testing.assert_array_equal(result.output_error[0], np.full(channels, -0.5))
    np.testing.assert_array_equal(result.control_error[0], np.full(channels, 0.5))
    np.testing.assert_array_equal(
        result.control_error, result.control_ideal - result.control_secure
    )
    np.testing.assert_array_equal(result.output_error, result.output_ideal - result.output_secure)


def test_branch_executes_hooks_in_order_and_records_pre_plant_output() -> None:
    """时间索引 t_k 的 output 只能是 plant.step 前取得的值。"""
    events: list[str] = []
    branch = SimulationBranch(
        ToyPlant(np.array([0.0]), events), ToyAdapter(1, events), ToyRuntime(events)
    )

    trajectory = simulate_branch(branch, np.array([0.0]))

    assert events == [
        "reference",
        "output",
        "controller_input",
        "runtime.step",
        "apply_control",
        "plant.step",
    ]
    np.testing.assert_array_equal(trajectory.output, np.array([[0.0]]))
    np.testing.assert_array_equal(trajectory.control, np.array([[1.0]]))


def test_plan_and_result_reject_nonincreasing_time() -> None:
    """runner plan 与八字段结果均不得把重复时间当成合法单步。"""
    plan = ToyScenario(1).build_plan()
    with pytest.raises(ValueError, match="严格递增"):
        SimulationPlan(plan.metadata, np.array([0.0, 0.0]), plan.ideal, plan.secure)
    with pytest.raises(ValueError, match="strictly increasing"):
        SimulationResult(
            time=np.array([0.0, 0.0]),
            reference=np.zeros((2, 1)),
            output_ideal=np.zeros((2, 1)),
            output_secure=np.zeros((2, 1)),
            control_ideal=np.zeros((2, 1)),
            control_secure=np.zeros((2, 1)),
            control_error=np.zeros((2, 1)),
            output_error=np.zeros((2, 1)),
        )


def test_compare_rejects_shared_mutable_branch_objects_before_steps() -> None:
    """两支共享 plant、adapter 或 runtime 时不得进入时间循环。"""
    plan = ToyScenario(1).build_plan()
    for shared_branch in (
        SimulationBranch(plan.ideal.plant, plan.secure.adapter, plan.secure.runtime),
        SimulationBranch(plan.secure.plant, plan.ideal.adapter, plan.secure.runtime),
        SimulationBranch(plan.secure.plant, plan.secure.adapter, plan.ideal.runtime),
    ):
        bad_plan = SimulationPlan(plan.metadata, plan.sample_times, plan.ideal, shared_branch)
        with pytest.raises(ValueError, match="不得共享"):
            run(_FixedPlanScenario(bad_plan))


def test_nonfinite_reference_and_bad_actuator_shape_fail_without_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """任一 hook 返回 NaN/错通道时必须在 plant 更新前拒绝，不能产生部分结果。"""
    events: list[str] = []
    plant = ToyPlant(np.array([0.0]), events)
    adapter = ToyAdapter(1, events)
    branch = SimulationBranch(plant, adapter, ToyRuntime(events))

    def nonfinite_reference(time: float) -> np.ndarray:
        """模拟 reference hook 返回无效实数。"""
        return np.array([np.nan])

    monkeypatch.setattr(adapter, "reference_at", nonfinite_reference)
    with pytest.raises(FloatingPointError, match="NaN"):
        simulate_branch(branch, np.array([0.0]))
    assert "plant.step" not in events
    monkeypatch.undo()
    events.clear()

    def wrong_control_shape(raw: np.ndarray) -> np.ndarray:
        """模拟场景 actuator 错误增加了一个 control channel。"""
        return np.array([raw[0], raw[0]])

    monkeypatch.setattr(adapter, "apply_control", wrong_control_shape)
    with pytest.raises(ValueError, match="channel shape"):
        simulate_branch(branch, np.array([0.0]))
    assert "plant.step" not in events


def test_mismatched_branch_references_fail_after_independent_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """相同时间网格的两支 reference 若不同，不能返回看似公平的八字段结果。"""
    plan = ToyScenario(1).build_plan()

    def shifted_reference(time: float) -> np.ndarray:
        """仅改变 secure 分支的场景 reference。"""
        return np.array([2.0])

    monkeypatch.setattr(plan.secure.adapter, "reference_at", shifted_reference)
    with pytest.raises(ValueError, match="reference 时间轨迹"):
        run(_FixedPlanScenario(plan))


@dataclass(frozen=True)
class _FixedPlanScenario:
    """让测试向通用 runner 注入一个已构造计划，不包含领域装配。"""

    plan: SimulationPlan

    def build_plan(self) -> SimulationPlan:
        """原样返回计划以验证执行前隔离检查。"""
        return self.plan
