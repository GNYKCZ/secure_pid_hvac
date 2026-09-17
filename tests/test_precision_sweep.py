"""Issue #15 扫描定义、精确范围和资源计数回归。"""

from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import yaml

from secure_control.experiments import sweep_runner
from secure_control.experiments.sweep import (
    SweepRunStatus,
    load_precision_sweep_definition,
    materialize_point_config,
)
from secure_control.experiments.sweep_runner import derive_protocol_cost
from secure_control.scenarios.hvac.integration import HvacSafetyCertificate, HvacScenario

PROJECT_ROOT = Path(__file__).parents[1]
DEFINITION_PATH = PROJECT_ROOT / "configs" / "hvac_2r2c_precision_sweep.yaml"


def test_definition_freezes_twelve_points_and_security_invariants() -> None:
    """扫描只改变 ell/k，固定 q、lambda、seed 集合与主 seed。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    assert definition.fractional_bits == (32, 40, 48, 56)
    assert definition.seeds == (42, 43, 44)
    assert definition.primary_seed == 42
    assert len(definition.points) == 12
    assert {(point.ell, point.k) for point in definition.points} == {
        (32, 60),
        (40, 68),
        (48, 76),
        (56, 84),
    }
    assert {point.lambda_ for point in definition.points} == {80}
    assert {point.q.bit_length() for point in definition.points} == {256}
    assert {point.kappa for point in definition.points} == {174}


def test_materialized_ell56_config_uses_proven_prime_and_exact_input_bound(
    tmp_path: Path,
) -> None:
    """ell=56 的输入 payload 上界按 float 精确比值计算，不丢失最后的 +1。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    point = next(item for item in definition.points if item.ell == 56 and item.seed == 42)
    path = tmp_path / "point.yaml"
    materialize_point_config(definition, point, path)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["security"]["integer_bits"] == 84
    assert loaded["security"]["fractional_bits"] == 56
    assert loaded["security"]["security_parameter"] == 80
    assert loaded["security"]["modulus"] == point.q

    scenario = HvacScenario(path, test_seed=42)
    low, high = scenario.safety_certificate.controller_input_bounds_celsius
    maximum = max(abs(low), abs(high))
    numerator, denominator = maximum.as_integer_ratio()
    expected = -(-(numerator * (1 << 56)) // denominator) + 1
    assert scenario.safety_certificate.input_payload_bound == expected


def test_protocol_cost_is_derived_from_actual_shapes_and_zero_truncation_ledger(
    tmp_path: Path,
) -> None:
    """2x1x1 PID 每步九个 triple，整数 A/B ledger 不分配 Protocol 2。"""
    definition = load_precision_sweep_definition(DEFINITION_PATH)
    point = definition.points[0]
    path = tmp_path / "point.yaml"
    materialize_point_config(definition, point, path)
    scenario = HvacScenario(path, test_seed=point.seed)
    plan = scenario.build_plan()
    cost = derive_protocol_cost(
        plan.secure.runtime,
        scenario.safety_certificate,
        scenario.effective_config_snapshot()["hvac"]["timing"]["sample_count"],
        1.25,
    )
    assert cost.protocol1_triples_per_step == 9
    assert cost.protocol1_triples_total == 1620
    assert cost.protocol2_truncations_per_step == 0
    assert cost.protocol2_truncations_total == 0
    assert cost.resource_count_kind == "derived_exact"
    assert cost.q_bit_length == 256
    assert cost.wall_clock_seconds == 1.25
    assert SweepRunStatus.SUCCESS.value == "success"
    assert asdict(cost)["timing_scope"] == "validated_point_execution_and_artifact_write"


def test_runner_publishes_success_infeasible_and_failed_points_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """单点不可行或异常不吞掉诊断，也不阻止完整批次原子发布。"""
    loaded = load_precision_sweep_definition(DEFINITION_PATH)
    definition = replace(loaded, fractional_bits=(32,), seeds=(42, 43, 44))
    centered_limit = (definition.q - 1) // 2

    class FakeScenario:
        """只为状态编排测试提供最小场景边界，不替代数值集成测试。"""

        scenario_version = "1"

        def __init__(self, _path: Path, *, test_seed: int) -> None:
            self.seed = test_seed
            payload = (1 << 59) if test_seed == 43 else 1
            self.safety_certificate = HvacSafetyCertificate(
                180,
                ("plant",),
                ((0.0, 1.0),),
                (-1.0, 1.0),
                ("state",),
                ((-1.0, 1.0),),
                (-1.0, 1.0),
                (0.0, 1.0),
                (payload,),
                (1,),
                (1,),
                (1,),
                centered_limit,
                0,
            )
            self.metadata = SimpleNamespace(name="hvac")

        def build_plan(self) -> SimpleNamespace:
            """第三个 seed 模拟资源建立后的执行异常。"""
            if self.seed == 44:
                raise RuntimeError("simulated point failure")
            runtime = SimpleNamespace(
                spec=SimpleNamespace(state_dimension=2, input_dimension=1, output_dimension=1),
                scale_ledger=SimpleNamespace(state_truncation_bits=0),
                modulus_verification=SimpleNamespace(bit_length=256),
            )
            return SimpleNamespace(
                ideal=object(),
                secure=SimpleNamespace(runtime=runtime),
                sample_times=np.arange(2, dtype=float),
            )

        def metrics_snapshot(self, _result: object) -> dict[str, bool]:
            """返回最小场景指标快照。"""
            return {"passed": True}

        def effective_config_snapshot(self) -> dict[str, object]:
            """返回 fake writer 不解释的最小快照。"""
            return {"scenario": {"name": "hvac", "version": "1"}}

    result = SimpleNamespace(
        output_error=np.array([[0.0], [0.25]]),
        control_error=np.array([[0.0], [0.5]]),
    )

    def fake_write(*_args: object, output_root: Path, **_kwargs: object) -> SimpleNamespace:
        """为编排测试创建最短已发布 run 路径。"""
        run_dir = Path(output_root) / "run"
        run_dir.mkdir(parents=True)
        return SimpleNamespace(run_dir=run_dir)

    stable = {"schur": {"status": "stable"}, "equilibria": [{"applicability": "applicable"}]}
    monkeypatch.setattr(sweep_runner, "load_precision_sweep_definition", lambda _path: definition)
    monkeypatch.setattr(
        sweep_runner, "stability_report_sha256", lambda _plant, _pid: ("hash", stable)
    )
    monkeypatch.setattr(sweep_runner, "_frozen_sources", lambda _definition, _hash: (True, {}))
    monkeypatch.setattr(sweep_runner, "HvacScenario", FakeScenario)
    monkeypatch.setattr(sweep_runner, "compare_closed_loops", lambda *_args: result)
    monkeypatch.setattr(sweep_runner, "collect_provenance", lambda **_kwargs: {})
    monkeypatch.setattr(sweep_runner, "write_artifacts", fake_write)
    monkeypatch.setattr(sweep_runner, "render_saved_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sweep_runner, "render_sweep_figures", lambda *_args, **_kwargs: ())

    artifacts = sweep_runner.run_precision_sweep(DEFINITION_PATH, output_root=tmp_path / "out")
    assert [record.status for record in artifacts.records] == [
        SweepRunStatus.SUCCESS,
        SweepRunStatus.INFEASIBLE,
        SweepRunStatus.FAILED,
    ]
    assert artifacts.manifest_path.is_file()
    assert not list((tmp_path / "out").glob(".incomplete-*"))
