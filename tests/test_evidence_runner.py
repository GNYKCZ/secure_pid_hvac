"""Issue #51 诊断复现器的严格等价与透明记录回归测试。"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from secure_control.experiments import evidence_runner, sweep_runner
from secure_control.experiments.evidence_runner import (
    _assert_exact_result,
    _RecordingRuntime,
    run_evidence_diagnostic,
)
from secure_control.experiments.sweep import (
    PrecisionPreflightReport,
    ProtocolCostReport,
    ResolvedBaselineSource,
    ResolvedPrecisionSweepPlan,
    SweepRunRecord,
    SweepRunStatus,
    load_precision_sweep_definition,
)
from secure_control.experiments.sweep_artifacts import VerifiedSweepData, write_definition
from secure_control.protocol import ControllerScaleLedger
from secure_control.simulation import SimulationResult

PROJECT_ROOT = Path(__file__).parents[1]
V2_DEFINITION = PROJECT_ROOT / "configs" / "hvac_2r2c_precision_sweep_definition.yaml"
CURRENT_BASELINE = PROJECT_ROOT / "configs" / "hvac_2r2c_dual_loop_25_20_15.yaml"
CURRENT_BASELINE_ID = "f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab"
HISTORICAL_BASELINE_ID = "2489e5476ad316ea2d9599783e29f2d849ffcf485ca860e0db76c80312c532f9"


class _RuntimeStub:
    """提供最小通用 runtime 行为，并允许验证 reset 委托。"""

    def __init__(self) -> None:
        self.state = 0.0

    def step(self, value: np.ndarray | float) -> np.ndarray:
        """返回独立数组，模拟会更新状态的 controller。"""
        self.state += float(np.asarray(value))
        return np.array([self.state])

    def reset(self) -> None:
        """恢复初态。"""
        self.state = 0.0


def _result() -> SimulationResult:
    """构造两个采样点的八字段结果。"""
    time = np.array([0.0, 1.0], dtype=np.float64)
    values = np.array([[1.0], [2.0]], dtype=np.float64)
    zeros = np.zeros((2, 1), dtype=np.float64)
    return SimulationResult(time, values, values, values, values, values, zeros, zeros)


def _v2_sweep_fixture(
    tmp_path: Path,
) -> tuple[VerifiedSweepData, ResolvedPrecisionSweepPlan]:
    """构造只用于 evidence composition 行为测试的 verified v2 内存对象。"""
    definition = load_precision_sweep_definition(V2_DEFINITION)
    point = next(item for item in definition.points if item.ell == 48 and item.seed == 42)
    sweep_root = tmp_path / "v2-sweep"
    sweep_root.mkdir()
    write_definition(sweep_root / "definition.json", definition)
    definition_payload = json.loads((sweep_root / "definition.json").read_text(encoding="utf-8"))
    source = ResolvedBaselineSource(
        CURRENT_BASELINE,
        "hvac_baseline_identity_v1",
        CURRENT_BASELINE_ID,
        {"wrapper": "1" * 64, "baseline": "2" * 64, "scenario": "3" * 64},
        "4" * 64,
        "5" * 64,
    )
    plan = ResolvedPrecisionSweepPlan(
        definition,
        source,
        {"schur": {"status": "stable"}, "equilibria": []},
        "6" * 64,
        True,
        definition.points,
        {},
    )
    record = SweepRunRecord(
        point,
        SweepRunStatus.SUCCESS,
        PrecisionPreflightReport(True, True, True, (), True, ()),
        None,
        None,
        {},
        ProtocolCostReport(9, 18, 0, 0, 256, 128, 0.1, "fixture"),
        f"runs/{point.point_id}/fixture-run",
        None,
        None,
    )
    resolved_source = {
        "schema_version": 1,
        "config_path": CURRENT_BASELINE.name,
        "identity_scheme": source.identity_scheme,
        "baseline_id": source.baseline_id,
        "source_hashes": dict(source.source_hashes),
        "effective_config_sha256": source.effective_config_sha256,
        "finite_horizon_certificate_sha256": source.finite_horizon_certificate_sha256,
    }
    resolved_plan = {
        "schema_version": 1,
        "definition_schema_version": 2,
        "definition_sha256": "7" * 64,
        "baseline_identity_scheme": source.identity_scheme,
        "baseline_id": source.baseline_id,
        "stability_report": plan.stability_report,
        "stability_report_sha256": plan.stability_report_sha256,
        "prime_evidence_passed": True,
        "points": [
            {
                "ell": item.ell,
                "k": item.k,
                "lambda_": item.lambda_,
                "q": item.q,
                "kappa": item.kappa,
                "seed": item.seed,
            }
            for item in definition.points
        ],
        "provenance": {},
    }
    verified = VerifiedSweepData(
        sweep_root,
        definition_payload,
        (record,),
        {point.point_id: SimpleNamespace(run_id="fixture-run", result=_result())},
        resolved_source,
        resolved_plan,
    )
    return verified, plan


def test_recording_runtime_is_transparent_returns_copies_and_resets() -> None:
    """记录 wrapper 不改变返回值，外部改写也不能污染已记录 raw control。"""
    runtime = _RuntimeStub()
    recording = _RecordingRuntime(runtime)
    returned = recording.step(0.25)
    returned[0] = 99.0
    assert np.array_equal(recording.outputs(), np.array([[0.25]]))
    recording.reset()
    assert runtime.state == 0.0
    with pytest.raises(ValueError, match="尚未记录"):
        recording.outputs()


def test_exact_result_gate_rejects_value_shape_and_dtype_changes() -> None:
    """八字段门禁同时锁定 bitwise 数值、shape 与 dtype，不能改成 tolerance。"""
    expected = _result()
    _assert_exact_result(expected, expected)

    changed = np.array(expected.control_secure, copy=True)
    changed[0, 0] = np.nextafter(changed[0, 0], np.inf)
    with pytest.raises(ValueError, match="control_secure"):
        _assert_exact_result(replace(expected, control_secure=changed), expected)

    float32 = np.asarray(expected.reference, dtype=np.float32)
    with pytest.raises(ValueError, match="reference"):
        _assert_exact_result(replace(expected, reference=float32), expected)

    shape_changed = SimpleNamespace(
        **{
            name: (np.array([0.0, 0.5, 1.0]) if name == "time" else getattr(expected, name))
            for name in (
                "time",
                "reference",
                "output_ideal",
                "output_secure",
                "control_ideal",
                "control_secure",
                "control_error",
                "output_error",
            )
        }
    )
    with pytest.raises(ValueError, match="time"):
        _assert_exact_result(shape_changed, expected)


def test_v2_evidence_reproduction_uses_explicit_verified_source_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v2 composition 主路径必须把显式 trust anchor 与 verified plan 交给统一 resolver。"""
    verified, materialization = _v2_sweep_fixture(tmp_path)
    captured: dict[str, object] = {}
    canonical_resolver = evidence_runner.resolve_verified_precision_sweep_plan

    def resolve_plan(definition, request, resolved_source, resolved_plan):
        captured.update(
            definition=definition,
            request=request,
            resolved_source=resolved_source,
            resolved_plan=resolved_plan,
        )
        return canonical_resolver(definition, request, resolved_source, resolved_plan)

    class CollectorStub:
        """提供不含 private shares 的最小 trace collector。"""

        def traces(self) -> tuple[object, ...]:
            """返回由门禁 stub 接受的空 trace。"""
            return ()

        def selected_share_audit(self) -> None:
            """正常公开路径不生成 combined-share audit。"""
            return

    class RecorderStub:
        """提供与 fixture 结果 shape 一致的 raw control。"""

        def __init__(self, _runtime: object) -> None:
            pass

        def outputs(self) -> np.ndarray:
            """返回两个采样点的 raw control。"""
            return np.ones((2, 1))

    ledger = ControllerScaleLedger(1, 1, 0, 0, 0, 0, 1, 0, 1, 1)
    runtime = SimpleNamespace(scale_ledger=ledger)
    execution_plan = SimpleNamespace(
        ideal=SimpleNamespace(plant=object(), adapter=object(), runtime=object()),
        secure=SimpleNamespace(runtime=runtime),
        sample_times=np.array([0.0, 1.0]),
    )

    class ScenarioStub:
        """隔离 composition 测试与真实 HVAC 仿真成本。"""

        metadata = SimpleNamespace(name="hvac")
        scenario_version = "1"

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def build_plan(self) -> SimpleNamespace:
            """返回具有 scale ledger 的最小执行计划。"""
            return execution_plan

        def metrics(self, _result: SimulationResult) -> dict[str, object]:
            """维持正式调用顺序但不引入无关品质计算。"""
            return {}

    expected_artifacts = SimpleNamespace(trace_id="fixture-trace")

    def write_artifacts(**kwargs: object) -> object:
        kwargs["prepublish_validator"]()
        captured["metadata"] = kwargs["metadata"]
        return expected_artifacts

    monkeypatch.setattr(evidence_runner, "_source_snapshot", lambda *_args: {"manifest": "x"})
    monkeypatch.setattr(
        evidence_runner, "load_verified_sweep_data", lambda *_args, **_kwargs: verified
    )
    monkeypatch.setattr(evidence_runner, "resolve_verified_precision_sweep_plan", resolve_plan)
    monkeypatch.setattr(
        sweep_runner,
        "resolve_hvac_baseline_source",
        lambda request, _requirements: (
            captured.update(source_request=request) or materialization.source
        ),
    )
    monkeypatch.setattr(
        sweep_runner,
        "stability_report_sha256",
        lambda *_args: (
            materialization.stability_report_sha256,
            dict(materialization.stability_report),
        ),
    )
    monkeypatch.setattr(sweep_runner, "HvacScenario", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        evidence_runner,
        "materialize_point_config",
        lambda _plan, _point, path: Path(path).write_text("fixture: true\n", encoding="utf-8"),
    )
    monkeypatch.setattr(evidence_runner, "SecureTraceCollector", CollectorStub)
    monkeypatch.setattr(evidence_runner, "HvacScenario", ScenarioStub)
    monkeypatch.setattr(evidence_runner, "_RecordingRuntime", RecorderStub)
    monkeypatch.setattr(
        evidence_runner, "SimulationBranch", lambda *args: SimpleNamespace(args=args)
    )
    monkeypatch.setattr(evidence_runner, "compare_closed_loops", lambda *_args: _result())
    monkeypatch.setattr(evidence_runner, "_validate_runtime_evidence", lambda *_args: None)
    monkeypatch.setattr(
        evidence_runner,
        "validate_resolved_baseline_source",
        lambda source: captured.update(validated_source=source),
    )
    monkeypatch.setattr(evidence_runner, "collect_provenance", lambda **_kwargs: {})
    monkeypatch.setattr(evidence_runner, "write_evidence_artifacts", write_artifacts)

    artifacts = run_evidence_diagnostic(
        sweep_dir=verified.root,
        ell=48,
        seed=42,
        selected_step=0,
        output_root=tmp_path / "evidence",
        baseline_config=CURRENT_BASELINE,
        expected_baseline_id=CURRENT_BASELINE_ID,
    )
    assert artifacts is expected_artifacts
    assert captured["request"].config_path == CURRENT_BASELINE
    assert captured["request"].expected_baseline_id == CURRENT_BASELINE_ID
    assert captured["source_request"] == captured["request"]
    assert captured["resolved_source"] is verified.resolved_source
    assert captured["resolved_plan"] is verified.resolved_plan
    assert captured["validated_source"] is materialization.source
    assert captured["metadata"]["resolved_baseline"] == {
        "identity_scheme": materialization.source.identity_scheme,
        "baseline_id": materialization.source.baseline_id,
    }


@pytest.mark.parametrize(
    ("baseline_config", "expected_id"),
    ((None, CURRENT_BASELINE_ID), (CURRENT_BASELINE, None)),
)
def test_v2_evidence_reproduction_rejects_incomplete_source_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    baseline_config: Path | None,
    expected_id: str | None,
) -> None:
    """v2 evidence 缺少 path 或 expected ID 时必须在仿真前失败。"""
    verified, _ = _v2_sweep_fixture(tmp_path)
    monkeypatch.setattr(evidence_runner, "_source_snapshot", lambda *_args: {})
    monkeypatch.setattr(
        evidence_runner, "load_verified_sweep_data", lambda *_args, **_kwargs: verified
    )
    with pytest.raises(ValueError, match="必须显式提供"):
        run_evidence_diagnostic(
            sweep_dir=verified.root,
            ell=48,
            seed=42,
            selected_step=0,
            output_root=tmp_path / "evidence",
            baseline_config=baseline_config,
            expected_baseline_id=expected_id,
        )


def test_v2_evidence_reproduction_rejects_resolved_plan_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """verified resolved plan 与显式 baseline 不一致时不得进入场景复现。"""
    verified, materialization = _v2_sweep_fixture(tmp_path)
    verified.resolved_plan["baseline_id"] = "0" * 64
    monkeypatch.setattr(evidence_runner, "_source_snapshot", lambda *_args: {})
    monkeypatch.setattr(
        evidence_runner, "load_verified_sweep_data", lambda *_args, **_kwargs: verified
    )
    monkeypatch.setattr(
        sweep_runner,
        "resolve_hvac_baseline_source",
        lambda *_args: materialization.source,
    )
    monkeypatch.setattr(
        sweep_runner,
        "stability_report_sha256",
        lambda *_args: (
            materialization.stability_report_sha256,
            dict(materialization.stability_report),
        ),
    )
    with pytest.raises(ValueError, match="resolved_plan"):
        run_evidence_diagnostic(
            sweep_dir=verified.root,
            ell=48,
            seed=42,
            selected_step=0,
            output_root=tmp_path / "evidence",
            baseline_config=CURRENT_BASELINE,
            expected_baseline_id=CURRENT_BASELINE_ID,
        )


def test_v2_evidence_reproduction_rejects_wrong_expected_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """evidence composition 必须把错误 trust anchor 交给真实 baseline resolver 拒绝。"""
    verified, _ = _v2_sweep_fixture(tmp_path)
    monkeypatch.setattr(evidence_runner, "_source_snapshot", lambda *_args: {})
    monkeypatch.setattr(
        evidence_runner, "load_verified_sweep_data", lambda *_args, **_kwargs: verified
    )
    with pytest.raises(ValueError, match="expected_baseline_id"):
        run_evidence_diagnostic(
            sweep_dir=verified.root,
            ell=48,
            seed=42,
            selected_step=0,
            output_root=tmp_path / "evidence",
            baseline_config=CURRENT_BASELINE,
            expected_baseline_id=HISTORICAL_BASELINE_ID,
        )
