"""#75：四水箱范围证明、独立 LAN 证据与 Fig. 4 只读汇总。"""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pytest
import yaml
from test_quadruple_tank_observer import ORACLE_U, ORACLE_Y

from secure_control.execution import (
    SecureStateSpaceRuntime,
    SecureTraceCollector,
    SecureTracePolicy,
)
from secure_control.experiments.artifacts import load_artifacts
from secure_control.experiments.quadruple_tank_fig4 import (
    PRECISIONS,
    _validate_record,
    build_saved_fig4,
    load_definition,
    verify_saved_fig4,
)
from secure_control.experiments.quadruple_tank_lan_profile import load_quadruple_tank_lan_profile
from secure_control.scenarios.quadruple_tank.secure_experiment import (
    assemble_quadruple_tank_plan,
    quadruple_tank_ideal_oracle,
)

ROOT = Path(__file__).resolve().parents[1]
DEFINITION = ROOT / "configs" / "quadruple_tank_fig4.yaml"
FORMAL = ROOT / "results" / "quadruple_tank_fig4"


@pytest.mark.parametrize("ell", PRECISIONS)
def test_four_precision_profiles_prove_two_measurements_and_payloads(
    tmp_path: Path, ell: int,
) -> None:
    """四个精度各自从 canonical 文件重算包络，而非从成功轨迹倒填。"""
    data = yaml.safe_load((ROOT / "configs" / "quadruple_tank_lan.example.yaml").read_text(
        encoding="utf-8"
    ))
    data["numeric"].update({"ell": ell, "k": ell + 8, "runtime_payload_bits": ell + 14})
    for key, filename in (("plant_source", "quadruple_tank_plant.yaml"),
                          ("observer_source", "quadruple_tank_observer.yaml")):
        data[key] = str(ROOT / "configs" / filename)
    data["numeric"]["prime_source"] = str(ROOT / "configs" /
                                            "shared_prime_256_pocklington.yaml")
    data["output_root"] = str(tmp_path / "runs")
    source = tmp_path / "profile.yaml"
    source.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    profile = load_quadruple_tank_lan_profile(source)
    assert profile.context.scale == 1 << ell
    assert profile.q.bit_length() - profile.security_parameter - 2 == 174
    assert profile.contract.horizon_steps == 51
    assert profile.contract.input_payload_bounds == (256 << ell, 256 << ell)
    assert profile.proof["measurement_envelope_v"][0] < 163
    assert profile.proof["measurement_envelope_v"][1] < 135
    assert all(bound <= profile.context.maximum_payload
               for bound in profile.contract.state_payload_bounds)
    profile.recheck_sources()
    oracle_y, oracle_u = quadruple_tank_ideal_oracle(profile.spec, profile.plant, 51)
    np.testing.assert_allclose(oracle_y[:5], ORACLE_Y, rtol=0, atol=2e-10)
    np.testing.assert_allclose(oracle_u[:5], ORACLE_U, rtol=0, atol=2e-10)
    assert oracle_y.shape == oracle_u.shape == (51, 2)
    assert np.max(np.abs(oracle_y), axis=0)[0] < 256
    assert np.max(np.abs(oracle_y), axis=0)[1] < 256
    plan = assemble_quadruple_tank_plan(profile.spec, profile.plant, object(), 51)
    assert plan.ideal.plant is not plan.secure.plant
    assert plan.ideal.adapter is not plan.secure.adapter
    np.testing.assert_array_equal(plan.sample_times, np.arange(51) * 0.5)


def test_source_drift_and_unproved_input_are_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load((ROOT / "configs" / "quadruple_tank_lan.example.yaml").read_text(
        encoding="utf-8"
    ))
    plant = tmp_path / "plant.yaml"
    plant.write_bytes((ROOT / "configs" / "quadruple_tank_plant.yaml").read_bytes())
    data["plant_source"] = str(plant)
    data["observer_source"] = str(ROOT / "configs" / "quadruple_tank_observer.yaml")
    data["numeric"]["prime_source"] = str(ROOT / "configs" /
                                            "shared_prime_256_pocklington.yaml")
    data["output_root"] = str(tmp_path / "runs")
    source = tmp_path / "profile.yaml"
    source.write_text(yaml.safe_dump(data), encoding="utf-8")
    profile = load_quadruple_tank_lan_profile(source)
    plant.write_bytes(plant.read_bytes() + b"\n# changed during session\n")
    with pytest.raises(ValueError, match="变化"):
        profile.recheck_sources()
    assert load_quadruple_tank_lan_profile(source).claim_level == "user-exploration"
    data["range"]["measurement_absolute_bounds_v"] = [160, 256]
    source.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="y1"):
        load_quadruple_tank_lan_profile(source)


@pytest.mark.parametrize("ell", [32, 56])
def test_real_mimo_protocol_preserves_s_squared_output_and_fresh_truncation(ell: int) -> None:
    """仅在测试边界重构 state，核对每行 Trunc 与两路无截断输出。"""
    source = ROOT / "configs" / "quadruple_tank_lan.example.yaml"
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    data["numeric"].update({"ell": ell, "k": ell + 8, "runtime_payload_bits": ell + 14})
    with TemporaryDirectory() as temporary:
        profile_path = Path(temporary) / "profile.yaml"
        data["plant_source"] = str(ROOT / "configs" / "quadruple_tank_plant.yaml")
        data["observer_source"] = str(ROOT / "configs" / "quadruple_tank_observer.yaml")
        data["numeric"]["prime_source"] = str(ROOT / "configs" /
                                                "shared_prime_256_pocklington.yaml")
        data["output_root"] = str(Path(temporary) / "runs")
        profile_path.write_text(yaml.safe_dump(data), encoding="utf-8")
        profile = load_quadruple_tank_lan_profile(profile_path)
        collector = SecureTraceCollector()
        runtime = SecureStateSpaceRuntime(
            profile.spec, profile.context, profile.contract,
            security_parameter=profile.security_parameter,
            modulus_evidence=profile.evidence, test_seed=75,
            trace_policy=SecureTracePolicy(0), trace_collector=collector,
        )
        scale = profile.context.scale
        encoded_b = np.asarray(profile.context.encode(profile.spec.B), dtype=object)
        encoded_c = np.asarray(profile.context.encode(profile.spec.C), dtype=object)
        encoded_y = np.asarray(profile.context.encode(np.array([5.0, 5.0])), dtype=object)
        np.testing.assert_array_equal(runtime.step(np.array([5.0, 5.0])), [0.0, 0.0])
        # 此处访问单进程测试 runtime 的私有双方 share；生产 P1/P2 API 不导出完整 state。
        residue = runtime._client.sharing.reconstruct(runtime._p1.state_share,
                                                      runtime._p2.state_share)
        actual = np.asarray(profile.context.from_residue(residue), dtype=object)
        raw = [sum(int(encoded_b[row, col]) * int(encoded_y[col]) for col in range(2))
               for row in range(4)]
        rounded = [(2 * value + scale) // (2 * scale) for value in raw]
        assert all(int(actual[row]) - rounded[row] in {-1, 0, 1} for row in range(4))
        second = runtime.step(np.array([5.0, 5.0]))
        expected = [sum(int(encoded_c[row, col]) * int(actual[col]) for col in range(4))
                    / (scale * scale) for row in range(2)]
        np.testing.assert_allclose(second, expected, rtol=0, atol=2**-ell)
        traces = collector.traces()
        assert len(traces) == 2
        assert [trace.operations.protocol1_triples for trace in traces] == [36, 36]
        assert [trace.operations.state_truncation for trace in traces] == [4, 4]
        assert len(set(traces[0].resource_id_sha256 + traces[1].resource_id_sha256)) == 80
        final = traces[-1].resources_after
        assert (final.triples_created, final.triples_consumed,
                final.truncations_created, final.truncations_consumed) == (72, 72, 8, 8)


def test_formal_fig4_four_distinct_sessions_and_verified_redraw(tmp_path: Path) -> None:
    """从仓库提交的四份真实三进程证据重新读取并生成图，不连接角色。"""
    manifest = verify_saved_fig4(FORMAL)
    runs = [FORMAL / item["relative_run_dir"] for item in manifest["runs"]]
    records = [load_artifacts(path) for path in runs]
    assert len({record.provenance["session_id"] for record in records}) == 4
    assert [record.effective_config["fractional_bits"] for record in records] == list(PRECISIONS)
    definition = load_definition(DEFINITION)
    for ell, record, summary in zip(PRECISIONS, records, manifest["summaries"], strict=True):
        assert _validate_record(record, ell, definition) == summary
        expected = np.sqrt(np.sum(record.result.control_error**2, axis=1))
        assert np.max(expected) == pytest.approx(summary["max_error_l2_v"], abs=1e-18)
        assert summary["below_epsilon"]
        assert record.provenance["resource_counts"] == {
            "products_consumed": 1836, "truncations_consumed": 204,
        }
    output = tmp_path / "fig4"
    build_saved_fig4(DEFINITION, runs, output)
    assert verify_saved_fig4(output)["summaries"] == manifest["summaries"]
    with pytest.raises(ValueError):
        build_saved_fig4(DEFINITION, [runs[0]] * 4, tmp_path / "duplicate")
    with pytest.raises(ValueError, match="来源|精度"):
        build_saved_fig4(DEFINITION, list(reversed(runs)), tmp_path / "reversed")
    forged = replace(records[0], effective_config={**records[0].effective_config,
                                                   "observer_source_sha256": "0" * 64})
    with pytest.raises(ValueError, match="来源"):
        _validate_record(forged, 32, definition)
    published = output / "manifest.json"
    content = json.loads(published.read_text(encoding="utf-8"))
    content["summaries"][0]["max_error_l2_v"] = 0
    published.write_text(json.dumps(content), encoding="utf-8")
    with pytest.raises(ValueError, match="摘要"):
        verify_saved_fig4(output)


def test_fig4_definition_source_digest_matches_canonical_files() -> None:
    definition = load_definition(DEFINITION)
    for key, filename in (("plant_sha256", "quadruple_tank_plant.yaml"),
                          ("observer_sha256", "quadruple_tank_observer.yaml"),
                          ("prime_sha256", "shared_prime_256_pocklington.yaml")):
        assert definition[key] == sha256((DEFINITION.parent / filename).read_bytes()).hexdigest()
