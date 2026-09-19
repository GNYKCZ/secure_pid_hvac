"""诊断 evidence 工件的无损整数、隔离、完整性与原子发布测试。"""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import FixedPointContext
from secure_control.execution import (
    SecureStateSpaceRuntime,
    SecureTraceCollector,
    SecureTracePolicy,
)
from secure_control.experiments.evidence_artifacts import (
    load_verified_evidence_artifacts,
    write_evidence_artifacts,
)
from secure_control.protocol import ControllerRangeContract, IntegerVectorEvidence
from secure_control.simulation import SimulationResult


def _fixture() -> tuple[tuple[object, ...], SimulationResult, np.ndarray, object]:
    """运行三步通用控制器，返回真实 trace 与配套八字段结果。"""
    spec = ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[-1.0]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=16, A=0, B=0, C=8, D=8),
    )
    collector = SecureTraceCollector()
    secure = SecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(state_payload_bounds=(256,), input_payload_bounds=(64,)),
        security_parameter=8,
        test_seed=7,
        trace_policy=SecureTracePolicy(selected_step=1, allow_combined_share_diagnostic=True),
        trace_collector=collector,
    )
    inputs = (0.125, -0.0625, 0.03125)
    secure_raw = np.vstack([secure.step(value) for value in inputs])
    plain_raw = np.array([[0.375], [0.1875], [-0.09375]])
    control_error = plain_raw - secure_raw
    zeros = np.zeros((3, 1), dtype=float)
    result = SimulationResult(
        time=np.arange(3, dtype=float),
        reference=zeros,
        output_ideal=zeros,
        output_secure=zeros,
        control_ideal=plain_raw,
        control_secure=secure_raw,
        control_error=control_error,
        output_error=zeros,
    )
    return collector.traces(), result, plain_raw, collector.selected_share_audit()


def test_evidence_artifacts_keep_large_integer_text_and_private_file_is_optional(
    tmp_path: Path,
) -> None:
    """大整数不经 binary64，private 文件删除后 sanitized reader 仍可独立验证。"""
    traces, result, plain_raw, audit = _fixture()
    huge = (1 << 80) + 1
    selected = traces[1]
    traces = (
        traces[0],
        replace(
            selected,
            raw_control=IntegerVectorEvidence(
                residue=((1 << 200) + 17,), centered=(huge,), fractional_bits=0
            ),
            decoded_raw_control=(float(huge),),
        ),
        traces[2],
    )
    artifacts = write_evidence_artifacts(
        traces=traces,
        result=result,
        plaintext_raw_control=plain_raw,
        metadata={"diagnostic_rng_seed": 7, "diagnostic_rng_mode": "reproducibility_only"},
        output_root=tmp_path / "diagnostics",
        source_sweep_id="source-sweep",
        share_audit=audit,
    )

    loaded = load_verified_evidence_artifacts(artifacts.directory)
    assert loaded.integer_control_rows[1]["secure_output_centered"] == huge
    assert artifacts.private_audit_path is not None
    assert artifacts.private_audit_path.is_file()
    manifest = json.loads((artifacts.directory / "manifest.json").read_text(encoding="utf-8"))
    assert "combined_share_step.json" not in manifest["files_sha256"]
    selected_text = (artifacts.directory / "selected_step_trace.json").read_text(encoding="utf-8")
    assert '"input_p1"' not in selected_text
    artifacts.private_audit_path.unlink()
    artifacts.private_audit_path.parent.rmdir()
    assert load_verified_evidence_artifacts(artifacts.directory).metadata["selected_step"] == 1


def test_evidence_reader_rejects_tamper_and_writer_omits_private_without_opt_in(
    tmp_path: Path,
) -> None:
    """sanitized 成员篡改 fail closed，未授权时不创建 combined-share 路径。"""
    traces, result, plain_raw, _ = _fixture()
    artifacts = write_evidence_artifacts(
        traces=traces,
        result=result,
        plaintext_raw_control=plain_raw,
        metadata={"diagnostic_rng_seed": 7, "diagnostic_rng_mode": "reproducibility_only"},
        output_root=tmp_path / "diagnostics",
        source_sweep_id="source-sweep",
        share_audit=None,
    )
    assert artifacts.private_audit_path is None
    assert artifacts.private_audit_sha256 is None
    selected = artifacts.directory / "selected_step_trace.json"
    selected.write_text(selected.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        load_verified_evidence_artifacts(artifacts.directory)


def test_evidence_writer_rejects_missing_or_duplicate_selected_state(tmp_path: Path) -> None:
    """selected state evidence 必须且只能出现一次，失败不发布正式目录。"""
    traces, result, plain_raw, _ = _fixture()
    without_state = tuple(replace(trace, state_transition=None) for trace in traces)
    with pytest.raises(ValueError, match="且只能包含一个"):
        write_evidence_artifacts(
            traces=without_state,
            result=result,
            plaintext_raw_control=plain_raw,
            metadata={},
            output_root=tmp_path / "diagnostics",
            source_sweep_id="source-sweep",
            share_audit=None,
        )
    published = tmp_path / "diagnostics" / "source-sweep"
    assert not published.exists() or list(published.iterdir()) == []


def test_reader_rejects_semantically_tampered_resource_lifecycle(tmp_path: Path) -> None:
    """即使攻击者重算文件 hash，成功 evidence 也不能包含未消费资源。"""
    traces, result, plain_raw, _ = _fixture()
    artifacts = write_evidence_artifacts(
        traces=traces,
        result=result,
        plaintext_raw_control=plain_raw,
        metadata={"diagnostic_rng_seed": 7, "diagnostic_rng_mode": "reproducibility_only"},
        output_root=tmp_path / "diagnostics",
        source_sweep_id="source-sweep",
        share_audit=None,
    )
    resource_path = artifacts.directory / "resource_counts.csv"
    rows = resource_path.read_text(encoding="utf-8").splitlines()
    fields = rows[1].split(",")
    fields[2] = str(int(fields[2]) - 1)
    rows[1] = ",".join(fields)
    resource_path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
    manifest_path = artifacts.directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files_sha256"]["resource_counts.csv"] = sha256(resource_path.read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ValueError, match="delta|全部消费"):
        load_verified_evidence_artifacts(artifacts.directory)


def test_writer_rejects_unsafe_source_sweep_directory_name(tmp_path: Path) -> None:
    """公开 writer 不允许 source ID 逃逸 diagnostics 根目录。"""
    traces, result, plain_raw, _ = _fixture()
    with pytest.raises(ValueError, match="单级目录名"):
        write_evidence_artifacts(
            traces=traces,
            result=result,
            plaintext_raw_control=plain_raw,
            metadata={},
            output_root=tmp_path / "diagnostics",
            source_sweep_id="../escape",
            share_audit=None,
        )
