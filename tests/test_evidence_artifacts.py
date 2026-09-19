"""诊断 evidence 工件的无损整数、隔离、完整性与原子发布测试。"""

from __future__ import annotations

import csv
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

MODULUS = (1 << 64) - 59


def _metadata() -> dict[str, object]:
    """返回与真实 trace 使用的模数绑定的最小诊断 metadata。"""
    return {
        "diagnostic_rng_seed": 7,
        "diagnostic_rng_mode": "reproducibility_only",
        "modulus": MODULUS,
        "source_point": {"q": MODULUS},
    }


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
        FixedPointContext(MODULUS, integer_bits=20, fractional_bits=8),
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
    huge = (1 << 60) + 1
    selected = traces[1]
    traces = (
        traces[0],
        replace(
            selected,
            raw_control=IntegerVectorEvidence(residue=(huge,), centered=(huge,), fractional_bits=0),
            decoded_raw_control=(float(huge),),
        ),
        traces[2],
    )
    artifacts = write_evidence_artifacts(
        traces=traces,
        result=result,
        plaintext_raw_control=plain_raw,
        metadata=_metadata(),
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
        metadata=_metadata(),
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
        metadata=_metadata(),
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


def _published_fixture(tmp_path: Path) -> Path:
    """发布一个可被篡改测试复用的 sanitized evidence 目录。"""
    traces, result, plain_raw, _ = _fixture()
    return write_evidence_artifacts(
        traces=traces,
        result=result,
        plaintext_raw_control=plain_raw,
        metadata=_metadata(),
        output_root=tmp_path / "diagnostics",
        source_sweep_id="source-sweep",
        share_audit=None,
    ).directory


def _refresh_manifest_hash(directory: Path, filename: str) -> None:
    """模拟攻击者修改成员后同步重算 manifest 文件摘要。"""
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files_sha256"][filename] = sha256((directory / filename).read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def test_reader_rejects_csv_residue_tamper_after_manifest_rehash(tmp_path: Path) -> None:
    """即使重算摘要，CSV residue 也必须与 q 下的 centered 映射一致。"""
    directory = _published_fixture(tmp_path)
    path = directory / "integer_control.csv"
    with path.open("r", encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
        fieldnames = tuple(rows[0])
    rows[1]["secure_output_residue"] = "1"
    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    _refresh_manifest_hash(directory, path.name)

    with pytest.raises(ValueError, match="residue|centered|模数"):
        load_verified_evidence_artifacts(directory)


def test_reader_rejects_manifest_hashed_modulus_source_mismatch(tmp_path: Path) -> None:
    """metadata 文件重算摘要后，模数仍必须与声明的 source point 绑定。"""
    directory = _published_fixture(tmp_path)
    path = directory / "metadata.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["modulus"] = MODULUS - 2
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _refresh_manifest_hash(directory, path.name)

    with pytest.raises(ValueError, match="source point|模数"):
        load_verified_evidence_artifacts(directory)


@pytest.mark.parametrize(
    "vector_path",
    [
        ("raw_control",),
        ("state_transition", "state_before"),
    ],
)
def test_reader_rejects_selected_integer_vector_residue_tamper(
    tmp_path: Path,
    vector_path: tuple[str, ...],
) -> None:
    """selected output 与状态向量的 residue 都必须通过 canonical 映射。"""
    directory = _published_fixture(tmp_path)
    path = directory / "selected_step_trace.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    vector = payload
    for name in vector_path:
        vector = vector[name]
    vector["residue"][0] = "1"
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _refresh_manifest_hash(directory, path.name)

    with pytest.raises(ValueError, match="residue|centered|模数"):
        load_verified_evidence_artifacts(directory)


def test_reader_rejects_valid_but_cross_file_selected_integer_mismatch(tmp_path: Path) -> None:
    """单文件内部合法的 selected integer 仍必须与同一步 CSV 完全一致。"""
    directory = _published_fixture(tmp_path)
    path = directory / "selected_step_trace.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    bits = payload["raw_control"]["fractional_bits"]
    payload["raw_control"]["residue"] = ["1"]
    payload["raw_control"]["centered"] = ["1"]
    payload["decoded_raw_control"] = [1 / (1 << bits)]
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _refresh_manifest_hash(directory, path.name)

    with pytest.raises(ValueError, match="跨文件|trajectory"):
        load_verified_evidence_artifacts(directory)


@pytest.mark.parametrize("member_kind", ["nested_raw_share", "empty_directory"])
def test_reader_rejects_undeclared_directory_members(
    tmp_path: Path,
    member_kind: str,
) -> None:
    """sanitized 根目录闭包拒绝嵌套 raw-share 文件和空目录。"""
    directory = _published_fixture(tmp_path)
    injected = directory / ("private" if member_kind == "nested_raw_share" else "empty")
    injected.mkdir()
    if member_kind == "nested_raw_share":
        (injected / "combined_share_step.json").write_text(
            '{"input_p1":[1],"input_p2":[2]}\n',
            encoding="utf-8",
            newline="\n",
        )

    with pytest.raises(ValueError, match="未声明|成员|目录"):
        load_verified_evidence_artifacts(directory)


def test_reader_rejects_undeclared_symlink_member(tmp_path: Path) -> None:
    """sanitized 根目录闭包拒绝链接或 reparse point 成员。"""
    directory = _published_fixture(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8", newline="\n")
    link = directory / "linked.json"
    try:
        link.symlink_to(outside)
    except OSError as error:
        pytest.skip(f"当前平台不允许创建测试 symlink：{error}")

    with pytest.raises(ValueError, match="未声明|链接|成员"):
        load_verified_evidence_artifacts(directory)
