"""schema v1 标量/向量读回、无覆盖发布与损坏产物拒绝测试。"""

from __future__ import annotations

import csv
import json
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest

from secure_control.experiments import artifacts
from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult


def _record(channels: int) -> tuple[SimulationResult, ScenarioMetadata]:
    """制造确切 binary64 值及可逐通道重算的 signed error，不依赖 HVAC。"""
    reference_channel = ChannelMetadata(
        tuple(f"reference_{index}" for index in range(channels)), ("unit_r",) * channels
    )
    output_channel = ChannelMetadata(
        tuple(f"output_{index}" for index in range(channels)), ("unit_y",) * channels
    )
    control_channel = ChannelMetadata(
        tuple(f"control_{index}" for index in range(channels)), ("unit_u",) * channels
    )
    metadata = ScenarioMetadata("toy", reference_channel, output_channel, control_channel)
    reference = np.tile(np.arange(channels, dtype=float) + 0.25, (3, 1))
    ideal_output = reference + np.nextafter(0.1, 1.0)
    secure_output = reference - 0.2
    ideal_control = reference * 0.5
    secure_control = reference * 0.25
    result = SimulationResult(
        time=np.array([0.0, 0.125, 1.0]),
        reference=reference,
        output_ideal=ideal_output,
        output_secure=secure_output,
        control_ideal=ideal_control,
        control_secure=secure_control,
        control_error=ideal_control - secure_control,
        output_error=ideal_output - secure_output,
    )
    return result, metadata


def _write(tmp_path: Path, channels: int = 1) -> artifacts.RunArtifacts:
    """把 run 写进含空格/Unicode 的临时路径，验证 Windows 路径兼容。"""
    result, metadata = _record(channels)
    return artifacts.write_artifacts(
        result,
        metadata,
        {"scenario": {"name": "toy", "version": "1"}, "input": {"value": 1.25}},
        {
            "scenario_name": "toy",
            "scenario_version": "1",
            "schema_version": 1,
            "configured_seeds": {"toy_seed": 4},
        },
        output_root=tmp_path / "带空格 输出",
    )


@pytest.mark.parametrize("channels", [1, 3])
def test_scalar_and_vector_schema_round_trip_binary64_and_metadata(
    tmp_path: Path, channels: int
) -> None:
    """SISO 与向量同用 field[index]、.17g 和通道映射，读回逐值相同。"""
    expected, expected_metadata = _record(channels)
    published = _write(tmp_path, channels)
    loaded = artifacts.load_artifacts(published.run_dir)

    assert published.run_dir.is_dir()
    assert loaded.run_id == published.run_id
    assert loaded.metadata == expected_metadata
    assert loaded.effective_config["input"]["value"] == 1.25
    assert loaded.provenance["configured_seeds"] == {"toy_seed": 4}
    for field in expected.__dataclass_fields__:
        np.testing.assert_array_equal(getattr(loaded.result, field), getattr(expected, field))
    with published.trajectory_path.open(encoding="utf-8", newline="") as source:
        header = next(csv.reader(source))
    assert header == ["time"] + [
        f"{field}[{index}]"
        for field in (
            "reference",
            "output_ideal",
            "output_secure",
            "control_ideal",
            "control_secure",
            "control_error",
            "output_error",
        )
        for index in range(channels)
    ]
    manifest = json.loads(published.metadata_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["success"] is True
    assert manifest["sample_count"] == 3
    assert manifest["channel_counts"] == {
        "reference": channels,
        "output": channels,
        "control": channels,
    }
    assert manifest["columns"][1]["channel_name"] == "reference_0"
    assert manifest["columns"][-1]["unit"] == "unit_y"
    assert manifest["columns"][-channels - 1]["unit"] == "unit_u"
    assert not list(published.run_dir.parent.glob(".incomplete-*"))


def test_existing_run_id_fails_without_overwrite_or_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """相同 ID 第二次必须拒绝，首个成功目录与两个文件摘要保持原样。"""
    run_id = "20260915T010203123456Z-abcdef123456"
    monkeypatch.setattr(artifacts, "_new_run_id", lambda: run_id)
    first = _write(tmp_path)
    csv_hash = sha256(first.trajectory_path.read_bytes()).hexdigest()
    metadata_hash = sha256(first.metadata_path.read_bytes()).hexdigest()

    with pytest.raises(FileExistsError, match="运行 ID 已存在"):
        _write(tmp_path)

    assert sha256(first.trajectory_path.read_bytes()).hexdigest() == csv_hash
    assert sha256(first.metadata_path.read_bytes()).hexdigest() == metadata_hash
    assert not list(first.run_dir.parent.glob(".incomplete-*"))


def test_writer_failure_cleans_only_owned_stage_and_no_success_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """partial CSV 写入异常后仅移除本调用 claim，不删除同 root 下用户目录。"""
    root = tmp_path / "带空格 输出"
    root.mkdir()
    user_dir = root / "user-owned"
    user_dir.mkdir()
    (user_dir / "keep.txt").write_text("保留", encoding="utf-8")

    def fail_csv(path: Path, columns: object, arrays: object) -> None:
        """模拟 staging 内文件写至一半后发生 I/O 错误。"""
        path.write_text("partial", encoding="utf-8")
        raise OSError("simulated write error")

    monkeypatch.setattr(artifacts, "_write_csv", fail_csv)
    with pytest.raises(OSError, match="simulated write error"):
        _write(tmp_path)
    assert (user_dir / "keep.txt").read_text(encoding="utf-8") == "保留"
    assert sorted(path.name for path in root.iterdir()) == ["user-owned"]


def test_reader_rejects_incomplete_corrupt_and_unknown_schema(tmp_path: Path) -> None:
    """reader 不接受 staging、缺失文件、hash 被破坏或未知 schema 版本。"""
    published = _write(tmp_path)
    staging = published.run_dir.parent / f".incomplete-{published.run_id}"
    staging.mkdir()
    with pytest.raises(ValueError, match="已发布"):
        artifacts.load_artifacts(staging)
    published.trajectory_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="摘要"):
        artifacts.load_artifacts(published.run_dir)
    staging.rmdir()

    other = _write(tmp_path)
    manifest = json.loads(other.metadata_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = 2
    other.metadata_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="schema version"):
        artifacts.load_artifacts(other.run_dir)

    missing = _write(tmp_path)
    missing.config_path.unlink()
    with pytest.raises(FileNotFoundError):
        artifacts.load_artifacts(missing.run_dir)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [("duplicate_header", "CSV header"), ("extra_column", "CSV row 列数"), ("nonfinite", "NaN")],
)
def test_reader_rejects_malformed_csv_even_when_manifest_hash_is_updated(
    tmp_path: Path, replacement: str, message: str
) -> None:
    """若文件 hash 被更新，reader 仍逐项检查 header、行列数和有限值。"""
    published = _write(tmp_path)
    lines = published.trajectory_path.read_text(encoding="utf-8").splitlines()
    if replacement == "duplicate_header":
        lines[0] = lines[0].replace("reference[0]", "time", 1)
    elif replacement == "extra_column":
        lines[1] += ",17"
    else:
        # 第一行的 time 为 0；直接替换其第一信号值以锁定有限性校验。
        parts = lines[1].split(",")
        parts[1] = "NaN"
        lines[1] = ",".join(parts)
    published.trajectory_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = json.loads(published.metadata_path.read_text(encoding="utf-8"))
    manifest["files_sha256"]["trajectory.csv"] = sha256(
        published.trajectory_path.read_bytes()
    ).hexdigest()
    published.metadata_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        artifacts.load_artifacts(published.run_dir)


def test_reader_rejects_empty_scenario_version_even_when_artifacts_agree(tmp_path: Path) -> None:
    """即使三个版本字段一致且配置摘要已更新，空版本也不是有效成功产物。"""
    published = _write(tmp_path)
    config = json.loads(published.config_path.read_text(encoding="utf-8"))
    config["scenario"]["version"] = ""
    published.config_path.write_text(json.dumps(config), encoding="utf-8")

    manifest = json.loads(published.metadata_path.read_text(encoding="utf-8"))
    manifest["scenario"]["version"] = ""
    manifest["provenance"]["scenario_version"] = ""
    manifest["files_sha256"]["config.json"] = sha256(published.config_path.read_bytes()).hexdigest()
    published.metadata_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="scenario version"):
        artifacts.load_artifacts(published.run_dir)


def test_writer_rejects_channel_or_error_mismatch_before_creating_root(tmp_path: Path) -> None:
    """错 shape 或错误公式不能生成一个看似完整的成功产物。"""
    result, metadata = _record(1)
    root = tmp_path / "not-created"
    wrong_channel = ScenarioMetadata(
        "toy", ChannelMetadata(("r0", "r1"), ("unit", "unit")), metadata.output, metadata.control
    )
    with pytest.raises(ValueError, match="shape"):
        artifacts.write_artifacts(
            result,
            wrong_channel,
            {"scenario": {"name": "toy", "version": "1"}},
            {"scenario_name": "toy", "scenario_version": "1", "schema_version": 1},
            output_root=root,
        )
    assert not root.exists()

    broken = SimulationResult(
        time=result.time,
        reference=result.reference,
        output_ideal=result.output_ideal,
        output_secure=result.output_secure,
        control_ideal=result.control_ideal,
        control_secure=result.control_secure,
        control_error=np.zeros_like(result.control_error),
        output_error=result.output_error,
    )
    with pytest.raises(ValueError, match="ideal-minus-secure"):
        artifacts.write_artifacts(
            broken,
            metadata,
            {"scenario": {"name": "toy", "version": "1"}},
            {"scenario_name": "toy", "scenario_version": "1", "schema_version": 1},
            output_root=root,
        )
    assert not root.exists()


def test_writer_rejects_unrepresentable_integer_precision(tmp_path: Path) -> None:
    """binary64 v1 不静默把大整数时间索引写成相邻值。"""
    base, metadata = _record(1)
    huge = SimulationResult(
        time=np.array([0, 1, (1 << 53) + 1], dtype=np.int64),
        reference=base.reference,
        output_ideal=base.output_ideal,
        output_secure=base.output_secure,
        control_ideal=base.control_ideal,
        control_secure=base.control_secure,
        control_error=base.control_error,
        output_error=base.output_error,
    )
    with pytest.raises(ValueError, match="binary64"):
        artifacts.write_artifacts(
            huge,
            metadata,
            {"scenario": {"name": "toy", "version": "1"}},
            {"scenario_name": "toy", "scenario_version": "1", "schema_version": 1},
            output_root=tmp_path / "not-created",
        )


def test_writer_rejects_inconsistent_provenance_before_staging(tmp_path: Path) -> None:
    """scenario/schema provenance 不得与正式结果的配置和通道分裂。"""
    result, metadata = _record(1)
    root = tmp_path / "not-created"
    with pytest.raises(ValueError, match="provenance"):
        artifacts.write_artifacts(
            result,
            metadata,
            {"scenario": {"name": "toy", "version": "1"}},
            {"scenario_name": "toy", "scenario_version": "2", "schema_version": 1},
            output_root=root,
        )
    assert not root.exists()
