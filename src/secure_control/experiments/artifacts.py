"""领域无关的 schema v1 CSV/JSON 序列化与无覆盖目录发布。"""

from __future__ import annotations

import csv
import json
import os
import re
import secrets
import shutil
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np

from secure_control.simulation import ChannelMetadata, ScenarioMetadata, SimulationResult

SCHEMA_VERSION = 1
_SIGNAL_FIELDS = (
    "reference",
    "output_ideal",
    "output_secure",
    "control_ideal",
    "control_secure",
    "control_error",
    "output_error",
)
_RUN_ID_PATTERN = re.compile(r"\A\d{8}T\d{12}Z-[0-9a-f]{12}\Z")


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    """将通用字段/通道 index 映射到稳定 CSV 列名与场景提供的单位。"""

    field: str
    channel_index: int | None
    column_name: str
    channel_name: str | None
    unit: str


@dataclass(frozen=True, slots=True)
class RunArtifacts:
    """一次已原子发布的运行 ID 和三个正式产物路径。"""

    run_id: str
    run_dir: Path
    trajectory_path: Path
    metadata_path: Path
    config_path: Path


@dataclass(frozen=True, slots=True)
class ExperimentRecord:
    """读回并复验后的八字段结果、通道、有效配置与公开 provenance。"""

    run_id: str
    result: SimulationResult
    metadata: ScenarioMetadata
    effective_config: dict[str, Any]
    provenance: dict[str, Any]


def _new_run_id() -> str:
    """UTC 微秒时间只用于排序，随机 nonce 保证重跑获得独立身份。"""
    now = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{now}-{secrets.token_hex(6)}"


def _columns(metadata: ScenarioMetadata) -> tuple[ColumnSpec, ...]:
    """即使 SISO 也使用 [0]，从而避免 scalar/vector 产生两套 schema。"""
    columns = [ColumnSpec("time", None, "time", None, "seconds")]
    channel_groups = {
        "reference": metadata.reference,
        "output_ideal": metadata.output,
        "output_secure": metadata.output,
        "control_ideal": metadata.control,
        "control_secure": metadata.control,
        "control_error": metadata.control,
        "output_error": metadata.output,
    }
    for field in _SIGNAL_FIELDS:
        channels = channel_groups[field]
        for index, (name, unit) in enumerate(zip(channels.names, channels.units)):
            columns.append(ColumnSpec(field, index, f"{field}[{index}]", name, unit))
    return tuple(columns)


def _binary64(name: str, values: np.ndarray) -> np.ndarray:
    """v1 只存 binary64；较高精度或大整数若会失真，拒绝而非静默缩窄。"""
    original = np.asarray(values)
    if original.dtype.kind not in "iuf" or not np.isfinite(original).all():
        raise ValueError(f"{name} 必须是有限实数。")
    if original.dtype.kind in "iu" and any(abs(int(item)) > 1 << 53 for item in original.flat):
        raise ValueError(f"{name} 超出无损 binary64 整数范围。")
    narrowed = original.astype(np.float64)
    if not np.array_equal(original, narrowed):
        raise ValueError(f"{name} 不能无损写入 schema v1 binary64。")
    return narrowed


def _validated_arrays(
    result: SimulationResult, metadata: ScenarioMetadata
) -> tuple[tuple[ColumnSpec, ...], dict[str, np.ndarray]]:
    """在创建 staging 前拒绝 shape、精度和通用误差定义不一致。"""
    if not isinstance(result, SimulationResult) or not isinstance(metadata, ScenarioMetadata):
        raise TypeError("result/metadata 必须使用通用 simulation 契约。")
    expected = {
        "reference": len(metadata.reference.names),
        "output_ideal": len(metadata.output.names),
        "output_secure": len(metadata.output.names),
        "control_ideal": len(metadata.control.names),
        "control_secure": len(metadata.control.names),
        "control_error": len(metadata.control.names),
        "output_error": len(metadata.output.names),
    }
    arrays = {"time": _binary64("time", result.time)}
    for field in _SIGNAL_FIELDS:
        value = getattr(result, field)
        if value.shape != (result.time.size, expected[field]):
            raise ValueError(f"{field} 与 scenario channel metadata 的 shape 不一致。")
        arrays[field] = _binary64(field, value)
    if not np.array_equal(
        arrays["control_error"], arrays["control_ideal"] - arrays["control_secure"]
    ) or not np.array_equal(
        arrays["output_error"], arrays["output_ideal"] - arrays["output_secure"]
    ):
        raise ValueError("八字段 error 必须等于逐通道 ideal-minus-secure。")
    return _columns(metadata), arrays


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    """不允许 JSON 的 NaN/Inf 扩展进入正式 metadata/config。"""
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def _write_bytes(path: Path, content: bytes) -> None:
    """exclusive 创建、flush 和 fsync，降低崩溃留下看似完整文件的风险。"""
    with path.open("xb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def _write_csv(path: Path, columns: tuple[ColumnSpec, ...], arrays: dict[str, np.ndarray]) -> None:
    """每个 binary64 值用 .17g 写入，可逐值读回而不修改数值内容。"""
    count = arrays["time"].size
    with path.open("x", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow([column.column_name for column in columns])
        for step in range(count):
            writer.writerow(
                [
                    format(
                        float(
                            arrays["time"][step]
                            if column.field == "time"
                            else arrays[column.field][step, column.channel_index]
                        ),
                        ".17g",
                    )
                    for column in columns
                ]
            )
        target.flush()
        os.fsync(target.fileno())


def _digest(path: Path) -> str:
    """以文件原始 bytes 的 SHA-256 关联 manifest 与实际发布产物。"""
    return sha256(path.read_bytes()).hexdigest()


def _owned_stage(stage: Path, root: Path, identity: int) -> bool:
    """仅允许清理由本次 mkdir 创建、且仍是该 root 直属非 symlink 目录的 staging。"""
    try:
        return (
            stage.resolve().parent == root.resolve()
            and stage.name.startswith(".incomplete-")
            and not stage.is_symlink()
            and stage.stat(follow_symlinks=False).st_ino == identity
        )
    except OSError:
        return False


def write_artifacts(
    result: SimulationResult,
    metadata: ScenarioMetadata,
    effective_config: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    output_root: str | Path,
) -> RunArtifacts:
    """用独占 staging claim 保存三个文件，复验后同盘 rename 为唯一成功目录。

    失败只清理本调用拥有的 staging；崩溃残留 `.incomplete-*` 不会被 reader
    当成成功运行，也不会在下次运行被自动删除或覆盖。
    """
    columns, arrays = _validated_arrays(result, metadata)
    if not isinstance(effective_config, Mapping) or not isinstance(provenance, Mapping):
        raise TypeError("effective_config/provenance 必须是 JSON-safe 映射。")
    scenario = effective_config.get("scenario")
    if (
        not isinstance(scenario, Mapping)
        or scenario.get("name") != metadata.name
        or not isinstance(scenario.get("version"), str)
        or not scenario["version"]
    ):
        raise ValueError("有效配置的 scenario name/version 与 channel metadata 不一致。")
    if (
        provenance.get("scenario_name") != metadata.name
        or provenance.get("scenario_version") != scenario["version"]
        or type(provenance.get("schema_version")) is not int
        or provenance["schema_version"] != SCHEMA_VERSION
    ):
        raise ValueError("provenance 的 scenario/schema version 与本次产物不一致。")
    config_payload = _json_bytes(effective_config)
    provenance_payload = json.loads(_json_bytes(provenance))
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    run_id = _new_run_id()
    if not _RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("run_id 格式不符合 schema v1。")
    stage = root / f".incomplete-{run_id}"
    final = root / run_id
    if os.path.lexists(final):
        raise FileExistsError(f"运行 ID 已存在：{run_id}")
    stage.mkdir(exist_ok=False)
    stage_identity = stage.stat(follow_symlinks=False).st_ino
    try:
        trajectory_path = stage / "trajectory.csv"
        config_path = stage / "config.json"
        metadata_path = stage / "metadata.json"
        _write_csv(trajectory_path, columns, arrays)
        _write_bytes(config_path, config_payload)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "success": True,
            "sample_count": int(result.time.size),
            "scenario": {"name": metadata.name, "version": scenario["version"]},
            "channels": {
                "reference": asdict(metadata.reference),
                "output": asdict(metadata.output),
                "control": asdict(metadata.control),
            },
            "channel_counts": {
                "reference": len(metadata.reference.names),
                "output": len(metadata.output.names),
                "control": len(metadata.control.names),
            },
            "columns": [asdict(column) for column in columns],
            "files_sha256": {
                "trajectory.csv": _digest(trajectory_path),
                "config.json": _digest(config_path),
            },
            "provenance": provenance_payload,
        }
        _write_bytes(metadata_path, _json_bytes(manifest))
        # 发布前按正式 reader 规则复验三个文件；不创建第二套 scenario/session。
        _read_record(stage, allow_staging=True)
        if os.path.lexists(final):
            raise FileExistsError(f"运行 ID 已存在：{run_id}")
        os.rename(stage, final)
    except Exception:
        if _owned_stage(stage, root, stage_identity):
            shutil.rmtree(stage)
        raise
    return RunArtifacts(
        run_id,
        final,
        final / "trajectory.csv",
        final / "metadata.json",
        final / "config.json",
    )


def _read_json(path: Path) -> dict[str, Any]:
    """拒绝非对象 JSON 与非标准 NaN/Infinity 常量。"""

    def reject_constant(value: str) -> None:
        """JSON 产物只接受标准、有限数值。"""
        raise ValueError(f"非标准 JSON 数值：{value}")

    loaded = json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_constant)
    if not isinstance(loaded, dict):
        raise TypeError(f"{path.name} 必须是 JSON 对象。")
    return loaded


def _parse_channels(value: Any, name: str) -> ChannelMetadata:
    """从 JSON 恢复 names/units，拒绝空、错型或不等长数组。"""
    if not isinstance(value, dict):
        raise TypeError(f"{name} channel metadata 必须是对象。")
    names, units = value.get("names"), value.get("units")
    if (
        not isinstance(names, list)
        or not isinstance(units, list)
        or any(not isinstance(item, str) for item in (*names, *units))
    ):
        raise ValueError(f"{name} channel names/units 必须是字符串数组。")
    return ChannelMetadata(tuple(names), tuple(units))


def _read_record(run_dir: Path, *, allow_staging: bool) -> ExperimentRecord:
    """复验发布状态、版本、列映射、hash 和八字段 arithmetic/shape。"""
    if (
        not run_dir.is_dir()
        or run_dir.is_symlink()
        or (run_dir.name.startswith(".incomplete-") and not allow_staging)
    ):
        raise ValueError("只允许读取已发布的成功运行目录。")
    manifest = _read_json(run_dir / "metadata.json")
    run_id = manifest.get("run_id")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != SCHEMA_VERSION
        or manifest.get("success") is not True
        or not isinstance(run_id, str)
        or not _RUN_ID_PATTERN.fullmatch(run_id)
        or run_dir.name != (f".incomplete-{run_id}" if allow_staging else run_id)
    ):
        raise ValueError("运行状态、ID 或 schema version 无效。")
    scenario = manifest.get("scenario")
    channels = manifest.get("channels")
    if (
        not isinstance(scenario, dict)
        or not isinstance(scenario.get("name"), str)
        or not isinstance(scenario.get("version"), str)
        or not isinstance(channels, dict)
    ):
        raise TypeError("scenario/channel metadata 缺失或无效。")
    metadata = ScenarioMetadata(
        scenario["name"],
        _parse_channels(channels.get("reference"), "reference"),
        _parse_channels(channels.get("output"), "output"),
        _parse_channels(channels.get("control"), "control"),
    )
    if manifest.get("channel_counts") != {
        "reference": len(metadata.reference.names),
        "output": len(metadata.output.names),
        "control": len(metadata.control.names),
    }:
        raise ValueError("channel_counts 与 scenario channel metadata 不一致。")
    columns = _columns(metadata)
    if manifest.get("columns") != [asdict(column) for column in columns]:
        raise ValueError("CSV column schema 与 channel metadata 不一致。")
    files = manifest.get("files_sha256")
    trajectory_path = run_dir / "trajectory.csv"
    config_path = run_dir / "config.json"
    if not isinstance(files, dict) or files != {
        "trajectory.csv": _digest(trajectory_path),
        "config.json": _digest(config_path),
    }:
        raise ValueError("CSV/config 文件摘要与 manifest 不一致。")
    effective_config = _read_json(config_path)
    if effective_config.get("scenario") != scenario:
        raise ValueError("有效配置与 manifest 的 scenario name/version 不一致。")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        raise TypeError("provenance 必须是对象。")
    if (
        provenance.get("scenario_name") != metadata.name
        or provenance.get("scenario_version") != scenario["version"]
        or type(provenance.get("schema_version")) is not int
        or provenance["schema_version"] != SCHEMA_VERSION
    ):
        raise ValueError("provenance 与产物 scenario/schema version 不一致。")

    rows: list[list[float]] = []
    with trajectory_path.open("r", encoding="utf-8", newline="") as source:
        reader = csv.reader(source)
        if next(reader, None) != [column.column_name for column in columns]:
            raise ValueError("CSV header 顺序或列名与 schema 不一致。")
        for row in reader:
            if len(row) != len(columns):
                raise ValueError("CSV row 列数与 schema 不一致。")
            try:
                numeric = [float(item) for item in row]
            except ValueError as error:
                raise ValueError("CSV 含非实数值。") from error
            if not np.isfinite(numeric).all():
                raise ValueError("CSV 含 NaN 或无穷大。")
            rows.append(numeric)
    if type(manifest.get("sample_count")) is not int or manifest["sample_count"] != len(rows):
        raise ValueError("CSV 行数与 sample_count 不一致。")
    data = np.asarray(rows, dtype=np.float64)
    field_arrays = {
        field: data[:, [index for index, column in enumerate(columns) if column.field == field]]
        for field in _SIGNAL_FIELDS
    }
    result = SimulationResult(time=data[:, 0], **field_arrays)
    _validated_arrays(result, metadata)
    return ExperimentRecord(run_id, result, metadata, effective_config, provenance)


def load_artifacts(run_dir: str | Path) -> ExperimentRecord:
    """只读取完整、success=true 且符合 schema v1 的正式运行目录。"""
    return _read_record(Path(run_dir), allow_staging=False)
