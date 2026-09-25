"""从四个已验证 LAN run 只读生成与复核四水箱 Fig. 4 范数图。"""

from __future__ import annotations

import argparse
import json
import os
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

import matplotlib
import numpy as np

from secure_control.execution.lan_config import _fields, _load_yaml

from .artifacts import ExperimentRecord, load_artifacts
from .plotting import verify_control_triptych

matplotlib.use("Agg")
from matplotlib import pyplot as plt

PRECISIONS = (32, 40, 48, 56)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_definition(path: str | Path) -> dict[str, Any]:
    """固定 Fig. 4 的项目选择、四个来源摘要及论文参数。"""
    source = Path(path).resolve()
    definition = _load_yaml(source)
    fixed = {
        "schema_version": 1, "scenario": "quadruple_tank",
        "claim_level": "paper-parameter-derived-linear-simulation",
        "fractional_bits": list(PRECISIONS), "parameter_headroom_bits": 8,
        "runtime_headroom_bits": 14, "security_parameter": 80,
        "measurement_absolute_bounds_v": [256, 256], "sample_count": 51,
        "sample_period_seconds": 0.5, "epsilon": 2**-10,
        "error_metric": "control_error_l2_v",
    }
    _fields(definition, set(fixed) | {"plant_sha256", "observer_sha256", "prime_sha256"})
    if any(type(definition[key]) is not type(value) or definition[key] != value
           for key, value in fixed.items()):
        raise ValueError("Fig.4 定义参数漂移。")
    for key in ("plant_sha256", "observer_sha256", "prime_sha256"):
        value = definition[key]
        if not isinstance(value, str) or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError("Fig.4 来源摘要无效。")
    for key, filename in (("plant_sha256", "quadruple_tank_plant.yaml"),
                          ("observer_sha256", "quadruple_tank_observer.yaml"),
                          ("prime_sha256", "shared_prime_256_pocklington.yaml")):
        if _digest(source.parent / filename) != definition[key]:
            raise ValueError("Fig.4 canonical 来源已漂移。")
    return definition


def _validate_record(record: ExperimentRecord, ell: int,
                     definition: dict[str, Any]) -> dict[str, Any]:
    """核对场景、真实会话、数值口径和每步资源；范数从 signed CSV 重算。"""
    config, provenance, result = record.effective_config, record.provenance, record.result
    if (record.metadata.name != "quadruple_tank"
            or config.get("scenario") != {"name": "quadruple_tank", "version": "1"}
            or config.get("fractional_bits") != ell
            or config.get("paper_parameter_bits") != ell + 8
            or config.get("runtime_payload_bits") != ell + 14
            or config.get("security_parameter") != 80
            or config.get("sample_count") != 51
            or config.get("plant_source_sha256") != definition["plant_sha256"]
            or config.get("observer_source_sha256") != definition["observer_sha256"]
            or config.get("prime_source_sha256") != definition["prime_sha256"]
            or config.get("range", {}).get("measurement_absolute_bounds_v") != [256, 256]
            or config.get("reference_used") is not False
            or config.get("raw_equals_applied") is not True
            or provenance.get("backend") != "lan_continuous"
            or provenance.get("claim_level") != definition["claim_level"]
            or provenance.get("secure_material_randomness") != "secure_random"
            or provenance.get("configured_seeds") != {}
            or provenance.get("prime_verification", {}).get("status") != "verified"
            or provenance.get("prime_verification", {}).get("modulus") != config.get("q")
            or provenance.get("scale_ledger", {}).get("state_truncation_bits") != ell
            or provenance.get("kappa") != config.get("q", 0).bit_length() - 82):
        raise ValueError("Fig.4 run 场景、来源或数值声明不符。")
    if (result.time.shape != (51,)
            or not np.allclose(result.time, np.arange(51) * 0.5, rtol=0, atol=1e-15)
            or any(getattr(result, name).shape != (51, 2) for name in
                   ("reference", "output_ideal", "output_secure", "control_ideal",
                    "control_secure", "control_error"))
            or not np.array_equal(result.reference, np.zeros((51, 2)))
            or not np.array_equal(result.control_error,
                                  result.control_ideal - result.control_secure)
            or record.metadata.control.units != ("V_deviation", "V_deviation")):
        raise ValueError("Fig.4 时间、双通道或 signed error 不符。")
    confirmed = provenance.get("confirmed_steps")
    if (provenance.get("resource_counts") != {"products_consumed": 1836,
                                              "truncations_consumed": 204}
            or not isinstance(confirmed, list) or len(confirmed) != 51
            or any(item != {"step": step, "status": "double_committed",
                            "products": 36, "truncations": 4}
                   for step, item in enumerate(confirmed))):
        raise ValueError("Fig.4 缺少 51 步双提交或真实资源证据。")
    error = np.linalg.norm(result.control_error, axis=1)
    resolution = float(np.max(np.spacing(np.maximum(np.abs(result.control_ideal),
                                                  np.abs(result.control_secure)))))
    maximum = float(np.max(error))
    return {"ell": ell, "run_id": record.run_id,
            "session_id": provenance["session_id"],
            "max_error_l2_v": maximum, "below_epsilon": maximum < definition["epsilon"],
            "zero_samples": int(np.count_nonzero(error == 0)),
            "binary64_ulp_upper_v": resolution,
            "at_or_below_numeric_resolution": bool(np.any((error > 0) &
                                                             (error <= resolution)) or
                                                   np.all(error == 0))}


def _render(records: list[ExperimentRecord], definition: dict[str, Any],
            target: Path) -> list[dict[str, Any]]:
    summaries = [_validate_record(record, ell, definition)
                 for ell, record in zip(PRECISIONS, records, strict=True)]
    figure, axis = plt.subplots(figsize=(9, 5))
    for record, summary in zip(records, summaries, strict=True):
        error = np.linalg.norm(record.result.control_error, axis=1)
        axis.plot(record.result.time, error, marker=".", markersize=3,
                  label=f"ell={summary['ell']} (max={summary['max_error_l2_v']:.3g} V)")
    axis.axhline(definition["epsilon"], color="black", linestyle="--",
                 label="epsilon=2^-10")
    axis.set_yscale("symlog", linthresh=1e-14)
    axis.set_xlabel("Time (s); 51 pre-update samples at Ts=0.5 s")
    axis.set_ylabel("L2 norm of signed u - uhat (V)")
    axis.set_title("Paper-parameter-derived linear tank simulation; Fig. 4 comparison")
    axis.legend()
    axis.grid(True, which="both", alpha=0.3)
    figure.text(0.01, 0.01,
                "Zero remains zero; binary64 resolution may hide ell=48/56 differences.",
                fontsize=8)
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    figure.savefig(target, dpi=160)
    plt.close(figure)
    return summaries


def _records(paths: list[Path], definition: dict[str, Any]) -> tuple[list[ExperimentRecord],
                                                                        list[dict[str, Any]]]:
    if len(paths) != 4:
        raise ValueError("Fig.4 必须给出四个独立 run。")
    records = [load_artifacts(path) for path in paths]
    for path, record in zip(paths, records, strict=True):
        verify_control_triptych(record, path)
    summaries = [_validate_record(record, ell, definition)
                 for ell, record in zip(PRECISIONS, records, strict=True)]
    if (len({record.run_id for record in records}) != 4
            or len({summary["session_id"] for summary in summaries}) != 4
            or len({record.effective_config["q"] for record in records}) != 1
            or len({record.provenance.get("transport") for record in records}) != 1):
        raise ValueError("Fig.4 的 run/session/q/transport 不独立或不一致。")
    return records, summaries


def build_saved_fig4(definition_path: str | Path, run_dirs: list[str | Path],
                     output_root: str | Path) -> Path:
    """只读四个成功 run，汇总图与清单同批发布，不触发协议运行。"""
    definition = load_definition(definition_path)
    paths = [Path(path).resolve() for path in run_dirs]
    records, summaries = _records(paths, definition)
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise FileExistsError("Fig.4 输出目录必须为空。")
    with TemporaryDirectory(dir=root, prefix=".incomplete-") as temporary:
        figure = Path(temporary) / "fig4.png"
        rendered = _render(records, definition, figure)
        if rendered != summaries:
            raise ValueError("Fig.4 两次计算结果不一致。")
        manifest = {
            "definition": definition,
            "definition_path": Path(os.path.relpath(Path(definition_path).resolve(), root)).as_posix(),
            "definition_sha256": _digest(Path(definition_path)),
            "runs": [
                {"ell": ell, "status": "success", "run_id": record.run_id,
                 "relative_run_dir": Path(os.path.relpath(path, root)).as_posix(),
                 "metadata_sha256": _digest(path / "metadata.json"),
                 "config_sha256": _digest(path / "config.json")}
                for ell, path, record in zip(PRECISIONS, paths, records, strict=True)
            ],
            "summaries": summaries, "figure_sha256": _digest(figure),
        }
        (Path(temporary) / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(figure, root / "fig4.png")
        os.replace(Path(temporary) / "manifest.json", root / "manifest.json")
    try:
        verify_saved_fig4(root)
    except Exception:
        (root / "manifest.json").unlink(missing_ok=True)
        (root / "fig4.png").unlink(missing_ok=True)
        raise
    return root


def verify_saved_fig4(output_root: str | Path) -> dict[str, Any]:
    """验证来源、四个 run、范数摘要和已发布图的摘要；不重新连接 LAN。"""
    root = Path(output_root).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {
        "definition", "definition_path", "definition_sha256", "runs", "summaries",
        "figure_sha256"
    }:
        raise ValueError("Fig.4 清单字段无效。")
    definition = manifest["definition"]
    if (not isinstance(manifest["definition_path"], str)
            or _digest(root.joinpath(*PurePosixPath(manifest["definition_path"]).parts).resolve())
            != manifest["definition_sha256"]
            or load_definition(root.joinpath(*PurePosixPath(manifest["definition_path"]).parts)
                               .resolve()) != definition):
        raise ValueError("Fig.4 定义来源摘要不符。")
    if (not isinstance(definition, dict) or tuple(definition.get("fractional_bits", ()))
            != PRECISIONS or not isinstance(manifest["runs"], list)
            or len(manifest["runs"]) != 4):
        raise ValueError("Fig.4 定义或精度不完整。")
    paths = []
    for ell, entry in zip(PRECISIONS, manifest["runs"], strict=True):
        if (not isinstance(entry, dict) or entry.get("ell") != ell
                or entry.get("status") != "success"
                or not isinstance(entry.get("relative_run_dir"), str)):
            raise ValueError("Fig.4 run 精度或状态不符。")
        path = root.joinpath(*PurePosixPath(entry["relative_run_dir"]).parts).resolve()
        if (_digest(path / "metadata.json") != entry.get("metadata_sha256")
                or _digest(path / "config.json") != entry.get("config_sha256")
                or path.name != entry.get("run_id")):
            raise ValueError("Fig.4 run 来源摘要不符。")
        paths.append(path)
    records, summaries = _records(paths, definition)
    if summaries != manifest["summaries"]:
        raise ValueError("Fig.4 范数或数值分辨率摘要不符。")
    with TemporaryDirectory() as temporary:
        recomputed = _render(records, definition, Path(temporary) / "fig4.png")
        if recomputed != summaries:
            raise ValueError("Fig.4 重新绘图数据不符。")
    if _digest(root / "fig4.png") != manifest["figure_sha256"]:
        raise ValueError("Fig.4 已发布图摘要不符。")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify or render four saved tank LAN runs")
    parser.add_argument("--definition", default="configs/quadruple_tank_fig4.yaml")
    parser.add_argument("--run-dirs", nargs=4)
    parser.add_argument("--output-root", default="results/quadruple_tank_fig4")
    parser.add_argument("--verify-dir")
    args = parser.parse_args()
    if args.verify_dir:
        result = verify_saved_fig4(args.verify_dir)
    else:
        if args.run_dirs is None:
            parser.error("生成 Fig.4 需要四个 --run-dirs。")
        root = build_saved_fig4(args.definition, args.run_dirs, args.output_root)
        result = verify_saved_fig4(root)
    print(json.dumps(result["summaries"], ensure_ascii=False))


if __name__ == "__main__":
    main()
