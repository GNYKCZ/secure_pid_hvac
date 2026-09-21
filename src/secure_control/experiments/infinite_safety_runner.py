"""从已验证精度扫描生成 #38 无限时域安全证书与只读报告。"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import uuid
from dataclasses import asdict, fields, is_dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from secure_control.core import RationalValue
from secure_control.experiments.sweep import SweepRunStatus
from secure_control.experiments.sweep_artifacts import load_verified_sweep_data
from secure_control.scenarios.hvac.infinite_safety import (
    HvacInfiniteSafetyBundle,
    load_hvac_infinite_safety_bundle,
)


def publish_infinite_safety_report(
    assumptions_path: str | Path,
    sweep_dir: str | Path,
    output_root: str | Path,
) -> Path:
    """复验来源后原子发布 certificate/report/manifest，绝不重新运行扫描。"""
    bundle = load_hvac_infinite_safety_bundle(assumptions_path)
    sweep_root = Path(sweep_dir).resolve()
    sweep_manifest_hashes = _sweep_manifest_hashes(sweep_root)
    verified = load_verified_sweep_data(sweep_dir)
    verified_data = load_verified_sweep_data(sweep_dir, manifest_name="data_manifest.json")
    _validate_sweep(bundle, verified)
    _validate_sweep(bundle, verified_data)
    if (
        verified.root != sweep_root
        or verified_data.root != sweep_root
        or verified.definition != verified_data.definition
        or verified.records != verified_data.records
    ):
        raise ValueError("verified sweep 的 final/data manifest 复验结果不一致")
    if _sweep_manifest_hashes(sweep_root) != sweep_manifest_hashes:
        raise ValueError("verified sweep 的 final/data manifest 在复验期间发生变化")
    certificate = _certificate_payload(bundle, verified.root, sweep_manifest_hashes)
    digest_source = json.dumps(
        certificate, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    safety_id = (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        + "-"
        + sha256(digest_source).hexdigest()[:12]
    )
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = root / safety_id
    temporary = root / f".{safety_id}.tmp-{uuid.uuid4().hex}"
    temporary.mkdir()
    try:
        _write_json(temporary / "certificate.json", certificate)
        (temporary / "report.md").write_text(
            _markdown_report(bundle, certificate), encoding="utf-8", newline="\n"
        )
        hashes = {
            name: sha256((temporary / name).read_bytes()).hexdigest()
            for name in ("certificate.json", "report.md")
        }
        _write_json(
            temporary / "manifest.json",
            {
                "schema_version": 1,
                "complete": True,
                "safety_id": safety_id,
                "files_sha256": hashes,
            },
        )
        if _sweep_manifest_hashes(verified.root) != sweep_manifest_hashes:
            raise ValueError("verified sweep 的 final/data manifest 在发布期间发生变化")
        os.replace(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target


def _validate_sweep(bundle: HvacInfiniteSafetyBundle, verified) -> None:
    """确认 reader 复验后的扫描恰好提供四个冻结精度点和零 Trunc 路径。"""
    definition = verified.definition
    expected_ells = [profile.fractional_bits for profile in bundle.profiles]
    if definition.get("fractional_bits") != expected_ells:
        raise ValueError("verified sweep 的 fractional_bits 与 #38 不一致")
    if definition.get("integer_headroom_bits") != 28:
        raise ValueError("verified sweep 的 integer headroom 与 #38 不一致")
    if definition.get("security_parameter") != 80:
        raise ValueError("verified sweep 的 security parameter 与 #38 不一致")
    if definition.get("seeds") != [42, 43, 44] or definition.get("primary_seed") != 42:
        raise ValueError("verified sweep 的 seed profile 与 #38 不一致")
    if definition.get("max_protocol2_truncations_per_point") != 0:
        raise ValueError("verified sweep 的 Protocol 2 预算与 #38 不一致")
    if len(verified.records) != 12:
        raise ValueError("verified sweep 必须完整包含四个 ell 与三个冻结 seed")
    source_hashes = dict(bundle.source_hashes)
    if definition.get("schema_version") == 2:
        _validate_v2_sweep_source(bundle, verified, source_hashes)
    else:
        sweep_sources = definition.get("source_hashes")
        if not isinstance(sweep_sources, dict):
            raise TypeError("verified sweep 缺少 source_hashes")
        if sweep_sources.get("plant") != source_hashes["plant"]:
            raise ValueError("verified sweep 的 plant source hash 与 #38 不一致")
        if sweep_sources.get("baseline") != source_hashes["pid"]:
            raise ValueError("verified sweep 的 PID source hash 与 #38 不一致")
    profiles = {profile.fractional_bits: profile for profile in bundle.profiles}
    for record in verified.records:
        if record.status is not SweepRunStatus.SUCCESS or record.cost is None:
            raise ValueError("#38 只接受全部成功且成本完整的 verified sweep")
        if record.cost.protocol2_truncations_total != 0:
            raise ValueError("#38 冻结的整数 A/B 路径要求 Protocol 2 计数为零")
        profile = profiles.get(record.point.ell)
        if profile is None or (
            record.point.k != profile.integer_bits
            or record.point.lambda_ != profile.security_parameter
            or record.point.q != profile.fixed_point.modulus
            or record.point.kappa != profile.kappa
        ):
            raise ValueError("verified sweep 的 q/kappa/k/lambda 与 #38 证书不一致")
    observed = {record.point.ell for record in verified.records}
    if observed != set(expected_ells):
        raise ValueError("verified sweep 未完整覆盖四个 ell")
    if {record.point.seed for record in verified.records} != {42, 43, 44}:
        raise ValueError("verified sweep 未完整覆盖三个冻结 seed")


def _validate_v2_sweep_source(bundle, verified, source_hashes: dict[str, str]) -> None:
    """把 v2 resolved provenance 与 assumptions 的正式 baseline 和稳定性逐项绑定。"""
    identity = bundle.baseline_identity
    resolved_source = verified.resolved_source
    resolved_plan = verified.resolved_plan
    if identity is None:
        raise ValueError("schema v2 sweep 必须由 schema v2 assumptions 声明 baseline identity")
    if not isinstance(resolved_source, dict) or not isinstance(resolved_plan, dict):
        raise TypeError("schema v2 sweep 缺少 verified resolved source/plan")
    expected_hashes = dict(identity.source_hashes)
    if (
        resolved_source.get("identity_scheme") != identity.scheme
        or resolved_source.get("baseline_id") != identity.baseline_id
        or resolved_source.get("source_hashes") != expected_hashes
        or expected_hashes["baseline"] != source_hashes["pid"]
        or expected_hashes["scenario"] != source_hashes["plant"]
    ):
        raise ValueError("schema v2 sweep 的 baseline/source identity 与 assumptions 不一致")
    if (
        resolved_plan.get("definition_sha256") != source_hashes["sweep"]
        or resolved_plan.get("baseline_identity_scheme") != identity.scheme
        or resolved_plan.get("baseline_id") != identity.baseline_id
        or resolved_plan.get("stability_report_sha256") != bundle.stability_report_sha256
        or resolved_plan.get("stability_report") != _json_value(asdict(bundle.stability_report))
        or resolved_plan.get("points") != _definition_points(verified.definition)
        or verified.definition.get("prime_evidence_hash") != source_hashes["prime"]
    ):
        raise ValueError("schema v2 sweep 的 resolved plan 与 assumptions 不一致")


def _definition_points(definition: dict[str, Any]) -> list[dict[str, Any]]:
    """读取 canonical reader 已验证的十二点载荷，供 source plan 再绑定。"""
    points = definition.get("points")
    if not isinstance(points, list) or not all(isinstance(item, dict) for item in points):
        raise TypeError("verified sweep definition points 无效")
    return points


def _json_value(value: Any) -> Any:
    """按工件 JSON 语义规范化 tuple，避免内存表示差异导致误拒绝。"""
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _certificate_payload(
    bundle: HvacInfiniteSafetyBundle,
    sweep_root: Path,
    sweep_manifest_hashes: dict[str, str],
) -> dict[str, Any]:
    """构造不含机器绝对路径的稳定证书载荷。"""
    profiles = []
    for profile in bundle.profiles:
        evidence = profile.range_contract.closed_loop_evidence
        assert evidence is not None
        profiles.append(
            {
                "ell": profile.fractional_bits,
                "k": profile.integer_bits,
                "lambda": profile.security_parameter,
                "q": profile.fixed_point.modulus,
                "kappa": profile.kappa,
                "status": profile.invariant_report.status,
                "reason_codes": list(profile.invariant_report.reason_codes),
                "certificate_sha256": profile.invariant_report.certificate_sha256,
                "controller_fingerprint": evidence.controller_fingerprint,
                "composition_sha256": evidence.composition_sha256,
                "composition": _exact_payload(evidence.composition),
                "model_sha256": profile.model_sha256,
                "float_hex_snapshot": list(profile.float_hex_snapshot),
                "state_payload_bounds": list(profile.range_contract.state_payload_bounds),
                "input_payload_bounds": list(profile.range_contract.input_payload_bounds),
                "state_accumulator_bounds": list(profile.state_accumulator_bounds),
                "output_accumulator_bounds": list(profile.output_accumulator_bounds),
                "state_truncation_bits": 0,
                "protocol2_truncations_per_step": 0,
                "maximum_truncation_message": (1 << profile.kappa) - 1,
                "centered_modulus_limit": (profile.fixed_point.modulus - 1) // 2,
                "constraint_bounds": [
                    {
                        "name": name,
                        "lower": [interval.lower.numerator, interval.lower.denominator],
                        "upper": [interval.upper.numerator, interval.upper.denominator],
                    }
                    for name, interval in profile.invariant_report.constraint_bounds
                ],
                "problem": _exact_payload(evidence.problem),
                "witness": _exact_payload(evidence.witness),
            }
        )
    payload = {
        "schema_version": 2,
        "scenario_id": bundle.scenario_id,
        "quantifier": "for_all_integer_k_greater_than_or_equal_to_zero",
        "proof_mode": "closed_loop_invariant",
        "source_hashes": dict(bundle.source_hashes),
        "upstream_stability": {
            "report_sha256": bundle.stability_report_sha256,
            "report": asdict(bundle.stability_report),
        },
        "verified_sweep": {
            "sweep_id": sweep_root.name,
            "final_manifest_sha256": sweep_manifest_hashes["manifest.json"],
            "data_manifest_sha256": sweep_manifest_hashes["data_manifest.json"],
        },
        "assumptions": list(bundle.assumptions),
        "claim_boundary": bundle.claim_boundary,
        "default_180_step_baseline_covered": False,
        "profiles": profiles,
    }
    if bundle.baseline_identity is not None:
        payload["baseline_identity"] = {
            "scheme": bundle.baseline_identity.scheme,
            "baseline_id": bundle.baseline_identity.baseline_id,
            "source_hashes": dict(bundle.baseline_identity.source_hashes),
        }
    return payload


def _sweep_manifest_hashes(sweep_root: Path) -> dict[str, str]:
    """读取两个已验证清单的稳定摘要，供发布前后检测上游替换。"""
    root = sweep_root.resolve()
    result: dict[str, str] = {}
    for name in ("manifest.json", "data_manifest.json"):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"verified sweep 缺少普通文件 {name}")
        result[name] = sha256(path.read_bytes()).hexdigest()
    return result


def _markdown_report(bundle: HvacInfiniteSafetyBundle, certificate: dict[str, Any]) -> str:
    """生成人可读中文报告，明确条件定理和不覆盖项。"""
    lines = [
        "# 2R2C HVAC 无限时域闭环安全证书",
        "",
        "## 结论",
        "",
        (
            "在下列假设同时成立时，四个冻结精度点均精确证明：初始集合包含于鲁棒正不变"
            "椭球，每一步闭包成立，且所有物理、控制器 payload 与执行器约束对任意整数 "
            "`k >= 0` 成立。"
        ),
        "",
        "| ell | k | kappa | 状态 | Protocol 2/step |",
        "| ---: | ---: | ---: | --- | ---: |",
    ]
    lines.extend(
        f"| {profile['ell']} | {profile['k']} | {profile['kappa']} | "
        f"{profile['status']} | {profile['protocol2_truncations_per_step']} |"
        for profile in certificate["profiles"]
    )
    lines.extend(["", "## 假设", ""])
    lines.extend(f"- {assumption}" for assumption in bundle.assumptions)
    lines.extend(
        [
            "",
            "## 不覆盖项",
            "",
            f"- {bundle.claim_boundary}",
            "- 本证书不覆盖 180 步切换轨迹；切换仿真与固定参考条件定理必须分别解释。",
            "- 本报告没有重新运行 sweep、仿真或绘图，也不扩展到一般切换系统。",
            "",
        ]
    )
    return "\n".join(lines)


def _write_json(path: Path, value: Any) -> None:
    """写入排序、禁止 NaN 的 UTF-8/LF JSON。"""
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _exact_payload(value: Any) -> Any:
    """把精确证书 dataclass 转为只含整数、字符串、布尔和数组的 JSON。"""
    if isinstance(value, RationalValue):
        return [value.numerator, value.denominator]
    if is_dataclass(value):
        return {field.name: _exact_payload(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_exact_payload(item) for item in value]
    if isinstance(value, (str, bool, int)):
        return value
    raise TypeError(f"证书含不可序列化类型：{type(value).__name__}")


def main(argv: list[str] | None = None) -> int:
    """解析 CLI 并发布一个新的原子安全报告目录。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assumptions", required=True)
    parser.add_argument("--sweep-dir", required=True)
    parser.add_argument("--output-root", default="results/safety")
    args = parser.parse_args(argv)
    target = publish_infinite_safety_report(args.assumptions, args.sweep_dir, args.output_root)
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
