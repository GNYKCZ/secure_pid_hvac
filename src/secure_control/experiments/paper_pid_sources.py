"""paper PID 实验共享的公开证书解析；冻结声明由各入口自行管理。"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from secure_control.crypto import PocklingtonCertificate, PocklingtonFactorEvidence


def _require_keys(name: str, value: Any, expected: set[str]) -> dict[str, Any]:
    """严格限定固定实验配置字段，避免拼写错误被静默忽略。"""
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} 字段必须恰好是 {sorted(expected)}")
    return value


def load_baseline_config(path: Path) -> tuple[dict[str, Any], str]:
    """锁定 paper PID 论文对象与配置来源，供两条实验路线共同读取。"""
    raw_bytes = path.read_bytes()
    loaded = yaml.safe_load(raw_bytes.decode("utf-8"))
    config = _require_keys(
        "config", loaded,
        {"schema_version", "claim_level", "sources", "controller", "plant", "sample_count"},
    )
    sources = _require_keys("sources", config["sources"], {"controller", "plant", "plant_equation"})
    plant = _require_keys(
        "plant", config["plant"],
        {"alpha", "sample_period_seconds", "initial_state", "realization", "discretization"},
    )
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("schema_version 必须是 1")
    if config["claim_level"] != "paper-inspired":
        raise ValueError("仅允许 paper-inspired 声明等级")
    if config["controller"] != "printed_section_vii":
        raise ValueError("仅允许论文 §VII 印刷控制器")
    if (
        sources["controller"] != "https://arxiv.org/html/2503.02176v3#S7"
        or sources["plant"] != "https://doi.org/10.1016/S1474-6670(17)38238-1"
        or sources["plant_equation"] != "Eq. (2)"
    ):
        raise ValueError("来源必须对应论文 v3 §VII 与 [38] Eq. (2)")
    if (
        plant["realization"] != "four_stage_cascade_outputs"
        or plant["discretization"] != "zoh"
    ):
        raise ValueError("只支持已审查的四级串联坐标和 ZOH")
    for name, expected in (("alpha", 0.2), ("sample_period_seconds", 0.1)):
        value = plant[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != expected:
            raise ValueError(f"{name} 必须保持论文实例值 {expected}")
    if (
        not isinstance(plant["initial_state"], list)
        or len(plant["initial_state"]) != 4
        or any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or value != 100.0
            for value in plant["initial_state"]
        )
    ):
        raise ValueError("initial_state 必须是论文四个 100 的数值向量")
    if type(config["sample_count"]) is not int or config["sample_count"] != 51:
        raise ValueError("sample_count 必须是 k=0..50 对应的 51")
    return config, sha256(raw_bytes).hexdigest()


def parse_prime_certificate(raw: dict[str, Any]) -> PocklingtonCertificate:
    """把公开 Pocklington YAML 结构转为已有 crypto 证书对象。"""
    if not isinstance(raw, dict) or set(raw) != {"candidate", "factors"}:
        raise ValueError("prime certificate 字段无效")
    factors = []
    for item in raw["factors"]:
        if not isinstance(item, dict) or set(item) - {"prime", "exponent", "witness", "certificate"}:
            raise ValueError("prime factor 字段无效")
        if not {"prime", "exponent", "witness"} <= set(item):
            raise ValueError("prime factor 缺失字段")
        factors.append(PocklingtonFactorEvidence(
            item["prime"], item["exponent"], item["witness"],
            parse_prime_certificate(item["certificate"]) if "certificate" in item else None,
        ))
    return PocklingtonCertificate(raw["candidate"], tuple(factors))
