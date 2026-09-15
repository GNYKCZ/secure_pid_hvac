"""只收集允许公开、实际可验证的项目/Git/运行环境与 seed 来源。"""

from __future__ import annotations

import importlib.metadata
import platform
import re
import subprocess
import tomllib
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any


def _file_digest(path: Path) -> dict[str, Any]:
    """缺少项目/锁文件时标记 unavailable，不伪造摘要或输出本地路径。"""
    try:
        return {"available": True, "sha256": sha256(path.read_bytes()).hexdigest()}
    except OSError:
        return {"available": False, "reason": "file_unavailable"}


def _git_provenance(project_root: Path) -> dict[str, Any]:
    """只保存 commit/dirty 布尔值，不把 status 文件名或命令错误写进产物。"""
    try:
        head = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(project_root), "status", "--porcelain=v1"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except FileNotFoundError:
        return {"available": False, "reason": "git_unavailable"}
    except subprocess.CalledProcessError:
        return {"available": False, "reason": "git_repository_unavailable"}
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        return {"available": False, "reason": "git_head_invalid"}
    return {"available": True, "commit": head, "dirty": bool(status.strip())}


def _project_versions(project_root: Path) -> dict[str, Any]:
    """记录 pyproject 中直接声明的依赖版本，而不是枚举机器全部软件。"""
    pyproject = project_root / "pyproject.toml"
    try:
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
        package_version = project["version"]
        requirements = project.get("dependencies", [])
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        distributions = importlib.metadata.packages_distributions().get("secure_control", [])
        try:
            package_version = importlib.metadata.version(distributions[0])
        except (IndexError, importlib.metadata.PackageNotFoundError):
            package_version = {"available": False, "reason": "project_version_unavailable"}
        requirements = []
    versions: dict[str, Any] = {}
    for requirement in requirements:
        name_match = re.match(r"[A-Za-z0-9_.-]+", requirement)
        if name_match is None:
            continue
        name = name_match.group().lower().replace("_", "-")
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = {"available": False, "reason": "dependency_unavailable"}
    return {"project_version": package_version, "dependency_versions": versions}


def collect_provenance(
    *,
    scenario_name: str,
    scenario_version: str,
    schema_version: int,
    test_seed: int | None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """记录真实 Git/锁文件/依赖与 test seed，绝不转储 RNG、share 或环境变量。

    固定 seed 只用于隔离研究复现；无 seed 记为 secure_random，而非虚构一个
    可复现 seed。若 Git/锁文件不可得，显式写 unavailable 与非敏感原因。
    """
    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[3]
    if test_seed is not None and (isinstance(test_seed, bool) or not isinstance(test_seed, int)):
        raise TypeError("test_seed 必须为整数或 None。")
    project = _project_versions(root)
    return {
        "collected_at_utc": datetime.now(UTC).isoformat(),
        "scenario_name": scenario_name,
        "scenario_version": scenario_version,
        "schema_version": schema_version,
        **project,
        "git": _git_provenance(root),
        "pyproject": _file_digest(root / "pyproject.toml"),
        "uv_lock": _file_digest(root / "uv.lock"),
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "configured_seeds": (
            {"secure_material_test_seed": test_seed} if test_seed is not None else {}
        ),
        "secure_material_randomness": (
            "deterministic_test" if test_seed is not None else "secure_random"
        ),
    }
