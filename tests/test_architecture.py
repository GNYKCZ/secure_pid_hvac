"""Fitness tests that protect scenario-independent package boundaries."""

import ast
import re
from pathlib import Path

PACKAGE_ROOT = Path(__file__).parents[1] / "src" / "secure_control"
GENERIC_LAYERS = ("core", "crypto", "protocol", "execution", "simulation")
FORBIDDEN_DOMAIN_TERMS = re.compile(
    r"(?<![A-Za-z0-9])(hvac|temperature|pendulum|cart|kp|ki|kd)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
FORBIDDEN_IMPORTS = {
    "core": ("secure_control.scenarios",),
    "crypto": (
        "secure_control.scenarios",
        "secure_control.execution",
        "secure_control.protocol",
        "secure_control.simulation",
    ),
    "protocol": ("secure_control.scenarios", "secure_control.simulation"),
    "execution": ("secure_control.scenarios",),
    "simulation": (
        "secure_control.crypto",
        "secure_control.protocol",
        "secure_control.scenarios",
    ),
}


def python_files(layer: str) -> list[Path]:
    """Return source files belonging to an architecture layer."""
    return sorted((PACKAGE_ROOT / layer).rglob("*.py"))


def imported_modules(path: Path) -> set[str]:
    """Extract absolute import targets from one Python source file."""
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_generic_layers_contain_no_domain_specific_terms() -> None:
    violations: list[str] = []
    for layer in GENERIC_LAYERS:
        for path in python_files(layer):
            if match := FORBIDDEN_DOMAIN_TERMS.search(path.read_text(encoding="utf-8")):
                violations.append(f"{path.relative_to(PACKAGE_ROOT)}: {match.group(0)}")
    assert violations == []


def test_dependency_direction_has_no_scenario_back_imports() -> None:
    violations: list[str] = []
    for layer, forbidden_prefixes in FORBIDDEN_IMPORTS.items():
        for path in python_files(layer):
            for module in imported_modules(path):
                if module.startswith(forbidden_prefixes):
                    violations.append(f"{path.relative_to(PACKAGE_ROOT)} imports {module}")
    assert violations == []


def test_stability_dependency_direction_remains_scenario_independent() -> None:
    """通用稳定性检查器不得依赖场景/协议，simulation 也不得反向依赖 HVAC 分析。"""
    core_stability = PACKAGE_ROOT / "core" / "stability.py"
    assert not any(
        module.startswith(("secure_control.scenarios", "secure_control.protocol"))
        for module in imported_modules(core_stability)
    )
    for path in python_files("simulation"):
        assert "secure_control.scenarios.hvac" not in imported_modules(path)


def test_infinite_safety_keeps_verifier_and_scenario_assembly_separate() -> None:
    """通用精确 verifier 不感知场景，HVAC 装配也不反向依赖 experiments。"""
    verifier = PACKAGE_ROOT / "core" / "invariance.py"
    assert not any(
        module.startswith(("secure_control.scenarios", "secure_control.protocol"))
        for module in imported_modules(verifier)
    )
    assembler = PACKAGE_ROOT / "scenarios" / "hvac" / "infinite_safety.py"
    assert not any(
        module.startswith("secure_control.experiments") for module in imported_modules(assembler)
    )


def test_private_diagnostics_are_ignored_and_not_uploaded_by_ci() -> None:
    """combined-share 私有诊断不得进入 Git 或未来 CI artifact 上传路径。"""
    project_root = PACKAGE_ROOT.parents[1]
    ignore = (project_root / ".gitignore").read_text(encoding="utf-8")
    assert "results/diagnostics/*" in ignore
    workflows = project_root / ".github" / "workflows"
    if workflows.is_dir():
        violations = [
            path.name
            for path in workflows.rglob("*")
            if path.is_file() and "results/diagnostics/private" in path.read_text(encoding="utf-8")
        ]
        assert violations == []


def test_multiprocessing_worker_is_transport_adapter_not_protocol3_copy() -> None:
    """execution worker 只能分派 endpoint，协议数学、顺序与 lifecycle 必须归 protocol。"""
    worker = PACKAGE_ROOT / "execution" / "_multiprocessing_workers.py"
    source = worker.read_text(encoding="utf-8")
    assert "_execute_role_round" not in source
    assert "_truncate_state" not in source
    assert "_lifecycle" not in source
    assert "_vector_from_scalars" not in source
    assert "for metadata in plan.product_resources" not in source
    assert "secure_control.protocol.roles" not in imported_modules(worker)
    assert "LocalProtocol3PartyEndpoint" in source


def test_localhost_layers_preserve_transport_only_boundaries() -> None:
    """localhost codec/transport/worker 不得感知场景或复制协议算法。"""
    execution = PACKAGE_ROOT / "execution"
    paths = tuple(
        execution / name
        for name in (
            "localhost_codec.py",
            "localhost_transport.py",
            "_localhost_peer.py",
            "_localhost_workers.py",
            "localhost_runtime.py",
        )
    )
    for path in paths:
        modules = imported_modules(path)
        assert not any(module.startswith("secure_control.scenarios") for module in modules)
        assert FORBIDDEN_DOMAIN_TERMS.search(path.read_text(encoding="utf-8")) is None

    worker_source = (execution / "_localhost_workers.py").read_text(encoding="utf-8")
    for forbidden in (
        "_lifecycle",
        "_vector_from_scalars",
        "for metadata in plan.product_resources",
        "BeaverMultiplier",
        "SecureTruncation",
    ):
        assert forbidden not in worker_source
    assert "dispatch_direct_protocol3_command" in worker_source


def test_lan_entry_keeps_scenario_and_transport_boundaries() -> None:
    """LAN 仅在实验入口装配 HVAC，不放宽旧 localhost 或协议数学层。"""
    execution = PACKAGE_ROOT / "execution"
    for name in ("lan_config.py", "lan_transport.py", "lan_runtime.py"):
        path = execution / name
        assert not any(
            module.startswith("secure_control.scenarios") for module in imported_modules(path)
        )
    transport = (execution / "lan_transport.py").read_text(encoding="utf-8")
    assert "CERT_REQUIRED" in transport and "TLSv1_3" in transport
    assert "CERT_NONE" not in transport
    assert "LocalhostTransportConfig" not in transport
    runner = PACKAGE_ROOT / "experiments" / "lan_runner.py"
    assert "secure_control.scenarios.hvac.integration" in imported_modules(runner)


def test_localhost_and_multiprocessing_share_protocol_authorities() -> None:
    """两种隔离 backend 复用同一 command dispatcher 和唯一 orchestrator。"""
    execution = PACKAGE_ROOT / "execution"
    multiprocessing_worker = (execution / "_multiprocessing_workers.py").read_text(encoding="utf-8")
    localhost_worker = (execution / "_localhost_workers.py").read_text(encoding="utf-8")
    multiprocessing_runtime = (execution / "multiprocessing_runtime.py").read_text(encoding="utf-8")
    localhost_runtime = (execution / "localhost_runtime.py").read_text(encoding="utf-8")
    assert "dispatch_protocol3_command" in multiprocessing_worker
    assert "dispatch_direct_protocol3_command" in localhost_worker
    assert "Protocol3Orchestrator" in multiprocessing_runtime
    assert "Protocol3Orchestrator" in localhost_worker
    assert "Protocol3Orchestrator" not in localhost_runtime

    for path in python_files("protocol"):
        modules = imported_modules(path)
        assert "socket" not in modules
        assert not any(module.startswith("secure_control.execution") for module in modules)
    for path in python_files("simulation"):
        assert "localhost" not in path.read_text(encoding="utf-8").lower()
