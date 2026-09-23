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


def test_experiment_io_boundary_imports_only_generic_contracts() -> None:
    """通用 writer/provenance/plotting 不导入场景算法；薄 CLI 只调用已保存数据。"""
    experiments = PACKAGE_ROOT / "experiments"
    for name in (
        "artifacts.py",
        "provenance.py",
        "plotting.py",
        "sweep.py",
        "sweep_metrics.py",
        "sweep_artifacts.py",
        "sweep_plotting.py",
        "reporting.py",
        "evidence_artifacts.py",
        "exact_grid.py",
        "exact_grid_artifacts.py",
    ):
        source = experiments / name
        assert "secure_control.scenarios" not in imported_modules(source)
        assert FORBIDDEN_DOMAIN_TERMS.search(source.read_text(encoding="utf-8")) is None
    plotting_imports = imported_modules(experiments / "plotting.py")
    assert "secure_control.simulation.runner" not in plotting_imports
    assert "secure_control.experiments.runner" not in plotting_imports
    figure_imports = imported_modules(experiments / "figure_runner.py")
    assert "secure_control.scenarios" not in figure_imports
    assert "secure_control.simulation.runner" not in figure_imports
    report_imports = imported_modules(experiments / "sweep_figure_runner.py")
    assert "secure_control.experiments.sweep_runner" not in report_imports
    assert "secure_control.simulation.runner" not in report_imports
    assert not any(module.startswith("secure_control.scenarios") for module in report_imports)
    selector_imports = imported_modules(experiments / "runner.py")
    scenario_imports = {
        module for module in selector_imports if module.startswith("secure_control.scenarios")
    }
    assert scenario_imports == {"secure_control.scenarios.hvac.integration"}
    assert "secure_control.scenarios.hvac.plant" not in selector_imports
    assert "secure_control.scenarios.hvac.pid" not in selector_imports
    sweep_runner_imports = imported_modules(experiments / "sweep_runner.py")
    assert {
        module for module in sweep_runner_imports if module.startswith("secure_control.scenarios")
    } == {
        "secure_control.scenarios.hvac.integration",
        "secure_control.scenarios.hvac.migration",
        "secure_control.scenarios.hvac.stability",
    }
    evidence_report_imports = imported_modules(experiments / "evidence_reporting.py")
    assert not any(
        module.startswith(
            (
                "secure_control.scenarios",
                "secure_control.execution",
                "secure_control.experiments.evidence_runner",
                "secure_control.simulation.runner",
            )
        )
        for module in evidence_report_imports
    )
    exact_grid_runner_imports = imported_modules(experiments / "exact_grid_runner.py")
    assert "secure_control.simulation.runner" not in exact_grid_runner_imports
    assert "secure_control.experiments.sweep_runner" not in exact_grid_runner_imports
    assert "secure_control.experiments.evidence_runner" not in exact_grid_runner_imports


def test_2r2c_types_remain_owned_by_hvac_scenario() -> None:
    """通用层与实验 I/O 不得感知 HVAC 的二维内部状态或具体模型类型。"""
    violations: list[str] = []
    for layer in (*GENERIC_LAYERS, "experiments"):
        for path in python_files(layer):
            source = path.read_text(encoding="utf-8")
            if "Hvac2R2C" in source or "second_order_2r2c_cooling" in source:
                violations.append(str(path.relative_to(PACKAGE_ROOT)))
    assert violations == []


def test_evidence_input_boundaries_do_not_branch_on_known_instances() -> None:
    """通用执行/报告路径不得把两个 fixture 的名字、ID 或 reference 变成运行逻辑。"""
    experiments = PACKAGE_ROOT / "experiments"
    sources = "\n".join(
        (experiments / name).read_text(encoding="utf-8")
        for name in ("sweep_runner.py", "evidence_runner.py", "evidence_reporting.py")
    )
    forbidden = (
        "hvac_2r2c_dual_loop_25_20_15.yaml",
        "hvac_2r2c_dual_loop_25_20_15_fast_response.yaml",
        "hvac_2r2c_dual_loop.yaml",
        "2489e5476ad316ea2d9599783e29f2d849ffcf485ca860e0db76c80312c532f9",
        "f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab",
        "e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7",
        "15_20_25",
        "25_20_15",
    )
    assert all(value not in sources for value in forbidden)


def test_hvac_tuning_is_plaintext_only_and_has_no_secure_protocol_dependency() -> None:
    """调参模块不能导入安全运行时、协议或密码层，防止 secure 结果参与选参。"""
    tuning = PACKAGE_ROOT / "scenarios" / "hvac" / "tuning.py"
    modules = imported_modules(tuning)
    assert not any(
        module.startswith(
            ("secure_control.crypto", "secure_control.protocol", "secure_control.execution")
        )
        for module in modules
    )


def test_hvac_migration_gate_remains_plaintext_only() -> None:
    """基线选择与身份模块不得导入密码、协议、安全运行时或实验层。"""
    migration = PACKAGE_ROOT / "scenarios" / "hvac" / "migration.py"
    modules = imported_modules(migration)
    assert not any(
        module.startswith(
            (
                "secure_control.crypto",
                "secure_control.protocol",
                "secure_control.execution",
                "secure_control.simulation",
                "secure_control.experiments",
            )
        )
        for module in modules
    )


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


def test_legacy_source_package_does_not_exist() -> None:
    assert not (PACKAGE_ROOT.parent / "secure_pid").exists()


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
