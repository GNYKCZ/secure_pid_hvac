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
    "simulation": ("secure_control.scenarios",),
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


def test_legacy_source_package_does_not_exist() -> None:
    assert not (PACKAGE_ROOT.parent / "secure_pid").exists()
