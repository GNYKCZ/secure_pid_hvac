"""Basic package smoke tests."""

import importlib.util


def test_secure_control_import() -> None:
    """The project package can be imported from the managed environment."""
    import secure_control

    assert secure_control.__version__ == "0.1.0"


def test_legacy_package_is_not_importable() -> None:
    """The old import package is not kept as an accidental compatibility alias."""
    assert importlib.util.find_spec("secure_pid") is None
