"""Basic package smoke tests."""


def test_secure_pid_import() -> None:
    """The project package can be imported from the managed environment."""
    import secure_pid

    assert secure_pid.__version__ == "0.1.0"
