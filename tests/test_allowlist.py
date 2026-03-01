from storai.models import CommandSpec
from storai.safety import SafetyError, validate_command_allowlist


def test_allowlist_accepts_safe_command() -> None:
    spec = CommandSpec(command="lsblk", args=["-J"])
    validate_command_allowlist(spec)


def test_allowlist_rejects_unknown_command() -> None:
    spec = CommandSpec(command="bash", args=["-lc", "rm -rf /"])
    try:
        validate_command_allowlist(spec)
    except SafetyError as exc:
        assert "not allowlisted" in str(exc)
    else:
        raise AssertionError("Expected SafetyError")
