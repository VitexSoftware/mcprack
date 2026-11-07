"""Branches of user_proxy.py that the main suite misses: signal fallback and
escalation, the Debian fastmcp fallback path, unreadable instance logs, port
probing, spawn-failure diagnostics, and explicit proxy teardown."""

import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from mcprack import user_proxy


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "user-proxies"
    monkeypatch.setattr(user_proxy, "STATE_DIR", d)
    return d


def _fake_proc(pid=99999, alive=True):
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = None if alive else 1
    return proc


def test_stop_pid_escalates_to_sigkill_and_tolerates_a_dead_pid(state_dir):
    """killpg fails (no such group) and os.kill fails (no such process):
    both must be swallowed, and after the timeout SIGKILL is attempted."""
    with patch("mcprack.user_proxy._pid_running", return_value=True), patch(
        "mcprack.user_proxy.os.killpg", side_effect=ProcessLookupError
    ), patch("mcprack.user_proxy.os.kill", side_effect=OSError("no such process")) as kill:
        user_proxy._stop_pid(4242, timeout=0.2)

    assert kill.call_count == 2  # SIGTERM, then SIGKILL after the deadline


def test_resolve_fastmcp_bin_uses_the_debian_default_when_not_on_path(app):
    app.config["FASTMCP_BIN"] = ""
    with app.app_context(), patch(
        "mcprack.user_proxy.shutil.which", return_value=None
    ), patch(
        "mcprack.user_proxy.os.access",
        side_effect=lambda path, mode: path == "/usr/bin/fastmcp",
    ):
        assert user_proxy._resolve_fastmcp_bin() == "/usr/bin/fastmcp"


def test_read_recent_log_swallows_unreadable_paths(tmp_path):
    # a directory cannot be opened for reading, a missing file cannot either
    assert user_proxy._read_recent_log(tmp_path) is None
    assert user_proxy._read_recent_log(tmp_path / "missing.log") is None


def test_is_port_available_false_for_a_bound_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        assert user_proxy._is_port_available(port) is False


def _spawn_failure_patches():
    return (
        patch("mcprack.user_proxy.subprocess.Popen", return_value=_fake_proc()),
        patch("mcprack.user_proxy._probe_upstream_health", return_value=False),
        patch("mcprack.user_proxy._pid_running", return_value=False),
        patch("mcprack.user_proxy._resolve_fastmcp_bin", return_value="/usr/bin/fastmcp"),
    )


def test_spawn_failure_without_log_points_at_the_log_file(state_dir):
    patches = _spawn_failure_patches()
    with patches[0], patches[1], patches[2], patches[3]:
        with pytest.raises(user_proxy.UserProxyError, match="check its log at"):
            user_proxy.ensure_user_server_proxy(
                user_id=1, server_id=11, server_name="broken",
                command="/bin/broken-mcp", args=[], env={},
            )


def test_spawn_failure_with_log_includes_its_tail(state_dir):
    paths = user_proxy._paths(1, 11)
    paths["log"].parent.mkdir(parents=True, exist_ok=True)
    paths["log"].write_text("ModuleNotFoundError: No module named 'jira'\n")

    patches = _spawn_failure_patches()
    with patches[0], patches[1], patches[2], patches[3]:
        with pytest.raises(user_proxy.UserProxyError, match="Last log lines") as excinfo:
            user_proxy.ensure_user_server_proxy(
                user_id=1, server_id=11, server_name="jira",
                command="/bin/jira-mcp", args=[], env={},
            )
    assert "No module named 'jira'" in str(excinfo.value)


def test_stop_user_server_proxy_clears_the_state_files(app, state_dir):
    paths = user_proxy._paths(1, 11)
    paths["pid"].parent.mkdir(parents=True, exist_ok=True)
    paths["pid"].write_text("4242")
    paths["port"].write_text(str(user_proxy._port_for(1, 11)))
    paths["last_used"].write_text(str(time.time()))

    with patch("mcprack.user_proxy._pid_running", side_effect=[True, False]), patch(
        "mcprack.user_proxy.os.killpg"
    ):
        user_proxy.stop_user_server_proxy(1, 11)

    for key in ("pid", "port", "last_used"):
        assert not paths[key].exists()
