from unittest.mock import patch

from mcprack import health


class FakeServer:
    def __init__(self, transport, command=None, url=None):
        self.transport = transport
        self.command = command
        self.url = url


def test_check_stdio_command_found_on_path():
    with patch("mcprack.health.shutil.which", return_value="/usr/bin/foo"):
        assert health.check_stdio_command("foo") is True


def test_check_stdio_command_not_found_on_path():
    with patch("mcprack.health.shutil.which", return_value=None):
        assert health.check_stdio_command("nonexistent-tool") is False


def test_check_stdio_command_absolute_path_executable():
    with patch("mcprack.health.os.path.isfile", return_value=True), patch("mcprack.health.os.access", return_value=True):
        assert health.check_stdio_command("/usr/bin/foo") is True


def test_check_stdio_command_absolute_path_missing():
    with patch("mcprack.health.os.path.isfile", return_value=False):
        assert health.check_stdio_command("/usr/bin/does-not-exist") is False


def test_check_stdio_command_empty():
    assert health.check_stdio_command("") is False
    assert health.check_stdio_command(None) is False


def test_check_http_reachable_success():
    with patch("mcprack.health.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = None
        assert health.check_http_reachable("http://example.test:1234/mcp") is True
        args, kwargs = mock_conn.call_args
        assert args[0] == ("example.test", 1234)


def test_check_http_reachable_default_ports():
    with patch("mcprack.health.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = None
        health.check_http_reachable("https://example.test/mcp")
        assert mock_conn.call_args[0][0] == ("example.test", 443)


def test_check_http_reachable_connection_refused():
    with patch("mcprack.health.socket.create_connection", side_effect=OSError("refused")):
        assert health.check_http_reachable("http://example.test:1234/mcp") is False


def test_check_http_reachable_no_url():
    assert health.check_http_reachable("") is False
    assert health.check_http_reachable(None) is False


def test_check_reachable_dispatches_by_url_presence():
    local_stdio_server = FakeServer("stdio", command="foo")
    http_server = FakeServer("http", url="http://example.test:1234/mcp")

    with patch("mcprack.health.check_stdio_command", return_value=True) as mock_stdio:
        assert health.check_reachable(local_stdio_server) is True
        mock_stdio.assert_called_once_with("foo")

    with patch("mcprack.health.check_http_reachable", return_value=False) as mock_http:
        assert health.check_reachable(http_server) is False
        mock_http.assert_called_once_with("http://example.test:1234/mcp")


def test_check_reachable_prefers_url_for_proxied_stdio_server():
    """A stdio server that's also proxied onto the network (url set) should
    be health-checked over the network, not by looking for a local binary —
    remote users connect via the proxy, not by spawning the command."""
    proxied_stdio_server = FakeServer("stdio", command="foo", url="http://mcphost:3100/mcp")

    with patch("mcprack.health.check_http_reachable", return_value=True) as mock_http, \
         patch("mcprack.health.check_stdio_command") as mock_stdio:
        assert health.check_reachable(proxied_stdio_server) is True
        mock_http.assert_called_once_with("http://mcphost:3100/mcp")
        mock_stdio.assert_not_called()


def test_check_stdio_startup_no_command():
    ok, detail = health.check_stdio_startup(None)
    assert ok is False
    assert "No command" in detail


def test_check_stdio_startup_missing_binary():
    ok, detail = health.check_stdio_startup("/definitely/does/not/exist-mcp")
    assert ok is False
    assert "Could not start" in detail


def test_check_stdio_startup_detects_immediate_crash():
    """Mirrors the real bug this was written for: a script that's a valid,
    executable file but crashes immediately at import time (e.g. a missing
    runtime dependency) — must be reported as broken, not just 'the file
    exists'."""
    ok, detail = health.check_stdio_startup(
        "python3", ["-c", "import nonexistent_module_xyz"], timeout=2.0
    )
    assert ok is False
    assert "Exited with code" in detail
    assert "nonexistent_module_xyz" in detail or "ModuleNotFoundError" in detail


def test_check_stdio_startup_treats_still_running_as_healthy():
    """A well-behaved MCP stdio server blocks waiting on stdin — still
    running after the grace period is the expected, healthy outcome."""
    ok, detail = health.check_stdio_startup(
        "python3", ["-c", "import time; time.sleep(30)"], timeout=1.0
    )
    assert ok is True
    assert "still running" in detail


def test_check_stdio_startup_treats_clean_exit_as_healthy():
    ok, detail = health.check_stdio_startup("python3", ["-c", "pass"], timeout=2.0)
    assert ok is True
    assert "cleanly" in detail
