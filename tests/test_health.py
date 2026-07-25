from unittest.mock import patch

import health


class FakeServer:
    def __init__(self, transport, command=None, url=None):
        self.transport = transport
        self.command = command
        self.url = url


def test_check_stdio_command_found_on_path():
    with patch("health.shutil.which", return_value="/usr/bin/foo"):
        assert health.check_stdio_command("foo") is True


def test_check_stdio_command_not_found_on_path():
    with patch("health.shutil.which", return_value=None):
        assert health.check_stdio_command("nonexistent-tool") is False


def test_check_stdio_command_absolute_path_executable():
    with patch("health.os.path.isfile", return_value=True), patch("health.os.access", return_value=True):
        assert health.check_stdio_command("/usr/bin/foo") is True


def test_check_stdio_command_absolute_path_missing():
    with patch("health.os.path.isfile", return_value=False):
        assert health.check_stdio_command("/usr/bin/does-not-exist") is False


def test_check_stdio_command_empty():
    assert health.check_stdio_command("") is False
    assert health.check_stdio_command(None) is False


def test_check_http_reachable_success():
    with patch("health.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = None
        assert health.check_http_reachable("http://example.test:1234/mcp") is True
        args, kwargs = mock_conn.call_args
        assert args[0] == ("example.test", 1234)


def test_check_http_reachable_default_ports():
    with patch("health.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = None
        health.check_http_reachable("https://example.test/mcp")
        assert mock_conn.call_args[0][0] == ("example.test", 443)


def test_check_http_reachable_connection_refused():
    with patch("health.socket.create_connection", side_effect=OSError("refused")):
        assert health.check_http_reachable("http://example.test:1234/mcp") is False


def test_check_http_reachable_no_url():
    assert health.check_http_reachable("") is False
    assert health.check_http_reachable(None) is False


def test_check_reachable_dispatches_by_url_presence():
    local_stdio_server = FakeServer("stdio", command="foo")
    http_server = FakeServer("http", url="http://example.test:1234/mcp")

    with patch("health.check_stdio_command", return_value=True) as mock_stdio:
        assert health.check_reachable(local_stdio_server) is True
        mock_stdio.assert_called_once_with("foo")

    with patch("health.check_http_reachable", return_value=False) as mock_http:
        assert health.check_reachable(http_server) is False
        mock_http.assert_called_once_with("http://example.test:1234/mcp")


def test_check_reachable_prefers_url_for_proxied_stdio_server():
    """A stdio server that's also proxied onto the network (url set) should
    be health-checked over the network, not by looking for a local binary —
    remote users connect via the proxy, not by spawning the command."""
    proxied_stdio_server = FakeServer("stdio", command="foo", url="http://mcphost:3100/mcp")

    with patch("health.check_http_reachable", return_value=True) as mock_http, \
         patch("health.check_stdio_command") as mock_stdio:
        assert health.check_reachable(proxied_stdio_server) is True
        mock_http.assert_called_once_with("http://mcphost:3100/mcp")
        mock_stdio.assert_not_called()
