from unittest.mock import MagicMock, patch

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


def test_parse_mcp_body_plain_json():
    assert health._parse_mcp_body('{"jsonrpc": "2.0", "id": 1, "result": {}}') == {
        "jsonrpc": "2.0", "id": 1, "result": {},
    }


def test_parse_mcp_body_sse_wrapped():
    """fastmcp's streamable-HTTP transport can wrap the same JSON payload in
    a single SSE event instead of returning it as a plain body - a bug that
    made the admin "Tools" button always fail with "Could not query server
    capabilities" until this was handled."""
    raw = 'event: message\r\ndata: {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\r\n\r\n'
    assert health._parse_mcp_body(raw) == {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}


def _fake_conn(status, body, headers=None):
    """A stand-in for http.client.HTTPConnection that returns a fixed
    response - mirrors the shape the real object exposes across
    request()/getresponse()/getresponse().read()/.getheader()."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body.encode("utf-8")
    resp.getheader.side_effect = lambda name, default=None: (headers or {}).get(name, default)
    conn = MagicMock()
    conn.getresponse.return_value = resp
    return conn


def test_send_jsonrpc_request_sets_streamable_http_accept_header():
    conn = _fake_conn(200, '{"jsonrpc": "2.0", "id": "x", "result": {"tools": []}}')
    with patch("mcprack.health.http.client.HTTPConnection", return_value=conn):
        ok, data = health._send_jsonrpc_request("127.0.0.1", 1234, "tools/list")

    assert ok is True
    headers = conn.request.call_args.kwargs["headers"]
    assert headers["Accept"] == "application/json, text/event-stream"


def test_send_jsonrpc_request_forwards_session_id_header():
    conn = _fake_conn(200, '{"jsonrpc": "2.0", "id": "x", "result": {}}')
    with patch("mcprack.health.http.client.HTTPConnection", return_value=conn):
        health._send_jsonrpc_request("127.0.0.1", 1234, "tools/list", session_id="abc123")

    headers = conn.request.call_args.kwargs["headers"]
    assert headers["mcp-session-id"] == "abc123"


def test_send_jsonrpc_request_parses_sse_response():
    conn = _fake_conn(200, 'event: message\r\ndata: {"jsonrpc": "2.0", "id": "x", "result": {"tools": [1]}}\r\n\r\n')
    with patch("mcprack.health.http.client.HTTPConnection", return_value=conn):
        ok, data = health._send_jsonrpc_request("127.0.0.1", 1234, "tools/list")

    assert ok is True
    assert data == {"tools": [1]}


def test_get_server_capabilities_full_flow_reuses_session_id():
    """Regression test for the real bug: fastmcp's streamable-HTTP servers
    require every request after `initialize` to carry the mcp-session-id
    the handshake returned (a fresh, session-less request gets a 400 "Missing
    session ID"), and reply with an SSE-wrapped body - get_server_capabilities
    must survive both."""
    init_conn = _fake_conn(
        200,
        'event: message\r\ndata: {"jsonrpc": "2.0", "id": "mcprack-init", "result": {}}\r\n\r\n',
        headers={"mcp-session-id": "sess-abc"},
    )
    tools_conn = _fake_conn(
        200, 'event: message\r\ndata: {"jsonrpc": "2.0", "id": "x", "result": {"tools": [{"name": "t1"}]}}\r\n\r\n'
    )
    resources_conn = _fake_conn(
        200, '{"jsonrpc": "2.0", "id": "x", "result": {"resources": []}}'
    )

    with patch(
        "mcprack.health.http.client.HTTPConnection",
        side_effect=[init_conn, tools_conn, resources_conn],
    ):
        caps = health.get_server_capabilities("127.0.0.1", 1234, timeout=5.0)

    assert caps == {"tools": [{"name": "t1"}], "resources": []}
    assert tools_conn.request.call_args.kwargs["headers"]["mcp-session-id"] == "sess-abc"
    assert resources_conn.request.call_args.kwargs["headers"]["mcp-session-id"] == "sess-abc"


def test_get_server_capabilities_returns_none_on_error_response():
    init_conn = _fake_conn(
        406, '{"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Not Acceptable"}}'
    )
    with patch("mcprack.health.http.client.HTTPConnection", return_value=init_conn):
        assert health.get_server_capabilities("127.0.0.1", 1234, timeout=5.0) is None
