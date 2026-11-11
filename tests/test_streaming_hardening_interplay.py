"""The SSE streaming / gthread work on main and the hardening branch changed
the same code from two sides (relay header handling, the start-up probe, the
GET route). These tests pin down that both guarantees hold *together*."""

import io
import json
from unittest.mock import MagicMock, patch

import pytest

from mcprack import catalog, user_proxy
from mcprack.extensions import db
from mcprack.models import ApiToken, McpServer, User, UserServerSelection


def _sse_upstream(headers):
    conn = MagicMock()
    upstream = conn.getresponse.return_value
    upstream.status = 200
    upstream.getheader.return_value = "text/event-stream"
    upstream.getheaders.return_value = headers
    upstream.read.side_effect = AssertionError("an SSE answer must not be buffered")
    upstream.read1.side_effect = [b"data: {}\n\n", b""]
    return conn


# --- the response allowlist (A-08) also applies to a streamed answer ----------------------------


def test_a_streamed_answer_still_goes_through_the_response_allowlist(app):
    conn = _sse_upstream(
        [
            ("Content-Type", "text/event-stream"),
            ("Mcp-Session-Id", "session-123"),
            ("Content-Length", "999"),
            ("Set-Cookie", "session=attacker; Path=/"),
            ("WWW-Authenticate", 'Bearer resource_metadata="https://evil.example/x"'),
            ("Access-Control-Allow-Origin", "https://evil.example"),
            ("Content-Security-Policy", "default-src *"),
            ("Location", "https://evil.example/"),
            ("Strict-Transport-Security", "max-age=0"),
        ]
    )

    with app.test_request_context("/", method="POST", json={"id": 1}):
        response = catalog._relay_request(conn, "/mcp")

    assert response.is_streamed
    assert response.headers["Mcp-Session-Id"] == "session-123"
    assert response.headers["X-Accel-Buffering"] == "no"  # ours: the proxy must not buffer the stream
    for header in ("Set-Cookie", "WWW-Authenticate", "Access-Control-Allow-Origin", "Content-Security-Policy",
                   "Location", "Strict-Transport-Security", "Content-Length"):
        assert header not in response.headers, header


def test_a_backend_cannot_switch_buffering_back_on(app):
    """X-Accel-Buffering is ours to set. Whatever the backend says, a stream
    stays unbuffered (and the backend's own header is not forwarded)."""
    conn = _sse_upstream([("Content-Type", "text/event-stream"), ("X-Accel-Buffering", "yes")])

    with app.test_request_context("/", method="POST", json={"id": 1}):
        response = catalog._relay_request(conn, "/mcp")

    assert response.headers["X-Accel-Buffering"] == "no"


def test_the_callers_credentials_are_not_forwarded_on_the_streaming_path_either(app):
    conn = _sse_upstream([("Content-Type", "text/event-stream")])
    headers = {"Authorization": "Bearer mcprack-token", "Cookie": "session=abc", "Accept": "text/event-stream"}

    with app.test_request_context("/", method="POST", json={"id": 1}, headers=headers):
        catalog._relay_request(conn, "/mcp")

    sent = {name.lower() for name in conn.request.call_args.kwargs["headers"]}
    assert "authorization" not in sent and "cookie" not in sent
    assert "accept" in sent


def test_a_stored_metadata_url_is_refused_for_a_legacy_sse_get_too(app):
    server = McpServer(name="legacy", label="L", transport="sse", url="http://169.254.169.254/sse", enabled=True)

    with app.test_request_context("/", method="GET"), \
         patch("mcprack.catalog.http.client.HTTPConnection") as connection:
        response = catalog._forward_to_backend_url(server.url, {}, server)

    connection.assert_not_called()
    assert response.status_code == 502


# --- the start-up probe: SSE reading (main) + failure classes (hardening) ------------------------


def _probe(stream: bytes, **kwargs):
    response = MagicMock()
    response.status = 200
    response.getheader.return_value = "text/event-stream"
    response.read.side_effect = AssertionError("must not wait for the stream to close")
    response.readline.side_effect = io.BytesIO(stream).readline
    report = {}
    with patch("mcprack.user_proxy.http.client.HTTPConnection") as connection:
        connection.return_value.getresponse.return_value = response
        ok = user_proxy._probe_upstream_health(12345, timeout=0.5, report=report, **kwargs)
    return ok, report


def test_an_sse_initialize_result_is_healthy_and_reports_nothing():
    stream = b'event: message\ndata: {"jsonrpc":"2.0","id":"mcprack-health-probe","result":{}}\n\n'

    assert _probe(stream) == (True, {})


def test_an_sse_initialize_error_is_a_handshake_error_with_its_message():
    error = {"jsonrpc": "2.0", "id": "mcprack-health-probe", "error": {"code": -32000, "message": "Connection closed"}}

    ok, report = _probe(b"event: message\ndata: " + json.dumps(error).encode() + b"\n\n")

    assert ok is False
    assert report == {"kind": "handshake_error", "detail": "Connection closed"}


def test_a_stream_that_ends_without_the_result_is_a_classified_failure_not_a_hang():
    ok, report = _probe(b": keepalive\n\n")

    assert ok is False
    assert report["kind"] == "handshake_error" and "ended before" in report["detail"]


def test_a_stream_carrying_garbage_is_a_classified_failure():
    ok, report = _probe(b"event: message\ndata: not-json\n\n")

    assert ok is False
    assert report["kind"] == "handshake_error"


def test_the_spawn_failure_for_a_broken_stream_reaches_the_user_as_a_class_not_a_log(tmp_path, monkeypatch):
    """End to end through _spawn: the class from the probe selects the message,
    the administrator gets the log tail, the end user does not."""
    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "up")
    paths = user_proxy._paths(1, 2)
    paths["log"].parent.mkdir(parents=True)
    paths["log"].write_text("Traceback ...\nModuleNotFoundError: lib_x (/opt/secret-path)")
    proc = MagicMock(pid=9_000_001)
    proc.poll.return_value = None
    stream = b": keepalive\n\n"
    response = MagicMock(status=200)
    response.getheader.return_value = "text/event-stream"
    response.readline.side_effect = io.BytesIO(stream).readline

    with patch("mcprack.user_proxy.subprocess.Popen", return_value=proc), \
         patch("mcprack.user_proxy.http.client.HTTPConnection") as connection, \
         patch("mcprack.user_proxy._resolve_fastmcp_bin", return_value="/usr/bin/fastmcp"), \
         patch("mcprack.user_proxy._pid_running", return_value=False), patch("mcprack.user_proxy._stop_pid"):
        connection.return_value.getresponse.return_value = response
        with pytest.raises(user_proxy.UserProxyError) as caught:
            user_proxy.ensure_user_server_proxy(1, 2, "zabbix", "/bin/zbx", [], {})

    assert caught.value.kind == "handshake_error"
    assert "ModuleNotFoundError" in str(caught.value)
    assert "ModuleNotFoundError" not in caught.value.public_message
    assert "/opt/secret-path" not in caught.value.public_message


# --- the 405 for the standalone GET stream, with the Bearer route (Claude Code) ----------------


@pytest.fixture
def bearer_setup(app):
    app.config["PUBLIC_BASE_URL"] = "https://mcprack.example.com"
    with app.app_context():
        user = User(username="gina", auth_type="local")
        user.set_password("gina-long-password-1")
        server = McpServer(name="zabbix", label="Z", transport="stdio", command="/bin/true", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        raw, token = ApiToken.generate("claude-code", user.id, scopes=["proxy:access"])
        db.session.add(token)
        db.session.commit()
        return raw, server.id


def test_the_standalone_get_stream_is_a_405_for_a_bearer_client(app, bearer_setup):
    raw, server_id = bearer_setup

    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy") as ensure:
        response = app.test_client().get(f"/proxy/mcp/{server_id}", headers={"Authorization": f"Bearer {raw}"})

    assert response.status_code == 405
    assert set(response.headers["Allow"].split(", ")) == {"POST", "DELETE"}
    assert response.headers["Cache-Control"] == "no-store"
    ensure.assert_not_called()  # no process is started for a stream nobody needs


def test_an_unauthenticated_get_is_still_a_401_not_a_405(app, bearer_setup):
    """The 405 must not become a way to learn that a server id exists."""
    _, server_id = bearer_setup

    response = app.test_client().get(f"/proxy/mcp/{server_id}")

    assert response.status_code == 401
