"""`mcprack user config verify` and the probe behind it (audit goal 3: prove the
generated Claude Code configuration works, end to end)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcprack import probe
from mcprack.extensions import db
from mcprack.models import ApiToken, AuditLogEntry, McpServer, User, UserServerSelection

TOKEN = "mcr_secret-token-value"


def _rpc(request_id, result=None, error=None):
    body = {"jsonrpc": "2.0", "id": request_id}
    body["error" if error else "result"] = error or result
    return json.dumps(body).encode()


def _transport(script):
    """A transport that answers from `script` ((status, headers, body) per call)
    and records what it was sent."""
    calls = []

    def transport(url, payload, headers, timeout):
        calls.append({"url": url, "payload": payload, "headers": headers})
        answer = script[min(len(calls) - 1, len(script) - 1)]
        if isinstance(answer, Exception):
            raise answer
        return answer

    transport.calls = calls
    return transport


INIT_OK = (200, {"Mcp-Session-Id": "sess-1"}, _rpc(1, {"protocolVersion": "2025-06-18", "capabilities": {}}))
INITIALIZED = (202, {}, b"")
TOOLS_OK = (200, {}, _rpc(2, {"tools": [{"name": "a"}, {"name": "b"}]}))


# --- the probe, with a scripted transport -------------------------------------------------------


def test_a_healthy_server_is_verified_and_the_negotiated_version_is_reported():
    transport = _transport([INIT_OK, INITIALIZED, TOOLS_OK])

    result = probe.probe("https://m.example/proxy/mcp/3", bearer=TOKEN, transport=transport)

    assert result.ok and result.tools == 2 and result.protocol == "2025-06-18"
    assert [c["payload"].get("method") for c in transport.calls] == ["initialize", "notifications/initialized", "tools/list"]
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert transport.calls[2]["headers"]["Mcp-Session-Id"] == "sess-1"  # the session is carried on


def test_an_sse_answer_is_read_like_json():
    sse = b"event: message\ndata: " + _rpc(1, {"protocolVersion": "2025-06-18"}) + b"\n\n"
    sse2 = b": ping\n\nevent: message\ndata: " + _rpc(2, {"tools": [{"name": "t"}]}) + b"\n\n"

    result = probe.probe("https://m.example/x", transport=_transport([(200, {}, sse), INITIALIZED, (200, {}, sse2)]))

    assert result.ok and result.tools == 1


@pytest.mark.parametrize(
    "answer,step,fragment",
    [
        ((401, {}, b""), "initialize", "credential was not accepted"),
        ((405, {}, b""), "initialize", "does not accept POST"),
        ((307, {"Location": "https://elsewhere.example/"}, b""), "initialize", "redirect"),
        ((502, {}, _rpc(1, error={"code": -32000, "message": "Upstream exited early"})), "initialize", "Upstream exited early"),
        ((200, {}, _rpc(1, error={"code": -32602, "message": "bad version"})), "initialize", "bad version"),
        ((502, {}, b"<html>Bad Gateway</html>"), "initialize", "HTTP 502"),
        ((200, {}, b"not json"), "initialize", "no JSON-RPC answer"),
    ],
)
def test_each_way_initialize_can_fail_is_named(answer, step, fragment):
    result = probe.probe("https://m.example/x", transport=_transport([answer]))

    assert not result.ok and result.step == step and fragment in result.detail


def test_a_server_without_tools_is_not_healthy():
    result = probe.probe("https://m.example/x", transport=_transport([INIT_OK, INITIALIZED, (200, {}, _rpc(2, {"tools": []}))]))

    assert not result.ok and "no tools" in result.detail and result.protocol == "2025-06-18"


def test_a_failing_tools_list_is_named():
    result = probe.probe(
        "https://m.example/x",
        transport=_transport([INIT_OK, INITIALIZED, (200, {}, _rpc(2, error={"code": -1, "message": "backend closed"}))]),
    )

    assert not result.ok and result.step == "tools/list" and "backend closed" in result.detail


def test_a_connection_failure_is_a_result_not_an_exception():
    import urllib.error

    result = probe.probe("https://m.example/x", transport=_transport([urllib.error.URLError("connection refused")]))

    assert not result.ok and "could not connect" in result.detail and "connection refused" in result.detail


def test_text_from_the_server_is_made_printable():
    hostile = _rpc(1, error={"code": 1, "message": "\x1b]0;pwned\x07\x1b[2Jboom"})

    result = probe.probe("https://m.example/x", transport=_transport([(200, {}, hostile)]))

    assert "\x1b" not in result.detail and "\x07" not in result.detail


def test_the_token_never_crosses_plain_http_to_a_remote_host():
    transport = _transport([INIT_OK])

    result = probe.probe("http://mcprack.lan:8912/proxy/mcp/3", bearer=TOKEN, transport=transport)

    assert not result.ok and "plain http" in result.detail
    assert transport.calls == []  # nothing was sent
    assert TOKEN not in result.detail
    assert probe.probe("http://mcprack.lan:8912/x", bearer=TOKEN, allow_insecure=True, transport=_transport([INIT_OK, INITIALIZED, TOOLS_OK])).ok


def test_a_credential_in_the_url_is_protected_the_same_way():
    """The older client formats carry the signed token in the path
    (/proxy/mcp/<token>/<id>). With no Authorization header at all, that URL is
    still the credential and must not cross plain http either."""
    transport = _transport([INIT_OK])
    url = "http://mcprack.lan:8912/proxy/mcp/PATH-TOKEN-VALUE/3"

    result = probe.probe(url, transport=transport)  # no bearer

    assert not result.ok and "plain http" in result.detail and "URL itself" in result.detail
    assert transport.calls == [] and "PATH-TOKEN-VALUE" not in result.detail
    assert probe.probe(url, allow_insecure=True, transport=_transport([INIT_OK, INITIALIZED, TOOLS_OK])).ok
    assert probe.probe("https://mcprack.lan/proxy/mcp/PATH-TOKEN-VALUE/3", transport=_transport([INIT_OK, INITIALIZED, TOOLS_OK])).ok


def test_loopback_http_is_fine():
    assert probe.probe("http://127.0.0.1:8912/x", bearer=TOKEN, transport=_transport([INIT_OK, INITIALIZED, TOOLS_OK])).ok


# --- the real transport against a local server --------------------------------------------------


class FakeMcp:
    def __init__(self, mode="ok", token=None):
        self.mode = mode
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                outer.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "method": body.get("method")})
                if outer.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", outer.location)
                    self.end_headers()
                    return
                if outer.mode == "broken":
                    answer = (502, _rpc(body.get("id"), error={"code": -32000, "message": "Upstream MCP server exited"}))
                elif body.get("method") == "initialize":
                    answer = (200, _rpc(body["id"], {"protocolVersion": "2025-06-18", "capabilities": {}}))
                elif body.get("method") == "tools/list":
                    answer = (200, _rpc(body["id"], {"tools": [{"name": "t1"}, {"name": "t2"}, {"name": "t3"}]}))
                else:
                    answer = (202, b"")
                self.send_response(answer[0])
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(answer[1])

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake():
    servers = []

    def make(**kwargs):
        server = FakeMcp(**kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def test_the_real_transport_verifies_a_server(fake):
    backend = fake()

    result = probe.probe(backend.url + "/proxy/mcp/3", bearer=TOKEN)

    assert result.ok and result.tools == 3
    assert {call["auth"] for call in backend.seen} == {f"Bearer {TOKEN}"}


def test_the_real_transport_never_follows_a_redirect_with_the_token(fake):
    elsewhere = fake()
    front = fake(mode="redirect")
    front.location = elsewhere.url + "/x"

    result = probe.probe(front.url + "/x", bearer=TOKEN)

    assert not result.ok and "redirect" in result.detail
    assert elsewhere.seen == []  # the other host never saw the token


# --- the command --------------------------------------------------------------------------------


@pytest.fixture
def carol(app):
    app.config["PUBLIC_BASE_URL"] = "https://mcprack.example.com"
    with app.app_context():
        user = User(username="carol", auth_type="local")
        user.set_password("carol-long-password-1")
        server = McpServer(name="zabbix", label="Z", transport="stdio", command="/bin/true", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        return {"user": user.id, "server": server.id}


def _verify(app, *args):
    return app.test_cli_runner().invoke(args=["user", "config", "verify", "carol", *args])


def _live_tokens(app):
    with app.app_context():
        return ApiToken.query.filter_by(name="cli-verify", revoked_at=None).count()


def test_verify_uses_a_temporary_token_and_removes_it(app, carol, fake):
    backend = fake()

    result = _verify(app, "claude-code", "--base-url", backend.url)

    assert result.exit_code == 0, result.output
    assert "OK    zabbix: 3 tool(s), protocol 2025-06-18" in result.output and "All 1 server(s) verified." in result.output
    auth = {call["auth"] for call in backend.seen}
    assert len(auth) == 1
    sent = auth.pop()
    assert sent.startswith("Bearer ") and "MCPRACK_TOKEN" not in sent and "${" not in sent
    assert sent.split(" ", 1)[1] not in result.output  # the token is not printed
    assert _live_tokens(app) == 0  # gone again
    with app.app_context():
        assert ApiToken.query.filter_by(name="cli-verify").count() == 0
        assert any("temporary verification token" in (row.error_message or "") for row in AuditLogEntry.query.filter_by(action="credential_access"))


def test_the_path_is_kept_when_the_origin_is_replaced(app, carol, fake):
    backend = fake()

    _verify(app, "claude-code", "--base-url", backend.url)

    assert {call["path"] for call in backend.seen} == {f"/proxy/mcp/{carol['server']}"}


def test_a_failing_server_fails_the_command_with_the_reason(app, carol, fake):
    backend = fake(mode="broken")

    result = _verify(app, "claude-code", "--base-url", backend.url)

    assert result.exit_code == 1
    assert "FAIL  zabbix: initialize: Upstream MCP server exited" in result.output and "1 of 1 server(s) failed." in result.output
    assert _live_tokens(app) == 0  # cleaned up on failure too


def test_formats_with_the_credential_in_the_url_need_no_token(app, carol, fake):
    backend = fake()

    result = _verify(app, "claude", "--base-url", backend.url)

    assert result.exit_code == 0, result.output
    assert {call["auth"] for call in backend.seen} == {None}  # the path token is the credential
    with app.app_context():
        assert ApiToken.query.count() == 0  # nothing was minted


def test_the_token_is_removed_even_if_the_probe_blows_up(app, carol, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(probe, "probe", explode)

    result = _verify(app, "claude-code", "--base-url", "http://127.0.0.1:9")

    assert result.exit_code != 0
    with app.app_context():
        assert ApiToken.query.filter_by(name="cli-verify").count() == 0


def test_the_server_filter_and_unknown_names(app, carol, fake):
    backend = fake()

    assert _verify(app, "claude-code", "--base-url", backend.url, "--server", "zabbix").exit_code == 0
    nothing = _verify(app, "claude-code", "--base-url", backend.url, "--server", "nope")

    assert nothing.exit_code != 0 and "matches --server" in nothing.output


def test_an_unknown_user_is_an_error(app, carol):
    result = app.test_cli_runner().invoke(args=["user", "config", "verify", "nobody"])

    assert result.exit_code != 0


def test_nothing_is_sent_over_plain_http_to_a_remote_origin(app, carol):
    result = _verify(app, "claude-code", "--base-url", "http://mcprack.lan:8912")

    assert result.exit_code == 1 and "plain http" in result.output
    assert _live_tokens(app) == 0


def test_the_path_token_formats_are_protected_too(app, carol):
    """`claude` puts the credential in the URL: no header, no minted token - and
    still nothing may cross plain http to a remote host."""
    result = _verify(app, "claude", "--base-url", "http://mcprack.lan:8912")

    assert result.exit_code == 1 and "plain http" in result.output
    assert "/proxy/mcp/" not in result.output  # the URL, i.e. the credential, is not echoed
