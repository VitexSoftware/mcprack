"""A-08 (docs/AUDIT-2026-11.md): which headers cross the relay.

The relay used to forward every request header except five - including the
caller's own `Authorization` (an mcprack OAuth/API token) - to whatever
backend the server points at, and copied every response header back. The MCP
spec says a server must not accept *or transit* tokens that were not issued
for it. Only protocol headers may pass; the backend's credential comes from
the server's own configuration.
"""

from unittest.mock import patch

from mcprack import catalog
from mcprack.models import McpServer


def _server(**kw):
    defaults = dict(name="remote", label="Remote", transport="http", url="http://10.1.2.3:3108/mcp", enabled=True)
    defaults.update(kw)
    return McpServer(**defaults)


def _relay(app, request_headers, server, env=None, upstream_headers=()):
    """Run one relayed request through a fake backend connection; returns
    (headers the backend received, the response mcprack produced)."""
    with app.test_request_context("/", method="POST", data=b"{}", headers=request_headers), \
         patch("mcprack.catalog.http.client.HTTPConnection") as conn_cls:
        conn = conn_cls.return_value
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = b"{}"
        conn.getresponse.return_value.getheaders.return_value = list(upstream_headers)

        response = catalog._forward_to_backend_url(server.url, env or {}, server)

        sent = conn.request.call_args.kwargs["headers"]
    return sent, response


CLIENT_HEADERS = {
    "Authorization": "Bearer mcprack-oauth-or-api-token",
    "Cookie": "session=abc",
    "X-Forwarded-For": "203.0.113.9",
    "X-Real-IP": "203.0.113.9",
    "X-Mcprack-Anything": "1",
    "Accept": "application/json, text/event-stream",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "Mcp-Session-Id": "sess-1",
    "Mcp-Protocol-Version": "2025-06-18",
    "Last-Event-ID": "7",
}


def _names(headers):
    return {name.lower() for name in headers}


def test_only_protocol_headers_reach_the_backend(app):
    sent, _ = _relay(app, CLIENT_HEADERS, _server())

    assert _names(sent) == {"accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id"}
    assert "mcprack-oauth-or-api-token" not in " ".join(sent.values())


def test_the_servers_own_credential_is_injected_and_the_callers_never_forwarded(app):
    server = _server(auth_header_name="Authorization", auth_env_key="SVC_TOKEN")

    sent, _ = _relay(app, CLIENT_HEADERS, server, env={"SVC_TOKEN": "Bearer backend-secret"})

    auth = [value for name, value in sent.items() if name.lower() == "authorization"]
    assert auth == ["Bearer backend-secret"]


def test_a_differently_cased_auth_header_cannot_sneak_the_callers_token_along(app):
    server = _server(auth_header_name="X-Api-Key", auth_env_key="SVC_TOKEN")
    headers = {**CLIENT_HEADERS, "x-api-key": "caller-chosen", "X-API-KEY": "caller-chosen-2"}

    sent, _ = _relay(app, headers, server, env={"SVC_TOKEN": "backend-secret"})

    values = [value for name, value in sent.items() if name.lower() == "x-api-key"]
    assert values == ["backend-secret"]


def test_no_credential_configured_means_no_authorization_header(app):
    sent, _ = _relay(app, CLIENT_HEADERS, _server())

    assert "authorization" not in _names(sent)


def test_unsafe_response_headers_are_not_copied_back(app):
    upstream = [
        ("Content-Type", "application/json"),
        ("Mcp-Session-Id", "s-123"),
        ("Cache-Control", "no-store"),
        ("Set-Cookie", "session=attacker; Path=/"),
        ("WWW-Authenticate", 'Bearer resource_metadata="https://evil.example/.well-known/x"'),
        ("Access-Control-Allow-Origin", "https://evil.example"),
        ("Content-Security-Policy", "default-src *"),
        ("Location", "https://evil.example/"),
        ("Strict-Transport-Security", "max-age=0"),
    ]

    _, response = _relay(app, CLIENT_HEADERS, _server(), upstream_headers=upstream)

    assert response.headers["Content-Type"].startswith("application/json")
    assert response.headers["Mcp-Session-Id"] == "s-123"
    assert response.headers["Cache-Control"] == "no-store"
    for dangerous in ("Set-Cookie", "WWW-Authenticate", "Access-Control-Allow-Origin", "Content-Security-Policy",
                      "Location", "Strict-Transport-Security"):
        assert dangerous not in response.headers, dangerous
