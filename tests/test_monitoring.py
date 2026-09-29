import json
import time
from unittest.mock import patch

import pytest

from mcprack import health, monitoring, user_proxy
from mcprack.extensions import db
from mcprack.models import McpServer, User




def _server(**kw):
    server = McpServer(name="email", label="Email", transport="stdio", command="/bin/x", **kw)
    db.session.add(server)
    db.session.commit()
    return server


def _user():
    user = User(username="monitor")
    db.session.add(user)
    db.session.commit()
    return user


def test_endpoint_disabled_without_token(client):
    assert client.get("/health/servers").status_code == 404


def test_endpoint_requires_matching_bearer(app, client):
    app.config["MONITORING_TOKEN"] = "s3cret"
    assert client.get("/health/servers").status_code == 401
    assert client.get("/health/servers", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_endpoint_returns_snapshot(app, client):
    app.config["MONITORING_TOKEN"] = "s3cret"
    snap = {"servers": [], "total": 0, "failed": 0, "age_seconds": 3}
    with patch("mcprack.monitoring.get_snapshot", return_value=snap):
        resp = client.get("/health/servers", headers={"Authorization": "Bearer s3cret"})
    assert resp.status_code == 200
    assert resp.get_json()["failed"] == 0


def test_check_server_reports_zero_tools_as_failure(app):
    server, user = _server(), _user()
    with patch("mcprack.monitoring.user_proxy.ensure_user_server_proxy", return_value=4321), \
         patch("mcprack.monitoring.health.probe_tools", return_value=(False, 0, "backend serves no tools")):
        result = monitoring.check_server(server, user)
    assert result["ok"] is False
    assert result["tools"] == 0
    assert "no tools" in result["error"]


def test_check_server_reports_spawn_failure(app):
    server, user = _server(), _user()
    with patch(
        "mcprack.monitoring.user_proxy.ensure_user_server_proxy",
        side_effect=user_proxy.UserProxyError("failed its startup handshake"),
    ):
        result = monitoring.check_server(server, user)
    assert result["ok"] is False
    assert "startup handshake" in result["error"]


def test_check_server_healthy(app):
    server, user = _server(), _user()
    with patch("mcprack.monitoring.user_proxy.ensure_user_server_proxy", return_value=4321), \
         patch("mcprack.monitoring.health.probe_tools", return_value=(True, 18, None)):
        result = monitoring.check_server(server, user)
    assert (result["ok"], result["tools"]) == (True, 18)


def test_check_server_missing_required_env_is_unconfigured_not_failed(app):
    server, user = _server(required_env_keys_json='["IMAP_PASSWORD"]'), _user()
    with patch("mcprack.monitoring.user_proxy.ensure_user_server_proxy") as spawn:
        result = monitoring.check_server(server, user)
    spawn.assert_not_called()
    assert result["ok"] is None and result["error"] == "unconfigured"


def test_get_snapshot_is_pending_then_served_from_shared_file(app):
    app.config["MONITORING_USER_ID"] = 1
    with patch("mcprack.monitoring.threading.Thread") as thread:
        first = monitoring.get_snapshot(app)
        # A second worker asking while the first holds the flock must not
        # start another refresh.
        second = monitoring.get_snapshot(app)
    assert first["pending"] is True and second["pending"] is True
    thread.assert_called_once()

    path, _ = monitoring._snapshot_paths()
    path.write_text(json.dumps({"generated_at": time.time(), "servers": [], "total": 0, "failed": 0}))
    with patch("mcprack.monitoring.threading.Thread") as thread:
        cached = monitoring.get_snapshot(app)
    assert "pending" not in cached and cached["age_seconds"] >= 0
    thread.assert_not_called()


def _rpc(responses):
    """Fake health._send/probe HTTP layer: initialize then tools/list."""
    class Resp:
        def __init__(self, status, body, sid="sid"):
            self.status, self._b, self._sid = status, body.encode(), sid
        def read(self): return self._b
        def getheader(self, _): return self._sid
    it = iter(responses)
    class Conn:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): self.r = next(it)
        def getresponse(self): return self.r
        def close(self): pass
    return Conn, Resp


def test_probe_tools_empty_list_is_failure():
    _, Resp = _rpc([])
    init = Resp(200, '{"jsonrpc":"2.0","id":1,"result":{}}')
    lst = Resp(200, 'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n')
    Conn, _ = _rpc([init, lst])
    with patch("mcprack.health.http.client.HTTPConnection", Conn):
        ok, count, error = health.probe_tools("127.0.0.1", 1)
    assert (ok, count) == (False, 0)
    assert "no tools" in error


def test_probe_tools_counts_tools():
    _, Resp = _rpc([])
    init = Resp(200, '{"jsonrpc":"2.0","id":1,"result":{}}')
    lst = Resp(200, '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"},{"name":"b"}]}}')
    Conn, _ = _rpc([init, lst])
    with patch("mcprack.health.http.client.HTTPConnection", Conn):
        assert health.probe_tools("127.0.0.1", 1) == (True, 2, None)


def test_relay_flags_empty_tools_list():
    from mcprack.catalog import _is_empty_tools_list

    body = b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    assert _is_empty_tools_list(body, b'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n')
    assert not _is_empty_tools_list(body, b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}]}}')
    assert not _is_empty_tools_list(b'{"method":"initialize"}', b'{"result":{"tools":[]}}')
    assert not _is_empty_tools_list(body, b"not json")


def test_spawn_probe_requires_tools_when_asked():
    import json as _json

    body = _json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()

    class Resp:
        status = 200
        def read(self): return body

    class Conn:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): pass
        def getresponse(self): return Resp()
        def close(self): pass

    with patch("mcprack.user_proxy.http.client.HTTPConnection", Conn):
        with patch("mcprack.user_proxy.health.probe_tools", return_value=(False, 0, "no tools")):
            assert user_proxy._probe_upstream_health(1234, require_tools=True) is False
        with patch("mcprack.user_proxy.health.probe_tools", return_value=(True, 3, None)):
            assert user_proxy._probe_upstream_health(1234, require_tools=True) is True
        # Recheck path (no require_tools) must not pay for tools/list.
        with patch("mcprack.user_proxy.health.probe_tools") as deep:
            assert user_proxy._probe_upstream_health(1234) is True
        deep.assert_not_called()
