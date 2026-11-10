"""B-14 (docs/AUDIT-2026-11.md): bounds on what one slow, huge or numerous
backend can cost the worker - the size of a buffered answer, the time `dpkg`
may take, and how many MCP servers may be starting at once."""

import subprocess
import threading
from unittest.mock import MagicMock, patch

import pytest

from mcprack import appstream_icons, catalog, user_proxy


# --- a buffered answer has a size limit ---------------------------------------------------------


def _upstream(body=b"{}", content_length=None, content_type="application/json"):
    conn = MagicMock()
    upstream = conn.getresponse.return_value
    upstream.status = 200
    headers = {"Content-Type": content_type}
    if content_length is not None:
        headers["Content-Length"] = str(content_length)
    upstream.getheader.side_effect = lambda name, default=None: headers.get(name, default)
    upstream.getheaders.return_value = list(headers.items())
    upstream.read.return_value = body
    return conn, upstream


def _relay(app, conn):
    with app.test_request_context("/", method="POST", json={"jsonrpc": "2.0", "id": 5, "method": "tools/list"}):
        return catalog._relay_request(conn, "/mcp", server_name="big")


def test_an_answer_within_the_limit_is_passed_on(app):
    app.config["PROXY_MAX_RESPONSE_BYTES"] = 100
    conn, upstream = _upstream(body=b"x" * 100)

    response = _relay(app, conn)

    assert response.status_code == 200 and response.get_data() == b"x" * 100
    upstream.read.assert_called_once_with(101)  # asks for one byte more than allowed, to notice


def test_an_answer_over_the_limit_is_refused_not_buffered(app):
    app.config["PROXY_MAX_RESPONSE_BYTES"] = 100
    conn, _ = _upstream(body=b"x" * 101)

    response = _relay(app, conn)

    assert response.status_code == 502
    assert b"larger than this relay will pass on" in response.get_data()
    assert b'"id": 5' in response.get_data() or b'"id":5' in response.get_data()  # still a JSON-RPC answer for that request


def test_a_declared_huge_length_is_refused_before_reading(app):
    app.config["PROXY_MAX_RESPONSE_BYTES"] = 100
    conn, upstream = _upstream(body=b"never read", content_length=10**9)

    response = _relay(app, conn)

    assert response.status_code == 502
    upstream.read.assert_not_called()


def test_the_default_limit_is_generous_but_finite(app):
    assert catalog._PROXY_MAX_RESPONSE_BYTES == 16 * 1024 * 1024
    conn, upstream = _upstream()

    _relay(app, conn)

    upstream.read.assert_called_once_with(catalog._PROXY_MAX_RESPONSE_BYTES + 1)


def test_the_limit_does_not_touch_streamed_answers(app):
    app.config["PROXY_MAX_RESPONSE_BYTES"] = 10
    conn = MagicMock()
    upstream = conn.getresponse.return_value
    upstream.status = 200
    upstream.getheader.return_value = "text/event-stream"
    upstream.getheaders.return_value = [("Content-Type", "text/event-stream")]
    upstream.read1.side_effect = [b"data: " + b"x" * 500 + b"\n\n", b""]

    with app.test_request_context("/", method="POST", json={"id": 1}):
        response = catalog._relay_request(conn, "/mcp")

    assert response.status_code == 200 and response.is_streamed
    assert len(b"".join(response.response)) > 500  # a stream has no total size; idle time bounds it instead


# --- dpkg-query ---------------------------------------------------------------------------------


@pytest.fixture(autouse=False)
def fresh_dpkg_cache():
    appstream_icons._dpkg_cache.clear()
    yield
    appstream_icons._dpkg_cache.clear()


def test_dpkg_query_has_a_timeout_and_a_hang_is_not_an_error(fresh_dpkg_cache):
    with patch("mcprack.appstream_icons.subprocess.run", side_effect=subprocess.TimeoutExpired("dpkg-query", 5)) as run:
        assert appstream_icons._owning_package("/usr/bin/zbx") is None

    assert run.call_args.kwargs["timeout"] == appstream_icons._DPKG_TIMEOUT


def test_dpkg_answers_are_remembered_including_unknown(fresh_dpkg_cache):
    ok = MagicMock(returncode=0, stdout="zabbix-mcp-server: /usr/bin/zabbix-mcp\n")
    with patch("mcprack.appstream_icons.subprocess.run", return_value=ok) as run:
        assert appstream_icons._owning_package("/usr/bin/zabbix-mcp") == "zabbix-mcp-server"
        assert appstream_icons._owning_package("/usr/bin/zabbix-mcp") == "zabbix-mcp-server"
    assert run.call_count == 1

    with patch("mcprack.appstream_icons.subprocess.run", side_effect=subprocess.TimeoutExpired("dpkg-query", 5)) as run:
        assert appstream_icons._owning_package("/opt/odd/bin") is None
        assert appstream_icons._owning_package("/opt/odd/bin") is None  # a wedged dpkg is not asked again on every page view
    assert run.call_count == 1


def test_the_cache_expires(fresh_dpkg_cache, monkeypatch):
    ok = MagicMock(returncode=0, stdout="pkg: /usr/bin/x\n")
    with patch("mcprack.appstream_icons.subprocess.run", return_value=ok) as run:
        appstream_icons._owning_package("/usr/bin/x")
        key = "/usr/bin/x"
        stamp, package = appstream_icons._dpkg_cache[key]
        appstream_icons._dpkg_cache[key] = (stamp - appstream_icons._DPKG_CACHE_TTL - 1, package)
        appstream_icons._owning_package("/usr/bin/x")
    assert run.call_count == 2


# --- cold starts --------------------------------------------------------------------------------


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "up")
    return tmp_path / "up"


def _ensure():
    return user_proxy.ensure_user_server_proxy(1, 2, "zabbix", "/bin/zbx", [], {})


def test_when_every_slot_is_taken_the_next_cold_start_is_told_to_retry(state_dir, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    slots.acquire()  # another thread of this worker is already starting a server
    monkeypatch.setattr(user_proxy, "_COLD_START_SLOTS", slots)
    monkeypatch.setattr(user_proxy, "COLD_START_WAIT", 0.05)

    with patch("mcprack.user_proxy._spawn") as spawn, patch("mcprack.user_proxy._pid_running", return_value=False):
        with pytest.raises(user_proxy.UserProxyError) as caught:
            _ensure()

    spawn.assert_not_called()
    assert caught.value.kind == "busy"
    assert "try again" in caught.value.public_message


def test_a_slot_is_given_back_after_a_successful_start(state_dir, monkeypatch):
    slots = threading.BoundedSemaphore(2)
    monkeypatch.setattr(user_proxy, "_COLD_START_SLOTS", slots)

    with patch("mcprack.user_proxy._spawn"), patch("mcprack.user_proxy._pid_running", return_value=False):
        _ensure()

    assert slots.acquire(blocking=False) and slots.acquire(blocking=False)  # both slots free again


def test_a_slot_is_given_back_after_a_failed_start(state_dir, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(user_proxy, "_COLD_START_SLOTS", slots)

    with patch("mcprack.user_proxy._spawn", side_effect=user_proxy.UserProxyError("boom", kind="exited_early")), \
         patch("mcprack.user_proxy._pid_running", return_value=False):
        with pytest.raises(user_proxy.UserProxyError):
            _ensure()

    assert slots.acquire(blocking=False)  # not leaked: the next start can proceed


def test_a_slot_is_given_back_even_for_an_unexpected_error(state_dir, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(user_proxy, "_COLD_START_SLOTS", slots)

    with patch("mcprack.user_proxy._spawn", side_effect=RuntimeError("bug")), \
         patch("mcprack.user_proxy._pid_running", return_value=False):
        with pytest.raises(RuntimeError):
            _ensure()

    assert slots.acquire(blocking=False)


def test_the_default_allows_a_few_at_once_not_one_and_not_all():
    assert 1 < user_proxy.COLD_START_CONCURRENCY < 8  # a gthread worker has 8 threads
    assert user_proxy.COLD_START_WAIT < user_proxy.HANDSHAKE_TIMEOUT + 10
