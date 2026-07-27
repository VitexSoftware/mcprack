import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import user_proxy


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


def test_spawn_raises_and_cleans_up_when_probe_fails(state_dir):
    with patch("user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("user_proxy._probe_upstream_health", return_value=False), \
         patch("user_proxy._pid_running", return_value=False), \
         patch("user_proxy._stop_pid"):
        with pytest.raises(user_proxy.UserProxyError, match="failed its startup handshake"):
            user_proxy.ensure_user_server_proxy(
                user_id=1, server_id=11, server_name="broken",
                command="/bin/broken-mcp", args=[], env={},
            )

    paths = user_proxy._paths(1, 11)
    assert not paths["pid"].exists()
    assert not paths["healthy_at"].exists()


def test_spawn_succeeds_and_records_healthy_at(state_dir):
    with patch("user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("user_proxy._probe_upstream_health", return_value=True), \
         patch("user_proxy._pid_running", return_value=False):
        port = user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="ok",
            command="/bin/ok-mcp", args=[], env={},
        )

    assert isinstance(port, int)
    paths = user_proxy._paths(1, 11)
    assert paths["healthy_at"].exists()


def test_reuse_skips_reprobe_within_recheck_interval(state_dir):
    with patch("user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("user_proxy._probe_upstream_health", return_value=True) as mock_probe, \
         patch("user_proxy._pid_running", return_value=False):
        user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="ok",
            command="/bin/ok-mcp", args=[], env={},
        )
    assert mock_probe.call_count == 1

    with patch("user_proxy._pid_running", return_value=True), \
         patch("user_proxy._probe_upstream_health") as mock_probe_2:
        port = user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="ok",
            command="/bin/ok-mcp", args=[], env={},
        )
    mock_probe_2.assert_not_called()
    assert isinstance(port, int)


def test_reuse_reprobes_after_recheck_interval_and_restarts_on_failure(state_dir):
    with patch("user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("user_proxy._probe_upstream_health", return_value=True), \
         patch("user_proxy._pid_running", return_value=False):
        user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="flaky",
            command="/bin/flaky-mcp", args=[], env={},
        )

    paths = user_proxy._paths(1, 11)
    # Force the recorded health check to look stale.
    stale = time.time() - user_proxy.HEALTH_RECHECK_INTERVAL - 1
    paths["healthy_at"].write_text(str(stale))

    # First probe (of the "still running" instance) fails, triggering a
    # restart; the second probe (of the freshly respawned instance, inside
    # _spawn) also fails -> should raise, not hang or silently hand back a
    # broken port.
    with patch("user_proxy._pid_running", return_value=True), \
         patch("user_proxy._probe_upstream_health", side_effect=[False, False]), \
         patch("user_proxy._stop_pid") as mock_stop, \
         patch("user_proxy.subprocess.Popen", return_value=_fake_proc(pid=88888)):
        with pytest.raises(user_proxy.UserProxyError):
            user_proxy.ensure_user_server_proxy(
                user_id=1, server_id=11, server_name="flaky",
                command="/bin/flaky-mcp", args=[], env={},
            )
    mock_stop.assert_called()


def test_concurrent_requests_for_same_key_only_spawn_once(state_dir):
    """Regression test for GitHub issue #1: two near-simultaneous cold
    requests for the same (user, server) pair used to race past each
    other with no locking, and the loser's failure-cleanup would delete
    the still-alive winner's pid/meta/healthy_at files — producing 502s
    on every following request even while an already-warm session kept
    working fine. Under the per-key lock, only one caller should actually
    spawn; the rest must block, then see the freshly-healthy instance and
    reuse it."""
    paths = user_proxy._paths(1, 11)
    spawn_calls = []
    spawn_lock = threading.Lock()

    def fake_popen(*args, **kwargs):
        with spawn_lock:
            spawn_calls.append(len(spawn_calls) + 1)
        # Hold the "startup" window open to widen the race if the lock
        # doesn't actually serialize callers.
        time.sleep(0.2)
        return _fake_proc(pid=1000 + len(spawn_calls))

    def fake_pid_running(pid):
        return paths["pid"].exists()

    results = []
    errors = []

    def worker():
        try:
            results.append(
                user_proxy.ensure_user_server_proxy(
                    user_id=1, server_id=11, server_name="racey",
                    command="/bin/racey-mcp", args=[], env={},
                )
            )
        except Exception as exc:  # noqa: BLE001 - captured for assertion below
            errors.append(exc)

    with patch("user_proxy.subprocess.Popen", side_effect=fake_popen), \
         patch("user_proxy._probe_upstream_health", return_value=True), \
         patch("user_proxy._pid_running", side_effect=fake_pid_running):
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

    assert not errors, errors
    assert len(results) == 5
    assert len(set(results)) == 1
    assert len(spawn_calls) == 1
    assert paths["pid"].exists()
    assert paths["healthy_at"].exists()


def test_probe_treats_jsonrpc_error_as_unhealthy():
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = b'{"jsonrpc":"2.0","id":"mcprack-health-probe","error":{"code":-32000,"message":"Connection closed"}}'

    with patch("user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.getresponse.return_value = resp
        assert user_proxy._probe_upstream_health(12345) is False


def test_probe_treats_connection_failure_as_unhealthy():
    with patch("user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.request.side_effect = ConnectionRefusedError()
        assert user_proxy._probe_upstream_health(12345) is False


def test_probe_treats_clean_result_as_healthy():
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = b'{"jsonrpc":"2.0","id":"mcprack-health-probe","result":{"protocolVersion":"2024-11-05"}}'

    with patch("user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.getresponse.return_value = resp
        assert user_proxy._probe_upstream_health(12345) is True


def test_probe_fails_open_on_non_json_body():
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = b"event: message\ndata: not-json\n\n"

    with patch("user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.getresponse.return_value = resp
        assert user_proxy._probe_upstream_health(12345) is True
