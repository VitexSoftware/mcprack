import fcntl
import json
import threading
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


def test_spawn_raises_and_cleans_up_when_probe_fails(state_dir):
    with patch("mcprack.user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("mcprack.user_proxy._probe_upstream_health", return_value=False), \
         patch("mcprack.user_proxy._pid_running", return_value=False), \
         patch("mcprack.user_proxy._stop_pid"):
        with pytest.raises(user_proxy.UserProxyError, match="failed its startup handshake"):
            user_proxy.ensure_user_server_proxy(
                user_id=1, server_id=11, server_name="broken",
                command="/bin/broken-mcp", args=[], env={},
            )

    paths = user_proxy._paths(1, 11)
    assert not paths["pid"].exists()
    assert not paths["healthy_at"].exists()


def test_spawn_succeeds_and_records_healthy_at(state_dir):
    with patch("mcprack.user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("mcprack.user_proxy._probe_upstream_health", return_value=True), \
         patch("mcprack.user_proxy._pid_running", return_value=False):
        port = user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="ok",
            command="/bin/ok-mcp", args=[], env={},
        )

    assert isinstance(port, int)
    paths = user_proxy._paths(1, 11)
    assert paths["healthy_at"].exists()


def test_reuse_skips_reprobe_within_recheck_interval(state_dir):
    with patch("mcprack.user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("mcprack.user_proxy._probe_upstream_health", return_value=True) as mock_probe, \
         patch("mcprack.user_proxy._pid_running", return_value=False):
        user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="ok",
            command="/bin/ok-mcp", args=[], env={},
        )
    assert mock_probe.call_count == 1

    with patch("mcprack.user_proxy._pid_running", return_value=True), \
         patch("mcprack.user_proxy._probe_upstream_health") as mock_probe_2:
        port = user_proxy.ensure_user_server_proxy(
            user_id=1, server_id=11, server_name="ok",
            command="/bin/ok-mcp", args=[], env={},
        )
    mock_probe_2.assert_not_called()
    assert isinstance(port, int)


def test_reuse_reprobes_after_recheck_interval_and_restarts_on_failure(state_dir):
    with patch("mcprack.user_proxy.subprocess.Popen", return_value=_fake_proc()), \
         patch("mcprack.user_proxy._probe_upstream_health", return_value=True), \
         patch("mcprack.user_proxy._pid_running", return_value=False):
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
    with patch("mcprack.user_proxy._pid_running", return_value=True), \
         patch("mcprack.user_proxy._probe_upstream_health", side_effect=[False, False]), \
         patch("mcprack.user_proxy._stop_pid") as mock_stop, \
         patch("mcprack.user_proxy.subprocess.Popen", return_value=_fake_proc(pid=88888)):
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

    with patch("mcprack.user_proxy.subprocess.Popen", side_effect=fake_popen), \
         patch("mcprack.user_proxy._probe_upstream_health", return_value=True), \
         patch("mcprack.user_proxy._pid_running", side_effect=fake_pid_running):
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

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.getresponse.return_value = resp
        assert user_proxy._probe_upstream_health(12345) is False


def test_probe_treats_connection_failure_as_unhealthy():
    with patch("mcprack.user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.request.side_effect = ConnectionRefusedError()
        # Explicit short timeout -- the retry-on-refused loop runs for the
        # full timeout budget, and this only needs to prove it eventually
        # gives up, not exercise the real (now larger) HANDSHAKE_TIMEOUT.
        assert user_proxy._probe_upstream_health(12345, timeout=0.3) is False


def test_probe_treats_clean_result_as_healthy():
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = b'{"jsonrpc":"2.0","id":"mcprack-health-probe","result":{"protocolVersion":"2024-11-05"}}'

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.getresponse.return_value = resp
        assert user_proxy._probe_upstream_health(12345) is True


def test_probe_fails_open_on_non_json_body():
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = b"event: message\ndata: not-json\n\n"

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.getresponse.return_value = resp
        assert user_proxy._probe_upstream_health(12345) is True


def _docker_server(env_var_names=(), env_config=None, auth_env_key=None):
    server = MagicMock()
    server.install_method = "docker"
    server.env_var_names = list(env_var_names)
    server.env_config = env_config or {}
    server.auth_env_key = auth_env_key
    return server


def test_effective_args_noop_for_non_docker_server():
    server = MagicMock(install_method="pip")
    args = ["run", "--rm", "-i", "ghcr.io/org/foo:latest"]
    assert user_proxy._effective_args(server, args) == args


def test_effective_args_noop_when_server_is_none():
    args = ["/some/binary"]
    assert user_proxy._effective_args(None, args) == args


def test_effective_args_injects_e_flags_for_docker_server_env_vars():
    server = _docker_server(env_var_names=["API_TOKEN"], env_config={"BASE_URL": "https://x"})
    args = ["run", "--rm", "-i", "ghcr.io/org/foo:latest"]
    result = user_proxy._effective_args(server, args)

    assert result[:3] == ["run", "--rm", "-i"]
    assert result[-1] == "ghcr.io/org/foo:latest"
    flags = result[3:-1]
    assert "-e" in flags
    for name in ("API_TOKEN", "BASE_URL"):
        idx = flags.index(name)
        assert flags[idx - 1] == "-e"


def test_effective_args_includes_auth_env_key():
    server = _docker_server(auth_env_key="AUTH_TOKEN")
    result = user_proxy._effective_args(server, ["run", "--rm", "-i", "img"])
    assert "-e" in result and "AUTH_TOKEN" in result


def test_effective_args_reflects_env_vars_added_after_registration():
    """Docker env forwarding must be computed fresh at spawn time — adding
    an env var later (e.g. via the credentials form) must show up on the
    next spawn without touching stored args."""
    server = _docker_server(env_var_names=[])
    args = ["run", "--rm", "-i", "img"]
    assert "-e" not in user_proxy._effective_args(server, args)

    server.env_var_names = ["NEW_VAR"]
    result = user_proxy._effective_args(server, args)
    assert "NEW_VAR" in result


def _make_idle_instance(user_id, server_id, idle_seconds=10_000, pid=99999):
    paths = user_proxy._paths(user_id, server_id)
    paths["pid"].parent.mkdir(parents=True, exist_ok=True)
    paths["pid"].write_text(str(pid))
    paths["last_used"].write_text(str(time.time() - idle_seconds))
    return paths


def test_cleanup_stops_idle_proxy(state_dir):
    paths = _make_idle_instance(1, 11)
    with patch("mcprack.user_proxy._pid_running", return_value=True), \
         patch("mcprack.user_proxy._stop_pid") as stop_pid:
        user_proxy.cleanup_idle_proxies()

    stop_pid.assert_called_once_with(99999)
    assert paths["pid"].exists()


def test_cleanup_audit_entry_carries_server_name(state_dir):
    """Even when the McpServer row is gone by the time an idle proxy is
    reaped, the proxy_stop audit row must keep a readable name — the
    meta file written at spawn time is the only source left."""
    _make_idle_instance(1, 11)
    user_proxy._paths(1, 11)["meta"].write_text(
        json.dumps({"mcpServers": {"jenkins": {"type": "stdio"}}})
    )
    with patch("mcprack.user_proxy._pid_running", return_value=True), \
         patch("mcprack.user_proxy._stop_pid"), \
         patch("mcprack.user_proxy.audit.log_audit_event") as audit_log:
        user_proxy.cleanup_idle_proxies()

    audit_log.assert_called_once_with(
        "proxy_stop",
        "success",
        user_id=1,
        server_id=11,
        server_name="jenkins",
        error_message="idle timeout",
    )


def test_stop_server_proxies_stops_every_instance_of_that_server(state_dir):
    """Regression (magnymph incident 2026-10-17): deleting a server row
    while per-user proxy processes are still running left orphans whose
    later proxy_stop audit insert violated the dead server_id FK. The
    delete paths must stop every instance of that server first."""
    jenkins_u1 = _make_idle_instance(1, 11, idle_seconds=0)
    jenkins_u2 = _make_idle_instance(2, 11, idle_seconds=0)
    other = _make_idle_instance(1, 12, idle_seconds=0)
    for user_id, server_id in ((1, 11), (2, 11), (1, 12)):
        user_proxy._paths(user_id, server_id)["meta"].write_text(
            json.dumps({"mcpServers": {"jenkins" if server_id == 11 else "other": {"type": "stdio"}}})
        )

    with patch("mcprack.user_proxy._stop_pid") as stop_pid, \
         patch("mcprack.user_proxy.audit.log_audit_event") as audit_log:
        user_proxy.stop_server_proxies(11)

    assert stop_pid.call_count == 2
    for paths in (jenkins_u1, jenkins_u2):
        assert not paths["pid"].exists()
        assert not paths["meta"].exists()
    assert other["pid"].exists()
    assert audit_log.call_count == 2
    audit_log.assert_any_call(
        "proxy_stop", "success", user_id=1, server_id=11, server_name="jenkins"
    )


def test_cleanup_skips_busy_lock_without_raising_or_waiting(state_dir):
    """Regression test for the request-killer: cleanup used to wait up to
    LOCK_WAIT_TIMEOUT for a pair's lock (held for a whole cold-start
    handshake by another worker) and then raise UserProxyError straight
    out of every /proxy/mcp request. It must instead skip a busy pair
    immediately and leave it for the next round."""
    paths = _make_idle_instance(1, 11)
    lock_path = user_proxy._lock_path(1, 11)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with open(lock_path, "w") as other_worker_lock:
        fcntl.flock(other_worker_lock, fcntl.LOCK_EX)
        try:
            with patch("mcprack.user_proxy._pid_running", return_value=True), \
                 patch("mcprack.user_proxy._stop_pid") as stop_pid:
                started = time.monotonic()
                user_proxy.cleanup_idle_proxies()
                waited = time.monotonic() - started
        finally:
            fcntl.flock(other_worker_lock, fcntl.LOCK_UN)

    # Must skip instantly, not queue behind the (22s-worth-of) lock holder.
    assert waited < 2, f"cleanup blocked for {waited:.1f}s on a busy lock"
    stop_pid.assert_not_called()
    assert paths["pid"].exists()

    # And once the lock is free again, the next round collects it.
    with patch("mcprack.user_proxy._pid_running", return_value=True), \
         patch("mcprack.user_proxy._stop_pid") as stop_pid:
        user_proxy.cleanup_idle_proxies()

    stop_pid.assert_called_once_with(99999)


def test_proxy_request_survives_cleanup_failure(app):
    """A raising cleanup must not take the user's proxy request down:
    the request should continue to its own (here: 403 for a bogus
    token) response instead of turning into a 500."""
    from unittest.mock import patch as _patch

    with _patch("mcprack.catalog.user_proxy.cleanup_idle_proxies",
                side_effect=RuntimeError("boom")):
        resp = app.test_client().post("/proxy/mcp/not-a-real-token/5")

    assert resp.status_code == 403
