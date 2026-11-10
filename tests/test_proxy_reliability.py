"""Reliability and diagnostics of MCP server start-up (docs/AUDIT-2026-11.md
B-12 / B-13): a recorded pid is never trusted blindly, children are reaped, and
a failed start says *which kind* of failure it was - with the log for the
administrator and without it for the end user."""

import json
import os
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from mcprack import catalog, user_proxy
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection

NO_SUCH_PID = 9_000_001  # above pid_max (4194304): never a real process


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "user-proxies"
    d.mkdir()
    monkeypatch.setattr(user_proxy, "STATE_DIR", d)
    return d


@pytest.fixture
def sleeper():
    """A real process whose command line carries the path given to it, like
    `fastmcp run <config>` does."""
    started = []

    def start(config_path):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", str(config_path)], start_new_session=True)
        started.append(proc)
        return proc

    yield start
    for proc in started:
        proc.kill()
        proc.wait()


# --- B-12: is this pid still our instance? ------------------------------------------------------


def test_a_process_started_from_the_config_is_recognised(state_dir, sleeper):
    config = state_dir / "u1-s2.json"
    proc = sleeper(config)
    deadline = time.monotonic() + 5
    while user_proxy._process_is_ours(proc.pid, config) is not True and time.monotonic() < deadline:
        time.sleep(0.02)  # until exec has replaced the forked image

    assert user_proxy._process_is_ours(proc.pid, config) is True
    assert user_proxy._process_is_ours(proc.pid, state_dir / "u9-s9.json") is False


def test_a_pid_that_does_not_exist_cannot_be_judged():
    assert user_proxy._process_is_ours(NO_SUCH_PID, "/x/u1-s2.json") is None


def test_a_recycled_pid_is_ignored(state_dir, caplog):
    """The pid file survived (crash, hard restart) and the number now belongs to
    an unrelated process - here: this very test runner."""
    (state_dir / "u1-s2.pid").write_text(str(os.getpid()))

    with caplog.at_level("WARNING", logger="mcprack.user_proxy"):
        assert user_proxy._read_pid(state_dir / "u1-s2.pid") is None

    assert "recycled pid" in caplog.text


def test_our_own_instance_is_still_found(state_dir, sleeper):
    config = state_dir / "u1-s2.json"
    proc = sleeper(config)
    (state_dir / "u1-s2.pid").write_text(str(proc.pid))
    deadline = time.monotonic() + 5
    while user_proxy._read_pid(state_dir / "u1-s2.pid") is None and time.monotonic() < deadline:
        time.sleep(0.02)

    assert user_proxy._read_pid(state_dir / "u1-s2.pid") == proc.pid


def test_a_pid_file_for_a_dead_process_is_returned_as_before(state_dir):
    """Nothing to contradict it - the callers' liveness check deals with it."""
    (state_dir / "u1-s2.pid").write_text(str(NO_SUCH_PID))

    assert user_proxy._read_pid(state_dir / "u1-s2.pid") == NO_SUCH_PID


def test_stopping_an_instance_never_signals_a_stranger(state_dir):
    """The consequence that matters: a stale pid file pointing at an unrelated
    process (of the same uid - gunicorn itself, say) must not get SIGTERM,
    SIGKILL, or a killpg()."""
    paths = user_proxy._paths(1, 2)
    paths["pid"].write_text(str(os.getpid()))
    paths["last_used"].write_text(str(time.time()))
    paths["port"].write_text("35001")

    with patch("mcprack.user_proxy.os.kill") as kill, patch("mcprack.user_proxy.os.killpg") as killpg:
        user_proxy.stop_user_server_proxy(1, 2)
        user_proxy.cleanup_idle_proxies(max_idle_seconds=0)

    kill.assert_not_called()
    killpg.assert_not_called()


def test_a_group_the_pid_does_not_lead_is_never_signalled(state_dir):
    with patch("mcprack.user_proxy._pid_running", side_effect=[True, False]), \
         patch("mcprack.user_proxy.os.getpgid", return_value=1), \
         patch("mcprack.user_proxy.os.killpg") as killpg, \
         patch("mcprack.user_proxy.os.kill") as kill:
        user_proxy._stop_pid(4242)

    killpg.assert_not_called()
    kill.assert_called_once_with(4242, 15)


def test_exited_children_are_reaped_instead_of_left_as_zombies():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    user_proxy._CHILDREN[proc.pid] = proc
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{proc.pid}/stat", "rb") as stat_file:
                if stat_file.read().rsplit(b")", 1)[1].split()[0] == b"Z":
                    break
        except OSError:
            break
        time.sleep(0.01)

    user_proxy._reap_children()

    assert proc.pid not in user_proxy._CHILDREN
    assert proc.returncode == 0  # wait()ed for: not a zombie any more
    assert not os.path.exists(f"/proc/{proc.pid}")


def test_a_running_child_is_kept_for_later(sleeper):
    proc = sleeper("/x/u1-s2.json")
    user_proxy._CHILDREN[proc.pid] = proc

    user_proxy._reap_children()

    assert proc.pid in user_proxy._CHILDREN
    user_proxy._CHILDREN.pop(proc.pid)


# --- B-13: which kind of failure? ---------------------------------------------------------------


def _probe(timeout=0.3, **kwargs):
    report = {}
    ok = user_proxy._probe_upstream_health(12345, timeout=timeout, report=report, **kwargs)
    return ok, report


def _answer(status=200, body=b"{}"):
    response = MagicMock()
    response.status = status
    response.read.return_value = body
    return response


def test_a_dead_process_is_reported_at_once_not_after_the_whole_timeout():
    """It will never bind its port: waiting 15 s to find that out only delays
    the answer, which is in its log."""
    proc = MagicMock()
    proc.poll.return_value = 3
    started = time.monotonic()

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.request.side_effect = ConnectionRefusedError()
        ok, report = _probe(timeout=30, proc=proc)

    assert ok is False
    assert report == {"kind": "exited_early", "detail": "exit status 3"}
    assert time.monotonic() - started < 2


def test_a_live_process_that_never_binds_is_a_timeout():
    proc = MagicMock()
    proc.poll.return_value = None

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.request.side_effect = ConnectionRefusedError()
        ok, report = _probe(proc=proc)

    assert ok is False and report["kind"] == "startup_timeout"


def test_an_accepted_connection_that_never_answers_is_a_timeout():
    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.getresponse.side_effect = TimeoutError()
        ok, report = _probe()

    assert ok is False and report["kind"] == "startup_timeout"


def test_a_jsonrpc_error_is_a_handshake_error_with_its_message():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "Connection closed"}}).encode()

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.getresponse.return_value = _answer(body=body)
        ok, report = _probe()

    assert ok is False
    assert report == {"kind": "handshake_error", "detail": "Connection closed"}


def test_an_http_error_with_a_non_json_body_is_an_http_error():
    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.getresponse.return_value = _answer(status=502, body=b"<html>Bad Gateway</html>")
        ok, report = _probe()

    assert ok is False
    assert report == {"kind": "http_error", "detail": "initialize returned HTTP 502"}


def test_a_connection_reset_is_unreachable():
    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.request.side_effect = ConnectionResetError("reset by peer")
        ok, report = _probe()

    assert ok is False and report["kind"] == "unreachable" and "reset by peer" in report["detail"]


@pytest.mark.parametrize(
    "probe_result,kind",
    [
        ((False, 0, "backend serves no tools (it probably crashed on startup)"), "no_tools"),
        ((False, 0, "tools/list timed out"), "tools_list_failed"),
    ],
)
def test_the_deep_check_distinguishes_no_tools_from_a_failing_listing(probe_result, kind):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn, \
         patch("mcprack.user_proxy.health.probe_tools", return_value=probe_result):
        conn.return_value.getresponse.return_value = _answer(body=body)
        ok, report = _probe(require_tools=True)

    assert ok is False and report["kind"] == kind


def test_a_healthy_instance_reports_nothing():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}).encode()

    with patch("mcprack.user_proxy.http.client.HTTPConnection") as conn:
        conn.return_value.getresponse.return_value = _answer(body=body)
        ok, report = _probe()

    assert ok is True and report == {}


# --- the failure the administrator and the user each get ------------------------------------------

LOG = "Traceback (most recent call last):\n  File \"/opt/secret-path/server.py\", line 3\nModuleNotFoundError: No module named 'lib_x'"


def _fail_start(state_dir, kind, detail="", popen_error=None):
    paths = user_proxy._paths(1, 2)
    paths["log"].parent.mkdir(parents=True, exist_ok=True)
    paths["log"].write_text(LOG)
    proc = MagicMock(pid=NO_SUCH_PID)
    proc.poll.return_value = 1 if kind == "exited_early" else None

    def fake_probe(port, report=None, **kwargs):
        report.update(kind=kind, detail=detail)
        return False

    popen = patch("mcprack.user_proxy.subprocess.Popen", side_effect=popen_error) if popen_error else \
        patch("mcprack.user_proxy.subprocess.Popen", return_value=proc)
    with popen, patch("mcprack.user_proxy._probe_upstream_health", side_effect=fake_probe), \
         patch("mcprack.user_proxy._pid_running", return_value=False), patch("mcprack.user_proxy._stop_pid"), \
         patch("mcprack.user_proxy._resolve_fastmcp_bin", return_value="/usr/bin/fastmcp"):
        with pytest.raises(user_proxy.UserProxyError) as caught:
            user_proxy.ensure_user_server_proxy(1, 2, "zabbix", "/bin/zbx", [], {})
    return caught.value, paths


@pytest.mark.parametrize(
    "kind,phrase",
    [
        ("startup_timeout", "never answered"),
        ("handshake_error", "initialize returned an error"),
        ("no_tools", "serves no tools"),
        ("tools_list_failed", "tools/list failed"),
        ("unreachable", "could not talk to it"),
    ],
)
def test_each_class_of_failure_has_its_own_message(state_dir, kind, phrase):
    error, paths = _fail_start(state_dir, kind, detail="x")

    assert error.kind == kind
    assert phrase in str(error)
    assert "failed its startup handshake" in str(error)
    assert not paths["pid"].exists()  # state cleaned up, so the next ensure() respawns


def test_the_administrator_sees_the_log_the_user_does_not(state_dir):
    error, _ = _fail_start(state_dir, "no_tools")

    assert "ModuleNotFoundError" in str(error)  # admin: log tail
    assert "/opt/secret-path" in str(error)
    assert "ModuleNotFoundError" not in error.public_message  # user: the class of failure only
    assert "/opt/secret-path" not in error.public_message
    assert "no tools" in error.public_message
    assert "administrator" in error.public_message  # ...and who to ask


def test_a_process_that_died_while_starting_carries_its_exit_status_and_log(state_dir):
    error, _ = _fail_start(state_dir, "exited_early", detail="exit status 1")

    assert error.kind == "exited_early"
    assert "exited early for zabbix (exit status 1)" in str(error)
    assert "No module named 'lib_x'" in str(error)


def test_a_process_that_cannot_even_be_launched_is_spawn_failed(state_dir):
    error, paths = _fail_start(state_dir, "x", popen_error=FileNotFoundError(2, "No such file or directory"))

    assert error.kind == "spawn_failed"
    assert "No such file or directory" in str(error)
    assert "No such file" not in error.public_message
    assert not paths["pid"].exists() and not paths["config"].exists()


def test_the_audit_entry_and_the_span_name_the_class(state_dir):
    with patch("mcprack.user_proxy.audit.log_audit_event") as audit:
        _fail_start(state_dir, "no_tools")

    error_entries = [call for call in audit.call_args_list if call.args[:2] == ("proxy_start", "error")]
    assert error_entries and error_entries[0].kwargs["error_message"].startswith("[no_tools] ")


# --- what the relay tells the end user ------------------------------------------------------------


def _relay_setup(app, client):
    with app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("alice-long-password-1")
        server = McpServer(name="zabbix", label="Z", transport="stdio", command="/bin/true", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        token = catalog._make_proxy_token(user.id, server.id)
        return token, server.id


def test_the_end_user_gets_the_class_of_failure_not_the_log(app, client, caplog):
    token, server_id = _relay_setup(app, client)
    error = user_proxy.UserProxyError(
        "Upstream MCP server 'zabbix' failed its startup handshake: it started but serves no tools\nLast log lines:\n" + LOG,
        kind="no_tools",
        public="The MCP server 'zabbix' started but serves no tools. Ask an administrator.",
    )

    with caplog.at_level("ERROR", logger="mcprack.catalog"), \
         patch.object(catalog.user_proxy, "ensure_user_server_proxy", side_effect=error):
        response = client.post(f"/proxy/mcp/{token}/{server_id}", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    body = response.get_data(as_text=True)
    assert "serves no tools" in body and "Ask an administrator" in body
    assert "ModuleNotFoundError" not in body and "/opt/secret-path" not in body
    assert "ModuleNotFoundError" in caplog.text  # the administrator still has all of it
    assert "no_tools" in caplog.text
