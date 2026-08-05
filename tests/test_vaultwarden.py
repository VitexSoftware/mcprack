import base64
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mcprack import vaultwarden


def _proc(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def test_get_notes_parses_key_value_lines(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.return_value = _proc(
                stdout="AUTH_TOKEN=abc123\n# a comment\n\nAPI_URL=https://example.test\n"
            )
            values = vaultwarden.get_notes("session-token", "MCP-jenkins")

    assert values == {"AUTH_TOKEN": "abc123", "API_URL": "https://example.test"}
    args = mock_run.call_args.kwargs
    called_argv = mock_run.call_args.args[0]
    assert "get" in called_argv and "notes" in called_argv and "MCP-jenkins" in called_argv
    assert args["timeout"] == 12.0


def test_get_notes_ignores_malformed_lines(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.return_value = _proc(stdout="not-a-kv-line\nOK=yes\n")
            values = vaultwarden.get_notes("session-token", "MCP-x")

    assert values == {"OK": "yes"}


def test_set_notes_creates_item_when_missing(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            # 1st call: list items -> empty list (item doesn't exist yet)
            # 2nd call: create item
            mock_run.side_effect = [
                _proc(stdout="[]"),
                _proc(stdout=""),
            ]
            vaultwarden.set_notes("session-token", "MCP-new", {"KEY": "value"})

        assert mock_run.call_count == 2
        create_call = mock_run.call_args_list[1]
        argv = create_call.args[0]
        assert "create" in argv and "item" in argv
        encoded_input = create_call.kwargs["input"]
        decoded = json.loads(base64.b64decode(encoded_input))
        assert decoded["name"] == "MCP-new"
        assert decoded["notes"] == "KEY=value"
        assert decoded["type"] == 2


def test_set_notes_edits_existing_item(app):
    existing_item = {"id": "item-123", "name": "MCP-jenkins", "notes": "OLD=1"}
    with app.app_context():
        with patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(stdout=json.dumps([{"id": "item-123", "name": "MCP-jenkins"}])),
                _proc(stdout=json.dumps(existing_item)),
                _proc(stdout=""),
            ]
            vaultwarden.set_notes("session-token", "MCP-jenkins", {"NEW": "2"})

        assert mock_run.call_count == 3
        edit_call = mock_run.call_args_list[2]
        argv = edit_call.args[0]
        assert "edit" in argv and "item-123" in argv
        decoded = json.loads(base64.b64decode(edit_call.kwargs["input"]))
        assert decoded["notes"] == "NEW=2"


def test_run_raises_vaultwarden_error_on_subprocess_timeout(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["bw", "status"], timeout=12)
            with pytest.raises(vaultwarden.VaultwardenError) as exc:
                vaultwarden._run(["status", "--raw"])

    assert "timed out" in str(exc.value)


def test_delete_item_noop_when_not_found(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.return_value = _proc(stdout="[]")
            vaultwarden.delete_item("session-token", "MCP-missing")

        # only the lookup call, no delete call issued
        assert mock_run.call_count == 1


def test_resolve_env_merges_override_over_default(app):
    class FakeServer:
        vault_item = "MCP-jenkins"

    class FakeUser:
        username = "carol"

    with app.app_context():
        with patch("mcprack.vaultwarden.get_notes") as mock_get_notes:
            mock_get_notes.side_effect = [
                {"AUTH_TOKEN": "default-token", "API_URL": "https://default.test"},
                {"AUTH_TOKEN": "carols-own-token"},
            ]
            merged = vaultwarden.resolve_env("session-token", FakeServer(), user=FakeUser())

    assert merged == {"AUTH_TOKEN": "carols-own-token", "API_URL": "https://default.test"}
    assert mock_get_notes.call_args_list[1].args[1] == "MCP-jenkins-user-carol"


def test_missing_credential_keys_flags_unset_hinted_vars(app):
    class FakeServer:
        url = None
        auth_env_key = None
        env_var_names = ["AUTH_TOKEN", "API_URL"]

    missing = vaultwarden.missing_credential_keys(FakeServer(), {"AUTH_TOKEN": "set"})
    assert missing == ["API_URL"]


def test_missing_credential_keys_includes_auth_env_key_when_url_set(app):
    class FakeServer:
        url = "http://example.test/mcp"
        auth_env_key = "AUTH_TOKEN"
        env_var_names = []

    missing = vaultwarden.missing_credential_keys(FakeServer(), {})
    assert missing == ["AUTH_TOKEN"]


def test_missing_credential_keys_ignores_auth_env_key_without_url():
    """A stdio server with no network endpoint has no remote auth header to
    check — auth_env_key is irrelevant until a url exists."""
    class FakeServer:
        url = None
        auth_env_key = "AUTH_TOKEN"
        env_var_names = []

    assert vaultwarden.missing_credential_keys(FakeServer(), {}) == []


def test_missing_credential_keys_empty_when_nothing_declared(app):
    class FakeServer:
        url = None
        auth_env_key = None
        env_var_names = []

    assert vaultwarden.missing_credential_keys(FakeServer(), {}) == []


def test_missing_credential_keys_empty_blank_value_counts_as_missing(app):
    class FakeServer:
        url = None
        auth_env_key = None
        env_var_names = ["AUTH_TOKEN"]

    assert vaultwarden.missing_credential_keys(FakeServer(), {"AUTH_TOKEN": ""}) == ["AUTH_TOKEN"]


def test_resolve_env_without_user_returns_defaults_only(app):
    class FakeServer:
        vault_item = "MCP-jenkins"

    with app.app_context():
        with patch("mcprack.vaultwarden.get_notes") as mock_get_notes:
            mock_get_notes.return_value = {"AUTH_TOKEN": "default-token"}
            merged = vaultwarden.resolve_env("session-token", FakeServer(), user=None)

    assert merged == {"AUTH_TOKEN": "default-token"}
    mock_get_notes.assert_called_once()


def _step_statuses(steps):
    return {s["key"]: s["status"] for s in steps}


def test_diagnose_all_checks_pass(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.os.path.isfile", return_value=True), \
             patch("mcprack.vaultwarden.os.access", return_value=True), \
             patch("mcprack.vaultwarden.health.check_http_reachable", return_value=True), \
             patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(),  # config server
                _proc(stdout='{"status":"unauthenticated"}'),  # status --raw
                _proc(returncode=0),  # login --apikey
                _proc(stdout="session-token-abc", returncode=0),  # unlock
                _proc(),  # lock
            ]
            steps = vaultwarden.diagnose()

    statuses = _step_statuses(steps)
    assert statuses == {
        "bw_binary": "ok",
        "bw_server_set": "ok",
        "bw_server_reachable": "ok",
        "bw_api_key_set": "ok",
        "bw_api_login": "ok",
        "bw_password_set": "ok",
        "bw_unlock": "ok",
    }


def test_diagnose_stops_at_missing_binary(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.os.path.isfile", return_value=False):
            steps = vaultwarden.diagnose()

    statuses = _step_statuses(steps)
    assert statuses["bw_binary"] == "fail"
    assert all(status == "skipped" for key, status in statuses.items() if key != "bw_binary")


def test_diagnose_stops_at_unreachable_server(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.os.path.isfile", return_value=True), \
             patch("mcprack.vaultwarden.os.access", return_value=True), \
             patch("mcprack.vaultwarden.health.check_http_reachable", return_value=False):
            steps = vaultwarden.diagnose()

    statuses = _step_statuses(steps)
    assert statuses["bw_binary"] == "ok"
    assert statuses["bw_server_set"] == "ok"
    assert statuses["bw_server_reachable"] == "fail"
    # everything after the first failure is skipped, even the purely
    # config-based checks that would otherwise pass on their own
    assert statuses["bw_api_key_set"] == "skipped"
    assert statuses["bw_api_login"] == "skipped"
    assert statuses["bw_password_set"] == "skipped"
    assert statuses["bw_unlock"] == "skipped"


def test_diagnose_reports_bad_api_credentials(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.os.path.isfile", return_value=True), \
             patch("mcprack.vaultwarden.os.access", return_value=True), \
             patch("mcprack.vaultwarden.health.check_http_reachable", return_value=True), \
             patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(),  # config server
                _proc(stdout='{"status":"unauthenticated"}'),  # status --raw
                _proc(returncode=1, stderr="Username or password is incorrect"),  # login fails
            ]
            steps = vaultwarden.diagnose()

    statuses = _step_statuses(steps)
    assert statuses["bw_server_reachable"] == "ok"
    assert statuses["bw_api_key_set"] == "ok"
    assert statuses["bw_api_login"] == "fail"
    assert statuses["bw_password_set"] == "skipped"
    assert statuses["bw_unlock"] == "skipped"
    login_step = next(s for s in steps if s["key"] == "bw_api_login")
    assert "incorrect" in login_step["detail"]


def test_diagnose_reports_bad_master_password(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.os.path.isfile", return_value=True), \
             patch("mcprack.vaultwarden.os.access", return_value=True), \
             patch("mcprack.vaultwarden.health.check_http_reachable", return_value=True), \
             patch("mcprack.vaultwarden.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(),  # config server
                _proc(stdout='{"status":"unlocked"}'),  # status --raw: already authenticated
                _proc(returncode=1, stderr="Master password is incorrect"),  # unlock fails
            ]
            steps = vaultwarden.diagnose()

    statuses = _step_statuses(steps)
    assert statuses["bw_api_login"] == "ok"
    assert statuses["bw_password_set"] == "ok"
    assert statuses["bw_unlock"] == "fail"
    unlock_step = next(s for s in steps if s["key"] == "bw_unlock")
    assert "incorrect" in unlock_step["detail"]


def test_session_unlocks_yields_and_locks(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.unlock", return_value="sess-token") as mock_unlock, \
             patch("mcprack.vaultwarden.lock") as mock_lock:
            with vaultwarden.session() as sess:
                assert sess == "sess-token"
                mock_unlock.assert_called_once()
                mock_lock.assert_not_called()
            mock_lock.assert_called_once_with("sess-token")


def test_session_locks_even_if_body_raises(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.unlock", return_value="sess-token"), \
             patch("mcprack.vaultwarden.lock") as mock_lock:
            with pytest.raises(RuntimeError):
                with vaultwarden.session():
                    raise RuntimeError("boom")
            mock_lock.assert_called_once_with("sess-token")


def test_session_propagates_unlock_failure_without_locking(app):
    with app.app_context():
        with patch("mcprack.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")), \
             patch("mcprack.vaultwarden.lock") as mock_lock:
            with pytest.raises(vaultwarden.VaultwardenError):
                with vaultwarden.session():
                    pass
            mock_lock.assert_not_called()


def test_session_serializes_across_concurrent_callers(app):
    """Two overlapping session() calls must not run their unlock/lock cycles
    concurrently — this is the fix for gunicorn workers racing each other's
    `bw lock` and yanking the vault out from under a still-in-flight
    request. Simulate overlap by having the first call's body attempt to
    acquire the same lock file non-blocking; it must fail while the first
    session is still open."""
    import fcntl

    with app.app_context():
        with patch("mcprack.vaultwarden.unlock", return_value="sess-token"), \
             patch("mcprack.vaultwarden.lock"):
            with vaultwarden.session():
                lock_path = vaultwarden._lock_file_path()
                with open(lock_path, "w") as probe:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

            # after the first session exits, the lock is free again
            with open(lock_path, "w") as probe:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_UN)


def test_session_lock_contention_fails_fast(app):
    import fcntl
    import threading
    import time

    with app.app_context():
        lock_path = vaultwarden._lock_file_path()
        current_app = app

    def hold_lock():
        with current_app.app_context():
            with open(lock_path, "w") as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                time.sleep(0.35)
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    holder = threading.Thread(target=hold_lock, daemon=True)
    holder.start()
    time.sleep(0.05)

    with app.app_context():
        app.config["BW_LOCK_TIMEOUT"] = 0.1
        with patch("mcprack.vaultwarden.unlock", return_value="sess-token"), patch("mcprack.vaultwarden.lock"):
            with pytest.raises(vaultwarden.VaultwardenError) as exc:
                with vaultwarden.session():
                    pass

    holder.join(timeout=1.0)
    assert "busy" in str(exc.value)
