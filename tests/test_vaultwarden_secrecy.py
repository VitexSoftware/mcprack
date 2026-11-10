"""B-01 (docs/AUDIT-2026-11.md): the Vaultwarden session key must stay secret.

`bw` was called with `--session <key>` on its command line (visible in `ps`),
and every failure raised an exception whose text was the whole command line -
so the key reached the browser (flash message), the MCP client (JSON-RPC
error), the audit table, the logs and the monitoring endpoint.
"""

import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mcprack import secret_store, vaultwarden
from mcprack.extensions import db
from mcprack.models import AuditLogEntry, McpServer, User

SESSION = "SESSION-KEY-0123456789-SECRET"


def _proc(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


# --- the key never appears on a command line ----------------------------------


def _argv_and_env(calls):
    return [(call.args[0], call.kwargs.get("env", {})) for call in calls]


@pytest.mark.parametrize(
    "operation",
    [
        lambda: vaultwarden.get_notes(SESSION, "MCP-x"),
        lambda: vaultwarden.get_notes(SESSION, "MCP-x", item_id="abc"),
        lambda: vaultwarden.list_notes(SESSION),
        lambda: vaultwarden.set_notes(SESSION, "MCP-x", {"K": "v"}),
        lambda: vaultwarden.delete_item(SESSION, "MCP-x"),
    ],
)
def test_session_is_passed_in_the_environment_not_on_the_command_line(app, operation):
    with app.app_context(), patch("mcprack.vaultwarden.subprocess.run") as run:
        run.return_value = _proc(stdout='[{"id": "abc", "name": "MCP-x", "type": 2, "notes": "K=v"}]')
        try:
            operation()
        except Exception:  # some operations need a follow-up call's output; only the argv matters
            pass

    assert run.call_args_list, "bw was never called"
    for argv, env in _argv_and_env(run.call_args_list):
        assert SESSION not in " ".join(argv), argv
        assert "--session" not in argv
        assert env.get("BW_SESSION") == SESSION


# --- failures do not echo secrets ------------------------------------------------


def test_timeout_message_has_no_session(app):
    with app.app_context(), patch("mcprack.vaultwarden.subprocess.run") as run:
        run.side_effect = subprocess.TimeoutExpired(cmd=["bw"], timeout=12)
        with pytest.raises(vaultwarden.VaultwardenError) as caught:
            vaultwarden.list_notes(SESSION)

    assert SESSION not in str(caught.value)


def test_failure_message_hides_secrets_echoed_by_bw_itself(app):
    """If bw (or a wrapper) prints a secret in its own error, it is masked."""
    app.config["BW_PASSWORD"] = "master-password-123"
    with app.app_context(), patch("mcprack.vaultwarden.subprocess.run") as run:
        run.return_value = _proc(returncode=1, stderr=f"bad things {SESSION} and master-password-123")
        with pytest.raises(vaultwarden.VaultwardenError) as caught:
            vaultwarden.list_notes(SESSION)

    assert SESSION not in str(caught.value)
    assert "master-password-123" not in str(caught.value)


def test_public_error_is_generic_for_vaultwarden_failures(app):
    with app.app_context():
        generic = secret_store.public_error(vaultwarden.VaultwardenError("bw get notes MCP-x failed: connect 10.1.2.3:443"))
        assert "10.1.2.3" not in generic
        assert "MCP-x" not in generic
        # other messages (e.g. the env policy's) are meant for the user
        assert secret_store.public_error(secret_store.SecretStoreError("pick another name")) == "pick another name"


# --- end to end: what the user sees ---------------------------------------------


def _fake_bw_that_times_out_after_unlock():
    def fake(cmd, **kw):
        args = cmd[1:]
        if args[:1] in (["config"], ["lock"]):
            return _proc()
        if args[:1] == ["status"]:
            return _proc(stdout='{"status":"locked"}')
        if args[:1] == ["unlock"]:
            return _proc(stdout=SESSION)
        raise subprocess.TimeoutExpired(cmd, 8)

    return fake


def _user_and_server(app, client):
    with app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("pw")
        server = McpServer(name="demo", label="Demo", transport="stdio", command="/bin/true",
                           enabled=True, allow_user_override=True)
        db.session.add_all([user, server])
        db.session.commit()
        server_id = server.id
    client.post("/login", data={"username": "alice", "password": "pw"})
    return server_id


def test_saving_a_credential_while_bw_times_out_shows_no_session_key(app, client):
    server_id = _user_and_server(app, client)

    with patch("mcprack.vaultwarden.subprocess.run", side_effect=_fake_bw_that_times_out_after_unlock()):
        resp = client.post(
            f"/override/{server_id}",
            data={"env_editor": "1", "env_key__a": "API_TOKEN", "env_value__a": "v"},
            follow_redirects=True,
        )

    page = resp.get_data(as_text=True)
    assert SESSION not in page
    assert "Could not save your credentials" in page


def test_api_error_for_a_user_shows_no_session_key_or_internals(app, client):
    server_id = _user_and_server(app, client)

    with patch("mcprack.vaultwarden.subprocess.run", side_effect=_fake_bw_that_times_out_after_unlock()):
        resp = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": {"API_TOKEN": "v"}})

    assert resp.status_code == 502
    assert SESSION not in resp.get_data(as_text=True)


def test_audit_entries_never_contain_the_session_key(app):
    class FakeServer:
        id = None
        name = "demo"
        vault_item = "MCP-demo"
        vault_item_id = None

    with app.app_context(), patch("mcprack.vaultwarden.subprocess.run") as run:
        run.side_effect = subprocess.TimeoutExpired(cmd=["bw"], timeout=12)
        # get_notes tolerates a failing `get` (check=False) but a timeout raises
        with pytest.raises(vaultwarden.VaultwardenError):
            vaultwarden.resolve_env_layers(SESSION, FakeServer(), user=None)

        entries = AuditLogEntry.query.all()

    assert entries
    assert all(SESSION not in (e.error_message or "") for e in entries)
