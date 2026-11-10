"""B-10 (docs/AUDIT-2026-11.md): reading credentials back in clear text is
audited - who, which server - and the values never reach the audit row."""

import pytest

from mcprack import secret_store
from mcprack.extensions import db
from mcprack.models import AuditLogEntry, McpServer, User, UserServerOverride

PW = "admin-long-password-1"
SECRET = "S3CR3T-TOKEN-VALUE"
OVERRIDE_SECRET = "USER-OWN-SECRET-VALUE"


@pytest.fixture
def setup(app, client):
    app.config["BW_SERVER"] = ""  # local encrypted store
    with app.app_context():
        admin = User(username="root", auth_type="local", is_admin=True)
        admin.set_password(PW)
        user = User(username="dave", auth_type="local")
        user.set_password("dave-long-password-1")
        server = McpServer(name="zabbix", label="Z", transport="stdio", command="/bin/true", enabled=True,
                           allow_user_override=True)
        db.session.add_all([admin, user, server])
        db.session.commit()
        server.env_var_names = ["ZABBIX_TOKEN"]
        db.session.commit()
        secret_store.save_server_secrets(server, {"ZABBIX_TOKEN": SECRET})
        secret_store.save_user_override(server, user, {}, {"ZABBIX_TOKEN": OVERRIDE_SECRET})
        db.session.commit()
        ids = {"admin": admin.id, "user": user.id, "server": server.id}
    client.post("/login", data={"username": "root", "password": PW})
    return ids


def _entries(app):
    with app.app_context():
        return [
            (row.action, row.user_id, row.server_id, row.error_message or "")
            for row in AuditLogEntry.query.filter_by(action="credential_access").all()
        ]


def test_revealing_server_secrets_over_the_api_is_audited(app, client, setup):
    response = client.get(f"/api/v1/admin/servers/{setup['server']}?reveal_secrets=1")

    assert response.get_json()["data"]["secrets"]["ZABBIX_TOKEN"] == SECRET
    entries = _entries(app)
    assert any(user == setup["admin"] and server == setup["server"] and "reveal_secrets" in note
               for _, user, server, note in entries), entries
    assert all(SECRET not in note for *_, note in entries)  # who and what - never the value


def test_looking_at_a_server_without_revealing_is_not_a_credential_access(app, client, setup):
    client.get(f"/api/v1/admin/servers/{setup['server']}")

    assert _entries(app) == []


def test_revealing_another_users_override_is_audited(app, client, setup):
    response = client.get(f"/api/v1/admin/users/{setup['user']}/overrides/{setup['server']}?reveal=1")

    assert response.get_json()["data"]["env"]["ZABBIX_TOKEN"] == OVERRIDE_SECRET
    entries = _entries(app)
    assert any(f"user #{setup['user']}" in note and user == setup["admin"] for _, user, _, note in entries), entries
    assert all(OVERRIDE_SECRET not in note for *_, note in entries)


def test_listing_override_key_names_only_is_not_audited(app, client, setup):
    client.get(f"/api/v1/admin/users/{setup['user']}/overrides/{setup['server']}")

    assert _entries(app) == []


def test_the_admin_edit_form_showing_secrets_is_audited(app, client, setup):
    response = client.get(f"/admin/servers/{setup['server']}/edit")

    assert response.status_code == 200
    entries = _entries(app)
    assert any("edit form" in note and user == setup["admin"] for _, user, _, note in entries), entries
    assert all(SECRET not in note for *_, note in entries)


def test_a_failing_reveal_does_not_leak_the_backend_error(app, client, setup):
    from unittest.mock import patch

    from mcprack import vaultwarden

    # What Vaultwarden failures really look like: the message carries the whole
    # `bw` command line, session key included.
    with patch("mcprack.api.secret_store.load_server_secrets",
               side_effect=vaultwarden.VaultwardenError("bw get item --session KEY123 failed")):
        response = client.get(f"/api/v1/admin/servers/{setup['server']}?reveal_secrets=1")

    assert "KEY123" not in response.get_data(as_text=True)
