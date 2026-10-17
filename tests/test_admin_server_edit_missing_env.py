import html
import json
import re
from unittest import mock

from mcprack import secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def _initial_rows(body):
    match = re.search(r"data-initial='([^']*)'", body)
    assert match, "env rows container not rendered"
    return json.loads(html.unescape(match.group(1)))


def _make_server(app):
    with app.app_context():
        server = McpServer(name="mail-box", label="Mail box", transport="stdio", command="/bin/true")
        server.env_config = {"MCP_EMAIL_SERVER_IMAP_HOST": "mail.example.com"}
        server.env_var_names = ["MCP_EMAIL_SERVER_PASSWORD"]
        server.required_env_keys = ["MCP_EMAIL_SERVER_PASSWORD"]
        db.session.add(server)
        db.session.commit()
        return server.id


def test_edit_form_lists_declared_secret_without_stored_value(app, client):
    _login_admin(client)
    server_id = _make_server(app)

    with mock.patch.object(secret_store, "load_server_secrets", return_value={}):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    assert resp.status_code == 200
    rows = {r["key"]: r for r in _initial_rows(resp.get_data(as_text=True))}
    row = rows["MCP_EMAIL_SERVER_PASSWORD"]
    assert row["value"] == ""
    assert row["sensitive"] is True
    assert row["required"] is True


def test_edit_form_does_not_duplicate_secret_that_has_a_value(app, client):
    _login_admin(client)
    server_id = _make_server(app)

    with mock.patch.object(
        secret_store, "load_server_secrets", return_value={"MCP_EMAIL_SERVER_PASSWORD": "s3cret"}
    ):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    keys = [r["key"] for r in _initial_rows(resp.get_data(as_text=True))]
    assert keys.count("MCP_EMAIL_SERVER_PASSWORD") == 1


def test_edit_form_adds_no_placeholders_when_secret_backend_fails(app, client):
    _login_admin(client)
    server_id = _make_server(app)

    with mock.patch.object(
        secret_store, "load_server_secrets", side_effect=secret_store.SecretStoreError("down")
    ):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    keys = [r["key"] for r in _initial_rows(resp.get_data(as_text=True))]
    assert "MCP_EMAIL_SERVER_PASSWORD" not in keys


def test_edit_form_lists_required_rows_first(app, client):
    """Required items must lead the env editor so the admin immediately
    sees what blocks the server from starting, before optional rows."""
    _login_admin(client)
    server_id = _make_server(app)

    with mock.patch.object(
        secret_store, "load_server_secrets", return_value={"MCP_EMAIL_SERVER_PASSWORD": "s3cret"}
    ):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    keys = [r["key"] for r in _initial_rows(resp.get_data(as_text=True))]
    assert keys.index("MCP_EMAIL_SERVER_PASSWORD") < keys.index("MCP_EMAIL_SERVER_IMAP_HOST")


def test_env_rows_from_form_sorts_required_first():
    from mcprack import admin

    rows = admin._env_rows_from_form(
        {
            "env_key__a": "MCP_OPTIONAL",
            "env_value__a": "x",
            "env_key__b": "MCP_PASSWORD",
            "env_value__b": "y",
            "env_required__b": "on",
        }
    )
    assert [r["key"] for r in rows] == ["MCP_PASSWORD", "MCP_OPTIONAL"]
    assert rows[0]["required"] is True
    assert rows[1]["required"] is False
