"""Edge branches of the per-user override editor and its storage/API paths:
known-key rendering, duplicate rejection, cache behaviour of
resolve_server_envs, stale Vaultwarden item cleanup, and the admin/API
error responses."""

import contextlib
from unittest.mock import patch

from mcprack import catalog, secret_store, vaultwarden
from mcprack.extensions import db
from mcprack.models import (
    McpServer,
    User,
    UserServerOverride,
    UserServerSelection,
)


def _user(username="alice"):
    user = User(username=username, auth_type="local")
    user.set_password("alicepass")
    db.session.add(user)
    db.session.commit()
    return user


def _server(**kwargs):
    defaults = dict(name="demo", label="Demo", transport="stdio", command="/bin/true", enabled=True)
    defaults.update(kwargs)
    server = McpServer(**defaults)
    db.session.add(server)
    db.session.commit()
    return server


def _secret_server(**kwargs):
    defaults = dict(
        name="jenkins",
        label="Jenkins",
        transport="http",
        url="https://jenkins.example.test/mcp",
        auth_header_name="Authorization",
        auth_env_key="AUTH_TOKEN",
        enabled=True,
    )
    defaults.update(kwargs)
    server = McpServer(**defaults)
    db.session.add(server)
    db.session.commit()
    return server


# --- known keys -------------------------------------------------------------


def test_known_keys_render_choices_required_and_admin_flags(app):
    with app.app_context():
        server = _server(
            detected_env_vars=[
                {"name": "MODE", "description": "Run mode", "choices": ["fast", "slow"]},
                {"name": "VERBOSE", "choices": ["yes", "no"]},
            ],
            required_env_keys=["API_KEY"],
            env_config={"LOG_LEVEL": "info"},
            env_var_names=["TOKEN_X"],
        )
        keys = {k["key"]: k for k in catalog.get_server_known_keys(server)}

    assert keys["MODE"]["description"] == "Run mode (one of: fast, slow)"
    assert keys["VERBOSE"]["description"] == "one of: yes, no"
    assert keys["API_KEY"]["required"] is True
    assert keys["API_KEY"]["source"] == "required"
    assert keys["LOG_LEVEL"]["default"] == "info"
    assert keys["LOG_LEVEL"]["admin_defined"] is True
    assert keys["TOKEN_X"]["sensitive"] is True
    assert keys["TOKEN_X"]["admin_secret"] is True


def test_override_context_uses_stored_non_secret_values(app):
    with app.app_context():
        server = _server(env_config={"LOG_LEVEL": "info"})
        user = _user()
        with patch(
            "mcprack.catalog.secret_store.load_user_override",
            return_value=({"LOG_LEVEL": "trace"}, {"API_KEY": "s3cr3t"}),
        ):
            rows, _known_keys, has_override = catalog.get_user_override_context(server, user)

    by_key = {row["key"]: row for row in rows}
    assert by_key["LOG_LEVEL"]["value"] == "trace"
    assert by_key["API_KEY"]["value"] == "s3cr3t"
    assert has_override is True


def test_override_context_flashes_when_vaultwarden_fails(app):
    from flask import get_flashed_messages

    with app.test_request_context():
        server = _server(env_config={"LOG_LEVEL": "info"})
        user = _user()
        with patch(
            "mcprack.catalog.secret_store.load_user_override",
            side_effect=vaultwarden.VaultwardenError("vault down"),
        ):
            rows, _known_keys, has_override = catalog.get_user_override_context(server, user)
        messages = [message for _category, message in get_flashed_messages(with_categories=True)]

    assert has_override is False
    assert any("Vaultwarden" in message for message in messages)
    assert rows and all(row["value"] == "" for row in rows)


# --- form parsing -----------------------------------------------------------


def test_parse_user_override_form_skips_blank_rows(app):
    with app.app_context():
        server = _server()
        form = {
            "env_editor": "1",
            "env_key__1": "",
            "env_value__1": "ignored",
            "env_key__2": "LOG_LEVEL",
            "env_value__2": "debug",
        }
        non_secret, secret, error = catalog.parse_user_override_form(server, form)

    assert error is None
    assert non_secret == {"LOG_LEVEL": "debug"}
    assert secret == {}


def test_parse_user_override_form_rejects_duplicate_keys(app):
    with app.app_context():
        server = _server()
        form = {
            "env_editor": "1",
            "env_key__1": "MODE",
            "env_value__1": "fast",
            "env_key__2": "MODE",
            "env_value__2": "slow",
        }
        non_secret, secret, error = catalog.parse_user_override_form(server, form)

    assert non_secret == {} and secret == {}
    assert "Duplicate key 'MODE'" in error


def test_override_rows_from_form_masks_admin_secrets(app):
    with app.app_context():
        server = _server(env_var_names=["API_TOKEN"])
        form = {
            "env_key__1": "",
            "env_value__1": "x",
            "env_key__2": "API_TOKEN",
            "env_value__2": "",
        }
        rows = catalog.override_rows_from_form(server, form)

    assert len(rows) == 1
    assert rows[0]["key"] == "API_TOKEN"
    assert rows[0]["admin_value"] == "●●●●●●"
    assert rows[0]["is_admin_defined"] is True


# --- secret_store batch resolution ------------------------------------------


def test_user_override_configs_guard_clauses(app):
    with app.app_context():
        assert secret_store._user_override_configs(None, [1]) == {}
        user = _user()
        assert secret_store._user_override_configs(user, []) == {}


def test_resolve_server_envs_uses_cache_and_overrides_without_unlocking(app):
    with app.app_context():
        server = _secret_server()
        user = _user()
        db.session.add(
            UserServerOverride(user_id=user.id, server_id=server.id, env_config={"EXTRA": "1"})
        )
        db.session.commit()
        secret_store._set_cached_secrets(
            secret_store._env_cache_key(server, user), {"AUTH_TOKEN": "tok"}
        )
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), patch(
            "mcprack.secret_store.vaultwarden.unlock"
        ) as mock_unlock:
            results = secret_store.resolve_server_envs([server], user=user)

    mock_unlock.assert_not_called()
    env = results[server.id]
    assert env["AUTH_TOKEN"] == "tok"
    assert env["EXTRA"] == "1"


def test_resolve_server_envs_rechecks_cache_under_the_lock(app):
    with app.app_context():
        server = _secret_server()
        user = _user()
        key = secret_store._env_cache_key(server, user)

        @contextlib.contextmanager
        def fill_cache_on_entry():
            # another worker fills the cache while we wait for the lock
            secret_store._set_cached_secrets(key, {"AUTH_TOKEN": "late"})
            yield

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), patch(
            "mcprack.secret_store.vaultwarden._serialized",
            side_effect=lambda: fill_cache_on_entry(),
        ), patch("mcprack.secret_store.vaultwarden.unlock") as mock_unlock:
            results = secret_store.resolve_server_envs([server], user=user)

    mock_unlock.assert_not_called()
    assert results[server.id]["AUTH_TOKEN"] == "late"


def test_resolve_server_envs_falls_through_to_vaultwarden_when_cache_stays_empty(app):
    with app.app_context():
        server = _secret_server()
        user = _user()
        server_id, vault_item = server.id, server.vault_item
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), patch(
            "mcprack.secret_store.vaultwarden._serialized"
        ), patch("mcprack.secret_store.vaultwarden.unlock", return_value="sess"), patch(
            "mcprack.secret_store.vaultwarden.list_notes",
            return_value={vault_item: ("item-id", "AUTH_TOKEN=abc")},
        ), patch("mcprack.secret_store.vaultwarden.lock"):
            results = secret_store.resolve_server_envs([server], user=user)

    assert results[server_id]["AUTH_TOKEN"] == "abc"


def test_save_user_override_deletes_stale_vault_item_when_secrets_cleared(app):
    with app.app_context():
        server = _secret_server()
        user = _user()
        row = UserServerOverride(user_id=user.id, server_id=server.id, env_config={"A": "1"})
        db.session.add(row)
        db.session.commit()
        server_id, user_id, vault_item = server.id, user.id, server.vault_item
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), patch(
            "mcprack.secret_store.vaultwarden.session"
        ) as mock_session, patch(
            "mcprack.secret_store.vaultwarden.delete_item"
        ) as mock_delete:
            mock_session.return_value.__enter__.return_value = "sess"
            secret_store.save_user_override(server, user, {"A": "2"}, {})

    mock_delete.assert_called_once_with("sess", f"{vault_item}-user-{user.username}")
    # save_user_override does not commit (the caller does), so the mutated
    # row is the same identity-map instance we added
    assert row.env_config == {"A": "2"}
    assert row.env_secrets_encrypted is None


# --- admin form + API --------------------------------------------------------


def test_admin_override_form_rerenders_on_duplicate_keys(app, client):
    with app.app_context():
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("adminpass")
        db.session.add(admin)
        target = _user("alice")
        server = _server()
        db.session.commit()
        target_id, server_id = target.id, server.id

    client.post("/login", data={"username": "admin", "password": "adminpass"})
    resp = client.post(
        f"/admin/users/{target_id}/override/{server_id}",
        data={
            "env_editor": "1",
            "env_key__1": "MODE",
            "env_value__1": "fast",
            "env_key__2": "MODE",
            "env_value__2": "slow",
        },
    )
    assert resp.status_code == 200
    assert "Duplicate key" in resp.get_data(as_text=True)


def _login_user_with_overridable_server(app, client):
    with app.app_context():
        user = _user("alice")
        server = _server(allow_user_override=True)
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        server_id = server.id
    client.post("/login", data={"username": "alice", "password": "alicepass"})
    return server_id


def test_me_override_put_rejects_non_object_env(app, client):
    server_id = _login_user_with_overridable_server(app, client)
    resp = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": "not-an-object"})
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_request"


def test_me_override_put_maps_vaultwarden_failure_to_502(app, client):
    server_id = _login_user_with_overridable_server(app, client)
    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False), patch(
        "mcprack.secret_store.save_user_override",
        side_effect=vaultwarden.VaultwardenError("vault down"),
    ):
        resp = client.put(
            f"/api/v1/me/overrides/{server_id}", json={"env": {"LOG_LEVEL": "debug"}}
        )
    assert resp.status_code == 502
    assert resp.get_json()["error"]["code"] == "vaultwarden_unreachable"
