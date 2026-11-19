"""Cold-start behaviour of Vaultwarden secret resolution.

A client connecting opens all of its servers at once; each one is its own
proxied request needing credentials. Resolving them one `bw` round trip at a
time behind the single cross-process lock made the last requests in the
queue exceed BW_LOCK_TIMEOUT and fail with a 502 ("Vaultwarden is busy").
These tests pin the two remedies: one bulk lookup that warms the cache for
all of the user's selected servers, and serving an expired cache entry when
Vaultwarden cannot be asked at all.
"""

import time
from unittest.mock import patch

import pytest

from mcprack import secret_store, vaultwarden
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection


def _server(name, selected_by=None, **overrides):
    defaults = dict(
        name=name,
        label=name.title(),
        transport="stdio",
        command=f"/usr/bin/{name}-mcp",
        enabled=True,
    )
    defaults.update(overrides)
    server = McpServer(**defaults)
    server.env_var_names = ["TOKEN"]
    db.session.add(server)
    db.session.commit()
    if selected_by is not None:
        db.session.add(UserServerSelection(user_id=selected_by.id, server_id=server.id))
        db.session.commit()
    return server


def _user(username="alice"):
    user = User(username=username, auth_type="local")
    user.set_password("pw")
    db.session.add(user)
    db.session.commit()
    return user


def _vault_patches(notes=None, unlock_side_effect=None):
    return (
        patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True),
        patch("mcprack.secret_store.vaultwarden._serialized"),
        patch(
            "mcprack.secret_store.vaultwarden.unlock",
            return_value="sess",
            side_effect=unlock_side_effect,
        ),
        patch("mcprack.secret_store.vaultwarden.lock"),
        patch("mcprack.secret_store.vaultwarden.list_notes", return_value=notes or {}),
        patch("mcprack.secret_store.vaultwarden.resolve_env_layers"),
    )


def test_cold_miss_warms_the_cache_for_all_selected_servers_in_one_lookup(app):
    with app.app_context():
        user = _user()
        zabbix = _server("zabbix", selected_by=user)
        redmine = _server("redmine", selected_by=user)
        netbox = _server("netbox", selected_by=user)
        unselected = _server("graylog")
        disabled = _server("ipex", selected_by=user, enabled=False)
        notes = {
            zabbix.vault_item: ("id-z", "TOKEN=z"),
            redmine.vault_item: ("id-r", "TOKEN=r"),
            f"{netbox.vault_item}-user-{user.username}": ("id-n", "TOKEN=mine"),
        }

        is_cfg, ser, unlock, lock, list_notes, single = _vault_patches(notes)
        with is_cfg, ser, unlock as mock_unlock, lock, list_notes as mock_list, single as mock_single:
            first = secret_store.resolve_server_env(zabbix, user=user)
            # the requests that were queued behind the lock are now cache hits
            second = secret_store.resolve_server_env(redmine, user=user)
            third = secret_store.resolve_server_env(netbox, user=user)

        assert first["TOKEN"] == "z"
        assert second["TOKEN"] == "r"
        assert third["TOKEN"] == "mine"
        assert mock_unlock.call_count == 1
        assert mock_list.call_count == 1
        mock_single.assert_not_called()
        for skipped in (unselected, disabled):
            assert secret_store._get_cached_secrets(secret_store._env_cache_key(skipped, user)) is None
        # the item id learned from the bulk listing is persisted
        assert db.session.get(McpServer, zabbix.id).vault_item_id == "id-z"


def test_single_uncached_server_keeps_the_targeted_lookup(app):
    with app.app_context():
        user = _user()
        zabbix = _server("zabbix", selected_by=user)
        redmine = _server("redmine", selected_by=user)
        secret_store._set_cached_secrets(secret_store._env_cache_key(redmine, user), {"TOKEN": "r"})

        is_cfg, ser, unlock, lock, list_notes, single = _vault_patches()
        with is_cfg, ser, unlock, lock, list_notes as mock_list, single as mock_single:
            mock_single.return_value = ({"TOKEN": "z"}, {})
            env = secret_store.resolve_server_env(zabbix, user=user)

        assert env["TOKEN"] == "z"
        mock_list.assert_not_called()
        mock_single.assert_called_once()


def test_lock_timeout_serves_an_expired_cache_entry(app):
    with app.app_context():
        app.config["BW_ENV_CACHE_TTL"] = 0.01
        user = _user()
        zabbix = _server("zabbix", selected_by=user)
        secret_store._set_cached_secrets(secret_store._env_cache_key(zabbix, user), {"TOKEN": "old"})
        time.sleep(0.02)

        busy = vaultwarden.VaultwardenError("Vaultwarden is busy (lock wait exceeded 20.0s)")
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden._serialized", side_effect=busy):
            env = secret_store.resolve_server_env(zabbix, user=user)

        assert env["TOKEN"] == "old"


def test_lock_timeout_without_any_cache_entry_still_fails(app):
    with app.app_context():
        user = _user()
        zabbix = _server("zabbix", selected_by=user)

        busy = vaultwarden.VaultwardenError("Vaultwarden is busy (lock wait exceeded 20.0s)")
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden._serialized", side_effect=busy), \
             pytest.raises(vaultwarden.VaultwardenError):
            secret_store.resolve_server_env(zabbix, user=user)


def test_entry_past_the_stale_grace_is_not_served(app):
    with app.app_context():
        app.config["BW_ENV_CACHE_TTL"] = 0.01
        app.config["BW_ENV_CACHE_STALE_GRACE"] = 0.01
        user = _user()
        zabbix = _server("zabbix", selected_by=user)
        secret_store._set_cached_secrets(secret_store._env_cache_key(zabbix, user), {"TOKEN": "old"})
        time.sleep(0.05)

        busy = vaultwarden.VaultwardenError("Vaultwarden is busy (lock wait exceeded 20.0s)")
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden._serialized", side_effect=busy), \
             pytest.raises(vaultwarden.VaultwardenError):
            secret_store.resolve_server_env(zabbix, user=user)


def test_invalidated_entry_is_never_served_stale(app):
    """A secret write in mcprack drops the entry, so the fallback cannot
    hand out a value that was just changed or removed."""
    with app.app_context():
        user = _user()
        zabbix = _server("zabbix", selected_by=user)
        secret_store._set_cached_secrets(secret_store._env_cache_key(zabbix, user), {"TOKEN": "old"})
        secret_store._invalidate_cached_secrets(zabbix.id, user.id)

        busy = vaultwarden.VaultwardenError("Vaultwarden is busy (lock wait exceeded 20.0s)")
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden._serialized", side_effect=busy), \
             pytest.raises(vaultwarden.VaultwardenError):
            secret_store.resolve_server_env(zabbix, user=user)


def test_batch_resolution_falls_back_to_expired_entries(app):
    with app.app_context():
        app.config["BW_ENV_CACHE_TTL"] = 0.01
        user = _user()
        zabbix = _server("zabbix", selected_by=user)
        redmine = _server("redmine", selected_by=user)
        secret_store._set_cached_secrets(secret_store._env_cache_key(zabbix, user), {"TOKEN": "old"})
        time.sleep(0.02)

        busy = vaultwarden.VaultwardenError("Vaultwarden is busy (lock wait exceeded 20.0s)")
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden._serialized", side_effect=busy):
            results = secret_store.resolve_server_envs([zabbix, redmine], user=user)

        assert results[zabbix.id]["TOKEN"] == "old"
        assert isinstance(results[redmine.id], vaultwarden.VaultwardenError)


def test_entries_past_the_grace_are_pruned_on_write(app):
    with app.app_context():
        app.config["BW_ENV_CACHE_TTL"] = 0.01
        app.config["BW_ENV_CACHE_STALE_GRACE"] = 0.01
        secret_store._set_cached_secrets("1:1", {"TOKEN": "a"})
        time.sleep(0.05)
        secret_store._set_cached_secrets("2:1", {"TOKEN": "b"})

        assert set(secret_store._load_env_cache()) == {"2:1"}
