from unittest.mock import patch

import pytest

from mcprack import secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerOverride


def _server(**overrides):
    defaults = dict(
        name="jenkins",
        label="Jenkins",
        transport="http",
        url="https://jenkins.example.test/mcp",
        auth_header_name="Authorization",
        auth_env_key="AUTH_TOKEN",
        enabled=True,
    )
    defaults.update(overrides)
    server = McpServer(**defaults)
    db.session.add(server)
    db.session.commit()
    return server


def test_server_needs_secrets_false_for_plain_stdio(app):
    with app.app_context():
        server = _server(
            name="filesystem",
            transport="stdio",
            command="/bin/true",
            url=None,
            auth_header_name=None,
            auth_env_key=None,
        )
        assert secret_store.server_needs_secrets(server) is False


def test_server_needs_secrets_true_for_declared_env_var(app):
    with app.app_context():
        server = _server()
        server.env_var_names = ["SOME_TOKEN"]
        assert secret_store.server_needs_secrets(server) is True


def test_resolve_server_env_skips_vaultwarden_entirely_when_not_needed(app):
    with app.app_context():
        server = _server(
            name="filesystem",
            transport="stdio",
            command="/bin/true",
            url=None,
            auth_header_name=None,
            auth_env_key=None,
        )
        server.env_config = {"LOG_LEVEL": "debug"}
        db.session.commit()

        with patch("mcprack.secret_store.vaultwarden.session") as mock_session:
            env = secret_store.resolve_server_env(server)

        mock_session.assert_not_called()
        assert env == {"LOG_LEVEL": "debug"}


def test_resolve_server_env_merges_config_and_vaultwarden_secrets(app):
    with app.app_context():
        server = _server()
        server.env_config = {"REGION": "eu"}
        db.session.commit()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch("mcprack.secret_store.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret"}):
            env = secret_store.resolve_server_env(server)

        assert env == {"REGION": "eu", "AUTH_TOKEN": "secret"}


def test_resolve_server_env_caches_vaultwarden_lookup_within_ttl(app):
    with app.app_context():
        server = _server()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch(
                 "mcprack.secret_store.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret"}
             ) as mock_resolve_env:
            first = secret_store.resolve_server_env(server)
            second = secret_store.resolve_server_env(server)

        assert first == second == {"AUTH_TOKEN": "secret"}
        mock_resolve_env.assert_called_once()


def test_resolve_server_env_cache_expires_after_ttl(app):
    with app.app_context():
        app.config["BW_ENV_CACHE_TTL"] = 0.01
        server = _server()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch(
                 "mcprack.secret_store.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret"}
             ) as mock_resolve_env:
            secret_store.resolve_server_env(server)
            import time as _time

            _time.sleep(0.02)
            secret_store.resolve_server_env(server)

        assert mock_resolve_env.call_count == 2


def test_save_server_secrets_invalidates_cache(app):
    with app.app_context():
        server = _server()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch(
                 "mcprack.secret_store.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "old"}
             ) as mock_resolve_env, \
             patch("mcprack.secret_store.vaultwarden.set_notes"):
            secret_store.resolve_server_env(server)
            secret_store.save_server_secrets(server, {"AUTH_TOKEN": "new"})
            secret_store.resolve_server_env(server)

        assert mock_resolve_env.call_count == 2


def test_save_user_override_secrets_only_invalidates_that_users_cache(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True):
        server = _server(allow_user_override=True)
        alice = User(username="alice", auth_type="local")
        alice.set_password("pw")
        bob = User(username="bob", auth_type="local")
        bob.set_password("pw")
        db.session.add_all([alice, bob])
        db.session.commit()

        with patch("mcprack.secret_store.vaultwarden.session"), \
             patch(
                 "mcprack.secret_store.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret"}
             ) as mock_resolve_env:
            secret_store.resolve_server_env(server, user=alice)
            secret_store.resolve_server_env(server, user=bob)
            assert mock_resolve_env.call_count == 2

            with patch("mcprack.secret_store.vaultwarden.set_notes"):
                secret_store.save_user_override_secrets(server, alice, {"AUTH_TOKEN": "alice-secret"})

            secret_store.resolve_server_env(server, user=bob)
            assert mock_resolve_env.call_count == 2  # bob still cached

            secret_store.resolve_server_env(server, user=alice)
            assert mock_resolve_env.call_count == 3  # alice's cache was invalidated


def test_local_encryption_roundtrip(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _server()
        secret_store.save_server_secrets(server, {"AUTH_TOKEN": "topsecret"})
        db.session.commit()

        assert server.env_secrets_encrypted is not None
        assert "topsecret" not in server.env_secrets_encrypted

        loaded = secret_store.load_server_secrets(server)
        assert loaded == {"AUTH_TOKEN": "topsecret"}


def test_local_storage_refuses_insecure_default_secret_key(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _server()
        app.config["SECRET_KEY"] = secret_store.INSECURE_DEFAULT_SECRET_KEY
        try:
            with pytest.raises(secret_store.SecretStoreError):
                secret_store.save_server_secrets(server, {"AUTH_TOKEN": "x"})
        finally:
            app.config["SECRET_KEY"] = "test-secret"


def test_migrate_local_to_vaultwarden_moves_and_clears_local_copy(app):
    with app.app_context():
        server = _server()
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
            secret_store.save_server_secrets(server, {"AUTH_TOKEN": "topsecret"})
        db.session.commit()
        assert server.env_secrets_encrypted is not None

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch("mcprack.secret_store.vaultwarden.set_notes") as mock_set_notes:
            summary = secret_store.migrate_local_to_vaultwarden()

        mock_set_notes.assert_called_once()
        assert summary["failed"] == []
        assert len(summary["moved"]) == 1
        assert server.env_secrets_encrypted is None


def test_migrate_local_to_vaultwarden_keeps_local_copy_on_write_failure(app):
    with app.app_context():
        server = _server()
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
            secret_store.save_server_secrets(server, {"AUTH_TOKEN": "topsecret"})
        db.session.commit()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch(
                 "mcprack.secret_store.vaultwarden.set_notes",
                 side_effect=secret_store.vaultwarden.VaultwardenError("boom"),
             ):
            summary = secret_store.migrate_local_to_vaultwarden()

        assert summary["moved"] == []
        assert len(summary["failed"]) == 1
        assert server.env_secrets_encrypted is not None


def test_snapshot_vaultwarden_to_local_keeps_vaultwarden_copy(app):
    with app.app_context():
        server = _server()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session"), \
             patch("mcprack.secret_store.vaultwarden.set_notes") as mock_set_notes, \
             patch("mcprack.secret_store.vaultwarden.get_notes", return_value={"AUTH_TOKEN": "topsecret"}):
            summary = secret_store.snapshot_vaultwarden_to_local()

        mock_set_notes.assert_not_called()
        assert summary["failed"] == []
        assert server.env_secrets_encrypted is not None
        assert secret_store._decrypt(server.env_secrets_encrypted) == {"AUTH_TOKEN": "topsecret"}


def test_user_override_secrets_roundtrip_local(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _server(allow_user_override=True)
        user = User(username="alice", auth_type="local")
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()

        secret_store.save_user_override_secrets(server, user, {"AUTH_TOKEN": "user-secret"})
        db.session.commit()

        row = UserServerOverride.query.filter_by(user_id=user.id, server_id=server.id).first()
        assert row is not None
        assert row.env_secrets_encrypted is not None

        loaded = secret_store.load_user_override_secrets(server, user)
        assert loaded == {"AUTH_TOKEN": "user-secret"}

        secret_store.delete_user_override_secrets(server, user)
        db.session.commit()
        assert UserServerOverride.query.filter_by(user_id=user.id, server_id=server.id).first() is None
