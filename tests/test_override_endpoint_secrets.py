"""A-09 (docs/AUDIT-2026-11.md): a user must not be able to point a server at
an endpoint of their choosing while it still carries the admin's shared
credentials.

The admin's defaults (`ZABBIX_URL` plain, `ZABBIX_TOKEN` secret) are inherited
by every user, who may override individual keys. Overriding only the URL used
to hand the shared token to whatever the user typed. Now, when a user
re-points an endpoint-like key, the *shared* secrets are withheld; the user's
own secrets are kept.
"""

from unittest.mock import MagicMock, patch

import pytest

from mcprack import env_policy, secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerOverride

SHARED = "ADMIN-SHARED-SECRET"


@pytest.fixture
def local_app(app):
    app.config["BW_SERVER"] = ""  # local encrypted store, no `bw`
    return app


def _setup(extra_admin_secret=False):
    server = McpServer(
        name="zabbix", label="Zabbix", transport="stdio", command="/usr/bin/zbx", enabled=True,
        allow_user_override=True,
    )
    db.session.add(server)
    db.session.commit()
    server.env_config = {"ZABBIX_URL": "https://zabbix.internal.example", "REGION": "eu"}
    secrets = {"ZABBIX_TOKEN": SHARED}
    if extra_admin_secret:
        secrets["OTHER_SECRET"] = "other-admin-secret"
    server.env_var_names = list(secrets)
    db.session.commit()
    secret_store.save_server_secrets(server, secrets)
    user = User(username="mallory", auth_type="local")
    user.set_password("pw")
    db.session.add(user)
    db.session.commit()
    return server, user


@pytest.mark.parametrize(
    "name",
    ["ZABBIX_URL", "MASTODON_INSTANCE", "API_BASE_URL", "OAUTH_TOKEN_URL", "NEXTCLOUD_HOST", "service_endpoint", "BASE_URL_OVERRIDE"],
)
def test_endpoint_like_names(name):
    assert env_policy.is_endpoint_key(name)


@pytest.mark.parametrize("name", ["API_KEY", "ZABBIX_TOKEN", "SERVER_TOKEN", "HOST_KEY", "REGION", "LOG_LEVEL", "HOSTILE_MODE"])
def test_other_names_are_not_endpoints(name):
    assert not env_policy.is_endpoint_key(name)


def test_user_without_override_gets_the_shared_secret(local_app):
    with local_app.app_context():
        server, user = _setup()
        env = secret_store.resolve_server_env(server, user=user)
        assert env["ZABBIX_TOKEN"] == SHARED
        assert env["ZABBIX_URL"] == "https://zabbix.internal.example"


def test_repointing_the_url_withholds_the_shared_secret(local_app):
    """The exact PoC 13 scenario of the audit."""
    with local_app.app_context():
        server, user = _setup()
        secret_store.save_user_override(server, user, {"ZABBIX_URL": "https://attacker.invalid"}, {})
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert env["ZABBIX_URL"] == "https://attacker.invalid"
    assert "ZABBIX_TOKEN" not in env
    assert SHARED not in env.values()


def test_repointing_with_own_token_keeps_only_the_users_own_secret(local_app):
    with local_app.app_context():
        server, user = _setup(extra_admin_secret=True)
        secret_store.save_user_override(
            server, user, {"ZABBIX_URL": "https://my.own.example"}, {"ZABBIX_TOKEN": "my-own-token"}
        )
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert env["ZABBIX_URL"] == "https://my.own.example"
    assert env["ZABBIX_TOKEN"] == "my-own-token"
    assert "OTHER_SECRET" not in env  # still the admin's, so still withheld


def test_marking_the_url_as_secret_does_not_dodge_the_rule(local_app):
    with local_app.app_context():
        server, user = _setup()
        secret_store.save_user_override(server, user, {}, {"ZABBIX_URL": "https://attacker.invalid"})
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert env["ZABBIX_URL"] == "https://attacker.invalid"
    assert SHARED not in env.values()


def test_overriding_the_url_with_the_admins_own_value_keeps_the_secret(local_app):
    with local_app.app_context():
        server, user = _setup()
        secret_store.save_user_override(server, user, {"ZABBIX_URL": "https://zabbix.internal.example"}, {})
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert env["ZABBIX_TOKEN"] == SHARED


def test_overriding_a_non_endpoint_key_keeps_the_secret(local_app):
    with local_app.app_context():
        server, user = _setup()
        secret_store.save_user_override(server, user, {"REGION": "us"}, {})
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert env["REGION"] == "us"
    assert env["ZABBIX_TOKEN"] == SHARED


def test_new_endpoint_key_the_admin_never_set_also_withholds(local_app):
    with local_app.app_context():
        server, user = _setup()
        secret_store.save_user_override(server, user, {"BACKUP_ENDPOINT": "https://elsewhere.invalid"}, {})
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert SHARED not in env.values()


def test_vaultwarden_path_withholds_and_survives_the_cache(app):
    """Vault mode keeps the layers apart in the shared cache, so the rule
    also holds on a warm cache hit - not just on the cold lookup."""
    with app.app_context():
        server = McpServer(
            name="zabbix", label="Zabbix", transport="stdio", command="/usr/bin/zbx", enabled=True,
            allow_user_override=True,
        )
        db.session.add(server)
        db.session.commit()
        server.env_config = {"ZABBIX_URL": "https://zabbix.internal.example"}
        server.env_var_names = ["ZABBIX_TOKEN"]
        user = User(username="mallory", auth_type="local")
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        row = UserServerOverride(user_id=user.id, server_id=server.id)
        row.env_config = {"ZABBIX_URL": "https://attacker.invalid"}
        db.session.add(row)
        db.session.commit()

        layers = patch(
            "mcprack.secret_store.vaultwarden.resolve_env_layers",
            return_value=({"ZABBIX_TOKEN": SHARED}, {}),
        )
        with patch("mcprack.secret_store.vaultwarden._serialized", MagicMock()), \
             patch("mcprack.secret_store.vaultwarden.unlock", return_value="sess"), \
             patch("mcprack.secret_store.vaultwarden.lock"), \
             layers as resolve_layers:
            cold = secret_store.resolve_server_env(server, user=user)
            warm = secret_store.resolve_server_env(server, user=user)

        assert resolve_layers.call_count == 1  # second call came from the cache

    for env in (cold, warm):
        assert env["ZABBIX_URL"] == "https://attacker.invalid"
        assert SHARED not in env.values()
