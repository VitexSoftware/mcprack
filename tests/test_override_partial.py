"""Partial overriding: a user inherits everything the admin configured and
replaces or adds individual keys, rather than supplying the whole set."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mcprack import secret_store, user_proxy
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerOverride


def _server(**overrides):
    """A committed stdio server with overrides allowed - the baseline every
    test here layers an admin or user configuration onto."""
    defaults = dict(
        name="jenkins",
        label="Jenkins",
        transport="stdio",
        command="/usr/bin/jenkins-mcp",
        enabled=True,
        allow_user_override=True,
    )
    defaults.update(overrides)
    server = McpServer(**defaults)
    db.session.add(server)
    db.session.commit()
    return server


def _user(username="alice"):
    """A committed local user to hang an override off."""
    user = User(username=username, auth_type="local")
    user.set_password("pw")
    db.session.add(user)
    db.session.commit()
    return user


def _admin_configured_server():
    """A server the admin gave one plain value and one secret."""
    server = _server()
    server.env_config = {"ADMIN_VAL": "1"}
    server.env_var_names = ["ADMIN_KEY"]
    db.session.commit()
    secret_store.save_server_secrets(server, {"ADMIN_KEY": "admin-secret"})
    db.session.commit()
    return server


def test_user_with_no_override_gets_every_admin_value(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()

        assert secret_store.resolve_server_env(server, user=user) == {
            "ADMIN_VAL": "1",
            "ADMIN_KEY": "admin-secret",
        }


def test_overriding_one_key_leaves_the_other_admin_values_inherited(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()

        secret_store.save_user_override(server, user, {"ADMIN_VAL": "2"}, {})
        db.session.commit()

        assert secret_store.resolve_server_env(server, user=user) == {
            "ADMIN_VAL": "2",
            "ADMIN_KEY": "admin-secret",
        }


def test_user_can_add_a_key_the_admin_never_configured(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()

        secret_store.save_user_override(server, user, {"USER_EXTRA": "foo"}, {})
        db.session.commit()

        assert secret_store.resolve_server_env(server, user=user) == {
            "ADMIN_VAL": "1",
            "ADMIN_KEY": "admin-secret",
            "USER_EXTRA": "foo",
        }


def test_user_secret_override_wins_over_the_admin_secret(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()

        secret_store.save_user_override(server, user, {}, {"ADMIN_KEY": "mine"})
        db.session.commit()

        assert secret_store.resolve_server_env(server, user=user) == {
            "ADMIN_VAL": "1",
            "ADMIN_KEY": "mine",
        }


def test_reset_puts_every_key_back_to_the_admin_default(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()
        secret_store.save_user_override(server, user, {"ADMIN_VAL": "2", "USER_EXTRA": "foo"}, {"ADMIN_KEY": "mine"})
        db.session.commit()

        secret_store.delete_user_override(server, user)
        db.session.commit()

        assert UserServerOverride.query.filter_by(user_id=user.id, server_id=server.id).first() is None
        assert secret_store.resolve_server_env(server, user=user) == {
            "ADMIN_VAL": "1",
            "ADMIN_KEY": "admin-secret",
        }


def test_saving_an_empty_override_drops_the_row_entirely(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()
        secret_store.save_user_override(server, user, {"ADMIN_VAL": "2"}, {})
        db.session.commit()

        secret_store.save_user_override(server, user, {}, {})
        db.session.commit()

        assert UserServerOverride.query.filter_by(user_id=user.id, server_id=server.id).first() is None


def test_load_user_override_reports_both_halves_separately(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _admin_configured_server()
        user = _user()
        secret_store.save_user_override(server, user, {"ADMIN_VAL": "2"}, {"ADMIN_KEY": "mine"})
        db.session.commit()

        assert secret_store.load_user_override(server, user) == ({"ADMIN_VAL": "2"}, {"ADMIN_KEY": "mine"})


def test_batch_resolve_applies_the_users_non_secret_override(app):
    """resolve_server_envs() is the Vaultwarden-batched path used by the
    monitoring prober. It used to merge only admin config + secrets, so a
    required key the user had filled in themselves still read as missing and
    the server showed up as "unconfigured"."""
    with app.app_context():
        server = _server()
        server.env_config = {"ADMIN_VAL": "1"}
        server.env_var_names = ["ADMIN_KEY"]
        db.session.commit()
        user = _user()
        db.session.add(UserServerOverride(
            user_id=user.id, server_id=server.id, env_config_json='{"ADMIN_VAL": "2", "USER_EXTRA": "foo"}',
        ))
        db.session.commit()

        notes = {server.vault_item: ("vid", "ADMIN_KEY=admin-secret")}
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store._get_cached_secrets", return_value=None), \
             patch("mcprack.secret_store._set_cached_secrets"), \
             patch("mcprack.secret_store.audit.log_audit_event"), \
             patch("mcprack.secret_store.vaultwarden._serialized", MagicMock()), \
             patch("mcprack.secret_store.vaultwarden.unlock", return_value="sess"), \
             patch("mcprack.secret_store.vaultwarden.lock"), \
             patch("mcprack.secret_store.vaultwarden.list_notes", return_value=notes):
            out = secret_store.resolve_server_envs([server], user=user)

        assert out[server.id] == {
            "ADMIN_VAL": "2",
            "ADMIN_KEY": "admin-secret",
            "USER_EXTRA": "foo",
        }


def test_batch_resolve_reads_every_users_override_in_one_query(app):
    """The batched path exists to avoid per-server round trips; loading the
    overrides must not reintroduce one query per server."""
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        servers = [_server(name=f"s{i}", command="/bin/true") for i in range(3)]
        user = _user()

        with patch("mcprack.secret_store._user_override_configs", return_value={}) as loader:
            secret_store.resolve_server_envs(servers, user=user)

        loader.assert_called_once()


def test_split_override_values_follows_the_admins_secret_declaration(app):
    with app.app_context():
        server = _server()
        server.env_var_names = ["PLAIN_LOOKING_NAME"]
        db.session.commit()

        non_secret, secret = secret_store.split_override_values(server, {
            "PLAIN_LOOKING_NAME": "a",   # admin declared it a secret
            "SOME_TOKEN": "b",           # name heuristic
            "REGION": "c",
        })

        assert non_secret == {"REGION": "c"}
        assert secret == {"PLAIN_LOOKING_NAME": "a", "SOME_TOKEN": "b"}


def test_split_override_values_keeps_an_already_secret_key_secret(app):
    """The editor lets a user mark any key sensitive, and that choice is
    invisible to the name heuristic. Re-splitting from the CLI or the API
    must not demote such a value into plain env_config_json."""
    with app.app_context():
        server = _server()

        non_secret, secret = secret_store.split_override_values(
            server,
            {"CONNECTION_STRING": "postgres://u:p@h/db", "REGION": "c"},
            secret_keys={"CONNECTION_STRING"},
        )

        assert non_secret == {"REGION": "c"}
        assert secret == {"CONNECTION_STRING": "postgres://u:p@h/db"}


def test_split_override_values_without_secret_keys_still_classifies_by_name(app):
    """Guards the default argument: callers that pass nothing keep the old
    admin-declaration + heuristic behaviour."""
    with app.app_context():
        server = _server()

        non_secret, secret = secret_store.split_override_values(
            server, {"CONNECTION_STRING": "x", "SOME_TOKEN": "y"}
        )

        assert non_secret == {"CONNECTION_STRING": "x"}
        assert secret == {"SOME_TOKEN": "y"}


def test_docker_args_forward_a_key_that_exists_only_in_the_user_override(app):
    """`docker run` only passes a variable through when a bare `-e NAME` asks
    for it, and the flags are rebuilt on every spawn. A key the user added for
    themselves is in neither env_var_names nor env_config, so without the
    resolved env's own keys the container would never see it."""
    with app.app_context():
        server = _server(install_method="docker")
        server.env_config = {"ADMIN_VAL": "1"}
        server.env_var_names = ["ADMIN_KEY"]
        db.session.commit()

        args = user_proxy._effective_args(
            server, ["run", "--rm", "-i", "example/image"],
            env_keys={"ADMIN_VAL": "1", "ADMIN_KEY": "s", "USER_EXTRA": "foo"}.keys(),
        )

        assert args[-1] == "example/image"
        assert args.count("-e") == 3
        for name in ("ADMIN_KEY", "ADMIN_VAL", "USER_EXTRA"):
            assert name in args


def test_docker_args_unchanged_without_extra_env_keys(app):
    with app.app_context():
        server = _server(install_method="docker")
        server.env_config = {"ADMIN_VAL": "1"}
        db.session.commit()

        assert user_proxy._effective_args(server, ["run", "example/image"]) == [
            "run", "-e", "ADMIN_VAL", "example/image",
        ]


def test_user_secret_on_a_server_without_admin_secrets_is_not_dropped(app):
    """server_needs_secrets() is False for a server the admin declared no
    secrets for, and with Vaultwarden configured the override row's
    env_secrets_encrypted column stays empty because the value lives in the
    vault — so neither signal alone is enough to decide whether to look."""
    with app.app_context():
        server = _server()  # no env_var_names, no auth_env_key
        user = _user()
        assert secret_store.server_needs_secrets(server) is False

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden.session", MagicMock()), \
             patch("mcprack.secret_store.vaultwarden.set_notes"), \
             patch("mcprack.secret_store.vaultwarden.delete_item"):
            secret_store.save_user_override(server, user, {}, {"MY_TOKEN": "mine"})
            db.session.commit()

        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True), \
             patch("mcprack.secret_store.vaultwarden._serialized", MagicMock()), \
             patch("mcprack.secret_store.vaultwarden.unlock", return_value="sess"), \
             patch("mcprack.secret_store.vaultwarden.lock"), \
             patch("mcprack.secret_store.vaultwarden.resolve_env", return_value={"MY_TOKEN": "mine"}):
            env = secret_store.resolve_server_env(server, user=user)

    assert env == {"MY_TOKEN": "mine"}
