"""A-02 (docs/AUDIT-2026-11.md): names of per-user environment overrides.

A user may add or replace environment variables for the MCP server process
mcprack starts for them. Without validation they could set variables that
change *what runs* (NODE_OPTIONS, LD_PRELOAD, PYTHONPATH, PATH, package
index/registry redirection, proxy settings, ...) - a path from "any account"
to code execution as the service user. These tests pin the policy at every
entry point and on the resolve path.
"""

import pytest

from mcprack import env_policy, secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerOverride


def _server(**kw):
    defaults = dict(
        name="svc",
        label="Svc",
        transport="stdio",
        command="/usr/bin/svc",
        enabled=True,
        allow_user_override=True,
    )
    defaults.update(kw)
    server = McpServer(**defaults)
    db.session.add(server)
    db.session.commit()
    return server


def _user(name="alice", admin=False):
    user = User(username=name, auth_type="local", is_admin=admin)
    user.set_password("pw")
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, name="alice"):
    return client.post("/login", data={"username": name, "password": "pw"})


# --- unit: names -----------------------------------------------------------


@pytest.mark.parametrize("name", ["API_TOKEN", "MASTODON_INSTANCE", "lower_case", "_X", "A1", "JENKINS_PAT"])
def test_ordinary_names_are_accepted(name):
    assert env_policy.check_key_name(name) is None


@pytest.mark.parametrize("name", ["", "1ABC", "A-B", "A B", "A=B", "A\nB", "A" * 200, "ÅB", "A.B"])
def test_malformed_names_are_rejected(name):
    assert env_policy.check_key_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_EXTRA_CA_CERTS",
        "LD_PRELOAD",
        "ld_preload",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PATH",
        "path",
        "HOME",
        "SHELL",
        "BASH_ENV",
        "ENV",
        "IFS",
        "NPM_CONFIG_REGISTRY",
        "npm_config_registry",
        "UV_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_COUNT",
        "DOCKER_HOST",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "PERL5OPT",
        "RUBYOPT",
        "XDG_CONFIG_HOME",
        "FASTMCP_SERVER_AUTH",
        "TMPDIR",
    ],
)
def test_process_altering_names_are_rejected(name):
    assert env_policy.check_key_name(name)


@pytest.mark.parametrize("value", ["line1\nline2", "a\rb", "a\x00b", "x" * 9000])
def test_hostile_values_are_rejected(value):
    assert env_policy.check_value("API_TOKEN", value)


def test_non_string_values_are_rejected():
    assert env_policy.check_value("API_TOKEN", 5)
    assert env_policy.check_value("API_TOKEN", None)


def test_admin_declared_keys_are_exempt_from_the_denylist(app):
    """The admin configured these on the server themselves; the policy is
    about what a *user* may add."""
    with app.app_context():
        server = _server()
        server.env_config = {"HTTPS_PROXY": "http://proxy.corp:3128"}
        server.env_var_names = ["NPM_TOKEN"]
        db.session.commit()

        assert env_policy.validate_override(server, {"HTTPS_PROXY": "http://other:3128", "NPM_TOKEN": "t"}) == []
        assert env_policy.validate_override(server, {"HTTP_PROXY": "x"})  # not declared -> still refused


def test_validate_override_reports_every_problem(app):
    with app.app_context():
        server = _server()
        errors = env_policy.validate_override(server, {"NODE_OPTIONS": "x", "API_TOKEN": "a\nb", "OK": "1"})
        assert len(errors) == 2
        assert any("NODE_OPTIONS" in e for e in errors)
        assert any("API_TOKEN" in e for e in errors)


def test_demo_mode_only_accepts_keys_the_server_declares(app):
    with app.app_context():
        server = _server()
        server.env_config = {"REGION": "eu"}
        db.session.commit()

        assert env_policy.validate_override(server, {"REGION": "us"}, demo_mode=True) == []
        assert env_policy.validate_override(server, {"SOMETHING_ELSE": "1"}, demo_mode=True)
        # outside demo mode a free-form, harmless key is fine
        assert env_policy.validate_override(server, {"SOMETHING_ELSE": "1"}, demo_mode=False) == []


# --- entry points ----------------------------------------------------------


def test_api_put_override_rejects_process_altering_names_atomically(app, client):
    with app.app_context():
        server = _server()
        _user()
        server_id = server.id
    _login(client)

    resp = client.put(
        f"/api/v1/me/overrides/{server_id}",
        json={"env": {"API_TOKEN": "fine", "NODE_OPTIONS": "--no-warnings", "LD_PRELOAD": "/x.so"}},
    )

    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_env"
    assert "NODE_OPTIONS" in resp.get_json()["error"]["message"]
    with app.app_context():
        assert UserServerOverride.query.count() == 0  # nothing partially saved


def test_api_put_override_accepts_ordinary_keys(app, client):
    app.config["BW_SERVER"] = ""  # local encrypted store: no `bw` round trip in a unit test
    with app.app_context():
        server = _server()
        _user()
        server_id = server.id
    _login(client)

    resp = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": {"API_TOKEN": "abc", "REGION": "eu"}})

    assert resp.status_code == 200


def test_api_put_override_rejects_non_string_values(app, client):
    with app.app_context():
        server = _server()
        _user()
        server_id = server.id
    _login(client)

    resp = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": {"API_TOKEN": 12345}})

    assert resp.status_code == 400


def test_user_html_editor_rejects_process_altering_names(app, client):
    with app.app_context():
        server = _server()
        _user()
        server_id = server.id
    _login(client)

    resp = client.post(
        f"/override/{server_id}",
        data={
            "env_editor": "1",
            "env_key__a": "NODE_OPTIONS",
            "env_value__a": "--no-warnings",
            "env_key__b": "API_TOKEN",
            "env_value__b": "fine",
        },
        follow_redirects=True,
    )

    assert resp.status_code == 200
    assert b"NODE_OPTIONS" in resp.data  # the error names the offender
    with app.app_context():
        assert UserServerOverride.query.count() == 0


def test_user_html_no_js_textarea_is_validated_too(app, client):
    with app.app_context():
        server = _server()
        _user()
        server_id = server.id
    _login(client)

    client.post(f"/override/{server_id}", data={"env_text": "PYTHONPATH=/tmp/x\nREGION=eu"})

    with app.app_context():
        assert UserServerOverride.query.count() == 0


def test_admin_editor_for_a_user_is_validated_too(app, client):
    with app.app_context():
        server = _server()
        _user("alice")
        _user("boss", admin=True)
        server_id = server.id
        alice_id = User.query.filter_by(username="alice").first().id
    _login(client, "boss")

    client.post(
        f"/admin/users/{alice_id}/override/{server_id}",
        data={"env_editor": "1", "env_key__a": "LD_PRELOAD", "env_value__a": "/x.so"},
    )

    with app.app_context():
        assert UserServerOverride.query.count() == 0


def test_admin_api_override_for_a_user_is_validated_too(app, client):
    with app.app_context():
        server = _server()
        _user("alice")
        _user("boss", admin=True)
        server_id = server.id
        alice_id = User.query.filter_by(username="alice").first().id
    _login(client, "boss")

    resp = client.put(f"/api/v1/admin/users/{alice_id}/overrides/{server_id}", json={"env": {"PATH": "/tmp"}})

    assert resp.status_code == 400


def test_cli_override_set_rejects_process_altering_names(app):
    with app.app_context():
        _server(name="jenkins")
        _user("alice")
        runner = app.test_cli_runner()

        result = runner.invoke(args=["user", "override", "set", "alice", "jenkins", "NODE_OPTIONS=--no-warnings"])

        assert result.exit_code != 0
        assert "NODE_OPTIONS" in result.output
        assert UserServerOverride.query.count() == 0


def test_save_user_override_is_a_last_line_of_defence(app):
    with app.app_context():
        server = _server()
        user = _user()
        with pytest.raises(secret_store.SecretStoreError):
            secret_store.save_user_override(server, user, {"LD_PRELOAD": "/x.so"}, {})


def test_demo_mode_restricts_overrides_to_declared_keys(app, client):
    app.config["DEMO_MODE"] = True
    with app.app_context():
        server = _server()
        server.env_config = {"REGION": "eu"}
        db.session.commit()
        _user()
        server_id = server.id
    _login(client)

    bad = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": {"NOT_DECLARED": "1"}})
    good = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": {"REGION": "us"}})

    assert bad.status_code == 400
    assert good.status_code == 200


# --- resolve path: legacy rows -------------------------------------------


def test_legacy_denied_keys_never_reach_the_process(app):
    """Rows stored before the policy existed must be neutralised when the
    environment is resolved, not just refused on the next save."""
    with app.app_context():
        app.config["BW_SERVER"] = ""
        server = _server()
        server.env_config = {"ADMIN_VAL": "1"}
        db.session.commit()
        user = _user()
        row = UserServerOverride(user_id=user.id, server_id=server.id)
        row.env_config = {"NODE_OPTIONS": "--no-warnings", "LD_PRELOAD": "/x.so", "REGION": "eu"}
        db.session.add(row)
        db.session.commit()

        env = secret_store.resolve_server_env(server, user=user)

    assert env == {"ADMIN_VAL": "1", "REGION": "eu"}
