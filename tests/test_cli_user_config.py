import json
from unittest.mock import patch

import click
import pytest

from mcprack import cli
from mcprack.extensions import db
from mcprack.models import (
    ConfigTemplate,
    McpServer,
    User,
    UserServerPermission,
    UserServerSelection,
)


def _make_user(username="alice"):
    user = User(username=username, auth_type="local")
    user.set_password("secret")
    db.session.add(user)
    db.session.commit()
    return user


def _make_server(name="jenkins", **kwargs):
    defaults = dict(label=name.title(), transport="stdio", command="/bin/true", enabled=True)
    defaults.update(kwargs)
    server = McpServer(name=name, **defaults)
    db.session.add(server)
    db.session.commit()
    return server


def test_user_server_allow_deny_and_list(app):
    with app.app_context():
        _make_user("alice")
        _make_server("jenkins")
        _make_server("grafana")
        runner = app.test_cli_runner()

        result = runner.invoke(args=["user", "server", "deny", "alice", "grafana"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(args=["user", "server", "list", "alice"])
        assert "jenkins\tallow" in result.output
        assert "grafana\tdeny" in result.output

        result = runner.invoke(args=["user", "server", "allow", "alice", "grafana"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(args=["user", "server", "list", "alice"])
        assert "grafana\tallow" in result.output


def test_user_server_deny_drops_existing_selection(app):
    with app.app_context():
        user = _make_user("alice")
        server = _make_server("jenkins")
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=["user", "server", "deny", "alice", "jenkins"])
        assert result.exit_code == 0, result.output

        assert UserServerSelection.query.filter_by(user_id=user.id, server_id=server.id).first() is None


def test_user_server_select_replaces_selection(app):
    with app.app_context():
        user = _make_user("alice")
        _make_server("jenkins")
        _make_server("grafana")
        runner = app.test_cli_runner()

        result = runner.invoke(args=["user", "server", "select", "alice", "--server", "jenkins"])
        assert result.exit_code == 0, result.output
        selected = {row.server_id for row in UserServerSelection.query.filter_by(user_id=user.id).all()}
        jenkins_id = McpServer.query.filter_by(name="jenkins").first().id
        assert selected == {jenkins_id}

        result = runner.invoke(args=["user", "server", "select", "alice"])
        assert result.exit_code == 0, result.output
        assert UserServerSelection.query.filter_by(user_id=user.id).count() == 0


def test_user_server_select_skips_denied_server(app):
    with app.app_context():
        user = _make_user("alice")
        server = _make_server("jenkins")
        db.session.add(UserServerPermission(user_id=user.id, server_id=server.id, is_allowed=False))
        db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=["user", "server", "select", "alice", "--server", "jenkins"])
        assert result.exit_code == 0, result.output
        assert UserServerSelection.query.filter_by(user_id=user.id).count() == 0


def test_user_override_set_list_reset(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        _make_user("alice")
        _make_server("jenkins", env_var_names=["API_TOKEN"])
        runner = app.test_cli_runner()

        result = runner.invoke(args=["user", "override", "set", "alice", "jenkins", "API_TOKEN=abc123"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(args=["user", "override", "list", "alice", "jenkins"])
        assert "API_TOKEN\tset" in result.output

        result = runner.invoke(args=["user", "override", "reset", "alice", "jenkins"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(args=["user", "override", "list", "alice", "jenkins"])
        assert "No individual credentials set" in result.output


def test_user_config_show_for_network_server(app):
    """A server with its own network `url` (e.g. a genuinely network-native
    MCP server, or one of mcp_rack's shared fastmcp proxies) is still handed
    to the user as a /proxy/mcp/ relay URL, never its raw backend address —
    the backend may be unreachable from the user's own machine (a private
    IP, a different host mcprack itself can reach but the user cannot)."""
    with app.app_context():
        user = _make_user("alice")
        server = McpServer(
            name="httpsvc",
            label="HTTP Svc",
            transport="http",
            url="https://example.test/mcp",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=["user", "config", "show", "alice", "copilot"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert "/proxy/mcp/" in payload["servers"]["httpsvc"]["url"]


def test_user_config_show_uses_public_base_url_for_stdio_server(app):
    """With PUBLIC_BASE_URL configured, `user config show` can build a
    proxy URL for a stdio-implemented server even though a CLI invocation
    has no real web request to infer a host from."""
    with app.app_context():
        user = _make_user("alice")
        server = _make_server("jenkins")
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()

        app.config["PUBLIC_BASE_URL"] = "https://mcprack.example.test"
        try:
            runner = app.test_cli_runner()
            result = runner.invoke(args=["user", "config", "show", "alice", "copilot"])
            assert result.exit_code == 0, result.output
            payload = json.loads(result.output)
            assert payload["servers"]["jenkins"]["url"].startswith("https://mcprack.example.test/")
        finally:
            app.config["PUBLIC_BASE_URL"] = ""


def test_build_user_config_or_fail_wraps_runtime_error(app):
    """A real CLI invocation (unlike this test's pytest-flask-provided app
    context) has no request context at all, so Flask's url_for raises
    RuntimeError when building a stdio server's proxy URL without
    PUBLIC_BASE_URL configured. Verify _build_user_config_or_fail turns
    that into an actionable ClickException instead of a raw traceback."""
    with app.app_context():
        user = _make_user("alice")
        with patch(
            "mcprack.cli.catalog._build_client_config_json",
            side_effect=RuntimeError("Unable to build URLs outside an active request"),
        ):
            with pytest.raises(click.ClickException) as exc_info:
                cli._build_user_config_or_fail(user, "copilot")
        assert "PUBLIC_BASE_URL" in str(exc_info.value)


def test_user_config_download_writes_file(app, tmp_path):
    with app.app_context():
        user = _make_user("alice")
        server = McpServer(
            name="httpsvc",
            label="HTTP Svc",
            transport="http",
            url="https://example.test/mcp",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()

        out_file = tmp_path / "out.json"
        runner = app.test_cli_runner()
        result = runner.invoke(
            args=["user", "config", "download", "alice", "copilot", "--out", str(out_file)]
        )
        assert result.exit_code == 0, result.output
        assert out_file.exists()
        payload = json.loads(out_file.read_text())
        assert "httpsvc" in payload["servers"]


def test_template_create_set_servers_show_apply_delete(app):
    with app.app_context():
        user = _make_user("alice")
        server = _make_server("jenkins")
        other = _make_server("grafana")
        runner = app.test_cli_runner()

        result = runner.invoke(args=["template", "create", "basic", "--label", "Basic"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            args=[
                "template",
                "set-servers",
                "basic",
                "--select",
                "jenkins",
                "--deny",
                "grafana",
            ]
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(args=["template", "show", "basic"])
        assert "jenkins\tallow\tselected" in result.output
        assert "grafana\tdeny\t-" in result.output

        result = runner.invoke(args=["template", "list"])
        assert "basic" in result.output

        result = runner.invoke(args=["template", "apply", "basic", "alice"])
        assert result.exit_code == 0, result.output

        permission_map = {
            row.server_id: row.is_allowed
            for row in UserServerPermission.query.filter_by(user_id=user.id).all()
        }
        assert permission_map[server.id] is True
        assert permission_map[other.id] is False
        selected = {row.server_id for row in UserServerSelection.query.filter_by(user_id=user.id).all()}
        assert selected == {server.id}
        assert db.session.get(User, user.id).config_template_id == (
            ConfigTemplate.query.filter_by(name="basic").first().id
        )

        result = runner.invoke(args=["template", "delete", "basic", "--yes"])
        assert result.exit_code == 0, result.output
        assert ConfigTemplate.query.filter_by(name="basic").first() is None
        # Deleting the template must not retroactively touch the user.
        assert UserServerSelection.query.filter_by(user_id=user.id, server_id=server.id).first() is not None


def test_template_create_duplicate_fails(app):
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["template", "create", "basic"])
        assert result.exit_code == 0, result.output
        result = runner.invoke(args=["template", "create", "basic"])
        assert result.exit_code != 0
        assert "already exists" in result.output


def test_template_and_user_server_commands_fail_for_unknown_names(app):
    with app.app_context():
        runner = app.test_cli_runner()
        for args in (
            ["template", "show", "ghost"],
            ["template", "apply", "ghost", "alice"],
            ["template", "delete", "ghost", "--yes"],
        ):
            result = runner.invoke(args=args)
            assert result.exit_code != 0
            assert "No such template" in result.output

        _make_user("alice")
        for args in (
            ["user", "server", "allow", "alice", "ghost"],
            ["user", "server", "deny", "alice", "ghost"],
            ["user", "override", "set", "alice", "ghost", "K=V"],
            ["user", "config", "show", "ghost", "copilot"],
        ):
            result = runner.invoke(args=args)
            assert result.exit_code != 0
