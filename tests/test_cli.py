from unittest.mock import patch

from mcprack import secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User


def _make_user(username="alice", admin=False, active=True):
    user = User(username=username, auth_type="local", is_admin=admin, is_active_flag=active)
    user.set_password("secret")
    db.session.add(user)
    db.session.commit()
    return user


def _make_server(name="jenkins", enabled=True, env_var_names=None):
    server = McpServer(name=name, label=name.title(), transport="stdio", command="/bin/true", enabled=enabled)
    if env_var_names is not None:
        server.env_var_names = env_var_names
    db.session.add(server)
    db.session.commit()
    return server


def test_user_create_and_list(app):
    with app.app_context():
        runner = app.test_cli_runner()

        result = runner.invoke(args=["user", "create", "--username", "bob", "--password", "hunter2", "--admin"])
        assert result.exit_code == 0, result.output

        user = User.query.filter_by(username="bob").first()
        assert user is not None
        assert user.is_admin is True
        assert user.check_password("hunter2")

        result = runner.invoke(args=["user", "list"])
        assert "bob" in result.output
        assert "admin" in result.output


def test_user_create_duplicate_fails(app):
    with app.app_context():
        _make_user("bob")
        runner = app.test_cli_runner()
        result = runner.invoke(args=["user", "create", "--username", "bob", "--password", "hunter2"])
        assert result.exit_code != 0
        assert "already exists" in result.output


def test_user_passwd_promote_demote_enable_disable(app):
    with app.app_context():
        _make_user("carol")
        runner = app.test_cli_runner()

        result = runner.invoke(args=["user", "passwd", "carol", "--password", "newpass123"])
        assert result.exit_code == 0, result.output
        assert User.query.filter_by(username="carol").first().check_password("newpass123")

        runner.invoke(args=["user", "promote", "carol"])
        assert User.query.filter_by(username="carol").first().is_admin is True

        runner.invoke(args=["user", "demote", "carol"])
        assert User.query.filter_by(username="carol").first().is_admin is False

        runner.invoke(args=["user", "disable", "carol"])
        assert User.query.filter_by(username="carol").first().is_active_flag is False

        runner.invoke(args=["user", "enable", "carol"])
        assert User.query.filter_by(username="carol").first().is_active_flag is True


def test_user_delete(app):
    with app.app_context():
        _make_user("dave")
        runner = app.test_cli_runner()
        result = runner.invoke(args=["user", "delete", "dave", "--yes"])
        assert result.exit_code == 0, result.output
        assert User.query.filter_by(username="dave").first() is None


def test_user_commands_fail_for_unknown_username(app):
    with app.app_context():
        runner = app.test_cli_runner()
        for args in (
            ["user", "passwd", "ghost", "--password", "x"],
            ["user", "enable", "ghost"],
            ["user", "disable", "ghost"],
            ["user", "promote", "ghost"],
            ["user", "demote", "ghost"],
            ["user", "delete", "ghost", "--yes"],
        ):
            result = runner.invoke(args=args)
            assert result.exit_code != 0
            assert "No such user" in result.output


def test_server_list_show_enable_disable(app):
    with app.app_context():
        _make_server("jenkins", enabled=True)
        runner = app.test_cli_runner()

        result = runner.invoke(args=["server", "list"])
        assert "jenkins" in result.output
        assert "enabled" in result.output

        result = runner.invoke(args=["server", "show", "jenkins"])
        assert "name:        jenkins" in result.output

        runner.invoke(args=["server", "disable", "jenkins"])
        assert McpServer.query.filter_by(name="jenkins").first().enabled is False

        runner.invoke(args=["server", "enable", "jenkins"])
        assert McpServer.query.filter_by(name="jenkins").first().enabled is True


def test_server_delete_clears_secrets(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins", env_var_names=["API_TOKEN"])
        secret_store.save_server_secrets(server, {"API_TOKEN": "abc123"})
        db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "delete", "jenkins", "--yes"])
        assert result.exit_code == 0, result.output
        assert McpServer.query.filter_by(name="jenkins").first() is None


def test_server_commands_fail_for_unknown_name(app):
    with app.app_context():
        runner = app.test_cli_runner()
        for args in (["server", "show", "ghost"], ["server", "enable", "ghost"], ["server", "disable", "ghost"]):
            result = runner.invoke(args=args)
            assert result.exit_code != 0
            assert "No such MCP server" in result.output


def test_secret_set_list_unset(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        _make_server("jenkins", env_var_names=["API_TOKEN"])
        runner = app.test_cli_runner()

        result = runner.invoke(args=["secret", "list", "jenkins"])
        assert "API_TOKEN\tunset" in result.output

        result = runner.invoke(args=["secret", "set", "jenkins", "API_TOKEN", "--value", "s3cr3t"])
        assert result.exit_code == 0, result.output

        server = McpServer.query.filter_by(name="jenkins").first()
        assert secret_store.load_server_secrets(server) == {"API_TOKEN": "s3cr3t"}

        result = runner.invoke(args=["secret", "list", "jenkins"])
        assert "API_TOKEN\tset" in result.output

        result = runner.invoke(args=["secret", "unset", "jenkins", "API_TOKEN"])
        assert result.exit_code == 0, result.output
        assert secret_store.load_server_secrets(server) == {}


def test_secret_unset_unknown_key_fails(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        _make_server("jenkins", env_var_names=["API_TOKEN"])
        runner = app.test_cli_runner()
        result = runner.invoke(args=["secret", "unset", "jenkins", "NOPE"])
        assert result.exit_code != 0
        assert "is not set" in result.output


def test_secret_backend_reports_vaultwarden_when_configured(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=True):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["secret", "backend"])
        assert "Vaultwarden" in result.output


def test_secret_backend_reports_local_when_not_configured(app):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["secret", "backend"])
        assert "Local encrypted fallback" in result.output


def test_server_import_env_splits_plain_and_secret(app, tmp_path):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        _make_server("jenkins")
        dotenv_file = tmp_path / "sample.env"
        dotenv_file.write_text('JENKINS_URL=https://ci.example.com\nAPI_TOKEN="s3cr3t"\n# comment\n\n')

        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "import-env", "jenkins", str(dotenv_file)])
        assert result.exit_code == 0, result.output
        assert "Plain:  JENKINS_URL" in result.output
        assert "Secret: API_TOKEN" in result.output

        server = McpServer.query.filter_by(name="jenkins").first()
        assert server.env_config == {"JENKINS_URL": "https://ci.example.com"}
        assert server.env_var_names == ["API_TOKEN"]
        assert secret_store.load_server_secrets(server) == {"API_TOKEN": "s3cr3t"}


def test_server_import_env_no_overwrite_skips_existing(app, tmp_path):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins")
        server.env_config = {"JENKINS_URL": "https://old.example.com"}
        db.session.commit()

        dotenv_file = tmp_path / "sample.env"
        dotenv_file.write_text("JENKINS_URL=https://new.example.com\n")

        runner = app.test_cli_runner()
        result = runner.invoke(
            args=["server", "import-env", "jenkins", str(dotenv_file), "--no-overwrite"]
        )
        assert result.exit_code == 0, result.output
        assert "Skipped" in result.output
        assert "JENKINS_URL" in result.output

        server = McpServer.query.filter_by(name="jenkins").first()
        assert server.env_config == {"JENKINS_URL": "https://old.example.com"}


def test_server_import_env_reclassifies_existing_key(app, tmp_path):
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins")
        server.env_config = {"API_TOKEN": "plain-oops"}
        db.session.commit()

        dotenv_file = tmp_path / "sample.env"
        dotenv_file.write_text("API_TOKEN=now-a-secret\n")

        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "import-env", "jenkins", str(dotenv_file)])
        assert result.exit_code == 0, result.output

        server = McpServer.query.filter_by(name="jenkins").first()
        assert server.env_config == {}
        assert server.env_var_names == ["API_TOKEN"]
        assert secret_store.load_server_secrets(server) == {"API_TOKEN": "now-a-secret"}


def test_server_import_env_unknown_server_fails(app, tmp_path):
    with app.app_context():
        dotenv_file = tmp_path / "sample.env"
        dotenv_file.write_text("X=1\n")
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "import-env", "ghost", str(dotenv_file)])
        assert result.exit_code != 0
        assert "No such MCP server" in result.output
