"""B-08 (docs/AUDIT-2026-11.md): where a server's command may live."""

import os
from unittest.mock import patch

import pytest

from mcprack import command_policy, user_proxy
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection

PW = "admin-long-password-1"


@pytest.fixture
def in_app(app):
    app.config["COMMAND_ALLOW_VOLATILE_DIRS"] = False  # the production default
    app.config["ALLOWED_COMMAND_DIRS"] = ""
    with app.test_request_context():
        yield app


# --- always refused -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "/tmp/payload", "/var/tmp/x/y", "/dev/shm/run", "/run/user/1000/x", "/proc/self/exe", "/dev/null",
        "/tmp", "/usr/bin/../../tmp/payload",  # normalised before it is judged
        "/usr/./../tmp/x",
    ],
)
def test_commands_in_volatile_places_are_refused(in_app, command):
    errors = command_policy.command_errors(command)

    assert errors and "temporary or world-writable" in errors[0], (command, errors)


@pytest.mark.parametrize("command", ["./run.sh", "bin/server", "../server", "sub/dir/x"])
def test_a_relative_path_is_refused(in_app, command):
    assert any("absolute path" in e for e in command_policy.command_errors(command))


@pytest.mark.parametrize("command", ["/usr/bin/x\0y", "/usr/bin/x\nrm -rf /", "/usr/bin/x\r"])
def test_control_characters_are_refused(in_app, command):
    assert command_policy.command_errors(command) == ["The command is not a valid program path."]


def test_a_symlink_that_leads_into_a_volatile_directory_is_refused(in_app):
    with patch("mcprack.command_policy.os.path.realpath", return_value="/tmp/evil"):
        errors = command_policy.command_errors("/usr/local/bin/innocent")

    assert errors and "temporary or world-writable" in errors[0]


@pytest.mark.parametrize(
    "command",
    ["/usr/bin/zabbix-mcp", "/usr/local/bin/x", "/opt/vendor/bin/server", "/var/lib/mcprack/installs/foo/venv/bin/foo", "/bin/true", "/usr/bin/tmp-tool", "/tmpfs/x", "/devices/x"],
)
def test_ordinary_places_are_fine(in_app, command):
    assert command_policy.command_errors(command) == [], command  # /tmpfs and /devices are not /tmp and /dev


@pytest.mark.parametrize("command", [None, ""])
def test_no_command_is_not_this_policys_business(in_app, command):
    assert command_policy.command_errors(command) == []


def test_a_bare_program_name_is_looked_up_on_path(in_app):
    with patch("mcprack.command_policy.shutil.which", return_value="/tmp/uvx"):
        assert command_policy.command_errors("uvx")  # found, but in /tmp
    with patch("mcprack.command_policy.shutil.which", return_value="/usr/bin/uvx"):
        assert command_policy.command_errors("uvx") == []
    with patch("mcprack.command_policy.shutil.which", return_value=None):
        assert command_policy.command_errors("not-installed") == []  # nothing to judge without the allowlist


def test_the_volatile_rule_can_be_lifted_for_development(in_app):
    in_app.config["COMMAND_ALLOW_VOLATILE_DIRS"] = True

    assert command_policy.command_errors("/tmp/payload") == []


# --- the strict mode ----------------------------------------------------------------------------


@pytest.fixture
def strict(in_app):
    in_app.config["ALLOWED_COMMAND_DIRS"] = "/usr/bin,/var/lib/mcprack/installs"
    return in_app


@pytest.mark.parametrize("command", ["/usr/bin/zabbix-mcp", "/var/lib/mcprack/installs/x/venv/bin/x", "/usr/bin/sub/dir/tool"])
def test_inside_an_allowed_directory_is_accepted(strict, command):
    assert command_policy.command_errors(command) == []


@pytest.mark.parametrize(
    "command",
    ["/opt/vendor/bin/server", "/usr/local/bin/x", "/home/user/bin/x", "/usr/binx/tool", "/usr/bin/../local/bin/x", "/usr/bin/../../opt/x", "/usr/bi"],
)
def test_outside_them_is_refused_including_prefix_and_dotdot_tricks(strict, command):
    errors = command_policy.command_errors(command)

    assert errors and "outside the directories the administrator allows" in errors[-1], (command, errors)
    assert "/usr/bin" in errors[-1]


def test_a_bare_name_must_resolve_inside_an_allowed_directory(strict):
    with patch("mcprack.command_policy.shutil.which", return_value="/usr/bin/uvx"):
        assert command_policy.command_errors("uvx") == []
    with patch("mcprack.command_policy.shutil.which", return_value="/usr/local/bin/uvx"):
        assert command_policy.command_errors("uvx")
    with patch("mcprack.command_policy.shutil.which", return_value=None):
        assert "cannot be found on PATH" in command_policy.command_errors("ghost")[0]


@pytest.mark.parametrize(
    "setting,expected",
    [
        ("/usr/bin,/opt/x", ["/usr/bin", "/opt/x"]),
        ("/usr/bin:/opt/x", ["/usr/bin", "/opt/x"]),
        (" /usr/bin , /opt/x/ ", ["/usr/bin", "/opt/x"]),
        ("relative/dir,/usr/bin", ["/usr/bin"]),  # a relative entry would mean "wherever we are"
        ("", []),
    ],
)
def test_the_allowlist_setting_is_parsed_strictly(in_app, setting, expected):
    in_app.config["ALLOWED_COMMAND_DIRS"] = setting

    assert command_policy.allowed_dirs() == expected


def test_the_strict_mode_is_off_by_default():
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-I", "-c", "from mcprack.config import Config; print(repr(Config.ALLOWED_COMMAND_DIRS), Config.COMMAND_ALLOW_VOLATILE_DIRS)"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert out.stdout.strip() == "'' False", out.stderr


# --- at registration ----------------------------------------------------------------------------


@pytest.fixture
def admin_client(app, client):
    app.config["COMMAND_ALLOW_VOLATILE_DIRS"] = False
    with app.app_context():
        admin = User(username="root", auth_type="local", is_admin=True)
        admin.set_password(PW)
        db.session.add(admin)
        db.session.commit()
    client.post("/login", data={"username": "root", "password": PW})
    return client


def test_the_api_refuses_a_command_in_tmp(app, admin_client):
    response = admin_client.post("/api/v1/admin/servers", json={"name": "evil", "transport": "stdio", "command": "/tmp/payload", "enabled": True})

    assert response.status_code == 400 and "temporary or world-writable" in response.get_json()["error"]["message"]
    with app.app_context():
        assert McpServer.query.filter_by(name="evil").first() is None


def test_the_api_refuses_to_edit_a_server_into_one(app, admin_client):
    created = admin_client.post("/api/v1/admin/servers", json={"name": "ok", "transport": "stdio", "command": "/usr/bin/ok-mcp", "enabled": True})
    server_id = created.get_json()["data"]["id"]

    response = admin_client.put(f"/api/v1/admin/servers/{server_id}", json={"transport": "stdio", "command": "/dev/shm/x"})

    assert response.status_code == 400
    with app.app_context():
        assert db.session.get(McpServer, server_id).command == "/usr/bin/ok-mcp"


def test_the_form_refuses_it_with_a_message(app, admin_client):
    response = admin_client.post("/admin/servers/new", data={"name": "evil2", "label": "E", "transport": "stdio", "command": "/var/tmp/x", "enabled": "on"})

    assert "temporary or world-writable" in response.get_data(as_text=True)
    with app.app_context():
        assert McpServer.query.filter_by(name="evil2").first() is None


def test_in_strict_mode_the_api_refuses_what_is_outside(app, admin_client):
    app.config["ALLOWED_COMMAND_DIRS"] = "/usr/bin"

    refused = admin_client.post("/api/v1/admin/servers", json={"name": "a", "transport": "stdio", "command": "/opt/x/run", "enabled": True})
    accepted = admin_client.post("/api/v1/admin/servers", json={"name": "b", "transport": "stdio", "command": "/usr/bin/run", "enabled": True})

    assert refused.status_code == 400 and accepted.status_code == 201


# --- at execution -------------------------------------------------------------------------------


def test_a_row_written_straight_into_the_database_is_still_refused_when_it_would_run(app, tmp_path, monkeypatch):
    """Registration can be bypassed by writing the row yourself; starting the
    process is where the policy is enforced for good."""
    app.config["COMMAND_ALLOW_VOLATILE_DIRS"] = False
    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "up")

    with patch("mcprack.user_proxy.subprocess.Popen") as popen:
        with pytest.raises(user_proxy.UserProxyError) as caught:
            user_proxy.ensure_user_server_proxy(1, 2, "sneaky", "/tmp/payload", [], {})

    popen.assert_not_called()
    assert caught.value.kind == "forbidden"
    assert "refused by policy" in str(caught.value)
    assert "/tmp" not in caught.value.public_message and "not permitted" in caught.value.public_message


def test_strict_mode_is_enforced_when_the_process_starts_too(app, tmp_path, monkeypatch):
    app.config["ALLOWED_COMMAND_DIRS"] = "/usr/bin"
    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "up")

    with patch("mcprack.user_proxy.subprocess.Popen") as popen:
        with pytest.raises(user_proxy.UserProxyError) as caught:
            user_proxy.ensure_user_server_proxy(1, 2, "sneaky", "/opt/x/run", [], {})

    popen.assert_not_called() and caught.value.kind == "forbidden"


def test_the_relay_tells_the_user_it_is_a_policy_matter(app, client):
    from mcprack import catalog

    app.config["COMMAND_ALLOW_VOLATILE_DIRS"] = False
    with app.app_context():
        user = User(username="dan", auth_type="local")
        user.set_password("dan-long-password-1")
        server = McpServer(name="tmpsrv", label="T", transport="stdio", command="/tmp/payload", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        token, server_id = catalog._make_proxy_token(user.id, server.id), server.id

    response = client.post(f"/proxy/mcp/{token}/{server_id}", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert response.status_code == 502 and "not permitted by the administrator's policy" in response.get_data(as_text=True)
    assert "/tmp/payload" not in response.get_data(as_text=True)


def test_without_an_app_context_the_environment_is_consulted(monkeypatch):
    monkeypatch.setenv("ALLOWED_COMMAND_DIRS", "/usr/bin")

    assert command_policy.allowed_dirs() == ["/usr/bin"] and os.environ["ALLOWED_COMMAND_DIRS"]
