"""B-07 (docs/AUDIT-2026-11.md): the package installer.

It put admin-supplied strings into a `bash -c` script with json.dumps() as
"quoting" (inside double quotes bash still runs $(...) and backticks), took
the server name straight into filesystem paths (name ".." made uninstall
delete the whole state directory), accepted any package spec - including
option injection ("--index-url=...") and unpinned/VCS sources - and let npm
run lifecycle scripts. Now: no shell at all (an argv runner), strict
validation, pinned versions by default, and uninstall refuses paths outside
its own directory."""

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from mcprack import installer
from mcprack.extensions import db
from mcprack.models import McpServer, User


# --- validation ------------------------------------------------------------------


@pytest.mark.parametrize("name", ["foo", "foo-mcp", "a1", "mcp.server_x", "x" * 63])
def test_good_names(name):
    installer.validate_name(name)


@pytest.mark.parametrize(
    "name", ["", "..", ".", ".hidden", "../etc", "a/b", "a b", "x$(id)", "x`id`", "x;y", "UPPER", "x" * 64, "-rf"]
)
def test_bad_names(name):
    with pytest.raises(installer.InstallError):
        installer.validate_name(name)


@pytest.mark.parametrize("spec", ["foo==1.0.0", "foo-mcp-server==2.3", "foo[extra]==1.0", "Foo_Bar==1.0.post1"])
def test_good_pinned_pip_specs(spec):
    installer.validate_pip_spec(spec)


@pytest.mark.parametrize(
    "spec",
    [
        "--index-url=http://evil.example/simple",
        "-r/etc/passwd",
        "foo --extra-index-url http://evil",
        "git+https://github.com/x/y.git",
        "https://evil.example/x.whl",
        "./local",
        "foo==1.0; rm -rf /",
        "foo==$(id)",
        "foo @ http://evil.example/foo.whl",
        "",
    ],
)
def test_hostile_pip_specs_are_refused_even_when_not_pinning(spec):
    with pytest.raises(installer.InstallError):
        installer.validate_pip_spec(spec, require_pinned=False)


@pytest.mark.parametrize("spec", ["foo", "foo>=1.0", "foo==1.*", "foo>=1,<2"])
def test_unpinned_pip_specs_are_refused_by_default_but_can_be_allowed(spec):
    with pytest.raises(installer.InstallError):
        installer.validate_pip_spec(spec)
    installer.validate_pip_spec(spec, require_pinned=False)


@pytest.mark.parametrize("spec", ["foo@1.2.3", "@scope/foo@1.2.3", "foo@1.2.3-beta.1"])
def test_good_pinned_npm_specs(spec):
    installer.validate_npm_spec(spec)


@pytest.mark.parametrize(
    "spec", ["--registry=http://evil", "foo@latest", "foo", "git+https://x/y.git", "file:../x", "foo@1.2.3;id", "http://x/y.tgz"]
)
def test_bad_or_unpinned_npm_specs(spec):
    with pytest.raises(installer.InstallError):
        installer.validate_npm_spec(spec)


@pytest.mark.parametrize(
    "ref", ["ghcr.io/org/img:1.2.3", "img:1.2", "host:5000/img:v2", "img@sha256:" + "a" * 64, "org/img:1.0-rc1"]
)
def test_good_pinned_image_refs(ref):
    installer.validate_image_ref(ref)


@pytest.mark.parametrize(
    "ref", ["--privileged", "img", "img:latest", "img:1.0;id", "img:1.0 --rm", "", "-v/:/host img:1"]
)
def test_bad_or_unpinned_image_refs(ref):
    with pytest.raises(installer.InstallError):
        installer.validate_image_ref(ref)


@pytest.mark.parametrize("binary", ["foo-mcp", "foo.mcp", "a1"])
def test_good_binary_names(binary):
    installer.validate_binary_name(binary)


@pytest.mark.parametrize("binary", ["", "../x", "a/b", "-x", "a b", "x;y"])
def test_bad_binary_names(binary):
    with pytest.raises(installer.InstallError):
        installer.validate_binary_name(binary)


# --- no shell ----------------------------------------------------------------------


def _launched(call):
    """(program, job dict) of one installer.subprocess.Popen call."""
    argv = call.args[0]
    return argv, json.loads(argv[-1])


def test_install_is_launched_without_a_shell_and_values_travel_as_data(tmp_path):
    with patch("mcprack.installer.STATE_DIR", tmp_path / "installs"), \
            patch("mcprack.installer.shutil.which", return_value="/usr/bin/x"), \
            patch("mcprack.installer.subprocess.Popen", return_value=MagicMock(pid=1)) as popen:
        installer.start_pip_install("foo", "foo-mcp-server==1.0", "foo-mcp")

    argv, job = _launched(popen.call_args)
    assert "bash" not in argv and "sh" not in argv and "-c" not in argv[1:2] or argv[1] == "-c"
    assert argv[0] == sys.executable
    steps = [step[0] for step in job["steps"]]
    assert steps[-1][-1] == "foo-mcp-server==1.0"  # the spec is one argv element, never parsed by a shell
    assert "--no-input" in steps[-1]


def test_pip_builds_wheels_only_by_default(tmp_path):
    with patch("mcprack.installer.STATE_DIR", tmp_path / "installs"), \
            patch("mcprack.installer.shutil.which", return_value="/usr/bin/x"), \
            patch("mcprack.installer.subprocess.Popen", return_value=MagicMock(pid=1)) as popen:
        installer.start_pip_install("foo", "foo==1.0", "foo")

    _, job = _launched(popen.call_args)
    assert "--only-binary=:all:" in job["steps"][-1][0]


def test_npm_never_runs_lifecycle_scripts(tmp_path):
    with patch("mcprack.installer.STATE_DIR", tmp_path / "installs"), \
            patch("mcprack.installer.shutil.which", return_value="/usr/bin/npm"), \
            patch("mcprack.installer.subprocess.Popen", return_value=MagicMock(pid=1)) as popen:
        installer.start_npm_install("foo", "foo@1.2.3", "foo")

    _, job = _launched(popen.call_args)
    install = job["steps"][-1][0]
    assert "--ignore-scripts" in install and install[-1] == "foo@1.2.3"


def test_the_runner_treats_shell_metacharacters_as_plain_text(tmp_path):
    """Run the real runner with an argument that WAS command substitution
    under the old bash -c construction (docs/AUDIT-2026-11.md PoC 10)."""
    log, exitcode = tmp_path / "install.log", tmp_path / "install.exitcode"
    job = {
        "log": str(log),
        "exitcode": str(exitcode),
        "steps": [[["echo", "x$(echo INJECTED)`echo INJECTED2`"], None]],
    }

    subprocess.run([sys.executable, "-c", installer._RUNNER, json.dumps(job)], check=True)

    text = log.read_text()
    assert "x$(echo INJECTED)`echo INJECTED2`" in text  # echoed back verbatim, not executed
    assert text.count("INJECTED") == 4  # the "$ ..." header line plus the echo, each with 2 literal tokens
    assert exitcode.read_text().strip() == "0"


def test_the_runner_stops_at_the_first_failing_step_and_records_its_code(tmp_path):
    log, exitcode = tmp_path / "l", tmp_path / "e"
    job = {
        "log": str(log), "exitcode": str(exitcode),
        "steps": [[[sys.executable, "-c", "raise SystemExit(7)"], None], [["echo", "never"], None]],
    }

    subprocess.run([sys.executable, "-c", installer._RUNNER, json.dumps(job)], check=True)

    assert exitcode.read_text().strip() == "7"
    assert "never" not in log.read_text()


def test_the_runner_reports_a_missing_program(tmp_path):
    log, exitcode = tmp_path / "l", tmp_path / "e"
    job = {"log": str(log), "exitcode": str(exitcode), "steps": [[["/no/such/program-xyz"], None]]}

    subprocess.run([sys.executable, "-c", installer._RUNNER, json.dumps(job)], check=True)

    assert exitcode.read_text().strip() == "127"


# --- uninstall stays inside its directory ------------------------------------------


@pytest.mark.parametrize("name", ["..", "../..", "a/../..", "/etc", ""])
def test_uninstall_never_leaves_the_install_directory(tmp_path, name):
    root = tmp_path / "state" / "installs"
    root.mkdir(parents=True)
    precious = tmp_path / "state" / "mcprack.db"
    precious.write_text("the database")
    server = MagicMock(install_method="pip")
    server.name = name

    with patch("mcprack.installer.STATE_DIR", root):
        installer.uninstall(server)

    assert precious.exists()
    assert root.exists()


def test_state_paths_refuse_unsafe_names(tmp_path):
    with patch("mcprack.installer.STATE_DIR", tmp_path / "installs"):
        for name in ("..", "a/b", "", "x\0y"):
            with pytest.raises(installer.InstallError):
                installer._paths(name)


# --- the admin routes --------------------------------------------------------------


def _login_admin(client):
    client.application.app_context().push()
    user = User(username="boss", auth_type="local", is_admin=True)
    user.set_password("boss-long-password-12")
    db.session.add(user)
    db.session.commit()
    client.post("/login", data={"username": "boss", "password": "boss-long-password-12"})


@pytest.mark.parametrize(
    "path,data",
    [
        ("/admin/install/pip", {"name": "ok", "package_spec": "--index-url=http://evil", "expected_binary": "ok"}),
        ("/admin/install/pip", {"name": "ok", "package_spec": "ok", "expected_binary": "ok"}),  # unpinned
        ("/admin/install/pip", {"name": "x$(id)", "package_spec": "ok==1", "expected_binary": "ok"}),
        ("/admin/install/pip", {"name": "..", "package_spec": "ok==1", "expected_binary": "ok"}),
        ("/admin/install/pip", {"name": "ok", "package_spec": "ok==1", "expected_binary": "../bin/sh"}),
        ("/admin/install/npm", {"name": "ok", "package_spec": "ok@latest", "expected_binary": "ok"}),
        ("/admin/install/npm", {"name": "ok", "package_spec": "--registry=http://evil", "expected_binary": "ok"}),
        ("/admin/install/docker", {"name": "ok", "image_ref": "--privileged"}),
        ("/admin/install/docker", {"name": "ok", "image_ref": "img:latest"}),
    ],
)
def test_routes_refuse_bad_input_and_register_nothing(app, client, path, data):
    _login_admin(client)

    with patch("mcprack.installer.start_pip_install") as pip, patch("mcprack.installer.start_npm_install") as npm, \
            patch("mcprack.installer.start_docker_pull") as docker, patch("mcprack.installer.docker_available", return_value=True):
        client.post(path, data=data, follow_redirects=True)

    assert McpServer.query.count() == 0
    assert not (pip.called or npm.called or docker.called)


def test_unpinned_specs_can_be_allowed_by_config(app, client):
    app.config["INSTALL_REQUIRE_PINNED"] = False
    _login_admin(client)

    with patch("mcprack.installer.start_pip_install", return_value="/x/venv") as pip:
        client.post("/admin/install/pip", data={"name": "ok", "package_spec": "ok>=1", "expected_binary": "ok"})

    assert pip.called
