import os
import stat
from unittest.mock import MagicMock, patch

import pytest

from mcprack import installer


def _make_executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def test_pip_install_queues_and_reports_running():
    with patch("mcprack.installer.subprocess.Popen", return_value=MagicMock(pid=4242)), \
         patch("mcprack.installer.shutil.which", return_value="/usr/bin/python3"):
        installer.start_pip_install("foo", "foo-mcp-server==1.0", "foo-mcp")

    with patch("mcprack.installer._pid_running", return_value=True):
        status = installer.get_install_status("foo")
    assert status["status"] == "running"


def test_get_install_status_success_when_exitcode_zero():
    paths = installer._paths("foo")
    paths["dir"].mkdir(parents=True)
    paths["exitcode"].write_text("0")
    status = installer.get_install_status("foo")
    assert status["status"] == "success"


def test_get_install_status_failed_on_nonzero_exit():
    paths = installer._paths("foo")
    paths["dir"].mkdir(parents=True)
    paths["exitcode"].write_text("1")
    status = installer.get_install_status("foo")
    assert status["status"] == "failed"
    assert "exited with status 1" in status["error"]


def test_get_install_status_failed_when_process_disappears_without_exitcode():
    paths = installer._paths("foo")
    paths["dir"].mkdir(parents=True)
    paths["pid"].write_text("99999")
    with patch("mcprack.installer._pid_running", return_value=False):
        status = installer.get_install_status("foo")
    assert status["status"] == "failed"
    assert "disappeared" in status["error"]


def test_verify_pip_binary_finds_executable(tmp_path):
    venv_dir = tmp_path / "venv"
    _make_executable(venv_dir / "bin" / "foo-mcp")
    assert installer.verify_pip_binary(str(venv_dir), "foo-mcp") == str(venv_dir / "bin" / "foo-mcp")


def test_verify_pip_binary_missing_returns_none(tmp_path):
    venv_dir = tmp_path / "venv"
    venv_dir.mkdir()
    assert installer.verify_pip_binary(str(venv_dir), "does-not-exist") is None


def test_verify_npm_binary_finds_executable(tmp_path):
    install_dir = tmp_path / "npm"
    _make_executable(install_dir / "node_modules" / ".bin" / "foo-mcp")
    assert installer.verify_npm_binary(str(install_dir), "foo-mcp") == str(
        install_dir / "node_modules" / ".bin" / "foo-mcp"
    )


def test_docker_available_false_when_docker_ps_fails():
    with patch("mcprack.installer.shutil.which", return_value="/usr/bin/docker"), \
         patch("mcprack.installer.subprocess.run", return_value=MagicMock(returncode=1)):
        assert installer.docker_available() is False


def test_docker_available_false_when_docker_not_on_path():
    with patch("mcprack.installer.shutil.which", return_value=None):
        assert installer.docker_available() is False


def test_docker_available_true_when_docker_ps_succeeds():
    with patch("mcprack.installer.shutil.which", return_value="/usr/bin/docker"), \
         patch("mcprack.installer.subprocess.run", return_value=MagicMock(returncode=0)):
        assert installer.docker_available() is True


def test_start_docker_pull_does_not_gate_itself(tmp_path):
    """start_docker_pull doesn't re-check docker_available() — the caller
    (admin.py's install_docker route) is responsible for that gate."""
    with patch("mcprack.installer.subprocess.Popen", return_value=MagicMock(pid=1)) as mock_popen:
        installer.start_docker_pull("foo", "ghcr.io/org/foo:latest")
    assert mock_popen.called


def test_uninstall_removes_install_path_for_pip(tmp_path):
    server = MagicMock(name="foo", install_method="pip", install_path=str(tmp_path / "installs" / "foo" / "venv"))
    server.name = "foo"
    (tmp_path / "installs" / "foo" / "venv" / "bin").mkdir(parents=True)

    with patch("mcprack.installer.STATE_DIR", tmp_path / "installs"):
        installer.uninstall(server)

    assert not (tmp_path / "installs" / "foo").exists()


def test_uninstall_noop_for_docker(tmp_path):
    server = MagicMock(install_method="docker", install_path=None)
    server.name = "foo"
    (tmp_path / "installs" / "foo").mkdir(parents=True)

    with patch("mcprack.installer.STATE_DIR", tmp_path / "installs"):
        installer.uninstall(server)

    assert (tmp_path / "installs" / "foo").exists()


def test_double_install_blocked_while_still_running():
    with patch("mcprack.installer.subprocess.Popen", return_value=MagicMock(pid=1)):
        installer.start_pip_install("foo", "foo-mcp==1.0", "foo-mcp")

    with patch("mcprack.installer._pid_running", return_value=True):
        with pytest.raises(installer.InstallError, match="already in progress"):
            installer.start_pip_install("foo", "foo-mcp==1.0", "foo-mcp")
