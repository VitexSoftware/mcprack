"""A-04 (minimum) and B-02 (docs/AUDIT-2026-11.md): what a spawned MCP
server process inherits and where its credentials rest.

The fastmcp process (and so, through it, the MCP server) started with a copy
of mcprack's ENTIRE environment - SECRET_KEY, the Vaultwarden master
password, the LDAP bind password, the database URL - readable from
/proc/<pid>/environ by every MCP server. And the resolved credentials of each
(user, server) pair lay in plain files that were not even removed when the
process was reaped. Now: an allowlisted environment, 0600 files in a runtime
directory that does not survive a restart, removed when the process stops."""

import json
import os
import stat
from unittest.mock import MagicMock, patch

from mcprack import user_proxy

SECRETS = {
    "SECRET_KEY": "k" * 40,
    "BW_PASSWORD": "master-password",
    "BW_CLIENTSECRET": "client-secret",
    "BW_CLIENTID": "client-id",
    "LDAP_BIND_PASSWORD": "ldap-pw",
    "SMTP_PASSWORD": "smtp-pw",
    "MONITORING_TOKEN": "mon-token",
    "SQLALCHEMY_DATABASE_URI": "postgresql://u:dbpassword@db/x",
    "GUNICORN_BIND": "127.0.0.1:8912",
    "INVOCATION_ID": "abc",
}


def _spawn(monkeypatch, extra_env=None, app=None, config=None):
    for key, value in {**SECRETS, **(extra_env or {})}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("LANG", "cs_CZ.UTF-8")
    paths = user_proxy._paths(1, 2)
    user_proxy._ensure_state_dir()
    popen = MagicMock()
    popen.return_value.poll.return_value = None
    popen.return_value.pid = 4242
    with patch("mcprack.user_proxy.subprocess.Popen", popen), \
            patch("mcprack.user_proxy._resolve_fastmcp_bin", return_value="/usr/bin/fastmcp"), \
            patch("mcprack.user_proxy._probe_upstream_health", return_value=True), \
            patch("mcprack.user_proxy.time.sleep"):
        cfg = user_proxy._desired_config("svc", "/usr/bin/svc", [], {"API_TOKEN": "user-secret"})
        user_proxy._spawn(paths, 35001, "svc", cfg, json.dumps(cfg, sort_keys=True))
    return popen.call_args.kwargs["env"], paths


def test_the_child_environment_contains_none_of_mcpracks_secrets(monkeypatch):
    env, _ = _spawn(monkeypatch)

    assert not set(SECRETS) & set(env)
    assert not any(value in " ".join(env.values()) for value in ("master-password", "dbpassword", "k" * 40))


def test_the_child_environment_keeps_what_a_process_needs(monkeypatch):
    env, _ = _spawn(monkeypatch)

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["LANG"] == "cs_CZ.UTF-8"
    assert env["PYTHONIOENCODING"] == "utf-8"


def test_proxy_and_ca_settings_set_by_the_operator_are_kept(monkeypatch):
    env, _ = _spawn(monkeypatch, {"HTTPS_PROXY": "http://proxy.corp:3128", "SSL_CERT_FILE": "/etc/ssl/ca.pem", "LC_ALL": "C.UTF-8"})

    assert env["HTTPS_PROXY"] == "http://proxy.corp:3128"
    assert env["SSL_CERT_FILE"] == "/etc/ssl/ca.pem"
    assert env["LC_ALL"] == "C.UTF-8"


def test_the_operator_can_extend_the_allowlist(app, monkeypatch):
    app.config["MCP_CHILD_ENV_ALLOW"] = "JAVA_HOME, MY_RUNTIME_DIR"
    env, _ = _spawn(monkeypatch, {"JAVA_HOME": "/usr/lib/jvm/x", "MY_RUNTIME_DIR": "/opt/rt", "OTHER": "no"})

    assert env["JAVA_HOME"] == "/usr/lib/jvm/x" and env["MY_RUNTIME_DIR"] == "/opt/rt"
    assert "OTHER" not in env
    assert not set(SECRETS) & set(env)  # the extension cannot re-add what is never allowed


def test_secrets_can_never_be_allowlisted(app, monkeypatch):
    app.config["MCP_CHILD_ENV_ALLOW"] = "SECRET_KEY,BW_PASSWORD"
    env, _ = _spawn(monkeypatch)

    assert "SECRET_KEY" not in env and "BW_PASSWORD" not in env


# --- files ---------------------------------------------------------------------------------


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_instance_files_are_private_whatever_the_umask(monkeypatch):
    old = os.umask(0o022)  # a permissive umask must not matter
    try:
        _, paths = _spawn(monkeypatch)
    finally:
        os.umask(old)

    for key in ("config", "meta", "port", "pid"):
        assert _mode(paths[key]) == 0o600, key
    assert _mode(user_proxy.STATE_DIR) == 0o700


def test_the_credentials_are_removed_when_an_idle_instance_is_reaped(monkeypatch):
    _, paths = _spawn(monkeypatch)
    paths["last_used"].write_text("0")  # idle for ever
    stopped = []
    monkeypatch.setattr(user_proxy, "_stop_pid", lambda pid, timeout=3.0: stopped.append(pid))
    monkeypatch.setattr(user_proxy, "_pid_running", lambda pid: True)

    with patch("mcprack.user_proxy.audit.log_audit_event"):
        user_proxy.cleanup_idle_proxies()

    assert stopped == [4242]
    assert not paths["config"].exists()
    assert not paths["meta"].exists()
    assert not paths["pid"].exists()


# --- where the state lives ------------------------------------------------------------------


def test_state_dir_prefers_the_runtime_directory_when_there_is_one(tmp_path, monkeypatch):
    runtime = tmp_path / "run-mcprack"
    runtime.mkdir()
    monkeypatch.setattr(user_proxy, "RUNTIME_DIR", runtime)
    monkeypatch.delenv("MCPRACK_STATE_DIR", raising=False)

    assert user_proxy.default_state_dir() == runtime / "user-proxies"


def test_state_dir_falls_back_to_the_persistent_location(tmp_path, monkeypatch):
    monkeypatch.setattr(user_proxy, "RUNTIME_DIR", tmp_path / "does-not-exist")
    monkeypatch.delenv("MCPRACK_STATE_DIR", raising=False)

    assert str(user_proxy.default_state_dir()) == "/var/lib/mcprack/user-proxies"


def test_state_dir_can_be_set_explicitly(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPRACK_STATE_DIR", str(tmp_path / "custom"))

    assert user_proxy.default_state_dir() == tmp_path / "custom"
