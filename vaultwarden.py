"""Thin subprocess wrapper around the `bw` (Bitwarden/Vaultwarden) CLI.

Mirrors the exact mechanism already used by the `mcp_rack` Ansible role
(`mcp-rack-run.sh.j2`, `mcp_store_credentials.yml`): configure server, log in
with an API key, unlock with the master password to get a session token, then
read/write a Secure Note's `notes` field as plain `KEY=value` lines.

No secret value is ever written to mcprack's own database — this module is
the only place mcprack talks to Vaultwarden, and callers pass resolved dicts
around in memory only for the lifetime of a single request.
"""

import base64
import contextlib
import fcntl
import json
import logging
import os
import subprocess
import time

from flask import current_app

import health

logger = logging.getLogger(__name__)


class VaultwardenError(RuntimeError):
    pass


def _env():
    cfg = current_app.config
    return {
        "BW_CLIENTID": cfg["BW_CLIENTID"],
        "BW_CLIENTSECRET": cfg["BW_CLIENTSECRET"],
        "BW_PASSWORD": cfg["BW_PASSWORD"],
        "BITWARDENCLI_APPDATA_DIR": cfg["BITWARDENCLI_APPDATA_DIR"],
        # bw needs a PATH/HOME to run at all
        "PATH": "/usr/bin:/bin",
        "HOME": cfg["BITWARDENCLI_APPDATA_DIR"],
        # Fail fast instead of blocking on stdin if something we didn't
        # anticipate makes `bw` want to prompt interactively (e.g. a stale
        # session from a concurrent request leaving the vault locked) — a
        # hung subprocess under gunicorn just burns a worker until its
        # request timeout kills it, with no useful error at all.
        "BW_NOINTERACTION": "true",
    }


def _lock_file_path():
    appdata_dir = current_app.config["BITWARDENCLI_APPDATA_DIR"]
    os.makedirs(appdata_dir, exist_ok=True)
    return os.path.join(appdata_dir, ".mcprack-bw.lock")


def _bw_lock_timeout_seconds():
    return float(current_app.config.get("BW_LOCK_TIMEOUT", 8.0))


@contextlib.contextmanager
def _serialized():
    """Cross-process mutex around a chunk of `bw` CLI calls.

    The `bw` CLI's local state directory is not safe for concurrent
    unlock/lock cycles: `bw lock` clears the encryption key for *all* local
    state in `BITWARDENCLI_APPDATA_DIR`, not just one session. With multiple
    gunicorn workers sharing one appdata dir, one worker finishing its
    request (and locking) can yank the vault out from under a different
    worker that's still mid-request with an earlier session — which is
    exactly what caused a worker to hang waiting on an unexpected
    interactive prompt. Serializing access here trades a little latency
    under concurrency for correctness.
    """
    deadline = time.monotonic() + _bw_lock_timeout_seconds()
    with open(_lock_file_path(), "w") as lock_file:
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    wait = _bw_lock_timeout_seconds()
                    raise VaultwardenError(
                        f"Vaultwarden is busy (lock wait exceeded {wait:.1f}s)"
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _bw_bin():
    return current_app.config["BW_BIN"]


def _bw_timeout_seconds():
    # Reduced from 12s to 8s to prevent gunicorn worker timeouts (30s default)
    # If bw commands consistently timeout, the Vaultwarden configuration or network
    # connectivity needs to be investigated
    return float(current_app.config.get("BW_COMMAND_TIMEOUT", 8.0))


def _item_name(item_name):
    return item_name


def _run(args, input_text=None, check=True):
    timeout = _bw_timeout_seconds()
    cmd_str = " ".join(args)
    logger.debug(f"Running: bw {cmd_str} (timeout={timeout}s)")
    
    try:
        result = subprocess.run(
            [_bw_bin(), *args],
            input=input_text,
            capture_output=True,
            text=True,
            env=_env(),
            timeout=timeout,
        )
        logger.debug(f"bw {cmd_str}: returncode={result.returncode}")
    except subprocess.TimeoutExpired as exc:
        logger.error(f"bw {cmd_str} timed out after {timeout:.1f}s")
        raise VaultwardenError(
            f"bw {' '.join(args)} timed out after {timeout:.1f}s"
        ) from exc

    if check and result.returncode != 0:
        error_msg = result.stderr.strip() or result.stdout.strip()
        logger.error(f"bw {cmd_str} failed: {error_msg}")
        raise VaultwardenError(
            f"bw {' '.join(args)} failed: {error_msg}"
        )
    return result


def unlock():
    """Configure server, log in with API key (idempotent), unlock the vault.
    Returns a session token string."""
    cfg = current_app.config
    
    # Validate configuration
    if not cfg.get("BW_SERVER"):
        raise VaultwardenError("BW_SERVER is not configured")
    if not cfg.get("BW_PASSWORD"):
        raise VaultwardenError("BW_PASSWORD is not configured")
    
    try:
        _run(["config", "server", cfg["BW_SERVER"]], check=False)

        status = _run(["status", "--raw"], check=False)
        if '"unauthenticated"' in (status.stdout or ""):
            _run(["login", "--apikey", "--quiet"])

        result = _run(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"])
        session = result.stdout.strip()
        if not session:
            raise VaultwardenError("bw unlock returned an empty session token")
        return session
    except subprocess.TimeoutExpired:
        raise VaultwardenError("Bitwarden CLI operation timed out (is the server reachable?)")
    except Exception as exc:
        # Catch any other unexpected errors and wrap them
        if isinstance(exc, VaultwardenError):
            raise
        raise VaultwardenError(f"Bitwarden CLI error: {str(exc)}")


def lock(session):
    """Lock the vault. This always succeeds silently, even if the vault is already locked."""
    try:
        _run(["lock"], check=False)
    except VaultwardenError as exc:
        # Lock failures should not fail the whole operation - the vault might already be locked
        logger.warning(f"Failed to lock vault: {exc}")
        pass


@contextlib.contextmanager
def session():
    """Preferred entry point for callers: unlock, yield a session token, and
    always lock again on the way out — the whole thing serialized against
    other requests (see _serialized()) so concurrent gunicorn workers can't
    race each other's unlock/lock cycles.

    Usage:
        with vaultwarden.session() as sess:
            vaultwarden.get_notes(sess, "MCP-jenkins")
    """
    with _serialized():
        sess = unlock()
        try:
            yield sess
        finally:
            lock(sess)


def _find_item_id(session, item_name):
    # `--search` avoids scanning and parsing the whole vault for each save.
    result = _run(["list", "items", "--search", item_name, "--session", session], check=False)
    if result.returncode != 0:
        result = _run(["list", "items", "--session", session])

    items = json.loads(result.stdout or "[]")
    for item in items:
        if item.get("name") == item_name:
            return item["id"]
    return None


def get_notes(session, item_name):
    """Fetch the Secure Note for `item_name` and parse KEY=value lines into a
    dict. Returns {} if the item doesn't exist."""
    result = _run(["get", "notes", item_name, "--session", session], check=False)
    notes = result.stdout or ""
    values = {}
    for line in notes.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.isidentifier():
            values[key] = val
    return values


def _render_notes(values):
    return "\n".join(f"{k}={v}" for k, v in values.items())


def set_notes(session, item_name, values):
    """Create or update the Secure Note named `item_name` with KEY=value
    lines built from `values`."""
    notes_text = _render_notes(values)
    existing_id = _find_item_id(session, item_name)

    if existing_id:
        item_json = _run(["get", "item", existing_id, "--session", session]).stdout
        item = json.loads(item_json)
        item["notes"] = notes_text
        encoded = base64.b64encode(json.dumps(item).encode()).decode()
        _run(["edit", "item", existing_id, "--session", session, "--quiet"], input_text=encoded)
    else:
        item = {
            "type": 2,
            "name": item_name,
            "notes": notes_text,
            "secureNote": {"type": 0},
        }
        encoded = base64.b64encode(json.dumps(item).encode()).decode()
        _run(["create", "item", "--session", session, "--quiet"], input_text=encoded)


def delete_item(session, item_name):
    existing_id = _find_item_id(session, item_name)
    if existing_id:
        _run(["delete", "item", existing_id, "--session", session, "--quiet"], check=False)


def missing_credential_keys(server, values):
    """Which of a server's *declared* required keys (its env_var_names hints
    plus, for http/sse, its auth_env_key) are absent or empty in `values`.
    A server with no declared keys is never flagged — we only know a key is
    "missing" if the admin said it should exist."""
    expected = set(server.env_var_names or [])
    if server.url and server.auth_env_key:
        expected.add(server.auth_env_key)
    return sorted(key for key in expected if not values.get(key))


def resolve_env(session, server, user=None):
    """Fetch a server's default env values, merged with the user's personal
    override (if any) — override keys win per-key, not all-or-nothing."""
    values = get_notes(session, server.vault_item)
    if user is not None:
        override_item = f"{server.vault_item}-user-{user.username}"
        overrides = get_notes(session, override_item)
        values.update(overrides)
    return values


def diagnose():
    """Step-by-step live diagnosis of the Vaultwarden connection, for the
    admin-facing "fix this" wizard. Runs the same checks unlock() does, one
    at a time, so a failure points at exactly which prerequisite is broken
    (binary missing / server unset / unreachable / bad API key / bad master
    password) instead of just surfacing `bw`'s raw stderr. Steps after the
    first failure are marked "skipped" rather than attempted, so a
    misconfigured BW_SERVER doesn't also produce a confusing failed login
    attempt right below it."""
    cfg = current_app.config
    steps = []
    blocked = False

    def add(key, label, ok, detail):
        nonlocal blocked
        if blocked:
            steps.append(
                {"key": key, "label": label, "status": "skipped", "detail": "Not checked — fix the step above first."}
            )
            return
        steps.append({"key": key, "label": label, "status": "ok" if ok else "fail", "detail": detail})
        if not ok:
            blocked = True

    bw_bin = cfg["BW_BIN"]
    bin_ok = os.path.isfile(bw_bin) and os.access(bw_bin, os.X_OK)
    add(
        "bw_binary",
        "bw CLI is installed",
        bin_ok,
        f"Found at {bw_bin}."
        if bin_ok
        else f"'{bw_bin}' was not found or is not executable. Install the bw-cli package, "
        "or set BW_BIN in /etc/mcprack/env to the correct path.",
    )

    server = cfg["BW_SERVER"]
    add(
        "bw_server_set",
        "BW_SERVER is configured",
        bool(server),
        f"Set to {server}."
        if server
        else "BW_SERVER is empty. Set it in /etc/mcprack/env to your Vaultwarden URL, "
        "e.g. https://vaultwarden-dev.proxy.spojenet.cz",
    )

    reachable = bool(server) and health.check_http_reachable(server)
    add(
        "bw_server_reachable",
        "Vaultwarden server is reachable",
        reachable,
        f"Connected to {server}."
        if reachable
        else f"Could not open a network connection to {server or '(not set)'}. Check the URL, DNS, "
        "firewall rules, and that Vaultwarden is actually running there.",
    )

    client_id, client_secret = cfg["BW_CLIENTID"], cfg["BW_CLIENTSECRET"]
    creds_set = bool(client_id) and bool(client_secret)
    add(
        "bw_api_key_set",
        "BW_CLIENTID / BW_CLIENTSECRET are configured",
        creds_set,
        "Both are set."
        if creds_set
        else "BW_CLIENTID and/or BW_CLIENTSECRET are empty. Get them from your Vaultwarden account: "
        "Account Settings -> Security -> API Key, then set them in /etc/mcprack/env.",
    )

    login_ok, login_detail = False, "Not attempted."
    if not blocked:
        with _serialized():
            _run(["config", "server", server], check=False)
            status_result = _run(["status", "--raw"], check=False)
            current_status = "unknown"
            if status_result and status_result.stdout:
                try:
                    current_status = json.loads(status_result.stdout).get("status", "unknown")
                except ValueError:
                    pass

            if current_status == "unauthenticated":
                login_result = _run(["login", "--apikey", "--quiet"], check=False)
                login_ok = login_result is not None and login_result.returncode == 0
                if login_ok:
                    login_detail = "Logged in successfully with the configured API key."
                else:
                    stderr = (login_result.stderr.strip() or login_result.stdout.strip()) if login_result else ""
                    login_detail = stderr or (
                        "Login failed — double check BW_CLIENTID/BW_CLIENTSECRET are correct for this "
                        "Vaultwarden server (Account Settings -> Security -> API Key)."
                    )
            else:
                login_ok = True
                login_detail = f"Already authenticated (status: {current_status})."
    add("bw_api_login", "API key login succeeds", login_ok, login_detail)

    password_set = bool(cfg["BW_PASSWORD"])
    add(
        "bw_password_set",
        "BW_PASSWORD is configured",
        password_set,
        "Set." if password_set else "BW_PASSWORD is empty. Set it in /etc/mcprack/env to the "
        "Vaultwarden account's master password.",
    )

    unlock_ok, unlock_detail = False, "Not attempted."
    if not blocked:
        with _serialized():
            unlock_result = _run(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"], check=False)
            unlock_ok = bool(unlock_result and unlock_result.returncode == 0 and unlock_result.stdout.strip())
            if unlock_ok:
                _run(["lock"], check=False)
                unlock_detail = "Vault unlocked successfully — Vaultwarden is fully configured."
            else:
                stderr = (
                    (unlock_result.stderr.strip() or unlock_result.stdout.strip()) if unlock_result else ""
                )
                unlock_detail = stderr or (
                    "Unlock failed — double check BW_PASSWORD is the correct master password for this account."
                )
    add("bw_unlock", "Vault unlocks with BW_PASSWORD", unlock_ok, unlock_detail)

    return steps
