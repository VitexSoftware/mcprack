"""What exactly changed on a server registration, for the audit trail
(docs/AUDIT-2026-11.md B-08).

Registering or editing a server defines what the service user EXECUTES, so "server
updated" is not an adequate record of who pointed which server at which command.
The description names the old and the new command and URL. It never contains an
argument or an environment VALUE - arguments sometimes carry a credential
(`--token ...`), and env values are exactly what the secret store exists to keep
out of logs - only their count/fingerprint and the key NAMES.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

_MAX = 470  # audit_log_entries.error_message is 500 characters


def _clip(text, limit=120):
    text = "(none)" if text in (None, "") else str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _quoted(value):
    """'/usr/bin/x' for a value, (none) for an empty one."""
    return "(none)" if value in (None, "") else repr(_clip(value))


def _safe_url(url):
    """scheme://host:port and a FINGERPRINT of the path - no credentials, no query
    string, and not the path itself: webhook-style endpoints keep their secret in
    the path (/hook/<secret>, even mcprack's own /proxy/mcp/<token>/<id>). Where the
    server points is the host; that the path changed is visible in the fingerprint."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
        port = f":{parts.port}" if parts.port else ""
        origin = f"{parts.scheme}://{parts.hostname or ''}{port}"
    except ValueError:
        return "(invalid URL)"
    if parts.path in ("", "/"):
        return origin
    return f"{origin} (path sha256:{hashlib.sha256(parts.path.encode()).hexdigest()[:10]})"


def _fingerprint(args):
    return hashlib.sha256("\0".join(str(a) for a in args).encode()).hexdigest()[:10]


def snapshot(server):
    """The tracked, log-safe state of a registration."""
    return {
        "transport": server.transport,
        "command": server.command,
        "args": [str(a) for a in (server.args or [])],
        "url": _safe_url(server.url),
        "enabled": bool(server.enabled),
        "allow_user_override": bool(server.allow_user_override),
        "auth_header_name": server.auth_header_name,
        "auth_env_key": server.auth_env_key,
        "env_keys": sorted((server.env_config or {}).keys()),
        "secret_keys": sorted(server.env_var_names or []),
    }


def describe(before, after):
    """One line saying what changed from `before` to `after` (None = a new server)."""
    if before is None:
        parts = [
            f"transport={after['transport']}",
            f"command={_quoted(after['command'])}" if after["command"] else "no command",
            f"args: {len(after['args'])} item(s) sha256:{_fingerprint(after['args'])}" if after["args"] else "no args",
        ]
        if after["url"]:
            parts.append(f"url={_clip(after['url'])}")
        if not after["enabled"]:
            parts.append("disabled")
        if after["env_keys"] or after["secret_keys"]:
            parts.append("env keys: " + ", ".join(after["env_keys"] + [f"{k} (secret)" for k in after["secret_keys"]]))
        return _clip("server created: " + "; ".join(parts), _MAX)

    changes = []
    if before["command"] != after["command"]:
        changes.append(f"command {_quoted(before['command'])} -> {_quoted(after['command'])}")
    if before["args"] != after["args"]:
        changes.append(
            f"args {len(before['args'])} -> {len(after['args'])} item(s), "
            f"sha256:{_fingerprint(before['args'])} -> sha256:{_fingerprint(after['args'])}"
        )
    if before["url"] != after["url"]:
        changes.append(f"url {_clip(before['url'])} -> {_clip(after['url'])}")
    for name in ("transport", "enabled", "allow_user_override", "auth_header_name", "auth_env_key"):
        if before[name] != after[name]:
            changes.append(f"{name} {_clip(before[name])} -> {_clip(after[name])}")
    for label, key in (("env", "env_keys"), ("secret", "secret_keys")):
        added = sorted(set(after[key]) - set(before[key]))
        removed = sorted(set(before[key]) - set(after[key]))
        if added or removed:
            changes.append(f"{label} keys " + " ".join([f"+{k}" for k in added] + [f"-{k}" for k in removed]))
    if not changes:
        return "server updated (no change to command, arguments, URL or environment keys)"
    return _clip("server updated: " + "; ".join(changes), _MAX)
