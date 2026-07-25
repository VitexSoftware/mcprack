"""Autodetection of MCP servers already available on the machine mcprack runs
on, so an admin can pre-populate the catalog with one click instead of typing
every entry by hand.

Three sources are checked, most reliable first:

1. The local Claude Code config (`~/.claude.json`'s top-level `mcpServers`
   dict, and — if run from inside a project checkout — a project-level
   `.mcp.json`). If mcprack runs on a developer/admin workstation that
   already has Claude Code configured, this is by far the most accurate
   source: it has the *exact* command/args/url Claude Code is actually using
   right now, instead of guessing binary names. Comparing this against the
   static registry below (see git history) is what caught several wrong
   guesses in the first place — e.g. the real webdriver binary is
   `mcp-server-webdriver`, not `selenium-webdriver-mcp`; ollama's is
   `ollama-mcp-server` at a custom path, not `mcp-client-for-ollama`;
   abraflexi's is `abraflexi-mcp`, not `abraflexi-mcp-server`; and
   zabbix-mcp-server there isn't an installed binary at all, it's a `uv run
   --directory <checkout> zabbix-mcp` dev invocation — none of which the
   static registry could ever have found.
   Only *structure* (command/args/url/which env keys exist) is imported —
   never the configured env var *values*, which are frequently an
   individual admin's own personal credentials (their own AbraFlexi login,
   their own Nextcloud password, ...) and must not be silently shared as the
   "default credentials for every remote user" without a human reviewing
   that first.
2. `mcp-rack-*.service` systemd units — these are stdio MCP servers already
   proxied to HTTP by the `mcp_rack` Ansible role (see
   spojeitisac/roles/mcp_rack). Each running unit becomes an `http` catalog
   entry pointing at that proxy's URL.
3. A static registry of known stdio MCP CLI binaries, as a last-resort
   fallback for hosts with neither a Claude Code config nor mcp_rack (e.g. a
   bare server that just has some MCP binaries installed).

No Flask/DB coupling — returns plain dicts; the caller (admin.py) decides
what to do with them (e.g. skip ones that already exist).
"""

import json
import os
import re
import shutil
import socket
import subprocess

# Fallback only — prefer detect_from_claude_config() whenever a Claude Code
# config is available, since it reflects the real, working invocation
# instead of a guessed binary name. Each entry lists candidate binary names
# in order of preference; the first one found on PATH wins.
KNOWN_STDIO_SERVERS = {
    "mastodon-mcp": {"label": "Mastodon MCP", "binaries": ["mastodon-mcp"], "args": []},
    "ollama": {"label": "Ollama MCP", "binaries": ["ollama-mcp-server", "mcp-client-for-ollama"], "args": []},
    "abraflexi-mcp": {"label": "AbraFlexi MCP", "binaries": ["abraflexi-mcp", "abraflexi-mcp-server"], "args": []},
    "cc-token-saver": {"label": "CC Token Saver MCP", "binaries": ["cc-token-saver-mcp"], "args": []},
    "webdriver": {"label": "WebDriver MCP", "binaries": ["mcp-server-webdriver", "selenium-webdriver-mcp"], "args": []},
    "warden-mcp": {"label": "Vaultwarden MCP", "binaries": ["warden-mcp"], "args": ["--stdio"]},
    "semaphore": {"label": "Semaphore MCP", "binaries": ["semaphore-mcp"], "args": []},
    "thunderbird-mcp": {"label": "Thunderbird MCP", "binaries": ["thunderbird-mcp"], "args": []},
    "phone-mcp": {"label": "Phone MCP", "binaries": ["phone-mcp"], "args": []},
    "datovka": {"label": "Datovka MCP", "binaries": ["mcp-server-datovka"], "args": []},
    "multiflexi": {"label": "MultiFlexi MCP", "binaries": ["multiflexi-mcp-server"], "args": []},
}

_UNIT_PREFIX = "mcp-rack-"
_UNIT_SUFFIX = ".service"

CLAUDE_USER_CONFIG_PATH = os.path.expanduser("~/.claude.json")


def _run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None


def _list_mcp_rack_units():
    result = _run(
        ["systemctl", "list-units", "--all", "--plain", "--no-legend", "--type=service", f"{_UNIT_PREFIX}*"]
    )
    if result is None or result.returncode != 0:
        return []

    names = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        unit = line.split()[0]
        if unit.startswith(_UNIT_PREFIX) and unit.endswith(_UNIT_SUFFIX):
            names.append(unit[len(_UNIT_PREFIX) : -len(_UNIT_SUFFIX)])
    return names


def _parse_exec_start(unit_text):
    lines = unit_text.splitlines()
    exec_lines = []
    capturing = False
    for line in lines:
        if capturing:
            exec_lines.append(line)
            if not line.rstrip().endswith("\\"):
                break
            continue
        if line.startswith("ExecStart="):
            capturing = True
            exec_lines.append(line[len("ExecStart=") :])
            if not line.rstrip().endswith("\\"):
                break
    joined = " ".join(part.rstrip("\\").strip() for part in exec_lines)
    return joined.split()


def _parse_label(unit_text):
    match = re.search(r"^Description=MCP Rack - (.+?) Proxy\s*$", unit_text, re.MULTILINE)
    return match.group(1) if match else None


def _reachable_host(bind_host):
    if bind_host in (None, "", "0.0.0.0", "::", "127.0.0.1", "localhost"):
        return socket.getfqdn()
    return bind_host


def detect_mcp_rack_proxies():
    """Detect running mcp-rack-<name>.service units and return them as http
    catalog entries pointing at their fastmcp proxy URL."""
    entries = []
    for name in _list_mcp_rack_units():
        unit = f"{_UNIT_PREFIX}{name}{_UNIT_SUFFIX}"
        result = _run(["systemctl", "cat", unit])
        if result is None or result.returncode != 0:
            continue

        argv = _parse_exec_start(result.stdout)
        if len(argv) < 4:
            continue
        # argv: [mcp-rack-run, <name>, <port>, <bind_host>, <config_path>, ...]
        port = argv[2]
        bind_host = argv[3]
        label = _parse_label(result.stdout) or name

        entries.append(
            {
                "name": name,
                "label": label,
                "transport": "http",
                "url": f"http://{_reachable_host(bind_host)}:{port}/mcp",
                "category": "mcp-rack",
            }
        )
    return entries


def detect_local_stdio_binaries(already_named=(), already_commands=()):
    """Last-resort fallback: detect known MCP CLI binaries on PATH that
    aren't already covered by a detected mcp-rack proxy or Claude config
    entry — by name, or by resolved command path (the same binary can be
    configured in Claude under a different catalog name, e.g. "mastodon"
    rather than this registry's "mastodon-mcp" key)."""
    entries = []
    for name, info in KNOWN_STDIO_SERVERS.items():
        if name in already_named:
            continue
        path = None
        for binary in info["binaries"]:
            path = shutil.which(binary)
            if path:
                break
        if not path or path in already_commands:
            continue
        entries.append(
            {
                "name": name,
                "label": info["label"],
                "transport": "stdio",
                "command": path,
                "args": info["args"],
                "category": "local-stdio",
            }
        )
    return entries


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _entry_from_claude_server(name, spec):
    """Build a structure-only catalog entry from one `mcpServers.<name>`
    object. Deliberately drops env/header *values* — only key names survive,
    as hints for the admin to fill in for real via the credentials form."""
    transport = spec.get("type") or ("http" if spec.get("url") else "stdio")

    entry = {
        "name": name,
        "label": name,
        "transport": transport,
        "category": "claude-config",
    }

    if spec.get("command"):
        entry["command"] = spec["command"]
        entry["args"] = list(spec.get("args") or [])

    if spec.get("url"):
        entry["url"] = spec["url"]

    env_keys = list((spec.get("env") or {}).keys())
    headers = spec.get("headers") or {}
    if headers:
        # Only one auth header is modeled per server today; take the first
        # and give it a synthetic env-var name the admin fills in later —
        # never the real header value, which is a live secret.
        header_name = next(iter(headers))
        entry["auth_header_name"] = header_name
        entry["auth_env_key"] = "AUTH_TOKEN"
        env_keys.append("AUTH_TOKEN")

    if env_keys:
        entry["env_var_names"] = env_keys

    return entry


def detect_from_claude_config(path=None):
    """Parse the local Claude Code user config's `mcpServers` dict. Returns
    structure-only entries (see module docstring) — no credential values."""
    config = _read_json(path or CLAUDE_USER_CONFIG_PATH)
    if not isinstance(config, dict):
        return []

    mcp_servers = config.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        return []

    entries = []
    for name, spec in mcp_servers.items():
        if not isinstance(spec, dict):
            continue
        if not (spec.get("command") or spec.get("url")):
            continue
        entries.append(_entry_from_claude_server(name, spec))
    return entries


def detect_local_mcp_servers():
    """Full autodetection, most-reliable source first: the local Claude Code
    config, then running mcp-rack proxies, then the static known-binary
    fallback — each source skips names (and, for the fallback, resolved
    command paths) already found by an earlier one."""
    claude_entries = detect_from_claude_config()
    named = {entry["name"] for entry in claude_entries}
    known_commands = {entry["command"] for entry in claude_entries if entry.get("command")}

    proxies = [e for e in detect_mcp_rack_proxies() if e["name"] not in named]
    named |= {entry["name"] for entry in proxies}

    stdio = detect_local_stdio_binaries(already_named=named, already_commands=known_commands)

    return claude_entries + proxies + stdio
