"""End-to-end server checks for external monitoring (Zabbix).

`/health` only proves the app and its database are up. That said nothing
when a registered MCP server's backend crashed: the relay still answered
`initialize` and returned an empty `tools/list`. `check_servers()` runs the
same handshake a real client does against every enabled server and reports
per-server results.

Probing spawns backends (cold starts take seconds), so it never runs inside
a request: `get_snapshot()` returns the last result immediately and, when it
has gone stale, refreshes it in a background thread. The result lives in a
file shared by all gunicorn workers; a flock keeps refreshes single-flight.

Vaultwarden is contacted only where the probe genuinely needs it: a cold
stdio spawn (a server start) or a network handshake that carries an auth
header. A warm stdio instance is probed on its running port with no
credential resolution at all, and a server already known to be unconfigured
for the monitoring user is answered from a negative cache (invalidated by a
server edit, expired hourly) — the refresh runs every couple of minutes and
must not be a periodic Vaultwarden client (a single failing `bw unlock` used
to mark every credential-backed server broken at once, 2026-10-16).
"""

import fcntl
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from . import health
from . import secret_store
from . import user_proxy
from . import vaultwarden

logger = logging.getLogger(__name__)

_MAX_PARALLEL = 4

# How long an "unconfigured" verdict for a server the monitoring user
# cannot start is trusted without re-checking Vaultwarden. Such a server is
# never warm (it can never be spawned), so without this cache the refresh
# would pay a credential lookup (unlock/list/lock) for it every time, even
# though its answer cannot change until the admin edits the server or its
# vault item. Invalidated sooner when the server row changes (config
# fingerprint), and expired wholesale by this TTL so an out-of-band change
# (vault item edited directly, monitoring user's override set via API) is
# picked up within an hour.
_UNCONFIGURED_TTL = 3600  # seconds


def _result(server, ok, tools=None, error=None, latency=0.0):
    return {
        "id": server.id,
        "name": server.name,
        "transport": server.transport,
        "ok": ok,
        "tools": tools,
        "latency_ms": int(latency * 1000),
        "error": error,
    }


def _env_or_early(server, resolved):
    """(env, early_result) from one resolve_server_env outcome (an env dict
    or the exception it raised)."""
    # latency stays 0 for early results: it is meant to be handshake latency,
    # and a slow Vaultwarden lookup must not raise "server is slow".
    if isinstance(resolved, (vaultwarden.VaultwardenError, secret_store.SecretStoreError)):
        return None, _result(server, False, error=f"could not resolve credentials: {resolved}"[:200])
    if isinstance(resolved, Exception):
        raise resolved
    if [key for key in server.required_env_keys if not resolved.get(key)]:
        return None, _result(server, None, error="unconfigured")
    return resolved, None


def resolve_env(server, user):
    """(env, early_result) for one server."""
    try:
        resolved = secret_store.resolve_server_env(server, user=user)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        resolved = exc
    return _env_or_early(server, resolved)


def resolve_envs(servers, user):
    """{server.id: (env, early_result)} for all servers. Credential lookups
    share Vaultwarden's single cross-process lock, so they are batched into
    one unlock/list/lock cycle (see secret_store.resolve_server_envs)
    rather than one cycle per server - parallel lookups would just time
    out on each other and read as outages."""
    resolved = secret_store.resolve_server_envs(servers, user=user)
    return {s.id: _env_or_early(s, resolved[s.id]) for s in servers}


def check_server(server, user, env=None):
    """Probe one server. ok is True/False, or None when the monitoring
    user simply lacks required configuration (not an outage). Pass `env`
    when already resolved (check_servers batches credential lookups);
    when None it is resolved here — but only where the probe genuinely
    needs credentials: a cold stdio proxy spawn (a server start) or a
    network handshake that carries an auth header. An already-running
    stdio instance is probed on its port without touching the secret
    store at all: /health/servers refreshes every couple of minutes and
    must not be a periodic Vaultwarden client — one failing `bw unlock`
    used to fan out as a mass "servers broken" alert (2026-10-16)."""

    start = time.monotonic()

    def done(ok, tools=None, error=None):
        return _result(server, ok, tools, error, time.monotonic() - start)

    if server.command:
        # Warm instance: probe it in place, no credential resolution.
        warm_port = user_proxy.running_proxy_port(user.id, server.id)
        if warm_port is not None:
            ok, tools, error = health.probe_tools(
                "127.0.0.1", warm_port, timeout=user_proxy.HANDSHAKE_TIMEOUT
            )
            if ok:
                user_proxy.mark_proxy_used(user.id, server.id)
                return done(True, tools)
            # A warm-but-broken instance falls through to the full start
            # path below, which restarts it — that spawn is a server
            # start, so resolving credentials there is allowed.
        if env is None:
            env, early = resolve_env(server, user)
            if early is not None:
                return early

        try:
            port = user_proxy.ensure_user_server_proxy(
                user_id=user.id,
                server_id=server.id,
                server_name=server.name,
                command=server.command,
                args=server.args,
                env=env,
                server=server,
            )
        except user_proxy.UserProxyError as exc:
            return done(False, error=str(exc)[:200])
        ok, tools, error = health.probe_tools("127.0.0.1", port, timeout=user_proxy.HANDSHAKE_TIMEOUT)
        return done(ok, tools if ok else 0, error)

    if env is None:
        env, early = resolve_env(server, user)
        if early is not None:
            return early

    if server.transport == "sse":
        # No streamable-HTTP handshake to run; reachability is all we can say.
        reachable = health.check_http_reachable(server.url, timeout=3.0)
        return done(reachable, error=None if reachable else "endpoint unreachable")

    parts = urlsplit(server.url)
    https = parts.scheme == "https"
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    headers = {}
    if server.auth_header_name and server.auth_env_key and env.get(server.auth_env_key):
        headers[server.auth_header_name] = env[server.auth_env_key]
    ok, tools, error = health.probe_tools(
        parts.hostname,
        parts.port or (443 if https else 80),
        timeout=user_proxy.HANDSHAKE_TIMEOUT,
        path=path,
        https=https,
        extra_headers=headers,
    )
    return done(ok, tools if ok else 0, error)


def check_servers(app):
    """Probe every enabled server as the monitoring user. Needs an app
    context per worker thread, hence `app` instead of using current_app."""
    from .models import McpServer, User
    from .extensions import db

    user_id = app.config["MONITORING_USER_ID"]
    with app.app_context():
        user = db.session.get(User, user_id)
        if user is None:
            raise RuntimeError("MONITORING_USER_ID does not name an existing user")
        servers = [
            s for s in McpServer.query.filter_by(enabled=True).order_by(McpServer.name).all()
            if s.command or s.url
        ]
        # Phase 1 (serial): decide what each probe needs. Warm stdio
        # instances are probed on their running port and never resolve
        # credentials — Vaultwarden is only contacted for a server start
        # or an authenticated network handshake, never merely because the
        # monitoring refresh runs. A server already known to be
        # unconfigured for this user is answered from the negative cache
        # without a lookup. Phase 2 (parallel): probes.
        results, todo = {}, []
        warm, resolve_needed = [], []
        unconfigured_cache = _read_unconfigured()
        for server in servers:
            if server.command and user_proxy.running_proxy_port(user.id, server.id) is not None:
                warm.append((server.id, server.name))
                continue
            verdict = _cached_unconfigured_verdict(server, unconfigured_cache)
            if verdict is not None:
                results[server.id] = verdict
            else:
                resolve_needed.append(server)
        learned = False
        envs = resolve_envs(resolve_needed, user=user) if resolve_needed else {}
        for server in resolve_needed:
            env, early = envs[server.id]
            if early is not None:
                results[server.id] = early
                if early.get("error") == "unconfigured":
                    unconfigured_cache[str(server.id)] = {
                        "ts": time.time(),
                        "fp": _server_fingerprint(server),
                    }
                    learned = True
            else:
                todo.append((server.id, server.name, env))
        todo.extend((server_id, name, None) for server_id, name in warm)
        order = [s.id for s in servers]
        if learned:
            _write_unconfigured(unconfigured_cache)

    def run(item):
        server_id, name, env = item
        # Own app context (= own DB session) per worker thread.
        with app.app_context():
            server = db.session.get(McpServer, server_id)
            try:
                return check_server(server, db.session.get(User, user_id), env=env)
            except Exception as exc:  # one broken server must not hide the rest
                logger.exception("monitoring probe of %s crashed", name)
                return {
                    "id": server_id, "name": name, "transport": server.transport,
                    "ok": False, "tools": 0, "latency_ms": 0,
                    "error": f"probe crashed: {exc}"[:200],
                }

    with ThreadPoolExecutor(max_workers=_MAX_PARALLEL) as pool:
        for result in pool.map(run, todo):
            results[result["id"]] = result
    results = [results[i] for i in order]

    failed = sum(1 for r in results if r["ok"] is False)
    return {
        "generated_at": int(time.time()),
        "servers": results,
        "total": len(results),
        "failed": failed,
    }


def _snapshot_paths():
    # Next to the per-user proxy state (isolated per test via STATE_DIR).
    base = user_proxy.STATE_DIR.parent
    return base / "monitoring.json", base / "monitoring.lock"


def _unconfigured_cache_path():
    _, lock_path = _snapshot_paths()
    return lock_path.parent / "monitoring-unconfigured.json"


def _read_unconfigured():
    try:
        cache = json.loads(_unconfigured_cache_path().read_text())
    except (OSError, ValueError):
        return {}
    return cache if isinstance(cache, dict) else {}


def _write_unconfigured(cache):
    path = _unconfigured_cache_path()
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(cache))
        os.replace(tmp, path)  # atomic — readers never see a partial file
    except OSError:
        logger.exception("monitoring: cannot persist unconfigured-server cache")


def _server_fingerprint(server):
    """The server-row state an 'unconfigured' verdict depends on. Edits to
    any of these (admin form save) invalidate a cached verdict; pure
    credential-value changes (vault item edited, user override set) don't
    touch the row and are picked up via _UNCONFIGURED_TTL instead."""
    return json.dumps({
        "command": server.command,
        "args": list(server.args or []),
        "env_var_names": list(server.env_var_names or []),
        "env_config": server.env_config or {},
        "required_env_keys": list(server.required_env_keys or []),
        "vault_item": server.vault_item,
        "auth_env_key": getattr(server, "auth_env_key", None),
    }, sort_keys=True, default=str)


def _cached_unconfigured_verdict(server, cache):
    """Cached "unconfigured" result for a cold server, or None when the
    verdict is unknown, stale (_UNCONFIGURED_TTL) or invalidated by a
    server edit (config fingerprint changed since the verdict)."""
    entry = cache.get(str(server.id))
    if not isinstance(entry, dict):
        return None
    if time.time() - entry.get("ts", 0) > _UNCONFIGURED_TTL:
        return None
    if entry.get("fp") != _server_fingerprint(server):
        return None
    return _result(server, None, error="unconfigured")


def _read_snapshot():
    path, _ = _snapshot_paths()
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _refresh(app, lock_file):
    """Runs in a background thread holding the (non-blocking) flock, so only
    one worker process probes at a time; the result goes to a shared file
    that every gunicorn worker serves."""
    try:
        try:
            snapshot = check_servers(app)
        except Exception as exc:
            logger.exception("monitoring refresh failed")
            snapshot = {
                "generated_at": int(time.time()),
                "servers": [],
                "total": 0,
                "failed": 0,
                "error": str(exc)[:200],
            }
        path, _ = _snapshot_paths()
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot))
        os.replace(tmp, path)
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()


def get_snapshot(app):
    """Last known result (with `age_seconds`); starts a background refresh
    when it is older than MONITORING_CACHE_TTL or missing. The snapshot is a
    file shared by all worker processes, and a flock makes refreshes
    single-flight across them."""
    ttl = app.config["MONITORING_CACHE_TTL"]
    snapshot = _read_snapshot()
    stale = snapshot is None or time.time() - snapshot["generated_at"] > ttl
    if stale:
        path, lock_path = _snapshot_paths()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            lock_file = open(lock_path, "w")
        except OSError:
            lock_file = None
            logger.exception("monitoring: cannot create lock file")
        if lock_file is not None:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                lock_file.close()  # another worker is refreshing
            else:
                threading.Thread(
                    target=_refresh, args=(app, lock_file), daemon=True, name="mcprack-monitor"
                ).start()

    if snapshot is None:
        return {"pending": True, "servers": [], "total": 0, "failed": 0, "age_seconds": None}
    result = dict(snapshot)
    result["age_seconds"] = int(time.time() - snapshot["generated_at"])
    return result
