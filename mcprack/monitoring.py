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
    when already resolved; otherwise it is resolved here."""
    if env is None:
        env, early = resolve_env(server, user)
        if early is not None:
            return early

    start = time.monotonic()

    def done(ok, tools=None, error=None):
        return _result(server, ok, tools, error, time.monotonic() - start)

    if server.command:
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
        # Phase 1 (serial): credentials. Phase 2 (parallel): probes.
        results, todo = {}, []
        envs = resolve_envs(servers, user)
        for server in servers:
            env, early = envs[server.id]
            if early is not None:
                results[server.id] = early
            else:
                todo.append((server.id, server.name, env))
        order = [s.id for s in servers]

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
