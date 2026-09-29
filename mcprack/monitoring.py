"""End-to-end server checks for external monitoring (Zabbix).

`/health` only proves the app and its database are up. That said nothing
when a registered MCP server's backend crashed: the relay still answered
`initialize` and returned an empty `tools/list`. `check_servers()` runs the
same handshake a real client does against every enabled server and reports
per-server results.

Probing spawns backends (cold starts take seconds), so it never runs inside
a request: `get_snapshot()` returns the last result immediately and, when it
has gone stale, refreshes it in a background thread (one at a time per
worker process).
"""

import logging
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
_lock = threading.Lock()
_snapshot = None
_refreshing = False


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


def resolve_env(server, user):
    """(env, early_result). Credential lookups go through Vaultwarden's
    single cross-process lock, so callers resolve them one server at a time
    (parallel lookups just time out on each other and read as outages)."""
    start = time.monotonic()
    try:
        env = secret_store.resolve_server_env(server, user=user)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        return None, _result(
            server, False, error=f"could not resolve credentials: {exc}"[:200],
            latency=time.monotonic() - start,
        )
    if [key for key in server.required_env_keys if not env.get(key)]:
        return None, _result(server, None, error="unconfigured", latency=time.monotonic() - start)
    return env, None


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
        for server in servers:
            env, early = resolve_env(server, user)
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


def _refresh(app):
    global _snapshot, _refreshing
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
    with _lock:
        _snapshot = snapshot
        _refreshing = False


def get_snapshot(app):
    """Last known result (with `age_seconds`); starts a background refresh
    when it is older than MONITORING_CACHE_TTL or missing."""
    global _refreshing
    ttl = app.config["MONITORING_CACHE_TTL"]
    with _lock:
        snapshot = _snapshot
        stale = snapshot is None or time.time() - snapshot["generated_at"] > ttl
        start = stale and not _refreshing
        if start:
            _refreshing = True
    if start:
        threading.Thread(target=_refresh, args=(app,), daemon=True, name="mcprack-monitor").start()

    if snapshot is None:
        return {"pending": True, "servers": [], "total": 0, "failed": 0, "age_seconds": None}
    result = dict(snapshot)
    result["age_seconds"] = int(time.time() - snapshot["generated_at"])
    return result
