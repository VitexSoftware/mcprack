import contextlib
import fcntl
import http.client
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

import audit
import telemetry


STATE_DIR = Path("/var/lib/mcprack/user-proxies")
_KEY_RE = re.compile(r"^u(?P<user_id>\d+)-s(?P<server_id>\d+)$")

# How long a spawn-time handshake probe result stays trusted before an
# already-running instance gets re-verified on its next use. Keeps the
# common (healthy) path fast — most requests just check a timestamp — while
# still catching an upstream that broke sometime after it was last proven
# to work (e.g. the backing command started crashing on every real
# connection after a package got corrupted underneath it).
HEALTH_RECHECK_INTERVAL = 30  # seconds
# Bounded connect+handshake timeout for the liveness probe itself. A dead
# or crash-looping upstream must fail within this window, not hang
# indefinitely or take an unpredictable number of seconds depending on
# fastmcp's own internal retry timing.
#
# A cold `fastmcp run ... --transport http` takes several seconds just to
# finish starting Uvicorn and bind its port before it can answer this probe
# at all -- and a server whose own MCP implementation makes an outbound
# call as part of its own startup (e.g. an auth handshake against a remote
# API) adds more on top of that, with real network-dependent variance: one
# measured cold run on production against a server that does exactly this
# (multiflexi-mcp-server, which authenticates against a remote host before
# it's ready) succeeded at 11.2s and a separate cold run of the *same*
# server hit a 12s budget and failed -- 12s was not a comfortable margin,
# it was a coin flip. 15s (still comfortably under gunicorn's 30s worker
# timeout, see LOCK_WAIT_TIMEOUT below) is. Overridable via env var since
# "how slow is cold start here" is a deployment- (and backend-) specific
# fact, not a code constant.
HANDSHAKE_TIMEOUT = int(os.environ.get("MCP_PROXY_HANDSHAKE_TIMEOUT", "15"))  # seconds
# How long a caller waits for another worker's lock on the same (user,
# server) pair before giving up — must comfortably exceed a full
# spawn+handshake cycle (HANDSHAKE_TIMEOUT plus spawn overhead) while
# staying under gunicorn's own request timeout (30s, see
# debian/mcprack.service) so a stuck lock surfaces as our own error
# instead of a bare worker-killed 502.
LOCK_WAIT_TIMEOUT = int(os.environ.get("MCP_PROXY_LOCK_WAIT_TIMEOUT", "22"))  # seconds


class UserProxyError(RuntimeError):
    pass


def _server_key(user_id, server_id):
    return f"u{user_id}-s{server_id}"


def _port_for(user_id, server_id):
    return 35000 + ((user_id * 997 + server_id * 37) % 20000)


def _paths(user_id, server_id):
    key = _server_key(user_id, server_id)
    base = STATE_DIR / key
    return {
        "config": base.with_suffix(".json"),
        "meta": base.with_suffix(".meta.json"),
        "pid": base.with_suffix(".pid"),
        "last_used": base.with_suffix(".last_used"),
        "healthy_at": base.with_suffix(".healthy_at"),
        "log": base.with_suffix(".log"),
    }


def _lock_path(user_id, server_id):
    return STATE_DIR / f"{_server_key(user_id, server_id)}.lock"


@contextlib.contextmanager
def _serialized(user_id, server_id):
    """Cross-process mutex around the read-decide-spawn sequence for one
    (user, server) pair.

    mcprack runs under multiple gunicorn worker *processes* (see
    `--workers 4` in debian/mcprack.service), not just threads, so an
    in-process lock isn't enough. Without this, two near-simultaneous cold
    requests for the same pair could both decide a restart was needed and
    both call `_spawn()`: the loser's failure-cleanup then deletes the
    still-alive winner's pid/meta/healthy_at files, which made every
    following request see "not running" and retry the same collision
    forever — 502s on every fresh request while an already-warm client
    session against the same server kept working undisturbed the whole
    time (GitHub issue #1). Locking is per-key, so unrelated (user,
    server) pairs never block each other.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_WAIT_TIMEOUT
    with open(_lock_path(user_id, server_id), "w") as lock_file:
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise UserProxyError(
                        f"Timed out waiting for another request to finish starting this "
                        f"server (lock wait exceeded {LOCK_WAIT_TIMEOUT}s)"
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _parse_key(stem):
    match = _KEY_RE.match(stem)
    if not match:
        return None, None
    return int(match.group("user_id")), int(match.group("server_id"))


def _read_text(path):
    try:
        return path.read_text()
    except OSError:
        return None


def _read_pid(path):
    raw = _read_text(path)
    if not raw:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def _read_float(path):
    raw = _read_text(path)
    if not raw:
        return None
    try:
        return float(raw.strip())
    except ValueError:
        return None


def _pid_running(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _stop_pid(pid, timeout=3.0):
    if not _pid_running(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_running(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _desired_config(server_name, command, args, env):
    return {
        "mcpServers": {
            server_name: {
                "type": "stdio",
                "command": command,
                "args": args or [],
                "env": env or {},
            }
        }
    }


def _probe_upstream_health(port, timeout=HANDSHAKE_TIMEOUT):
    """Bounded, best-effort liveness probe against a fastmcp proxy
    instance — does its backing stdio command actually respond, or does
    every real request fail? A broken backend (crashes on import, wrong
    path, missing dependency, ...) should never be handed out as if it
    were usable; this catches that in a fixed, short window instead of the
    caller discovering it after an unpredictable hang or delay.

    Deliberately permissive on anything short of a clear failure signal:
    a transport-level failure (refused/timed-out connection) or an
    explicit top-level JSON-RPC "error" in the response means unhealthy.
    Anything else — a real result, a non-JSON body (e.g. an SSE stream),
    an unexpected-but-non-error shape — is treated as probably fine. The
    goal is to catch a definitely-broken upstream, not to fully validate
    protocol compliance and risk false positives against a healthy one.

    Connection-refused is retried (with a short backoff) until `timeout`
    elapses rather than failing on the first attempt: the caller only
    reaches here once the subprocess itself is confirmed still alive
    (`_spawn`'s poll() check already caught the exited-immediately case),
    so a refused connection here just means the HTTP server hasn't
    finished binding its port yet, not that the backend is broken. A
    fresh interpreter loading heavy dependencies for the first time can
    easily take longer than the old single-shot ~0.2s grace period,
    which made cold spawns fail the handshake even though the backend
    would have come up fine a second later.
    """
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "mcprack-health-probe",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcprack-health-probe", "version": "1.0"},
            },
        }
    ).encode()

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=remaining)
        try:
            conn.request(
                "POST",
                "/mcp",
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            resp = conn.getresponse()
            body = resp.read()
        except ConnectionRefusedError:
            time.sleep(min(0.1, max(remaining, 0)))
            continue
        except (OSError, http.client.HTTPException):
            return False
        finally:
            conn.close()
        break

    try:
        data = json.loads(body)
    except ValueError:
        return True

    if isinstance(data, dict) and "error" in data:
        return False
    return True


def _clear_state_files(paths):
    for key in ("pid", "meta", "config", "healthy_at"):
        try:
            paths[key].unlink()
        except OSError:
            pass


def _spawn(paths, port, server_name, desired_config, desired_json):
    paths["config"].write_text(json.dumps(desired_config, indent=2))
    paths["meta"].write_text(desired_json)

    with paths["log"].open("a") as log_file:
        proc = subprocess.Popen(
            [
                "/usr/bin/fastmcp",
                "run",
                str(paths["config"]),
                "--transport",
                "http",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "INFO",
            ],
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )

    paths["pid"].write_text(str(proc.pid))
    paths["last_used"].write_text(str(int(time.time())))
    time.sleep(0.2)
    if proc.poll() is not None:
        _clear_state_files(paths)
        raise UserProxyError(f"User proxy process exited early for {server_name}")

    if not _probe_upstream_health(port):
        _stop_pid(proc.pid)
        _clear_state_files(paths)
        raise UserProxyError(
            f"Upstream MCP server '{server_name}' failed its startup handshake within "
            f"{HANDSHAKE_TIMEOUT}s — the registered command is likely broken (check its "
            f"log at {paths['log']}, or its registration in Admin → Servers)."
        )

    paths["healthy_at"].write_text(str(time.time()))


def ensure_user_server_proxy(user_id, server_id, server_name, command, args, env):
    if not command:
        raise UserProxyError("Cannot start user proxy for server without command")

    with _serialized(user_id, server_id):
        paths = _paths(user_id, server_id)
        port = _port_for(user_id, server_id)

        desired_config = _desired_config(server_name, command, args, env)
        desired_json = json.dumps(desired_config, sort_keys=True)

        meta_current = _read_text(paths["meta"])
        pid = _read_pid(paths["pid"])
        running = _pid_running(pid)

        needs_restart = (not running) or (meta_current != desired_json)

        if not needs_restart:
            healthy_at = _read_float(paths["healthy_at"])
            if healthy_at is not None and (time.time() - healthy_at) < HEALTH_RECHECK_INTERVAL:
                paths["last_used"].write_text(str(int(time.time())))
                return port

            # Health verification is stale (or this instance predates the
            # health-tracking columns) — re-probe an already-running instance
            # before handing it out again, so an upstream that started failing
            # sometime after it was last proven to work gets caught and
            # restarted here instead of failing unpredictably per-request.
            if _probe_upstream_health(port):
                paths["healthy_at"].write_text(str(time.time()))
                paths["last_used"].write_text(str(int(time.time())))
                return port

            _stop_pid(pid)
        elif running:
            _stop_pid(pid)

        start_time = time.monotonic()
        with telemetry.span("mcp.proxy.start", {"server_name": server_name}) as current_span:
            try:
                _spawn(paths, port, server_name, desired_config, desired_json)
            except UserProxyError as exc:
                audit.log_audit_event(
                    "proxy_start",
                    "error",
                    user_id=user_id,
                    server_id=server_id,
                    server_name=server_name,
                    error_message=str(exc)[:500],
                    duration_ms=int((time.monotonic() - start_time) * 1000),
                )
                if current_span is not None:
                    current_span.set_attribute("mcp.result", "error")
                raise
            audit.log_audit_event(
                "proxy_start",
                "success",
                user_id=user_id,
                server_id=server_id,
                server_name=server_name,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
            if current_span is not None:
                current_span.set_attribute("mcp.result", "success")
        return port


def cleanup_idle_proxies(max_idle_seconds=900):
    if not STATE_DIR.exists():
        return

    now = time.time()
    for pid_path in STATE_DIR.glob("*.pid"):
        base = pid_path.with_suffix("")
        last_used_path = base.with_suffix(".last_used")

        pid = _read_pid(pid_path)
        if not pid:
            continue

        try:
            last_used = float((last_used_path.read_text() or "0").strip())
        except OSError:
            last_used = 0.0
        except ValueError:
            last_used = 0.0

        if (now - last_used) > max_idle_seconds:
            user_id, server_id = _parse_key(pid_path.stem)
            if user_id is None:
                continue
            with _serialized(user_id, server_id):
                # Re-check under the lock — a concurrent request may have
                # refreshed (or already stopped) this instance since the
                # unlocked scan above.
                pid = _read_pid(pid_path)
                if not pid:
                    continue
                try:
                    last_used = float((last_used_path.read_text() or "0").strip())
                except (OSError, ValueError):
                    last_used = 0.0
                if (now - last_used) <= max_idle_seconds:
                    continue
                _stop_pid(pid)
            audit.log_audit_event(
                "proxy_stop",
                "success",
                user_id=user_id,
                server_id=server_id,
                error_message="idle timeout",
            )


def stop_user_server_proxy(user_id, server_id):
    with telemetry.span("mcp.proxy.stop", {"server_id": server_id}):
        with _serialized(user_id, server_id):
            paths = _paths(user_id, server_id)
            pid = _read_pid(paths["pid"])
            if pid:
                _stop_pid(pid)
            for key in ("pid", "last_used", "meta", "config", "healthy_at"):
                try:
                    paths[key].unlink()
                except OSError:
                    pass
        audit.log_audit_event("proxy_stop", "success", user_id=user_id, server_id=server_id)


def list_proxy_instances():
    instances = []
    if not STATE_DIR.exists():
        return instances

    for pid_path in STATE_DIR.glob("*.pid"):
        stem = pid_path.stem
        user_id, server_id = _parse_key(stem)
        if user_id is None:
            continue

        paths = _paths(user_id, server_id)
        pid = _read_pid(paths["pid"])
        running = _pid_running(pid)
        port = _port_for(user_id, server_id)

        last_used = 0.0
        try:
            last_used = float((paths["last_used"].read_text() or "0").strip())
        except (OSError, ValueError):
            last_used = 0.0

        instances.append(
            {
                "user_id": user_id,
                "server_id": server_id,
                "pid": pid,
                "running": running,
                "port": port,
                "last_used": last_used,
                "idle_seconds": max(0, int(time.time() - last_used)) if last_used else None,
                "log_path": str(paths["log"]),
            }
        )

    instances.sort(key=lambda row: (not row["running"], row["idle_seconds"] or 0, row["user_id"], row["server_id"]))
    return instances