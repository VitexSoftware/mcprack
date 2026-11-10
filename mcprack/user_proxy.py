import contextlib
import fcntl
import http.client
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

from . import audit
from . import health
from . import telemetry


logger = logging.getLogger(__name__)

# Where the per-(user, server) instances keep their files - including the
# RESOLVED credentials of the pair (the fastmcp config carries them in its
# `env`). systemd's RuntimeDirectory=mcprack gives a tmpfs directory that is
# private to the service and disappears when it stops, so neither credentials
# nor stale pid files survive a restart (docs/AUDIT-2026-11.md B-02, B-12).
# Without it (development, containers) the old persistent location is used.
RUNTIME_DIR = Path("/run/mcprack")
LEGACY_STATE_DIR = Path("/var/lib/mcprack/user-proxies")


def default_state_dir():
    explicit = os.environ.get("MCPRACK_STATE_DIR")
    if explicit:
        return Path(explicit)
    if RUNTIME_DIR.is_dir() and os.access(RUNTIME_DIR, os.W_OK):
        return RUNTIME_DIR / "user-proxies"
    return LEGACY_STATE_DIR


STATE_DIR = default_state_dir()
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
# How long a relayed request waits for the pair's shared relay guard
# before proceeding unguarded. The guard only ever contends with a stop
# path holding the exclusive lock, and a relay itself is bounded by the
# request timeout, so this only needs to cover a stop cycle, not a spawn.
RELAY_GUARD_WAIT = int(os.environ.get("MCP_PROXY_RELAY_GUARD_WAIT", "5"))  # seconds


class UserProxyError(RuntimeError):
    """A proxy instance could not be started or reached.

    `kind` says which class of failure it is (docs/AUDIT-2026-11.md B-13), so
    "the binary is missing", "the process died while starting", "it is alive
    but never answered", "it answered with an error" and "it started but has no
    tools" are no longer one undifferentiated message:

        spawn_failed       fastmcp (or the OS) refused to launch the process
        exited_early       the process died during startup - see its log
        startup_timeout    alive, but never answered on its port in time
        unreachable        the port could not be connected to / spoke no HTTP
        http_error         initialize returned an HTTP error status
        handshake_error    initialize returned a JSON-RPC error
        no_tools           initialize worked, tools/list is empty (crash on load)
        tools_list_failed  tools/list itself failed
        handshake_failed   generic (older code paths)
        unknown            anything raised without a class

    `str(exc)` is the administrator's view and may end with the tail of the
    instance log. `public_message` is what an end user's client gets: the class
    of failure and who to ask, without log lines (paths, host names, and
    whatever the MCP server decided to print)."""

    def __init__(self, message="", kind="unknown", public=None):
        super().__init__(message)
        self.kind = kind
        self._public = public

    @property
    def public_message(self):
        return self._public if self._public is not None else str(self)


# What a spawned fastmcp process (and, through it, the MCP server) may inherit
# from mcprack's own environment. It used to be a copy of ALL of it:
# SECRET_KEY, BW_PASSWORD (the Vaultwarden master password), LDAP_BIND_PASSWORD,
# the database URL ... readable from /proc/<pid>/environ by every MCP server
# (docs/AUDIT-2026-11.md A-04). Everything a server needs comes from its own
# configuration (the `env` of the config file); only the plumbing below is
# passed on, plus whatever the operator lists in MCP_CHILD_ENV_ALLOW.
_CHILD_ENV_ALLOW = frozenset(
    {
        "PATH", "LANG", "LANGUAGE", "TZ", "HOME", "USER", "LOGNAME", "TMPDIR",
        "PYTHONIOENCODING",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    }
)
_CHILD_ENV_PREFIXES = ("LC_",)
# Names that must never reach a child, even if an operator lists them.
_CHILD_ENV_NEVER_PREFIXES = (
    "SECRET_KEY", "BW_", "BITWARDEN", "LDAP_", "SMTP_", "MONITORING_", "SQLALCHEMY_", "OAUTH_", "OTEL_",
    "GUNICORN", "MCPRACK_", "PASSWORD_", "LOGIN_",
)


def _extra_child_env_names():
    raw = os.environ.get("MCP_CHILD_ENV_ALLOW", "")
    try:
        from flask import current_app, has_app_context

        if has_app_context():
            raw = current_app.config.get("MCP_CHILD_ENV_ALLOW", raw) or raw
    except Exception:  # pragma: no cover
        pass
    names = {name.strip() for name in raw.split(",") if name.strip()}
    return {n for n in names if not n.upper().startswith(_CHILD_ENV_NEVER_PREFIXES)}


def _child_environment():
    allowed = _CHILD_ENV_ALLOW | _extra_child_env_names()
    env = {
        name: value
        for name, value in os.environ.items()
        if name in allowed or name.startswith(_CHILD_ENV_PREFIXES)
    }
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    # systemd does not set LANG, so without these a Python-based MCP server
    # inherits an ASCII locale and dies on the first non-ASCII byte it tries
    # to write.
    env.setdefault("LANG", "C.UTF-8")
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _ensure_state_dir():
    """The state directory, private to the service user (it holds credentials)."""
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass


def _write_private(path, text):
    """Write `text` to `path` readable by the service user only, whatever the
    process umask is, replacing any older (possibly more open) file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _server_key(user_id, server_id):
    return f"u{user_id}-s{server_id}"


def _port_for(user_id, server_id):
    return 35000 + ((user_id * 997 + server_id * 37) % 20000)


def _paths(user_id, server_id):
    """Every state file one (user, server) proxy owns. The state lives in
    files rather than in memory because the gunicorn workers are separate
    processes - whichever one handles the next relay has to find the
    instance another worker spawned."""
    key = _server_key(user_id, server_id)
    base = STATE_DIR / key
    return {
        "config": base.with_suffix(".json"),
        "meta": base.with_suffix(".meta.json"),
        "pid": base.with_suffix(".pid"),
        "port": base.with_suffix(".port"),
        "last_used": base.with_suffix(".last_used"),
        "healthy_at": base.with_suffix(".healthy_at"),
        "log": base.with_suffix(".log"),
    }


def _lock_path(user_id, server_id):
    return STATE_DIR / f"{_server_key(user_id, server_id)}.lock"


@contextlib.contextmanager
def _serialized(user_id, server_id, wait_seconds=None):
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

    `wait_seconds` bounds how long acquisition may poll before giving up
    with UserProxyError. None means the full LOCK_WAIT_TIMEOUT — right for
    a request that actually needs this pair (the caller has nothing to
    fall back to). Callers that can simply skip a busy pair — idle-proxy
    cleanup — pass a short (or zero) value instead of queueing behind a
    spawn that may legitimately hold the lock for a whole cold-start
    handshake.
    """
    wait = LOCK_WAIT_TIMEOUT if wait_seconds is None else wait_seconds
    _ensure_state_dir()
    deadline = time.monotonic() + wait
    with open(_lock_path(user_id, server_id), "w") as lock_file:
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise UserProxyError(
                        f"Timed out waiting for another request to finish starting this "
                        f"server (lock wait exceeded {wait}s)"
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


@contextlib.contextmanager
def relay_guard(user_id, server_id):
    """Shared (read) hold on the pair's lock file for the duration of one
    relayed request, so no stop path — idle reaper, health re-probe
    restart, server deletion — can SIGTERM/SIGKILL the per-user proxy
    while a request is in flight against it.

    Every stop path takes the same file's lock exclusively first (via
    `_serialized`), so a held shared lock makes those paths either skip
    the pair (cleanup/deletion use wait_seconds=0) or wait for the relay
    to drain (ensure uses the blocking wait). GET relays are deliberately
    NOT guarded by the caller: they carry a long-lived SSE stream that
    would hold the lock for minutes and block reaping.

    Best-effort by design: the guard must never fail a relay. If the
    lock file cannot be opened, or the shared lock is not acquired
    within RELAY_GUARD_WAIT, the relay proceeds unguarded (the previous
    behaviour). A fresh fd is used because ensure_user_server_proxy has
    already released its own exclusive hold by relay time — taking
    LOCK_SH on that same fd would self-deadlock. The kernel releases the
    lock automatically if this worker dies mid-relay, so nothing leaks.
    """
    guard_file = None
    try:
        _ensure_state_dir()
        guard_file = open(_lock_path(user_id, server_id), "a")
    except OSError:
        guard_file = None

    if guard_file is not None:
        deadline = time.monotonic() + RELAY_GUARD_WAIT
        while True:
            try:
                fcntl.flock(guard_file, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    # Proceed unguarded rather than fail or hang the relay.
                    guard_file.close()
                    guard_file = None
                    break
                time.sleep(0.05)

    try:
        yield
    finally:
        if guard_file is not None:
            try:
                fcntl.flock(guard_file, fcntl.LOCK_UN)
            finally:
                guard_file.close()


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


def _process_is_ours(pid, config_path):
    """Whether `pid` is the fastmcp instance started from `config_path`.

    True / False when /proc can tell, None when it cannot (the process is gone,
    or there is no /proc). The instance's command line contains its own config
    file as an argument, which a recycled pid - a gunicorn worker, sshd, anything
    else of the same uid - never will."""
    try:
        with open(f"/proc/{int(pid)}/cmdline", "rb") as handle:
            arguments = handle.read().split(b"\0")
    except (OSError, ValueError):
        return None
    return os.fsencode(str(config_path)) in arguments


def _read_pid(path):
    """The pid recorded for an instance, or None when the file is missing,
    empty or corrupt - or when the pid now belongs to some other process.

    A half-written file during a crash must read as "no instance", not raise.
    And a pid file that outlived its process (crash, hard restart) must never
    make the stop path signal whatever has since been given that pid: after
    `kill(pid)` and `killpg(pid)` we would be shooting at a stranger
    (docs/AUDIT-2026-11.md B-12)."""
    raw = _read_text(path)
    if not raw:
        return None
    try:
        pid = int(raw.strip())
    except ValueError:
        return None
    if _process_is_ours(pid, Path(path).with_suffix(".json")) is False:
        logger.warning("pid %s recorded in %s is not that instance any more (recycled pid) - ignoring it", pid, path)
        return None
    return pid


def _read_port(path):
    """The port a spawn actually bound. It is not always _port_for()'s value:
    a collision moves the instance to base+N, and that is the only record of
    which port the live process is on. None when there is no usable record,
    so callers fall back to the deterministic base port."""
    raw = _read_text(path)
    if not raw:
        return None
    try:
        port = int(raw.strip())
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _read_float(path):
    raw = _read_text(path)
    if not raw:
        return None
    try:
        return float(raw.strip())
    except ValueError:
        return None


# The instances this worker process started. A child nobody wait()s for stays
# a zombie - in the process table, and (since it does not count as running)
# invisible to every check - until its parent collects it. Only the parent can,
# so each worker keeps its own children and polls them whenever it passes
# through the proxy code (docs/AUDIT-2026-11.md B-12).
_CHILDREN = {}


def _reap_children():
    for pid, proc in list(_CHILDREN.items()):
        try:
            if proc.poll() is not None:
                del _CHILDREN[pid]
        except Exception:  # noqa: BLE001 - housekeeping must never break a relay
            _CHILDREN.pop(pid, None)


def _pid_running(pid):
    """Whether `pid` is a process that could still serve a relay. A zombie
    counts as gone - see the comment below for why kill(pid, 0) alone is
    not enough."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # A zombie holds no sockets and can never answer a probe, but
    # kill(pid, 0) alone reports it as "running" — which would waste a
    # stop cycle's SIGTERM/SIGKILL on a corpse and then probe a dead
    # port. Treat it as gone so the caller respawns instead. Linux-only
    # (/proc); anywhere else, fall back to the kill(0) result.
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat_file:
            state = stat_file.read().rsplit(b")", 1)[1].split()[0]
        if state == b"Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def _stop_pid(pid, timeout=3.0):
    """SIGTERM, then SIGKILL once `timeout` has passed with the process
    still alive. Escalating rather than waiting indefinitely: a wedged
    fastmcp still holds the port the respawn needs."""
    if not _pid_running(pid):
        return

    def _send_signal(sig):
        """Signal the whole process group, falling back to the pid alone.
        fastmcp runs with start_new_session=True so its process group is
        pid; signalling the group is what stops the stdio MCP server it
        spawned from being orphaned."""
        # killpg(pid) only means "the instance's group" when the instance leads
        # it. If the pid has been recycled into somebody else's group (or the
        # instance was somehow not started in a new session) never signal that
        # group - signal the pid alone.
        leads_its_group = True
        try:
            leads_its_group = os.getpgid(pid) == pid
        except OSError:
            pass  # gone already: the calls below are harmless
        if leads_its_group:
            try:
                os.killpg(pid, sig)
                return
            except (OSError, ProcessLookupError) as exc:
                logger.debug("killpg(%s, %s) failed (%s), signalling the pid alone", pid, sig, exc)
        try:
            os.kill(pid, sig)
        except OSError:
            pass

    _send_signal(signal.SIGTERM)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_running(pid):
            _reap_children()
            return
        time.sleep(0.1)
    _send_signal(signal.SIGKILL)
    _reap_children()


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


def _probe_upstream_health(port, timeout=HANDSHAKE_TIMEOUT, require_tools=False, proc=None, report=None):
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

    `proc` (the Popen of the instance being started, when there is one) is
    polled on every round: a process that has died will never bind its port, so
    waiting out the whole timeout for it only delays the real answer - which is
    in its log. `report`, when given, is a dict that receives `kind` and
    `detail` for a failure (see UserProxyError); the return value stays a bool.
    """
    def fail(kind, detail=""):
        if report is not None:
            report["kind"] = kind
            report["detail"] = detail
        return False

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
        if proc is not None and proc.poll() is not None:
            return fail("exited_early", f"exit status {proc.poll()}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return fail("startup_timeout", f"no answer on port {port} within {timeout:g}s")
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
            body = health._read_mcp_response(resp, "mcprack-health-probe")
        except ConnectionRefusedError:
            time.sleep(min(0.1, max(remaining, 0)))
            continue
        except TimeoutError:
            return fail("startup_timeout", f"port {port} accepted the connection but did not answer within {timeout:g}s")
        except ValueError as exc:
            # health._read_mcp_response: the event stream ended without the
            # initialize result, or carried something that is not JSON-RPC.
            return fail("handshake_error", f"not a valid MCP response ({exc})"[:200])
        except (OSError, http.client.HTTPException) as exc:
            return fail("unreachable", f"{type(exc).__name__}: {exc}")
        finally:
            conn.close()
        break

    try:
        data = json.loads(body)
    except ValueError:
        status = getattr(resp, "status", None)
        if isinstance(status, int) and status >= 400:
            return fail("http_error", f"initialize returned HTTP {status}")
        data = None  # not JSON, not an error status: judged by the tools check below, if one was asked for

    if isinstance(data, dict) and "error" in data:
        error = data["error"]
        message = error.get("message") if isinstance(error, dict) else error
        return fail("handshake_error", str(message)[:200] if message else "")

    if require_tools:
        # initialize alone proves nothing about the wrapped backend (see
        # health.probe_tools). Spawn time is the one moment where a cold
        # backend start is expected anyway, so the deeper check lives here
        # and not in the frequent recheck path.
        ok, _count, error = health.probe_tools(
            "127.0.0.1", port, timeout=max(deadline - time.monotonic(), 1.0)
        )
        if not ok:
            error = str(error or "")
            return fail("no_tools" if "no tools" in error else "tools_list_failed", error)
        return True
    return True


def _clear_state_files(paths):
    """Drop the records of a dead instance so the next ensure() spawns
    instead of probing a port nothing listens on. `last_used` and `log`
    deliberately survive - one drives idle reaping, the other is the only
    evidence left of why the instance died."""
    for key in ("pid", "port", "meta", "config", "healthy_at"):
        try:
            paths[key].unlink()
        except OSError:
            pass


def _resolve_fastmcp_bin():
    """Explicit FASTMCP_BIN, else PATH, else the Debian package location.
    Tested for executability rather than mere existence, and raising instead
    of returning a guess: Popen on a missing path raises FileNotFoundError,
    which callers that only catch UserProxyError would turn into a 500."""
    from flask import current_app
    try:
        cfg = current_app.config.get("FASTMCP_BIN")
    except Exception:
        cfg = None
    if cfg:
        if os.access(cfg, os.X_OK):
            return cfg
        logger.warning("FASTMCP_BIN=%s is not executable; falling back to PATH lookup", cfg)
    found = shutil.which("fastmcp")
    if found:
        return found
    if os.access("/usr/bin/fastmcp", os.X_OK):
        return "/usr/bin/fastmcp"
    raise UserProxyError(
        "No usable 'fastmcp' executable found - install the python3-fastmcp package, "
        "or point FASTMCP_BIN in /etc/mcprack/env at it."
    )


def _read_recent_log(log_path, max_lines=20):
    """The tail of an instance's own log, for a startup failure message.
    Never raises: a missing or unreadable log must not replace the real
    error with an IOError. Callers must redact it before it leaves the
    process - the spawned server may have logged credentials into it."""
    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
            if lines:
                return "".join(lines[-max_lines:]).strip()
    except Exception:
        pass
    return None


# How far past the deterministic base port a spawn may walk when the port
# is taken (by a stale instance, or by an unrelated local service).
_PORT_SEARCH_RANGE = 10


def _is_port_available(port, host="127.0.0.1"):
    """Whether a spawn could bind `port` right now. Racy by nature - the
    answer can be stale by the time fastmcp binds - but it turns the
    common case (a stale instance or an unrelated local service) from an
    opaque handshake failure into a port that simply works."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _find_available_port(user_id, server_id):
    """The deterministic base port for this pair, or the first free port
    above it. Walking upward keeps the mapping stable in the normal case
    while still letting an instance start when the base port is taken."""
    base_port = _port_for(user_id, server_id)
    for offset in range(_PORT_SEARCH_RANGE):
        cand = base_port + offset
        if _is_port_available(cand):
            if offset:
                logger.info("port %s busy, using %s for u%s-s%s", base_port, cand, user_id, server_id)
            return cand
    # Returning the busy base port instead would surface as a generic
    # handshake failure, with the real "address already in use" buried in
    # the instance log.
    raise UserProxyError(
        f"No free local port for this MCP server: {base_port}-{base_port + _PORT_SEARCH_RANGE - 1} "
        "are all in use. Stop stale proxy instances in Admin -> Proxy instances."
    )


_ASK_ADMIN = " Ask an administrator to check the instance log (Admin → Proxy instances)."


def _startup_failure(kind, server_name, paths, detail=""):
    """Clean up after a failed start and build the UserProxyError for it.

    The administrator's message (str) names the failure class, carries the
    detail and the tail of the instance log; the public message names the class
    and who to ask - no log lines, no file system paths (B-13)."""
    recent_log = _read_recent_log(paths["log"])
    _clear_state_files(paths)
    name = server_name
    detail_suffix = f" ({detail})" if detail else ""
    if kind == "exited_early":
        summary = f"User proxy process exited early for {name}{detail_suffix}"
        public = f"The MCP server '{name}' exited right after it was started - its command, a missing dependency or its configuration is probably wrong."
    elif kind == "startup_timeout":
        summary = f"Upstream MCP server '{name}' failed its startup handshake within {HANDSHAKE_TIMEOUT}s: it is running but never answered{detail_suffix}"
        public = f"The MCP server '{name}' started but did not answer within {HANDSHAKE_TIMEOUT}s."
    elif kind == "handshake_error":
        summary = f"Upstream MCP server '{name}' failed its startup handshake: initialize returned an error{detail_suffix}"
        public = f"The MCP server '{name}' answered the start-up handshake with an error."
    elif kind == "http_error":
        summary = f"Upstream MCP server '{name}' failed its startup handshake: {detail or 'HTTP error'}"
        public = f"The MCP server '{name}' answered the start-up handshake with an HTTP error."
    elif kind == "unreachable":
        summary = f"Upstream MCP server '{name}' failed its startup handshake: could not talk to it{detail_suffix}"
        public = f"The MCP server '{name}' started but could not be reached."
    elif kind == "no_tools":
        summary = f"Upstream MCP server '{name}' failed its startup handshake: it started but serves no tools (it probably crashed while loading)"
        public = f"The MCP server '{name}' started but serves no tools - it probably crashed while loading."
    elif kind == "tools_list_failed":
        summary = f"Upstream MCP server '{name}' failed its startup handshake: tools/list failed{detail_suffix}"
        public = f"The MCP server '{name}' started but could not list its tools."
    else:
        kind = "handshake_failed"
        summary = (
            f"Upstream MCP server '{name}' failed its startup handshake within "
            f"{HANDSHAKE_TIMEOUT}s (or serves no tools) — the registered command is likely broken."
        )
        public = f"The MCP server '{name}' failed its start-up handshake."
    err = summary
    if recent_log:
        err += f":\n{recent_log}" if kind == "exited_early" else f"\nLast log lines:\n{recent_log}"
    else:
        err += f" (check its log at {paths['log']}, or its registration in Admin → Servers)."
    return UserProxyError(err, kind=kind, public=public + _ASK_ADMIN)


def _spawn(paths, port, server_name, desired_config, desired_json):
    """Write the instance's config and start fastmcp on `port`. The config
    and meta files are written first so a worker that finds the pid can
    tell whether the running instance matches the config it wants."""
    _write_private(paths["config"], json.dumps(desired_config, indent=2))
    _write_private(paths["meta"], desired_json)
    _write_private(paths["port"], str(port))

    fastmcp_bin = _resolve_fastmcp_bin()
    spawn_env = _child_environment()

    _reap_children()
    try:
        with paths["log"].open("a") as log_file:
            proc = subprocess.Popen(
                [
                    fastmcp_bin,
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
                env=spawn_env,
                start_new_session=True,
            )
    except OSError as exc:
        # Not found / not executable / out of processes: nothing was started,
        # so there is no log to read - the OS error is the whole story.
        _clear_state_files(paths)
        raise UserProxyError(
            f"Could not launch fastmcp for {server_name}: {exc.strerror or exc}",
            kind="spawn_failed",
            public=f"The MCP server '{server_name}' could not be launched on this host.{_ASK_ADMIN}",
        ) from exc
    _CHILDREN[proc.pid] = proc

    _write_private(paths["pid"], str(proc.pid))
    _write_private(paths["last_used"], str(int(time.time())))
    time.sleep(0.2)
    if proc.poll() is not None:
        raise _startup_failure("exited_early", server_name, paths, f"exit status {proc.poll()}")

    report = {}
    if not _probe_upstream_health(port, require_tools=True, proc=proc, report=report):
        kind = report.get("kind", "handshake_failed")
        if kind != "exited_early":
            _stop_pid(proc.pid)  # alive but useless: free its port for the respawn
        raise _startup_failure(kind, server_name, paths, report.get("detail", ""))

    _write_private(paths["healthy_at"], str(time.time()))


def _effective_args(server, args, env_keys=()):
    """For Docker-installed servers, dynamically appends `-e <NAME>` for
    every currently configured env var name, computed fresh on each spawn
    rather than baked once into stored args — `docker run` never forwards
    host process env into the container on its own (only a bare `-e NAME`
    does, pulling the value from the calling process's own environment), so
    without this a Docker-sourced server would silently never see its
    credentials. Computing it at spawn time (instead of once at install/
    registration time) means adding or removing an env var later via the
    credentials form takes effect on the next proxy start, with nothing
    else to keep in sync. No-op for pip/npm/manually registered servers.

    Registration enforces args always ending in the image ref (see
    admin.py's docker install route), so args[-1] is reliably the image."""
    if server is None or getattr(server, "install_method", None) != "docker":
        return args

    names = list(server.env_var_names) + list(server.env_config.keys()) + list(env_keys)
    if server.auth_env_key:
        names.append(server.auth_env_key)

    flags = []
    for name in dict.fromkeys(names):  # de-dup, preserve first-seen order
        flags += ["-e", name]

    return list(args[:-1]) + flags + list(args[-1:])


def ensure_user_server_proxy(user_id, server_id, server_name, command, args, env, server=None):
    """Return the port of a live proxy for this (user, server), starting or
    restarting it as needed, and raise UserProxyError when it will not come
    up. Idempotent and safe to call from every relay: the whole
    read-decide-spawn sequence is held under the cross-process lock, so
    concurrent workers converge on one instance instead of racing to spawn
    several on the same port."""
    if not command:
        raise UserProxyError("Cannot start user proxy for server without command")

    # env_keys covers keys that exist only in this user's personal override -
    # server.env_var_names/env_config alone would miss them.
    args = _effective_args(server, args, env_keys=(env or {}).keys())
    _reap_children()

    with _serialized(user_id, server_id):
        paths = _paths(user_id, server_id)
        recorded_port = _read_port(paths["port"])
        port = recorded_port if recorded_port else _port_for(user_id, server_id)

        desired_config = _desired_config(server_name, command, args, env)
        desired_json = json.dumps(desired_config, sort_keys=True)

        meta_current = _read_text(paths["meta"])
        pid = _read_pid(paths["pid"])
        running = _pid_running(pid)

        needs_restart = (not running) or (meta_current != desired_json)

        if not needs_restart:
            healthy_at = _read_float(paths["healthy_at"])
            if healthy_at is not None and (time.time() - healthy_at) < HEALTH_RECHECK_INTERVAL:
                _write_private(paths["last_used"], str(int(time.time())))
                return port

            # Health verification is stale (or this instance predates the
            # health-tracking columns) — re-probe an already-running instance
            # before handing it out again, so an upstream that started failing
            # sometime after it was last proven to work gets caught and
            # restarted here instead of failing unpredictably per-request.
            if _probe_upstream_health(port):
                _write_private(paths["healthy_at"], str(time.time()))
                _write_private(paths["last_used"], str(int(time.time())))
                return port

            _stop_pid(pid)
        elif running:
            _stop_pid(pid)

        # For a fresh spawn, find an available port starting from the base port
        port = _find_available_port(user_id, server_id)

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
                    error_message=(f"[{exc.kind}] " if exc.kind != "unknown" else "") + str(exc)[:480],
                    duration_ms=int((time.monotonic() - start_time) * 1000),
                )
                if current_span is not None:
                    current_span.set_attribute("mcp.result", "error")
                    current_span.set_attribute("mcp.failure_kind", exc.kind)
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


def running_proxy_port(user_id, server_id):
    """Port of the already-running instance for this (user, server) pair,
    or None when there is no live pid. Read-only and deliberately lock-free:
    callers use it to decide whether a spawn is needed at all, and any race
    with a concurrent spawn/cleanup is absorbed by the caller's own probe
    or start path. Used by the monitoring prober so a periodic health
    refresh can reuse a warm instance without resolving credentials."""
    paths = _paths(user_id, server_id)
    if not _pid_running(_read_pid(paths["pid"])):
        return None
    recorded_port = _read_port(paths["port"])
    if recorded_port:
        return recorded_port
    return _port_for(user_id, server_id)


def mark_proxy_used(user_id, server_id):
    """Refresh a running instance's idle timer without spawning anything
    or touching its config — the monitoring prober verifies a warm
    instance directly and must keep it alive exactly like a real request
    would, without becoming a periodic credential client."""
    try:
        _write_private(_paths(user_id, server_id)["last_used"], str(int(time.time())))
    except OSError:
        pass


def cleanup_idle_proxies(max_idle_seconds=900):
    _reap_children()
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
            try:
                with _serialized(user_id, server_id, wait_seconds=0):
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
                    stopped_name = _server_name_from_meta(user_id, server_id)  # read before the file goes
                    _stop_pid(pid)
                    # the process is gone: so must the credentials it was started with
                    paths = _paths(user_id, server_id)
                    for key in ("pid", "port", "meta", "config", "healthy_at"):
                        try:
                            paths[key].unlink()
                        except OSError:
                            pass
            except UserProxyError:
                # Another worker holds this pair's lock — it is starting
                # (or stopping) the instance right now. Never queue a user
                # request behind it: skip this pair and let the next
                # request's cleanup round collect it. Waiting here is what
                # turned cleanup into a request killer: a cold-start spawn
                # holds the lock for the whole handshake (up to
                # HANDSHAKE_TIMEOUT seconds), so every concurrent request
                # burned up to LOCK_WAIT_TIMEOUT in cleanup *before even
                # parsing its token*, then surfaced as 500/502.
                continue
            audit.log_audit_event(
                "proxy_stop",
                "success",
                user_id=user_id,
                server_id=server_id,
                server_name=stopped_name,
                error_message="idle timeout",
            )


def _server_name_from_meta(user_id, server_id):
    """Best-effort server-name snapshot from the instance's meta file, for
    audit rows written after the McpServer row is gone (e.g. an admin
    deleted the server while a proxy process was still running)."""
    raw = _read_text(_paths(user_id, server_id)["meta"])
    if not raw:
        return None
    try:
        names = list(json.loads(raw).get("mcpServers", {}).keys())
    except (ValueError, AttributeError):
        return None
    return names[0] if len(names) == 1 else None


def stop_server_proxies(server_id):
    """Stop every running per-user proxy instance for one server.

    Callers: server deletion paths (admin route, API, CLI). Without this,
    an already-spawned process outlives its mcp_servers row and the
    later idle-timeout proxy_stop audit entry references a dead foreign
    key. Pairs whose lock is held by another worker are skipped — the
    audit fallback (server_id dropped, name kept) covers those.
    """
    if not STATE_DIR.exists():
        return
    for pid_path in STATE_DIR.glob("*.pid"):
        pid_user_id, pid_server_id = _parse_key(pid_path.stem)
        if pid_user_id is None or pid_server_id != server_id:
            continue
        try:
            with _serialized(pid_user_id, server_id, wait_seconds=0):
                server_name = _server_name_from_meta(pid_user_id, server_id)
                pid = _read_pid(pid_path)
                if pid:
                    _stop_pid(pid)
                for key in ("pid", "port", "last_used", "meta", "config", "healthy_at"):
                    try:
                        _paths(pid_user_id, server_id)[key].unlink()
                    except OSError:
                        pass
        except UserProxyError:
            continue
        audit.log_audit_event(
            "proxy_stop",
            "success",
            user_id=pid_user_id,
            server_id=server_id,
            server_name=server_name,
        )


def stop_user_proxies(user_id):
    """Stop every running proxy instance of one user and forget its state
    (credentials included). Called when an account is disabled or deleted:
    their processes must not outlive their access.

    Unlike the idle reaper this waits briefly for a pair's lock instead of
    skipping a busy one - an instance mid-request is exactly the one that
    still serves a user who has just lost access."""
    if not STATE_DIR.exists():
        return
    for pid_path in STATE_DIR.glob(f"u{user_id}-s*.pid"):
        pid_user_id, server_id = _parse_key(pid_path.stem)
        if pid_user_id != user_id:
            continue
        try:
            with _serialized(user_id, server_id, wait_seconds=5):
                pid = _read_pid(pid_path)
                if pid:
                    _stop_pid(pid)
                paths = _paths(user_id, server_id)
                for key in ("pid", "port", "last_used", "meta", "config", "healthy_at"):
                    try:
                        paths[key].unlink()
                    except OSError:
                        pass
        except UserProxyError:
            logger.warning("proxy u%s-s%s is busy; it will be reaped when idle", user_id, server_id)
            continue
        audit.log_audit_event(
            "proxy_stop",
            "success",
            user_id=user_id,
            server_id=server_id,
            error_message="account disabled or deleted",
        )


def stop_user_server_proxy(user_id, server_id):
    """Terminate this pair's proxy and forget it. Takes the same exclusive
    lock as a spawn, so it cannot cut in on a relay mid-request."""
    with telemetry.span("mcp.proxy.stop", {"server_id": server_id}):
        with _serialized(user_id, server_id):
            paths = _paths(user_id, server_id)
            pid = _read_pid(paths["pid"])
            if pid:
                _stop_pid(pid)
            for key in ("pid", "port", "last_used", "meta", "config", "healthy_at"):
                try:
                    paths[key].unlink()
                except OSError:
                    pass
        audit.log_audit_event("proxy_stop", "success", user_id=user_id, server_id=server_id)


def list_proxy_instances():
    """Every proxy the state directory knows about, running or not, for the
    admin view. Reads files rather than process state because the instances
    belong to other gunicorn workers."""
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
        port = _read_port(paths["port"]) or _port_for(user_id, server_id)

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