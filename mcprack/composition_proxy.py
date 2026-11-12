"""Per-user FastMCP composition processes for the aggregate MCP endpoint."""

import argparse
import contextlib
import fcntl
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from . import user_proxy

logger = logging.getLogger(__name__)

STATE_DIR = user_proxy.STATE_DIR / "compositions"
IDLE_TIMEOUT = 900
HEALTH_RECHECK_INTERVAL = user_proxy.HEALTH_RECHECK_INTERVAL


class CompositionProxyError(RuntimeError):
    def __init__(self, message, public_message=None):
        super().__init__(message)
        self.public_message = public_message or "The aggregated MCP endpoint could not be started. Please try again."


def _ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass


def _paths(user_id):
    base = STATE_DIR / f"u{user_id}-composition"
    return {
        "config": base.with_suffix(".json"),
        "meta": base.with_suffix(".meta.json"),
        "pid": base.with_suffix(".pid"),
        "port": base.with_suffix(".port"),
        "last_used": base.with_suffix(".last_used"),
        "healthy_at": base.with_suffix(".healthy_at"),
    }


@contextlib.contextmanager
def _serialized(user_id, wait_seconds=None):
    _ensure_state_dir()
    lock_path = STATE_DIR / f"u{user_id}-composition.lock"
    wait = user_proxy.LOCK_WAIT_TIMEOUT if wait_seconds is None else wait_seconds
    deadline = time.monotonic() + wait
    with open(lock_path, "a") as lock_file:
        os.fchmod(lock_file.fileno(), 0o600)
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CompositionProxyError("Timed out waiting for the user's composition process lock")
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _read_text(path):
    try:
        return path.read_text()
    except OSError:
        return None


def _process_is_ours(pid, config_path):
    try:
        with open(f"/proc/{int(pid)}/cmdline", "rb") as handle:
            arguments = handle.read().split(b"\0")
    except (OSError, ValueError):
        return None
    return os.fsencode(str(config_path)) in arguments


def _read_pid(path):
    raw = _read_text(path)
    if not raw:
        return None
    try:
        pid = int(raw.strip())
    except ValueError:
        return None
    if _process_is_ours(pid, path.with_suffix(".json")) is False:
        logger.warning("composition pid recorded in %s no longer belongs to mcprack", path)
        return None
    return pid


def _read_port(path):
    try:
        port = int(path.read_text().strip())
    except (OSError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _write_private(path, value):
    user_proxy._write_private(path, value)


def _clear(paths):
    for key in ("pid", "port", "meta", "config", "healthy_at"):
        try:
            paths[key].unlink()
        except OSError:
            pass


def _find_port(user_id):
    base = user_proxy._port_for(user_id, 0)
    for offset in range(user_proxy._PORT_SEARCH_RANGE):
        port = base + offset
        if user_proxy._is_port_available(port):
            return port
    raise CompositionProxyError("No free local port is available for this user's composition")


def ensure_user_composition_proxy(user_id, connectors, fingerprint):
    """Return the port of a healthy composition matching the user's selection."""
    if not connectors:
        raise CompositionProxyError("No servers are selected for this composition")

    paths = _paths(user_id)
    config = json.dumps({"servers": connectors}, sort_keys=True)
    fingerprint = str(fingerprint)
    with _serialized(user_id):
        pid = _read_pid(paths["pid"])
        port = _read_port(paths["port"]) or user_proxy._port_for(user_id, 0)
        running = user_proxy._pid_running(pid)

        if running and _read_text(paths["meta"]) == fingerprint:
            healthy_at = _read_text(paths["healthy_at"])
            try:
                health_is_fresh = healthy_at and time.time() - float(healthy_at) < HEALTH_RECHECK_INTERVAL
            except ValueError:
                health_is_fresh = False
            if health_is_fresh or user_proxy._probe_upstream_health(port):
                _write_private(paths["healthy_at"], str(time.time()))
                _write_private(paths["last_used"], str(int(time.time())))
                return port

        if running:
            user_proxy._stop_pid(pid)
        _clear(paths)

        port = _find_port(user_id)
        _write_private(paths["config"], config)
        _write_private(paths["meta"], fingerprint)
        _write_private(paths["port"], str(port))

        try:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "mcprack.composition_proxy",
                    "--config",
                    str(paths["config"]),
                    "--port",
                    str(port),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=user_proxy._child_environment(),
                start_new_session=True,
            )
        except OSError as exc:
            _clear(paths)
            raise CompositionProxyError(f"Could not launch the composition process: {exc.strerror or exc}") from exc

        user_proxy._CHILDREN[proc.pid] = proc
        _write_private(paths["pid"], str(proc.pid))
        _write_private(paths["last_used"], str(int(time.time())))
        time.sleep(0.2)
        report = {}
        if proc.poll() is not None or not user_proxy._probe_upstream_health(
            port, proc=proc, report=report
        ):
            user_proxy._stop_pid(proc.pid)
            _clear(paths)
            raise CompositionProxyError(
                f"The composition process failed its MCP initialization ({report.get('kind', 'exited early')})"
            )

        _write_private(paths["healthy_at"], str(time.time()))
        return port


@contextlib.contextmanager
def relay_guard(user_id):
    """Best-effort shared hold while a non-streaming relay uses the process."""
    _ensure_state_dir()
    lock_file = open(STATE_DIR / f"u{user_id}-composition.lock", "a")
    deadline = time.monotonic() + user_proxy.RELAY_GUARD_WAIT
    try:
        os.fchmod(lock_file.fileno(), 0o600)
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
        yield
    finally:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        finally:
            lock_file.close()


def _stop_locked(user_id, paths):
    pid = _read_pid(paths["pid"])
    if pid:
        user_proxy._stop_pid(pid)
    _clear(paths)
    try:
        paths["last_used"].unlink()
    except OSError:
        pass


def stop_user_composition(user_id, wait_seconds=5):
    """Stop and forget a user's aggregate process, including its private URLs."""
    with _serialized(user_id, wait_seconds=wait_seconds):
        _stop_locked(user_id, _paths(user_id))


def cleanup_idle_compositions(max_idle_seconds=IDLE_TIMEOUT):
    if not STATE_DIR.exists():
        return
    now = time.time()
    for pid_path in STATE_DIR.glob("u*-composition.pid"):
        try:
            user_id = int(pid_path.name.split("-", 1)[0][1:])
        except ValueError:
            continue
        paths = _paths(user_id)
        pid = _read_pid(pid_path)
        if not pid:
            continue
        try:
            last_used = float((_read_text(paths["last_used"]) or "0").strip())
        except ValueError:
            last_used = 0
        if now - last_used <= max_idle_seconds:
            continue
        try:
            with _serialized(user_id, wait_seconds=0):
                try:
                    last_used = float((_read_text(paths["last_used"]) or "0").strip())
                except ValueError:
                    last_used = 0
                if now - last_used > max_idle_seconds:
                    _stop_locked(user_id, paths)
        except CompositionProxyError:
            continue


# How long the aggregate waits for ONE backend before it gives up on it for
# that request. Without a bound a single backend that accepts the connection
# but never answers (a stdio server stuck at start-up, a host behind a firewall)
# holds up tools/list of the whole aggregate until the client's own timeout, and
# the client sees no tools at all. With it the answer lists every backend that
# did respond and only the silent one is missing.
BACKEND_TIMEOUT = float(os.environ.get("MCPRACK_COMPOSITION_BACKEND_TIMEOUT", "10"))


def _bounded_proxy(url, timeout=None):
    from fastmcp import Client
    from fastmcp.server import create_proxy

    seconds = BACKEND_TIMEOUT if timeout is None else timeout
    return create_proxy(Client(url, timeout=seconds, init_timeout=seconds))


def build_composition_server(config, proxy_factory=None):
    from fastmcp import FastMCP

    if proxy_factory is None:
        proxy_factory = _bounded_proxy

    server = FastMCP("mcprack-composition")
    for entry in config["servers"]:
        server.mount(proxy_factory(entry["url"]), namespace=entry["namespace"])
    return server


def _serve(config_path, port):
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    server = build_composition_server(config)

    logging.basicConfig(level=logging.WARNING)
    server.run(transport="streamable-http", host="127.0.0.1", port=port, show_banner=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    _serve(args.config, args.port)


if __name__ == "__main__":
    main()