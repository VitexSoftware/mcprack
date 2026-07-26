import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path


STATE_DIR = Path("/var/lib/mcprack/user-proxies")
_KEY_RE = re.compile(r"^u(?P<user_id>\d+)-s(?P<server_id>\d+)$")


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
        "log": base.with_suffix(".log"),
    }


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


def ensure_user_server_proxy(user_id, server_id, server_name, command, args, env):
    if not command:
        raise UserProxyError("Cannot start user proxy for server without command")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    paths = _paths(user_id, server_id)
    port = _port_for(user_id, server_id)

    desired_config = _desired_config(server_name, command, args, env)
    desired_json = json.dumps(desired_config, sort_keys=True)

    meta_current = _read_text(paths["meta"])
    pid = _read_pid(paths["pid"])
    running = _pid_running(pid)

    needs_restart = (not running) or (meta_current != desired_json)
    if not needs_restart:
        paths["last_used"].write_text(str(int(time.time())))
        return port

    if running:
        _stop_pid(pid)

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
        raise UserProxyError(f"User proxy process exited early for {server_name}")

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
            _stop_pid(pid)


def stop_user_server_proxy(user_id, server_id):
    paths = _paths(user_id, server_id)
    pid = _read_pid(paths["pid"])
    if pid:
        _stop_pid(pid)
    for key in ("pid", "last_used", "meta", "config"):
        try:
            paths[key].unlink()
        except OSError:
            pass


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