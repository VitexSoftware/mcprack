"""Installs new MCP servers from PyPI (pip), npm, or a Docker image, so an
admin doesn't need shell access to the host to add one to the catalog.

Architecturally parallel to user_proxy.py: detached subprocess + per-name
flock + state files under /var/lib/mcprack/installs/<name>/, because
mcprack runs under multiple gunicorn worker processes with a 30s request
timeout and `pip install`/`npm install`/`docker pull` can easily exceed
that. The install command therefore always runs as a *detached* child
(start_new_session=True) that this module never waits on directly — status
is derived after the fact from state files, polled by the caller.

Python installs get their own isolated venv (pipx-style); npm installs get
their own local (non -g) install directory. Neither is shared between
servers, so uninstalling one is a plain `rm -rf` of its own directory.
Docker never gets a persistent install directory — the server is invoked as
an ephemeral `docker run --rm -i <image>` per session (see user_proxy.py's
_effective_args), so the only "install" step is `docker pull` plus an
`docker image inspect` sanity check.

No Flask/DB coupling beyond an optional audit log call — callers (admin.py)
own the McpServer row and decide when to write install_status/install_error
back to it, based on what get_install_status() reports.
"""

import contextlib
import fcntl
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

STATE_DIR = Path("/var/lib/mcprack/installs")

# Bounded pre-flight checks only (e.g. "is docker usable at all") — never
# used to bound the install itself, which runs detached and unwatched.
PREFLIGHT_TIMEOUT = 5  # seconds


class InstallError(RuntimeError):
    """Raised only for pre-flight problems (bad name, tool missing, docker
    not usable) — never for the install command's own eventual success or
    failure, which is inherently asynchronous; see get_install_status()."""


def _paths(server_name):
    base = STATE_DIR / server_name
    return {
        "dir": base,
        "pid": base / "install.pid",
        "exitcode": base / "install.exitcode",
        "log": base / "install.log",
    }


def _lock_path(server_name):
    return STATE_DIR / f"{server_name}.lock"


@contextlib.contextmanager
def _serialized(server_name):
    """Guards against two overlapping install attempts for the same server
    name (e.g. an admin double-clicking the install button) racing on the
    same install directory. The flock itself only protects the brief
    spawn-setup window (the actual pip/npm/docker work runs detached, well
    past when this context manager exits) — the real "is one already
    running" check is the pid/exitcode state inspected below, under the
    lock, so the two checks can't race each other either."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(_lock_path(server_name), "w") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError(
                f"An install is already in progress for '{server_name}'."
            )
        try:
            if get_install_status(server_name)["status"] == "running":
                raise InstallError(f"An install is already in progress for '{server_name}'.")
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _pid_running(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_text(path):
    try:
        return path.read_text()
    except OSError:
        return None


def _tail(path, max_bytes=8192):
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _spawn_detached(server_name, install_dir, shell_command):
    """Launches `shell_command` as a detached bash child that appends its
    combined stdout/stderr to the log file and atomically writes its own
    exit code to the exitcode file when done — the only way to observe a
    detached child's outcome later without blocking a gunicorn worker on
    it now."""
    paths = _paths(server_name)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    install_dir.mkdir(parents=True, exist_ok=True)

    for key in ("exitcode",):
        try:
            paths[key].unlink()
        except OSError:
            pass

    wrapper = (
        "set -o pipefail\n"
        f"{{ {shell_command} ; }} >> {json.dumps(str(paths['log']))} 2>&1\n"
        f"echo $? > {json.dumps(str(paths['exitcode']) + '.tmp')}\n"
        f"mv {json.dumps(str(paths['exitcode']) + '.tmp')} {json.dumps(str(paths['exitcode']))}\n"
    )

    proc = subprocess.Popen(
        ["bash", "-c", wrapper],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    paths["pid"].write_text(str(proc.pid))


def start_pip_install(server_name, package_spec, expected_binary):
    """Creates a fresh venv under STATE_DIR/<name>/venv and installs
    `package_spec` into it, detached. Returns the venv path immediately —
    it is NOT yet installed when this returns; poll get_install_status()."""
    if shutil.which("python3") is None:
        raise InstallError("python3 not found on PATH.")

    with _serialized(server_name):
        install_dir = STATE_DIR / server_name / "venv"
        command = (
            f"python3 -m venv {json.dumps(str(install_dir))} && "
            f"{json.dumps(str(install_dir / 'bin' / 'pip'))} install --no-input "
            f"{json.dumps(package_spec)}"
        )
        _spawn_detached(server_name, install_dir, command)
    return str(install_dir)


def start_npm_install(server_name, package_spec, expected_binary):
    """Creates a fresh, isolated (non-global) npm project directory and
    installs `package_spec` into it, detached."""
    if shutil.which("npm") is None:
        raise InstallError("npm not found on PATH.")

    with _serialized(server_name):
        install_dir = STATE_DIR / server_name / "npm"
        quoted_dir = json.dumps(str(install_dir))
        command = (
            f"cd {quoted_dir} && "
            f"npm init -y --silent > /dev/null && "
            f"npm install --no-audit --no-fund {json.dumps(package_spec)}"
        )
        _spawn_detached(server_name, install_dir, command)
    return str(install_dir)


def docker_available():
    """True only if the `docker` CLI is on PATH AND a real `docker ps` call
    against the daemon succeeds within PREFLIGHT_TIMEOUT — i.e. the mcprack
    service account actually has usable access (typically via `docker`
    group membership), not just that the binary exists. Never attempts to
    grant that access itself — see README's Docker security section."""
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            timeout=PREFLIGHT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def start_docker_pull(server_name, image_ref):
    """Pulls `image_ref`, detached. Caller must check docker_available()
    first — this does not re-check, so a caller that skips the gate could
    end up with a permission-denied failure captured in the log instead of
    a clean pre-flight rejection."""
    with _serialized(server_name):
        install_dir = STATE_DIR / server_name
        command = f"docker pull {json.dumps(image_ref)}"
        _spawn_detached(server_name, install_dir, command)


def get_install_status(server_name):
    """Reads state files for `server_name` and returns
    {"status": "running"|"success"|"failed", "log_tail": str,
     "error": str | None}. Never blocks. Safe to call repeatedly (e.g. from
     an admin polling endpoint) — completion-time work (binary
     verification) re-runs cheaply every time since it's just local file
     stats, not re-triggered install work."""
    paths = _paths(server_name)
    pid = None
    raw_pid = _read_text(paths["pid"])
    if raw_pid:
        try:
            pid = int(raw_pid.strip())
        except ValueError:
            pid = None

    exitcode_raw = _read_text(paths["exitcode"])
    log_tail = _tail(paths["log"])

    if exitcode_raw is None:
        if _pid_running(pid):
            return {"status": "running", "log_tail": log_tail, "error": None}
        return {
            "status": "failed",
            "log_tail": log_tail,
            "error": "Install process disappeared without recording an exit code "
            "(it may have been killed, e.g. out of memory).",
        }

    try:
        exitcode = int(exitcode_raw.strip())
    except ValueError:
        exitcode = 1

    if exitcode != 0:
        return {
            "status": "failed",
            "log_tail": log_tail,
            "error": f"Install command exited with status {exitcode}. See log for detail.",
        }

    return {"status": "success", "log_tail": log_tail, "error": None}


def verify_pip_binary(install_path, expected_binary):
    """Returns the absolute path to `expected_binary` inside the venv's
    bin/ directory if it exists and is executable, else None. Deliberately
    exact-match only — no guessing at alternate names, since a wrong guess
    silently registering the wrong binary was a real, documented problem
    for this app's autodetection (see detection.py's module docstring)."""
    candidate = Path(install_path) / "bin" / expected_binary
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def verify_npm_binary(install_path, expected_binary):
    """Same as verify_pip_binary, but for an npm project's node_modules/.bin/."""
    candidate = Path(install_path) / "node_modules" / ".bin" / expected_binary
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def verify_docker_image(image_ref):
    """Best-effort: True if `docker image inspect` finds the pulled image."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image_ref],
            capture_output=True,
            timeout=PREFLIGHT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def resolve_installed_version(install_method, install_path, package_spec):
    """Best-effort version lookup for display only — never raises, returns
    None on any failure since this is cosmetic info, not load-bearing."""
    try:
        if install_method == "pip":
            pip_bin = Path(install_path) / "bin" / "pip"
            package_name = package_spec.split("==")[0].split(">=")[0].split("<")[0].strip()
            result = subprocess.run(
                [str(pip_bin), "show", package_name],
                capture_output=True,
                text=True,
                timeout=PREFLIGHT_TIMEOUT,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        elif install_method == "npm":
            package_name = package_spec.split("@")[0] if not package_spec.startswith("@") else "@" + package_spec[1:].split("@")[0]
            result = subprocess.run(
                ["npm", "list", "--prefix", str(install_path), package_name, "--depth=0", "--json"],
                capture_output=True,
                text=True,
                timeout=PREFLIGHT_TIMEOUT,
                check=False,
            )
            data = json.loads(result.stdout or "{}")
            deps = data.get("dependencies", {})
            info = deps.get(package_name)
            if info:
                return info.get("version")
        elif install_method == "docker":
            result = subprocess.run(
                ["docker", "image", "inspect", package_spec, "--format", "{{.Id}}"],
                capture_output=True,
                text=True,
                timeout=PREFLIGHT_TIMEOUT,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()[:19]
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError, IndexError):
        return None
    return None


def uninstall(server):
    """Removes the on-disk install directory for a pip/npm-installed
    server. No-op for docker (pulled images are left in place — they may
    be shared/reused and Docker has its own GC via `docker image prune`;
    see the plan's uninstall/reinstall decision) and for manually
    registered servers (nothing mcprack-managed to remove)."""
    if server.install_method not in ("pip", "npm"):
        return
    # install_path (the venv/ or npm/ subdirectory) lives inside this
    # server's whole state directory, alongside its install log/pid files —
    # removing the parent covers both in one step.
    shutil.rmtree(STATE_DIR / server.name, ignore_errors=True)
