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
import re
import shutil
import subprocess
import sys
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


# --- input validation (docs/AUDIT-2026-11.md B-07) --------------------------
#
# Everything an admin types here ends up in a command that downloads and runs
# third-party code as the service user, and some of it in filesystem paths. It
# is validated strictly BEFORE anything is created, and never parsed by a
# shell. Sources are limited to registry packages: no URLs, paths, VCS
# references or option-looking strings.

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_BINARY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PIP_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_PIP_CLAUSE = r"(?:==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9][A-Za-z0-9.*+!_-]*"
_PIP_RE = re.compile(rf"^{_PIP_NAME}(?:\[[A-Za-z0-9,._-]+\])?(?:\s*{_PIP_CLAUSE}(?:\s*,\s*{_PIP_CLAUSE})*)?$")
_PIP_PINNED_RE = re.compile(r"^[^<>=!~,]+==\s*[A-Za-z0-9][A-Za-z0-9.+!_-]*$")  # one exact version, no wildcard
_NPM_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(?:@[A-Za-z0-9][A-Za-z0-9.+-]*)?$")
_NPM_PINNED_RE = re.compile(r"@\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?$")
_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(?::[0-9]{1,5})?(?:/[a-z0-9][a-z0-9._-]*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$"
)


def _config(key, default):
    try:
        from flask import current_app, has_app_context

        if has_app_context():
            return current_app.config.get(key, default)
    except Exception:  # pragma: no cover - installer works without Flask too
        pass
    return default


def _require_pinned(explicit):
    return _config("INSTALL_REQUIRE_PINNED", True) if explicit is None else explicit


def validate_name(name):
    """A new install's server name: lowercase letters, digits, '.', '_', '-';
    it becomes a directory name, so no path separators, no leading dot."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise InstallError(
            "The server name must be 1-63 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit."
        )


def validate_binary_name(binary):
    if not isinstance(binary, str) or not _BINARY_RE.match(binary):
        raise InstallError("The expected binary must be a plain file name (letters, digits, '.', '_', '-').")


def validate_pip_spec(spec, require_pinned=None):
    """A PyPI requirement: name, optional extras, optional version clauses.
    Refuses URLs, paths, VCS references and anything option-looking."""
    if not isinstance(spec, str) or not _PIP_RE.match(spec.strip()):
        raise InstallError(
            "The pip package must be a plain PyPI requirement such as 'name==1.2.3' - no URLs, paths, "
            "VCS references or options."
        )
    if _require_pinned(require_pinned) and not _PIP_PINNED_RE.match(spec.strip()):
        raise InstallError(
            "Pin the pip package to an exact version ('name==1.2.3'); set INSTALL_REQUIRE_PINNED=false to allow ranges."
        )


def validate_npm_spec(spec, require_pinned=None):
    if not isinstance(spec, str) or not _NPM_RE.match(spec):
        raise InstallError(
            "The npm package must be a plain registry name such as '@scope/name@1.2.3' - no URLs, paths or options."
        )
    if _require_pinned(require_pinned) and not _NPM_PINNED_RE.search(spec):
        raise InstallError(
            "Pin the npm package to an exact version ('name@1.2.3'); set INSTALL_REQUIRE_PINNED=false to allow tags/ranges."
        )


def validate_image_ref(ref, require_pinned=None):
    if not isinstance(ref, str) or not _IMAGE_RE.match(ref):
        raise InstallError("The Docker image reference is not valid (registry/name:tag or name@sha256:digest).")
    if _require_pinned(require_pinned):
        has_digest = "@sha256:" in ref
        tag = ref.rsplit(":", 1)[1] if re.search(r":[^/:@]+$", ref) and not has_digest else None
        if not has_digest and (tag is None or tag == "latest"):
            raise InstallError(
                "Pin the Docker image to a version tag (not 'latest') or a digest; "
                "set INSTALL_REQUIRE_PINNED=false to allow it."
            )


def _safe_component(server_name):
    """State paths are built from the server name. Servers registered before
    the strict rule may use other characters, so this only guarantees the
    name is ONE path component."""
    if (
        not isinstance(server_name, str)
        or server_name in ("", ".", "..")
        or "/" in server_name
        or "\\" in server_name
        or "\0" in server_name
    ):
        raise InstallError("Unsafe server name.")
    return server_name


def _paths(server_name):
    base = STATE_DIR / _safe_component(server_name)
    return {
        "dir": base,
        "pid": base / "install.pid",
        "exitcode": base / "install.exitcode",
        "log": base / "install.log",
    }


def _lock_path(server_name):
    return STATE_DIR / f"{_safe_component(server_name)}.lock"


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


# Runs the install steps one after another WITHOUT a shell: every step is an
# argv list, executed with subprocess.run(list). It writes the combined output
# to the log and the exit code of the first failing step (or 0) atomically to
# the exitcode file - the same files get_install_status() has always read. The
# job travels as one JSON argument, so nothing an admin typed is ever parsed
# as code.
_RUNNER = r"""
import json, os, subprocess, sys
job = json.loads(sys.argv[1])
code = 0
with open(job["log"], "ab") as log:
    for argv, cwd in job["steps"]:
        log.write(("$ " + " ".join(argv) + "\n").encode()); log.flush()
        try:
            rc = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT).returncode
        except OSError as exc:
            log.write((str(exc) + "\n").encode()); rc = 127
        if rc != 0:
            code = rc
            break
tmp = job["exitcode"] + ".tmp"
with open(tmp, "w") as fh:
    fh.write(str(code) + "\n")
os.replace(tmp, job["exitcode"])
"""


def _spawn_detached(server_name, install_dir, steps):
    """Launch `steps` - a list of (argv list, cwd or None) - as a detached
    runner and return immediately; the outcome is read later from the state
    files by get_install_status()."""
    paths = _paths(server_name)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    install_dir.mkdir(parents=True, exist_ok=True)

    for key in ("exitcode",):
        try:
            paths[key].unlink()
        except OSError:
            pass

    job = {
        "log": str(paths["log"]),
        "exitcode": str(paths["exitcode"]),
        "steps": [[list(argv), cwd] for argv, cwd in steps],
    }
    proc = subprocess.Popen(
        [sys.executable, "-c", _RUNNER, json.dumps(job)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    paths["pid"].write_text(str(proc.pid))


def start_pip_install(server_name, package_spec, expected_binary):
    """Creates a fresh venv under STATE_DIR/<name>/venv and installs
    `package_spec` into it, detached. Returns the venv path immediately —
    it is NOT yet installed when this returns; poll get_install_status()."""
    validate_name(server_name)
    validate_pip_spec(package_spec)
    validate_binary_name(expected_binary)
    if shutil.which("python3") is None:
        raise InstallError("python3 not found on PATH.")

    with _serialized(server_name):
        install_dir = STATE_DIR / server_name / "venv"
        install = [str(install_dir / "bin" / "pip"), "install", "--no-input"]
        if not _config("INSTALL_ALLOW_SOURCE_BUILDS", False):
            # a source distribution runs its setup code while building
            install.append("--only-binary=:all:")
        install.append(package_spec.strip())
        _spawn_detached(
            server_name,
            install_dir,
            [(["python3", "-m", "venv", str(install_dir)], None), (install, None)],
        )
    return str(install_dir)


def start_npm_install(server_name, package_spec, expected_binary):
    """Creates a fresh, isolated (non-global) npm project directory and
    installs `package_spec` into it, detached."""
    validate_name(server_name)
    validate_npm_spec(package_spec)
    validate_binary_name(expected_binary)
    if shutil.which("npm") is None:
        raise InstallError("npm not found on PATH.")

    with _serialized(server_name):
        install_dir = STATE_DIR / server_name / "npm"
        _spawn_detached(
            server_name,
            install_dir,
            [
                (["npm", "init", "-y", "--silent"], str(install_dir)),
                # lifecycle scripts (preinstall/postinstall) are arbitrary code
                (["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts", package_spec], str(install_dir)),
            ],
        )
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
    validate_name(server_name)
    validate_image_ref(image_ref)
    with _serialized(server_name):
        install_dir = STATE_DIR / server_name
        _spawn_detached(server_name, install_dir, [(["docker", "pull", image_ref], None)])


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
    try:
        target = (STATE_DIR / _safe_component(server.name)).resolve()
    except InstallError:
        return
    root = STATE_DIR.resolve()
    if root not in target.parents:  # never delete anything outside the install directory
        return
    shutil.rmtree(target, ignore_errors=True)
