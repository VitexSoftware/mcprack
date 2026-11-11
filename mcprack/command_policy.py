"""Where an MCP server's `command` may live (docs/AUDIT-2026-11.md B-08).

A registered command is run as the service user. A directory allowlist cannot make
that safe by itself - /usr/bin holds shells and interpreters as well - so this is
deliberately modest and says so. It closes the cheap routes:

* ALWAYS refused: a command in a volatile, world-writable place (/tmp, /var/tmp,
  /dev/shm, /run/user, /proc, /dev) - nothing legitimate is installed there, and
  those are where a dropped payload would sit; a relative path (its meaning depends
  on the working directory); anything with a NUL or a newline in it. The check is
  made on the normalised path (`/usr/bin/../../tmp/x` is /tmp/x) and on where a
  symlink really leads.
* With ALLOWED_COMMAND_DIRS (comma or colon separated absolute directories): the
  command must be inside one of them (a bare name such as `uvx` is looked up on PATH
  first). Off by default, because what is legitimate is a property of the
  installation - /usr/bin only, plus /var/lib/mcprack/installs for the package
  installer, is a sensible production value.

The same check runs when a server is registered or edited AND when the process is
started, so a row written straight into the database does not get around it.
"""

from __future__ import annotations

import os
import shutil

from flask import current_app, has_app_context

VOLATILE_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run/user", "/proc", "/dev")


def _inside(path, directory):
    directory = directory.rstrip("/") or "/"
    return path == directory or path.startswith(directory + "/")


def _setting(name, default=""):
    if has_app_context():
        return current_app.config.get(name, default)
    return os.environ.get(name, default)


def allowed_dirs():
    """The configured allowlist as normalised absolute directories (relative entries are ignored)."""
    raw = _setting("ALLOWED_COMMAND_DIRS", "") or ""
    entries = [item.strip() for chunk in str(raw).split(",") for item in chunk.split(":")]
    return [os.path.normpath(item) for item in entries if item.startswith("/")]


def _volatile(path):
    return any(_inside(path, directory) for directory in VOLATILE_DIRS)


def command_errors(command):
    """Reasons `command` is refused (empty = acceptable)."""
    if command in (None, ""):
        return []
    if not isinstance(command, str) or "\0" in command or "\n" in command or "\r" in command:
        return ["The command is not a valid program path."]
    if not os.path.isabs(command) and "/" in command:
        return ["Use an absolute path (or a bare program name found on PATH): a relative path means whatever the working directory is."]

    if os.path.isabs(command):
        path = os.path.normpath(command)
    else:
        found = shutil.which(command)
        path = os.path.normpath(found) if found else None

    errors = []
    if path is not None and not _setting("COMMAND_ALLOW_VOLATILE_DIRS", False):
        real = os.path.realpath(path)
        if _volatile(path) or _volatile(real):
            errors.append(
                "A command in a temporary or world-writable location (/tmp, /var/tmp, /dev/shm, ...) is refused: "
                "nothing legitimate is installed there."
            )

    allowed = allowed_dirs()
    if allowed and not errors:
        if path is None:
            errors.append(f"'{command}' cannot be found on PATH, so it cannot be checked against ALLOWED_COMMAND_DIRS.")
        elif not any(_inside(path, directory) for directory in allowed):
            errors.append("The command is outside the directories the administrator allows (ALLOWED_COMMAND_DIRS: " + ", ".join(allowed) + ").")
    return errors
