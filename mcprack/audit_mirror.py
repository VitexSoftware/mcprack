"""A second copy of every audit event, outside the database
(docs/AUDIT-2026-11.md B-10).

The audit table is "append-only" by convention only: whoever can write to the
database - a compromised application, a stolen DB credential, an administrator
covering their tracks - can edit or delete rows, and nothing would show. So every
event is ALSO written, as one authenticated line, to places the database does not
control:

* standard error, i.e. the systemd journal of the service (`journalctl -u
  mcprack | grep ^AUDIT`), which can be shipped off the host;
* optionally a file (`AUDIT_LOG_FILE`; by default /var/log/mcprack/audit.log when
  that directory is writable), rotated by logrotate.

Each line carries the row's id and its content plus an HMAC keyed from SECRET_KEY.
`flask audit-verify` compares the lines with the table and reports rows that are
missing, rows that were changed, lines whose MAC is wrong (the *log* was edited)
and rows that have no line at all. It is tamper-EVIDENCE, not prevention: it
cannot stop a row being changed, it makes the change visible - provided the log
itself is out of reach of the attacker (ship it off the host, or `chattr +a`).

Emitting a line never raises and never blocks the request that is being audited.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
from logging.handlers import WatchedFileHandler

from flask import current_app, has_app_context

# NOT "mcprack.audit": that is the name of audit.py's own logger, whose
# operational messages (tracebacks, warnings) would then be written into the
# audit mirror alongside the events.
MIRROR_LOGGER = "mcprack.audit.mirror"
LINE_PREFIX = "AUDIT "
DEFAULT_FILE = "/var/log/mcprack/audit.log"
_KEY_LABEL = b"mcprack.audit.mirror.v1"
_HANDLER_TAG = "_mcprack_audit_mirror"

logger = logging.getLogger(__name__)
_mirror = logging.getLogger(MIRROR_LOGGER)


# --- authentication of a line ------------------------------------------------------------------


def _keys(config=None):
    """HMAC keys for the lines: the current SECRET_KEY first, then any
    SECRET_KEY_FALLBACKS (so a rotated key does not make old lines unverifiable)."""
    cfg = config if config is not None else (current_app.config if has_app_context() else {})
    raw = [cfg.get("SECRET_KEY", ""), *(cfg.get("SECRET_KEY_FALLBACKS") or [])]
    return [hmac.new(str(key).encode(), _KEY_LABEL, hashlib.sha256).digest() for key in raw if key]


def _canonical(record):
    body = {key: value for key, value in record.items() if key != "mac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def mac_for(record, key):
    return hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()


def mac_is_valid(record, keys):
    claimed = record.get("mac")
    if not isinstance(claimed, str):
        return False
    return any(hmac.compare_digest(claimed, mac_for(record, key)) for key in keys)


def format_line(record, keys):
    signed = dict(record)
    signed["mac"] = mac_for(record, keys[0]) if keys else None
    return LINE_PREFIX + json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_line(line):
    """The record in a mirror line (as written to the journal or the file), or None."""
    text = line.strip()
    marker = text.find(LINE_PREFIX + "{")
    if marker >= 0:
        text = text[marker + len(LINE_PREFIX):]
    elif not text.startswith("{"):
        return None
    try:
        record = json.loads(text)
    except ValueError:
        return None
    return record if isinstance(record, dict) and record.get("v") == 1 else None


def emit(record):
    """Write one event to every configured sink. Never raises."""
    try:
        _mirror.info(format_line(record, _keys()))
    except Exception:  # noqa: BLE001 - auditing must never break what it audits
        logger.exception("Could not mirror an audit event (action=%s)", record.get("action"))


# --- sinks -------------------------------------------------------------------------------------


class _MirrorFileHandler(WatchedFileHandler):
    """Append-only file sink that follows logrotate and keeps its owner.

    The management CLI may run as root while the service runs as `mcprack`: a
    file root creates here would otherwise be unwritable for the service, and its
    events would silently stop. So a file created as root is handed to whoever
    owns the directory."""

    def _open(self):
        stream = super()._open()
        try:
            if os.geteuid() == 0:
                parent = os.stat(os.path.dirname(os.path.abspath(self.baseFilename)))
                os.chown(self.baseFilename, parent.st_uid, parent.st_gid)
            os.chmod(self.baseFilename, 0o640)
        except OSError:
            pass
        return stream


def resolve_file(setting, testing=False):
    """The mirror file for an AUDIT_LOG_FILE value. Unset: the package's log
    directory, when it exists and is writable - but never under TESTING, so a test
    run on a host that has the package installed cannot write into its real log.
    "", "off" or "none": no file."""
    if setting is None:
        if testing:
            return None
        directory = os.path.dirname(DEFAULT_FILE)
        return DEFAULT_FILE if os.path.isdir(directory) and os.access(directory, os.W_OK) else None
    if str(setting).strip().lower() in ("", "off", "none", "false"):
        return None
    return str(setting)


def _remove_installed_handlers():
    for handler in list(_mirror.handlers):
        if getattr(handler, _HANDLER_TAG, False):
            _mirror.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # noqa: BLE001
                pass


def shutdown():
    """Detach the sinks (tests, and a clean exit of the CLI)."""
    _remove_installed_handlers()


def init_app(app):
    """Attach the sinks the configuration asks for. Idempotent: building another
    app (the tests do, the CLI does) replaces the handlers instead of stacking
    them."""
    _remove_installed_handlers()
    _mirror.setLevel(logging.INFO)
    _mirror.propagate = False
    cfg = app.config
    if not cfg.get("AUDIT_MIRROR_ENABLED", True):
        return

    def attach(handler):
        handler.setFormatter(logging.Formatter("%(message)s"))
        setattr(handler, _HANDLER_TAG, True)
        _mirror.addHandler(handler)

    if cfg.get("AUDIT_MIRROR_STDERR", True):
        attach(logging.StreamHandler(sys.stderr))
    path = resolve_file(cfg.get("AUDIT_LOG_FILE"), testing=bool(cfg.get("TESTING")))
    if path:
        try:
            attach(_MirrorFileHandler(path, encoding="utf-8"))
        except OSError as exc:
            # The audit trail in the database is unaffected; say so loudly, once.
            logger.error("Audit mirror file %s cannot be opened (%s) - events are mirrored to stderr only", path, exc)
