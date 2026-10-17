"""Append-only audit trail for mcprack (intranet deployment).

log_audit_event() is the single entry point every call site should use to
record a security-relevant event. It NEVER logs request/response bodies or
credential values — only that an action happened, who triggered it, against
which server, and its outcome. It also never raises: a failure to write the
audit row must not break the request it's auditing, so any DB error here is
caught and reported to the application logger instead.

Call it *after* your own primary db.session.commit() (if any) — it manages
its own transaction for the audit row so it never interferes with, or is
rolled back by, the caller's own unit of work.
"""

import logging
import uuid

import flask
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import AuditLogEntry

logger = logging.getLogger(__name__)

# Foreign-key constraint names on audit_log_entries (PostgreSQL's default
# naming) — used to tell *which* reference went stale when an insert
# fails with IntegrityError, so only that one is degraded.
_SERVER_ID_FK = "audit_log_entries_server_id_fkey"
_USER_ID_FK = "audit_log_entries_user_id_fkey"


def new_request_id():
    return str(uuid.uuid4())


def current_request_id():
    """A UUID stable for the lifetime of the current Flask request, so
    multiple audit events emitted while handling one incoming request (e.g.
    credential_access then proxy_start) can be correlated later. Returns
    None outside of a request context (e.g. CLI commands)."""
    if not flask.has_request_context():
        return None
    if not hasattr(flask.g, "mcprack_audit_request_id"):
        flask.g.mcprack_audit_request_id = new_request_id()
    return flask.g.mcprack_audit_request_id


def log_audit_event(
    action,
    result="success",
    *,
    user=None,
    user_id=None,
    server=None,
    server_id=None,
    server_name=None,
    error_code=None,
    error_message=None,
    duration_ms=None,
    request_id=None,
    source_ip=None,
    hostname=None,
):
    """Append one audit row. Returns the created AuditLogEntry, or None if
    the write itself failed (already logged to the app logger)."""
    if action not in AuditLogEntry.ACTIONS:
        raise ValueError(f"Unknown audit action: {action!r}")
    if result not in AuditLogEntry.RESULTS:
        raise ValueError(f"Unknown audit result: {result!r}")

    resolved_user_id = user_id if user_id is not None else getattr(user, "id", None)
    resolved_server_id = server_id if server_id is not None else getattr(server, "id", None)
    resolved_server_name = server_name or getattr(server, "name", None)

    if source_ip is None and flask.has_request_context():
        source_ip = flask.request.remote_addr
    if hostname is None and flask.has_request_context():
        hostname = flask.request.host

    entry = AuditLogEntry(
        user_id=resolved_user_id,
        server_id=resolved_server_id,
        server_name=resolved_server_name,
        action=action,
        result=result,
        error_code=error_code,
        error_message=(error_message[:500] if error_message else None),
        source_ip=source_ip,
        hostname=hostname,
        duration_ms=duration_ms,
        request_id=request_id or current_request_id(),
    )

    if not flask.has_app_context():
        # Callers like user_proxy.py are plain functions with no guaranteed
        # Flask context (e.g. unit tests exercising them directly) — never
        # let auditing be the reason a context-less call blows up.
        logger.warning("Skipped audit log entry (no app context): action=%s", action)
        return None

    try:
        db.session.add(entry)
        db.session.commit()
    except IntegrityError as exc:
        # The row this event points at may have been deleted between the
        # event and this write (e.g. an admin deleted a server while one
        # of its per-user proxy processes was still running; the process
        # later idle-times out and logs proxy_stop against a dead
        # server_id). The audit row itself must still land — drop the
        # stale reference and retry once; the denormalized server_name
        # snapshot keeps the entry readable.
        try:
            db.session.rollback()
        except Exception:
            pass
        message = str(getattr(exc, "orig", None) or exc)
        if _SERVER_ID_FK not in message and _USER_ID_FK not in message:
            logger.exception("Failed to write audit log entry (action=%s)", action)
            return None
        if _SERVER_ID_FK in message:
            resolved_server_id = None
        if _USER_ID_FK in message:
            resolved_user_id = None
        logger.warning(
            "Audit log entry (action=%s) references a deleted row "
            "(server_id=%s, user_id=%s); writing it without that reference",
            action,
            resolved_server_id,
            resolved_user_id,
        )
        entry = AuditLogEntry(
            user_id=resolved_user_id,
            server_id=resolved_server_id,
            server_name=resolved_server_name,
            action=action,
            result=result,
            error_code=error_code,
            error_message=(error_message[:500] if error_message else None),
            source_ip=source_ip,
            hostname=hostname,
            duration_ms=duration_ms,
            request_id=request_id or current_request_id(),
        )
        try:
            db.session.add(entry)
            db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            logger.exception("Failed to write audit log entry (action=%s)", action)
            return None
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.exception("Failed to write audit log entry (action=%s)", action)
        return None
    return entry
