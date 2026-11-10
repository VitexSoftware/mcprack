"""Compare the audit mirror (audit_mirror.py) with the audit table.

What it can tell you, and what it cannot:

* a mirror line whose MAC is wrong      -> the LOG was edited (or SECRET_KEY changed
                                           without SECRET_KEY_FALLBACKS)
* a line with no row in the table       -> the row was DELETED
* two lines with the same id but different
  content                              -> a row was deleted and a later event was given
                                           its id (SQLite re-uses the highest id)
* a line whose row differs              -> the row was ALTERED
* a row with no (authentic) line        -> the row was INSERTED, or the mirror was
                                           not running then
* an event whose row could not be written is in the log with id null: informational.

It proves nothing about an attacker who can edit the log as well - keep the log
off the host (ship the journal) or append-only (`chattr +a`). Lines older than the
retention window are not checked: `audit-archive` legitimately removes those rows.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import audit_mirror
from .extensions import db
from .models import AuditLogEntry

# Row/line fields that must agree. user_id and server_id are handled separately:
# the foreign keys are ON DELETE SET NULL, so a row may legitimately lose them.
_PLAIN_FIELDS = (
    "action", "result", "error_code", "error_message", "source_ip", "hostname", "duration_ms", "request_id", "server_name",
)
_TIMESTAMP_TOLERANCE = timedelta(seconds=2)
_CHUNK = 500


@dataclass
class Report:
    files: list = field(default_factory=list)
    lines: int = 0
    garbled: int = 0
    bad_mac: list = field(default_factory=list)  # (file, line number)
    unwritten: int = 0  # events whose row could not be written (id null)
    checked: int = 0
    window_start: datetime | None = None
    missing_in_db: list = field(default_factory=list)  # ids
    reused_ids: list = field(default_factory=list)  # ids that two different events carry
    altered: list = field(default_factory=list)  # (id, [field names])
    unmirrored: list = field(default_factory=list)  # ids

    @property
    def tampering(self):
        """Evidence that something was changed: exit status 1."""
        return bool(self.bad_mac or self.missing_in_db or self.altered or self.reused_ids)

    @property
    def warnings(self):
        return bool(self.unmirrored or self.garbled)


def _utc(value):
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def log_files(path):
    """`path` and the files logrotate made from it (audit.log.1, audit.log.2.gz ...)."""
    base = Path(path)
    found = [base] if base.is_file() else []
    found += sorted(candidate for candidate in base.parent.glob(base.name + ".*") if candidate.is_file())
    return found


def _read(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            yield number, line


def verify(paths, *, keys, retention_days, now=None, max_ids=None):
    report = Report()
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)

    authentic = {}  # id -> record
    for path in paths:
        report.files.append(str(path))
        for number, line in _read(path):
            if not line.strip():
                continue
            report.lines += 1
            record = audit_mirror.parse_line(line)
            if record is None:
                report.garbled += 1
                continue
            if not audit_mirror.mac_is_valid(record, keys):
                report.bad_mac.append((str(path), number))
                continue
            if record.get("id") is None:
                report.unwritten += 1
                continue
            earlier = authentic.get(record["id"])
            if earlier is not None and audit_mirror._canonical(earlier) != audit_mirror._canonical(record):
                # Keeping only the last line for an id would hide the first event: a
                # row deleted, its id handed to the next event, and the table looks
                # complete. (The same event seen twice - journal and file - is identical
                # and fine; the MAC is left out of the comparison so a key rotation does
                # not make it look different.)
                if record["id"] not in report.reused_ids:
                    report.reused_ids.append(record["id"])
            authentic[record["id"]] = record

    stamps = [stamp for stamp in (_utc(r.get("ts")) for r in authentic.values()) if stamp is not None]
    if not stamps:
        return report
    report.window_start = start = max(cutoff, min(stamps))

    in_window = {rid: rec for rid, rec in authentic.items() if (_utc(rec.get("ts")) or start) >= start}
    report.checked = len(in_window)

    ids = sorted(in_window)
    rows = {}
    for offset in range(0, len(ids), _CHUNK):
        chunk = ids[offset : offset + _CHUNK]
        for row in AuditLogEntry.query.filter(AuditLogEntry.id.in_(chunk)).all():
            rows[row.id] = row

    for rid in ids:
        record, row = in_window[rid], rows.get(rid)
        if row is None:
            report.missing_in_db.append(rid)
            continue
        differing = [name for name in _PLAIN_FIELDS if getattr(row, name) != record.get(name)]
        for name in ("user_id", "server_id"):
            stored = getattr(row, name)
            if stored is not None and stored != record.get(name):  # NULL is the ON DELETE SET NULL case
                differing.append(name)
        stamp, logged = _utc(row.timestamp), _utc(record.get("ts"))
        if stamp is None or logged is None or abs(stamp - logged) > _TIMESTAMP_TOLERANCE:
            differing.append("timestamp")
        if differing:
            report.altered.append((rid, differing))

    mirrored = set(authentic)
    query = db.session.query(AuditLogEntry.id).filter(AuditLogEntry.timestamp >= start.replace(tzinfo=None))
    report.unmirrored = sorted(rid for (rid,) in query.all() if rid not in mirrored)
    return report
