"""Retention/archival helpers for the audit trail, used by the
`flask audit-archive` CLI command (see app.py). Exports old rows to a plain
JSON or CSV file, then deletes them — the export always happens before the
delete, and the caller is responsible for recording an audit entry for the
archival run itself (append-only: the archive action is the one thing that
removes rows, so it must leave a trace).
"""

import csv
import json
from datetime import datetime, timedelta, timezone

from .extensions import db
from .models import AuditLogEntry

FIELDS = (
    "id",
    "timestamp",
    "user_id",
    "server_id",
    "server_name",
    "action",
    "result",
    "error_code",
    "error_message",
    "source_ip",
    "hostname",
    "duration_ms",
    "request_id",
)


def cutoff_datetime(retention_days):
    return datetime.now(timezone.utc) - timedelta(days=retention_days)


def entries_older_than(cutoff):
    return (
        AuditLogEntry.query.filter(AuditLogEntry.timestamp < cutoff)
        .order_by(AuditLogEntry.timestamp.asc())
        .all()
    )


def default_archive_path(cutoff, export_format):
    return f"audit-archive-{cutoff.date().isoformat()}.{export_format}"


def _entry_to_row(entry):
    row = {field: getattr(entry, field) for field in FIELDS}
    if row["timestamp"] is not None:
        row["timestamp"] = row["timestamp"].isoformat()
    return row


def export_entries(entries, path, export_format):
    rows = [_entry_to_row(e) for e in entries]
    if export_format == "json":
        with open(path, "w") as f:
            json.dump(rows, f, indent=2)
    elif export_format == "csv":
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    else:
        raise ValueError(f"Unknown export format: {export_format!r}")


def delete_entries(entries):
    count = 0
    for entry in entries:
        db.session.delete(entry)
        count += 1
    db.session.commit()
    return count
