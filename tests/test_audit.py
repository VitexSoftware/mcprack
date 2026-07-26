from datetime import datetime, timedelta, timezone

import pytest

import audit
import audit_retention
from extensions import db
from models import AuditLogEntry, McpServer, User


def _make_user():
    user = User(username="alice", auth_type="local", is_admin=False)
    user.set_password("secret")
    db.session.add(user)
    db.session.commit()
    return user


def _make_server():
    server = McpServer(name="jenkins", label="Jenkins", transport="stdio", command="/bin/true")
    db.session.add(server)
    db.session.commit()
    return server


def test_log_audit_event_writes_row(app):
    with app.app_context():
        user = _make_user()
        server = _make_server()

        entry = audit.log_audit_event(
            "credential_access", "success", user=user, server=server
        )

        assert entry is not None
        assert entry.id is not None
        assert entry.user_id == user.id
        assert entry.server_id == server.id
        assert entry.server_name == server.name
        assert entry.action == "credential_access"
        assert entry.result == "success"
        assert AuditLogEntry.query.count() == 1


def test_log_audit_event_has_no_secret_value_parameter():
    """The utility's signature deliberately has no field for a raw secret
    value — only that a credential access happened, never the value."""
    import inspect

    params = inspect.signature(audit.log_audit_event).parameters
    assert not any("secret" in name or "value" in name or "password" in name for name in params)


def test_log_audit_event_rejects_unknown_action(app):
    with app.app_context():
        with pytest.raises(ValueError):
            audit.log_audit_event("not_a_real_action")


def test_log_audit_event_rejects_unknown_result(app):
    with app.app_context():
        with pytest.raises(ValueError):
            audit.log_audit_event("login", result="maybe")


def test_log_audit_event_survives_db_failure(app, monkeypatch):
    """A broken audit write must never raise into the caller."""
    with app.app_context():
        def boom():
            raise RuntimeError("db is down")

        monkeypatch.setattr(db.session, "commit", boom)
        entry = audit.log_audit_event("login", "success")
        assert entry is None


def test_audit_log_entry_is_append_only_by_convention(app):
    """AuditLogEntry deliberately exposes no update/delete helper methods —
    callers that need to remove rows go through audit_retention.py, which
    is the only place that calls db.session.delete() on this model."""
    with app.app_context():
        for name in ("update", "edit", "delete_row", "remove"):
            assert not hasattr(AuditLogEntry, name)


def test_current_request_id_stable_within_request(app):
    with app.test_request_context("/"):
        first = audit.current_request_id()
        second = audit.current_request_id()
        assert first == second


def test_current_request_id_none_outside_request():
    """pytest-flask's `app` fixture auto-pushes a test request context, so
    this constructs its own app/app-context (no request context) to prove
    current_request_id() returns None for genuinely request-less callers
    like the audit-archive CLI command."""
    from app import create_app
    from tests.conftest import TestConfig

    application = create_app(TestConfig)
    with application.app_context():
        assert audit.current_request_id() is None


def _entry_at(days_ago, action="login"):
    return AuditLogEntry(
        timestamp=datetime.now(timezone.utc) - timedelta(days=days_ago),
        action=action,
        result="success",
    )


def test_entries_older_than_filters_by_cutoff(app):
    with app.app_context():
        db.session.add_all([_entry_at(100), _entry_at(10), _entry_at(1)])
        db.session.commit()

        cutoff = audit_retention.cutoff_datetime(30)
        old = audit_retention.entries_older_than(cutoff)

        assert len(old) == 1
        assert old[0].action == "login"


def test_delete_entries_removes_rows(app):
    with app.app_context():
        db.session.add_all([_entry_at(100), _entry_at(200)])
        db.session.commit()

        entries = AuditLogEntry.query.all()
        count = audit_retention.delete_entries(entries)

        assert count == 2
        assert AuditLogEntry.query.count() == 0


def test_export_entries_json(app, tmp_path):
    with app.app_context():
        db.session.add(_entry_at(100))
        db.session.commit()
        entries = AuditLogEntry.query.all()

        out = tmp_path / "archive.json"
        audit_retention.export_entries(entries, str(out), "json")

        import json

        data = json.loads(out.read_text())
        assert len(data) == 1
        assert data[0]["action"] == "login"


def test_export_entries_csv(app, tmp_path):
    with app.app_context():
        db.session.add(_entry_at(100))
        db.session.commit()
        entries = AuditLogEntry.query.all()

        out = tmp_path / "archive.csv"
        audit_retention.export_entries(entries, str(out), "csv")

        content = out.read_text()
        assert "action" in content.splitlines()[0]
        assert "login" in content


def test_cli_audit_archive_exports_and_purges(app, tmp_path):
    with app.app_context():
        db.session.add_all([_entry_at(100), _entry_at(1)])
        db.session.commit()

    runner = app.test_cli_runner()
    out_file = tmp_path / "out.json"
    result = runner.invoke(
        args=["audit-archive", "--days", "30", "--output", str(out_file)]
    )

    assert result.exit_code == 0
    assert out_file.exists()

    with app.app_context():
        remaining = AuditLogEntry.query.all()
        # The one recent entry, plus the archival run's own audit_change entry.
        assert any(e.action == "login" for e in remaining)
        assert any(e.error_message and "audit-archive" in e.error_message for e in remaining)


def test_cli_audit_archive_dry_run_does_not_delete(app, tmp_path):
    with app.app_context():
        db.session.add(_entry_at(100))
        db.session.commit()

    runner = app.test_cli_runner()
    result = runner.invoke(args=["audit-archive", "--days", "30", "--dry-run"])

    assert result.exit_code == 0
    with app.app_context():
        assert AuditLogEntry.query.count() == 1


def test_login_success_writes_audit_entry(app, client):
    with app.app_context():
        _make_user()

    client.post("/login", data={"username": "alice", "password": "secret"})

    with app.app_context():
        entries = AuditLogEntry.query.filter_by(action="login").all()
        assert len(entries) == 1
        assert entries[0].result == "success"


def test_login_failure_writes_audit_entry(app, client):
    with app.app_context():
        _make_user()

    client.post("/login", data={"username": "alice", "password": "wrong"})

    with app.app_context():
        entries = AuditLogEntry.query.filter_by(action="login_failed").all()
        assert len(entries) == 1
        assert entries[0].result == "error"
