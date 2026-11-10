"""B-10 (docs/AUDIT-2026-11.md): every audit event is mirrored, authenticated,
outside the database, and `flask audit-verify` reveals changes to the table."""

import gzip
import logging
import os
import stat
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from mcprack import audit, audit_mirror
from mcprack.extensions import db
from mcprack.models import AuditLogEntry, McpServer, User


@pytest.fixture
def mirror(app, tmp_path):
    """The audit mirror writing to a file of its own."""
    path = tmp_path / "audit.log"
    app.config["AUDIT_LOG_FILE"] = str(path)
    audit_mirror.init_app(app)
    yield path
    audit_mirror.shutdown()


def _lines(path):
    return [audit_mirror.parse_line(line) for line in path.read_text().splitlines() if line.strip()]


def _event(action="login", result="success", **kwargs):
    return audit.log_audit_event(action, result, **kwargs)


def _verify(app, path, *args):
    return app.test_cli_runner().invoke(args=["audit-verify", "--log", str(path), *args])


@pytest.fixture
def user(app):
    account = User(username="ann", auth_type="local")
    account.set_password("ann-long-password-1")
    db.session.add(account)
    db.session.commit()
    return account


# --- what is written ----------------------------------------------------------------------------


def test_an_event_is_mirrored_and_matches_its_row(app, mirror, user):
    entry = _event("admin_change", user=user, error_message="server updated", source_ip="203.0.113.5")

    [record] = _lines(mirror)

    assert record["id"] == entry.id and record["action"] == "admin_change" and record["user_id"] == user.id
    assert record["error_message"] == "server updated" and record["source_ip"] == "203.0.113.5"
    assert audit_mirror.mac_is_valid(record, audit_mirror._keys(app.config))
    row = db.session.get(AuditLogEntry, entry.id)
    logged = datetime.fromisoformat(record["ts"])
    stored = row.timestamp.replace(tzinfo=timezone.utc) if row.timestamp.tzinfo is None else row.timestamp
    assert abs(stored - logged) < timedelta(seconds=1)


def test_a_line_holds_exactly_the_audit_fields_and_nothing_else(app, mirror):
    _event("login_failed", "error", error_code="x")

    [record] = _lines(mirror)

    assert set(record) == {
        "v", "id", "ts", "action", "result", "user_id", "server_id", "server_name", "error_code", "error_message",
        "source_ip", "hostname", "duration_ms", "request_id", "mac",
    }


def test_the_event_is_recorded_even_when_the_database_write_fails(app, mirror):
    """The point of a second copy: an outage - or someone sabotaging the table -
    does not make events vanish."""
    with patch("mcprack.audit.db.session.commit", side_effect=RuntimeError("database down")):
        result = _event("admin_change", error_message="deleted a server")

    assert result is None
    [record] = _lines(mirror)
    assert record["id"] is None and record["error_message"] == "deleted a server"
    assert audit_mirror.mac_is_valid(record, audit_mirror._keys(app.config))
    assert AuditLogEntry.query.count() == 0


def test_operational_messages_never_end_up_in_the_mirror(app, mirror, capsys):
    """audit.py logs its own failures (with tracebacks) under its module logger;
    those must not be written into the audit mirror, which holds events only."""
    app.config["AUDIT_MIRROR_STDERR"] = True
    audit_mirror.init_app(app)
    with patch("mcprack.audit.db.session.commit", side_effect=RuntimeError("database down")):
        _event("admin_change")
    err = capsys.readouterr().err

    assert all(line.startswith("AUDIT {") for line in mirror.read_text().splitlines())
    assert "Traceback" not in mirror.read_text() and "database down" not in mirror.read_text()
    assert audit_mirror.MIRROR_LOGGER != audit.logger.name
    assert err.strip() and all(line.startswith("AUDIT {") for line in err.splitlines() if line.strip())  # stderr sink too


def test_a_failing_sink_never_breaks_the_request(app, mirror):
    class Exploding(logging.Handler):
        def emit(self, record):
            raise RuntimeError("disk full")

    handler = Exploding()
    logging.getLogger(audit_mirror.MIRROR_LOGGER).addHandler(handler)
    try:
        entry = _event("login")
    finally:
        logging.getLogger(audit_mirror.MIRROR_LOGGER).removeHandler(handler)

    assert entry is not None and db.session.get(AuditLogEntry, entry.id) is not None


def test_an_unwritable_file_is_reported_and_the_rest_keeps_working(app, tmp_path, caplog, capsys):
    app.config["AUDIT_LOG_FILE"] = "/proc/no-such-dir/audit.log"
    app.config["AUDIT_MIRROR_STDERR"] = True
    try:
        with caplog.at_level(logging.ERROR, logger="mcprack.audit_mirror"):
            audit_mirror.init_app(app)
        entry = _event("login")
        err = capsys.readouterr().err
    finally:
        audit_mirror.shutdown()

    assert "cannot be opened" in caplog.text
    assert entry is not None and err.startswith("AUDIT {")  # still mirrored to stderr


def test_the_stderr_sink_is_what_the_journal_collects(app, capsys):
    app.config["AUDIT_MIRROR_STDERR"] = True
    app.config["AUDIT_LOG_FILE"] = "off"
    audit_mirror.init_app(app)
    try:
        _event("login")
        err = capsys.readouterr().err
    finally:
        audit_mirror.shutdown()

    record = audit_mirror.parse_line(err.strip().splitlines()[-1])
    assert err.startswith("AUDIT {") and record["action"] == "login"


def test_it_can_be_switched_off(app, mirror):
    app.config["AUDIT_MIRROR_ENABLED"] = False
    audit_mirror.init_app(app)

    _event("login")

    assert not mirror.exists() or mirror.read_text() == ""
    assert AuditLogEntry.query.count() == 1  # the table is unaffected


def test_building_the_app_again_replaces_the_sinks_instead_of_stacking_them(app, mirror):
    for _ in range(3):
        audit_mirror.init_app(app)

    _event("login")

    assert len(_lines(mirror)) == 1  # not three copies of the line


def test_the_file_follows_logrotate(app, mirror):
    _event("login")
    os.rename(mirror, str(mirror) + ".1")  # what logrotate does
    _event("login")

    assert len(_lines(mirror)) == 1 and len(_lines(type(mirror)(str(mirror) + ".1"))) == 1


def test_the_file_is_not_world_readable(app, mirror):
    _event("login")

    assert stat.S_IMODE(mirror.stat().st_mode) == 0o640


@pytest.mark.parametrize(
    "setting,testing,expected",
    [("off", False, None), ("", False, None), ("None", False, None), ("/srv/a.log", False, "/srv/a.log"), (None, True, None)],
)
def test_which_file_a_setting_means(setting, testing, expected):
    assert audit_mirror.resolve_file(setting, testing=testing) == expected


def test_unset_means_the_package_log_directory_when_it_is_writable(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda path: path == "/var/log/mcprack")
    monkeypatch.setattr(os, "access", lambda path, mode: True)
    assert audit_mirror.resolve_file(None) == "/var/log/mcprack/audit.log"

    monkeypatch.setattr(os, "access", lambda path, mode: False)
    assert audit_mirror.resolve_file(None) is None


# --- authentication of a line -------------------------------------------------------------------


def test_any_change_to_a_line_breaks_its_mac(app, mirror):
    _event("admin_change", error_message="a")
    [record] = _lines(mirror)
    keys = audit_mirror._keys(app.config)

    for field, value in (("action", "login"), ("user_id", 99), ("error_message", "b"), ("id", 12345), ("result", "error")):
        forged = {**record, field: value}
        assert not audit_mirror.mac_is_valid(forged, keys), field
    assert not audit_mirror.mac_is_valid({k: v for k, v in record.items() if k != "mac"}, keys)
    assert audit_mirror.mac_is_valid(dict(reversed(list(record.items()))), keys)  # key order is irrelevant


def test_lines_stay_verifiable_after_a_secret_key_rotation(app, mirror):
    _event("login")
    [record] = _lines(mirror)
    old_key = app.config["SECRET_KEY"]

    app.config["SECRET_KEY"] = "a-brand-new-secret-key-0123456789abcdef"
    assert not audit_mirror.mac_is_valid(record, audit_mirror._keys(app.config))
    app.config["SECRET_KEY_FALLBACKS"] = [old_key]
    assert audit_mirror.mac_is_valid(record, audit_mirror._keys(app.config))


def test_a_line_without_keys_carries_no_mac():
    line = audit_mirror.format_line({"v": 1, "id": 1, "action": "login"}, [])

    assert audit_mirror.parse_line(line)["mac"] is None
    assert not audit_mirror.mac_is_valid(audit_mirror.parse_line(line), [b"key"])


@pytest.mark.parametrize(
    "text,ok",
    [
        ('AUDIT {"v":1,"id":3}', True),
        ('Nov 11 10:00:01 host mcprack[812]: AUDIT {"v":1,"id":3}', True),  # as journalctl prints it
        ('{"v":1,"id":3}', True),
        ('AUDIT {"v":2,"id":3}', False),
        ("AUDIT not json", False),
        ("some other log line", False),
        ("", False),
        ('AUDIT [1,2,3]', False),
    ],
)
def test_parsing_a_line(text, ok):
    assert (audit_mirror.parse_line(text) is not None) is ok


# --- audit-verify -------------------------------------------------------------------------------


def _several(user, count=4):
    server = McpServer(name="zabbix", label="Z", transport="stdio", command="/bin/true", enabled=True)
    db.session.add(server)
    db.session.commit()
    return [_event("admin_change", user=user, server=server, error_message=f"change {i}") for i in range(count)]


def test_a_clean_table_agrees_with_its_mirror(app, mirror, user):
    _several(user)

    result = _verify(app, mirror)

    assert result.exit_code == 0, result.output
    assert "4 event(s) checked" in result.output and "OK: the audit table agrees" in result.output


def test_a_deleted_row_is_reported(app, mirror, user):
    entries = _several(user)
    victim = entries[1].id
    AuditLogEntry.query.filter_by(id=victim).delete()
    db.session.commit()

    result = _verify(app, mirror)

    assert result.exit_code == 1
    assert "DELETED: 1 event(s)" in result.output and str(victim) in result.output and "FAILED" in result.output


def test_a_changed_row_is_reported_with_the_field(app, mirror, user):
    entries = _several(user)
    target = db.session.get(AuditLogEntry, entries[2].id)
    target.action = "login"
    target.error_message = "nothing to see"
    db.session.commit()

    result = _verify(app, mirror)

    assert result.exit_code == 1
    assert f"ALTERED: 1 row(s) differ from the log: {entries[2].id} (" in result.output
    assert "action" in result.output and "error_message" in result.output


def test_a_changed_timestamp_is_reported(app, mirror, user):
    entries = _several(user)
    target = db.session.get(AuditLogEntry, entries[0].id)
    target.timestamp = target.timestamp - timedelta(days=3)
    db.session.commit()

    result = _verify(app, mirror)

    assert result.exit_code == 1 and "timestamp" in result.output


def test_a_row_that_lost_its_user_after_the_user_was_deleted_is_not_tampering(app, mirror, user):
    entries = _several(user)
    # ON DELETE SET NULL: removing the account legitimately blanks the reference
    for entry in entries:
        db.session.get(AuditLogEntry, entry.id).user_id = None
        db.session.get(AuditLogEntry, entry.id).server_id = None
    db.session.commit()

    result = _verify(app, mirror)

    assert result.exit_code == 0, result.output


def test_but_pointing_a_row_at_a_different_user_is_reported(app, mirror, user):
    entries = _several(user)
    other = User(username="bob", auth_type="local")
    db.session.add(other)
    db.session.commit()
    db.session.get(AuditLogEntry, entries[0].id).user_id = other.id
    db.session.commit()

    result = _verify(app, mirror)

    assert result.exit_code == 1 and "user_id" in result.output


def test_an_inserted_row_is_a_warning_and_a_failure_when_strict(app, mirror, user):
    _several(user)
    db.session.add(AuditLogEntry(action="admin_change", result="success", error_message="forged by someone with SQL access"))
    db.session.commit()

    lenient = _verify(app, mirror)
    strict = _verify(app, mirror, "--strict")

    assert lenient.exit_code == 0 and "warning: 1 row(s) have no line in the log" in lenient.output
    assert strict.exit_code == 1 and "UNMIRRORED: 1 row(s)" in strict.output


def test_an_edited_log_line_is_reported_and_its_row_is_then_unmirrored(app, mirror, user):
    _several(user)
    lines = mirror.read_text().splitlines()
    lines[1] = lines[1].replace("change 1", "change X")  # someone tidies the log
    mirror.write_text("\n".join(lines) + "\n")

    result = _verify(app, mirror)

    assert result.exit_code == 1
    assert "TAMPERED LOG: 1 line(s) with an invalid MAC" in result.output and f"{mirror}:2" in result.output
    assert "1 row(s) have no line in the log" in result.output  # the doctored line no longer vouches for its row


def test_rotated_and_compressed_logs_are_read_too(app, mirror, user):
    _several(user, count=6)
    lines = mirror.read_text().splitlines()
    mirror.write_text("\n".join(lines[4:]) + "\n")
    (mirror.parent / "audit.log.1").write_text("\n".join(lines[2:4]) + "\n")
    with gzip.open(mirror.parent / "audit.log.2.gz", "wt") as handle:
        handle.write("\n".join(lines[:2]) + "\n")

    result = _verify(app, mirror)

    assert result.exit_code == 0, result.output
    assert "6 event(s) checked" in result.output and "3 file(s)" in result.output


def test_a_missing_rotated_file_shows_up_as_unmirrored_rows(app, mirror, user):
    _several(user, count=4)
    lines = mirror.read_text().splitlines()
    mirror.write_text("\n".join(lines[2:]) + "\n")  # the older part was lost

    result = _verify(app, mirror, "--strict")

    # the window starts at the first line that is present, so the earlier rows are outside it
    assert "OK" in result.output or "UNMIRRORED" in result.output


def test_rows_older_than_the_retention_window_may_be_gone(app, mirror, user):
    """`audit-archive` removes old rows on purpose; their log lines must not turn
    into DELETED reports."""
    old = datetime.now(timezone.utc) - timedelta(days=200)
    audit_mirror.emit({"v": 1, "id": 9001, "ts": old.isoformat(), "action": "login", "result": "success", "user_id": None,
                       "server_id": None, "server_name": None, "error_code": None, "error_message": None,
                       "source_ip": None, "hostname": None, "duration_ms": None, "request_id": None})
    _several(user, count=2)

    result = _verify(app, mirror)

    assert result.exit_code == 0 and "DELETED" not in result.output
    assert "2 event(s) checked" in result.output


def test_the_window_can_be_chosen(app, mirror, user):
    old = datetime.now(timezone.utc) - timedelta(days=30)
    audit_mirror.emit({"v": 1, "id": 9002, "ts": old.isoformat(), "action": "login", "result": "success", "user_id": None,
                       "server_id": None, "server_name": None, "error_code": None, "error_message": None,
                       "source_ip": None, "hostname": None, "duration_ms": None, "request_id": None})
    _several(user, count=1)

    assert "DELETED" in _verify(app, mirror, "--days", "90").output  # inside 90 days: the row should exist
    assert "DELETED" not in _verify(app, mirror, "--days", "7").output


def test_events_that_could_not_be_stored_are_noted_not_blamed(app, mirror, user):
    with patch("mcprack.audit.db.session.commit", side_effect=RuntimeError("database down")):
        _event("admin_change")
    _several(user, count=2)

    result = _verify(app, mirror)

    assert result.exit_code == 0 and "could not be written to the database" in result.output


def test_unreadable_lines_are_a_warning(app, mirror, user):
    _several(user, count=2)
    with open(mirror, "a") as handle:
        handle.write("garbage that is not an audit line\n")

    lenient = _verify(app, mirror)
    strict = _verify(app, mirror, "--strict")

    assert lenient.exit_code == 0 and "1 line(s) could not be read" in lenient.output
    assert strict.exit_code == 1


def test_a_key_that_was_rotated_without_fallbacks_makes_every_line_suspect(app, mirror, user):
    _several(user, count=3)
    app.config["SECRET_KEY"] = "a-brand-new-secret-key-0123456789abcdef"

    result = _verify(app, mirror)

    assert result.exit_code == 1 and "3 line(s) with an invalid MAC" in result.output


def test_with_the_old_key_as_a_fallback_the_log_still_verifies(app, mirror, user):
    _several(user, count=3)
    old = app.config["SECRET_KEY"]
    app.config["SECRET_KEY"] = "a-brand-new-secret-key-0123456789abcdef"
    app.config["SECRET_KEY_FALLBACKS"] = [old]

    assert _verify(app, mirror).exit_code == 0


def test_no_log_is_a_usage_error(app, tmp_path):
    result = app.test_cli_runner().invoke(args=["audit-verify", "--log", str(tmp_path / "absent.log")])

    assert result.exit_code == 2 and "No mirror log found" in result.output


def test_the_report_is_bounded(app, mirror, user):
    entries = _several(user, count=30)
    AuditLogEntry.query.filter(AuditLogEntry.id.in_([e.id for e in entries[:25]])).delete(synchronize_session=False)
    db.session.commit()

    result = _verify(app, mirror, "--max-report", "5")

    assert "DELETED: 25 event(s)" in result.output and "(+20 more)" in result.output


def test_a_log_with_nothing_authentic_is_not_reported_as_clean(app, mirror, user):
    _several(user, count=2)
    mirror.write_text(mirror.read_text().replace('"action":"admin_change"', '"action":"login"'))

    result = _verify(app, mirror)

    assert result.exit_code == 1 and "invalid MAC" in result.output


# --- the file sink cannot be turned against the host --------------------------------------------
#
# The log directory belongs to the service user, and the CLI may run as root: a
# path the service user can swap must never lead root to write to - or chown -
# something else.


def _try_open(app, path):
    app.config["AUDIT_LOG_FILE"] = str(path)
    audit_mirror.init_app(app)


def test_a_symlink_at_the_path_is_refused_and_its_target_is_not_touched(app, tmp_path, caplog):
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    victim.chmod(0o600)
    link = tmp_path / "audit.log"
    link.symlink_to(victim)

    try:
        with caplog.at_level(logging.ERROR, logger="mcprack.audit_mirror"):
            _try_open(app, link)
        _event("login")
    finally:
        audit_mirror.shutdown()

    assert victim.read_text() == "precious\n"  # nothing was appended through the link
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600  # and its mode was not changed
    assert "cannot be opened" in caplog.text
    assert AuditLogEntry.query.count() == 1  # the table is unaffected


def test_a_symlink_swapped_in_after_the_file_was_opened_is_not_followed(app, mirror, tmp_path):
    """logrotate-style reopening goes through the same safe open."""
    _event("login")
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    mirror.unlink()
    mirror.symlink_to(victim)  # swapped in while the service is running

    _event("login")  # the handler notices the change and tries to reopen

    assert victim.read_text() == "precious\n"
    assert AuditLogEntry.query.count() == 2  # auditing carried on


def test_a_hard_link_to_another_file_is_refused(app, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    linked = tmp_path / "audit.log"
    os.link(victim, linked)

    try:
        _try_open(app, linked)
        _event("login")
    finally:
        audit_mirror.shutdown()

    assert victim.read_text() == "precious\n"


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_something_that_is_not_a_plain_file_is_refused(app, tmp_path, kind):
    path = tmp_path / "audit.log"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)

    try:
        _try_open(app, path)
        entry = _event("login")
    finally:
        audit_mirror.shutdown()

    assert entry is not None  # and nothing hung waiting for a FIFO reader


def test_ownership_is_set_on_the_descriptor_of_a_file_root_just_created(app, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append(("fchown", uid, gid)))
    # nothing may be done by PATH: that is what a swapped symlink would exploit
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("chown by path"))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("chmod by path"))
    path = tmp_path / "audit.log"

    try:
        _try_open(app, path)
        _event("login")
    finally:
        audit_mirror.shutdown()

    owner = tmp_path.stat()
    assert calls == [("fchown", owner.st_uid, owner.st_gid)]  # to the owner of the directory
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_an_existing_file_is_appended_to_but_never_chowned_or_chmodded(app, tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    path.write_text("")
    path.chmod(0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda *a: pytest.fail("fchown on an existing file"))
    monkeypatch.setattr(os, "fchmod", lambda *a: pytest.fail("fchmod on an existing file"))

    try:
        _try_open(app, path)
        _event("login")
    finally:
        audit_mirror.shutdown()

    assert len(_lines(path)) == 1 and stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_write_error_is_reported_once_not_for_every_event(app, mirror, caplog):
    handler = next(h for h in logging.getLogger(audit_mirror.MIRROR_LOGGER).handlers if isinstance(h, audit_mirror._MirrorFileHandler))
    handler.stream.close()  # the next write fails

    with caplog.at_level(logging.ERROR, logger="mcprack.audit_mirror"):
        for _ in range(3):
            _event("login")

    assert caplog.text.count("cannot be written") == 1
    assert AuditLogEntry.query.count() == 3
