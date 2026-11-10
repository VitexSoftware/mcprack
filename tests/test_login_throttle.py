"""B-04 (docs/AUDIT-2026-11.md): brute-force protection that holds across
gunicorn workers. The Flask-Limiter budget was per worker (x4), per IP only,
there was no account lockout, and every failed login wrote the typed name -
often a password pasted into the wrong box - into the audit table."""

from datetime import datetime, timedelta, timezone

import pytest

from mcprack import throttle
from mcprack.extensions import db
from mcprack.models import AuditLogEntry, LoginThrottle, User

GOOD = "frank-long-password-1"


@pytest.fixture
def frank(app):
    app.config.update(LOGIN_MAX_FAILURES=3, LOGIN_IP_MAX_FAILURES=50, LOGIN_LOCK_BASE=60)
    with app.app_context():
        user = User(username="frank", auth_type="local")
        user.set_password(GOOD)
        db.session.add(user)
        db.session.commit()
    return app


def _try(client, username="frank", password="wrong-password-0", ip="198.51.100.7"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        environ_overrides={"REMOTE_ADDR": ip},
    )


def _logged_in(client):
    return client.get("/").status_code == 200


def test_an_account_is_locked_after_too_many_failures_even_with_the_right_password(frank, client):
    for _ in range(3):
        assert _try(client).status_code == 200  # ordinary "invalid" page

    locked = _try(client, password=GOOD)

    assert locked.status_code == 429
    assert "Retry-After" in locked.headers
    assert not _logged_in(client)


def test_the_lock_is_per_account_not_global(frank, client):
    with frank.app_context():
        other = User(username="gail", auth_type="local")
        other.set_password("gail-long-password-1")
        db.session.add(other)
        db.session.commit()
    for _ in range(3):
        _try(client)

    assert _try(client, username="gail", password="gail-long-password-1").status_code == 302


def test_unknown_usernames_are_locked_the_same_way(frank, client):
    """Otherwise the lock would tell an attacker which names exist."""
    for _ in range(3):
        _try(client, username="no-such-user")

    assert _try(client, username="no-such-user").status_code == 429


def test_usernames_are_case_insensitive_for_the_lock(frank, client):
    for name in ("frank", "FRANK", "Frank"):
        _try(client, username=name)

    assert _try(client, username="fRaNk", password=GOOD).status_code == 429


def test_the_lock_expires_and_a_success_resets_the_counter(frank, client):
    for _ in range(3):
        _try(client)
    with frank.app_context():
        for row in LoginThrottle.query.all():
            row.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

    assert _try(client, password=GOOD).status_code == 302
    with frank.app_context():
        assert LoginThrottle.query.filter_by(scope="user").count() == 0


def test_the_lock_grows_with_repeated_failures(frank):
    with frank.app_context():
        for _ in range(3):
            throttle.record_failure("frank", "198.51.100.7")
        first = throttle.seconds_locked("frank", "198.51.100.7")
        # simulate the lock expiring, then another failure
        row = LoginThrottle.query.filter_by(scope="user").one()
        row.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()
        throttle.record_failure("frank", "198.51.100.7")
        second = throttle.seconds_locked("frank", "198.51.100.7")

    assert first > 0 and second > first


def test_one_address_trying_many_names_is_locked_out(frank, client):
    frank.config["LOGIN_IP_MAX_FAILURES"] = 4
    for i in range(4):
        _try(client, username=f"guess{i}", ip="203.0.113.50")

    assert _try(client, username="frank", password=GOOD, ip="203.0.113.50").status_code == 429
    # another address is not affected
    assert _try(client, username="frank", password=GOOD, ip="203.0.113.51").status_code == 302


def test_the_typed_username_is_not_written_to_the_audit_table(frank, client):
    _try(client, username="hunter2-pasted-password")
    _try(client, username="frank")

    with frank.app_context():
        messages = " ".join((e.error_message or "") for e in AuditLogEntry.query.all())

    assert "hunter2-pasted-password" not in messages
    assert "frank" not in messages


def test_stored_keys_are_hashed(frank, client):
    _try(client, username="frank")

    with frank.app_context():
        keys = [row.key for row in LoginThrottle.query.all()]

    assert keys and all("frank" not in key and "198.51.100.7" not in key for key in keys)


def test_old_rows_are_pruned(frank):
    with frank.app_context():
        db.session.add(LoginThrottle(scope="user", key="stale", failures=1,
                                     first_failure_at=datetime.now(timezone.utc) - timedelta(days=3)))
        db.session.commit()

        throttle.record_failure("frank", "198.51.100.7")

        assert LoginThrottle.query.filter_by(key="stale").count() == 0


def test_throttle_can_be_switched_off(frank, client):
    frank.config["LOGIN_THROTTLE_ENABLED"] = False
    for _ in range(10):
        _try(client)

    assert _try(client, password=GOOD).status_code == 302


def test_demo_mode_never_locks_the_shared_account(frank, client):
    """The demo credentials are public; locking the account would let anybody
    lock everybody else out. Only the per-address limit applies."""
    frank.config["DEMO_MODE"] = True
    for i in range(6):
        _try(client, ip=f"203.0.113.{10 + i}")  # six different addresses

    assert _try(client, password=GOOD, ip="203.0.113.99").status_code == 302
