"""B-04 (docs/AUDIT-2026-11.md): brute-force protection that holds across
gunicorn workers. The Flask-Limiter budget was per worker (x4), per IP only,
there was no account lockout, and every failed login wrote the typed name -
often a password pasted into the wrong box - into the audit table.

Design points pinned here: the attempt is counted before the password is
checked and the increment is atomic; the primary lock is per account AND
address, so a stranger cannot lock the real owner out; the account is
identified by its resolved id."""

from datetime import datetime, timedelta, timezone

import pytest

from mcprack import throttle
from mcprack.extensions import db
from mcprack.models import AuditLogEntry, LoginThrottle, User

GOOD = "frank-long-password-1"
HOME = "198.51.100.7"


@pytest.fixture
def frank(app):
    app.config.update(
        LOGIN_MAX_FAILURES=3, LOGIN_ACCOUNT_MAX_FAILURES=8, LOGIN_IP_MAX_FAILURES=50, LOGIN_LOCK_BASE=60
    )
    with app.app_context():
        user = User(username="frank", auth_type="local")
        user.set_password(GOOD)
        db.session.add(user)
        db.session.commit()
    return app


def _try(client, username="frank", password="wrong-password-0", ip=HOME):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        environ_overrides={"REMOTE_ADDR": ip},
    )


def _logged_in(client):
    return client.get("/").status_code == 200


def test_after_too_many_failures_even_the_right_password_is_refused_from_that_address(frank, client):
    for _ in range(3):
        assert _try(client).status_code == 200  # the ordinary "invalid" page

    locked = _try(client, password=GOOD)

    assert locked.status_code == 429
    assert "Retry-After" in locked.headers
    assert not _logged_in(client)


def test_a_stranger_cannot_lock_the_real_owner_out(frank, client):
    """The lock is per account AND address: the attacker's failures lock the
    attacker's address, the owner logs in from theirs."""
    for _ in range(5):
        _try(client, ip="203.0.113.66")  # the attacker

    owner = app_client = frank.test_client()
    assert _try(owner, password=GOOD, ip=HOME).status_code == 302


def test_guessing_spread_over_many_addresses_hits_the_account_ceiling(frank, client):
    for i in range(8):
        _try(client, ip=f"203.0.113.{100 + i}")  # one failure each: no pair lock

    assert _try(client, password=GOOD, ip="203.0.113.200").status_code == 429


def test_other_accounts_are_unaffected(frank, client):
    with frank.app_context():
        other = User(username="gail", auth_type="local")
        other.set_password("gail-long-password-1")
        db.session.add(other)
        db.session.commit()
    for _ in range(4):
        _try(client)

    assert _try(client, username="gail", password="gail-long-password-1").status_code == 302


def test_unknown_usernames_are_locked_the_same_way(frank, client):
    """Otherwise the lock would tell an attacker which names exist."""
    for _ in range(3):
        _try(client, username="no-such-user")

    assert _try(client, username="no-such-user").status_code == 429


def test_spellings_of_an_unknown_name_share_one_counter(frank, client):
    for name in ("Ghost", "GHOST", "ghost"):
        _try(client, username=name)

    assert _try(client, username="gHoSt").status_code == 429


def test_unicode_variants_of_an_unknown_name_share_one_counter(frank, client):
    for name in ("ﬁnn", "finn", "FINN"):  # a ligature normalises (NFKC) to "fi"
        _try(client, username=name)

    assert _try(client, username="Finn").status_code == 429


def test_waiting_is_not_punished(frank, client):
    """Attempts made while locked are refused without being counted, so
    retrying does not stretch the lock."""
    for _ in range(4):
        _try(client)  # the fourth locks
    with frank.app_context():
        before = sorted(row.failures for row in LoginThrottle.query.all())

    for _ in range(5):
        assert _try(client).status_code == 429

    with frank.app_context():
        assert sorted(row.failures for row in LoginThrottle.query.all()) == before


def test_the_lock_expires_and_a_success_resets_the_counters(frank, client):
    for _ in range(4):
        _try(client)
    with frank.app_context():
        for row in LoginThrottle.query.all():
            row.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

    assert _try(client, password=GOOD).status_code == 302
    with frank.app_context():
        assert LoginThrottle.query.filter(LoginThrottle.scope.in_(["user", "pair"])).count() == 0


def test_the_lock_grows_with_repeated_excess(frank):
    with frank.app_context():
        user = User.query.filter_by(username="frank").first()
        for _ in range(4):
            wait_first = throttle.begin("frank", user, HOME)
        for row in LoginThrottle.query.all():
            row.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()
        assert throttle.begin("frank", user, HOME) == 0  # the probationary attempt is allowed
        wait_second = throttle.begin("frank", user, HOME)  # ... and failing it locks again, longer

    assert wait_first > 0 and wait_second > wait_first


def test_one_address_trying_many_names_is_locked_out(frank, client):
    frank.config["LOGIN_IP_MAX_FAILURES"] = 4
    for i in range(5):
        _try(client, username=f"guess{i}", ip="203.0.113.50")

    assert _try(client, username="frank", password=GOOD, ip="203.0.113.50").status_code == 429
    assert _try(client, username="frank", password=GOOD, ip="203.0.113.51").status_code == 302


def test_a_normal_login_does_not_eat_into_the_address_budget(frank, client):
    frank.config["LOGIN_IP_MAX_FAILURES"] = 2
    for _ in range(10):
        c = frank.test_client()
        assert _try(c, password=GOOD).status_code == 302


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

    assert keys and all("frank" not in key and HOME not in key for key in keys)


def test_old_rows_are_pruned(frank):
    with frank.app_context():
        db.session.add(LoginThrottle(scope="user", key="stale", failures=1,
                                     first_failure_at=datetime.now(timezone.utc) - timedelta(days=3)))
        db.session.commit()

        throttle.begin("frank", None, HOME)

        assert LoginThrottle.query.filter_by(key="stale").count() == 0


def test_the_counter_is_incremented_in_sql_not_read_modified_written(frank):
    """Two overlapping workers must not lose an attempt: the bump is a single
    UPDATE ... SET failures = failures + 1, whatever the ORM object says."""
    with frank.app_context():
        user = User.query.filter_by(username="frank").first()
        throttle.begin("frank", user, HOME)
        row = LoginThrottle.query.filter_by(scope="pair").one()
        stale = row.failures  # a worker that read the row earlier ...
        throttle.begin("frank", user, HOME)  # ... another worker bumps it ...
        row.failures = stale  # ... the first one's in-memory copy is now stale
        db.session.expire_all()  # (a real second worker has its own session)

        assert LoginThrottle.query.filter_by(scope="pair").one().failures == 2


def test_throttle_can_be_switched_off(frank, client):
    frank.config["LOGIN_THROTTLE_ENABLED"] = False
    for _ in range(10):
        _try(client)

    assert _try(client, password=GOOD).status_code == 302


def test_demo_mode_never_locks_the_shared_account(frank, client):
    """The demo credentials are public; an account lock would let anybody
    lock everybody else out. Only the per-address limit applies."""
    frank.config["DEMO_MODE"] = True
    for i in range(10):
        _try(client, ip=f"203.0.113.{10 + i}")  # ten different addresses

    assert _try(client, password=GOOD, ip="203.0.113.99").status_code == 302
