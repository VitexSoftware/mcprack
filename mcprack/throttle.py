"""Brute-force protection for the login form that holds across workers.

State lives in the database (`login_throttle`), so it is shared by every
gunicorn worker and survives a restart - the in-memory Flask-Limiter budget
was per worker and per IP only (docs/AUDIT-2026-11.md B-04).

Three counters, because each alone has a hole:

* **pair** (account + client address): the first line. It stops guessing
  against one account from one place, and it does NOT let a stranger lock the
  real owner out - the owner comes from another address.
* **account**: a much higher ceiling over all addresses, the backstop against
  guessing spread over many addresses.
* **address**: stops one address trying many names.

The attempt is COUNTED BEFORE the password is checked, with an atomic SQL
increment, and judged on the committed count. Counting afterwards (read, check,
write) would let a burst of parallel requests all pass the check before any
of them was recorded. A correct login erases the account's and pair's
counters and takes back its own count on the address. Attempts made while a
key is locked are refused without being counted, so waiting is never
punished by a longer lock.

The account is identified by its resolved database id when it exists (so every
spelling the database maps to the same account shares one counter) and by a
normalised name (NFKC, case-folded) when it does not. Keys are keyed hashes;
neither names nor addresses are stored. After a limit is exceeded the key is
locked for LOGIN_LOCK_BASE seconds, doubling each time it is locked again
within the window, up to LOGIN_LOCK_MAX. When a lock runs out the next attempt
is a probation: a correct password gets in, a wrong one locks again. In DEMO_MODE (public shared login) only the address counter
applies, otherwise anybody could lock the demo account for everyone.
"""

import hashlib
import hmac
import unicodedata
from datetime import datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import or_, update
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import LoginThrottle


def _enabled():
    return bool(current_app.config.get("LOGIN_THROTTLE_ENABLED", True))


def _now():
    return datetime.now(timezone.utc)


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _hash(scope, value):
    digest = hmac.new(
        current_app.config["SECRET_KEY"].encode(), f"{scope}:{value}".encode(), hashlib.sha256
    ).hexdigest()
    return digest[:48]


def _normalised(name):
    return unicodedata.normalize("NFKC", (name or "").strip()).casefold()


def _identity(username, user):
    return f"id:{user.id}" if user is not None else f"name:{_normalised(username)}"


def _limits():
    cfg = current_app.config
    return {
        "pair": int(cfg.get("LOGIN_MAX_FAILURES", 5)),
        "user": int(cfg.get("LOGIN_ACCOUNT_MAX_FAILURES", 50)),
        "ip": int(cfg.get("LOGIN_IP_MAX_FAILURES", 30)),
    }


def _keys(username, user, ip):
    identity = _identity(username, user)
    address = ip or "-"
    keys = [
        ("pair", _hash("pair", f"{identity}|{address}")),
        ("user", _hash("user", identity)),
        ("ip", _hash("ip", address)),
    ]
    if current_app.config.get("DEMO_MODE"):
        keys = [entry for entry in keys if entry[0] == "ip"]
    return keys


def _locked_wait(rows, now):
    waits = [
        int((_aware(row.locked_until) - now).total_seconds()) + 1
        for row in rows
        if row is not None and _aware(row.locked_until) and _aware(row.locked_until) > now
    ]
    return max(waits, default=0)


def _bump(scope, key, now, window):
    """Atomically add one failure to (scope, key) and return the new count."""
    cutoff = now - window
    still_locked = or_(LoginThrottle.locked_until.is_(None), LoginThrottle.locked_until < now)
    # the window moved on and no lock is running: start counting afresh
    db.session.execute(
        update(LoginThrottle)
        .where(LoginThrottle.scope == scope, LoginThrottle.key == key,
               LoginThrottle.first_failure_at < cutoff, still_locked)
        .values(failures=0, first_failure_at=now, locked_until=None, lock_level=0)
        .execution_options(synchronize_session=False)
    )
    for _ in range(2):
        updated = db.session.execute(
            update(LoginThrottle)
            .where(LoginThrottle.scope == scope, LoginThrottle.key == key)
            .values(failures=LoginThrottle.failures + 1)
            .execution_options(synchronize_session=False)
        )
        if updated.rowcount:
            break
        try:
            db.session.add(LoginThrottle(scope=scope, key=key, failures=0, first_failure_at=now))
            db.session.flush()
        except IntegrityError:  # another worker inserted it first: just bump theirs
            db.session.rollback()
    db.session.commit()
    row = LoginThrottle.query.filter_by(scope=scope, key=key).first()
    db.session.refresh(row)
    return row


def begin(username, user, ip):
    """Count one login attempt and return how many seconds the caller must
    wait (0 = go ahead and check the password). Call before verifying it."""
    if not _enabled():
        return 0
    cfg = current_app.config
    window = timedelta(seconds=int(cfg.get("LOGIN_FAILURE_WINDOW", 900)))
    base = int(cfg.get("LOGIN_LOCK_BASE", 30))
    maximum = int(cfg.get("LOGIN_LOCK_MAX", 3600))
    limits = _limits()
    now = _now()

    # housekeeping: forget everything older than a day
    LoginThrottle.query.filter(LoginThrottle.first_failure_at < now - timedelta(days=1)).delete(
        synchronize_session=False
    )

    keys = _keys(username, user, ip)
    existing = [LoginThrottle.query.filter_by(scope=s, key=k).first() for s, k in keys]
    wait = _locked_wait(existing, now)
    if wait:
        db.session.commit()
        return wait  # waiting is not an attempt: refused, not counted

    # A lock that has run out grants ONE probationary attempt: the count drops
    # to just below the limit, so a correct password gets in and a wrong one
    # locks again (for longer - lock_level is kept).
    for (scope, key), row in zip(keys, existing):
        if row is not None and row.locked_until is not None:
            db.session.execute(
                update(LoginThrottle)
                .where(LoginThrottle.scope == scope, LoginThrottle.key == key)
                .values(failures=max(limits[scope] - 1, 0), locked_until=None)
                .execution_options(synchronize_session=False)
            )
    db.session.commit()

    for scope, key in keys:
        row = _bump(scope, key, now, window)
        if row.failures > limits[scope]:
            row.lock_level = (row.lock_level or 0) + 1
            row.locked_until = now + timedelta(seconds=min(base * (2 ** (row.lock_level - 1)), maximum))
    db.session.commit()
    return _locked_wait([LoginThrottle.query.filter_by(scope=s, key=k).first() for s, k in keys], now)


def success(username, user, ip):
    """A correct login: forget the pair and the account (both spellings of the
    identity) and take back this attempt's count on the address."""
    if not _enabled():
        return
    identities = {_identity(username, user), _identity(username, None)}
    address = ip or "-"
    for identity in identities:
        LoginThrottle.query.filter_by(scope="user", key=_hash("user", identity)).delete()
        LoginThrottle.query.filter_by(scope="pair", key=_hash("pair", f"{identity}|{address}")).delete()
    db.session.execute(
        update(LoginThrottle)
        .where(LoginThrottle.scope == "ip", LoginThrottle.key == _hash("ip", address), LoginThrottle.failures > 0)
        .values(failures=LoginThrottle.failures - 1)
        .execution_options(synchronize_session=False)
    )
    db.session.commit()
