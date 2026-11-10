"""Brute-force protection for the login form that holds across workers.

State lives in the database (`login_throttle`), so it is shared by every
gunicorn worker and survives a restart - the in-memory Flask-Limiter budget
was per worker and per IP only (docs/AUDIT-2026-11.md B-04). Two counters:

* per account (lower-cased username, whether or not it exists - so a lock
  does not reveal which names are real);
* per client address.

After LOGIN_MAX_FAILURES (per account) or LOGIN_IP_MAX_FAILURES (per address)
failures inside LOGIN_FAILURE_WINDOW seconds the key is locked, for
LOGIN_LOCK_BASE seconds and doubling with every further failure up to
LOGIN_LOCK_MAX. A successful login clears the account counter. Keys are
hashed, so neither names nor addresses are stored.
"""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from flask import current_app

from .extensions import db
from .models import LoginThrottle


def _enabled():
    return bool(current_app.config.get("LOGIN_THROTTLE_ENABLED", True))


def _key(scope, value):
    digest = hmac.new(
        current_app.config["SECRET_KEY"].encode(), f"{scope}:{value}".encode(), hashlib.sha256
    ).hexdigest()
    return digest[:48]


def _now():
    return datetime.now(timezone.utc)


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _entries(username, ip):
    keys = [("user", _key("user", (username or "").strip().lower())), ("ip", _key("ip", ip or "-"))]
    if current_app.config.get("DEMO_MODE"):
        # The demo login is public (prefilled on the page): an account lock
        # would let anybody lock everybody else out of the demo. Only the
        # per-address limit applies there.
        keys = [entry for entry in keys if entry[0] == "ip"]
    return [(scope, key, LoginThrottle.query.filter_by(scope=scope, key=key).first()) for scope, key in keys]


def seconds_locked(username, ip):
    """Seconds until `username` / `ip` may try again (0 = not locked)."""
    if not _enabled():
        return 0
    now = _now()
    remaining = 0
    for _scope, _key_, row in _entries(username, ip):
        locked_until = _aware(row.locked_until) if row else None
        if locked_until and locked_until > now:
            remaining = max(remaining, int((locked_until - now).total_seconds()) + 1)
    return remaining


def record_failure(username, ip):
    """Count one failed attempt against the account and the address."""
    if not _enabled():
        return
    cfg = current_app.config
    window = timedelta(seconds=int(cfg.get("LOGIN_FAILURE_WINDOW", 900)))
    limits = {
        "user": int(cfg.get("LOGIN_MAX_FAILURES", 5)),
        "ip": int(cfg.get("LOGIN_IP_MAX_FAILURES", 30)),
    }
    base = int(cfg.get("LOGIN_LOCK_BASE", 30))
    maximum = int(cfg.get("LOGIN_LOCK_MAX", 3600))
    now = _now()

    # housekeeping: forget everything older than a day
    LoginThrottle.query.filter(LoginThrottle.first_failure_at < now - timedelta(days=1)).delete(
        synchronize_session=False
    )

    for scope, key, row in _entries(username, ip):
        if row is None:
            row = LoginThrottle(scope=scope, key=key, failures=0, first_failure_at=now)
            db.session.add(row)
        elif _aware(row.first_failure_at) < now - window and not (_aware(row.locked_until) and _aware(row.locked_until) > now):
            row.failures, row.first_failure_at = 0, now  # the window moved on
        row.failures += 1
        over = row.failures - limits[scope]
        if over >= 0:
            row.locked_until = now + timedelta(seconds=min(base * (2 ** over), maximum))
    db.session.commit()


def record_success(username):
    """A correct login clears the account counter (the address keeps its own)."""
    if not _enabled():
        return
    LoginThrottle.query.filter_by(scope="user", key=_key("user", (username or "").strip().lower())).delete()
    db.session.commit()
