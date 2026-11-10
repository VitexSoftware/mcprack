"""Second factor (TOTP) for local and LDAP accounts (docs/AUDIT-2026-11.md B-03).

The shared secret is stored encrypted with the same key hierarchy as the local
secret store (SECRET_KEY, SECRET_KEY_FALLBACKS - so a rotated key does not lose
anybody's enrolment). A user is "enrolled" only after confirming a code from
their authenticator app. A code is accepted once: the time step of the last
accepted code is kept and recorded atomically, so two simultaneous requests with
the same code cannot both succeed. Recovery codes are single-use and stored as
keyed hashes, never in clear.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from cryptography.fernet import InvalidToken
from flask import current_app
from sqlalchemy import update

from . import secret_store, totp
from .extensions import db
from .models import User

_RECOVERY_SALT = b"mcprack.mfa.recovery.v1"


def is_enabled(user) -> bool:
    return bool(user is not None and user.totp_enabled and user.totp_secret)


def is_enrolling(user) -> bool:
    """A secret has been issued but not yet confirmed."""
    return bool(user.totp_secret and not user.totp_enabled)


def _secret(user):
    if not user.totp_secret:
        return None
    try:
        return secret_store._fernet().decrypt(user.totp_secret.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError, secret_store.SecretStoreError):
        return None


def pending_secret(user):
    """The secret of an enrolment in progress (to show it again after a mistyped code)."""
    return _secret(user) if is_enrolling(user) else None


def provisioning_uri(user, secret):
    return totp.provisioning_uri(secret, user.email or user.username, current_app.config.get("MFA_ISSUER", "mcprack"))


# --- recovery codes -----------------------------------------------------------------------------


def _recovery_keys():
    cfg = current_app.config
    keys = [cfg.get("SECRET_KEY", ""), *(cfg.get("SECRET_KEY_FALLBACKS") or [])]
    return [hmac.new(str(key).encode(), _RECOVERY_SALT, hashlib.sha256).digest() for key in keys if key]


def _recovery_hash(normalised, key):
    return hmac.new(key, normalised.encode("ascii"), hashlib.sha256).hexdigest()


def _stored_recovery(user):
    try:
        data = json.loads(user.recovery_codes or "[]")
    except ValueError:
        return []
    return [item for item in data if isinstance(item, str)] if isinstance(data, list) else []


def remaining_recovery_codes(user) -> int:
    return len(_stored_recovery(user))


def _issue_recovery_codes(user):
    count = int(current_app.config.get("MFA_RECOVERY_CODE_COUNT", 10))
    codes = [totp.generate_recovery_code() for _ in range(count)]
    key = _recovery_keys()[0]
    user.recovery_codes = json.dumps([_recovery_hash(totp.normalise_recovery_code(code), key) for code in codes])
    return codes


def _consume_recovery_code(user, code) -> bool:
    normalised = totp.normalise_recovery_code(code)
    if normalised is None:
        return False
    stored = _stored_recovery(user)
    wanted = {_recovery_hash(normalised, key) for key in _recovery_keys()}
    # every stored entry is compared, so the time taken does not say which one matched
    matches = [entry for entry in stored if any(hmac.compare_digest(entry, candidate) for candidate in wanted)]
    if not matches:
        return False
    remaining = [entry for entry in stored if entry != matches[0]]
    previous = user.recovery_codes
    # compare-and-set: of two simultaneous uses of the same code only one wins
    result = db.session.execute(
        update(User)
        .where(User.id == user.id, User.recovery_codes == previous)
        .values(recovery_codes=json.dumps(remaining))
        .execution_options(synchronize_session=False)
    )
    db.session.commit()
    if result.rowcount != 1:
        return False
    db.session.refresh(user)
    return True


# --- enrolment ----------------------------------------------------------------------------------


def begin_enrollment(user):
    """Issue a new secret (replacing any unconfirmed one). Returns (secret, uri).
    The factor is NOT active until confirm_enrollment() succeeds."""
    secret = totp.generate_secret()
    user.totp_secret = secret_store._fernet().encrypt(secret.encode("ascii")).decode("ascii")
    user.totp_enabled = False
    user.totp_last_step = 0
    user.recovery_codes = None
    db.session.commit()
    return secret, provisioning_uri(user, secret)


def confirm_enrollment(user, code):
    """Switch the factor on if `code` is valid for the pending secret. Returns the
    recovery codes - shown once, never again - or None for a wrong code."""
    secret = pending_secret(user)
    if secret is None:
        return None
    step = totp.match(secret, code, after_step=int(user.totp_last_step or 0))
    if step is None:
        return None
    user.totp_enabled = True
    user.totp_last_step = step
    codes = _issue_recovery_codes(user)
    db.session.commit()
    return codes


def regenerate_recovery_codes(user):
    codes = _issue_recovery_codes(user)
    db.session.commit()
    return codes


def disable(user):
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_step = 0
    user.recovery_codes = None
    db.session.commit()


# --- verification -------------------------------------------------------------------------------


def verify_login(user, code):
    """Check a second-factor `code` (an authenticator code or a recovery code).
    Returns "totp", "recovery" or None."""
    if not is_enabled(user):
        return None
    secret = _secret(user)
    if secret is not None:
        step = totp.match(secret, code, after_step=int(user.totp_last_step or 0))
        if step is not None:
            # atomic: if a parallel request got there first, this one is refused
            result = db.session.execute(
                update(User)
                .where(User.id == user.id, User.totp_last_step < step)
                .values(totp_last_step=step)
                .execution_options(synchronize_session=False)
            )
            db.session.commit()
            if result.rowcount == 1:
                db.session.refresh(user)
                return "totp"
            return None
    if _consume_recovery_code(user, code):
        return "recovery"
    return None
