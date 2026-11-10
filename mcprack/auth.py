import hashlib
import hmac
from functools import wraps
from urllib.parse import urlparse

import ldap3
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_babel import _
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from . import accounts, audit, mailer, passwords, throttle
from .urls import external_url
from .extensions import db, limiter, login_manager
from .models import User

bp = Blueprint("auth", __name__)

_RESET_TOKEN_SALT = "password-reset"


def _safe_next_url(fallback=None):
    """Return a same-host next URL from the request, or `fallback`
    (default: catalog). Honors Flask-Login's ``?next=`` (e.g. returning to
    ``/oauth/authorize?...`` after login) without allowing open redirects.

    Accepts relative paths starting with a single ``/`` (not ``//``) or
    absolute http(s) URLs whose host matches ``request.host``."""
    if fallback is None:
        fallback = url_for("catalog.index")
    candidate = (request.values.get("next") or request.args.get("next") or "").strip()
    if not candidate:
        return fallback
    # Browsers drop tab/CR/LF from URLs, so "/\t/evil.example" would become
    # "//evil.example"; reject any control character or whitespace outright.
    if any(ord(c) < 0x21 or c == "\x7f" for c in candidate):
        return fallback
    # Protocol-relative and schemeless host tricks: //evil.example
    if candidate.startswith("//") or "\\" in candidate:
        return fallback
    parsed = urlparse(candidate)
    if candidate.startswith("/"):
        if not parsed.scheme and not parsed.netloc:
            return candidate
        return fallback
    if parsed.scheme in ("http", "https") and parsed.netloc == request.host:
        return candidate
    return fallback

# Applied to both self-service change and email-reset completion — a
# password this short isn't worth generating a reset link for.
MIN_PASSWORD_LENGTH = 8


def _reset_serializer():
    cfg = current_app.config
    keys = [*reversed(cfg.get("SECRET_KEY_FALLBACKS") or []), cfg["SECRET_KEY"]]
    return URLSafeTimedSerializer(keys, salt=_RESET_TOKEN_SALT)


def _password_fingerprint(user):
    """A keyed fingerprint of the current password hash. The token has to stop
    working once the password changes, but it is signed, not encrypted: it
    must not carry the hash itself (anyone holding the link could read it)."""
    return hmac.new(
        current_app.config["SECRET_KEY"].encode(),
        b"password-reset-fingerprint:" + (user.password_hash or "").encode(),
        hashlib.sha256,
    ).hexdigest()[:32]


def _generate_reset_token(user):
    return _reset_serializer().dumps({"user_id": user.id, "fp": _password_fingerprint(user)})


def _verify_reset_token(token, max_age):
    """Returns the User the token was issued for, or None if the token is
    invalid/expired/for a since-changed password. Embedding the current
    password_hash in the token means it stops working the moment the
    password actually changes, so a link can't be replayed after use."""
    try:
        data = _reset_serializer().loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    user = db.session.get(User, data.get("user_id"))
    fingerprint = data.get("fp")
    # tokens of the previous format (raw hash, no "fp") are not honoured
    if user is None or not isinstance(fingerprint, str):
        return None
    if not hmac.compare_digest(fingerprint, _password_fingerprint(user)):
        return None
    return user


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    # The cookie is signed, not stored, so it cannot be recalled - instead it
    # carries the account's session_version from login, and a mismatch (logout,
    # password change, account disabled/revoked) ends the session. Cookies
    # from before versions existed carry none and count as 0.
    if user is not None and session.get("sv", 0) != (user.session_version or 0):
        return None
    return user


def _start_session(user):
    """Log `user` in on a clean session: nothing a visitor (or somebody who
    planted a cookie) put in the old one survives, apart from the language
    choice."""
    locale = session.get("locale")
    session.clear()
    if locale:
        session["locale"] = locale
    login_user(user)
    session["sv"] = user.session_version or 0


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            from flask import abort

            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _ldap_authenticate(username, password):
    """Search-then-bind against the configured AD. Returns a dict of mapped
    attributes on success, or None on any failure (unknown user, bad
    password, LDAP unreachable)."""
    if not password:
        return None

    cfg = current_app.config
    # Set connect_timeout to 5 seconds to prevent worker hangs
    server = ldap3.Server(cfg["LDAP_SERVER"], get_info=None, connect_timeout=5)
    search_filter = cfg["LDAP_USER_FILTER"] % {"user": escape_filter_chars(username)}

    try:
        bind_dn = cfg["LDAP_BIND_DN"] or None
        bind_pw = cfg["LDAP_BIND_PASSWORD"] or None
        with ldap3.Connection(server, user=bind_dn, password=bind_pw, auto_bind=True) as search_conn:
            search_conn.search(
                search_base=cfg["LDAP_USER_OU"],
                search_filter=search_filter,
                attributes=["givenName", "sn", "mail", "memberOf"],
            )
            if not search_conn.entries:
                return None
            entry = search_conn.entries[0]
            user_dn = entry.entry_dn

        with ldap3.Connection(server, user=user_dn, password=password, auto_bind=True):
            pass
    except LDAPBindError:
        return None
    except LDAPException:
        current_app.logger.exception("LDAP authentication error")
        return None

    def _attr(name):
        values = entry[name].values if name in entry else []
        return values[0] if values else None

    # Optional group restriction (LDAP_REQUIRED_GROUP): authenticating against
    # the directory is not enough, the account must be in the group.
    required_group = (cfg.get("LDAP_REQUIRED_GROUP") or "").strip().lower()
    if required_group:
        groups = {str(group).strip().lower() for group in (entry["memberOf"].values if "memberOf" in entry else [])}
        if required_group not in groups:
            current_app.logger.info("LDAP login of '%s' refused: not a member of the required group", username)
            return None

    return {
        "first_name": _attr("givenName"),
        "last_name": _attr("sn"),
        "email": _attr("mail"),
    }


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"])
def login():
    next_url = _safe_next_url()

    if current_user.is_authenticated:
        return redirect(next_url)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        # The attempt is counted (atomically) and a locked account/address is
        # refused BEFORE any password is checked, with the same answer for
        # names that do not exist (docs/AUDIT-2026-11.md B-04).
        wait = throttle.begin(username, user, request.remote_addr)
        if wait:
            audit.log_audit_event("login_failed", "error", error_message="login refused: too many failures")
            flash(_("Too many failed attempts. Try again in a few minutes."), "error")
            response = current_app.make_response((render_template("login.html", next=next_url), 429))
            response.headers["Retry-After"] = str(wait)
            return response

        if user is not None and user.auth_type == "local" and user.password_hash:
            if user.check_password(password) and user.is_active:
                throttle.success(username, user, request.remote_addr)
                _start_session(user)
                audit.log_audit_event("login", "success", user=user)
                return redirect(next_url)
            # Never write what was typed into the audit trail: the username
            # field often holds a password pasted into the wrong box.
            audit.log_audit_event(
                "login_failed",
                "error",
                user_id=user.id,
                error_message="local authentication failed",
            )
            flash(_("Invalid username or password."), "error")
            return render_template("login.html", next=next_url)

        if current_app.config["LDAP_ENABLED"]:
            attrs = _ldap_authenticate(username, password)
        else:
            attrs = None

        if attrs is not None:
            if user is None:
                user = User(username=username, auth_type="ldap")
                db.session.add(user)
            user.first_name = attrs["first_name"] or user.first_name
            user.last_name = attrs["last_name"] or user.last_name
            user.email = attrs["email"] or user.email
            db.session.commit()
            if not user.is_active:
                audit.log_audit_event(
                    "login_failed", "error", user=user, error_message="account deactivated"
                )
                flash(_("This account has been deactivated."), "error")
                return render_template("login.html", next=next_url)
            throttle.success(username, user, request.remote_addr)
            _start_session(user)
            audit.log_audit_event("login", "success", user=user)
            return redirect(next_url)

        audit.log_audit_event(
            "login_failed",
            "error",
            user_id=user.id if user else None,
            error_message="invalid credentials",
        )
        flash(_("Invalid username or password."), "error")
        return render_template("login.html", next=next_url)

    # The GET query-param prefill only exists for the public demo link
    # (README's "Demo mode" section) - honoring it outside DEMO_MODE would
    # mean a real password could end up in the URL, browser history, and
    # server access logs. Within DEMO_MODE, a query string still wins, but
    # when there isn't one (e.g. a bare "/" redirecting here as
    # "/login?next=%2F") DEMO_USERNAME/DEMO_PASSWORD fill in instead, so
    # the demo is never just a blank login wall.
    demo_mode = current_app.config["DEMO_MODE"]
    if demo_mode:
        prefill_username = request.args.get("username") or current_app.config["DEMO_USERNAME"]
        prefill_password = request.args.get("password") or current_app.config["DEMO_PASSWORD"]
    else:
        prefill_username = ""
        prefill_password = ""
    return render_template(
        "login.html",
        prefill_username=prefill_username,
        prefill_password=prefill_password,
        next=next_url,
    )


@bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    # POST (the menu button, CSRF-protected) ends the account's sessions
    # everywhere: a copy of the cookie cannot be recalled any other way (see
    # load_user). A plain GET - an old bookmark, or a link on somebody else's
    # page - only logs out this browser, so it cannot be used to throw a user
    # out of all their devices.
    if request.method == "POST":
        accounts.invalidate_sessions(current_user)
        db.session.commit()
    logout_user()
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
# Same brute-force surface as /login: the form checks current_password, so an
# authenticated session (or a hijacked one) could otherwise guess it freely.
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"])
@login_required
def account_password():
    if current_user.auth_type != "local":
        flash(_("Your account is managed externally (LDAP) — its password can't be changed here."), "error")
        return redirect(url_for("catalog.index"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_user.check_password(current_password):
            flash(_("Current password is incorrect."), "error")
        elif new_password != confirm_password:
            flash(_("New password and confirmation don't match."), "error")
        elif problem := passwords.check_strength(new_password, current_user.username):
            flash(problem, "error")
        else:
            current_user.set_password(new_password)
            accounts.invalidate_sessions(current_user, keep_current=True)
            db.session.commit()
            audit.log_audit_event(
                "password_change", "success", user=current_user, error_message="self-service change"
            )
            flash(_("Password changed."), "success")
            return redirect(url_for("catalog.index"))

    return render_template("account_password.html")


@bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["PASSWORD_RESET_RATE_LIMIT"])
def forgot_password():
    smtp_configured = mailer.smtp_configured()

    if request.method == "POST" and smtp_configured:
        identifier = request.form.get("identifier", "").strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        # Always show the same message regardless of whether the account
        # exists, has an email, or is local — telling a caller which of
        # those is false would let them enumerate accounts/emails.
        if user is not None and user.auth_type == "local" and user.email:
            token = _generate_reset_token(user)
            reset_url = external_url("auth.reset_password", token=token)
            max_age_minutes = current_app.config["PASSWORD_RESET_MAX_AGE"] // 60
            mailer.send_email(
                user.email,
                _("mcprack password reset"),
                _(
                    "Someone (hopefully you) requested a password reset for the "
                    "mcprack account '%(username)s'.\n\n"
                    "Reset it here (valid for %(minutes)d minutes):\n%(url)s\n\n"
                    "If you didn't request this, ignore this email — your "
                    "password hasn't been changed.",
                    username=user.username,
                    minutes=max_age_minutes,
                    url=reset_url,
                ),
            )

        flash(
            _("If that account exists and has an email on file, a reset link has been sent."),
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html", smtp_configured=smtp_configured)


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["PASSWORD_RESET_RATE_LIMIT"])
def reset_password(token):
    user = _verify_reset_token(token, current_app.config["PASSWORD_RESET_MAX_AGE"])
    if user is None:
        flash(_("This password reset link is invalid or has expired."), "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            flash(_("New password and confirmation don't match."), "error")
        elif problem := passwords.check_strength(new_password, user.username):
            flash(problem, "error")
        else:
            user.set_password(new_password)
            accounts.invalidate_sessions(user)
            db.session.commit()
            audit.log_audit_event(
                "password_change", "success", user=user, error_message="reset via emailed link"
            )
            flash(_("Password reset. You can now log in."), "success")
            return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)


@bp.route("/set-locale/<locale>")
def set_locale(locale):
    from flask import session
    if locale in ["cs", "sk", "en"]:
        session["locale"] = locale
    # Back to the page the user came from - but only to a path on THIS host.
    # The old check (`request.host in referrer`) was a substring test, so
    # https://mcprack.example.com.attacker.invalid/ passed it
    # (docs/AUDIT-2026-11.md C-01). Redirect to the path only, never the
    # attacker-influenced string.
    parts = urlparse(request.referrer or "")
    if parts.scheme in ("http", "https") and parts.netloc == request.host and parts.path.startswith("/") \
            and not parts.path.startswith("//"):
        return redirect(parts.path + (f"?{parts.query}" if parts.query else ""))
    return redirect(url_for("catalog.index"))
