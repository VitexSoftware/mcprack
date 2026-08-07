from functools import wraps

import ldap3
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_babel import _
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from . import audit, mailer
from .extensions import db, limiter, login_manager
from .models import User

bp = Blueprint("auth", __name__)

_RESET_TOKEN_SALT = "password-reset"

# Applied to both self-service change and email-reset completion — a
# password this short isn't worth generating a reset link for.
MIN_PASSWORD_LENGTH = 8


def _reset_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=_RESET_TOKEN_SALT)


def _generate_reset_token(user):
    return _reset_serializer().dumps({"user_id": user.id, "password_hash": user.password_hash})


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
    if user is None or user.password_hash != data.get("password_hash"):
        return None
    return user


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


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
                attributes=["givenName", "sn", "mail"],
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

    return {
        "first_name": _attr("givenName"),
        "last_name": _attr("sn"),
        "email": _attr("mail"),
    }


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("catalog.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user is not None and user.auth_type == "local" and user.password_hash:
            if user.check_password(password) and user.is_active:
                login_user(user)
                audit.log_audit_event("login", "success", user=user)
                return redirect(url_for("catalog.index"))
            audit.log_audit_event(
                "login_failed",
                "error",
                user_id=user.id,
                error_message=f"local auth failed for '{username}'",
            )
            flash(_("Invalid username or password."), "error")
            return render_template("login.html")

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
                return render_template("login.html")
            login_user(user)
            audit.log_audit_event("login", "success", user=user)
            return redirect(url_for("catalog.index"))

        audit.log_audit_event(
            "login_failed",
            "error",
            user_id=user.id if user else None,
            error_message=f"invalid credentials for '{username}'",
        )
        flash(_("Invalid username or password."), "error")
        return render_template("login.html")

    # The GET query-param prefill only exists for the public demo link
    # (README's "Demo mode" section) - honoring it outside DEMO_MODE would
    # mean a real password could end up in the URL, browser history, and
    # server access logs.
    demo_mode = current_app.config["DEMO_MODE"]
    return render_template(
        "login.html",
        prefill_username=request.args.get("username", "") if demo_mode else "",
        prefill_password=request.args.get("password", "") if demo_mode else "",
    )


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
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
        elif len(new_password) < MIN_PASSWORD_LENGTH:
            flash(_("New password must be at least %(n)d characters.", n=MIN_PASSWORD_LENGTH), "error")
        elif new_password != confirm_password:
            flash(_("New password and confirmation don't match."), "error")
        else:
            current_user.set_password(new_password)
            db.session.commit()
            audit.log_audit_event(
                "password_change", "success", user=current_user, error_message="self-service change"
            )
            flash(_("Password changed."), "success")
            return redirect(url_for("catalog.index"))

    return render_template("account_password.html")


@bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"])
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
            reset_url = url_for("auth.reset_password", token=token, _external=True)
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
def reset_password(token):
    user = _verify_reset_token(token, current_app.config["PASSWORD_RESET_MAX_AGE"])
    if user is None:
        flash(_("This password reset link is invalid or has expired."), "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < MIN_PASSWORD_LENGTH:
            flash(_("New password must be at least %(n)d characters.", n=MIN_PASSWORD_LENGTH), "error")
        elif new_password != confirm_password:
            flash(_("New password and confirmation don't match."), "error")
        else:
            user.set_password(new_password)
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
    # Redirect back to original page, or index as default
    ref = request.referrer
    if ref and request.host in ref:
        return redirect(ref)
    return redirect(url_for("catalog.index"))
