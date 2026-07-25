from functools import wraps

import ldap3
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from extensions import db, login_manager
from models import User

bp = Blueprint("auth", __name__)


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
                return redirect(url_for("catalog.index"))
            flash("Invalid username or password.", "error")
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
                flash("This account has been deactivated.", "error")
                return render_template("login.html")
            login_user(user)
            return redirect(url_for("catalog.index"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
