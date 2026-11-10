"""B-05 (docs/AUDIT-2026-11.md): a session cookie is signed, not stored, so a
copy captured earlier kept working after logout and after a password change.
Every account now carries a session_version that is embedded in the cookie at
login and checked on each request; logging out, changing the password,
disabling the account or revoking its tokens changes it."""

import re

import pytest

from mcprack import accounts
from mcprack.extensions import db
from mcprack.models import User

PW = "erin-long-password-1"


@pytest.fixture
def erin(app):
    with app.app_context():
        user = User(username="erin", auth_type="local")
        user.set_password(PW)
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(app, password=PW):
    """A fresh client plus the session cookie value the login produced."""
    client = app.test_client()
    resp = client.post("/login", data={"username": "erin", "password": password})
    match = re.search(r"session=([^;]+)", " ".join(resp.headers.getlist("Set-Cookie")))
    assert match, "login did not set a session cookie"
    return client, match.group(1)


def _replay(app, cookie):
    other = app.test_client()
    other.set_cookie("session", cookie)
    return other.get("/").status_code


def test_a_live_session_works(app, erin):
    client, cookie = _login(app)

    assert client.get("/").status_code == 200
    assert _replay(app, cookie) == 200


def test_cookie_captured_before_logout_is_dead_after_it(app, erin):
    client, cookie = _login(app)

    client.post("/logout")

    assert _replay(app, cookie) == 302


def test_cookie_captured_before_a_self_service_password_change_is_dead_but_the_changing_device_stays_in(app, erin):
    client, _ = _login(app)
    _, stolen = _login(app)  # a second login, e.g. the attacker's copy

    client.post(
        "/account/password",
        data={"current_password": PW, "new_password": "a-brand-new-long-password", "confirm_password": "a-brand-new-long-password"},
    )

    assert _replay(app, stolen) == 302
    assert client.get("/").status_code == 200  # the device that changed it is not thrown out


def test_cookie_is_dead_after_an_admin_resets_the_password(app, erin):
    _, cookie = _login(app)
    with app.app_context():
        boss = User(username="boss", auth_type="local", is_admin=True)
        boss.set_password("boss-long-password-12")
        db.session.add(boss)
        db.session.commit()
    admin_client = app.test_client()
    admin_client.post("/login", data={"username": "boss", "password": "boss-long-password-12"})

    admin_client.post(f"/admin/users/{erin}/edit", data={"is_active": "on", "password": "reset-by-admin-long-1"})

    assert _replay(app, cookie) == 302


def test_cookie_is_dead_after_revoking_the_users_tokens(app, erin):
    _, cookie = _login(app)

    with app.app_context():
        accounts.revoke_tokens(db.session.get(User, erin))
        db.session.commit()

    assert _replay(app, cookie) == 302


def test_cookie_is_dead_after_an_email_reset(app, erin):
    from mcprack import auth

    _, cookie = _login(app)
    with app.app_context():
        token = auth._generate_reset_token(db.session.get(User, erin))

    app.test_client().post(
        f"/reset-password/{token}",
        data={"new_password": "emailed-reset-long-1", "confirm_password": "emailed-reset-long-1"},
    )

    assert _replay(app, cookie) == 302


def test_sessions_from_before_the_column_existed_keep_working_for_existing_accounts(app, erin):
    """Upgrade safety: an account that predates the feature is at version 0
    and its cookies carry no version - nobody is logged out by the upgrade."""
    with app.app_context():
        db.session.get(User, erin).session_version = 0
        db.session.commit()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(erin)
        sess["_fresh"] = True  # a cookie as the previous release wrote it: no "sv"

    assert client.get("/").status_code == 200


def test_new_accounts_start_at_a_random_non_zero_version(app, erin):
    with app.app_context():
        assert db.session.get(User, erin).session_version not in (0, None)


def test_login_starts_from_a_clean_session(app, erin):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["planted"] = "attacker-chosen"

    client.post("/login", data={"username": "erin", "password": PW})

    with client.session_transaction() as sess:
        assert "planted" not in sess


def test_a_plain_get_logout_only_ends_this_browsers_session(app, erin):
    """A link on a third-party page must not be able to log a user out of all
    their devices: only the CSRF-protected POST does that."""
    first, _ = _login(app)
    _, other_cookie = _login(app)

    first.get("/logout")

    assert first.get("/").status_code == 302
    assert _replay(app, other_cookie) == 200


def test_post_logout_is_csrf_protected(app, erin):
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(erin)
        sess["_fresh"] = True
        sess["sv"] = 0
    with app.app_context():
        db.session.get(User, erin).session_version = 0
        db.session.commit()

    resp = client.post("/logout")  # no token

    assert resp.status_code == 400


def test_demo_mode_logout_does_not_log_other_visitors_out(app, erin):
    """The demo login is shared: a POST /logout must only end this browser's
    session, not everybody's."""
    app.config["DEMO_MODE"] = True
    first, _ = _login(app)
    _, other_cookie = _login(app)

    first.post("/logout")

    assert _replay(app, other_cookie) == 200
