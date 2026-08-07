from unittest.mock import patch

from mcprack.auth import _generate_reset_token
from mcprack.extensions import db
from mcprack.models import User


def _make_local_user(app, username="alice", password="old-password", email="alice@example.com"):
    with app.app_context():
        user = User(username=username, auth_type="local", email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


def test_change_password_requires_correct_current_password(app, client):
    _make_local_user(app, "alice", "old-password")
    _login(client, "alice", "old-password")

    resp = client.post(
        "/account/password",
        data={
            "current_password": "wrong-password",
            "new_password": "new-password-123",
            "confirm_password": "new-password-123",
        },
        follow_redirects=True,
    )
    assert b"Current password is incorrect" in resp.data

    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        assert user.check_password("old-password")


def test_change_password_rejects_mismatched_confirmation(app, client):
    _make_local_user(app, "alice", "old-password")
    _login(client, "alice", "old-password")

    resp = client.post(
        "/account/password",
        data={
            "current_password": "old-password",
            "new_password": "new-password-123",
            "confirm_password": "something-else",
        },
        follow_redirects=True,
    )
    assert b"don&#39;t match" in resp.data or b"don't match" in resp.data


def test_change_password_succeeds(app, client):
    _make_local_user(app, "alice", "old-password")
    _login(client, "alice", "old-password")

    resp = client.post(
        "/account/password",
        data={
            "current_password": "old-password",
            "new_password": "new-password-123",
            "confirm_password": "new-password-123",
        },
        follow_redirects=True,
    )
    assert b"Password changed" in resp.data

    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        assert user.check_password("new-password-123")
        assert not user.check_password("old-password")


def test_change_password_blocked_for_ldap_user(app, client):
    with app.app_context():
        user = User(username="dave", auth_type="ldap", email="dave@example.com")
        db.session.add(user)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["_user_id"] = "1"
        sess["_fresh"] = True

    resp = client.get("/account/password", follow_redirects=True)
    assert b"managed externally" in resp.data


def test_forgot_password_shows_explanation_when_smtp_not_configured(app, client):
    assert app.config["SMTP_HOST"] == ""
    resp = client.get("/forgot-password")
    assert b"isn&#39;t configured" in resp.data or b"isn't configured" in resp.data


def test_forgot_password_sends_email_and_reset_link_works(app, client):
    user_id = _make_local_user(app, "alice", "old-password", "alice@example.com")
    app.config["SMTP_HOST"] = "smtp.example.test"

    with patch("mcprack.auth.mailer.send_email", return_value=True) as mock_send:
        resp = client.post(
            "/forgot-password", data={"identifier": "alice"}, follow_redirects=True
        )
        assert b"reset link has been sent" in resp.data
        mock_send.assert_called_once()
        _, _, body = mock_send.call_args[0]

    # Pull the reset URL's token out of the emailed body.
    import re

    match = re.search(r"/reset-password/([\w.\-]+)", body)
    assert match, body
    token = match.group(1)

    reset_resp = client.post(
        f"/reset-password/{token}",
        data={"new_password": "brand-new-pw", "confirm_password": "brand-new-pw"},
        follow_redirects=True,
    )
    assert b"Password reset" in reset_resp.data

    with app.app_context():
        user = db.session.get(User, user_id)
        assert user.check_password("brand-new-pw")

    # The token embeds the old password hash, so it can't be replayed.
    replay_resp = client.post(
        f"/reset-password/{token}",
        data={"new_password": "yet-another-pw", "confirm_password": "yet-another-pw"},
        follow_redirects=True,
    )
    assert b"invalid or has expired" in replay_resp.data


def test_forgot_password_does_not_reveal_unknown_account(app, client):
    app.config["SMTP_HOST"] = "smtp.example.test"

    with patch("mcprack.auth.mailer.send_email", return_value=True) as mock_send:
        resp = client.post(
            "/forgot-password", data={"identifier": "nobody"}, follow_redirects=True
        )
        assert b"reset link has been sent" in resp.data
        mock_send.assert_not_called()


def test_reset_password_rejects_invalid_token(app, client):
    resp = client.get("/reset-password/not-a-real-token", follow_redirects=True)
    assert b"invalid or has expired" in resp.data


def test_reset_password_rejects_expired_token(app, client):
    with app.app_context():
        user = User(username="erin", auth_type="local", email="erin@example.com")
        user.set_password("old-password")
        db.session.add(user)
        db.session.commit()
        token = _generate_reset_token(user)

    app.config["PASSWORD_RESET_MAX_AGE"] = -1
    resp = client.get(f"/reset-password/{token}", follow_redirects=True)
    assert b"invalid or has expired" in resp.data
