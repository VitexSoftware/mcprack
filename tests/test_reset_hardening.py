"""A-05 (docs/AUDIT-2026-11.md): password-reset links and Host handling.

The reset link was built from the request's Host header (ignoring
PUBLIC_BASE_URL), so a forged Host put an attacker's domain into the e-mail
sent to the victim; and the signed token carried the user's password hash in
the clear. Now the link comes from PUBLIC_BASE_URL, the token holds only a
keyed fingerprint, and a configured public host makes Flask refuse any other
Host.
"""

import re
from unittest.mock import patch

import pytest
from itsdangerous import URLSafeTimedSerializer

from mcprack import auth
from mcprack.app import create_app
from mcprack.extensions import db
from mcprack.models import User

from conftest import TestConfig


def _user(app, name="victim", email="victim@example.com", password="old-password-1"):
    with app.app_context():
        user = User(username=name, email=email, auth_type="local")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user.id


def _emailed_link(app, client, host=None):
    app.config["SMTP_HOST"] = "smtp.example.test"
    kwargs = {"base_url": f"http://{host}"} if host else {}
    with patch("mcprack.auth.mailer.send_email", return_value=True) as sent:
        client.post("/forgot-password", data={"identifier": "victim"}, **kwargs)
    _, _, body = sent.call_args[0]
    return re.search(r"https?://\S+/reset-password/\S+", body).group(0)


def test_reset_link_uses_public_base_url_not_the_host_header(app, client):
    app.config["PUBLIC_BASE_URL"] = "https://mcprack.example.com"
    _user(app)

    link = _emailed_link(app, client, host="evil.invalid")

    assert link.startswith("https://mcprack.example.com/reset-password/")
    assert "evil.invalid" not in link


def test_reset_link_falls_back_to_the_request_host_without_public_base_url(app, client):
    app.config["PUBLIC_BASE_URL"] = ""
    _user(app)

    link = _emailed_link(app, client, host="localhost")

    assert link.startswith("http://localhost/reset-password/")


def test_token_does_not_contain_the_password_hash(app):
    user_id = _user(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        token = auth._generate_reset_token(user)
        # readable by anyone, without the signing key
        _, payload = URLSafeTimedSerializer("another-key", salt="password-reset").loads_unsafe(token)

        assert "password_hash" not in payload
        assert user.password_hash not in str(payload)
        assert user.password_hash[:20] not in str(payload)


def test_token_stops_working_after_the_password_changes(app):
    user_id = _user(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        token = auth._generate_reset_token(user)
        assert auth._verify_reset_token(token, 3600).id == user_id

        user.set_password("changed-password-2")
        db.session.commit()

        assert auth._verify_reset_token(token, 3600) is None


def test_tokens_in_the_old_format_are_refused(app):
    """Tokens that carry the raw hash (previous release) are not honoured."""
    user_id = _user(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        legacy = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset").dumps(
            {"user_id": user.id, "password_hash": user.password_hash}
        )

        assert auth._verify_reset_token(legacy, 3600) is None


# --- trusted hosts -----------------------------------------------------------


def _app_with(**config):
    attrs = dict(PUBLIC_BASE_URL="https://mcprack.example.com")
    attrs.update(config)
    return create_app(type("HostConfig", (TestConfig,), attrs))


@pytest.mark.parametrize(
    "host,expected",
    [
        ("mcprack.example.com", 200),
        ("localhost", 200),  # health checks from the reverse proxy host
        ("127.0.0.1:8912", 200),
        ("evil.invalid", 400),
        ("mcprack.example.com.evil.invalid", 400),
    ],
)
def test_public_base_url_restricts_the_accepted_hosts(host, expected):
    app = _app_with()
    resp = app.test_client().get("/health", base_url=f"http://{host}")

    assert resp.status_code == expected


def test_trusted_hosts_can_be_configured_explicitly():
    app = _app_with(TRUSTED_HOSTS=["mcprack.example.org"])

    assert app.test_client().get("/health", base_url="http://mcprack.example.org").status_code == 200
    assert app.test_client().get("/health", base_url="http://mcprack.example.com").status_code == 400


def test_no_public_base_url_means_no_host_restriction():
    app = _app_with(PUBLIC_BASE_URL="")

    assert app.test_client().get("/health", base_url="http://anything.example").status_code == 200
