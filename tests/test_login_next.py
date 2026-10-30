"""Login must honor Flask-Login's ?next= so OAuth authorize can resume."""

from mcprack.extensions import db
from mcprack.models import User


def _make_user(username="alice", password="secret"):
    user = User(username=username, auth_type="local", is_admin=False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def test_login_redirects_to_safe_next(app, client):
    with app.app_context():
        _make_user()

    next_path = "/oauth/authorize?response_type=code&client_id=abc&state=xyz"
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "secret", "next": next_path},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    assert resp.headers["Location"].endswith(next_path) or next_path in resp.headers["Location"]


def test_login_rejects_open_redirect(app, client):
    with app.app_context():
        _make_user()

    resp = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "secret",
            "next": "https://evil.example/phish",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    assert "evil.example" not in resp.headers["Location"]
    assert resp.headers["Location"].endswith("/") or "/login" not in resp.headers["Location"]


def test_login_rejects_protocol_relative_next(app, client):
    with app.app_context():
        _make_user()

    resp = client.post(
        "/login",
        data={"username": "alice", "password": "secret", "next": "//evil.example/x"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    assert "evil.example" not in resp.headers["Location"]


def test_login_form_preserves_next_query(client):
    resp = client.get("/login?next=%2Foauth%2Fauthorize%3Fclient_id%3Dx")
    assert resp.status_code == 200
    assert b'name="next"' in resp.data
    assert b"/oauth/authorize" in resp.data
