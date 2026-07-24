from unittest.mock import MagicMock, patch

from ldap3.core.exceptions import LDAPBindError

from extensions import db
from models import User


class FakeAttr:
    def __init__(self, value):
        self.values = [value] if value is not None else []


class FakeEntry:
    def __init__(self, entry_dn, attrs):
        self.entry_dn = entry_dn
        self._attrs = attrs

    def __contains__(self, name):
        return name in self._attrs

    def __getitem__(self, name):
        return FakeAttr(self._attrs[name])


def _make_search_connection(entries):
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    conn.entries = entries

    def _search(**kwargs):
        return True

    conn.search.side_effect = _search
    return conn


def test_local_login_never_calls_ldap(app, client):
    with app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("correct horse")
        db.session.add(user)
        db.session.commit()

    with patch("auth.ldap3.Connection") as mock_connection:
        resp = client.post(
            "/login",
            data={"username": "alice", "password": "correct horse"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        mock_connection.assert_not_called()


def test_local_login_wrong_password_rejected(app, client):
    with app.app_context():
        user = User(username="bob", auth_type="local")
        user.set_password("right-password")
        db.session.add(user)
        db.session.commit()

    with patch("auth.ldap3.Connection") as mock_connection:
        resp = client.post(
            "/login",
            data={"username": "bob", "password": "wrong-password"},
            follow_redirects=True,
        )
        assert b"Invalid username or password" in resp.data
        mock_connection.assert_not_called()


def test_ldap_login_search_then_bind_provisions_user(app, client):
    entry = FakeEntry(
        "CN=Carol,OU=Users,DC=spojent,DC=cz",
        {"givenName": "Carol", "sn": "Danvers", "mail": "carol@spojent.cz"},
    )
    search_conn = _make_search_connection([entry])
    bind_conn = MagicMock()
    bind_conn.__enter__.return_value = bind_conn
    bind_conn.__exit__.return_value = False

    calls = []

    def connection_side_effect(server, user=None, password=None, auto_bind=None):
        calls.append({"user": user, "password": password})
        if user == entry.entry_dn:
            if password != "correct-ad-password":
                raise LDAPBindError("invalid credentials")
            return bind_conn
        return search_conn

    with patch("auth.ldap3.Connection", side_effect=connection_side_effect):
        resp = client.post(
            "/login",
            data={"username": "carol", "password": "correct-ad-password"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    # search-then-bind: first call resolves the DN, second call verifies the password
    assert len(calls) == 2
    assert calls[1]["user"] == entry.entry_dn

    with app.app_context():
        user = User.query.filter_by(username="carol").first()
        assert user is not None
        assert user.auth_type == "ldap"
        assert user.password_hash is None
        assert user.first_name == "Carol"
        assert user.last_name == "Danvers"
        assert user.email == "carol@spojent.cz"


def test_ldap_login_wrong_password_rejected(app, client):
    entry = FakeEntry("CN=Dave,OU=Users,DC=spojent,DC=cz", {})
    search_conn = _make_search_connection([entry])

    def connection_side_effect(server, user=None, password=None, auto_bind=None):
        if user == entry.entry_dn:
            raise LDAPBindError("invalid credentials")
        return search_conn

    with patch("auth.ldap3.Connection", side_effect=connection_side_effect):
        resp = client.post(
            "/login",
            data={"username": "dave", "password": "wrong"},
            follow_redirects=True,
        )
        assert b"Invalid username or password" in resp.data

    with app.app_context():
        assert User.query.filter_by(username="dave").first() is None
