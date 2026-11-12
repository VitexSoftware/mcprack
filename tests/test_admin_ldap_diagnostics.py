from unittest.mock import MagicMock, patch

from ldap3.core.exceptions import LDAPBindError

from mcprack.extensions import db
from mcprack.models import User


def _login_admin(client, app):
    with app.app_context():
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("adminpass")
        db.session.add(admin)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_ldap_diagnostics_prefills_configuration_when_ldap_is_disabled(app, client):
    app.config["LDAP_ENABLED"] = False
    app.config["LDAP_BIND_PASSWORD"] = "configured-secret"
    _login_admin(client, app)

    response = client.get("/admin/ldap/diagnostics")

    assert response.status_code == 200
    assert b"ldap://10.11.25.3:389" in response.data
    assert b"dc=spojent,dc=cz" in response.data
    assert b"configured-secret" in response.data


def test_ldap_diagnostics_success_shows_confirmed_fragment_when_disabled(app, client):
    app.config["LDAP_ENABLED"] = False
    _login_admin(client, app)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.__exit__.return_value = False
    connection.result = {"result": 0}
    connection.entries = [MagicMock()]
    values = {
        "LDAP_SERVER": "ldaps://directory.example.test:636",
        "LDAP_BASE_DN": "dc=example,dc=test",
        "LDAP_USER_OU": "ou=People,dc=example,dc=test",
        "LDAP_USER_FILTER": "(uid=%(user)s)",
        "LDAP_BIND_DN": "cn=reader,dc=example,dc=test",
        "LDAP_BIND_PASSWORD": "reader-secret",
    }

    with patch("mcprack.admin.ldap3.Server"), patch(
        "mcprack.admin.ldap3.Connection", return_value=connection
    ):
        response = client.post("/admin/ldap/diagnostics", data=values)

    assert response.status_code == 200
    assert b"Connection confirmed" in response.data
    assert b"LDAP_ENABLED=true" in response.data
    assert b"LDAP_SERVER=ldaps://directory.example.test:636" in response.data
    assert b"LDAP_BIND_PASSWORD=reader-secret" in response.data
    assert connection.search.call_count == 3


def test_ldap_diagnostics_bind_failure_does_not_show_success_fragment(app, client):
    _login_admin(client, app)
    values = {
        "LDAP_SERVER": "ldap://directory.example.test:389",
        "LDAP_BASE_DN": "dc=example,dc=test",
        "LDAP_USER_OU": "ou=People,dc=example,dc=test",
        "LDAP_USER_FILTER": "(uid=%(user)s)",
        "LDAP_BIND_DN": "cn=reader,dc=example,dc=test",
        "LDAP_BIND_PASSWORD": "reader-secret",
    }

    with patch("mcprack.admin.ldap3.Server"), patch(
        "mcprack.admin.ldap3.Connection", side_effect=LDAPBindError("invalid credentials")
    ):
        response = client.post("/admin/ldap/diagnostics", data=values)

    assert response.status_code == 200
    assert b"invalid credentials" in response.data
    assert b"Connection confirmed" not in response.data


def test_ldap_diagnostics_is_admin_only(client):
    response = client.get("/admin/ldap/diagnostics")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]