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
    # the configured bind password is never rendered, only a hint that one exists
    assert b"configured-secret" not in response.data
    assert b"leave empty to use the configured password" in response.data


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

def test_blank_password_field_uses_the_configured_password(app, client):
    app.config["LDAP_ENABLED"] = False
    app.config["LDAP_BIND_PASSWORD"] = "configured-secret"
    _login_admin(client, app)
    seen = {}

    def fake(values):
        seen.update(values)

    with patch("mcprack.admin._run_ldap_diagnostic", side_effect=fake):
        response = client.post("/admin/ldap/diagnostics", data={
            "LDAP_SERVER": "ldaps://directory.example.test:636", "LDAP_BASE_DN": "dc=example,dc=test",
            "LDAP_USER_OU": "ou=People,dc=example,dc=test", "LDAP_USER_FILTER": "(uid=%(user)s)",
            "LDAP_BIND_DN": "cn=reader,dc=example,dc=test", "LDAP_BIND_PASSWORD": "",
        })
    assert response.status_code == 200
    assert seen["LDAP_BIND_PASSWORD"] == "configured-secret"
    # the form field itself never contains a password, even after a POST
    assert b'name="LDAP_BIND_PASSWORD" type="password" class="form-control" value=""' in response.data


def test_typed_password_is_not_echoed_back_on_failure(app, client):
    app.config["LDAP_ENABLED"] = False
    _login_admin(client, app)
    with patch("mcprack.admin._run_ldap_diagnostic", side_effect=ValueError("bind failed")):
        response = client.post("/admin/ldap/diagnostics", data={
            "LDAP_SERVER": "ldaps://directory.example.test:636", "LDAP_BASE_DN": "dc=example,dc=test",
            "LDAP_USER_OU": "ou=People,dc=example,dc=test", "LDAP_USER_FILTER": "(uid=%(user)s)",
            "LDAP_BIND_DN": "cn=reader,dc=example,dc=test", "LDAP_BIND_PASSWORD": "typed-secret",
        })
    assert b"bind failed" in response.data and b"typed-secret" not in response.data
