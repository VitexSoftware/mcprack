from mcprack.catalog import _allowed_enabled_server_ids
from mcprack.extensions import db
from mcprack.models import McpServer, User


def _make_user_and_server(app):
    with app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("pw")
        server = McpServer(
            name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True
        )
        db.session.add_all([user, server])
        db.session.commit()
        return user.id, server.id


def test_default_fail_open_returns_all_enabled_servers_with_no_permission_rows(app):
    user_id, server_id = _make_user_and_server(app)
    with app.app_context():
        app.config["STRICT_SERVER_PERMISSIONS"] = False
        assert _allowed_enabled_server_ids(user_id) == {server_id}


def test_strict_mode_returns_nothing_with_no_permission_rows(app):
    user_id, _server_id = _make_user_and_server(app)
    with app.app_context():
        app.config["STRICT_SERVER_PERMISSIONS"] = True
        assert _allowed_enabled_server_ids(user_id) == set()


# --- A-06: fail-closed is the default; upgrade keeps existing access --------


def test_production_default_is_strict():
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-I", "-c", "from mcprack.config import Config; print(Config.STRICT_SERVER_PERMISSIONS)"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert out.stdout.strip() == "True", out.stderr


def test_strict_user_with_a_grant_sees_only_the_granted_server(app):
    from mcprack.models import UserServerPermission

    user_id, server_id = _make_user_and_server(app)
    with app.app_context():
        other = McpServer(name="other", label="Other", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(other)
        db.session.commit()
        db.session.add(UserServerPermission(user_id=user_id, server_id=server_id, is_allowed=True))
        db.session.commit()
        app.config["STRICT_SERVER_PERMISSIONS"] = True

        assert _allowed_enabled_server_ids(user_id) == {server_id}


def test_ldap_provisioned_account_sees_nothing_in_strict_mode(app, client):
    from unittest.mock import MagicMock, patch

    app.config["LDAP_ENABLED"] = True
    app.config["STRICT_SERVER_PERMISSIONS"] = True
    with app.app_context():
        db.session.add(McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True))
        db.session.commit()

    class Entry:
        entry_dn = "CN=Carol,OU=Users,DC=x"

        def __contains__(self, name):
            return name in ("givenName", "sn", "mail")

        def __getitem__(self, name):
            return MagicMock(values=["x"])

    search = MagicMock()
    search.__enter__.return_value = search
    search.__exit__.return_value = False
    search.entries = [Entry()]
    bind = MagicMock()
    bind.__enter__.return_value = bind
    bind.__exit__.return_value = False

    def connection(server, user=None, password=None, auto_bind=None):
        return bind if user == Entry.entry_dn else search

    with patch("mcprack.auth.ldap3.Connection", side_effect=connection):
        client.post("/login", data={"username": "carol", "password": "directory-password"})

    with app.app_context():
        carol = User.query.filter_by(username="carol").first()
        assert carol is not None
        assert _allowed_enabled_server_ids(carol.id) == set()
