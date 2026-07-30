from catalog import _allowed_enabled_server_ids
from extensions import db
from models import McpServer, User


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
