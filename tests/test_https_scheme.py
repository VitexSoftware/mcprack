"""Proxy URL scheme/host honour X-Forwarded-* when ProxyFix is applied."""

import json

from werkzeug.middleware.proxy_fix import ProxyFix

from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection


def _seed_user_with_stdio_server(username="testuser"):
    user = User(username=username, auth_type="local")
    user.set_password("pw")
    db.session.add(user)
    db.session.flush()

    server = McpServer(
        name="testserver",
        label="Test Server",
        transport="stdio",
        command="echo test",
        enabled=True,
    )
    db.session.add(server)
    db.session.flush()

    db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
    db.session.commit()
    return user


def _download_proxy_url(client, headers=None):
    client.post("/login", data={"username": "testuser", "password": "pw"})
    resp = client.get("/download/copilot", headers=headers or {})
    assert resp.status_code == 200
    data = json.loads(resp.data)
    return data["servers"]["testserver"]["url"]


def test_copilot_proxy_url_stays_http_without_forwarded_proto(app, client):
    with app.app_context():
        _seed_user_with_stdio_server()

    url = _download_proxy_url(client)
    assert url.startswith("http://")


def test_copilot_proxy_url_uses_https_with_proxy_fix(app, client):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    with app.app_context():
        _seed_user_with_stdio_server()

    url = _download_proxy_url(
        client,
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "mcprack-dev.spojenet.cz",
        },
    )
    assert url.startswith("https://")
    assert "mcprack-dev.spojenet.cz" in url
