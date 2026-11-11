"""C-04 / C-05 (docs/AUDIT-2026-11.md): caching of per-user answers, a
client-supplied X-Forwarded-Prefix, and the permissions of a downloaded config."""

import os
import stat
from urllib.parse import urlsplit

import pytest

from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection
from mcprack.urls import sanitize_script_name, trust_one_proxy_hop


def _login(app, client):
    with app.app_context():
        user = User(username="dora", auth_type="local")
        user.set_password("dora-long-password-1")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "dora", "password": "dora-long-password-1"})


@pytest.mark.parametrize("path", ["/", "/login", "/api/v1/me", "/api/v1/servers", "/view/claude", "/download/claude"])
def test_per_user_responses_are_not_cacheable(app, client, path):
    _login(app, client)

    response = client.get(path)

    assert response.headers.get("Cache-Control") == "no-store", (path, response.status_code)


def test_static_assets_stay_cacheable(app, client):
    response = client.get("/static/style.css")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") != "no-store"


def _seen_script_name(prefix):
    seen = {}

    def inner(environ, start_response):
        seen["script_name"] = environ.get("SCRIPT_NAME")
        return []

    sanitize_script_name(inner)({"SCRIPT_NAME": prefix}, None)
    return seen["script_name"]


@pytest.mark.parametrize("prefix", ["", "/mcprack", "/tools/mcprack", "/a-b_c.d~e"])
def test_a_plain_path_prefix_is_kept(prefix):
    assert _seen_script_name(prefix) == prefix


@pytest.mark.parametrize(
    "prefix",
    ["//evil.example", "/../x", "/a/../b", "/..", "javascript:alert(1)", "/a b", "/a\\b", "/a\nb", "/a?x=1", "/a#f", "mcprack", "///", "/a//b"],
)
def test_anything_that_is_not_a_plain_path_is_dropped(prefix):
    assert _seen_script_name(prefix) == ""


def test_config_download_is_created_private(app, tmp_path):
    with app.app_context():
        user = User(username="erin", auth_type="local")
        user.set_password("erin-long-password-1")
        server = McpServer(name="svc", label="S", transport="http", url="http://127.0.0.1:9/mcp", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
    target = tmp_path / "out.json"
    old_umask = os.umask(0o022)
    try:
        result = app.test_cli_runner().invoke(args=["user", "config", "download", "erin", "claude", "--out", str(target)])
    finally:
        os.umask(old_umask)

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_a_pre_existing_world_readable_file_is_tightened(app, tmp_path):
    with app.app_context():
        user = User(username="erin", auth_type="local")
        user.set_password("erin-long-password-1")
        server = McpServer(name="svc", label="S", transport="http", url="http://127.0.0.1:9/mcp", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
    target = tmp_path / "out.json"
    target.write_text("old")
    target.chmod(0o644)

    result = app.test_cli_runner().invoke(args=["user", "config", "download", "erin", "claude", "--out", str(target)])

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert "mcpServers" in target.read_text()


# --- the order of the middleware matters: exercised through the real stack ----------------------


@pytest.mark.parametrize("prefix", ["//evil.example", "/../x", "javascript:alert(1)", "/a\\b", "///"])
def test_a_hostile_forwarded_prefix_never_reaches_a_redirect(app, prefix):
    """A request to a protected page redirects to the login page through
    url_for(), which prepends SCRIPT_NAME. Whatever the client sent in
    X-Forwarded-Prefix, the Location must stay on this host."""
    trust_one_proxy_hop(app)

    response = app.test_client().get("/", headers={"X-Forwarded-Prefix": prefix})

    assert response.status_code in (301, 302, 303, 307)
    target = urlsplit(response.headers["Location"])
    assert target.scheme == "" and target.netloc == "", response.headers["Location"]  # stays on this host
    assert target.path == "/login"
    assert "evil" not in response.headers["Location"] and "javascript" not in response.headers["Location"]


def test_a_legitimate_forwarded_prefix_still_mounts_the_app(app):
    trust_one_proxy_hop(app)

    response = app.test_client().get("/", headers={"X-Forwarded-Prefix": "/mcprack"})

    assert urlsplit(response.headers["Location"]).path == "/mcprack/login"


def test_the_sanitizer_must_sit_inside_proxyfix(app):
    """Guards the ordering itself: composed the other way round the sanitizer
    runs before ProxyFix has set SCRIPT_NAME and the hostile prefix gets
    through. This is the bug the first version of this fix had."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    wrong = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    wrong = sanitize_script_name(wrong)
    app.wsgi_app = wrong

    response = app.test_client().get("/", headers={"X-Forwarded-Prefix": "//evil.example"})

    assert "evil.example" in response.headers["Location"]  # documents why the order is what it is
