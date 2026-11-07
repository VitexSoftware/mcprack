def test_security_headers_present_on_login_page(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "same-origin"
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "Content-Security-Policy" in resp.headers
    assert "fonts.googleapis.com" in csp
    assert "fonts.gstatic.com" in csp


def test_csp_has_no_unsafe_inline(client):
    """The CSP must not allow inline styles or scripts: templates and JS set
    classes only (see the utility/component classes in style.css), so an
    injected style="..." attribute or <style> block would be dead weight —
    and, more importantly, an XSS payload would not be able to use them."""
    resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "unsafe-inline" not in csp
    assert "style-src 'self'" in csp
    assert "script-src 'self'" in csp


def test_rendered_pages_have_no_inline_style_attributes(client, app):
    """Every rendered page must be free of style="..." attributes — that is
    what keeps style-src without 'unsafe-inline' working."""
    from mcprack.extensions import db
    from mcprack.models import McpServer, User

    with app.app_context():
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("adminpass")
        db.session.add(admin)
        db.session.add(
            McpServer(name="demo", label="Demo", transport="stdio", command="/bin/true")
        )
        db.session.commit()
    for page in ["/login", "/forgot-password"]:
        resp = client.get(page)
        assert resp.status_code == 200, f"{page}: {resp.status_code}"
        assert 'style="' not in resp.get_data(as_text=True), (
            f"{page} still renders an inline style attribute"
        )

    client.post("/login", data={"username": "admin", "password": "adminpass"})

    authed_pages = [
        "/",
        "/admin/servers",
        "/admin/servers/1/edit",
        "/admin/servers/new",
        "/admin/users",
        "/admin/audit-log",
        "/admin/proxy-instances",
        "/account/password",
    ]
    for page in authed_pages:
        resp = client.get(page)
        assert resp.status_code == 200, f"{page}: {resp.status_code}"
        body = resp.get_data(as_text=True)
        assert 'style="' not in body, f"{page} still renders an inline style attribute"


def test_hsts_absent_on_plain_http_test_request(client):
    resp = client.get("/login")
    # The Werkzeug test client's default requests are not HTTPS, so the
    # conditional (request.is_secure) HSTS header must not appear - setting
    # it unconditionally would be wrong for a plain-HTTP intranet install.
    assert "Strict-Transport-Security" not in resp.headers


def test_permissions_policy_and_coop_on_html_pages(client):
    resp = client.get("/login")
    permissions = resp.headers.get("Permissions-Policy", "")
    for feature in ("camera=()", "geolocation=()", "microphone=()", "usb=()"):
        assert feature in permissions
    assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"


def test_coop_omitted_where_cross_origin_mcp_clients_need_access(client):
    """A browser-based MCP client (Claude Desktop, claude.ai) calls the proxy
    and OAuth endpoints cross-origin; those are bearer-authenticated, not
    cookie-authenticated, and must not be isolated."""
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.headers.get("Cross-Origin-Opener-Policy") is None


def test_override_pages_have_no_inline_style_attributes(app, client):
    """The row editors were the one place inline styles crept back in: the
    .env import control was hidden with style="display:none", which this
    app's own CSP blocks, leaving a stray file input on the page."""
    from mcprack.extensions import db
    from mcprack.models import McpServer, User, UserServerSelection

    with app.app_context():
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("adminpass")
        db.session.add(admin)
        server = McpServer(
            name="demo", label="Demo", transport="stdio", command="/bin/true",
            enabled=True, allow_user_override=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=admin.id, server_id=server.id))
        db.session.commit()
        admin_id, server_id = admin.id, server.id

    client.post("/login", data={"username": "admin", "password": "adminpass"})

    for page in [f"/override/{server_id}", f"/admin/users/{admin_id}/override/{server_id}"]:
        resp = client.get(page)
        assert resp.status_code == 200, f"{page}: {resp.status_code}"
        assert 'style="' not in resp.get_data(as_text=True), (
            f"{page} still renders an inline style attribute"
        )


def test_error_page_has_no_inline_style_attributes(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    assert 'style="' not in resp.get_data(as_text=True)


def test_html_request_gets_the_rendered_error_page(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    body = resp.get_data(as_text=True)
    assert "404" in body
    assert "Back to Catalog" in body
    # no stack trace or filesystem path leaks out
    assert "Traceback" not in body and "/home/" not in body


def test_api_request_gets_a_json_error(client):
    resp = client.get("/api/v1/no-such-endpoint")
    assert resp.status_code == 404
    assert resp.is_json
    assert resp.get_json()["error"] == "not_found"


def test_oversized_body_renders_the_error_page_too(client):
    """413 is reachable through MAX_CONTENT_LENGTH, so it needs a handler of
    its own or Werkzeug's default page shows instead."""
    limit = client.application.config["MAX_CONTENT_LENGTH"]
    resp = client.post("/login", data={"username": "x", "password": "y" * (limit + 1024)})
    assert resp.status_code == 413
    assert "Back to Catalog" in resp.get_data(as_text=True)
