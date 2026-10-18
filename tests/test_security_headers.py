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
