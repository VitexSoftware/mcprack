def test_security_headers_present_on_login_page(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "same-origin"
    assert "Content-Security-Policy" in resp.headers


def test_hsts_absent_on_plain_http_test_request(client):
    resp = client.get("/login")
    # The Werkzeug test client's default requests are not HTTPS, so the
    # conditional (request.is_secure) HSTS header must not appear - setting
    # it unconditionally would be wrong for a plain-HTTP intranet install.
    assert "Strict-Transport-Security" not in resp.headers
