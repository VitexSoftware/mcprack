import pytest
from flask import session
from extensions import db
from models import User

def test_set_locale_route(client):
    # Set locale via route
    resp = client.get("/set-locale/cs", follow_redirects=True)
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("locale") == "cs"

    resp = client.get("/set-locale/sk", follow_redirects=True)
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("locale") == "sk"

    resp = client.get("/set-locale/en", follow_redirects=True)
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("locale") == "en"

def test_browser_autodetect_language(client):
    # Verify Czech string on login page
    resp_cs = client.get("/login", headers={"Accept-Language": "cs"})
    assert resp_cs.status_code == 200
    assert b"V\xc3\xadtejte v mcprack" in resp_cs.data or b"Heslo" in resp_cs.data

    # Verify Slovak string on login page
    resp_sk = client.get("/login", headers={"Accept-Language": "sk"})
    assert resp_sk.status_code == 200
    assert b"Vitajte v mcprack" in resp_sk.data or b"Heslo" in resp_sk.data

def test_session_locale_precedence(app, client):
    # Set locale to 'cs' in session
    with client.session_transaction() as sess:
        sess["locale"] = "cs"

    # Even with Accept-Language: en, session-based locale 'cs' should take precedence
    resp = client.get("/login", headers={"Accept-Language": "en"})
    assert b"V\xc3\xadtejte v mcprack" in resp.data or b"Heslo" in resp.data
