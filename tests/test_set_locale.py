"""C-01 (docs/AUDIT-2026-11.md): /set-locale redirected to the Referer when
the request host was a *substring* of it, so a look-alike domain such as
mcprack.example.com.attacker.invalid sent the visitor away."""

import pytest


@pytest.mark.parametrize(
    "referer",
    [
        "https://mcprack.example.com.attacker.invalid/landing",
        "https://attacker.invalid/?mcprack.example.com",
        "https://attacker.invalid/mcprack.example.com",
        "https://user@attacker.invalid/",
        "//attacker.invalid/",
        "javascript:alert(1)",
    ],
)
def test_foreign_referers_never_receive_the_redirect(client, referer):
    resp = client.get("/set-locale/cs", base_url="http://mcprack.example.com", headers={"Referer": referer})

    assert resp.status_code == 302
    assert "attacker" not in resp.headers["Location"]
    assert resp.headers["Location"].startswith("/")


def test_same_site_referer_returns_to_the_page_the_user_came_from(client):
    resp = client.get(
        "/set-locale/cs",
        base_url="http://mcprack.example.com",
        headers={"Referer": "http://mcprack.example.com/override/3?x=1"},
    )

    assert resp.headers["Location"] == "/override/3?x=1"


def test_no_referer_goes_to_the_catalog(client):
    resp = client.get("/set-locale/en")

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


def test_an_unknown_locale_is_ignored(client):
    client.get("/set-locale/xx")

    with client.session_transaction() as sess:
        assert "locale" not in sess
