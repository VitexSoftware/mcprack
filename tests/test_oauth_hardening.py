"""A-07 / B-15 (docs/AUDIT-2026-11.md): the optional OAuth authorization server.

* Dynamic client registration is open by design (MCP clients have no prior
  relationship), but it accepted ANY redirect URI and the consent page never
  showed it - so a registered "Claude" pointing at an attacker's host, plus a
  link, was consent phishing. Redirect URIs now follow a policy, the consent
  page shows where the code goes, and registrations are capped and pruned.
* Refresh tokens died with the 1-hour access token (is_expired() looks at the
  access lifetime), although 30 days were configured.
* Tokens sat in the database in clear text (API tokens are hashed).
* Registration, consent and token issue were not audited."""

import hashlib
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from mcprack.extensions import db
from mcprack.models import (
    OAUTH_MCP_SCOPE,
    AuditLogEntry,
    OAuthClient,
    OAuthToken,
    User,
)

from test_oauth_proxy import OAuthConfig, _login, _make_server, _make_user, _pkce_pair

CALLBACK = "https://app.client.test/cb"


class HardenedConfig(OAuthConfig):
    OAUTH_ALLOWED_REDIRECT_HOSTS = "claude.ai,claude.com,*.client.test"


@pytest.fixture
def oauth_client(oauth_app):
    return oauth_app.test_client()


@pytest.fixture
def oauth_app(tmp_path, monkeypatch):
    from mcprack import installer, user_proxy
    from mcprack.app import create_app

    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")
    monkeypatch.setattr(installer, "STATE_DIR", tmp_path / "installs")
    application = create_app(HardenedConfig)
    application.config["BITWARDENCLI_APPDATA_DIR"] = str(tmp_path / "bw")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _register(client, uris, name="Test MCP Client"):
    return client.post(
        "/oauth/register",
        json={
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": OAUTH_MCP_SCOPE,
        },
    )


# --- redirect URI policy ---------------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "http://localhost:51234/callback",
        "http://127.0.0.1:8080/cb",
        "http://[::1]:9000/cb",
        "https://claude.ai/api/mcp/auth_callback",
        "https://app.client.test/cb",
    ],
)
def test_acceptable_redirect_uris(oauth_client, uri):
    assert _register(oauth_client, [uri]).status_code in (200, 201)


@pytest.mark.parametrize(
    "uri",
    [
        "https://attacker.invalid/cb",
        "http://attacker.invalid/cb",
        "http://claude.ai/cb",  # not https
        "https://claude.ai.attacker.invalid/cb",
        "https://attacker.invalid/claude.ai",
        "https://claude.ai@attacker.invalid/cb",
        "https://user:pw@claude.ai/cb",
        "javascript:alert(1)",
        "data:text/html,x",
        "myapp://callback",
        "https://claude.ai/cb#frag",
        "http://localhost.attacker.invalid/cb",
        "http://127.0.0.1.attacker.invalid/cb",
    ],
)
def test_other_redirect_uris_are_refused(oauth_client, uri):
    resp = _register(oauth_client, [uri])

    assert resp.status_code == 400
    # some shapes are caught by authlib's own metadata validation first
    assert resp.get_json()["error"] in ("invalid_redirect_uri", "invalid_client_metadata")


def test_one_bad_uri_in_the_list_refuses_the_registration(oauth_client):
    assert _register(oauth_client, ["http://localhost:1/cb", "https://attacker.invalid/cb"]).status_code == 400


def test_custom_schemes_can_be_allowed_by_prefix(oauth_app, oauth_client):
    oauth_app.config["OAUTH_ALLOWED_REDIRECT_PREFIXES"] = "myapp://callback"

    assert _register(oauth_client, ["myapp://callback/x"]).status_code in (200, 201)
    assert _register(oauth_client, ["myapp://evil"]).status_code == 400


def test_too_many_redirect_uris_are_refused(oauth_client):
    assert _register(oauth_client, [f"http://localhost:{i}/cb" for i in range(1, 12)]).status_code == 400


# --- registration cap and pruning --------------------------------------------------


def test_the_number_of_registered_clients_is_capped(oauth_app, oauth_client):
    oauth_app.config["OAUTH_MAX_CLIENTS"] = 2
    for i in range(2):
        assert _register(oauth_client, [f"http://localhost:{i + 1}/cb"]).status_code in (200, 201)

    assert _register(oauth_client, ["http://localhost:99/cb"]).status_code == 503


def test_stale_unused_clients_are_pruned_to_make_room(oauth_app, oauth_client):
    oauth_app.config["OAUTH_MAX_CLIENTS"] = 1
    oauth_app.config["OAUTH_CLIENT_TTL_DAYS"] = 7
    stale = _register(oauth_client, ["http://localhost:1/cb"]).get_json()["client_id"]
    OAuthClient.query.filter_by(client_id=stale).update({"client_id_issued_at": int(time.time()) - 30 * 86400})
    db.session.commit()

    assert _register(oauth_client, ["http://localhost:2/cb"]).status_code in (200, 201)
    assert OAuthClient.query.filter_by(client_id=stale).count() == 0


def test_clients_with_tokens_are_never_pruned(oauth_app, oauth_client):
    oauth_app.config["OAUTH_MAX_CLIENTS"] = 1
    oauth_app.config["OAUTH_CLIENT_TTL_DAYS"] = 7
    old = _register(oauth_client, ["http://localhost:1/cb"]).get_json()["client_id"]
    OAuthClient.query.filter_by(client_id=old).update({"client_id_issued_at": int(time.time()) - 30 * 86400})
    db.session.add(OAuthToken(client_id=old, token_type="Bearer", access_token="a", scope="mcp",
                              issued_at=int(time.time()), expires_in=3600))
    db.session.commit()

    assert _register(oauth_client, ["http://localhost:2/cb"]).status_code == 503
    assert OAuthClient.query.filter_by(client_id=old).count() == 1


# --- consent page ---------------------------------------------------------------------


def _authorize_query(client_id, redirect, challenge):
    return {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
        "scope": OAUTH_MCP_SCOPE, "state": "xyz", "code_challenge": challenge, "code_challenge_method": "S256",
    }


def test_consent_page_shows_where_the_code_will_be_sent(oauth_app, oauth_client):
    _make_user()
    client_id = _register(oauth_client, [CALLBACK], name="Claude").get_json()["client_id"]
    _login(oauth_client)

    page = oauth_client.get("/oauth/authorize", query_string=_authorize_query(client_id, CALLBACK, _pkce_pair()[1]))

    html = page.get_data(as_text=True)
    assert page.status_code == 200
    assert CALLBACK in html
    assert "app.client.test" in html


def test_consent_page_warns_about_a_loopback_redirect(oauth_app, oauth_client):
    _make_user()
    callback = "http://localhost:51234/callback"
    client_id = _register(oauth_client, [callback], name="Claude").get_json()["client_id"]
    _login(oauth_client)

    html = oauth_client.get(
        "/oauth/authorize", query_string=_authorize_query(client_id, callback, _pkce_pair()[1])
    ).get_data(as_text=True)

    assert callback in html
    assert "this computer" in html.lower()


# --- tokens: storage, refresh, revocation ------------------------------------------------


def _obtain_tokens(oauth_app, oauth_client):
    _make_user()
    client_id = _register(oauth_client, [CALLBACK]).get_json()["client_id"]
    verifier, challenge = _pkce_pair()
    _login(oauth_client)
    query = _authorize_query(client_id, CALLBACK, challenge)
    consent = oauth_client.post("/oauth/authorize", query_string=query, data={"confirm": "yes"})
    code = parse_qs(urlparse(consent.headers["Location"]).query)["code"][0]
    resp = oauth_client.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK,
              "client_id": client_id, "code_verifier": verifier},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return client_id, resp.get_json()


def test_tokens_are_stored_hashed(oauth_app, oauth_client):
    _, tokens = _obtain_tokens(oauth_app, oauth_client)

    row = OAuthToken.query.one()
    assert row.access_token == hashlib.sha256(tokens["access_token"].encode()).hexdigest()
    assert row.refresh_token == hashlib.sha256(tokens["refresh_token"].encode()).hexdigest()
    assert tokens["access_token"] not in (row.access_token, row.refresh_token)


def test_a_hashed_access_token_authenticates_and_a_made_up_one_does_not(oauth_app, oauth_client):
    from mcprack import oauth

    _, tokens = _obtain_tokens(oauth_app, oauth_client)

    assert oauth.resolve_oauth_bearer_user(tokens["access_token"]).username == "alice"
    assert oauth.resolve_oauth_bearer_user(hashlib.sha256(tokens["access_token"].encode()).hexdigest()) is None
    assert oauth.resolve_oauth_bearer_user("nonsense") is None


def test_tokens_stored_in_clear_text_by_the_previous_release_still_work(oauth_app, oauth_client):
    from mcprack import oauth

    user = _make_user()
    db.session.add(OAuthToken(user_id=user.id, client_id="c", token_type="Bearer", access_token="legacy-plain-token",
                              scope="mcp", issued_at=int(time.time()), expires_in=3600))
    db.session.commit()

    assert oauth.resolve_oauth_bearer_user("legacy-plain-token").username == "alice"


def _refresh(oauth_client, client_id, refresh_token):
    return oauth_client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
    )


def test_a_refresh_token_outlives_the_access_token(oauth_app, oauth_client):
    client_id, tokens = _obtain_tokens(oauth_app, oauth_client)
    OAuthToken.query.update({"issued_at": int(time.time()) - 2 * 3600})  # access token long expired
    db.session.commit()

    resp = _refresh(oauth_client, client_id, tokens["refresh_token"])

    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["access_token"] != tokens["access_token"]


def test_a_refresh_token_does_expire_after_its_own_lifetime(oauth_app, oauth_client):
    client_id, tokens = _obtain_tokens(oauth_app, oauth_client)
    OAuthToken.query.update({"issued_at": int(time.time()) - 31 * 86400})
    db.session.commit()

    assert _refresh(oauth_client, client_id, tokens["refresh_token"]).status_code == 400


def test_a_refresh_token_cannot_be_used_twice(oauth_app, oauth_client):
    client_id, tokens = _obtain_tokens(oauth_app, oauth_client)

    assert _refresh(oauth_client, client_id, tokens["refresh_token"]).status_code == 200
    assert _refresh(oauth_client, client_id, tokens["refresh_token"]).status_code == 400


def test_revoking_a_token_by_its_value_works_with_hashed_storage(oauth_app, oauth_client):
    from mcprack import oauth

    client_id, tokens = _obtain_tokens(oauth_app, oauth_client)

    resp = oauth_client.post("/oauth/revoke", data={"token": tokens["access_token"], "client_id": client_id})

    assert resp.status_code == 200
    assert oauth.resolve_oauth_bearer_user(tokens["access_token"]) is None


# --- audit ---------------------------------------------------------------------------------


def _actions():
    return [(e.action, e.error_message or "") for e in AuditLogEntry.query.order_by(AuditLogEntry.id).all()]


def test_registration_consent_and_token_issue_are_audited(oauth_app, oauth_client):
    _obtain_tokens(oauth_app, oauth_client)

    actions = [a for a, _ in _actions()]
    assert "oauth_client_registered" in actions
    assert "oauth_consent" in actions
    assert "oauth_token_issued" in actions
    assert any("app.client.test" in message for _, message in _actions())  # where the code went


def test_a_denied_consent_is_audited_too(oauth_app, oauth_client):
    _make_user()
    client_id = _register(oauth_client, [CALLBACK]).get_json()["client_id"]
    _login(oauth_client)

    oauth_client.post(
        "/oauth/authorize",
        query_string=_authorize_query(client_id, CALLBACK, _pkce_pair()[1]),
        data={"confirm": "no"},
    )

    assert any(a == "oauth_consent" and "denied" in m for a, m in _actions())


def test_a_refresh_token_is_actually_issued(oauth_app, oauth_client):
    """The generator configuration used to be applied after authlib had read
    it, so no refresh token was ever issued."""
    _, tokens = _obtain_tokens(oauth_app, oauth_client)

    assert tokens.get("refresh_token")
    assert tokens["expires_in"] == oauth_app.config["OAUTH_ACCESS_TOKEN_EXPIRES"]
