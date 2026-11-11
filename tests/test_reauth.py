"""B-08 (docs/AUDIT-2026-11.md): fresh authentication before the dangerous
administrator actions - a stolen session has already passed password and MFA."""

import time
from unittest.mock import patch

import pytest

from mcprack import mfa, reauth, totp
from mcprack.extensions import db
from mcprack.models import ApiToken, AuditLogEntry, McpServer, User

PW = "admin-long-password-1"


def _admin(app, username="root", enrolled=False, auth_type="local"):
    with app.app_context():
        user = User(username=username, auth_type=auth_type, is_admin=True, email=f"{username}@example.com")
        if auth_type == "local":
            user.set_password(PW)
        db.session.add(user)
        db.session.commit()
        info = {"id": user.id, "secret": None, "codes": None}
        if enrolled:
            info["secret"], _ = mfa.begin_enrollment(user)
            info["codes"] = mfa.confirm_enrollment(user, totp.hotp(info["secret"], totp.current_step()))
        return info


def _login(app, username="root", info=None):
    client = app.test_client()
    client.post("/login", data={"username": username, "password": PW})
    if info and info["codes"]:
        client.post("/login/mfa", data={"code": info["codes"][0]})
    assert client.get("/api/v1/me").status_code == 200
    return client


def _stale(client, seconds=3600):
    with client.session_transaction() as session:
        session["reauth_at"] = int(time.time()) - seconds


def _new_server_form(name="svc"):
    return {"name": name, "label": name, "transport": "stdio", "command": "/usr/bin/" + name, "enabled": "on"}


def _api_server(name="svc"):
    return {"name": name, "transport": "stdio", "command": "/usr/bin/" + name, "enabled": True}


def _server_count(app):
    with app.app_context():
        return McpServer.query.count()


@pytest.fixture
def fresh(app):
    """The production default: the check is on."""
    app.config["ADMIN_REAUTH_SECONDS"] = 600
    return app


# --- the registry -------------------------------------------------------------------------------


def test_every_mutating_admin_endpoint_has_been_decided(app):
    """Default-deny: a new admin route that is in neither set fails here, so the
    decision "does this need a fresh login?" cannot be skipped by accident."""
    mutating = set()
    for rule in app.url_map.iter_rules():
        methods = rule.methods - {"GET", "HEAD", "OPTIONS"}
        if methods and (rule.endpoint.startswith("admin.") or rule.endpoint.startswith("api.admin_")):
            mutating.add(rule.endpoint)

    decided = reauth.SENSITIVE_ENDPOINTS | set(reauth.REVIEWED_NOT_SENSITIVE)
    assert not (mutating - decided), f"decide: {sorted(mutating - decided)}"
    assert not (reauth.SENSITIVE_ENDPOINTS & set(reauth.REVIEWED_NOT_SENSITIVE)), "in both sets"
    registered = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert not (decided - registered), f"stale entries: {sorted(decided - registered)}"
    assert all(reason.strip() for reason in reauth.REVIEWED_NOT_SENSITIVE.values())


def test_the_demo_registry_knows_the_new_routes(app):
    from mcprack import demo

    assert "auth.reauth_view" in demo.REVIEWED_SAFE and "api.auth_reauth" in demo.REVIEWED_SAFE


# --- a fresh session is not bothered ------------------------------------------------------------


def test_signing_in_counts_as_a_fresh_authentication(fresh):
    _admin(fresh)
    client = _login(fresh)

    assert client.post("/admin/servers/new", data=_new_server_form()).status_code == 302
    assert _server_count(fresh) == 1
    assert client.post("/api/v1/admin/servers", json=_api_server("two")).status_code == 201


# --- a stale one is asked ------------------------------------------------------------------------


def test_a_stale_session_cannot_register_a_server_and_is_sent_to_confirm(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    response = client.post("/admin/servers/new", data=_new_server_form(), headers={"Referer": "http://localhost/admin/servers/new"})

    assert response.status_code == 302 and response.headers["Location"].startswith("/account/reauth?next=")
    assert response.headers["Location"] == "/account/reauth?next=/admin/servers/new"  # back to the page the form was on
    assert _server_count(fresh) == 0  # nothing was saved


def test_the_api_says_reauth_required_and_saves_nothing(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    response = client.post("/api/v1/admin/servers", json=_api_server())

    assert response.status_code == 403 and response.get_json()["error"]["code"] == "reauth_required"
    assert "/api/v1/auth/reauth" in response.get_json()["error"]["message"]
    assert _server_count(fresh) == 0


def test_a_session_from_before_the_feature_existed_is_stale(fresh):
    _admin(fresh)
    client = _login(fresh)
    with client.session_transaction() as session:
        session.pop("reauth_at")

    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 403


@pytest.mark.parametrize("value", ["yesterday", None, 1.5, True, -1, 4_102_444_800])  # junk, and a timestamp in 2100
def test_a_mangled_or_future_timestamp_is_not_fresh(fresh, value):
    _admin(fresh)
    client = _login(fresh)
    with client.session_transaction() as session:
        session["reauth_at"] = value

    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 403


@pytest.mark.parametrize(
    "method,path,kwargs",
    [
        ("post", "/admin/install/pip", {"data": {"name": "x", "package_spec": "x==1.0", "expected_binary": "x"}}),
        ("post", "/admin/users/new", {"data": {"username": "new1", "password": "a-long-password-123", "is_admin": "on"}}),
        ("post", "/api/v1/admin/users", {"json": {"username": "new2", "password": "a-long-password-123", "is_admin": True}}),
        ("post", "/admin/vaultwarden/snapshot-to-local", {}),
        ("post", "/admin/servers/autodetect", {"data": {"command": "/usr/bin/x"}}),
    ],
)
def test_the_other_dangerous_actions_are_guarded_too(fresh, method, path, kwargs):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    response = getattr(client, method)(path, **kwargs)

    assert response.status_code in (302, 403)
    if response.status_code == 302:
        assert "/account/reauth" in response.headers["Location"]
    else:
        assert response.get_json()["error"]["code"] == "reauth_required"
    with fresh.app_context():
        assert User.query.filter(User.username.in_(["new1", "new2"])).count() == 0


def test_promoting_an_account_needs_a_fresh_login(fresh):
    """The point of guarding user edits: a stolen session cannot mint a second
    administrator to keep control after the owner changes the password."""
    _admin(fresh)
    with fresh.app_context():
        other = User(username="ann", auth_type="local")
        other.set_password(PW)
        db.session.add(other)
        db.session.commit()
        other_id = other.id
    client = _login(fresh)
    _stale(client)

    response = client.put(f"/api/v1/admin/users/{other_id}", json={"is_admin": True})

    assert response.status_code == 403
    with fresh.app_context():
        assert db.session.get(User, other_id).is_admin is False


def test_resetting_somebodys_second_factor_needs_a_fresh_login(fresh):
    _admin(fresh)
    victim = _admin(fresh, username="vic", enrolled=True)
    client = _login(fresh)
    _stale(client)

    assert client.post(f"/api/v1/admin/users/{victim['id']}/mfa-reset").status_code == 403
    with fresh.app_context():
        assert db.session.get(User, victim["id"]).totp_enabled


# --- what stays one click -----------------------------------------------------------------------


def test_reading_and_the_defensive_actions_need_no_fresh_login(fresh):
    _admin(fresh)
    client = _login(fresh)
    created = client.post("/api/v1/admin/servers", json=_api_server()).get_json()["data"]["id"]
    _stale(client)

    assert client.get("/admin/servers").status_code == 200
    assert client.get(f"/admin/servers/{created}/edit").status_code == 200  # the form itself
    assert client.get("/api/v1/admin/servers").status_code == 200
    assert client.post("/api/v1/admin/templates", json={"name": "t1", "label": "T"}).status_code in (200, 201)
    other = _admin(fresh, username="bob")
    assert client.post(f"/api/v1/admin/users/{other['id']}/revoke-tokens").status_code == 200  # taking access away


def test_an_ordinary_user_gets_the_routes_own_403_not_a_reauth_prompt(fresh):
    with fresh.app_context():
        user = User(username="ann", auth_type="local")
        user.set_password(PW)
        db.session.add(user)
        db.session.commit()
    client = _login(fresh, "ann")
    _stale(client)

    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 403
    response = client.post("/admin/servers/new", data=_new_server_form())
    assert response.status_code == 403


def test_it_can_be_switched_off_and_the_window_is_respected(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client, seconds=3600)
    fresh.config["ADMIN_REAUTH_SECONDS"] = 0
    assert client.post("/api/v1/admin/servers", json=_api_server("off")).status_code == 201

    fresh.config["ADMIN_REAUTH_SECONDS"] = 600
    _stale(client, seconds=300)  # inside the window
    assert client.post("/api/v1/admin/servers", json=_api_server("inside")).status_code == 201
    _stale(client, seconds=700)  # outside it
    assert client.post("/api/v1/admin/servers", json=_api_server("outside")).status_code == 403


def test_the_public_demo_is_exempt(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)
    fresh.config["DEMO_MODE"] = True

    response = client.post("/api/v1/admin/servers", json=_api_server())

    assert response.get_json()["error"]["code"] != "reauth_required"  # the demo guard answers instead


# --- tokens and the cookie ---------------------------------------------------------------------


def test_a_bearer_token_is_not_asked_to_reauthenticate(fresh):
    info = _admin(fresh)
    with fresh.app_context():
        raw, token = ApiToken.generate("automation", info["id"], scopes=["admin:write"])
        db.session.add(token)
        db.session.commit()

    response = fresh.test_client().post("/api/v1/admin/servers", json=_api_server(), headers={"Authorization": f"Bearer {raw}"})

    assert response.status_code == 201


def test_a_junk_authorization_header_does_not_get_a_stale_cookie_past_the_check(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    response = client.post("/api/v1/admin/servers", json=_api_server(), headers={"Authorization": "Bearer definitely-not-a-token"})

    assert response.status_code == 403 and response.get_json()["error"]["code"] == "reauth_required"
    assert _server_count(fresh) == 0


# --- re-authenticating --------------------------------------------------------------------------


def test_confirming_the_password_makes_the_session_fresh_again(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    response = client.post("/account/reauth", data={"current_password": PW, "next": "/admin/servers/new"})

    assert response.status_code == 302 and response.headers["Location"].endswith("/admin/servers/new")
    assert client.post("/admin/servers/new", data=_new_server_form()).status_code == 302
    assert _server_count(fresh) == 1
    with fresh.app_context():
        assert any("re-authenticated" in (row.error_message or "") for row in AuditLogEntry.query.filter_by(action="login"))


def test_the_reauth_page_asks_for_a_code_only_when_there_is_a_second_factor(fresh):
    _admin(fresh)
    client = _login(fresh)
    assert 'name="code"' not in client.get("/account/reauth").get_data(as_text=True)

    info = _admin(fresh, username="sec", enrolled=True)
    secured = _login(fresh, "sec", info)
    assert 'name="code"' in secured.get("/account/reauth").get_data(as_text=True)


@pytest.mark.parametrize("target", ["//evil.example/x", "https://evil.example/", "javascript:alert(1)", "/\\evil.example"])
def test_it_cannot_be_used_as_an_open_redirect(fresh, target):
    _admin(fresh)
    client = _login(fresh)

    response = client.post("/account/reauth", data={"current_password": PW, "next": target})

    assert response.status_code == 302 and "evil.example" not in response.headers["Location"] and "javascript" not in response.headers["Location"]


def test_a_wrong_password_leaves_it_stale_and_is_audited(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    response = client.post("/account/reauth", data={"current_password": "nope"})

    assert response.status_code == 200 and "not correct" in response.get_data(as_text=True)
    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 403
    with fresh.app_context():
        assert any("re-authentication failed" in (row.error_message or "") for row in AuditLogEntry.query.filter_by(action="login_failed"))


def test_guessing_the_password_through_it_is_throttled(fresh):
    """A hijacked session must not become a password-guessing oracle."""
    _admin(fresh)
    client = _login(fresh)
    _stale(client)
    statuses = [client.post("/account/reauth", data={"current_password": f"guess-{i}"}).status_code for i in range(12)]

    assert 429 in statuses
    assert client.post("/account/reauth", data={"current_password": PW}).status_code == 429  # even the right one, while locked
    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 403


def test_an_account_with_mfa_needs_the_code_too(fresh):
    info = _admin(fresh, enrolled=True)
    client = _login(fresh, info=info)
    _stale(client)
    code = totp.hotp(info["secret"], totp.current_step() + 1)

    only_password = client.post("/account/reauth", data={"current_password": PW, "code": ""})
    wrong_code = client.post("/account/reauth", data={"current_password": PW, "code": "000000"})
    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 403

    ok = client.post("/account/reauth", data={"current_password": PW, "code": code})

    assert only_password.status_code == 200 and wrong_code.status_code == 200 and ok.status_code == 302
    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 201


def test_a_wrong_password_does_not_spend_the_code(fresh):
    info = _admin(fresh, enrolled=True)
    client = _login(fresh, info=info)
    _stale(client)
    code = totp.hotp(info["secret"], totp.current_step() + 1)

    client.post("/account/reauth", data={"current_password": "wrong", "code": code})
    ok = client.post("/account/reauth", data={"current_password": PW, "code": code})  # the same code, now with the right password

    assert ok.status_code == 302


def test_a_recovery_code_will_do(fresh):
    info = _admin(fresh, enrolled=True)
    client = _login(fresh, info=info)
    _stale(client)

    ok = client.post("/account/reauth", data={"current_password": PW, "code": info["codes"][1]})

    assert ok.status_code == 302


def test_an_ldap_administrator_proves_themselves_to_the_directory(fresh):
    fresh.config["LDAP_ENABLED"] = True
    _admin(fresh, username="carol", auth_type="ldap")
    attrs = {"first_name": "C", "last_name": "C", "email": "carol@example.com"}
    client = fresh.test_client()
    with patch("mcprack.auth._ldap_authenticate", return_value=attrs):
        client.post("/login", data={"username": "carol", "password": "directory-password"})
        _stale(client)
        with patch("mcprack.auth._ldap_authenticate", return_value=None):
            refused = client.post("/account/reauth", data={"current_password": "wrong"})
        accepted = client.post("/account/reauth", data={"current_password": "directory-password"})

    assert refused.status_code == 200 and accepted.status_code == 302


# --- over the API -------------------------------------------------------------------------------


def test_the_api_reauth_endpoint(fresh):
    _admin(fresh)
    client = _login(fresh)
    _stale(client)

    wrong = client.post("/api/v1/auth/reauth", json={"password": "nope"})
    ok = client.post("/api/v1/auth/reauth", json={"password": PW})

    assert wrong.status_code == 403 and wrong.get_json()["error"]["code"] == "invalid_credentials"
    assert ok.status_code == 200 and ok.get_json()["data"]["fresh_for"] == 600
    assert client.post("/api/v1/admin/servers", json=_api_server()).status_code == 201


def test_the_api_reauth_endpoint_needs_a_login_and_refuses_bearer_tokens(fresh):
    info = _admin(fresh)
    assert fresh.test_client().post("/api/v1/auth/reauth", json={"password": PW}).status_code == 401
    with fresh.app_context():
        raw, token = ApiToken.generate("t", info["id"], scopes=None)
        db.session.add(token)
        db.session.commit()

    response = fresh.test_client().post("/api/v1/auth/reauth", json={"password": PW}, headers={"Authorization": f"Bearer {raw}"})

    assert response.status_code == 400 and response.get_json()["error"]["code"] == "not_applicable"


def test_the_api_reauth_is_throttled_and_audited(fresh):
    _admin(fresh)
    client = _login(fresh)
    codes = [client.post("/api/v1/auth/reauth", json={"password": f"guess-{i}"}).status_code for i in range(12)]

    assert 429 in codes
    with fresh.app_context():
        assert AuditLogEntry.query.filter(AuditLogEntry.error_message.like("re-authentication%")).count() >= 5


def test_the_default_is_ten_minutes():
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-I", "-c", "from mcprack.config import Config; print(Config.ADMIN_REAUTH_SECONDS)"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert out.stdout.strip() == "600", out.stderr
