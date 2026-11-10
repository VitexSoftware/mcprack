"""A-03 (docs/AUDIT-2026-11.md): taking a user's access away must work.

A proxy path token used to keep working after the account was disabled, never
expired and could not be revoked individually; processes of a disabled or
deleted user kept running. Now: a disabled account's token is refused, an
admin can revoke a user's tokens (a per-user version embedded in every
token), and disabling/deleting a user stops their running MCP processes.
"""

import json

import pytest

from mcprack import catalog, user_proxy
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection


def _relay_target(app):
    """A user, an enabled network server (nothing listens on it) and the
    selection linking them: a request that gets past authentication ends in
    mcprack's own 502, not in a 403."""
    with app.app_context():
        user = User(username="leaver", auth_type="local")
        user.set_password("pw")
        server = McpServer(name="dummy", label="Dummy", transport="http", url="http://127.0.0.1:9/mcp", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        return user.id, server.id


def _version(app, user_id):
    with app.app_context():
        return db.session.get(User, user_id).token_version


def _call(client, token, server_id):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    return client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")


def _token(app, user_id, server_id):
    with app.app_context():
        user = db.session.get(User, user_id)
        return catalog._make_proxy_token(user, server_id)


def test_active_user_token_passes_authentication(app, client):
    user_id, server_id = _relay_target(app)

    resp = _call(client, _token(app, user_id, server_id), server_id)

    assert resp.status_code == 502  # authenticated; the upstream is unreachable


def test_disabled_user_token_is_refused(app, client):
    user_id, server_id = _relay_target(app)
    token = _token(app, user_id, server_id)
    with app.app_context():
        db.session.get(User, user_id).is_active_flag = False
        db.session.commit()

    resp = _call(client, token, server_id)

    assert resp.status_code == 403


def test_revoking_a_users_tokens_invalidates_the_old_ones_only(app, client):
    user_id, server_id = _relay_target(app)
    old = _token(app, user_id, server_id)
    with app.app_context():
        user = db.session.get(User, user_id)
        user.token_version += 1
        db.session.commit()
    new = _token(app, user_id, server_id)

    assert _call(client, old, server_id).status_code == 403
    assert _call(client, new, server_id).status_code == 502


def test_tokens_issued_before_versions_existed_work_until_revoked(app, client):
    """Upgrade safety: an account that existed before versions did is at
    version 0, and the tokens the previous release minted for it carry no
    version. They keep working and die on the first revocation."""
    user_id, server_id = _relay_target(app)
    with app.app_context():
        db.session.get(User, user_id).token_version = 0  # a pre-existing account
        db.session.commit()
        legacy = catalog._proxy_serializer().dumps({"u": user_id, "s": server_id})

    assert _call(client, legacy, server_id).status_code == 502

    with app.app_context():
        from mcprack import accounts

        accounts.revoke_tokens(db.session.get(User, user_id))
        db.session.commit()

    assert _call(client, legacy, server_id).status_code == 403


def test_a_deleted_users_token_does_not_authenticate_a_new_account_with_the_same_id(app, client):
    """SQLite reuses the id of a deleted last row. The new account starts at a
    random token version, so neither a versioned token nor a legacy one of the
    former owner matches it."""
    user_id, server_id = _relay_target(app)
    with app.app_context():
        versioned = catalog._make_proxy_token(user_id, server_id)
        legacy = catalog._proxy_serializer().dumps({"u": user_id, "s": server_id})
        db.session.delete(db.session.get(User, user_id))
        db.session.commit()

        newcomer = User(username="newcomer", auth_type="local")
        newcomer.set_password("pw")
        db.session.add(newcomer)
        db.session.commit()
        assert newcomer.id == user_id  # the id really was reused
        assert newcomer.token_version != 0
        db.session.add(UserServerSelection(user_id=newcomer.id, server_id=server_id))
        db.session.commit()

    assert _call(client, versioned, server_id).status_code == 403
    assert _call(client, legacy, server_id).status_code == 403


def test_new_accounts_get_distinct_random_non_zero_versions(app):
    with app.app_context():
        users = []
        for i in range(5):
            u = User(username=f"u{i}", auth_type="local")
            u.set_password("pw")
            users.append(u)
        db.session.add_all(users)
        db.session.commit()

        versions = {u.token_version for u in users}
        assert 0 not in versions
        assert len(versions) == 5


def test_token_for_another_user_or_server_is_still_refused(app, client):
    user_id, server_id = _relay_target(app)
    token = _token(app, user_id, server_id)

    assert _call(client, token, server_id + 1).status_code == 403


def test_revoking_also_revokes_api_and_oauth_tokens(app):
    from mcprack import accounts
    from mcprack.models import ApiToken, OAuthToken

    user_id, _ = _relay_target(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        raw, api_token = ApiToken.generate("ci", user.id)
        oauth = OAuthToken(user_id=user.id, client_id="c", token_type="Bearer", access_token="a",
                           refresh_token="r", scope="mcp", issued_at=1, expires_in=3600)
        db.session.add_all([api_token, oauth])
        db.session.commit()

        accounts.revoke_tokens(user)
        db.session.commit()

        assert api_token.is_revoked
        assert oauth.is_revoked()
        assert not oauth.is_refresh_token_active()


# --- admin / CLI entry points ------------------------------------------------


def _admin_and_victim(app):
    with app.app_context():
        admin = User(username="boss", auth_type="local", is_admin=True)
        admin.set_password("pw")
        victim = User(username="victim", auth_type="local")
        victim.set_password("pw")
        db.session.add_all([admin, victim])
        db.session.commit()
        return victim.id


def _login_boss(client):
    client.post("/login", data={"username": "boss", "password": "pw"})


def test_admin_can_revoke_a_users_tokens(app, client):
    victim_id = _admin_and_victim(app)
    before = _version(app, victim_id)
    _login_boss(client)

    resp = client.post(f"/admin/users/{victim_id}/revoke-tokens", follow_redirects=True)

    assert resp.status_code == 200
    assert _version(app, victim_id) not in (0, before)


def test_non_admin_cannot_revoke_tokens(app, client):
    victim_id = _admin_and_victim(app)
    before = _version(app, victim_id)
    with app.app_context():
        other = User(username="other", auth_type="local")
        other.set_password("pw")
        db.session.add(other)
        db.session.commit()
    client.post("/login", data={"username": "other", "password": "pw"})

    resp = client.post(f"/admin/users/{victim_id}/revoke-tokens")

    assert resp.status_code == 403
    assert _version(app, victim_id) == before


def test_api_can_revoke_a_users_tokens(app, client):
    victim_id = _admin_and_victim(app)
    before = _version(app, victim_id)
    _login_boss(client)

    resp = client.post(f"/api/v1/admin/users/{victim_id}/revoke-tokens")

    assert resp.status_code == 200
    assert _version(app, victim_id) not in (0, before)


def test_cli_revoke_tokens(app):
    victim_id = _admin_and_victim(app)
    before = _version(app, victim_id)

    with app.app_context():
        result = app.test_cli_runner().invoke(args=["user", "revoke-tokens", "victim"])
        assert result.exit_code == 0, result.output
    assert _version(app, victim_id) not in (0, before)


@pytest.fixture
def stopped(monkeypatch):
    calls = []
    monkeypatch.setattr(user_proxy, "stop_user_proxies", lambda user_id: calls.append(user_id))
    return calls


def test_disabling_a_user_in_the_admin_ui_stops_their_proxies(app, client, stopped):
    victim_id = _admin_and_victim(app)
    _login_boss(client)

    client.post(f"/admin/users/{victim_id}/edit", data={"is_active": ""})  # box unchecked = disabled

    assert stopped == [victim_id]


def test_disabling_a_user_through_the_api_stops_their_proxies(app, client, stopped):
    victim_id = _admin_and_victim(app)
    _login_boss(client)

    client.put(f"/api/v1/admin/users/{victim_id}", json={"is_active": False})

    assert stopped == [victim_id]


def test_deleting_a_user_through_the_api_stops_their_proxies(app, client, stopped):
    victim_id = _admin_and_victim(app)
    _login_boss(client)

    client.delete(f"/api/v1/admin/users/{victim_id}")

    assert stopped == [victim_id]


def test_cli_disable_stops_their_proxies(app, stopped):
    victim_id = _admin_and_victim(app)

    with app.app_context():
        app.test_cli_runner().invoke(args=["user", "disable", "victim"])

    assert stopped == [victim_id]


def test_keeping_a_user_enabled_does_not_stop_anything(app, client, stopped):
    victim_id = _admin_and_victim(app)
    _login_boss(client)

    client.post(f"/admin/users/{victim_id}/edit", data={"is_active": "on"})

    assert stopped == []


# --- user_proxy.stop_user_proxies ---------------------------------------------


def test_stop_user_proxies_stops_only_that_users_instances(app, monkeypatch):
    state = user_proxy.STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    for key, pid in (("u5-s1", 9_000_111), ("u5-s2", 9_000_222), ("u6-s1", 9_000_333), ("u50-s1", 9_000_444)):
        (state / f"{key}.pid").write_text(str(pid))
        (state / f"{key}.meta.json").write_text("{}")
    stopped = []
    monkeypatch.setattr(user_proxy, "_stop_pid", lambda pid, timeout=3.0: stopped.append(pid))

    with app.app_context():
        user_proxy.stop_user_proxies(5)

    assert sorted(stopped) == [9_000_111, 9_000_222]  # not u6, and not u50 (prefix of the id)
    assert not (state / "u5-s1.pid").exists()
    assert not (state / "u5-s1.meta.json").exists()
    assert (state / "u6-s1.pid").exists()
    assert (state / "u50-s1.pid").exists()
