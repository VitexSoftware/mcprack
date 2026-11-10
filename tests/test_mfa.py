"""Second factor (TOTP) - docs/AUDIT-2026-11.md B-03."""

import re
from unittest.mock import patch

import pytest

from mcprack import accounts, mfa, totp
from mcprack.auth import _generate_reset_token
from mcprack.extensions import db
from mcprack.models import ApiToken, AuditLogEntry, User

PW = "correct-horse-battery-1"


class Clock:
    """A controllable clock for mcprack.totp, so tests can say "30 seconds later"
    instead of racing the real one."""

    def __init__(self, start):
        self.now = float(start)

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    import time as real_time

    fake = Clock((int(real_time.time()) // 30) * 30 + 5)  # inside a step, away from its edges
    monkeypatch.setattr(totp, "time", fake)
    return fake


@pytest.fixture
def mfa_on(app):
    app.config["MFA_REQUIRED_FOR_ADMINS"] = True


def _make_user(app, username="ann", admin=False, auth_type="local", enrolled=False):
    with app.app_context():
        user = User(username=username, auth_type=auth_type, is_admin=admin, email=f"{username}@example.com")
        if auth_type == "local":
            user.set_password(PW)
        db.session.add(user)
        db.session.commit()
        info = {"id": user.id, "secret": None, "codes": None}
        if enrolled:
            info["secret"], _ = mfa.begin_enrollment(user)
            info["codes"] = mfa.confirm_enrollment(user, totp.hotp(info["secret"], totp.current_step()))
            assert info["codes"], "enrolment helper failed"
        return info


def _code(secret, offset=0):
    return totp.hotp(secret, totp.current_step() + offset)


def _password_step(client, username="ann", password=PW, next_url=None):
    url = "/login" + (f"?next={next_url}" if next_url else "")
    return client.post(url, data={"username": username, "password": password})


def _me_status(client):
    return client.get("/api/v1/me").status_code


def _audit(app, action):
    with app.app_context():
        return [(row.result, row.error_message or "") for row in AuditLogEntry.query.filter_by(action=action).all()]


# --- the login flow -----------------------------------------------------------------------------


def test_an_account_without_mfa_logs_in_as_before(app, clock):
    _make_user(app)
    client = app.test_client()

    response = _password_step(client)

    assert response.status_code == 302 and "/login/mfa" not in response.headers["Location"]
    assert _me_status(client) == 200


def test_the_password_alone_does_not_log_an_mfa_account_in(app, clock):
    _make_user(app, enrolled=True)
    client = app.test_client()

    response = _password_step(client)

    assert response.status_code == 302 and response.headers["Location"].endswith("/login/mfa")
    assert _me_status(client) == 401  # parked, not signed in
    assert client.get("/").status_code == 302  # the catalogue still wants a login


def test_the_right_code_completes_the_login(app, clock):
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    client = app.test_client()
    _password_step(client)

    response = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert response.status_code == 302 and not response.headers["Location"].endswith("/login/mfa")
    assert _me_status(client) == 200
    assert any("second factor: totp" in note for _, note in _audit(app, "login"))


def test_a_wrong_code_does_not(app, clock):
    _make_user(app, enrolled=True)
    clock.advance(30)
    client = app.test_client()
    _password_step(client)

    response = client.post("/login/mfa", data={"code": "000000"})

    assert response.status_code == 200 and _me_status(client) == 401
    assert any("second factor rejected" in note for _, note in _audit(app, "login_failed"))


def test_the_requested_page_survives_the_second_step(app, clock):
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    client = app.test_client()
    _password_step(client, next_url="/account/mfa")

    response = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert response.headers["Location"].endswith("/account/mfa")


def test_a_code_works_once(app, clock):
    """The same code - over a shoulder, from a phishing proxy - is useless a second time."""
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    code = _code(info["secret"])
    first = app.test_client()
    _password_step(first)
    assert first.post("/login/mfa", data={"code": code}).status_code == 302

    second = app.test_client()
    _password_step(second)
    response = second.post("/login/mfa", data={"code": code})

    assert response.status_code == 200 and _me_status(second) == 401


def test_the_next_code_works_after_the_clock_moves_on(app, clock):
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    first = app.test_client()
    _password_step(first)
    first.post("/login/mfa", data={"code": _code(info["secret"])})

    clock.advance(30)
    second = app.test_client()
    _password_step(second)

    assert second.post("/login/mfa", data={"code": _code(info["secret"])}).status_code == 302
    assert _me_status(second) == 200


def test_a_recovery_code_works_exactly_once(app, clock):
    info = _make_user(app, enrolled=True)
    recovery = info["codes"][0]
    first = app.test_client()
    _password_step(first)
    assert first.post("/login/mfa", data={"code": recovery}).status_code == 302
    assert _me_status(first) == 200

    second = app.test_client()
    _password_step(second)
    response = second.post("/login/mfa", data={"code": recovery})

    assert response.status_code == 200 and _me_status(second) == 401
    with app.app_context():
        assert mfa.remaining_recovery_codes(db.session.get(User, info["id"])) == len(info["codes"]) - 1


def test_recovery_codes_are_accepted_in_any_case_and_spacing(app, clock):
    info = _make_user(app, enrolled=True)
    client = app.test_client()
    _password_step(client)
    sloppy = info["codes"][1].lower().replace("-", " ")

    assert client.post("/login/mfa", data={"code": sloppy}).status_code == 302


def test_the_code_step_needs_the_password_step_first(app, clock):
    _make_user(app, enrolled=True)

    response = app.test_client().post("/login/mfa", data={"code": "123456"})

    assert response.status_code == 302 and response.headers["Location"].endswith("/login")


def test_the_pending_login_runs_out(app, clock, monkeypatch):
    import time as real_time

    from mcprack import auth

    info = _make_user(app, enrolled=True)
    client = app.test_client()
    _password_step(client)
    clock.advance(30)
    later = real_time.time() + 3600
    monkeypatch.setattr(auth.time, "time", lambda: later)

    response = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    assert _me_status(client) == 401


def test_a_password_change_in_between_cancels_the_pending_login(app, clock):
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    client = app.test_client()
    _password_step(client)
    with app.app_context():
        accounts.invalidate_sessions(db.session.get(User, info["id"]))
        db.session.commit()

    response = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert response.headers["Location"].endswith("/login") and _me_status(client) == 401


def test_a_deactivated_account_cannot_finish_the_login(app, clock):
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    client = app.test_client()
    _password_step(client)
    with app.app_context():
        user = db.session.get(User, info["id"])
        user.is_active_flag = False
        db.session.commit()

    response = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert response.headers["Location"].endswith("/login") and _me_status(client) == 401


def test_a_tampered_next_target_is_not_followed(app, clock):
    info = _make_user(app, enrolled=True)
    clock.advance(30)
    client = app.test_client()
    _password_step(client)
    with client.session_transaction() as session:
        session["mfa_next"] = "//evil.example/phish"

    response = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert "evil.example" not in response.headers["Location"]


def test_the_shared_demo_login_is_not_asked_for_a_code(app, clock):
    info = _make_user(app, username="demo", enrolled=True)
    app.config["DEMO_MODE"] = True
    app.config["DEMO_USERNAME"] = "demo"
    client = app.test_client()

    response = _password_step(client, username="demo")

    assert not response.headers["Location"].endswith("/login/mfa") and info["secret"]


# --- brute force on the code --------------------------------------------------------------------


def test_guessing_the_code_is_throttled_and_re_entering_the_password_does_not_reset_it(app, clock):
    """Whoever knows the password still has to get past the throttle for the
    code: a correct password is not a finished login, so it must not wipe the
    failure counters (it would make six digits guessable without limit)."""
    info = _make_user(app, enrolled=True)
    locked = False
    for _ in range(12):
        client = app.test_client()
        response = _password_step(client)
        if response.status_code == 429:
            locked = True
            break
        response = client.post("/login/mfa", data={"code": "000000"})
        if response.status_code == 429:
            locked = True
            break

    assert locked, "twelve full attempts - password then wrong code - never locked"
    # and while locked, even the right password and the right code are refused
    clock.advance(30)
    client = app.test_client()
    refused = _password_step(client)
    if refused.status_code == 302:
        refused = client.post("/login/mfa", data={"code": _code(info["secret"])})
    assert refused.status_code == 429
    assert "Retry-After" in refused.headers


# --- enrolment ----------------------------------------------------------------------------------


def _logged_in(app, username="ann", admin=False, auth_type="local", enrolled=False):
    info = _make_user(app, username=username, admin=admin, auth_type=auth_type, enrolled=enrolled)
    client = app.test_client()
    if enrolled:
        _password_step(client, username=username)
        client.post("/login/mfa", data={"code": info["codes"][0]})
    else:
        _password_step(client, username=username)
    assert _me_status(client) == 200
    return client, info


def test_the_page_needs_a_login(app):
    response = app.test_client().get("/account/mfa")

    assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_beginning_an_enrolment_shows_the_secret_but_does_not_switch_anything_on(app, clock):
    client, info = _logged_in(app)

    response = client.post("/account/mfa", data={"action": "begin"})

    body = response.get_data(as_text=True)
    assert response.status_code == 200 and "otpauth://totp/" in body
    with app.app_context():
        user = db.session.get(User, info["id"])
        assert user.totp_enabled is False and user.totp_secret
        plain = mfa.pending_secret(user)
        assert plain and plain not in user.totp_secret  # stored encrypted
        assert totp.group(plain) in body
    # a half-finished enrolment locks nobody out: the password alone still logs in
    other = app.test_client()
    assert not _password_step(other).headers["Location"].endswith("/login/mfa")
    assert _me_status(other) == 200


def test_confirming_with_a_wrong_code_enables_nothing(app, clock):
    client, info = _logged_in(app)
    client.post("/account/mfa", data={"action": "begin"})

    response = client.post("/account/mfa", data={"action": "confirm", "code": "000000"})

    assert "not valid" in response.get_data(as_text=True)
    with app.app_context():
        assert db.session.get(User, info["id"]).totp_enabled is False


def test_confirming_with_the_right_code_enables_it_and_shows_recovery_codes_once(app, clock):
    client, info = _logged_in(app)
    client.post("/account/mfa", data={"action": "begin"})
    with app.app_context():
        secret = mfa.pending_secret(db.session.get(User, info["id"]))

    response = client.post("/account/mfa", data={"action": "confirm", "code": _code(secret)})

    body = response.get_data(as_text=True)
    shown = re.findall(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", body)
    assert len(shown) == 10 and len(set(shown)) == 10
    with app.app_context():
        user = db.session.get(User, info["id"])
        assert user.totp_enabled is True and mfa.remaining_recovery_codes(user) == 10
        stored = user.recovery_codes
        assert not any(code.replace("-", "") in stored for code in shown)  # keyed hashes, not the codes
    assert _me_status(client) == 200  # this session stays signed in
    again = client.get("/account/mfa").get_data(as_text=True)
    assert not re.findall(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", again)  # never shown again
    assert any("enabled" in note for _, note in _audit(app, "mfa_change"))


def test_enabling_ends_the_other_sessions(app, clock):
    client, info = _logged_in(app)
    elsewhere = app.test_client()
    _password_step(elsewhere)
    assert _me_status(elsewhere) == 200
    client.post("/account/mfa", data={"action": "begin"})
    with app.app_context():
        secret = mfa.pending_secret(db.session.get(User, info["id"]))

    client.post("/account/mfa", data={"action": "confirm", "code": _code(secret)})

    assert _me_status(elsewhere) == 401 and _me_status(client) == 200


def test_you_cannot_start_over_while_it_is_on(app, clock):
    client, info = _logged_in(app, enrolled=True)
    with app.app_context():
        before = db.session.get(User, info["id"]).totp_secret

    client.post("/account/mfa", data={"action": "begin"})

    with app.app_context():
        user = db.session.get(User, info["id"])
        assert user.totp_enabled is True and user.totp_secret == before


def _advance_and_code(clock, info):
    clock.advance(30)
    return _code(info["secret"])


def test_turning_it_off_needs_the_password_and_a_code(app, clock):
    client, info = _logged_in(app, enrolled=True)

    wrong_password = client.post("/account/mfa", data={"action": "disable", "current_password": "nope", "code": _advance_and_code(clock, info)})
    wrong_code = client.post("/account/mfa", data={"action": "disable", "current_password": PW, "code": "000000"})
    with app.app_context():
        assert db.session.get(User, info["id"]).totp_enabled is True
    assert "not correct" in wrong_password.get_data(as_text=True) and "not correct" in wrong_code.get_data(as_text=True)

    ok = client.post("/account/mfa", data={"action": "disable", "current_password": PW, "code": _advance_and_code(clock, info)})

    assert ok.status_code == 302
    with app.app_context():
        user = db.session.get(User, info["id"])
        assert user.totp_enabled is False and user.totp_secret is None and user.recovery_codes is None
    assert any("disabled" in note for _, note in _audit(app, "mfa_change"))


def test_regenerating_replaces_the_recovery_codes(app, clock):
    client, info = _logged_in(app, enrolled=True)
    old = info["codes"][1]

    response = client.post("/account/mfa", data={"action": "regenerate", "current_password": PW, "code": _advance_and_code(clock, info)})

    new = re.findall(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", response.get_data(as_text=True))
    assert len(new) == 10 and old not in new
    other = app.test_client()
    _password_step(other)
    assert other.post("/login/mfa", data={"code": old}).status_code == 200  # the old ones are dead
    assert _me_status(other) == 401


def test_a_stolen_session_cannot_switch_the_factor_off_without_the_password(app, clock):
    client, info = _logged_in(app, enrolled=True)

    client.post("/account/mfa", data={"action": "disable", "current_password": "", "code": _advance_and_code(clock, info)})

    with app.app_context():
        assert db.session.get(User, info["id"]).totp_enabled is True


def test_administrators_cannot_turn_it_off_even_with_a_hand_made_post(app, clock, mfa_on):
    client, info = _logged_in(app, username="boss", admin=True, enrolled=True)

    client.post("/account/mfa", data={"action": "disable", "current_password": PW, "code": _advance_and_code(clock, info)})

    with app.app_context():
        assert db.session.get(User, info["id"]).totp_enabled is True
    page = client.get("/account/mfa").get_data(as_text=True)
    assert 'value="disable"' not in page and "cannot turn it off" in page  # the page does not even offer it


def test_ldap_accounts_can_enrol_and_are_asked_for_the_code(app, clock):
    app.config["LDAP_ENABLED"] = True
    info = _make_user(app, username="carol", auth_type="ldap", enrolled=True)
    attrs = {"first_name": "Carol", "last_name": "C", "email": "carol@example.com"}
    client = app.test_client()
    clock.advance(30)

    with patch("mcprack.auth._ldap_authenticate", return_value=attrs):
        response = client.post("/login", data={"username": "carol", "password": "directory-password"})
        assert response.headers["Location"].endswith("/login/mfa") and _me_status(client) == 401
        done = client.post("/login/mfa", data={"code": _code(info["secret"])})

    assert done.status_code == 302 and _me_status(client) == 200


def test_the_password_reset_flow_does_not_bypass_the_factor(app, clock):
    info = _make_user(app, enrolled=True)
    with app.app_context():
        token = _generate_reset_token(db.session.get(User, info["id"]))
    client = app.test_client()
    client.post(f"/reset-password/{token}", data={"new_password": "another-long-password-2", "confirm_password": "another-long-password-2"})

    response = _password_step(client, password="another-long-password-2")

    assert response.headers["Location"].endswith("/login/mfa") and _me_status(client) == 401


# --- the secret and the codes at rest -----------------------------------------------------------


def test_enrolment_survives_a_secret_key_rotation(app, clock):
    info = _make_user(app, enrolled=True)
    old_key = app.config["SECRET_KEY"]
    app.config["SECRET_KEY"] = "a-brand-new-secret-key-0123456789abcdef"
    app.config["SECRET_KEY_FALLBACKS"] = [old_key]
    clock.advance(30)

    with app.app_context():
        user = db.session.get(User, info["id"])
        assert mfa.verify_login(user, _code(info["secret"])) == "totp"
        assert mfa.verify_login(user, info["codes"][0]) == "recovery"


def test_without_the_old_key_the_secret_is_unreadable_not_guessable(app, clock):
    info = _make_user(app, enrolled=True)
    app.config["SECRET_KEY"] = "a-brand-new-secret-key-0123456789abcdef"
    clock.advance(30)

    with app.app_context():
        user = db.session.get(User, info["id"])
        assert mfa.verify_login(user, _code(info["secret"])) is None
        assert mfa.verify_login(user, info["codes"][0]) is None


def test_two_parallel_uses_of_one_code_cannot_both_win(app, clock):
    """The accepted step is recorded with a conditional UPDATE. A request that
    read the row *before* another one used the code still believes the step is
    free; the UPDATE (WHERE totp_last_step < step) is what refuses it."""
    from sqlalchemy import update

    info = _make_user(app, enrolled=True)
    clock.advance(30)
    code = _code(info["secret"])
    step = totp.current_step()
    with app.app_context():
        user = db.session.get(User, info["id"])
        # "the other request" has already used this step ...
        db.session.execute(update(User).where(User.id == user.id).values(totp_last_step=step))
        db.session.commit()
        # ... while this one's read still says it is free
        with patch("mcprack.mfa.totp.match", return_value=step):
            assert mfa.verify_login(user, code) is None
        assert db.session.get(User, info["id"]).totp_last_step == step


# --- who must have one --------------------------------------------------------------------------


def _admin_with(app, enrolled):
    return _logged_in(app, username="boss", admin=True, enrolled=enrolled)


def test_an_administrator_without_mfa_is_sent_to_set_it_up(app, clock, mfa_on):
    client, _ = _admin_with(app, enrolled=False)

    response = client.get("/admin/servers")

    assert response.status_code == 302 and response.headers["Location"].endswith("/account/mfa")


def test_an_administrator_without_mfa_is_refused_by_the_admin_api_in_a_browser_session(app, clock, mfa_on):
    client, _ = _admin_with(app, enrolled=False)

    response = client.get("/api/v1/admin/servers")

    assert response.status_code == 403 and response.get_json()["error"]["code"] == "mfa_required"


def test_an_administrator_with_mfa_gets_in(app, clock, mfa_on):
    client, _ = _admin_with(app, enrolled=True)

    assert client.get("/admin/servers").status_code == 200
    assert client.get("/api/v1/admin/servers").status_code == 200


def test_an_admin_api_token_is_not_asked_for_a_factor(app, clock, mfa_on):
    info = _make_user(app, username="boss", admin=True)
    with app.app_context():
        raw, token = ApiToken.generate("automation", info["id"], scopes=["admin:read"])
        db.session.add(token)
        db.session.commit()

    response = app.test_client().get("/api/v1/admin/servers", headers={"Authorization": f"Bearer {raw}"})

    assert response.status_code == 200


def test_ordinary_users_are_not_forced(app, clock, mfa_on):
    client, _ = _logged_in(app, username="ann", enrolled=False)

    assert client.get("/").status_code == 200


def test_the_requirement_can_be_switched_off(app, clock):
    app.config["MFA_REQUIRED_FOR_ADMINS"] = False
    client, _ = _admin_with(app, enrolled=False)

    assert client.get("/admin/servers").status_code == 200


def test_the_demo_instance_is_exempt(app, clock, mfa_on):
    client, _ = _admin_with(app, enrolled=False)
    app.config["DEMO_MODE"] = True

    assert client.get("/admin/servers").status_code == 200


def test_the_default_requires_it_for_administrators():
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-I", "-c", "from mcprack.config import Config; print(Config.MFA_REQUIRED_FOR_ADMINS)"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert out.stdout.strip() == "True", out.stderr


# --- getting back in ----------------------------------------------------------------------------


def _admin_client(app):
    app.config["MFA_REQUIRED_FOR_ADMINS"] = False
    client, info = _logged_in(app, username="root", admin=True)
    return client, info


def test_an_administrator_can_reset_a_users_factor_over_the_api(app, clock):
    victim = _make_user(app, username="vic", enrolled=True)
    client, _ = _admin_client(app)
    elsewhere = app.test_client()
    _password_step(elsewhere, username="vic")
    elsewhere.post("/login/mfa", data={"code": victim["codes"][0]})
    assert _me_status(elsewhere) == 200

    response = client.post(f"/api/v1/admin/users/{victim['id']}/mfa-reset")

    assert response.status_code == 200 and response.get_json()["data"]["mfa_enabled"] is False
    with app.app_context():
        user = db.session.get(User, victim["id"])
        assert not user.totp_enabled and user.totp_secret is None and user.recovery_codes is None
    assert _me_status(elsewhere) == 401  # their sessions ended
    assert any("reset by an administrator" in note for _, note in _audit(app, "mfa_change"))
    assert not _password_step(app.test_client(), username="vic").headers["Location"].endswith("/login/mfa")


def test_the_html_admin_page_can_reset_it_too(app, clock):
    victim = _make_user(app, username="vic", enrolled=True)
    client, _ = _admin_client(app)

    response = client.post(f"/admin/users/{victim['id']}/mfa-reset")

    assert response.status_code == 302
    with app.app_context():
        assert not db.session.get(User, victim["id"]).totp_enabled


def test_the_user_form_offers_the_buttons(app, clock):
    victim = _make_user(app, username="vic", enrolled=True)
    client, _ = _admin_client(app)

    html = client.get(f"/admin/users/{victim['id']}/edit").get_data(as_text=True)

    assert f"/admin/users/{victim['id']}/mfa-reset" in html
    assert f"/admin/users/{victim['id']}/revoke-tokens" in html


def test_an_ordinary_user_cannot_reset_anybodys_factor(app, clock):
    victim = _make_user(app, username="vic", enrolled=True)
    client, _ = _logged_in(app, username="ann")

    assert client.post(f"/api/v1/admin/users/{victim['id']}/mfa-reset").status_code == 403
    assert client.post(f"/admin/users/{victim['id']}/mfa-reset").status_code == 403
    with app.app_context():
        assert db.session.get(User, victim["id"]).totp_enabled


def test_the_command_line_is_the_way_back_for_a_locked_out_admin(app, clock):
    info = _make_user(app, username="boss", admin=True, enrolled=True)
    runner = app.test_cli_runner()

    status = runner.invoke(args=["user", "mfa-status", "boss"])
    reset = runner.invoke(args=["user", "mfa-reset", "boss"])
    after = runner.invoke(args=["user", "mfa-status", "boss"])

    assert "on; 10 recovery code(s)" in status.output
    assert reset.exit_code == 0 and "is off" in reset.output
    assert "off; 0 recovery" in after.output
    with app.app_context():
        assert not db.session.get(User, info["id"]).totp_enabled


def test_the_demo_cannot_change_a_factor(app, clock):
    client, _ = _logged_in(app, username="ann")
    app.config["DEMO_MODE"] = True

    response = client.post("/account/mfa", data={"action": "begin"})

    assert response.status_code == 302
    with app.app_context():
        assert db.session.query(User).filter_by(username="ann").first().totp_secret is None


def test_the_openapi_user_schema_documents_the_flag():
    import yaml
    from pathlib import Path

    spec = yaml.safe_load((Path(__file__).resolve().parent.parent / "mcprack" / "openapi" / "openapi.yaml").read_text())

    assert "mfa_enabled" in spec["components"]["schemas"]["User"]["properties"]
    assert "/admin/users/{userId}/mfa-reset" in spec["paths"]
