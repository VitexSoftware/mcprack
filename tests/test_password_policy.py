"""B-03 (docs/AUDIT-2026-11.md): password policy.

An admin could create an account with an EMPTY password (and log in with it),
the API accepted one character, and the minimum was 8. One policy now applies
to every way a password is set: self-service change, e-mail reset, admin UI,
REST API, CLI and create-admin.
"""

import pytest

from mcprack import passwords
from mcprack.extensions import db
from mcprack.models import User


# --- the policy itself ----------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        "correct horse battery staple",
        "Tr0ub4dor&3-and-more",
        "a1b2c3d4e5f6g7h8",
        "correct-horse-battery-staple-correct-horse",
    ],
)
def test_acceptable_passwords(app, password):
    with app.app_context():
        assert passwords.check_strength(password, username="alice") is None


@pytest.mark.parametrize(
    "password,why",
    [
        ("", "empty"),
        ("   ", "blank"),
        ("short1!", "too short"),
        ("elevenchars", "11 chars"),
        ("password1234", "common"),
        ("Password1234", "common, case-insensitive"),
        ("123456789012", "sequence"),
        ("aaaaaaaaaaaa", "repeated"),
        ("qwertyuiop12", "keyboard run"),
        ("alice-the-user", "contains the username"),
        ("ALICE", "equals the username"),
        ("x" * 2000, "absurdly long"),
    ],
)
def test_rejected_passwords(app, password, why):
    with app.app_context():
        assert passwords.check_strength(password, username="alice"), why


def test_minimum_length_is_configurable(app):
    app.config["PASSWORD_MIN_LENGTH"] = 16
    with app.app_context():
        assert passwords.check_strength("fifteen-chars!!", username="u")
        assert passwords.check_strength("sixteen-chars!!!!", username="u") is None


def test_non_strings_are_rejected(app):
    with app.app_context():
        assert passwords.check_strength(None, username="u")


# --- the model never stores or accepts a blank password ----------------------


def test_set_password_refuses_an_empty_password(app):
    with app.app_context():
        user = User(username="x", auth_type="local")
        with pytest.raises(ValueError):
            user.set_password("")


def test_a_legacy_blank_password_cannot_log_in(app, client):
    """Accounts that already hold a hash of the empty string (created by the
    old admin form) stop being usable: empty never verifies."""
    from werkzeug.security import generate_password_hash

    with app.app_context():
        user = User(username="blank", auth_type="local", password_hash=generate_password_hash(""))
        db.session.add(user)
        db.session.commit()

    client.post("/login", data={"username": "blank", "password": ""})

    assert client.get("/").status_code == 302  # still sent to the login page


# --- entry points ---------------------------------------------------------------


def _login(client, name, password):
    return client.post("/login", data={"username": name, "password": password})


def _admin(app, client):
    with app.app_context():
        admin = User(username="boss", auth_type="local", is_admin=True)
        admin.set_password("boss-password-12345")
        db.session.add(admin)
        db.session.commit()
    _login(client, "boss", "boss-password-12345")


def test_admin_ui_refuses_to_create_a_user_with_an_empty_password(app, client):
    _admin(app, client)

    client.post("/admin/users/new", data={"username": "blank", "password": ""})

    with app.app_context():
        assert User.query.filter_by(username="blank").first() is None


def test_admin_ui_accepts_a_strong_password_and_the_user_can_log_in(app, client):
    _admin(app, client)

    client.post("/admin/users/new", data={"username": "carol", "password": "a-good-long-password"})

    other = app.test_client()
    other.post("/login", data={"username": "carol", "password": "a-good-long-password"})
    assert other.get("/").status_code == 200


def test_admin_ui_refuses_a_duplicate_username_without_a_500(app, client):
    _admin(app, client)

    resp = client.post("/admin/users/new", data={"username": "boss", "password": "a-good-long-password"})

    assert resp.status_code < 500


def test_admin_ui_edit_refuses_a_weak_new_password_and_keeps_the_old_one(app, client):
    _admin(app, client)
    with app.app_context():
        victim = User(username="dave", auth_type="local")
        victim.set_password("dave-original-password")
        db.session.add(victim)
        db.session.commit()
        victim_id = victim.id

    client.post(f"/admin/users/{victim_id}/edit", data={"is_active": "on", "password": "weak"})

    with app.app_context():
        assert db.session.get(User, victim_id).check_password("dave-original-password")


@pytest.mark.parametrize("password", ["", "a", "short1!", "password1234"])
def test_api_refuses_weak_passwords_on_create(app, client, password):
    _admin(app, client)

    resp = client.post("/api/v1/admin/users", json={"username": "erin", "password": password})

    assert resp.status_code == 400
    with app.app_context():
        assert User.query.filter_by(username="erin").first() is None


def test_api_refuses_a_weak_password_on_update(app, client):
    _admin(app, client)
    with app.app_context():
        victim = User(username="frank", auth_type="local")
        victim.set_password("frank-original-password")
        db.session.add(victim)
        db.session.commit()
        victim_id = victim.id

    resp = client.put(f"/api/v1/admin/users/{victim_id}", json={"password": "weak"})

    assert resp.status_code == 400
    with app.app_context():
        assert db.session.get(User, victim_id).check_password("frank-original-password")


def test_self_service_change_applies_the_policy(app, client):
    with app.app_context():
        user = User(username="gina", auth_type="local")
        user.set_password("gina-original-password")
        db.session.add(user)
        db.session.commit()
    _login(client, "gina", "gina-original-password")

    client.post(
        "/account/password",
        data={"current_password": "gina-original-password", "new_password": "password1234",
              "confirm_password": "password1234"},
    )

    with app.app_context():
        assert User.query.filter_by(username="gina").first().check_password("gina-original-password")


def test_email_reset_applies_the_policy(app, client):
    from mcprack import auth

    with app.app_context():
        user = User(username="hank", email="h@example.com", auth_type="local")
        user.set_password("hank-original-password")
        db.session.add(user)
        db.session.commit()
        token = auth._generate_reset_token(user)

    client.post(f"/reset-password/{token}", data={"new_password": "short", "confirm_password": "short"})

    with app.app_context():
        assert User.query.filter_by(username="hank").first().check_password("hank-original-password")


def test_cli_create_and_passwd_apply_the_policy(app):
    with app.app_context():
        runner = app.test_cli_runner()

        weak = runner.invoke(args=["user", "create", "--username", "ivy", "--password", "hunter2"])
        assert weak.exit_code != 0
        assert User.query.filter_by(username="ivy").first() is None

        ok = runner.invoke(args=["user", "create", "--username", "ivy", "--password", "a-long-enough-pass"])
        assert ok.exit_code == 0, ok.output

        weak_change = runner.invoke(args=["user", "passwd", "ivy", "--password", "newpass123"])
        assert weak_change.exit_code != 0
        assert User.query.filter_by(username="ivy").first().check_password("a-long-enough-pass")


def test_create_admin_command_applies_the_policy(app):
    with app.app_context():
        runner = app.test_cli_runner()

        weak = runner.invoke(args=["create-admin", "--username", "root2", "--password", "1234", "--email", ""])
        assert weak.exit_code != 0
        assert User.query.filter_by(username="root2").first() is None
