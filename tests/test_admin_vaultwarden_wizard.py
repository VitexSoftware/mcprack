from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_wizard_renders_steps_in_order(app, client):
    _login_admin(client)

    fake_steps = [
        {"key": "bw_binary", "label": "bw CLI is installed", "status": "ok", "detail": "Found at /usr/bin/bw."},
        {"key": "bw_server_set", "label": "BW_SERVER is configured", "status": "ok", "detail": "Set to https://x."},
        {"key": "bw_server_reachable", "label": "Vaultwarden server is reachable", "status": "fail", "detail": "Could not connect."},
        {"key": "bw_api_key_set", "label": "BW_CLIENTID / BW_CLIENTSECRET are configured", "status": "skipped", "detail": "Not checked — fix the step above first."},
    ]

    with patch("mcprack.admin.vaultwarden.diagnose", return_value=fake_steps):
        resp = client.get("/admin/vaultwarden/wizard")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Vaultwarden connection wizard" in body
    assert "wizard-ok" in body
    assert "wizard-fail" in body
    assert "wizard-skipped" in body
    assert "Could not connect." in body
    # order preserved: reachable failure appears before the skipped step after it
    assert body.index("Vaultwarden server is reachable") < body.index("BW_CLIENTID / BW_CLIENTSECRET")


def test_wizard_requires_admin(app, client):
    with app.app_context():
        user = User(username="regular", auth_type="local", is_admin=False)
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "regular", "password": "pw"})

    resp = client.get("/admin/vaultwarden/wizard")
    assert resp.status_code == 403


def test_wizard_shows_success_message_when_all_ok(app, client):
    _login_admin(client)

    fake_steps = [{"key": "bw_unlock", "label": "Vault unlocks with BW_PASSWORD", "status": "ok", "detail": "Vault unlocked successfully."}]

    with patch("mcprack.admin.vaultwarden.diagnose", return_value=fake_steps):
        resp = client.get("/admin/vaultwarden/wizard")

    assert b"All checks passed" in resp.data
