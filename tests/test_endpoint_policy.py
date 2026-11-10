"""B-09 (docs/AUDIT-2026-11.md): backend URLs an administrator may register."""

import pytest

from mcprack import admin, endpoint_policy
from mcprack.extensions import db
from mcprack.models import McpServer, User

PW = "admin-long-password-1"


@pytest.fixture
def in_app(app):
    with app.test_request_context():
        yield app


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/mcp",
        "http://10.1.2.3:3108/mcp",
        "http://localhost:8080/mcp",
        "http://127.0.0.1:35001/mcp",
        "https://[2001:db8::1]/mcp",
        "http://zabbix.internal.lan/mcp",
    ],
)
def test_ordinary_backends_are_accepted(in_app, url):
    assert endpoint_policy.url_errors(url) == []


@pytest.mark.parametrize(
    "url,fragment",
    [
        ("http://169.254.169.254/latest/meta-data/", "Link-local"),
        ("http://169.254.0.7:80/x", "Link-local"),
        ("http://[fe80::1]/x", "Link-local"),
        ("http://[::ffff:169.254.169.254]/x", "Link-local"),
        ("http://metadata.google.internal/computeMetadata/v1/", "metadata"),
        ("http://METADATA.GOOGLE.INTERNAL./x", "metadata"),
        ("http://0.0.0.0:8000/x", "0.0.0.0"),
        ("http://[::]/x", "0.0.0.0"),
        ("http://224.0.0.1/x", "Multicast"),
        ("file:///etc/passwd", "http://"),
        ("ftp://host/x", "http://"),
        ("gopher://host/x", "http://"),
        ("http://user:pw@host.example/x", "credentials"),
        ("http://user@host.example/x", "credentials"),
        ("http:///nohost", "no host"),
        ("http://host:notaport/x", "not valid"),
    ],
)
def test_wrong_destinations_are_refused(in_app, url, fragment):
    errors = endpoint_policy.url_errors(url)

    assert errors and any(fragment.lower() in error.lower() for error in errors), (url, errors)


def test_the_credentials_themselves_are_not_echoed(in_app):
    assert "hunter2" not in " ".join(endpoint_policy.url_errors("http://admin:hunter2@host.example/x"))


def test_link_local_can_be_allowed_explicitly(in_app):
    in_app.config["BACKEND_ALLOW_LINK_LOCAL"] = True

    assert endpoint_policy.url_errors("http://169.254.10.10/mcp") == []


def test_no_url_is_not_this_modules_business(in_app):
    assert endpoint_policy.url_errors(None) == [] and endpoint_policy.url_errors("") == []


def test_the_server_validator_uses_it(in_app):
    errors, _ = admin.validate_server_endpoint("http", None, "http://169.254.169.254/latest/")

    assert any("Link-local" in error for error in errors)


# --- through both doors: the admin form and the REST API --------------------------------------


def _admin(client, app):
    with app.app_context():
        user = User(username="root", auth_type="local", is_admin=True)
        user.set_password(PW)
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "root", "password": PW})


def test_the_api_refuses_a_metadata_url(app, client):
    _admin(client, app)

    response = client.post("/api/v1/admin/servers", json={
        "name": "meta", "label": "Meta", "transport": "http", "url": "http://169.254.169.254/latest/", "enabled": True,
    })

    assert response.status_code in (400, 422)
    with app.app_context():
        assert McpServer.query.filter_by(name="meta").first() is None


def test_the_api_still_accepts_an_ordinary_backend(app, client):
    _admin(client, app)

    response = client.post("/api/v1/admin/servers", json={
        "name": "fine", "label": "Fine", "transport": "http", "url": "http://10.1.2.3:3108/mcp", "enabled": True,
    })

    assert response.status_code == 201, response.get_json()
