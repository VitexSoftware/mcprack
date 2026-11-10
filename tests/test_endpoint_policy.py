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


@pytest.mark.parametrize(
    "url",
    [
        "http://2852039166/latest/meta-data/",  # decimal
        "http://0xa9fea9fe/",  # hex
        "http://0251.0376.0251.0376/",  # octal parts
        "http://0xA9.0xFE.0xA9.0xFE/",
        "http://169.254.43518/",  # 3-part
        "http://169.254.169.254./",  # trailing dot
        "http://0xA9FEA9FE:8080/x",
    ],
)
def test_numeric_spellings_of_a_metadata_address_are_the_same_address(in_app, url):
    """The resolver reads these as 169.254.169.254; ipaddress.ip_address() does
    not, so a check that only asked it would have waved them through."""
    errors = endpoint_policy.url_errors(url)

    assert any("Link-local" in error for error in errors), (url, errors)


@pytest.mark.parametrize(
    "url", ["http://127.1:8080/mcp", "http://010.0.0.1/mcp", "http://0x7f.1/mcp", "http://cafe.example/mcp", "http://deadbeef.lan/mcp"]
)
def test_legacy_spellings_of_harmless_addresses_and_names_that_look_hexish_are_fine(in_app, url):
    assert endpoint_policy.url_errors(url) == [], url


@pytest.mark.parametrize("url", ["http://999.1.1.1/x", "http://1.2.3.4.5/x", "http://0xzz/x"])
def test_a_numeric_looking_non_address_is_rejected_or_treated_as_a_name(in_app, url):
    """999.1.1.1 is numeric in form but no address - refuse it rather than guess
    what some resolver would make of it. (A dotted name such as 1.2.3.4.5 or
    0xzz is not numeric-shaped and is just a host name.)"""
    errors = endpoint_policy.url_errors(url)

    if url == "http://999.1.1.1/x":
        assert any("numeric address" in error for error in errors)
    else:
        assert errors == []


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


# --- the destination is checked again when the relay connects ---------------------------------


def _legacy_server(app, url):
    """A server that was saved before the policy existed."""
    from mcprack.models import UserServerSelection

    with app.app_context():
        user = User(username="frank", auth_type="local")
        user.set_password("frank-long-password-1")
        server = McpServer(name="legacy", label="L", transport="http", url=url, enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        from mcprack import catalog
        return catalog._make_proxy_token(user.id, server.id), server.id


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/", "http://2852039166/", "http://metadata.google.internal/x"])
def test_the_relay_refuses_a_stored_metadata_url_without_connecting(app, client, url):
    from unittest.mock import patch

    token, server_id = _legacy_server(app, url)

    with patch("mcprack.catalog.http.client.HTTPConnection") as connection:
        response = client.post(f"/proxy/mcp/{token}/{server_id}", json={"jsonrpc": "2.0", "id": 7, "method": "ping"})

    connection.assert_not_called()
    assert response.status_code == 502
    assert "not allowed" in response.get_data(as_text=True)
    assert "169.254" not in response.get_data(as_text=True)  # the address is not echoed to the client


def test_a_stored_url_with_credentials_still_relays(app, client):
    """Registration refuses credentials in a URL; a server that already has one
    keeps working - the relay only enforces the destination."""
    from unittest.mock import patch

    token, server_id = _legacy_server(app, "http://user:pw@10.1.2.3:3108/mcp")

    with patch("mcprack.catalog.http.client.HTTPConnection") as connection:
        connection.return_value.getresponse.return_value.status = 200
        connection.return_value.getresponse.return_value.read.return_value = b"{}"
        connection.return_value.getresponse.return_value.getheaders.return_value = []
        client.post(f"/proxy/mcp/{token}/{server_id}", json={"jsonrpc": "2.0", "id": 7, "method": "ping"})

    connection.assert_called_once()
