"""B-11 (docs/AUDIT-2026-11.md): LDAP traffic (user passwords, the bind
password) crossed the network in clear text, and nothing verified the
directory's certificate. ldaps:// and StartTLS are supported with
certificate validation on; plain ldap:// still works (intranet opt-in) but
is flagged at startup."""

import logging
import os
import ssl
from unittest.mock import MagicMock, patch

import ldap3
import pytest

from mcprack import auth
from mcprack.app import create_app

from conftest import TestConfig


def _config(**kw):
    attrs = dict(LDAP_ENABLED=True, LDAP_SERVER="ldap://dc.example.test:389", LDAP_BIND_DN="CN=svc,DC=x", LDAP_BIND_PASSWORD="pw")
    attrs.update(kw)
    return type("C", (TestConfig,), attrs)


def _run(app):
    """Run one authentication with ldap3 stubbed; returns (Server kwargs list, Connection kwargs list)."""
    entry = MagicMock()
    entry.entry_dn = "CN=Carol,DC=x"
    entry.__contains__ = lambda self, name: False
    search = MagicMock()
    search.__enter__.return_value = search
    search.__exit__.return_value = False
    search.entries = [entry]
    bind = MagicMock()
    bind.__enter__.return_value = bind
    bind.__exit__.return_value = False

    servers, conns = [], []

    def fake_server(host, **kwargs):
        servers.append((host, kwargs))
        return MagicMock()

    def fake_conn(server, user=None, password=None, auto_bind=None):
        conns.append({"user": user, "auto_bind": auto_bind})
        return bind if user == entry.entry_dn else search

    with app.app_context(), patch("mcprack.auth.ldap3.Server", side_effect=fake_server), \
            patch("mcprack.auth.ldap3.Connection", side_effect=fake_conn):
        auth._ldap_authenticate("carol", "correct-ad-password")
    return servers, conns


def test_plain_ldap_keeps_working_unchanged():
    servers, conns = _run(create_app(_config()))

    assert "tls" not in servers[0][1] or servers[0][1]["tls"] is None
    assert all(c["auto_bind"] is True for c in conns)


CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


@pytest.mark.skipif(not os.path.exists(CA_BUNDLE), reason="no system CA bundle to point at")
def test_ldaps_validates_the_certificate_by_default():
    app = create_app(_config(LDAP_SERVER="ldaps://dc.example.test:636", LDAP_CA_FILE=CA_BUNDLE))

    servers, conns = _run(app)

    tls = servers[0][1]["tls"]
    assert tls.validate == ssl.CERT_REQUIRED
    assert tls.ca_certs_file == CA_BUNDLE
    assert all(c["auto_bind"] is True for c in conns)


def test_starttls_upgrades_every_connection_before_binding():
    app = create_app(_config(LDAP_STARTTLS=True))

    servers, conns = _run(app)

    assert servers[0][1]["tls"].validate == ssl.CERT_REQUIRED
    assert {c["auto_bind"] for c in conns} == {ldap3.AUTO_BIND_TLS_BEFORE_BIND}


def test_validation_can_be_switched_off_explicitly_for_a_lab():
    app = create_app(_config(LDAP_SERVER="ldaps://dc.example.test:636", LDAP_TLS_VALIDATE=False))

    servers, _ = _run(app)

    assert servers[0][1]["tls"].validate == ssl.CERT_NONE


def test_plain_ldap_is_flagged_in_the_log_at_startup(caplog):
    with caplog.at_level(logging.WARNING):
        create_app(_config())

    assert any("unencrypted" in r.getMessage() and "LDAP" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("kw", [dict(LDAP_SERVER="ldaps://dc.example.test:636"), dict(LDAP_STARTTLS=True), dict(LDAP_ENABLED=False)])
def test_no_warning_when_tls_is_used_or_ldap_is_off(caplog, kw):
    with caplog.at_level(logging.WARNING):
        create_app(_config(**kw))

    assert not any("unencrypted" in r.getMessage() for r in caplog.records)
