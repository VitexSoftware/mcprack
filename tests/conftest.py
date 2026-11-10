import pytest

from mcprack import installer
from mcprack import user_proxy
from mcprack.app import create_app
from mcprack.config import Config
from mcprack.extensions import db as _db


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    # The existing suite uses free-form override keys (REGION, CUSTOM, ...);
    # tests of the production default ("credentials") set it explicitly.
    OVERRIDE_UNDECLARED_KEYS = "any"
    # The existing suite predates the fail-closed default and relies on users
    # seeing every enabled server; tests of the production default and of
    # strict behaviour set it explicitly (tests/test_strict_server_permissions.py).
    STRICT_SERVER_PERMISSIONS = False
    BW_SERVER = "https://vault.example.test"
    BW_CLIENTID = "test-client-id"
    BW_CLIENTSECRET = "test-client-secret"
    BW_PASSWORD = "test-master-password"
    BITWARDENCLI_APPDATA_DIR = "/tmp/mcprack-test-bw"


@pytest.fixture(scope="session", autouse=True)
def _compile_translations():
    import subprocess
    subprocess.run(["pybabel", "compile", "-d", "mcprack/translations"])


@pytest.fixture(autouse=True)
def _isolate_user_proxy_state(tmp_path, monkeypatch):
    """Every test gets its own scratch user-proxy state dir, never the real
    /var/lib/mcprack/user-proxies — which may hold live state from an
    actually-installed instance on the machine running the tests."""
    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")
    monkeypatch.setattr(installer, "STATE_DIR", tmp_path / "installs")


@pytest.fixture
def app(tmp_path):
    application = create_app(TestConfig)

    # The fixture below keeps one outer app context open for the whole test,
    # and Flask reuses an already-pushed app context for test-client
    # requests - so flask.g, and with it Flask-Login's cached `_login_user`
    # and the resolved API token, would leak from one request (or client) to
    # the next and make a logged-out request look authenticated. Real
    # requests each get their own g; reproduce that.
    @application.before_request
    def _isolate_request_globals():
        from flask import g

        for attr in ("_login_user", "api_token"):
            g.pop(attr, None)

    # Isolated per test - secret_store's shared env-cache file and
    # vaultwarden's lock file both live here, and a fixed shared path would
    # leak cached secrets between otherwise-independent tests.
    application.config["BITWARDENCLI_APPDATA_DIR"] = str(tmp_path / "bw")
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
