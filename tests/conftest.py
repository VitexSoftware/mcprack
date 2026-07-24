import pytest

from app import create_app
from config import Config
from extensions import db as _db


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    WTF_CSRF_ENABLED = False
    BW_SERVER = "https://vault.example.test"
    BW_CLIENTID = "test-client-id"
    BW_CLIENTSECRET = "test-client-secret"
    BW_PASSWORD = "test-master-password"
    BITWARDENCLI_APPDATA_DIR = "/tmp/mcprack-test-bw"


@pytest.fixture
def app():
    application = create_app(TestConfig)
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
