import pytest

from mcprack.app import create_app
from mcprack.config import Config
from mcprack.secret_store import INSECURE_DEFAULT_SECRET_KEY


class InsecureProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # SECRET_KEY intentionally left at Config's insecure default.
    # DEBUG/TESTING intentionally left at Config's defaults (both False).


class InsecureButTestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # SECRET_KEY intentionally left at Config's insecure default.


class SecureProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "a-real-randomly-generated-secret"


def test_refuses_to_start_with_insecure_default_secret_key_in_production():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(InsecureProductionConfig)


def test_allows_insecure_default_secret_key_under_testing():
    application = create_app(InsecureButTestingConfig)
    assert application.config["SECRET_KEY"] == INSECURE_DEFAULT_SECRET_KEY


def test_allows_real_secret_key_in_production():
    application = create_app(SecureProductionConfig)
    assert application.config["SECRET_KEY"] == "a-real-randomly-generated-secret"
