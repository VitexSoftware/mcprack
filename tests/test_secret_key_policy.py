"""B-16 (docs/AUDIT-2026-11.md): SECRET_KEY quality and rotation.

The startup guard rejected only the literal default, so `change-me` (from
.env.example) or `change-me-<epoch>` passed; and rotating the key destroyed
the locally encrypted secrets and invalidated every proxy URL. Now weak keys
are refused and old keys can stay valid for verification/decryption through
SECRET_KEY_FALLBACKS."""

import pytest

from mcprack import catalog, secret_store
from mcprack.app import create_app
from mcprack.config import Config

GOOD = "k" * 8 + "7f3a9c1e5b2d4f60a8e1c3d5b7f90246"


class ProdConfig(Config):
    TESTING = False
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    BW_SERVER = ""


def _app(key, **extra):
    attrs = dict(SECRET_KEY=key)
    attrs.update(extra)
    return create_app(type("C", (ProdConfig,), attrs))


@pytest.mark.parametrize(
    "key",
    [
        "",
        "dev-insecure-secret-change-me",
        "change-me",
        "change-me-1699999999",
        "CHANGEME",
        "secret",
        "password",
        "short-but-random-1a2b",  # < 32 characters
        "a" * 40,  # one repeated character
    ],
)
def test_weak_keys_refuse_to_start(key):
    with pytest.raises(RuntimeError):
        _app(key)


def test_a_strong_key_starts():
    assert _app(GOOD) is not None


def test_testing_mode_skips_the_guard():
    class T(ProdConfig):
        TESTING = True
        SECRET_KEY = "test-secret"

    assert create_app(T) is not None


# --- rotation ------------------------------------------------------------------


OLD = "0ld7f3a9c1e5b2d4f60a8e1c3d5b7f90246abcd"
NEW = "n3w7f3a9c1e5b2d4f60a8e1c3d5b7f90246abcd"


def test_fallbacks_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("SECRET_KEY_FALLBACKS", f"{OLD}, another-old-key-0123456789abcdef0123")
    import subprocess, sys

    out = subprocess.run(
        [sys.executable, "-I", "-c", "from mcprack.config import Config; print(Config.SECRET_KEY_FALLBACKS)"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "SECRET_KEY_FALLBACKS": f"{OLD}, other-key"},
    )
    assert OLD in out.stdout and "other-key" in out.stdout, out.stderr


def test_proxy_tokens_survive_a_key_rotation():
    old_app = _app(OLD)
    with old_app.app_context():
        token = catalog._proxy_serializer().dumps({"u": 1, "s": 2, "v": 3})

    new_app = _app(NEW, SECRET_KEY_FALLBACKS=[OLD])
    with new_app.app_context():
        assert catalog._parse_proxy_token(token) == {"u": 1, "s": 2, "v": 3}
        fresh = catalog._proxy_serializer().dumps({"u": 1})
    # new tokens are signed with the NEW key only
    with _app(NEW).app_context():
        assert catalog._parse_proxy_token(fresh) == {"u": 1}
    with _app(OLD).app_context():
        assert catalog._parse_proxy_token(fresh) is None


def test_a_rotation_without_fallbacks_rejects_old_tokens():
    with _app(OLD).app_context():
        token = catalog._proxy_serializer().dumps({"u": 1, "s": 2})

    with _app(NEW).app_context():
        assert catalog._parse_proxy_token(token) is None


def test_locally_encrypted_secrets_survive_a_key_rotation():
    with _app(OLD).app_context():
        blob = secret_store._encrypt({"API_TOKEN": "s3cret"})

    with _app(NEW, SECRET_KEY_FALLBACKS=[OLD]).app_context():
        assert secret_store._decrypt(blob) == {"API_TOKEN": "s3cret"}
        # new writes use the new key
        new_blob = secret_store._encrypt({"A": "b"})
    with _app(NEW).app_context():
        assert secret_store._decrypt(new_blob) == {"A": "b"}


def test_sessions_survive_a_key_rotation(monkeypatch):
    from flask.sessions import SecureCookieSessionInterface

    old_app = _app(OLD)
    with old_app.test_request_context():
        serializer = SecureCookieSessionInterface().get_signing_serializer(old_app)
        cookie = serializer.dumps({"hello": "world"})

    new_app = _app(NEW, SECRET_KEY_FALLBACKS=[OLD])
    with new_app.test_request_context():
        serializer = SecureCookieSessionInterface().get_signing_serializer(new_app)
        assert serializer.loads(cookie) == {"hello": "world"}
