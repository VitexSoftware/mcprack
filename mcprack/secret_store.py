"""Single source-of-truth switch between Vaultwarden and a local encrypted
fallback store for MCP server secrets.

Design:
- A server's *secret* keys (declared via env_var_names, plus auth_env_key for
  network servers) are the only things that ever touch Vaultwarden or the
  local encrypted fallback. Everything else (server.env_config) is plain
  config and lives directly in the app DB — no Vaultwarden round-trip.
- Which backend is authoritative is decided purely by configuration, not by
  live reachability: BW_SERVER set -> Vaultwarden is the source of truth,
  and an unreachable Vaultwarden is a hard error (no silent fallback to the
  local store on an unplanned outage). BW_SERVER unset -> the local
  Fernet-encrypted column is the source of truth.
- A server with no declared secret keys never touches either backend.
- Switching between the two modes is a deliberate admin action
  (migrate_local_to_vaultwarden / snapshot_vaultwarden_to_local), never an
  automatic fallback.
"""

import base64
import functools
import hashlib
import hmac
import json

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from . import vaultwarden

_KEY_SALT = b"mcprack-secret-storage-v1"

# Shared with app.py's startup guard - the one literal string that means
# "nobody has set a real SECRET_KEY yet" everywhere it's checked.
INSECURE_DEFAULT_SECRET_KEY = "dev-insecure-secret-change-me"


class SecretStoreError(RuntimeError):
    pass


def is_vaultwarden_configured():
    return bool(current_app.config.get("BW_SERVER"))


@functools.lru_cache(maxsize=4)
def _fernet_for_key(secret_key):
    derived = hmac.new(secret_key.encode(), _KEY_SALT, hashlib.sha256).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def _fernet():
    secret_key = current_app.config.get("SECRET_KEY", "")
    if not secret_key or secret_key == INSECURE_DEFAULT_SECRET_KEY:
        raise SecretStoreError(
            "Cannot use local encrypted secret storage: SECRET_KEY is unset or still the "
            "insecure default ('dev-insecure-secret-change-me'). Set a real SECRET_KEY in "
            "/etc/mcprack/env first."
        )
    return _fernet_for_key(secret_key)


def _encrypt(values):
    payload = json.dumps(values or {}).encode()
    return _fernet().encrypt(payload).decode()


def _decrypt(blob):
    if not blob:
        return {}
    try:
        raw = _fernet().decrypt(blob.encode())
    except InvalidToken as exc:
        raise SecretStoreError(
            "Locally stored secrets could not be decrypted (SECRET_KEY changed since they "
            "were saved?)."
        ) from exc
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def server_needs_secrets(server):
    """Whether this server has any declared secret keys at all. If not,
    neither Vaultwarden nor the local encrypted store is ever touched."""
    if server.env_var_names:
        return True
    if server.url and server.auth_env_key:
        return True
    return False


def resolve_server_env(server, user=None):
    """Non-secret config (server.env_config) merged with resolved secrets
    (server default, then the user's personal override on top). The single
    entry point callers should use instead of touching vaultwarden.py or the
    local encrypted columns directly."""
    env = dict(server.env_config or {})

    if not server_needs_secrets(server):
        return env

    if is_vaultwarden_configured():
        with vaultwarden.session() as sess:
            env.update(vaultwarden.resolve_env(sess, server, user=user))
        return env

    env.update(_decrypt(server.env_secrets_encrypted))
    if user is not None:
        from .models import UserServerOverride

        override_row = UserServerOverride.query.filter_by(
            user_id=user.id, server_id=server.id
        ).first()
        if override_row:
            env.update(_decrypt(override_row.env_secrets_encrypted))
    return env


def load_server_secrets(server):
    """The admin-default secret values for a server, from whichever backend
    is currently authoritative."""
    if not server_needs_secrets(server) and not server.env_secrets_encrypted:
        return {}
    if is_vaultwarden_configured():
        with vaultwarden.session() as sess:
            return vaultwarden.get_notes(sess, server.vault_item)
    return _decrypt(server.env_secrets_encrypted)


def save_server_secrets(server, values):
    """Save the admin-default secret values for a server."""
    if is_vaultwarden_configured():
        with vaultwarden.session() as sess:
            vaultwarden.set_notes(sess, server.vault_item, values)
        server.env_secrets_encrypted = None
    else:
        server.env_secrets_encrypted = _encrypt(values) if values else None


def load_user_override_secrets(server, user):
    from .models import UserServerOverride

    override_row = UserServerOverride.query.filter_by(
        user_id=user.id, server_id=server.id
    ).first()
    if not override_row:
        return {}
    if is_vaultwarden_configured():
        override_item = f"{server.vault_item}-user-{user.username}"
        with vaultwarden.session() as sess:
            return vaultwarden.get_notes(sess, override_item)
    return _decrypt(override_row.env_secrets_encrypted)


def save_user_override_secrets(server, user, values):
    from .extensions import db
    from .models import UserServerOverride

    override_row = UserServerOverride.query.filter_by(
        user_id=user.id, server_id=server.id
    ).first()

    if is_vaultwarden_configured():
        override_item = f"{server.vault_item}-user-{user.username}"
        with vaultwarden.session() as sess:
            vaultwarden.set_notes(sess, override_item, values)
        if not override_row:
            override_row = UserServerOverride(user_id=user.id, server_id=server.id)
            db.session.add(override_row)
        override_row.env_secrets_encrypted = None
    else:
        if not override_row:
            override_row = UserServerOverride(user_id=user.id, server_id=server.id)
            db.session.add(override_row)
        override_row.env_secrets_encrypted = _encrypt(values)


def delete_user_override_secrets(server, user):
    from .extensions import db
    from .models import UserServerOverride

    if is_vaultwarden_configured():
        override_item = f"{server.vault_item}-user-{user.username}"
        with vaultwarden.session() as sess:
            vaultwarden.delete_item(sess, override_item)

    override_row = UserServerOverride.query.filter_by(
        user_id=user.id, server_id=server.id
    ).first()
    if override_row:
        db.session.delete(override_row)


# --- Migration actions ------------------------------------------------------


def migrate_local_to_vaultwarden():
    """Move everything currently stored in the local encrypted fallback into
    Vaultwarden. Call this once Vaultwarden has been newly configured and is
    reachable — each write is verified before the local copy is cleared, so
    a failure on one server never loses data. Returns
    {"moved": [label, ...], "failed": [(label, error), ...]}."""
    from .extensions import db
    from .models import McpServer, UserServerOverride

    if not is_vaultwarden_configured():
        raise SecretStoreError("Vaultwarden is not configured — nothing to migrate to.")

    moved, failed = [], []
    with vaultwarden.session() as sess:
        for server in McpServer.query.filter(
            McpServer.env_secrets_encrypted.isnot(None)
        ).all():
            label = f"server '{server.name}' defaults"
            try:
                values = _decrypt(server.env_secrets_encrypted)
                vaultwarden.set_notes(sess, server.vault_item, values)
                server.env_secrets_encrypted = None
                moved.append(label)
            except (vaultwarden.VaultwardenError, SecretStoreError) as exc:
                failed.append((label, str(exc)))

        for row in UserServerOverride.query.filter(
            UserServerOverride.env_secrets_encrypted.isnot(None)
        ).all():
            server = row.server
            label = f"'{server.name}' override for user #{row.user_id}"
            try:
                values = _decrypt(row.env_secrets_encrypted)
                override_item = f"{server.vault_item}-user-{row.user.username}"
                vaultwarden.set_notes(sess, override_item, values)
                row.env_secrets_encrypted = None
                moved.append(label)
            except (vaultwarden.VaultwardenError, SecretStoreError) as exc:
                failed.append((label, str(exc)))

    db.session.commit()
    return {"moved": moved, "failed": failed}


def snapshot_vaultwarden_to_local():
    """Copy everything currently in Vaultwarden into the local encrypted
    store, WITHOUT touching Vaultwarden's copy — preparation for a planned
    Vaultwarden outage. Vaultwarden stays the source of truth until the
    admin deliberately unsets BW_SERVER. Returns
    {"copied": [label, ...], "failed": [(label, error), ...]}."""
    from .extensions import db
    from .models import McpServer, UserServerOverride

    if not is_vaultwarden_configured():
        raise SecretStoreError("Vaultwarden is not configured — nothing to snapshot from.")

    copied, failed = [], []
    with vaultwarden.session() as sess:
        for server in McpServer.query.all():
            if not server_needs_secrets(server):
                continue
            label = f"server '{server.name}' defaults"
            try:
                values = vaultwarden.get_notes(sess, server.vault_item)
                server.env_secrets_encrypted = _encrypt(values) if values else None
                copied.append(label)
            except (vaultwarden.VaultwardenError, SecretStoreError) as exc:
                failed.append((label, str(exc)))

        for row in UserServerOverride.query.all():
            server = row.server
            label = f"'{server.name}' override for user #{row.user_id}"
            try:
                override_item = f"{server.vault_item}-user-{row.user.username}"
                values = vaultwarden.get_notes(sess, override_item)
                row.env_secrets_encrypted = _encrypt(values) if values else None
                copied.append(label)
            except (vaultwarden.VaultwardenError, SecretStoreError) as exc:
                failed.append((label, str(exc)))

    db.session.commit()
    return {"copied": copied, "failed": failed}
