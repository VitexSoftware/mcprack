import hashlib
from datetime import datetime, timezone

from flask import g

from .extensions import db, login_manager
from .models import (
    ApiToken,
    OAUTH_ADMIN_READ_SCOPE,
    OAUTH_ADMIN_WRITE_SCOPE,
    OAUTH_MANAGE_SCOPE,
    OAUTH_MCP_SCOPE,
    OAUTH_READ_SCOPE,
    User,
)


class OAuthApiGrant:
    """Adapter exposing an OAuth management token through the API token
    scope check without converting or copying its credential into the DB."""

    def __init__(self, scopes):
        granted = set()
        if OAUTH_MCP_SCOPE in scopes:
            granted.add("proxy:access")
        if OAUTH_READ_SCOPE in scopes:
            granted.update(("profile:read", "servers:read", "config:read"))
        if OAUTH_MANAGE_SCOPE in scopes:
            granted.update(
                (
                    "profile:read",
                    "servers:read",
                    "selections:manage",
                    "overrides:manage",
                    "config:read",
                )
            )
        if OAUTH_ADMIN_READ_SCOPE in scopes:
            granted.add("admin:read")
        if OAUTH_ADMIN_WRITE_SCOPE in scopes:
            granted.add("admin:write")
        self.scope_list = sorted(granted)

    def allows_any(self, required_scopes):
        return any(scope in self.scope_list for scope in required_scopes)


@login_manager.request_loader
def load_user_from_bearer_token(request):
    """flask_login falls back to this when there's no valid session cookie,
    so @login_required/@admin_required work unmodified for bearer-token
    requests too. Only mints a user for a live, unrevoked, unexpired token.
    The resolved token is stashed on flask.g so api.api_scope_required can
    enforce its scope restriction for the rest of the request."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    raw = auth_header[len("Bearer "):].strip()
    if not raw:
        return None

    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    token = ApiToken.query.filter_by(token_hash=token_hash).first()
    if token is not None and not token.is_revoked and not token.is_expired:
        user = db.session.get(User, token.user_id)
        if user is None or not user.is_active:
            return None
        g.api_token = token
        token.last_used_at = datetime.now(timezone.utc)
        db.session.commit()
        return user

    from .oauth import resolve_oauth_management_token

    user, scopes = resolve_oauth_management_token(raw)
    if user is None:
        return None
    g.api_token = OAuthApiGrant(scopes)
    return user
