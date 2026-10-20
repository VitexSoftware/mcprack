import hashlib
from datetime import datetime, timezone

from flask import g

from .extensions import db, login_manager
from .models import ApiToken, User


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
    if token is None or token.is_revoked or token.is_expired:
        return None

    user = db.session.get(User, token.user_id)
    if user is None or not user.is_active:
        return None

    g.api_token = token
    token.last_used_at = datetime.now(timezone.utc)
    db.session.commit()
    return user
