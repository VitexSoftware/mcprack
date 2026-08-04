import hashlib
from datetime import datetime, timezone

from extensions import db, login_manager
from models import ApiToken, User


@login_manager.request_loader
def load_user_from_bearer_token(request):
    """flask_login falls back to this when there's no valid session cookie,
    so @login_required/@admin_required work unmodified for bearer-token
    requests too. Only mints a user for a live, unrevoked token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    raw = auth_header[len("Bearer "):].strip()
    if not raw:
        return None

    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    token = ApiToken.query.filter_by(token_hash=token_hash).first()
    if token is None or token.is_revoked:
        return None

    user = db.session.get(User, token.user_id)
    if user is None or not user.is_active:
        return None

    token.last_used_at = datetime.now(timezone.utc)
    db.session.commit()
    return user
