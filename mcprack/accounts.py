"""Taking a user's access away (docs/AUDIT-2026-11.md A-03).

Disabling or deleting an account must also end what the account can do
without a browser session: its MCP proxy path tokens, API tokens, OAuth
tokens and the MCP server processes already running on its behalf.
"""

import logging
import time

from . import user_proxy
from .models import new_token_version

logger = logging.getLogger(__name__)


def revoke_tokens(user):
    """Invalidate every credential `user` holds for programmatic access:
    proxy path tokens (version bump), API tokens and OAuth tokens. Does not
    commit; the caller does."""
    from .models import ApiToken, OAuthToken
    from datetime import datetime, timezone

    user.token_version = new_token_version(user.token_version)
    user.session_version = new_token_version(user.session_version)

    now = datetime.now(timezone.utc)
    for token in ApiToken.query.filter_by(user_id=user.id, revoked_at=None).all():
        token.revoked_at = now

    stamp = int(time.time())
    for token in OAuthToken.query.filter_by(user_id=user.id).all():
        if not token.access_token_revoked_at:
            token.access_token_revoked_at = stamp
        if not token.refresh_token_revoked_at:
            token.refresh_token_revoked_at = stamp


def invalidate_sessions(user, keep_current=False):
    """Kill every browser session of `user` (their cookies stop working). With
    keep_current the session making this request stays logged in, e.g. when
    the user changes their own password. Does not commit."""
    user.session_version = new_token_version(user.session_version)
    if keep_current:
        from flask import has_request_context, session

        if has_request_context():
            session["sv"] = user.session_version


def stop_processes(user):
    """Stop the MCP server processes running for `user` and drop their state
    (credentials included). Never raises: ending access must not fail halfway
    because one process refused to die."""
    try:
        from . import composition_proxy

        composition_proxy.stop_user_composition(user.id)
    except Exception:
        logger.exception("could not stop the MCP composition of user %s", user.id)
    try:
        user_proxy.stop_user_proxies(user.id)
    except Exception:
        logger.exception("could not stop the MCP proxies of user %s", user.id)
