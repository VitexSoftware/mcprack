"""Optional MCP OAuth 2.1 Authorization Server.

Enabled with OAUTH_ENABLED=true. Implements the discovery + registration +
authorize + token flow that MCP HTTP clients expect (RFC8414 AS metadata,
RFC9728 Protected Resource Metadata, RFC7591 Dynamic Client Registration,
authorization-code + PKCE + refresh_token), so a connector URL can be the
stable `/proxy/mcp/<server_id>` form without a signed path token.

Path-token URLs keep working either way; this only adds the Bearer path.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from urllib.parse import urlsplit

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc7591 import InvalidRedirectURIError
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint as _ClientRegistrationEndpoint
from authlib.oauth2.rfc7636 import CodeChallenge as _CodeChallenge
from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from . import audit, oauth_policy
from .extensions import csrf, db, limiter
from .models import (
    OAUTH_MCP_SCOPE,
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthToken,
    User,
)

bp = Blueprint("oauth", __name__)


class TemporarilyUnavailableError(OAuth2Error):
    """RFC 6749 section 4.1.2.1 temporary_unavailable, answered with 503."""

    error = "temporarily_unavailable"
    status_code = 503

authorization = AuthorizationServer()


def hash_token(raw):
    """What is stored for a token: its SHA-256. The tokens are random and long,
    so (as for API tokens) an unsalted hash is enough, and a database leak no
    longer hands out working credentials (docs/AUDIT-2026-11.md B-15)."""
    return hashlib.sha256(raw.encode()).hexdigest()


_HASH_SHAPE = re.compile(r"^\s*[0-9a-fA-F]{64}\s*$")


def _token_candidates(raw):
    """Values a presented token may be stored as: its hash, or - for tokens
    issued by the previous release, which stored them in clear text - itself.
    Legacy rows disappear as they expire. A value shaped like a SHA-256 is
    never tried as itself: otherwise somebody who can read the table could
    present a stored hash as if it were the token."""
    if _HASH_SHAPE.match(raw):
        return [hash_token(raw)]
    return [hash_token(raw), raw]


def _stored_value_matches(stored, raw):
    """Whether the column value `stored` is the hash of `raw` - or, for a
    legacy row, `raw` itself - compared EXACTLY. The database lookup may be
    looser than that (MySQL collations ignore case and trailing blanks), so
    its answer is double-checked here."""
    if not stored:
        return False
    if hmac.compare_digest(stored.encode(), hash_token(raw).encode()):
        return True
    return not _HASH_SHAPE.match(raw) and hmac.compare_digest(stored.encode(), raw.encode())


def _find_token(raw, hint=None):
    candidates = _token_candidates(raw)
    if hint != "refresh_token":
        for row in OAuthToken.query.filter(OAuthToken.access_token.in_(candidates)).all():
            if _stored_value_matches(row.access_token, raw):
                return row
    if hint != "access_token":
        for row in OAuthToken.query.filter(OAuthToken.refresh_token.in_(candidates)).all():
            if _stored_value_matches(row.refresh_token, raw):
                return row
    return None


def _refresh_token_expired(token):
    lifetime = int(current_app.config.get("OAUTH_REFRESH_TOKEN_EXPIRES", 30 * 86400))
    return (token.issued_at or 0) + lifetime < time.time()


def _public_base_url():
    """Issuer / resource base. Prefer PUBLIC_BASE_URL so metadata stays
    stable behind a reverse proxy; fall back to the current request URL."""
    configured = (current_app.config.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if configured:
        return configured
    return request.url_root.rstrip("/")


def _issuer_url():
    return _public_base_url()


def init_oauth(app):
    """Wire AuthorizationServer into `app`. No-op when OAUTH_ENABLED is off
    so imports stay cheap and unused tables stay unused."""
    if not app.config.get("OAUTH_ENABLED"):
        return

    # authlib refuses non-HTTPS authorize/token URLs unless this is set.
    # Production sits behind TLS (ProxyFix + apache-mcprack.conf); tests and
    # plain-HTTP intranet demos need the escape hatch explicitly.
    if app.config.get("TESTING") or app.config.get("OAUTH_ALLOW_INSECURE_TRANSPORT"):
        import os

        os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")

    # These must be in place BEFORE authorization.init_app(): authlib reads the
    # token generators once, at init. They used to be set after it, so no
    # refresh token was ever issued and every client had to repeat the whole
    # browser authorization each hour (docs/AUDIT-2026-11.md B-15).
    app.config.setdefault(
        "OAUTH2_ACCESS_TOKEN_GENERATOR",
        True,  # use authlib's default random token generator
    )
    app.config.setdefault(
        "OAUTH2_REFRESH_TOKEN_GENERATOR",
        True,
    )
    app.config.setdefault(
        "OAUTH2_TOKEN_EXPIRES_IN",
        {
            "authorization_code": app.config["OAUTH_ACCESS_TOKEN_EXPIRES"],
            "refresh_token": app.config["OAUTH_ACCESS_TOKEN_EXPIRES"],
        },
    )

    query_client = create_query_client_func(db.session, OAuthClient)

    def save_token(token, request):
        """Store the token HASHED (the plaintext only ever goes back to the
        client in the response) and audit the issue."""
        user_id = request.user.get_user_id() if request.user else None
        stored = dict(token)
        stored["access_token"] = hash_token(stored["access_token"])
        if stored.get("refresh_token"):
            stored["refresh_token"] = hash_token(stored["refresh_token"])
        db.session.add(OAuthToken(client_id=request.client.client_id, user_id=user_id, **stored))
        db.session.commit()
        audit.log_audit_event(
            "oauth_token_issued", "success", user_id=user_id,
            error_message=f"client {request.client.client_name or request.client.client_id}"[:500],
        )

    authorization.init_app(app, query_client=query_client, save_token=save_token)

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

        def save_authorization_code(self, code, request):
            client = request.client
            auth_code = OAuthAuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.payload.redirect_uri,
                scope=request.scope or OAUTH_MCP_SCOPE,
                user_id=request.user.get_user_id(),
                code_challenge=request.payload.data.get("code_challenge"),
                code_challenge_method=request.payload.data.get("code_challenge_method"),
            )
            db.session.add(auth_code)
            db.session.commit()
            return auth_code

        def query_authorization_code(self, code, client):
            item = OAuthAuthorizationCode.query.filter_by(
                code=code, client_id=client.client_id
            ).first()
            if item and not item.is_expired():
                return item
            return None

        def delete_authorization_code(self, authorization_code):
            db.session.delete(authorization_code)
            db.session.commit()

        def authenticate_user(self, authorization_code):
            return db.session.get(User, authorization_code.user_id)

    class CodeChallenge(_CodeChallenge):
        # MCP / OAuth 2.1 require S256; keep plain out of the allow-list.
        SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
        INCLUDE_NEW_REFRESH_TOKEN = True

        def authenticate_refresh_token(self, refresh_token):
            item = _find_token(refresh_token, hint="refresh_token")
            # The refresh token has its OWN lifetime (OAUTH_REFRESH_TOKEN_EXPIRES).
            # is_expired() is the ACCESS token's, which made every refresh token
            # useless an hour after it was issued.
            if item and item.is_refresh_token_active() and not _refresh_token_expired(item):
                return item
            return None

        def authenticate_user(self, credential):
            return db.session.get(User, credential.user_id)

        def revoke_old_credential(self, credential):
            now = int(time.time())
            credential.access_token_revoked_at = now
            credential.refresh_token_revoked_at = now
            db.session.add(credential)
            db.session.commit()

    authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    authorization.register_grant(RefreshTokenGrant)
    from authlib.oauth2.rfc7009 import RevocationEndpoint

    class HashedRevocationEndpoint(RevocationEndpoint):
        # MCP clients are public clients (no secret); the default accepted
        # only client_secret_basic, so they could not revoke at all.
        CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

        def query_token(self, token, token_type_hint):
            return _find_token(token, hint=token_type_hint)

        def revoke_token(self, token, request):
            now = int(time.time())
            token.access_token_revoked_at = now
            if request.form.get("token_type_hint") != "access_token":
                token.refresh_token_revoked_at = now
            db.session.add(token)
            db.session.commit()

    authorization.register_endpoint(HashedRevocationEndpoint)

    class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):
        """Open Dynamic Client Registration — MCP clients have no prior
        relationship with the AS, so no initial_access_token is required."""

        def authenticate_token(self, request):
            return True

        def get_server_metadata(self):
            return {
                "issuer": _issuer_url(),
                "authorization_endpoint": f"{_issuer_url()}/oauth/authorize",
                "token_endpoint": f"{_issuer_url()}/oauth/token",
                "registration_endpoint": f"{_issuer_url()}/oauth/register",
                "revocation_endpoint": f"{_issuer_url()}/oauth/revoke",
                "scopes_supported": [OAUTH_MCP_SCOPE],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_basic",
                    "client_secret_post",
                ],
                "code_challenge_methods_supported": ["S256"],
            }

        def save_client(self, client_info, client_metadata, request):
            cfg = current_app.config
            metadata = dict(client_metadata or {})
            problem = oauth_policy.check_redirect_uris(metadata.get("redirect_uris"), cfg)
            if problem:
                raise InvalidRedirectURIError(description=problem)
            _make_room_for_a_client(cfg)
            # Default MCP-friendly metadata when the client omits fields.
            metadata.setdefault("scope", OAUTH_MCP_SCOPE)
            metadata.setdefault("grant_types", ["authorization_code", "refresh_token"])
            metadata.setdefault("response_types", ["code"])
            metadata.setdefault("token_endpoint_auth_method", "none")
            # Public clients (token_endpoint_auth_method=none) must not keep a
            # secret — authlib still generates one in client_info, discard it.
            info = dict(client_info)
            if metadata.get("token_endpoint_auth_method") == "none":
                info["client_secret"] = ""
            client = OAuthClient(user_id=None, **info)
            client.set_client_metadata(metadata)
            db.session.add(client)
            db.session.commit()
            audit.log_audit_event(
                "oauth_client_registered", "success",
                error_message=(
                    f"client '{(metadata.get('client_name') or '')[:80]}' redirect "
                    + ", ".join(urlsplit(u).netloc or u for u in metadata["redirect_uris"])
                )[:500],
            )
            return client

    authorization.register_endpoint(ClientRegistrationEndpoint)

    app.register_blueprint(bp)
    # token/register/revoke are called by MCP clients with no session cookie,
    # so CSRF has nothing to defend. The authorize consent form keeps CSRF
    # (it's a browser session POST that grants access to the user's MCP
    # servers — exactly the ambient-credential attack CSRF exists for).
    csrf.exempt(issue_token)
    csrf.exempt(register_client)
    csrf.exempt(revoke_token)


def _make_room_for_a_client(cfg):
    """Registration is open, so it is capped - but a cap that REFUSES would let
    anybody fill the table and lock every real client out. So: clients that
    never obtained a token are dropped once they are older than
    OAUTH_UNUSED_CLIENT_TTL_HOURS (a real client authorizes within minutes),
    and when the table is still full the OLDEST unused ones are evicted to make
    room. Only when every slot belongs to a client that holds a token is the
    registration refused."""
    now = int(time.time())
    ttl = int(cfg.get("OAUTH_UNUSED_CLIENT_TTL_HOURS", 24)) * 3600
    min_age = int(cfg.get("OAUTH_CLIENT_MIN_AGE_SECONDS", 900))
    # Authorization codes live five minutes (authlib: auth_time + 300). An
    # expired one proves nothing and must not keep its client in the table
    # for ever, so they are purged first.
    OAuthAuthorizationCode.query.filter(OAuthAuthorizationCode.auth_time < now - 300).delete(
        synchronize_session=False
    )
    # "unused": no token issued and no authorization code waiting to be
    # redeemed - a client in the middle of its browser flow is NOT unused.
    unused = ~OAuthClient.client_id.in_(db.session.query(OAuthToken.client_id).distinct()) & ~OAuthClient.client_id.in_(
        db.session.query(OAuthAuthorizationCode.client_id).distinct()
    )
    OAuthClient.query.filter(OAuthClient.client_id_issued_at < now - ttl, unused).delete(synchronize_session=False)
    limit = int(cfg.get("OAUTH_MAX_CLIENTS", 500))
    overflow = OAuthClient.query.count() - limit + 1
    if overflow > 0:
        # Only clients past a minimum age may be evicted, oldest first: a
        # client that registered a moment ago is about to authorize, and
        # whoever floods the table must not be able to cycle real clients out.
        victims = (
            OAuthClient.query.filter(unused, OAuthClient.client_id_issued_at < now - min_age)
            .order_by(OAuthClient.client_id_issued_at.asc())
            .limit(overflow)
            .all()
        )
        for client in victims:
            db.session.delete(client)
    db.session.commit()
    if OAuthClient.query.count() >= limit:
        raise TemporarilyUnavailableError(description="too many registered clients; try again later")


def oauth_unauthorized_response(server_id=None, resource_path=None):
    """401 + WWW-Authenticate pointing at Protected Resource Metadata, as
    required by MCP Authorization / RFC9728 §5.1."""
    base = _public_base_url()
    if resource_path is not None:
        metadata_url = f"{base}/.well-known/oauth-protected-resource{resource_path}"
    elif server_id is not None:
        metadata_url = f"{base}/.well-known/oauth-protected-resource/proxy/mcp/{server_id}"
    else:
        metadata_url = f"{base}/.well-known/oauth-protected-resource"
    response = jsonify({"error": "invalid_token", "error_description": "Bearer token required"})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = (
        f'Bearer realm="mcprack", resource_metadata="{metadata_url}", '
        f'scope="{OAUTH_MCP_SCOPE}"'
    )
    return response


def resolve_oauth_bearer_user(raw_token):
    """Validate an OAuth access token string; return the owning User or None."""
    token = _find_token(raw_token, hint="access_token")
    if token is None or token.is_revoked() or token.is_expired():
        return None
    scopes = set((token.scope or "").split())
    if scopes and OAUTH_MCP_SCOPE not in scopes:
        return None
    user = db.session.get(User, token.user_id) if token.user_id else None
    if user is None or not user.is_active:
        return None
    return user


# --- Discovery -------------------------------------------------------------


@bp.route("/.well-known/oauth-authorization-server")
def authorization_server_metadata():
    issuer = _issuer_url()
    return jsonify(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register",
            "revocation_endpoint": f"{issuer}/oauth/revoke",
            "scopes_supported": [OAUTH_MCP_SCOPE],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
            "service_documentation": "https://github.com/VitexSoftware/mcprack",
        }
    )


def _protected_resource_metadata(resource_url):
    issuer = _issuer_url()
    return jsonify(
        {
            "resource": resource_url,
            "authorization_servers": [issuer],
            "scopes_supported": [OAUTH_MCP_SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://github.com/VitexSoftware/mcprack",
        }
    )


@bp.route("/.well-known/oauth-protected-resource")
def protected_resource_metadata_root():
    return _protected_resource_metadata(_issuer_url())


@bp.route("/.well-known/oauth-protected-resource/proxy/mcp/<int:server_id>")
def protected_resource_metadata_server(server_id):
    resource = f"{_issuer_url()}/proxy/mcp/{server_id}"
    return _protected_resource_metadata(resource)


@bp.route("/.well-known/oauth-protected-resource/proxy/mcp/aggregate")
def protected_resource_metadata_aggregate():
    resource = f"{_issuer_url()}/proxy/mcp/aggregate"
    return _protected_resource_metadata(resource)


# --- AS endpoints ----------------------------------------------------------


@bp.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    try:
        grant = authorization.get_consent_grant(end_user=current_user)
    except OAuth2Error as error:
        return authorization.handle_error_response(request, error)

    client = grant.client
    payload = getattr(grant.request, "payload", None)
    redirect_uri = (getattr(payload, "redirect_uri", None) if payload is not None else None) or request.values.get(
        "redirect_uri", ""
    )
    where = urlsplit(redirect_uri).netloc or redirect_uri
    if request.method == "GET":
        return render_template(
            "oauth_consent.html",
            grant=grant,
            client=client,
            scopes=(getattr(grant.request, "scope", None) or OAUTH_MCP_SCOPE).split(),
            redirect_uri=redirect_uri,
            redirect_host=where,
            loopback_redirect=oauth_policy.is_loopback(redirect_uri),
        )

    # The decision is audited with the host the code is sent to.
    allowed = request.form.get("confirm") == "yes"
    audit.log_audit_event(
        "oauth_consent", "success" if allowed else "error", user=current_user,
        error_message=f"{'allowed' if allowed else 'denied'} client '{(client.client_name or '')[:80]}' -> {where}"[:500],
    )
    if not allowed:
        return authorization.create_authorization_response(grant=grant, grant_user=None)
    return authorization.create_authorization_response(grant=grant, grant_user=current_user)


# These three are unauthenticated POST endpoints reachable by anyone who can
# reach the instance: /oauth/token is a credential-guessing surface, and
# /oauth/register mints a client row per call (RFC7591 DCR has no auth by
# design). /oauth/authorize is deliberately left unlimited - it sits behind
# @login_required, and the login itself is already rate limited.
@bp.route("/oauth/token", methods=["POST"])
@limiter.limit(lambda: current_app.config["OAUTH_TOKEN_RATE_LIMIT"])
def issue_token():
    return authorization.create_token_response()


def _register_limit_key():
    """Rate-limit key for registration: the client address, but an IPv6
    address counts as its /64 - a single machine routinely owns billions of
    addresses in one, so per-address limits would mean no limit."""
    import ipaddress

    address = request.remote_addr or "-"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 6:
        # An IPv4 client reported as ::ffff:a.b.c.d is an IPv4 client: folding
        # every mapped address into one /64 would put them all in one bucket.
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return address


@bp.route("/oauth/register", methods=["POST"])
@limiter.limit(lambda: current_app.config["OAUTH_REGISTER_RATE_LIMIT"], key_func=_register_limit_key)
def register_client():
    return authorization.create_endpoint_response("client_registration")


@bp.route("/oauth/revoke", methods=["POST"])
@limiter.limit(lambda: current_app.config["OAUTH_TOKEN_RATE_LIMIT"])
def revoke_token():
    return authorization.create_endpoint_response("revocation")
