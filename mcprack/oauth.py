"""Optional MCP OAuth 2.1 Authorization Server.

Enabled with OAUTH_ENABLED=true. Implements the discovery + registration +
authorize + token flow that MCP HTTP clients expect (RFC8414 AS metadata,
RFC9728 Protected Resource Metadata, RFC7591 Dynamic Client Registration,
authorization-code + PKCE + refresh_token), so a connector URL can be the
stable `/proxy/mcp/<server_id>` form without a signed path token.

Path-token URLs keep working either way; this only adds the Bearer path.
"""

from __future__ import annotations

import time

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_revocation_endpoint,
    create_save_token_func,
)
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint as _ClientRegistrationEndpoint
from authlib.oauth2.rfc7636 import CodeChallenge as _CodeChallenge
from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from .extensions import csrf, db
from .models import (
    OAUTH_MCP_SCOPE,
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthToken,
    User,
)

bp = Blueprint("oauth", __name__)

authorization = AuthorizationServer()


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

    query_client = create_query_client_func(db.session, OAuthClient)
    save_token = create_save_token_func(db.session, OAuthToken)
    authorization.init_app(app, query_client=query_client, save_token=save_token)

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
            item = OAuthToken.query.filter_by(refresh_token=refresh_token).first()
            if item and item.is_refresh_token_active() and not item.is_expired():
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
    authorization.register_endpoint(create_revocation_endpoint(db.session, OAuthToken))

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
            # Default MCP-friendly metadata when the client omits fields.
            metadata = dict(client_metadata or {})
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


def oauth_unauthorized_response(server_id=None):
    """401 + WWW-Authenticate pointing at Protected Resource Metadata, as
    required by MCP Authorization / RFC9728 §5.1."""
    base = _public_base_url()
    if server_id is not None:
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
    token = OAuthToken.query.filter_by(access_token=raw_token).first()
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


# --- AS endpoints ----------------------------------------------------------


@bp.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    try:
        grant = authorization.get_consent_grant(end_user=current_user)
    except OAuth2Error as error:
        return authorization.handle_error_response(request, error)

    client = grant.client
    if request.method == "GET":
        return render_template(
            "oauth_consent.html",
            grant=grant,
            client=client,
            scopes=(getattr(grant.request, "scope", None) or OAUTH_MCP_SCOPE).split(),
        )

    if request.form.get("confirm") != "yes":
        return authorization.create_authorization_response(grant=grant, grant_user=None)
    return authorization.create_authorization_response(grant=grant, grant_user=current_user)


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


@bp.route("/oauth/register", methods=["POST"])
def register_client():
    return authorization.create_endpoint_response("client_registration")


@bp.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    return authorization.create_endpoint_response("revocation")
