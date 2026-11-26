"""Authenticated MCP control plane for an mcprack user.

The transport is deliberately thin: every tool dispatches to the existing
JSON API in-process, so ACL, validation, audit, demo-mode and reauth policies
cannot drift between the web application and an AI agent.
"""

import json

from flask import Blueprint, Response, current_app, g, jsonify, request
from flask_login import current_user
from jsonschema import Draft202012Validator

from .extensions import csrf
from .version import get_version


bp = Blueprint("management_mcp", __name__)

PROTOCOL_VERSION = "2025-06-18"

READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
CREATE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False,
}
ASSIGN = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
DESTRUCTIVE = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": True,
    "openWorldHint": False,
}


def _schema(properties=None, required=()):
    properties = properties or {}
    properties = {
        name: _describe_parameter(name, dict(schema))
        for name, schema in properties.items()
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def _describe_parameter(name, schema):
    schema.setdefault(
        "description",
        f"{name.replace('_', ' ').capitalize()} parameter.",
    )
    nested = schema.get("properties")
    if isinstance(nested, dict):
        schema["properties"] = {
            child_name: _describe_parameter(child_name, dict(child_schema))
            for child_name, child_schema in nested.items()
        }
    items = schema.get("items")
    if isinstance(items, dict):
        schema["items"] = _describe_parameter("item", dict(items))
    return schema


TOOLS = [
    {
        "name": "mcprack_get_profile",
        "title": "Get Profile",
        "description": "Get the authenticated user's profile and role.",
        "inputSchema": _schema(),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/me",
    },
    {
        "name": "mcprack_list_catalog",
        "title": "List MCP Catalog",
        "description": "List every catalog entry with permission, selection, and configuration state.",
        "inputSchema": _schema(),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/me/catalog",
    },
    {
        "name": "mcprack_list_subscriptions",
        "title": "List Subscriptions",
        "description": "List the authenticated user's selected MCP servers.",
        "inputSchema": _schema(),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/me/selections",
    },
    {
        "name": "mcprack_subscribe",
        "title": "Subscribe to MCP Server",
        "description": "Add a permitted MCP server to the user's selected servers.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": ASSIGN,
        "method": "POST",
        "path": "/api/v1/me/selections/{server_id}",
    },
    {
        "name": "mcprack_unsubscribe",
        "title": "Unsubscribe from MCP Server",
        "description": "Remove an MCP server from the user's selected servers.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "DELETE",
        "path": "/api/v1/me/selections/{server_id}",
    },
    {
        "name": "mcprack_request_access",
        "title": "Request Server Access",
        "description": "Ask an administrator to grant access to a denied MCP server.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": ASSIGN,
        "method": "POST",
        "path": "/api/v1/me/access-requests/{server_id}",
    },
    {
        "name": "mcprack_list_access_requests",
        "title": "List Access Requests",
        "description": "List the authenticated user's MCP server access requests.",
        "inputSchema": _schema(),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/me/access-requests",
    },
    {
        "name": "mcprack_get_configuration_schema",
        "title": "Get Configuration Schema",
        "description": "Describe a server's allowed user configuration keys without revealing values.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/servers/{server_id}/configuration-schema",
    },
    {
        "name": "mcprack_get_configuration",
        "title": "Get Server Configuration",
        "description": "List which personal values are configured for a server without returning secret or non-secret values.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/me/overrides/{server_id}",
    },
    {
        "name": "mcprack_set_configuration",
        "title": "Set Server Configuration",
        "description": "Replace the authenticated user's complete configuration for one MCP server.",
        "inputSchema": _schema(
            {
                "server_id": {"type": "integer", "description": "MCP server id."},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": ["string", "number", "boolean", "null"]},
                    "description": "Complete key/value configuration. Omitted keys are removed.",
                },
                "secret_keys": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Keys whose values must be stored as secrets.",
                },
            },
            ("server_id", "env"),
        ),
        "annotations": DESTRUCTIVE,
        "method": "PUT",
        "path": "/api/v1/me/overrides/{server_id}",
        "body": ("env", "secret_keys"),
    },
    {
        "name": "mcprack_reset_configuration",
        "title": "Reset Server Configuration",
        "description": "Delete the user's overrides for a server and restore administrator defaults.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "DELETE",
        "path": "/api/v1/me/overrides/{server_id}",
    },
    {
        "name": "mcprack_get_client_config",
        "title": "Get Client Configuration",
        "description": "Generate client configuration for the user's selected MCP servers; the result may contain an access URL.",
        "inputSchema": _schema(
            {
                "client": {
                    "type": "string",
                    "description": "Client format, for example claude, cursor, vscode, or copilot.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["aggregate", "servers"],
                    "description": "Use one aggregate URL or one URL per selected server.",
                },
                "auth": {
                    "type": "string",
                    "enum": ["oauth", "token"],
                    "description": "Optional authentication mode for the generated config.",
                },
            },
            ("client",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/me/config/{client}",
        "query": ("mode", "auth"),
    },
    {
        "name": "mcprack_admin_list_servers",
        "title": "List Admin Servers",
        "description": "List all registered MCP servers and their operational settings.",
        "inputSchema": _schema(
            {
                "page": {"type": "integer", "minimum": 1},
                "per_page": {"type": "integer", "minimum": 1, "maximum": 200},
                "include_health": {"type": "boolean"},
            }
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/servers",
        "admin": True,
        "query": ("page", "per_page", "include_health"),
    },
    {
        "name": "mcprack_admin_get_server",
        "title": "Get Admin Server",
        "description": "Get one MCP server's operational settings without revealing secrets.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/servers/{server_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_create_server",
        "title": "Create MCP Server",
        "description": "Register an MCP server, including the command or endpoint that mcprack will execute or relay.",
        "inputSchema": _schema(
            {
                "name": {"type": "string"},
                "label": {"type": "string"},
                "description": {"type": "string"},
                "transport": {"type": "string", "enum": ["stdio", "http", "sse"]},
                "command": {"type": ["string", "null"]},
                "args": {"type": "array", "items": {"type": "string"}},
                "url": {"type": ["string", "null"]},
                "enabled": {"type": "boolean"},
                "allow_user_override": {"type": "boolean"},
                "category": {"type": ["string", "null"]},
                "env": {"type": "object", "additionalProperties": True},
                "secrets": {"type": "object", "additionalProperties": True},
            },
            ("name", "transport"),
        ),
        "annotations": DESTRUCTIVE,
        "method": "POST",
        "path": "/api/v1/admin/servers",
        "admin": True,
        "body": (
            "name", "label", "description", "transport", "command", "args",
            "url", "enabled", "allow_user_override", "category", "env", "secrets",
        ),
    },
    {
        "name": "mcprack_admin_update_server",
        "title": "Update MCP Server",
        "description": "Change an existing MCP server's executable, endpoint, environment, or availability.",
        "inputSchema": _schema(
            {
                "server_id": {"type": "integer"},
                "label": {"type": "string"},
                "description": {"type": ["string", "null"]},
                "transport": {"type": "string", "enum": ["stdio", "http", "sse"]},
                "command": {"type": ["string", "null"]},
                "args": {"type": "array", "items": {"type": "string"}},
                "url": {"type": ["string", "null"]},
                "enabled": {"type": "boolean"},
                "allow_user_override": {"type": "boolean"},
                "category": {"type": ["string", "null"]},
                "env": {"type": "object", "additionalProperties": True},
                "secrets": {"type": "object", "additionalProperties": True},
            },
            ("server_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "PUT",
        "path": "/api/v1/admin/servers/{server_id}",
        "admin": True,
        "body": (
            "label", "description", "transport", "command", "args", "url",
            "enabled", "allow_user_override", "category", "env", "secrets",
        ),
    },
    {
        "name": "mcprack_admin_delete_server",
        "title": "Delete MCP Server",
        "description": "Delete a registered MCP server and stop its per-user proxy instances.",
        "inputSchema": _schema(
            {"server_id": {"type": "integer", "description": "MCP server id."}},
            ("server_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "DELETE",
        "path": "/api/v1/admin/servers/{server_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_list_access_requests",
        "title": "List Access Requests",
        "description": "List pending or resolved MCP server access requests.",
        "inputSchema": _schema(
            {
                "status": {
                    "type": "string",
                    "enum": ["pending", "approved", "denied", "all"],
                },
                "page": {"type": "integer", "minimum": 1},
                "per_page": {"type": "integer", "minimum": 1, "maximum": 200},
            }
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/access-requests",
        "admin": True,
        "query": ("status", "page", "per_page"),
    },
    {
        "name": "mcprack_admin_resolve_access_request",
        "title": "Resolve Access Request",
        "description": "Approve or deny a user's request for MCP server access; approval changes the user's ACL.",
        "inputSchema": _schema(
            {
                "user_id": {"type": "integer"},
                "server_id": {"type": "integer"},
                "decision": {"type": "string", "enum": ["approve", "deny"]},
            },
            ("user_id", "server_id", "decision"),
        ),
        "annotations": ASSIGN,
        "method": "POST",
        "path": "/api/v1/admin/access-requests/{user_id}/{server_id}/{decision}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_list_users",
        "title": "List Users",
        "description": "List mcprack users and profile state.",
        "inputSchema": _schema(
            {
                "page": {"type": "integer", "minimum": 1},
                "per_page": {"type": "integer", "minimum": 1, "maximum": 200},
            }
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/users",
        "admin": True,
        "query": ("page", "per_page"),
    },
    {
        "name": "mcprack_admin_create_user",
        "title": "Create User",
        "description": "Create a local mcprack user account with the requested role.",
        "inputSchema": _schema(
            {
                "username": {"type": "string", "minLength": 1},
                "password": {"type": "string", "minLength": 1},
                "email": {"type": "string"},
                "is_admin": {"type": "boolean"},
            },
            ("username", "password"),
        ),
        "annotations": DESTRUCTIVE,
        "method": "POST",
        "path": "/api/v1/admin/users",
        "admin": True,
        "body": ("username", "password", "email", "is_admin"),
    },
    {
        "name": "mcprack_admin_get_user",
        "title": "Get User",
        "description": "Get one user's profile, permissions, and MCP configuration metadata.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}},
            ("user_id",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/users/{user_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_update_user",
        "title": "Update User",
        "description": "Change a user's active/admin state, password, or server permissions.",
        "inputSchema": _schema(
            {
                "user_id": {"type": "integer"},
                "is_admin": {"type": "boolean"},
                "is_active": {"type": "boolean"},
                "password": {"type": "string"},
                "permissions": {"type": "object", "additionalProperties": {"type": "boolean"}},
            },
            ("user_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "PUT",
        "path": "/api/v1/admin/users/{user_id}",
        "admin": True,
        "body": ("is_admin", "is_active", "password", "permissions"),
    },
    {
        "name": "mcprack_admin_delete_user",
        "title": "Delete User",
        "description": "Permanently delete a mcprack user and stop their running MCP servers.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}},
            ("user_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "DELETE",
        "path": "/api/v1/admin/users/{user_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_revoke_user_tokens",
        "title": "Revoke User Tokens",
        "description": "Revoke a user's proxy, API, and OAuth tokens and stop their MCP servers.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}},
            ("user_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "POST",
        "path": "/api/v1/admin/users/{user_id}/revoke-tokens",
        "admin": True,
    },
    {
        "name": "mcprack_admin_reset_user_mfa",
        "title": "Reset User Two-Factor Authentication",
        "description": "Disable a user's two-factor authentication and end all their sessions.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}},
            ("user_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "POST",
        "path": "/api/v1/admin/users/{user_id}/mfa-reset",
        "admin": True,
    },
    {
        "name": "mcprack_admin_set_user_subscriptions",
        "title": "Set User Subscriptions",
        "description": "Replace a user's selected server ids, restricted to servers that user may use.",
        "inputSchema": _schema(
            {
                "user_id": {"type": "integer"},
                "server_ids": {"type": "array", "items": {"type": "integer"}},
            },
            ("user_id", "server_ids"),
        ),
        "annotations": DESTRUCTIVE,
        "method": "PUT",
        "path": "/api/v1/admin/users/{user_id}/selections",
        "admin": True,
        "body": ("server_ids",),
    },
    {
        "name": "mcprack_admin_get_user_subscriptions",
        "title": "Get User Subscriptions",
        "description": "List another user's selected server ids.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}},
            ("user_id",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/users/{user_id}/selections",
        "admin": True,
    },
    {
        "name": "mcprack_admin_get_user_configuration",
        "title": "Get User Server Configuration",
        "description": "List a user's configured keys for one server without revealing values.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}, "server_id": {"type": "integer"}},
            ("user_id", "server_id"),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/users/{user_id}/overrides/{server_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_set_user_configuration",
        "title": "Set User Server Configuration",
        "description": "Replace a user's complete personal configuration for one server.",
        "inputSchema": _schema(
            {
                "user_id": {"type": "integer"},
                "server_id": {"type": "integer"},
                "env": {"type": "object", "additionalProperties": True},
                "secret_keys": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            ("user_id", "server_id", "env"),
        ),
        "annotations": DESTRUCTIVE,
        "method": "PUT",
        "path": "/api/v1/admin/users/{user_id}/overrides/{server_id}",
        "admin": True,
        "body": ("env", "secret_keys"),
    },
    {
        "name": "mcprack_admin_reset_user_configuration",
        "title": "Reset User Server Configuration",
        "description": "Delete a user's overrides for one server and restore administrator defaults.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}, "server_id": {"type": "integer"}},
            ("user_id", "server_id"),
        ),
        "annotations": DESTRUCTIVE,
        "method": "DELETE",
        "path": "/api/v1/admin/users/{user_id}/overrides/{server_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_get_user_client_config",
        "title": "Get User Client Configuration",
        "description": "Generate client configuration for another user's selected MCP servers.",
        "inputSchema": _schema(
            {
                "user_id": {"type": "integer"},
                "client": {"type": "string"},
                "mode": {"type": "string", "enum": ["aggregate", "servers"]},
                "auth": {"type": "string", "enum": ["oauth", "token"]},
            },
            ("user_id", "client"),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/users/{user_id}/config/{client}",
        "admin": True,
        "query": ("mode", "auth"),
    },
    {
        "name": "mcprack_admin_list_templates",
        "title": "List Configuration Templates",
        "description": "List administrator-defined server permission and selection templates.",
        "inputSchema": _schema(),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/templates",
        "admin": True,
    },
    {
        "name": "mcprack_admin_get_template",
        "title": "Get Configuration Template",
        "description": "Get one permission and selection template.",
        "inputSchema": _schema(
            {"template_id": {"type": "integer"}},
            ("template_id",),
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/admin/templates/{template_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_create_template",
        "title": "Create Configuration Template",
        "description": "Create a reusable permission and selection template.",
        "inputSchema": _schema(
            {
                "name": {"type": "string", "minLength": 1},
                "label": {"type": "string"},
                "description": {"type": ["string", "null"]},
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "server_id": {"type": "integer"},
                            "is_allowed": {"type": "boolean"},
                            "is_selected": {"type": "boolean"},
                        },
                        "required": ["server_id", "is_allowed", "is_selected"],
                    },
                },
            },
            ("name", "servers"),
        ),
        "annotations": CREATE,
        "method": "POST",
        "path": "/api/v1/admin/templates",
        "admin": True,
        "body": ("name", "label", "description", "servers"),
    },
    {
        "name": "mcprack_admin_update_template",
        "title": "Update Configuration Template",
        "description": "Replace a permission and selection template's labels or server entries.",
        "inputSchema": _schema(
            {
                "template_id": {"type": "integer"},
                "label": {"type": "string"},
                "description": {"type": ["string", "null"]},
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "server_id": {"type": "integer"},
                            "is_allowed": {"type": "boolean"},
                            "is_selected": {"type": "boolean"},
                        },
                        "required": ["server_id", "is_allowed", "is_selected"],
                    },
                },
            },
            ("template_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "PUT",
        "path": "/api/v1/admin/templates/{template_id}",
        "admin": True,
        "body": ("label", "description", "servers"),
    },
    {
        "name": "mcprack_admin_delete_template",
        "title": "Delete Configuration Template",
        "description": "Delete an administrator-defined permission and selection template.",
        "inputSchema": _schema(
            {"template_id": {"type": "integer"}},
            ("template_id",),
        ),
        "annotations": DESTRUCTIVE,
        "method": "DELETE",
        "path": "/api/v1/admin/templates/{template_id}",
        "admin": True,
    },
    {
        "name": "mcprack_admin_apply_template",
        "title": "Apply Configuration Template",
        "description": "Apply a server permission and selection template to one user.",
        "inputSchema": _schema(
            {"user_id": {"type": "integer"}, "template_id": {"type": "integer"}},
            ("user_id", "template_id"),
        ),
        "annotations": ASSIGN,
        "method": "POST",
        "path": "/api/v1/admin/users/{user_id}/apply-template",
        "admin": True,
        "body": ("template_id",),
    },
    {
        "name": "mcprack_admin_get_audit_log",
        "title": "Get Audit Log",
        "description": "Read the audit trail of administrative, credential, and configuration activity.",
        "inputSchema": _schema(
            {
                "page": {"type": "integer", "minimum": 1},
                "per_page": {"type": "integer", "minimum": 1, "maximum": 200},
                "user_id": {"type": "integer"},
                "server_id": {"type": "integer"},
                "action": {"type": "string"},
            }
        ),
        "annotations": READ_ONLY,
        "method": "GET",
        "path": "/api/v1/audit-log",
        "admin": True,
        "query": ("page", "per_page", "user_id", "server_id", "action"),
    },
]
TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}


def _bearer_unauthorized():
    base_url = (
        current_app.config.get("PUBLIC_BASE_URL") or request.url_root.rstrip("/")
    ).rstrip("/")
    metadata_url = f"{base_url}/.well-known/oauth-protected-resource/mcp/management"
    response = jsonify(
        {
            "error": {
                "code": "invalid_token",
                "message": "A bearer token with mcprack management scopes is required.",
            },
            "error_description": "A bearer token with mcprack management scopes is required.",
        }
    )
    response.status_code = 401
    response.headers["WWW-Authenticate"] = (
        f'Bearer realm="mcprack", resource_metadata="{metadata_url}", '
        'scope="mcprack:read mcprack:manage"'
    )
    return response


def _authenticate():
    # Force Flask-Login's request loader. Browser cookies are deliberately
    # rejected: this endpoint is an AI-client capability, not ambient web UI
    # state that a cross-site request could exploit.
    if not current_user.is_authenticated or getattr(g, "api_token", None) is None:
        return None
    return current_user


def _public_tool(tool):
    return {
        key: value
        for key, value in tool.items()
        if key
        in ("name", "title", "description", "inputSchema", "annotations")
    }


def _tool_scopes(tool):
    if tool.get("admin"):
        return (
            ("admin:write",)
            if tool["method"] not in ("GET", "HEAD", "OPTIONS")
            else ("admin:read", "admin:write")
        )
    path = tool["path"]
    if "/configuration-schema" in path:
        return ("servers:read",)
    if "/overrides/" in path:
        return ("overrides:manage",)
    if "/selections" in path or "/access-requests/" in path and tool["method"] != "GET":
        return ("selections:manage",)
    if "/config/" in path:
        return ("config:read",)
    if path == "/api/v1/me":
        return ("profile:read",)
    return ("servers:read",)


def _available_tools(user):
    credential = getattr(g, "api_token", None)
    return [
        _public_tool(tool)
        for tool in TOOLS
        if (not tool.get("admin") or user.is_admin)
        and credential is not None
        and credential.allows_any(_tool_scopes(tool))
    ]


def _jsonrpc_result(request_id, result):
    return jsonify({"jsonrpc": "2.0", "id": request_id, "result": result})


def _jsonrpc_error(request_id, code, message):
    return jsonify(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }
    )


def _dispatch_api(tool, arguments):
    path_values = {
        key: value
        for key, value in arguments.items()
        if f"{{{key}}}" in tool["path"]
    }
    try:
        path = tool["path"].format(**path_values)
    except KeyError as exc:
        return 422, {"error": {"code": "invalid_params", "message": f"Missing {exc.args[0]}"}}

    body_keys = tool.get("body", ())
    body = {key: arguments[key] for key in body_keys if key in arguments}
    query = {
        key: ("1" if arguments[key] else "0")
        if key == "include_health"
        else arguments[key]
        for key in tool.get("query", ())
        if key in arguments
    }
    authorization = request.headers.get("Authorization", "")
    remote_addr = request.remote_addr
    with current_app.test_client() as client:
        response = client.open(
            path,
            method=tool["method"],
            headers={"Authorization": authorization},
            json=body if body else None,
            query_string=query,
            environ_base={"REMOTE_ADDR": remote_addr or "127.0.0.1"},
        )
        payload = response.get_json(silent=True)
        if payload is None:
            payload = {
                "data": None,
                "status": response.status,
            }
        return response.status_code, payload


def _call_tool(user, name, arguments):
    tool = TOOLS_BY_NAME.get(name)
    if tool is None:
        raise ValueError(f"Unknown tool: {name}")
    if tool.get("admin") and not user.is_admin:
        raise PermissionError("Administrator privileges are required")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    credential = getattr(g, "api_token", None)
    if credential is None or not credential.allows_any(_tool_scopes(tool)):
        raise PermissionError("The bearer token lacks the scope required for this tool")
    errors = sorted(
        Draft202012Validator(tool["inputSchema"]).iter_errors(arguments),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        suffix = f" at {location}" if location else ""
        raise ValueError(
            f"Invalid arguments{suffix}: failed '{errors[0].validator}' validation"
        )

    status, payload = _dispatch_api(tool, arguments)
    body = {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            }
        ],
        "isError": status >= 400,
    }
    if status < 400:
        body["structuredContent"] = payload
    return body


@bp.route("/mcp/management", methods=["POST", "DELETE", "OPTIONS"])
def endpoint():
    if request.method == "OPTIONS":
        return Response(status=204)
    if request.method == "DELETE":
        user = _authenticate()
        if user is None:
            return _bearer_unauthorized()
        return Response(status=204)

    user = _authenticate()
    if user is None:
        return _bearer_unauthorized()
    message = request.get_json(silent=True)
    if not isinstance(message, dict):
        return _jsonrpc_error(None, -32700, "Invalid JSON"), 400

    request_id = message.get("id")
    method = message.get("method")
    if method == "initialize":
        return _jsonrpc_result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "mcprack-management",
                    "version": get_version(),
                },
                "instructions": (
                    "Manage only the authenticated user's mcprack subscription and "
                    "configuration. Ask for confirmation before destructive tools."
                ),
            },
        )
    if method == "notifications/initialized":
        return Response(status=202)
    if method == "ping":
        return _jsonrpc_result(request_id, {})
    if method == "tools/list":
        return _jsonrpc_result(request_id, {"tools": _available_tools(user)})
    if method == "tools/call":
        params = message.get("params") or {}
        try:
            result = _call_tool(
                user, params.get("name"), params.get("arguments") or {}
            )
        except PermissionError as exc:
            return _jsonrpc_error(request_id, -32602, str(exc))
        except ValueError as exc:
            return _jsonrpc_error(request_id, -32602, str(exc))
        return _jsonrpc_result(request_id, result)
    if request_id is None:
        return Response(status=202)
    return _jsonrpc_error(request_id, -32601, f"Method not found: {method}")


csrf.exempt(endpoint)
