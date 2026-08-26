import os
import re

import yaml
from openapi_spec_validator import validate

from mcprack.version import get_version

_SPEC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "mcprack", "openapi", "openapi.yaml"
)
_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


def _load_spec():
    with open(_SPEC_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_spec_file_is_valid_openapi_3():
    validate(_load_spec())


def test_spec_endpoint_returns_current_version(client):
    resp = client.get("/api/v1/openapi.json")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "paths" in body
    assert body["info"]["version"] == get_version()


def test_every_operation_has_a_unique_operation_id():
    """operationId is required for clean client SDK codegen (openapi-generator
    et al.) — without it, generators fall back to ugly path+method-derived
    names. Every operation must declare one, and they must all be unique."""
    spec = _load_spec()
    seen = set()
    missing = []
    for path, operations in spec["paths"].items():
        for method, operation in operations.items():
            if method not in _HTTP_METHODS:
                continue
            operation_id = operation.get("operationId")
            if not operation_id:
                missing.append(f"{method.upper()} {path}")
                continue
            assert operation_id not in seen, f"Duplicate operationId '{operation_id}'"
            seen.add(operation_id)
    assert not missing, f"Missing operationId for: {missing}"


def _normalize_path(path):
    """Collapse any {param} (or Flask's <converter:param>) placeholder to a
    single wildcard token, so param-name casing differences (Flask's
    user_id vs. the spec's camelCase userId) don't matter — only the
    literal path structure does."""
    path = re.sub(r"<(?:[^:>]+:)?[^>]+>", "{}", path)
    return re.sub(r"\{[^}]+\}", "{}", path)


def test_spec_paths_match_registered_api_routes(app):
    """Every /api/v1/* Flask route (except the spec endpoint itself) should
    be documented in openapi.yaml with the same path structure, and vice
    versa — catches endpoints added to api.py but never documented (or
    spec paths for routes that no longer exist)."""
    with app.app_context():
        flask_paths = {
            _normalize_path(rule.rule[len("/api/v1") :])
            for rule in app.url_map.iter_rules()
            if rule.rule.startswith("/api/v1/")
        }
    spec = _load_spec()
    spec_paths = {_normalize_path(p) for p in spec["paths"]}
    assert flask_paths == spec_paths
