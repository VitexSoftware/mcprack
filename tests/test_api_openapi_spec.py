import os

import yaml
from openapi_spec_validator import validate

from mcprack.version import get_version

_SPEC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "mcprack", "openapi", "openapi.yaml"
)


def test_spec_file_is_valid_openapi_3():
    with open(_SPEC_PATH, encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    validate(spec)


def test_spec_endpoint_returns_current_version(client):
    resp = client.get("/api/v1/openapi.json")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "paths" in body
    assert body["info"]["version"] == get_version()
