import json
import os
import subprocess
from unittest.mock import MagicMock, patch

from mcprack import env_detection


# --- registry tier ------------------------------------------------------

def _http_response(payload):
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    return resp


def test_from_registry_maps_environment_variables():
    search_payload = {
        "servers": [
            {"server": {"name": "io.github.foo/foo-mcp", "packages": [{"identifier": "foo-mcp"}]}}
        ]
    }
    version_payload = {
        "server": {
            "name": "io.github.foo/foo-mcp",
            "packages": [
                {
                    "identifier": "foo-mcp",
                    "environmentVariables": [
                        {"name": "API_KEY", "isRequired": True, "isSecret": True, "description": "key"},
                        {"name": "LOG_LEVEL", "isRequired": False, "isSecret": False},
                    ],
                }
            ],
        }
    }
    with patch(
        "mcprack.env_detection.urllib.request.urlopen",
        side_effect=[_http_response(search_payload), _http_response(version_payload)],
    ):
        results = env_detection._from_registry("foo-mcp==1.0", "pip")

    assert {"name": "API_KEY", "required": True, "secret": True, "description": "key", "source": "registry"} in results
    assert {"name": "LOG_LEVEL", "required": False, "secret": False, "description": None, "source": "registry"} in results


def test_from_registry_no_match_returns_empty():
    with patch(
        "mcprack.env_detection.urllib.request.urlopen",
        return_value=_http_response({"servers": []}),
    ):
        assert env_detection._from_registry("nonexistent-pkg", "pip") == []


def test_from_registry_network_error_swallowed():
    import urllib.error

    with patch(
        "mcprack.env_detection.urllib.request.urlopen",
        side_effect=urllib.error.URLError("no network"),
    ):
        assert env_detection._from_registry("foo-mcp", "pip") == []


def test_from_registry_timeout_swallowed():
    with patch("mcprack.env_detection.urllib.request.urlopen", side_effect=TimeoutError()):
        assert env_detection._from_registry("foo-mcp", "pip") == []


def test_from_registry_malformed_json_swallowed():
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    resp.read.return_value = b"not json"
    with patch("mcprack.env_detection.urllib.request.urlopen", return_value=resp):
        assert env_detection._from_registry("foo-mcp", "pip") == []


# --- bundled manifest tier -----------------------------------------------

def test_from_bundled_manifest_pip_server_json(tmp_path):
    pkg_dir = tmp_path / "lib" / "python3.11" / "site-packages" / "foo_mcp"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "server.json").write_text(
        json.dumps(
            {
                "environmentVariables": [
                    {"name": "REQ_TOKEN", "isRequired": True, "isSecret": True},
                ]
            }
        )
    )
    results = env_detection._from_bundled_manifest(str(tmp_path), "pip", "foo-mcp==1.0")
    assert results == [
        {"name": "REQ_TOKEN", "required": True, "secret": True, "description": None, "source": "manifest"}
    ]


def test_from_bundled_manifest_npm_smithery_yaml(tmp_path):
    pkg_dir = tmp_path / "node_modules" / "foo-mcp"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "smithery.yaml").write_text(
        "configSchema:\n"
        "  type: object\n"
        "  required:\n"
        "    - apiKey\n"
        "  properties:\n"
        "    apiKey:\n"
        "      type: string\n"
        "    timeout:\n"
        "      type: number\n"
    )
    results = env_detection._from_bundled_manifest(str(tmp_path), "npm", "foo-mcp")
    by_name = {r["name"]: r for r in results}
    assert by_name["apiKey"]["required"] is True
    assert by_name["apiKey"]["secret"] is True  # "Key" matches sensitivity heuristic
    assert by_name["timeout"]["required"] is False
    assert all(r["source"] == "manifest" for r in results)


def test_from_bundled_manifest_missing_file_returns_empty(tmp_path):
    assert env_detection._from_bundled_manifest(str(tmp_path), "pip", "foo-mcp") == []


# --- heuristic source-scan tier -------------------------------------------

def test_from_source_scan_pip_finds_env_names(tmp_path):
    pkg_dir = tmp_path / "lib" / "python3.11" / "site-packages" / "foo_mcp"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "main.py").write_text(
        'import os\nTOKEN = os.environ.get("FOO_TOKEN")\nURL = os.getenv("BAR_URL", "x")\n'
    )
    results = env_detection._from_source_scan(str(tmp_path), "pip", "foo-mcp==1.0")
    names = {r["name"] for r in results}
    assert names == {"FOO_TOKEN", "BAR_URL"}
    # Never marks anything required — a grep can't know that.
    assert all(r["required"] is False for r in results)
    assert all(r["source"] == "source-scan" for r in results)
    by_name = {r["name"]: r for r in results}
    assert by_name["FOO_TOKEN"]["secret"] is True
    assert by_name["BAR_URL"]["secret"] is False


def test_from_source_scan_npm_finds_env_names(tmp_path):
    pkg_dir = tmp_path / "node_modules" / "foo-mcp"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "index.js").write_text(
        'const k = process.env.BAZ_KEY;\nconst s = process.env["QUX_SECRET"];\n'
    )
    results = env_detection._from_source_scan(str(tmp_path), "npm", "foo-mcp")
    names = {r["name"] for r in results}
    assert names == {"BAZ_KEY", "QUX_SECRET"}
    assert all(r["secret"] is True for r in results)  # both match sensitivity hints


def test_from_source_scan_never_descends_into_nested_node_modules(tmp_path):
    pkg_dir = tmp_path / "node_modules" / "foo-mcp"
    nested = pkg_dir / "node_modules" / "some-dep"
    nested.mkdir(parents=True)
    (nested / "index.js").write_text('process.env.SHOULD_NOT_APPEAR;\n')
    pkg_dir_file = pkg_dir / "index.js"
    pkg_dir_file.write_text('process.env.SHOULD_APPEAR;\n')

    results = env_detection._from_source_scan(str(tmp_path), "npm", "foo-mcp")
    names = {r["name"] for r in results}
    assert names == {"SHOULD_APPEAR"}


def test_from_source_scan_bounded_by_file_count(tmp_path, monkeypatch):
    monkeypatch.setattr(env_detection, "SCAN_MAX_FILES", 5)
    pkg_dir = tmp_path / "lib" / "python3.11" / "site-packages" / "foo_mcp"
    pkg_dir.mkdir(parents=True)
    for i in range(50):
        (pkg_dir / f"mod_{i}.py").write_text(f'os.environ.get("VAR_{i}")\n')
    # Should not raise / hang, and should not scan all 50 files.
    results = env_detection._from_source_scan(str(tmp_path), "pip", "foo-mcp")
    assert len(results) <= 5


# --- docker inspect tier ---------------------------------------------------

def test_from_docker_inspect_filters_denylist_and_maps_source():
    fake_result = MagicMock(returncode=0, stdout=json.dumps(["FOO=bar", "PATH=/usr/bin", "HOME=/root"]))
    with patch("mcprack.env_detection.subprocess.run", return_value=fake_result):
        results = env_detection._from_docker_inspect("ghcr.io/org/foo:latest")
    assert results == [
        {
            "name": "FOO",
            "required": False,
            "secret": False,
            "description": "declared in Docker image",
            "source": "docker-inspect",
        }
    ]


def test_from_docker_inspect_never_marks_required():
    fake_result = MagicMock(returncode=0, stdout=json.dumps(["API_KEY=x"]))
    with patch("mcprack.env_detection.subprocess.run", return_value=fake_result):
        results = env_detection._from_docker_inspect("ghcr.io/org/foo:latest")
    assert results[0]["required"] is False
    assert results[0]["secret"] is True  # matches sensitivity heuristic


def test_from_docker_inspect_nonzero_exit_returns_empty():
    fake_result = MagicMock(returncode=1, stdout="")
    with patch("mcprack.env_detection.subprocess.run", return_value=fake_result):
        assert env_detection._from_docker_inspect("nope") == []


def test_from_docker_inspect_timeout_swallowed():
    with patch(
        "mcprack.env_detection.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5),
    ):
        assert env_detection._from_docker_inspect("ghcr.io/org/foo:latest") == []


def test_from_docker_inspect_missing_docker_binary_swallowed():
    with patch("mcprack.env_detection.subprocess.run", side_effect=OSError("not found")):
        assert env_detection._from_docker_inspect("ghcr.io/org/foo:latest") == []


# --- dispatch / dedupe -----------------------------------------------------

class _FakeServer:
    def __init__(self, install_method, package_spec="foo-mcp==1.0", install_path="/tmp/does-not-matter"):
        self.install_method = install_method
        self.package_spec = package_spec
        self.install_path = install_path


def test_detect_env_vars_skips_manifest_and_scan_if_registry_found():
    registry_result = [{"name": "X", "required": True, "secret": False, "description": None, "source": "registry"}]
    with patch("mcprack.env_detection._from_registry", return_value=registry_result), \
         patch("mcprack.env_detection._from_bundled_manifest") as mock_manifest, \
         patch("mcprack.env_detection._from_source_scan") as mock_scan:
        results = env_detection.detect_env_vars(_FakeServer("pip"))

    assert results == registry_result
    mock_manifest.assert_not_called()
    mock_scan.assert_not_called()


def test_detect_env_vars_falls_back_through_tiers():
    with patch("mcprack.env_detection._from_registry", return_value=[]), \
         patch("mcprack.env_detection._from_bundled_manifest", return_value=[]) as mock_manifest, \
         patch(
             "mcprack.env_detection._from_source_scan",
             return_value=[{"name": "Y", "required": False, "secret": False, "description": None, "source": "source-scan"}],
         ) as mock_scan:
        results = env_detection.detect_env_vars(_FakeServer("pip"))

    mock_manifest.assert_called_once()
    mock_scan.assert_called_once()
    assert results == [{"name": "Y", "required": False, "secret": False, "description": None, "source": "source-scan"}]


def test_detect_env_vars_docker_always_runs_inspect_plus_registry():
    with patch("mcprack.env_detection._from_registry", return_value=[]) as mock_registry, \
         patch(
             "mcprack.env_detection._from_docker_inspect",
             return_value=[{"name": "Z", "required": False, "secret": False, "description": None, "source": "docker-inspect"}],
         ) as mock_docker:
        results = env_detection.detect_env_vars(_FakeServer("docker", package_spec="ghcr.io/org/foo:latest"))

    mock_registry.assert_called_once()
    mock_docker.assert_called_once()
    assert results == [{"name": "Z", "required": False, "secret": False, "description": None, "source": "docker-inspect"}]


def test_detect_env_vars_dedupes_keeping_first_tier_wins():
    with patch(
        "mcprack.env_detection._from_registry",
        return_value=[{"name": "DUP", "required": True, "secret": True, "description": "authoritative", "source": "registry"}],
    ):
        results = env_detection.detect_env_vars(_FakeServer("pip"))
    assert len(results) == 1
    assert results[0]["required"] is True
    assert results[0]["description"] == "authoritative"


def test_detect_env_vars_swallows_exceptions_from_any_tier():
    with patch("mcprack.env_detection._from_registry", side_effect=RuntimeError("boom")):
        assert env_detection.detect_env_vars(_FakeServer("pip")) == []


def test_detect_env_vars_returns_empty_for_manual_servers():
    server = _FakeServer(None, package_spec=None, install_path=None)
    assert env_detection.detect_env_vars(server) == []


def test_source_scan_and_docker_inspect_can_never_produce_required_true():
    """Regression guard on the trust boundary: only registry/manifest tiers
    may ever claim a variable is required."""
    pkg_dir_holder = {}

    def make_pkg(tmp_path):
        pkg_dir = tmp_path / "lib" / "python3.11" / "site-packages" / "foo_mcp"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "main.py").write_text('os.environ.get("ANYTHING_REQUIRED_LOOKING")\n')
        return pkg_dir

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        make_pkg(__import__("pathlib").Path(tmp))
        scan_results = env_detection._from_source_scan(tmp, "pip", "foo-mcp")
        assert all(r["required"] is False for r in scan_results)

    fake_result = MagicMock(returncode=0, stdout=json.dumps(["REQUIRED_LOOKING=x"]))
    with patch("mcprack.env_detection.subprocess.run", return_value=fake_result):
        docker_results = env_detection._from_docker_inspect("ghcr.io/org/foo:latest")
    assert all(r["required"] is False for r in docker_results)
