import json

import pytest

from mcprack import manifest
from tests.test_server_page import DECLARED, _unified


def test_example_manifest_is_valid():
    assert manifest.validate(_unified()) == []


def test_schema_is_valid_json_schema():
    import jsonschema

    jsonschema.Draft7Validator.check_schema(manifest.schema())


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d.pop("repository"), "repository"),
        (lambda d: d.update(description="x" * 101), "description"),
        (lambda d: d.update(name="no-slash"), "name"),
        (lambda d: d.update(version="latest"), "version"),
        (lambda d: d["packages"][0]["environmentVariables"][0].update(name="1BAD"), "name"),
        (lambda d: d["packages"][0]["environmentVariables"][1].update(default="x"), "environmentVariables"),
        (lambda d: manifest.extension(d).pop("uuid"), "uuid"),
        (lambda d: manifest.extension(d).update(uuid="not-a-uuid"), "uuid"),
        (lambda d: manifest.extension(d).pop("tools"), "tools"),
        (lambda d: manifest.extension(d)["author"].pop("name"), "author"),
        (lambda d: d.pop("_meta"), "_meta"),
    ],
)
def test_schema_rejects(mutate, expected):
    data = _unified()
    mutate(data)
    problems = manifest.validate(data)
    assert problems and any(expected in p for p in problems), problems


def test_extra_registry_fields_are_allowed():
    data = _unified()
    data["icons"] = [{"src": "https://example.test/i.png"}]
    data["remotes"] = []
    assert manifest.validate(data) == []


def test_extension_and_environment_variables():
    data = _unified()
    assert manifest.extension(data)["uuid"] == DECLARED
    assert [e["name"] for e in manifest.environment_variables(data)] == ["SEMAPHORE_URL", "SEMAPHORE_API_TOKEN"]
    assert manifest.extension({"_meta": "x"}) == {}


def test_legacy_conversion_validates_once_uuid_is_known():
    legacy = {
        "identifier": "vitexsoftware-x", "name": "X", "version": "1.0.0", "author": "Me",
        "authorUrl": "https://me.example", "homepage": "https://github.com/me/x",
        "description": "d" * 150, "category": "developer", "tools": [{"name": "t", "description": "td"}],
    }
    converted = manifest.from_legacy_plugin(legacy, "mcp-server-x")
    assert len(converted["description"]) <= 100
    assert manifest.extension(converted)["longDescription"] == ["d" * 150]
    assert any("uuid" in p for p in manifest.validate(converted))
    manifest.extension(converted)["uuid"] = DECLARED
    assert manifest.validate(converted) == []


def test_cli_validate_and_convert(app, tmp_path):
    runner = app.test_cli_runner()
    good = tmp_path / "server.json"
    good.write_text(json.dumps(_unified()), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")

    ok = runner.invoke(args=["server", "manifest-validate", str(good)])
    assert ok.exit_code == 0 and "OK" in ok.output
    fail = runner.invoke(args=["server", "manifest-validate", str(bad)])
    assert fail.exit_code == 1 and "FAIL" in fail.output

    plugin = tmp_path / "lhm.plugin.json"
    plugin.write_text(json.dumps({"identifier": "i", "name": "N", "description": "d", "author": "A", "homepage": "https://github.com/a/b", "version": "0.1.0"}), encoding="utf-8")
    out = tmp_path / "converted.json"
    res = runner.invoke(args=["server", "manifest-convert", str(plugin), "--package", "mcp-server-n", "--new-uuid", "-o", str(out)])
    assert res.exit_code == 0, res.output
    converted = json.loads(out.read_text())
    assert manifest.validate(converted) == []


def test_standalone_module_entry_point(tmp_path, capsys):
    good = tmp_path / "server.json"
    good.write_text(json.dumps(_unified()), encoding="utf-8")
    assert manifest.main(["validate", str(good)]) == 0
    assert "OK" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert manifest.main(["validate", str(bad)]) == 1
