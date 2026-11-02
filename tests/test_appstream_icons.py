from types import SimpleNamespace

from mcprack import appstream_icons as ai


def test_dotted_icon_name_resolves_svg(tmp_path, monkeypatch):
    (tmp_path / "cz.vitexsoftware.foo.svg").write_text("<svg/>")
    monkeypatch.setattr(ai, "_ICON_DIRS", (str(tmp_path),))
    assert ai._resolve_icon_file("cz.vitexsoftware.foo") == str(tmp_path / "cz.vitexsoftware.foo.svg")


def test_short_name_matches_conventional_binary():
    srv = SimpleNamespace(command=None, name="netbox")
    assert "mcp-server-netbox" in ai._binary_candidates(srv)
    assert "netbox-mcp-server" in ai._binary_candidates(srv)
    assert "mcp-ollama-python" in ai._binary_candidates(SimpleNamespace(command=None, name="ollama"))
