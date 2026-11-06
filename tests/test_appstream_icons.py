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


def test_metainfo_glob_skips_a_directory_match(tmp_path, monkeypatch):
    """Debian's ardour ships /usr/share/metainfo/ardour.appdata.xml as a
    *directory* of per-version files, so a *.xml glob can match something
    ET.parse() cannot open."""
    real = tmp_path / "real.xml"
    real.write_text("<component/>")
    bogus = tmp_path / "bogus.xml"
    bogus.mkdir()

    seen = []

    def fake_glob(pattern):
        seen.append(pattern)
        return [str(real), str(bogus)] if len(seen) == 1 else []

    monkeypatch.setattr(ai, "glob", fake_glob)
    assert list(ai._iter_metainfo_files()) == [str(real)]


def test_build_index_survives_a_directory_match(tmp_path, monkeypatch):
    """The symptom was a 500 on every Admin -> Servers -> edit page: the
    IsADirectoryError is an OSError, which _build_index() does not catch."""
    bogus = tmp_path / "bogus.xml"
    bogus.mkdir()
    monkeypatch.setattr(ai, "glob", lambda pattern: [str(bogus)])
    assert ai._build_index() == {"by_binary": {}, "by_package": {}}
