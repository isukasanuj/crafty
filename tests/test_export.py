"""Offline export tests. The network-dependent bundle build (download of a
standalone runtime) is exercised manually / in CI, not here, to keep the suite
fast and hermetic. These cover the parts that must be correct regardless."""

import zipfile

import pytest

from crafty import export

RAW = {
    "id": "t",
    "transport": "tcp",
    "role": "client",
    "target": "{{RHOST}}:{{RPORT|9}}",
    "flow": [{"send": {"bytes": "hi"}}],
}


def test_pyz_builds_and_is_self_contained(tmp_path):
    out = tmp_path / "a.pyz"
    p = export.export_pyz(RAW, {"RHOST": "1.2.3.4"}, str(out))
    assert out.exists()
    zf = zipfile.ZipFile(p)
    names = zf.namelist()
    assert "__main__.py" in names
    assert any(n.startswith("crafty/") for n in names)      # engine bundled
    assert any(n.startswith("yaml/") for n in names)        # dependency bundled
    main = zf.read("__main__.py").decode()
    assert "1.2.3.4" in main                                # param baked in


def test_pyz_omits_platform_yaml_extension(tmp_path):
    # Only the pure-python yaml package is bundled, never a platform _yaml ext,
    # so a bundle stays cross-target.
    p = export.export_pyz(RAW, {}, str(tmp_path / "a.pyz"))
    names = zipfile.ZipFile(p).namelist()
    assert not any("_yaml" in n for n in names)


def test_bundle_rejects_unknown_target(tmp_path):
    with pytest.raises(RuntimeError, match="unknown target"):
        export.export_bundle(RAW, {}, "solaris/sparc", out_dir=str(tmp_path))


def test_targets_cover_the_os_arch_matrix():
    for k in ["windows/amd64", "windows/x86", "linux/amd64", "linux/arm64",
              "linux/musl-arm64", "macos/arm64"]:
        assert k in export.TARGETS


def test_runner_source_is_valid_python():
    import ast
    src = export._runner_source({"version": "0.1.0", "template": RAW, "params": {}})
    ast.parse(src)  # must be syntactically valid
