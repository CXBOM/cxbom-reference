"""The wheel: reproducible, package-only, anonymous metadata (spec 3, 12).

Owner: ATACE Working Group.
"""
import email.parser
import hashlib
import os
import pwd
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

import cxbom
from conftest import EPOCH, ROOT, copy_source

sys.path.insert(0, str(ROOT / "scripts"))
import build_wheel  # noqa: E402

DIST_INFO = f"cxbom-{cxbom.__version__}.dist-info"
APACHE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


def members(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as z:
        return set(z.namelist())


def metadata(wheel: Path):
    with zipfile.ZipFile(wheel) as z:
        return email.parser.Parser().parsestr(z.read(f"{DIST_INFO}/METADATA").decode("utf-8"))


def test_two_builds_from_different_directories_are_identical(tmp_path, built_wheel):
    other = build_wheel.build_wheel(copy_source(tmp_path / "elsewhere" / "src"), tmp_path / "out", EPOCH)
    assert other.name == built_wheel.name == f"cxbom-{cxbom.__version__}-py3-none-any.whl"
    assert other.read_bytes() == built_wheel.read_bytes()


def test_the_wheel_holds_the_package_and_nothing_else(built_wheel):
    package = {p.relative_to(ROOT).as_posix() for p in (ROOT / "cxbom").rglob("*")
               if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    dist = {f"{DIST_INFO}/{n}" for n in ("METADATA", "WHEEL", "RECORD", "entry_points.txt",
                                         "licenses/LICENSE", "licenses/NOTICE")}
    assert members(built_wheel) == package | dist
    assert "cxbom/_data/cxbom-0.2.0.schema.json" in package
    assert "cxbom/_data/catalogs/SOURCES.json" in package


def test_metadata_is_anonymous_and_matches_spec_3(built_wheel):
    meta = metadata(built_wheel)
    assert meta["Name"] == "cxbom"
    assert meta["Version"] == cxbom.__version__
    assert meta["Requires-Python"] == ">=3.10"
    assert meta["Author"] == "ATACE Working Group"
    assert meta["Author-email"] is None and meta["Maintainer"] is None and meta["Maintainer-email"] is None
    assert meta.get_all("Project-URL") == ["Homepage, https://cxbom.org"]
    assert meta["License-Expression"] == "Apache-2.0"
    assert meta.get_all("Provides-Extra") == ["emit"]
    reqs = {Requirement(v).name: Requirement(v) for v in meta.get_all("Requires-Dist")}
    expected = {"rfc8785": ">=0.1.4,<0.2", "jsonschema": ">=4.23,<5", "rfc3339-validator": "",
                "cryptography": ">=42,<51", "tokenizers": ">=0.20,<0.24"}
    assert set(reqs) == set(expected)
    for name, spec in expected.items():
        assert reqs[name].specifier == SpecifierSet(spec), name
    assert reqs["jsonschema"].extras == {"format-nongpl"}
    assert str(reqs["tokenizers"].marker) == 'extra == "emit"'
    assert all(reqs[n].marker is None for n in expected if n != "tokenizers")


def test_entries_carry_the_source_date_epoch(built_wheel):
    with zipfile.ZipFile(built_wheel) as z:
        assert {i.date_time for i in z.infolist()} == {time.gmtime(EPOCH)[:6]}


def test_the_wheel_names_no_home_or_build_path(built_wheel, tmp_path_factory):
    with zipfile.ZipFile(built_wheel) as z:
        blob = b"".join(z.read(n) for n in z.namelist())
    assert pwd.getpwuid(os.getuid()).pw_dir.encode() not in blob
    assert str(tmp_path_factory.getbasetemp()).encode() not in blob
    assert str(ROOT).encode() not in blob


def test_license_is_apache_and_notice_covers_every_fixture(built_wheel):
    assert hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == APACHE_SHA256
    with zipfile.ZipFile(built_wheel) as z:
        assert hashlib.sha256(z.read(f"{DIST_INFO}/licenses/LICENSE")).hexdigest() == APACHE_SHA256
        assert z.read(f"{DIST_INFO}/licenses/NOTICE") == (ROOT / "NOTICE").read_bytes()
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    for needle in ("ATACE", "CWE", "ATLAS", "OWASP", "Phi-3.5"):
        assert needle in notice
    fixtures = sorted((ROOT / "tests" / "fixtures").glob("*/NOTICE"))
    assert fixtures
    for fixture_notice in fixtures:
        assert f"tests/fixtures/{fixture_notice.parent.name}/" in notice


def _git(src: Path, home: Path, *args: str, date: int) -> None:
    env = {"HOME": str(home), "PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "CxBOM", "GIT_AUTHOR_EMAIL": "noreply@cxbom.org",
           "GIT_COMMITTER_NAME": "CxBOM", "GIT_COMMITTER_EMAIL": "noreply@cxbom.org",
           "GIT_AUTHOR_DATE": f"@{date} +0000", "GIT_COMMITTER_DATE": f"@{date} +0000"}
    subprocess.run(["git", *args], cwd=src, env=env, check=True, capture_output=True)


def test_the_build_uses_committed_sources_and_the_last_package_commit_time(tmp_path, capsys):
    src = copy_source(tmp_path / "src")
    _git(src, tmp_path, "init", "-q", date=EPOCH)
    _git(src, tmp_path, "add", "-A", date=EPOCH)
    _git(src, tmp_path, "commit", "-q", "-m", "package", date=EPOCH)
    (src / "cxbom" / "stray.py").write_text("x = 1\n")
    assert build_wheel.main(["--out", str(tmp_path / "out1")], root=src) == 2
    assert "uncommitted" in capsys.readouterr().err
    (src / "cxbom" / "stray.py").unlink()
    (src / "notes.txt").write_text("not packaged\n")
    _git(src, tmp_path, "add", "notes.txt", date=EPOCH + 5000)
    _git(src, tmp_path, "commit", "-q", "-m", "not the package", date=EPOCH + 5000)
    assert build_wheel.main(["--out", str(tmp_path / "out2")], root=src) == 0
    sha, name = capsys.readouterr().out.split()
    wheel = tmp_path / "out2" / name
    assert sha == hashlib.sha256(wheel.read_bytes()).hexdigest()
    with zipfile.ZipFile(wheel) as z:
        assert {i.date_time for i in z.infolist()} == {time.gmtime(EPOCH)[:6]}


def test_the_build_refuses_an_output_directory_with_a_wheel(tmp_path, built_wheel):
    out = tmp_path / "out"
    out.mkdir()
    (out / built_wheel.name).write_bytes(built_wheel.read_bytes())
    try:
        build_wheel.build_wheel(copy_source(tmp_path / "src"), out, EPOCH)
    except build_wheel.BuildError as e:
        assert "already holds" in str(e)
    else:
        raise AssertionError("build_wheel overwrote an existing wheel")


def test_the_release_build_ships_exactly_the_committed_package(tmp_path, capsys, built_wheel):
    # hatchling honors .gitignore in the directory it builds, so a release build from the repo
    # root would silently drop a committed package file that an ignore pattern matches. The
    # release path must ship the committed package and ignore stray files, byte for byte.
    src = copy_source(tmp_path / "src")
    (src / ".gitignore").write_text("cxbom/_data/catalogs/owasp-*.json\ncxbom/_data/stray.json\n")
    _git(src, tmp_path, "init", "-q", date=EPOCH)
    _git(src, tmp_path, "add", "-A", "-f", date=EPOCH)
    _git(src, tmp_path, "commit", "-q", "-m", "package", date=EPOCH)
    (src / "cxbom" / "_data" / "stray.json").write_text("{}\n")
    assert build_wheel.main(["--out", str(tmp_path / "out")], root=src) == 0
    _, name = capsys.readouterr().out.split()
    assert (tmp_path / "out" / name).read_bytes() == built_wheel.read_bytes()


def _committed_copy(tmp_path: Path) -> Path:
    src = copy_source(tmp_path / "src")
    _git(src, tmp_path, "init", "-q", date=EPOCH)
    _git(src, tmp_path, "add", "-A", date=EPOCH)
    _git(src, tmp_path, "commit", "-q", "-m", "package", date=EPOCH)
    return src


@pytest.mark.parametrize("kind", ["symlink", "submodule"])
def test_the_release_build_refuses_links_and_submodules(tmp_path, capsys, kind):
    src = _committed_copy(tmp_path)
    (tmp_path / "outside.json").write_text('{"secret": 1}\n')
    if kind == "symlink":
        # copyfile follows links, so a committed link would ship a file from outside the repo.
        os.symlink(tmp_path / "outside.json", src / "cxbom" / "_data" / "leak.json")
        _git(src, tmp_path, "add", "cxbom/_data/leak.json", date=EPOCH)
    else:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src, capture_output=True, text=True).stdout.strip()
        # An empty directory is how git status sees an uninitialized submodule, so check_clean passes.
        (src / "cxbom" / "sub").mkdir()
        _git(src, tmp_path, "update-index", "--add", "--cacheinfo", f"160000,{head},cxbom/sub", date=EPOCH)
    _git(src, tmp_path, "commit", "-q", "-m", kind, date=EPOCH)
    assert build_wheel.main(["--out", str(tmp_path / "out")], root=src) == 2
    assert kind in capsys.readouterr().err
    assert not list((tmp_path / "out").glob("*.whl"))


def test_an_edit_hidden_from_git_status_does_not_ship(tmp_path, capsys, built_wheel):
    src = _committed_copy(tmp_path)
    with open(src / "cxbom" / "__init__.py", "a") as f:
        f.write("HIDDEN = 1\n")
    _git(src, tmp_path, "update-index", "--assume-unchanged", "cxbom/__init__.py", date=EPOCH)
    assert build_wheel.main(["--out", str(tmp_path / "out")], root=src) == 0
    _, name = capsys.readouterr().out.split()
    assert (tmp_path / "out" / name).read_bytes() == built_wheel.read_bytes()


def test_an_executable_file_keeps_its_mode_in_release_and_test_builds(tmp_path, capsys):
    src = copy_source(tmp_path / "base")
    tool = src / "cxbom" / "_data" / "tool.sh"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    test_wheel = build_wheel.build_wheel(copy_source(tmp_path / "test-src", root=src), tmp_path / "t", EPOCH)
    _git(src, tmp_path, "init", "-q", date=EPOCH)
    _git(src, tmp_path, "add", "-A", date=EPOCH)
    _git(src, tmp_path, "commit", "-q", "-m", "package", date=EPOCH)
    assert build_wheel.main(["--out", str(tmp_path / "r")], root=src) == 0
    release = tmp_path / "r" / capsys.readouterr().out.split()[1]
    assert release.read_bytes() == test_wheel.read_bytes()
    with zipfile.ZipFile(release) as z:
        modes = {i.filename: i.external_attr >> 16 for i in z.infolist()}
    assert modes["cxbom/_data/tool.sh"] & 0o777 == 0o755
    assert modes["cxbom/__init__.py"] & 0o777 == 0o644


def test_a_mismatched_build_requirement_exits_2_with_one_redacted_line(tmp_path, capsys):
    src = copy_source(tmp_path / "src")
    pyproject = src / "pyproject.toml"
    pyproject.write_text(pyproject.read_text().replace('"hatchling==1.32.4"', '"hatchling==9.9.9"'))
    _git(src, tmp_path, "init", "-q", date=EPOCH)
    _git(src, tmp_path, "add", "-A", date=EPOCH)
    _git(src, tmp_path, "commit", "-q", "-m", "package", date=EPOCH)
    assert build_wheel.main(["--out", str(tmp_path / "out")], root=src) == 2
    err = capsys.readouterr().err
    assert len(err.strip().splitlines()) == 1 and "9.9.9" in err
    assert str(Path.home()) not in err and str(tmp_path) not in err and "/private/" not in err


def test_a_wrong_installed_hatchling_is_refused(tmp_path):
    fake = tmp_path / "python"
    fake.write_text("#!/bin/sh\necho 9.9.9\n")
    fake.chmod(0o755)
    with pytest.raises(build_wheel.BuildError, match=r"hatchling 9\.9\.9\b.*exactly 1\.32\.4"):
        build_wheel.build_wheel(copy_source(tmp_path / "src"), tmp_path / "out", EPOCH, python=str(fake))


def test_the_build_ignores_the_callers_python_path(tmp_path, monkeypatch, built_wheel):
    # An inherited PYTHONPATH could put a different hatchling in front of the pinned one.
    shadow = tmp_path / "shadow" / "hatchling"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text("raise SystemExit('shadow hatchling loaded')\n")
    monkeypatch.setenv("PYTHONPATH", str(shadow.parent))
    wheel = build_wheel.build_wheel(copy_source(tmp_path / "src"), tmp_path / "out", EPOCH)
    assert wheel.read_bytes() == built_wheel.read_bytes()


def fake_python(tmp_path: Path, pip_line: str, hatchling: str = build_wheel.HATCHLING) -> Path:
    """A stand-in interpreter that answers the hatchling probe and `-m pip --version`."""
    python = tmp_path / "fake" / "python"
    python.parent.mkdir(parents=True, exist_ok=True)
    python.write_text(f'''#!/bin/sh
case "$*" in
  *"pip --version"*) printf '%s\\n' "{pip_line}" ;;
  *) printf '%s\\n' "{hatchling}" ;;
esac
''', encoding="utf-8")
    python.chmod(0o755)
    return python


@pytest.mark.parametrize("pip_line, refused", [
    ("pip 22.0.2 from /u/lib/python3.10/site-packages/pip (python 3.10)", "pip 22.0"),
    ("pip 23.3.1 from /u (python 3.11)", "pip 23.3"),
    ("pip 9.0.1 from /u (python 3.10)", "pip 9.0"),
    ("", "no usable pip"),
], ids=["ubuntu-22.04", "23.3.1", "9.0.1", "no pip"])
def test_a_build_pip_older_than_24_0_is_refused(tmp_path, pip_line, refused):
    # Ubuntu 22.04's pip 22.0.2 has no --check-build-dependencies, so it cannot build.
    # It stays the install floor, which .github/workflows/install.yml proves separately.
    with pytest.raises(build_wheel.BuildError, match=rf"{re.escape(refused)}.*needs pip 24\.0 or newer"):
        build_wheel.build_wheel(copy_source(tmp_path / "src"), tmp_path / "out", EPOCH,
                                python=str(fake_python(tmp_path, pip_line)))


def test_a_build_pip_of_24_0_or_newer_passes_the_version_gate(tmp_path):
    for pip_line in ("pip 24.0 from /u (python 3.12)", "pip 26.2.1 from /u (python 3.14)"):
        python = fake_python(tmp_path / pip_line[:7].replace(" ", "-"), pip_line)
        # The gate passes, so the fake interpreter reaches the build, where it writes no wheel.
        with pytest.raises(build_wheel.BuildError, match="expected one cxbom wheel"):
            build_wheel.build_wheel(copy_source(tmp_path / f"src-{pip_line[4:8]}"), tmp_path / f"out-{pip_line[4:8]}",
                                    EPOCH, python=str(python))


def test_the_pip_gate_runs_before_the_build_and_exits_2_with_one_redacted_line(tmp_path, capsys, monkeypatch):
    calls: list[list[str]] = []
    real = build_wheel.subprocess.run

    def run(cmd, **kw):
        calls.append(list(cmd))
        return real(cmd, **kw)
    monkeypatch.setattr(build_wheel.subprocess, "run", run)
    monkeypatch.setattr(build_wheel, "MIN_PIP", (99, 0))
    assert build_wheel.main(["--out", str(tmp_path / "out")]) == 2
    err = capsys.readouterr().err
    assert len(err.strip().splitlines()) == 1 and "needs pip 99.0 or newer" in err
    assert str(Path.home()) not in err and str(tmp_path) not in err and "/private/" not in err
    assert not [c for c in calls if "wheel" in c], calls


def test_the_wheel_declares_the_cxbom_console_script(built_wheel):
    with zipfile.ZipFile(built_wheel) as z:
        text = z.read(f"{DIST_INFO}/entry_points.txt").decode("utf-8")
    assert text.split() == ["[console_scripts]", "cxbom", "=", "cxbom.cli:main"]
