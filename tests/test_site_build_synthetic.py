"""Guards in build.py that the canonical test_site_build.py cannot exercise yet.

Owner: ATACE Working Group.

tests/test_site_build.py is the plan's prescribed test file for build.py. Its
`built` fixture calls build.build(ROOT, out) against the real repository, which
needs spec/SPEC.md and site/content/landing.md. Those two files are Task 9's
deliverable and have not landed on this branch (checked: absent from every ref
in `git log --all`). Until they land, every test built on that fixture errors
at collection of the fixture, not from a defect in build.py.

This module verifies the guards that do not depend on Task 9's content, using
a synthetic copy of spec/ and site/ with stand-in text swapped in for the two
missing files. The stand-in text exists only inside a pytest tmp_path and is
never written to the repository. It closes two mutation gaps found while
auditing the prescribed suite:

1. The "is this directory a previous build" check in build() tests for both
   index.html and _headers. test_site_build.py only exercises a target
   directory with neither marker present, so a mutant that drops the
   _headers half of the check survives that suite unnoticed.
2. lock_new_schemas refuses to serve two schema files at the same $id-derived
   URL. test_site_build.py never adds a second file at an already-served URL,
   so a mutant that deletes that guard survives that suite unnoticed.

It also runs the atomic-build contract (a failing rebuild must not disturb the
previous site and must not leave a temp directory behind) end to end, which
test_site_build.py's own version of this test cannot reach: its first
build.build(ROOT, out) call raises FileNotFoundError before the monkeypatch
scenario it means to test.

The interruption tests below cover the failure shape neither file reached
before: a stop that is not a synchronous Exception raised inside the try block.
A monkeypatched function that raises is still an Exception; a cancelled CI job,
an OOM kill, a Ctrl-C or a timeout SIGTERM is not. Each of these drives a real
SIGKILL in a child process, or a real KeyboardInterrupt, and pins what survives:

3. spec/published.lock.json is committed state that every later build reads
   unconditionally, so a kill part way through the lock write must leave it
   intact rather than truncated, and the temp file must be a sibling of the
   target so the install rename cannot cross a filesystem.
4. A killed build leaves its .dist-* scratch directory behind because nothing
   in the process runs; the next build must reap it.
5. A KeyboardInterrupt must clean up the scratch directory in-process, which
   the earlier `except Exception` did not do.
6. The module docstring must claim only the atomicity the code delivers.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import build  # noqa: E402

_LANDING = "# Context Bill of Materials\n\nStand-in landing text. Task 9 has not landed on this branch.\n"
_SPEC = "# CxBOM specification 0.2.0\n\nStand-in specification text. Task 9 has not landed on this branch.\n"
_PREFIX = 20  # bytes each child writes before killing itself, as the review's kill did

# Child processes, because SIGKILL is the point: nothing in the dying process
# gets to clean up, so the guarantee has to come from the order of the writes.
# Both children truncate the write before the kill, so a non-atomic write path
# leaves its target truncated exactly as the review reproduced it.
_KILL_LOCK_CHILD = '''\
"""Kill this process part way through the schema-lock write. Test helper."""
import io
import os
import signal
import sys
from pathlib import Path

root, prefix, site_dir = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
sys.path.insert(0, site_dir)
from cxsite import build


def _die():
    os.kill(os.getpid(), signal.SIGKILL)


# Two hooks, because a write can reach the filesystem either way: os.write for
# the raw-descriptor path an atomic install uses, io.open for the buffered path
# Path.write_text uses. Whichever one the code under test takes, it dies part
# way through the first write to the file it chose.
_os_write = os.write


def _killing_os_write(fd, data):
    _os_write(fd, data[:prefix])
    _die()


os.write = _killing_os_write
_io_open = io.open


class _Truncating:
    def __init__(self, f):
        self._f = f

    def write(self, data):
        self._f.write(data[:prefix])
        self._f.flush()
        _die()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __getattr__(self, name):
        return getattr(self._f, name)


def _killing_io_open(file, mode="r", *a, **k):
    f = _io_open(file, mode, *a, **k)
    return _Truncating(f) if any(c in mode for c in "wax") else f


io.open = _killing_io_open

build.lock_new_schemas(root)
sys.exit(97)  # never reached: the write above kills this process
'''

_KILL_BUILD_CHILD = '''\
"""Kill this process part way through a site build. Test helper."""
import os
import signal
import sys
from pathlib import Path

root, out, stop_at, site_dir = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
sys.path.insert(0, site_dir)
from cxsite import build

_write = build._write


def _killing_write(target, rel, data):
    if rel != stop_at:
        return _write(target, rel, data)
    _write(target, rel, data[:20])
    os.kill(os.getpid(), signal.SIGKILL)


build._write = _killing_write

build.build(root, out)
sys.exit(97)  # never reached: the write above kills this process
'''


def _spec_copy(tmp_path: Path) -> Path:
    root = tmp_path / "lock-root"
    shutil.copytree(ROOT / "spec", root / "spec")
    return root


def _add_unlocked_schema(root: Path, version: str) -> str:
    """Write a self-describing spec/cxbom-<version>.schema.json that is not yet locked."""
    name = f"cxbom-{version}.schema.json"
    doc = json.loads((root / "spec" / build.REFERENCE_SCHEMA).read_text(encoding="utf-8"))
    doc["$id"] = f"https://cxbom.org/schema/{version}/cxbom.schema.json"
    (root / "spec" / name).write_text(json.dumps(doc), encoding="utf-8")
    return name


def _run_child(tmp_path: Path, name: str, source: str, *args: str) -> subprocess.CompletedProcess:
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    return subprocess.run([sys.executable, str(script), *args], capture_output=True, timeout=180)


def _killed_lock_run(tmp_path: Path) -> tuple[Path, Path, bytes]:
    """SIGKILL a lock run part way through its write. Returns root, lock path, and the bytes before."""
    root = _spec_copy(tmp_path)
    _add_unlocked_schema(root, "0.9.0")
    lock_path = root / "spec" / "published.lock.json"
    before = lock_path.read_bytes()
    proc = _run_child(tmp_path, "kill_lock_child.py", _KILL_LOCK_CHILD,
                      str(root), str(_PREFIX), str(ROOT / "site"))
    assert proc.returncode == -signal.SIGKILL, (proc.returncode, proc.stderr.decode())
    return root, lock_path, before


def _synthetic_root(tmp_path: Path) -> Path:
    """A copy of spec/ and site/ with Task 9's two missing files stood in."""
    root = tmp_path / "synthetic-root"
    shutil.copytree(ROOT / "spec", root / "spec", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "site", root / "site", ignore=shutil.ignore_patterns("__pycache__"))
    (root / "docs" / "design").mkdir(parents=True)
    shutil.copy(ROOT / "docs" / "design" / "tool.md", root / "docs" / "design" / "tool.md")
    (root / "site" / "content").mkdir(parents=True, exist_ok=True)
    (root / "site" / "content" / "landing.md").write_text(_LANDING, encoding="utf-8")
    (root / "spec" / "SPEC.md").write_text(_SPEC, encoding="utf-8")
    return root


def test_synthetic_root_builds_the_full_site_map(tmp_path: Path):
    # Confirms the stand-in is sufficient (a real build succeeds), which every
    # other test in this module depends on.
    root = _synthetic_root(tmp_path)
    out = tmp_path / "dist"
    written = build.build(root, out)
    assert "index.html" in written
    assert "spec/index.html" in written
    assert (out / "index.html").is_file()


def test_refuses_a_directory_with_only_one_of_the_two_marker_files(tmp_path: Path):
    root = _synthetic_root(tmp_path)
    victim = tmp_path / "dist"
    victim.mkdir()
    (victim / "index.html").write_text("not a real build", encoding="utf-8")
    # Deliberately no _headers file: a real previous build always has both, so
    # this directory must still be refused, the same as one with neither marker.
    with pytest.raises(build.BuildError, match="Refusing"):
        build.build(root, victim)
    assert (victim / "index.html").read_text(encoding="utf-8") == "not a real build"
    assert not (victim / "_headers").exists()


def test_failed_rebuild_keeps_the_previous_site_and_leaves_no_temp_dir(tmp_path: Path, monkeypatch):
    root = _synthetic_root(tmp_path)
    out = tmp_path / "dist"
    build.build(root, out)
    before = (out / "index.html").read_bytes()

    def refuse(_tool_md):
        raise build.scope.ScopeError("section 2 lead-in changed: test")
    monkeypatch.setattr(build.scope, "scope_markdown", refuse)
    with pytest.raises(build.scope.ScopeError):
        build.build(root, out)
    assert (out / "index.html").read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dist", "synthetic-root"]


def test_lock_refuses_to_serve_two_schemas_at_the_same_url(tmp_path: Path):
    # Every filename that matches _SCHEMA_NAME determines its own url, so two
    # files glob-discovered in the same call can never collide (the mapping
    # from filename to url is injective). The real hazard is a lock entry
    # added under a different key (a hand edit, or a future renaming) that
    # already claims the url a brand new, correctly self-describing file
    # would also compute. This test recreates that: the lock gets an extra
    # entry, under a key with no file on disk, that already serves
    # /schema/0.5.0/; a new cxbom-0.5.0.schema.json file, whose own $id
    # correctly names its own filename-derived url, must still be refused.
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "spec", root / "spec")
    lock_path = root / "spec" / "published.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    vendored = lock.pop("vendored")
    lock["cxbom-0.5.0-hand-added.schema.json"] = {
        "sha256": "0" * 64,
        "servedAt": "https://cxbom.org/schema/0.5.0/cxbom.schema.json",
        "immutable": True,
    }
    lock["vendored"] = vendored
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")

    doc = json.loads((root / "spec/cxbom-0.2.0.schema.json").read_text(encoding="utf-8"))
    doc["$id"] = "https://cxbom.org/schema/0.5.0/cxbom.schema.json"
    (root / "spec/cxbom-0.5.0.schema.json").write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(build.BuildError, match="already served"):
        build.lock_new_schemas(root)


def test_a_kill_during_the_lock_write_leaves_the_committed_lock_intact(tmp_path: Path):
    root, lock_path, before = _killed_lock_run(tmp_path)
    after = lock_path.read_bytes()
    assert after == before, f"{len(before)} bytes before, {len(after)} after"
    json.loads(after.decode("utf-8"))  # raises if the kill left it truncated

    temps = sorted((root / "spec").glob("published.lock.json.*.tmp"))
    # The truncated bytes landed on a sibling inside spec/, which is what makes
    # the install rename atomic: os.replace is atomic only within a filesystem,
    # so a temp file anywhere else would be a copy across a boundary instead.
    assert len(temps) == 1, temps
    assert len(temps[0].read_bytes()) == _PREFIX


def test_the_lock_install_fsyncs_then_renames_within_the_spec_directory(tmp_path: Path, monkeypatch):
    # The kill test above pins what survives a dying process. This one pins the
    # mechanism, which is the part a dying process cannot show: a copy, a direct
    # write, or a temp file on another filesystem all leave the same evidence
    # behind at the moment of a kill, and all three lose the guarantee.
    root = _spec_copy(tmp_path)
    _add_unlocked_schema(root, "0.9.0")
    lock_path = root / "spec" / "published.lock.json"
    mode_before = lock_path.stat().st_mode & 0o777
    events: list[tuple] = []
    real_fsync, real_replace = os.fsync, os.replace

    def recording_fsync(fd):
        events.append(("fsync",))
        return real_fsync(fd)

    def recording_replace(src, dst, **kwargs):
        events.append(("replace", Path(src), Path(dst)))
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(build.os, "fsync", recording_fsync)
    monkeypatch.setattr(build.os, "replace", recording_replace)
    assert build.lock_new_schemas(root) == ["cxbom-0.9.0.schema.json"]

    # fsync first: the data has to reach the disk before the rename names it, or
    # a host that loses power can come back with the new name over blocks that
    # were never written. Then one rename, whose source is a sibling of the
    # target, because a rename is atomic only within a single filesystem.
    assert [e[0] for e in events] == ["fsync", "replace"], events
    _, src, dst = events[1]
    assert dst == lock_path
    assert src.parent == lock_path.parent
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock["cxbom-0.9.0.schema.json"]["servedAt"] == "https://cxbom.org/schema/0.9.0/cxbom.schema.json"
    # A temp file starts 0600. Installing one over a committed file must not
    # narrow that file's permissions as a side effect.
    assert lock_path.stat().st_mode & 0o777 == mode_before


def test_a_keyboard_interrupt_during_the_lock_install_leaves_no_temp_file(tmp_path: Path, monkeypatch):
    root = _spec_copy(tmp_path)
    _add_unlocked_schema(root, "0.9.0")
    lock_path = root / "spec" / "published.lock.json"
    before = lock_path.read_bytes()

    def interrupt(_src, _dst, **_kwargs):
        # A BaseException, not an Exception: `except Exception` never sees it.
        raise KeyboardInterrupt

    monkeypatch.setattr(build.os, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt):
        build.lock_new_schemas(root)
    assert lock_path.read_bytes() == before
    assert sorted((root / "spec").glob("published.lock.json.*.tmp")) == []


def test_the_next_lock_run_reaps_the_temp_file_a_killed_run_left(tmp_path: Path):
    root, lock_path, _ = _killed_lock_run(tmp_path)
    spec = root / "spec"
    assert len(sorted(spec.glob("published.lock.json.*.tmp"))) == 1

    assert build.lock_new_schemas(root) == ["cxbom-0.9.0.schema.json"]
    assert sorted(spec.glob("published.lock.json.*.tmp")) == []
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock["cxbom-0.9.0.schema.json"]["servedAt"] == "https://cxbom.org/schema/0.9.0/cxbom.schema.json"
    assert list(lock)[-1] == "vendored"


def test_a_killed_build_leaves_a_scratch_dir_that_the_next_build_reaps(tmp_path: Path):
    root = _synthetic_root(tmp_path)
    out = tmp_path / "dist"
    build.build(root, out)
    before = (out / "index.html").read_bytes()

    proc = _run_child(tmp_path, "kill_build_child.py", _KILL_BUILD_CHILD,
                      str(root), str(out), "reference/index.html", str(ROOT / "site"))
    assert proc.returncode == -signal.SIGKILL, (proc.returncode, proc.stderr.decode())
    orphans = sorted(p for p in out.parent.glob(".dist-*") if p.is_dir())
    assert len(orphans) == 1, orphans
    assert (out / "index.html").read_bytes() == before  # the served tree is untouched

    build.build(root, out)
    assert sorted(out.parent.glob(".dist-*")) == []
    assert (out / "index.html").read_bytes() == before
    assert (out / "reference" / "index.html").is_file()


def test_a_keyboard_interrupt_during_a_build_leaves_no_scratch_dir(tmp_path: Path, monkeypatch):
    root = _synthetic_root(tmp_path)
    out = tmp_path / "dist"
    build.build(root, out)
    before = (out / "index.html").read_bytes()

    def interrupt(_tool_md):
        # A BaseException, not an Exception: `except Exception` never sees it.
        raise KeyboardInterrupt

    monkeypatch.setattr(build.scope, "scope_markdown", interrupt)
    with pytest.raises(KeyboardInterrupt):
        build.build(root, out)
    assert (out / "index.html").read_bytes() == before
    assert sorted(out.parent.glob(".dist-*")) == []


def test_the_module_docstring_claims_only_the_atomicity_the_code_delivers():
    # Pinned deliberately: every clause below is a claim one of the tests in this
    # module holds the code to. An unmarked claim the code does not deliver is
    # the defect this test exists to stop from coming back.
    doc = build.__doc__
    assert "never leaves a half-built site behind" not in doc  # a SIGKILL does leave the scratch dir
    assert "never a partial tree" in doc  # what the directory swap really gives
    assert "reaps the `.dist-*`" in doc  # how the scratch directory is collected
    assert "never truncated" in doc  # the schema-lock write's guarantee
