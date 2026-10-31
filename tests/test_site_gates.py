"""Each publication gate passes on the real build and fires on a planted fault.

Owner: ATACE Working Group.

The negative controls use a synthetic denylist, so no real identity string
appears in this file.

Three kinds of case run against every gate, because a publication gate that
reads "pass" on input it should refuse is a disclosure:

    the gate passing on the real build, so a gate that refuses everything is
    not mistaken for a working one;

    the gate refusing a planted fault, driven through the public entry point;

    the gate's own tooling absent, unreadable, or exiting non-zero for a reason
    other than a finding. A gate that treats "the checker crashed" as "the
    checker passed" is the defect this suite exists to catch.
"""
import ast
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import build, gates, links, reference  # noqa: E402

TOKENS = ["zz-secret-person", "zz-secret-org"]
ROOT_ONLY = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site") / "dist"
    build.build(ROOT, out)
    return out


@pytest.fixture
def dist(built: Path, tmp_path: Path) -> Path:
    copy = tmp_path / "dist"
    shutil.copytree(built, copy)
    return copy


def _lock() -> dict:
    return build.load_lock(ROOT)


def _append(p: Path, text: str) -> None:
    p.write_text(p.read_text(encoding="utf-8").replace("</main>", text + "</main>"), encoding="utf-8")


@pytest.fixture
def unreadable():
    """Drop a file's permissions for one test, restoring them so cleanup works."""
    restored: list[tuple[Path, int]] = []

    def drop(p: Path) -> Path:
        restored.append((p, p.stat().st_mode))
        p.chmod(0o000)
        return p

    yield drop
    for p, mode in restored:
        p.chmod(mode)


def test_real_build_passes_every_gate(built: Path):
    assert gates.run_all(built, _lock(), TOKENS) == []


def test_each_gate_passes_the_real_build_on_its_own(built: Path):
    # run_all passing could also mean run_all skips gates. Drive each one.
    assert gates.check_freeze(built, _lock()) == []
    assert gates.check_anonymity(built, TOKENS) == []
    assert gates.check_links(built) == []
    assert gates.check_scripts(built) == []
    assert gates.check_inline(built) == []
    assert gates.check_schema_ids(built) == []
    assert gates.check_site_urls(built) == []
    assert gates.check_contrast(built) == []


# Gate 1: freeze
def test_freeze_skips_a_local_entry_and_refuses_one_that_claims_a_served_url(built: Path):
    # A local lock entry is a site artifact the build reads but does not serve at a
    # frozen URL (the 0.3.0 reference record), and the build skips it the same way.
    lock = _lock()
    assert any(e.get("local") for n, e in lock.items() if n != "vendored")
    assert gates.check_freeze(built, lock) == []
    name = next(n for n, e in lock.items() if n != "vendored" and e.get("local"))
    lock[name] = dict(lock[name], servedAt="https://cxbom.org/data/x.json")
    errs = gates.check_freeze(built, lock)
    assert errs == [f"freeze: {name}: a local entry cannot also claim servedAt"]


def test_freeze_fires_on_changed_schema_bytes(dist: Path):
    p = dist / "schema/0.2.0/cxbom.schema.json"
    p.write_bytes(p.read_bytes() + b"\n")
    assert gates.check_freeze(dist, _lock()) == [
        "freeze: cxbom-0.2.0.schema.json: https://cxbom.org/schema/0.2.0/cxbom.schema.json does not match its locked hash"]


def test_freeze_fires_on_missing_schema(dist: Path):
    (dist / "schema/0.2.0/cxbom.schema.json").unlink()
    assert "is missing from the build" in gates.check_freeze(dist, _lock())[0]


def test_freeze_refuses_a_lock_that_pins_nothing(dist: Path):
    # An empty lock would otherwise pass by having no artifact to disagree with.
    assert gates.check_freeze(dist, {"vendored": {"anything": 1}}) == [
        "freeze: the lock pins no published artifact, so nothing is frozen"]


@pytest.mark.parametrize("served", [
    "https://evil.example/schema/0.2.0/cxbom.schema.json",
    "http://cxbom.org/schema/0.2.0/cxbom.schema.json",
    "/schema/0.2.0/cxbom.schema.json",
    "https://cxbom.orgschema/x.json",
])
def test_freeze_fires_when_served_at_is_not_on_the_site_origin(dist: Path, served: str):
    lock = {"a.json": {"servedAt": served, "sha256": "0" * 64}}
    errs = gates.check_freeze(dist, lock)
    assert len(errs) == 1 and "is not on https://cxbom.org" in errs[0]


def test_freeze_fires_on_a_served_at_that_walks_out_of_the_build(dist: Path, tmp_path: Path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    lock = {"a.json": {"servedAt": "https://cxbom.org/../outside.json",
                       "sha256": hashlib.sha256(b"{}").hexdigest()}}
    # The digest matches the file the path walks to, so a gate that resolved the
    # path would report a pass. Containment is what makes this a refusal.
    assert gates.check_freeze(dist, lock) == [
        "freeze: a.json: https://cxbom.org/../outside.json is missing from the build"]


def test_freeze_fires_on_a_symlink_that_leaves_the_build(dist: Path, tmp_path: Path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (dist / "escape.json").symlink_to(outside)
    lock = {"a.json": {"servedAt": "https://cxbom.org/escape.json",
                       "sha256": hashlib.sha256(b"{}").hexdigest()}}
    # The digest matches what the link points at, so a gate that followed the
    # link out of the build would hash the outside file and report a pass.
    assert gates.check_freeze(dist, lock) == [
        "freeze: a.json: https://cxbom.org/escape.json is missing from the build"]


@pytest.mark.parametrize("digest", ["", "0" * 63, "0" * 65, "Z" * 64, "0" * 64 + "a", None, 1])
def test_freeze_fires_on_a_digest_that_is_not_a_sha256(dist: Path, digest):
    lock = {"a.json": {"servedAt": "https://cxbom.org/schema/0.2.0/cxbom.schema.json", "sha256": digest}}
    errs = gates.check_freeze(dist, lock)
    assert len(errs) == 1 and "is not a sha-256 digest" in errs[0]


def test_freeze_fires_on_a_lock_entry_that_is_not_an_object(dist: Path):
    assert gates.check_freeze(dist, {"a.json": "nope"}) == ["freeze: a.json: lock entry is not an object"]


@ROOT_ONLY
def test_freeze_fires_when_the_served_file_cannot_be_read(dist: Path, unreadable):
    unreadable(dist / "schema/0.2.0/cxbom.schema.json")
    errs = gates.check_freeze(dist, _lock())
    assert len(errs) == 1 and "cannot be read" in errs[0]


# Gate 2: anonymity, invoked as scripts/anon_check.py site
def test_anonymity_fires_on_a_denylisted_token(dist: Path):
    _append(dist / "spec/index.html", "<p>ZZ-Secret-Org</p>")
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1
    assert errs[0].startswith("anonymity: index.html: contains a denylisted token")
    assert "#2" in errs[0]


def test_anonymity_fails_closed_without_a_denylist(dist: Path):
    errs = gates.check_anonymity(dist, [])
    assert len(errs) == 1 and "refusing to certify anonymity" in errs[0]


@pytest.mark.parametrize("token", ["#zz-not-a-comment", "", "   "])
def test_anonymity_refuses_a_token_the_denylist_format_would_drop(dist: Path, token: str):
    # A token that does not survive the round trip would leave the scan running
    # against fewer tokens than the caller asked for, which reads as a pass.
    errs = gates.check_anonymity(dist, TOKENS + [token])
    assert len(errs) == 1 and "do not survive" in errs[0]


def test_anonymity_reads_the_repository_denylist_when_given_its_root(built: Path):
    anon = gates.anon_module()
    tokens = anon.load_tokens(ROOT / anon.DENYLIST_NAME)
    if not tokens:
        pytest.skip(f"{anon.DENYLIST_NAME} is absent; the pre-commit hook is the fail-closed path")
    # The publish path. Nothing is written anywhere, and the build is clean, so
    # the pass here is the checker's, not this test's.
    assert gates.check_anonymity(built, tokens, denylist_root=ROOT) == []


def test_anonymity_positive_control_through_the_repository_denylist(dist: Path):
    anon = gates.anon_module()
    tokens = anon.load_tokens(ROOT / anon.DENYLIST_NAME)
    if not tokens:
        pytest.skip(f"{anon.DENYLIST_NAME} is absent")
    # Proves the denylist_root path scans rather than passing vacuously, without
    # this file ever holding a real token. The planted fault is structural, a
    # file the checker cannot scan, so the refusal does not depend on what the
    # real denylist contains and nothing it reports can carry a token.
    os.mkfifo(dist / "pipe")
    errs = gates.check_anonymity(dist, tokens, denylist_root=ROOT)
    assert errs == ["anonymity: pipe: not a regular file"]


_STUB_TOKENS = (
    'DENYLIST_NAME = ".anon-tokens"\n'
    "def load_tokens(path):\n"
    "    return [l.strip().lower() for l in path.read_text().splitlines() if l.strip()]\n"
    "def require_tokens(tokens):\n"
    '    return [] if tokens else ["refusing to certify anonymity"]\n'
)
# A stub stands in for a checker, and the gate asks a checker to prove it can
# still find a planted token before it takes the checker's verdict on the build.
# So a stub that is meant to be believed detects: it exits 1 on the canary
# directory and only then falls through to whatever the test scripted. Exiting
# first also keeps the canary invocation out of the recording bodies below, so
# each test still observes exactly one scan, the real one.
def _stub_canary(skip: str | None = None, code: int = 1) -> str:
    """The canary half of a stub checker: one finding per planted file, as the real one reports.

    `skip` names a suffix the stub does not read, which is the fault a checker
    narrowed by file type has. `code` is the exit status it reports them with.
    """
    return (
        f"CANARY_TOKEN = {gates.CANARY_TOKEN!r}\n"
        f"SKIP = {skip!r}\n"
        "import pathlib, sys\n"
        "def _canary(argv):\n"
        '    if len(argv) != 3 or argv[1] != "site":\n'
        "        return\n"
        "    root = pathlib.Path(argv[2])\n"
        "    hits = [p.name for p in sorted(root.rglob('*')) if p.is_file()\n"
        '            and CANARY_TOKEN in p.read_text(errors="ignore")]\n'
        "    if not hits:\n"
        "        return\n"
        "    for name in hits:\n"
        "        if SKIP is None or pathlib.Path(name).suffix != SKIP:\n"
        '            print(f"anon-check: {name}: contains a denylisted token (#1 in .anon-tokens)",\n'
        "                  file=sys.stderr)\n"
        f"    raise SystemExit({code})\n"
    )


_STUB_CANARY = _stub_canary()
_STUB_HELPERS = (_STUB_CANARY + _STUB_TOKENS
                 + 'if __name__ == "__main__":\n'
                   "    _canary(sys.argv)\n")


def _stub(tmp_path: Path, body: str, monkeypatch) -> Path:
    """Stand in for scripts/anon_check.py with a scripted exit, and bind the gate to it."""
    return _raw_stub(tmp_path, _STUB_HELPERS + "".join(f"    {ln}\n" for ln in body.splitlines()),
                     monkeypatch)


def _raw_stub(tmp_path: Path, source: str, monkeypatch) -> Path:
    """Bind the gate to a checker written out in full, for faults in the helpers themselves."""
    p = tmp_path / "anon_check.py"
    p.write_text(source, encoding="utf-8")
    monkeypatch.setattr(gates, "ANON_SCRIPT", p)
    return p


def test_anonymity_refuses_when_the_checker_is_absent(dist: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(gates, "ANON_SCRIPT", tmp_path / "no_such_anon_check.py")
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "cannot be loaded" in errs[0] and "refusing to certify" in errs[0]


@ROOT_ONLY
def test_anonymity_refuses_when_the_checker_cannot_be_read(dist: Path, tmp_path: Path, monkeypatch, unreadable):
    p = _stub(tmp_path, "sys.exit(0)", monkeypatch)
    unreadable(p)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "cannot be loaded" in errs[0]


@pytest.mark.parametrize("status", ["0", "1", '"exploded"'])
def test_anonymity_refuses_a_checker_that_exits_while_loading(dist: Path, tmp_path: Path,
                                                             monkeypatch, status: str):
    # SystemExit is not an Exception. A checker whose top level raised
    # SystemExit(0) once ended the build at status 0 with no gate having run.
    p = tmp_path / "anon_check.py"
    p.write_text(f"raise SystemExit({status})\n", encoding="utf-8")
    monkeypatch.setattr(gates, "ANON_SCRIPT", p)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1
    assert "failed while loading" in errs[0] and "refusing to certify anonymity" in errs[0]


def test_build_command_exits_one_when_the_checker_exits_while_loading(tmp_path: Path, monkeypatch, capsys):
    p = tmp_path / "anon_check.py"
    p.write_text("raise SystemExit(0)\n", encoding="utf-8")
    monkeypatch.setattr(gates, "ANON_SCRIPT", p)
    assert build.main(["--out", str(tmp_path / "dist")]) == 1
    assert "gate: anonymity: " in capsys.readouterr().err


def test_anonymity_passes_only_on_exit_zero(dist: Path, tmp_path: Path, monkeypatch):
    _stub(tmp_path, "sys.exit(0)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == []


@pytest.mark.parametrize("code", [2, 3, 70, 255])
def test_anonymity_refuses_any_exit_code_that_is_not_a_finding(dist: Path, tmp_path: Path, monkeypatch, code: int):
    _stub(tmp_path, f"sys.exit({code})", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1
    assert f"exited {code} without completing a scan" in errs[0]
    assert "refusing to certify anonymity" in errs[0]


def test_anonymity_refuses_a_finding_exit_that_printed_no_detail(dist: Path, tmp_path: Path, monkeypatch):
    # Exit 1 with an empty report must not collapse to an empty error list.
    _stub(tmp_path, "sys.exit(1)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == [
        "anonymity: anon_check.py site reported a finding and printed no detail"]


def test_anonymity_reports_the_checkers_own_lines_on_a_finding(dist: Path, tmp_path: Path, monkeypatch):
    _stub(tmp_path, 'sys.stderr.write("anon-check: a.html: something\\nanon-check: b.html: else\\n")\n'
                    "sys.exit(1)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == [
        "anonymity: a.html: something", "anonymity: b.html: else"]


def test_anonymity_refuses_when_the_checker_cannot_be_spawned(dist: Path, tmp_path: Path, monkeypatch):
    _stub(tmp_path, "sys.exit(0)", monkeypatch)
    monkeypatch.setattr(gates.sys, "executable", str(tmp_path / "no-such-interpreter"))
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "could not be run" in errs[0] and "refusing to certify" in errs[0]


def test_anonymity_refuses_when_the_scan_of_the_build_cannot_be_spawned(
        dist: Path, tmp_path: Path, monkeypatch):
    # The probe and the canary spawn before this one, so an interpreter that
    # cannot be spawned at all is caught by them and the scan's own OSError
    # branch is never reached. Only a failure aimed at the build scan reaches it,
    # and that branch must refuse rather than return an empty finding list.
    real = gates.subprocess.run

    def fail_only_on_the_build(argv, **kw):
        if argv[-1] == str(dist):
            raise OSError(13, "Permission denied")
        return real(argv, **kw)

    _stub(tmp_path, "sys.exit(0)", monkeypatch)
    monkeypatch.setattr(gates.subprocess, "run", fail_only_on_the_build)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1
    assert "could not be run" in errs[0] and "refusing to certify anonymity" in errs[0]


def test_anonymity_refuses_an_empty_denylist_without_invoking_the_checker(dist: Path, tmp_path: Path, monkeypatch):
    # The checker refuses an empty denylist too, so an assertion on the message
    # alone would pass with this layer removed. What distinguishes the two is
    # that the gate never gets as far as a scan.
    ran = tmp_path / "ran"
    _stub(tmp_path, f"import pathlib\npathlib.Path({str(ran)!r}).write_text('x')\nsys.exit(0)", monkeypatch)
    errs = gates.check_anonymity(dist, [])
    assert len(errs) == 1 and "refusing to certify anonymity" in errs[0]
    assert not ran.exists(), "the gate scanned with no denylist to scan against"


def test_anonymity_refuses_an_exit_one_that_is_a_traceback_rather_than_a_report(
        dist: Path, tmp_path: Path, monkeypatch):
    """An uncaught exception in the checker exits 1 with a traceback on stderr.

    Every frame carries an absolute filesystem path, and the checker's own
    withholding pass never ran, because the crash happened before it. Reachable
    with no tampering: running the build where `git rev-parse --show-toplevel`
    fails, which is any export without a .git, produced fifteen such lines.
    """
    _stub(tmp_path, r'sys.stderr.write("Traceback (most recent call last):\n'
                    r'  File \"/zz-home/zz-person/scripts/anon_check.py\", line 913, in <module>\n'
                    r'RuntimeError: planted\n")' "\n"
                    "sys.exit(1)", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1
    assert "crash report rather than a report" in errs[0]
    assert "refusing to certify anonymity" in errs[0]
    # Nothing forwarded, so nothing that could be part of a path.
    assert "/" not in errs[0] and "zz-person" not in errs[0]


def test_anonymity_refuses_a_finding_report_mixed_with_unprefixed_lines(
        dist: Path, tmp_path: Path, monkeypatch):
    # A real finding alongside a traceback is still a crash report. Forwarding
    # the findings and dropping the rest would print a partial report as if the
    # checker had finished.
    _stub(tmp_path, r'sys.stderr.write("anon-check: a.html: something\n'
                    r'  File \"/zz-home/zz-person/x.py\", line 1\n")' "\n"
                    "sys.exit(1)", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "crash report rather than a report" in errs[0]
    assert "a.html" not in errs[0]


def test_the_forwarding_bound_is_a_bound(built: Path):
    # Asserted as a range before the test below reads it, because a bound raised
    # to something enormous is the same as no bound and the test below would
    # quietly try to print that many lines rather than fail.
    assert 1 <= gates.ANON_MAX_FINDINGS <= 200


def test_anonymity_bounds_how_many_findings_it_forwards(dist: Path, tmp_path: Path, monkeypatch):
    # The exit-1 branch was the only one with no bound on how much it forwards.
    assert 1 <= gates.ANON_MAX_FINDINGS <= 200
    over = 7
    n = gates.ANON_MAX_FINDINGS + over
    _stub(tmp_path, f"for i in range({n}):\n"
                    r'    sys.stderr.write("anon-check: f%d.html: something\n" % i)' "\n"
                    "sys.exit(1)", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == gates.ANON_MAX_FINDINGS + 1
    assert errs[0] == "anonymity: f0.html: something"
    assert errs[-1] == f"anonymity: and {over} further findings, not shown"


def test_anonymity_forwards_no_unprefixed_detail_on_any_other_exit_code(
        dist: Path, tmp_path: Path, monkeypatch):
    # The usage gate exits 2 and prints the module docstring, unprefixed. The
    # refusal names the code; the docstring is not a finding and is not forwarded.
    _stub(tmp_path, r'sys.stderr.write("/zz-home/zz-person: usage text\n")' "\n"
                    "sys.exit(2)", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert errs == ["anonymity: anon_check.py site exited 2 without completing a scan; "
                    "refusing to certify anonymity"]


# Gate 2, the canary. A zero exit is the only evidence the gate gets from the
# checker, and a zero exit cannot tell "scanned and found nothing" from
# "returned without scanning".
def test_the_real_checker_reports_the_canary_token(built: Path):
    # The exhibit: the live checker, the live scratch-denylist machinery, and a
    # planted synthetic token, with exit 1 required. Every check_anonymity call
    # in this file goes through this, so the whole gate-2 block is also its
    # regression test.
    anon = gates.anon_module()
    assert gates._canary_scan(anon.DENYLIST_NAME, built) == []


@pytest.mark.parametrize("body,what", [
    ("sys.exit(0)", "returns 0 with no output"),
    (r'sys.stderr.write("anon-check: canary.html: something\n")' "\nsys.exit(0)",
     "prints a finding and returns 0"),
    ("import os\nos._exit(0)", "hard-exits 0 inside the scan"),
    ("raise SystemExit(0)", "raises SystemExit(0) inside the scan"),
])
def test_anonymity_refuses_a_checker_that_cannot_find_a_planted_token(
        dist: Path, tmp_path: Path, monkeypatch, body: str, what: str):
    """Cases 5, 7, 10 and 11 of the injection table, all of which exit 0.

    Nothing outside the checker can tell these from a clean scan, because a zero
    exit is all they offer. The canary can, because it knows the answer.
    """
    # Deliberately not _stub: these stand in for a checker whose site path does
    # not detect, so they must not inherit the canary-aware behaviour.
    _raw_stub(tmp_path, _STUB_TOKENS + "import sys\n" + 'if __name__ == "__main__":\n'
              + "".join(f"    {ln}\n" for ln in body.splitlines()), monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1, (what, errs)
    assert "did not report a planted token in every published file type" in errs[0], what
    assert "refusing to certify anonymity" in errs[0], what


def test_the_canary_plants_every_file_type_the_build_publishes(built: Path):
    # Read back from the build with a walk of its own, so a canary that planted
    # a fixed list would disagree with it as soon as the build published a type
    # the list did not name.
    published = {p.suffix for p in built.rglob("*") if p.is_file()}
    assert {".html", ".json"} <= published, "the build publishes less than this test assumes"
    assert gates._published_suffixes(built) == sorted(published)


def test_an_empty_build_still_gets_a_canary(tmp_path: Path):
    assert gates._published_suffixes(tmp_path) == [""]


def _skipping_stub(tmp_path: Path, skip: str, monkeypatch) -> None:
    """A checker whose canary report leaves out every file with one suffix, and whose
    real scan passes, so only the canary stands between it and a certified build."""
    _raw_stub(tmp_path, _stub_canary(skip) + _STUB_TOKENS + 'if __name__ == "__main__":\n'
              "    _canary(sys.argv)\n    sys.exit(0)\n", monkeypatch)


def test_the_canary_refuses_a_checker_that_skips_any_published_file_type(
        dist: Path, tmp_path: Path, monkeypatch):
    """N2: a checker narrowed by file type fails open for that type alone.

    One case per suffix the build actually publishes, read from the build, so
    each type the site ships is proved scanned rather than assumed.
    """
    suffixes = gates._published_suffixes(dist)
    assert ".json" in suffixes
    for skip in suffixes:
        _skipping_stub(tmp_path, skip, monkeypatch)
        errs = gates.check_anonymity(dist, TOKENS)
        assert len(errs) == 1, (skip, errs)
        assert "did not report a planted token in every published file type" in errs[0], skip
        assert f"{len(suffixes) - 1} of {len(suffixes)} planted files reported" in errs[0], skip
        assert f"missed: {skip or 'no suffix'})" in errs[0], skip


def test_the_canary_covers_a_file_type_the_build_newly_publishes(
        dist: Path, tmp_path: Path, monkeypatch):
    # A type no list anywhere names. A canary built from a list would plant
    # nothing of this type and pass the checker that skips it.
    (dist / "assets" / "notes.zzq").write_text("plain\n", encoding="utf-8")
    _skipping_stub(tmp_path, ".zzq", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "missed: .zzq)" in errs[0], errs


def test_the_canary_does_not_print_a_suffix_long_enough_to_hold_a_name(
        dist: Path, tmp_path: Path, monkeypatch):
    (dist / "assets" / "notes.zzlongsuffix").write_text("plain\n", encoding="utf-8")
    _skipping_stub(tmp_path, ".zzlongsuffix", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "missed: 1 other)" in errs[0], errs
    assert "zzlongsuffix" not in errs[0]


@pytest.mark.parametrize("code", [0, 2])
def test_the_canary_refuses_a_full_report_with_the_wrong_exit(
        dist: Path, tmp_path: Path, monkeypatch, code: int):
    # Every planted file named, so the per-file clause is satisfied and only the
    # exit status can refuse. Exit 0 with findings on stderr is injection case 5.
    _raw_stub(tmp_path, _stub_canary(code=code) + _STUB_TOKENS + 'if __name__ == "__main__":\n'
              "    _canary(sys.argv)\n    sys.exit(0)\n", monkeypatch)
    n = len(gates._published_suffixes(dist))
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1, errs
    assert f"(exit {code}, {n} of {n} planted files reported, missed: none)" in errs[0]


def test_the_canary_refuses_a_checker_that_crashes_on_it(dist: Path, tmp_path: Path, monkeypatch):
    """N3: exit 1 with no finding, only a traceback line, is not a detection.

    The build scan exits 0 here, so the canary is the only thing that can
    refuse. The stray-line refusal on the build scan never sees this checker.
    """
    _raw_stub(tmp_path, _STUB_TOKENS + f"CANARY_TOKEN = {gates.CANARY_TOKEN!r}\n"
              "import pathlib, sys\n"
              'if __name__ == "__main__":\n'
              "    root = pathlib.Path(sys.argv[2])\n"
              "    if any(CANARY_TOKEN in p.read_text(errors='ignore')\n"
              "           for p in root.rglob('*') if p.is_file()):\n"
              '        sys.stderr.write("Traceback (most recent call last):\\n")\n'
              "        sys.exit(1)\n"
              "    sys.exit(0)\n", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1, errs
    assert "(exit 1, 0 of " in errs[0] and "refusing to certify anonymity" in errs[0]


def test_the_canary_runs_before_the_build_is_scanned(dist: Path, tmp_path: Path, monkeypatch):
    # A gate that scanned first and checked the canary afterwards would still
    # report a pass on a build it had already certified.
    seen = tmp_path / "scanned.txt"
    _raw_stub(tmp_path, _STUB_TOKENS + "import pathlib, sys\n"
              'if __name__ == "__main__":\n'
              f"    pathlib.Path({str(seen)!r}).write_text(sys.argv[2])\n"
              "    sys.exit(0)\n", monkeypatch)
    assert len(gates.check_anonymity(dist, TOKENS)) == 1
    assert seen.read_text() != str(dist), "the build was scanned before the canary was believed"


def test_the_canary_token_is_synthetic(dist: Path):
    # It is planted in a file on disk, so it must not be a real denylist entry
    # and must not match anything in the build.
    assert gates.CANARY_TOKEN.startswith("zz-")
    anon = gates.anon_module()
    assert gates.CANARY_TOKEN not in anon.load_tokens(ROOT / anon.DENYLIST_NAME)
    assert gates.check_anonymity(dist, [gates.CANARY_TOKEN]) == []


# Gate 2, the probe. The three helpers gate 2 shares with the checker are fetched
# out of process, so nothing in that file runs in the process that has to survive
# to report.
@pytest.mark.parametrize("helper", ["require_tokens", "load_tokens"])
@pytest.mark.parametrize("fault", ["raise SystemExit(0)", "import os\n    os._exit(0)"])
def test_anonymity_refuses_a_helper_that_exits_the_interpreter(
        dist: Path, tmp_path: Path, monkeypatch, helper: str, fault: str):
    """Injection cases 8 and 9, and their os._exit siblings.

    Both helpers were called in-process with no handler at all, so a
    SystemExit(0) from either ended the build at status 0 with no gate having run
    and nothing on either stream. Out of process it costs a child.
    """
    # Canary-aware, so the refusal is the probe's and not the canary's: the two
    # closures are independent and this test is aimed at the probe.
    bodies = {
        "require_tokens": "def require_tokens(tokens):\n    {fault}\n    return []\n",
        "load_tokens": ("def load_tokens(path):\n    {fault}\n"
                        "    return [l.strip().lower() for l in path.read_text().splitlines()"
                        " if l.strip()]\n"),
    }
    src = [_STUB_CANARY, 'DENYLIST_NAME = ".anon-tokens"\n']
    for name, template in bodies.items():
        src.append(template.format(fault=fault if name == helper else "pass"))
    src.append('if __name__ == "__main__":\n    _canary(sys.argv)\n    sys.exit(0)\n')
    _raw_stub(tmp_path, "".join(src), monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1, errs
    assert "cannot be loaded in a probe process" in errs[0]
    assert "refusing to certify anonymity" in errs[0]
    if "SystemExit" in fault:
        # The child's own BaseException clause names it. Narrowed to Exception
        # the child dies silently instead and the refusal can only say the probe
        # answered nothing, which is the same verdict with a worse diagnostic.
        assert "SystemExit escaped the probe" in errs[0]
    else:
        assert "it answered nothing" in errs[0]


def test_anonymity_refuses_a_require_tokens_answer_that_is_not_a_list(
        dist: Path, tmp_path: Path, monkeypatch):
    # The parent validates the shape, because the child cannot: coercing a
    # string with list() there would hand up a list of characters that passes.
    _raw_stub(tmp_path, 'DENYLIST_NAME = ".anon-tokens"\n'
              "def load_tokens(path):\n    return []\n"
              'def require_tokens(tokens):\n    return "refusing to certify anonymity"\n',
              monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == [
        "anonymity: anon_check.py did not answer whether the denylist is usable; "
        "refusing to certify anonymity"]


def test_the_build_refuses_a_token_list_that_is_not_a_list_of_strings(
        tmp_path: Path, monkeypatch, capsys):
    # The build reads the repository denylist through the same probe, and a
    # token list that is not one would reach every later comparison as data of
    # the wrong type.
    _raw_stub(tmp_path, 'DENYLIST_NAME = ".anon-tokens"\n'
              "def load_tokens(path):\n    return [1, 2]\n"
              "def require_tokens(tokens):\n    return []\n", monkeypatch)
    with pytest.raises(gates.GateError) as caught:
        gates.denylist_tokens(ROOT)
    assert "did not return a list of tokens" in str(caught.value)
    assert build.main(["--out", str(tmp_path / "dist")]) == 1
    assert "gate: anonymity: " in capsys.readouterr().err


def test_anonymity_refuses_a_checker_that_hangs_on_the_canary(
        dist: Path, tmp_path: Path, monkeypatch):
    # The canary is a subprocess too. A checker that never answers it has not
    # shown it can detect anything, so the timeout is a refusal and not a pass.
    _raw_stub(tmp_path, _STUB_TOKENS + "import time\n"
              'if __name__ == "__main__":\n    time.sleep(30)\n', monkeypatch)
    monkeypatch.setattr(gates, "ANON_TIMEOUT", 1)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "the canary scan did not finish within 1s" in errs[0]
    assert "refusing to certify anonymity" in errs[0]


def test_anonymity_refuses_a_checker_that_hard_exits_while_loading(
        dist: Path, tmp_path: Path, monkeypatch):
    # Injection case 6. os._exit has no handler anywhere, in any process, so the
    # only defence is that the process it ends is not this one.
    _raw_stub(tmp_path, "import os\nos._exit(0)\n", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1
    assert "cannot be loaded in a probe process" in errs[0]
    assert "refusing to certify anonymity" in errs[0]


def test_the_build_command_refuses_a_checker_that_hard_exits_while_loading(
        tmp_path: Path, monkeypatch, capsys):
    # The same fault on the build's own path, which read the denylist in-process.
    _raw_stub(tmp_path, "import os\nos._exit(0)\n", monkeypatch)
    assert build.main(["--out", str(tmp_path / "dist")]) == 1
    err = capsys.readouterr().err
    assert "gate: anonymity: " in err and "refusing to certify anonymity" in err


def test_anonymity_refuses_a_denylist_name_that_is_not_a_filename(
        dist: Path, tmp_path: Path, monkeypatch):
    # DENYLIST_NAME comes from the untrusted file and is used to name a file in a
    # scratch directory. A walk in it must not become a write outside.
    _raw_stub(tmp_path, 'DENYLIST_NAME = "../../escape"\n'
              "def load_tokens(path):\n    return []\n"
              "def require_tokens(tokens):\n    return []\n", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "single filename" in errs[0]


def test_the_probe_answer_is_the_file_not_the_exit_status(dist: Path, tmp_path: Path, monkeypatch):
    # A checker that prints on its way through its module body must not be able
    # to pass that off as the answer, and a zero exit status is not an answer.
    _raw_stub(tmp_path, 'import sys\nsys.stdout.write(\'{"ok": true, '
              '"denylist_name": ".anon-tokens", "missing": []}\')\n'
              "import os\nos._exit(0)\n", monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "cannot be loaded in a probe process" in errs[0]


def test_a_probe_message_that_is_not_fixed_text_is_withheld(dist: Path, tmp_path: Path, monkeypatch):
    # require_tokens' message reaches the gate output. The checker writes it, so
    # it crosses the same withholding rule as everything else from that file.
    _raw_stub(tmp_path, 'DENYLIST_NAME = ".anon-tokens"\n'
              "def load_tokens(path):\n    return []\n"
              "def require_tokens(tokens):\n"
              '    return ["/zz-home/zz-person/.anon-tokens is missing"]\n', monkeypatch)
    errs = gates.check_anonymity(dist, TOKENS)
    assert errs == ["anonymity: a message that is not fixed text, withheld"]


def test_anonymity_refuses_a_checker_that_does_not_finish(dist: Path, tmp_path: Path, monkeypatch):
    _stub(tmp_path, "import time\ntime.sleep(30)", monkeypatch)
    monkeypatch.setattr(gates, "ANON_TIMEOUT", 1)
    # The build carries the film, so the per-megabyte allowance would outlast the stub.
    monkeypatch.setattr(gates, "ANON_SECONDS_PER_MB", 0)
    errs = gates.check_anonymity(dist, TOKENS)
    assert len(errs) == 1 and "did not finish within 1s" in errs[0]


def test_anonymity_invokes_the_site_subcommand_on_the_build(dist: Path, tmp_path: Path, monkeypatch):
    # The ruled acceptance for this gate: the site subcommand is what runs, on
    # the directory under test. Removing the invocation fails here.
    record = tmp_path / "argv.json"
    _stub(tmp_path, f"import json, pathlib\n"
                    f"pathlib.Path({str(record)!r}).write_text(json.dumps(sys.argv[1:]))\n"
                    f"sys.exit(0)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == []
    assert json.loads(record.read_text()) == ["site", str(dist)]


def test_anonymity_hands_the_checker_the_tokens_it_was_given(dist: Path, tmp_path: Path, monkeypatch):
    record = tmp_path / "seen.json"
    _stub(tmp_path, f"import json, pathlib, subprocess\n"
                    f"top = subprocess.run(['git', 'rev-parse', '--show-toplevel'],\n"
                    f"                     capture_output=True, text=True).stdout.strip()\n"
                    f"pathlib.Path({str(record)!r}).write_text(json.dumps(\n"
                    f"    load_tokens(pathlib.Path(top) / DENYLIST_NAME)))\n"
                    f"sys.exit(0)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == []
    assert json.loads(record.read_text()) == TOKENS


def test_anonymity_leaves_no_denylist_behind(dist: Path, tmp_path: Path, monkeypatch):
    record = tmp_path / "root.txt"
    _stub(tmp_path, f"import os, pathlib\n"
                    f"pathlib.Path({str(record)!r}).write_text(os.getcwd())\n"
                    f"sys.exit(0)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == []
    scratch = Path(record.read_text())
    assert not scratch.exists(), "the scratch denylist outlived the scan"


def test_anonymity_scratch_denylist_is_private_while_it_exists(dist: Path, tmp_path: Path, monkeypatch):
    record = tmp_path / "modes.json"
    _stub(tmp_path, f"import json, os, pathlib\n"
                    f"root = pathlib.Path(os.getcwd())\n"
                    f"pathlib.Path({str(record)!r}).write_text(json.dumps(\n"
                    f"    [oct(root.stat().st_mode & 0o777),\n"
                    f"     oct((root / DENYLIST_NAME).stat().st_mode & 0o777)]))\n"
                    f"sys.exit(0)", monkeypatch)
    assert gates.check_anonymity(dist, TOKENS) == []
    assert json.loads(record.read_text()) == ["0o700", "0o600"]


# Gate 2, continued: the outbound-link allowlist
@pytest.mark.parametrize("href", [
    "https://github.com/example/repo", "https://arxiv.org/abs/0000.00000", "http://owasp.org/",
    "//cdn.example.net/x.js", "https://owasp.org.evil.example/", "https://user@owasp.org/",
    "javascript:alert(1)", "mailto:someone@example.net", "relative/page.html"])
def test_link_gate_rejects_identifying_and_unlisted_targets(dist: Path, href: str):
    _append(dist / "index.html", f'<a href="{href}">x</a>')
    errs = gates.check_links(dist)
    assert len(errs) == 1 and errs[0].startswith("links: index.html: ")


@pytest.mark.parametrize("href", [
    # Every shape lane 2's third fix round established, over the built page this
    # time. Uppercase and scheme-less forms reach the host check through the
    # same "//" anchor, credentials and ports stay whole, and the separators a
    # host parser accepts are folded before the comparison.
    "HTTPS://leaking-identity.ac.uk/profile",
    "HtTp://leaking-identity.ac.uk/profile",
    "//leaking-identity.ac.uk/profile",
    "https://leaking-identity.ac.uk@owasp.org/",
    "https://owasp.org:8443/x",
    "https://leaking-identity%2Eac%2Euk/x",
    "https://leaking-identity&#46;ac&#46;uk/x",
    "https://leaking-identity。ac。uk/x",
    "https://leaking­identity.ac.uk/x",
])
def test_link_gate_reads_every_shape_that_carries_an_authority(dist: Path, href: str):
    _append(dist / "index.html", f'<a href="{href}">x</a>')
    errs = gates.check_links(dist)
    assert len(errs) == 1, errs
    assert "not on the allowlist" in errs[0] or "is not an https link" in errs[0]


@pytest.mark.parametrize("href", [
    "https://owasp.org/", "https://genai.owasp.org/x", "https://cwe.mitre.org/", "https://atlas.mitre.org/",
    "https://json-schema.org/", "https://cyclonedx.org/", "mailto:spec@cxbom.org", "/spec/#purpose",
    "https://cxbom.org/schema/0.2.0/cxbom.schema.json", "#main"])
def test_link_gate_accepts_same_origin_and_allowlisted_targets(dist: Path, href: str):
    _append(dist / "index.html", f'<a href="{href}">x</a>')
    assert gates.check_links(dist) == []


# Written out, not read from gates.URL_ATTRS. Parametrising over the set under
# test makes the test shrink with it: cutting URL_ATTRS to href and src left two
# cases, both passing. A literal list plus the equality assertion below is what
# actually holds the nine.
_URL_ATTRS = ["href", "src", "action", "formaction", "poster", "data", "xlink:href", "srcset", "cite"]


def test_the_url_attribute_list_is_the_one_the_tests_cover():
    assert gates.URL_ATTRS == frozenset(_URL_ATTRS)
    assert len(_URL_ATTRS) == len(gates.URL_ATTRS), "a duplicate would hide an uncovered attribute"


@pytest.mark.parametrize("attr", _URL_ATTRS)
def test_link_gate_reads_every_attribute_it_claims(dist: Path, attr: str):
    # Seven of the nine could be cut from URL_ATTRS with a green suite. xlink:href
    # on an inline SVG use is a real disclosure vector, and a meta refresh, a
    # form action and a poster all reach the network without an href or a src.
    tag = "image" if attr == "xlink:href" else "a"
    _append(dist / "index.html", f'<{tag} {attr}="https://leaking-identity.ac.uk/x"></{tag}>')
    errs = gates.check_links(dist)
    assert len(errs) == 1, (attr, errs)
    assert "not on the allowlist" in errs[0], attr


def test_resolve_refuses_a_walk_that_lands_back_inside_the_build(built: Path):
    # The containment check hides every ".." that leaves the build, which is why
    # the existing tests do not distinguish the guard from containment. A walk
    # that lands back inside does: dropping the guard would resolve this.
    assert (built / "index.html").is_file()
    assert gates.resolve(built, "/spec/../index.html") is None
    assert gates.resolve(built, "/index.html") == built / "index.html"


def test_link_gate_fires_on_broken_internal_link_and_fragment(dist: Path):
    _append(dist / "index.html", '<a href="/nope/">a</a><a href="/spec/#no-such-section">b</a>')
    errs = gates.check_links(dist)
    assert errs == ["links: index.html: /nope/ does not resolve to a file in the build",
                    "links: index.html: /spec/#no-such-section names a fragment that spec/index.html lacks"]


def test_link_gate_checks_a_fragment_on_the_sites_own_absolute_url(dist: Path):
    # The same broken target written as an absolute self-reference. Dropping the
    # fragment on this path would pass it.
    _append(dist / "index.html", '<a href="https://cxbom.org/spec/#no-such-section">b</a>')
    assert gates.check_links(dist) == [
        "links: index.html: /spec/#no-such-section names a fragment that spec/index.html lacks"]


def test_link_gate_fires_on_a_same_page_fragment_with_no_target(dist: Path):
    _append(dist / "index.html", '<a href="#no-such-anchor">x</a>')
    assert gates.check_links(dist) == ["links: index.html: fragment #no-such-anchor has no target"]


def test_link_gate_checks_stylesheet_urls(dist: Path):
    css = dist / "assets/site.css"
    css.write_text(css.read_text(encoding="utf-8") + '\n@font-face{src:url("https://fonts.example.net/a.woff2")}\n', encoding="utf-8")
    assert gates.check_links(dist) == [
        "links: assets/site.css: https://fonts.example.net/a.woff2 is not a same-origin file in the build"]


def test_link_gate_refuses_a_protocol_relative_stylesheet_url(dist: Path):
    # "//assets/site.css" names the host "assets", not a directory in the build,
    # and a file of that path existing must not make it resolve.
    css = dist / "assets/site.css"
    css.write_text(css.read_text(encoding="utf-8") + '\n@font-face{src:url("//assets/site.css")}\n',
                   encoding="utf-8")
    assert gates.check_links(dist) == [
        "links: assets/site.css: //assets/site.css is not a same-origin file in the build"]


def test_link_gate_checks_a_bare_stylesheet_import(dist: Path):
    # @import "x"; carries a URL with no url() wrapper for a url() pattern to find.
    css = dist / "assets/site.css"
    css.write_text('@import "https://fonts.example.net/a.css";\n' + css.read_text(encoding="utf-8"), encoding="utf-8")
    assert gates.check_links(dist) == [
        "links: assets/site.css: https://fonts.example.net/a.css is not a same-origin file in the build"]


def test_link_gate_checks_a_meta_refresh_target(dist: Path):
    # A navigation, so no CSP directive covers it, and it carries a host.
    p = dist / "index.html"
    p.write_text(p.read_text(encoding="utf-8").replace(
        "</head>", '<meta http-equiv="refresh" content="0;url=https://leaking-identity.ac.uk/"></head>'),
        encoding="utf-8")
    errs = gates.check_links(dist)
    assert len(errs) == 1 and "leaking-identity.ac.uk" in errs[0]


def test_link_gate_refuses_a_url_it_cannot_parse(dist: Path):
    _append(dist / "index.html", '<a href="https://cxbom.org:8x/">x</a>')
    errs = gates.check_links(dist)
    assert len(errs) == 1 and "links: index.html: " in errs[0]


@ROOT_ONLY
def test_link_gate_refuses_a_page_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "spec/index.html")
    errs = gates.check_links(dist)
    assert errs == ["links: spec/index.html: cannot be read (Permission denied)"]


@ROOT_ONLY
def test_link_gate_refuses_a_stylesheet_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "assets/site.css")
    assert gates.check_links(dist) == ["links: assets/site.css: cannot be read (Permission denied)"]


def test_link_gate_refuses_a_page_that_is_not_utf8(dist: Path):
    (dist / "spec/index.html").write_bytes(b"<html><body>\xff\xfe</body></html>")
    assert gates.check_links(dist) == [
        "links: spec/index.html: is not valid UTF-8, so it cannot be checked"]


# Gate 3: no third-party scripts, and no inline code where the CSP would block it
def test_script_gate_fires_on_third_party_script(dist: Path):
    _append(dist / "viewer/index.html", '<script src="https://cdn.example.net/a.js"></script>')
    assert gates.check_scripts(dist) == [
        "scripts: viewer/index.html: script https://cdn.example.net/a.js is not a same-origin file in the build"]


@pytest.mark.parametrize("src", ["//cdn.example.net/a.js", "a.js", "/no/such/a.js", "data:text/javascript,1"])
def test_script_gate_fires_on_any_src_that_is_not_a_file_in_the_build(dist: Path, src: str):
    _append(dist / "viewer/index.html", f'<script src="{src}"></script>')
    errs = gates.check_scripts(dist)
    assert len(errs) == 1 and "is not a same-origin file in the build" in errs[0]


def test_script_gate_accepts_a_script_the_build_serves(dist: Path):
    (dist / "assets/app.js").write_text("void 0;\n", encoding="utf-8")
    _append(dist / "viewer/index.html", '<script src="/assets/app.js"></script>')
    assert gates.check_scripts(dist) == []


@ROOT_ONLY
def test_script_gate_refuses_a_page_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "viewer/index.html")
    assert gates.check_scripts(dist) == ["scripts: viewer/index.html: cannot be read (Permission denied)"]


def test_inline_gate_fires_outside_the_viewer(dist: Path):
    _append(dist / "spec/index.html", '<script>x()</script><p style="color:red" onclick="x()">y</p>')
    assert gates.check_inline(dist) == [
        "inline: spec/index.html: inline script, which the site CSP blocks",
        "inline: spec/index.html: inline style, which the site CSP blocks",
        "inline: spec/index.html: event handler attribute onclick"]


def test_inline_gate_reports_every_distinct_handler(dist: Path):
    # Reporting only the first would let a fix for it hide the next one.
    _append(dist / "spec/index.html", '<p onclick="x()">a</p><p onmouseover="x()">b</p><p onclick="y()">c</p>')
    assert gates.check_inline(dist) == [
        "inline: spec/index.html: event handler attribute onclick",
        "inline: spec/index.html: event handler attribute onmouseover"]


def test_inline_gate_fires_on_a_style_element_alone(dist: Path):
    _append(dist / "spec/index.html", "<style>p{color:red}</style>")
    assert gates.check_inline(dist) == [
        "inline: spec/index.html: inline style, which the site CSP blocks"]


def test_viewer_may_carry_inline_script(built: Path):
    assert "<script>" in (built / "viewer/index.html").read_text(encoding="utf-8")
    assert gates.check_inline(built) == []


def test_inline_allowance_is_the_exact_viewer_path(dist: Path):
    # A second page under viewer/ is not the viewer and gets no allowance.
    (dist / "viewer/extra.html").write_text(
        "<html><body><main><script>x()</script></main></body></html>", encoding="utf-8")
    assert gates.check_inline(dist) == [
        "inline: viewer/extra.html: inline script, which the site CSP blocks"]


@ROOT_ONLY
def test_inline_gate_refuses_a_page_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "spec/index.html")
    assert gates.check_inline(dist) == ["inline: spec/index.html: cannot be read (Permission denied)"]


# Gate 4: $id agreement and cxbom.org URL resolution
def test_id_gate_fires_on_wrong_id(dist: Path):
    p = dist / "schema/0.2.0/cxbom.schema.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["$id"] = "https://cxbom.org/schema/0.2.0/other.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert gates.check_schema_ids(dist) == [
        "ids: schema/0.2.0/cxbom.schema.json: $id 'https://cxbom.org/schema/0.2.0/other.json' "
        "does not equal https://cxbom.org/schema/0.2.0/cxbom.schema.json"]


def test_id_gate_fires_on_a_missing_id(dist: Path):
    p = dist / "schema/0.2.0/cxbom.schema.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    del doc["$id"]
    p.write_text(json.dumps(doc), encoding="utf-8")
    errs = gates.check_schema_ids(dist)
    assert len(errs) == 1 and "$id None does not equal" in errs[0]


def test_id_gate_fires_when_no_schema_is_published(dist: Path):
    shutil.rmtree(dist / "schema")
    assert gates.check_schema_ids(dist) == ["ids: the build publishes no schema"]


def test_id_gate_fires_when_the_schema_directory_holds_no_json(dist: Path):
    shutil.rmtree(dist / "schema")
    (dist / "schema/0.2.0").mkdir(parents=True)
    (dist / "schema/0.2.0/cxbom.schema.txt").write_text("{}", encoding="utf-8")
    assert gates.check_schema_ids(dist) == ["ids: the build publishes no schema"]


@pytest.mark.parametrize("body,reason", [("not json at all", "is not valid JSON"),
                                         ('["a"]', "is not a JSON object"),
                                         ('"a"', "is not a JSON object")])
def test_id_gate_refuses_a_schema_it_cannot_read_as_an_object(dist: Path, body: str, reason: str):
    (dist / "schema/0.2.0/cxbom.schema.json").write_text(body, encoding="utf-8")
    errs = gates.check_schema_ids(dist)
    assert len(errs) == 1 and reason in errs[0]


@ROOT_ONLY
def test_id_gate_refuses_a_schema_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "schema/0.2.0/cxbom.schema.json")
    assert gates.check_schema_ids(dist) == [
        "ids: schema/0.2.0/cxbom.schema.json: cannot be read (Permission denied)"]


def test_site_url_gate_fires_on_unserved_cxbom_url(dist: Path):
    p = dist / "examples/cxbom_example_clean_baseline.json"
    p.write_text(p.read_text(encoding="utf-8").replace("/schema/0.3.1/", "/schema/0.9.0/", 1), encoding="utf-8")
    assert gates.check_site_urls(dist) == [
        "site-urls: examples/cxbom_example_clean_baseline.json: "
        "//cxbom.org/schema/0.9.0/cxbom.schema.json is not served by the build"]


@pytest.mark.parametrize("ref", [
    "https://cxbom.org/schema/0.9.0/cxbom.schema.json",
    "HTTPS://CXBOM.ORG/schema/0.9.0/cxbom.schema.json",
    "//cxbom.org/schema/0.9.0/cxbom.schema.json",
    "http://cxbom.org/schema/0.9.0/cxbom.schema.json",
    "https://cxbom%2Eorg/schema/0.9.0/cxbom.schema.json",
])
def test_site_url_gate_reads_the_reference_however_it_is_spelled(dist: Path, ref: str):
    _append(dist / "spec/index.html", f"<p>{ref}</p>")
    errs = gates.check_site_urls(dist)
    assert len(errs) == 1 and "is not served by the build" in errs[0]


def test_site_url_gate_ignores_authorities_that_are_not_this_site(dist: Path):
    # Example records name illustrative third-party hosts as data. Resolving
    # those against the build is not this gate's job and never passes.
    _append(dist / "spec/index.html", "<p>//example.invalid/nope and //github.com/x/y</p>")
    assert gates.check_site_urls(dist) == []


def test_site_url_gate_resolves_this_site_with_no_path_at_all(dist: Path):
    # "//cxbom.org" with nothing after it names the site root, which the build
    # serves as index.html. Without the "/" fallback the root is unresolvable and
    # the gate refuses its own home page.
    _append(dist / "spec/index.html", "<p>see //cxbom.org for more</p>")
    assert gates.check_site_urls(dist) == []


def test_site_url_gate_reports_one_line_per_distinct_reference(dist: Path):
    _append(dist / "spec/index.html", "<p>//cxbom.org/a //cxbom.org/a //cxbom.org/b</p>")
    errs = gates.check_site_urls(dist)
    assert errs == ["site-urls: spec/index.html: //cxbom.org/a is not served by the build",
                    "site-urls: spec/index.html: //cxbom.org/b is not served by the build"]


def test_site_url_gate_refuses_a_text_file_that_is_not_utf8(dist: Path):
    (dist / "examples/cxbom_example_clean_baseline.json").write_bytes(b"\xff\xfe{}")
    assert gates.check_site_urls(dist) == [
        "site-urls: examples/cxbom_example_clean_baseline.json: is not valid UTF-8, so it cannot be checked"]


@ROOT_ONLY
def test_site_url_gate_refuses_a_text_file_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "index.html")
    assert gates.check_site_urls(dist) == [
        "site-urls: index.html: cannot be read (Permission denied)"]


def test_every_record_url_resolves_in_the_real_build(built: Path):
    assert gates.check_site_urls(built) == []
    served = built / "schema/0.2.0/cxbom.schema.json"
    assert served.read_bytes() == (ROOT / "spec/cxbom-0.2.0.schema.json").read_bytes()
    assert hashlib.sha256(served.read_bytes()).hexdigest() == _lock()["cxbom-0.2.0.schema.json"]["sha256"]


# Gate 5: contrast, run over the built stylesheet
def test_run_all_includes_contrast(dist: Path):
    css = dist / "assets/site.css"
    css.write_text(css.read_text(encoding="utf-8").replace("#585E66", "#A89B8A"), encoding="utf-8")
    errs = gates.run_all(dist, _lock(), TOKENS)
    assert errs == ["contrast: light muted on bg is 2.38, below 4.5", "contrast: light muted on surface is 2.63, below 4.5"]


def test_contrast_gate_refuses_a_missing_stylesheet(dist: Path):
    (dist / "assets/site.css").unlink()
    assert gates.check_contrast(dist) == ["contrast: assets/site.css is missing from the build"]


@ROOT_ONLY
def test_contrast_gate_refuses_a_stylesheet_it_cannot_read(dist: Path, unreadable):
    unreadable(dist / "assets/site.css")
    assert gates.check_contrast(dist) == ["contrast: assets/site.css: cannot be read (Permission denied)"]


def test_contrast_gate_refuses_a_stylesheet_with_no_palette(dist: Path):
    (dist / "assets/site.css").write_text("body{color:#000}\n", encoding="utf-8")
    errs = gates.check_contrast(dist)
    assert len(errs) == 1 and "expected one palette block, found 0" in errs[0]


# run_all: no path on which a gate that did not pass reads as a pass
def test_run_all_turns_an_unexpected_exception_into_a_refusal(built: Path, monkeypatch):
    def boom(_dist):
        raise RuntimeError("planted")

    monkeypatch.setattr(gates, "check_links", boom)
    errs = gates.run_all(built, _lock(), TOKENS)
    # The type, not the message: an exception's str() can carry an absolute path.
    assert errs == ["links: refused after an unexpected RuntimeError"]


def test_run_all_keeps_the_other_gates_findings_when_one_raises(dist: Path, monkeypatch):
    def boom(_dist):
        raise RuntimeError("planted")

    monkeypatch.setattr(gates, "check_links", boom)
    shutil.rmtree(dist / "schema")
    errs = gates.run_all(dist, _lock(), TOKENS)
    assert "links: refused after an unexpected RuntimeError" in errs
    assert "ids: the build publishes no schema" in errs
    assert any(e.startswith("freeze: ") for e in errs)


@pytest.mark.parametrize("make", [lambda: SystemExit(0), lambda: GeneratorExit(),
                                  lambda: RuntimeError("planted")],
                         ids=["SystemExit", "GeneratorExit", "RuntimeError"])
def test_run_all_refuses_a_gate_that_raises_outside_exception(built: Path, monkeypatch, make):
    # SystemExit is not an Exception. A gate that raised SystemExit(0) once left
    # run_all and ended the process at status 0 with no error line and nothing on
    # either stream: the last net before the build reports had a hole in it.
    def boom(_dist):
        raise make()

    monkeypatch.setattr(gates, "check_links", boom)
    errs = gates.run_all(built, _lock(), TOKENS)
    assert errs == [f"links: refused after an unexpected {type(make()).__name__}"]


def test_run_all_lets_an_interrupt_reach_the_caller(built: Path, monkeypatch):
    # An interrupt is not a finding, so it must not be reported as one.
    def boom(_dist):
        raise KeyboardInterrupt

    monkeypatch.setattr(gates, "check_links", boom)
    with pytest.raises(KeyboardInterrupt):
        gates.run_all(built, _lock(), TOKENS)


def test_run_all_fires_on_a_denylisted_token_in_the_build(dist: Path):
    # Dropping the anonymity gate from run_all otherwise dies only to the
    # call-order test below, which drives monkeypatched stubs. This drives the
    # real gate over a real fault, so a structural assertion is not the only
    # thing standing between a dropped gate and a green suite.
    _append(dist / "spec/index.html", "<p>ZZ-Secret-Org</p>")
    errs = gates.run_all(dist, _lock(), TOKENS)
    assert len(errs) == 1, errs
    assert errs[0].startswith("anonymity: index.html: contains a denylisted token")


def test_run_all_runs_every_gate(built: Path, monkeypatch):
    # A gate dropped from run_all would stop being reached by the build at all.
    called: list[str] = []
    for name in ("check_freeze", "check_anonymity", "check_links", "check_scripts",
                 "check_inline", "check_schema_ids", "check_site_urls", "check_contrast"):
        monkeypatch.setattr(gates, name,
                            (lambda n: lambda *a, **k: called.append(n) or [])(name))
    assert gates.run_all(built, _lock(), TOKENS) == []
    assert called == ["check_freeze", "check_anonymity", "check_links", "check_scripts",
                      "check_inline", "check_schema_ids", "check_site_urls", "check_contrast"]


# The build command
def test_build_command_builds_and_passes(tmp_path: Path, monkeypatch, capsys):
    # A clean checkout has no .anon-tokens, and the build refuses without it, so
    # every gate runs here against TOKENS in a throwaway root. The real denylist
    # is enforced by the site workflow, which writes it before it builds.
    run_all = gates.run_all
    monkeypatch.setattr(gates, "denylist_tokens", lambda root: list(TOKENS))
    monkeypatch.setattr(gates, "run_all",
                        lambda dist, lock, tokens, denylist_root=None: run_all(dist, lock, tokens))
    out = tmp_path / "dist"
    assert build.main(["--out", str(out)]) == 0
    assert (out / "index.html").is_file()
    assert "all gates pass" in capsys.readouterr().out


def test_build_command_exits_one_on_a_gate_error(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(gates, "run_all", lambda *a, **k: ["links: planted"])
    assert build.main(["--out", str(tmp_path / "dist")]) == 1
    assert "gate: links: planted" in capsys.readouterr().err


def test_build_command_exits_two_on_a_refused_build(tmp_path: Path, capsys):
    out = tmp_path / "dist"
    out.mkdir()
    (out / "not-a-build").write_text("x", encoding="utf-8")
    assert build.main(["--out", str(out)]) == 2
    assert "build refused" in capsys.readouterr().err


def test_build_command_exits_one_when_the_anonymity_checker_cannot_load(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(gates, "ANON_SCRIPT", tmp_path / "gone.py")
    assert build.main(["--out", str(tmp_path / "dist")]) == 1
    err = capsys.readouterr().err
    assert "gate: anonymity: " in err and "cannot be loaded" in err


def test_build_command_reads_the_repository_denylist(tmp_path: Path, monkeypatch):
    seen: dict[str, object] = {}

    def spy(dist, lock, tokens, denylist_root=None):
        seen["root"] = denylist_root
        seen["tokens"] = tokens
        return []

    anon = gates.anon_module()
    want = anon.load_tokens(ROOT / anon.DENYLIST_NAME)
    if not want:
        # Both sides would be empty and the assertion below would prove nothing.
        pytest.skip(f"{anon.DENYLIST_NAME} is absent")
    monkeypatch.setattr(gates, "run_all", spy)
    assert build.main(["--out", str(tmp_path / "dist")]) == 0
    assert seen["root"] == ROOT
    assert seen["tokens"] == want


def test_build_command_lock_reports_nothing_new(capsys):
    assert build.main(["--lock"]) == 0
    assert capsys.readouterr().out.strip() == "locked: nothing new"


def test_a_second_schema_version_is_served_at_its_own_path(tmp_path: Path):
    root = tmp_path / "repo"
    for rel in ("spec", "site", "docs/design"):
        shutil.copytree(ROOT / rel, root / rel, ignore=shutil.ignore_patterns("dist", "node_modules", ".wrangler"))
    doc = json.loads((root / "spec/cxbom-0.2.0.schema.json").read_text(encoding="utf-8"))
    doc["$id"] = "https://cxbom.org/schema/0.4.0/cxbom.schema.json"
    (root / "spec/cxbom-0.4.0.schema.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    assert build.lock_new_schemas(root) == ["cxbom-0.4.0.schema.json"]
    out = root / "site/dist"
    build.build(root, out)
    assert (out / "schema/0.4.0/cxbom.schema.json").is_file()
    assert (out / "schema/0.2.0/cxbom.schema.json").read_bytes() == (ROOT / "spec/cxbom-0.2.0.schema.json").read_bytes()
    assert gates.run_all(out, build.load_lock(root), TOKENS) == []


# No message the gate path can print carries an absolute filesystem path.
#
# The rule the checker states at scripts/anon_check.py and follows: "OSError text
# carries absolute paths, so every failure below is reported with fixed text
# only." The layer above it did not, in five places, and one of them was
# reachable with no tampering at all. Two tests hold it: one structural over the
# source, so a new handler cannot reintroduce it, and one behavioural over the
# messages the gate path actually produces.
#
# GateError, PaletteError, BuildError, ScopeError, StripError and RenderError are
# written in this codebase, and their text names a repository-relative path, a
# basename, or an exception type. Every other exception's str() can carry an
# absolute path: OSError.args includes the filename, and a traceback names every
# frame's file.
_PROJECT_ERRORS = frozenset({"GateError", "PaletteError", "BuildError", "ScopeError",
                             "StripError", "RenderError"})
_GATE_PATH = ("site/build.py", "site/cxsite/gates.py", "site/cxsite/build.py",
              "site/cxsite/links.py", "site/cxsite/palette.py", "site/cxsite/reference.py",
              "site/cxsite/render.py", "site/cxsite/scope.py", "site/cxsite/strip.py")


def _caught_names(node) -> set[str]:
    """The exception class names one except clause catches, however they are spelled."""
    if node is None:
        return set()
    if isinstance(node, ast.Tuple):
        return set().union(*(_caught_names(e) for e in node.elts)) if node.elts else set()
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Name):
        return {node.id}
    return {"<unknown>"}


def _rendered_exception_values(src: str) -> list[int]:
    """Line numbers where a caught exception's own value could be rendered into text.

    The allowed uses of a bound exception name are `type(e).__name__`,
    `e.strerror`, and `raise ... from e`. Anything else -- an f-string field,
    str(e), a %-format argument -- puts the exception's str() into a message, and
    that is where an absolute path gets in.
    """
    tree = ast.parse(src)
    parent = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    bad: list[int] = []
    for h in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
        if h.name is None or _caught_names(h.type) <= _PROJECT_ERRORS:
            continue
        for node in ast.walk(h):
            if not (isinstance(node, ast.Name) and node.id == h.name
                    and isinstance(node.ctx, ast.Load)):
                continue
            up = parent.get(node)
            if isinstance(up, ast.Attribute) and up.attr == "strerror":
                continue
            if isinstance(up, ast.Call) and isinstance(up.func, ast.Name) and up.func.id == "type":
                continue
            if isinstance(up, ast.Raise) and up.cause is node:
                continue
            bad.append(node.lineno)
    return bad


@pytest.mark.parametrize("rel", _GATE_PATH)
def test_no_gate_path_message_renders_an_exception_value(rel: str):
    src = (ROOT / rel).read_text(encoding="utf-8")
    assert _rendered_exception_values(src) == [], f"{rel}: lines that render a caught exception"


def test_the_structural_message_check_would_catch_the_shape_it_forbids():
    # A positive control. Without this the test above passes on any source in
    # which the walk is broken, including one where it finds nothing at all.
    assert _rendered_exception_values(
        "try:\n    pass\nexcept OSError as e:\n    print(f'{e}')\n") == [4]
    assert _rendered_exception_values(
        "try:\n    pass\nexcept OSError as e:\n    print(e.strerror, type(e).__name__)\n") == []
    assert _rendered_exception_values(
        "try:\n    pass\nexcept GateError as e:\n    print(f'{e}')\n") == []


def test_no_gate_refusal_names_an_absolute_path(dist: Path, tmp_path: Path, monkeypatch, capsys):
    """Every refusal path the review measured an absolute path on, driven again.

    The two it named were the anonymity loader and run_all's outer net; the
    output-directory refusal and the changelog anchor turned up once the property
    was made structural rather than checked by inspection.
    """
    planted = "/zz-home/zz-person/no/such/file"
    lines: list[str] = []

    def boom(_dist):
        raise FileNotFoundError(2, "No such file or directory", planted)

    monkeypatch.setattr(gates, "check_links", boom)
    lines += gates.run_all(dist, _lock(), TOKENS)
    monkeypatch.undo()

    monkeypatch.setattr(gates, "ANON_SCRIPT", tmp_path / "zz-no-such-checker.py")
    lines += gates.check_anonymity(dist, TOKENS)
    monkeypatch.undo()

    out = tmp_path / "zz-not-a-build"
    out.mkdir()
    (out / "stray").write_text("x", encoding="utf-8")
    assert build.main(["--out", str(out)]) == 2
    lines += capsys.readouterr().err.splitlines()

    assert len(lines) >= 3
    for ln in lines:
        assert planted not in ln, ln
        assert str(ROOT) not in ln, ln
        assert str(tmp_path) not in ln, ln


def test_the_changelog_anchor_refusal_names_no_absolute_path(monkeypatch):
    # reference._changelog_anchor runs at import time, so main() never prints this
    # refusal. Driven directly, because the message named an absolute constant and
    # the structural check over except clauses does not see a raise site.
    monkeypatch.setattr(reference, "_CHANGELOG_HEADING_RE", re.compile("zz-no-such-heading"))
    with pytest.raises(reference.RenderError) as caught:
        reference._changelog_anchor()
    assert str(caught.value) == "no 0.2.0 heading found in spec/CHANGELOG.md"


def test_the_site_scan_cap_grows_with_the_published_bytes(tmp_path: Path):
    # The scan reads every published byte through every view, so its run time is
    # linear in what the site publishes: the 15 MB homepage film alone takes about a
    # minute on a laptop and twice that on a CI runner. A fixed cap that fits one
    # size fails the gate on a slower machine for a correct, unfinished scan.
    small = tmp_path / "small"
    small.mkdir()
    (small / "index.html").write_text("<p>x</p>\n", encoding="utf-8")
    assert gates.site_scan_timeout(small) == gates.ANON_TIMEOUT
    big = tmp_path / "big"
    (big / "video").mkdir(parents=True)
    (big / "video" / "film.mp4").write_bytes(b"\0" * (2 * 1024 * 1024))
    assert gates.site_scan_timeout(big) == gates.ANON_TIMEOUT + 2 * gates.ANON_SECONDS_PER_MB


def test_the_anonymity_timeout_is_a_bound_not_a_stall(built: Path):
    # Measured, run_all over this build is under two seconds and the scan is the
    # bulk of it. A 600 s cap meant a hung checker stalled a build for ten
    # minutes before the gate refused, which is a worse failure than refusing.
    assert gates.ANON_TIMEOUT <= 120
    assert gates.ANON_PROBE_TIMEOUT <= gates.ANON_TIMEOUT
    # The real build's cap stays a bound: the base plus a fixed rate per published megabyte.
    size = sum(f.stat().st_size for f in built.rglob("*") if f.is_file())
    assert gates.site_scan_timeout(built) <= gates.ANON_TIMEOUT + gates.ANON_SECONDS_PER_MB * size / 2**20


# The shared host matcher is one matcher, used from one place
def test_gate_host_allowance_is_the_shared_one():
    assert gates.ALLOWED_HOSTS is links.ALLOWED_HOSTS
    assert gates.ALLOWED_MAILTO is links.ALLOWED_MAILTO
    assert links.SITE_HOST in gates.ALLOWED_HOSTS


def test_a_bare_comment_marker_is_not_a_reference():
    # The stated purpose of the empty-authority filter in references(). No input
    # in either site test file contained a bare "//", so the claim was unverified
    # and the filter could be removed with a green suite.
    assert links.references("// not a reference\n//cxbom.org/x") == [("cxbom.org", "/x")]
    assert links.references("a // b") == []


# The whole-build authority sweep.
#
# check_links covers the references a page points a browser at. This covers every
# authority anywhere in the published text, record data included, and permits by
# name rather than by scheme.
#
# Scoping it to http and https would make every entry below except four vanish
# with no list at all, and it would reintroduce exactly the skip that a TLD
# allowlist had: an identifying host typed "vault://reviewer-lab.example.net/x"
# would never be looked at, and the denylist scan only covers tokens already
# known. So match every "//" authority whatever the scheme, and pay for it with
# eleven reasoned entries.
#
# Two kinds, written into each reason because the distinction is the argument for
# the list: a host reached over a network scheme, and the authority segment of a
# non-network URI carried as record data. The third label covers the one entry
# that is not an authority at all.
#
# Scope is the text files, the same suffixes check_site_urls reads. Measured, the
# only authority the matcher finds outside them is a nine-byte run inside a
# Brotli-compressed font table, which is not a reference and cannot be read as
# one; the denylist scan covers those bytes by decoding every byte of every file
# and unpacking the font tables.
PUBLISHED_AUTHORITIES = {
    "marketdata.external-provider.com":
        "network host: an illustrative market-data server in the finance record, whose second "
        "label says placeholder out loud",
    "scripts.sil.org":
        "network host: the Open Font License's own canonical URL, inside the licence text the "
        "fonts ship with",
    "www.adobe.com":
        "network host: the Source Serif 4 copyright line, which names the typeface's author and "
        "not anyone connected to this submission",
    "acme-ai":
        "record data: the authority of a vault: URI in the finance record; Acme is the canonical "
        "fictional company",
    "contoso-ai":
        "record data: the authority of a vault: URI in the multi-turn record; Contoso is a "
        "documented fictional company",
    "fabrikam-ai":
        "record data: the authority of a vault: and a config: URI in the clean baseline record; "
        "Fabrikam is a documented fictional company, and it replaced an invented name that read "
        "as a real vendor (see the declared patch in spec/published.lock.json)",
    "ref":
        "record data: the namespace segment of vault://ref/system-prompt in the viewer's embedded "
        "sample record, not a hostname",
    "fetch":
        "record data: the namespace segment of mcp://fetch/tools in the viewer's embedded sample "
        "record; fetch is the standard MCP server name",
    "public-domain":
        "record data: the namespace segment of doc://public-domain/federalist/chunk-1 in the "
        "viewer's embedded sample record, not a hostname",
    ",":
        "not an authority: the comma the matcher reads out of the schema's own sourceUri prose, "
        "\"URI of the source (e.g., vault://, mcp://, config://).\" Rewording it at source is the "
        "right fix and is owed at the next schema version: 0.2.0 is printed as the $id in a paper "
        "under review, so spec/cxbom-0.2.0.schema.json must not change its bytes",
    "www.w3.org":
        "not an authority: the host of the SVG XML namespace URI the viewer's createElementNS "
        "calls pass to build the trust-ring diagram. It is a namespace identifier fixed by the "
        "SVG standard, never dereferenced, and unreachable from the offline page",
}
_AUTHORITY_KINDS = ("network host: ", "record data: ", "not an authority: ")


def _published_authorities(dist: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for p in sorted(dist.rglob("*")):
        if not (p.is_file() and p.suffix in gates.TEXT_SUFFIXES):
            continue
        for authority, _ in links.references(p.read_text(encoding="utf-8")):
            if authority not in links.ALLOWED_HOSTS:
                found.setdefault(authority, set()).add(p.relative_to(dist).as_posix())
    return found


def test_the_published_authorities_are_exactly_the_permitted_list(built: Path):
    found = _published_authorities(built)
    assert found, "the sweep found no authority at all, so it proves nothing"
    assert sorted(found) == sorted(PUBLISHED_AUTHORITIES), \
        f"unreasoned: {sorted(set(found) - set(PUBLISHED_AUTHORITIES))}; " \
        f"stale: {sorted(set(PUBLISHED_AUTHORITIES) - set(found))}"


def test_every_permitted_authority_carries_a_reason():
    # Exactness alone would let an entry be added with an empty string. The kind
    # prefix is what stops the reason being a shrug: an entry has to say whether
    # it is a host the site reaches, data a record carries, or not an authority.
    for name, reason in PUBLISHED_AUTHORITIES.items():
        assert reason.startswith(_AUTHORITY_KINDS), name
        assert len(reason) >= 60, name


def test_the_sweep_flags_an_identifying_host_under_a_non_network_scheme(built: Path, tmp_path: Path):
    # The trap this list exists to avoid. A sweep narrowed to http and https would
    # pass this, and the denylist scan would not catch it either unless the host
    # were already a known token.
    copy = tmp_path / "dist"
    shutil.copytree(built, copy)
    p = copy / "examples/cxbom_example_clean_baseline.json"
    p.write_text(p.read_text(encoding="utf-8").replace(
        "vault://fabrikam-ai/", "vault://reviewer-lab.example.net/", 1), encoding="utf-8")
    found = _published_authorities(copy)
    assert "reviewer-lab.example.net" in found
    assert "reviewer-lab.example.net" not in PUBLISHED_AUTHORITIES


def test_a_reference_never_carries_a_path_inside_its_authority(built: Path):
    """The authority group ends at the first delimiter, whatever follows it.

    references() added a second group to the pattern link_authorities reads, so
    the split is held to the real build here rather than to the argument that a
    group which can match empty cannot move where the group before it ends.
    """
    seen = 0
    for p in sorted(built.rglob("*")):
        if not (p.is_file() and p.suffix in gates.TEXT_SUFFIXES):
            continue
        for authority, rest in links.references(p.read_text(encoding="utf-8")):
            seen += 1
            assert not set(authority) & set(" \t\r\n/?#`<>)]"), authority
            assert rest == "" or rest[0] in "/?#", (authority, rest[:40])
    assert seen > 0, "no reference in the build, so this test proved nothing"
