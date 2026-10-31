"""Tests for the anonymity guard that backs the git hooks.

Owner: ATACE Working Group.

Every test builds a throwaway git repository with a synthetic denylist, so no
real identity string ever appears in this file or in a fixture.
"""
from __future__ import annotations

import ast
import base64
import bz2
import functools
import gzip
import html
import io
import json
import lzma
import os
import random
import re
import string
import struct
import subprocess
import sys
import tarfile
import time
import tracemalloc
import unicodedata
import urllib.parse
import zipfile
import zlib
from pathlib import Path

import brotli
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import anon_check  # noqa: E402

ANON = "CxBOM <noreply@cxbom.org>"
# The scan holds no windows any more. These are the offsets it used to break at,
# and the filler probes still straddle them, because that is where a split name
# went unseen for four rounds.
FORMER_BOUNDARY = 1024 * 1024
TOKENS = ["zz-secret-person", "zz-secret-org"]
# The only shape of line that is a catch. Everything else check_site emits is a
# refusal: fail-closed, and not the same thing.
CATCH = "contains a denylisted token"


def assert_caught(errs: list[str]) -> list[str]:
    """The scan's lines, asserted to be catches and not refusals.

    A refusal fails closed, so a witness that asserts only "something was
    reported" passes on one. That is how round 7's escaped-payload cases came out
    green while every one of them was reporting "malformed woff2 font": the fix
    had corrupted the payload with unquote_plus and the name was never read at
    all. A false green in a red-then-green table is the most expensive kind of
    wrong, so every witness that drives check_site goes through here.
    """
    refusals = [e for e in errs if CATCH not in e]
    assert refusals == [], f"refused rather than caught: {refusals}"
    return errs


def _thrown_away(source: str) -> list[int]:
    # Lines where a check is written and then discarded: a comparison or a
    # boolean expression standing alone as a statement, and an assert whose test
    # is a tuple, which is always true whatever it holds.
    return [node.lineno for node in ast.walk(ast.parse(source))
            if (isinstance(node, ast.Expr) and isinstance(node.value, (ast.Compare, ast.BoolOp)))
            or (isinstance(node, ast.Assert) and isinstance(node.test, ast.Tuple))]


def test_no_comparison_in_this_file_is_thrown_away():
    # A witness written as "assert_caught(check_site(...)) == [...]" without the
    # assert compares nothing and reports nothing. One of round 8's own witnesses
    # was written that way and went green while a mutant deleted the finding it
    # was supposed to prove; the mutation run found it and this test is what keeps
    # it found. ast, not a grep, because a comparison can span lines. Every test
    # file and script is read, not only this one: the shape is a class, and the
    # other files were clean by accident rather than by a guard.
    sources = sorted({*ROOT.glob("tests/**/*.py"), *ROOT.glob("scripts/**/*.py"),
                      *ROOT.glob("lab/**/tests/**/*.py")})
    # The public export has no lab tree, so that file is required only where lab/ exists.
    lab = [ROOT / "lab" / "j1" / "tests" / "test_canaries.py"] if (ROOT / "lab").is_dir() else []
    assert {Path(__file__), ROOT / "tests" / "conftest.py", ROOT / "scripts" / "anon_check.py", *lab} <= set(sources)
    thrown_away = {str(p.relative_to(ROOT)): lines for p in sources
                   if (lines := _thrown_away(p.read_text(encoding="utf-8")))}
    assert thrown_away == {}, f"a check with no effect: {thrown_away}"
    # Each shape is recognized, and none of the ordinary ones is.
    assert _thrown_away("x == 1\n") == [1]
    assert _thrown_away("x and y\n") == [1]
    assert _thrown_away("assert (x == 1, 'why')\n") == [1]
    assert _thrown_away("assert x == 1, 'why'\nflag = x == 1\nf(x == 1)\n"
                        "ys = [y == 1 for y in x]\nif (z := x == 1): pass\n") == []


def test_the_witness_helper_tells_a_catch_from_a_refusal():
    # The guard's own guard. If this helper ever stops separating the two, every
    # witness below silently accepts a refusal in place of a finding.
    caught = ["a.html: contains a denylisted token (#1 in .anon-tokens, raw view)"]
    assert assert_caught(caught) == caught
    for refusal in ("a.woff2: cannot be fully scanned (malformed woff2 font)",
                    "a.css: wide-encoded text the container stage cannot read",
                    "a.html: escapes nest deeper than the decode limit unwinds",
                    "a.zip: larger than the per-blob scan limit"):
        with pytest.raises(AssertionError, match="refused rather than caught"):
            assert_caught([refusal])
        with pytest.raises(AssertionError, match="refused rather than caught"):
            assert_caught(caught + [refusal])


def git(repo: Path, *args: str, env_ident: str = ANON) -> str:
    name, email = env_ident.split(" <")
    env = {
        "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email.rstrip(">"),
        "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email.rstrip(">"),
        "HOME": str(repo), "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
    }
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True,
                          capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    # check_staged reads `git var`, which honors repo config, so pin it like a real clone.
    git(tmp_path, "config", "user.name", "CxBOM")
    git(tmp_path, "config", "user.email", "noreply@cxbom.org")
    (tmp_path / ".anon-tokens").write_text("# synthetic\n" + "\n".join(TOKENS) + "\n")
    return tmp_path


def test_missing_denylist_fails_closed(tmp_path: Path):
    assert anon_check.load_tokens(tmp_path / ".anon-tokens") == []
    errs = anon_check.require_tokens([])
    assert errs and "refusing" in errs[0]


def test_comment_only_denylist_fails_closed(tmp_path: Path):
    p = tmp_path / ".anon-tokens"
    p.write_text("# only a comment\n\n")
    assert anon_check.require_tokens(anon_check.load_tokens(p))


def test_identity_must_be_anonymous():
    assert anon_check.check_identity("CxBOM <noreply@cxbom.org> 1727200000 +0000", "author") == []
    errs = anon_check.check_identity("Some Person <someone@example.net> 1727200000 +0000", "author")
    assert errs and "author" in errs[0]


def test_scan_text_is_case_insensitive():
    assert anon_check.scan_text("a.md", "hello ZZ-Secret-Person", TOKENS)
    assert anon_check.scan_text("a.md", "hello world", TOKENS) == []


def test_staged_clean_file_passes(repo: Path):
    (repo / "ok.md").write_text("nothing identifying\n")
    git(repo, "add", "ok.md")
    assert anon_check.check_staged(repo, TOKENS) == []


def test_staged_token_is_caught(repo: Path):
    (repo / "leak.md").write_text("written by zz-secret-person\n")
    git(repo, "add", "leak.md")
    errs = anon_check.check_staged(repo, TOKENS)
    assert any("leak.md" in e for e in errs)


def test_staging_the_denylist_is_refused(repo: Path):
    git(repo, "add", "-f", ".anon-tokens")
    errs = anon_check.check_staged(repo, TOKENS)
    assert any(".anon-tokens" in e for e in errs)


def test_range_catches_foreign_author_and_message_token(repo: Path):
    (repo / "a.md").write_text("a\n")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean")
    base = git(repo, "rev-parse", "HEAD").strip()
    (repo / "b.md").write_text("b\n")
    git(repo, "add", "b.md")
    git(repo, "commit", "-q", "-m", "fix for zz-secret-org", env_ident="Real Name <real@example.net>")
    errs = anon_check.check_range(repo, f"{base}..HEAD", TOKENS)
    joined = "\n".join(errs)
    assert "author" in joined and "committer" in joined and "message" in joined


def test_tree_scan_catches_tracked_token(repo: Path):
    (repo / "notes.txt").write_text("zz-secret-org internal\n")
    git(repo, "add", "notes.txt")
    git(repo, "commit", "-q", "-m", "add notes")
    errs = anon_check.check_tree(repo, "HEAD", TOKENS)
    assert any("notes.txt" in e for e in errs)


def test_range_accepts_new_branch_arguments(repo: Path):
    (repo / "a.md").write_text("a\n")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean")
    # A new branch has no remote sha, so pre-push passes `<sha> --not --remotes`.
    assert anon_check.check_range(repo, ["HEAD", "--not", "--remotes"], TOKENS) == []


def test_range_missing_remote_object_fails_closed(repo: Path, monkeypatch):
    # Push race: the pre-push hook builds `<remote_sha>..<local_sha>` from the sha
    # git advertised, but that remote object is not yet in the local store. The old
    # code let `git log` abort and died with a traceback. It must now fail closed
    # with a clean, actionable message and a non-zero exit, never a traceback.
    (repo / "a.md").write_text("a\n")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean")
    tip = git(repo, "rev-parse", "HEAD").strip()
    missing = "0123456789abcdef0123456789abcdef01234567"
    assert not anon_check._rev_present(repo, missing)  # guard: the sha is truly absent
    errs = anon_check.check_range(repo, f"{missing}..{tip}", TOKENS)
    assert errs and "local object store" in errs[0] and missing in errs[0]
    # Exit is a clean non-zero (fail closed). main resolves the repo from cwd.
    monkeypatch.chdir(repo)
    assert anon_check.main(["range", f"{missing}..{tip}"]) == 1


def test_range_clean_resolvable_passes(repo: Path, monkeypatch):
    # A range whose endpoints both resolve locally and hides no token or foreign
    # identity must still pass. Pins the fix against a false fail-closed.
    (repo / "a.md").write_text("a\n")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean one")
    base = git(repo, "rev-parse", "HEAD").strip()
    (repo / "b.md").write_text("b\n")
    git(repo, "add", "b.md")
    git(repo, "commit", "-q", "-m", "clean two")
    assert anon_check.check_range(repo, f"{base}..HEAD", TOKENS) == []
    monkeypatch.chdir(repo)
    assert anon_check.main(["range", f"{base}..HEAD"]) == 0


def test_range_unresolvable_with_no_named_endpoint_fails_closed(repo: Path, monkeypatch):
    # A range git rejects while naming no missing endpoint (here an empty rev arg)
    # reaches the generic branch. It must still fail closed with a finding and a
    # non-zero exit, never a traceback and never a silent pass.
    (repo / "a.md").write_text("a\n")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean")
    assert anon_check._missing_range_endpoints(repo, [""]) == []  # guard: generic branch, not missing
    errs = anon_check.check_range(repo, [""], TOKENS)
    assert errs and "could not resolve" in errs[0]
    monkeypatch.chdir(repo)
    assert anon_check.main(["range", ""]) == 1


def test_cli_usage_errors_return_2():
    assert anon_check.main([]) == 2
    assert anon_check.main(["range"]) == 2
    assert anon_check.main(["tree", "a", "b"]) == 2


# ---------------------------------------------------------------------------
# site mode. Every fixture is built in tmp_path from synthetic tokens, so no
# real font, archive, or name enters the repository.
# ---------------------------------------------------------------------------



def _png_ztxt(key: bytes, text: bytes) -> bytes:
    def chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", bytes(13))
            + chunk(b"zTXt", key + b"\0\0" + zlib.compress(text)) + chunk(b"IEND", b""))


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_gz(members: dict[str, bytes], uname: str = "builder", gname: str = "builder") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.uname, info.gname = len(data), uname, gname
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _b128(n: int) -> bytes:
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


def _name_table(family: str) -> bytes:
    # One Windows-platform record (platform 3, encoding 1, English) in UTF-16BE,
    # the way font tools store a family name.
    s = family.encode("utf-16-be")
    return struct.pack(">HHH", 0, 1, 18) + struct.pack(">6H", 3, 1, 0x409, 1, len(s), 0) + s


def _woff2(family: str, metadata: str = "") -> bytes:
    # A minimal WOFF2: one 'name' table (known-tag index 5, null transform) in a
    # Brotli stream after the directory, plus an optional Brotli metadata block.
    table = _name_table(family)
    tables = brotli.compress(table, mode=brotli.MODE_FONT)
    directory = bytes([5]) + _b128(len(table))
    meta = brotli.compress(metadata.encode()) if metadata else b""
    meta_off = 48 + len(directory) + len(tables) if meta else 0
    body = directory + tables + meta
    header = struct.pack(">4sIIHHIIHHIIIII", b"wOF2", 0x00010000, 48 + len(body), 1, 0,
                         12 + 16 + len(table), len(tables), 1, 0,
                         meta_off, len(meta), len(metadata), 0, 0)
    return header + body


def _clean_site(root: Path) -> None:
    (root / "css").mkdir(parents=True)
    (root / "index.html").write_text("<p>A clean <em>page</em> &amp; more</p>")
    (root / "css" / "site.css").write_text("/* layout */ body { margin: 0 }")
    (root / "app.js.map").write_text('{"version":3,"sources":["src/app.ts"],"sourcesContent":["let a = 1\\n"]}')
    (root / "font.woff2").write_bytes(_woff2("Test Sans", "<metadata><vendor name='x'/></metadata>"))
    (root / "dl.zip").write_bytes(_zip({"README.txt": b"hello"}))
    (root / "src.tar.gz").write_bytes(_tar_gz({"pkg/README.txt": b"hello"}))


def test_site_clean_tree_passes(tmp_path: Path):
    _clean_site(tmp_path)
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_site_names_files_by_base_name_only(tmp_path: Path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "page.html").write_text("<p>By ZZ-Secret-Person</p>")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "page.html: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def test_site_catches_a_css_comment_and_a_sourcemap(tmp_path: Path):
    (tmp_path / "site.css").write_text("body{} /* zz-secret-org */")
    # sourcesContent is JSON, so an escaped name only shows after decoding.
    (tmp_path / "app.js.map").write_text(
        '{"version":3,"sourcesContent":["// zz-secret-\\u0070erson\\n"]}')
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "app.js.map: contains a denylisted token (#1 in .anon-tokens, decoded view)",
        "site.css: contains a denylisted token (#2 in .anon-tokens, raw view)"]


def test_site_unpacks_zip_and_tar_gz(tmp_path: Path):
    body = b"notes by zz-secret-person " + b"padding " * 40
    (tmp_path / "dl.zip").write_bytes(_zip({"docs/inner.txt": body}))
    (tmp_path / "src.tar.gz").write_bytes(_tar_gz({"pkg/inner.txt": body}))
    assert b"zz-secret-person" not in (tmp_path / "dl.zip").read_bytes()
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "dl.zip > inner.txt: contains a denylisted token (#1 in .anon-tokens, raw view)",
        # The plain tar is scanned whole as well as member by member.
        "src.tar.gz > gzip stream: contains a denylisted token (#1 in .anon-tokens, raw view)",
        "src.tar.gz > gzip stream > inner.txt: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def test_site_scans_tar_uname_and_gname(tmp_path: Path):
    (tmp_path / "a.tar.gz").write_bytes(_tar_gz({"x.txt": b"x"}, uname="zz-secret-person"))
    (tmp_path / "b.tar.gz").write_bytes(_tar_gz({"x.txt": b"x"}, gname="zz-secret-org"))
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert "a.tar.gz > gzip stream > x.txt: contains a denylisted token (#1 in .anon-tokens, tar header view)" in errs
    assert "b.tar.gz > gzip stream > x.txt: contains a denylisted token (#2 in .anon-tokens, tar header view)" in errs


def test_site_decompresses_woff2_name_table_and_metadata(tmp_path: Path):
    (tmp_path / "a.woff2").write_bytes(_woff2("ZZ-Secret-Person Sans"))
    (tmp_path / "b.woff2").write_bytes(_woff2("Test Sans", "<vendor name='zz-secret-org'/>" * 8))
    assert b"zz-secret-org" not in (tmp_path / "b.woff2").read_bytes()
    # The family name is UTF-16BE, so every other byte is NUL. The fold erases
    # NUL now, which means the UTF-8 read of those bytes already spells the name
    # and reports first; the utf-16 views still see it, which the odd-offset test
    # below pins on a name the UTF-8 read cannot spell.
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "a.woff2 > woff2 tables: contains a denylisted token (#1 in .anon-tokens, utf-8 view)",
        "b.woff2 > woff2 metadata: contains a denylisted token (#2 in .anon-tokens, raw view)"]


def test_site_fails_closed_on_a_malformed_woff2(tmp_path: Path):
    (tmp_path / "bad.woff2").write_bytes(_woff2("Test Sans")[:52])
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "bad.woff2: cannot be fully scanned (malformed woff2 font)"]


def test_site_refuses_a_symlink_that_escapes(tmp_path: Path):
    (tmp_path / "outside.txt").write_text("clean")
    d = tmp_path / "dist"
    d.mkdir()
    (d / "page.html").write_text("clean")
    (d / "inside.html").symlink_to(d / "page.html")
    (d / "escape.txt").symlink_to(tmp_path / "outside.txt")
    (d / "sub").symlink_to(tmp_path)
    assert anon_check.check_site(d, TOKENS) == [
        "sub: symlink points outside the scanned directory",
        "escape.txt: symlink points outside the scanned directory"]


def test_site_refuses_the_denylist_and_a_missing_dir(tmp_path: Path):
    (tmp_path / ".anon-tokens").write_text("x\n")
    (tmp_path / "dl.zip").write_bytes(_zip({"sub/.anon-tokens": b"x"}))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        ".anon-tokens: the denylist is inside the scanned directory",
        "dl.zip > .anon-tokens: the archive holds the denylist"]
    assert anon_check.check_site(tmp_path / "nope", TOKENS) == ["nope: not a directory"]


def test_site_withholds_names_that_match(tmp_path: Path):
    (tmp_path / "zz-secret-org").mkdir()
    (tmp_path / "zz-secret-org" / "index.html").write_text("clean")
    (tmp_path / "zz%2Dsecret%2Dperson.html").write_text("clean")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "[name withheld]: contains a denylisted token (#2 in .anon-tokens, name view)",
        "[name withheld]: contains a denylisted token (#1 in .anon-tokens, name, decoded view)"]


def test_site_catches_encoded_and_smuggled_tokens(tmp_path: Path):
    inner = _zip({"x.txt": b"by zz-secret-org " * 20})
    cases = {
        "entity.html": "<p>zz&#45;secret&#x2d;person</p>".encode(),
        "percent.html": b"<a href='/q?by=zz%2Dsecret%252Dperson'>x</a>",
        "markup.html": b"<p>zz-secret<span></span>-person</p>",
        "wide.html": "<p>ｚｚ-secret-per​son</p>".encode(),
        "utf16.txt": "by zz-secret-person".encode("utf-16"),
        "double.gz": gzip.compress(gzip.compress(b"zz-secret-person " * 20)),
        "zip-in.woff2": inner,
        "tar-in-zip.zip": _zip({"x.tar.gz": _tar_gz({"y.txt": b"zz-secret-org " * 20})}),
        "datauri.css": b"@font-face{src:url(data:font/woff2;base64,"
                       + base64.b64encode(_woff2("zz-secret-person")) + b")}",
        "atob.js": b"var s=atob('" + base64.b64encode(b"zz-secret-person") + b"')",
        "cyrillic.html": "<p>zz-s\u0435cr\u0435t-p\u0435rson</p>".encode(),
        "app.js.br": brotli.compress(b"// zz-secret-org " * 20),
        "shot.png": _png_ztxt(b"Author", b"zz-secret-person " * 4),
        "polyglot.woff2": _woff2("Test Sans") + inner,
    }
    for name in ("app.js.br", "shot.png", "polyglot.woff2", "double.gz"):
        assert b"zz-secret" not in cases[name]
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
    flagged = {e.split(":")[0].split(" > ")[0]
               for e in assert_caught(anon_check.check_site(tmp_path, TOKENS))}
    assert flagged == set(cases)


def test_site_bounds_expansion_and_depth(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 1000)
    (tmp_path / "bomb.gz").write_bytes(gzip.compress(b"\0" * 100_000))
    nested = b"clean"
    for _ in range(anon_check.SITE_MAX_DEPTH + 1):
        nested = gzip.compress(nested)
    (tmp_path / "deep.gz").write_bytes(nested)
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert errs[0] == "bomb.gz: cannot be fully scanned (expands past the scan size limit)"
    assert errs[1].startswith("deep.gz > gzip stream") and errs[1].endswith("nesting exceeds the scan depth limit")
    assert len(errs) == 2


def test_site_refuses_a_fifo(tmp_path: Path):
    os.mkfifo(tmp_path / "pipe")
    assert anon_check.check_site(tmp_path, TOKENS) == ["pipe: not a regular file"]


def test_cli_site_mode_never_prints_a_token(repo: Path, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    d = repo / "dist"
    (d / "zz-secret-org").mkdir(parents=True)
    (d / "zz-secret-org" / "zz-secret-person.html").write_text("zz-secret-person")
    (d / "dl.zip").write_bytes(_zip({"ZZ-Secret-Org/zz-secret-person.txt": b"zz-secret-org"}))
    assert anon_check.main(["site", str(d)]) == 1
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert "anon-check: " in text and "[name withheld]" in text
    assert all(t not in text and t.replace("-", "") not in text for t in TOKENS)


def test_cli_site_mode_passes_clean_and_fails_closed(repo: Path, monkeypatch):
    monkeypatch.chdir(repo)
    d = repo / "dist"
    d.mkdir()
    _clean_site(d)
    assert anon_check.main(["site", str(d)]) == 0
    assert anon_check.main(["site"]) == 2
    (repo / ".anon-tokens").unlink()
    assert anon_check.main(["site", str(d)]) == 1


def test_site_refuses_a_dangling_symlink(tmp_path: Path):
    # The target would sit inside DIR, but it does not exist, so it could
    # resolve to anything once deployed.
    (tmp_path / "gone.html").symlink_to(tmp_path / "missing.html")
    assert anon_check.check_site(tmp_path, TOKENS) == ["gone.html: symlink target is missing"]


def test_site_refuses_an_encrypted_zip_member(tmp_path: Path):
    data = bytearray(_zip({"x.txt": b"hello " * 20}))
    # Set the encryption bit (bit 0 of the general purpose flags) in both the
    # local header and the central directory entry, which is what zipfile reads.
    data[6] |= 1
    data[data.index(b"PK\x01\x02") + 8] |= 1
    (tmp_path / "dl.zip").write_bytes(bytes(data))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "dl.zip > x.txt: encrypted member cannot be scanned"]


def test_site_inflates_pdf_streams(tmp_path: Path):
    # Built at run time: a stream header spelled here as escapes is, to the
    # backslash reading, a declared Flate stream of source text, and refused.
    body = zlib.compress(b"<x:xmpmeta><dc:creator>zz-secret-person</dc:creator></x:xmpmeta>")
    pdf = _pdf_bytes([(b"FlateDecode", body)])
    assert b"zz-secret" not in pdf
    (tmp_path / "paper.pdf").write_bytes(pdf)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "paper.pdf > pdf stream: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def test_cli_site_guard_withholds_a_leaking_line(repo: Path, monkeypatch, capsys):
    # check_site already withholds matching names, so the guard in main only
    # matters if a scanner branch ever leaks. Simulate that leak directly.
    monkeypatch.chdir(repo)
    d = repo / "dist"
    d.mkdir()
    monkeypatch.setattr(anon_check, "check_site", lambda root, tokens: [
        "ZZ-Secret-Person.html: contains a denylisted token (#1 in .anon-tokens, raw view)",
        "clean.html: not a regular file"])
    assert anon_check.main(["site", str(d)]) == 1
    err = capsys.readouterr().err
    assert "zz-secret-person" not in err.lower()
    assert "withheld" in err and "clean.html: not a regular file" in err


def test_site_gzip_bomb_is_bounded(tmp_path: Path):
    import tracemalloc
    # 64 MiB of zeros compresses to about 64 KiB, twice the expansion budget.
    (tmp_path / "bomb.gz").write_bytes(gzip.compress(b"\0" * (64 * 1024 * 1024)))
    tracemalloc.start()
    try:
        errs = anon_check.check_site(tmp_path, TOKENS)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert errs == ["bomb.gz: cannot be fully scanned (expands past the scan size limit)"]
    # One budget of output plus working buffers, far below the ~8 GB the
    # previous 256 MiB budget allowed.
    assert peak < 48 * 1024 * 1024


def test_site_finds_a_literal_name_across_a_former_boundary(tmp_path: Path):
    # A plain name written across the offset the scan used to break at.
    (tmp_path / "big.txt").write_bytes(b"." * (FORMER_BOUNDARY - 6) + b"zz-secret-org" + b"." * 600)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "big.txt: contains a denylisted token (#2 in .anon-tokens, raw view)"]


def test_site_refuses_a_blob_over_the_cap(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(anon_check, "SITE_MAX_BLOB", 1000)
    (tmp_path / "big.bin").write_bytes(b"x" * 1001)
    (tmp_path / "ok.zip").write_bytes(_zip({"inner.bin": b"\0" * 2000}))
    # An oversized file is refused from its size, before it is read into memory.
    read: list[str] = []
    real_read = Path.read_bytes
    monkeypatch.setattr(anon_check.Path, "read_bytes", lambda self: read.append(self.name) or real_read(self))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "big.bin: larger than the per-blob scan limit",
        "ok.zip > inner.bin: larger than the per-blob scan limit"]
    assert read == ["ok.zip"]


def test_site_reports_os_errors_without_their_text(tmp_path: Path, monkeypatch, capsys):
    (tmp_path / "link.html").symlink_to(tmp_path / "page.html")
    (tmp_path / "page.html").write_text("clean")

    def fail(*_args, **_kwargs):
        raise OSError(2, "No such file", "zz-secret-person/site/link.html")
    monkeypatch.setattr(anon_check.os, "readlink", fail)
    assert anon_check.check_site(tmp_path, TOKENS) == ["link.html: symlink cannot be resolved"]
    monkeypatch.setattr(anon_check.Path, "lstat", fail)
    assert anon_check.check_site(tmp_path, TOKENS) == ["link.html: cannot be inspected",
                                                       "page.html: cannot be inspected"]


def test_site_decodes_wrapped_and_misaligned_base64(tmp_path: Path):
    payload = base64.b64encode(b"x" * 40 + b"zz-secret-person" + b"x" * 40).decode()
    # 64-column PEM wrapping puts the token's bytes 40 to 56 across the break at 48.
    pem = "-----BEGIN DATA-----\n" + "\n".join(payload[i:i + 64] for i in range(0, len(payload), 64))
    (tmp_path / "wrapped.pem").write_text(pem + "\n-----END DATA-----\n")
    (tmp_path / "json.map").write_text('{"b":"' + "\\n".join(payload[i:i + 64] for i in range(0, len(payload), 64)) + '"}')
    # Base64 letters just before the payload shift the run off its alignment.
    (tmp_path / "shifted.js").write_text("var tok=abc" + base64.b64encode(b"zz-secret-org").decode() + ";")
    flagged = {e.split(":")[0]
               for e in assert_caught(anon_check.check_site(tmp_path, TOKENS))}
    assert flagged == {"wrapped.pem > base64", "json.map > base64", "shifted.js > base64"}


def test_site_reports_a_zip_inside_a_tar_once(tmp_path: Path):
    inner = _zip({"y.txt": b"zz-secret-org " * 20})
    (tmp_path / "a.tar.gz").write_bytes(_tar_gz({"pkg/inner.zip": inner}))
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "a.tar.gz > gzip stream > inner.zip > y.txt: contains a denylisted token (#2 in .anon-tokens, raw view)"]
    # A zip glued after the tar's last member is still found.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("x.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
    (tmp_path / "a.tar.gz").unlink()
    (tmp_path / "glued.tar").write_bytes(buf.getvalue() + inner)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "glued.tar > y.txt: contains a denylisted token (#2 in .anon-tokens, raw view)"]


def test_hooks_run_without_lzma_or_bz2(repo: Path, tmp_path: Path):
    (repo / "a.md").write_text("clean\n")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean")
    (repo / "b.md").write_text("clean\n")
    git(repo, "add", "b.md")
    site = tmp_path / "site"
    site.mkdir()
    import lzma
    (site / "x.xz").write_bytes(lzma.compress(b"clean"))
    # A None entry in sys.modules makes the import fail, as on a python3 built
    # without _lzma and _bz2.
    prog = ("import sys\n"
            "for m in ('lzma', '_lzma', 'bz2', '_bz2'): sys.modules[m] = None\n"
            f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
            "import anon_check\n"
            "sys.exit(anon_check.main(sys.argv[1:]))\n")
    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-c", prog, *args], cwd=repo,
                              capture_output=True, text=True, timeout=120)
    for args in (["staged"], ["range", "HEAD"], ["tree", "HEAD"]):
        r = run(*args)
        assert r.returncode == 0, (args, r.stderr)
    r = run("site", str(site))
    assert r.returncode == 1 and "x.xz: cannot be fully scanned (xz needs the lzma module)" in r.stderr

# ---------------------------------------------------------------------------
# Filler units. A unit is text a reader never sees, so a name written around one
# reads whole to a person while its bytes are split. A unit is one character and
# one encoding of it, and neither axis is decided by anon_check.
#
# The encoder axis is decided by the standard library and by the grammars. An
# entity or percent form is in the catalogue only when decoding it, as often as
# it is wrapped, yields the character it claims; the escape forms are in because
# the JavaScript and CSS grammars say so.
#
# The character axis is derived from Unicode general categories and from a
# browser measurement. Round 5 hand-listed it instead, in two tuples written to
# match what _fold already did, so the catalogue could not hold a character the
# fold mishandles. That is the seam alphabet's circularity moved one layer down,
# and it hid 61 zero-ink code points the fold neither erased nor spaced.
#
# Neither axis carries a fold class. Whether a character a reader cannot see
# closes the gap it sits in or leaves one varies by code point, font and browser,
# so _hits matches a multi-word token with its own spaces closed up as well. One
# name written with a space therefore probes both outcomes at once, and nothing
# about a character has to be predicted.
#
# Every unit is caught because the folded views are built from the whole input
# and scanned whole. Four rounds of naming filler in a byte alphabet could not
# converge, since a name can be encoded to any depth: "&amp;amp;#8203;" and
# "%2525E2%252580%25258B" go on forever. Scanning what the decoders produced
# needs no alphabet at all.
# ---------------------------------------------------------------------------
# Code points a reader cannot see that no general category isolates. A browser
# cannot run in CI, so the measurement is committed here as data.
#
# Provenance: measured 2026-09-27 in Chrome 153.0.0.0 on macOS (Darwin 25.5.0),
# driven over a page served from localhost, each candidate rendered at 64 px
# serif two ways. Advance is the width of a pre-formatted element holding
# "x<candidate>x" less the width of the same element holding "xx". Ink is the
# count of non-white pixels after canvas fillText of the candidate alone into a
# white 600x160 bitmap, read back with getImageData. U+2800, the braille blank,
# measured zero ink with a 43.75 px advance, and is the only code point outside
# the categories below that the run found a reader cannot see.
#
# The same run measured the advances the erase-or-space question turns on, all of
# them at zero ink: U+200B 0 px, U+000B 16 px which is exactly a space, U+0001
# 21.313 px, U+007F 32.078 px, U+009F 64 px. Because the answer differs by code
# point, the scan matches both shapes rather than choosing one. The run also
# found two format characters a font does supply a glyph for, U+0600 at 513 ink
# pixels and U+13430 at 1108, so treating all of Cf as invisible is stricter than
# a reader is. Stricter costs a false finding, which fails closed.
MEASURED_ZERO_INK = frozenset({0x2800})
# Invisible letters and marks that no category isolates, because Mn and Lo both
# hold visible members: Hangul fillers, the combining grapheme joiner, Khmer
# inherent vowels, Mongolian free variation selectors, and variation selectors
# with their supplement. Named rather than derived. anon_check erases the whole
# tag block, so the unassigned holes in it are covered as well.
LOOKALIKE_CHARS = ("͏ᅟᅠ឴឵᠋᠏ㅤ"
                   "︀️ﾠ\U000e0100\U000e0400")
# Code points this round's review and the four before it named. They stay in the
# sample whatever the buckets below would have chosen: adding to the catalogue is
# always safe, and it is choosing what to leave out that hid every hole so far.
REVIEW_CHARS = ("\u0000\u0001\u000b\u001c\u001d\u001e\u001f\u007f\u0082\u0085"
                "\u009f­؀​  ⠀"
                "\U00013430\U0001d173")
# Named forms, including the ones the legacy table resolves without a semicolon.
NAMED_ENTITIES = {"­": "shy", "​": "ZeroWidthSpace",
                  " ": "nbsp", " ": "thinsp"}
# Forms the reviews called out by name, which the catalogue must hold.
REQUIRED_UNITS = (
    "U+00AD as named entity bare", "U+00AD as decimal entity bare",
    "U+00AD as hex entity bare", "U+00AD as backslash named",
    "U+200B as backslash literal", "U+00AD as backslash percent",
    "U+200B as double entity", "U+200B as double percent",
    "U+200B as triple entity", "U+200B as triple percent",
    "U+200B as css escape", "U+E0100 as literal", "U+001F as literal",
    "U+0085 as literal", "U+1680 as literal",
    # Round 6: html.unescape erases these, the HTML spec and Chrome 153 emit
    # them, and round 5's oracle dropped all eight entity forms of each because
    # the implementation failed on them.
    "U+000B as decimal entity", "U+000B as hex entity",
    "U+000B as padded decimal entity", "U+000B as double entity",
    "U+001C as decimal entity", "U+001D as upper hex entity",
    "U+001E as hex entity bare", "U+001F as triple entity",
    # Round 6: code points the round-5 fold neither erased nor spaced.
    "U+0001 as literal", "U+007F as literal", "U+009F as literal",
    "U+2800 as literal", "U+0600 as literal", "U+13430 as literal",
    "U+1D173 as literal",
    "comment holding a bracket", "comment holding many brackets",
    "script element", "style element", "nul run", "plus run",
    "empty tag", "comment", "tag between spaces",
    # Round 6: the three comment ends a reader loses that "-->" does not cover.
    "comment closed at once", "comment closed after one dash",
    "comment closed with a bang",
)


@functools.cache
def derived_invisible() -> tuple[int, ...]:
    """Every code point a reader cannot see, from Unicode general categories plus
    the measurement above. Cf is the format class a renderer consumes; Cc is the
    control class, whose whitespace members a renderer shows as a space and whose
    others it shows as nothing; Zs, Zl and Zp are the separators."""
    return tuple(cp for cp in range(0x110000)
                 if unicodedata.category(chr(cp)) in ("Cf", "Cc", "Zs", "Zl", "Zp")
                 or cp in MEASURED_ZERO_INK)


def sample_chars(per_bucket: int = 3) -> str:
    """A derived sample of the character axis for the encoder cross product. An
    encoder cares about a code point's range, not which code point it is, so the
    cross product runs over up to `per_bucket` members of every (category, is
    whitespace, escape width, has a named form) bucket, in code point order. The
    axis in full is covered by test_the_fold_loses_every_invisible_character."""
    buckets: dict[tuple, list[str]] = {}
    for cp in derived_invisible():
        char = chr(cp)
        width = 1 if cp <= 0xFF else (2 if cp <= 0xFFFF else 3)
        key = (unicodedata.category(char), char.isspace(), width, char in NAMED_ENTITIES)
        buckets.setdefault(key, []).append(char)
    chosen = [c for members in buckets.values() for c in members[:per_bucket]]
    chosen += [c for c in LOOKALIKE_CHARS + REVIEW_CHARS if c not in chosen]
    return "".join(sorted(set(chosen), key=ord))


# WHATWG HTML, numeric character reference end state: U+0000, a surrogate and an
# out-of-range value become U+FFFD, the 0x80 to 0x9F rows are replaced from this
# table, and every other code point is emitted as it stands even where the spec
# calls it a parse error. That last rule is where html.unescape differs, and
# where round 5's oracle dropped 49 forms because the implementation failed on
# them. The table is the spec's, transcribed, not html.entities'.
_C1_REPLACEMENTS = {
    0x80: "€", 0x82: "‚", 0x83: "ƒ", 0x84: "„",
    0x85: "…", 0x86: "†", 0x87: "‡", 0x88: "ˆ",
    0x89: "‰", 0x8a: "Š", 0x8b: "‹", 0x8c: "Œ",
    0x8e: "Ž", 0x91: "‘", 0x92: "’", 0x93: "“",
    0x94: "”", 0x95: "•", 0x96: "–", 0x97: "—",
    0x98: "˜", 0x99: "™", 0x9a: "š", 0x9b: "›",
    0x9c: "œ", 0x9e: "ž", 0x9f: "Ÿ",
}
# The spec's production, which bounds neither the digits nor the leading zeros.
# For five rounds this carried "{1,12}" and "{1,10}", character for character the
# implementation's bounds, under a comment claiming spec provenance. An oracle
# that inherits the implementation's bound cannot fail on a form the bound breaks,
# and this one dropped rather than flagged "&#00000000000011;", which the
# implementation erased and a browser emits as U+000B.
_SPEC_NUM_REF = re.compile(r"&#([0-9]+|[xX][0-9a-fA-F]+);?")


def _spec_unescape(text: str) -> str:
    """html.unescape for the named references, the spec's own rule for the
    numeric ones, which has to run first or html.unescape erases them before this
    sees them. The rule is transcribed from the spec, not read off anon_check."""
    def one(m: re.Match[str]) -> str:
        body = m.group(1)
        hexadecimal = body[0] in "xX"
        digits = (body[1:] if hexadecimal else body).lstrip("0")
        # Out of range, and long enough that int() would refuse the string.
        code = (int(digits, 16 if hexadecimal else 10) if digits else 0
                ) if len(digits) <= 7 else 0x110000
        if code in _C1_REPLACEMENTS:
            return _C1_REPLACEMENTS[code]
        if code == 0 or 0xD800 <= code <= 0xDFFF or code > 0x10FFFF:
            return "�"
        return chr(code)
    return html.unescape(_SPEC_NUM_REF.sub(one, text))


def _repeatedly(decode, text: str, rounds: int = 4) -> str:
    for _ in range(rounds):
        text = decode(text)
    return text


def _percent_of(char: str) -> str:
    return "".join(f"%{b:02X}" for b in char.encode())


def _entity_forms(char: str) -> dict[str, str]:
    code = ord(char)
    forms = {"decimal entity": f"&#{code};", "decimal entity bare": f"&#{code}",
             "padded decimal entity": f"&#{code:07d};", "hex entity": f"&#x{code:04x};",
             "hex entity bare": f"&#x{code:04x}", "upper hex entity": f"&#X{code:04X};",
             "double entity": f"&amp;#{code};", "triple entity": f"&amp;amp;#{code};"}
    if char in NAMED_ENTITIES:
        forms["named entity"] = f"&{NAMED_ENTITIES[char]};"
        forms["named entity bare"] = f"&{NAMED_ENTITIES[char]}"
    # The oracle: keep a form only when unescaping it by the spec's rules, as
    # often as it is wrapped, yields the character itself. It was html.unescape
    # for five rounds, which erases code points the spec emits, so it dropped all
    # eight entity forms of U+000B and of U+001C to U+001F -- 40 of the 49 forms
    # it dropped -- because the implementation failed on them.
    return {name: form for name, form in forms.items()
            if _repeatedly(_spec_unescape, form) == char}


def _percent_forms(char: str) -> dict[str, str]:
    plain = _percent_of(char)
    forms = {"percent utf-8": plain, "double percent": plain.replace("%", "%25"),
             "triple percent": plain.replace("%", "%2525")}
    return {name: form for name, form in forms.items()
            if _repeatedly(urllib.parse.unquote, form) == char}


def _escape_forms(char: str) -> dict[str, str]:
    code = ord(char)
    forms = {"js escape": f"\\u{{{code:x}}}" if code > 0xffff else f"\\u{code:04x}",
             "js braced": f"\\u{{{code:x}}}", "css escape": f"\\{code:x} ",
             "css padded": f"\\{code:06x} ", "backslash literal": f"\\{char}",
             "backslash percent": "\\" + _percent_of(char)}
    if code <= 0xff:
        forms["js hex"] = f"\\x{code:02x}"
    if char in NAMED_ENTITIES:
        forms["backslash named"] = f"\\&{NAMED_ENTITIES[char]};"
    return forms


def filler_units(repeat: int = 3) -> dict[str, bytes]:
    """Every unit as the filler bytes that split a name. No unit carries a fold
    class: the name written around it holds a space, and the scan matches that
    entry with its space closed up as well, so a unit that disappears and a unit
    that leaves a gap are both probed by the same name."""
    units: dict[str, bytes] = {}
    for char in sample_chars():
        forms = {"literal": char}
        forms.update(_entity_forms(char))
        forms.update(_percent_forms(char))
        forms.update(_escape_forms(char))
        for name, form in forms.items():
            units[f"U+{ord(char):04X} as {name}"] = (form * repeat).encode()
    for name, filler in {
        "nul run": b"\0" * 200,
        "empty tag": b"<i></i>",
        "nested empty tags": b"<b><i><em></em></i></b>",
        "long tag": b'<i data-k="' + b"x" * 9000 + b'">',
        "tag holding an angle bracket": b'<i alt="a<b">',
        "comment": b"<!-- nothing to see -->",
        "comment holding a bracket": b"<!-- a > b -->",
        "comment holding many brackets": b"<!-- " + b"> " * 400 + b"-->",
        "long comment": b"<!-- " + b"x" * 9000 + b" -->",
        # The three comment ends a reader loses that "-->" does not cover.
        "comment closed at once": b"<!-->",
        "comment closed after one dash": b"<!--->",
        "comment closed with a bang": b"<!-- c --!>",
        "long comment closed with a bang": b"<!-- " + b"x" * 9000 + b" --!>",
        "comment closed at once then a tag": b"<!--><i></i>",
        "comment holding a bracket closed with a bang": b"<!-- a > b --!>",
        "script element": b"<script>var a = 1 > 0;</script>",
        "style element": b"<style>.a{content:'>'}</style>",
        "uppercase script element": b"<SCRIPT>var a = 2 > 1;</SCRIPT>",
        "script with attributes": b'<script type="text/javascript">x = 3 > 2;</script>',
        "tag inside a comment": b"<!-- <i></i> -->",
        "entity run then tag": b"&#8203;" * 50 + b"<i></i>",
        "control entity run": b"&#11;" * 40,
        "mixed encodings": b"&#173;\\u200b%C2%AD\\00ad " + "​".encode(),
        "deeply wrapped entity": b"&amp;amp;amp;#8203;",
        "whitespace then comment": b" " * 200 + b"<!-- c -->",
        "comment then whitespace": b"<!-- c -->" + b" " * 200,
        "tag between spaces": b" <i></i> ",
        # unquote_plus reads every "+" as a space, so a run folds to one.
        "plus run": b"+" * 200,
    }.items():
        units[name] = filler
    return units


def boundary_units(minimum_bytes: int = 12 * 1024) -> dict[str, bytes]:
    """A slice of the catalogue for the boundary probes: every structural unit,
    three characters per encoder, every form the reviews named, and each one
    repeated past `minimum_bytes`. Filler shorter than a window's overlap could
    not be split by a window in the first place, so a short unit would not probe
    a boundary at all."""
    catalogue = filler_units()
    chosen: dict[str, bytes] = {}
    seen: dict[str, int] = {}
    for name, unit in catalogue.items():
        if " as " not in name:
            chosen[name] = unit
            continue
        key = name.split(" as ", 1)[1]
        if seen.get(key, 0) < 3:
            seen[key] = seen.get(key, 0) + 1
            chosen[name] = unit
    for name in REQUIRED_UNITS:
        assert name in catalogue, name
        chosen[name] = catalogue[name]
    assert len(chosen) >= 105, len(chosen)
    return {name: unit * -(-minimum_bytes // len(unit)) for name, unit in chosen.items()}


def _name_around(index: int) -> tuple[bytes, bytes, str]:
    """Two halves of a synthetic name and the denylist entry they spell. The
    entry holds a space, which probes both outcomes at once: the scan matches it
    as written where the filler leaves a gap, and with the space closed up where
    the filler disappears."""
    head, tail = f"zz{index:03d}first", f"last{index:03d}"
    return head.encode(), tail.encode(), f"{head} {tail}"


def test_the_fold_loses_every_invisible_character(tmp_path: Path):
    # The character axis in full, walked from unicodedata rather than from a list
    # written to match the fold. Round 5's hand-listed axis could not hold a
    # character the fold mishandled, and 61 zero-ink code points sat outside it.
    derived = derived_invisible()
    assert len(derived) > 240
    missed = [f"U+{cp:04X}" for cp in derived
              if anon_check._fold(f"a{chr(cp)}b") not in ("ab", "a b")]
    assert missed == []
    lookalikes = [f"U+{ord(c):04X}" for c in LOOKALIKE_CHARS
                  if anon_check._fold(f"a{c}b") != "ab"]
    assert lookalikes == []


def test_invisible_matches_every_format_and_control_character(tmp_path: Path):
    # The regex claims Cf; round 5's matched 129 of the 170 Cf code points in
    # this Python's tables. It is committed rather than derived at import, so the
    # derivation lives here instead and fails if the class ever narrows.
    want: set[int] = set(MEASURED_ZERO_INK)
    spaces: list[str] = []
    for cp in range(0x110000):
        char = chr(cp)
        category = unicodedata.category(char)
        if category == "Cf" or (category == "Cc" and not char.isspace()):
            want.add(cp)
        if char.isspace() and anon_check._INVISIBLE.fullmatch(char):
            spaces.append(f"U+{cp:04X}")
    # Literal totals, so emptying either input fails here. Written as
    # "170 + 55 + len(MEASURED_ZERO_INK)" the expected value was computed from the
    # constant under test, and replacing MEASURED_ZERO_INK with an empty set
    # passed all 56 tests: 170 Cf, 55 non-whitespace Cc, and U+2800 measured.
    # Unicode 13.0, in Python 3.10, has 161 Cf. A version not listed fails here,
    # so a new table is counted before it is trusted.
    assert MEASURED_ZERO_INK == frozenset({0x2800})
    assert len(want) == {"13.0.0": 217, "15.0.0": 226, "15.1.0": 226,
                         "16.0.0": 226}[unicodedata.unidata_version]
    assert [f"U+{cp:04X}" for cp in sorted(want)
            if not anon_check._INVISIBLE.fullmatch(chr(cp))] == []
    # Erasing a space would read "First<br>Last" as one word and miss the name
    # a reader sees, so nothing Unicode calls whitespace may be in the class.
    assert spaces == []


def test_a_comment_ends_the_four_ways_a_reader_loses_it(tmp_path: Path):
    # Chrome 153 gives all four of these the same textContent, "zz-secret-org":
    # "-->" closes a comment, and so do "--!>" and a ">" or "->" straight after
    # "<!--", which WHATWG HTML calls abrupt-closing-of-empty-comment. Reading
    # only "-->" left a name behind a closed comment, where the decoded views
    # never looked and nothing else would either.
    closed = tmp_path / "closed"
    closed.mkdir()
    cases = {"at-once.html": b"<!-->zz-secret<i></i>-org",
             "one-dash.html": b"<!--->zz-secret<i></i>-org",
             "bang.html": b"<!-- x --!>zz-secret<i></i>-org",
             "plain.html": b"<!-- x -->zz-secret<i></i>-org",
             # Two ends in one file, the "-->" first: a comment has to stop at
             # whichever comes first or the first one swallows the name.
             "both-ends.html": b"<!-- x -->zz-secret<!-- y --!>-org"}
    for name, data in cases.items():
        (closed / name).write_bytes(data)
        assert b"zz-secret-org" not in data
    assert assert_caught(anon_check.check_site(closed, TOKENS)) == [
        f"{name}: contains a denylisted token (#2 in .anon-tokens, decoded view)"
        for name in sorted(cases)]
    # "<!--!>" is not a close in the spec either: the comment swallows the rest
    # of the file, which the module docstring lists as a limit rather than a
    # hiding place, because a reader sees nothing after it at all.
    swallowed = tmp_path / "swallowed"
    swallowed.mkdir()
    (swallowed / "unclosed.html").write_bytes(b"<!--!>zz-secret<i></i>-org")
    assert anon_check.check_site(swallowed, TOKENS) == []


def test_a_control_reference_decodes_to_its_code_point(tmp_path: Path):
    # The scan finds a two-word name either way, because the entry matches with
    # its space closed up. What this pass fixes is the decode itself: the spec
    # emits U+000B, so the text a reader sees holds a gap the width of a space,
    # and a one-word entry must not match across it.
    assert anon_check.rendered_text("zz first&#11;last") == "zz first\u000blast"
    assert anon_check.rendered_text("&#x1f;&#X1D;&#0000028;") == "\u001f\u001d\u001c"
    assert anon_check.rendered_text("&amp;#30;") == "\u001e"
    assert anon_check.rendered_text("&#30") == "\u001e"
    assert anon_check.rendered_text("&#1;&#8;&#14;&#27;&#127;") == "\u0001\u0008\u000e\u001b\u007f"
    # The 0x80 to 0x9F rows stay replaced and U+0000 stays U+FFFD, because the
    # spec replaces both and Chrome agrees that "&#133;" is an ellipsis.
    assert anon_check.rendered_text("&#133;&#0;") == "…�"
    # Leading zeros do not count, so a padded reference names the same code point
    # however deeply it is padded. A digit bound in the pattern erased this one
    # instead, and this test asserted the erasure as correct for five rounds.
    assert anon_check.rendered_text("&#00000000000011;") == "\u000b"
    assert anon_check.rendered_text("&#x0000000b;") == "\u000b"
    # A value past U+10FFFF is out of range, which the spec answers with U+FFFD.
    # The pad is longer than int() will convert, so the length is checked first.
    assert anon_check.rendered_text("&#99999999999;") == "�"
    assert anon_check.rendered_text("&#" + "0" * 6000 + "11;") == "\u000b"
    # However the reference is spelled, it reaches the same code point, so the
    # rule for U+000B below holds for every spelling of it.
    one_word = tmp_path / "one-word"
    one_word.mkdir()
    forms = {"dec.html": "&#11;", "hex.html": "&#x0b;", "padded.html": "&#0000011;",
             "literal.html": "\u000b"}
    for name, form in forms.items():
        (one_word / name).write_bytes(f"<p>zzfirst{form}last</p>".encode())
    assert assert_caught(anon_check.check_site(one_word, ["zzfirstlast"])) == [
        f"{name}: contains a denylisted token (#1 in .anon-tokens, "
        f"{'utf-8' if name == 'literal.html' else 'decoded'} view)" for name in sorted(forms)]


def test_vertical_tab_and_shift_out_are_ruled_alike(tmp_path: Path):
    # Round 7 spaced U+000B on a measured 16 px advance at zero ink while U+000E,
    # measured at 21.3 px at zero ink, was erased, so the rule spaced the smaller
    # gap and erased the larger one and "zzsecret&#11;person" passed in every form
    # the build emits. Both are control characters that no rendering standard calls
    # whitespace, which is the rule now. The two are asserted together, in each
    # form, so neither can drift from the other again.
    forms = {
        "dec.html": lambda c: f"<p>zzsecret&#{ord(c)};&#{ord(c)};person</p>",
        "hex.html": lambda c: f"<p>zzsecret&#x{ord(c):02x};person</p>",
        "raw.html": lambda c: f"<p>zzsecret{c}{c}person</p>",
        "css.css": lambda c: f".n:after{{content:'zzsecret\\{ord(c):06x}person'}}",
        "map.json": lambda c: '{"sourcesContent":["zzsecret\\u%04xperson"]}' % ord(c),
        "text.svg": lambda c: f"<svg><text>zzsecret&#{ord(c)};person</text></svg>",
    }
    for char in ("\u000b", "\u000e"):
        root = tmp_path / f"u{ord(char):04x}"
        root.mkdir()
        for name, form in forms.items():
            (root / name).write_bytes(form(char).encode())
        found = assert_caught(anon_check.check_site(root, ["zzsecretperson"]))
        assert sorted(line.split(":")[0] for line in found) == sorted(forms), char
    # The same six with a space are the entry written in two whole words, which the
    # separator rule reads as the entry. Running on into a longer word, they are
    # not the entry, in any form: that boundary, not the gap, is what keeps the
    # rule off prose.
    root = tmp_path / "space"
    root.mkdir()
    runs_on = tmp_path / "runs-on"
    runs_on.mkdir()
    for name, form in forms.items():
        (root / name).write_bytes(form(" ").encode())
        (runs_on / name).write_bytes(form(" ").replace("person", "personal").encode())
    found = assert_caught(anon_check.check_site(root, ["zzsecretperson"]))
    assert sorted(line.split(":")[0] for line in found) == sorted(forms)
    assert anon_check.check_site(runs_on, ["zzsecretperson"]) == []


def test_control_references_the_spec_emits_are_decoded(tmp_path: Path):
    # html.unescape returns "" for these; the HTML spec emits the code point and
    # Chrome 153 does emit it. Dropping the reference instead joined "first" and
    # "last" in the only reading there was, so the two-word name went unseen.
    tokens = ["zz first last"]
    forms = {"dec.html": "&#11;", "hex.html": "&#x0b;", "upper.html": "&#X1F;",
             "padded.html": "&#0000028;", "wrapped.html": "&amp;#29;",
             "bare.html": "&#30"}
    for name, form in forms.items():
        (tmp_path / name).write_bytes(f"<p>zz first{form * 3}last</p>".encode())
    # The 0x80 to 0x9F rows stay replaced, because the spec replaces them and
    # Chrome agrees that "&#133;" is an ellipsis and not U+0085. An ellipsis is
    # ink, so this file is not a finding and does not appear below.
    (tmp_path / "ellipsis.html").write_bytes(b"<p>zz first&#133;&#133;last</p>")
    assert assert_caught(anon_check.check_site(tmp_path, tokens)) == [
        f"{name}: contains a denylisted token (#1 in .anon-tokens, decoded view)"
        for name in sorted(forms)]


def test_a_multi_word_token_matches_with_its_spaces_closed_up(tmp_path: Path):
    # Whether an invisible character leaves a gap differs by code point: U+000E
    # measured a 21.313 px advance in Chrome 153 and U+200B none, both at zero
    # ink. Matching the space-free form of the entry covers both.
    both = tmp_path / "both"
    both.mkdir()
    (both / "gap.html").write_bytes("zz first\u000e\u000e\u000elast".encode())
    (both / "join.html").write_bytes("zz first​​​last".encode())
    (both / "plain.html").write_bytes(b"zz first last")
    assert assert_caught(anon_check.check_site(both, ["zz first last"])) == [
        f"{name}: contains a denylisted token (#1 in .anon-tokens, {layer} view)"
        for name, layer in (("gap.html", "utf-8"), ("join.html", "utf-8"),
                            ("plain.html", "raw"))]
    # The other direction goes only as far as whole words. "zzfirst last" is the
    # one-word entry written in two parts, which the separator rule reads as the
    # entry. "zzfirst lastly" and "azzfirst last" run on into longer words at one
    # end, and squeezing the view would have joined them into findings on prose.
    oneway = tmp_path / "oneway"
    oneway.mkdir()
    (oneway / "spaced.html").write_bytes(b"zzfirst last")
    (oneway / "longer.html").write_bytes(b"zzfirst lastly")
    (oneway / "earlier.html").write_bytes(b"azzfirst last")
    assert assert_caught(anon_check.check_site(oneway, ["zzfirstlast"])) == [
        "spaced.html: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def _escape_every(text: str, every: int, form) -> str:
    return "".join(form(c) if i % every == 0 else c for i, c in enumerate(text))


def test_a_base64_payload_is_expanded_after_its_escapes_come_off(tmp_path: Path):
    # The container stage used to pattern-match the raw bytes, in front of the
    # decoders rather than behind them, so any escape a browser removes before it
    # calls atob() broke the run and the payload was never expanded at all. One
    # ordinary URL escape in a build pipeline reported this file clean with no
    # error line. The woff2 name table holds the entry and the file's own bytes
    # never spell it, at any escape depth.
    payload = base64.b64encode(_woff2("zz-secret-person")).decode()
    css = "@font-face{src:url(data:font/woff2;base64,%s)}"
    cases = {
        "plain.css": css % payload,
        "percent.css": css % _escape_every(
            payload, 10, lambda c: "".join(f"%{b:02X}" for b in c.encode())),
        "entity.css": css % _escape_every(payload, 10, lambda c: f"&#{ord(c)};"),
        "hex-entity.css": css % _escape_every(payload, 5, lambda c: f"&#x{ord(c):02x};"),
        "js-escape.css": css % _escape_every(payload, 10, lambda c: f"\\u{ord(c):04x}"),
    }
    for name, text in cases.items():
        assert "zz-secret-person" not in text, name
        (tmp_path / name).write_text(text)
    # Each file is caught, and caught rather than refused: the name is reported
    # from inside the font's own table, not from a "cannot be fully scanned" line.
    # The whole chain is asserted, because a corrupted payload decodes to a font
    # that reports malformed, which is fail-closed but is not this finding.
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        f"{name} > base64 > woff2 tables: contains a denylisted token "
        f"(#1 in .anon-tokens, utf-8 view)" for name in sorted(cases)]


def test_a_base64_run_crosses_every_filler_its_decoder_discards(tmp_path: Path):
    # Forgiving-base64 strips all ASCII whitespace and b64decode(validate=False)
    # drops every byte outside the alphabet, so a run finder that continues only
    # across CR and LF decodes a payload line by line and a name straddling the
    # wrap is in no single decode. Newline plus indentation is the ordinary shape
    # in XML, YAML and pretty-printed JSON, so this is the default case.
    payload = base64.b64encode(b"x" * 40 + b"zz-secret-person" + b"x" * 40).decode()
    at = 64  # 64 columns is byte 48, inside the token's bytes 40 to 56
    wraps = {"newline": "\n", "crlf": "\r\n", "space": " ", "tab": "\t",
             "form-feed": "\f", "vertical-tab": "\v", "indent": "\n      "}
    for name, wrap in wraps.items():
        body = payload[:at] + wrap + payload[at:]
        # Neither fragment decodes to the whole name on its own.
        assert b"zz-secret-person" not in base64.b64decode(payload[:at] + "==")
        (tmp_path / f"{name}.xml").write_text(f"<data>{body}</data>")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        f"{name}.xml > base64: contains a denylisted token (#1 in .anon-tokens, raw view)"
        for name in sorted(wraps)]


def test_a_payload_inside_a_wide_encoded_document_is_refused(tmp_path: Path):
    # Round 7 found this hole in its own fix, documented it and passed the file.
    # The container stage reads the UTF-8 and latin-1 decodes, not the four utf-16
    # ones, so a UTF-16 document puts a NUL between every two characters of its
    # base64 payload and no run is recognized. A scanner that reads an input it
    # cannot scan and reports clean is fail-open, so the file is refused instead.
    css = ("@font-face{src:url(data:font/woff2;base64,"
           + base64.b64encode(_woff2("zz-secret-person")).decode() + ")}")
    wide = {"utf16le.css": "utf-16-le", "utf16be.css": "utf-16-be",
            "bom.css": "utf-16", "utf32.css": "utf-32-le"}
    for name, enc in wide.items():
        (tmp_path / name).write_bytes(css.encode(enc))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        f"{name}: wide-encoded text the container stage cannot read "
        f"(re-encode as UTF-8)" for name in sorted(wide)]
    # Instance N+1 of the refusal above, found by hunting it: the wide-encoded
    # document is itself percent-encoded, so the file's own bytes are not
    # interleaved and the first version of this check saw nothing. A reader reaches
    # it through a data URI with charset=utf-16, and the container stage still reads
    # an interleaved payload, so the test is on every source and not on the file.
    for name in wide:
        (tmp_path / name).unlink()
    (tmp_path / "wrapped.html").write_bytes(
        b"<p>" + urllib.parse.quote(css.encode("utf-16-le"), safe="").encode()
        + b"</p>")
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "wrapped.html: wide-encoded text the container stage cannot read "
        "(re-encode as UTF-8)"]
    # The document's own text is still read either way, so a refusal never
    # replaces a finding: this one reports both.
    (tmp_path / "wrapped.html").unlink()
    (tmp_path / "both.css").write_bytes(
        f"/* {css} by zz-secret-org */".encode("utf-16-le"))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "both.css: contains a denylisted token (#2 in .anon-tokens, utf-8 view)",
        "both.css: wide-encoded text the container stage cannot read "
        "(re-encode as UTF-8)"]


def test_the_interleaving_alone_does_not_make_a_wide_document(tmp_path: Path):
    # The refusal costs a whole file, so it asks what the interleaving hides and
    # not only whether the bytes are interleaved. b"\x00\xff" repeated is byte for
    # byte UTF-16-BE for a run of U+00FF, and the UTF-8 read of it turns every
    # 0xFF into "?", which any proportion of printable ASCII accepts: a base64
    # fixture already in this suite was refused twice over before the test became
    # "de-interleave and see whether the container stage would have read it".
    assert not anon_check._wide_encoded_text(b"\x00\xff" * 300)
    assert not anon_check._wide_encoded_text(b"\x00?" * 300)
    assert not anon_check._wide_encoded_text(bytes(range(256)) * 4)
    assert anon_check._wide_encoded_text("a clean page of text".encode("utf-16-le") * 4)
    # Too short to be a document, which is what keeps a UTF-16 string inside a
    # binary (a font name record, a PE resource) from refusing the whole file.
    assert not anon_check._wide_encoded_text("short".encode("utf-16-le"))
    # A mark settles a stride the interleaving cannot. This page is mostly outside
    # Latin, so most high bytes are filled and the filler proportion never reaches;
    # the ASCII payload inside it is still interleaved and still hidden from the
    # container stage, and the mark is what says which stride to undo.
    page = "日本語のページを公開する" * 8 + "data:font/woff2;base64,QUJDREVGR0hJSktM"
    assert not anon_check._wide_encoded_text(page.encode("utf-16-le"))
    assert anon_check._wide_encoded_text(page.encode("utf-16"))
    # A mark with no NUL behind it hides nothing. A wide encoding hides ASCII from
    # the container stage only by putting a NUL beside every character, so a
    # latin-1 page that happens to open with "ÿþ", which is FF FE, is read as
    # it stands. Without that condition the mark alone chose the stride, every
    # other letter of the prose formed a base64 run, and the page was refused.
    latin = ("ÿþ is how a UTF-16 mark reads in latin-1, followed by an "
             "ordinary page of prose about nothing in particular").encode("latin-1")
    assert b"\0" not in latin and latin[:2] == b"\xff\xfe"
    assert not anon_check._wide_encoded_text(latin)
    (tmp_path / "latin.txt").write_bytes(latin)
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_a_container_an_escape_hides_is_scanned_or_refused(tmp_path: Path):
    # The second hole round 7 documented and passed: a file that is a container of
    # its own does not get its derived sources expanded, and _expand reads a stream
    # only from offset zero, so a percent-encoded gzip glued to a font or sitting
    # in a data URI mid-page was in no view at all.
    #
    # Two answers. Where the stream expands it is scanned, which is better than a
    # refusal. Where it does not, and the bytes are a container the scan declines
    # to finish rather than ordinary text, it is refused by name.
    payload = urllib.parse.quote(gzip.compress(b"a page by zz-secret-org\n"),
                                 safe="").encode()
    assert b"zz-secret-org" not in payload
    (tmp_path / "glued.woff2").write_bytes(_woff2("Clean Sans") + payload)
    (tmp_path / "page.html").write_bytes(b'<img src="data:application/gzip,'
                                         + payload + b'">')
    (tmp_path / "clean.woff2").write_bytes(_woff2("Clean Sans"))
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        f"{name} > encoded gzip stream: contains a denylisted token "
        f"(#2 in .anon-tokens, raw view)" for name in ("glued.woff2", "page.html")]
    # A bomb inside the hidden stream is the shape that has to refuse: it is a real
    # container and the scan will not finish it.
    for name in ("glued.woff2", "page.html", "clean.woff2"):
        (tmp_path / name).unlink()
    bomb = urllib.parse.quote(gzip.compress(b"\0" * (64 * 1024 * 1024)),
                              safe="").encode()
    (tmp_path / "bomb.woff2").write_bytes(_woff2("Clean Sans") + bomb)
    # And the same bomb with the rest of a page after it, so the member ends
    # before the file does and the reader stops at the member's end. Its own
    # budget check is the one that has to refuse here.
    (tmp_path / "bomb.html").write_bytes(b'<img src="data:application/gzip,'
                                         + bomb + b'">')
    assert anon_check.check_site(tmp_path, TOKENS) == [
        f"{name}: encodes a container the scan cannot expand "
        f"(expands past the scan size limit)"
        for name in ("bomb.html", "bomb.woff2")]


def test_a_hidden_bomb_is_bounded_before_it_materializes(tmp_path: Path,
                                                         monkeypatch):
    # A bomb reached through the hidden-stream pass rather than as a file of its
    # own. The refusal line alone would not prove much, because the budget refuses
    # once the bytes exist either way; what this pins is that they never exist,
    # since the chunked read stops one byte past the budget.
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 1 << 20)
    bomb = urllib.parse.quote(gzip.compress(b"\0" * (64 << 20)), safe="").encode()
    (tmp_path / "bomb.html").write_bytes(b'<img src="data:application/gzip,'
                                         + bomb + b'">')
    tracemalloc.start()
    try:
        assert anon_check.check_site(tmp_path, TOKENS) == [
            "bomb.html: encodes a container the scan cannot expand "
            "(expands past the scan size limit)"]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # 64 MiB unbounded against a 1 MiB budget, so the two are two orders apart and
    # the bound sits well clear of the file's own bytes.
    assert peak < 16 << 20, f"peak {peak >> 20} MiB"


def test_magic_at_the_head_of_a_decoded_source_is_expanded_once(tmp_path: Path):
    # Offset zero is where _expand already reads a container from, so a whole file
    # of percent-encoded gzip is expanded there and the hidden-stream pass must not
    # report it a second time.
    payload = urllib.parse.quote(gzip.compress(b"by zz-secret-org\n"), safe="")
    (tmp_path / "whole.txt").write_text(payload)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "whole.txt > gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_magic_a_decode_manufactures_out_of_text_is_not_a_finding(tmp_path: Path):
    # The hidden-stream pass follows magic bytes a decode produced, and ordinary
    # source text produces them: this file and the scanner both spell container
    # magic as hex escapes, and the JavaScript escape rule decodes "\x89PNG" to a
    # PNG header. The header behind the magic is what says whether a container is
    # there, and here none is, so nothing is decompressed and nothing is refused.
    (tmp_path / "sniff.js").write_bytes(
        rb'const sigs = ["\x89PNG\r\n", "PK\x03\x04", "\x1f\x8b\x08|", "BZh",'
        rb' "\xfd7zXZ\x00", "\x28\xb5\x2f\xfd", "%PDF-", "wOF2", "ustar"];')
    assert anon_check.check_site(tmp_path, TOKENS) == []
    assert anon_check._containers_in(anon_check.payload_bytes(
        (tmp_path / "sniff.js").read_text())) == []
    # The gzip magic carries its compression-method byte: RFC 1952 defines only
    # CM=8, and a stream that names any other method is no gzip a reader reads.
    assert anon_check._containers_in(b"pad\x1f\x8b\x00\x00rest" + bytes(8)) == []
    # The header is built from parts so this file never spells a valid one: the
    # site scan refuses a validated header that does not decompress.
    head = gzip.compress(b"")[:3] + bytes(1)
    assert anon_check._containers_in(b"pad" + head + b"rest" + bytes(8)) == [(3, "gzip")]


def _heads() -> dict[str, bytes]:
    # One real container of every kind the scan follows past offset zero.
    text = b"a page of ordinary prose\n" * 40
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = len(text)
        tf.addfile(info, io.BytesIO(text))
    heads = {"gzip": gzip.compress(text), "xz": lzma.compress(text),
             "bzip2": bz2.compress(text), "zip": _zip({"a.txt": text}),
             "woff2": _woff2("Test Sans"), "png": _png_ztxt(b"k", text),
             "pdf": b"%PDF-1.7\n", "tar": tar.getvalue()}
    try:
        from compression import zstd
        heads["zstd"] = zstd.compress(text)
    except ImportError:
        pass
    return heads


def test_every_header_field_the_validator_reads_is_required(tmp_path: Path):
    # The validator is what stands between "magic" and "a container that must be
    # expanded or refused". Each real container validates at an offset, and each
    # one with a single field its format fixes broken does not, so no check in it
    # is decoration. A check that failed a real stream would be the miss, so the
    # real side is asserted for every kind.
    breaks = {"gzip": (3, 0xE0), "xz": (7, 0x10), "bzip2": (4, 0xFF), "zip": (8, 0x40),
              "woff2": (14, 0x01), "png": (12, 0x20), "pdf": (5, 0x0A), "tar": (262, 0x01),
              "zstd": (4, 0x08)}
    for kind, head in _heads().items():
        placed = b"prefix" + head
        assert anon_check._valid_container(placed, 6, kind), kind
        assert (6, kind) in anon_check._containers_in(placed), kind
        at, bits = breaks[kind]
        broken = bytearray(placed)
        broken[6 + at] ^= bits
        assert not anon_check._valid_container(bytes(broken), 6, kind), kind
    # And the fields read past a fixed position, one at a time.
    xz = b"p" + lzma.compress(b"x")
    assert not anon_check._valid_container(xz[:9] + bytes([xz[9] ^ 1]) + xz[10:], 1, "xz")
    bz = b"p" + bz2.compress(b"")
    assert anon_check._valid_container(bz, 1, "bzip2")  # the empty-stream magic
    assert not anon_check._valid_container(b"pBZh0" + bz[5:], 1, "bzip2")
    eocd = b"p" + _zip({})
    assert anon_check._valid_container(eocd, 1, "zip")
    assert not anon_check._valid_container(eocd[:5] + b"\x00\x01" + eocd[7:], 1, "zip")
    woff2 = b"p" + _woff2("Test Sans")
    for field, value in ((8, struct.pack(">I", len(woff2))), (8, struct.pack(">I", 40)),
                         (12, b"\x00\x00")):
        cut = woff2[:1 + field] + value + woff2[1 + field + len(value):]
        assert not anon_check._valid_container(cut, 1, "woff2"), (field, value)
    assert not anon_check._valid_container(b"p" + _woff2("Test Sans"), 1, "woff")
    woff = b"p" + b"wOFF" + bytes(8) + struct.pack(">HH", 1, 0) + bytes(28)
    assert not anon_check._valid_container(woff, 1, "woff")  # length 0 is no font
    woff = woff[:9] + struct.pack(">I", 44) + woff[13:]
    assert anon_check._valid_container(woff, 1, "woff")
    tar = b"p" + _heads()["tar"]
    assert not anon_check._valid_container(tar[:1 + 511], 1, "tar")
    assert anon_check._valid_container(tar[:1 + 512], 1, "tar")
    # The checksum is not read: it covers the member name, which is text.
    assert anon_check._valid_container(tar[:149] + b"zzzzzzzz" + tar[157:], 1, "tar")
    assert not anon_check._valid_container(b"p" + bytes(8), 1, "gzip")
    # xz's reserved flag bits are checked on their own, not only through the CRC:
    # a writer that sets one also writes the CRC that matches it.
    for flags, ok in ((b"\x00\x04", True), (b"\x01\x04", False), (b"\x00\x14", False)):
        head = b"p\xfd7zXZ\x00" + flags + struct.pack("<I", zlib.crc32(flags))
        assert anon_check._valid_container(head, 1, "xz") is ok, flags
    # An end record is 22 bytes, and eight of one is not an archive.
    assert not anon_check._valid_container(b"pPK\x05\x06" + bytes(4), 1, "zip")
    # A head cut off inside the fields the check reads is no container, whatever
    # the error reading past the end is.
    for kind, cut in (("gzip", b"p\x1f\x8b\x08"), ("xz", b"p\xfd7zXZ\x00\x00"),
                      ("bzip2", b"pBZh"), ("zstd", b"p\x28\xb5\x2f\xfd"),
                      ("woff2", b"pwOF2" + bytes(4)), ("zip", b"pPK\x03\x04")):
        assert not anon_check._valid_container(cut, 1, kind), kind
    # Offset zero is _expand's, for a tar as for the rest.
    assert anon_check._containers_in(_heads()["tar"]) == []
    assert anon_check._containers_in(b"x" + _heads()["tar"]) == [(1, "tar")]


def test_the_zstd_frame_header_is_walked_to_its_first_block(tmp_path: Path):
    # zstd's magic is four bytes and the descriptor after it has one reserved bit,
    # so the first block header is what separates a frame from four bytes of hex
    # escapes in a script: its type must not be the reserved one and its size must
    # fit the 128 KiB block maximum.
    zstd = pytest.importorskip("compression.zstd")
    frame = b"p" + zstd.compress(b"a page of ordinary prose\n" * 40)
    assert anon_check._valid_container(frame, 1, "zstd")
    descriptor = frame[5]
    single = bool(descriptor & 0x20)
    block_at = (1 + 5 + (0 if single else 1) + (0, 1, 2, 4)[descriptor & 3]
                + (int(single), 2, 4, 8)[descriptor >> 6])
    block = int.from_bytes(frame[block_at:block_at + 3], "little")
    for bad in (block | 0b110, (block & 0b111) | (128 * 1024 + 1) << 3):
        cut = frame[:block_at] + bad.to_bytes(3, "little") + frame[block_at + 3:]
        assert not anon_check._valid_container(cut, 1, "zstd"), hex(bad)
    exact = (block & 0b111) | (128 * 1024) << 3
    assert anon_check._valid_container(
        frame[:block_at] + exact.to_bytes(3, "little") + frame[block_at + 3:], 1, "zstd")
    assert not anon_check._valid_container(frame[:block_at + 2], 1, "zstd")
    # A frame written as a stream does not know its size, so it carries a window
    # byte and no single-segment flag, and the walk has to step over that byte.
    # Its block is large enough that reading the block header one byte early, from
    # the window byte on, names a block past the 128 KiB maximum.
    rng = random.Random(5)
    writer = zstd.ZstdCompressor()
    streamed = b"p" + writer.compress(bytes(rng.choice(b"abcdefghij") for _ in range(20_000)))
    streamed += writer.flush()
    assert not streamed[5] & 0x20
    assert anon_check._valid_container(streamed, 1, "zstd")


def _realistic_gzip() -> bytes:
    # A payload the size a page really carries, with every byte a decoder rewrites
    # in its compressed form. Round 8's witness compressed to 44 bytes with no
    # backslash, ampersand or percent in it, so the decode could not damage it, and
    # the same feature failed 25 times in 25 on realistic input.
    for seed in range(200):
        rng = random.Random(seed)
        words = ["".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(2, 9)))
                 for _ in range(260)]
        words.insert(130, "zz-secret-org")
        payload = gzip.compress(" ".join(words).encode(), mtime=0)
        if all(b in payload for b in (b"\\", b"&", b"%", b"\n")):
            return payload
    raise AssertionError("no payload holds every byte a decoder rewrites")


def test_a_realistic_payload_an_escape_hides_is_read_byte_for_byte(tmp_path: Path):
    # The decode fixed point ran every decoder again over what a percent escape
    # had restored, so a backslash, an ampersand or a percent sign inside the
    # binary was decoded as if it were text and the stream came back damaged.
    # Round 8 then skipped every stream zlib refused. Each form below is how a
    # build really writes a binary into text, and each is read the way a reader
    # reads it: once per layer.
    payload = _realistic_gzip()
    assert len(payload) > 1000
    escaped = urllib.parse.quote(payload, safe="").encode()
    forms = {
        "percent.html": b'<img src="data:application/gzip,' + escaped + b'">',
        # JSON writes 0x08 and 0x0C as "\b" and "\f" and 0x0A as "\n".
        "json.js": b"var blob = " + json.dumps(payload.decode("latin-1")).encode() + b";",
        # A URL encoder that leaves "&" alone, then the attribute's own escaping.
        "attr.html": b'<a href="data:application/gzip,' + html.escape(
            urllib.parse.quote(payload, safe="&=+$,;:@")).encode() + b'">x</a>',
        "glued.woff2": _woff2("Clean Sans") + escaped,
    }
    for name, data in forms.items():
        assert b"zz-secret" not in data, name
        (tmp_path / name).write_bytes(data)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        f"{name} > encoded gzip stream: contains a denylisted token "
        f"(#2 in .anon-tokens, raw view)" for name in sorted(forms)]


def test_a_payload_every_reading_damages_is_refused_not_passed(tmp_path: Path):
    # A data URL keeps a raw backslash. Round 9 applied the script layer to every
    # file, so that payload came back one byte short and was refused. The reading
    # that takes character references and then percent escapes, and no backslash
    # escapes, is the data URL's own, so the payload is now read whole and caught.
    payload = _realistic_gzip()
    minimal = "".join(chr(c) if 33 <= c < 127 and chr(c) not in '%"<>&' else f"%{c:02X}"
                      for c in payload).encode()
    assert b"\\" in minimal
    (tmp_path / "page.html").write_bytes(b'<img src="data:x,' + minimal + b'">')
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "page.html > encoded gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]
    # Damage no reading undoes is refused, after what came before it is scanned:
    # one byte flipped after the name, and one flipped before it.
    (tmp_path / "page.html").unlink()
    for name, spot in (("after.html", len(payload) - 40), ("before.html", 20)):
        flipped = payload[:spot] + bytes([payload[spot] ^ 0xFF]) + payload[spot + 1:]
        escaped = urllib.parse.quote(flipped, safe="").encode()
        (tmp_path / name).write_bytes(b'<img src="data:x,' + escaped + b'">')
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert "before.html: encodes a container the scan cannot expand (corrupt gzip stream)" in errs
    assert "after.html: encodes a container the scan cannot expand (corrupt gzip stream)" in errs
    # The name sits at about half way, so only the stream damaged after it gives it
    # up before the damage.
    assert [e for e in errs if CATCH in e] == [
        "after.html > encoded gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]
    assert len(errs) == 3


def test_a_stream_cut_short_is_scanned_as_far_as_it_goes_and_refused(tmp_path: Path):
    # The GzipFile fallback scanned a truncated member as far as it went and said
    # nothing about the rest. Now what was read is scanned, and the stream is
    # refused as well, for every stream kind, so a refusal never stands where a
    # finding was there to report.
    rng = random.Random(1)
    text = b" ".join(b"".join(rng.choice(string.ascii_lowercase).encode()
                              for _ in range(rng.randint(2, 9))) for _ in range(9000))
    text = text[:30000] + b" zz-secret-org " + text[30000:]
    cut = {"cut.gz": gzip.compress(text), "cut.xz": lzma.compress(text),
           "cut.bz2": bz2.compress(text)}
    for name, data in cut.items():
        (tmp_path / name).write_bytes(data[:len(data) * 3 // 4])
    kinds = {"cut.gz": "gzip", "cut.xz": "xz", "cut.bz2": "bzip2"}
    errs = anon_check.check_site(tmp_path, TOKENS)
    for name, kind in kinds.items():
        assert f"{name}: cannot be fully scanned (truncated {kind} stream)" in errs, name
    # bzip2 emits nothing until a whole block decodes, and this text is one block,
    # so it is the one kind with nothing before the cut to scan.
    assert sorted(e for e in errs if CATCH in e) == [
        f"{name} > {kinds[name]} stream: contains a denylisted token "
        f"(#2 in .anon-tokens, raw view)" for name in ("cut.gz", "cut.xz")]
    assert len(errs) == 5


def test_a_container_glued_into_a_file_is_expanded(tmp_path: Path):
    # Round 8 expanded a stream a percent escape hid mid-file and never the same
    # stream written plainly, because _expand reads only from offset zero. Every
    # stream kind, behind a page, a font and a binary prefix.
    text = " ".join(_realistic_gzip().hex()[i:i + 7] for i in range(0, 1400, 7)).encode()
    text = text[:700] + b" zz-secret-org " + text[700:]
    streams = {"gzip": gzip.compress(text), "xz": lzma.compress(text), "bzip2": bz2.compress(text)}
    try:
        from compression import zstd
        streams["zstd"] = zstd.compress(text)
    except ImportError:
        pass
    fronts = {"html": b"<p>hello</p>" * 50, "woff2": _woff2("Clean Sans"), "bin": b"\0" * 64}
    expected = []
    for kind, stream in streams.items():
        assert b"zz-secret" not in stream, kind
        for front, head in fronts.items():
            name = f"{kind}.{front}"
            (tmp_path / name).write_bytes(head + stream)
            expected.append(f"{name} > embedded {kind} stream: contains a denylisted "
                            f"token (#2 in .anon-tokens, raw view)")
    (tmp_path / "clean.woff2").write_bytes(_woff2("Clean Sans"))
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == sorted(expected)


def test_a_glued_stream_does_not_hide_an_escaped_one(tmp_path: Path):
    # Round 8 dropped every stream a decode revealed whose magic the file's own
    # bytes held anywhere, so one raw gzip glued to a font hid every gzip a percent
    # escape put there too. A stream now belongs to the file's bytes only when its
    # own first byte is a copy of one that starts a valid header of the same kind.
    raw = gzip.compress(b"notes by zz-secret-person\n" * 40)
    escaped = urllib.parse.quote(gzip.compress(b"notes by zz-secret-org\n" * 40),
                                 safe="").encode()
    (tmp_path / "both.woff2").write_bytes(_woff2("Clean Sans") + raw + escaped)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "both.woff2 > embedded gzip stream: contains a denylisted token "
        "(#1 in .anon-tokens, raw view)",
        "both.woff2 > encoded gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_a_later_member_is_not_read_twice(tmp_path: Path):
    # Every member of a multi-member gzip after the first is a valid header past
    # offset zero. Its content is already in the whole stream's output, so it is
    # not reported a second time. A zip stored inside a zip is the other shape: the
    # member is handed on and read from its own offset zero.
    (tmp_path / "two.gz").write_bytes(gzip.compress(b"clean\n" * 40)
                                      + gzip.compress(b"by zz-secret-org\n" * 40))
    inner = gzip.compress(b"by zz-secret-person\n" * 40)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("inner.gz", inner)
    (tmp_path / "stored.zip").write_bytes(buf.getvalue())
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "stored.zip > inner.gz > gzip stream: contains a denylisted token "
        "(#1 in .anon-tokens, raw view)",
        "two.gz > gzip stream: contains a denylisted token (#2 in .anon-tokens, raw view)"]


def test_a_tar_past_offset_zero_is_found_by_its_header(tmp_path: Path):
    # A tar carries its magic 257 bytes in, so it was never found past offset
    # zero. Its members are stored, so a plaintext member is read by the file's
    # own views either way; a brotli member has no magic and no plaintext, and is
    # read only once the tar around it is.
    tar = io.BytesIO()
    member = brotli.compress(b"// zz-secret-org " * 20)
    assert b"zz-secret" not in member
    with tarfile.open(fileobj=tar, mode="w") as tf:
        info = tarfile.TarInfo("app.js.br")
        info.size = len(member)
        tf.addfile(info, io.BytesIO(member))
    (tmp_path / "glued.woff2").write_bytes(_woff2("Clean Sans") + tar.getvalue())
    (tmp_path / "page.html").write_bytes(
        b"<p>" + urllib.parse.quote(tar.getvalue(), safe="").encode() + b"</p>")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "glued.woff2 > embedded app.js.br > brotli stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)",
        "page.html > encoded app.js.br > brotli stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]
    # The header check reads the magic and not the checksum, which covers the
    # member name. A script string leaves "&amp;" and "%41" in a name as they are.
    # The readings that decode them bring the tar back with a bad checksum, which
    # tarfile refuses; the reading that takes backslash escapes alone is the
    # script's own and reads it whole. A checksum in the header check would have
    # turned the damaged copies away as no tar at all, which is harmless now, but
    # it would also have been the only thing standing between a damaged copy and
    # silence when no reading reads it whole.
    for name in ("glued.woff2", "page.html"):
        (tmp_path / name).unlink()
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        info = tarfile.TarInfo("a&amp;b%41.js.br")
        info.size = len(member)
        tf.addfile(info, io.BytesIO(member))
    (tmp_path / "bundle.js").write_bytes(
        b"var t = " + json.dumps(tar.getvalue().decode("latin-1")).encode() + b";")
    # The damaged copies find the tar's magic 257 bytes in at a head the lost
    # bytes shifted, which is another place, not another tar: its magic sits
    # inside the one that read whole, so it is no refusal.
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "bundle.js > encoded a&amp;b%41.js.br > brotli stream: contains a denylisted "
        "token (#2 in .anon-tokens, raw view)"]


def test_the_payload_map_points_every_copied_byte_at_itself(tmp_path: Path):
    # The map is what tells a stream a decode made from one the file holds. Every
    # byte a layer copied maps to its own offset in the file; every byte a layer
    # produced maps to nothing, including the tail of a named reference that
    # html.unescape hands back unchanged, which is a copy.
    text = "ab%41&amp;\\x41c&notit;&zz"
    out, trail = anon_check._payload(text, utf8=False)
    assert out == b"abA&Ac\xacit;&zz"
    assert [anon_check._file_offset(trail, p) for p in range(len(out))] == [
        0, 1, None, None, None, 14, None, 19, 20, 21, 22, 23, 24]
    # And over arbitrary input made of the characters the layers act on.
    rng = random.Random(3)
    for _ in range(300):
        raw = "".join(rng.choice("ab&%;#x1f0uFnl\\<amp ") for _ in range(rng.randint(0, 60)))
        for utf8 in (True, False):
            out, trail = anon_check._payload(raw, utf8)
            for p in range(len(out)):
                q = anon_check._file_offset(trail, p)
                assert q is None or raw.encode("latin-1")[q] == out[p], (raw, p, q)


def test_the_payload_reading_decodes_a_reference_as_the_html_spec_does(tmp_path: Path):
    # A control the spec emits is emitted, a C1 reference becomes the windows-1252
    # character the spec maps it to, which no byte holds, and U+0000 is U+FFFD.
    # So a gzip written as references, whose magic holds 0x8B, is no gzip to a
    # reader either, and this reading does not invent one.
    assert anon_check.payload_bytes("&#1;&#139;&#0;&#65") == b"\x01??A"


def test_a_raw_utf8_character_can_name_a_byte(tmp_path: Path):
    # JSON written without its ASCII escape puts U+0080 to U+00FF into the file as
    # UTF-8, and a script reading the string back gets one byte per character.
    # Only the payload source that takes the UTF-8 read first holds the stream.
    payload = _realistic_gzip()
    text = json.dumps(payload.decode("latin-1"), ensure_ascii=False)
    (tmp_path / "blob.js").write_bytes(b"var s = " + text.encode("utf-8") + b";")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "blob.js > encoded gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_an_ampersand_before_a_glued_stream_is_not_a_decode(tmp_path: Path):
    # html.unescape answers "&" and the 32 bytes after it with the same bytes when
    # they name no entity. Marked decoded, those bytes made a raw stream glued
    # right after an "&" look like one a decode revealed, and the damaged copy of
    # it in the decoded source was refused beside the real finding.
    (tmp_path / "page.html").write_bytes(b"<p>Q&A</p>&" + _realistic_gzip())
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "page.html > embedded gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_a_multi_member_stream_is_one_stream(tmp_path: Path):
    # A reader decompresses every member, so a name in the last one is in the
    # stream, and padding between members is what the format allows: NUL for gzip
    # and xz. The later members are read as part of the whole and not again.
    clean, secret = b"a clean page\n" * 40, b"by zz-secret-org\n" * 40
    files = {"two.gz": gzip.compress(clean) + b"\0" * 8 + gzip.compress(secret),
             "two.xz": lzma.compress(clean) + b"\0" * 4 + lzma.compress(secret),
             "joined.xz": lzma.compress(clean) + lzma.compress(secret),
             "two.bz2": bz2.compress(clean) + bz2.compress(secret)}
    kinds = {"gz": "gzip", "xz": "xz", "bz2": "bzip2", "zst": "zstd"}
    try:
        from compression import zstd
        files["two.zst"] = zstd.compress(clean) + zstd.compress(secret)
    except ImportError:
        pass
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    found = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert [line for line in found if "denylisted" in line and " > " not in line] == [
        f"{name}: contains a denylisted token (#2 in .anon-tokens, raw view)"
        for name in sorted(files) if name.endswith(".zst")]
    assert [line for line in found if " > " in line] == [
        f"{name} > {kinds[name.rsplit('.', 1)[1]]} stream: contains a denylisted token "
        f"(#2 in .anon-tokens, raw view)" for name in sorted(files)]


def test_a_later_member_is_not_expanded_again(tmp_path: Path, monkeypatch):
    # Each later member is a valid header past offset zero, and reading it as a
    # stream of its own reads every member after it again, which is quadratic in
    # the members and charged to the budget each time. Twenty members of 1,000
    # bytes fit a 30,000-byte budget once and not twice.
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 30_000)
    member = b"<.> " * 250  # no base64 letters, so only the stream is charged
    (tmp_path / "many.gz").write_bytes(b"".join(gzip.compress(member) for _ in range(20)))
    (tmp_path / "many.xz").write_bytes(b"".join(lzma.compress(member) for _ in range(20)))
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_every_stream_is_charged_to_the_budget(tmp_path: Path, monkeypatch):
    # The stream's output and the members read out of it both count: 10,240
    # bytes of tar and 3,000 bytes of member pass an 12,000-byte budget only if
    # the stream is free.
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 12_000)
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 3000
        tf.addfile(info, io.BytesIO(b"<.> " * 750))
    assert len(tar.getvalue()) == 10_240
    (tmp_path / "a.tar.gz").write_bytes(gzip.compress(tar.getvalue()))
    (tmp_path / "a.tar.xz").write_bytes(lzma.compress(tar.getvalue()))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        f"{name} > {kind} stream: cannot be fully scanned (expands past the scan size limit)"
        for name, kind in (("a.tar.gz", "gzip"), ("a.tar.xz", "xz"))]


def test_every_stream_kind_is_bounded_before_it_materializes(tmp_path: Path, monkeypatch):
    # Each reader stops one piece past the budget, so a bomb of any kind never
    # exists in memory whole. 32 MiB of zeros against a 1 MiB budget; the bound
    # leaves room for xz's own 8 MiB dictionary, which tracemalloc sees too.
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 1 << 20)
    zeros = bytes(32 << 20)
    bombs = {"bomb.xz": lzma.compress(zeros), "bomb.bz2": bz2.compress(zeros)}
    try:
        from compression import zstd
        bombs["bomb.zst"] = zstd.compress(zeros)
    except ImportError:
        pass
    del zeros
    for name, data in bombs.items():
        (tmp_path / name).write_bytes(data)
        tracemalloc.start()
        try:
            errs = anon_check.check_site(tmp_path, TOKENS)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert errs == [f"{name}: cannot be fully scanned (expands past the scan size limit)"]
        assert peak < 16 << 20, f"{name} peak {peak >> 20} MiB"
        (tmp_path / name).unlink()


def test_one_refusal_per_stream_that_cannot_be_read(tmp_path: Path):
    # A page with UTF-8 text in it is read with and without the UTF-8 read first,
    # and each reading finds the same damaged stream at the same place in the file.
    # It is refused once. The same readings of a readable stream are reported once
    # as well, and so is a later member of a stream a decode revealed, whose output
    # is part of the whole stream's.
    payload = _realistic_gzip()
    flipped = payload[:600] + bytes([payload[600] ^ 0xFF]) + payload[601:]
    (tmp_path / "damaged.html").write_bytes(
        b'<img src="data:x,' + urllib.parse.quote(flipped, safe="").encode()
        + '"><p>caf\u00e9 &amp; \\n</p>'.encode())
    two = gzip.compress(b"a clean page\n" * 40) + gzip.compress(b"by zz-secret-org\n" * 40)
    (tmp_path / "members.html").write_bytes(
        b'<img src="data:x,' + urllib.parse.quote(two, safe="").encode()
        + '"><p>caf\u00e9 &amp; \\n</p>'.encode())
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert [e for e in errs if CATCH not in e] == [
        "damaged.html: encodes a container the scan cannot expand (corrupt gzip stream)"]
    assert [e for e in errs if e.startswith("members.html")] == [
        "members.html > encoded gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_an_archive_covers_its_members_and_not_what_it_hides(tmp_path: Path):
    # A zip's own bytes are each listed member's local header and data, and its
    # central directory. A container that starts inside a member is the member's
    # to find, from the member's own offset zero; here the member is the first 300
    # bytes of a tar header, whose magic the file's bytes carry on into the zip's
    # records. No reader sees a tar there, and the member's own scan finds none.
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("head.bin", tar.getvalue()[:300])
        zf.writestr("pad.txt", b"<.> " * 200)
    (tmp_path / "split.zip").write_bytes(buf.getvalue())
    assert anon_check.check_site(tmp_path, TOKENS) == []
    # A local entry the central directory does not list is no member, so it is not
    # the archive's either: a reader that walks local headers unpacks it, and the
    # scan reads the stream stored in it.
    hidden = gzip.compress(b"notes by zz-secret-org\n" * 40)
    entry = (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0, zlib.crc32(hidden),
                                          len(hidden), len(hidden), 6, 0)
             + b"hid.gz" + hidden)
    (tmp_path / "split.zip").write_bytes(entry + buf.getvalue())
    found = anon_check.check_site(tmp_path, TOKENS)
    assert "split.zip > embedded gzip stream: contains a denylisted token " \
           "(#2 in .anon-tokens, raw view)" in found


def test_a_tar_file_is_not_expanded_again_at_each_header(tmp_path: Path):
    # Every member of a tar starts with a header that carries the magic, so a tar
    # file holds a valid tar header past offset zero for each member after the
    # first. Those are its own members, read once.
    # A header's own fields are scanned where the header is read, so a header read
    # twice reports its owner twice.
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        for name, data, owner in (("a.txt", b"clean", "builder"),
                                  ("b.br", brotli.compress(b"// zz-secret-org " * 20),
                                   "zz-secret-person")):
            info = tarfile.TarInfo(name)
            info.size, info.uname = len(data), owner
            tf.addfile(info, io.BytesIO(data))
    (tmp_path / "two.tar").write_bytes(tar.getvalue())
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "two.tar: contains a denylisted token (#1 in .anon-tokens, raw view)",
        "two.tar > b.br: contains a denylisted token (#1 in .anon-tokens, tar header view)",
        "two.tar > b.br > brotli stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_the_depth_bound_counts_a_container_an_escape_hides(tmp_path: Path,
                                                            monkeypatch):
    # Every other bound here refuses by name. Without the hidden stream in the
    # depth check, the bound would drop one silently, which is the fail-open shape
    # the whole gate exists to close.
    monkeypatch.setattr(anon_check, "SITE_MAX_DEPTH", 0)
    payload = urllib.parse.quote(gzip.compress(b"by zz-secret-org\n"), safe="")
    (tmp_path / "page.html").write_text(f'<img src="data:x,{payload}">')
    # And a stream glued into the file's own bytes, which _expand does not read.
    (tmp_path / "glued.html").write_bytes(b"<p>x</p>" + gzip.compress(b"clean\n" * 40))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "glued.html: nesting exceeds the scan depth limit",
        "page.html: nesting exceeds the scan depth limit"]


def test_a_decoded_source_keeps_every_byte_a_byte(tmp_path: Path):
    # Why the two above can see anything at all. The container sources used to
    # percent-decode as UTF-8, which is right for a name and destroys a payload:
    # "%1F%8B%08" is a gzip header and as UTF-8 it is one byte and two replacement
    # characters, so no derived source ever held the stream to be found. The text
    # reading is unchanged and still reads a percent escape as a character.
    # Built from its parts, so no escape in this file spells a whole gzip header.
    magic = gzip.compress(b"")[:3] + bytes(1)
    header = "".join(f"%{b:02X}" for b in magic)
    assert anon_check.payload_bytes(header) == magic
    assert anon_check.rendered_text(header) == "\x1f�" + "".join(map(chr, magic[2:]))
    # The payload reading also leaves "+" alone, because "+" is a base64 letter
    # whose space the decoder discards.
    assert anon_check.payload_bytes("a+b") == b"a+b"
    assert anon_check.rendered_text("a+b") == "a b"


def test_the_ambiguous_space_set_is_derived_not_listed(tmp_path: Path):
    # The set expression, walked here rather than at import: the code points
    # str.split() turns into a space where no rendering authority calls them
    # whitespace and no browser measurement settled them.
    spaces = {cp for cp in range(0x110000) if chr(cp).isspace()}
    assert len(spaces) == 29
    separators = {cp for cp in spaces
                  if unicodedata.category(chr(cp)) in ("Zs", "Zl", "Zp")}
    derived = spaces - separators - set(map(ord, anon_check._CSS_WHITESPACE))
    assert sorted(f"U+{cp:04X}" for cp in derived) == [
        "U+000B", "U+001C", "U+001D", "U+001E", "U+001F", "U+0085"]
    assert {cp for cp in range(0x110000)
            if anon_check._AMBIGUOUS_SPACE.fullmatch(chr(cp))} == derived


def test_a_one_word_entry_split_by_a_space_fold(tmp_path: Path):
    # The whole 29-code-point axis against a one-word entry. Every one folds to a
    # space, and a space between two whole words that spell the entry is the entry
    # written in two parts, so all 29 are caught there. Where the split name runs on
    # into a longer word at either end, only the six characters no renderer calls
    # whitespace are still caught, by the view that erases them; for the other 23
    # not catching them is the answer, because a reader sees a gap inside a word.
    folded = anon_check._fold_tokens(["zzsecretperson"])
    spaces = sorted(cp for cp in range(0x110000) if chr(cp).isspace())
    whole, runs_on = [], []
    for cp in spaces:
        split = "zzsecret" + chr(cp) * 3 + "person"
        if 0 in anon_check._blob_hits(split.encode(), folded):
            whole.append(f"U+{cp:04X}")
        if any(0 in anon_check._blob_hits(text.encode(), folded)
               for text in ("a" + split, split + "al")):
            runs_on.append(f"U+{cp:04X}")
    assert len(spaces) == 29 and whole == [f"U+{cp:04X}" for cp in spaces]
    assert runs_on == ["U+000B", "U+001C", "U+001D", "U+001E", "U+001F", "U+0085"]


def test_erasing_every_space_invents_findings_on_prose(tmp_path: Path):
    # The measured residual behind the test above, pinned as the mechanism rather
    # than as a preference. Catching a one-word entry split by U+0020 means erasing
    # every space, and then every pair of adjacent words joins: over the 230
    # tracked files of the merged tree, 1,947 of 205,276 dictionary words between 6
    # and 14 letters became findings that the six-character set does not produce.
    # This is one of them, and it is a common surname.
    variant = re.compile("[" + "".join(
        re.escape(chr(cp)) for cp in range(0x110000) if chr(cp).isspace()) + "]")
    blob = b"        errs = fn()\n        return errs\n"
    folded = anon_check._fold_tokens(["turner"])
    assert anon_check._blob_hits(blob, folded) == {}
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(anon_check, "_AMBIGUOUS_SPACE", variant)
        assert 0 in anon_check._blob_hits(blob, folded)
    # The separator rule joins whole words and nothing else, which is why "return
    # errs" above stays clean under it: "turn" does not start a word. A name written
    # in two whole words is the entry; running on at either end, it is not.
    joined = anon_check._fold_tokens(["zzfirstlast"])
    assert anon_check._blob_hits(b"zzfirst last", joined) == {0: "raw"}
    assert anon_check._blob_hits(b"zzfirst lastly", joined) == {}
    assert anon_check._blob_hits(b"azzfirst last", joined) == {}


def test_no_tag_pattern_rescans_from_every_later_angle_bracket(tmp_path: Path):
    # Round 7 wrote _BIDI_OPEN with "[^>]*" and reintroduced the quadratic rescan
    # the markup pass had been rewritten to lose: 786 s on 896 KiB of "if(a<b)",
    # against 0.32 s once every run inside a tag excluded "<" as well.
    #
    # The structural half fails at the edit rather than at the clock, so a reverted
    # pattern is caught with no timing to be flaky about.
    for name in ("_BIDI_OPEN", "_BIDI_CLOSE", "_HIDDEN_START", "_HIDDEN_END"):
        pattern = getattr(anon_check, name).pattern
        assert "[^>]" not in pattern, f"{name} rescans to the end of the text"
    # The timing half covers a pattern nobody thought to name. The input opens a
    # tag that is never closed and holds a "dir" attribute, so it is _BIDI_OPEN's
    # own worst case and not the markup pass's. Measured on 640 KiB of it: the
    # whole scan takes 0.27 s, while one _BIDI_OPEN.search with "[^>]*" restored
    # runs 0.14 s at 16 KiB, 0.57 s at 32, 2.27 s at 64 and 9.11 s at 128, four
    # times the cost for twice the input, which reaches roughly 230 s here. The
    # bound sits between the two with fifty times' headroom over the measurement.
    blob = b"<a dir=lt " * (1 << 16)
    (tmp_path / "a.html").write_bytes(blob + b"zz-secret-org")
    start = time.monotonic()
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "a.html: contains a denylisted token (#2 in .anon-tokens, raw view)"]
    assert time.monotonic() - start < 15


def test_a_right_to_left_override_is_read_in_reading_order(tmp_path: Path):
    # A name written backwards inside a right-to-left override renders forwards in
    # every browser: CVE-2021-42574 aimed at an anonymity gate. Erasing the bidi
    # controls, which the invisible class does, destroyed the only evidence that
    # the displayed order is not the stored order.
    back = "zz-secret-person"[::-1]
    cases = {
        "control.html": f"<p>‮{back}‬</p>",
        "entity.html": f"<p>&#x202e;{back}&#x202c;</p>",
        # No invisible character at all: pure markup, which is what makes this
        # more than an exotic-character case.
        "bdo.html": f'<p><bdo dir="rtl">{back}</bdo></p>',
        "attribute.html": f'<p dir=rtl>{back}</p>',
        # Half forwards and half reversed across the boundary, which reads whole
        # to a person and is why the span is reversed where it stands rather than
        # the entry being matched backwards on its own.
        "split.html": '<p>zz-sec<bdo dir="rtl">' + "ret-person"[::-1] + "</bdo></p>",
        "isolate.html": f"<p>⁧{back}⁩</p>",
    }
    for name, text in cases.items():
        assert "zz-secret-person" not in text, name
        (tmp_path / name).write_text(text)
    flagged = {e.split(":")[0]
               for e in assert_caught(anon_check.check_site(tmp_path, TOKENS))}
    assert flagged == set(cases)
    # And a reordering this module does not model at all, for which the entry is
    # matched reversed: a CSS rule carries no bidi control and no bdo element.
    css = tmp_path / "css"
    css.mkdir()
    (css / "page.html").write_text(
        "<style>.n{direction:rtl;unicode-bidi:bidi-override}</style>"
        f'<p class="n">{back}</p>')
    assert assert_caught(anon_check.check_site(css, TOKENS)) == [
        "page.html: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def test_the_fold_repairs_a_dash_variant(tmp_path: Path):
    # Dropping _DASHES survived round 6's mutation run: no fixture held a dash
    # variant, and a two-word probe name cannot expose one either, because the
    # squeeze satisfies it whatever the dashes became. A one-word entry can.
    for i, cp in enumerate((0x2013, 0x2011, 0x2212, 0x301C)):
        blob = f"pad zz{chr(cp)}secret{chr(cp)}org pad".encode()
        assert b"zz-secret-org" not in blob
        hits = anon_check._blob_hits(blob, anon_check._fold_tokens(["zz-secret-org"]))
        assert 0 in hits, f"U+{cp:04X}"


def test_an_escaped_line_break_is_a_space_and_a_continuation_is_nothing(tmp_path: Path):
    # Two guards a two-word probe name cannot separate. _WS_ESC turns a
    # two-character "\n" into a space, which the catalogue never spells: it only
    # ever writes a backslash before a real control character. _LINE_CONT deletes
    # a backslash before a real line break, and without it the newline survives
    # and the fold spaces it apart.
    (tmp_path / "map.json").write_bytes(b'{"s":"zz first\\nlast"}')
    assert assert_caught(anon_check.check_site(tmp_path, ["zz first last"])) == [
        "map.json: contains a denylisted token (#1 in .anon-tokens, decoded view)"]
    (tmp_path / "map.json").unlink()
    (tmp_path / "app.css").write_bytes(b"/* zz-secret\\\n-org */")
    assert assert_caught(anon_check.check_site(tmp_path, ["zz-secret-org"])) == [
        "app.css: contains a denylisted token (#1 in .anon-tokens, decoded view)"]


def test_the_latin_1_view_reads_a_name_every_decoder_destroys(tmp_path: Path):
    # The view that was called nul-stripped: the latin-1 read folded, with nothing
    # decoded. A latin-1 micro sign needs the fold, utf-8 reads it as U+FFFD, and
    # unquote_plus turns the "+" into a space in both decoded bases, so this name
    # is in that one view and nowhere else.
    (tmp_path / "a.bin").write_bytes("zzµorg+end".encode("latin-1"))
    assert assert_caught(anon_check.check_site(tmp_path, ["zzµorg+end"])) == [
        "a.bin: contains a denylisted token (#1 in .anon-tokens, latin-1 view)"]


def test_base64_charges_every_alignment_to_the_budget(tmp_path: Path, monkeypatch):
    # Only the aligned decode used to be charged, so three quarters of the work
    # ran for free: a 32 MiB base64 file was scanned to the end at 1798 MiB of
    # peak resident memory in 77 s. Charged, it is refused by name in 40 s.
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 1200)
    payload = base64.b64encode(b"\x00\xff" * 300)
    assert len(payload) == 800
    (tmp_path / "a.b64").write_bytes(payload)
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "a.b64: cannot be fully scanned (expands past the scan size limit)"]
    # Under a budget that covers all four, the same file scans clean.
    monkeypatch.setattr(anon_check, "SITE_MAX_EXPANDED", 4000)
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_decoding_to_a_fixed_point_needs_the_whole_bound(tmp_path: Path, monkeypatch):
    # One layer of wrapping comes off per pass, so the bound is exactly how deep
    # an encoding unwinds. The probe is wrapped to the shipped bound, which pins
    # it from below: lowering 16 to 4 passed all 48 tests of round 5, and even 8
    # passed, which is what an unpinned guard looks like.
    assert anon_check.SITE_MAX_DECODE == 16
    form = "%E2%80%8B"
    for _ in range(15):
        form = form.replace("%", "%25")
    blob = b"zz-secret" + (form * 3).encode() + b"-org"
    folded = anon_check._fold_tokens(["zz-secret-org"])
    assert 0 in anon_check._blob_hits(blob, folded)
    for lower in (4, 8, 15):
        with monkeypatch.context() as patched:
            patched.setattr(anon_check, "SITE_MAX_DECODE", lower)
            assert 0 not in anon_check._blob_hits(blob, folded), lower


def test_an_encoding_too_deep_to_unwind_is_refused(tmp_path: Path):
    # Every other bound refuses by name. The decode bound used to stop and report
    # nothing, which is the one behaviour a fail-closed gate cannot have: the file
    # passed with layers still wrapped. It is a finding now, and the file is still
    # scanned, so a name the first sixteen passes do reveal is reported as well.
    form = "%E2%80%8B"
    for _ in range(anon_check.SITE_MAX_DECODE + 4):
        form = form.replace("%", "%25")
    (tmp_path / "deep.html").write_bytes(b"<p>clean" + form.encode() + b"text</p>")
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "deep.html: escapes nest deeper than the decode limit unwinds"]
    # And the ordinary depths a real file reaches are not refused. Measured over
    # every tracked file in this repository: 4 passes at worst, binaries included.
    (tmp_path / "deep.html").unlink()
    (tmp_path / "shallow.html").write_bytes(b"<p>clean%2525E2%252580%25258Btext</p>")
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_every_filler_unit_is_caught(tmp_path: Path):
    # Per-unit coverage of the whole catalogue, with no boundary involved: this
    # is about the views decoding and folding each form, not about windows.
    catalogue = filler_units()
    assert len(catalogue) >= 700
    missed = []
    for index, (name, unit) in enumerate(catalogue.items()):
        head, tail, token = _name_around(index)
        blob = b"pad " + head + unit + tail + b" pad"
        if 0 not in anon_check._blob_hits(blob, anon_check._fold_tokens([token])):
            missed.append(name)
    assert missed == []


def test_every_filler_unit_is_caught_at_a_real_window_boundary(tmp_path: Path):
    # The headline probe. Each unit is long enough that no fixed overlap could
    # cover it, and it starts well before the raw window boundary and ends
    # after it. Round 4 caught 65 of these, fewer than the 96 its own
    # pre-windowing baseline caught, which is why the windowing came out.
    units = boundary_units()
    missed = []
    for index, (name, unit) in enumerate(units.items()):
        head, tail, token = _name_around(index)
        blob = (b"." * (FORMER_BOUNDARY - len(head) - (len(unit) - 2048))
                + head + unit + tail + b"." * 4000)
        assert len(blob) > FORMER_BOUNDARY
        if 0 not in anon_check._blob_hits(blob, anon_check._fold_tokens([token])):
            missed.append(name)
    assert missed == []


@pytest.mark.parametrize("boundary", [2, 3])
def test_filler_units_across_the_later_boundaries(tmp_path: Path, boundary: int):
    # The same units packed into one block that straddles the second and third
    # raw window boundaries, so every name in the block has to be found from a
    # view built across them.
    units = boundary_units(minimum_bytes=512)
    pieces, tokens = [], []
    for index, unit in enumerate(units.values()):
        head, tail, token = _name_around(index)
        pieces.append(head + unit + tail + b"|qq|")
        tokens.append(token)
    block = b"".join(pieces)
    at = FORMER_BOUNDARY * boundary - len(block) // 2
    blob = b"." * at + block + b"." * 4000
    found = anon_check._blob_hits(blob, anon_check._fold_tokens(tokens))
    assert sorted(found) == list(range(len(tokens)))


def test_views_see_the_whole_input(tmp_path: Path):
    # The structural guarantee behind every probe above: a view is built from
    # the whole blob, so it is identical to folding the file in one piece.
    blob = b"." * (FORMER_BOUNDARY + 4096) + "zz-secret\u200b".encode() + b"-org"
    views = dict(anon_check._blob_views(anon_check._Normalized(blob)))
    assert views["utf-8"] == anon_check._fold(blob.decode("utf-8", "replace"))
    assert "zz-secret-org" in views["utf-8"]


def test_markup_a_reader_never_sees_is_dropped(tmp_path: Path):
    # A comment ends at "-->", not at the first ">" inside it, and the body of a
    # script or style element is not shown at all. Each hid a name before.
    (tmp_path / "a.html").write_bytes(b"<p>zz-secret<!-- a > b -->-org</p>")
    (tmp_path / "b.html").write_bytes(b"<p>zz-secret<script>if(1>0){}</script>-org</p>")
    (tmp_path / "c.html").write_bytes(b"<p>zz-secret<STYLE>.x{content:'>'}</STYLE>-org</p>")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "a.html: contains a denylisted token (#2 in .anon-tokens, decoded view)",
        "b.html: contains a denylisted token (#2 in .anon-tokens, decoded view)",
        "c.html: contains a denylisted token (#2 in .anon-tokens, decoded view)"]


def test_decoding_runs_to_a_fixed_point(tmp_path: Path):
    # Encoding depth is unbounded, so the decode loop repeats until it settles
    # rather than a fixed number of times.
    wrapped = b"zz-secret" + b"&amp;amp;amp;#8203;" * 3 + b"-org"
    deep = b"zz-secret" + b"%2525E2%252580%25258B" * 3 + b"-org"
    (tmp_path / "a.html").write_bytes(wrapped)
    (tmp_path / "b.html").write_bytes(deep)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "a.html: contains a denylisted token (#2 in .anon-tokens, decoded view)",
        "b.html: contains a denylisted token (#2 in .anon-tokens, decoded view)"]


def test_site_scans_unclosed_angle_brackets_in_linear_time(tmp_path: Path):
    # Finding markup with "<[^>]*>" rescans from every later "<" when one is
    # never closed. That cost 24 s for 256 KiB and grew with the square, so a
    # few megabytes of it hung the gate for hours.
    (tmp_path / "a.js").write_bytes(b"if(a<b)" * (1 << 17) + b"zz-secret-org")
    start = time.monotonic()
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "a.js: contains a denylisted token (#2 in .anon-tokens, raw view)"]
    assert time.monotonic() - start < 20


def test_site_decodes_a_wrapped_payload_whose_last_line_is_short(tmp_path: Path):
    tokens = ["zz-person"]
    payload = base64.b64encode(b"x" * 40 + b"zz-person").decode()
    # The last wrapped line holds 2 characters before its padding, and dropping
    # that line truncates the decoded bytes mid-name.
    lines = [payload[i:i + 64] for i in range(0, len(payload), 64)]
    assert len(lines) == 2 and len(lines[1].rstrip("=")) < 4
    (tmp_path / "keys.pem").write_text("-----BEGIN DATA-----\n" + "\n".join(lines) + "\n")
    assert assert_caught(anon_check.check_site(tmp_path, tokens)) == [
        "keys.pem > base64: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def test_decoded_views_read_bytes_that_are_not_utf_8(tmp_path: Path):
    # A name carrying a latin-1 byte is mangled by a UTF-8 decode, so the
    # decoded views are built over both bases.
    token = "zz-sécret-org"
    (tmp_path / "a.html").write_bytes("zz-sécret".encode("latin-1")
                                      + b"&#8203;" + b"-org")
    assert assert_caught(anon_check.check_site(tmp_path, [token])) == [
        "a.html: contains a denylisted token (#1 in .anon-tokens, decoded view)"]


def test_utf_16_name_at_an_odd_offset(tmp_path: Path):
    # A UTF-16 string inside a binary can start on an odd byte, where a decode
    # from offset zero pairs the bytes wrongly and reads nothing. The name holds
    # a non-ASCII letter, so the UTF-8 and latin-1 reads of these bytes cannot
    # spell it and only the utf-16 views can: that is what pins all four.
    tokens = ["zz-sécret-org"]
    for enc in ("utf-16-le", "utf-16-be"):
        name = "zz-sécret-org".encode(enc)
        (tmp_path / f"even-{enc}.bin").write_bytes(b"\x01\x02" + name + b"\x01\x01")
        (tmp_path / f"odd-{enc}.bin").write_bytes(b"\x01" + name + b"\x01\x01")
    assert assert_caught(anon_check.check_site(tmp_path, tokens)) == [
        f"{side}-{enc}.bin: contains a denylisted token (#1 in .anon-tokens, utf-16 view)"
        for side in ("even", "odd") for enc in ("utf-16-be", "utf-16-le")]


# ---------------------------------------------------------------------------
# Round 10: one decode dispatcher, weak magic, pinned bounds, the work budget,
# combining marks and multi-part entries. Every container below is built at run
# time from parts, so this file never spells a header a reading could follow.
# ---------------------------------------------------------------------------

SCANNER = ROOT / "scripts" / "anon_check.py"
# Module attributes that decompress or unpack. Referenced anywhere outside the
# decoders _dispatch hands work to, they are a second way in, which is how round 9
# kept a skip-on-corrupt branch in the PDF reader after closing it everywhere else.
DECOMPRESSORS = {
    "zlib.decompressobj", "zlib.decompress", "lzma.LZMADecompressor", "lzma.decompress",
    "lzma.open", "bz2.BZ2Decompressor", "bz2.decompress", "bz2.open",
    "zstd.ZstdDecompressor", "zstd.decompress", "brotli.Decompressor", "brotli.decompress",
    "base64.b64decode", "base64.urlsafe_b64decode", "zipfile.ZipFile", "tarfile.open",
    "gzip.decompress", "gzip.GzipFile", "gzip.open"}


def _handler_problems(source: str, dispatcher: str = "_dispatch") -> list[str]:
    """Every except handler that could let a failure pass, by line.

    Outside the dispatcher a handler must end by raising, or begin by reporting a
    refusal through a problem() call. Nowhere may one hold a pass, or be nothing
    but a continue or a break. The dispatcher itself holds exactly one handler.
    """
    tree = ast.parse(source)
    found: list[str] = []
    owners: dict[int, str] = {}
    for top in tree.body:
        if isinstance(top, (ast.FunctionDef, ast.ClassDef)):
            for node in ast.walk(top):
                owners.setdefault(id(node), top.name)
                if isinstance(top, ast.ClassDef) and isinstance(node, ast.FunctionDef):
                    for inner in ast.walk(node):
                        owners[id(inner)] = node.name
    in_dispatcher = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        owner = owners.get(id(node), "<module>")
        body = node.body
        if any(isinstance(n, ast.Pass) for stmt in body for n in ast.walk(stmt)):
            found.append(f"{node.lineno}: pass in a handler")
        if all(isinstance(stmt, (ast.Continue, ast.Break)) for stmt in body):
            found.append(f"{node.lineno}: a handler that only skips")
        if owner == dispatcher:
            in_dispatcher += 1
            continue
        raises = isinstance(body[-1], ast.Raise)
        reports = (isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Call)
                   and isinstance(body[0].value.func, ast.Attribute)
                   and body[0].value.func.attr == "problem")
        if not (raises or reports):
            found.append(f"{node.lineno}: {owner} handles a failure without raising or reporting")
    if dispatcher in {getattr(n, "name", "") for n in tree.body} and in_dispatcher != 1:
        found.append(f"{dispatcher} holds {in_dispatcher} handlers, not one")
    return found


def test_every_failure_leaves_through_the_one_refusal_path(tmp_path: Path):
    # The class nine rounds closed one instance at a time: a decode that fails and
    # is skipped, passed or read as empty. Closed by construction instead. Every
    # failure anywhere in the scanner either raises into _dispatch, whose one
    # handler turns it into a refusal, or is reported where it is caught.
    assert _handler_problems(SCANNER.read_text(encoding="utf-8")) == []
    # The rule itself, on the shapes it exists for. Round 9's PDF reader was the
    # first of these, and it is flagged.
    shapes = {
        "def f():\n for m in x:\n  try: y()\n  except E: continue\n": True,
        "def f():\n try: y()\n except E: pass\n": True,
        "def f():\n try: y()\n except E: return b''\n": True,
        "def f():\n try: y()\n except E: return False\n": True,
        "def f():\n try: y()\n except E: out = b''\n": True,
        "def _dispatch():\n try: y()\n except E: pass\n": True,
        "def f():\n try: y()\n except E: raise R('fixed') from None\n": False,
        "def f():\n for m in x:\n  try: y()\n  except E:\n   scan.problem(c, 'why')\n   continue\n": False,
        "def _dispatch():\n try: y()\n except E: r = 1\n": False,
        "def _dispatch():\n try: y()\n except E: r = 1\n try: z()\n except E: r = 2\n": True,
    }
    for source, flagged in shapes.items():
        assert bool(_handler_problems(source)) is flagged, source


def test_every_decompressor_is_reached_only_through_the_dispatcher(tmp_path: Path):
    # One way in. Every decompressing library call sits in a decoder that
    # _dispatch hands work to, and nothing but those decoders and the dispatch
    # tables names a decoder, so no path can decode around the one refusal path.
    tree = ast.parse(SCANNER.read_text(encoding="utf-8"))
    family = ({f.__name__ for f in anon_check._CODECS.values()}
              | {f.__name__ for f in anon_check._STRUCTURES.values()} | {"_inflate", "_unpack"})
    assert {"_gzip", "_zlib", "_deflate", "_xz", "_bzip2", "_zstd", "_brotli", "_base64",
            "_member", "_zip", "_tar", "_woff2", "_woff", "_png", "_pdf"} <= family
    tops = {top.name: top for top in tree.body if isinstance(top, ast.FunctionDef)}
    outside: list[str] = []
    for top in tree.body:
        name = getattr(top, "name", None)
        targets = {t.id for t in getattr(top, "targets", []) if isinstance(t, ast.Name)}
        for node in ast.walk(top):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and f"{node.value.id}.{node.attr}" in DECOMPRESSORS and name not in family):
                outside.append(f"{node.lineno}: {node.value.id}.{node.attr} in {name}")
            if (isinstance(node, ast.Name) and node.id in family and name not in family
                    and not targets & {"_CODECS", "_STRUCTURES"}):
                outside.append(f"{node.lineno}: {node.id} named in {name}")
    assert outside == []
    assert set(family) <= set(tops)


def _pdf_bytes(streams: list[tuple[bytes, bytes]]) -> bytes:
    # A PDF assembled at run time. Each stream is (filter name, or b"" for none,
    # data). The newline is made from its code, so no line of this file holds a
    # stream keyword with a newline escape after it.
    nl = bytes([10])
    parts = [b"%PDF-" + b"1.7"]
    for i, (name, data) in enumerate(streams, 1):
        declared = b" /Filter /" + name if name else b""
        parts += [f"{i} 0 obj".encode(),
                  b"<< /Length " + str(len(data)).encode() + declared + b" >>",
                  b"stream", data, b"endstream", b"endobj"]
    return nl.join(parts + [b"%%EOF"]) + nl


def _words(seed: int, count: int, token: str | None = "zz-secret-org", at: float = 0.5) -> bytes:
    rng = random.Random(seed)
    words = ["".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(2, 9)))
             for _ in range(count)]
    if token:
        words.insert(int(count * at), token)
    return " ".join(words).encode()


def test_a_pdf_is_read_in_the_reading_that_reads_it_whole(tmp_path: Path):
    # Round 9's Critical A. A PDF header is printable, so JSON leaves "%PDF-1.7"
    # raw while it escapes the newline after "stream". The ownership rule handed
    # the PDF to the raw bytes, which hold no stream keyword, and said nothing. A
    # data URL keeps a raw backslash, which the one reading round 9 had damaged.
    # Each is now read in the reading that reads it whole and caught.
    found = 0
    for seed in range(200):
        body = zlib.compress(_words(seed, 400), 9)
        if b"\\" not in body:
            continue
        pdf = _pdf_bytes([(b"FlateDecode", body)])
        minimal = "".join(chr(c) if 33 <= c < 127 and chr(c) not in '%"<>&' else f"%{c:02X}"
                          for c in pdf).encode()
        forms = {
            f"ascii{seed}.html": b"<script>const pdf=" + json.dumps(pdf.decode("latin-1")).encode()
                                 + b";</script>",
            f"utf8{seed}.html": b"<script>const pdf=" + json.dumps(
                pdf.decode("latin-1"), ensure_ascii=False).encode("utf-8") + b";</script>",
            f"url{seed}.html": b"<embed src='data:application/pdf," + minimal + b"'>"}
        for name, page in forms.items():
            assert b"zz-secret" not in page
            (tmp_path / name).write_bytes(page)
        found += 1
        if found == 3:
            break
    assert found == 3
    caught = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert len(caught) == 9
    assert all(line.endswith("> encoded pdf stream: contains a denylisted token "
                             "(#2 in .anon-tokens, raw view)") for line in caught)


def test_a_declared_pdf_stream_that_fails_is_refused(tmp_path: Path):
    # The dictionary says what a stream is. A Flate stream that fails is refused,
    # after what it inflated first is scanned; a filter the scan does not decode
    # is refused; a picture is left alone, as a JPEG file is; a stream with no
    # filter is plain bytes the file's own views read.
    # A flipped byte does not stop deflate: it decodes on through garbage, so
    # what follows the damage may still come out, and here does for late.pdf,
    # but the stream fails its check and is refused either way.
    early = zlib.compress(_words(1, 900, at=0.05), 9)
    late = zlib.compress(_words(2, 900, at=0.95), 9)
    flip = len(early) // 2
    files = {
        "early.pdf": _pdf_bytes([(b"FlateDecode", early[:flip] + bytes([early[flip] ^ 0xFF])
                                  + early[flip + 1:])]),
        "late.pdf": _pdf_bytes([(b"FlateDecode", late[:flip] + bytes([late[flip] ^ 0xFF])
                                 + late[flip + 1:])]),
        "cut.pdf": _pdf_bytes([(b"FlateDecode", late[:flip])]),
        "a85.pdf": _pdf_bytes([(b"ASCII85Decode", b"87cURD]i,\"Ebo80~>")]),
        "photo.pdf": _pdf_bytes([(b"DCTDecode", bytes(range(256)) * 8)]),
        "plain.pdf": _pdf_bytes([(b"", b"BT (by zz-secret-person) Tj ET")]),
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    # Text that mentions the filter and ends a line on the word is not a stream.
    (tmp_path / "notes.txt").write_bytes(b"%PDF-" + b"1.7 notes" + bytes([10]).join(
        [b"", b"/Filter /FlateDecode is the usual filter, and the next line ends a stream",
         b"of ordinary prose, which no reader inflates."]))
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert [e for e in errs if CATCH not in e] == [
        "a85.pdf: cannot be fully scanned (a pdf stream filter the scan does not decode)",
        "cut.pdf: cannot be fully scanned (truncated zlib stream)",
        "early.pdf: cannot be fully scanned (corrupt zlib stream)",
        "late.pdf: cannot be fully scanned (corrupt zlib stream)"]
    assert {"early.pdf > pdf stream: contains a denylisted token (#2 in .anon-tokens, raw view)",
            "plain.pdf: contains a denylisted token (#1 in .anon-tokens, raw view)"} <= set(errs)
    assert not [e for e in errs if e.startswith(("photo.pdf", "notes.txt"))]


def test_zlib_is_followed_wherever_its_header_is(tmp_path: Path):
    # Round 9's Critical B. Nothing followed zlib, and every zlib carrier was
    # clean: a file, a published loose git object, pako-style base64 in a script,
    # a JSON string, a stream glued after a page. A header is two bytes, so it is
    # a candidate until its first 128 bytes inflate, and a stream from then on.
    text = _words(3, 300)
    stream = zlib.compress(text, 9)
    assert b"zz-secret" not in stream
    commit = (b"tree " + b"4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor "
              + b"zz-secret-person <a@b> 1 +0000\n\nmsg\n")
    obj = b"commit " + str(len(commit)).encode() + bytes(1) + commit
    digest = __import__("hashlib").sha1(obj).hexdigest()
    (tmp_path / ".git" / "objects" / digest[:2]).mkdir(parents=True)
    (tmp_path / ".git" / "objects" / digest[:2] / digest[2:]).write_bytes(zlib.compress(obj))
    (tmp_path / "blob.bin").write_bytes(stream)
    (tmp_path / "pako.html").write_bytes(b"<script>inflate(atob('" + base64.b64encode(stream)
                                         + b"'))</script>")
    (tmp_path / "json.js").write_bytes(b"var z = " + json.dumps(stream.decode("latin-1")).encode())
    (tmp_path / "glued.html").write_bytes(b"<p>hello</p>" * 20 + stream)
    # A directory's own files are scanned before the directories under it.
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "blob.bin > zlib stream: contains a denylisted token (#2 in .anon-tokens, raw view)",
        "glued.html > embedded zlib stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)",
        "json.js > encoded zlib stream: contains a denylisted token (#2 in .anon-tokens, raw view)",
        "pako.html > base64 > zlib stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)",
        f"{digest[2:]} > zlib stream: contains a denylisted token (#1 in .anon-tokens, raw view)"]


def test_a_weak_candidate_is_proven_by_its_first_bytes_and_refused_after(tmp_path: Path):
    # Where the proof ends is the whole rule, so both sides of it are pinned, with
    # streams cut short, because a cut is the one damage that stops a decoder at a
    # known byte. A zlib stream that ends inside its first 128 bytes is no stream,
    # as a header whose fields do not validate is none: what it inflated is
    # scanned for names and it is not refused. One that runs past them is a
    # stream, and refused where it stops. Raw deflate has no header and no check,
    # so it proves itself only by its first 1,024 bytes, and a payload that ends
    # cleanly before then is scanned for names.
    # Fixed Huffman codes carry no code tables, so the name, written first, comes
    # out of the first few bytes rather than after a hundred bytes of tables.
    whole = zlib.compressobj(9, zlib.DEFLATED, 15, 9, zlib.Z_FIXED)
    long = whole.compress(_words(4, 2500, at=0)) + whole.flush()
    raw = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_FIXED)
    deflated = raw.compress(_words(5, 2500, at=0)) + raw.flush()
    short = zlib.compressobj(9, zlib.DEFLATED, -15)
    tiny = short.compress(b"notes by zz-secret-person, filed") + short.flush()
    assert len(long) > 2000 and len(deflated) > 2000 and len(tiny) < 64
    files = {"inside.bin": long[:100], "past.bin": long[:400],
             "raw-inside.js": b'var d = "' + base64.b64encode(deflated[:900]) + b'";',
             "raw-past.js": b'var d = "' + base64.b64encode(deflated[:1500]) + b'";',
             "raw-short.js": b'var d = "' + base64.b64encode(tiny) + b'";'}
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    errs = anon_check.check_site(tmp_path, TOKENS)
    # raw-inside.js is refused as well, and that is a cost this rule accepts: its
    # fixed-Huffman data holds a zlib header whose 128 bytes inflate as literals,
    # so the header proves itself and the rest fails. Round 10 hid that header
    # inside the unproven raw trial's span, and the same span hid a real gzip.
    # A failed weak trial now suppresses nothing, which fails closed here.
    assert [e for e in errs if CATCH not in e] == [
        "past.bin: cannot be fully scanned (truncated zlib stream)",
        "raw-inside.js > base64: holds a container the scan cannot expand (corrupt zlib stream)",
        "raw-past.js > base64: cannot be fully scanned (truncated deflate stream)"]
    assert sorted(e.split(":")[0] for e in errs if CATCH in e) == [
        "inside.bin > inflated fragment", "past.bin > zlib stream",
        "raw-inside.js > base64 > inflated fragment", "raw-past.js > base64 > deflate stream",
        "raw-short.js > base64 > inflated fragment"]


def test_a_weak_header_in_text_or_binary_is_no_stream(tmp_path: Path):
    # "(S", "8O", "HK", "XG", "hC" and "x^" are zlib headers, and followed by a
    # letter that opens a Huffman block they are candidates, as one position in a
    # few thousand of random binary is. None of them is a stream, and none is
    # refused. A quote, a comma and a ">" all start a payload, and the bytes after
    # them are no raw deflate either.
    prose = (b"(Sub HKey XGen hCert x^tt 8Oes " * 400
             + b'<p class="a">b, c = "d", e = \'f\'</p>' * 400)
    rng = random.Random(11)
    noise = bytes(rng.randrange(256) for _ in range(1 << 18))
    assert len(anon_check._ZLIB_HEAD.findall(noise)) > 40
    assert len(anon_check._ZLIB_HEAD.findall(prose)) > 500
    (tmp_path / "prose.html").write_bytes(prose)
    (tmp_path / "noise.bin").write_bytes(noise)
    assert anon_check.check_site(tmp_path, TOKENS) == []


def _probe_payload(fmt: str, rng: random.Random) -> bytes:
    # The round 9 review's generator: prose of about 1.5 KB with the name at a
    # random place, retried until the compressed bytes hold a backslash, an
    # ampersand and a percent sign, the three bytes a text decoder rewrites.
    words = ("the of and a to in is was for on with as by at from this that report "
             "study paper result method data model per cent & 100% back\\slash").split()
    for _ in range(5000):
        out: list[str] = []
        while sum(len(w) + 1 for w in out) < 1500:
            out.append(rng.choice(words))
        out.insert(rng.randrange(len(out)), "zz-secret-org")
        data = " ".join(out).encode()
        if fmt == "gzip":
            packed = gzip.compress(data, mtime=rng.randrange(1 << 31))
        elif fmt == "zlib":
            packed = zlib.compress(data, 9)
        elif fmt == "deflate-raw":
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            packed = c.compress(data) + c.flush()
        elif fmt == "bzip2":
            packed = bz2.compress(data)
        else:
            packed = lzma.compress(data)
        if all(b in packed for b in (b"\\", b"&", b"%")):
            return packed
    raise AssertionError("no payload holds all three bytes")


def test_the_fifty_payload_probe_reads_every_payload(tmp_path: Path):
    # The round 9 review's headline probe, reproduced: five compression formats,
    # five ways a build writes a binary into a page, two seeds each. Round 9
    # caught 22, refused 8 and passed 20 clean, every clean one zlib or raw
    # deflate. The target was zero clean; every one is caught.
    encodings = {
        "percent-all": lambda c: b'<img src="data:application/octet-stream,'
                                 + "".join(f"%{b:02X}" for b in c).encode() + b'">',
        "uri-component+attr": lambda c: ('<a href="data:application/gzip,' + html.escape(
            urllib.parse.quote(c, safe="-_.!~*'()")) + '">x</a>').encode(),
        "json-ascii": lambda c: ("<script>const blob = " + json.dumps(c.decode("latin-1"))
                                 + ";</script>").encode(),
        "js-hex": lambda c: ("<script>var b='" + "".join(
            chr(b) if chr(b).isalnum() or chr(b) in " .,-_" else f"\\x{b:02x}" for b in c)
            + "';</script>").encode(),
        "html-escape-raw": lambda c: b"<pre>" + html.escape(c.decode("latin-1")).encode(
            "latin-1") + b"</pre>",
    }
    names = []
    for fmt in ("gzip", "bzip2", "xz", "zlib", "deflate-raw"):
        for enc, encode in encodings.items():
            for seed in range(2):
                page = (b"<!doctype html><html><body><p>hello</p>"
                        + encode(_probe_payload(fmt, random.Random(f"{fmt}{enc}{seed}")))
                        + b"<p>bye</p></body></html>")
                assert b"zz-secret" not in page
                name = f"{fmt}-{enc}-{seed}.html"
                (tmp_path / name).write_bytes(page)
                names.append(name)
    caught = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert sorted({line.split(" > ")[0] for line in caught}) == sorted(names)


def _bomb(kind: str, zeros: bytes) -> bytes:
    # One bomb per decoder, each carrying the zeros where that decoder reads them.
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body))
    if kind == "gzip":
        return gzip.compress(zeros)
    if kind == "zlib":
        return zlib.compress(zeros)
    if kind == "deflate":
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(zeros) + c.flush()
    if kind == "xz":
        return lzma.compress(zeros)
    if kind == "bzip2":
        return bz2.compress(zeros)
    # zstd and brotli are written streamed, as a build writes a large asset: a
    # streamed frame hands its output out in pieces the one-shot form does not,
    # and the zstd reader first mistook one of those for a truncation.
    pieces = [zeros[i:i + (1 << 20)] for i in range(0, len(zeros), 1 << 20)]
    if kind == "zstd":
        writer = pytest.importorskip("compression.zstd").ZstdCompressor()
        return b"".join(map(writer.compress, pieces)) + writer.flush()
    if kind == "brotli":
        writer = brotli.Compressor(quality=5)
        return b"".join(map(writer.process, pieces)) + writer.finish()
    if kind == "zip":
        return _zip_deflated({"zeros.bin": zeros})
    if kind == "tar":
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode="w") as tf:
            info = tarfile.TarInfo("zeros.bin")
            info.size = len(zeros) // 2
            tf.addfile(info, io.BytesIO(zeros[:info.size]))
        return tar.getvalue()
    head = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    if kind == "png chunk":
        return head + chunk(b"zTXt", b"Author" + bytes(2) + zlib.compress(zeros)) + chunk(b"IEND", b"")
    if kind == "png image":
        return head + chunk(b"IDAT", zlib.compress(zeros)) + chunk(b"IEND", b"")
    if kind == "woff table":
        table = zlib.compress(zeros)
        return (struct.pack(">4sIIHHIHHIIIII", b"wOFF", 0x00010000, 64 + len(table), 1, 0, 0,
                            1, 0, 0, 0, 0, 0, 0)
                + struct.pack(">4sIIII", b"name", 64, len(table), len(zeros), 0) + table)
    if kind == "pdf stream":
        return _pdf_bytes([(b"FlateDecode", zlib.compress(zeros))])
    raise AssertionError(kind)


def _zip_deflated(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


BOMB_ROUTES = {"gzip": "gzip", "zlib": "zlib", "deflate": "deflate", "xz": "xz", "bzip2": "bzip2",
               "zstd": "zstd", "brotli": "brotli", "zip": "zip", "tar": "tar",
               "png chunk": "png", "png image": "png", "woff table": "woff", "pdf stream": "pdf"}


@pytest.mark.parametrize("route", sorted(BOMB_ROUTES))
def test_every_decoder_is_bounded_before_it_materializes(tmp_path: Path, route: str):
    # One test per bound, through the dispatcher itself. 32 MiB of zeros against a
    # 256 KiB budget: each decoder asks the sink for at most one piece past what is
    # left, so the refusal comes one piece past the budget, and a decoder whose
    # bound is removed materializes the whole 32 MiB before the sink sees any of
    # it. xz and zstd keep a window of their own, which tracemalloc sees as well.
    zeros = bytes(32 << 20)
    bomb = _bomb(route, zeros)
    del zeros
    scan = anon_check._SiteScan(TOKENS)
    started = time.monotonic()
    tracemalloc.start()
    try:
        res = anon_check._dispatch(BOMB_ROUTES[route], bomb, anon_check._Work(256 << 10),
                                   scan, ["bomb"])
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert res.refusal == anon_check._LIMIT, (route, res.refusal)
    assert peak < 12 << 20, f"{route} peak {peak >> 20} MiB"
    assert time.monotonic() - started < 20, route


def test_a_failed_stream_is_charged_and_never_read_again(tmp_path: Path):
    # The round 9 review's file: 5,000 gzip members of 64 KiB zeros, 480 KB on
    # disk. Every member after the first is a valid header, and round 9 charged a
    # stream only when it returned, so each one decompressed up to the whole
    # budget again: 84.6 s to refuse, at 2.6 GiB. Charged as produced and recorded
    # as read, it is refused once, well inside ten seconds.
    member = gzip.compress(bytes(64 << 10))
    (tmp_path / "many.gz").write_bytes(member * 5000)
    assert len(member) * 5000 < 500_000
    refusal = ["many.gz: cannot be fully scanned (expands past the scan size limit)"]
    # Timed without tracemalloc, which multiplies the run time about fivefold and made
    # the bound measure the tracer on a slow shared runner rather than the scan.
    started = time.monotonic()
    assert anon_check.check_site(tmp_path, TOKENS) == refusal
    assert time.monotonic() - started < 10
    tracemalloc.start()
    try:
        errs = anon_check.check_site(tmp_path, TOKENS)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert errs == refusal
    assert peak < 128 << 20, f"peak {peak >> 20} MiB"
    # And a stream that fails is charged for what it produced before failing.
    work = anon_check._Work(1 << 20)
    cut = gzip.compress(_words(6, 20000))
    res = anon_check._dispatch("gzip", cut[:len(cut) // 2], work)
    assert res.refusal == "truncated gzip stream"
    assert work.left == (1 << 20) - len(res.parts[0][1]) and work.left < (1 << 20) - 1000


# Default_Ignorable_Code_Point, DerivedCoreProperties.txt, Unicode 16.0.0: the
# published ranges, assigned and unassigned alike, written out because Python's
# unicodedata does not expose the property.
DEFAULT_IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
                     (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
                     (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
                     (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
                     (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF))


def test_every_default_ignorable_is_invisible(tmp_path: Path):
    # Round 9 derived the class from Cf and Cc, which cannot see an unassigned
    # default-ignorable: U+FFF0 to U+FFF8 draw nothing and take no advance in
    # Chrome 153, and a name written around one passed raw and as a reference.
    points = [cp for lo, hi in DEFAULT_IGNORABLE for cp in range(lo, hi + 1)]
    assert len(points) == 4174 and 0xFFF4 in points
    assert [f"U+{cp:04X}" for cp in points
            if not anon_check._INVISIBLE.fullmatch(chr(cp))] == []
    folded = anon_check._fold_tokens(["zzsecretperson"])
    for cp in range(0xFFF0, 0xFFF9):
        for form in (f"<p>zzsecret{chr(cp)}person</p>", f"<p>zzsecret&#x{cp:x};person</p>"):
            assert 0 in anon_check._blob_hits(form.encode("utf-8"), folded), (hex(cp), form)


def test_a_combining_mark_inside_a_name_is_folded_out(tmp_path: Path):
    # A combining mark takes no advance and draws on the letter before it, so a
    # name with a stroke through one letter reads as the name. Round 9 missed all
    # of Mn and Me. They are folded out of text and entries alike and never
    # refused, because most scripts are written with them.
    marks = [cp for cp in range(0x110000) if unicodedata.category(chr(cp)) in ("Mn", "Me")]
    assert len(marks) > 1700
    folded = anon_check._fold_tokens(["zzsecretperson"])
    missed = [f"U+{cp:04X}" for cp in marks
              if 0 not in anon_check._blob_hits(f"zzsecret{chr(cp)}person".encode("utf-8"), folded)
              or 0 not in anon_check._blob_hits(f"zzsecret&#x{cp:x};person".encode(), folded)]
    assert missed == []
    # One that composes with the letter before it is dropped before it can.
    assert 0 in anon_check._blob_hits("zzse\u0301cretperson".encode(), folded)
    # Marks are never a refusal, and text dense with them passes clean.
    (tmp_path / "vi.html").write_bytes("<p>Tie\u0302\u0301ng Vie\u0323\u0302t</p>".encode() * 200)
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_a_multi_part_entry_is_read_through_one_separator_between_whole_words(tmp_path: Path):
    # Carried from Task 12: "peopleco" written "people-co" must be caught, and "the
    # people could" must not be. A separator may sit between any two of the
    # entry's letters, and the run must start and end on a word boundary, where a
    # hyphen, an underscore or a dot running on into more of a word is no boundary.
    folded = anon_check._fold_tokens(["peopleco", "zz-secret-org"])
    must_catch = {"people-co": 0, "People Co.": 0, "people_co builds": 0, "PEOPLE.CO": 0,
                  "p.e.o.p.l.e.c.o": 0, "ocelpoep": 0, "(people co)": 0,
                  "zz_secret_org": 1, "zz secret.org": 1, "zzsecret-org": 1, "zz-secret-org": 1}
    must_pass = ["the people could", "people co-authored it", "people.company", "the_people_code",
                 "xpeople-co", "people-cox", "a.people-co", "peopl eco-nomics", "zz secret organ",
                 "fizz secret org"]
    for text, entry in must_catch.items():
        assert entry in anon_check._blob_hits(text.encode(), folded), text
    for text in must_pass:
        assert anon_check._blob_hits(text.encode(), folded) == {}, text


def test_a_payload_written_one_reference_per_byte_is_read(tmp_path: Path):
    # Round 9's Minor 3. "&#139;" is a gzip magic byte to a script that maps the
    # numbers itself, and a single right angle quote to the HTML spec, which
    # replaces 0x80 to 0x9F with windows-1252 punctuation. Read the spec's way only,
    # no magic survives, and gzip, xz, zlib and raw deflate written this way all
    # passed clean. The references step has a second answer, the byte, tried only
    # where such a reference is written.
    payloads = {"gzip": gzip.compress(_words(8, 300)), "xz": lzma.compress(_words(9, 300)),
                "zlib": zlib.compress(_words(10, 300), 9)}
    for name, packed in payloads.items():
        assert any(0x80 <= b <= 0x9F for b in packed), name
        (tmp_path / f"{name}-dec.html").write_bytes(
            b"<textarea>" + "".join(f"&#{b};" for b in packed).encode() + b"</textarea>")
        (tmp_path / f"{name}-hex.html").write_bytes(
            b'<div data-b="' + "".join(f"&#x{b:x};" for b in packed).encode() + b'"></div>')
    caught = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert sorted({line.split(" > ")[0] for line in caught}) == sorted(
        f"{name}-{form}.html" for name in payloads for form in ("dec", "hex"))
    # A page that writes the replaced references as text is read no differently.
    (tmp_path / "prose.html").write_bytes(b"<p>&#150; and &#x93;quoted&#x94; &#0;</p>" * 50)
    assert [e for e in anon_check.check_site(tmp_path, TOKENS) if e.startswith("prose")] == []


def test_a_container_at_a_displaced_base64_alignment_is_followed(tmp_path: Path):
    # Base64 letters just before a payload start its run early, so the payload's
    # own bytes come out of the second, third or fourth alignment. Round 9 read
    # only the first as a container and scanned the others for names alone, and a
    # gzip after "abc" was clean. An alignment that starts with a validated header
    # or a proven weak one is now followed like the first.
    payload = base64.b64encode(gzip.compress(b"notes by zz-secret-org " * 30)).decode()
    for k, prefix in enumerate(("", "a", "ab", "abc")):
        (tmp_path / f"s{k}.js").write_text(f"var tok={prefix}{payload};")
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        f"s{k}.js > base64 > gzip stream: contains a denylisted token "
        f"(#2 in .anon-tokens, raw view)" for k in range(4)]


def test_a_stored_block_proves_nothing(tmp_path: Path):
    # A stored deflate block checks its length with 16 bits and copies its body as
    # it stands. In 32 MiB of random bytes one zlib header in about a quarter
    # million met a stored length that checked, "inflated" 128 clean bytes of copy,
    # and the file was refused as holding a corrupt stream. What a stored block
    # holds is in the file as it stands, so it is no candidate, for zlib or raw.
    rng = random.Random(12)
    body = rng.randbytes(1500)
    stored = bytes([0]) + struct.pack("<HH", len(body), len(body) ^ 0xFFFF) + body + bytes([0xFF]) * 8
    zlib_head = next(p for p in anon_check._ZLIB_PAIRS if p[0] == 0x78)
    (tmp_path / "z.bin").write_bytes(b"prefix " + zlib_head + stored)
    (tmp_path / "r.js").write_bytes(b'var r = "' + stored)
    assert not anon_check._deflate_head(stored, 0)
    assert anon_check.check_site(tmp_path, TOKENS) == []
    # Each is a stream by every other measure: its trial reads its whole proof.
    trial = anon_check._dispatch("deflate", stored[:1024], anon_check._Work(1 << 16))
    assert trial.refusal == "truncated deflate stream"


def test_inflate_is_bounded_by_what_it_is_fed(tmp_path: Path):
    # Why removing max_length from _inflate changes nothing a test can see: it is
    # fed 64 bytes at a time, and deflate cannot expand a byte past 1,032, so no
    # call can hand the sink more than the 1 MiB piece the sink allows anyway.
    # This is that premise. Feed zlib more per call and the bomb tests lose it.
    assert anon_check._FEED * 1032 <= 1 << 20
    pieces: list[int] = []
    sink_add = anon_check._Sink.add

    def record(self, piece):
        pieces.append(len(piece))
        return sink_add(self, piece)
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(anon_check._Sink, "add", record)
        res = anon_check._dispatch("zlib", zlib.compress(bytes(8 << 20)), anon_check._Work(64 << 20))
    assert not res.refusal and max(pieces) <= anon_check._FEED * 1032


# Measured peaks with 16 MiB to spend, 1 MiB pieces: bzip2 19, xz 26 (its own
# 8 MiB window included), zstd 18 and brotli 18 MiB. A decoder handed room for
# the whole budget in one call holds the output twice, about 16 MiB more.
LARGE_BUDGET_PEAK = {"bzip2": 26, "xz": 34, "zstd": 26, "brotli": 26}


@pytest.mark.parametrize("kind", sorted(LARGE_BUDGET_PEAK))
def test_no_decoder_hands_the_sink_more_than_one_mebibyte(tmp_path: Path, kind: str):
    # With a large budget the sink's own cap is what bounds a piece, and a streamed
    # frame is what exercises the drain between pieces: zstd hands out a piece
    # exactly at the limit and asks for input on the next call, which a stall
    # guard once read as a truncation, so this bomb was refused for the wrong
    # reason with its first 3.6 MB scanned. The refusal is asserted by name.
    zeros = bytes(64 << 20)
    bomb = _bomb(kind, zeros)
    del zeros
    tracemalloc.start()
    try:
        res = anon_check._dispatch(kind, bomb, anon_check._Work(16 << 20))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert res.refusal == anon_check._LIMIT, res.refusal
    assert peak < LARGE_BUDGET_PEAK[kind] << 20, f"{kind} peak {peak >> 20} MiB"


def test_the_block_prefilter_turns_away_only_what_inflate_refuses(tmp_path: Path):
    # The pattern that finds weak candidates checks the first block's header
    # before any trial runs. Apart from a stored block, which it turns away on
    # purpose, everything it turns away inflate refuses at the first byte anyway,
    # so the check saves trials and hides nothing. Pinned byte by byte, so a
    # widened check shows up here rather than as a mutant no test can see.
    # The bytes are chosen by RFC 1951's rule, not read from the set under test,
    # so widening the set cannot shrink what is checked here.
    rng = random.Random(13)
    refused = [b for b in range(256) if b >> 1 & 3 == 3 or (b >> 1 & 3 == 2 and b >> 3 > 29)]
    assert len(refused) == 68
    assert not set(refused) & set(anon_check._HUFFMAN_OPENERS)
    for first in refused:
        for _ in range(8):
            trial = anon_check._dispatch("deflate", bytes([first]) + rng.randbytes(63),
                                         anon_check._Work(1 << 16))
            assert trial.refusal == "corrupt deflate stream" and not trial.parts, hex(first)


def test_a_payload_opens_in_text_and_not_in_binary(tmp_path: Path):
    # Raw deflate is tried after a delimiter only where eight bytes of text stand
    # before it, which is a bound on work: random binary holds a delimiter-valued
    # byte in every thirty-six, and each was a trial. What a page writes before a
    # payload is text.
    noise = random.Random(14).randbytes(1 << 20)
    assert len(list(anon_check._PAYLOAD_START.finditer(noise))) < 20
    opener = bytes([anon_check._HUFFMAN_OPENERS[0]])
    for page in (b'const b = "', b'<img src="data:x,', b"<pre>", b'{"b":"', b'"'):
        # Every place a payload could open counts, the "=" before a quote included.
        assert len(page) in [m.end() for m in anon_check._PAYLOAD_START.finditer(page + opener)]
    assert list(anon_check._PAYLOAD_START.finditer(bytes([0, 1]) + b'ab"' + opener)) == []


def test_a_stream_that_expands_past_one_piece_is_drained_not_cut(tmp_path: Path):
    # A small asset that expands far is read whole when it fits the budget. The
    # decoders are fed in 64-byte pieces and hand out at most one 1 MiB piece a
    # call, so the input runs out while output is still held back; brotli says
    # then that it can accept more input, and reading that as a truncation refused
    # a 56-byte .br asset that expands to 6 MiB. Brotli runs past its output
    # limit to the end of a block, so a small expansion comes out whole; this one
    # is large enough to be held back, which the fixture asserts, since a fixture
    # that stopped holding output back would pass this test for the wrong reason.
    text = b"// by zz-secret-org\n" + b"var x = 1;\n" * (300 << 10)
    zw = pytest.importorskip("compression.zstd").ZstdCompressor()
    assets = {"app.js.br": brotli.compress(text), "app.js.gz": gzip.compress(text),
              "app.js.xz": lzma.compress(text), "app.js.bz2": bz2.compress(text),
              "app.js.zst": zw.compress(text) + zw.flush(), "app.js.z": zlib.compress(text)}
    assert len(assets["app.js.br"]) < 100 and len(text) > 3 << 20
    held = brotli.Decompressor()
    held.process(assets["app.js.br"], output_buffer_limit=1 << 20)
    assert not held.is_finished() and held.can_accept_more_data()
    for name, data in assets.items():
        (tmp_path / name).write_bytes(data)
    # zstd keeps the opening literals raw, so its file is caught as it stands too.
    caught = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert sorted(line.split(":")[0] for line in caught if " > " in line) == sorted(
        f"{name} > {kind} stream" for name, kind in (
            ("app.js.br", "brotli"), ("app.js.gz", "gzip"), ("app.js.xz", "xz"),
            ("app.js.bz2", "bzip2"), ("app.js.zst", "zstd"), ("app.js.z", "zlib")))
    # And cut short, each of the two that drain between pieces is refused by name
    # rather than read as finished or left waiting for input that never comes.
    for name in list(assets):
        (tmp_path / name).unlink()
    big = b"// by zz-secret-org\n" + _words(15, 40000)
    zw = pytest.importorskip("compression.zstd").ZstdCompressor()
    for name, data in (("cut.js.br", brotli.compress(big)), ("cut.js.zst", zw.compress(big) + zw.flush())):
        (tmp_path / name).write_bytes(data[:len(data) // 2])
    assert [e for e in anon_check.check_site(tmp_path, TOKENS) if CATCH not in e] == [
        "cut.js.br: cannot be fully scanned (truncated brotli stream)",
        "cut.js.zst: cannot be fully scanned (truncated zstd stream)"]


def test_every_weak_candidate_pattern_opens_on_a_byte(tmp_path: Path):
    # A pattern that opens with a lookahead or a lookbehind gives the regex engine
    # no byte to scan for, so it runs the assertion at every position of every
    # reading. Both of these did, and 8 MiB of random bytes spent 30 s in them.
    # Pinned by structure rather than by a clock, because a clock on a shared
    # machine is noise: each must open on a byte or a class of bytes it consumes.
    for pattern in (anon_check._ZLIB_HEAD, anon_check._PAYLOAD_START):
        assert not pattern.pattern.startswith(b"(?"), pattern.pattern[:12]
    noise = random.Random(15).randbytes(1 << 20)
    assert len(list(anon_check._weak_heads(noise))) < 400


# ---------------------------------------------------------------------------
# Round 11: the round 10 review's two Criticals and three Importants.
# ---------------------------------------------------------------------------


def _fixed_then_stored(inner: bytes, lead: bytes) -> bytes:
    # A fixed-Huffman lead block, then one final stored block holding inner. The
    # lead makes the raw deflate stream a weak candidate that ends cleanly inside
    # its proof, so its trial is unproven with a clean span over inner.
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_FIXED)
    head = c.compress(lead) + c.flush(zlib.Z_FULL_FLUSH)
    return head + b"\x01" + struct.pack("<HH", len(inner), len(inner) ^ 0xFFFF) + inner


def test_a_strong_header_inside_an_unproven_raw_deflate_span_is_still_followed(tmp_path: Path):
    # Round 10's Critical 1. An unproven raw deflate trial that read 128 bytes
    # cleanly dropped every candidate inside them, strong kinds included, so a
    # well-formed gzip member lying in the file's own bytes came back clean for
    # the review's seeds 5 and 32. A failed weak trial now suppresses nothing.
    for seed in (5, 32):
        rng = random.Random(seed)
        text = (b"notes filed by zz-secret-org for the record "
                + bytes(rng.choice(b"abcdefgh ") for _ in range(20)))
        member = gzip.compress(text, mtime=rng.randrange(1 << 31))
        lead = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz ") for _ in range(300))
        stream = _fixed_then_stored(member, lead)
        for wrap, page in (("bare", b'var data = "' + stream),
                           ("html", b'<html><body><script>var data = "' + stream
                            + b'";</script></body></html>')):
            assert b"zz-secret" not in page
            (tmp_path / f"s{seed}-{wrap}.bin").write_bytes(page)
    errs = anon_check.check_site(tmp_path, TOKENS)
    for seed in (5, 32):
        for wrap in ("bare", "html"):
            name = f"s{seed}-{wrap}.bin"
            assert any(e.startswith(name) and "gzip stream: " + CATCH in e for e in errs), (name, errs)


def test_a_short_raw_deflate_payload_is_followed_for_what_it_holds(tmp_path: Path):
    # Round 10's Important 1. What an unproven raw deflate trial inflated was
    # read for names only, so raw deflate around a small gzip, which is what
    # DecompressionStream("deflate-raw") reads from a .gz asset, and raw deflate
    # around a base64 payload, both came back clean. Read as a file of its own.
    text = b"notes filed by zz-secret-org for the record, nothing more here"

    def raw(data: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()
    files = {"raw-gzip.js": raw(gzip.compress(text, mtime=0)),
             "raw-base64.js": raw(b"payload " + base64.b64encode(text))}
    for name, stream in files.items():
        page = b'var d = "' + base64.b64encode(stream) + b'";'
        assert b"zz-secret" not in page
        (tmp_path / name).write_bytes(page)
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "raw-base64.js > base64 > inflated fragment > base64: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)",
        "raw-gzip.js > base64 > inflated fragment > gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def _inflating_heads(count: int) -> bytes:
    # The review's file: 128-byte chunks, each a zlib header and the start of
    # 60,000 zeros under a sync flush, padded with 0xFF. Each chunk's trial
    # inflates about 48 KiB before it fails inside its proof.
    c = zlib.compressobj(9, zlib.DEFLATED, 15, 9)
    stream = c.compress(bytes(60000)) + c.flush(zlib.Z_SYNC_FLUSH)
    return (stream + b"\xff" * 128)[:128] * count


def test_every_trial_byte_is_charged_to_the_file(tmp_path: Path):
    # Round 10's Important 2. Trials ran on a budget of their own and their
    # output piled up uncharged, so this file at 512 KiB peaked at 8.0 GiB and
    # came back clean. Every byte a trial inflates is charged to the file now, and
    # a file the budget cannot pay for is refused.
    trials, queue = {}, []
    work = anon_check._Work(1 << 20)
    assert not anon_check._proven("zlib", _inflating_heads(1), 0, trials, work, queue)
    [(_, inflated)] = queue
    assert len(inflated) > 40_000
    assert work.left == (1 << 20) - len(inflated)
    (tmp_path / "r.bin").write_bytes(_inflating_heads(1024))
    started = time.monotonic()
    tracemalloc.start()
    try:
        errs = anon_check.check_site(tmp_path, TOKENS)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert errs == ["r.bin: cannot be fully scanned (expands past the scan size limit)"]
    # Round 10: 18.6 s and 3.4 GiB for this 128 KiB file. The budget is 32 MiB of
    # output, and the residue it paid for is dropped once the budget is gone.
    assert peak < 96 << 20, f"peak {peak >> 20} MiB"
    assert time.monotonic() - started < 20


def _early_damage(at: int, width: int) -> tuple[bytes, bytes]:
    real = zlib.compress(_words(21, 600, at=0.9), 9)
    damaged = bytearray(real)
    for i in range(at, at + width):
        damaged[i] ^= 0xFF
    return bytes(damaged), real


def test_the_trial_cache_keys_on_the_whole_first_piece(tmp_path: Path):
    # Round 10's Important 3, first half. A failed trial is cached by kind and its
    # first 64-byte piece, the only bytes its answer depended on. Keyed on fewer,
    # a stream damaged inside its first piece stands in for a real one that shares
    # the shorter key, and the real one is never tried: the review's mutant keyed
    # on 32 bytes, and this file came back clean.
    damaged, real = _early_damage(40, 8)
    assert damaged[:32] == real[:32] and damaged[:64] != real[:64]
    (tmp_path / "early-damage.bin").write_bytes(damaged + b"\n" + real)
    assert b"zz-secret" not in (tmp_path / "early-damage.bin").read_bytes()
    assert any(e.startswith("early-damage.bin > embedded zlib stream: " + CATCH)
               for e in anon_check.check_site(tmp_path, TOKENS))


def test_the_trial_cache_holds_only_a_failure_in_the_first_piece(tmp_path: Path):
    # The second half. A failure is cached only when the first piece itself
    # raised: then the answer depends on those 64 bytes and nothing else. A trial
    # that read its first piece cleanly, even with no output, failed on later
    # bytes, and a real stream that shares the first piece must still be tried.
    # This stream's dynamic code tables run past byte 64, so its first piece
    # inflates to nothing, and damage at byte 64 fails the next piece.
    rng = random.Random(0)
    weights = [rng.random() ** 3 for _ in range(256)]
    real = zlib.compress(bytes(rng.choices(bytes(range(256)), weights, k=6000))
                         + b" filed by zz-secret-org", 9)
    assert zlib.decompressobj().decompress(real[:64]) == b""
    damaged = bytearray(real)
    damaged[64] ^= 0xFF
    trial = anon_check._dispatch("zlib", bytes(damaged[:128]), anon_check._Work(1 << 16))
    assert trial.refusal == "corrupt zlib stream" and not trial.parts
    assert trial.extents[0][1] == 64
    trials = {}
    anon_check._proven("zlib", bytes(damaged), 0, trials, anon_check._Work(1 << 20), [])
    assert trials == {}
    (tmp_path / "late-damage.bin").write_bytes(bytes(damaged) + b"\n" + real)
    assert b"zz-secret" not in (tmp_path / "late-damage.bin").read_bytes()
    assert any(e.startswith("late-damage.bin > embedded zlib stream: " + CATCH)
               for e in anon_check.check_site(tmp_path, TOKENS))


def test_a_zlib_window_and_a_deflate_window_never_share_a_first_byte(tmp_path: Path):
    # Why the cache key's kind is redundant today: no zlib CMF byte opens a
    # Huffman block, so the two kinds' first pieces never collide. The kind stays
    # in the key; this pins the premise that makes dropping it harmless now.
    assert not set(range(0x08, 0x80, 0x10)) & set(anon_check._HUFFMAN_OPENERS)


def test_a_multi_word_entry_is_found_glued_into_a_handle(tmp_path: Path):
    # Round 10's Critical 2, a regression. The separator rule was tried first and
    # the space-closed match only when it had no patterns, which is never for a
    # multi-word entry, so every handle below was missed at c274684 and caught at
    # 9b4acf6. No test had pinned the glued shape, which is how it was lost. Both
    # rules run now, each where the other does not reach.
    tokens = ["zz secret person"]
    must_catch = {
        "url.html": '<a href="https://github.com/zzsecretperson42">repo</a>',
        "handle.html": "<p>@zzsecretperson_dev</p>",
        "suffix.html": "<p>zzsecret personal</p>",
        "prefix.html": "<p>xzz secretperson</p>",
        "spaced.html": "<p>by zz secret person here</p>",
        "hyphens.html": "<p>by zz-secret-person here</p>",
        "zero-width.html": "<p>by zz\u2003\u200b secret person here</p>",
        "control.html": "<p>by zz\u0001 secret person here</p>",
    }
    # The English a separator rule must not reach for a one-word entry, and ink
    # that is not the name for a multi-word one.
    must_pass = {"people.html": ("peopleco", "<p>the people could</p>"),
                 "coauthor.html": ("peopleco", "<p>people co-authored it</p>"),
                 "ellipsis.html": ("zz first last", "<p>zz first&#133;&#133;last</p>")}
    for name, page in must_catch.items():
        (tmp_path / name).write_text(page, encoding="utf-8")
    assert sorted(e.split(":")[0] for e in assert_caught(anon_check.check_site(tmp_path, tokens))) \
        == sorted(must_catch)
    for name in must_catch:
        (tmp_path / name).unlink()
    for name, (entry, page) in must_pass.items():
        (tmp_path / name).write_text(page, encoding="utf-8")
        assert anon_check.check_site(tmp_path, [entry]) == [], name
        (tmp_path / name).unlink()


def test_a_pdf_filter_is_read_through_escapes_and_references(tmp_path: Path):
    # Round 10's Minor 2. "/Fil#74er" is "/Filter", and "/Filter 9 0 R" names the
    # filter in another object. Both were read as plain bytes and caught only by
    # the zlib path, so damage in the first 128 bytes was never refused. A filter
    # the scan cannot resolve is refused.
    body = zlib.compress(_words(22, 400), 9)
    cut = body[:60]
    nl = bytes([10])

    def pdf(dictionary: bytes, data: bytes, extra: bytes = b"") -> bytes:
        return nl.join([b"%PDF-" + b"1.7", b"1 0 obj", dictionary, b"stream", data,
                        b"endstream", b"endobj", extra, b"%%EOF"]) + nl
    files = {"escaped.pdf": pdf(b"<< /Fil#74er /FlateDecode >>", cut),
             "indirect.pdf": pdf(b"<< /Filter 9 0 R >>", cut, b"9 0 obj /FlateDecode endobj"),
             "array.pdf": pdf(b"<< /Filter 9 0 R >>", cut, b"9 0 obj [/FlateDecode] endobj"),
             "dangling.pdf": pdf(b"<< /Filter 9 0 R >>", cut),
             "picture.pdf": pdf(b"<< /Filter 9 0 R >>", bytes(range(256)), b"9 0 obj /DCTDecode endobj")}
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "array.pdf: cannot be fully scanned (truncated zlib stream)",
        "dangling.pdf: cannot be fully scanned (a pdf stream filter the scan cannot read)",
        "escaped.pdf: cannot be fully scanned (truncated zlib stream)",
        "indirect.pdf: cannot be fully scanned (truncated zlib stream)"]


def test_an_exhausted_budget_decodes_nothing_more(tmp_path: Path, monkeypatch):
    # Round 10's Minor 1, first half. Once the budget is gone no decoder runs at
    # all. Without the check a decoder still refuses at its first piece, so only
    # the work tells the two apart, and that is what is counted here.
    calls: list[int] = []
    real = anon_check._CODECS["gzip"]
    monkeypatch.setitem(anon_check._CODECS, "gzip", lambda *a: calls.append(1) or real(*a))
    work = anon_check._Work(10)
    assert not work.spend(11) and work.exhausted
    res = anon_check._dispatch("gzip", gzip.compress(b"x" * 1000), work)
    assert res.refusal == anon_check._LIMIT and calls == []


def test_a_failed_decode_is_not_repeated_in_another_reading(tmp_path: Path, monkeypatch):
    # The second half. A failure is keyed on every byte the decoder was fed, so a
    # reading that holds the same bytes at the same place does not decompress
    # them again. The "&amp;" makes a second reading that copies the damaged
    # stream unchanged.
    payload = gzip.compress(_words(23, 2000), mtime=0)
    damaged = payload[:300] + bytes([payload[300] ^ 0xFF]) + payload[301:]
    (tmp_path / "p.html").write_bytes(b"<p>a &amp; b</p>" + damaged)
    # Readings that rewrite a byte inside the stream feed it different bytes and
    # are tried again, rightly. What must never happen is two calls fed the same.
    fed: list[bytes] = []
    real = anon_check._CODECS["gzip"]

    def recording(data, start, sink):
        try:
            return real(data, start, sink)
        finally:
            fed.append(bytes(data[start:sink.fed]))
    monkeypatch.setitem(anon_check._CODECS, "gzip", recording)
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert "p.html: holds a container the scan cannot expand (corrupt gzip stream)" in errs
    assert len(fed) >= 2 and len(set(fed)) == len(fed), [len(f) for f in fed]


def test_a_multi_word_entry_is_read_through_one_joining_separator(tmp_path: Path):
    # Controller ruling after round 11: the parts of a multi-word entry may be
    # joined by one ".", "-" or "_" with at most one optional space on each side.
    # An ellipsis is no join: U+2026, "..." and any run of two or more separator
    # characters, so round 7's ruling on "zz first...last" stands.
    tokens = ["zz secret person"]
    must_catch = {"dot-space.html": "<p>by zz. secret person</p>",
                  "spaced-hyphen.html": "<p>by zz - secret person</p>",
                  "handle.html": "<p>@zz_secretperson1</p>",
                  "mixed.html": "<p>zz.secret-person</p>",
                  "reversed.html": "<p>\u202enosrep-terces .zz\u202c</p>",
                  # Reversed with no marker, as a CSS direction rule lays it out:
                  # only the entry matched backwards reaches it.
                  "unmarked.html": "<p>nosrep-terces .zz</p>"}
    must_pass = {"ellipsis.html": "<p>zz secret…person</p>",
                 "dots.html": "<p>zz secret...person</p>",
                 "two-dots.html": "<p>zz secret..person</p>",
                 "two-kinds.html": "<p>zz secret-_person</p>",
                 "spaced-run.html": "<p>zz secret . . person</p>",
                 "double-hyphen.html": "<p>zz secret -- person</p>",
                 "entity-ellipsis.html": "<p>zz secret&#133;person</p>",
                 "english.html": "<p>the zz secretary; person of interest</p>",
                 # Punctuation that is not one of the three separators is no join.
                 "comma.html": "<p>zz secret, person</p>",
                 "slash.html": "<p>zz secret/person</p>",
                 "semicolon.html": "<p>zz secret; person</p>",
                 # The rule runs only where the entry's letters appear together once
                 # the separators are squeezed out. A run of two dots inside a part
                 # supplies them here, so a comma between parts elsewhere in the same
                 # text reaches the rule, and must still not count as a join.
                 "comma-and-run.html": "<p>zz,secret person and zzsec..retperson</p>"}
    for name, page in {**must_catch, **must_pass}.items():
        (tmp_path / name).write_text(page, encoding="utf-8")
    found = assert_caught(anon_check.check_site(tmp_path, tokens))
    assert sorted({line.split(":")[0] for line in found}) == sorted(must_catch)
    # "At most one optional space" is read after the fold, which collapses every
    # whitespace run to one space, as a browser does in rendered text. So a run of
    # spaces around the separator is one space to the rule, and a pattern that
    # allowed any number of spaces could only change which view reports it.
    assert anon_check._fold("zz   -\t\n  secret person") == "zz - secret person"


# ---------------------------------------------------------------------------
# Round 12: decoded output cannot be dropped, capped trials are charged, and the
# depth-limit refusal of residue is pinned.
# ---------------------------------------------------------------------------


def _enqueue_problems(source: str) -> list[str]:
    """Every call to _dispatch that is not the direct second argument of a call
    to _enqueue: a bare call, a result assigned and read, or a result used only
    in a test. Each of those can drop decoded output on the floor."""
    tree = ast.parse(source)
    wrapped = {id(node.args[1]) for node in ast.walk(tree)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == "_enqueue" and len(node.args) >= 2}
    return [f"{node.lineno}: _dispatch outside _enqueue" for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "_dispatch" and id(node) not in wrapped]


def test_every_decode_hands_its_output_to_the_one_queue(tmp_path: Path):
    # Round 9 dropped a damaged PDF stream's output, round 10 read a failed
    # trial's output for names only, round 11 threw a shifted alignment's trial
    # output away: the same class in three new places. Closed by construction.
    # Every call to the dispatcher is the direct argument of _enqueue, which moves
    # every part into a queue that is scanned for names and followed as a
    # container, and the dispatcher is the only way anything is decoded.
    source = SCANNER.read_text(encoding="utf-8")
    assert _enqueue_problems(source) == []
    assert source.count("_dispatch(") >= 6
    shapes = {
        "_enqueue(q, _dispatch(k, d, w))\n": False,
        "r = _enqueue(q, _dispatch(k, d, w), prefix='x')\n": False,
        "_dispatch(k, d, w)\n": True,
        "r = _dispatch(k, d, w)\nif r.parts: pass\n": True,
        "ok = bool(_dispatch(k, d, w).parts)\n": True,
        "_enqueue(q, f(_dispatch(k, d, w)))\n": True,
        "_enqueue(_dispatch(k, d, w), q)\n": True,
    }
    for shape, flagged in shapes.items():
        assert bool(_enqueue_problems(shape)) is flagged, shape
    # _enqueue itself leaves nothing behind in the result it hands back.
    res = anon_check._Result()
    res.parts = [("gzip stream", b"a"), ("gzip stream", b"b")]
    queue: list[tuple[str, bytes]] = []
    assert anon_check._enqueue(queue, res, prefix="embedded ").parts == []
    assert queue == [("embedded gzip stream", b"a"), ("embedded gzip stream", b"b")]


def test_a_short_raw_deflate_payload_at_a_displaced_alignment_is_read(tmp_path: Path):
    # Round 11's Critical 1, the review's six files. Base64 letters before the
    # payload shift its run, and the shifted alignment was followed only when a
    # trial proved a container there. A short raw deflate payload never proves
    # itself, so its trial output was charged and dropped. Every alignment is
    # now read whole.
    text = b"notes filed by zz-secret-org for the record, nothing more here"

    def raw(data: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()
    payloads = {"raw": raw(text), "rawgz": raw(gzip.compress(text, mtime=0))}
    for name, stream in payloads.items():
        for prefix in ("k", "ke", "key"):
            page = b'var d = "' + prefix.encode() + base64.b64encode(stream) + b'";'
            assert b"zz-secret" not in page
            (tmp_path / f"{name}-{prefix}.js").write_bytes(page)
    found = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert sorted({line.split(" > ")[0] for line in found}) == sorted(
        f"{name}-{prefix}.js" for name in payloads for prefix in ("k", "ke", "key"))


def _gzip_from(text: bytes, os_byte: int) -> bytes:
    # gzip.compress writes 255 as the OS byte on 3.10 and 3.13 on, and zlib's own
    # code on 3.11 and 3.12: 3 on Linux, 19 on macOS. The byte changes the deflate
    # stream around it, and with it which readings of that stream a layer damages.
    packed = bytearray(gzip.compress(text, mtime=0))
    packed[9] = os_byte
    return bytes(packed)


@pytest.mark.parametrize("os_byte", [3, 19, 255])
def test_raw_deflate_around_a_gzip_is_read_whole_whatever_its_os_byte(tmp_path: Path, os_byte: int):
    # Round 13's review found two tests red on 3.12 only: the payload was caught,
    # and beside the catch the file was refused as a corrupt gzip. The UTF-8
    # reading of the raw deflate rewrote bytes inside it, the trial there inflated
    # the gzip's valid header and a damaged body, and that piece, read as a file of
    # its own, was refused. The raw reading had read the same gzip whole at the
    # same offset. Clean pages were refused the same way, about a third of them.
    def raw(data: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()
    for seed in range(12):
        clean = _words(seed, 12, token=None)
        (tmp_path / f"clean-{seed}.js").write_bytes(
            b'var d = "' + base64.b64encode(raw(_gzip_from(clean, os_byte))) + b'";')
        (tmp_path / f"clean-{seed}.bin").write_bytes(raw(_gzip_from(clean, os_byte)))
    assert anon_check.check_site(tmp_path, TOKENS) == []
    text = b"notes filed by zz-secret-org for the record, nothing more here"
    (tmp_path / "secret.js").write_bytes(
        b'var d = "k' + base64.b64encode(raw(_gzip_from(text, os_byte))) + b'";')
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS)) == [
        "secret.js > base64 > inflated fragment > gzip stream: contains a denylisted token "
        "(#2 in .anon-tokens, raw view)"]


def test_a_misread_piece_is_matched_to_its_sibling_by_file_offset(tmp_path: Path):
    # One UTF-8 character before a payload start moves the payload one byte
    # earlier in every reading with the UTF-8 layer, and that layer is the one
    # that damages the stream. Pieces are matched by the file offset their trial
    # started at, not by where it sits in its reading.
    def raw(data: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()
    for seed in range(24):
        (tmp_path / f"s{seed}.js").write_bytes(
            "\u00e9".encode() + b' var text = "' + raw(_gzip_from(_words(seed, 12, token=None), 3)))
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_a_corrupt_gzip_in_a_trial_piece_is_refused_when_no_reading_reads_it_whole(tmp_path: Path):
    # The rule that drops a misreading's refusal needs a sibling that read the
    # stream whole. A gzip damaged in the file itself is damaged in every reading.
    # Fixed Huffman codes, so the gzip's magic is not in the file as it stands.
    packed = bytearray(_gzip_from(_words(4, 12, token=None), 255))
    packed[len(packed) // 2] ^= 0xFF
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_FIXED)
    (tmp_path / "bad.bin").write_bytes(c.compress(bytes(packed)) + c.flush())
    assert b"\x1f\x8b" not in (tmp_path / "bad.bin").read_bytes()
    # Two readings, each failing in its own place, and neither read it whole.
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert "bad.bin > inflated fragment: cannot be fully scanned (corrupt gzip stream)" in errs
    assert all(e.startswith("bad.bin > inflated fragment: cannot be fully scanned (") for e in errs)


def test_a_clean_piece_settles_only_its_own_offset(tmp_path: Path):
    # Two trials in one page: a clean gzip after one delimiter, and a gzip damaged
    # in the file itself after the next. The clean piece is no sibling of the
    # damaged one, so the damaged one is still refused.
    def raw(data: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_FIXED)
        return c.compress(data) + c.flush()
    damaged = bytearray(_gzip_from(_words(4, 12, token=None), 255))
    damaged[len(damaged) // 2] ^= 0xFF
    page = (b'var a = "' + raw(_gzip_from(_words(5, 12, token=None), 255))
            + b'"; var bb = "' + raw(bytes(damaged)) + b'";')
    assert b"\x1f\x8b" not in page
    (tmp_path / "two.js").write_bytes(page)
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert "two.js > inflated fragment: cannot be fully scanned (corrupt gzip stream)" in errs, errs


def test_only_a_misread_stream_refusal_is_dropped_and_only_beside_a_clean_sibling():
    # settle_misreadings on lines set by hand: which pieces share a trial's
    # offset, which one drained clean, and which of a sibling's lines may go.
    scan = anon_check._SiteScan(TOKENS)
    frag = "f.bin > inflated fragment"
    catch = f"{frag} > gzip stream: {CATCH} (#2 in .anon-tokens, raw view)"
    corrupt = f"{frag}: cannot be fully scanned (corrupt gzip stream)"
    cut = f"{frag}: holds a container the scan cannot expand (truncated xz stream)"
    unread = f"{frag}: cannot be fully scanned (zstd needs Python 3.14 or later)"
    malformed = f"{frag}: cannot be fully scanned (malformed png)"
    # A chain may spell a catch. The reason at the end of the line is what counts.
    spelled = f"f.bin > x: {CATCH} (#1 in .anon-tokens, raw view) > y: {corrupt.split(': ')[1]}"
    lines = {b"a": [catch], b"b": [corrupt, cut, unread, malformed], b"c": [corrupt + " "],
             b"d": [corrupt.replace("f.bin", "g.bin")], b"e": [spelled],
             b"f": [corrupt.replace("f.bin", "h.bin")]}
    residue = [("deflate stream", k) for k in (b"a", b"b", b"c", b"d", b"d", b"e", b"f")]
    anchors = [0, 0, 40, 0, 40, 80, 80]
    spans = {}
    for key, text in lines.items():
        spans[anon_check._digest(key)] = (len(scan.errs), len(scan.errs) + len(text))
        scan.errs += text
    before = list(scan.errs)
    anon_check._SiteScan.settle_misreadings(scan, residue, anchors, spans, anon_check._Work(1))
    # Offset 0 has a clean sibling, so b loses its two codec refusals and keeps the
    # two that leave bytes unread. c is alone at 40, d sits at 40 as well, and at
    # 80 the only piece with no problem line is a spelled catch, which is none.
    assert scan.errs == [catch, unread, malformed, corrupt + " ", lines[b"d"][0], spelled,
                         lines[b"f"][0]]
    spent = anon_check._Work(1)
    spent.spend(2)
    scan.errs = list(before)
    anon_check._SiteScan.settle_misreadings(scan, residue, anchors, spans, spent)
    assert scan.errs == before


def test_raw_deflate_inside_raw_deflate_is_read_at_every_piece(tmp_path: Path):
    # Each piece an unproven trial inflates is read as a file of its own, so raw
    # deflate at its head is tried wherever the piece sits among the others. The
    # review's probe put a benign payload first so the secret's piece was not at
    # the head of one joined fragment.
    def raw(data: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_FIXED)
        return c.compress(data) + c.flush()
    benign = b"a harmless sentence about the weather and nothing else at all"
    text = b"notes filed by zz-secret-org for the record, nothing more here"
    pages = {"one.js": b'var d = "' + base64.b64encode(raw(raw(text))) + b'";',
             "two.js": b'var a = "' + base64.b64encode(raw(raw(benign))) + b'";\nvar b = "'
                       + base64.b64encode(raw(raw(text))) + b'";'}
    for name, page in pages.items():
        assert b"zz-secret" not in page
        (tmp_path / name).write_bytes(page)
    found = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert sorted({line.split(" > ")[0] for line in found}) == ["one.js", "two.js"]


def test_a_trial_that_reaches_its_cap_is_charged_the_cap(tmp_path: Path):
    # Round 11's Important 1. A trial the cap stopped kept no output, and it was
    # charged the length of what it kept: nothing. Charged what it spent now.
    head = zlib.compress(bytes(4 << 20), 9)[:128]
    work = anon_check._Work(1 << 20)
    assert anon_check._proven("zlib", head, 0, {}, work, [])
    assert work.left == (1 << 20) - anon_check._TRIAL_OUTPUT
    # The review's file of such heads spends the file's budget on trials alone.
    work = anon_check._Work(anon_check.SITE_MAX_EXPANDED)
    anon_check._candidates(head * 1024, False, {}, [], work)
    assert work.exhausted


def test_residue_at_the_depth_limit_is_refused(tmp_path: Path):
    # Round 11's Important 2. Eight levels of base64 over a short raw deflate
    # payload put the trial's residue at the depth limit, where it is refused.
    # Dropped there, the file came back clean.
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = c.compress(b"notes filed by zz-secret-org for the record, nothing more here") + c.flush()
    for _ in range(8):
        stream = base64.b64encode(stream)
    (tmp_path / "nest8.js").write_bytes(b'var d = "' + stream + b'";')
    errs = anon_check.check_site(tmp_path, TOKENS)
    assert errs and all(e.endswith("nesting exceeds the scan depth limit") for e in errs), errs


# A run of one digit is a fixed-Huffman block to raw deflate, and it inflates to
# itself less one byte, and so on down, each level a substring of the one above.
# A tree file held one such piece in its garbage residue.
_SELF_PEELING = b"2" * 200


def test_a_trial_that_only_copies_what_it_read_ends(tmp_path: Path):
    # Output that is a copy of bytes its trial read, in the file's own bytes,
    # holds no name and no container this file does not already hold at the same
    # place, so it is not read again. Read again, this piece peeled one byte per
    # level to the depth limit and its file was refused.
    queue: list[tuple[str, bytes]] = []
    anon_check._proven("deflate", _SELF_PEELING, 0, {}, anon_check._Work(1 << 20), queue, raw=False)
    [(_, peeled)] = queue
    assert peeled in _SELF_PEELING and peeled != _SELF_PEELING
    queue.clear()
    anon_check._proven("deflate", _SELF_PEELING, 0, {}, anon_check._Work(1 << 20), queue, raw=True)
    assert queue == []
    (tmp_path / "peel.bin").write_bytes(_SELF_PEELING)
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_derived_output_is_a_container_at_its_head_only_where_it_validates(tmp_path: Path):
    # An unproven trial's output and a shifted base64 alignment are output no
    # format declared. Thousands of short garbage pieces made one that opened with
    # the two bytes of gzip magic, refused as a corrupt gzip. At the head of such
    # output the header must validate, as it must past offset zero anywhere. A
    # file's own head still needs only the magic, which is what refuses a cut font.
    rng = random.Random(16)
    garbage = b"\x1f\x8b" + bytes([0x00, 0xE0]) + rng.randbytes(40)
    assert not anon_check._valid_container(garbage, 0, "gzip")
    assert anon_check._candidates(garbage, False, {}, [], anon_check._Work(1 << 20)) == [(0, "gzip")]
    assert anon_check._candidates(garbage, False, {}, [], anon_check._Work(1 << 20),
                                  derived=True) == []
    real = gzip.compress(b"x" * 50)
    assert (0, "gzip") in anon_check._candidates(real, False, {}, [], anon_check._Work(1 << 20),
                                                 derived=True)


def test_no_trial_runs_and_no_residue_is_read_after_the_budget_is_gone(tmp_path: Path, monkeypatch):
    # Round 11's Minor 3: two cost-only guards. Once the budget is gone no trial
    # runs, and the residue it paid for is not read.
    calls: list[int] = []
    real_proven = anon_check._proven
    monkeypatch.setattr(anon_check, "_proven", lambda *a, **k: calls.append(1) or real_proven(*a, **k))
    work = anon_check._Work(10)
    work.spend(11)
    anon_check._candidates(_inflating_heads(4), False, {}, [], work)
    assert calls == []
    monkeypatch.setattr(anon_check, "_proven", real_proven)
    reads: list[list[str]] = []
    real_drain = anon_check._SiteScan.drain
    monkeypatch.setattr(anon_check._SiteScan, "drain",
                        lambda self, chain, queue, *a, **k: reads.append([l for l, _ in queue])
                        or real_drain(self, chain, queue, *a, **k))
    (tmp_path / "r.bin").write_bytes(_inflating_heads(1024))
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "r.bin: cannot be fully scanned (expands past the scan size limit)"]
    assert not any("inflated fragment" in labels for labels in reads)


def test_the_last_definition_of_a_referenced_filter_wins(tmp_path: Path):
    # Round 11's Minor 4. Under an incremental update the last definition of an
    # object is the one a reader uses (ISO 32000-1 7.5.6).
    nl = bytes([10])
    cut = zlib.compress(_words(24, 400), 9)[:60]
    pdf = nl.join([b"%PDF-" + b"1.7", b"9 0 obj /DCTDecode endobj", b"1 0 obj",
                   b"<< /Filter 9 0 R >>", b"stream", cut, b"endstream", b"endobj",
                   b"9 0 obj /FlateDecode endobj", b"%%EOF"]) + nl
    (tmp_path / "update.pdf").write_bytes(pdf)
    assert anon_check.check_site(tmp_path, TOKENS) == [
        "update.pdf: cannot be fully scanned (truncated zlib stream)"]


def test_an_inflated_piece_opening_with_magic_is_no_container_unless_it_validates(tmp_path: Path):
    # The same rule end to end: an unproven raw deflate trial inflates a piece
    # that opens with the two bytes of gzip magic and a header no gzip writes.
    # Read as a file of its own, it is derived output, so its head must validate,
    # and the page is clean. Taken from magic alone it was refused as corrupt.
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    piece = b"\x1f\x8b\x00\xe0 a harmless sentence about the weather and nothing else"
    stream = c.compress(piece) + c.flush()
    (tmp_path / "magic.js").write_bytes(b'var d = "' + base64.b64encode(stream) + b'";')
    assert anon_check.check_site(tmp_path, TOKENS) == []


def test_identical_decoded_content_is_read_once(tmp_path: Path, monkeypatch):
    # Two members with the same bytes are the same content: read once, not twice.
    # Cost only, since each finding's line is kept once either way.
    reads: list[bytes] = []
    real_blob = anon_check._SiteScan.blob
    monkeypatch.setattr(anon_check._SiteScan, "blob",
                        lambda self, chain, blob, *a, **k: reads.append(blob)
                        or real_blob(self, chain, blob, *a, **k))
    same = b"<.> " * 300
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", same)
        zf.writestr("b.txt", same)
    (tmp_path / "two.zip").write_bytes(buf.getvalue())
    assert anon_check.check_site(tmp_path, TOKENS) == []
    assert reads.count(same) == 1


# ---------------------------------------------------------------------------
# Round 13: decoders reachable only through the dispatcher, every queue one the
# scan drains, and a payload witness for every site the dispatcher decodes.
# ---------------------------------------------------------------------------

_TABLES = ("_CODECS", "_STRUCTURES")
_SHARED_DECODERS = ("_inflate", "_unpack")
# The two documented releases in _proven, each "del queue[before:]".
_RELEASES = 2


def _flow_problems(source: str) -> list[str]:
    """Every way decoded output could leave the flow from decoder to drain.

    1. A dispatched decoder, or the table holding it, named anywhere but in the
       table definitions and _dispatch: no direct call, alias, lambda or value.
       The shared helpers only inside the decoders.
    2. _dispatch named anywhere but as the called function of a call that is
       _enqueue's second argument.
    3. _enqueue called lazily (in a lambda, a comprehension or a generator), or
       given a queue that is not the scan's: it must be the enclosing structure's
       res.parts, a local list the same function passes to self.drain, or a
       parameter every caller fills with such a queue.
    4. A queue cleared, popped or deleted from outside drain, beyond the two
       documented releases, or sliced on its way into drain.
    """
    tree = ast.parse(source)
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    def ancestors(node):
        while id(node) in parent:
            node = parent[id(node)]
            yield node

    def owner(node) -> ast.AST | None:
        return next((a for a in ancestors(node)
                     if isinstance(a, (ast.FunctionDef, ast.Lambda))), None)

    def top_statement(node) -> ast.AST:
        return [a for a in [node, *ancestors(node)] if id(a) in {id(t) for t in tree.body}][0]

    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    table_funcs: set[str] = set()
    table_stmts: set[int] = set()
    for stmt in tree.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id in _TABLES):
            table_stmts.add(id(stmt))
            table_funcs |= {v.id for v in stmt.value.values if isinstance(v, ast.Name)}
    found: list[str] = []
    if not table_funcs:
        return ["no dispatch tables found"]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Name):
            continue
        fn = owner(node)
        fname = fn.name if isinstance(fn, ast.FunctionDef) else None
        in_table = id(top_statement(node)) in table_stmts
        if node.id in _TABLES and not in_table and fname != "_dispatch":
            found.append(f"{node.lineno}: {node.id} used outside _dispatch")
        if node.id in table_funcs and not in_table:
            found.append(f"{node.lineno}: decoder {node.id} named outside the tables")
        if node.id in _SHARED_DECODERS and fname not in table_funcs:
            found.append(f"{node.lineno}: {node.id} used outside a decoder")
        if node.id == "_dispatch":
            call = parent.get(id(node))
            outer = parent.get(id(call)) if call is not None else None
            if not (isinstance(call, ast.Call) and call.func is node
                    and isinstance(outer, ast.Call) and isinstance(outer.func, ast.Name)
                    and outer.func.id == "_enqueue" and len(outer.args) >= 2
                    and outer.args[1] is call):
                found.append(f"{node.lineno}: _dispatch used other than as _enqueue(q, _dispatch(...))")

    def drained_in(fn: ast.FunctionDef, name: str) -> bool:
        return any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                   and c.func.attr == "drain"
                   and any(isinstance(n, ast.Name) and n.id == name
                           for arg in c.args for n in ast.walk(arg))
                   for c in ast.walk(fn))

    def params(fn: ast.FunctionDef) -> list[str]:
        return [a.arg for a in fn.args.args]

    def good_queue(expr, fn, seen) -> bool:
        if not isinstance(fn, ast.FunctionDef):
            return False
        if (isinstance(expr, ast.Attribute) and expr.attr == "parts"
                and isinstance(expr.value, ast.Name) and expr.value.id in params(fn)
                and fn.name in table_funcs | {"_piece", "_member_part"}):
            return True
        if not isinstance(expr, ast.Name):
            return False
        if expr.id not in params(fn):
            return drained_in(fn, expr.id)
        if (fn.name, expr.id) in seen:
            return True
        seen = seen | {(fn.name, expr.id)}
        index = params(fn).index(expr.id)
        sites = [c for c in ast.walk(tree) if isinstance(c, ast.Call)
                 and ((isinstance(c.func, ast.Name) and c.func.id == fn.name)
                      or (isinstance(c.func, ast.Attribute) and c.func.attr == fn.name))]
        if not sites:
            return False
        for c in sites:
            shift = 1 if params(fn)[:1] == ["self"] and isinstance(c.func, ast.Attribute) else 0
            given = [k.value for k in c.keywords if k.arg == expr.id]
            if not given and len(c.args) > index - shift >= 0:
                given = [c.args[index - shift]]
            if not given or not good_queue(given[0], owner(c), seen):
                return False
        return True

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_enqueue"):
            continue
        if any(isinstance(a, (ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp,
                              ast.DictComp)) for a in ancestors(node)):
            found.append(f"{node.lineno}: _enqueue called lazily")
            continue
        if not node.args or not good_queue(node.args[0], owner(node), frozenset()):
            found.append(f"{node.lineno}: _enqueue given a queue the scan does not drain")

    releases = 0
    for node in ast.walk(tree):
        fn = owner(node)
        fname = fn.name if isinstance(fn, ast.FunctionDef) else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "drain":
            if any(isinstance(n, ast.Subscript) for arg in node.args for n in ast.walk(arg)):
                found.append(f"{node.lineno}: a queue sliced on its way into drain")
        if fname in ("drain", "_enqueue"):
            continue
        if isinstance(node, ast.Delete) and any(
                isinstance(n, ast.Name) and n.id in ("queue", "residue")
                for t in node.targets for n in ast.walk(t)):
            if fname == "_proven" and ast.unparse(node) == "del queue[before:]":
                releases += 1
            else:
                found.append(f"{node.lineno}: {ast.unparse(node)}")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("clear", "pop", "remove")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("queue", "residue")):
            found.append(f"{node.lineno}: {ast.unparse(node)}")
    if releases != _RELEASES:
        found.append(f"{releases} documented releases, not {_RELEASES}")
    return found


# The round 12 review's nine walker mutants, each an edit to the real source that
# drops decoded output in a shape the round 12 walker could not see.
_ATT = "        res = _enqueue(queue, _dispatch(kind, data, work, self, chain, start=pos), prefix=how[0])\n"
_PNG = ('rows = _enqueue(res.parts, _dispatch("zlib", b"".join(data[b:e] for b, e in image), work),\n'
        '                        rename="png image")')
_B64 = '            res = _enqueue(queue, _dispatch("base64", run, work, start=shift))\n'
WALKER_MUTANTS = {
    "alias-dispatch": [(_ATT, "        d = _dispatch\n        res = d(kind, data, work, self, chain, start=pos)\n")],
    "codecs-direct-png": [(_PNG, 'rows = _Result()\n        _CODECS["zlib"](b"".join(data[b:e] for b, e in image), 0, _Sink(work))')],
    "throwaway-piece": [("part = _enqueue(res.parts, _dispatch(", "part = _enqueue([], _dispatch(")],
    "throwaway-member": [("member = _enqueue(res.parts, _dispatch(", "member = _enqueue([], _dispatch(")],
    "lambda-png": [(_PNG, 'rows = (lambda q: _enqueue(q, _dispatch("zlib", b"".join(data[b:e] for b, e in image), work),\n'
                          '                        rename="png image"))([])')],
    "clear-shifted": [("            self.drain(chain, queue, depth, work, scanned, derived=shift != 0)\n",
                       "            if shift:\n                queue.clear()\n"
                       "            self.drain(chain, queue, depth, work, scanned, derived=shift != 0)\n")],
    "stored-not-drained": [("        self.drain(chain, queue, depth, work, scanned)\n", "        self.pending = queue\n")],
    "generator-unconsumed": [(_B64, '            gen = (_enqueue(queue, _dispatch("base64", run, work, start=s)) for s in [shift])\n'
                                    '            res = next(gen) if shift == 0 else _Result()\n')],
    "residue-first-only": [('[("inflated fragment", out) for _, out in residue]',
                            '[("inflated fragment", out) for _, out in residue][:1]')],
}


def test_decoded_output_can_only_flow_from_the_dispatcher_to_a_drain(tmp_path: Path):
    # Round 12 checked the shape of a _dispatch call and nothing else, so a decoder
    # reached through its table, an alias, a lambda over a throwaway queue or a
    # queue nobody drained all passed it, and two of those dropped every decoded
    # PNG image byte with the whole suite green. The walker now holds the flow:
    # decoders only through _dispatch, _dispatch only into _enqueue, and every
    # queue one the scan drains, traced through parameters to the drain that reads
    # it. Each of the review's nine mutants of the real source fails it.
    source = SCANNER.read_text(encoding="utf-8")
    assert _flow_problems(source) == []
    for name, edits in WALKER_MUTANTS.items():
        mutated = source
        for old, new in edits:
            assert mutated.count(old) == 1, (name, old[:40])
            mutated = mutated.replace(old, new)
        assert _flow_problems(mutated), name


def test_the_queue_a_trial_fills_is_the_one_the_scan_drains(tmp_path: Path, monkeypatch):
    # The identity the walker traces through parameters, checked at run time: every
    # list _proven puts trial output into is the residue list of the scan loop that
    # called it, and that loop hands every piece of it to drain.
    filled: list[int] = []
    real_proven = anon_check._proven
    monkeypatch.setattr(anon_check, "_proven",
                        lambda kind, data, pos, trials, work, queue, *a: filled.append(id(queue))
                        or real_proven(kind, data, pos, trials, work, queue, *a))
    drained: list[list[str]] = []
    real_drain = anon_check._SiteScan.drain
    monkeypatch.setattr(anon_check._SiteScan, "drain",
                        lambda self, chain, queue, *a, **k: drained.append([l for l, _ in queue])
                        or real_drain(self, chain, queue, *a, **k))
    residues: list[int] = []
    real_candidates = anon_check._candidates
    monkeypatch.setattr(anon_check, "_candidates",
                        lambda data, br, trials, residue, work, **k: residues.append(id(residue))
                        or real_candidates(data, br, trials, residue, work, **k))
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = c.compress(b"notes filed by zz-secret-org for the record") + c.flush()
    (tmp_path / "raw.js").write_bytes(b'var d = "' + base64.b64encode(stream) + b'";')
    assert assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert filled and set(filled) <= set(residues)
    assert any("inflated fragment" in labels for labels in drained)


def _png_chunk(tag: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body))


def _png(*chunks: bytes, width: int = 1) -> bytes:
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, 1, 8, 0, 0, 0, 0))
            + b"".join(chunks) + _png_chunk(b"IEND", b""))


def _woff(table: bytes, original: int, metadata: bytes = b"", meta_original: int = 0) -> bytes:
    length = 64 + len(table) + len(metadata)
    meta_off = 64 + len(table) if metadata else 0
    header = struct.pack(">4sIIHHIHHIIIII", b"wOFF", 0x00010000, length, 1, 0, 0, 1, 0,
                         meta_off, len(metadata), meta_original, 0, 0)
    return header + struct.pack(">4sIIII", b"name", 64, len(table), original, 0) + table + metadata


_SECRET = b"notes filed by zz-secret-org for the record " * 8


def _streamed_zstd(zstd, text: bytes, label: str) -> tuple[bytes, str]:
    zw = zstd.ZstdCompressor()
    return zw.compress(text) + zw.flush(), label


def _site_witnesses() -> dict[str, tuple[bytes, str] | None]:
    # One file per site the dispatcher decodes, each holding the name only in its
    # decoded output, and the label a catch from that output carries. None where
    # this Python cannot build the witness. This runs at collection, so it must
    # never skip: round 13 called pytest.importorskip here, and on 3.10 and 3.12,
    # CI's two versions, that skipped every test in this file.
    z = zlib.compress(_SECRET, 9)
    raw = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = raw.compress(_SECRET) + raw.flush()
    try:
        from compression import zstd
    except ImportError:
        zstd = None
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        info = tarfile.TarInfo("notes.txt.gz")
        packed = gzip.compress(_SECRET)
        info.size = len(packed)
        tf.addfile(info, io.BytesIO(packed))
    return {
        "a.gz": (gzip.compress(_SECRET), "a.gz > gzip stream"),
        "a.zz": (z, "a.zz > zlib stream"),
        "raw.js": (b'var d = "' + base64.b64encode(deflated) + b'";', "raw.js > base64 > inflated fragment"),
        "a.bz2": (bz2.compress(_SECRET), "a.bz2 > bzip2 stream"),
        "a.xz": (lzma.compress(_SECRET), "a.xz > xz stream"),
        # zstd stores short literals as they are, so its text is long enough to be
        # Huffman-coded and the name is not in the file.
        "a.zst": _streamed_zstd(zstd, _words(25, 3000), "a.zst > zstd stream") if zstd else None,
        "app.js.br": (brotli.compress(_SECRET), "app.js.br > brotli stream"),
        "a.zip": (_zip_deflated({"notes.txt": _SECRET}), "a.zip > notes.txt"),
        "a.tar": (tar.getvalue(), "a.tar > notes.txt.gz > gzip stream"),
        "tables.woff2": (_woff2("zz-secret-org Sans"), "tables.woff2 > woff2 tables"),
        "meta.woff2": (_woff2("Test Sans", "<vendor name='zz-secret-org'/>" * 8), "meta.woff2 > woff2 metadata"),
        "table.woff": (_woff(z, len(_SECRET)), "table.woff > woff table"),
        "meta.woff": (_woff(zlib.compress(b"clean " * 40), 240, z, len(_SECRET)), "meta.woff > woff metadata"),
        "ztxt.png": (_png(_png_chunk(b"zTXt", b"Author" + bytes(2) + z)), "ztxt.png > png chunk"),
        "itxt.png": (_png(_png_chunk(b"iTXt", b"Author\x00\x01\x00en\x00Author\x00" + z)), "itxt.png > png chunk"),
        "iccp.png": (_png(_png_chunk(b"iCCP", b"profile" + bytes(2) + z)), "iccp.png > png chunk"),
        "image.png": (_png(_png_chunk(b"IDAT", zlib.compress(b"\x00" + _SECRET, 9)), width=len(_SECRET)),
                      "image.png > png image"),
        "a.pdf": (_pdf_bytes([(b"FlateDecode", z)]), "a.pdf > pdf stream"),
    }


def test_woff_metadata_and_png_image_data_are_read_a_container_down(tmp_path: Path):
    # Round 13's review: a mutant that decoded WOFF metadata into a throwaway sink,
    # and one that swapped the PNG image's queue out with setattr, were each killed
    # by one witness only. A second input for each site, reached another way: the
    # font as a zip member, and the image as a data URL in a page.
    font = _woff(zlib.compress(b"clean " * 40), 240, zlib.compress(_SECRET, 9), len(_SECRET))
    image = _png(_png_chunk(b"IDAT", zlib.compress(b"\x00" + _SECRET, 9)), width=len(_SECRET))
    (tmp_path / "fonts.zip").write_bytes(_zip({"f.woff": font}))
    (tmp_path / "page.html").write_bytes(
        b'<img src="data:image/png;base64,' + base64.b64encode(image) + b'">')
    for data in (font, image, (tmp_path / "page.html").read_bytes()):
        assert b"zz-secret" not in data
    found = assert_caught(anon_check.check_site(tmp_path, TOKENS))
    assert {line.split(": ")[0] for line in found} == {
        "fonts.zip > f.woff > woff metadata", "page.html > base64 > png image"}, found


@pytest.mark.parametrize("name", sorted(_site_witnesses()))
def test_every_site_the_dispatcher_decodes_is_read_for_names(tmp_path: Path, name: str):
    # Round 12's review found PNG image data held by no test that reads a name
    # from it, so a mutant that dropped every IDAT byte passed the whole file. The
    # sweep found four more sites with no such test: iTXt, iCCP, and a WOFF 1.0
    # table and its metadata. One witness per site, each asserting the label.
    witness = _site_witnesses()[name]
    if witness is None:
        pytest.skip("compression.zstd needs Python 3.14 or later")
    data, label = witness
    assert b"zz-secret" not in data
    (tmp_path / name).write_bytes(data)
    # Any view: a woff2 name table is UTF-16, which the UTF-8 view reads first.
    assert any(line.startswith(f"{label}: {CATCH} (#2 in .anon-tokens, ")
               for line in assert_caught(anon_check.check_site(tmp_path, TOKENS))), label
