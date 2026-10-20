"""Vendored ATACE files keep their exact bytes (spec 3, 4 and 18).

Owner: ATACE Working Group.

spec/published.lock.json lists every vendored file under "vendored". A file
copied byte-identical carries only its hash. A file that diverges carries a
declared patch: a list of hunks, each naming the upstream text it replaces, the
text that replaces it, how many times, and the reason for that hunk. Reversing
every hunk must reproduce the upstream bytes, so the patch is provably the only
change.

A hunk's upstream text must be gone from the file and from everything the site
publishes. Both checks run the site anonymity scanner itself,
anon_check.check_site, with the lock's replaced texts as its token list. So
every view and decoder that scanner has covers them too: case, Unicode
compatibility forms, confusable letters, invisible characters, entities and
escapes, base64 runs, archives and fonts, and file names. No second matcher is
kept here to drift from it. The first rename checked only the exact spelling it
replaced, and the capitalized form of the old name survived and shipped.

The replaced texts are read from the lock. They are never written to the
repository denylist, and no test file spells them.

The set of patched files is exact and is written out below, so a patch added to
the lock without a reason fails here, and so does a reason left behind after its
patch is gone.
"""
import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "site"))
import anon_check  # noqa: E402
from cxsite import build  # noqa: E402

FROZEN = "3e7f88f4ed86953a8aee17fa4c98253fbd0f2c85"
LOCK = json.loads((ROOT / "spec/published.lock.json").read_text(encoding="utf-8"))
VENDORED = LOCK["vendored"]
VENDORED_DIRS = ("cxbom/_data/catalogs", "tests/fixtures/phi3", "tests/fixtures/atace", "site/data")
# Exactly the vendored files allowed to differ from upstream. Two move a data
# path for the packaged layout. The clean example's rename is declared in its
# top-level entry, because that example is authored here now, not vendored.
PATCHED = ("cxbom/crosswalk.py", "cxbom/validator.py")
# The 0.3.0 examples are authored here, not vendored from ATACE. The clean
# example keeps its declared rename in the top-level lock entry.
RENAMED = tuple(n for n, e in LOCK.items() if "renamed" in e)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hunks(rel: str) -> list[dict]:
    return VENDORED[rel]["patch"]


def _replaced(rel: str | None = None) -> list[str]:
    """The upstream texts the lock's patches or renames replaced."""
    def entry(r):
        return VENDORED.get(r) or LOCK.get(Path(r).name) or {}
    rels = [rel] if rel else list(PATCHED) + [f"spec/{n}" for n in RENAMED]
    out = []
    for r in rels:
        e = entry(r)
        out += [h["from"] for h in e.get("patch", [])]
        out += [h["from"] for h in e.get("renamed", [])]
    return out


def _scan(root: Path, tokens: list[str]) -> list[str]:
    """The site anonymity scanner's entry point, with `tokens` as its whole token list.

    anon_check.check_site takes its tokens as an argument and reads no denylist,
    so the replaced names reach every view it has without touching
    .anon-tokens. Its token rule is plain containment in a folded view, with a
    multi-word token also matched with its spaces closed up. The replaced names
    are single words, so "people could" does not match: the space stays in the
    view and breaks the name.
    """
    return anon_check.check_site(root, tokens)


def _files_named(findings: list[str]) -> set[str]:
    # A finding's first chain element is the file, or the withheld marker when
    # the file's own name carries a token.
    return {f.split(": ", 1)[0].split(" > ", 1)[0] for f in findings}


@pytest.mark.parametrize("rel", sorted(VENDORED))
def test_vendored_file_matches_lock(rel, tmp_path):
    entry = VENDORED[rel]
    data = (ROOT / rel).read_bytes()
    assert _sha(data) == entry["sha256"], f"{rel} drifted from its locked hash"
    patch = entry.get("patch")
    if patch is None:
        assert entry["upstreamSha256"] == entry["sha256"], f"{rel} must be byte-identical to upstream"
        return
    text = data.decode("utf-8")
    hunks = patch
    assert hunks, f"{rel}: a patch with no hunks declares nothing"
    for h in hunks:
        want = h["occurrences"]
        assert text.count(h["to"]) == want, \
            f"{rel}: the patched text appears {text.count(h['to'])} times, not {want}"
    # The upstream text is gone in every spelling the site scanner reads, not
    # merely in the one each hunk names. This is the check that let the
    # capitalized form through when it compared exact strings.
    alone = tmp_path / "vendored"
    alone.mkdir()
    (alone / Path(rel).name).write_bytes(data)
    assert _scan(alone, _replaced(rel)) == [], \
        f"{rel}: the text a patch hunk replaces is still present in some spelling"
    restored = text
    for h in reversed(hunks):
        restored = restored.replace(h["to"], h["from"])
    assert _sha(restored.encode("utf-8")) == entry["upstreamSha256"], \
        f"{rel} differs from upstream beyond its declared patch"


@pytest.mark.parametrize("prose,flagged", [
    ("Operators tell people concretely what ran.", False),
    ("Operators tell {Name} concretely what ran.", True),
    ("the people could see it", False),
    ("the {NAME} could see it", True),
])
def test_ordinary_english_is_not_the_old_name(tmp_path: Path, prose: str, flagged: bool):
    # "people" followed by a word starting "co" holds the old name's letters in
    # order. It is not the name, and the scan must not refuse a page for it.
    # Each phrase stands next to the same sentence with a real spelling in it,
    # derived from the lock, so a scan that flags nothing fails too.
    old = _replaced("spec/cxbom_example_clean_baseline.json")[0]
    (tmp_path / "page.html").write_text(
        "<p>" + prose.format(Name=old[:1].upper() + old[1:], NAME=old.upper()) + "</p>",
        encoding="utf-8")
    assert bool(_scan(tmp_path, _replaced())) is flagged


@pytest.fixture(scope="module")
def published(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site") / "dist"
    build.build(ROOT, out)
    return out


def test_no_published_file_carries_a_name_a_patch_removed(published: Path):
    files = {p.relative_to(published).as_posix() for p in published.rglob("*") if p.is_file()}
    # The scanner walks every file and every name, not a list of the ones
    # expected to hold the record. The record the rename exists for is among
    # them, so a build that stopped publishing it cannot pass vacuously.
    assert "examples/cxbom_example_clean_baseline.json" in files
    assert _scan(published, _replaced()) == []


def test_the_published_scan_finds_a_planted_spelling(published: Path, tmp_path: Path):
    # Positive control for the test above, through the same call on a copy of
    # the build, so a scan that reads nothing is not mistaken for a clean site.
    # Every spelling comes from the lock and is written only under tmp_path. Each
    # plant exercises a different view: a \u escape in JSON, a zero-width joiner,
    # markup splitting the name, a base64 data URI, and a file name.
    old = _replaced("spec/cxbom_example_clean_baseline.json")[0]
    capital = old[:1].upper() + old[1:]
    dist = tmp_path / "dist"
    shutil.copytree(published, dist)
    b64 = base64.b64encode(f"<p>{capital}</p>".encode()).decode()
    plants = {
        "examples/plant-escaped.json": '{"operator": "%s"}' % "".join(f"\\u{ord(c):04x}" for c in capital),
        "plant-zwj.txt": old[:6] + "\u200d" + old[6:],
        "plant-split.html": f"<p>{capital[:4]}<b></b>{capital[4:]}</p>",
        "assets/plant-b64.css": f'a{{background:url("data:text/html;base64,{b64}")}}',
        f"assets/{capital}.txt": "plain\n",
    }
    for rel, body in plants.items():
        (dist / rel).write_text(body, encoding="utf-8")
    # The planted file name is withheld in the scanner's own output, which is
    # the scanner working, so the marker stands for it.
    want = {Path(rel).name for rel in plants if capital not in rel} | {anon_check.WITHHELD}
    assert _files_named(_scan(dist, _replaced())) == want


def test_exactly_the_declared_files_are_patched():
    assert sorted(r for r, e in VENDORED.items() if "patch" in e) == sorted(PATCHED)


def test_every_declared_patch_says_why():
    # A divergence from upstream without a written reason is undocumented drift,
    # whatever its hash proves.
    for rel in PATCHED:
        hunks = VENDORED[rel]["patch"]
        assert hunks, rel
        for h in hunks:
            reason = h.get("reason", "")
            assert isinstance(reason, str) and len(reason) >= 60, rel


def test_every_entry_names_the_frozen_commit():
    for rel, entry in VENDORED.items():
        assert entry["sourceCommit"] == FROZEN, rel
        assert entry["upstream"].startswith("CXBOM/ATACE "), rel


def test_package_schema_is_the_published_schema():
    for version in ("0.2.0", "0.3.0"):
        assert (ROOT / f"cxbom/_data/cxbom-{version}.schema.json").read_bytes() == \
            (ROOT / f"spec/cxbom-{version}.schema.json").read_bytes()


def test_vendored_dirs_hold_only_locked_files():
    for d in VENDORED_DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.is_file():
                rel = p.relative_to(ROOT).as_posix()
                assert rel in VENDORED or rel in LOCK, f"{p.name} is not in the vendored or local lock"
