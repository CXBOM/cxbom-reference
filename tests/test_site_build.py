"""The build produces the design's site map, deterministically, with accessible pages.

Owner: ATACE Working Group.
"""
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import build  # noqa: E402

SITE_MAP = [
    "404.html", "_headers", "_worker.js", "assets/site.css", "changelog/index.html",
    "examples/cxbom_example_clean_baseline.json", "examples/cxbom_example_finance_assistant.json",
    "examples/cxbom_example_multiturn_ring1derived.json", "examples/index.html",
    "fonts/OFL.txt", "fonts/source-code-pro-latin-400-normal.woff2", "fonts/source-code-pro-latin-600-normal.woff2",
    "fonts/source-serif-4-latin-400-italic.woff2", "fonts/source-serif-4-latin-400-normal.woff2",
    "fonts/source-serif-4-latin-600-normal.woff2", "index.html", "reference/index.html",
    "schema/0.2.0/cxbom.schema.json", "schema/0.3.0/cxbom.schema.json", "scope/index.html",
    "spec/index.html", "video/keeper-poster.jpg", "video/keeper.mp4", "video/keeper.vtt", "viewer/index.html",
]
PRIVACY = ("This site sets no cookies, loads no third-party resources, and runs no analytics. "
           "Server access logs are kept at the host's default retention and are not examined.")


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("b") / "dist"
    assert build.build(ROOT, out) == SITE_MAP
    return out


def _pages(d: Path) -> list[Path]:
    return sorted(d.rglob("*.html"))


def test_the_film_figcaption_is_the_supported_sentence():
    """The homepage caption may not say more than the signed sentence.

    The production change that fails this is a figcaption that names attack
    wordings the sentence does not, or that drops the re-listing limit.
    """
    html = build._film_html()
    match = re.search(r"<figcaption>(.*?)</figcaption>", html)
    assert match, "the homepage film has no figcaption"
    assert match.group(1) == (
        "On this recording, for three attacks, a notes tool description that "
        "changed after it was signed sent the secret when the gate was off and "
        "the inbox showed that it arrived, and when the gate was on that tool "
        "was dropped from the listing, the secret did not arrive, and the model "
        "kept calling fetch until it hit its limit, and only on the third attack "
        "was that definition clean on the first listing and changed on a "
        "re-listing within the session."
    )


def test_site_map_is_exact(built: Path):
    assert sorted(p.relative_to(built).as_posix() for p in built.rglob("*") if p.is_file()) == SITE_MAP


def test_build_is_deterministic(built: Path, tmp_path: Path):
    again = tmp_path / "dist"
    build.build(ROOT, again)
    for rel in SITE_MAP:
        assert (again / rel).read_bytes() == (built / rel).read_bytes(), rel


def test_copied_artifacts_are_byte_identical(built: Path):
    assert (built / "schema/0.2.0/cxbom.schema.json").read_bytes() == (ROOT / "spec/cxbom-0.2.0.schema.json").read_bytes()
    assert (built / "schema/0.3.0/cxbom.schema.json").read_bytes() == (ROOT / "spec/cxbom-0.3.0.schema.json").read_bytes()
    for name, _ in build.EXAMPLES:
        assert (built / "examples" / name).read_bytes() == (ROOT / "spec" / name).read_bytes()
    assert (built / "viewer/index.html").read_bytes() == (ROOT / "site/viewer/cxbom_view.html").read_bytes()
    assert (built / "_headers").read_bytes() == (ROOT / "site/_headers").read_bytes()


def test_every_page_has_one_h1_and_ordered_headings(built: Path):
    for page in _pages(built):
        text = page.read_text(encoding="utf-8")
        levels = [int(n) for n in re.findall(r"<h([1-6])[\s>]", text)]
        assert levels.count(1) == 1, page
        assert levels[0] == 1, page
        assert all(b - a <= 1 for a, b in zip(levels, levels[1:])), page


def test_every_generated_page_has_landmarks_and_lang(built: Path):
    for page in _pages(built):
        text = page.read_text(encoding="utf-8")
        assert '<html lang="en">' in text, page
        assert 'href="#main"' in text and '<main id="main"' in text, page


def test_every_svg_is_labelled(built: Path):
    for page in _pages(built):
        for svg in re.findall(r"<svg[^>]*>", page.read_text(encoding="utf-8")):
            assert ('role="img"' in svg and "aria-labelledby" in svg) or 'aria-hidden="true"' in svg, page


def test_landing_states_privacy_contact_and_the_ledger(built: Path):
    text = (built / "index.html").read_text(encoding="utf-8")
    flat = " ".join(re.sub(r"<[^>]+>", "", text).split())
    assert PRIVACY in flat
    assert '<a href="mailto:spec@cxbom.org">spec@cxbom.org</a>' in text
    assert '<table class="ledger">' in text


def test_strip_is_on_every_generated_page(built: Path):
    for page in _pages(built):
        if page.name == "index.html" and page.parent.name == "viewer":
            continue
        assert '<svg class="strip"' in page.read_text(encoding="utf-8"), page


def test_headers_file_sets_csp_schema_type_and_cors():
    text = (ROOT / "site/_headers").read_text(encoding="utf-8")
    assert "  Content-Security-Policy: default-src 'self'; base-uri 'none'" in text
    assert "/viewer/*\n  ! Content-Security-Policy\n  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'" in text
    assert "/schema/*\n  Content-Type: application/schema+json\n  Access-Control-Allow-Origin: *" in text
    rules = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
    assert rules.count("'unsafe-inline'") == 2


def test_build_refuses_to_replace_a_directory_that_is_not_a_build(tmp_path: Path):
    victim = tmp_path / "dist"
    victim.mkdir()
    (victim / "notes.txt").write_text("keep me")
    with pytest.raises(build.BuildError, match="Refusing"):
        build.build(ROOT, victim)
    assert (victim / "notes.txt").read_text() == "keep me"


def _repo_copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "spec", root / "spec")
    return root


def test_lock_adds_a_new_schema_version_only_on_request(tmp_path: Path):
    root = _repo_copy(tmp_path)
    doc = json.loads((root / "spec/cxbom-0.2.0.schema.json").read_text(encoding="utf-8"))
    doc["$id"] = "https://cxbom.org/schema/0.9.0/cxbom.schema.json"
    (root / "spec/cxbom-0.9.0.schema.json").write_text(json.dumps(doc), encoding="utf-8")
    before = (root / "spec/published.lock.json").read_text(encoding="utf-8")
    assert "cxbom-0.9.0" not in before
    assert build.lock_new_schemas(root) == ["cxbom-0.9.0.schema.json"]
    lock = json.loads((root / "spec/published.lock.json").read_text(encoding="utf-8"))
    assert lock["cxbom-0.9.0.schema.json"]["servedAt"] == "https://cxbom.org/schema/0.9.0/cxbom.schema.json"
    assert lock["cxbom-0.2.0.schema.json"] == json.loads(before)["cxbom-0.2.0.schema.json"]
    assert list(lock)[-1] == "vendored"
    assert build.lock_new_schemas(root) == []


def test_lock_refuses_a_schema_whose_id_does_not_match_its_path(tmp_path: Path):
    root = _repo_copy(tmp_path)
    (root / "spec/cxbom-0.9.0.schema.json").write_text(
        (root / "spec/cxbom-0.2.0.schema.json").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(build.BuildError, match="must be https://cxbom.org/schema/0.9.0/cxbom.schema.json"):
        build.lock_new_schemas(root)


def test_failed_build_keeps_the_previous_site_and_leaves_no_temp_dir(tmp_path: Path, monkeypatch):
    out = tmp_path / "dist"
    build.build(ROOT, out)
    before = (out / "index.html").read_bytes()

    def refuse(_tool_md):
        raise build.scope.ScopeError("section 2 lead-in changed: test")
    monkeypatch.setattr(build.scope, "scope_markdown", refuse)
    with pytest.raises(build.scope.ScopeError):
        build.build(ROOT, out)
    assert (out / "index.html").read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["dist"]
