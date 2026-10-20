"""The /scope/ page states the proxy's threat model verbatim, and fails the
build when it cannot.

Owner: ATACE Working Group.
"""
import html
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import render, scope  # noqa: E402

TOOL_MD = (ROOT / "docs/design/tool.md").read_text(encoding="utf-8")

SYNTHETIC = """# t

## 1. Purpose

p

## 2. Scope and threat model

**Actors defended against:**

- (a) a server

**Out of scope, stated on the site and in the talk:**

- A hostile server process.

**Not covered in this version.** Listed in `cxbom --help`, on the site, and on a talk slide:

| Channel | Instead |
|---|---|
| Registry runners (any tool not in the section 6 runner table) | argv pinned |

**CVE coverage.** Every talk claim must match this table.

| CVE | Mechanism | CxBOM's role |
|---|---|---|
| CVE-2025-54136 | edit | refuses |

## 6. Lockfile

- rules

  | Runner | Exact pin form | Allowed flags before the package |
  |---|---|---|
  | `uvx` | `pkg==1.2.3` | `--from` |

## 7. Next
"""


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def _cells(md: str) -> list[str]:
    cells = []
    for line in md.splitlines():
        line = line.strip()
        if line.startswith("|") and not set(line) <= set("|-: "):
            cells += [c.strip().replace("`", "") for c in line.strip("|").split("|")]
    return cells


def test_every_section_2_table_cell_appears_on_the_page():
    # A raw cell is compared against the rendered page only after the same
    # known, tested rewrites scope_markdown() itself applies to the whole
    # body: RUNNER_REF (the section 6 runner-table pointer) and every
    # SECTION_REFS entry (in-body cross-references such as "section 7 step
    # 1", resolved to a plain description per Ruling C5 fix round 1). Both
    # rewrites are already pinned by their own tests
    # (test_runner_reference_points_at_the_appended_table and
    # test_every_bare_section_reference_in_the_newer_tool_md_is_mapped /
    # test_an_unmapped_cross_reference_stops_the_build), so mirroring them
    # here does not hide a mapping bug -- it stops a cell that legitimately
    # carries a resolved cross-reference from being flagged as dropped.
    # Anything not covered by a known rewrite still has to appear verbatim,
    # so a genuinely dropped or corrupted cell still fails this assertion.
    page = _text(render.md_to_html(scope.scope_markdown(TOOL_MD)))
    for cell in _cells(scope.section(TOOL_MD, 2)):
        for old, new in scope.SECTION_REFS.items():
            cell = cell.replace(old, new)
        cell = cell.replace(scope.RUNNER_REF, scope.RUNNER_REPL)
        assert cell in page, cell


def test_every_out_of_scope_bullet_appears_on_the_page():
    page = _text(render.md_to_html(scope.scope_markdown(TOOL_MD)))
    body = scope.section(TOOL_MD, 2)
    block = body.split("**Out of scope", 1)[1].split("**Not covered", 1)[0]
    bullets = re.findall(r"^- \*\*(.+?)\*\*", block, re.M | re.S)
    # Pre-flight minor: derive the expected count from the spec text itself,
    # via a second, independent (line-based) count, instead of a hard-coded
    # literal like `len(bullets) == 3`. A bullet added or removed in the
    # source still passes, as long as both counting methods agree.
    line_based_count = sum(1 for line in block.splitlines() if line.strip().startswith("- **"))
    assert bullets
    assert len(bullets) == line_based_count
    flat = " ".join(page.split())
    for b in bullets:
        assert " ".join(b.replace("`", "").split()) in flat


def test_lead_ins_lose_talk_wording_and_nothing_mentions_the_talk():
    md = scope.scope_markdown(SYNTHETIC)
    assert "**Out of scope:**" in md and "**Not covered in this version:**" in md and "**CVE coverage:**" in md
    assert not re.search(r"\btalk\b", md, re.I)


def test_runner_reference_points_at_the_appended_table():
    md = scope.scope_markdown(SYNTHETIC)
    assert "(any tool not in the runner table below)" in md
    assert md.rstrip().endswith("| `uvx` | `pkg==1.2.3` | `--from` |")


def test_see_below_in_the_runner_table_is_resolved():
    md = scope.scope_markdown(SYNTHETIC.replace("| `--from` |", "| every documented `run` flag (see below) |"))
    assert "(see below)" not in md
    assert "every documented `run` flag (not reproduced on this page)" in md


def test_changed_lead_in_stops_the_build():
    with pytest.raises(scope.ScopeError, match="lead-in changed"):
        scope.scope_markdown(SYNTHETIC.replace("Every talk claim must match this table.", "Claims follow this table."))


def test_runner_reference_without_the_table_stops_the_build():
    no_table = SYNTHETIC.replace("  | Runner |", "  | Launcher |")
    with pytest.raises(scope.ScopeError, match="runner table"):
        scope.scope_markdown(no_table)


def test_a_new_talk_mention_stops_the_build():
    with pytest.raises(scope.ScopeError, match="talk"):
        scope.scope_markdown(SYNTHETIC.replace("- A hostile server process.", "- As shown in the talk."))


def test_page_has_one_h1():
    assert render.md_to_html(scope.scope_markdown(TOOL_MD)).count("<h1") == 1


# --- Ruling C5: name it "the proxy's threat model", never a section number ---


def test_generated_wording_names_the_proxy_and_never_a_section_number():
    # The tool design document is not published on the site, so nothing this
    # module writes on its own account may send a reader to "section N" of
    # it, or call it "the specification" as if they could look it up.
    md = scope.scope_markdown(TOOL_MD)
    assert "the proxy's threat model" in md
    assert not re.search(r"\bsection\s+\d+\b", md, re.I)
    assert "specification" not in md.lower()


def test_runner_table_intro_names_the_proxy_not_a_section():
    # The real docs/design/tool.md on this branch does not yet cite the
    # runner table (that lands with the proxy-branch rebase), so this checks
    # the same naming rule against the synthetic fixture that does.
    md = scope.scope_markdown(SYNTHETIC)
    assert "the proxy's lockfile rules" in md
    assert not re.search(r"\bsection\s+\d+\b", md, re.I)
    assert "specification" not in md.lower()


# --- Ruling C11: the "Not covered" row count must never be hard-coded ---


def test_not_covered_table_row_count_matches_the_source_table():
    # This branch's copy of section 2 currently has 4 "Not covered" rows;
    # the proxy branch's has 10 or more. Both must pass, because the
    # expected count below is derived from whatever docs/design/tool.md the
    # branch has at test time, never pinned to today's number.
    section2 = scope.section(TOOL_MD, 2)
    source_block = section2.split("**Not covered", 1)[1].split("**CVE coverage", 1)[0]
    source_rows = [
        line.strip() for line in source_block.splitlines()
        if line.strip().startswith("|") and not set(line.strip()) <= set("|-: ")
    ]
    expected_rows = len(source_rows) - 1  # the first non-separator row is the header
    assert expected_rows > 0

    rendered = render.md_to_html(scope.scope_markdown(TOOL_MD))
    marker = "<strong>Not covered in this version:</strong>"
    start = rendered.index(marker)
    tbody_start = rendered.index("<tbody>", start)
    tbody_end = rendered.index("</tbody>", tbody_start)
    rendered_rows = rendered.count("<tr>", tbody_start, tbody_end)
    assert rendered_rows == expected_rows


# --- Ruling C10: the build gate greps every page for "talk" and "arXiv" ---


def test_real_page_mentions_neither_the_talk_nor_arxiv():
    md = scope.scope_markdown(TOOL_MD)
    assert not re.search(r"\btalk\b", md, re.I)
    assert not re.search(r"arxiv", md, re.I)


# --- Ruling C5 fix round 1: in-body cross-references, not just lead-ins ---

# Resolved from the home directory, never spelled out as a literal path: a
# hard-coded absolute path here would put a machine-specific, identity-
# adjacent string in committed source, which this anonymous repository must
# not carry. The skipif below makes the sibling checkout optional everywhere
# else (CI, a fresh clone, another contributor's machine).
_PROXY_TOOL_MD = Path.home() / "github_projects" / "cxbom-proxy" / "docs" / "design" / "tool.md"


@pytest.mark.skipif(not _PROXY_TOOL_MD.exists(), reason="sibling cxbom-proxy checkout not present")
def test_every_bare_section_reference_in_the_newer_tool_md_is_mapped():
    # SECTION_REFS was built against the newer docs/design/tool.md (the
    # proxy branch's copy), which is what this branch sees after it
    # rebases. Every "section N" or "section N step M" reference in section
    # 2's raw source, other than the one RUNNER_REF already resolves, must
    # be a key in SECTION_REFS, or scope_markdown would reprint a pointer
    # into a document this site does not publish.
    newer_tool_md = _PROXY_TOOL_MD.read_text(encoding="utf-8")
    section2 = scope.section(newer_tool_md, 2)
    without_runner_ref = section2.replace(scope.RUNNER_REF, "")
    found = {m.group(0).lower() for m in scope._BARE_SECTION_REF_RE.finditer(without_runner_ref)}
    assert found  # sanity: the newer source really does carry a bare reference
    mapped = {key.lower() for key in scope.SECTION_REFS}
    assert found <= mapped, found - mapped

    # And the extractor resolves it end to end: no bare reference survives,
    # and the mapped description is on the page.
    md = scope.scope_markdown(newer_tool_md)
    assert not scope._BARE_SECTION_REF_RE.search(md)
    assert "approve's identifying-content check" in md


def test_an_unmapped_cross_reference_stops_the_build():
    # Same fail-closed style as LEADS and RUNNER_REF: a cross-reference this
    # module has never seen must not publish a dead pointer, it must stop
    # the build for review.
    unmapped = SYNTHETIC.replace(
        "- A hostile server process.",
        "- A hostile server process (section 9 step 2).",
    )
    with pytest.raises(scope.ScopeError, match="cross-reference"):
        scope.scope_markdown(unmapped)
