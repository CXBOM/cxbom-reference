"""The /scope/ page: the proxy's threat model, reproduced at build time.

Owner: ATACE Working Group.

The site states the tool's threat model, what it does not cover, and its CVE
coverage. Copying those tables by hand would let them drift from the design
source, so the build extracts section 2 of `docs/design/tool.md` verbatim.
It rewrites only the three lead-in lines that address talk and site authors,
the "section 6 runner table" reference, which points at the runner table
the page appends, and any in-body cross-reference listed in `SECTION_REFS`.
Each rewrite must match exactly once (or, for `SECTION_REFS`, zero or more
times, since which cross-references a given copy of section 2 carries
depends on which copy it is), so a source edit to those lines stops the
build for review instead of publishing stale wording.

Ruling C5 (site ledger, 2026-09-26): the tool design document is not itself
published on the site, so nothing this page generates may point a reader at
a section number or call the source "the specification" as if they could
look it up. Every piece of generated wording (`INTRO`, the runner-table
lead-in, and the `SEE_BELOW` resolution) names the source as "the proxy"
instead, and the page as a whole is "the proxy's threat model". The
extracted body text is reprinted verbatim regardless, since it is the
source's own words, not this page's; only what this module writes on its
own account is held to the naming rule.

Ruling C5 fix round 1 (2026-09-26): "verbatim" covers the source's claims,
not its internal navigation aids. Section 2's body itself carries in-body
cross-references such as "(section 7 step 1)", which is a pointer into a
document this site does not publish, so it would point at nothing once
reprinted here. `SECTION_REFS` maps each known cross-reference to a plain
description of what it points to; the description replaces the reference in
place, leaving the surrounding claim untouched. Any "section N" pattern that
survives every known rewrite (`SECTION_REFS`, `RUNNER_REF`) fails the build,
the same fail-closed style as `LEADS`, so an edit that adds a new
cross-reference is caught for review instead of shipping a dead pointer.
"""
from __future__ import annotations

import re

LEADS = (
    ("**Out of scope, stated on the site and in the talk:**", "**Out of scope:**"),
    ("**Not covered in this version.** Listed in `cxbom --help`, on the site, and on a talk slide:",
     "**Not covered in this version:**"),
    ("**CVE coverage.** Every talk claim must match this table.", "**CVE coverage:**"),
)
RUNNER_REF = "the section 6 runner table"
RUNNER_REPL = "the runner table below"
SEE_BELOW = ("every documented `run` flag (see below)",
             "every documented `run` flag (not reproduced on this page)")
# Known in-body cross-references in section 2, keyed by the exact source
# text, valued by a plain description that does not name a section number.
# Built against docs/design/tool.md as it stands on main: the "Hostnames
# under a TLD outside `approve`'s fixed list" row cites "(section 7 step 1)",
# which is `cxbom approve`'s validate step, specifically its
# identifying-content check. The CVE-coverage row cites "(next plan, section
# 11)" for the `cxbom scan` and `cxbom guard` commands, which a later plan
# delivers. Both are rewritten to a plain description so the standalone site
# names no section of a document it does not reprint.
SECTION_REFS = {
    "section 7 step 1": "approve's identifying-content check",
    "next plan, section 11": "a later plan",
}
_BARE_SECTION_REF_RE = re.compile(r"\bsection\s+\d+(?:\s+step\s+\d+)?\b", re.IGNORECASE)
INTRO = (
    "This page states the proxy's threat model verbatim: the actors it "
    "defends against, what it leaves out of scope, the channels it does not "
    "cover, and how it relates to specific CVEs. The build generates this "
    "page from the proxy's own design source, so the two cannot drift."
)


class ScopeError(ValueError):
    """Section 2 no longer has the shape this page depends on."""


def section(tool_md: str, number: int) -> str:
    m = re.search(rf"^## {number}\. .*?$(.*?)(?=^## \d+\. |\Z)", tool_md, re.M | re.S)
    if not m:
        raise ScopeError(f"section {number} not found")
    return m.group(1).strip("\n")


def runner_table(tool_md: str) -> str | None:
    lines = section(tool_md, 6).splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("| Runner |"):
            table = []
            for row in lines[i:]:
                if not row.strip().startswith("|"):
                    break
                table.append(row.strip())
            text = "\n".join(table)
            # The runner table's "see below" points into section 6, which the page does not reproduce.
            return text.replace(*SEE_BELOW)
    return None


def scope_markdown(tool_md: str) -> str:
    body = section(tool_md, 2)
    for old, new in SECTION_REFS.items():
        body = body.replace(old, new)
    for old, new in LEADS:
        if body.count(old) != 1:
            raise ScopeError(f"section 2 lead-in changed: {old[:40]}")
        body = body.replace(old, new)
    runner = runner_table(tool_md)
    refs = body.count(RUNNER_REF)
    if refs > 1 or (refs == 1 and runner is None):
        raise ScopeError("section 2 cites the section 6 runner table, which was not found once")
    body = body.replace(RUNNER_REF, RUNNER_REPL)
    stray = _BARE_SECTION_REF_RE.search(body)
    if stray:
        raise ScopeError(f"section 2 has an unmapped cross-reference: {stray.group(0)!r}")
    if re.search(r"\btalk\b", body, re.I):
        raise ScopeError("section 2 mentions the talk, which the anonymous site must not")
    parts = ["# Scope and threat model", INTRO, body]
    if refs == 1:
        parts += ["## Runner table", "Registry runners that `approve` recognizes, from the proxy's lockfile rules.", runner]
    return "\n\n".join(parts) + "\n"
