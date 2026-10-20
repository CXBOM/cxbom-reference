"""Whether a document claims something this repository has not built.

Owner: ATACE Working Group.

One implementation of the unbuilt-claim ban, shared by every suite that polices
talk wording. Both suites that police it, `tests/test_spec_wording.py` and the
J2 claims suite `tests/test_j2_claims.py`, import from here and keep no copy,
so the convention lives in one place.

The shape, and why it is this shape:

- The trigger is naming a thing the code does not have, never a verb. A verb
  list cannot close the class, because the ways English can say a thing works
  cannot be enumerated. The ways this repository is allowed to say a thing does
  not exist yet can be, because they are ours to choose, so the one closed
  vocabulary sits on the escape hatch (UNBUILT_MARKER) and not on the violation.
- "Does it exist" comes from three derived oracles and nothing else: the CLI
  parser for what ships, an `ast` walk for what the Python defines, and the tool
  spec's synopsis lines for which word after `cxbom` is a command name at all.
  No maintained list, so a command that lands drops out of the ban on its own.
- The unit is the sentence. A marker in the sentence before is not a marker on
  this sentence, which is the leak a fixed character window had.
- Backticks are optional in both notations. A claim does not stop being a claim
  because its author left the code formatting off, and a pattern anchored on the
  backticks covers only the mentions whose author was already being careful.

What this ban cannot reach, and what does:

- A sentence that names nothing. "the rug-pull scanner already flags a removed
  wrapper today" claims a capability this repository does not have and offers no
  referent to resolve, so no derived oracle can see it. Widening the notation
  does not help either: over the four surfaces these guards scan, the unbuilt
  command names appear 32 times as ordinary English ("a CI gate over emitted
  records", "shown as a diff on screen", "the trust inversion", "the proxy
  guards what the model reads"), so reading a bare word as a command name would
  reject honest prose, and a guard that forces prose nobody will write is a
  guard somebody switches off.
- What covers it is reviewed_wording(): the set of sentences a talk surface is
  allowed to contain is finite because it is ours to choose, so the closed
  vocabulary sits on the escape hatch one more time. A sentence nobody recorded
  fails whether or not it names anything.
- A sentence that says where its own words came from is the third case, and it
  is checkable on its own terms: EXACTNESS_CLAIM and MARKER_CLAIM are phrases
  this repository writes on purpose, and each makes a claim a test can resolve
  against the source it names.
"""
from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import re
import subprocess
from collections import Counter
from functools import lru_cache
from pathlib import Path

from cxbom import cli as cxbom_cli

ROOT = Path(__file__).resolve().parent.parent

# The tool spec, read for one thing only: the command vocabulary its synopsis
# lines write. shipped_commands() answers what the CLI parser accepts today;
# this answers what counts as a command name at all, which is what lets
# "cxbom checks the server's code" stay ordinary English while "cxbom scan" is
# read as a command.
TOOL_SPEC = ROOT / "docs" / "design" / "tool.md"

# The wording a human signed, one line per reviewed sentence. See
# reviewed_wording() for the format and for why the file exists.
REVIEWED_WORDING = Path(__file__).resolve().parent / "reviewed-talk-wording.txt"

# Directories the walk skips: version-control metadata, tool caches, and the
# sibling worktrees, each of which holds another checkout of this same
# repository and would answer for its own branch instead of this one. Every
# other directory is walked, dot-prefixed or not, because "hidden" is not a
# reason a claim goes unscanned.
UNWALKED = frozenset({".git", ".worktrees", ".pytest_cache", ".venv", ".tox",
                      ".mypy_cache", ".ruff_cache", ".eggs", "node_modules",
                      "__pycache__"})

# A command written the way the CLI is invoked, backticks optional.
CXBOM_INVOCATION = re.compile(r"\bcxbom\s+`?([a-z][a-z-]*)`?(?:\s+`?([a-z][a-z-]*)`?)?")

# An inline code span. Used twice: a span whose whole content is a command name
# is a command mention without the word `cxbom` in front of it, and a span is
# where a call to a named function is written.
CODE_SPAN = re.compile(r"`([^`\n]+)`")

# A call, inside a code span. No whitespace before the parenthesis, because a
# call is written `f(x)`: `search_notes (blocked by cxbom: changed)` is a tool
# name followed by a parenthetical, not a call, and a `\s*` here read it as one.
SPAN_CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\(")

# The same call shape outside a code span, where the name has to carry an
# underscore or a dot. Inside backticks the span itself says "this is code";
# outside them that punctuation is the only thing separating an identifier from
# an English word that happens to sit in front of a parenthesis.
BARE_CALL = re.compile(r"(?<![`\w.])([A-Za-z_]\w*(?:[._]\w+)+)\(")

# Every marker this repository already uses for something that does not exist
# yet: "(not in slice 1)" beside `cxbom diff` and the J2 script's corrections,
# "(forthcoming, ...)" for C2 1.3.0, and tool.md's "(next plan)" or "once
# built" for `cxbom scan` and `cxbom guard`. Closed on purpose, and the only
# closed vocabulary in the ban.
#
# Either hyphenation of "next plan" counts. tool.md writes both, "next-plan
# feature" in section 11 and "(next plan)" in section 2, and a guard that turns
# on one character fails for the wrong reason: the honest sentence gets rejected
# and the next editor reaches for the hyphen the document already uses.
#
# The hyphen is a widening as well as a fix, and the trade is deliberate. Any
# sentence holding the substring "next-plan" now reads as marked, including one
# where the phrase modifies something else: "`--rebind-binary` is a next-plan
# feature" (tool.md section 13) marks its whole sentence, so a claim about a
# second unbuilt command in that same sentence would escape the ban, and the
# inverse ban below reads that sentence as a stale marker over `approve`, which
# ships. Accepted, for two reasons. The escape needs two unbuilt names in one
# sentence, which is already this ban's documented residual, and the false
# positive needs section 13 inside a scanned surface, which it is not. The
# consequence to carry forward: widening the scanned surfaces to section 13
# means handling that sentence, and the J2 lane's copy of this module, which
# writes the space-only form, diverges from this one on 3 of 1612 corpus
# sentences -- one of them live text -- so folding the copies is
# behaviour-changing in both directions, not one implementation twice.
UNBUILT_MARKER = re.compile(
    r"not in slice 1|forthcoming|next[- ]plan|once built|not yet built", re.I)

# A fenced block is a specimen, not an assertion. A synopsis, a JSON payload or
# a terminal transcript shows what a thing would look like rather than claiming
# it runs, and the tool spec's own synopsis is the clearest case: it lists every
# planned command, none of which it thereby claims to ship. Cut before the
# sentences are split, so a fence cannot merge two units either.
FENCED_BLOCK = re.compile(r"^[ \t]*```.*?^[ \t]*```[ \t]*$", re.M | re.S)

# Where one prose unit ends inside a block: the start of a list item, a table
# row, a heading or a blockquote line. A sentence wrapped across two lines stays
# one unit, but two bullets are two units and two table cells are two units, so
# a marker in one cannot excuse a claim in the next.
PROSE_UNIT_BREAK = re.compile(r"\n(?=[ \t]*(?:[-*+] |\d+[.)] |\||#{1,6} |> ))")

# A sentence boundary: terminal punctuation, whitespace, then something that
# opens a sentence. Requiring that opener keeps a version (`4.56.2`), a filename
# (`lab-j2.md`) and an abbreviation ("e.g. the") from splitting a sentence in
# half, which would put a claim and its marker into different units.
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\"(\[*])")

# A quoted sentence inside the guardrails section is the ban list itself: that
# section exists to write down what the narration must not say. Masking those
# quotations, rather than cutting the whole section, is what lets the
# corrections beside them be scanned. Those corrections are narration the
# audience hears, and two of them claimed an unbuilt command acts.
GUARDRAIL_QUOTATION = re.compile(r'"[^"\n]*"')

# The section that quotes the sentences the narration must not say. Named by
# heading text because documents carry it at different depths and numbers.
GUARDRAILS = "Honesty guardrails"

# The tool spec's synopsis lines, and the parts of one that are not the command
# name. A bracketed flag list goes before the line is split on the alternation
# bar, or `[--mode enforce|observe]` contributes a command named `observe`.
SYNOPSIS_LINE = re.compile(r"^cxbom[ \t]+(.*)$", re.M)
SYNOPSIS_OPTIONAL = re.compile(r"\[[^\]]*\]|\([^)]*\)")
SYNOPSIS_WORD = re.compile(r"(?<![\w-])([A-Za-z][\w-]*)")

# The spec's own claims gate, and the sentence a section uses to bind the talk
# to itself. Both are read out of the document rather than typed here, because a
# hand-typed section list is how this guard came to cover sections 2 and 17
# while the gate named 16 and 17: section 16, titled "Talk and site wording",
# is the list of sentences the speaker says, and it carried three unmarked
# claims that an unbuilt command acts while the ban ran past it.
CLAIMS_GATE = re.compile(r"\*\*Claims gate:\*\*[^|\n]*")
SECTION_REFERENCE = re.compile(r"section (\d+)", re.I)
TALK_CLAIM_BINDING = "Every talk claim must match this table"
SECTION_NUMBER = re.compile(r"^## (\d+)\. ", re.M)

# What a sentence can claim about the words in front of it. Both vocabularies
# are closed for the reason UNBUILT_MARKER is: they are phrases this repository
# writes on purpose, not shapes English can vary without limit. Keyed on the
# claim rather than on the attribution's phrasing, because a closed list of
# attribution phrasings ("Section N wording", "Correction slide") is escaped by
# rewording the attribution, while a claim of exactness has to say it is exact.
#
# MARKER_CLAIM matches the noun phrase, not one sentence built around it, so
# "carries the slice 1 marker" and "with the slice 1 marker" are the same claim.
# The marker it names is one alternative of UNBUILT_MARKER, not any of them: a
# sentence marked "(next plan)" does not carry the slice 1 marker, and an
# attribution saying it does is wrong about its own passage.
EXACTNESS_CLAIM = re.compile(r"verbatim|exact words|word for word", re.I)
MARKER_CLAIM = re.compile(r"slice 1 marker", re.I)
SLICE_1_MARKER = re.compile(r"not in slice 1", re.I)
SOURCE_SECTION = re.compile(r"section (\d+)", re.I)
SOURCE_SLIDE = re.compile(r"slide", re.I)
CORRECTION_HEADING = re.compile(r"^## (\d+)\. Correction to the abstract", re.M)


def walk(suffix: str, root: Path = ROOT) -> list[Path]:
    """Every tracked or untracked-but-not-ignored file with this suffix under root.

    git decides what exists, so a file the repository ignores (a scratch note, a local plan) is never a
    surface for a claims check, and no clone carries it. rglob saw ignored files, which made the result
    depend on what one machine had lying around. A root that is not a git work tree raises instead of
    returning an empty list, because an empty walk reads as a pass.
    """
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture_output=True, check=False)
    assert listing.returncode == 0, "walk needs a git work tree"
    names = (n for n in listing.stdout.decode("utf-8").split("\0") if n.endswith(suffix))
    # A tracked file deleted in the work tree is still listed by --cached.
    return sorted(p for p in (root / n for n in names)
                  if p.is_file() and not (UNWALKED & set(p.relative_to(root).parts)))


def collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def blocks_of(text: str) -> list[str]:
    """The document split at blank lines."""
    return [b for b in re.split(r"\n[ \t]*\n", text) if b.strip()]


def section_bounds(text: str, title: str) -> tuple[int, int]:
    """The character span of one named section, at whatever depth it sits.

    Found by heading text rather than by line number, so a renumbering cannot
    silently widen or narrow the scan. A missing heading is a failure, not a
    pass, because it means the scope this scan was written for has moved.
    """
    match = re.search(r"^(#+)[^\n]*" + re.escape(title) + r"[^\n]*\n", text, re.M)
    assert match is not None, (
        f"no {title!r} heading found. Its quotations are masked out of the "
        "claim scan, and the J2 caption scan cuts the section whole, because it "
        "quotes the narration the talk must not say. If the section was renamed, "
        "update GUARDRAILS here in the same commit."
    )
    depth = len(match.group(1))
    following = re.search(r"^#{1,%d} " % depth, text[match.end():], re.M)
    end = match.end() + (following.start() if following else len(text) - match.end())
    cut = text[match.start():end]
    headings = re.findall(r"^#+ ", cut, re.M)
    assert len(headings) == 1, (
        f"the {title!r} section spans {len(headings)} headings, expected one. "
        "Its own heading sits at a depth that swallows the sections after it, "
        f"so real claims and captions are leaving the scans. The span starts: "
        f"{collapse(cut)[:160]!r}"
    )
    return match.start(), end


def numbered_section(text: str, number: int) -> str:
    """One `## N.` section of a document, its heading included."""
    match = re.search(rf"^## {number}\. .*?(?=^## \d+\. |\Z)", text, re.M | re.S)
    assert match is not None, f"section {number} is missing"
    return match.group(0)


@lru_cache(maxsize=None)
def talk_claim_sections() -> tuple[int, ...]:
    """Every tool.md section the talk reads from, named by the spec itself.

    Two sources, both in the document. The Oct 19 claims-gate row says which
    sections every talk sentence must map to a passing test, and a section that
    binds the talk to its own table says so in its own words. Reading both is
    what keeps this guard's scope tied to the spec's: when the gate names
    another section, the ban covers it in the same commit that names it, with no
    edit here.

    A missing gate or a missing binding is a failure, not a pass, because either
    one means the scope this scan was written for has moved.
    """
    text = TOOL_SPEC.read_text(encoding="utf-8")
    gate = CLAIMS_GATE.search(text)
    assert gate is not None, (
        "tool.md no longer carries a '**Claims gate:**' row. That row is where "
        "the spec says which sections the talk reads from, and this ban's scope "
        "is read from it. Restore it or name the new authority here.")
    numbers = {int(n) for n in SECTION_REFERENCE.findall(gate.group(0))}
    assert numbers, (
        f"the claims-gate row names no section: {gate.group(0)!r}. The ban's "
        "scope cannot be derived, so every talk sentence would go unscanned.")
    bound = [int(n) for n in SECTION_NUMBER.findall(text)
             if TALK_CLAIM_BINDING in numbered_section(text, int(n))]
    assert len(bound) == 1, (
        f"{len(bound)} sections carry {TALK_CLAIM_BINDING!r}, expected one. "
        "That sentence is how the CVE table declares itself a talk surface.")
    numbers.update(bound)
    return tuple(sorted(numbers))


def prose_units(text: str) -> list[str]:
    """Each block, list item and table row of a document, flattened.

    The unit a reader sees as one statement. A guard that resolves a claim
    against neighbouring words has to stop at this boundary, or a marker in one
    bullet excuses a claim in the next.
    """
    units: list[str] = []
    for block in blocks_of(text):
        for chunk in PROSE_UNIT_BREAK.split(block):
            flat = collapse(chunk).strip()
            if flat:
                units.append(flat)
    return units


def sentences_of(text: str) -> list[str]:
    """One sentence per element, splitting blocks and list items first.

    The sentence is the unit the ban is scoped to, because a claim and the
    marker that qualifies it belong to the same sentence.
    """
    return [s for unit in prose_units(text) for s in SENTENCE_BREAK.split(unit) if s.strip()]


def document_text(path: Path, *, mask_guardrails: bool = False) -> str:
    """The whole document, minus its ban-list quotations. Fences intact.

    Deliberately not a caption surface. A claim that something works when it
    does not exist reads the same in engineering prose as in a caption, and the
    caption surface is the smaller half of these documents: the `cxbom scan`
    overclaim that survived the S4 caption fix sat in an acceptance paragraph
    two bullets below the caption that got fixed.

    One exclusion: the quoted sentences inside the guardrails section, because
    quoting an overclaim is not making one. Only the quotations go, never the
    section: the corrections beside them are the words the audience hears.
    """
    text = path.read_text(encoding="utf-8")
    if mask_guardrails:
        start, end = section_bounds(text, GUARDRAILS)
        return text[:start] + GUARDRAIL_QUOTATION.sub(" ", text[start:end]) + text[end:]
    assert GUARDRAILS not in text, (
        f"{path.name} carries a {GUARDRAILS!r} section. Pass "
        "mask_guardrails=True for it, or the sentences it quotes as "
        "forbidden are reported as claims of its own."
    )
    return text


def prose_text(path: Path, *, mask_guardrails: bool = False) -> str:
    """The same document with its code fences cut as well.

    What the claim ban reads: a listing is a specimen, not an assertion. The
    reviewed-wording ledger reads document_text instead, because a listing added
    to a talk section is still a change to what the slide shows, and the ban's
    exclusion would otherwise be a place to write a claim nothing checks.
    """
    return FENCED_BLOCK.sub("\n", document_text(path, mask_guardrails=mask_guardrails))


def prose_sentences(path: Path, *, mask_guardrails: bool = False) -> list[str]:
    return sentences_of(prose_text(path, mask_guardrails=mask_guardrails))


def shipped_commands() -> list[str]:
    """Every command this repository's own CLI parser accepts, walked rather
    than typed out, so a command the parser gains later drops out of the
    unbuilt-command check on its own instead of leaving a stale name that has
    since shipped.
    """
    def descend(parser: argparse.ArgumentParser, prefix: str = "") -> list[str]:
        found: list[str] = []
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    deeper = descend(sub, f"{prefix}{name} ")
                    found.extend(deeper or [f"{prefix}{name}"])
        return found
    return sorted(descend(cxbom_cli._parser()))


@lru_cache(maxsize=None)
def planned_commands() -> frozenset[str]:
    """Every command name the tool spec's own synopsis lines write.

    Read rather than listed, for the reason shipped_commands() is read. This
    half answers a different question from the parser walk, though. The parser
    says what ships; the synopsis says what the word after `cxbom` has to be
    before it is a command name at all, which is what keeps "cxbom prevents
    MCPoison" and "cxbom checks the server's code" out of the ban as the
    ordinary English they are, while `cxbom scan` goes in.

    A word belongs to the command name only while it stays lowercase, because
    the synopsis writes arguments in capitals (`RECORD...`, `KEY.pub`, `FP`).
    That is what separates the two-word `trust add` and `attest prune` from the
    one-word `gate RECORD...`.
    """
    names: set[str] = set()
    for line in SYNOPSIS_LINE.finditer(TOOL_SPEC.read_text(encoding="utf-8")):
        for alternative in SYNOPSIS_OPTIONAL.sub(" ", line.group(1)).split("|"):
            words: list[str] = []
            for word in SYNOPSIS_WORD.findall(alternative):
                if not word.islower():
                    break
                words.append(word)
            if words:
                names.add(" ".join(words[:2]))
    return frozenset(names)


def next_plan_commands() -> list[str]:
    """Documented but not in the parser: every command the spec's synopsis
    writes and this slice does not ship.

    Both halves are derived (planned_commands reads the synopsis,
    shipped_commands walks the parser), so a command that lands or a command the
    spec gains reaches every guard that reads this list without an edit here.
    Lives beside them rather than in one suite's module, because the README ban
    and the claim ban both rest on it and a test module importing another test
    module for a shared derivation is the shape this file exists to remove.
    """
    names = sorted(planned_commands() - set(shipped_commands()))
    assert len(names) >= 5, f"the spec documents almost nothing beyond this slice: {names}"
    return names


def sentence_digest(sentence: str) -> str:
    """A short stable digest of one sentence, whitespace flattened first.

    Truncated because this is a ledger key, not a signature: the file it keys is
    in the repository beside the documents it describes, and a reviewer reading
    a diff needs a column narrow enough to sit beside the sentence's own words.
    """
    return hashlib.sha256(collapse(sentence).strip().encode("utf-8")).hexdigest()[:16]


def reviewed_wording_line(surface: str, sentence: str) -> str:
    """The ledger line that records one sentence as reviewed.

    Printed by the failing test, so answering the failure needs no tool: the
    reviewer reads the sentence in the output, decides whether it is true of the
    code as built, and pastes the line. Nothing can stop someone pasting without
    reading; what this buys is that the sentence lands in a commit diff where the
    next reader sees it.
    """
    flat = collapse(sentence).strip()
    return f"{surface}\t{sentence_digest(flat)}\t{flat[:88]}"


@lru_cache(maxsize=None)
def reviewed_wording() -> dict[str, tuple[tuple[str, str], ...]]:
    """The talk wording a human reviewed: surface -> ((digest, opening words), ...).

    Why a ledger and not another equality pin. The ban above cannot see a
    sentence that names nothing, and the five strings pinned in the suites cover
    five strings: a paraphrase moved one line outside them ("the rug-pull scanner
    already flags a removed wrapper today", as section 2 prose, as a table cell,
    as an on-screen caption) passes everything. There is no pattern that
    separates a false capability claim from a true one, because the difference is
    the system's behaviour and not the sentence's shape. What is finite is the
    set of sentences a reviewer has signed, so the closed vocabulary sits on the
    escape hatch exactly as it does for UNBUILT_MARKER, and any other sentence in
    a talk surface fails until a human puts it here.

    The digest is what the check compares; the opening words are what makes the
    diff of this file readable, so a commit that changes talk wording shows which
    sentence changed to whoever reviews the commit. That visibility is the whole
    mechanism. Recording a line without reading the sentence defeats it, and no
    test can catch that.

    Format, one reviewed sentence per line, tab separated:

        <surface>\t<16 hex digest>\t<the first words of the sentence>

    Lines starting with # and blank lines are comments. Duplicates are kept: a
    sentence that appears twice in a surface has two lines, so deleting one copy
    fails.
    """
    assert REVIEWED_WORDING.exists(), (
        f"{REVIEWED_WORDING.name} is missing. It is the record of which talk "
        "sentences a human reviewed, and without it every talk surface is "
        "unguarded against a reworded claim.")
    found: dict[str, list[tuple[str, str]]] = {}
    ledger = REVIEWED_WORDING.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(ledger, 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        assert len(parts) == 3, (
            f"{REVIEWED_WORDING.name} line {number} is not three tab-separated fields")
        surface, digest, _stem = parts
        assert re.fullmatch(r"[0-9a-f]{16}", digest), (
            f"{REVIEWED_WORDING.name} line {number} has no digest: {digest!r}")
        found.setdefault(surface, []).append((digest, parts[2]))
    assert found, f"{REVIEWED_WORDING.name} records no reviewed sentence at all"
    return {surface: tuple(entries) for surface, entries in found.items()}


def unreviewed_wording(surface: str, sentences: list[str]) -> tuple[list[str], list[str]]:
    """(sentences no reviewer recorded, reviewed sentences the surface has lost).

    Both directions are load-bearing. The first is a reworded or added claim; the
    second is a reviewed claim deleted, which is how a disclaimer goes missing.
    Multiplicity counts, order does not: moving a bullet is not a claim change,
    deleting one of two identical sentences is.
    """
    recorded = reviewed_wording().get(surface)
    assert recorded, (
        f"{REVIEWED_WORDING.name} records nothing for {surface!r}, so every "
        "sentence of that surface would read as unreviewed. Add its lines, or "
        "remove the surface from the check in the same commit.")
    have = Counter(sentence_digest(s) for s in sentences)
    want = Counter(digest for digest, _stem in recorded)
    surplus = have - want
    new = []
    for sentence in sentences:
        digest = sentence_digest(sentence)
        if surplus[digest]:
            surplus[digest] -= 1
            new.append(sentence)
    missing = want - have
    gone = [f"{digest} {stem}" for digest, stem in recorded if missing[digest]]
    return new, sorted(set(gone))


@lru_cache(maxsize=None)
def defined_callables() -> frozenset[str]:
    """Every function, method and class name this repository defines, plus the
    Python builtins.

    Walked with `ast` over the repository's own source, the same principle
    shipped_commands() applies to the CLI parser: ground truth for what exists
    comes out of the code, not out of a list here that would be wrong the first
    time somebody lands a function. The builtins are in the set because
    `len(...)` appears in the design documents and is built.

    A file that will not parse is skipped rather than failing the walk, so a
    half-written module in another lane cannot turn this into a red suite. The
    oracle floor test is what catches a walk that stopped finding anything.
    """
    names = set(dir(builtins))
    for path in walk(".py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
    return frozenset(names)


def code_referents(unit: str) -> list[tuple[str, str, bool]]:
    """(kind, name, built) for every name in `unit` written as code.

    Two notations, because the repository names code two ways: a command is
    written the way it is invoked, and a callable is written the way it is
    called. Neither branch requires backticks, which is the hole a
    backtick-anchored pattern leaves.

    Whether the name is built is answered by the three derived oracles and
    nothing else. Whether the sentence *asserts* anything is not answered here
    at all, because no pattern can enumerate that.
    """
    planned = planned_commands()
    shipped = frozenset(shipped_commands())
    defined = defined_callables()
    found: list[tuple[str, str, bool]] = []
    for mention in CXBOM_INVOCATION.finditer(unit):
        pair = f"{mention.group(1)} {mention.group(2)}" if mention.group(2) else None
        name = pair if pair in planned else mention.group(1)
        if name in planned:
            found.append(("command", name, name in shipped))
    for span in CODE_SPAN.finditer(unit):
        content = span.group(1).strip()
        # A span that is exactly a command name is a command mention with the
        # `cxbom` left off, which is how the guardrails corrections write it.
        if content in planned:
            found.append(("command", content, content in shipped))
        for call in SPAN_CALL.finditer(content):
            found.append(("callable", call.group(1),
                          call.group(1).rsplit(".", 1)[-1] in defined))
    for call in BARE_CALL.finditer(CODE_SPAN.sub(" ", unit)):
        found.append(("callable", call.group(1),
                      call.group(1).rsplit(".", 1)[-1] in defined))
    return found


def unbuilt_referents(unit: str) -> list[tuple[str, str]]:
    """Every name in `unit` that this repository's own code says does not exist."""
    return [(kind, name) for kind, name, built in code_referents(unit) if not built]


def unbuilt_claim_offences(units: list[str]) -> list[tuple[str, str, str]]:
    """Every unit that names a thing this repository has not built, with no
    not-yet-built marker in that same unit.

    No verb list. The check this replaced gated on the one verb a caption had
    used, `detects`, and everything else walked through: an acceptance paragraph
    saying `cxbom scan` exits 1, an open item saying `cxbom gate` exits 0, and
    two guardrail corrections saying `scan` and `guard` detect a removed wrapper
    were all live while that gate passed. A finite verb list cannot close the
    class for the same reason a finite TLD list could not close its own.

    Scoped to one unit, never across two. Within one sentence a marker covers
    every name it holds, because the alternative -- one marker per name --
    makes an honest sentence about two commands read "`scan` (not in slice 1)
    and `guard` (not in slice 1)", and a guard that forces prose nobody will
    write is a guard somebody switches off. Two different unbuilt names in one
    sentence with one marker between them is the residual, and it is a
    reviewer's job.

    Returns (kind, name, unit) triples so a caller can name exactly what failed.
    """
    found: list[tuple[str, str, str]] = []
    for unit in units:
        referents = unbuilt_referents(unit)
        if referents and not UNBUILT_MARKER.search(unit):
            found += [(kind, name, unit) for kind, name in sorted(set(referents))]
    return found


def stale_marker_offences(units: list[str]) -> list[tuple[str, str]]:
    """Every unit whose not-yet-built marker sits beside a command that now ships.

    The other direction of the same ban, and the reason the ban is allowed to
    say a command drops out of it on its own when it lands. It only drops out
    cleanly if the marker beside it goes too: a sentence reading that
    `cxbom gate` is not in slice 1, on a branch where `gate` ships, is as wrong
    as the unmarked claim was, and it is wrong on screen.

    Scoped to commands. A marker in these documents is always about a command or
    a contract version, and a sentence that happens to mention `len(...)` beside
    one is not making a claim about `len`. Returns (name, unit) pairs.
    """
    found: list[tuple[str, str]] = []
    for unit in units:
        if not UNBUILT_MARKER.search(unit):
            continue
        commands = {(name, built) for kind, name, built in code_referents(unit)
                    if kind == "command"}
        if commands and all(built for _, built in commands):
            found += [(name, unit) for name, _ in sorted(commands)]
    return found


def attribution_text(path: Path) -> str:
    """The document with its code fences cut and nothing else.

    What an attribution and its pinned passage are read from. Not prose_text:
    that masks every quotation inside the guardrails section, and both
    attributed passages sit in that section, so a quoted overclaim written into
    one ("The rug-pull scanner already flags a removed wrapper today.") was
    invisible to every guard that read the masked copy. A quotation the narrator
    reads out is part of the passage whatever the quote marks mean to the claim
    ban.
    """
    return FENCED_BLOCK.sub("\n", path.read_text(encoding="utf-8"))


def attribution_pairs(path: Path) -> list[tuple[str, str]]:
    """(previous sentence, sentence) for every sentence, never crossing a unit.

    An attribution binds the sentence in front of it, so the check needs the
    pair, and the unit boundary is what keeps a quote in one table cell from
    being read as the quote a claim in the next row is attributing.
    """
    pairs: list[tuple[str, str]] = []
    for unit in prose_units(attribution_text(path)):
        sentences = [s.strip() for s in SENTENCE_BREAK.split(unit) if s.strip()]
        pairs += list(zip([""] + sentences, sentences))
    return pairs


def claims_about_its_source(sentence: str) -> bool:
    """Whether a sentence claims something checkable about the words in front of it."""
    return bool(EXACTNESS_CLAIM.search(sentence) or MARKER_CLAIM.search(sentence))


def attributed_units(path: Path) -> list[str]:
    """Every prose unit that holds a sentence claiming something about its source.

    Keyed on the claim, through claims_about_its_source, not on a phrasing of the
    attribution. A passage joins the set by making the claim, however it names
    its source, so "Quoted from section 17, word for word." is found where the
    two-phrase list it replaced ("Section N wording", "Correction slide") was
    blind to it. What stays outside: an attribution that claims neither
    exactness nor a marker ("Taken from section 17."). It makes no claim these
    guards can resolve, and the reviewed-wording ledger is what sees it change.
    """
    return [unit for unit in prose_units(attribution_text(path))
            if any(claims_about_its_source(s) for s in SENTENCE_BREAK.split(unit))]


def correction_section_number() -> int:
    """The section number of the talk-slide correction, read from the headings.

    A claim naming the slide rather than a number resolves through here, so
    renumbering the spec moves the guard instead of silently pointing it at
    whatever section 17 becomes.
    """
    match = CORRECTION_HEADING.search(TOOL_SPEC.read_text(encoding="utf-8"))
    assert match is not None, "tool.md no longer has a correction-to-the-abstract section"
    return int(match.group(1))


def last_cell(sentence: str) -> str:
    """The sentence without the table-row cells in front of it.

    A table row is one unit, so the first sentence of an answer cell carries the
    question cell with it ("| q | CxBOM does not prevent them."). Compared as it
    stands, a true quotation in an answer cell could never be found in its
    source, and the exactness check would refuse it for the row around it.
    """
    return sentence.strip(" |").rsplit(" | ", 1)[-1].strip()


def attribution_offences(path: Path) -> list[tuple[str, str, str]]:
    """(what is wrong, previous sentence, claiming sentence) for every claim that fails.

    Two claims, two resolutions. A slice 1 marker claim means the sentence in
    front carries "not in slice 1". An exactness claim means that sentence
    appears character for character in the tool-spec section the claim names,
    by number or as the correction slide, and a claim naming neither is an
    offence rather than a skip.

    No count floor. A floor of two attributions per document was retired by a
    third legitimate one, after which deleting an original went unseen here.
    Deletion is a wording change, so the equality pin on attributed_units and the
    reviewed-wording ledger are what catch it.

    One implementation, called by both suites and by their fixtures, so a
    fixture exercises the mechanism the documents are checked with.
    """
    found: list[tuple[str, str, str]] = []
    spec = TOOL_SPEC.read_text(encoding="utf-8")
    for previous, sentence in attribution_pairs(path):
        exact = EXACTNESS_CLAIM.search(sentence)
        marker = MARKER_CLAIM.search(sentence)
        if not exact and not marker:
            continue
        if not previous:
            # SENTENCE_BREAK does not split after a closing quotation mark, so a
            # quotation followed by its attribution is one sentence with nothing
            # in front of it. Saying "nothing to attribute" there sends the
            # writer looking for a missing quotation that is on the same line.
            if last_cell(sentence).startswith('"'):
                found.append(("the quotation it attributes is in the same sentence, "
                              "because a closing quotation mark does not end a "
                              "sentence here: unquote it or put the attribution "
                              "after a sentence of its own", previous, sentence))
            else:
                found.append(("nothing in front of it to attribute", previous, sentence))
            continue
        if marker and not SLICE_1_MARKER.search(previous):
            found.append(("claims the slice 1 marker and the sentence in front has none",
                          previous, sentence))
        if not exact:
            continue
        number = SOURCE_SECTION.search(sentence)
        if number:
            source = int(number.group(1))
        elif SOURCE_SLIDE.search(sentence):
            source = correction_section_number()
        else:
            found.append(("claims exactness and names no source a test can resolve",
                          previous, sentence))
            continue
        if not re.search(rf"^## {source}\. ", spec, re.M):
            found.append((f"claims exactness against section {source}, which tool.md "
                          "does not have", previous, sentence))
        elif last_cell(previous) not in collapse(numbered_section(spec, source)):
            found.append((f"claims exactness and is not in section {source}",
                          previous, sentence))
    return found
