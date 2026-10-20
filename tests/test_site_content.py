"""Hand-written site text follows the anonymity and style rules.

Owner: ATACE Working Group.

spec/SPEC.md restates the paper's CxBOM section and appendix as a standalone
specification. It must not read as a paper, must not point into one, and must
not cite anyone by author name.

Every value checked here comes from a source outside the two documents: the
0.2.0 schema, the vendored reference record, or the site's own nav table. A
number typed into the prose and typed again here would be one mistake twice,
so the expected strings are built from those sources instead.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
sys.path.insert(0, str(ROOT / "scripts"))
from cxsite import links, render  # noqa: E402
import anon_check  # noqa: E402

SPEC = (ROOT / "spec/SPEC.md").read_text(encoding="utf-8")
LANDING = (ROOT / "site/content/landing.md").read_text(encoding="utf-8")
SCHEMA = json.loads((ROOT / "spec/cxbom-0.3.0.schema.json").read_text(encoding="utf-8"))
RECORD_BYTES = (ROOT / "site/data/session_reference.json").read_bytes()
RECORD = json.loads(RECORD_BYTES.decode("utf-8"))
DOCS = [("SPEC.md", SPEC), ("landing.md", LANDING)]

# The privacy sentence is a contract with the build test, which reads it back out
# of the rendered page, so it is pinned here as text rather than derived.
PRIVACY = ("This site sets no cookies, loads no third-party resources, and runs no "
           "analytics. Server access logs are kept at the host's default retention and are "
           "not examined.")
# The site links out only to the standards it maps to. Any other host is a leak
# risk while the paper is in double-blind review. Same list as the link gate's.
STANDARDS_HOSTS = links.STANDARDS_HOSTS
ALLOWED_HOSTS = links.ALLOWED_HOSTS
NUMBER_WORD = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight"}
# A token that reaches both documents, so a scan that finds nothing is a scan
# that ran, not a scan that silently had no denylist.
POSITIVE_CONTROL = "cyclonedx"
DENYLIST = anon_check.load_tokens(ROOT / anon_check.DENYLIST_NAME)


def _number_word(n: int) -> str:
    # A raw dict lookup raises KeyError past the table's range, which pytest
    # reports as a collection error, not a readable assertion failure. A
    # ninth component or catalog should fail this test with a reason, not
    # crash it.
    try:
        return NUMBER_WORD[n]
    except KeyError:
        pytest.fail(f"NUMBER_WORD has no entry for {n}; extend the table before this test can run")


def _prose(text: str) -> str:
    """The document minus fenced code, which house style does not govern."""
    return re.sub(r"```.*?```", "", text, flags=re.S)


def _flat(text: str) -> str:
    """One line, so a sentence checked here survives any prose line wrap."""
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    m = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    assert m, f"no section named {heading!r}"
    return m.group(1)


def _ticks(text: str) -> set[str]:
    # Line-bounded, so two separate code spans never pair across a paragraph.
    return set(re.findall(r"`([^`\n]+)`", text))


def _enum(definition: str, field: str) -> list[str]:
    return SCHEMA["definitions"][definition]["properties"][field]["enum"]


def _deref(node: dict) -> dict:
    while "$ref" in node:
        node = SCHEMA["definitions"][node["$ref"].rsplit("/", 1)[1]]
    return node


def _resolves(path: str) -> bool:
    """Walk a dotted field path through the schema, following $ref along the way."""
    node: dict = SCHEMA
    for part in path.split("."):
        properties = _deref(node).get("properties") or {}
        if part not in properties:
            return False
        node = properties[part]
    return True


def _schema_vocabulary() -> tuple[set[str], set[str]]:
    names: set[str] = set()
    values: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            names.update(node.get("properties") or {})
            if isinstance(node.get("enum"), list):
                values.update(str(v) for v in node["enum"])
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(SCHEMA)
    return names, values


STANDALONE_PATTERNS = [
    r"\bthis paper\b", r"\bwe\b", r"\bour\b", r"\\cite", r"\\ref", r"\bSection[~ ]\d",
    r"\bFigure\b", r"\bAppendix\b", r"\bet al\.", r"\(\s*[A-Z][a-z]+,\s*20\d\d\s*\)", r"arxiv", r"github",
    # An acknowledgements section is a leak class of its own: it names people
    # by role even when it does not name them outright.
    r"\backnowledg", r"\bthanks to\b",
]


# Two of the patterns above name a service rather than a paper convention, so
# they belong to every document, not only to the one held to a paper's voice.
# A repository or preprint host named as a bare word carries no dot, so the
# host-shape sweep further down cannot see it, and landing.md is not held to
# the voice rules ("we", "our", "this paper") that keep the rest of the list
# scoped to SPEC. Named as a subset of the list, and asserted to be one, so
# the two cannot drift apart.
IDENTIFYING_SERVICE_PATTERNS = (r"arxiv", r"github")


@pytest.mark.parametrize("pattern", STANDALONE_PATTERNS)
def test_spec_reads_as_a_standalone_specification(pattern):
    assert not re.search(pattern, SPEC, re.I), pattern


@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
@pytest.mark.parametrize("pattern", IDENTIFYING_SERVICE_PATTERNS)
def test_no_document_names_an_identifying_service(pattern, name, text):
    assert pattern in STANDALONE_PATTERNS, f"{pattern} left STANDALONE_PATTERNS"
    assert not re.search(pattern, text, re.I), f"{name}: {pattern}"


def test_identifying_service_patterns_still_carry_the_shapes_they_gate():
    # Neither document names either service, so the test above is a scan that
    # finds nothing. An emptied tuple would collect no cases at all and pass in
    # silence, so prove here that the list is populated and that each pattern
    # fires on the phrasing it exists to catch.
    assert IDENTIFYING_SERVICE_PATTERNS
    for pattern, leak in ((r"arxiv", "A preprint sits on arXiv as 2026.00000."),
                          (r"github", "The code is on GitHub.")):
        assert pattern in IDENTIFYING_SERVICE_PATTERNS
        assert re.search(pattern, leak, re.I), pattern


def test_standalone_patterns_cover_the_acknowledgements_leak_class():
    # The parametrized test above only proves SPEC avoids every pattern in
    # the list. Neither document has an acknowledgements section to catch,
    # so this proves the list still carries a pattern for that class, and
    # that the pattern actually fires on plausible phrasing rather than
    # sitting in the list unable to match anything.
    assert r"\backnowledg" in STANDALONE_PATTERNS
    assert r"\bthanks to\b" in STANDALONE_PATTERNS
    assert any(re.search(p, "## Acknowledgements", re.I) for p in STANDALONE_PATTERNS)
    assert any(re.search(p, "Thanks to our reviewers for their time.", re.I) for p in STANDALONE_PATTERNS)


@pytest.mark.parametrize("name,text", [("SPEC.md", SPEC), ("landing.md", LANDING)])
def test_house_style(name, text):
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    assert "—" not in prose, f"{name}: em dash"
    assert ";" not in prose, f"{name}: semicolon"
    for word in ("seamless", "robust", "leverage", "utilize", "comprehensive", "cutting-edge"):
        assert word not in prose.lower(), f"{name}: {word}"


SLOP_WORDS = ("unlock", "unleash", "empower", "transformative", "holistic", "ecosystem",
              "journey", "facilitate", "delve", "powerful", "effortless", "state-of-the-art",
              "best-in-class", "just", "very", "really", "actually", "certainly", "basically",
              "literally")
# "just-in-time" is standard vocabulary for a context-assembly spec. The
# hyphen still reads as a word boundary to \b, so the bare stem "just" would
# flag the compound as filler. Carve the compound out by name instead of
# loosening the boundary, which would let bare "just" back in as filler too.
ALLOWED_SLOP_COMPOUNDS = {"just": ("just-in-time",)}

# One suffix alternation shared by all twenty stems already produced a real
# collision: adding bare "ly" to catch "powerfully" also made "just" match
# "justly" ("fairly, with justice"), a word with no relation to the filler
# sense. A verb inflects differently from an adjective, which inflects
# differently from a word that never legitimately inflects at all, so the
# suffix set is scoped per stem instead of shared globally. An empty set
# means the stem matches only its own literal spelling, which is what stops
# the next accidental collision as this list grows: adding a word means
# choosing its own suffixes, not inheriting everyone else's.
SLOP_SUFFIXES: dict[str, str] = {
    "unlock": "s|ed|ing",
    "unleash": "es|ed|ing",
    "empower": "s|ed|ing|ment",
    "transformative": "",
    "holistic": "ally",
    "ecosystem": "s",
    "journey": "s",
    # These two drop a trailing "e" before a suffix is appended (below), so
    # "e" itself is listed to reconstruct the bare word, and "es"/"ed"/"ing"
    # reconstruct the inflections a dropped vowel would otherwise block
    # ("facilitating", "delving").
    "facilitate": "e|es|ed|ing",
    "delve": "e|es|ed|ing",
    "powerful": "ly",
    "effortless": "ly",
    "state-of-the-art": "",
    "best-in-class": "",
    "just": "",
    "very": "",
    "really": "",
    "actually": "",
    "certainly": "",
    "basically": "",
    "literally": "",
}


def _slop_pattern(word: str) -> str:
    suffixes = SLOP_SUFFIXES[word]
    # Only drop the trailing "e" when a suffix is actually listed to
    # reconstruct it afterward. A word with no suffix at all (e.g.
    # "transformative") keeps its own spelling as the only thing it matches.
    stem = word[:-1] if suffixes and word.endswith("e") else word
    optional = rf"(?:{suffixes})?" if suffixes else ""
    # The leading boundary keeps "every" out of "very".
    return rf"\b{re.escape(stem)}{optional}\b"


def _has_slop(word: str, prose: str) -> bool:
    for compound in ALLOWED_SLOP_COMPOUNDS.get(word, ()):
        prose = re.sub(re.escape(compound), "", prose, flags=re.I)
    return bool(re.search(_slop_pattern(word), prose, re.I))


@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
def test_no_marketing_or_filler_words(name, text):
    prose = _prose(text)
    for word in SLOP_WORDS:
        assert not _has_slop(word, prose), f"{name}: {word}"


@pytest.mark.parametrize("stem,mutant", [
    ("facilitate", "facilitating"),
    ("delve", "delving"),
    ("powerful", "powerfully"),
    ("holistic", "holistically"),
    ("empower", "empowerment"),
])
def test_slop_pattern_catches_inflections_the_narrower_suffix_set_missed(stem, mutant):
    # The first four are exactly the inflections the original suffix set
    # (s|es|ed|d|ing|ment) could not reach: the gerund re-adds a vowel the
    # stem dropped, and the adverb suffix ("ly", "ally") was never in the set
    # at all. "empowerment" pins the pre-existing "ment" branch, which this
    # rewrite carries forward unchanged. Neither document contains any of
    # these words, so only a direct probe against the pattern, not a scan of
    # committed prose, can catch a regression here.
    assert _has_slop(stem, f"this text contains {mutant} somewhere")


@pytest.mark.parametrize("stem,mutant", [
    ("ecosystem", "ecosystems"),
    ("journey", "journeys"),
])
def test_slop_pattern_catches_the_plural_of_a_singular_metaphor(stem, mutant):
    # Same filler sense, plural form. A mutation sweep of the per-stem table
    # found these two suffixes were the only ones in SLOP_SUFFIXES with no
    # probe backing them: dropping "s" from either entry left every existing
    # test green. Neither word appears in either document, so, matching the
    # style of the inflection probes above, this is a direct probe against
    # the pattern rather than a scan of committed prose.
    assert _has_slop(stem, f"this text contains {mutant} somewhere")


@pytest.mark.parametrize("word", SLOP_WORDS)
def test_slop_pattern_matches_the_bare_word_with_no_inflection(word):
    # The suffix group is optional, so the literal filler word by itself,
    # with no inflection at all, must still match. This is the base case an
    # inflection-only proof (above) cannot exercise.
    assert _has_slop(word, f"the draft states {word} plainly")


def test_slop_pattern_does_not_flag_very_inside_every():
    # The leading \b keeps "every" out of "very": the boundary fails because
    # the preceding "e" is a word character.
    assert not _has_slop("very", "every one of these components")


def test_just_stem_does_not_match_the_unrelated_word_justly():
    # "justly" means "fairly, with justice", a sense with nothing to do with
    # the filler "just" this list bans. Before the per-stem suffix table,
    # "ly" was one of ten suffixes shared by every stem, so "just" + "ly"
    # matched this real, unrelated word. "just" now has an empty suffix set,
    # so \bjust\b never extends past the bare word: "t" and "l" are both
    # word characters, so the trailing boundary fails inside "justly".
    assert not _has_slop("just", "The court ruled justly on a matter of contract law.")


def test_just_in_time_allowance_does_not_hide_bare_just_as_filler():
    # The allowed compound alone must pass...
    assert not _has_slop("just", "The pipeline performs just-in-time retrieval of tool definitions.")
    # ...but the allowance is scoped to that compound, not to "just" generally.
    assert _has_slop("just", "The pipeline is just a wrapper around retrieval.")


def test_spec_names_the_schema_url_and_the_maintainer():
    assert "`https://cxbom.org/schema/0.3.0/cxbom.schema.json`" in SPEC
    assert "Maintained by the ATACE Working Group." in SPEC
    assert SPEC.count("\n# ") + SPEC.startswith("# ") == 1


# The versioned segment of the schema's own $id, so this pattern tracks the
# schema instead of restating it. Case-insensitive: a scheme or host typed in
# another case is the same URL to a browser, so the scan has to come back with
# it and let the set comparison reject it, rather than miss it and leave the
# set looking clean.
_SCHEMA_URL_PATTERN = (r"(?i)" + re.escape(SCHEMA["$id"].rsplit("/", 2)[0])
                       + r"/\S*?" + re.escape(SCHEMA["$id"].rsplit("/", 1)[-1]))


def _served_schema_urls(text: str) -> set[str]:
    return set(re.findall(_SCHEMA_URL_PATTERN, text))


def _stale_schema_url() -> str:
    base, _version, name = SCHEMA["$id"].rsplit("/", 2)
    return f"{base}/0.0.0/{name}"


def test_both_documents_name_the_schema_s_own_id():
    schema_id = SCHEMA["$id"]
    for name, text in DOCS:
        assert f"`{schema_id}`" in text, name
        # No stale version may hide next to the current one.
        served = _served_schema_urls(text)
        assert served == {schema_id}, f"{name}: {served}"


@pytest.mark.parametrize("spelling", [str, str.upper, lambda s: s.replace("https", "HtTpS")])
def test_stale_schema_url_scan_reads_a_url_however_its_scheme_is_cased(spelling):
    # Neither document carries a stale URL, so the scan above finds nothing and
    # cannot prove it would. A direct probe can: a superseded version has to
    # come back from the scan whatever case it was typed in, because coming
    # back is what makes the set comparison fail.
    stale = spelling(_stale_schema_url())
    assert _served_schema_urls(f"An early draft pointed at `{stale}`.") == {stale}
    assert stale != SCHEMA["$id"]


@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
def test_headings_are_one_h1_then_level_two_sections(name, text):
    # The spec page numbers h2 headings as sections, so a deeper heading would
    # render as an unnumbered orphan, and the build refuses a second h1.
    levels = [len(m.group(1)) for m in re.finditer(r"^(#{1,6}) \S", _prose(text), re.M)]
    assert levels[0] == 1, name
    assert levels.count(1) == 1, name
    assert set(levels[1:]) == {2}, f"{name}: {sorted(set(levels[1:]))}"


def test_record_structure_table_lists_every_required_top_level_field():
    assert _ticks(_section(SPEC, "Record structure")) == set(SCHEMA["required"])


def test_trust_model_table_matches_the_schema_tiers_and_the_record_rings():
    body = _section(SPEC, "Trust model")
    rings = {r["designation"]: int(r["ring"]) for r in RECORD["trustModel"]["rings"]}
    expected = {(ring, name) for name, ring in rings.items()}
    for tier in _enum("contextComponent", "trustTier"):
        if tier in rings:
            continue
        # A tier the trust model derives names its own ring, as `ring-1-derived` does.
        m = re.fullmatch(r"ring-(\d)-\w+", tier)
        assert m, f"{tier} does not name its ring"
        expected.add((int(m.group(1)), tier))
    rows = {(int(r), t) for r, t in re.findall(r"^\| (\d) \| `([a-z0-9-]+)` \|", body, re.M)}
    assert rows == expected


def test_component_type_list_is_exactly_the_schema_enum():
    m = re.search(r"The component types are ([^.]+)\.", _section(SPEC, "Context components"), re.S)
    assert m, "no component type sentence"
    assert _ticks(m.group(1)) == set(_enum("contextComponent", "type"))


def test_finding_severities_are_exactly_the_schema_enum():
    m = re.search(r"a severity \(([^)]*)\)", _section(SPEC, "Findings and the audit gate"), re.S)
    assert m, "no severity list"
    assert _ticks(m.group(1)) == set(_enum("finding", "severity"))


def test_catalog_section_counts_the_hashed_pins_and_names_the_pointer():
    catalogs = SCHEMA["properties"]["catalogVersions"]
    hashed = {k for k, v in catalogs["properties"].items() if v.get("$ref", "").endswith("catalogPinHashed")}
    pointers = {k for k, v in catalogs["properties"].items() if v.get("$ref", "").endswith("catalogPinPointer")}
    assert hashed == set(catalogs["required"])
    body = _section(SPEC, "Catalog pins")
    assert f"Each of the {_number_word(len(hashed))} carries a content hash" in _flat(body)
    assert pointers == {"cyclonedx"} and "CycloneDX appears as a pointer" in _flat(body)
    pinned = RECORD["catalogVersions"]
    assert f"CycloneDX {pinned['cyclonedx']['version']}" in _flat(SPEC)
    for key, label in (("owaspLlm", "OWASP Top 10 for LLM Applications"),
                       ("owaspAgentic", "OWASP Top 10 for Agentic Applications")):
        assert f"{label} {pinned[key]['version']}" in _flat(SPEC), key


def test_spec_token_accounting_matches_the_reference_record():
    assert "46,205 tokens: 46,192 in six components\nand 13 of template overhead" in SPEC


def test_spec_token_numbers_come_from_the_reference_record():
    summary = RECORD["sessionSummary"]
    used = RECORD["metadata"]["session"]["contextWindowTokensUsed"]
    assert used == summary["totalContextTokens"] + summary["templateOverheadTokens"]
    # _flat() collapses the prose's own line wrap, so a reflow of this
    # sentence that keeps the numbers right does not fail on whitespace alone.
    assert (f"uses {used:,} tokens: {summary['totalContextTokens']:,} in "
            f"{_number_word(len(RECORD['contextComponents']))} components "
            f"and {summary['templateOverheadTokens']} of template overhead.") in _flat(SPEC)
    # The record is served as a page-sized file, so round to whole KB.
    assert f"about {round(len(RECORD_BYTES) / 1000)} KB" in SPEC


def test_number_word_fails_cleanly_past_its_table():
    with pytest.raises(pytest.fail.Exception, match="no entry for 9"):
        _number_word(9)


def test_token_formula_is_the_schema_s_own_formula():
    formula = SCHEMA["properties"]["sessionSummary"]["properties"]["templateOverheadTokens"]["description"]
    formula = formula.split(". ", 1)[1].rstrip(".")
    assert formula == "contextWindowTokensUsed = totalContextTokens + templateOverheadTokens"
    assert f"```\n{formula}\n```" in SPEC


def test_every_backticked_term_is_schema_vocabulary():
    names, values = _schema_vocabulary()
    for term in _ticks(_prose(SPEC)) | _ticks(_prose(LANDING)):
        if "://" in term:
            assert term == SCHEMA["$id"], term
        elif "." in term:
            assert _resolves(term), f"{term} does not resolve in the schema"
        else:
            assert term in names or term in values, f"{term} is not a schema field or value"


def _published_schema_paths() -> set[str]:
    # The published schema artifacts are valid link targets even though they are
    # not nav items. They live in the JSON-only /schema/* namespace (served as
    # application/schema+json with no HTML shell, enforced by live_check), so the
    # nav must never point a reader into it; a doc may still link to one as a
    # download. Derived from the lock so a newly locked version is covered too.
    lock = json.loads((ROOT / "spec/published.lock.json").read_text(encoding="utf-8"))
    return {urlsplit(e["servedAt"]).path for n, e in lock.items()
                if n != "vendored" and "servedAt" in e}


def test_nav_never_strands_a_reader_in_the_json_only_schema_namespace():
    # A nav link into /schema/* drops the reader onto raw JSON with no nav and no
    # way back (the bug this pins). The schema stays one click away as a download
    # from the reference page; it is never itself a top-nav destination.
    offenders = [href for href, _ in render.NAV if href.startswith("/schema/")]
    assert not offenders, f"nav links into the JSON-only /schema/* namespace: {offenders}"


def test_schema_is_reachable_through_a_nav_item_labelled_schema():
    # The schema's HTML home is the reference page; the nav reaches it under the
    # label the audience looks for ("Schema"), pointing at the HTML page rather
    # than the raw /schema/* artifact.
    assert ("/reference/", "Schema") in render.NAV


@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
def test_site_links_point_at_pages_the_nav_serves(name, text):
    served = {href for href, _ in render.NAV} | {"/"} | _published_schema_paths()
    links = set(re.findall(r"\]\((/[^)\s]*)\)", text))
    assert links, f"{name}: no site links"
    assert links <= served, f"{name}: {sorted(links - served)}"


ALLOWED_MAILTO_HREFS = frozenset({"mailto:spec@cxbom.org"})


def _mailto_hrefs(text: str) -> set[str]:
    # Case-insensitive on the scheme. A "MAILTO:" href is a mail href, and the
    # allowance is a set of exact strings, so a differently cased spelling is
    # not in it and fails the gate rather than slipping past the pattern.
    return set(re.findall(r"(?i)mailto:[^)\s]+", text))


def _mailto_hrefs_within_allowance(text: str) -> bool:
    # A set comparison, not a list-shape check, so a second legitimate
    # mailto:spec@cxbom.org does not fail this on repetition alone. Shared by
    # the document gate and the two probes below, so mutating this one
    # definition, not just the doc-facing call site, is what the probes
    # below are pinned against.
    return _mailto_hrefs(text) <= ALLOWED_MAILTO_HREFS


# ---------------------------------------------------------------------------
# Hosts and addresses.
#
# A hostname reaches a built page in more shapes than a lower-case "https://"
# link: a protocol-relative "//host/path" with no scheme at all, an upper-case
# "HTTPS://", credentials in the authority, a percent- or entity-encoded
# separator, and whitespace typed around a dot. Rounds 1 and 2 gated the
# bare-host sweep on a list of TLDs ("com|net|org|edu|io|ai|dev"), which is
# fail-open by construction: a host whose TLD is not on the list is never
# matched at all. No such list can be finished either. IANA delegates new TLDs
# continuously, and a multi-label suffix such as "ac.uk" or "co.jp" cannot
# match a single-label alternation however long the list grows, so
# "//leaking-identity.ac.uk/profile" passed every gate in this file.
#
# So the design is inverted. Recognise the broad host *shape*, a dotted label
# sequence, and permit only what this project is demonstrably allowed to
# write. An unrecognised host is flagged, not skipped, which is the right
# default here: a false positive is a test failure that names the token, and a
# false negative is an identity disclosure in a double-blind submission.
#
# The matcher itself moved to site/cxsite/links.py when the publication link
# gate needed the same decision over built pages instead of source Markdown.
# One matcher, one place: a second copy would drift from the first, and the
# failure mode of a drifted host matcher is a disclosure. The names below are
# bound back to module scope so the tests read as they did when it lived here.
_CANONICAL_AUTHORITY = links.CANONICAL_AUTHORITY
_decoded = links.decoded
_link_authorities = links.link_authorities


@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
def test_external_links_name_only_standards_bodies(name, text):
    hosts = _link_authorities(text)
    assert hosts <= ALLOWED_HOSTS, f"{name}: {sorted(hosts - ALLOWED_HOSTS)}"
    assert _mailto_hrefs_within_allowance(text), name


@pytest.mark.parametrize("leak", [
    # Upper-case scheme: the old "https?://" pattern is case-sensitive, so
    # this reference was invisible to the host allowlist entirely, and the
    # bare sweep caught it only when the TLD happened to be on its list.
    "HTTPS://leaking-identity.ac.uk/profile",
    "HtTp://leaking-identity.ac.uk/profile",
    # No scheme at all, so there is no "https?://" for the old pattern to find.
    "//leaking-identity.ac.uk/profile",
    # Credentials: a URL parser resolves this to the permitted host, but the
    # identifying host is typed into the document all the same.
    "https://leaking-identity.ac.uk@owasp.org/",
    # A permitted host on a port is not the permitted host.
    "https://owasp.org:8443/x",
    # Encoded separators, which the page's own decoders undo.
    "https://leaking-identity%2Eac%2Euk/x",
    "https://leaking-identity&#46;ac&#46;uk/x",
])
def test_link_gate_reads_every_shape_that_carries_an_authority(leak):
    assert not _link_authorities(f"See [x]({leak}) for details.") <= ALLOWED_HOSTS


def test_link_gate_still_accepts_the_documents_own_references():
    for host in sorted(ALLOWED_HOSTS):
        assert _link_authorities(f"See <https://{host}/path>.") <= ALLOWED_HOSTS


def test_mailto_gate_tolerates_a_repeated_legitimate_address():
    text = "Write to [a](mailto:spec@cxbom.org) or write again to [b](mailto:spec@cxbom.org)."
    assert _mailto_hrefs_within_allowance(text)


def test_mailto_gate_still_catches_a_second_address():
    text = "Write to [a](mailto:spec@cxbom.org) or [b](mailto:other@cxbom.org)."
    assert not _mailto_hrefs_within_allowance(text)


@pytest.mark.parametrize("scheme", ["MAILTO", "MailTo"])
def test_mailto_gate_catches_an_address_whose_scheme_is_cased_differently(scheme):
    # A mail href is a mail href however its scheme is spelled. The allowance is
    # a set of exact strings, so a differently cased spelling is not in it and
    # fails the gate, but only if the scan sees the href at all.
    assert not _mailto_hrefs_within_allowance(f"Write to [b]({scheme}:other@cxbom.org).")


ALLOWED_BARE_EMAILS = frozenset({"spec@cxbom.org"})
# A dotted label sequence and nothing else: no TLD alternation, no trailing
# lookahead, no leading "@" exclusion. Dropping "@" from the lookbehind is what
# makes the host inside "user@host" visible to this sweep; the address this
# project is allowed to write is blanked by name before the sweep runs, so its
# own contact line is not a finding. "_" stays in the label class even though
# DNS forbids it, so a token like "session_reference.json" is recognised and
# then has to be permitted deliberately rather than silently skipped.
_BARE_HOST_PATTERN = r"(?<![\w.-])[\w-]+(?:\.[\w-]+)+(?![\w-])"
_BARE_EMAIL_PATTERN = r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"
# Whitespace typed around a separator, so "reviewer-lab .example.net" reads
# back as one host. Prose never puts whitespace *before* a period, so that side
# joins unconditionally (neither document contains a single instance). The other
# side is every sentence boundary in the document ("inference. Orchestration"),
# so it joins only where the next label starts lower-case, which no sentence in
# either document does. Both run before any lower-casing, because the capital
# is the whole signal that separates a sentence boundary from a split host.
_JOIN_BEFORE_SEPARATOR = re.compile(r"\s+([.@])")
_JOIN_AFTER_SEPARATOR = re.compile(r"([.@])\s+(?=[a-z0-9])")
# A bracketed separator, which is the defanging habit a security document
# reaches for ("reviewer-lab[.]example[.]net"). No browser reconstructs this
# one, but every reader does, and a reader is who breaks double-blind review.
# Only the punctuation forms: substituting the *word* ("x dot y", "x at y")
# opens an unbounded vocabulary, and unbracketed word forms would join ordinary
# prose into host-shaped tokens ("looks at the" into "looks.the"), so those stay
# out deliberately and are recorded as a residual rather than half-listed.
_DEFANGED_SEPARATOR = re.compile(r"[\[({]\s*([.@])\s*[\])}]")
# The schema's own file name is host-shaped ("cxbom.schema.json"), and both
# documents link to it. Derived from the schema's $id rather than typed, like
# every other expected value in this file.
SCHEMA_FILE_NAME = urlsplit(SCHEMA["$id"]).path.rsplit("/", 1)[-1]


def _prepared(text: str) -> str:
    """Decode, then close what was put around a separator. Shared by both sweeps."""
    text = _DEFANGED_SEPARATOR.sub(r"\1", _decoded(text))
    text = _JOIN_BEFORE_SEPARATOR.sub(r"\1", text)
    return _JOIN_AFTER_SEPARATOR.sub(r"\1", text)


def _without_markup(text: str) -> str:
    # Strip the markup a legitimate link or address lives inside, so what
    # remains is prose the link and mailto gates above never look at. Only the
    # scheme'd *authority* goes, not the whole reference: the path and query a
    # link carries are prose as far as this sweep is concerned, so a host
    # smuggled into a query string stays visible. Only the canonical lower-case
    # scheme is stripped (see _CANONICAL_AUTHORITY); a protocol-relative or
    # oddly cased reference is left for the sweep to flag, and
    # _link_authorities holds every one of those shapes to the permitted-host
    # list independently.
    text = _CANONICAL_AUTHORITY.sub("", _prepared(text))
    return re.sub(r"\(mailto:[^)]*\)", "", text)


def _permitted_non_host(token: str) -> bool:
    """True for a host-shaped token that is demonstrably not a hostname.

    The bare sweep permits no host at all, not even one on ALLOWED_HOSTS: a
    scheme'd link to a standards body is the link gate's business, and an
    unlinked mention is a host typed into the prose either way. What this
    allowance covers is the shapes that are not hosts. Each test is derived or
    structural, never an enumeration of names, so the allowance cannot grow
    into another list that has to keep up with the world.
    """
    labels = token.split(".")
    if all(label.isascii() and label.isdigit() for label in labels):
        # An all-digit label sequence is not a DNS name, so it is a version
        # number ("0.2.0", "1.6"), except at IPv4's four-octet shape, which is
        # a host address and stays flagged.
        return len(labels) != 4
    # A dotted field path that walks the schema is the spec's own vocabulary,
    # checked against the schema itself (case-sensitive, as the schema is).
    return _resolves(token) or token.lower() == SCHEMA_FILE_NAME.lower()


def _bare_hosts(text: str) -> set[str]:
    prose = _without_markup(text)
    for address in sorted(ALLOWED_BARE_EMAILS):
        # Whole-token only. A bare prefix replacement would shorten
        # "spec@cxbom.org.evil.example" into something the sweep no longer
        # recognises, which is the fail-open mistake this rewrite exists to
        # remove. _bare_emails keeps its own allowance by subtraction instead,
        # so this blanking is scoped to the host sweep.
        prose = re.sub(rf"(?i)(?<![\w.@-]){re.escape(address)}(?![\w.-])", "", prose)
    return {t.lower() for t in re.findall(_BARE_HOST_PATTERN, prose) if not _permitted_non_host(t)}


def _bare_emails(text: str) -> set[str]:
    return set(re.findall(_BARE_EMAIL_PATTERN, _without_markup(text), re.I))


@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
def test_no_bare_host_or_email_outside_a_link(name, text):
    # .anon-tokens only catches a token someone already thought to list. A
    # hostname or address typed as plain prose, with no https:// scheme and
    # no mailto: wrapper, passes every other gate in this file. This is the
    # gate for that shape.
    hosts = _bare_hosts(text)
    assert not hosts, f"{name}: bare host(s) outside a link: {sorted(hosts)}"
    emails = _bare_emails(text) - ALLOWED_BARE_EMAILS
    assert not emails, f"{name}: bare email(s) outside a mailto link: {sorted(emails)}"


@pytest.mark.parametrize("leak,host", [
    ("Contact the reviewer at reviewer-lab.example.net for details.", "reviewer-lab.example.net"),
    # Every host in ALLOWED_HOSTS is a .org host, so the TLD this project
    # actually uses is the one that most needs its own probe here.
    ("The mirror also lives at reviewer-lab.example.org for now.", "reviewer-lab.example.org"),
    # Protocol-relative: no "http"/"https" scheme at all, so the URL strip
    # never sees it, and the trailing "/track" is exactly the shape the
    # dropped lookahead used to wave through unflagged.
    ("See //evil-lab.example.net/track for details.", "evil-lab.example.net"),
    # Same shape, against a host that would otherwise be on the allowlist.
    # The allowlist governs scheme'd links
    # (test_external_links_name_only_standards_bodies); a bare, unlinked
    # mention gets no exemption for naming an approved host.
    ("The standard also appears at //cyclonedx.org/spec in some drafts.", "cyclonedx.org"),
])
def test_bare_host_sweep_catches_a_hostname_with_no_protocol(leak, host):
    assert _bare_hosts(leak) == {host}


def test_bare_host_sweep_catches_a_protocol_relative_host_with_no_trailing_path():
    # Same missing scheme, no trailing path this time. This case was already
    # caught before the lookahead was dropped (nothing followed the host but
    # a space), so it is a no-regression check on the fix above, not new
    # coverage.
    assert _bare_hosts("A stray reference reads //cxbom.org with nothing after it.") == {"cxbom.org"}


@pytest.mark.parametrize("leak,host", [
    # The shape that proved the TLD list could never work. Rounds 1 and 2 both
    # returned an empty set here: ".uk" is not on the list, and ".ac.uk" cannot
    # be reached by a single-label alternation at any list length.
    ("See //leaking-identity.ac.uk/profile for the mirror.",
     "leaking-identity.ac.uk"),
    ("Also //leaking-identity.co.jp/profile in translation.",
     "leaking-identity.co.jp"),
    # A single-label TLD that simply was not on the list.
    ("A personal page sits at reviewer-lab.me these days.", "reviewer-lab.me"),
    # An upper-case scheme is not the canonical form the strip removes, so the
    # reference falls through to this sweep and is flagged on its shape alone.
    ("Mirrored at HTTPS://leaking-identity.ac.uk/profile today.",
     "leaking-identity.ac.uk"),
    ("Mirrored at HtTp://leaking-identity.ac.uk/profile today.",
     "leaking-identity.ac.uk"),
    # Credentials in a protocol-relative authority: the host sits after an "@",
    # which the old lookbehind treated as a reason not to match.
    ("Fetched from //reviewer@leaking-identity.ac.uk/profile nightly.",
     "leaking-identity.ac.uk"),
    # Whitespace typed around the only dot, on the side prose never uses.
    ("The mirror is at reviewer-lab .example.net right now.", "reviewer-lab.example.net"),
    ("The mirror is at reviewer-lab\n.example.net right now.", "reviewer-lab.example.net"),
    # And on the sentence-boundary side, where a lower-case label is the signal
    # that this is a split host rather than a new sentence.
    ("The mirror is at reviewer-lab. example.net right now.", "reviewer-lab.example.net"),
    # Encoded separators. markdown-it decodes the character reference and a URL
    # parser decodes the percent escape, so both reach the page as real dots.
    ("Mirrored at //leaking-identity&#46;ac&#46;uk/profile today.",
     "leaking-identity.ac.uk"),
    ("Mirrored at //leaking-identity%2Eac%2Euk/profile today.",
     "leaking-identity.ac.uk"),
    # Double-encoded, which a single decoding pass would leave intact.
    ("Mirrored at //leaking-identity%252Eac%252Euk/profile today.",
     "leaking-identity.ac.uk"),
    # A host parser's other label separators. Each of these renders to the page
    # exactly as typed and reads as the host, and the bare form below carries no
    # "//" for the link gate to find either.
    ("Mirrored at leaking-identity。ac。uk in one draft.", "leaking-identity.ac.uk"),
    ("Mirrored at leaking-identity｡ac｡uk in one draft.", "leaking-identity.ac.uk"),
    ("Mirrored at leaking-identity．ac．uk in one draft.", "leaking-identity.ac.uk"),
    ("Mirrored at leaking-identity․ac․uk in one draft.", "leaking-identity.ac.uk"),
    # Percent-encoded fullwidth stop: only a separator once the percent decoding
    # has handed it to the fold, which is why the two run in one loop.
    ("Mirrored at //leaking-identity%EF%BC%8Eac%EF%BC%8Euk/x today.",
     "leaking-identity.ac.uk"),
    # A character the host parser drops, mid-label. Before the fold this
    # returned the truncated "identity.ac.uk" instead of the whole host.
    ("Mirrored at leaking\u00adidentity.ac.uk in one draft.", "leakingidentity.ac.uk"),
    ("Mirrored at leaking\u200bidentity.ac.uk in one draft.", "leakingidentity.ac.uk"),
    # Fullwidth letters fold to ASCII, so the finding names the host a reader
    # would recognise rather than a lookalike.
    ("Mirrored at ｌeaking-identity.ac.uk in one draft.", "leaking-identity.ac.uk"),
    # Defanged, the way a security document writes a host it does not want
    # clicked. A reader reassembles it on sight.
    ("Mirrored at leaking-identity[.]ac[.]uk in one draft.", "leaking-identity.ac.uk"),
    ("Mirrored at leaking-identity(.)ac(.)uk in one draft.", "leaking-identity.ac.uk"),
    ("Mirrored at leaking-identity{.}ac{.}uk in one draft.", "leaking-identity.ac.uk"),
    # An IPv4 literal is all digits, so the version-number allowance has to
    # stop short of it.
    ("The lab box answers on 198.51.100.7 directly.", "198.51.100.7"),
])
def test_bare_host_sweep_catches_every_shape_a_host_arrives_in(leak, host):
    assert host in _bare_hosts(leak), f"{leak!r} -> {sorted(_bare_hosts(leak))}"


def test_bare_host_sweep_reports_a_host_in_one_case_however_it_was_typed():
    # The finding is the host, so a differently cased spelling must not read as
    # a different host in the failure message or in a caller's comparison.
    assert _bare_hosts("Mirrored at //LEAKING-IDENTITY.AC.UK/profile.") == {"leaking-identity.ac.uk"}


def test_bare_host_sweep_sees_a_host_smuggled_into_a_permitted_url():
    # The authority passes the link gate, so only this sweep can catch the
    # query string. Stripping the whole "https://\S+" reference, as rounds 1
    # and 2 did, deleted the leak along with the link.
    leak = "Cited as https://owasp.org/x?ref=reviewer-lab.example.net here."
    assert _bare_hosts(leak) == {"reviewer-lab.example.net"}


@pytest.mark.parametrize("text", [
    # The version numbers, field paths and file name both documents really
    # contain. Each is host-shaped, so the allowance carries the whole weight
    # of not failing the gate on the project's own vocabulary.
    "Version 0.3.0 extends CycloneDX 1.6.",
    "The join keys are `metadata.agent.id` and `sessionSummary.totalContextTokens`.",
    "The [JSON Schema](/schema/0.3.0/cxbom.schema.json) is served at that path.",
    "A record names `metadata.generatedBy.schema` and `sessionSummary.sessionAuditClean`.",
])
def test_bare_host_sweep_does_not_flag_the_projects_own_dotted_vocabulary(text):
    assert not _bare_hosts(text), sorted(_bare_hosts(text))


def test_bare_host_sweep_does_not_flag_a_sentence_boundary_as_a_split_host():
    # The after-the-dot join is the one that borders on ordinary prose, so the
    # capitalised case has to stay unjoined or every sentence in both documents
    # becomes a finding.
    assert not _bare_hosts("Assembly happens before inference. Orchestration state is outside.")


def test_bare_host_sweep_does_not_flag_the_documents_own_contact_line():
    # The allowed address is blanked whole, so the host inside it is not a
    # finding, while a lookalike built on top of it still is.
    assert not _bare_hosts("Write to [spec@cxbom.org](mailto:spec@cxbom.org).")
    assert _bare_hosts("Write to spec@cxbom.org.evil.example instead.") == {"cxbom.org.evil.example"}


@pytest.mark.parametrize("leak,address", [
    # Whitespace around the "@", the same class as the split host above.
    ("The author is a.author @uni.example.edu today.", "a.author@uni.example.edu"),
    ("The author is a.author@ uni.example.edu today.", "a.author@uni.example.edu"),
    # An encoded "@" still addresses mail.
    ("The author is a.author%40uni.example.edu today.", "a.author@uni.example.edu"),
    # Defanged, the convention for an address a document does not want harvested.
    ("The author is a[.]author[@]uni[.]example[.]edu today.", "a.author@uni.example.edu"),
])
def test_bare_email_sweep_catches_a_separator_the_page_reassembles(leak, address):
    assert _bare_emails(leak) - ALLOWED_BARE_EMAILS == {address}


def test_bare_email_sweep_catches_an_address_with_no_mailto_link():
    leak = "The corresponding author is a.author@uni.example.edu."
    assert _bare_emails(leak) - ALLOWED_BARE_EMAILS == {"a.author@uni.example.edu"}


def test_bare_email_sweep_catches_a_plus_addressed_leak():
    # The local-part class includes "+" for exactly this shape; without it,
    # the match would still fire but truncated at the "+", which is a
    # different, wrong string, not a clean miss.
    leak = "Route replies to a.author+conf@uni.example.edu."
    assert _bare_emails(leak) - ALLOWED_BARE_EMAILS == {"a.author+conf@uni.example.edu"}


def test_bare_host_sweep_does_not_flag_a_url_with_no_trailing_path():
    # The host pattern carries no trailing lookahead, so nothing at the pattern
    # level stops it from matching mid-path ("cxbom.org" inside
    # ".../cxbom.org/schema/..."). What keeps a real, canonically schemed URL
    # from tripping this gate is _without_markup removing its authority, which
    # _link_authorities has already checked against the permitted-host list.
    # That strip does not care whether a path follows the authority, so a
    # reference with nothing after it ("https://cxbom.org") is removed the same
    # way. Without it, this would be a false positive on a legitimate link.
    assert not _bare_hosts("See https://cxbom.org for the schema.")


def test_landing_states_privacy_and_contact():
    assert PRIVACY in _flat(LANDING)
    assert "[spec@cxbom.org](mailto:spec@cxbom.org)" in LANDING


def test_landing_introduces_the_strip_and_the_ledger():
    body = _section(LANDING, "The reference session")
    assert "strip at the top of every page" in _flat(body)
    assert "ledger below" in _flat(body)


@pytest.mark.skipif(not DENYLIST, reason=f"{anon_check.DENYLIST_NAME} is absent from this checkout")
@pytest.mark.parametrize("name,text", DOCS, ids=[n for n, _ in DOCS])
def test_neither_document_carries_a_denylisted_token(name, text):
    assert anon_check.require_tokens(DENYLIST) == []
    assert anon_check.scan_text(name, text, [POSITIVE_CONTROL]), f"{name}: the scan did not run"
    assert anon_check.scan_text(name, text, DENYLIST) == []
