"""The field reference covers every schema field and escapes schema text.

Owner: ATACE Working Group.
"""
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import reference  # noqa: E402
from cxsite import render  # noqa: E402

SCHEMA = json.loads((ROOT / "spec/cxbom-0.3.0.schema.json").read_text(encoding="utf-8"))
HTML = reference.schema_reference_html(SCHEMA, "/schema/0.3.0/cxbom.schema.json")


def test_every_top_level_field_and_definition_is_present():
    for name in SCHEMA["properties"]:
        assert f"<code>{name}</code></th>" in HTML, name
    for name in SCHEMA["definitions"]:
        assert f'<h2 id="def-{name}"><code>{name}</code></h2>' in HTML, name


def test_nested_fields_are_flattened_to_paths():
    assert "<code>metadata.session</code></th>" in HTML
    assert "<code>sessionSummary.componentBreakdown.byTrustRing</code></th>" in HTML


def test_every_ref_link_has_a_target_on_the_page():
    ids = set(re.findall(r'id="([^"]+)"', HTML))
    targets = set(re.findall(r'href="#([^"]+)"', HTML))
    assert targets and targets <= ids


def test_required_flags_follow_the_schema():
    assert "<th scope=\"row\"><code>catalogVersions</code></th><td><code>object</code></td><td>yes</td>" in HTML
    assert "<th scope=\"row\"><code>_comment</code></th><td><code>string</code></td><td>no</td>" in HTML


def test_enums_are_listed():
    assert "<code>ring-1-derived</code>" in HTML
    assert "<code>not-assessed</code>" in HTML


def test_schema_text_is_escaped():
    evil = {"$id": "https://cxbom.org/x", "properties": {"a": {"type": "string", "description": "<script>x</script>"}}}
    out = reference.schema_reference_html(evil, "/x")
    assert "<script>" not in out and "&lt;script&gt;x&lt;/script&gt;" in out


def test_exactly_one_h1():
    assert HTML.count("<h1") == 1


# --- Ruling C4: erratum notes beside frozen-schema attention claims ---


def _row_segment(html_text: str, field_path: str) -> str:
    marker = f'<th scope="row"><code>{field_path}</code></th>'
    start = html_text.index(marker)
    end = html_text.index("</tr>", start)
    return html_text[start:end]


def _definition_header_segment(html_text: str, def_name: str) -> str:
    marker = f'<h2 id="def-{def_name}">'
    start = html_text.index(marker)
    end = html_text.index("<table", start)
    return html_text[start:end]


def test_the_attention_erratum_rule_is_a_plain_case_insensitive_substring_match():
    # Name the rule so a change to it shows up as a visible diff, not a guess.
    # Fix round 1 widened it from "attention" alone to "attention|softmax|
    # crowding", since the schema's own $comment calls Lemma 1 "Softmax
    # Crowding" and ties it to the same attention-mechanism claim.
    assert reference._ATTENTION_RE.pattern == r"attention|softmax|crowding"
    assert reference._attention_erratum("mentions ATTENTION in caps")
    assert reference._attention_erratum("the Attention Mechanism used")
    assert reference._attention_erratum("SoftMax crowding pressure")
    assert reference._attention_erratum("context CROWDING expansion")
    assert not reference._attention_erratum("no matching word here")
    assert not reference._attention_erratum("")


# Known 0.2.0 schema descriptions that mention "attention", "softmax", or
# "crowding", found by walking every description in
# spec/cxbom-0.2.0.schema.json for the widened pattern. Each entry is
# (rendered field path or definition name, "row" or "definition").
KNOWN_ATTENTION_DESCRIPTIONS = []


def test_every_known_attention_description_gets_an_erratum_note():
    anchor = reference._changelog_anchor()
    for path, kind in KNOWN_ATTENTION_DESCRIPTIONS:
        segment = (
            _row_segment(HTML, path) if kind == "row" else _definition_header_segment(HTML, path)
        )
        assert "Reprinted verbatim" in segment, path
        assert f'href="/changelog/#{anchor}"' in segment, path


def test_erratum_count_tracks_every_attention_mention_in_the_schema_not_just_the_known_list():
    # A regression that drops the erratum call, or that adds it somewhere new,
    # changes this count against an independent walk of the raw schema, so the
    # test fails instead of quietly passing next to the known-list check above.
    def count_attention_descriptions(node) -> int:
        count = 0
        if isinstance(node, dict):
            description = node.get("description")
            if isinstance(description, str) and reference._ATTENTION_RE.search(description):
                count += 1
            for value in node.values():
                count += count_attention_descriptions(value)
        elif isinstance(node, list):
            for value in node:
                count += count_attention_descriptions(value)
        return count

    expected = count_attention_descriptions(SCHEMA)
    assert expected == len(KNOWN_ATTENTION_DESCRIPTIONS)
    assert HTML.count("Reprinted verbatim") == expected


def test_frozen_citations_stay_exactly_where_the_schema_has_them():
    # Ruling C4: "Young (2025)" and "(Lemma 1)" stay only where the frozen
    # schema has them. This task adds no citation and removes none.
    # "Young (2025)" is in one rendered description (tokenDemocracyApplies).
    # "(Lemma 1)" is in two rendered descriptions (contextualSharePercent and
    # sessionSummary.dualFailureMultiplierAssessment.qualityPressureRating).
    # A third mention, in the top-level $comment and in trustModel's
    # $comment, is not rendered at all, since $comment is not a field this
    # page displays (matching the brief's verbatim code).
    assert HTML.count("Young (2025)") == 0
    assert HTML.count("(Lemma 1)") == 0


def test_the_widened_rule_still_fires_on_synthetic_attention_text():
    # The rule stays load-bearing even though 0.3.0 has no matching field: a
    # future schema edit that reintroduces the wording must still get a note.
    assert reference._attention_erratum("SoftMax crowding pressure")
    assert "Reprinted verbatim" in reference._attention_erratum("SoftMax crowding pressure")


def test_every_non_root_schema_description_appears_verbatim():
    # Direct check of the "reprinted verbatim" property, rather than only
    # inferring it from the other tests passing. The root schema's own
    # top-level description is the one deliberate exclusion: the intro
    # paragraph names the schema $id and served_at path instead of repeating
    # the schema's own blurb (212 of 213 descriptions in the real 0.3.0
    # schema are non-root and must all appear).
    descriptions = []

    def walk(node, is_root=False):
        if isinstance(node, dict):
            description = node.get("description")
            if isinstance(description, str) and not is_root:
                descriptions.append(description)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(SCHEMA, is_root=True)
    assert len(descriptions) == 212
    unescaped = html.unescape(HTML)
    for description in descriptions:
        assert description in unescaped, description


def test_changelog_anchor_is_derived_and_exists_in_the_rendered_changelog():
    # The anchor must never be hard-coded (fix round 1, item 2). This test
    # renders the real changelog through the shared Markdown renderer and
    # confirms the id reference.py derived is one the renderer actually
    # produces, without spelling the anchor's literal value out anywhere.
    changelog_text = (ROOT / "spec/CHANGELOG.md").read_text(encoding="utf-8")
    rendered_changelog = render.md_to_html(changelog_text)
    anchor = reference._changelog_anchor()
    assert f'id="{anchor}"' in rendered_changelog
    assert f"/changelog/#{anchor}" in reference._ERRATUM_MD


def test_leaf_definition_does_not_nest_a_p_inside_a_p():
    # A definition with no "properties" prints its description (and any
    # erratum, itself a <p> from md_to_html) once, then a second "<p>Type:
    # ...</p>" for the bare type. Before this fix, _notes_html re-added the
    # description and its erratum inside that second <p>, nesting one <p>
    # block inside another, which browsers do not render as written.
    schema = {
        "$id": "https://cxbom.org/x",
        "properties": {},
        "definitions": {
            "attentionLeaf": {
                "type": "string",
                "description": "A leaf value tied to the attention mechanism.",
            }
        },
    }
    out = reference.schema_reference_html(schema, "/x")
    assert out.count("Reprinted verbatim") == 1
    type_start = out.index("<p>Type:")
    type_end = out.index("</p>", type_start)
    assert "<p>" not in out[type_start + len("<p>"):type_end]


def test_array_item_flattening_with_a_synthetic_schema():
    # rows() flattens an array-of-objects property into "field[].subfield"
    # paths. The real 0.2.0 schema exercises this too, but a small synthetic
    # schema pins the branch directly instead of relying on incidental
    # coverage from the full schema's other tests.
    schema = {
        "$id": "https://cxbom.org/x",
        "properties": {
            "items": {
                "type": "array",
                "description": "A list of named items.",
                "items": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Item name."}},
                    "required": ["name"],
                },
            }
        },
    }
    out = reference.schema_reference_html(schema, "/x")
    assert '<th scope="row"><code>items</code></th>' in out
    assert '<th scope="row"><code>items[].name</code></th>' in out
