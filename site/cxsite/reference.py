"""The field reference page, generated from the published schema at build time.

Owner: ATACE Working Group.

One table covers the top-level fields and one table covers each entry under
`definitions`. Inline objects are flattened into dotted paths (`metadata.session`),
and array items into `[]` paths. A `$ref` becomes a same-page link to its
definition. Every string from the schema is HTML-escaped.

Ruling C4 (site ledger, 2026-09-26, fix round 1) is implemented here: the
frozen 0.2.0 schema is reprinted verbatim, citations included, because the
schema itself is frozen and this page is not the place to rewrite it. Any
description that mentions "attention", "softmax", or "crowding" gets an
erratum note pointing at the 0.2.0 changelog entry instead, so the page
never asserts an attention-mechanism claim on its own account. The rule
(`_ATTENTION_RE`) is a plain case-insensitive substring match, widened in
fix round 1 from "attention" alone once the schema's own $comment field
confirmed Lemma 1 ("Softmax Crowding") and the SoftMax-pressure language are
the same claim under a different name. This is a deliberately blunt rule:
judging which of these claims are precise enough to stand alone is not this
page's job, and a keyword match keeps firing even if a future frozen-schema
edit rewords the claim into a phrase a narrower pattern would miss. The
changelog link's anchor is derived at build time from the changelog's own
0.2.0 heading (`_changelog_anchor`), never hard-coded, so it cannot drift out
of sync with a changelog edit. `tests/test_site_reference.py` pins the rule
against the eight known matches in the current 0.2.0 schema and fails if any
of them stops getting a note.
"""
from __future__ import annotations

import html
import re
from collections.abc import Iterator
from pathlib import Path

from .render import RenderError, md_to_html, slug

_ATTENTION_RE = re.compile(r"attention|softmax|crowding", re.IGNORECASE)

_CHANGELOG_PATH = Path(__file__).resolve().parents[2] / "spec" / "CHANGELOG.md"
_CHANGELOG_HEADING_RE = re.compile(r"^##\s+(0\.2\.0.*)$", re.MULTILINE)


def _changelog_anchor() -> str:
    # Same slug() the renderer uses for every heading id, so this anchor
    # matches whatever id the changelog page actually gets when it is built.
    text = _CHANGELOG_PATH.read_text(encoding="utf-8")
    match = _CHANGELOG_HEADING_RE.search(text)
    if not match:
        # Repository-relative by hand, because main() prints this refusal and
        # _CHANGELOG_PATH is absolute.
        raise RenderError("no 0.2.0 heading found in spec/CHANGELOG.md")
    return slug(match.group(1))


_ERRATUM_MD = (
    "Reprinted verbatim from the frozen 0.2.0 schema. This site does not "
    "assert the attention claim above. See the "
    f"[changelog](/changelog/#{_changelog_anchor()})."
)


def _esc(s: object) -> str:
    return html.escape(str(s))


def _def_anchor(ref: str) -> str:
    return "def-" + ref.rsplit("/", 1)[-1]


def _type_html(node: dict) -> str:
    if "$ref" in node:
        name = node["$ref"].rsplit("/", 1)[-1]
        return f'<a href="#{_def_anchor(node["$ref"])}"><code>{_esc(name)}</code></a>'
    t = node.get("type")
    if t == "array" and isinstance(node.get("items"), dict):
        return "array of " + _type_html(node["items"])
    if isinstance(t, list):
        return " or ".join(f"<code>{_esc(x)}</code>" for x in t)
    if t:
        return f"<code>{_esc(t)}</code>"
    return "any"


def _attention_erratum(description: str) -> str:
    # Ruling C4's rule lives here, and only here, so the schema-descriptions
    # code path and the definitions-header code path apply the same check.
    if not description or not _ATTENTION_RE.search(description):
        return ""
    return md_to_html(_ERRATUM_MD)


def _notes_html(node: dict, include_description: bool = True) -> str:
    parts = []
    description = node.get("description")
    if include_description and description:
        parts.append(_esc(description))
        erratum = _attention_erratum(description)
        if erratum:
            parts.append(erratum)
    if "enum" in node:
        parts.append("One of: " + ", ".join(f"<code>{_esc(v)}</code>" for v in node["enum"]) + ".")
    if "const" in node:
        parts.append(f"Always <code>{_esc(node['const'])}</code>.")
    if "pattern" in node:
        parts.append(f"Pattern <code>{_esc(node['pattern'])}</code>.")
    return " ".join(parts)


def rows(node: dict, prefix: str = "") -> Iterator[tuple[str, dict, bool]]:
    required = set(node.get("required", []))
    for name, child in node.get("properties", {}).items():
        path = f"{prefix}{name}"
        yield path, child, name in required
        if child.get("type") == "object" and "properties" in child:
            yield from rows(child, path + ".")
        items = child.get("items")
        if child.get("type") == "array" and isinstance(items, dict) and "properties" in items:
            yield from rows(items, path + "[].")


def _table(node: dict, caption: str) -> str:
    body = "".join(
        f'<tr><th scope="row"><code>{_esc(path)}</code></th><td>{_type_html(child)}</td>'
        f'<td>{"yes" if req else "no"}</td><td>{_notes_html(child)}</td></tr>'
        for path, child, req in rows(node))
    return (f'<div class="table-wrap" tabindex="0" role="region" aria-label="{_esc(caption)}">'
            f'<table><caption>{_esc(caption)}</caption>'
            '<thead><tr><th scope="col">Field</th><th scope="col">Type</th><th scope="col">Required</th>'
            f'<th scope="col">Notes</th></tr></thead><tbody>{body}</tbody></table></div>')


def schema_reference_html(schema: dict, served_at: str) -> str:
    out = [
        '<h1 id="field-reference">Field reference</h1>',
        f'<p>Generated from <a href="{_esc(served_at)}"><code>{_esc(schema["$id"])}</code></a> '
        f"when the site is built. The schema is the normative source. This page restates it.</p>",
        '<h2 id="top-level">Top-level fields</h2>',
        _table(schema, "Top-level fields of a CxBOM record"),
    ]
    for name, node in schema.get("definitions", {}).items():
        out.append(f'<h2 id="def-{_esc(name)}"><code>{_esc(name)}</code></h2>')
        description = node.get("description")
        if description:
            out.append(f"<p>{_esc(description)}</p>")
            erratum = _attention_erratum(description)
            if erratum:
                out.append(erratum)
        if "properties" in node:
            out.append(_table(node, f"Fields of {name}"))
        else:
            # The description (and any erratum, which is itself a <p> block
            # from md_to_html) was already appended above, so this call must
            # skip the description or the erratum's <p> would nest inside
            # this one.
            out.append(f"<p>Type: {_type_html(node)}. {_notes_html(node, include_description=False)}</p>")
    return "\n".join(out)
