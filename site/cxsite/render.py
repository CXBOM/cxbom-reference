"""Markdown rendering and the page template.

Owner: ATACE Working Group.

Markdown goes through markdown-it-py in CommonMark mode with tables enabled and
raw HTML disabled, so no source file can inject markup or script. The renderer
adds stable heading ids and `scope` on table headers, and wraps each table in a
scrolling container so wide tables never widen the page.
"""
from __future__ import annotations

import html
import re
import string
from dataclasses import dataclass

from markdown_it import MarkdownIt

# The "Schema" nav item lands on the HTML schema page at /reference/, which
# restates the schema field by field and links the raw file. The published JSON
# Schema itself is a download, not a nav destination: it lives in the JSON-only
# /schema/* namespace (served application/schema+json with no HTML shell,
# enforced by live_check), so a nav link straight there would strand a reader on
# raw JSON with no way back. See tests/test_site_content.py
# (test_nav_never_strands_a_reader_in_the_json_only_schema_namespace).
NAV = (
    ("/spec/", "Specification"),
    ("/scope/", "Scope"),
    ("/reference/", "Schema"),
    ("/examples/", "Examples"),
    ("/viewer/", "Viewer"),
    ("/changelog/", "Changelog"),
)

_MD = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False}).enable("table")


TABLE_WRAP = '<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable table">'


class RenderError(ValueError):
    """Rendered output would break the page contract (for example, an inline style)."""


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "section"


def _is_external(url: str) -> bool:
    # A scheme (http:, https:, ...) or a protocol-relative "//host" leaves the site origin.
    return bool(re.match(r"^[a-z][a-z0-9+.-]*:", url, re.IGNORECASE)) or url.startswith("//")


def md_to_html(text: str) -> str:
    tokens = _MD.parse(text)
    seen: dict[str, int] = {}
    for i, tok in enumerate(tokens):
        if tok.type == "heading_open":
            base = slug(tokens[i + 1].content)
            n = seen.get(base, 0)
            seen[base] = n + 1
            tok.attrSet("id", base if n == 0 else f"{base}-{n + 1}")
        elif tok.type == "th_open":
            tok.attrSet("scope", "col")
            _refuse_alignment_style(tok)
        elif tok.type == "td_open":
            _refuse_alignment_style(tok)
        elif tok.type == "inline" and tok.children:
            for child in tok.children:
                if child.type == "image" and _is_external(child.attrGet("src") or ""):
                    # An image auto-loads with no click, so a spec file could beacon a
                    # reviewer's IP to an outside host and break double-blind review.
                    raise RenderError(f"image src is not a same-origin path: {child.attrGet('src')}")
    out = _MD.renderer.render(tokens, _MD.options, {})
    # A scrolling table must be reachable by keyboard (axe scrollable-region-focusable).
    return out.replace("<table>", TABLE_WRAP + "<table>").replace("</table>", "</table></div>")


def _refuse_alignment_style(tok) -> None:
    # Column alignment (":--", "--:", ":-:") sets a "style" attr on the th/td
    # token itself, which the site CSP blocks. Reading the token attribute
    # directly, instead of scanning the rendered string for "style=", means
    # prose that happens to contain the literal text "style=" still renders.
    if tok.attrGet("style") is not None:
        raise RenderError("markdown table alignment renders an inline style; remove the alignment colons")


@dataclass(frozen=True)
class Page:
    path: str          # URL path, for example "/spec/"
    title: str         # text of the page's single h1, reused in <title>
    body: str          # HTML for <main>, which must contain exactly one <h1>
    numbered: bool = False


def nav_html(current: str) -> str:
    items = []
    for href, label in NAV:
        cur = ' aria-current="page"' if href == current else ""
        items.append(f'<li><a href="{href}"{cur}>{html.escape(label)}</a></li>')
    return "\n".join(items)


def render_page(template: str, page: Page, strip: str, strip_note: str) -> str:
    if page.body.count("<h1") != 1:
        raise RenderError(f"{page.path}: a page needs exactly one h1")
    title = "CxBOM" if page.path == "/" else f"{page.title} | CxBOM"
    return string.Template(template).substitute(
        title=html.escape(title),
        strip=strip,
        strip_note=strip_note,
        nav=nav_html(page.path),
        main_class="numbered" if page.numbered else "plain",
        body=page.body,
    )
