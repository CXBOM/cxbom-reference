"""Markdown rendering and the page template keep the accessibility contract.

Owner: ATACE Working Group.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import render  # noqa: E402

TEMPLATE = (ROOT / "site/templates/page.html").read_text(encoding="utf-8")


def test_headings_get_stable_unique_ids():
    out = render.md_to_html("# Title\n\n## Trust rings\n\n## Trust rings\n\n### A/B: c\n")
    assert '<h1 id="title">' in out
    assert '<h2 id="trust-rings">' in out and '<h2 id="trust-rings-2">' in out
    assert '<h3 id="a-b-c">' in out


def test_raw_html_is_escaped_not_rendered():
    out = render.md_to_html("<script>alert(1)</script>\n\nText <b>bold</b>\n")
    assert "<script>" not in out and "<b>" not in out
    assert "&lt;script&gt;" in out


def test_tables_are_wrapped_and_headers_scoped():
    out = render.md_to_html("| A | B |\n|---|---|\n| 1 | 2 |\n")
    assert out.startswith('<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable table"><table>')
    assert '<th scope="col">A</th>' in out
    assert out.rstrip().endswith("</table></div>")


def test_aligned_table_is_refused_because_it_renders_inline_style():
    with pytest.raises(render.RenderError, match="inline style"):
        render.md_to_html("| A |\n|--:|\n| 1 |\n")


def test_page_has_landmarks_skip_link_lang_and_current_nav():
    page = render.Page(path="/spec/", title="Specification", body="<h1>Specification</h1>", numbered=True)
    out = render.render_page(TEMPLATE, page, strip="<svg></svg>", strip_note="<p>n</p>")
    assert '<html lang="en">' in out
    assert '<a class="skip" href="#main">' in out
    for tag in ("<header", "<nav", '<main id="main" class="numbered">', "<footer"):
        assert tag in out
    assert '<a href="/spec/" aria-current="page">Specification</a>' in out
    assert out.count('aria-current="page"') == 1
    assert "<title>Specification | CxBOM</title>" in out
    assert '<input type="checkbox" id="theme-flip"><label for="theme-flip">' in out


def test_page_without_exactly_one_h1_is_refused():
    with pytest.raises(render.RenderError, match="exactly one h1"):
        render.render_page(TEMPLATE, render.Page(path="/x/", title="X", body="<h2>X</h2>"), "", "")
    with pytest.raises(render.RenderError, match="exactly one h1"):
        render.render_page(TEMPLATE, render.Page(path="/x/", title="X", body="<h1>a</h1><h1>b</h1>"), "", "")


def test_template_loads_nothing_from_another_origin():
    # The template links to the project's own repository in the header. That is
    # a navigation link, not a loaded resource, so it is removed before the
    # origin check; a stylesheet, script, image or font URL would still fail.
    template = TEMPLATE.replace('href="https://github.com/CXBOM/cxbom"', "")
    assert "http://" not in template and "https://" not in template
    assert "<script" not in TEMPLATE and "style=" not in TEMPLATE


def test_javascript_link_is_refused_as_a_scheme_not_rendered_as_href():
    out = render.md_to_html("[click me](javascript:alert(1))\n")
    assert "href=" not in out
    assert "javascript:" in out  # kept only as inert paragraph text


def test_external_image_is_refused_as_a_reviewer_tracking_beacon():
    with pytest.raises(render.RenderError, match="same-origin path"):
        render.md_to_html("![x](https://evil.example/track.png)\n")
    # A same-origin image is not a beacon risk and stays allowed.
    out = render.md_to_html("![x](/img/local.png)\n")
    assert '<img src="/img/local.png"' in out


# Each of these is a distinct way to smuggle a non-same-origin image src past
# a weaker guard. Every input here must fail if either half of _is_external's
# check (the scheme regex or the "//" protocol-relative check) is narrowed or
# dropped, so this list stays a mutation-kill set, not just an example set.
@pytest.mark.parametrize(
    "markdown_source",
    [
        pytest.param("![x](//e.com/x.png)\n", id="protocol-relative"),
        pytest.param("![x](HTTP://e.com/x.png)\n", id="uppercase-scheme"),
        pytest.param("![x](ftp://e.com/x.png)\n", id="non-http-scheme"),
        pytest.param("![a][r]\n\n[r]: //e.com/x.png\n", id="reference-style-protocol-relative"),
        pytest.param("![x](data:image/png;base64,AA)\n", id="data-uri"),
    ],
)
def test_image_src_guard_refuses_every_non_same_origin_form(markdown_source):
    with pytest.raises(render.RenderError, match="same-origin path"):
        render.md_to_html(markdown_source)


def test_prose_containing_the_literal_text_style_equals_still_renders():
    # The alignment guard reads the th/td token's "style" attribute, not the
    # rendered string, so ordinary prose that happens to contain "style=" is
    # not mistaken for a refused inline style.
    out = render.md_to_html("Use `style=` sparingly.\n")
    assert "style=" in out
    out = render.md_to_html("| A |\n|---|\n| 1 |\n")
    assert '<th scope="col">A</th>' in out


def test_aligned_table_cell_is_still_refused_via_the_token_attribute():
    with pytest.raises(render.RenderError, match="inline style"):
        render.md_to_html("| A |\n|--:|\n| 1 |\n")


def test_html_entity_encoded_script_is_a_markdown_it_library_behavior_pin():
    # CommonMark decodes "&lt;script&gt;" into the literal characters "<script>"
    # during inline text parsing, then markdown-it's own text renderer escapes
    # them back on output. That happens regardless of the html=False config
    # (it still passes with html=True), so this test pins markdown-it's own
    # decode-then-escape behavior, not a property render.py enforces itself.
    out = render.md_to_html("&lt;script&gt;alert(1)&lt;/script&gt;\n")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
