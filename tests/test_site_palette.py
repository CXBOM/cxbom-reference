"""The palette passes WCAG 2.2 AA in both themes, and gate 5 fires when it does not.

Owner: ATACE Working Group.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import palette  # noqa: E402

CSS = (ROOT / "site/templates/site.css").read_text(encoding="utf-8")


def test_design_palette_values_are_the_stylesheet_values():
    p = palette.parse_palette(CSS)
    assert p["light"] == {
        "bg": "#EEF0F3", "surface": "#FAFBFD", "ink": "#16181C", "muted": "#585E66",
        "rule": "#7B818A", "accent": "#BC1C1C", "ring0": "#0A7A50", "ring1": "#0A5C9E",
        "ring2": "#B5440E", "sevHigh": "#9E520C", "sevMed": "#82600E"}
    assert p["dark"] == {
        "bg": "#14171B", "surface": "#1E2229", "ink": "#E7E9ED", "muted": "#AAB1BA",
        "rule": "#7C838D", "accent": "#F2564A", "ring0": "#28AC7F", "ring1": "#3E90D2",
        "ring2": "#DD7035", "sevHigh": "#F0974A", "sevMed": "#E8C05C"}


def test_stylesheet_palette_passes():
    assert palette.check_contrast(CSS) == []


@pytest.mark.parametrize("a,b,ratio", [
    ("#16181C", "#EEF0F3", 15.57), ("#7B818A", "#EEF0F3", 3.44), ("#7C838D", "#14171B", 4.7),
    ("#000000", "#FFFFFF", 21.0), ("#777777", "#FFFFFF", 4.48)])
def test_contrast_matches_wcag_formula(a, b, ratio):
    assert round(palette.contrast(a, b), 2) == ratio


def test_gate_fires_on_low_text_contrast():
    bad = CSS.replace("--muted: light-dark(#585E66, #AAB1BA);", "--muted: light-dark(#A89B8A, #AAB1BA);")
    errs = palette.check_contrast(bad)
    assert errs == ["contrast: light muted on bg is 2.38, below 4.5", "contrast: light muted on surface is 2.63, below 4.5"]


def test_gate_fires_on_low_rule_contrast_in_dark_theme():
    bad = CSS.replace("--rule: light-dark(#7B818A, #7C838D);", "--rule: light-dark(#7B818A, #2E333A);")
    assert palette.check_contrast(bad)[0].startswith("contrast: dark rule on bg is ")


def test_gate_fails_closed_without_a_palette_block():
    assert palette.check_contrast("body{color:red}") == ["contrast: expected one palette block, found 0"]
    no_accent = CSS.replace("  --accent: light-dark(#BC1C1C, #F2564A);\n", "")
    assert palette.check_contrast(no_accent) == ["contrast: palette is missing accent"]
