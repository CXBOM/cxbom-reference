"""Palette tokens and the contrast gate (design gate 5).

Owner: ATACE Working Group.

site/templates/site.css is the single source of the palette. Between the
`/* palette */` and `/* end palette */` markers it declares one token per line
as `--name: light-dark(#light, #dark);`. This module parses that block and
recomputes every pairing with the WCAG 2.2 relative-luminance formula, so a
stylesheet edit that drops a pairing below AA fails the build.
"""
from __future__ import annotations

import re

GROUNDS = ("bg", "surface")
TEXT_TOKENS = ("ink", "muted", "accent", "ring0", "ring1", "ring2", "sevHigh", "sevMed")
NONTEXT_TOKENS = ("rule",)
TEXT_MIN = 4.5
NONTEXT_MIN = 3.0

_BLOCK = re.compile(r"/\* palette \*/(.*?)/\* end palette \*/", re.S)
_DECL = re.compile(r"--([A-Za-z0-9]+)\s*:\s*light-dark\(\s*(#[0-9A-Fa-f]{6})\s*,\s*(#[0-9A-Fa-f]{6})\s*\)\s*;")


class PaletteError(ValueError):
    """The stylesheet has no parseable palette block."""


def parse_palette(css: str) -> dict[str, dict[str, str]]:
    blocks = _BLOCK.findall(css)
    if len(blocks) != 1:
        raise PaletteError(f"expected one palette block, found {len(blocks)}")
    light: dict[str, str] = {}
    dark: dict[str, str] = {}
    for name, lo, hi in _DECL.findall(blocks[0]):
        if name in light:
            raise PaletteError(f"--{name} is declared twice")
        light[name], dark[name] = lo.upper(), hi.upper()
    missing = [t for t in GROUNDS + TEXT_TOKENS + NONTEXT_TOKENS if t not in light]
    if missing:
        raise PaletteError("palette is missing " + ", ".join(missing))
    return {"light": light, "dark": dark}


def _channel(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (_channel(int(h[i:i + 2], 16) / 255) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def check_contrast(css: str) -> list[str]:
    try:
        themes = parse_palette(css)
    except PaletteError as e:
        return [f"contrast: {e}"]
    errs: list[str] = []
    for theme, p in themes.items():
        for ground in GROUNDS:
            for tokens, floor in ((TEXT_TOKENS, TEXT_MIN), (NONTEXT_TOKENS, NONTEXT_MIN)):
                for t in tokens:
                    ratio = contrast(p[t], p[ground])
                    # Round down to two places so a ratio of 4.499 never reads as a pass.
                    if int(ratio * 100) / 100 < floor:
                        errs.append(f"contrast: {theme} {t} on {ground} is {ratio:.2f}, below {floor}")
    return errs
