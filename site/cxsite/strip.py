"""The context strip and the landing ledger, rendered from the reference record.

Owner: ATACE Working Group.

The strip divides the reference session's context window by trust ring at true
proportion: ring 0, ring 1, ring 2, then template overhead. The numbers come from
site/data/session_reference.json, never from constants, and the strip refuses a
record whose ring totals do not add up. Each ring carries a text label and its
own fill pattern (solid, hatched, dotted, lined), so color never carries meaning alone.
"""
from __future__ import annotations

import html
from dataclasses import dataclass

VIEW_W = 1000
VIEW_H = 24
RINGS = (("ring0", "Ring 0", "operator", "0"), ("ring1", "Ring 1", "agent", "1"), ("ring2", "Ring 2", "user", "2"))
PATTERN = {"0": "solid", "1": "hatched", "2": "dotted", "o": "lined"}


class StripError(ValueError):
    """The record's token accounting does not reconcile."""


@dataclass(frozen=True)
class Segment:
    key: str      # "0", "1", "2" or "o" for template overhead
    label: str    # "Ring 0 (operator)" or "Template overhead"
    tokens: int


def _fmt(n: int) -> str:
    return f"{n:,}"


def segments(record: dict) -> list[Segment]:
    summary = record["sessionSummary"]
    rings = summary["componentBreakdown"]["byTrustRing"]
    segs = [Segment(k, f"{name} ({role})", int(rings[field]["tokens"])) for field, name, role, k in RINGS]
    if sum(s.tokens for s in segs) != summary["totalContextTokens"]:
        raise StripError("ring tokens do not sum to totalContextTokens")
    segs.append(Segment("o", "Template overhead", int(summary["templateOverheadTokens"])))
    if sum(s.tokens for s in segs) != record["metadata"]["session"]["contextWindowTokensUsed"]:
        raise StripError("ring tokens plus template overhead do not equal contextWindowTokensUsed")
    return segs


def _defs(uid: str) -> str:
    # userSpaceOnUse keeps pattern cells a fixed size whatever the segment width.
    return (
        "<defs>"
        f'<pattern id="{uid}-p1" width="6" height="6" patternUnits="userSpaceOnUse">'
        '<rect class="f1" width="6" height="6"/><path class="pat-line" d="M0 6L6 0"/></pattern>'
        f'<pattern id="{uid}-p2" width="6" height="6" patternUnits="userSpaceOnUse">'
        '<rect class="f2" width="6" height="6"/><circle class="pat-dot" cx="3" cy="3" r="1.2"/></pattern>'
        f'<pattern id="{uid}-po" width="4" height="6" patternUnits="userSpaceOnUse">'
        '<rect class="fo" width="4" height="6"/><path class="pat-line" d="M2 0V6"/></pattern>'
        "</defs>"
    )


def _fill(uid: str, key: str) -> str:
    return 'class="f0"' if key == "0" else f'fill="url(#{uid}-p{key})"'


def describe(record: dict) -> str:
    segs = segments(record)
    total = sum(s.tokens for s in segs)
    parts = [f"{s.label}: {_fmt(s.tokens)} tokens, {PATTERN[s.key]}" for s in segs]
    return f"Reference session context window use: {_fmt(total)} tokens. " + ". ".join(parts) + "."


def strip_svg(record: dict, uid: str) -> str:
    segs = segments(record)
    total = sum(s.tokens for s in segs)
    rects, x = [], 0.0
    for s in segs:
        w = VIEW_W * s.tokens / total
        rects.append(f'<rect x="{x:.3f}" y="8" width="{w:.3f}" height="16" {_fill(uid, s.key)}/>')
        x += w
    # The ring 0 slice is under one unit wide, so a marker above the bar calls it out.
    marker = '<path class="f0" d="M0 0H8L0 7Z"/>'
    return (
        f'<svg class="strip" viewBox="0 0 {VIEW_W} {VIEW_H}" preserveAspectRatio="none" role="img" '
        f'aria-labelledby="{uid}-t {uid}-d">'
        f'<title id="{uid}-t">Context strip: the reference session by trust ring</title>'
        f'<desc id="{uid}-d">{html.escape(describe(record))}</desc>'
        + _defs(uid) + "".join(rects) + marker
        + f'<rect class="edge" x="0.5" y="8.5" width="{VIEW_W - 1}" height="15"/></svg>'
    )


def strip_note(record: dict) -> str:
    segs = segments(record)
    total = sum(s.tokens for s in segs)
    return (f'<p class="strip-note">Reference session: ring 0 (operator, marked) holds '
            f"{_fmt(segs[0].tokens)} of {_fmt(total)} tokens.</p>")


def ledger_table(record: dict) -> str:
    segs = segments(record)
    summary = record["sessionSummary"]
    rows = []
    for n, c in enumerate(record["contextComponents"], start=1):
        ring = int(c["trustRing"])
        _, name, role, key = RINGS[ring]
        share = float(c["content"]["contextualSharePercent"])
        if (c.get("toolDefinitionTrustInversion") or {}).get("detected"):
            status = '<span class="stamp">TRUST INVERSION</span>'
        elif c.get("injectionRiskRating") == "not-assessed":
            status = '<span class="stamp plain">NOT ASSESSED</span>'
        else:
            status = html.escape(str(c.get("injectionRiskRating", "")))
        bar = (f'<svg class="bar" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true" focusable="false">'
               f'<rect class="track" width="100" height="6"/><rect class="f{key}" width="{max(share, 0.5):.2f}" height="6"/></svg>')
        rows.append(
            f'<tr><td class="num">{n}</td><th scope="row">{html.escape(c["id"])}</th>'
            f'<td>{html.escape(c["label"])}<br><code>{html.escape(c["type"])}</code></td>'
            f'<td><span class="ring-label t{key}">{name} ({role})</span></td>'
            f'<td class="num">{_fmt(int(c["content"]["tokenCount"]))}</td>'
            f'<td class="num">{share:.2f}%{bar}</td><td>{status}</td></tr>')
    overhead = segs[-1].tokens
    used = record["metadata"]["session"]["contextWindowTokensUsed"]
    caption = (f"Reference session ledger: {len(rows)} components, {_fmt(summary['totalContextTokens'])} "
               f"component tokens and {_fmt(overhead)} template overhead tokens.")
    return (
        '<div class="table-wrap" tabindex="0" role="region" aria-label="Reference session ledger">'
        '<table class="ledger">'
        f"<caption>{html.escape(caption)}</caption>"
        '<thead><tr><th scope="col" class="num">Row</th><th scope="col">Component</th><th scope="col">Label and type</th>'
        '<th scope="col">Trust ring</th><th scope="col" class="num">Tokens</th>'
        '<th scope="col" class="num">Share</th><th scope="col">Status</th></tr></thead>'
        "<tbody>" + "".join(rows) + "</tbody>"
        f'<tfoot><tr><th scope="row" colspan="4">Template overhead</th><td class="num">{_fmt(overhead)}</td><td></td><td></td></tr>'
        f'<tr><th scope="row" colspan="4">Context window used</th><td class="num">{_fmt(used)}</td><td></td><td></td></tr></tfoot>'
        "</table></div>"
    )
