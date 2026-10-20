"""Host recognition shared by the publication link gate and the content tests.

Owner: ATACE Working Group.

One matcher, one place. This code was written for tests/test_site_content.py,
which held it through three fix rounds; it moved here when site/cxsite/gates.py
needed the same decision over built pages instead of source Markdown. A second
copy would have drifted from the first, and the failure mode of a drifted host
matcher is an identity disclosure in a double-blind submission.

The design is inverted from an allowlist of TLDs, which was tried and removed.
A finite TLD enumeration cannot close the class: `.ac.uk` and `.co.jp` defeat
single-label matching and delegation never stops. So recognise the broad host
*shape*, a dotted label sequence inside an authority, and permit only the hosts
this project is demonstrably allowed to name. An unrecognised authority is
flagged, not skipped, because a false positive is a failing gate that names the
token and a false negative is a disclosure.
"""
from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from . import SITE_ORIGIN

# The site links out only to the standards it maps to, and to the code repository.
# Any other host is a leak risk while the paper is in double-blind review.
STANDARDS_HOSTS = frozenset({
    "json-schema.org", "cyclonedx.org", "owasp.org", "genai.owasp.org", "cwe.mitre.org", "atlas.mitre.org",
    # The code repository. Reviewers get a separate anonymized copy. This host is the public tree.
    "github.com"})
SITE_HOST = urlsplit(SITE_ORIGIN).hostname
ALLOWED_HOSTS = STANDARDS_HOSTS | {SITE_HOST}
# The one address the site publishes, matched whole. A different address, or the
# same address carrying a query, is not this one and is refused.
ALLOWED_MAILTO = frozenset({"mailto:spec@cxbom.org"})

# The authority ends at the first delimiter, so a path, query or fragment is not
# mistaken for part of the host.
_AUTHORITY_CHARS = r"[^\s/?#`<>)\]]"
# What follows the authority in the same reference, up to whatever ends the
# reference in the text it was read from: whitespace, a quote, a backtick, an
# angle bracket, or a closing paren or bracket from Markdown link syntax. The
# authority group above is unchanged by this group's presence, because a group
# that can match empty cannot move where the group before it ends.
_REFERENCE_CHARS = r"[^\s\"'`<>)\]]"
# Anchored on the "//" that opens an authority, not on a scheme. A scheme is
# optional in this shape ("//host/path" is a reference all by itself) and it
# tells the authority parser nothing, so matching it was redundant: an
# upper-case "HTTPS://" or a missing scheme cannot evade a pattern that never
# looked at the scheme in the first place.
AUTHORITY_REF = re.compile(rf"//({_AUTHORITY_CHARS}*)({_REFERENCE_CHARS}*)")
# The same shape with the scheme required, and deliberately *not*
# case-insensitive. Match broadly, strip narrowly: this pattern is the only step
# in the bare-host sweep that deletes text, so every spelling it covers is a
# blind spot for that sweep. It covers the canonical lower-case form the
# documents actually write, which link_authorities has already held to the
# permitted-host list. Any other spelling ("HTTPS://", "HtTp://") falls through
# to the bare sweep instead, which flags it whatever its TLD, and a
# protocol-relative "//host" is left in place for the same reason: that shape is
# exactly what the bare sweep exists to catch. The leading lookbehind is
# case-insensitive even though the scheme is not, because without it the tail of
# "HtTp://host" still offers a lower-case "p" in front of the "://" and the
# reference would be stripped after all.
CANONICAL_AUTHORITY = re.compile(r"(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s/?#`<>)\]]*")
DECODE_ROUNDS = 8
# The label separators a host parser accepts besides the plain full stop, less
# the fullwidth stop (U+FF0E) that NFKC already folds: the ideographic full stop
# and its halfwidth form. Unlike a TLD list this set is closed by specification
# rather than by delegation policy, since the URL standard names exactly four
# label separators, so an author who types one is naming the host and a reader
# reads one. "reviewer-lab。example。net" survives Markdown rendering into the
# page unchanged, which is how it reached a built page with every other content
# gate green.
LABEL_SEPARATORS = str.maketrans({"。": ".", "｡": "."})
# Characters an IDNA mapping drops before it parses a host, spelled as escapes
# because they are invisible in source: soft hyphen, combining grapheme joiner,
# zero-width space, ZWNJ, ZWJ, word joiner, BOM. They cannot make a host
# unrecognisable to a parser, so they must not make one unrecognisable here.
# Dropping a character can only join labels, never invent a separator, so this
# cannot turn prose into a finding. A soft hyphen mid-label used to yield a
# truncated host ("lab.example.net"), which is a wrong answer rather than a
# clean miss.
IGNORABLE_IN_HOST = str.maketrans(dict.fromkeys(
    "\u00ad\u034f\u200b\u200c\u200d\u2060\ufeff"))


def decoded(text: str) -> str:
    """Undo every encoding of a separator that the page itself undoes, to a fixed point.

    All of these decodings happen downstream of the sources. markdown-it decodes
    HTML character references even with raw HTML disabled, so a source file
    reading "reviewer&#46;example&#46;net" renders a real dotted host on the
    page. A URL parser percent-decodes an authority, so "%2E" does the same
    inside a link, and then maps the separator and drops the ignorable
    characters on its way to a hostname.

    They compose, which is why this runs to a fixed point instead of once:
    "&amp;#46;" survives a single unescape, "%252E" survives a single unquote,
    and "%EF%BC%8E" only becomes a separator after percent-decoding hands a
    fullwidth stop to the fold. Bounded so a pathological input cannot spin.
    """
    for _ in range(DECODE_ROUNDS):
        nxt = unicodedata.normalize("NFKC", html.unescape(unquote(text)))
        nxt = nxt.translate(LABEL_SEPARATORS).translate(IGNORABLE_IN_HOST)
        if nxt == text:
            break
        text = nxt
    return text


def references(text: str) -> list[tuple[str, str]]:
    """Every reference the text opens an authority for, as (authority, the rest of it).

    The authority is lower-cased; the rest is left as written, because a caller
    resolving it against a built tree needs the path exactly as the page names
    it. References with an empty authority are dropped, which is what keeps a
    "// " comment marker in a script out of the results.
    """
    return [(a.lower(), rest) for a, rest in AUTHORITY_REF.findall(decoded(text)) if a]


def link_authorities(text: str) -> set[str]:
    """Every authority the text points a reference at, lower-cased.

    An authority carrying credentials comes back whole, so "user@host" fails
    the membership check even when the host after the "@" is permitted:
    "https://reviewer-lab.example.net@owasp.org/" names the identifying host
    in the document whatever a URL parser resolves it to. A port is kept for
    the same reason, rather than trimmed to a bare host that would then be
    permitted.
    """
    return {a for a, _ in references(text)}


def unpermitted_authorities(text: str) -> list[str]:
    """The authorities in `text` that are not on the permitted-host list, sorted."""
    return sorted(link_authorities(text) - ALLOWED_HOSTS)
