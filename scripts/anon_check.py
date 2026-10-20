"""Anonymity guard for commits and pushes while the paper is in double-blind review.

Owner: ATACE Working Group.

The git hooks in .githooks/ call this script, so the rule holds on every machine
that clones the repository, not only where an instruction file is read.

Fail-closed: a missing or empty `.anon-tokens` denylist is an error, never a pass.
The denylist is gitignored, one token per line, case-insensitive, with blank lines
and `#` comments skipped. It never enters a tracked file.

Usage:
    python scripts/anon_check.py staged              # pre-commit
    python scripts/anon_check.py range <rev args...> # pre-push, e.g. A..B or B --not --remotes
    python scripts/anon_check.py tree <rev>          # full scan of a revision
    python scripts/anon_check.py site <dir>          # every published file, archives unpacked
Exit 0 on pass, 1 on any finding, 2 on a usage error.

Known limits of `site`:
    Every view except the raw one is folded and decoded from the whole file and
    scanned whole, so peak memory tracks the largest file rather than a window.
    Measured peak resident memory, one process per file: 269 MiB for 8 MiB of
    prose-dense HTML, about 34 times its size, and 3.2 GiB for 32 MiB of random
    bytes, about 99 times, bounded by the 32 MiB per-file cap. Random bytes are
    the worst case for a binary, because every view of them is non-ASCII. This
    docstring said 2.4 GiB for a 32 MiB binary until round 10, and round 9's own
    code measured 2.9 GiB on the same file, so the figure was low before the
    readings and the combining-mark fold added their 8%. A page is refused by
    the expansion budget, below, before it reaches the cap. Nothing is refused
    for being dense with markup any more.

    A base64 run continues across every ASCII whitespace character, because that
    is what the reader's decoder discards. Ordinary text satisfies that shape, so a
    text file's words join into runs and each is decoded at all four alignments
    and charged to the 32 MiB expansion budget. A run met in more than one
    payload reading is decoded and charged once. Measured on prose-dense HTML at
    load 4 to 8: 40 s for 8 MiB, scanned whole; at 16 MiB the budget is spent and
    the file is refused with "expands past the scan size limit" after 76 s rather
    than half scanned, and at 32 MiB after 88 s. Round 9 refused the same 8 MiB
    page, because it decoded each run once per reading. That is the price of
    finding a name that straddles a payload wrapped with a space, a tab or an
    indent. 32 MiB of random bytes takes 122 s, where round 9 took 94 s.

    A UTF-16 document is only half decoded, and it is refused rather than
    scanned. The four utf-16 views undo no escapes and strip no markup, the
    decoded views and the payload readings are built over the UTF-8 and latin-1
    reads, and UTF-16 text is NUL-interleaved in both of those. Markup survives
    the interleaving, so a name a tag splits is still found, but an escape does
    not and a base64 payload does not: a data URI inside a UTF-16 document has a
    NUL between every two characters and no run is recognized. Scanning it would
    mean adding the four utf-16 reads as payload readings, which doubles the
    decoding every file pays and charges four more readings of mostly garbage
    against the expansion budget. So the file is refused with "wide-encoded text
    the container stage cannot read" instead, which costs nothing for a build that
    writes UTF-8 and never reports such a document clean. The test is on every
    reading and not on the file's own bytes, so a percent-encoded UTF-16 document
    inside a page is refused as well.

    An interleaving that is not NUL is not covered and does not need to be. The
    entity form of the same document, "&#0;" between every two characters, decodes
    to U+FFFD for every reader, so nothing extracts the payload from it either.

    Escapes wrapped deeper than 16 layers are not unwound, and the file is
    refused for it rather than passed. A reader only ever sees one layer decoded,
    so deeper nesting is not a hiding place, but a bound that stops scanning
    without saying so would be one.

    Right-to-left reordering is modelled for the bidi controls UAX #9 names, for
    a bdo element and for a dir="rtl" attribute: each span is scanned reversed as
    well as forwards. Any other way of reordering text, a CSS direction rule or
    an SVG text path, is covered only for a name that sits whole inside it, since
    every entry is also matched reversed. A name that one of those unmodelled
    mechanisms splits in half across the boundary is missed.

    A name is still missed when a reader cannot see it joined either: text
    hidden by a style rule, by an unclosed comment that swallows the rest of
    the file, or built at runtime by a script. Those are not hiding places so
    much as deletions, and the raw view still catches the name in the source.

    Everything the scan decompresses or unpacks goes through one dispatcher,
    whose one way out of a failure is a refusal by a fixed reason, carried beside
    whatever was decoded before the failure, which is scanned all the same. No
    decoder catches its own failure, and the test suite reads this file's syntax
    tree to keep it that way.

    A container is followed wherever its header is: at the head of the file, past
    offset zero in the file's own bytes, and past offset zero in what a decode
    reveals. Magic alone is not a header. Text spells it, this file's own source
    among it, so the fields each format fixes are read first, and only a header
    that validates is a container; from then on every failure is a refusal. The
    cost is a file that spells a complete header as escapes with nothing a
    decompressor reads after it, and it is refused. Of the 711 files of the round
    9 review corpus, the two oldest copies of this file's own test suite are the
    only ones, for a gzip header and a PDF stream header they spell as escapes.

    zlib's header is two bytes and raw deflate has none, so neither is a claim on
    its own. zlib is tried wherever its header is, and raw deflate where a payload
    begins: at the head of every reading and of every base64 decode, and just past
    a quote, a backtick, a comma, a ">", an "=" or a "(" that follows eight bytes
    of text, where a stored block, whose check is 16 bits and whose body the views
    already read, proves nothing. Each is a stream once its
    first 128 bytes (zlib) or 1,024 bytes (raw deflate) inflate without an error,
    four times the worst case measured over the review corpus: no zlib-header
    candidate that was not a stream got past 32 bytes, and no raw deflate trial
    past 240. A candidate that fails inside its proof is no stream and is not
    refused, but what whole 64-byte pieces of it inflated is read as a file of its
    own, one level deeper: names, base64 runs and containers, so raw deflate
    around a small gzip is followed into the gzip. A trial runs in every reading,
    and a reading that rewrote bytes inside the stream inflates a damaged copy.
    Where a piece from the same offset drained with no problem, a sibling's
    corrupt or truncated stream is that misreading and is not refused. Every
    other refusal and every catch stays. So a real stream damaged
    inside its first 128 or 1,024 bytes is read only as far as the damage, and
    not refused: that is the residual of reading a header this weak. A raw
    deflate payload short enough to end inside its proof is read the same way,
    and not as a proven stream, because an end proves nothing for raw deflate:
    6,045 of the corpus's non-streams ended cleanly. A failed trial suppresses
    no other candidate, strong or weak, and everything a trial spends, up to its
    64 KiB cap, is charged to the file's budget.

    Every byte any decode produces goes to one queue, through one function,
    _enqueue. What bounds that flow is behavioral: every site the dispatcher
    decodes has a test that reads a name from its output, so output a site drops
    fails a test whatever code dropped it. The test suite also reads the syntax
    tree for an early warning over names: a decoder named outside the dispatcher,
    the dispatcher's result put anywhere but _enqueue, a queue no drain reads.
    That check sees names only. A decoder reached by string through getattr or
    globals(), a queue swapped with setattr, a call made through
    functools.partial and a queue kept on a class attribute all pass it, and the
    witnesses catch each one. A queue is read for names and
    followed as containers, one level deeper: a container's members, each piece
    an unproven trial inflated, and all four alignments of every base64 run. The
    output that leaves a queue unread is output something else reads: a proven
    trial's head, which is decoded whole from the same bytes, and an unproven
    trial's output that is a copy of bytes the trial read in the file's own
    bytes, which the file's views and containers already read at the same place.
    Output past a budget is not queued, because the file is refused for it.

    Brotli has no header and is read only where a format or a name declares it: a
    woff2 font's tables and a .br asset. A PDF stream is read by the filter its
    dictionary declares. Flate is decoded or refused, a picture filter (DCT, JPX,
    CCITT, JBIG2) is left to the file's own views as a JPEG file is, and any other
    filter is refused. A stream that declares none is plain bytes the views read.

    A payload is read the way a reader might read it. A reader takes character
    references, then backslash escapes, then percent escapes, each once, in that
    order, and which of the three it applies depends on where the payload sits: a
    data URL in an attribute takes the first and the last, a JSON string in a
    script takes only the second. Bytes do not say where they sit, so every
    combination is read, each once, and a container is refused only when no
    reading of it decodes whole. The references step has a second answer as
    well, for the references the HTML spec replaces with other characters,
    "&#0;" and the 0x80 to 0x9F rows: the byte the number names, which is what a
    page script that maps the numbers itself reads. A reading equal to one
    already made is not made again, so a file with nothing to decode is read once
    and an ordinary page with entities, a script and a URL in it about eight times.

    A payload encoded twice in one layer, a percent escape of a percent escape,
    is not unwound for the container reading, because no reader unwinds it:
    a data URL decodes once. The text reading still decodes it to a fixed point,
    so a name written that way is found either way.

    A percent escape that names a latin-1 byte rather than a UTF-8 sequence,
    "zzs%E9cret", decodes to U+FFFD in the text reading, which reads a percent
    escape as UTF-8, so a name spelled that way is missed. Only the container
    reading keeps the byte, and it scans for containers, not names. A current
    browser also decodes a percent escape as UTF-8, so the spelling reads as the
    name only to a legacy server.

    A multi-part entry written with a separator inside it is found: "peopleco"
    written "people-co", "people co", "people_co" or "people.co". The denylist does
    not say where an entry's parts are, so a space, a hyphen, an underscore or a
    dot may stand between any two of its letters, and what keeps that off ordinary
    English is where the run starts and ends: on a word boundary at both ends,
    where a hyphen, an underscore or a dot running on into more of a word is no
    boundary. "the people could" is no finding, and neither is "people co-authored".
    Every one of the 29 code points Python calls whitespace folds to a space, so a
    one-word entry split by any of them between two whole words is found. Split
    inside a word that runs on, it is found only for the six characters no
    rendering standard calls whitespace, U+000B, U+001C to U+001F and U+0085, which
    are also scanned erased.

    That is not free, and it was measured the way round 8 measured erasing every
    space, over the 230 files of the review corpus's round 9 tree: of 205,276
    dictionary words between 6 and 14 letters, standing in for the one-word entries
    a denylist really holds, 258 become findings the substring rule does not
    produce, 683 at file level. Erasing all 29 spaces gave 1,947 on the merged tree
    of the same size. What remains is two whole words that spell a third: "so
    this", "see the", "by name", "a fresh", "re.compile", and "for t in" spelling
    Fortin. Runs joined by a space account for 190 of the 258 and runs joined by a
    hyphen, an underscore or a dot for 70, most of those real compounds such as
    "co-author". Dropping the space from the separators is one edit and takes the
    190 with it, along with "People Co". The real ten-entry denylist fires no
    extra time on the 711-file corpus.

    Combining marks, Mn and Me, are folded out of the text and of every entry
    before anything is compared, because one drawn between two letters takes no
    advance and reads as part of the name. A precomposed accent is a letter and
    stays one.
"""
from __future__ import annotations

import base64
import bisect
import functools
import hashlib
import html
import io
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import unicodedata
import urllib.parse
import zipfile
import zlib
from array import array
from pathlib import Path
from typing import Generator, Iterator

REQUIRED_IDENTITY = "CxBOM <noreply@cxbom.org>"
DENYLIST_NAME = ".anon-tokens"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout


def _git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True).stdout


def load_tokens(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip().lower() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def require_tokens(tokens: list[str]) -> list[str]:
    if tokens:
        return []
    return [f"{DENYLIST_NAME} missing or empty; refusing to certify anonymity. "
            f"Copy the denylist into the repository root (it is gitignored)."]


def check_identity(ident: str, role: str) -> list[str]:
    # `git var` appends a timestamp and zone after the email, so compare the prefix.
    if ident.startswith(REQUIRED_IDENTITY):
        return []
    return [f"{role} identity is not {REQUIRED_IDENTITY!r}; run "
            f"`git config user.name CxBOM && git config user.email noreply@cxbom.org`"]


def scan_text(name: str, text: str, tokens: list[str]) -> list[str]:
    low = text.lower()
    return [f"{name}: contains a denylisted token (#{i + 1} in {DENYLIST_NAME})"
            for i, t in enumerate(tokens) if t in low]


def _decode(blob: bytes) -> str:
    # latin-1 maps every byte, so binary files (images, fonts, PDFs) are scanned too.
    # Their metadata is a common place for an author name to hide.
    return blob.decode("latin-1")


def check_staged(repo: Path, tokens: list[str]) -> list[str]:
    errs: list[str] = []
    errs += check_identity(_git(repo, "var", "GIT_AUTHOR_IDENT"), "author")
    errs += check_identity(_git(repo, "var", "GIT_COMMITTER_IDENT"), "committer")
    names = [n for n in _git(repo, "diff", "--cached", "--name-only", "-z",
                             "--diff-filter=ACMR").split("\0") if n]
    for name in names:
        if Path(name).name == DENYLIST_NAME:
            errs.append(f"{name}: the denylist must never be committed")
            continue
        errs += scan_text(name, _decode(_git_bytes(repo, "show", f":{name}")), tokens)
    return errs


def _rev_present(repo: Path, endpoint: str) -> bool:
    # Fail-closed resolvability probe. `--verify --quiet` exits nonzero with no
    # output when the object is absent, so it never raises or prints a traceback.
    # The `^{commit}` peel forces an object lookup, which is what fails on a push
    # race or a force-updated remote when the endpoint is not in the local store.
    return subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{endpoint}^{{commit}}"],
                          cwd=repo, capture_output=True, text=True).returncode == 0


def _missing_range_endpoints(repo: Path, rev_args: list[str]) -> list[str]:
    # The revision endpoints named in the pre-push range that git cannot resolve
    # locally. Flags (`--not`, `--remotes`, ...) and the empty side of a range
    # (which defaults to HEAD and is always present) are skipped.
    missing: list[str] = []
    for arg in rev_args:
        if arg.startswith("-"):
            continue
        for endpoint in arg.replace("...", "..").split(".."):
            endpoint = endpoint.strip()
            if endpoint and endpoint not in missing and not _rev_present(repo, endpoint):
                missing.append(endpoint)
    return missing


def check_range(repo: Path, rev_range: str | list[str], tokens: list[str]) -> list[str]:
    rev_args = [rev_range] if isinstance(rev_range, str) else list(rev_range)
    fmt = "%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e"
    try:
        log = _git(repo, "log", f"--format={fmt}", *rev_args)
    except subprocess.CalledProcessError:
        # The pre-push hook builds the range from the remote sha git advertised.
        # On a push race, or when the remote was force-updated, that sha is not
        # yet in the local object store and `git log <remote>..<local>` aborts.
        # This is the anonymity gate, so fail closed with a clean, actionable
        # message rather than a traceback, and never let the push pass unscanned.
        missing = _missing_range_endpoints(repo, rev_args)
        if missing:
            return [f"push range unresolved: {', '.join(missing)} not in local object store. "
                    f"Fetch origin and retry. The remote moved, a push race or a "
                    f"force-updated remote."]
        return [f"git could not resolve the push range {' '.join(rev_args)!r}. "
                f"Refusing to certify anonymity. Fetch origin and retry."]
    errs: list[str] = []
    for rec in log.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, author, committer, message = rec.split("\x1f", 3)
        short = sha[:10]
        errs += [f"{short} {e}" for e in check_identity(author, "author")]
        errs += [f"{short} {e}" for e in check_identity(committer, "committer")]
        errs += scan_text(f"{short} message", message, tokens)
    return errs


def check_tree(repo: Path, rev: str, tokens: list[str]) -> list[str]:
    errs: list[str] = []
    names = [n for n in _git(repo, "ls-tree", "-r", "-z", "--name-only", rev).split("\0") if n]
    for name in names:
        if Path(name).name == DENYLIST_NAME:
            errs.append(f"{name}: the denylist is tracked in {rev}")
            continue
        errs += scan_text(name, _decode(_git_bytes(repo, "show", f"{rev}:{name}")), tokens)
    return errs


# ---------------------------------------------------------------------------
# Site mode: scan a directory that is about to be published, such as site/dist.
#
# Every file is scanned as bytes under several text views (raw, UTF-8, UTF-16,
# latin-1, and a decoded view that undoes markup, entities, percent and
# backslash escapes). Containers are recognized by their headers, not by file
# extension, in every payload reading of the file, and unpacked recursively
# through the one dispatcher, _dispatch: zip (and .whl), tar, gzip, zlib, raw
# deflate, xz, bzip2, zstd where the runtime has it, woff and woff2 fonts, PNG
# text chunks and image data, PDF streams by their declared filter, brotli where
# declared, and base64 runs. A container that cannot be decoded is a finding, so
# the scan fails closed.
#
# Output names a file by its base name only, and a name that itself matches the
# denylist is withheld. The token class is the token's entry number in the
# denylist, counting only entries. No message ever carries the token, because CI
# logs are public during review.
# ---------------------------------------------------------------------------

# Bounds on untrusted input. A decompression bomb or a deeply nested archive
# must end the scan with a finding, not exhaust memory or recursion.
SITE_MAX_EXPANDED = 32 * 1024 * 1024
SITE_MAX_BLOB = 32 * 1024 * 1024
# Nothing is scanned in windows. Filler can be encoded to any depth, so no
# pattern can name all of it, and a window boundary inside filler hides the name
# it splits. Every view is therefore built from the whole file: folding and
# decoding only ever shorten text, so a view is never larger than what it came
# from. Windowing the raw scan alone was measured and saved nothing, because the
# folded views dominate the cost either way.
# Decoding runs to a fixed point. Every decoder here shortens its input, so the
# loop settles, and the bound only stops a pathologically deep encoding.
SITE_MAX_DECODE = 16
SITE_MAX_DEPTH = 8
WITHHELD = "[name withheld]"

# Characters a reader never sees, so a name written around one reads whole. The
# set is the union of three authorities, none of them this file's own behaviour:
#   Unicode general category Cf, the format characters a renderer consumes, and
#     the Cc controls Unicode does not class as whitespace. The whitespace Cc
#     characters are left in, because collapsing whitespace below already turns
#     each of them into one space.
#   The invisible letters and marks NFKC leaves alone: Hangul fillers, the
#     combining grapheme joiner, Khmer inherent vowels, variation selectors, and
#     the tag block in full, so the unassigned holes in it are covered too.
#   Code points measured to draw nothing: U+2800, the braille blank, which is
#     zero ink with a 43.75 px advance at 64 px serif in Chrome 153.
#   Default_Ignorable_Code_Point (Unicode DerivedCoreProperties) in full,
#     assigned or not. Round 9 covered every assigned one and missed U+FFF0 to
#     U+FFF8, which are unassigned: Chrome 153 draws U+FFF0, U+FFF4 and U+FFF8 at
#     a 0 px advance and no ink, the exact class this set exists for.
# The ranges are committed rather than derived at import, because walking
# unicodedata would slow every git hook that imports this file. The test
# re-derives them from unicodedata and from the property's published ranges,
# and fails if this class is any narrower.
#
# Combining marks (Mn, Me) are not in this set, because erasing one from the
# middle of a word it belongs to is not the same as erasing an invisible
# character. They are folded out instead, from the text and from every entry
# alike: see _fold.
#
# A format character that a font does supply a glyph for is erased here anyway:
# U+0600 draws ink in Chrome 153, so a name written around it does not really
# read whole. Erasing too much costs a false finding, which fails closed;
# erasing too little hides a name.
_INVISIBLE = re.compile("[\u0000-\u0008\u000e-\u001b\u007f-\u0084\u0086-\u009f"
                        "\u00ad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891"
                        "\u08e2\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
                        "\u202a-\u202e\u2060-\u206f\u2800\u3164\ufe00-\ufe0f"
                        "\ufeff\uffa0\ufff0-\ufffb\U000110bd\U000110cd"
                        "\U00013430-\U0001343f\U0001bca0-\U0001bca3"
                        "\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")
# The dash variants NFKC leaves alone.
_DASHES = str.maketrans(dict.fromkeys(
    "\u058a\u05be\u1400\u1806\u2010\u2011\u2012\u2013\u2014\u2015\u2212"
    "\u2e17\u2e1a\u2e3a\u2e3b\u2e40\u301c\u3030\u30a0\ufe31\ufe32", "-"))
# The characters Python calls whitespace that no rendering authority does. The
# fold collapses whitespace with str.split(), so every one of the 29 code points
# str.isspace() accepts becomes a space. A one-word entry split by one between two
# whole words is found by the separator rule at _split_patterns. Split inside a
# word that runs on, a space, a Zs, a Zl, a Zp or one of the five characters CSS
# names as whitespace is a gap a reader sees, so erasing it there would invent
# findings on prose. What is left is where str.split() took a decision no
# renderer agrees to:
#   Python whitespace - CSS whitespace - (Zs | Zl | Zp) - measured as a space
# and it is scanned both ways, spaced and erased, so no renderer and no font has
# to be right for the name to be found. Derived by that set expression in the
# test; committed here because walking unicodedata at import would slow every git
# hook that imports this file.
#
# U+000B is in it. Round 7 took it out on one browser measurement, a 16 px advance
# at zero ink, while U+000E, measured at a larger 21.3 px advance at zero ink, was
# erased: the rule spaced the smaller gap and erased the larger one, and a name
# written around a vertical tab passed in every form the build emits. An advance
# is one renderer's answer, so it no longer decides anything here. The authority
# does: U+000B is a control character that no rendering standard calls
# whitespace, so it is read both ways like the other five. U+2009 and U+200A stay
# spaced for the same reason in the other direction: they are Zs, and a Zs is a
# gap by definition, however narrow a font draws it.
#
# Widening this to all 29 is one edit and it was measured rather than argued.
# Over the 230 tracked files of the merged tree, 1,947 of 205,276 dictionary words
# of 6 to 14 letters become findings the six-character set does not produce,
# because erasing a space joins every pair of adjacent words, wherever each starts
# and ends: "turner" out of "return errs" is a plausible surname and goes from 3
# findings to 17 on those files. The separator rule joins whole words only and
# costs 258 on the same kind of tree; the docstring carries both measurements. Do
# not widen this without measuring again, on the tree the code will run against.
_AMBIGUOUS_SPACE = re.compile("[\u000b\u001c-\u001f\u0085]")
# CSS Syntax 3, section 4.2: whitespace is newline (line feed, carriage return,
# form feed), tab and space. HTML's "ASCII whitespace" is the same five.
_CSS_WHITESPACE = "\t\n\f\r "
# A numeric character reference, with or without its semicolon. The HTML spec
# bounds neither its digits nor its leading zeros, so neither does this. The
# value is read by _code_point, which strips the zeros and answers None for a run
# too long to name a code point, both because the spec's answer there is U+FFFD
# and because int() refuses a 4300-digit string outright.
_NUM_REF = re.compile(r"&#([0-9]+|[xX][0-9a-fA-F]+);?")
# The C0 controls and DEL that html.unescape returns "" for and the HTML spec
# emits. WHATWG HTML, numeric character reference end state: a control is a
# parse error, but the code point still reaches the DOM, and Chrome 153 does emit
# them. So "zz first&#11;last" decodes to a vertical tab and is read both ways,
# as the two-word name and as "zz firstlast", rather than decoded and dropped.
#
# U+0000 and the 0x80-0x9F rows are deliberately absent: the spec replaces those
# (U+0000 with U+FFFD, "&#133;" with an ellipsis, which Chrome agrees with) and
# html.unescape already applies the same replacements. Tab, newline, form feed
# and carriage return are absent because html.unescape passes them through.
_SPEC_CONTROLS = frozenset(range(0x01, 0x09)) | {0x0B} | frozenset(range(0x0E, 0x20)) | {0x7F}
_JS_ESC = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_WS_ESC = re.compile(r"\\[nrt]")
_CSS_ESC = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?")
# A backslash before a real line break is a continuation in both JavaScript and
# CSS: the pair disappears. Before anything else that is not a hex digit, the
# backslash disappears and the character stays, whitespace included, which is
# how "\ " hides the space in a two-word entry.
_LINE_CONT = re.compile(r"\\(?:\r\n|[\r\n\f\u2028\u2029])")
_CHAR_ESC = re.compile(r"\\([^0-9a-fA-F])")
# Any run long enough to carry a name once base64-encoded, data URI or not.
# A run continues across exactly the filler the reader's decoder throws away, and
# that is every ASCII whitespace character: forgiving-base64 (WHATWG HTML), which
# is what atob() and a data URI run, strips all five and then refuses anything
# else in the alphabet's place. Listing the two line breaks a wrapped payload
# usually uses left a name straddling a payload wrapped with a space, a tab, a
# form feed, a vertical tab or a newline and an indent -- the ordinary shape in
# XML, YAML and pretty-printed JSON -- in no single decode. An escaped line break
# needs no alternative here any more: the run finder reads a normalized source,
# where "\n" is already a space.
#
# The reader is the authority and not _b64 below, which calls b64decode with
# validate=False and so discards every non-alphabet byte, NUL and "<" included.
# Crossing everything that decoder crosses would make one run of a whole file and
# join text no reader could ever join, so the two do not agree and should not: a
# run this finder declines is a run no browser would have decoded either.
# Only the first segment needs 4 characters. A later one can be shorter, since
# the last line of a wrapped payload can hold as little as one character before
# its "=" padding, and dropping that line truncates the decoded bytes.
_B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{4,}(?:[ \t\n\v\f\r]+[A-Za-z0-9+/_-]+)*")
_B64_WRAP = re.compile(rb"[ \t\n\v\f\r]+")
_B64_MIN = 16
# Cyrillic and Greek letters that render like Latin ones. NFKC keeps them
# distinct, so "zz-s\u0435cret" (Cyrillic e) would read as the name yet pass.
_CONFUSABLES = str.maketrans("\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u04bb\u0501"
                             "\u03b1\u03bf\u03c1\u03bd\u03b9\u03ba\u03c4\u0261",
                             "aeopcyxijshdaopvikt" "g")
# Elements whose text a reader never sees. Matched case-insensitively on the
# text itself, because lowercasing a copy first can change its length.
_HIDDEN_START = re.compile(r"<(?:script|style)\b", re.I)
_HIDDEN_END = re.compile(r"</\s*(?:script|style)\b", re.I)
# Reader-side reordering. Text under a right-to-left override is laid out from
# the right, so a name written backwards reads forwards and no forward view holds
# it: CVE-2021-42574 aimed at an anonymity gate rather than at a code reviewer.
# Erasing the controls, which the invisible class does, destroys the only
# evidence that the displayed order is not the stored order.
#
# Two answers, and neither models bidi. A span an override opens is scanned
# reversed as well as forwards, which covers a name the boundary splits in half.
# And every denylist entry is matched against its own reverse, which covers a
# reordering this module does not model at all -- a CSS direction rule, an SVG
# text path, a font built backwards -- for as long as the whole name sits inside
# it. Over-reaching a span costs nothing, because the forward view stays.
# UAX #9: LRE, RLE, LRO, RLO and the three isolate initiators open; PDF and PDI
# close. HTML: bdo overrides, and dir="rtl" sets the base direction.
# The controls are written as escapes, never as themselves: a literal bidi
# character in source is the very trick this pair exists to catch.
#
# Every run inside a tag excludes "<" as well as ">". With "[^>]*" a "<" that is
# never closed sends the scan to the end of the text and back from every later
# one, which is the quadratic rescan the markup pass was rewritten to lose: it
# cost 786 s on 896 KiB of "if(a<b)". Stopping at the next "<" bounds each tag by
# the distance to its neighbour. The cost is a tag whose attribute value holds a
# "<", which loses this view and no other.
_BIDI_OPEN = re.compile(r"[\u202a\u202b\u202d\u202e\u2066-\u2068]"
                        r"|<\s*bdo\b[^<>]*>"
                        r"|<[^<>]*\bdir\s*=\s*[\"']?rtl\b[^<>]*>", re.I)
_BIDI_CLOSE = re.compile(r"[\u202c\u2069]|</[^<>]*>")
# The magic bytes _container_kind recognizes, searched anywhere rather than at a
# head, so a container glued into or escaped inside the middle of a file is found.
# Matched as bytes, so no decode is involved. A hit is only a candidate until
# _valid_container reads the header behind it.
#
# gzip is matched with its compression-method byte, which _container_kind does not
# need: RFC 1952 defines only CM=8, deflate. A tar carries "ustar" 257 bytes into
# its header rather than at its head, so it has a pattern of its own.
_CONTAINER_MAGIC = re.compile(rb"PK\x03\x04|PK\x05\x06|\x1f\x8b\x08|\xfd7zXZ\x00"
                              rb"|BZh|\x28\xb5\x2f\xfd|wOF2|wOFF|\x89PNG|%PDF-")
_MAGIC_KIND = {b"PK\x03\x04": "zip", b"PK\x05\x06": "zip", b"\x1f\x8b\x08": "gzip",
               b"\xfd7zXZ\x00": "xz", b"BZh": "bzip2", b"\x28\xb5\x2f\xfd": "zstd",
               b"wOF2": "woff2", b"wOFF": "woff", b"\x89PNG": "png", b"%PDF-": "pdf"}
# POSIX writes "ustar" NUL "00", GNU tar writes "ustar" and two spaces and a NUL.
_TAR_MAGIC = re.compile(rb"ustar(?:\x0000| {2}\x00)")
# A bzip2 stream's first block starts with the digits of pi, and an empty stream
# with the digits of its square root.
_BZIP2_BLOCK = (b"\x31\x41\x59\x26\x53\x59", b"\x17\x72\x45\x38\x50\x90")
# The compression methods APPNOTE 4.4.5 assigns.
_ZIP_METHODS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 19, 20,
                          93, 94, 95, 96, 97, 98, 99})
_PDF_HEADER = re.compile(rb"%PDF-[0-9]\.[0-9]")
# UTF-16 and UTF-32 put a NUL between the bytes of every ASCII character, and the
# container stage reads only the UTF-8 and latin-1 decodes, where that
# interleaving survives. A base64 payload or an archive inside such a document is
# never recognized, so the document is refused rather than reported clean.
#
# Both byte orders of both encodings begin with one of these two byte pairs
# (UTF-32-LE's mark starts with UTF-16-LE's), which settles a document that
# declares itself. A document without a mark is settled by the interleaving
# itself, below.
_WIDE_BOM = (b"\xff\xfe", b"\xfe\xff")
# Long enough that a UTF-16 string embedded in a binary cannot satisfy the test
# by accident: a font's name record or a PE resource is a few dozen bytes of
# interleaved text inside a file that is not interleaved at all.
_WIDE_MIN = 64
# A real document is not perfectly interleaved -- a non-ASCII character fills its
# high byte -- so the filler test is a proportion and not an equality. 95% is wide
# enough for prose in any Latin script and narrow enough that no file in the
# 1,217-file corpus reaches it without being wide-encoded.
_WIDE_FILLER_NUL = 0.95
# And the text half has to be a text half. A tar, a zip and a PNG are all sparse
# enough that every stride's filler is over 95% NUL, and their text halves are
# just as NUL-heavy: interleaving means one half carries the text and the other
# carries the NULs, not that both do. Without this the clean-tree fixture was
# refused for holding an ordinary archive.
_WIDE_TEXT_NUL = 0.10

# zlib, RFC 1950 2.2: CMF names deflate (CM = 8) with a window of at most 32 KiB
# (CINFO <= 7), FLG makes CMF * 256 + FLG a multiple of 31, and FDICT, a preset
# dictionary no web reader holds, is clear. That is two bytes: about one position
# in a thousand of random binary satisfies it, and so does "x " in prose. So a
# header is a candidate and never proof, and _proven below settles it.
_ZLIB_PAIRS = [bytes((cmf, flg)) for cmf in range(0x08, 0x80, 0x10) for flg in range(256)
               if (cmf * 256 + flg) % 31 == 0 and not flg & 0x20]
# The first byte of a deflate block a weak candidate can prove itself by: a
# Huffman-coded block, fixed (BTYPE 1) or dynamic (BTYPE 2) naming at most 286
# literal and length codes. See _deflate_head for why a stored block is not one.
_HUFFMAN_OPENERS = bytes(b for b in range(256)
                         if b >> 1 & 3 == 1 or (b >> 1 & 3 == 2 and b >> 3 <= 29))
_HUFFMAN_OPENER = b"[" + b"".join(re.escape(bytes([b])) for b in _HUFFMAN_OPENERS) + b"]"
# The CMF byte is matched and not looked ahead of, so the engine scans for one
# of eight byte values and checks the rest only there. A pattern that opens
# with a lookahead gives it no byte to scan for, and it ran the check at every
# position of every reading: 30 s on 8 MiB of random bytes.
_ZLIB_HEAD = re.compile(b"|".join(
    re.escape(bytes([cmf])) + b"(?=[" + b"".join(re.escape(p[1:]) for p in _ZLIB_PAIRS
                                                if p[0] == cmf) + b"]" + _HUFFMAN_OPENER + b")"
    for cmf in range(0x08, 0x80, 0x10)))
# Raw deflate has no header at all, and DecompressionStream("deflate-raw") is as
# available to a page as "gzip" is. It is tried where a payload begins: at the
# head of every reading and of every base64 decode, and just past a character
# that opens a payload in text -- a quote, a backtick, the comma that ends a data
# URL's media type, the ">" that opens an element's text, the "=" of an unquoted
# attribute, the "(" of a CSS url() or a call. In text, which is what the bytes
# before it are, up to eight of them: a payload opens after "const b = \"",
# "data:x/y," or "<pre>", and in binary those characters are only bytes. Random
# bytes spell eight printable ones in a row about five times in ten thousand, so
# a font or an image no longer turns every delimiter-valued byte into a trial:
# that was 2.65 million trials on 8 MiB of random bytes.
# The delimiter is matched first and the text before it is looked behind from
# there, for the same reason _ZLIB_HEAD matches its first byte. A lookbehind has
# one width, so the head of a reading, where fewer than eight bytes stand before
# a delimiter, takes one anchored alternative per width.
_DELIMITER = rb"[\"'`,>=(]"
_TEXT_BEFORE = (rb"(?:(?<=[\t\n\r -~]{8}" + _DELIMITER + rb")"
                + b"".join(rb"|(?<=^[\t\n\r -~]{%d}" % k + _DELIMITER + rb")" for k in range(8))
                + b")")
_PAYLOAD_START = re.compile(_DELIMITER + _TEXT_BEFORE + rb"(?=" + _HUFFMAN_OPENER + rb")")
# How much of a weak candidate must inflate without an error before it counts as
# a stream. Measured, not chosen: over the 711 files of the round 9 review corpus,
# the 18,128 zlib-header candidates that were not streams all failed within 32
# bytes and none reached an end. The 1,589,758 raw deflate trials at payload
# starts all failed within 240 bytes, and 6,045 of them reached an end, so an end
# proves nothing for raw deflate. Each proof is four times the worst case seen.
_PROOF = {"zlib": 128, "deflate": 1024}
# A trial reads at most this much output, and whatever it reads, up to all of
# this, is charged to the file's budget.
_TRIAL_OUTPUT = 1 << 16
# Compressed input is fed this many bytes at a time, so a failure keeps whatever
# was inflated before the piece it happened in. zlib raises and hands back nothing
# from the call that fails, and round 9 fed each stream in one call, so a damaged
# stream lost everything that came before the damage.
_FEED = 64
_NULS = re.compile(rb"\0*")
# A PDF stream keyword where PDF grammar puts one: right after the closing ">>"
# of its dictionary (ISO 32000-1 7.3.8.1), and not the tail of "endstream". Text
# that mentions a Flate filter and ends a line with the word "stream" is not a
# stream, and this file's own test suite is such text.
_PDF_STREAM = re.compile(rb">>\s*(?<!end)stream\r?\n")
# The first filter a stream dictionary names, which is the encoding its bytes
# are written in.
_PDF_FILTER = re.compile(rb"/Filter\s*\[?\s*/([A-Za-z0-9]+)")
_PDF_FLATE = frozenset({b"FlateDecode", b"Fl"})
# A name may write any byte as "#" and two hex digits (ISO 32000-1 7.3.5), so
# "/Fil#74er" is "/Filter". And a filter may be an indirect reference to an
# object that holds the name or an array of names.
_PDF_NAME_ESCAPE = re.compile(rb"#([0-9a-fA-F]{2})")
_PDF_FILTER_REF = re.compile(rb"/Filter\s*([0-9]+)\s+([0-9]+)\s+R")
# Filters that encode a picture. A picture's bytes are text in no file the scan
# reads, a JPEG on its own included, so a stream in one is left to the file's own
# views, as a JPEG file is. Every other filter encodes arbitrary bytes the scan
# does not decode, and a stream written in one is refused rather than passed.
_PDF_PICTURE = frozenset({b"DCTDecode", b"DCT", b"JPXDecode", b"CCITTFaxDecode", b"CCF",
                          b"JBIG2Decode"})


_LIMIT = "expands past the scan size limit"


class _Refuse(Exception):
    """A decode that stopped short. The reason is fixed text, never library text,
    because library errors can quote member names.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Work:
    """What decoding one published file may cost, spent as it is spent.

    Every byte any decode produces is charged the moment it is produced, whether
    that decode goes on to finish or not. Round 9 charged a stream only when it
    returned, so a multi-member stream over the budget raised at its first member
    and was then decompressed again, uncharged, from each later member header:
    5,000 members of 64 KiB took 84.6 s to refuse. Spent is spent here, and once
    the budget is gone every decode after it refuses at once.
    """

    def __init__(self, limit: int) -> None:
        self.left = limit
        self.exhausted = False
        # The limit is refused once per file. Every decode after it refuses for the
        # same reason, and one line per stream would bury the one that matters.
        self.reported = False

    def spend(self, n: int) -> bool:
        # Charge n, or mark the budget exhausted and say so. For the callers that
        # are not inside a decoder and so have no refusal to raise into.
        if n > self.left:
            self.left = 0
            self.exhausted = True
            return False
        self.left -= n
        return True

    def take(self, n: int) -> None:
        if not self.spend(n):
            raise _Refuse(_LIMIT)


class _Sink:
    """Where a decoder writes, which is what bounds it: no decoder holds output
    of its own. A decoder asks for at most room() bytes per call, so a bomb is
    refused one 1 MiB piece past the budget and never exists whole.
    """

    def __init__(self, work: _Work) -> None:
        self.work = work
        self.out = bytearray()
        # How far into its input the decoder has read, for the extent it covers,
        # and how far it has been fed, which is where a failure can lie.
        self.used = 0
        self.fed = 0

    def room(self) -> int:
        return min(1 << 20, self.work.left + 1)

    def add(self, piece: bytes) -> None:
        self.work.take(len(piece))
        self.out += piece


class _Result:
    """What one decode produced: every output, partial ones included; the byte
    ranges of its input it read; and, when it stopped short, the one fixed reason.
    """

    __slots__ = ("parts", "extents", "refusal", "stopped", "tail", "fed")

    def __init__(self) -> None:
        self.parts: list[tuple[str, bytes]] = []
        self.extents: list[tuple[int, int]] = []
        self.refusal = ""
        # A piece inside a structure that stopped short. The structure reads on,
        # so its other pieces are still scanned, and the first of these becomes its
        # refusal when it is done.
        self.stopped: list[str] = []
        # What follows a tar's last member, where a zip can be glued.
        self.tail = b""
        # For a codec, the end of the input it was fed: every byte its outcome can
        # depend on. A structure leaves it at zero.
        self.fed = 0


def _dispatch(kind: str, data, work: _Work, scan: "_SiteScan | None" = None,
            chain: list[str] | None = None, start: int = 0) -> _Result:
    """The one way anything in this file is decompressed or unpacked.

    It returns decoded output, or a refusal with a fixed reason beside whatever was
    decoded before the failure, which the caller scans all the same. There is no
    third answer: no decoder below catches its own failure, and this handler turns
    every failure into a refusal. Round 9 closed the skip-on-corrupt branch for four
    stream kinds and left it in the PDF reader, where a damaged Flate stream and a
    JSON-escaped PDF both came back clean. One exit for every failure closes that
    class by construction, and tests/test_anon_check.py walks this file's syntax
    tree to keep it closed.
    """
    res = _Result()
    if work.exhausted:
        res.refusal = _LIMIT
        return res
    sink = _Sink(work)
    structure = _STRUCTURES.get(kind)
    try:
        if structure is not None:
            structure(data[start:], work, res, scan, chain or [])
        else:
            _CODECS[kind](data, start, sink)
    except Exception as exc:  # the one refusal path
        res.refusal = exc.reason if isinstance(exc, _Refuse) else _CORRUPT[kind]
    if structure is not None:
        res.extents = [(start + b, start + e) for b, e in res.extents]
    else:
        res.extents.append((start, sink.used))
        res.fed = sink.fed
        # Output past the budget is dropped rather than scanned: the file is refused
        # for it either way, and scanning a bomb's first 32 MiB costs 2.4 GiB.
        if sink.out and res.refusal != _LIMIT:
            res.parts.append((_LABEL[kind], bytes(sink.out)))
    if not res.refusal and res.stopped:
        res.refusal = res.stopped[0]
    return res


def _enqueue(queue: list[tuple[str, bytes]], res: _Result, prefix: str = "",
             rename: str = "") -> _Result:
    """The one place a dispatcher result's output goes: every part of it, moved
    into queue, and the result handed back with no parts left to drop.

    The bound on this flow is behavioral: tests/test_anon_check.py has a witness
    for every site the dispatcher decodes, a file whose name lies only in that
    site's output, so output any code drops fails a test. The same file also
    reads the syntax tree, as an early warning over names only: it flags a
    decoder or its table named outside _dispatch, _dispatch named other than as
    this function's second argument, this function called lazily, a queue that
    no traced parameter carries to a drain, and a queue cleared or cut outside
    drain and _proven's two documented releases. It does not see a reflective
    lookup. getattr or globals() reaching a decoder by string, setattr swapping
    a queue, functools.partial hiding a call site and a queue kept on a class
    attribute all pass it, and the witnesses kill each of the five. Round 12
    held only the call shape, and a decoder reached through _CODECS, or a lambda
    over a throwaway queue, dropped every decoded PNG image byte with the whole
    suite green.
    Round 9 dropped a damaged PDF stream's output, round 10 read a failed trial's
    output for names only, and round 11 charged a shifted base64 alignment's
    trial and threw its output away: three rounds, three new places. A queue is
    drained by _SiteScan.drain, which scans every part for names and follows it
    as a container; a structure's queue is its own result's parts, which the
    dispatcher that called it hands on the same way. The one output that never
    reaches a queue is what a decode produced past a budget: the file is refused
    for the file's budget, and a trial that reached its own cap is proven and
    decoded whole from the same bytes.
    """
    queue += [(rename or prefix + label, out) for label, out in res.parts]
    res.parts = []
    return res


# Any code point outside the BMP, as one range.
_ASTRAL = re.compile("[\U00010000-\U0010ffff]")


@functools.cache
def _mark_classes() -> tuple[re.Pattern[str], frozenset[str]]:
    # Every combining mark, Mn and Me: the BMP ones as a character class and the
    # rest as a set. Built on first use rather than at import, because walking
    # unicodedata costs about 0.3 s and every git hook imports this file; only
    # site mode ever folds text. Derived from the running interpreter's own tables,
    # so they and the normalization beside them agree on the Unicode version.
    # Split because sre matches a class that fits the BMP through a bitmap and one
    # that reaches past it range by range: one class of all 354 ranges searched
    # 200,000 characters in 42 ms, the BMP class alone in 0.5 ms. The astral marks
    # are checked one character at a time instead, because random bytes read as
    # UTF-16 hold an astral character in every 4,096 code units, and the astral
    # class took 0.55 s to search and strip 4 million characters that the set
    # takes 0.01 s over.
    spans: list[list[int]] = []
    for cp in range(0x110000):
        if unicodedata.category(chr(cp)) in ("Mn", "Me"):
            if spans and spans[-1][1] == cp - 1:
                spans[-1][1] = cp
            else:
                spans.append([cp, cp])

    bmp = re.compile("[" + "".join(f"\\U{lo:08x}-\\U{min(hi, 0xFFFF):08x}"
                                   for lo, hi in spans if lo <= 0xFFFF) + "]")
    return bmp, frozenset(chr(cp) for lo, hi in spans for cp in range(max(lo, 0x10000), hi + 1))


def _drop_marks(text: str) -> str:
    bmp, astral = _mark_classes()
    if bmp.search(text):
        text = bmp.sub("", text)
    if _ASTRAL.search(text):
        text = _ASTRAL.sub(lambda m: "" if m.group() in astral else m.group(), text)
    return text


def _fold(text: str) -> str:
    # One canonical form for tokens and text: compatibility-normalized (full-width
    # letters become ASCII), combining marks dropped, lowercase, invisible format
    # characters dropped, dash variants unified, whitespace collapsed.
    #
    # A combining mark takes no advance and draws on the letter before it, so
    # "zzsecret" + U+0335 + "person" reads as the name with a stroke through one
    # letter. Round 9 missed all 1,770 Mn and Me code points that way. Refusing
    # them would refuse most text in most scripts, so they are folded out of the
    # matching form instead, from the text and from every entry alike. They are
    # dropped before NFKC, so a mark written between two letters is gone before
    # composition could fuse it with the one before it. A precomposed accent is a
    # letter and stays one: it is how a name is spelled, not something hidden in
    # it. Dropping them after a full decomposition was measured at four times the
    # cost of this fold on the review corpus, for that one case.
    if not text.isascii():
        text = unicodedata.normalize("NFKC", _drop_marks(text))
    # Lowercasing U+0130 is the one unconditional case mapping that emits a mark,
    # U+0307 after the "i", so that mark is dropped again here.
    text = text.lower().replace("\u0307", "").translate(_CONFUSABLES)
    return " ".join(_INVISIBLE.sub("", text).translate(_DASHES).split())


def _folds(text: str) -> Iterator[str]:
    # Both readings of the characters str.split() spaces and no renderer does.
    # A one-word entry split by one of them is only found in the second reading,
    # and the round-6 squeeze cannot reach it, because the squeeze runs only for
    # an entry that holds a space of its own. The second view is built only when
    # one of the six characters is present, so an ordinary file pays a search.
    yield _fold(text)
    if _AMBIGUOUS_SPACE.search(text):
        yield _fold(_AMBIGUOUS_SPACE.sub("", text))


def _reordered(text: str) -> str | None:
    # The text in the order a reader sees it wherever a right-to-left override
    # reorders it: every span an override opens, reversed where it stands. A span
    # reversed in place also joins with what surrounds it, so a name written half
    # forwards and half reversed across the boundary reads whole here too.
    # None when no override opens, so the extra views cost one search.
    opened = _BIDI_OPEN.search(text)
    if opened is None:
        return None
    out, pos = [], 0
    while opened is not None:
        out.append(text[pos:opened.end()])
        closed = _BIDI_CLOSE.search(text, opened.end())
        pos = closed.start() if closed else len(text)
        out.append(text[opened.end():pos][::-1])
        opened = _BIDI_OPEN.search(text, pos)
    out.append(text[pos:])
    return "".join(out)


def _chr(code: str) -> str:
    n = int(code, 16)
    return chr(n) if n <= 0x10FFFF and not 0xD800 <= n <= 0xDFFF else ""


def _code_point(body: str) -> int | None:
    # The value a numeric character reference names, or None for a digit run too
    # long to name one. The spec bounds neither the digits nor the leading zeros,
    # and a bound in the pattern silently turned "&#00000000000011;" into nothing
    # where a browser emits U+000B. Length is checked here rather than in the
    # pattern because int() refuses a string of more than 4300 digits.
    hexadecimal = body[0] in "xX"
    digits = (body[1:] if hexadecimal else body).lstrip("0")
    if len(digits) > 7:
        return None  # past U+10FFFF, which the spec answers with U+FFFD
    return int(digits, 16 if hexadecimal else 10) if digits else 0


def _spec_control(m: re.Match[str]) -> str:
    code = _code_point(m.group(1))
    return chr(code) if code in _SPEC_CONTROLS else m.group(0)


def _unescape_once(text: str) -> str:
    text = html.unescape(_NUM_REF.sub(_spec_control, text))
    text = urllib.parse.unquote_plus(text, errors="replace")
    text = _JS_ESC.sub(lambda m: _chr(m.group(1) or m.group(2) or m.group(3)), text)
    text = _WS_ESC.sub(" ", text)
    text = _CSS_ESC.sub(lambda m: _chr(m.group(1)), text)
    return _CHAR_ESC.sub(r"\1", _LINE_CONT.sub("", text))


def _render(text: str) -> tuple[str, bool]:
    # The decoded text, and whether the loop reached its fixed point inside the
    # bound. A bound that stops scanning and says nothing is the fail-open shape
    # this whole gate exists to close, so the caller turns a no into a finding.
    for _ in range(SITE_MAX_DECODE):
        decoded = _unescape_once(text)
        if decoded == text:
            return text, True
        text = decoded
    return text, False


def rendered_text(text: str) -> str:
    # Escapes and entities decoded to a fixed point, so any depth of encoding
    # unwinds: "&amp;#8203;" and "%2525E2%252580%25258B" alike. Markup stays,
    # because attributes such as an href or an alt publish too. This is the
    # reading for a name: "+" is a space, which is the form-encoding rule, and a
    # percent escape names a UTF-8 character. A payload is read by payload_bytes.
    return _render(text)[0]


# The reading for a payload, which a fixed point cannot give. Every decoder above
# rewrites bytes it finds, and a fixed point runs every decoder again over what the
# others produced, so once a percent escape restores a binary the backslash, entity
# and percent rules go on rewriting the binary itself: a 0x5C byte and the byte
# after it become one byte, "&lt" becomes "<", "%41" becomes "A". Round 8 read
# payloads that way and 25 of 25 percent-escaped 1.5 KB gzip streams in a page came
# back damaged. A reader never does that. It takes a payload through its layers
# once each, in a fixed order, and no layer reads its own output: the HTML parser's
# character references, then a script's or a style sheet's backslash escapes, then
# the URL parser's percent escapes, which hand a data URL its bytes. So does this.
#
# Layer zero is the UTF-8 read of the file's bytes, which only one of the two
# payload sources takes. It lets a raw UTF-8 character name a byte, as a script's
# binary string written out literally does, and leaves every byte that is not part
# of a UTF-8 sequence alone.
_UTF8_SEQ = re.compile("[\u00c2-\u00df][\u0080-\u00bf]|[\u00e0-\u00ef][\u0080-\u00bf]{2}"
                       "|[\u00f0-\u00f4][\u0080-\u00bf]{3}")
# The same shape html.unescape matches, so each reference decodes exactly as it
# would there, with the controls the spec emits added as _NUM_REF adds them.
_CHARREF = re.compile(r"&(?:#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)")
# One alternation, so a byte one escape produced is never read by another. The
# order is the order the text reading applies them in, with one change: the
# single-letter escapes a script string uses for a control byte come before the
# CSS hex rule, and "\n" is a line feed, not a space. JSON writes 0x08 and 0x0C as
# "\b" and "\f", which CSS would read as U+000B and U+000F, and a binary string is
# written by a JSON or script encoder, never by a style sheet.
_BACKSLASH = re.compile(r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})"
                        r"|([bfnrtv])|([0-9a-fA-F]{1,6})[ \t\n]?"
                        r"|\r\n|[\r\n\f\u2028\u2029]|(.))", re.S)
_JS_CONTROL = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_PERCENT = re.compile(r"%([0-9a-fA-F]{2})")


def _utf8_char(m: re.Match[str]) -> str:
    return m.group(0).encode("latin-1").decode("utf-8", "surrogateescape")


def _charref(m: re.Match[str]) -> str:
    ref = m.group(0)
    if ref[1] != "#":
        return html.unescape(ref)
    code = _code_point(ref[2:].rstrip(";"))
    if code is None:
        return "\ufffd"
    if code in _SPEC_CONTROLS:
        return chr(code)
    return html.unescape(f"&#{code};")


# A numeric reference the HTML spec replaces rather than emits: U+0000, and the
# 0x80 to 0x9F rows, which it maps to windows-1252 punctuation. A binary written
# one reference per byte loses every such byte to a reader that takes the spec's
# answer, so its gzip magic, 0x8B, never survives; a page script that maps the
# numbers back itself gets every byte. Round 9 passed those payloads clean.
_SPEC_REMAPPED = re.compile(r"&#(?:0*(?:12[89]|1[34][0-9]|15[0-9])|0+)(?![0-9])"
                            r"|&#[xX](?:0*[89][0-9a-fA-F]|0+)(?![0-9a-fA-F])")


def _charref_byte(m: re.Match[str]) -> str:
    # The reading of a numeric reference below 256 as the byte it names, for the
    # reader that maps the numbers itself. Every other reference reads as the spec
    # has it.
    ref = m.group(0)
    if ref[1] == "#":
        code = _code_point(ref[2:].rstrip(";"))
        if code is not None and code < 0x100:
            return chr(code)
    return _charref(m)


def _backslash(m: re.Match[str]) -> str:
    code = m.group(1) or m.group(2) or m.group(3) or m.group(5)
    if code:
        return _chr(code)
    if m.group(4):
        return _JS_CONTROL[m.group(4)]
    # A line continuation disappears, which is the one alternative with no group.
    return m.group(6) or ""


def _percent(m: re.Match[str]) -> str:
    return chr(int(m.group(1), 16))


# (output starts, input starts, lengths, copied) of every piece a layer wrote.
# A copied piece maps byte for byte to its input. A decoded piece maps as a whole
# to the start of the escape that produced it.
_Runs = tuple[array, array, array, array]


def _layer(text: str, pattern: re.Pattern[str], repl) -> tuple[str, _Runs]:
    # One layer applied once, and where each piece of its output came from. The
    # runs are what lets the container stage name the file offset a stream came
    # from, whichever reading it was found in.
    #
    # What a match hands back unchanged at its end is a copy, not a decode.
    # html.unescape answers "&" and up to 32 bytes that name no entity with the
    # same text, and a named reference without its semicolon with the entity and
    # the rest of the match as it was. In binary that span runs over whatever
    # follows an "&", so marking it all decoded made the next member header of an
    # ordinary multi-member gzip look like something a decode revealed.
    out: list[str] = []
    runs: _Runs = (array("q"), array("q"), array("q"), array("b"))
    pos = at = 0

    def run(start: int, length: int, copied: int) -> None:
        for column, value in zip(runs, (at, start, length, copied)):
            column.append(value)

    for m in pattern.finditer(text):
        piece = repl(m)
        found = m.group(0)
        kept = 0
        while (kept < len(piece) and kept < len(found)
               and piece[-1 - kept] == found[-1 - kept]):
            kept += 1
        if m.start() > pos:
            run(pos, m.start() - pos, 1)
            out.append(text[pos:m.start()])
            at += m.start() - pos
        if len(piece) > kept:
            run(m.start(), len(piece) - kept, 0)
            out.append(piece[:len(piece) - kept])
            at += len(piece) - kept
        pos = m.end() - kept
    if pos < len(text):
        run(pos, len(text) - pos, 1)
        out.append(text[pos:])
    return "".join(out), runs


# The three layers a reader takes a payload through, in the order it takes them:
# the HTML parser's character references, a script's or a style sheet's
# backslash escapes, then the URL parser's percent escapes, which hand a data URL
# its bytes.
_LAYERS = ((_CHARREF, _charref), (_BACKSLASH, _backslash), (_PERCENT, _percent),
           (_CHARREF, _charref_byte))
# Which layers may stand at each step of a reading, in a reader's order: none, or
# one of these. The references step has two answers for the few references the
# spec replaces, and the second is tried only where one is written.
_STEPS = (((0, None), (3, _SPEC_REMAPPED)), ((1, None),), ((2, None),))


def _payload(latin: str, utf8: bool, applied: tuple[int, ...] = (0, 1, 2)
             ) -> tuple[bytes, list[_Runs]]:
    # The file read as a payload: its bytes, then the layers named in applied, in a
    # reader's order, and the runs that map every byte back to the file. latin-1 in
    # and out keeps a byte a byte; a code point no byte can hold is no part of a
    # container header or a base64 payload, so "?" ends a run there.
    layers = ([(_UTF8_SEQ, _utf8_char)] if utf8 else []) + [_LAYERS[i] for i in applied]
    text, trail = latin, []
    for pattern, repl in layers:
        text, runs = _layer(text, pattern, repl)
        trail.append(runs)
    return text.encode("latin-1", "replace"), trail


def _file_offset(trail: list[_Runs], pos: int) -> int | None:
    # Where the byte at pos in a payload source sits in the file, or None when a
    # decode produced it rather than copied it.
    for outs, ins, lens, copied in reversed(trail):
        i = bisect.bisect_right(outs, pos) - 1
        if i < 0 or pos >= outs[i] + lens[i] or not copied[i]:
            return None
        pos = ins[i] + pos - outs[i]
    return pos


def _origin(trail: list[_Runs], pos: int) -> int:
    # Where the byte at pos in a reading came from in the file: its own offset when
    # every layer copied it, or the start of the escape that produced it.
    for outs, ins, lens, copied in reversed(trail):
        i = bisect.bisect_right(outs, pos) - 1
        if i < 0:
            return 0
        pos = ins[i] + (pos - outs[i] if copied[i] else 0)
    return pos


def payload_bytes(text: str) -> bytes:
    # The payload reading of text written as latin-1, for a caller holding text.
    return _payload(text, utf8=False)[0]


def _digest(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=16).digest()


def _readings(blob: bytes) -> Iterator[tuple[bytes, tuple[bool, tuple[int, ...]] | None]]:
    """Every way a reader could take the file's bytes as a payload, each once.

    The file itself comes first. Then every combination of the three layers, each
    applied or not, in a reader's order, with and without the UTF-8 read first.
    The references layer has a second answer, below, for the few references the
    spec replaces with another character. Round 9 applied all three everywhere
    and read a payload right only where all
    three belonged. A raw backslash in a data URL, a raw "%41" in a JSON string and
    an "&not" in element text each came back damaged, and the round then had to
    decide whether a stream that failed to decompress had been damaged or had
    never been a stream at all. Which layers a context applies is something a scan
    of bytes cannot know, so it reads every combination and a stream counts as
    read when any reading of it decodes whole. A reading equal to one already made
    is skipped, so a file with nothing to decode is read once, and an ordinary
    page with entities, a script and a URL in it is read about eight times.

    Depth first, so at most one string per layer is alive at a time.
    """
    yield blob, None
    seen = {_digest(blob)}
    latin = blob.decode("latin-1")
    for utf8 in (False, True):
        base = _UTF8_SEQ.sub(_utf8_char, latin) if utf8 else latin
        if utf8 and base == latin:
            continue
        stack: list[tuple[str, int, tuple[int, ...]]] = [(base, 0, ())]
        while stack:
            text, depth, applied = stack.pop()
            if depth == len(_STEPS):
                data = text.encode("latin-1", "replace")
                key = _digest(data)
                if key not in seen:
                    seen.add(key)
                    yield data, (utf8, applied)
                continue
            stack.append((text, depth + 1, applied))
            for layer, only_if in _STEPS[depth]:
                pattern, repl = _LAYERS[layer]
                if (only_if or pattern).search(text):
                    stack.append((pattern.sub(repl, text), depth + 1, applied + (layer,)))
        del base


class _Origins:
    """Maps a position in one reading to the file offset it came from, building
    the reading's runs only when something in it needs an origin.
    """

    def __init__(self, blob: bytes, path: tuple[bool, tuple[int, ...]] | None) -> None:
        self.blob, self.path = blob, path
        self.trail: list[_Runs] | None = None

    def __call__(self, pos: int) -> int:
        if self.path is None:
            return pos
        if self.trail is None:
            self.trail = _payload(self.blob.decode("latin-1"), *self.path)[1]
        return _origin(self.trail, pos)


def _markup_end(text: str, opened: int) -> int:
    # Where the markup starting at "opened" ends, the way a reader loses it: a
    # comment at any of its four ends, a script or style element after its
    # closing tag, any other tag at its first ">". Reading a comment past an
    # interior ">" is what a tag pattern cannot do, and a comment holding one
    # hid a name behind it.
    if text.startswith("<!--", opened):
        # Four shapes close a comment, not one. "<!-->" and "<!--->" close it at
        # once (WHATWG HTML calls both abrupt-closing-of-empty-comment) and
        # "--!>" closes it as well (incorrectly-closed-comment). Chrome 153
        # emits the text after each of them, so reading only "-->" put a name
        # behind a closed comment where nothing would look for it.
        if text.startswith(">", opened + 4):
            return opened + 5
        if text.startswith("->", opened + 4):
            return opened + 6
        # Whichever of the two ends comes first, so a "-->" is not skipped for a
        # later "--!>" or the other way round. They can never land on the same
        # index, because one needs a ">" where the other needs a "!".
        ends = [at + past for at, past in ((text.find("-->", opened + 4), 3),
                                          (text.find("--!>", opened + 4), 4))
                if at >= 0]
        return min(ends) if ends else len(text)
    if _HIDDEN_START.match(text, opened):
        end = _HIDDEN_END.search(text, opened + 1)
        if end is None:
            return len(text)
        closed = text.find(">", end.end())
        return len(text) if closed < 0 else closed + 1
    closed = text.find(">", opened + 1)
    return -1 if closed < 0 else closed + 1


def _strip_markup(text: str, filler: str) -> str:
    # Everything above, dropped. Each search starts where the last one stopped,
    # so the pass is linear: a "<" that is never closed used to send a regex
    # rescanning to the end of the text from every later one.
    out, pos = [], 0
    while (opened := text.find("<", pos)) >= 0:
        closed = _markup_end(text, opened)
        if closed < 0:
            break
        out.append(text[pos:opened])
        out.append(filler)
        pos = closed
    out.append(text[pos:])
    return "".join(out)


def _decoded_views(decoded: str) -> Iterator[str]:
    # With markup kept, then with it removed for "Fi<b></b>rst", then both again
    # with every right-to-left span reversed.
    #
    # There used to be a third reading with each piece of markup replaced by a
    # space, for "First<br>Last". It is redundant and always was: the removed
    # reading is the spaced one with a subset of its spaces deleted, and deleting
    # a space can only merge neighbours, so a space-free entry found in one is
    # found in the other, and an entry holding a space is found by the squeeze,
    # which sees the same text either way. Round 5 claimed a test pinned the view;
    # round 6's squeeze made that claim false, and 200,000 differential inputs
    # found no input that tells the two apart.
    for text in (decoded, _strip_markup(decoded, "")):
        yield from _folds(text)
    reordered = _reordered(decoded)
    if reordered is not None:
        for text in (reordered, _strip_markup(reordered, "")):
            yield from _folds(text)


def _str_views(text: str) -> Iterator[tuple[str, str]]:
    yield "name", text.lower()
    for view in _decoded_views(rendered_text(text)):
        yield "name, decoded", view


class _Normalized:
    """One blob, decoded once, read by every text view.

    The container stage no longer reads from here. It reads _readings, which
    hands it one payload reading at a time after the views are freed, so the two
    phases' peaks do not add up.
    """

    def __init__(self, blob: bytes) -> None:
        self.blob = blob
        self.latin = blob.decode("latin-1")
        self.utf8 = blob.decode("utf-8", "replace")
        # settled is false when an encoding is nested deeper than the decode bound
        # unwinds. The scan reports that rather than passing the file quietly.
        self.settled = True
        self.rendered = []
        for base in (self.utf8, self.latin):
            text, settled = _render(base)
            self.rendered.append(text)
            self.settled &= settled


def _blob_views(norm: _Normalized) -> Iterator[tuple[str, str]]:
    # Every view of one file, each built from all of it.
    yield "raw", norm.latin.lower()
    for view in _folds(norm.utf8):
        yield "utf-8", view
    # Both byte orders at both alignments, because a UTF-16 string inside a
    # binary (a font name record, a PE resource) can start at an odd offset.
    for enc in ("utf-16-le", "utf-16-be"):
        for o in (0, 1):
            for view in _folds(norm.blob[o:].decode(enc, "replace")):
                yield "utf-16", view
    # The latin-1 read folded and nothing decoded. It was called nul-stripped and
    # stripped NUL first, which the fold has erased since round 6; what the view
    # actually carries is a name the fold repairs and every decoder destroys, such
    # as a latin-1 micro sign next to a "+" that unquote_plus reads as a space.
    for view in _folds(norm.latin):
        yield "latin-1", view
    for decoded in norm.rendered:
        for view in _decoded_views(decoded):
            yield "decoded", view


def _blob_hits(blob: bytes, folded: list[tuple[str, ...]]) -> dict[int, str]:
    return _hits(_blob_views(_Normalized(blob)), folded)


# A multi-part entry written with a separator inside it. "peopleco" reads as the
# entry in "people-co", "people co", "people_co" and "people.co", and a denylist
# of lowercase entries does not say where the parts are, so a separator may sit
# between any two of the entry's letters. What keeps that off ordinary English is
# where the run starts and ends: on a word boundary at both ends, and a hyphen,
# an underscore or a dot followed by more of a word does not count as one, because
# those three join a compound rather than end it. So "the people could" is no
# finding ("co" runs on into "uld"), and neither is "people co-authored" ("co"
# runs on through the hyphen), while "people-co site" and "People Co." are.
#
# A space is a boundary and a separator both, which is what makes this a
# different rule from erasing every space: round 8 measured that erasing all 29
# space code points invents 1,947 findings on the merged tree, because it joins
# any two adjacent words into any entry that spans them with no regard to where
# either word starts or ends. This rule joins only whole words, and only when the
# whole run is the entry.
_SPLIT_SEP = "[ _.\\-]?"
_SPLIT_END = "(?![^\\W_])(?![_.\\-][^\\W_])"


# How the parts of a multi-word entry may be joined (controller ruling, round
# 11): one ".", "-" or "_", with at most one optional space on each side, or a
# space, or nothing. So "zz. secret person", "zz - secret person",
# "zz_secretperson1" and "zz.secret-person" read as the entry "zz secret person".
# An ellipsis does not: "..." is three separator characters, and U+2026 folds to
# it, so round 7's ruling that "zz first...last" is ink and not the name stands.
# No word boundary is asked for, as none is by the space-closed match beside it,
# because a handle glues the name to what follows.
_JOIN = "(?: ?[._\\-] ?| ?)"


def _join_patterns(folded: str) -> tuple[re.Pattern[str], ...]:
    # The entry's parts joined by _JOIN, forwards and with every letter reversed
    # for text a right-to-left override lays out backwards. None for an entry of
    # one part, which the separator rule in _split_patterns covers.
    parts = folded.split(" ")
    if len(parts) < 2:
        return ()
    return tuple(re.compile(_JOIN.join(map(re.escape, ways)))
                 for ways in dict.fromkeys((tuple(parts), tuple(p[::-1] for p in reversed(parts)))))


def _core(folded: str) -> str:
    return folded.translate(_SQUEEZE)


def _split_patterns(folded: str) -> tuple[re.Pattern[str], ...]:
    # The entry's letters with an optional separator between each two, forwards
    # and reversed. Each pattern opens with the entry's first letter and checks the
    # boundary behind it afterwards, so the engine scans for that letter rather
    # than trying a lookbehind at every position of every view.
    core = _core(folded)
    if len(core) < 2:
        return ()
    out = []
    for letters in dict.fromkeys((core, core[::-1])):
        first = re.escape(letters[0])
        out.append(re.compile(
            first + f"(?<![^\\W_]{first})(?<![^\\W_][_.\\-]{first})"
            + "".join(_SPLIT_SEP + re.escape(c) for c in letters[1:]) + _SPLIT_END))
    return tuple(out)


def _fold_tokens(tokens: list[str]) -> list[tuple]:
    """Each token folded, with its own spaces closed up, and each of those
    reversed for text a right-to-left override lays out backwards, then the
    separator-tolerant patterns for the same entry and the letters they match."""
    return [(folded, closed, folded[::-1], closed[::-1], _split_patterns(folded), _core(folded),
             _join_patterns(folded))
            for folded, closed in ((f, f.replace(" ", "")) for f in map(_fold, tokens))]


_SQUEEZE = str.maketrans(dict.fromkeys(" _.-"))


def _hits(views: Iterator[tuple[str, str]], folded: list[tuple]) -> dict[int, str]:
    found: dict[int, str] = {}
    for layer, view in views:
        closed = squeezed = None
        for i, (token, no_space, back, back_no_space, split, core, join) in enumerate(folded):
            if not token or i in found:
                continue
            # Matching the entry reversed is the same test as reversing the view,
            # for a quarter of the cost and without a model of what reordered it.
            if token in view or back in view:
                found[i] = layer
                continue
            if split:
                # The separator rule can match only where the entry's letters run
                # together once every separator is gone, so that is asked first, of
                # one string per view, and the patterns run only where it holds.
                if squeezed is None:
                    squeezed = view.translate(_SQUEEZE)
                if ((core in squeezed or core[::-1] in squeezed)
                        and any(pattern.search(view) for pattern in split)):
                    found[i] = layer
                    continue
            if join:
                # The join rule, gated as the separator rule is: its letters must
                # run together once every separator is gone.
                if squeezed is None:
                    squeezed = view.translate(_SQUEEZE)
                if ((core in squeezed or core[::-1] in squeezed)
                        and any(pattern.search(view) for pattern in join)):
                    found[i] = layer
                    continue
            # Not an elif. The separator rule demands a word boundary at both ends
            # and the join rule a separator between whole parts, and this test
            # demands neither, so a multi-word entry glued into a handle,
            # "github.com/zzsecretperson42" or "@zzsecretperson_dev", is found only
            # here. Round 10 ran this only when the entry had no separator patterns,
            # which is never for a multi-word entry, and lost every such handle.
            if no_space != token:
                # A character a reader cannot see either closes the gap it sits
                # in or leaves one, and which it does varies by browser and font:
                # U+200B takes no advance in Chrome 153, U+0001 takes 21.3 px
                # with no ink. Matching the space-free form of a multi-word token
                # against the space-free view covers both, so no character has to
                # be classified as one or the other. Built once per view, and
                # only for a denylist entry that holds a space. Only spaces are
                # closed: closing dots as well joins "first...last", which round 7
                # ruled is ink and not the name.
                if closed is None:
                    closed = view.replace(" ", "")
                if no_space in closed or back_no_space in closed:
                    found[i] = layer
    return found


def _label(name: str, folded: list[tuple[str, ...]]) -> str:
    base = name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if _hits(_str_views(base), folded):
        return WITHHELD
    # Control characters in a name could rewrite the terminal line, so mask them.
    return "".join(c if c.isprintable() else "?" for c in base) or "[unnamed]"


# How a container is labelled and refused, by where it was found: at the head of
# a reading, past offset zero in the file's own bytes, or past offset zero in
# what a decode revealed.
_AT_HEAD = ("", "cannot be fully scanned ({})")
_EMBEDDED = ("embedded ", "holds a container the scan cannot expand ({})")
_ENCODED = ("encoded ", "encodes a container the scan cannot expand ({})")


class _SiteScan:
    def __init__(self, tokens: list[str]) -> None:
        self.folded = _fold_tokens(tokens)
        self.errs: list[str] = []

    @staticmethod
    def _where(chain: list[str]) -> str:
        return " > ".join(chain)

    def report_hits(self, chain: list[str], hits: dict[int, str]) -> None:
        for i in sorted(hits):
            self.errs.append(f"{self._where(chain)}: contains a denylisted token "
                             f"(#{i + 1} in {DENYLIST_NAME}, {hits[i]} view)")

    def problem(self, chain: list[str], reason: str) -> None:
        self.errs.append(f"{self._where(chain)}: {reason}")

    def refuse(self, chain: list[str], how: tuple[str, str], reason: str, work: _Work) -> None:
        if reason == _LIMIT:
            if work.reported:
                return
            work.reported = True
        self.problem(chain, how[1].format(reason))

    def name(self, chain: list[str], raw_name: str, layer: str = "") -> None:
        hits = _hits(_str_views(raw_name), self.folded)
        self.report_hits(chain, {i: layer or found for i, found in hits.items()})

    def blob(self, chain: list[str], blob: bytes, depth: int, work: _Work,
             derived: bool = False) -> None:
        # derived is true for output no format declared: what an unproven trial
        # inflated, and a base64 alignment other than the first. At its head a
        # container must validate, as it must past offset zero anywhere.
        if len(blob) > SITE_MAX_BLOB:
            self.problem(chain, "larger than the per-blob scan limit")
            return
        norm = _Normalized(blob)
        self.report_hits(chain, _hits(_blob_views(norm), self.folded))
        if not norm.settled:
            # Every other bound here refuses by name. This one used to stop
            # decoding and report nothing, which is the one behaviour the gate
            # cannot afford. Measured: every tracked file in this repository
            # settles within 4 passes of the 16, binaries included.
            self.problem(chain, "escapes nest deeper than the decode limit unwinds")
        # The views are freed before the container stage builds its readings, so
        # the two phases' peaks do not add up.
        del norm
        mark = len(self.errs)
        self.containers(chain, blob, depth, work, derived)
        # A container one reading damages and another reads whole has its names and
        # members read twice, so the lines this file's containers added are kept
        # once each.
        self.errs[mark:] = dict.fromkeys(self.errs[mark:])

    def containers(self, chain: list[str], blob: bytes, depth: int, work: _Work,
                   derived: bool = False) -> None:
        # Every container in every reading of the file, each read once.
        #
        # A container is known by where it came from in the file and what kind it
        # is, whichever reading it was found in, and it is read until one reading
        # of it decodes whole. Only when none does is it refused, once. That is what
        # replaces round 9's ownership rule, which handed a container whose header
        # sat unescaped in the file to the raw bytes alone: a JSON-escaped PDF keeps
        # "%PDF-1.7" raw and "stream\n" escaped, so the raw read found no stream
        # and said nothing, and the decoded read that did find one was never asked.
        # A PDF read that finds no stream proves nothing, so it does not settle the
        # container either.
        # Per container: whether a reading decoded it whole, the first reason one
        # did not, how it is labelled, the file offset of its magic, and the bytes
        # each failed attempt read, so the same bytes in another reading are not
        # decompressed again for the same failure.
        groups: dict[tuple[int, str], list] = {}
        # The file offsets a whole decode read, in any reading. A candidate there is
        # part of a container already read, and a refusal whose magic sits there is
        # a misreading of one: a damaged reading of a tar finds its magic 257 bytes
        # in at a shifted head, which is a different group, but not a different tar.
        # Only a whole decode goes here. A failed one would block the reading that
        # reads the same bytes whole, which is round 9's ownership bug again.
        settled: list[tuple[int, int]] = []
        scanned: set[bytes] = set()
        runs_seen: set[bytes] = set()
        trials: dict[tuple[str, bytes], bool] = {}
        residue: list[tuple[str, bytes]] = []
        # The file offset where the trial that inflated each residue piece started,
        # one entry per piece, in the same order. Not the trial's kind: the
        # container stage settles an offset for any kind, and so does this.
        anchors: list[int] = []
        wide = deep = False
        by_name = chain[-1].lower().endswith(".br")
        for data, path in _readings(blob):
            if work.exhausted:
                break
            origin = _Origins(blob, path)
            if not wide and _wide_encoded_text(data):
                # The text views read this document; the container stage cannot,
                # because the NUL interleaving survives into every reading.
                # Scanning it would mean four more decodes of every file ever
                # scanned; refusing it costs only the files that are wide-encoded,
                # and a build writing UTF-8 has none.
                wide = True
                self.problem(chain, "wide-encoded text the container stage cannot read "
                                    "(re-encode as UTF-8)")
            starts: list[int] = []
            found = _candidates(data, by_name and path is None, trials, residue, work,
                                raw=path is None, derived=derived, starts=starts)
            anchors += [origin(pos) for pos in starts]
            runs = []
            for run in _b64_runs(data):
                key = _digest(run)
                if key not in runs_seen:
                    runs_seen.add(key)
                    runs.append(run)
            if depth >= SITE_MAX_DEPTH:
                # A container in any reading counts here. Without it the depth
                # bound would drop one silently, which is the shape every other
                # bound here refuses.
                if not deep and (found or runs):
                    deep = True
                    self.problem(chain, "nesting exceeds the scan depth limit")
                continue
            # The positions in this reading any decode read, whole or not, so a later
            # member header inside a stream is not read again as a stream of its own.
            # Round 9 recorded a span only when a stream returned, and a stream that
            # failed was decompressed again from every member header in it.
            read_here: list[tuple[int, int]] = []
            for pos, kind in found:
                if work.exhausted:
                    break
                how = _AT_HEAD if pos == 0 else _EMBEDDED if path is None else _ENCODED
                res = self.attempt(chain, data, pos, kind, how, origin, groups, read_here,
                                   settled, scanned, depth, work)
                if res is not None and pos == 0 and kind not in _WEAK and kind != "zip":
                    # A polyglot: a font, a PDF or a stream with a zip glued to its
                    # end. For a tar only the bytes past its last member count,
                    # because a zip stored as a member was already read as one.
                    tail = res.tail if kind == "tar" else data
                    if zipfile.is_zipfile(io.BytesIO(tail)):
                        self.attempt(chain, data, len(data) - len(tail), "zip", _AT_HEAD,
                                     origin, groups, read_here, settled, scanned, depth, work,
                                     glued=True)
            for run in runs:
                if work.exhausted:
                    break
                self.base64(chain, run, depth, work)
        for done, reason, how, anchor, _ in groups.values():
            if not done and reason and not any(begin <= anchor < end for begin, end in settled):
                self.refuse(chain, how, reason, work)
        if work.exhausted:
            # Trials and the readings stop where the budget runs out, so the file
            # is refused for it here as well as in any decode that hit it.
            self.refuse(chain, _AT_HEAD, _LIMIT, work)
        elif residue and depth < SITE_MAX_DEPTH:
            # What unproven trials inflated, each piece read as a file of its own:
            # names, base64 runs and containers, with raw deflate tried at its head
            # as at the head of every decode, one level deeper and charged to the
            # same budget, which has already paid for every piece. Round 10 read
            # the pieces for names only, and raw deflate around a small gzip came
            # back clean. Round 11 joined them into one fragment, so only the first
            # piece's head was a payload start, and the order of the pieces decided
            # whether raw deflate inside raw deflate was read.
            spans: dict[bytes, tuple[int, int]] = {}
            self.drain(chain, [("inflated fragment", out) for _, out in residue], depth, work,
                       set(), derived=True, spans=spans)
            self.settle_misreadings(residue, anchors, spans, work)
        elif residue:
            self.problem(chain, "nesting exceeds the scan depth limit")

    def attempt(self, chain: list[str], data: bytes, pos: int, kind: str, how: tuple[str, str],
                origin: _Origins, groups: dict, read_here: list[tuple[int, int]],
                settled: list[tuple[int, int]], scanned: set[bytes], depth: int, work: _Work,
                glued: bool = False) -> _Result | None:
        # A glued zip starts inside the extent of the container it is glued to,
        # which is where it lives, so it is the one read that does not skip there.
        if not glued and any(begin <= pos < end for begin, end in read_here):
            return None
        at = origin(pos)
        if not glued and any(begin <= at < end for begin, end in settled):
            return None
        group = groups.setdefault((at, kind), [False, "", how,
                                               origin(pos + (257 if kind == "tar" else 0)),
                                               set()])
        if group[0]:
            return None
        for length, digest in group[4]:
            if _digest(data[pos:pos + length]) == digest:
                return None
        queue: list[tuple[str, bytes]] = []
        res = _enqueue(queue, _dispatch(kind, data, work, self, chain, start=pos), prefix=how[0])
        decoded = bool(queue)
        self.drain(chain, queue, depth, work, scanned)
        spans = [(begin, end) for begin, end in res.extents if end > begin]
        read_here += spans
        if res.refusal == _LIMIT:
            self.refuse(chain, group[2], _LIMIT, work)
        elif res.refusal:
            group[1] = group[1] or res.refusal
            # Keyed on every byte the decoder was fed, because the failure lies in
            # the last piece fed, not in the bytes it had finished with. A structure
            # has no one such end, so its failures are not keyed at all.
            if res.fed > pos:
                group[4].add((res.fed - pos, _digest(data[pos:res.fed])))
        elif decoded or kind != "pdf":
            group[0] = True
            settled += [(origin(begin), origin(end - 1) + 1) for begin, end in spans]
        return res

    def base64(self, chain: list[str], run: bytes, depth: int, work: _Work) -> None:
        # A run can start early when the text before the encoding uses base64
        # letters too ("key" + payload), so all four alignments are read, and every
        # one is read whole: names, base64 runs and containers. Round 10 followed an
        # alignment other than the first only when a container provably started it,
        # and a short raw deflate payload never proves itself, so the trial that
        # asked was charged and its output thrown away: a payload after "k", "ke"
        # or "key" came back clean. Every alignment is charged to the budget, which
        # is what bounds this: three more decodes of three quarters of a run each.
        scanned: set[bytes] = set()
        for shift in range(4):
            queue: list[tuple[str, bytes]] = []
            res = _enqueue(queue, _dispatch("base64", run, work, start=shift))
            if res.refusal:
                self.refuse(chain, _AT_HEAD, res.refusal, work)
                return
            self.drain(chain, queue, depth, work, scanned, derived=shift != 0)

    def drain(self, chain: list[str], queue: list[tuple[str, bytes]], depth: int, work: _Work,
              scanned: set[bytes], derived: bool = False,
              spans: dict[bytes, tuple[int, int]] | None = None) -> None:
        # Every part of a queue, read as a file of its own one level deeper, once
        # per distinct content. spans, when given, gets the lines of self.errs each
        # distinct content added.
        while queue:
            label, part = queue.pop(0)
            key = _digest(part)
            if key not in scanned:
                scanned.add(key)
                begin = len(self.errs)
                self.blob(chain + [label], part, depth + 1, work, derived)
                if spans is not None:
                    spans[key] = (begin, len(self.errs))

    def settle_misreadings(self, residue: list[tuple[str, bytes]], anchors: list[int],
                           spans: dict[bytes, tuple[int, int]], work: _Work) -> None:
        # A trial at one file offset runs once per reading, and a reading that
        # rewrote bytes inside the stream inflates a damaged copy of what another
        # reading inflated whole. The damage lies past the first bytes, so the copy
        # opens with the same valid header and fails in its body: raw deflate around
        # a gzip whose OS byte is not 255, read with the UTF-8 layer, was refused as
        # a corrupt gzip in about a third of clean files, while the raw reading read
        # the same gzip whole. This is the rule the container stage keeps for a
        # container, applied to the pieces: at an offset where one piece drained
        # with no problem line, a sibling's corrupt or truncated stream is a
        # misreading, and that refusal is dropped. Only that one: a catch, a limit,
        # and every refusal that leaves bytes unread for any other reason stay.
        if work.exhausted:
            return
        keys = [_digest(out) for _, out in residue]
        clean = {key for key, (begin, end) in spans.items()
                 if all(_CATCH_LINE.search(line) for line in self.errs[begin:end])}
        at: dict[bytes, set[int]] = {}
        for key, anchor in zip(keys, anchors):
            at.setdefault(key, set()).add(anchor)
        settled = {anchor for key, anchor in zip(keys, anchors) if key in clean}
        drop = sorted(i for key, (begin, end) in spans.items() if at[key] <= settled
                      for i in range(begin, end) if _MISREAD_LINE.search(self.errs[i]))
        for i in reversed(drop):
            del self.errs[i]


def _candidates(data: bytes, br: bool, trials: dict[tuple[str, bytes], bool],
                residue: list[tuple[str, bytes]], work: _Work, raw: bool = False,
                derived: bool = False,
                starts: list[int] | None = None) -> list[tuple[int, str]]:
    # Every container one reading holds, as (position, kind), in position order,
    # a strong kind before a weak one at the same place. A weak candidate is kept
    # once its trial proves it. The output of one that fails its trial is kept in
    # residue, which the caller reads as a file of its own, containers included.
    #
    # A failed weak candidate suppresses nothing. Round 10 dropped every candidate
    # inside the bytes an unproven raw deflate trial had read, so a short raw
    # deflate stream at a payload start hid a gzip lying whole in the file's own
    # bytes, and the file came back clean. Every candidate is tried now. The cost
    # is the false refusal that span existed to stop: a zlib header met inside
    # raw deflate data can inflate its 128 bytes as fixed-Huffman literals and be
    # refused when the rest fails, which fails closed.
    #
    # starts, when given, gets the position of the trial behind each piece this
    # call adds to residue, in the same order.
    head = _container_kind(data) or ("brotli" if br else "")
    if (derived and head and head not in ("zip", "brotli")
            and not _valid_container(data, 0, head)):
        # Output no format declared is taken at its head only where the header
        # validates. Garbage trials make thousands of short pieces, and one that
        # opened with the two bytes of gzip magic was refused as a corrupt gzip.
        head = ""
    found = [(0, head)] if head else []
    found += _containers_in(data)
    for pos, kind in _weak_heads(data):
        if work.exhausted:
            break
        before = len(residue)
        if _proven(kind, data, pos, trials, work, residue, raw):
            found.append((pos, kind))
        if starts is not None:
            starts += [pos] * (len(residue) - before)
    return sorted(found, key=lambda c: (c[0], c[1] in _WEAK))


def _weak_heads(data: bytes) -> Iterator[tuple[int, str]]:
    # Both patterns check the block header ahead of them, so no position that
    # cannot open a Huffman block reaches Python: a page has a delimiter in
    # every few bytes, and random binary one in about thirty-six.
    for m in _ZLIB_HEAD.finditer(data):
        yield m.start(), "zlib"
    if _deflate_head(data, 0):
        yield 0, "deflate"
    for m in _PAYLOAD_START.finditer(data):
        yield m.end(), "deflate"


def _deflate_head(data: bytes, pos: int) -> bool:
    # Whether the block raw deflate opens with (RFC 1951 3.2.3) is one a weak
    # candidate can prove itself by: a Huffman-coded block, fixed or dynamic, and
    # a dynamic one naming at most 286 literal and length codes. BTYPE 3 is
    # reserved. A stored block, BTYPE 0, proves nothing: its check is 16 bits and
    # its body is copied as it stands, so in 32 MiB of random bytes one zlib header
    # in about a quarter million was followed by a stored length that checked,
    # "inflated" 128 clean bytes of copy and was refused as a corrupt stream. What
    # a stored block holds is in the file as it stands, where every view reads it.
    if pos >= len(data):
        return False
    first = data[pos]
    btype = first >> 1 & 3
    return btype == 1 or (btype == 2 and first >> 3 <= 29)


def _proven(kind: str, data: bytes, pos: int, trials: dict[tuple[str, bytes], bool],
            work: _Work, queue: list[tuple[str, bytes]], raw: bool = False) -> bool:
    # Whether a weak candidate is a stream. What an unproven trial inflated goes to
    # queue, which the caller reads as a file of its own. It is a
    # stream when its first _PROOF bytes inflate without an error, or when it ends
    # cleanly before them; from then on it is decoded like any other container and
    # refused where it fails. A candidate that fails inside its proof is no stream,
    # exactly as a strong header whose fields do not validate is none.
    #
    # Most candidates fail inside the first fed piece, which depends on nothing but
    # that piece, so those answers are cached by it. A page's delimiters repeat the
    # same few bytes, and every reading of a file repeats most of the others.
    proof = _PROOF[kind]
    window = data[pos:pos + proof]
    key = (kind, window[:_FEED])
    if key in trials:
        return False
    trial_work = _Work(_TRIAL_OUTPUT)
    before = len(queue)
    trial = _enqueue(queue, _dispatch(kind, window, trial_work))
    inflated = len(queue) > before
    clean = trial.extents[0][1]
    # Everything the trial spent is charged to the file, proven or not, and a
    # trial that reached its own cap spent all of it. Round 10 ran trials on a
    # budget of their own and a 512 KiB file peaked at 8.0 GiB; round 11 charged
    # the length of what a trial kept, which is nothing for a trial the cap
    # stopped, so a 32 MiB file of capped trials ran 16 GiB of uncharged work. A
    # trial the file cannot pay for proves nothing, and the file is refused.
    if not work.spend(_TRIAL_OUTPUT - trial_work.left):
        return False
    if trial.refusal == _LIMIT:
        proven = True
    elif not trial.refusal:
        # A zlib stream that ends cleanly passed its Adler-32 check, which no
        # candidate that was not a stream did in the corpus. Raw deflate carries no
        # check, and 6,045 non-streams there ended cleanly, so its end proves
        # nothing: what it inflated stays in the queue, read as a file of its own.
        proven = kind == "zlib"
    elif trial.refusal.startswith("truncated"):
        # Every byte it was given inflated cleanly. That proves a stream only when
        # it was given the whole proof, not when the reading ran out first.
        proven = len(window) == proof
    else:
        proven = False
        if not inflated and clean == 0:
            trials[key] = False
    if proven:
        # A proven candidate is decoded whole from these same bytes by the caller,
        # so the trial's head of it leaves the queue rather than being read twice
        # under two names.
        del queue[before:]
    elif raw and inflated and queue[before][1] in window:
        # An unproven trial in the file's own bytes whose output is a copy of bytes
        # it read has decoded nothing new: every name in it is in this file's raw
        # view, and every container and base64 run in it lies at the same bytes of
        # this same reading, which is read for both. What reading it again would
        # add is a raw deflate trial at its head, a position that is no payload
        # start here, which the docstring already excludes. Without this, garbage
        # that inflates to itself less one byte ran every fragment down to the
        # depth limit, and 2 files of the 230 in this tree were refused for it.
        del queue[before:]
    return proven


def _b64_runs(blob: bytes) -> Iterator[bytes]:
    # Runs with the filler a decoder discards removed and URL-safe letters mapped
    # to standard ones.
    for m in _B64_RUN.finditer(blob):
        run = _B64_WRAP.sub(b"", m.group(0))
        if len(run) >= _B64_MIN:
            yield run.replace(b"-", b"+").replace(b"_", b"/")


def _container_kind(blob: bytes) -> str:
    head = blob[:6]
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head == b"\xfd7zXZ\x00":
        return "xz"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if head[:4] == b"wOF2":
        return "woff2"
    if head[:4] == b"wOFF":
        return "woff"
    if head[:4] == b"\x89PNG":
        return "png"
    if head[:5] == b"%PDF-":
        return "pdf"
    if len(blob) >= 512 and blob[257:262] == b"ustar":
        return "tar"
    if zipfile.is_zipfile(io.BytesIO(blob)):
        return "zip"
    return ""


def _containers_in(data: bytes) -> list[tuple[int, str]]:
    # Every container whose header starts past offset zero and validates, as
    # (offset, kind). A tar is found by the magic it carries 257 bytes in.
    found = [(m.start(), _MAGIC_KIND[m.group(0)])
             for m in _CONTAINER_MAGIC.finditer(data) if m.start()]
    found += [(m.start() - 257, "tar") for m in _TAR_MAGIC.finditer(data)
              if m.start() > 257]
    return sorted((at, kind) for at, kind in found if _valid_container(data, at, kind))


# The bytes each check below reads, from the head of the container. A head cut
# off inside them is no container, and asking first means no check ever reads
# past the end, so none needs an exception handler to say so.
_HEAD_BYTES = {"gzip": 4, "xz": 12, "bzip2": 10, "zstd": 5, "woff": 16, "woff2": 16,
               "png": 16, "pdf": 8, "tar": 512}


def _valid_container(data: bytes, at: int, kind: str) -> bool:
    # Whether the bytes at "at" are the head of a container of this kind: its
    # magic, then the fields its format fixes. Magic alone is weak. Ordinary text
    # decodes to it (this file spells five of them as hex escapes) and binary
    # holds a three-byte gzip magic by chance once in 16 MiB, so round 8 followed
    # magic and then had to guess, from how the decompressor failed, whether it
    # had followed a container at all. It guessed "no" for real streams its own
    # decode had damaged. This asks first, from fields every conforming writer
    # sets and text almost never spells, and it only ever asks what the format
    # requires: a check that turned a real stream away would be the miss.
    left = len(data) - at
    if kind == "zip":
        if data.startswith(b"PK\x03\x04", at):  # APPNOTE 4.3.7
            return left >= 10 and struct.unpack_from("<H", data, at + 8)[0] in _ZIP_METHODS
        # APPNOTE 4.3.16, the end record of an empty archive: the two disk numbers
        # of any archive a reader opens are small.
        return (data.startswith(b"PK\x05\x06", at) and left >= 22
                and max(struct.unpack_from("<HH", data, at + 4)) < 0x100)
    if left < _HEAD_BYTES.get(kind, len(data) + 1):
        return False
    if kind == "gzip":  # RFC 1952 2.3.1: FLG bits 5 to 7 are reserved, zero
        return data.startswith(b"\x1f\x8b\x08", at) and not data[at + 3] & 0xE0
    if kind == "xz":  # xz file format 2.1.1: stream flags, then their CRC32
        flags = data[at + 6:at + 8]
        return (data.startswith(b"\xfd7zXZ\x00", at)
                and flags[0] == 0 and not flags[1] & 0xF0
                and zlib.crc32(flags) == struct.unpack_from("<I", data, at + 8)[0])
    if kind == "bzip2":  # a level digit, then a block or end-of-stream magic
        return (data.startswith(b"BZh", at) and data[at + 3] in b"123456789"
                and data[at + 4:at + 10] in _BZIP2_BLOCK)
    if kind == "zstd":
        return data.startswith(b"\x28\xb5\x2f\xfd", at) and _zstd_head_ok(data, at)
    if kind in ("woff", "woff2"):  # WOFF 1.0 and 2.0: reserved is zero
        sig, _, length, tables, reserved = struct.unpack_from(">4sIIHH", data, at)
        return (sig == (b"wOF2" if kind == "woff2" else b"wOFF") and reserved == 0
                and tables > 0 and 44 <= length <= left)
    if kind == "png":  # the signature, then IHDR as the first chunk
        return data.startswith(b"\x89PNG\r\n\x1a\n", at) and data[at + 12:at + 16] == b"IHDR"
    if kind == "pdf":
        return _PDF_HEADER.match(data, at) is not None
    # A tar: the eight bytes of the magic, NUL included, and a whole header. Not
    # the checksum: it covers the member name and the owner names, which are
    # text, so a layer that decoded an "&" in a name would turn a real tar away.
    # tarfile checks it, and a failure there is a refusal.
    return _TAR_MAGIC.match(data, at + 257) is not None


def _zstd_head_ok(data: bytes, at: int) -> bool:
    # RFC 8878 3.1.1.1: the descriptor's reserved bit is zero, and the first
    # block header after the frame header names a real block type and a size no
    # larger than the 128 KiB maximum.
    descriptor = data[at + 4]
    if descriptor & 0x08:
        return False
    single = bool(descriptor & 0x20)
    pos = (at + 5 + (0 if single else 1) + (0, 1, 2, 4)[descriptor & 3]
           + (int(single), 2, 4, 8)[descriptor >> 6])
    if pos + 3 > len(data):
        return False
    block = int.from_bytes(data[pos:pos + 3], "little")
    return (block >> 1) & 3 != 3 and block >> 3 <= 128 * 1024


def _wide_encoded_text(blob: bytes) -> bool:
    # Whether the blob is text in an encoding that interleaves NUL bytes and hides
    # something from the container stage by doing it.
    #
    # Two questions, and the second is the one that matters. A stride and a lead
    # are candidates when a byte-order mark declares them or when every filler byte
    # is almost always NUL. Then the interleaving is undone at that stride and the
    # candidate only counts if what comes out is something the container stage
    # would have acted on: a container header, magic anywhere, or a base64 run.
    #
    # Asking that second question rather than measuring how much of the text half
    # looks like ASCII is what keeps this off ordinary binaries. b"\x00\xff"
    # repeated is byte for byte UTF-16-BE for a run of U+00FF, and the UTF-8 read
    # of it turns every 0xFF into "?", which any proportion of printable ASCII
    # accepts. Neither hides a payload, and neither is refused.
    if len(blob) < _WIDE_MIN or b"\0" not in blob:
        return False
    marked = blob[:2] in _WIDE_BOM
    for stride in (2, 4):  # UTF-16 and UTF-32
        parts = [blob[i::stride] for i in range(stride)]
        for lead, text in enumerate(parts):
            filler = parts[:lead] + parts[lead + 1:]
            if text.count(0) > len(text) * _WIDE_TEXT_NUL:
                continue
            if not (marked or all(p.count(0) >= len(p) * _WIDE_FILLER_NUL
                                  for p in filler)):
                continue
            if (_container_kind(text) or _CONTAINER_MAGIC.search(text)
                    or next(_b64_runs(text), None)):
                return True
    return False


# ---------------------------------------------------------------------------
# The decoders _dispatch hands work to. A codec writes one stream into a sink and
# lets every failure propagate; a structure walks a format and hands each
# compressed piece back to _dispatch. None of them catches its own failure.
# ---------------------------------------------------------------------------


def _inflate(data: bytes, start: int, sink: _Sink, wbits: int, what: str) -> int:
    # One zlib-format stream from data[start:]: gzip (wbits 31), zlib (15) or
    # raw deflate (-15). Returns the offset just past it.
    d = zlib.decompressobj(wbits)
    pos, pending = start, b""
    while not d.eof:
        if not pending and pos < len(data):
            pending = data[pos:pos + _FEED]
            pos += len(pending)
            sink.fed = pos
        piece = d.decompress(pending, sink.room())
        sink.add(piece)
        pending = d.unconsumed_tail
        sink.used = pos - len(pending)
        if not (piece or pending or d.eof) and pos >= len(data):
            raise _Refuse(f"truncated {what}")  # every byte read, no end marker
    sink.used = pos - len(d.unused_data)
    return sink.used


def _gzip(data: bytes, start: int, sink: _Sink) -> None:
    # Member by member. Zero padding between members is skipped, as GzipFile skips
    # it, and bytes after the last member are not gzip: the file's own views read
    # them, and a container among them is found past offset zero like any other.
    while True:
        start = _NULS.match(data, _inflate(data, start, sink, 31, "gzip stream")).end()
        if not data.startswith(b"\x1f\x8b", start):
            return


def _zlib(data: bytes, start: int, sink: _Sink) -> None:
    _inflate(data, start, sink, 15, "zlib stream")


def _deflate(data: bytes, start: int, sink: _Sink) -> None:
    _inflate(data, start, sink, -15, "deflate stream")


def _unpack(data: bytes, start: int, sink: _Sink, make, head: bytes, what: str) -> None:
    # xz, bzip2 and zstd, stream by stream, fed as _inflate feeds. Each of these
    # decompressors keeps what it cannot hand out yet, so it is asked again with
    # no input until it needs some. xz pads between streams with NUL.
    while True:
        d = make()
        pos = start
        while not d.eof:
            chunk = b""
            if d.needs_input:
                if pos >= len(data):
                    raise _Refuse(f"truncated {what}")
                chunk = data[pos:pos + _FEED]
                pos += len(chunk)
                sink.fed = pos
            piece = d.decompress(chunk, sink.room())
            sink.add(piece)
            sink.used = pos
            # A call with no input that hands out nothing and still needs none is a
            # decoder that will never finish. One that now asks for input is not:
            # zstd drains a piece exactly at the limit and asks on the next call.
            if not (chunk or piece or d.eof or d.needs_input):
                raise _Refuse(f"truncated {what}")
        sink.used = pos - len(d.unused_data)
        start = _NULS.match(data, sink.used).end()
        if not data.startswith(head, start):
            return


def _xz(data: bytes, start: int, sink: _Sink) -> None:
    # Imported here, as brotli is, so a python3 built without _lzma or _bz2 still
    # runs the staged, range and tree hooks.
    try:
        import lzma
    except ImportError:
        raise _Refuse("xz needs the lzma module") from None
    _unpack(data, start, sink, lzma.LZMADecompressor, b"\xfd7zXZ\x00", "xz stream")


def _bzip2(data: bytes, start: int, sink: _Sink) -> None:
    try:
        import bz2
    except ImportError:
        raise _Refuse("bzip2 needs the bz2 module") from None
    _unpack(data, start, sink, bz2.BZ2Decompressor, b"BZh", "bzip2 stream")


def _zstd(data: bytes, start: int, sink: _Sink) -> None:
    try:
        from compression import zstd  # type: ignore[import-not-found]
    except ImportError:
        raise _Refuse("zstd needs Python 3.14 or later") from None
    _unpack(data, start, sink, zstd.ZstdDecompressor, b"\x28\xb5\x2f\xfd", "zstd stream")


def _brotli(data: bytes, start: int, sink: _Sink) -> None:
    # Brotli has no magic, so it is read only where a format or a name declares
    # it: a woff2 font's tables and a precompressed .br asset.
    try:
        import brotli  # type: ignore[import-not-found]
    except ImportError:
        raise _Refuse("woff2 needs the brotli package from requirements-dev.txt") from None
    d = brotli.Decompressor()
    pos = start
    while not d.is_finished():
        # Brotli says it can accept more input while it still holds output past
        # the last limit, so running out of input is not yet a truncation: the
        # empty call drains what it holds, and only an empty call that hands out
        # nothing and does not finish the stream is one. A 56-byte asset that
        # expands to 6 MiB was refused as truncated before this.
        chunk = b""
        if d.can_accept_more_data() and pos < len(data):
            chunk = data[pos:pos + _FEED]
            pos += len(chunk)
            sink.fed = pos
        piece = d.process(chunk, output_buffer_limit=sink.room())
        sink.add(piece)
        sink.used = pos
        if not (chunk or piece or d.is_finished()):
            raise _Refuse("truncated brotli stream")


def _base64(run: bytes, start: int, sink: _Sink) -> None:
    # A run holds only the alphabet, with "=" left out, so padding is restored
    # and a length of 1 mod 4, never valid base64, drops its stray last letter.
    # That leaves nothing b64decode can refuse; the dispatcher refuses it anyway if
    # it ever does, because nothing here may read a failure as an empty decode.
    run = run[start:]
    if len(run) % 4 == 1:
        run = run[:-1]
    sink.add(base64.b64decode(run + b"=" * (-len(run) % 4)))
    sink.used = start + len(run)


def _member(opener, start: int, sink: _Sink) -> None:
    # One member of a zip or a tar, read through the archive's own reader in
    # pieces the sink bounds.
    with opener() as f:
        while chunk := f.read(sink.room()):
            sink.add(chunk)


def _piece(res: _Result, kind: str, data: bytes, begin: int, end: int, work: _Work,
           label: str) -> None:
    # One compressed piece of a structure, through the dispatcher. The limit ends
    # the structure; any other refusal is recorded and the structure reads on.
    part = _enqueue(res.parts, _dispatch(kind, data[begin:end], work), rename=label)
    res.extents += [(begin + b, begin + e) for b, e in part.extents]
    if part.refusal == _LIMIT:
        raise _Refuse(_LIMIT)
    if part.refusal:
        res.stopped.append(part.refusal)


def _member_part(res: _Result, kind: str, opener, work: _Work, scan: _SiteScan,
                 where: list[str], label: str) -> None:
    # A member that cannot be read is refused where it stands and the archive
    # reads on, as a reader's own unpacker would, and what it read is scanned.
    member = _enqueue(res.parts, _dispatch(kind, opener, work), rename=label)
    if member.refusal == _LIMIT:
        raise _Refuse(_LIMIT)
    if member.refusal:
        scan.problem(where, member.refusal)


def _zip(data: bytes, work: _Work, res: _Result, scan: _SiteScan, chain: list[str]) -> None:
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    for info in infos:
        label = _label(info.filename, scan.folded)
        where = chain + [label]
        scan.name(where, info.filename, "member name")
        scan.name(where, info.comment.decode("utf-8", "replace"), "member comment")
        if Path(info.filename).name == DENYLIST_NAME:
            scan.problem(where, "the archive holds the denylist")
        elif info.flag_bits & 0x1:
            scan.problem(where, "encrypted member cannot be scanned")
        elif not info.is_dir():
            _member_part(res, "zip member", functools.partial(zf.open, info), work, scan,
                         where, label)
    # Each member's local header and data, and the central directory, are the
    # archive's own bytes. Nothing else is: a polyglot's prefix, and a local entry
    # the central directory does not list, which a reader that walks local headers
    # does unpack, are left for the scan to find containers in.
    for info in infos:
        name_len, extra_len = struct.unpack_from("<HH", data, info.header_offset + 26)
        res.extents.append((info.header_offset,
                            info.header_offset + 30 + name_len + extra_len + info.compress_size))
    res.extents.append((zf.start_dir, len(data)))


def _tar(data: bytes, work: _Work, res: _Result, scan: _SiteScan, chain: list[str]) -> None:
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    for m in tf.getmembers():
        label = _label(m.name, scan.folded)
        where = chain + [label]
        scan.name(where, m.name, "member name")
        # The spec names uname and gname: an archive built on a laptop carries the
        # builder's login in every header.
        header = "\n".join([m.linkname, m.uname, m.gname,
                            *(f"{k}={v}" for k, v in m.pax_headers.items())])
        scan.name(where, header, "tar header")
        if Path(m.name).name == DENYLIST_NAME:
            scan.problem(where, "the archive holds the denylist")
        elif m.isfile():
            _member_part(res, "tar member", functools.partial(tf.extractfile, m), work, scan,
                         where, label)
    # tf.offset sits just past the last member's data, before the end blocks.
    res.extents.append((0, tf.offset))
    res.tail = data[tf.offset:]


def _uint_base128(b: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for i in range(5):
        byte = b[pos + i]
        if i == 0 and byte == 0x80:
            raise ValueError("leading zero")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, pos + i + 1
    raise ValueError("UIntBase128 too long")


def _uint_255(b: bytes, pos: int) -> tuple[int, int]:
    code = b[pos]
    if code == 253:
        return struct.unpack_from(">H", b, pos + 1)[0], pos + 3
    if code == 255:
        return b[pos + 1] + 253, pos + 2
    if code == 254:
        return b[pos + 1] + 506, pos + 2
    return code, pos + 1


def _woff2(data: bytes, work: _Work, res: _Result, scan: _SiteScan, chain: list[str]) -> None:
    # WOFF2 (W3C Recommendation, section 5) packs every table into one Brotli
    # stream that starts right after the table directory. Its length depends on
    # variable-length fields, so the directory has to be walked to find it.
    (_, flavor, _, num_tables, _, _, comp_size, _, _, meta_off, meta_len, _, _, _
     ) = struct.unpack_from(">4sIIHHIIHHIIIII", data, 0)
    pos = 48
    for _ in range(num_tables):
        flags = data[pos]
        pos += 1
        if flags & 0x3F == 0x3F:
            tag = data[pos:pos + 4]
            pos += 4
        else:
            tag = {10: b"glyf", 11: b"loca"}.get(flags & 0x3F, b"")
        _, pos = _uint_base128(data, pos)
        version = flags >> 6
        # glyf and loca use version 0 for their transform, every other table uses
        # version 0 for none, and only a transform adds a length.
        if (version == 0) == (tag in (b"glyf", b"loca")):
            _, pos = _uint_base128(data, pos)
    if flavor == 0x74746366:  # 'ttcf', a font collection
        pos += 4
        num_fonts, pos = _uint_255(data, pos)
        for _ in range(num_fonts):
            n, pos = _uint_255(data, pos)
            pos += 4
            for _ in range(n):
                _, pos = _uint_255(data, pos)
    if pos + comp_size > len(data) or meta_off + meta_len > len(data):
        raise _Refuse("malformed woff2 font")
    _piece(res, "brotli", data, pos, pos + comp_size, work, "woff2 tables")
    if meta_len:
        _piece(res, "brotli", data, meta_off, meta_off + meta_len, work, "woff2 metadata")


def _woff(data: bytes, work: _Work, res: _Result, scan: _SiteScan, chain: list[str]) -> None:
    # WOFF 1.0 compresses each table on its own with zlib, and stores it as it is
    # when that would not save space.
    num_tables = struct.unpack_from(">H", data, 12)[0]
    meta_off, meta_len, _ = struct.unpack_from(">III", data, 24)
    entries = [struct.unpack_from(">4sIIII", data, 44 + 20 * i) for i in range(num_tables)]
    for _, off, comp_len, orig_len, _ in entries:
        if comp_len < orig_len:
            _piece(res, "zlib", data, off, off + comp_len, work, "woff table")
    if meta_len:
        _piece(res, "zlib", data, meta_off, meta_off + meta_len, work, "woff metadata")


def _png(data: bytes, work: _Work, res: _Result, scan: _SiteScan, chain: list[str]) -> None:
    # zTXt, iTXt and iCCP chunks hold zlib-compressed author or profile text, and
    # the IDAT chunks together hold one zlib stream of pixel rows. Pixels are not
    # text, but a stream a format declares is read or refused, never assumed.
    pos, image = 8, []
    while pos + 8 <= len(data):
        length, ctype = struct.unpack_from(">I4s", data, pos)
        body, pos = pos + 8, pos + 12 + length
        if pos > len(data):
            raise _Refuse("truncated png")
        if ctype in (b"zTXt", b"iCCP"):
            text = data.index(b"\0", body, body + length) + 2
            _piece(res, "zlib", data, text, body + length, work, "png chunk")
        elif ctype == b"iTXt":
            key = data.index(b"\0", body, body + length)
            if data[key + 1]:  # the compression flag
                lang = data.index(b"\0", key + 3, body + length)
                text = data.index(b"\0", lang + 1, body + length) + 1
                _piece(res, "zlib", data, text, body + length, work, "png chunk")
        elif ctype == b"IDAT":
            image.append((body, body + length))
        elif ctype == b"IEND":
            break
    if image:
        # The IDAT chunks are one stream split across chunk boundaries, so they are
        # joined before inflating. Read at the first chunk alone, the stream runs
        # into the next chunk's length and type and fails.
        rows = _enqueue(res.parts, _dispatch("zlib", b"".join(data[b:e] for b, e in image), work),
                        rename="png image")
        res.extents += image
        if rows.refusal == _LIMIT:
            raise _Refuse(_LIMIT)
        if rows.refusal:
            res.stopped.append(rows.refusal)


def _pdf(data: bytes, work: _Work, res: _Result, scan: _SiteScan, chain: list[str]) -> None:
    # Every stream whose dictionary names a filter is decoded or refused. Round 9
    # tried zlib on every stream and skipped the ones zlib refused, because a PDF
    # holds pictures that are not zlib; that skip passed a Flate stream with one
    # byte flipped as clean. The dictionary says what a stream is, so a declared
    # Flate stream that fails is refused, a picture is left alone, and a filter
    # this scan does not decode is refused. A stream that names no filter is
    # plain bytes, which the file's own views already read.
    done = 0
    for m in _PDF_STREAM.finditer(data):
        if m.start() < done:
            continue  # the keyword sits inside the previous stream's own bytes
        head = data[max(done, m.start() - 4096):m.start()]
        head = _PDF_NAME_ESCAPE.sub(lambda e: bytes([int(e.group(1), 16)]),
                                    head[head.rfind(b"obj") + 1:])
        end = data.find(b"endstream", m.end())
        done = end = len(data) if end < 0 else end
        name = _pdf_filter(data, head)
        if name is None or name in _PDF_PICTURE:
            continue
        if name in _PDF_FLATE:
            _piece(res, "zlib", data, m.end(), end, work, "pdf stream")
        elif name == b"":
            # The dictionary names a filter the scan cannot read: an indirect
            # reference to no object it can find. Round 10 read that stream as
            # plain bytes, which a Flate stream is not.
            res.stopped.append("a pdf stream filter the scan cannot read")
        else:
            res.stopped.append("a pdf stream filter the scan does not decode")


def _pdf_filter(data: bytes, head: bytes) -> bytes | None:
    # The first filter a stream dictionary declares: its name, None when it
    # declares none, or b"" when it declares one the scan cannot read.
    declared = _PDF_FILTER.search(head)
    if declared is not None:
        return declared.group(1)
    ref = _PDF_FILTER_REF.search(head)
    if ref is None:
        return b"" if b"/Filter" in head else None
    # Under an incremental update the last definition of an object is the one a
    # reader uses (ISO 32000-1 7.5.6), so the last match wins.
    targets = list(re.finditer(rb"(?<![0-9])" + ref.group(1) + rb"\s+" + ref.group(2)
                               + rb"\s+obj\s*\[?\s*/([A-Za-z0-9#]+)", data))
    if not targets:
        return b""
    target = targets[-1]
    return _PDF_NAME_ESCAPE.sub(lambda e: bytes([int(e.group(1), 16)]), target.group(1))


_CODECS = {"gzip": _gzip, "zlib": _zlib, "deflate": _deflate, "xz": _xz, "bzip2": _bzip2,
           "zstd": _zstd, "brotli": _brotli, "base64": _base64, "zip member": _member,
           "tar member": _member}
_STRUCTURES = {"zip": _zip, "tar": _tar, "woff2": _woff2, "woff": _woff, "png": _png,
               "pdf": _pdf}
_LABEL = {"gzip": "gzip stream", "zlib": "zlib stream", "deflate": "deflate stream",
          "xz": "xz stream", "bzip2": "bzip2 stream", "zstd": "zstd stream",
          "brotli": "brotli stream", "base64": "base64", "zip member": "", "tar member": ""}
# The one reason each kind is refused for when its own reader raises. Fixed text,
# because the reader's message can quote a member name.
_CORRUPT = {"gzip": "corrupt gzip stream", "zlib": "corrupt zlib stream",
            "deflate": "corrupt deflate stream", "xz": "corrupt xz stream",
            "bzip2": "corrupt bzip2 stream", "zstd": "corrupt zstd stream",
            "brotli": "corrupt brotli stream", "base64": "undecodable base64 run",
            "zip member": "member cannot be decompressed", "tar member": "member cannot be read",
            "zip": "corrupt zip archive", "tar": "corrupt tar archive",
            "woff2": "malformed woff2 font", "woff": "malformed woff font",
            "png": "malformed png", "pdf": "malformed pdf"}
# The kinds whose header is too weak to be a claim on its own; see _proven.
_WEAK = frozenset(_PROOF)
# A line a catch wrote, and a refusal that settle_misreadings may drop: a stream
# codec that failed in its body. Anchored at the end, where the reason is, because
# the chain before it holds names a file chose.
_CATCH_LINE = re.compile(
    r": contains a denylisted token \(#\d+ in " + re.escape(DENYLIST_NAME) + r", [^():]+ view\)\Z")
_MISREAD_LINE = re.compile(
    ": (?:" + "|".join(re.escape(how[1].split(" (")[0]) for how in (_AT_HEAD, _EMBEDDED, _ENCODED))
    + r") \((?:corrupt|truncated) (?:"
    + "|".join(("gzip", "zlib", "deflate", "xz", "bzip2", "zstd", "brotli")) + r") stream\)\Z")


def _scan_file(scan: _SiteScan, path: Path, label: str, size: int) -> None:
    if size > SITE_MAX_BLOB:
        scan.problem([label], "larger than the per-blob scan limit")
        return
    try:
        data = path.read_bytes()
    except OSError:
        scan.problem([label], "cannot be read")
        return
    scan.blob([label], data, 0, _Work(SITE_MAX_EXPANDED))


def check_site(root: Path, tokens: list[str]) -> list[str]:
    """Scan every file under root, including archive and font contents."""
    scan = _SiteScan(tokens)
    if not root.is_dir():
        return [f"{_label(root.name, scan.folded)}: not a directory"]
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for entry in sorted(dirnames) + sorted(filenames):
            path = Path(dirpath) / entry
            label = _label(entry, scan.folded)
            scan.name([label], entry)
            # OSError text carries absolute paths, so every failure below is
            # reported with fixed text only.
            try:
                st = path.lstat()
            except OSError:
                scan.problem([label], "cannot be inspected")
                continue
            if stat.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(path)
                    resolved = path.resolve()
                    exists = resolved.exists()
                except (OSError, RuntimeError):
                    scan.problem([label], "symlink cannot be resolved")
                    continue
                scan.report_hits([label], {i: "symlink target" for i in
                                           _hits(_str_views(target), scan.folded)})
                if not (resolved == root or root in resolved.parents):
                    scan.problem([label], "symlink points outside the scanned directory")
                elif not exists:
                    # A dangling link could resolve anywhere once deployed.
                    scan.problem([label], "symlink target is missing")
            elif stat.S_ISDIR(st.st_mode):
                continue
            elif not stat.S_ISREG(st.st_mode):
                scan.problem([label], "not a regular file")
            elif entry == DENYLIST_NAME:
                scan.problem([label], "the denylist is inside the scanned directory")
            else:
                _scan_file(scan, path, label, st.st_size)
    return scan.errs


def _withhold_tokens(lines: list[str], tokens: list[str]) -> list[str]:
    # Last line of defense: no output line reaches the log if it matches.
    folded = _fold_tokens(tokens)
    return [ln if not _hits(_str_views(ln), folded)
            else "a finding was withheld because its text matched the denylist"
            for ln in lines]


def main(argv: list[str]) -> int:
    usage_ok = bool(argv) and (
        (argv[0] == "staged" and len(argv) == 1)
        or (argv[0] == "range" and len(argv) >= 2)
        or (argv[0] in ("tree", "site") and len(argv) == 2))
    if not usage_ok:
        print(__doc__, file=sys.stderr)
        return 2
    repo = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").strip())
    tokens = load_tokens(repo / DENYLIST_NAME)
    errs = require_tokens(tokens)
    if not errs:
        if argv[0] == "staged":
            errs = check_staged(repo, tokens)
        elif argv[0] == "range":
            errs = check_range(repo, argv[1:], tokens)
        elif argv[0] == "site":
            errs = _withhold_tokens(check_site(Path(argv[1]), tokens), tokens)
        else:
            errs = check_tree(repo, argv[1], tokens)
    for e in errs:
        print(f"anon-check: {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
