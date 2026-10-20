"""Split-canary redaction and the hash-keyed publish check (J2 spec 10.1, K4).

Owner: ATACE Working Group.

`cxbom.proxy.redact` matches a canary only where the whole token sits inside
one value, so any fragment boundary through the canary defeats it: measured on
a 44-character canary, 0 of 43 split points were redacted and the reassembled
text carried the canary in clear at all 43. `model_delta` also never reaches
that rule, because it is a demo event and not a sidecar one.

The fix is not to enumerate where a boundary can fall. It is to normalize
across the boundary before matching: hold a rolling window over consecutive
fragments and match on the joined stream, so the number and position of the
splits stops mattering. The same shape closed the sibling instances in
`demo/anon.py` and `scripts/anon_check.py`.

Matching is keyed on SHA-256, so the plaintext canary is never in this file or
in a caller's. A hash alone cannot say where a candidate substring starts and
ends, which is why the proxy's rule once guessed at token runs and missed a
canary glued to other characters (it now keys on the shape's prefix, which
says where a canary of the shape starts). Here the caller supplies the
canary's *lengths* alongside its hashes -- the length is public (J2 spec 6 fixes the shape at `lab-demo-`
plus 32 hex characters) while the value is not -- and every window is scanned
at every offset for each length. That is complete for a given length: no
offset, no embedding, and no split can hide a canary of a length the caller
declared.

Two consequences are handled rather than chosen between.

The window is bounded, at `window_chars` characters. The bound is a memory
bound and never a coverage bound: `feed` admits at most `_admit` characters per
scan pass and loops, so a fragment far larger than the window is still scanned
whole. Every path that cannot make the guarantee raises `CanaryWindowError`
rather than returning text it has not scanned -- a redactor that silently stops
checking when a window fills is the fail-open hole this module exists to close.
Handed no key material, every entry point refuses rather than returning the
stream verbatim, because an identity function that calls itself a redactor is
that same hole with nothing to close it.

A canary longer than one window is refused at construction, not scanned with a
window too small to hold it. The construction bound is `window_chars >= 2 *
max(lengths)`: a canary must fit in half the window, because the other half is
the overlap the rolling window retains across flushes. A canary straddling a
flush is therefore still matched whole -- `_drain` retains the last
`max_len - 1` characters and never releases a character whose canary is not yet
determined.

The window bound is reachable, and the shape is what keeps a canary from
reaching it. A run of occurrences that overlap merges into one match the
redactor holds back whole, so the buffer grows and the guard refuses. Two
occurrences overlap only when a later one starts strictly inside an earlier
one, and the character it starts on is the shape's first character, `l`. That
character is outside the hexadecimal alphabet and appears nowhere else in the
prefix, so it occurs in a canary at index 0 and nowhere else. No occurrence of
any value of the shape can start inside another, so no two overlap, one canary
or many, at any length. The proof is in the comment above `SHAPE_PREFIX`. What
the shape does not reach is the hash intake: the redactor, the publish check and
`--redact-sha256` are keyed on a SHA-256, the shape cannot be checked through a
hash, and a caller that builds key material itself can key a value that does
overlap itself. So `_check_window` stays, and stays tested.

A fragment boundary is not the only boundary. A model controls its own tool
arguments, so it can put half the canary in one argument and half in the next,
and a per-value scan misses that for exactly the reason a per-fragment scan
missed the split fragment. `redact_value` therefore joins a container's string
leaves in document order and scans the join as well, and `publish_errors` joins
every event's `data` values across the whole stream at the last gate. Keys and
the C2 envelope are left out of those joins because each sits between two values
the join exists to make adjacent; both are still scanned whole.

Document order is where a join stops, and adjacency was never the property worth
protecting. Recovery is. The shape is published -- `lab-demo-` and 32
hexadecimal characters -- so a viewer with two halves on screen in any order
recovers the canary by trying both concatenations and keeping the one that has
the shape: measured over 2,000 synthetic canaries, unique recovery every time.
So `shape_errors` takes the shape rather than a third join. It reads every string
in the stream, keys included, and asks whether any concatenation of them, in any
order, spells the shape. It needs no key material at all, which is why it
reaches four cases the hash-keyed scans cannot: halves in the reverse of
document order, halves with a third value between them, a half in a value and
the other half in the key that follows it, and a canary whose declared length is
wrong. `redact_value` applies the same rule to every string of one value, keys
included, and replaces each string that is a piece of an assembly, so a pane
that prints tool calls live does not show those pieces either. Having no key,
it also replaces strings that only look like pieces, which fails closed.

Two more forms are closed, both keyed. Pieces with text between them, one URL
parameter per chunk (review O2), are read as fragments inside their strings,
and a head plus one or two nearby fragments is hashed (`_fragment_participants`,
in `redact_value`, in `redact_events` through it, and in `publish_errors` over
the whole stream). A canary split across tool calls (review O1) is caught by
`TakeRedactor`, the one redactor a take's harness uses for its terminal line
and its events: it holds the heads earlier calls brought, never prints one that
carries the literal prefix, and replaces the later piece that finishes one. Both
this chaining and the gate's keyed completion seed only from a head that carries
the literal `lab-demo-`: a fragment that spells only the prefix's public tail
(`demo-`, `-` and hex) is ordinary text as often as a canary piece, and seeding
the completion from one rebuilt the keyed canary out of unrelated hex in the
window -- the stream's own whole-in-place canary included -- so the gate refused
about one real take in eight (re-review of the J2 e2e gate). A canary whose
prefix is split across pieces or dropped is left to `_shape_assembly` and the
residuals below, not to this fragment path.

Three key-free gate rules widen the publish check past what the hash-keyed
completion reaches (`shape_errors`, so they run even with no key material).
`_partial_head` refuses a literal prefix followed by PARTIAL_HEAD_MIN_HEX or more
hexadecimal digits, the head of a canary the whole-shape rule is too long to see
-- a near-total leak the gate let through before (measured: 40 of 40 missed for
11 to 29 digits). `_prefix_reach` refuses a literal prefix that a full canary's
worth of hexadecimal digits follows within GATE_FRAGMENT_WINDOW, however the tail
is split, glued (hexadecimal filler included), reordered within a run, or merged
into one run: a split that leaves the prefix whole in any one piece is refused at
the gate whatever is done to the digits after it. Both key on the literal prefix,
a token a benign take never emits, so a bare hexadecimal run without it -- a
model revision, a git sha -- trips neither and is neither needed by them. And the
keyed scans fold letter case (see `_fold`), so a canary emitted as `LAB-DEMO-...`
or with uppercase hex, prefix and digits alike, is caught whole wherever it
appears in a scan window.

What stays open, exactly:

- a canary whose PREFIX itself is split across pieces, so no one string carries
  `lab-demo-` whole: `_prefix_reach` has no literal anchor, and the keyed
  completion seeds only from a literal head (a virtual-head seed, which would
  supply the public prefix, rebuilt the canary from unrelated hex and refused
  benign takes), so neither reaches it. `_shape_assembly` still catches this for
  two or three clean pieces in any order; four-character pieces (which cut the
  nine-character prefix), a split whose first cut lands inside the prefix with the
  tail also cut up, and such a split with the shape's own alphabet glued between
  the pieces stay open. This is the residual the runtime runner closes with the
  plaintext digits it holds and the offline gate cannot;
- characters of the shape's own alphabet on the inner side of a split piece,
  which cannot be told from the canary's digits: the keyed completion reads a
  tail at any offset now (`_hex_windows`), and `_prefix_reach` counts through the
  filler, so this stays open only when the prefix is also split (above);
- pieces more than FRAGMENT_WINDOW fragments apart in one value on the pane, or
  more than GATE_FRAGMENT_WINDOW apart in the stream at the gate;
- on the pane, and refused by the gate within GATE_FRAGMENT_WINDOW: model
  output that carries the canary other than whole and contiguous, such as its
  prefix dropped, its pieces with text between them, or its pieces out of
  order, because the rolling window matches a contiguous canary only; and a
  head in model output with its tail in a later tool argument;
- on the pane, but refused by the take's own publish verdict (re-review C1): a
  tail sent in an earlier call than its head, and a head in a tool argument
  with its tail in later model output. The take replaces the head on arrival,
  so what it emits holds nothing to pair, but `TakeRedactor.publish_errors`
  decides publication over the raw events the take kept, which still carry both
  pieces, and refuses these within GATE_FRAGMENT_WINDOW. More than HELD_HEADS
  heads pushing the real one out is past that window on both, so the take
  records the eviction and fails closed there rather than reporting a pass;
- a canary whose case is changed AND that is split so only the shape reader, not
  a hash, would reassemble it: the fold is at the hash boundary, not in the shape
  reader or the intake (see `_fold`);
- a transformation rather than an order: base64, a fully percent-encoded
  value, or characters inserted inside the canary is not shaped like one any
  more, and no layer here decodes.

Cost is O(n * len(lengths)) hashes over the stream, each over at most
`max(lengths)` bytes. The retained overlap is re-scanned once per pass.
"""
from __future__ import annotations

import bisect
import hashlib
import itertools
import re
import secrets

# The same placeholder the proxy writes, so one stream never carries two
# spellings of a redaction. tests/test_canary.py reads both and compares.
CANARY = "<canary>"

# 8192 characters holds any canary up to 4096, two orders of magnitude above
# the 41-character shape spec 6 fixes, and caps the redactor's live memory at
# one window regardless of how long a take runs.
DEFAULT_WINDOW_CHARS = 8192

# C2 event types this module reads. model_delta is the streamed model output,
# the surface K4 names and the one the rolling window covers. tool_call and
# exfil_attempt are K4's other two named carriers; each is a single value, so
# the whole-value convention applies there.
STREAM_TYPE = "model_delta"
VALUE_FIELDS = {"tool_call": ("arguments",), "exfil_attempt": ("url",)}


class CanaryWindowError(RuntimeError):
    """The redactor cannot make its guarantee, so it refuses to pass text through.

    Raised instead of returning unscanned text. Every message names the bound
    or the state that was violated and never any part of a canary.
    """


def _encoded(text: str) -> bytes:
    """text as UTF-8, refusing rather than skipping when it will not encode.

    A lone surrogate reaches a Python str through several paths this repository
    already guards elsewhere (contracts.checks hashes raw lines for exactly
    this reason). A matcher that caught UnicodeEncodeError and moved on would
    hand an attacker a one-character prefix that turns redaction off.
    """
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as e:
        raise CanaryWindowError(
            f"cxbom: canary scan cannot encode this text as UTF-8 ({e.reason} at "
            f"offset {e.start}), so it cannot be hashed and is refused rather "
            "than passed through unscanned") from None


# The only uppercase letters a canary of the shape can carry -- `lab-demo-` and
# the hex digits a-f -- mapped to lowercase. A model that ships the canary with
# its case changed still spells the same secret: a viewer who lowercases what is
# on screen recovers it, so a case change is an order-preserving disguise, not a
# transformation the matcher may ignore. Every hash comparison folds these nine
# letters first, so the redactor, the whole-value and reassembled-stream scans,
# and every keyed completion match a canary emitted as `LAB-DEMO-...`, with
# uppercase hex, or in any mixed case -- prefix and digits alike, because the
# whole candidate is folded before it is hashed.
#
# The table is length-preserving by construction (each key maps to exactly one
# codepoint), which is why it is a fixed nine-entry table and not `str.lower` or
# `str.casefold`: those change the length of a handful of Unicode inputs
# (`'İ'.lower()` is two characters), and the redactor rewrites by character
# offset, so a fold that moved a span would publish text it had not scanned. Only
# the canary's own alphabet is folded, so no unrelated character shifts a span.
#
# The fold stays at the hash boundary and does not reach `_spells`, the intake,
# or the key-free shape rule, which stay case-exact: the canonical lowercase
# value is the definition of the secret (spec 6), so `key_material` still refuses
# a non-canonical value and the file still commits no shape-shaped literal. The
# residual is a canary whose case is changed AND that is split so that only the
# shape reader, not a hash, would reassemble it (an uppercase prefix piece the
# head finder skips); a case-changed canary that appears whole in any scan
# window is caught here.
_CASE_FOLD = {ord(u): ord(u.lower()) for u in "ABCDEFLMO"}


def _fold(text: str) -> str:
    """text with the canary alphabet's uppercase letters lowercased, length unchanged."""
    return text.translate(_CASE_FOLD)


def _sha256_hex(text: str) -> str:
    # Fold before hashing so a canary emitted in any letter case matches the
    # hash of its lowercase value. `key_material` hashes the canonical lowercase
    # canary, where the fold is the identity, so the two agree.
    return hashlib.sha256(_encoded(_fold(text))).hexdigest()


def _normalized(hashes, lengths) -> tuple[frozenset, tuple]:
    """Validate and normalize the key material both the redactor and the check use."""
    hashes = frozenset(hashes)
    for h in hashes:
        if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise CanaryWindowError(
                "cxbom: a canary hash is not 64 lowercase hex characters, so it can "
                "never match and would leave the scan silently empty")
    sizes = []
    for n in lengths:
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            # The type and not the value. A caller who passes the canary string
            # where `lengths` belongs iterates it into characters, and repr of one
            # would print a character of the canary in the refusal.
            raise CanaryWindowError(
                f"cxbom: a canary length is not a positive integer "
                f"(got {type(n).__name__})")
        sizes.append(n)
    if hashes and not sizes:
        raise CanaryWindowError(
            "cxbom: canary hashes were supplied with no canary length. A hash alone "
            "does not say where a candidate substring begins or ends, so the scan "
            "would fall back to guessing token boundaries -- which is the defect "
            "this module exists to close. Supply len(canary) for every hash")
    return hashes, tuple(sorted(set(sizes)))


# The message both halves use, so one doctrine is spelled one way. Measured
# before this existed: `redact_events` and `SplitCanaryRedactor` handed no key
# material returned the stream verbatim and silently, while only the publish
# check refused. The artifact was still safe, because publishing fails closed,
# but the pane a viewer watches during a take was not.
NO_KEY_MATERIAL = (
    "no canary hash was supplied, so this would report a pass on a stream carrying "
    "the canary in clear. Refusing rather than scanning for nothing")


def _require_key_material(hashes: frozenset) -> None:
    """Refuse a redaction pass with nothing to look for.

    A redactor with no hashes is the identity, and an identity that calls itself
    a redactor is the fail-open shape this module exists to close: a take started
    without a canary hash would stream the canary to the pane with no error
    anywhere. The check that looks for nothing already refuses; so does this.
    """
    if not hashes:
        raise CanaryWindowError(f"cxbom: {NO_KEY_MATERIAL}")


def _hit(text: str, hashes: frozenset, sizes: tuple) -> bool:
    """True when text is, or contains at any offset, a declared canary.

    The whole string is hashed as well as every fixed-width slice, so a caller
    that declares a length that does not match its canary still matches an
    exact value. Offsets rather than token runs: an embedded canary is the same
    defect as a split one.
    """
    if _sha256_hex(text) in hashes:
        return True
    for size in sizes:
        for i in range(0, len(text) - size + 1):
            if _sha256_hex(text[i:i + size]) in hashes:
                return True
    return False


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Strictly overlapping match spans merged into disjoint ones, in order.

    Two declared lengths can match at overlapping offsets, and a shorter canary
    can sit inside a longer one. Merging keeps one placeholder per run of canary
    bytes instead of rewriting a region twice.

    Strictly overlapping, not touching, and the difference is load-bearing.
    Merging a span that merely touches the previous one makes a run of
    back-to-back canaries a single span of unbounded length; `_drain` then pins
    its release to that span's start, so the buffer never drains and the window
    guard fires. Measured at the shipped default window: 187 consecutive
    canaries refused. Touching spans also collapsed N occurrences into one
    placeholder, so the redacted stream could not show how many times the model
    reached for the secret.
    """
    out: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if out and start < out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


class SplitCanaryRedactor:
    """A rolling-window canary redactor over consecutive text fragments.

    Feed fragments in stream order; each `feed` returns the text that is safe
    to publish now, and `finish` returns the remainder. Output is the input
    stream with every canary occurrence replaced by `CANARY`, wherever the
    fragment boundaries fell.

    Release lags the input by up to `max(lengths)` characters, because a
    character cannot be published until every canary that could cover it is
    determined. Nothing is lost: `finish` releases the tail. A caller that
    never calls `finish` withholds that tail, which fails closed.
    """

    def __init__(self, hashes, lengths, window_chars: int = DEFAULT_WINDOW_CHARS):
        if not isinstance(window_chars, int) or isinstance(window_chars, bool) or window_chars < 1:
            raise CanaryWindowError(
                f"cxbom: window_chars is not a positive integer "
                f"(got {type(window_chars).__name__})")
        self._hashes, self._lengths = _normalized(hashes, lengths)
        _require_key_material(self._hashes)
        self._window = window_chars
        self._max_len = max(self._lengths) if self._lengths else 0
        if self._hashes and window_chars < 2 * self._max_len:
            raise CanaryWindowError(
                f"cxbom: a declared canary is {self._max_len} characters and the window "
                f"is {window_chars}. A canary must fit in half the window, because the "
                "other half is the overlap retained across flushes. Refused rather "
                f"than scanned with a window too small to hold it: raise window_chars "
                f"to at least {2 * self._max_len}")
        # Admitting this much per pass keeps len(_buf) at or under the window
        # while no match span is longer than max_len: the retained tail is then
        # at most max_len characters (see _drain), and this is what is left. A
        # run of overlapping canaries breaks that premise, which is why
        # _check_window is a guard that fires rather than an assertion of a
        # theorem.
        self._admit = max(1, window_chars - 2 * self._max_len + 1)
        self._buf = ""
        self._finished = False

    @property
    def window_chars(self) -> int:
        return self._window

    @property
    def held_chars(self) -> int:
        """Characters buffered but not yet released.

        Never above `window_chars` on any path that returns: a pass that would
        leave more than the bound in the buffer refuses instead.
        """
        return len(self._buf)

    def feed(self, text: str) -> str:
        if self._finished:
            raise CanaryWindowError(
                "cxbom: feed() after finish(). The window was flushed, so the boundary "
                "between the old stream and this text is no longer covered. Build a new "
                "redactor per run rather than reusing a finished one")
        if not isinstance(text, str):
            raise CanaryWindowError(f"cxbom: canary redaction takes str, not {type(text).__name__}")
        _encoded(text)  # refuse unencodable text before any of it is buffered
        if not text:
            return text
        out = []
        for start in range(0, len(text), self._admit):
            self._buf += text[start:start + self._admit]
            out.append(self._drain(final=False))
        return "".join(out)

    def finish(self) -> str:
        """Release the retained tail. Idempotent; further feeds are refused."""
        if self._finished:
            return ""
        self._finished = True
        return self._drain(final=True)

    def _drain(self, final: bool) -> str:
        buf = self._buf
        # A character at index i is determined once every canary that could
        # cover it lies inside the buffer. The latest such canary starts at i,
        # so i is determined once i + max_len <= len(buf).
        safe_end = len(buf) if final else len(buf) - self._max_len + 1
        if safe_end <= 0:
            self._check_window()
            return ""
        spans = self._spans(buf)
        release = safe_end
        for start, end in spans:
            # Releasing half a match would publish half a canary. Hold the
            # whole match back instead; a later pass, or finish(), releases it.
            if start < release < end:
                release = start
        out = self._rewrite(buf, [s for s in spans if s[1] <= release], release)
        self._buf = buf[release:]
        self._check_window()
        return out

    def _spans(self, buf: str) -> list[tuple[int, int]]:
        """Every canary occurrence in buf, at every offset, for every declared length."""
        hits: list[tuple[int, int]] = []
        for size in self._lengths:
            for i in range(0, len(buf) - size + 1):
                if _sha256_hex(buf[i:i + size]) in self._hashes:
                    hits.append((i, i + size))
        return _merge(hits)

    @staticmethod
    def _rewrite(buf: str, spans: list[tuple[int, int]], release: int) -> str:
        out = []
        at = 0
        for start, end in spans:
            # `at` never moves backwards. With merged spans it cannot, and this
            # is what stops a merge that regressed from re-emitting the tail of
            # an enclosing canary: sorted nested spans put (5, 15) before
            # (6, 10), so an unguarded rewrite jumps its cursor forward to 10
            # and then back, publishing the characters between 10 and 15 in
            # clear.
            if start < at:
                at = max(at, end)
                continue
            out.append(buf[at:start])
            out.append(CANARY)
            at = end
        out.append(buf[at:release])
        return "".join(out)

    def _check_window(self) -> None:
        """The memory bound, enforced rather than assumed. Reachable, and measured so.

        An earlier version of this module claimed the branch was unreachable by
        construction. The claim was false: the algebra assumed a match span is at
        most `max_len` long, and merged spans are not. Merging touching spans is
        fixed in `_merge`, and that closes the back-to-back case but not the
        general one -- a run of occurrences that genuinely overlap still merges
        into one span of unbounded length, `_drain` holds the whole run back,
        and this guard fires. `tests/test_canary.py` builds that chain from a
        value whose last character is its first and pins the refusal.

        Holding the whole run back is what makes the guard necessary rather than
        avoidable. Releasing at a merged span's end instead publishes the
        characters of the next, overlapping occurrence whose first character has
        already gone out inside a placeholder: measured on that chain, capping
        the hold-back published the canary whole. So the run is held, the buffer
        can grow on adversarial input, and this raises rather than truncating,
        because truncation silently drops text the caller handed us and a
        refusal does not. The exposure is availability, and the publish check
        catches the same stream independently.

        No value of the shape spec 6 fixes can build that chain, so a canary from
        `make_canary` or through `key_material` never reaches this guard. The
        hash intake still can, which is why the guard stays: the redactor takes
        hashes, the shape cannot be checked through a hash, and key material a
        caller assembled without `key_material` may key a value that is not the
        shape and does overlap itself.
        """
        if len(self._buf) > self._window:
            raise CanaryWindowError(
                f"cxbom: the canary window holds {len(self._buf)} characters, above its "
                f"bound of {self._window}. Refusing rather than releasing text this "
                "scan has not covered")


def redact_value(value, hashes, lengths):
    """Replace any string carrying a canary with `CANARY`, whole, at any depth.

    The whole-value convention is the proxy's (spec 4.6 item 4 asks the demo
    harness to redact `tool_call.arguments` with the same rule), because a
    partially rewritten URL or tool argument reads as a real value that matches
    nothing. The matcher is not the proxy's: this one scans every offset for
    every declared length, so it needs no shape to find a canary embedded in a
    longer run of token characters. The proxy scans the shape's prefix instead.
    """
    keys, sizes = _normalized(hashes, lengths)
    _require_key_material(keys)
    return _redact_tree(value, keys, sizes)


def _redact_tree(value, hashes: frozenset, sizes: tuple):
    """`_redact_value` over one whole value, with the key-free assembly rule applied first.

    The keyed join below reads the leaves in document order, so it cannot see a
    canary whose pieces are out of that order: halves with another field between
    them, halves in reverse order, or a half in a value and the other half in the
    key after it. Measured before this existed, each of those returned the prefix
    and 31 of the 32 secret hex digits in clear, and only the publish gate
    refused the stream. A pane that prints tool calls live is not behind that
    gate. So every string of the value, keys included, is read as it arrived by
    the same assembly rule the gate uses, and every string that is a piece of an
    assembly is replaced whole. The rule has no key, so a string that only looks
    like a piece is replaced too: that fails closed.
    """
    strings = list(_strings_in_order(value))
    shaped = _shape_participants(strings) | _fragment_participants(strings, hashes)[0]
    return _redact_value(value, hashes, sizes, shaped, itertools.count())


def _strings_in_order(node):
    """Every string in a value, keys included, in the order `_redact_value` visits them."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield k
            yield from _strings_in_order(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings_in_order(v)


def _redact_value(value, hashes: frozenset, sizes: tuple, shaped: set, order):
    """value with every canary replaced. `order` numbers the strings as `_strings_in_order` does."""
    if isinstance(value, str):
        return CANARY if next(order) in shaped or _hit(value, hashes, sizes) else value
    if isinstance(value, dict):
        # A loop, not a comprehension, so the key is visited before its value
        # on every Python this runs on, which is the order `shaped` counts in.
        out = {}
        for k, v in value.items():
            key = _redact_value(k, hashes, sizes, shaped, order)
            out[key] = _redact_value(v, hashes, sizes, shaped, order)
    elif isinstance(value, list):
        out = [_redact_value(v, hashes, sizes, shaped, order) for v in value]
    else:
        return value
    # A field boundary is a boundary like any other. A model that controls its
    # own tool arguments can put half the canary in one argument and half in the
    # next, and a per-value scan misses that for exactly the reason a
    # per-fragment scan missed the split fragment. So the container's own string
    # leaves are joined in document order and scanned too; a hit there blanks
    # every leaf, because nothing attributes the match to one of them.
    #
    # The join is of the leaves as they arrived, not as redacted. Redacting
    # first replaces a leaf that holds a whole canary with the placeholder,
    # and that also removes the characters a second, split canary needs from
    # it: measured with a canary glued back to back and cut through the first
    # copy, {"a": first half, "b": second half + canary} blanked "b" and
    # published the first half in clear. Only a match that spans two or more
    # leaves counts, because one inside a single leaf is already that leaf's
    # own redaction and blanking its neighbours for it hides nothing.
    #
    # "Two or more leaves" means leaves anywhere below this container, not only
    # its direct children. Every container on the path from a split to the root
    # runs this join over all the leaves beneath it, so each one finds the same
    # crossing match again and blanks all of its own leaves, including leaves
    # that held none of the canary. That over-blanks and fails closed, and
    # `test_a_nested_crossing_split_blanks_every_ancestor_leaf` pins it.
    if _crosses_leaves(list(_leaves(value)), hashes, sizes):
        return _blank_leaves(out)
    return out


def _crosses_leaves(leaves: list[str], hashes: frozenset, sizes: tuple) -> bool:
    """True when the leaves' join carries a canary that no single leaf holds whole."""
    joined = "".join(leaves)
    ends = list(itertools.accumulate(len(leaf) for leaf in leaves))

    def spans_two(start: int, end: int) -> bool:
        # bisect_right(ends, i) is the index of the leaf holding character i.
        return bisect.bisect_right(ends, start) != bisect.bisect_right(ends, end - 1)

    # No guard for an empty join. Every leaf is then empty, and if the empty
    # string is a key, each leaf's own scan has already replaced it.
    if _sha256_hex(joined) in hashes and spans_two(0, len(joined)):
        return True
    for size in sizes:
        for i in range(0, len(joined) - size + 1):
            if _sha256_hex(joined[i:i + size]) in hashes and spans_two(i, i + size):
                return True
    return False


def _leaves(node):
    """Every string value in a container, in document order. A key is not a value."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _leaves(value)
    elif isinstance(node, list):
        for value in node:
            yield from _leaves(value)


def _blank_leaves(node):
    if isinstance(node, str):
        return CANARY
    if isinstance(node, dict):
        return {k: _blank_leaves(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_blank_leaves(v) for v in node]
    return node


def _stream_order(events: list[dict]) -> list[int]:
    """Indices of the stream events, refusing a list whose seq is not increasing.

    Reassembly is defined by stream order, so a list handed over out of order
    would be joined in the wrong order and a canary split across the swapped
    pair would not be found. That is silent, so it is refused.
    """
    at = [i for i, ev in enumerate(events) if ev.get("type") == STREAM_TYPE]
    seqs = [events[i].get("seq") for i in at]
    if any(not isinstance(s, int) or isinstance(s, bool) for s in seqs):
        raise CanaryWindowError(
            f"cxbom: a {STREAM_TYPE} event has no integer seq, so stream order cannot "
            "be confirmed and the reassembled scan is refused")
    if any(b <= a for a, b in zip(seqs, seqs[1:])):
        raise CanaryWindowError(
            f"cxbom: {STREAM_TYPE} events are not in increasing seq order. Reassembly "
            "follows list order, so this list would be joined wrong and a canary split "
            "across the swapped pair would be missed")
    return at


def redact_events(events, hashes, lengths, window_chars: int = DEFAULT_WINDOW_CHARS) -> list[dict]:
    """A C2 event stream with every canary redacted, including a split one.

    One `TakeRedactor` over the whole list, in list order, so this and a live
    harness produce the same bytes. `model_delta.data.text` goes through one
    rolling window for the whole run, so a canary split across any number of
    fragments at any offsets is replaced in place. `tool_call.arguments` and
    `exfil_attempt.url` go through the take's argument redactor, which also
    catches a canary split across calls.

    Runs before the collector computes `prev_sha256`, and refuses a stream that
    already carries the chain: rewriting a chained line breaks every hash after
    it, and handing a publisher a stream whose chain silently no longer verifies
    is worse than stopping here.

    Fragment boundaries move by up to `max(lengths)` characters, because release
    lags the window. Event count, order, and every other field are unchanged,
    and the concatenation of the stream's text is the redacted stream exactly.
    """
    events = list(events)
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise CanaryWindowError(f"cxbom: event[{i}] is not an object")
        if ev.get("prev_sha256") is not None:
            raise CanaryWindowError(
                f"cxbom: event[{i}] already carries prev_sha256. Redaction rewrites "
                "line bytes, so it must run before the collector chains them. Refusing "
                "rather than returning a stream whose chain no longer verifies")
    order = _stream_order(events)
    take = TakeRedactor(hashes, lengths, window_chars=window_chars)
    out = []
    for i, ev in enumerate(events):
        try:
            out.append(take.event(ev))
        except CanaryWindowError as e:
            raise CanaryWindowError(f"cxbom: event[{i}]: {str(e)[len('cxbom: '):]}") from None
    tail = take.finish()
    if tail:
        if not order:  # unreachable: a non-empty tail means something was fed
            raise CanaryWindowError("cxbom: the canary window holds text but no event carried it")
        out[order[-1]]["data"]["text"] += tail
    return out


# How much of a take's argument text the cross-call redactor holds. A head is at
# most SHAPE_LEN - 1 characters, so nothing held is ever a whole canary, and the
# counts bound the memory at a few kilobytes whatever the take's length.
HELD_HEADS = 32
HELD_EXTENSIONS = 64
# The most pure-hex fragments of one call considered as a continuation of a
# held head, longest first.
EXTENSION_CANDIDATES = 256
# The most hex-bearing fragments one call may carry while a head is held. A
# call with more fails closed: every string holding one is replaced.
MAX_CALL_HEX_FRAGMENTS = 4096
# The most hex digits of one chain of pieces across calls that may reach the
# pane. With at most 15 of 32 shown, at least 17 stay hidden, 68 bits.
PRINT_BUDGET_HEX = 16


class TakeRedactor:
    """The one redactor a take's harness uses for its terminal line and its emitted events.

    Call `event` on every C2 event in stream order and print or emit what it
    returns, never the input. Call `finish` at the end of the take and append
    what it returns to the last `model_delta`: that is the tail the rolling
    window held back. Then call `publish_errors` and refuse to publish the take
    if it returns anything: that is the take's own verdict, and it is decided
    over the raw events rather than the redacted ones for the reason below.

    `redact_value` sees one tool call at a time, so a canary split across two
    calls, the standard way to smuggle a secret out in chunks, reached the pane
    whole less one digit: measured on 80 two-call splits at 271b8c7, runs of up
    to 40 characters. This keeps, across calls, the heads a later call could
    finish: a head is a fragment ending in the shape's prefix and some of its
    digits, or one starting inside the prefix and running past it. Then:

    - a head that carries the literal prefix is never printed. Its string is
      replaced when it arrives, because a later call may finish it.
    - a later fragment that finishes a held head into a key is replaced. Keyed,
      so only the real canary's tail matches. Every held head, literal or
      virtual, is completed this way.
    - a later pure-hex fragment that continues a held LITERAL head is held as a
      longer head, and replaced once the digits of that chain shown on the pane
      would reach PRINT_BUDGET_HEX. So a canary cut into three or more calls
      shows at most 15 of its 32 digits. Only a literal head chains a
      continuation: a virtual head is a fragment of ordinary text as often as a
      canary piece, and chaining one blanked about half of all benign calls on
      the pane (re-review I1).

    Redacting the pane and deciding publication are two jobs, and the gap
    between them is re-review C1. Replacing a head on arrival is right for the
    pane but destroys the piece a gate would pair, so a gate over what this
    class emits passes a tail sent before its head, or a head whose tail went to
    model output. `publish_errors` decides over the raw events the take kept,
    which still carry both pieces, and refuses those within GATE_FRAGMENT_WINDOW.

    What stays open, on the pane only unless noted: a tail sent before its head
    (it prints before anything marks it), a head in a tool argument with its
    tail in later model output, and the fragment rule's own limits
    (`_fragment_participants`) -- the first two are refused by `publish_errors`.
    More than HELD_HEADS heads pushing the real one out, and pieces more than
    GATE_FRAGMENT_WINDOW fragments apart, are past the gate's reach on both the
    pane and the raw events; an evicted literal head is recorded so
    `publish_errors` fails closed there rather than reporting a pass.

    Nothing held is ever printed, logged or put in a message. `repr` shows
    counts only.
    """

    def __init__(self, hashes, lengths, window_chars: int = DEFAULT_WINDOW_CHARS):
        self._keys, self._sizes = _normalized(hashes, lengths)
        _require_key_material(self._keys)
        self._stream = SplitCanaryRedactor(hashes, lengths, window_chars=window_chars)
        # (head, digits of it shown, literal), oldest first. `literal` says the
        # head carries the prefix; only a literal head chains continuations
        # across calls (see `_arguments`).
        self._heads: list[tuple[str, int, bool]] = []
        self._extensions: list[tuple[str, int, bool]] = []
        self._seq = None
        # The raw events, retained so the take carries its own publish verdict.
        # Redacting for the pane replaces the head of a cross-call split when it
        # arrives, so what this class emits no longer holds the piece the gate
        # pairs: a gate over the emitted stream then passes a tail sent before
        # its head, or a head whose tail went to model output (re-review C1).
        # The verdict is decided over these raw events instead, which still hold
        # both pieces. The harness holds the same events to write the merged
        # stream, so this adds no memory the run did not already spend.
        self._raw: list[dict] = []
        # Set when a literal head is pushed out of `_heads` by more than
        # HELD_HEADS later heads. Past that point the gate's fragment window can
        # no longer pair the evicted head with a later tail, so the take fails
        # closed rather than reporting a pass it cannot stand behind.
        self._evicted_literal_head = False

    def __repr__(self) -> str:
        return (f"TakeRedactor(held_heads={len(self._heads)}, "
                f"held_extensions={len(self._extensions)})")

    @property
    def unpublishable(self) -> bool:
        """True when `publish_errors` would refuse the take. A quick precheck only."""
        return bool(self.publish_errors())

    def publish_errors(self) -> list[str]:
        """The take's own publish verdict: what leaks into the artifact, plus the splits a gate over it would miss.

        The one method the harness calls to decide publication. It reads two
        streams, because neither alone is both complete and precise (re-review
        C1, M-9):

        - the published (redacted) stream, scanned by the module `publish_errors`
          for a canary or a piece that SURVIVES into what ships. A whole
          contiguous canary in one field (S2a: the exfiltration url) was replaced
          in place with `<canary>`, so it leaves nothing here and is allowed --
          that is the M-9 false refusal this fixes. A whole canary in a field the
          take does not redact, or a partial the redactor missed, does survive
          and is refused here;
        - the raw events, scanned by `_split_errors` for a canary broken across
          more than one leaf, field or event. Redacting the pane blanks the head
          of a cross-surface split when it arrives, so the published stream can
          lose the prefix that would anchor a bare tail left in the clear (a tail
          sent before its head, or a head in a tool argument with its tail in
          later model output). The raw events still carry both pieces, so this
          pairs them and refuses within `GATE_FRAGMENT_WINDOW`. `_split_errors`
          runs only the multi-leaf rules, so it never re-refuses the S2a
          whole-in-place occurrence the published scan already cleared.

        Past that window the fragment join no longer reaches, so a literal head
        evicted by more than HELD_HEADS later heads adds its own refusal rather
        than passing silently. Fail closed: if the published stream cannot even
        be produced, the take is unpublishable.
        """
        try:
            published = self._published()
        except CanaryWindowError as e:
            # A raw stream the redactor refuses to produce a clean copy of cannot
            # be published. Refuse rather than skip the survival scan.
            return [f"canary: {e}"]
        survived = publish_errors(published, self._keys, self._sizes)
        split = _split_errors(self._raw, self._keys, self._sizes)
        errs = list(dict.fromkeys(survived + split))  # de-duplicate, keep order
        if self._evicted_literal_head:
            errs = errs + [
                "canary: this take held a string that spells the head of a canary and "
                f"then saw more than {HELD_HEADS} later heads push it out of memory, so a "
                "tail arriving after it can no longer be paired. Refusing rather than "
                "reporting a pass this take cannot stand behind"]
        return errs

    def _published(self) -> list[dict]:
        """The redacted stream this take ships, rebuilt from the raw events it kept.

        `redact_events` runs a fresh redactor over the same raw events and appends
        the held tail to the last `model_delta`, so it reproduces this take's own
        emitted bytes exactly (`test_the_take_redactor_is_the_live_form_of_redact_events`
        pins that equality). Rebuilding rather than storing keeps this class's live
        memory at what a run already spends and reuses the one assembly the harness
        uses, so the scanned stream cannot drift from the shipped one.
        """
        return redact_events(self._raw, self._keys, self._sizes,
                             window_chars=self._stream.window_chars)

    def event(self, ev: dict) -> dict:
        """ev as it may be printed or emitted. Events must arrive in stream order."""
        if not isinstance(ev, dict):
            raise CanaryWindowError("cxbom: an event is not an object")
        self._raw.append(ev)
        out = dict(ev)
        kind = ev.get("type")
        if kind == STREAM_TYPE:
            seq = ev.get("seq")
            if not isinstance(seq, int) or isinstance(seq, bool):
                raise CanaryWindowError(
                    f"cxbom: a {STREAM_TYPE} event has no integer seq, so stream order "
                    "cannot be confirmed")
            if self._seq is not None and seq <= self._seq:
                raise CanaryWindowError(
                    f"cxbom: {STREAM_TYPE} events are not in increasing seq order")
            self._seq = seq
            data = dict(ev.get("data") or {})
            text = data.get("text")
            if not isinstance(text, str):
                raise CanaryWindowError(f"cxbom: a {STREAM_TYPE} event has no text string to scan")
            data["text"] = self._stream.feed(text)
            out["data"] = data
        elif kind in VALUE_FIELDS:
            data = dict(ev.get("data") or {})
            for field in VALUE_FIELDS[kind]:
                if field in data:
                    data[field] = self._arguments(data[field])
            out["data"] = data
        return out

    def finish(self) -> str:
        """The model output the rolling window still holds. Idempotent."""
        return self._stream.finish()

    def _arguments(self, value):
        strings = list(_strings_in_order(value))
        blank = _shape_participants(strings) | _fragment_participants(strings, self._keys)[0]
        frags = _fragments(strings)
        held = self._heads + self._extensions
        hexed = [(at, owner, f) for at, (owner, f) in enumerate(frags) if _hex_run(f)]
        if held and len(hexed) > MAX_CALL_HEX_FRAGMENTS:
            # Too many to pair with what is held: fail closed on every string
            # that could carry a digit of a held canary.
            blank |= {owner for _, owner, _ in hexed}
            hexed = []
        # A later piece that finishes a held head into a key. Every held head,
        # literal or virtual, is completed: completion is keyed, so it never
        # fires on ordinary text, and a canary split inside its public prefix
        # leaves a virtual head that a later tail must still close.
        for head, _, _ in held:
            need = SHAPE_LEN - len(head)
            for at, owner, f in hexed:
                if _hex_run(f) >= need and _sha256_hex(head + f[:need]) in self._keys:
                    blank.add(owner)
            for at, owner, m in hexed:
                if not _pure_hex(m) or need - len(m) < 1:
                    continue
                side = [(j, frags[j][1]) for j in range(max(0, at - FRAGMENT_WINDOW),
                                                         min(len(frags), at + FRAGMENT_WINDOW + 1))
                        if j != at]
                for _, c_at in _completes(head + m, len(head) + len(m), (), side, self._keys):
                    blank.add(owner)
                    blank.add(frags[c_at][0])
        # Heads this call brings, held for the calls after it.
        heads = []
        for owner, f in frags:
            for head, k, literal in _fragment_heads(f):
                digits = k - len(SHAPE_PREFIX)
                if f.endswith(head) or digits >= PRINT_BUDGET_HEX:
                    blank.add(owner)
                heads.append((head, owner, digits, literal))
        # Continuations of what is held, longest first, within the candidate cap.
        # Only a literal-rooted head chains a continuation across calls. A
        # virtual head is a fragment of ordinary text (`-4` of `gpt-4`) as often
        # as it is a canary piece, and any pure-hex word (`add`, `be`) extended
        # it, so the shown count of benign chains climbed to the budget and
        # blanked about half of all real tool calls on the pane (re-review I1).
        # A literal head needs the `lab-demo-` characters ordinary text does not
        # spell, so restricting the chain to it brings the benign rewrite rate
        # to `redact_value`'s zero without reopening a keyed completion above.
        pure = sorted(((at, owner, f) for at, owner, f in hexed if _pure_hex(f)),
                      key=lambda x: -len(x[2]))[:EXTENSION_CANDIDATES]
        extensions = []
        for head, shown, literal in held:
            if not literal:
                continue
            for _, owner, f in pure:
                if len(head) + len(f) < SHAPE_LEN:
                    if shown + len(f) >= PRINT_BUDGET_HEX:
                        blank.add(owner)
                    extensions.append((head + f, shown, owner, len(f)))
        merged_heads = self._heads + [(h, 0 if o in blank else d, lit) for h, o, d, lit in heads]
        # A literal head shoved past the HELD_HEADS window can no longer pair
        # with a tail that arrives later, and the gate's fragment window cannot
        # reach that far either, so record the loss and fail closed at the gate.
        if any(lit for _, _, lit in merged_heads[:-HELD_HEADS]):
            self._evicted_literal_head = True
        self._heads = merged_heads[-HELD_HEADS:]
        extensions.sort(key=lambda x: x[3])  # the longest continuations survive the cut
        self._extensions = (self._extensions + [
            (h, s + (0 if o in blank else n), True) for h, s, o, n in extensions])[-HELD_EXTENSIONS:]
        return _redact_value(value, self._keys, self._sizes, blank, itertools.count())


# J2 spec 6 fixes the canary's shape: `lab-demo-` and 32 lowercase hexadecimal
# characters. The shape is public and the value is not, so a shape rule needs no
# key material at all, and spec 6 already asks for one in the same breath as the
# value -- no canary value, and nothing shaped like one, is ever committed.
# Nothing in the repository implemented that half: `scripts/anon_check.py` is a
# token denylist and has no shape rule.
#
# The prefix is chosen so that no two occurrences of canaries of this shape can
# overlap, by construction rather than by a check. Its first character, `l`, is
# outside the hexadecimal alphabet and appears nowhere else in the prefix, so in
# any value of the shape it occurs at index 0 and nowhere else. Take two
# occurrences in one text, of the same canary or of two, at i and j with
# i < j < i + SHAPE_LEN. Every value of the shape has the same length, so j is
# strictly inside the occurrence at i and the text at j is that occurrence's
# character j - i, with 1 <= j - i < SHAPE_LEN. The occurrence at j starts
# there, so that character is `l`, which the occurrence at i carries only at
# index 0. So no two overlap. A proper border, a proper prefix that is also a
# proper suffix, is the one-canary case of the same thing, so no value of the
# shape has one at any length, and a run of occurrences is a run of disjoint
# spans that `_merge` leaves apart and `_drain` releases one at a time.
#
# A prefix opening on a hexadecimal digit would let a tail end on that digit,
# which is a border of length 1 and a chain the window guard refuses. That would
# need a draw loop in `make_canary` and a refusal in `key_material`, and neither
# exists because no value of this shape reaches one. `tests/test_canary.py` pins
# the two facts this proof uses and checks every shift against the shape.
SHAPE_PREFIX = "lab-demo-"
SHAPE_HEX = "0123456789abcdef"
SHAPE_HEX_CHARS = 32
SHAPE_LEN = len(SHAPE_PREFIX) + SHAPE_HEX_CHARS

# How many hexadecimal digits must sit right after a literal `lab-demo-` before
# the key-free gate refuses the stream as a canary head. `_shape_whole` catches
# only a full 41-character shape, so a model that emitted the prefix and 11 to 31
# digits of the canary -- a near-total leak, and the piece a real cross-call
# split always carries -- reached the gate unflagged (measured: 40 of 40 missed
# for 11..29 digits). The prefix is the whole signal: `lab-demo-` is a literal a
# benign take never emits, and a run of hexadecimal digits after it is either the
# canary or a decoy shaped like its head, both of which spec 6 bans. Eight is set
# below the measured 11 so a split cut a few digits past the prefix is caught
# too, and above the longest hex run that follows the prefix in the benign corpus
# (a stray `lab-demo-de` spells two), which keeps the false-positive rate at the
# 0.000% this check measured. A bare hexadecimal run without the literal prefix
# -- a model revision, a git sha, a UUID -- carries no prefix and never trips
# this, so a revision's 40 hex digits neither trigger the gate nor are needed by
# it (M-8 gap 2).
PARTIAL_HEAD_MIN_HEX = 8


def _spells(text: str, first: int, last: int, at: int) -> bool:
    """True when text[first:last] spells the canary's shape from position `at` on.

    Indices rather than slices, because this runs once per shape position per
    string in a take and a slice would copy the characters to read them.
    """
    if at < 0 or at + (last - first) > SHAPE_LEN or first < 0 or last > len(text):
        return False
    position = at
    for i in range(first, last):
        c = text[i]
        if position < len(SHAPE_PREFIX):
            if c != SHAPE_PREFIX[position]:
                return False
        elif c not in SHAPE_HEX:
            return False
        position += 1
    return True


def make_canary() -> str:
    """A fresh canary for one take, in the shape spec 6 fixes.

    Spec 6 assigns the generator to this side. It lives here, in the module that
    owns the shape, the matcher and the redactor, so the value's construction
    cannot drift from the rule the redactor depends on -- the discipline
    `lab/j1/canaries.py` follows when it imports its format from `j1.detect`
    rather than restating it. A demo harness calls this rather than spelling the
    shape again. One draw is always enough: the prefix makes every value of the
    shape unable to overlap itself or another (see `SHAPE_PREFIX`).

    Never logged, never interpolated into a message, never written to a tracked
    file.
    """
    return SHAPE_PREFIX + secrets.token_hex(SHAPE_HEX_CHARS // 2)


def key_material(canary: str) -> tuple[frozenset, tuple]:
    """The `(hashes, lengths)` pair every entry point here takes, from a canary value.

    The one door a canary *value* passes through on this side, and so the place
    a value that is not the shape is refused. Only the shape is checked, because
    the shape is the whole guarantee: a value of it cannot overlap itself or
    another. `--redact-sha256`, the redactor and the publish check are keyed on a
    SHA-256 and never see the value, so a caller that skips this door keeps the
    window guard as its only protection.

    No refusal names the value or any part of it.
    """
    if not isinstance(canary, str):
        raise CanaryWindowError(f"cxbom: a canary is a str, not {type(canary).__name__}")
    if len(canary) != SHAPE_LEN or not _spells(canary, 0, SHAPE_LEN, 0):
        raise CanaryWindowError(
            f"cxbom: a canary is {SHAPE_LEN} characters -- the prefix spec 6 publishes "
            f"and {SHAPE_HEX_CHARS} lowercase hexadecimal digits. Refused rather than "
            "keyed on a value the shape rule cannot recognise")
    return frozenset({_sha256_hex(canary)}), (SHAPE_LEN,)


def _shape_whole(text: str) -> bool:
    """True when the shape sits at any offset inside text, with no key material."""
    for at in range(0, len(text) - SHAPE_LEN + 1):
        if _spells(text, at, at + SHAPE_LEN, 0):
            return True
    return False


def _partial_head(text: str) -> bool:
    """True when a literal `lab-demo-` in text is followed by PARTIAL_HEAD_MIN_HEX+ hex digits.

    The head of a canary, short of the whole shape `_shape_whole` needs. The
    prefix carries the signal on its own: it is a literal a benign take does not
    emit, so the run after it is the canary's own digits or a decoy shaped like
    them. Case-exact on the prefix, like the rest of the shape rule, because the
    canonical value is lowercase (spec 6); a whole canary whose case was changed
    is caught by the keyed scans, which fold.
    """
    at = text.find(SHAPE_PREFIX)
    while at >= 0:
        run = _hex_run(text[at + len(SHAPE_PREFIX):])
        if run >= PARTIAL_HEAD_MIN_HEX:
            return True
        at = text.find(SHAPE_PREFIX, at + 1)
    return False


def _shape_assembly(strings: list[str]) -> tuple[int, ...] | None:
    """The strings whose concatenation, in some order, spells the shape.

    This is the check that replaces a third join rather than adding one. A canary
    reassembled from pieces of a stream is contiguous in whatever order a viewer
    reads them, so it takes a suffix of one string, then whole strings, then a
    prefix of one string. Walking the shape's positions covers that without
    order entering anywhere: an opener is a suffix spelling the shape's first k
    characters, a middle is a whole string spelling an interior slice, and a
    closer is a prefix spelling the rest. Reverse order, a third value between the
    halves, a half in a value and the other half in the following key, and a
    mis-declared length stop being four cases.

    Every piece must be a distinct string, because the stream carries each string
    once. That is why one middle is allowed and not a chain of them: without
    tracking which strings a path has already spent, a single one-character value
    could be re-used to bridge any gap and the gate would refuse takes whose
    stream cannot spell the shape at all. Measured while building this: a
    one-character hexadecimal key reused twenty-two times reported a clean stream.
    Four or more pieces out of document order is the stated residual; in document
    order any number of pieces is already caught by the joins.

    Returns the piece indices in shape order, or None. The search is `_Pieces`,
    which is linear in the number of strings.
    """
    return _Pieces(strings).assembly()


def _shape_participants(strings: list[str]) -> set[int]:
    """Every string that is a piece of at least one assembly `_shape_assembly` accepts."""
    return _Pieces(strings).participants()


class _Pairs:
    """Pairs of distinct string indices, kept so "one pair avoiding x" is exact in O(1).

    Keeps the first pair, the first later pair that avoids its first index, and
    the first later pair that avoids its second. For any x: if x is in neither
    slot of the first pair, the first pair avoids it. If x is the first pair's
    first index, a pair avoiding x exists exactly when the second slot is set,
    and likewise for the second index. So three pairs answer the query for every
    x, however many pairs were offered.
    """

    __slots__ = ("first", "no_first", "no_second")

    def __init__(self):
        self.first = self.no_first = self.no_second = None

    def add(self, pair: tuple[int, int]) -> None:
        if self.first is None:
            self.first = pair
            return
        a, b = self.first
        if self.no_first is None and a not in pair:
            self.no_first = pair
        if self.no_second is None and b not in pair:
            self.no_second = pair

    def avoiding(self, x: int) -> tuple[int, int] | None:
        if self.first is None or x not in self.first:
            return self.first
        return self.no_first if x == self.first[0] else self.no_second


def _keep(kept: list[int], i: int) -> None:
    """Keep up to three distinct indices: enough to pick one outside any two."""
    if len(kept) < 3 and i not in kept:
        kept.append(i)


def _pick(kept: list[int], *excluded: int) -> int | None:
    return next((i for i in kept if i not in excluded), None)


class _Pieces:
    """Openers, middles and closers of the shape among some strings, and who they pair with.

    The bound, stated because a model chooses how many strings a tool call
    carries. An earlier version kept every (opener, middle) pair it reached, so
    n openers and n middles made n * n pairs and each middle walked them all.
    Measured on `l`, `a` and `b` repeated: 300, 600 and 1,200 strings took 0.01,
    0.06 and 0.55 s, about nine times per doubling. This version takes 0.17 s
    for 30,000 and 0.72 s for 120,000. Here each shape position keeps at most three openers, three
    closers, and two `_Pairs` of three pairs, which is enough to answer every
    distinctness question exactly (see `_Pairs` and `_keep`). Each string is then
    examined at a bounded number of positions:

    - as an opener at one position at most, because the shape's first character
      appears in it once, so a suffix spelling a head of the shape starts at the
      string's last `l`;
    - as a closer or a middle at the eight prefix positions, checked character
      by character, and at a range of hex positions read off the string's
      leading hex run rather than checked one by one.

    So the work is O(n * SHAPE_LEN) steps over n strings plus one pass over each
    string's first SHAPE_LEN characters and last SHAPE_LEN characters. The
    memory beyond the input is O(n): one opener position per string, plus the
    fixed per-position sets. Each pass regenerates the moves.
    """

    def __init__(self, strings: list[str]):
        # Nothing per string is stored but its opener position. The closer
        # positions and the middle moves are regenerated from the string on each
        # pass instead: storing the moves cost up to 31 tuples, about 2.4 KB, per
        # short hex string, and 16 MB of them peaked at 9.8 GB (review N-M1).
        self.strings = strings
        self.openers: list[list[int]] = [[] for _ in range(SHAPE_LEN)]
        self.closers: list[list[int]] = [[] for _ in range(SHAPE_LEN)]
        self.opener_at: dict[int, int] = {}
        for i, s in enumerate(strings):
            k = _opener_position(s)
            if k:
                self.opener_at[i] = k
                _keep(self.openers[k], i)
            for k in _closer_positions(s):
                _keep(self.closers[k], i)
        # (opener, middle) pairs by the position they reach, and (middle, closer)
        # pairs by the position they leave. Two pairs per move are enough: of three
        # kept openers, at most one is the middle itself, and the two left cannot
        # both be the closer a later query excludes.
        self.forward = [_Pairs() for _ in range(SHAPE_LEN)]
        self.backward = [_Pairs() for _ in range(SHAPE_LEN)]
        for j, k, nxt in self._moves():
            for o in [o for o in self.openers[k] if o != j][:2]:
                self.forward[nxt].add((o, j))
            for m in [m for m in self.closers[nxt] if m != j][:2]:
                self.backward[k].add((j, m))

    def _moves(self):
        """(middle, from position, to position) for every string that can be a middle."""
        for j, s in enumerate(self.strings):
            for k in _middle_positions(s):
                yield j, k, k + len(s)

    def assembly(self) -> tuple[int, ...] | None:
        for k in range(1, SHAPE_LEN):
            for o in self.openers[k]:
                m = _pick(self.closers[k], o)
                if m is not None:
                    return (o, m)
        for k in range(1, SHAPE_LEN):
            # Three kept closers are enough: the first pair holds two indices, so
            # it avoids at least one of three distinct closers.
            for m in self.closers[k]:
                pair = self.forward[k].avoiding(m)
                if pair is not None:
                    return (pair[0], pair[1], m)
        return None

    def participants(self) -> set[int]:
        found: set[int] = set()
        for i, k in self.opener_at.items():
            if _pick(self.closers[k], i) is not None or self.backward[k].avoiding(i) is not None:
                found.add(i)
        for i, s in enumerate(self.strings):
            if any(_pick(self.openers[k], i) is not None or self.forward[k].avoiding(i) is not None
                   for k in _closer_positions(s)):
                found.add(i)
        for j, k, nxt in self._moves():
            if j not in found and any(_pick(self.closers[nxt], j, o) is not None
                                      for o in self.openers[k] if o != j):
                found.add(j)
        return found


def _closer_positions(s: str):
    """Every k, 0 < k < SHAPE_LEN, where a prefix of s spells the shape from position k on.

    The eight prefix positions are checked character by character. Past them
    the rest is hexadecimal, so the positions are a range read off s's leading
    hex run.
    """
    head = len(SHAPE_PREFIX)
    for k in range(1, head):
        if _spells(s, 0, SHAPE_LEN - k, k):
            yield k
    yield from range(max(head, SHAPE_LEN - _hex_run(s)), SHAPE_LEN)


def _middle_positions(s: str):
    """Every k where s, whole and non-empty, spells the shape from k and stops short of its end."""
    n = len(s)
    if not 0 < n < SHAPE_LEN:
        return
    head = len(SHAPE_PREFIX)
    for k in range(1, head):
        if k + n < SHAPE_LEN and _spells(s, 0, n, k):
            yield k
    if _hex_run(s) == n:
        yield from range(head, SHAPE_LEN - n)


def _opener_position(s: str) -> int:
    """k when a suffix of s spells the shape's first k characters, 0 < k < SHAPE_LEN, else 0.

    At most one k can, because such a suffix starts with the shape's first
    character and holds it nowhere else, so it starts at the last one in s.
    """
    at = s.rfind(SHAPE_PREFIX[0], max(0, len(s) - SHAPE_LEN + 1))
    if at < 0 or not _spells(s, at, len(s), 0):
        return 0
    return len(s) - at


def _hex_run(s: str) -> int:
    """How many of s's leading characters are hexadecimal, up to SHAPE_HEX_CHARS."""
    n = 0
    while n < min(len(s), SHAPE_HEX_CHARS) and s[n] in SHAPE_HEX:
        n += 1
    return n


def _count_hex(s: str) -> int:
    """How many of s's characters are hexadecimal, at any position."""
    return sum(1 for c in s if c in SHAPE_HEX)


def _hex_windows(f: str, size: int):
    """Every length-`size` all-hexadecimal substring of f, at every offset.

    A tail's digits sit inside one maximal hexadecimal run of the fragment, and
    the shape's own alphabet glued to the inner side of the piece -- hex before
    the digits, or an `l`/`m`/`o`/`-` that breaks the run -- puts them at an
    offset a prefix-only read (`c[:need]`) walks past. Sliding a window of the
    needed width across each maximal run reads them out wherever they sit. Keyed
    by the caller, so a window is a candidate, never a match on its own.
    """
    if size <= 0:
        return
    n, i = len(f), 0
    while i < n:
        if f[i] not in SHAPE_HEX:
            i += 1
            continue
        j = i
        while j < n and f[j] in SHAPE_HEX:
            j += 1
        for start in range(i, j - size + 1):
            yield f[start:start + size]
        i = j


# --- pieces with other text between them (review O2) -------------------------
#
# The shape rule reads whole strings, so it needs a piece to start or end its
# string. The keyed join needs the pieces to touch. A model told to send the
# canary in chunks does neither: `?a=<first half>` in one URL and `?b=<second
# half>` in another. Measured at 271b8c7 on 128 such streams, redact_value left
# up to 40 characters in clear and the publish gate passed 122 of them.
#
# So the pieces are read where they sit inside text. A fragment is a maximal run
# of the characters the shape is written in, so the text between two pieces
# ends one fragment and starts the next. Candidates are then hashed, so this is
# keyed and matches the canary only:
#
# - one fragment that starts partway through the prefix and runs on through all
#   32 hex digits. The prefix is public, so its missing head costs nothing to
#   supply. A split inside the prefix, or a dropped prefix, is this case.
# - a LITERAL head (a fragment ending in the literal `lab-demo-` and some hex
#   digits) followed by one or two more fragments within FRAGMENT_WINDOW fragments
#   of it, on either side. A VIRTUAL head -- a fragment that spells only the
#   prefix's public tail (`demo-`, `-` and hex) and carries no literal `lab-demo-`
#   -- does NOT seed this search, though `_fragment_heads` still yields it for the
#   contiguous-remainder case above. It is ordinary text as often as a canary
#   piece, and seeding the completion from one let `_completes` rebuild the keyed
#   canary out of unrelated hex in the window -- the stream's own whole-in-place
#   canary (an exfil url redacted in place, M-9) included -- so a hex-dense take
#   refused a fresh session canary about one run in eight. The pane redactor
#   `_arguments` already chains continuations only from a literal head for the
#   same reason (re-review I1); the gate now matches it.
#
# The bound. Hashing starts only once a literal head is found, and a literal head
# needs the `lab-demo-` characters, which ordinary text does not spell. Each head
# costs at most 2W + (2W)^2 hashes for a window of W fragments per side. Above
# MAX_HEADS heads in one value, the search stops and fails closed: every string
# holding a head, or a fragment beside one, is reported.
#
# What stays open: shape characters glued to the inner side of a piece (hex
# glue after a head or before a tail is indistinguishable from the canary's own
# digits), a split with the prefix dropped or cut inside itself and the hex also
# cut in two (no literal head left to seed the completion -- `_shape_assembly`
# reaches the clean-piece form of this, the runtime runner the rest), pieces
# further apart than the window, and four or more pieces.

_FRAGMENT = re.compile(r"[0-9a-flmo\-]+")  # every character the shape is written in
# How far apart, in fragments, the cross-piece search looks for the pieces of a
# canary split with text between them. The two windows differ on purpose (M-7).
#
# FRAGMENT_WINDOW governs `redact_value` and the live take redactor: the pane a
# viewer watches during a take. GATE_FRAGMENT_WINDOW governs `publish_errors`:
# the one-time, offline decision on the artifact that ships. The gate is the
# irreversible boundary, so it takes the wide window and, above it, the keyless
# `_prefix_reach` rule, which needs no completion search at all. The pane is
# transient: a canary whose pieces sit more than FRAGMENT_WINDOW fragments apart
# inside a single value is still refused at the gate (the wide window, plus reach
# for a prefix-intact split), so it never reaches the artifact; widening the pane
# to match would only shorten the window in which it shows on screen. Measured,
# the alignment is not free: with the offset search `_completes` now runs, a
# single value carrying hundreds of hexadecimal fragments costs about thirty
# times as much to redact at 256 as at 16, per value, live, for no change in what
# the gate publishes. So the boundary that matters is wide and the live pane is
# not.
FRAGMENT_WINDOW = 16
GATE_FRAGMENT_WINDOW = 256
MAX_HEADS = 512
# The head of a match is always replaced. A middle or tail shorter than this is
# not: it shows at most two of the 32 digits, and a one- or two-digit fragment
# of ordinary text (the `e` of `text`) matches such a piece whenever the digits
# agree, which is one time in 16 or 256, so replacing it would blank ordinary
# text for no secrecy.
MIN_PIECE = 3


def _fragments(strings: list[str]) -> list[tuple[int, str]]:
    """(owning string index, fragment) for every fragment of every string, in order."""
    return [(i, m.group()) for i, s in enumerate(strings) for m in _FRAGMENT.finditer(s)]


def _pure_hex(f: str) -> bool:
    return len(f) <= SHAPE_HEX_CHARS and _hex_run(f) == len(f)


def _fragment_heads(f: str):
    """(head, k, literal) for each head this fragment is: a string spelling the shape's first k characters.

    Real (literal True): the fragment ends with the prefix and 0 or more hex
    digits, 9 <= k < SHAPE_LEN, so the fragment itself carries `lab-demo-`.
    Virtual (literal False): the fragment, whole, spells the shape from inside
    the prefix and past it, so the public head of the prefix is supplied, 10 <=
    k < SHAPE_LEN, and the fragment carries none of the literal prefix.

    The flag is what lets the take hold every head but chain continuations only
    from a literal one. A virtual head is a fragment of ordinary text (the `-4`
    of `gpt-4`) as often as it is a canary piece, so extending it across calls
    blanked about half of all benign tool calls on the pane (re-review I1). A
    literal head needs the `lab-demo-` characters, which ordinary text does not
    spell, so it is the piece a real cross-call split carries.
    """
    head = len(SHAPE_PREFIX)
    at = f.rfind(SHAPE_PREFIX[0], max(0, len(f) - SHAPE_LEN + 1))
    if at >= 0 and len(f) - at >= head and _spells(f, at, len(f), 0):
        yield f[at:], len(f) - at, True
    for k0 in range(1, head):
        k = k0 + len(f)
        if head < k < SHAPE_LEN and _spells(f, 0, len(f), k0):
            yield SHAPE_PREFIX[:k0] + f, k, False


def _completes(head: str, k: int, middles, closers, keys: frozenset):
    """The (middle, closer) pairs, middle possibly None, that finish `head` into a key.

    `middles` and `closers` are (position, fragment) pairs. A closer contributes
    SHAPE_LEN - k hexadecimal characters taken from any offset inside one of its
    maximal hexadecimal runs, so the shape's own alphabet glued to the inner side
    of the tail -- hex before the digits, or an `l`/`m`/`o`/`-` that breaks the
    run -- no longer hides it. The middle contributes its whole value, so its
    length is what the caller subtracts for the closer, and a middle with glue on
    its inner side is a residual the multi-piece gate reaches instead.
    """
    need = SHAPE_LEN - k
    for c_at, c in closers:
        for tail in _hex_windows(c, need):
            if _sha256_hex(head + tail) in keys:
                yield None, c_at
                break
    for m_at, m in middles:
        rest = need - len(m)
        if rest < 1 or not _pure_hex(m):
            continue
        for c_at, c in closers:
            if c_at == m_at:
                continue
            for tail in _hex_windows(c, rest):
                if _sha256_hex(head + m + tail) in keys:
                    yield m_at, c_at
                    break


def _stream_strings(events: list[dict], order: list[int]) -> list[str]:
    """Every string in the stream in order, each run of consecutive model output joined into one."""
    stream = set(order)
    out: list[str] = []
    run: list[str] = []
    for i, ev in enumerate(events):
        if i in stream:
            text = (ev.get("data") or {}).get("text")
            if isinstance(text, str):
                run.append(text)
            continue
        if run:
            out.append("".join(run))
            run = []
        out.extend(value for _, value in _strings(ev))
    if run:
        out.append("".join(run))
    return out


def _fragment_participants(strings: list[str], keys: frozenset,
                           window: int = FRAGMENT_WINDOW) -> tuple[set[int], bool]:
    """Indices of strings holding a piece of a keyed canary split with text between its pieces.

    Returns (indices, overflowed). On overflow the indices are every string that
    holds a head or a fragment in a head's window, which fails closed.
    """
    frags = _fragments(strings)
    found: set[int] = set()
    for owner, f in frags:
        for k0 in range(1, len(SHAPE_PREFIX) + 1):
            need = SHAPE_LEN - k0
            if len(f) >= need and _spells(f, 0, need, k0) and \
                    _sha256_hex(SHAPE_PREFIX[:k0] + f[:need]) in keys:
                found.add(owner)
    # Only a LITERAL head (a fragment that carries `lab-demo-` itself) seeds a
    # completion search. A virtual head supplies the public prefix for a fragment
    # that is nothing but hex (`-4`, `demo-ab`), which ordinary text spells as
    # often as a canary piece; seeding from one lets `_completes` reassemble the
    # keyed tail from unrelated hex in the window -- including the stream's own
    # whole-in-place canary, which `_split_errors` scans in the raw events and
    # which M-9 has already cleared on the published side. A hex-dense take then
    # refuses a fresh session canary about one run in eight (re-review of the J2
    # e2e gate; measured 7% here, higher on a denser stream). The pane redactor
    # already chains continuations only from a literal head for the same reason
    # (`_arguments`, re-review I1); the gate must match it. What a literal head
    # cannot reach -- a prefix split across fragments, a prefix dropped with the
    # tail cut up -- stays covered by `_shape_assembly` and the contiguous
    # prefix-split loop above, or is a stated-open residual, not this path.
    every = ((at, head, k) for at, (_, f) in enumerate(frags)
             for head, k, lit in _fragment_heads(f) if lit)
    heads = list(itertools.islice(every, MAX_HEADS + 1))
    if len(heads) > MAX_HEADS:
        # A second pass rather than a list of every head, so the memory stays
        # O(n) on a value built of nothing but heads.
        near = {frags[j][0]
                for at, (_, f) in enumerate(frags) if any(lit for _, _, lit in _fragment_heads(f))
                for j in range(max(0, at - window), min(len(frags), at + window + 1))}
        return found | near, True
    for at, head, k in heads:
        side = [(j, frags[j][1]) for j in range(max(0, at - window), min(len(frags), at + window + 1))
                if j != at]
        for m_at, c_at in _completes(head, k, side, side, keys):
            found.add(frags[at][0])
            if m_at is not None and len(frags[m_at][1]) >= MIN_PIECE:
                found.add(frags[m_at][0])
            used = SHAPE_LEN - k - (len(frags[m_at][1]) if m_at is not None else 0)
            if used >= MIN_PIECE:
                found.add(frags[c_at][0])
    return found, False


def _hex_before_prefix(s: str) -> tuple[int, bool]:
    """(hexadecimal characters in s before its first literal prefix, whether one was found).

    A canary's tail is 32 hexadecimal digits and holds no `lab-demo-`, so the
    count of a prefix's reachable tail stops at the next literal prefix: the
    digits of one canary do not run through the head of another, and the letters
    of a second `lab-demo-` are not tail digits.
    """
    cut = s.find(SHAPE_PREFIX)
    return (_count_hex(s if cut < 0 else s[:cut]), cut >= 0)


def _prefix_reach(strings: list[str], window: int = GATE_FRAGMENT_WINDOW) -> set[int]:
    """String indices holding a literal prefix that a canary's worth of hex follows within `window`.

    The key-free catch for a canary split with the prefix left intact in one
    piece, however the 32 digits after it are broken up. The literal `lab-demo-`
    is a token a benign take never emits, so once it is on the way out the
    question is only whether enough of the canary's body is reachable to finish
    it -- and the count answers that without caring how the digits are split,
    glued, reordered within a run, or merged into one run with hexadecimal filler
    between the pieces. It reaches what the hash-keyed completion cannot: a tail
    cut into four or more pieces, and pieces with the shape's own alphabet glued
    to their inner sides, both stated residuals of the keyed path.

    `strings` are the data-value and data-key strings only, in document order:
    the C2 envelope the collector writes (`type`, `run`, ...) is left out because
    it is not the model's to spell a canary with, and counting its stray hex
    would refuse takes that never carried a tail. The count runs from just after
    the prefix, across the next strings up to `window`, and stops at the next
    literal prefix (`_hex_before_prefix`), because a tail carries no `lab-demo-`.
    Refusing at SHAPE_HEX_CHARS fails closed: within that region the count can
    only over-count hexadecimal filler, never under-count a real tail present in
    the window. A bare hexadecimal run with no literal prefix -- a model
    revision, a git sha -- is never counted, so the revision neither triggers
    this nor is needed by it (M-8 gap 2). The residual is a tail whose pieces
    reach past `window` strings, and a prefix that is itself split so no string
    carries it whole.
    """
    hits: set[int] = set()
    for i, s in enumerate(strings):
        start = s.find(SHAPE_PREFIX)
        while start >= 0:
            count, stopped = _hex_before_prefix(s[start + len(SHAPE_PREFIX):])
            j = i + 1
            while not stopped and count < SHAPE_HEX_CHARS and j < len(strings) and j - i < window:
                add, stopped = _hex_before_prefix(strings[j])
                count += add
                j += 1
            if count >= SHAPE_HEX_CHARS:
                hits.add(i)
                break
            start = s.find(SHAPE_PREFIX, start + 1)
    return hits


def shape_errors(events) -> list[str]:
    """Anything shaped like a canary, found with no key material at all.

    The companion to the hash-keyed check rather than a substitute for it: a hash
    says which value is the secret, a shape says a secret-shaped string is on the
    way out. The shape rule reaches four cases the hash rule cannot, because it
    needs neither the canary's length nor the order its pieces appear in.

    Three key-free rules run here. `_shape_whole` finds a full 41-character shape
    at any offset. `_partial_head` finds a literal prefix and PARTIAL_HEAD_MIN_HEX
    or more digits, the head of a canary the whole-shape rule is too long to see.
    `_prefix_reach` finds a literal prefix that a canary's worth of hexadecimal
    digits follows within the window, however the tail is split or glued. All
    three key on the literal prefix, a token a benign take never emits, so a bare
    hexadecimal run without it -- a model revision, a git sha -- trips none.

    What stays open, and it is a transformation rather than an order: a canary a
    model rewrites before emitting -- base64, a fully percent-encoded value,
    characters inserted inside it -- is not shaped like one any more, and no layer
    here decodes. A decoder invites an arms race over encodings, so the residual
    is recorded rather than chased.
    """
    events = list(events)
    strings: list[tuple[int, str, str]] = [
        (i, path, s) for i, ev in enumerate(events) for path, s in _strings(ev)]
    errs: list[str] = []
    # Reach runs over the data strings alone (values and keys, not the C2
    # envelope) so unrelated envelope hex cannot inflate a tail count.
    data_strings = [(i, s) for i, ev in enumerate(events)
                    for _, s in _strings(ev.get("data"))]
    reached_events = {data_strings[idx][0] for idx in _prefix_reach([s for _, s in data_strings])}
    flagged: set[int] = set()
    for i, path, s in strings:
        if _shape_whole(s):
            errs.append(
                f"event[{i}]: field {path} carries a string shaped like a canary. J2 spec "
                "6 bans a canary value and anything shaped like one, so this stream must "
                "not be published")
            flagged.add(i)
        elif _partial_head(s):
            errs.append(
                f"event[{i}]: field {path} carries a literal canary prefix followed by "
                f"at least {PARTIAL_HEAD_MIN_HEX} hexadecimal digits -- the head of a "
                "canary. J2 spec 6 bans a canary and anything shaped like one, so this "
                "stream must not be published")
            flagged.add(i)
    for i in sorted(reached_events - flagged):
        errs.append(_reach_error(i))
    found = _shape_assembly([s for _, _, s in strings])
    if found is not None:
        touched = sorted({strings[at][0] for at in found})
        errs.append(_assembly_error(len(found), touched))
    return errs


# The refusal wording each split/partial rule uses, defined once so the whole-
# stream gate (`publish_errors`, `shape_errors`) and the multi-leaf subset
# (`_split_errors`) that `TakeRedactor` runs over its raw events spell one rule
# one way. A message carries only fixed text, integers, and event indices --
# never a caller-supplied string -- for the reason `_strings` documents.
def _reach_error(i: int) -> str:
    return (f"event[{i}]: a literal canary prefix here is followed by a full canary's "
            "worth of hexadecimal digits within the window, however the tail is split, "
            "glued or reordered across pieces. This stream must not be published")


def _assembly_error(count: int, touched: list[int]) -> str:
    return (f"canary: {count} strings in event(s) {touched} spell the canary's "
            "published shape when they are read one after another, in some order. No "
            "single field carries it, so a reader who concatenates what is on screen "
            "recovers it whatever order the stream put the pieces in. This stream must "
            "not be published")


def _crossed_field_error() -> str:
    return ("canary: the stream's data values joined in document order carry a "
            "canary that no single field and no reassembled model output carries. "
            "Something split it across a field boundary, so this stream must not "
            "be published")


def _too_many_heads_error() -> str:
    return (f"canary: the stream holds more than {MAX_HEADS} strings shaped like the "
            "head of a canary, too many to check each against the key, so this "
            "stream must not be published")


def _pieces_error(count: int) -> str:
    return (f"canary: {count} strings in this stream hold pieces that spell a "
            "canary once the text between them is removed, so this stream must not "
            "be published")


def _split_errors(events, hashes, lengths) -> list[str]:
    """Refusals for a canary split across more than one string leaf, field or event.

    The multi-leaf subset of the publish gate: exactly the rules that fire only
    when the canary is broken up, and none of the rules that fire on a single
    contiguous canary sitting whole in one string. `TakeRedactor.publish_errors`
    runs this over the raw events it kept and adds it to a survival scan over the
    published (redacted) stream. The division is the M-9 distinction:

    - a whole contiguous canary in one field (S2a: the exfiltration url) is
      replaced in place, so the published stream carries `<canary>` and nothing
      leaks. The whole-in-one-leaf rules (`_shape_whole`, a field's own `_hit`,
      the contiguous reassembled-model scan) would refuse it over the raw events
      even though it was handled, so they are left to the survival scan, which
      sees the redacted `<canary>` and passes it;
    - a split can leave a bare tail in the clear whose head the redactor blanked
      (re-review C1: a tail sent before its head, or a head in a tool argument
      with its tail in later model output). The survival scan over the published
      stream cannot pair that tail, because the prefix that anchors it is gone.
      The raw events still carry both pieces, so these rules pair them and refuse.

    Fail closed: a whole canary in a field the take does not redact is not a
    split, so this misses it -- the survival scan catches it because it survives
    the redaction. Anything this cannot prove is a bare whole-in-place occurrence
    is judged by one rule or the other.

    None of these rules fires on a single contiguous canary in one string:
    `_prefix_reach` is suppressed on any event whose string carries the whole
    shape (that is whole-in-one-leaf), a whole canary is one fragment with no
    head so `_fragment_participants` finds nothing, it is not an assembly piece
    so `_shape_assembly` returns None, and it sits inside one leaf so
    `_crosses_leaves` does not count it.
    """
    events = list(events)
    try:
        keys, sizes = _normalized(hashes, lengths)
    except CanaryWindowError as e:
        return [f"canary: {e}"]
    if not keys:
        return [f"canary: {NO_KEY_MATERIAL}"]
    try:
        order = _stream_order(events)
    except CanaryWindowError as e:
        return [f"canary: {e}"]

    errs: list[str] = []
    strings = [(i, path, s) for i, ev in enumerate(events) for path, s in _strings(ev)]
    # An event whose string carries the whole shape is whole-in-one-leaf, not a
    # split, so the key-free reach rule is suppressed there exactly as
    # `shape_errors` suppresses it on a `_shape_whole` flag.
    whole_leaf_events = {i for i, _, s in strings if _shape_whole(s)}
    data_strings = [(i, s) for i, ev in enumerate(events)
                    for _, s in _strings(ev.get("data"))]
    reached_events = {data_strings[idx][0] for idx in _prefix_reach([s for _, s in data_strings])}
    for i in sorted(reached_events - whole_leaf_events):
        errs.append(_reach_error(i))
    found = _shape_assembly([s for _, _, s in strings])
    if found is not None:
        touched = sorted({strings[at][0] for at in found})
        errs.append(_assembly_error(len(found), touched))
    try:
        # A canary the data-value join carries that no single leaf holds whole:
        # a split across a field or an event boundary. `_crosses_leaves` requires
        # the match to span two leaves, so two whole canaries each in their own
        # field (S2a's tool_call and exfil_attempt) do not trip it, unlike the
        # errs-guarded whole-value join in `publish_errors`.
        if _crosses_leaves([leaf for ev in events for leaf in _leaves(ev.get("data"))],
                           keys, sizes):
            errs.append(_crossed_field_error())
        pieces, overflowed = _fragment_participants(_stream_strings(events, order), keys,
                                                    GATE_FRAGMENT_WINDOW)
        if overflowed:
            errs.append(_too_many_heads_error())
        elif pieces:
            errs.append(_pieces_error(len(pieces)))
    except CanaryWindowError as e:
        errs.append(f"canary: {e}")
    return errs


def publish_errors(events, hashes, lengths) -> list[str]:
    """The hash-keyed publish check: no take publishes a canary, split or whole.

    Reassembles `model_delta.data.text` in stream order and scans the join, so
    a canary the fragment boundaries hid from a per-record scan is found here.
    Then scans every other string in the stream, keys included.

    Runs `shape_errors` as well, on every path including the ones that refuse for
    want of key material, because the shape needs none and a take started without
    a canary hash is exactly when the shape rule is the only rule left.

    Returns human-readable errors in the style of `contracts.checks`; an empty
    list is a pass. Missing key material is an error and not a pass: a check
    that looked for nothing and reported clean is the failure mode the whole
    module is about.

    No message interpolates a string the caller supplied. Messages are built from
    fixed text, integers, and path segments drawn from a literal set of C2 field
    names, because a model names its own tool-argument keys: an earlier version
    interpolated a key-derived path and so printed the canary in clear whenever
    the canary was a key.
    """
    events = list(events)
    shape = shape_errors(events)
    errs: list[str] = []
    try:
        keys, sizes = _normalized(hashes, lengths)
    except CanaryWindowError as e:
        return [f"canary: {e}"] + shape
    if not keys:
        return [f"canary: {NO_KEY_MATERIAL}"] + shape
    try:
        order = _stream_order(events)
    except CanaryWindowError as e:
        return [f"canary: {e}"] + shape

    joined: list[str] = []
    spans: list[tuple[int, int, int]] = []  # (start, end, event index) in the join
    for i in order:
        text = (events[i].get("data") or {}).get("text")
        if not isinstance(text, str):
            errs.append(f"event[{i}]: {STREAM_TYPE} carries no text string")
            continue
        start = sum(len(p) for p in joined)
        joined.append(text)
        spans.append((start, start + len(text), i))
    stream = "".join(joined)
    try:
        for size in sizes:
            for at in range(0, len(stream) - size + 1):
                if _sha256_hex(stream[at:at + size]) in keys:
                    touched = sorted({i for s, e, i in spans if s < at + size and at < e})
                    errs.append(
                        f"canary: the reassembled {STREAM_TYPE} output carries a canary "
                        f"of {size} characters spanning event(s) {touched}. It is not "
                        "redacted, so this stream must not be published")
        for i, ev in enumerate(events):
            for path, value in _strings(ev):
                if path == "data.text" and ev.get("type") == STREAM_TYPE:
                    continue  # covered by the reassembled scan above
                if _hit(value, keys, sizes):
                    # The event's own type is not interpolated either. It is
                    # caller-supplied text, and the index plus the path names the
                    # field without it.
                    errs.append(f"event[{i}]: field {path} carries a canary")
        # The last gate joins the stream rather than reading it record by record.
        # A canary split across two tool arguments, or across one event's last
        # data value and the next event's first, is the same defect one layer
        # out, and this is the check that has the whole stream in hand. Reported
        # separately from the reassembled model output, which is the one spec
        # 10.1 names.
        #
        # Data values only, in document order. Two exclusions, both so the join
        # restores an adjacency rather than inventing a break in one: keys,
        # because joining `_strings` interleaves every key between the two values
        # either side of it (that defeated the first version of this check), and
        # the C2 envelope -- v, seq, t, run, type, prev_sha256 -- because it sits
        # between one event's data and the next's. Both are still scanned whole by
        # the loop above, and the value-to-key boundary the exclusion leaves open
        # is closed by `shape_errors`, which needs no adjacency and no key
        # material. That was the reason to take a shape rule over a third join.
        whole = "".join(leaf for ev in events for leaf in _leaves(ev.get("data")))
        if _hit(whole, keys, sizes) and not errs:
            errs.append(_crossed_field_error())
        # Pieces with other text between them, across the whole stream: one
        # URL parameter per chunk, or one chunk per tool call. Consecutive model
        # output is read as one string so a head the fragment boundaries cut is
        # whole again. The window is wider than the live one because the gate
        # runs once, offline.
        pieces, overflowed = _fragment_participants(_stream_strings(events, order), keys,
                                                    GATE_FRAGMENT_WINDOW)
        if overflowed:
            errs.append(_too_many_heads_error())
        elif pieces:
            errs.append(_pieces_error(len(pieces)))
    except CanaryWindowError as e:
        errs.append(f"canary: {e}")
    return errs + shape


# The only key names a message may print. Both halves are already hardcoded
# here: the C2 envelope, which the collector writes and no model touches, and
# the data fields this module reads by name. Any other key prints as its
# position, so no message can carry text a model chose.
ENVELOPE_KEYS = frozenset({"v", "seq", "t", "run", "type", "data", "prev_sha256"})
PATH_SAFE_KEYS = ENVELOPE_KEYS | {"text"} | {
    field for fields in VALUE_FIELDS.values() for field in fields}


def _segment(key, position: int) -> str:
    return key if isinstance(key, str) and key in PATH_SAFE_KEYS else f"{{{position}}}"


def _strings(node, path: str = ""):
    """Every string in an event, keys included, with a path to each.

    The path is built only from literals in this module and from integers, never
    from a key the caller supplied. A model names its own tool-argument keys, so
    it can make the canary a key, and a path that echoed the key printed the
    canary in clear in this gate's own refusal -- the leak the gate exists to
    prevent. `lab/guard/scan.py` already sets the discipline: report a path, a
    line and a rule without echoing the matched text.
    """
    if isinstance(node, str):
        yield path or ".", node
    elif isinstance(node, dict):
        for i, (k, v) in enumerate(node.items()):
            here = f"{path}.{_segment(k, i)}" if path else _segment(k, i)
            if isinstance(k, str):
                yield f"{here} (key)", k
            yield from _strings(v, here)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _strings(v, f"{path}[{i}]")
