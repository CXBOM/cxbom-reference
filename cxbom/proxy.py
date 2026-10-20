"""cxbom proxy: splicing, verdicts, chains, interception, events, and the process.

Owner: ATACE Working Group.

The module is built in layers, each over the one before:

- Splicing. A rewritten result is the original bytes with a few spans
  replaced. Kept array elements, kept object members, and every value the
  proxy does not touch keep their exact bytes (spec 8.2). The only new bytes
  are values the proxy writes itself.
- Verdicts and chains. One pure function gives each listed tool its verdict,
  and Chains carries spec 8.5's chain rules, which state.compute cannot see
  (the obligations in the state.py docstring).
- InterceptCore. Everything decided about relayed messages: the era latch,
  write-ahead attestation, splicing out blocked items, and gating tools/call.
  It never originates a request.
- ProxyCore. The proxy's own requests: re-listing, held calls, and discovery
  for a modern client that skipped it.
- EventSink and run(). The C2 sidecar, the startup checks, the relay
  threads, and shutdown.
"""
from __future__ import annotations

import difflib
import json
import os
import pwd
import queue
import re
import signal
import socket
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

from . import attestation, jsonstrict, launch, lockfile, paths, signing, state
from .canary import SHAPE_LEN, SHAPE_PREFIX
from .canonical import (CanonicalizationError, IgnoredFieldError, instructions_sha256, object_sha256,
                        sha256_hex, tool_sha256)
from .jsonstrict import Node
from .relay import (C2S, META_CLIENT_CAPABILITIES, META_LOG_LEVEL, META_PROTOCOL_VERSION, META_SERVER_INFO,
                    MISSING_CLIENT_CAPABILITY, OVERSIZE, PROXY_ID_PREFIX, S2C, SESSION_META_KEY,
                    UNSUPPORTED_PROTOCOL_VERSION, DuplicateId, LineWriter, Message, Pending, PendingTable,
                    ProxyIds, RelayError, ShapeError, WriterOverflow, classify, read_lines)
from .store import Store, StoreError
from .timeutil import now_rfc3339

Edit = tuple[int, int, bytes]
CXBOM_META_PREFIX = "org.cxbom/"


def json_bytes(value) -> bytes:
    # ensure_ascii escapes U+2028, U+2029 and U+0085, which the relay refuses
    # raw on input, so the proxy never emits a line a text-mode reader splits.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def apply_edits(data: bytes, edits: Iterable[Edit]) -> bytes:
    out = bytearray()
    pos = 0
    for start, end, rep in sorted(edits, key=lambda e: (e[0], e[1])):
        if start < pos or end < start or end > len(data):
            raise ValueError("overlapping or malformed edits")
        out += data[pos:start]
        out += rep
        pos = end
    out += data[pos:]
    return bytes(out)


def member_edits(data: bytes, obj: Node, values: dict[str, bytes]) -> list[Edit]:
    """Replace present members' values in place, and insert absent ones before the closing brace."""
    present = {k: v for k, _kn, v in obj.items}
    edits: list[Edit] = []
    missing: list[bytes] = []
    for key, value in values.items():
        if key in present:
            edits.append((present[key].start, present[key].end, value))
        else:
            missing.append(json_bytes(key) + b":" + value)
    if missing:
        insert = b",".join(missing)
        edits.append((obj.end - 1, obj.end - 1, (b"," + insert) if obj.items else insert))
    return edits


def rebuild_object(data: bytes, obj: Node, drop: Callable[[str], bool], values: dict[str, bytes]) -> bytes:
    """A new object: kept members as their original bytes, values set in place or appended."""
    parts: list[bytes] = []
    emitted: set[str] = set()
    for key, knode, vnode in obj.items:
        if key in values:
            parts.append(data[knode.start:knode.end] + b":" + values[key])
            emitted.add(key)
        elif not drop(key):
            parts.append(data[knode.start:vnode.end])
    for key, value in values.items():
        if key not in emitted:
            parts.append(json_bytes(key) + b":" + value)
    return b"{" + b",".join(parts) + b"}"


def rebuild_array(data: bytes, arr: Node, keep: Iterable[int]) -> bytes:
    keep = list(keep)
    if keep != sorted(set(keep)) or any(i < 0 or i >= len(arr.items) for i in keep):
        raise ValueError("keep must be ascending, unique, in-range indices")
    return b"[" + b",".join(data[arr.items[i].start:arr.items[i].end] for i in keep) + b"]"


def _is_cxbom_key(key: str) -> bool:
    return key.startswith(CXBOM_META_PREFIX)


def result_edits(data: bytes, result: Node, values: dict[str, bytes], proxy_session_id: str) -> list[Edit]:
    """Set members of a result object and stamp _meta with the proxy session id.

    Server-supplied org.cxbom/* keys in the result's _meta are removed, so a
    server cannot forge the session id an emitter binds to (spec 8.2).
    """
    sid = json_bytes(proxy_session_id)
    meta = result.get("_meta")
    edits: list[Edit] = []
    if meta is not None and meta.kind == "object":
        edits.append((meta.start, meta.end, rebuild_object(data, meta, _is_cxbom_key, {SESSION_META_KEY: sid})))
    else:
        values = dict(values, _meta=b"{" + json_bytes(SESSION_META_KEY) + b":" + sid + b"}")
    return edits + member_edits(data, result, values)


PINNED_MATCH = "pinned-match"
UNPINNED = "unpinned"
UNPINNED_VERSION = "unpinned-version"
CHANGED = "changed"
UNCANONICALIZABLE = "uncanonicalizable"
DUPLICATE_NAME = "duplicate-name"
ACCEPT_FLAG_NOT_ALLOWED = "accept-flag-not-allowed"


@dataclass(frozen=True)
class ItemVerdict:
    name: str
    verdict: str
    sha256: str
    pin: dict | None
    obj: object          # the wire object to store, or None when it cannot be canonicalized


def tool_verdict(tool: object, raw: bytes, era: dict | None, caps_ok: bool,
                 allow_accept_flag: bool) -> ItemVerdict | None:
    """Verdict for one wire tool object, or None for an item the proxy refuses to name.

    A tool without a string name, or named "*", is refused: "*" is the
    wildcard in state lines, so a verdict for it would read as every item
    (state.py obligation).
    """
    name = tool.get("name") if isinstance(tool, dict) else None
    if not isinstance(name, str) or name == "*":
        return None
    ignore = [f["pointer"] for f in era["ignoreFields"]] if era is not None else []
    try:
        sha = tool_sha256(tool, ignore)
    except CanonicalizationError:
        return ItemVerdict(name, UNCANONICALIZABLE, sha256_hex(raw), None, None)
    except IgnoredFieldError:
        # The ignored leaf failed benign-value checking, so the tool hashes
        # unstripped. That whole-object hash can itself be uncanonicalizable
        # (the bad leaf is out of the I-JSON domain, or an unrelated field
        # is), and this path must not let that escape uncaught.
        try:
            changed_sha = object_sha256(tool)
        except CanonicalizationError:
            return ItemVerdict(name, UNCANONICALIZABLE, sha256_hex(raw), None, None)
        return ItemVerdict(name, CHANGED, changed_sha, None, tool)
    if era is None or not caps_ok:
        return ItemVerdict(name, UNPINNED_VERSION, sha, None, tool)
    pin = era["tools"].get(name)
    if pin is None:
        return ItemVerdict(name, UNPINNED, sha, None, tool)
    if pin["sha256"] != sha:
        return ItemVerdict(name, CHANGED, sha, None, tool)
    if pin["approvalMode"] == "accept-flag" and not allow_accept_flag:
        return ItemVerdict(name, ACCEPT_FLAG_NOT_ALLOWED, sha, pin, tool)
    return ItemVerdict(name, PINNED_MATCH, sha, pin, tool)


def instructions_verdict(node: Node | None, raw: bytes, era: dict | None, caps_ok: bool) -> tuple[str, str, str | None]:
    """(verdict, sha256, text) for a result's instructions. An absent or null value hashes as ""."""
    if node is None or node.kind == "null":
        text = ""
    elif node.kind == "string":
        text = node.value
    else:
        return CHANGED, sha256_hex(raw[node.start:node.end]), None
    sha = instructions_sha256(text)
    if era is None or not caps_ok:
        return UNPINNED_VERSION, sha, text
    return (PINNED_MATCH if sha == era["instructionsSha256"] else CHANGED), sha, text


@dataclass(frozen=True)
class PageDecision:
    commit: bool                  # the page belongs to the latest chain, so its verdicts are written
    duplicates: frozenset         # names that appear more than once in the chain so far
    complete: bool                # the latest chain just finished (no nextCursor)
    chain_names: frozenset        # every name in the chain, filled only when complete


class Chains:
    """Spec 8.5 listing chains, so verdict lines obey chain precedence.

    A chain starts at a list request without a cursor and continues only with
    a nextCursor the proxy saw. Chains are ordered by start. Only pages of the
    latest chain commit verdicts, so an earlier chain never overrides a later
    one (state.py obligation). Pages are keyed by the cursor that fetched
    them, so a re-fetched page replaces itself and never counts its names twice.

    A cursor string can be reused (a server or a stale retry might replay
    one), so a cursor's owner only ever moves to a newer-or-equal chain, never
    back to an older one. Once the latest chain completes, cursors owned by
    strictly older chains are dropped, since a strictly newer completed chain
    makes them permanently superseded, and this keeps the cursor map bounded.
    """

    def __init__(self) -> None:
        self._next = 1
        self.latest = 0
        self.completed_latest = 0
        self._cursors: dict[str, int] = {}
        self._pages: dict[int, dict] = {}

    def start(self) -> int:
        cid = self._next
        self._next += 1
        self.latest = cid
        self._pages = {k: v for k, v in self._pages.items() if k >= cid - 1}
        self._pages[cid] = {}
        return cid

    def lookup(self, cursor: str) -> int | None:
        return self._cursors.get(cursor)

    def page(self, cid: int, cursor: str | None, names: list, next_cursor: str | None) -> PageDecision:
        if isinstance(next_cursor, str):
            owner = self._cursors.get(next_cursor)
            if owner is None or cid >= owner:
                self._cursors[next_cursor] = cid
        pages = self._pages.setdefault(cid, {})
        pages[cursor] = list(names)
        counts: dict[str, int] = {}
        for page_names in pages.values():
            for n in page_names:
                counts[n] = counts.get(n, 0) + 1
        dups = frozenset(n for n, c in counts.items() if c > 1)
        commit = cid == self.latest
        complete = commit and next_cursor is None
        if complete:
            self.completed_latest = cid
            self._cursors = {cur: own for cur, own in self._cursors.items() if own >= cid}
        return PageDecision(commit, dups, complete, frozenset(counts) if complete else frozenset())


MODERN_CUTOVER = "2026-07-28"
LEGACY = "legacy"
MODERN = "modern"
TOOLS_ONLY_PREFIXES = ("prompts/", "resources/")
_DIAGNOSTIC_MAX = 2000
_BLOCK_ALL = "cxbom: attestation is unavailable. Everything is blocked"
# Every request the proxy tracks at once: the pending table (cancelled
# entries in their retention window included) plus held calls and lists.
# Past it, a new client request gets -32603 and a new server request gets
# -32603 back, so a peer that never lets requests finish cannot grow the
# proxy's memory without limit. 4096 is far above what an agent session
# keeps in flight.
MAX_IN_FLIGHT = 4096
_TOO_MANY = "cxbom: too many requests in flight"
# The count cap alone does not bound memory: a held call keeps the full
# request (and its edited copy) in memory until its chain settles, and a
# held list keeps a full result. MAX_ID_RAW bounds a pending table entry's
# own contribution to a few KB. This caps the total across everything the
# proxy is holding onto at once, so MAX_IN_FLIGHT entries near MAX_LINE
# each cannot run the process out of memory. Checked at the same two
# admission points as MAX_IN_FLIGHT, so a proxy-owned re-list or discover
# request is exempt the same way: it never passes through either gate.
MAX_IN_FLIGHT_BYTES = 256 * 1024 * 1024
_TOO_MANY_BYTES = "cxbom: too many bytes in flight"


class _AttestationDown(Exception):
    """The attestation log cannot be written, so nothing may be forwarded on its account."""


class NullEvents:
    def emit(self, type_: str, data: dict) -> None:
        return None


def error_line(id_raw: bytes, code: int, message: str) -> bytes:
    if id_raw.startswith(b'"'):
        # A client-supplied string id can carry raw non-ASCII UTF-8. A number
        # id cannot (its grammar is ASCII-only), so only strings need this.
        # Route it through json_bytes so this proxy-authored line stays ASCII
        # like every other value the proxy writes.
        id_raw = json_bytes(jsonstrict.to_python(jsonstrict.parse(id_raw)))
    return (b'{"jsonrpc":"2.0","id":' + id_raw + b',"error":{"code":' + str(code).encode()
            + b',"message":' + json_bytes(message) + b"}}")


_VERSION_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$")


def _version_tuple(version: str) -> tuple[int, int, int] | None:
    """Parse a YYYY-MM-DD version string into a comparable tuple, or None if malformed.

    Naive string comparison ("9" >= "2026-07-28") is true for garbage input
    that is not a date at all, which would let a server falsely claim modern
    support. Only a strictly-shaped date string compares as one.

    The pattern uses [0-9], not \\d, because \\d matches any Unicode decimal
    digit (Arabic-Indic digits included), and int() would happily convert
    those too. An ASCII-only match keeps a non-ASCII "date" out of the
    modern-support comparison instead of silently parsing it.
    """
    m = _VERSION_RE.fullmatch(version)
    return tuple(int(part) for part in m.groups()) if m is not None else None


def is_modern_error(err: Node | None) -> bool:
    """A recognized modern JSON-RPC error: the server is modern even though it refused (spec 8.3).

    UnsupportedProtocolVersionError (-32022) must list the versions the server
    supports in data.supported. MissingRequiredClientCapability (-32021) is
    modern by definition. Any other error proves nothing, because legacy
    servers answer unknown pre-initialize methods with arbitrary errors.
    """
    code = err.get("code") if err is not None and err.kind == "object" else None
    if code is None or code.kind != "number":
        return False
    if code.value == str(MISSING_CLIENT_CAPABILITY):
        return True
    if code.value != str(UNSUPPORTED_PROTOCOL_VERSION):
        return False
    data = err.get("data")
    supported = data.get("supported") if data is not None and data.kind == "object" else None
    if supported is None or supported.kind != "array":
        return False
    cutover = _version_tuple(MODERN_CUTOVER)
    for v in supported.items:
        if v.kind != "string":
            continue
        parsed = _version_tuple(v.value)
        if parsed is not None and parsed >= cutover:
            return True
    return False


def caps_sha256(caps: object) -> str | None:
    try:
        return object_sha256(caps)
    except CanonicalizationError:
        return None


def rpc_id(msg: Message) -> object:
    value = msg.id_python()
    return value if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def id_key_from(node: Node | None) -> tuple | None:
    if node is None or node.kind not in ("string", "number"):
        return None
    return (node.kind, node.value)


# The descriptionDiff rendering. A tool_swapped diff prints text an untrusted
# server chose, and the operator reads it on screen (J2's reveal). The core
# only records the two descriptions (DescriptionChange). The sidecar writer
# renders them, because rendering has to start from text that is already
# redacted and scrubbed: the per-line marker glues "-" or "+" to the start of
# every line, and both are token characters to redact, so a canary at a line
# start is only matched before a marker exists. So render_description_diff
# redacts the two whole descriptions first, then scrubs them, and only then
# splits, diffs, marks, escapes and bounds. No marker or escape the proxy
# writes can sit next to a live canary, because none exists by then.
#
# Context lines around each change, as in `diff -U2`.
DIFF_CONTEXT_LINES = 2
# Lines of each side of the changed region fed to difflib. Lines both sides
# share at the start and at the end are trimmed first, down to the context,
# so a change after any number of unchanged lines still shows. The cap bounds
# SequenceMatcher, whose cost grows with the product of the two line counts.
DIFF_MAX_INPUT_LINES = 1000
# Rendered lines per diff, the elision line included, and characters per line
# after escaping. J2's changed paragraph is one line of about 200 characters,
# so it renders whole.
DIFF_MAX_LINES = 48
DIFF_MAX_LINE_CHARS = 256
# Every proxy-authored marker carries an unescaped backslash, and every
# backslash in server text is escaped, so no description can write one. Meta
# lines start with a backslash, as unified diff's own "\ No newline at end of
# file" does, and a line printed from a description starts with "+", "-" or " ".
DIFF_LINE_CUT = " \\ line cut"
DIFF_INPUT_CUT = f"\\ only {DIFF_MAX_INPUT_LINES} lines of each side of the change are compared"
DIFF_HEADERS = ("--- approved", "+++ served")


@dataclass(frozen=True)
class DescriptionChange:
    """The approved and served descriptions behind one tool_swapped event, unrendered.

    Not a string on purpose: json.dumps refuses it, so a writer that forgets
    to render it (and so to redact it first) fails instead of publishing.
    """
    old: str
    new: str


def _description_text(obj: object) -> str:
    text = obj.get("description", "") if isinstance(obj, dict) else ""
    # json.dumps writes no raw newline, so a non-string description is one line.
    return text if isinstance(text, str) else json.dumps(text)


def description_change(old: object, new: object) -> DescriptionChange:
    return DescriptionChange(_description_text(old), _description_text(new))


def _escaped(ch: str) -> str:
    # The backslash too, so the proxy's own escapes and markers stay unforgeable.
    return "\\u{005C}" if ch == "\\" else launch.escape_for_display(ch)


def _cut(pieces: list[str]) -> str:
    """pieces joined and cut to DIFF_MAX_LINE_CHARS, never inside a piece."""
    room = DIFF_MAX_LINE_CHARS - len(DIFF_LINE_CUT)
    keep = None      # how many pieces fit beside the cut marker, once that many is known
    used = 0
    for i, piece in enumerate(pieces):
        if keep is None and used + len(piece) > room:
            keep = i
        used += len(piece)
        if used > DIFF_MAX_LINE_CHARS:
            return "".join(pieces[:keep]) + DIFF_LINE_CUT
    return "".join(pieces)


def _escape_and_cut(text: str, limit: int = DIFF_MAX_LINE_CHARS + 1) -> list[str]:
    # Escapes at most `limit` characters: one more than a line can show is
    # enough for _cut to know it must cut, however long the line.
    return [_escaped(ch) for ch in text[:limit]]


def _diff_line(marker: str, text: str) -> str:
    pieces = [marker] + _escape_and_cut(text)
    # A removed line whose text starts "--" would read "--- ...", and an added
    # one starting "++" "+++ ...": the file headers. Escaping the text's first
    # character keeps the only header lines the first two.
    if text[:2] == marker * 2:
        pieces[1] = f"\\u{{{ord(marker):04X}}}"
    return _cut(pieces)


def _range(start: int, stop: int) -> str:
    # difflib's unified range format: "3" for one line, "3,4" for four, "2,0" for none after line 2.
    length = stop - start
    if length == 1:
        return f"{start + 1}"
    return f"{start + 1 if length else start},{length}"


def _hunks(a: list[str], b: list[str]) -> tuple[list[str], bool]:
    """Unified hunks from a to b over the changed region, and whether the input cap cut it."""
    n = DIFF_CONTEXT_LINES
    most = min(len(a), len(b))
    p = 0
    while p < most and a[p] == b[p]:
        p += 1
    s = 0
    while s < most - p and a[-1 - s] == b[-1 - s]:
        s += 1
    lo = max(0, p - n)
    wa, wb = a[lo:min(len(a), len(a) - s + n)], b[lo:min(len(b), len(b) - s + n)]
    cut = len(wa) > DIFF_MAX_INPUT_LINES or len(wb) > DIFF_MAX_INPUT_LINES
    wa, wb = wa[:DIFF_MAX_INPUT_LINES], wb[:DIFF_MAX_INPUT_LINES]
    out: list[str] = []
    for group in difflib.SequenceMatcher(None, wa, wb).get_grouped_opcodes(n):
        out.append(f"@@ -{_range(group[0][1] + lo, group[-1][2] + lo)} "
                   f"+{_range(group[0][3] + lo, group[-1][4] + lo)} @@")
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                out.extend(_diff_line(" ", t) for t in wa[i1:i2])
                continue
            if tag in ("replace", "delete"):
                out.extend(_diff_line("-", t) for t in wa[i1:i2])
            if tag in ("replace", "insert"):
                out.extend(_diff_line("+", t) for t in wb[j1:j2])
    return out, cut


def _cap_lines(lines: list[str]) -> list[str]:
    if len(lines) <= DIFF_MAX_LINES:
        return lines
    hidden = len(lines) - (DIFF_MAX_LINES - 1)
    return lines[:DIFF_MAX_LINES - 1] + [f"\\ {hidden} more lines not shown"]


def render_description_diff(change: DescriptionChange, hashes: frozenset = frozenset(), scrub=None) -> str:
    """The descriptionDiff text for one change: redact, scrub, then diff line by line and bound.

    An unchanged description gives "" (a revert to the approved body, spec
    8.7). A description holding a redacted value makes the whole field
    "<canary>", as the one-element diff did. Only "\\n" splits a line. Every
    other line break (\\r, \\v, \\f, U+0085, U+2028, U+2029) stays inside its
    line as an escape, so the proxy's own line breaks are the only ones a
    reader sees. Any other text always gets the two headers, so a cut or a
    change the scrub hid never renders as "nothing changed".
    """
    old, new = change.old, change.new
    if old == new:
        return ""
    if redact(old, hashes) != old or redact(new, hashes) != new:
        return CANARY
    if scrub is not None:
        old, new = scrub(old), scrub(new)
    body, cut = _hunks(old.split("\n"), new.split("\n"))
    return "\n".join(_cap_lines(list(DIFF_HEADERS) + ([DIFF_INPUT_CUT] if cut else []) + body)) + "\n"


def description_diff(old: object, new: object) -> str:
    """render_description_diff of two tool objects, with no redaction or scrub (for tests and tooling)."""
    return render_description_diff(description_change(old, new))


def bound_diff_for_display(text: str) -> str:
    """A descriptionDiff given as finished text, bounded the same way: every line escaped and cut, 48 lines.

    The core emits a DescriptionChange, which render_description_diff bounds
    itself. This covers a caller that emits the field as a string, so no
    string reaches the screen unbounded. The whole text is untrusted here, so
    every line is escaped, backslashes included. A trailing newline survives.
    """
    body, end = (text[:-1], "\n") if text.endswith("\n") else (text, "")
    return "\n".join(_cap_lines([_cut(_escape_and_cut(ln)) for ln in body.split("\n")])) + end


class InterceptCore:
    """Everything the proxy decides about messages it relays, one line at a time.

    This layer never originates a request. A call to a tool that is not
    allowed is blocked, a list result that arrives before verified server
    instructions is refused, and list_changed is only forwarded. ProxyCore
    adds the proxy's own requests on top (spec 8.2, 8.4).

    The core does no I/O except the attestation log and the store. Lines
    leave through to_client and to_server, which are LineWriter.send in
    production and list appends in tests. Callers serialize calls into the
    core with one lock.
    """

    def __init__(self, *, server_id: str, mode: str, entry: dict, log, store, to_client, to_server,
                 proxy_session_id: str, events=None, clock=time.monotonic, on_fatal=None, scrub=None):
        self.server_id = server_id
        self.enforce = mode == "enforce"
        self.entry = entry
        self.log = log
        self.store = store
        self.to_client = to_client
        self.to_server = to_server
        self.psid = proxy_session_id
        self.events = events if events is not None else NullEvents()
        self.clock = clock
        self.on_fatal = on_fatal if on_fatal is not None else (lambda reason: None)
        # Free text the proxy writes (diagnostics, block messages) passes
        # through scrub, so a client- or server-chosen string carrying a
        # home path or user name does not land in the log or on the wire
        # as proxy output (anonymity, spec 3).
        self.scrub = scrub if scrub is not None else (lambda text: text)
        self.pending = PendingTable()
        self.ids = ProxyIds(proxy_session_id)
        self.chains = Chains()
        self.states: dict = {}
        self.era: str | None = None
        self.protocol_written = False
        self.server_line_written = False
        self.list_forwarded = False
        self.legacy_caps_ok = True
        self.legacy_initialized = False
        self.initialize_sent = False
        self.attestation_down = False
        self.committed_any_chain = False
        self.last_meta: dict[str, object] = {}
        self.last_declared_caps: dict[str, object] = {}
        # name -> (sha256, wire object) of the last listing that reached
        # allowed. The hash travels with the object because a tool_swapped
        # event has to name the same body its diff prints on the approved side.
        self.last_allowed: dict[str, tuple[str, object]] = {}

    # ----- attestation (write-ahead, spec 8.6) --------------------------------------

    def _write(self, kind: str, **fields) -> None:
        if self.attestation_down:
            raise _AttestationDown()
        try:
            self.log.append(kind, **fields)
        except (attestation.AttestationIOError, OSError):
            self._attestation_failed()
            raise _AttestationDown() from None

    def _diagnostic(self, message: str) -> None:
        self._write("diagnostic", message=self.scrub(message)[:_DIAGNOSTIC_MAX])

    def _recompute(self) -> None:
        # The proxy reads its own log back through the same function the
        # emitter uses, so the two can never disagree about an item's state.
        try:
            self.states = state.compute(attestation.read_log(self.log.path))
        except (state.StateError, attestation.AttestationFormatError, attestation.AttestationIOError):
            self._attestation_failed()
            raise _AttestationDown() from None

    def _attestation_failed(self) -> None:
        if self.attestation_down:
            return
        self.attestation_down = True
        try:
            self.log.end("attestation-io")
        except (attestation.AttestationIOError, attestation.AttestationFormatError, OSError):
            pass
        if not self.enforce:
            self.on_fatal("attestation-io")
            return
        # Enforce keeps the session open with everything blocked (spec 8.6)
        # rather than tearing it down, so nothing else will ever answer a
        # request already forwarded to the server before the break: a late
        # server line for one of these is dropped, not relayed
        # (_blocked_server_line). Each gets its -32603 now, at the moment
        # the break is detected, instead of hanging forever. Proxy-owned
        # entries are untouched. They settle (or fail) through the normal
        # per-method handlers, which already refuse to write or forward
        # while attestation_down is set.
        for p in self.pending.outstanding(C2S):
            if not p.own:
                self.pending.discard(p)
                self._fail_client(p, _BLOCK_ALL)

    # ----- small helpers ------------------------------------------------------------

    def _reply_client(self, msg: Message, code: int, message: str) -> None:
        self.to_client(error_line(msg.id_raw, code, message))

    def _fail_client(self, p: Pending, message: str) -> None:
        if not p.own:
            self.to_client(error_line(p.context["id_raw"], -32603, message))

    def _message_event(self, frm: str, to: str, method: str, rid: object, summary: str) -> None:
        # The summary is cut to its schema cap by EventSink, after redaction
        # and scrubbing, so the cut can never split a canary.
        self.events.emit("mcp_message", {"from": frm, "to": to, "method": method, "rpcId": rid,
                                         "summary": summary})

    def _in_flight(self) -> int:
        return len(self.pending)

    def _in_flight_bytes(self) -> int:
        """Bytes retained by the pending table: each entry's id_raw (spec 8.2)."""
        return sum(len(p.context.get("id_raw") or b"") for p in self.pending.values())

    def _era_pins(self, version: object) -> dict | None:
        if self.era == LEGACY:
            return self.entry["eras"].get(LEGACY)
        return self.entry["eras"].get(version) if isinstance(version, str) else None

    # ----- entry points -------------------------------------------------------------

    def tick(self) -> None:
        self.pending.expire(self.clock())

    def from_client(self, raw) -> None:
        try:
            self._from_client(raw)
        except _AttestationDown:
            return

    def from_server(self, raw) -> None:
        try:
            self._from_server(raw)
        except _AttestationDown:
            return

    # ----- client to server ---------------------------------------------------------

    def _from_client(self, raw) -> None:
        if raw is OVERSIZE:
            self._diagnostic("client sent a line over the size limit. Dropped")
            return
        try:
            msg = classify(raw)
        except (jsonstrict.StrictJSONError, ShapeError) as e:
            self._diagnostic(f"client sent a line that is not one JSON-RPC message ({e})")
            if not self.enforce:
                self.to_server(raw)
            elif str(e) == "batch":
                self.to_client(error_line(b"null", -32600, "cxbom: JSON-RPC batching is not supported"))
            return
        if self.attestation_down and self.enforce:
            # Spec 8.6: enforce blocks everything once attestation cannot be
            # written, not just tools/call. A request gets the one blanket
            # error. A notification or a response to an already-pending
            # server request has no reply channel, so it is just dropped.
            if msg.kind == "request":
                self._reply_client(msg, -32603, _BLOCK_ALL)
            return
        if msg.kind == "request":
            self._client_request(msg)
        elif msg.kind == "notification":
            self._client_notification(msg)
        else:
            self._client_response(msg)

    def _client_request(self, msg: Message) -> None:
        if msg.id_key[0] == "string" and msg.id_key[1].startswith(PROXY_ID_PREFIX):
            self._reply_client(msg, -32600, "cxbom: request ids starting with cxbom- are reserved")
            return
        if self.pending.get(C2S, msg.id_key) is not None:
            self._reply_client(msg, -32600, "cxbom: this request id is already pending")
            return
        if self._in_flight() >= MAX_IN_FLIGHT:
            self._reply_client(msg, -32603, _TOO_MANY)
            return
        if self._in_flight_bytes() + len(msg.raw) > MAX_IN_FLIGHT_BYTES:
            self._reply_client(msg, -32603, _TOO_MANY_BYTES)
            return
        meta = msg.meta()
        version = meta.get(META_PROTOCOL_VERSION) if isinstance(meta, dict) else None
        modern_shaped = msg.method == "server/discover" or isinstance(version, str)
        if self.enforce:
            if msg.method == "initialize" and (self.era == MODERN or self.list_forwarded):
                self._reply_client(msg, -32600, "cxbom: this server process is latched to the modern era")
                return
            if msg.method == "initialize" and self.initialize_sent:
                # Keyed on "already sent", not "protocol_written": a second
                # initialize pipelined ahead of the first result still finds
                # protocol_written False, and forwarding it would let the
                # server answer twice and write a second server line.
                self._reply_client(msg, -32600, "cxbom: this server process already completed initialize")
                return
            if modern_shaped and self.era == LEGACY:
                self._reply_client(msg, -32600, "cxbom: this server process is latched to the legacy era")
                return
            if msg.method.startswith(TOOLS_ONLY_PREFIXES):
                self._reply_client(msg, -32601, "cxbom: this version verifies tools only")
                return
        out = msg.raw
        edits: list[Edit] = []
        pending = Pending(C2S, msg.id_key, msg.method, meta=meta, context={"id_raw": msg.id_raw})
        if modern_shaped:
            meta_edit, pending.meta = self._modern_caps_edit(msg, meta)
            if meta_edit is not None:
                edits.append(meta_edit)
            caps = meta.get(META_CLIENT_CAPABILITIES, {}) if isinstance(meta, dict) else {}
            pending.context["version"] = version
            pending.context["declared_caps"] = caps
            pending.context["caps_ok"] = caps_sha256(caps) == self.entry["clientCapabilitiesSha256"]
        if msg.method == "initialize":
            if self.era is None:
                self.era = LEGACY
            legacy_edit = self._legacy_caps_edit(msg)
            if legacy_edit is not None:
                edits.append(legacy_edit)
            self.initialize_sent = True
        if edits:
            # A hybrid request (a legacy "initialize" carrying modern-shaped
            # _meta) needs both the modern _meta.clientCapabilities strip and
            # the legacy capabilities strip. They address disjoint spans of
            # msg.raw, so both edits must go through one apply_edits call:
            # applying one and then re-deriving the other's node offsets
            # against the already-edited bytes would misplace the second edit.
            #
            # Applied here, before the tools/list and tools/call branches,
            # because both can return early below. A tools/call that returned
            # before this point would reach the server with its edits only in
            # pending.meta, not in the bytes actually sent.
            out = apply_edits(msg.raw, edits)
        if msg.method == "tools/list":
            if not self._client_tools_list(msg, pending):
                return
        elif msg.method == "tools/call":
            self._client_tools_call(msg, pending, out)
            return
        self._remember_meta(msg, pending)
        self.pending.add(pending)
        self.to_server(out)
        self._message_event("agent", "server", msg.method, rpc_id(msg), f"agent sends {msg.method}")

    def _remember_meta(self, msg: Message, pending: Pending) -> None:
        """Record a modern-shaped request's stripped _meta and declared capabilities together.

        Called only once a request is accepted (forwarded or held), never for
        one the proxy rejects, and always as a pair from the one request. The
        proxy's own requests copy last_meta and compute caps_ok from
        last_declared_caps, so recording them from different requests (or
        from a rejected one) would let the two paths disagree on caps_ok.
        """
        if "declared_caps" not in pending.context or not isinstance(pending.meta, dict):
            return
        for key in (msg.method, "*"):
            self.last_meta[key] = pending.meta
            self.last_declared_caps[key] = pending.context["declared_caps"]

    def _modern_caps_edit(self, msg: Message, meta: object) -> tuple[Edit | None, object]:
        """An edit stripping "sampling" from a modern request's clientCapabilities, plus the updated meta."""
        if self.entry["allowSampling"] or not isinstance(meta, dict):
            return None, meta
        caps = meta.get(META_CLIENT_CAPABILITIES)
        if not isinstance(caps, dict) or "sampling" not in caps:
            return None, meta
        caps_node = msg.param("_meta").get(META_CLIENT_CAPABILITIES)
        new = rebuild_object(msg.raw, caps_node, lambda k: k == "sampling", {})
        stripped = dict(meta, **{META_CLIENT_CAPABILITIES: {k: v for k, v in caps.items() if k != "sampling"}})
        return (caps_node.start, caps_node.end, new), stripped

    def _legacy_caps_edit(self, msg: Message) -> Edit | None:
        """An edit stripping "sampling" from a legacy initialize's capabilities, or None."""
        caps_node = msg.param("capabilities")
        caps = jsonstrict.to_python(caps_node) if caps_node is not None else {}
        self.legacy_caps_ok = caps_sha256(caps) == self.entry["clientCapabilitiesSha256"]
        if self.entry["allowSampling"] or caps_node is None or caps_node.kind != "object" \
                or caps_node.get("sampling") is None:
            return None
        new = rebuild_object(msg.raw, caps_node, lambda k: k == "sampling", {})
        return (caps_node.start, caps_node.end, new)

    def _client_tools_list(self, msg: Message, pending: Pending) -> bool:
        cursor = msg.param("cursor")
        if cursor is None:
            pending.chain = self.chains.start()
            return True
        if cursor.kind == "string":
            pending.cursor = cursor.value
            pending.chain = self.chains.lookup(cursor.value)
            if pending.chain is not None or not self.enforce:
                return True
            self._reply_client(msg, -32602, "cxbom: unknown cursor for this listing")
            return False
        if not self.enforce:
            return True
        self._reply_client(msg, -32602, "cxbom: cursor must be a string")
        return False

    def _client_notification(self, msg: Message) -> None:
        if self.enforce and not msg.method.startswith("notifications/"):
            # A request-shaped method with no id (a client-crafted or buggy
            # notification for "tools/call", say) has no gating path of its
            # own and no response channel to carry a block error back, so it
            # must never reach the server (spec 8.4).
            self._diagnostic(f"client sent a notification-shaped {msg.method} request. Dropped")
            return
        if msg.method == "notifications/cancelled":
            key = id_key_from(msg.param("requestId"))
            if key is not None and key[0] == "string" and key[1].startswith(PROXY_ID_PREFIX):
                self._diagnostic("client tried to cancel a proxy request. Dropped")
                return
            if key is not None:
                self.pending.cancel(C2S, key, self.clock())
        elif msg.method == "notifications/initialized":
            self.legacy_initialized = True
        self.to_server(msg.raw)

    def _client_response(self, msg: Message) -> None:
        p = self.pending.take(S2C, msg.id_key)
        if (p is not None and p.cancelled_at is None) or (p is None and not self.enforce):
            self.to_server(msg.raw)
            return
        self._diagnostic("client sent a response with no pending server request. Dropped")

    # ----- tools/call gating (spec 8.4, 8.5) ----------------------------------------

    def _block_text(self, name: str, reason: str) -> str:
        return self.scrub(f"Unknown tool: {name} (blocked by cxbom: {reason})")

    def _block_call(self, msg: Message, name: str, reason: str) -> None:
        self.events.emit("gate_decision", {"serverId": self.server_id, "tool": name, "decision": "block",
                                           "reason": reason})
        meta = msg.meta()
        if (self.era == LEGACY and self.legacy_initialized) or (isinstance(meta, dict) and META_LOG_LEVEL in meta):
            self.to_client(json_bytes({"jsonrpc": "2.0", "method": "notifications/message",
                                       "params": {"level": "warning", "logger": "cxbom",
                                                  "data": self._block_text(name, reason)}}))
        self._reply_client(msg, -32602, self._block_text(name, reason))
        self._message_event("proxy", "agent", "tools/call", rpc_id(msg), f"proxy blocks tools/call {name}")

    def _forward_call(self, msg: Message, pending: Pending, out: bytes, name: str) -> None:
        self.pending.add(pending)
        self.to_server(out)
        self._message_event("agent", "server", "tools/call", rpc_id(msg), f"agent calls {name}")

    def _client_tools_call(self, msg: Message, pending: Pending, out: bytes) -> None:
        name_node = msg.param("name")
        name = name_node.value if name_node is not None and name_node.kind == "string" else None
        if not self.enforce:
            item = state.lookup(self.states, "tool", name) if name is not None else None
            if item is not None and item.state != state.ALLOWED:
                # C2 1.1.0: observe takes log the block enforce mode would have made.
                self.events.emit("gate_decision", {"serverId": self.server_id, "tool": name,
                                                   "decision": "would-block", "reason": item.cause})
            self._remember_meta(msg, pending)
            self._forward_call(msg, pending, out, name or "")
            return
        if name is None:
            self._reply_client(msg, -32602, "cxbom: tools/call needs a string name")
            return
        if self.attestation_down:
            self._block_call(msg, name, "attestation-io")
            return
        item = state.lookup(self.states, "tool", name)
        if item.state == state.ALLOWED:
            self._remember_meta(msg, pending)
            self._forward_call(msg, pending, out, name)
        elif item.state in (state.NOT_LISTED, state.UNVERIFIED):
            self._remember_meta(msg, pending)
            self._unlisted_call(msg, pending, out, name, item)
        else:
            self._block_call(msg, name, item.cause)

    def _unlisted_call(self, msg: Message, pending: Pending, out: bytes, name: str, item) -> None:
        self._block_call(msg, name, item.cause)

    # ----- server to client ---------------------------------------------------------

    def _from_server(self, raw) -> None:
        if raw is OVERSIZE:
            self._server_unparseable("a line over the size limit", None)
            return
        try:
            msg = classify(raw)
        except (jsonstrict.StrictJSONError, ShapeError) as e:
            self._server_unparseable(str(e), raw)
            return
        if self.attestation_down and self.enforce:
            self._blocked_server_line(msg)
            return
        if msg.kind == "request":
            self._server_request(msg)
        elif msg.kind == "notification":
            self._server_notification(msg)
        else:
            self._server_response(msg)

    def _blocked_server_line(self, msg: Message) -> None:
        """Spec 8.6: enforce drops every server line once attestation is down.

        One exception is a response to a request the proxy made of itself
        (own re-list or discover pages): those still need to settle chains
        and release held calls, but the method-specific handlers already
        refuse to write attestation or forward anything to the client
        while attestation_down is set, so routing an own response through
        the normal path here cannot leak or resurrect a write.

        The other is a backstop, not the primary path: _attestation_failed
        already fails every outstanding non-own client entry the instant
        the break is detected, so a client's own pending request should
        not still be sitting in the table by the time a late server line
        for it arrives here. If one somehow is (a timing gap this review
        did not anticipate, say), it still gets its -32603 here rather
        than being silently dropped and left to hang forever.
        """
        if msg.kind not in ("result", "error"):
            return
        p = self.pending.get(C2S, msg.id_key)
        if p is None:
            return
        if p.own:
            self._server_response(msg)
        else:
            self.pending.discard(p)
            self._fail_client(p, _BLOCK_ALL)

    def _server_unparseable(self, reason: str, raw: bytes | None) -> None:
        # Attestation may already be down when this fires. The write attempts
        # below are best-effort: failing pending client requests must still
        # happen even if neither write below can land, or those requests hang
        # forever instead of getting -32603 (spec 8.6).
        try:
            self._diagnostic(f"server sent a line that is not one JSON-RPC message ({reason})")
        except _AttestationDown:
            pass
        if not self.enforce:
            if raw is not None:
                self.to_client(raw)
            return
        try:
            self._write("state", itemType="*", name="*", state=state.UNVERIFIED, cause="strict-parse")
            self._recompute()
        except _AttestationDown:
            pass
        for p in self.pending.outstanding(C2S):
            self.pending.discard(p)
            self._fail_client(p, "cxbom: the server sent an unparseable message")

    def _server_request(self, msg: Message) -> None:
        if msg.method == "sampling/createMessage" and not self.entry["allowSampling"]:
            self._diagnostic("server requested sampling. Refused because allowSampling is false")
            self.to_server(error_line(msg.id_raw, -32601, "cxbom: sampling is disabled for this server"))
            return
        if self._in_flight() >= MAX_IN_FLIGHT:
            self.to_server(error_line(msg.id_raw, -32603, _TOO_MANY))
            return
        if self._in_flight_bytes() + len(msg.raw) > MAX_IN_FLIGHT_BYTES:
            self.to_server(error_line(msg.id_raw, -32603, _TOO_MANY_BYTES))
            return
        try:
            self.pending.add(Pending(S2C, msg.id_key, msg.method, context={"id_raw": msg.id_raw}))
        except DuplicateId:
            self.to_server(error_line(msg.id_raw, -32600, "cxbom: this request id is already pending"))
            return
        self.to_client(msg.raw)

    def _server_notification(self, msg: Message) -> None:
        if msg.method == "notifications/cancelled":
            key = id_key_from(msg.param("requestId"))
            if key is not None:
                self.pending.cancel(S2C, key, self.clock())
        self.to_client(msg.raw)
        self._message_event("server", "agent", msg.method, None, f"server sends {msg.method}")

    def _forward_stamped(self, msg: Message) -> None:
        """Forward a server response, stripping any server-supplied org.cxbom/* key.

        Used on observe-mode paths where the message never reached one of the
        typed result handlers (initialize, discover, tools/list), so nothing
        else would otherwise strip a forged org.cxbom/* key or stamp the real
        proxy session id (spec 8.2). A non-object result, or an error, has no
        _meta to stamp and goes out unchanged.
        """
        result = msg.node.get("result") if msg.kind == "result" else None
        if result is not None and result.kind == "object":
            self.to_client(apply_edits(msg.raw, result_edits(msg.raw, result, {}, self.psid)))
        else:
            self.to_client(msg.raw)

    def _server_response(self, msg: Message) -> None:
        p = self.pending.take(C2S, msg.id_key)
        if p is None:
            if self.enforce:
                self._diagnostic("server sent a response with no pending request. Dropped")
            else:
                self._forward_stamped(msg)
            return
        if p.cancelled_at is not None:
            return
        if p.method == "initialize":
            self._initialize_result(p, msg)
        elif p.method == "server/discover":
            self._discover_result(p, msg)
        elif p.method == "tools/list":
            self._tools_list_result(p, msg)
        elif not p.own:
            self.to_client(msg.raw)

    # ----- initialize and discover (spec 8.3, 8.4) ----------------------------------

    def _server_line(self, msg: Message, result: Node, era: dict | None, caps_ok: bool) -> dict:
        verdict, sha, text = instructions_verdict(result.get("instructions"), msg.raw, era, caps_ok)
        ref = None
        if text is not None:
            try:
                ref = self.store.put_json(text)
            except (StoreError, OSError):
                ref = None
        info = result.get("serverInfo")
        if info is None and self.era == MODERN:
            # Modern servers report identity in _meta, not in the result body.
            meta = result.get("_meta")
            info = meta.get(META_SERVER_INFO) if meta is not None and meta.kind == "object" else None
        info_py = jsonstrict.to_python(info) if info is not None and info.kind == "object" else {}
        self._write("server", instructionsSha256=sha, serverInfo=info_py, verdict=verdict, storeRef=ref)
        self.server_line_written = True
        self._recompute()
        if verdict != PINNED_MATCH and self.enforce and result.get("instructions") is not None:
            return {"instructions": b'""'}
        return {}

    def _initialize_result(self, p: Pending, msg: Message) -> None:
        result = msg.node.get("result")
        if msg.kind == "error" or result is None or result.kind != "object":
            self.to_client(msg.raw)
            return
        if self.era != LEGACY:
            # Not a legacy initialize this core will verify (era already
            # latched elsewhere), but still a real result object a server
            # could stamp with a forged org.cxbom/* key.
            self._forward_stamped(msg)
            return
        if self.attestation_down and self.enforce:
            self._fail_client(p, _BLOCK_ALL)
            return
        try:
            pv = result.get("protocolVersion")
            if not self.protocol_written:
                self._write("protocol", era=LEGACY,
                            protocolVersion=pv.value if pv is not None and pv.kind == "string" else "unknown")
                self.protocol_written = True
            values = self._server_line(msg, result, self.entry["eras"].get(LEGACY), self.legacy_caps_ok)
        except _AttestationDown:
            self._fail_client(p, _BLOCK_ALL)
            return
        edits = result_edits(msg.raw, result, values, self.psid)
        caps = result.get("capabilities")
        if self.enforce and caps is not None and caps.kind == "object" \
                and any(k in ("prompts", "resources") for k, _kn, _vn in caps.items):
            edits.append((caps.start, caps.end,
                          rebuild_object(msg.raw, caps, lambda k: k in ("prompts", "resources"), {})))
        self.to_client(apply_edits(msg.raw, edits))
        self._message_event("proxy", "agent", "initialize", rpc_id(msg), "proxy returns the checked initialize result")

    def _discover_result(self, p: Pending, msg: Message) -> None:
        result = msg.node.get("result")
        versions = result.get("supportedVersions") if result is not None and result.kind == "object" else None
        if msg.kind == "error" or versions is None or versions.kind != "array":
            if msg.kind == "error" and self.era is None and is_modern_error(msg.node.get("error")):
                self.era = MODERN
            if not p.own:
                # A non-error object result still has a _meta a server could
                # forge org.cxbom/proxySessionId into, even though it is
                # malformed for discovery (no usable supportedVersions).
                # _forward_stamped stamps that case and forwards an error, or
                # a non-object result, unchanged.
                self._forward_stamped(msg)
            return
        if self.era == LEGACY:
            if self.enforce:
                self._fail_client(p, "cxbom: this server process is latched to the legacy era")
            elif not p.own:
                self._forward_stamped(msg)
            return
        self.era = MODERN
        version = p.context.get("version")
        if not isinstance(version, str):
            offered = [v.value for v in versions.items if v.kind == "string"]
            known = [v for v in offered if v in self.entry["eras"]]
            version = (known or offered or ["unknown"])[0]
        try:
            if not self.protocol_written:
                self._write("protocol", era=MODERN, protocolVersion=version)
                self.protocol_written = True
            values = self._server_line(msg, result, self._era_pins(version), p.context.get("caps_ok", False))
        except _AttestationDown:
            self._fail_client(p, _BLOCK_ALL)
            return
        if p.own:
            return
        values.update({"ttlMs": b"0", "cacheScope": b'"private"'})
        self.to_client(apply_edits(msg.raw, result_edits(msg.raw, result, values, self.psid)))
        self._message_event("proxy", "agent", "server/discover", rpc_id(msg), "proxy returns the checked discovery")

    # ----- tools/list (spec 8.4, 8.5) -----------------------------------------------

    def _tools_list_result(self, p: Pending, msg: Message) -> None:
        if msg.kind == "error":
            self._list_failed(p, None, msg.raw)
            return
        if not self.server_line_written:
            self._list_failed(p, "cxbom: server instructions were not verified before this listing", None)
            return
        if self.attestation_down and self.enforce:
            self._list_failed(p, _BLOCK_ALL, None)
            return
        result = msg.node.get("result")
        tools = result.get("tools") if result is not None and result.kind == "object" else None
        if tools is None or tools.kind != "array":
            if self.enforce:
                self._list_failed(p, "cxbom: tools/list result has no tools array", None)
            elif not p.own:
                self._forward_stamped(msg)
            return
        try:
            keep = self._commit_tools(p, msg, result, tools)
        except _AttestationDown:
            self._list_failed(p, _BLOCK_ALL, None)
            return
        self._forward_list(p, msg, result, tools, keep)

    def _list_failed(self, p: Pending, message: str | None, raw: bytes | None) -> None:
        if p.own:
            return
        if raw is not None:
            self.to_client(raw)
        else:
            self._fail_client(p, message)

    def _forward_list(self, p: Pending, msg: Message, result: Node, tools: Node, keep: list) -> None:
        if p.own:
            return
        values = {"ttlMs": b"0", "cacheScope": b'"private"'} if self.era == MODERN else {}
        edits = result_edits(msg.raw, result, values, self.psid)
        if len(keep) != len(tools.items):
            edits.append((tools.start, tools.end, rebuild_array(msg.raw, tools, keep)))
        self.list_forwarded = True
        self.to_client(apply_edits(msg.raw, edits))
        self._message_event("proxy", "agent", "tools/list", rpc_id(msg),
                            f"proxy returns {len(keep)} of {len(tools.items)} tools")

    def _commit_tools(self, p: Pending, msg: Message, result: Node, tools: Node) -> list[int]:
        """Write verdicts ahead of forwarding, then return the indexes the client may see."""
        caps_ok = self.legacy_caps_ok if self.era == LEGACY else p.context.get("caps_ok", False)
        era = self._era_pins(p.context.get("version"))
        verdicts = [tool_verdict(jsonstrict.to_python(n), msg.raw[n.start:n.end], era, caps_ok,
                                 self.entry["allowAcceptFlag"]) for n in tools.items]
        refused = sum(1 for v in verdicts if v is None)
        if refused:
            self._diagnostic(f"server listed {refused} tool(s) without a usable name. Refused")
        nxt = result.get("nextCursor")
        next_cursor = nxt.value if nxt is not None and nxt.kind == "string" else None
        decision = None
        if p.chain is not None:
            decision = self.chains.page(p.chain, p.cursor, [v.name for v in verdicts if v is not None], next_cursor)
        if decision is not None and decision.commit:
            self._write_verdicts(verdicts, decision, era)
            if decision.complete:
                absent = sorted(n for (t, n) in self.states if t == "tool" and n not in decision.chain_names)
                for name in absent:
                    self._write("state", itemType="tool", name=name, state=state.NOT_LISTED,
                                cause="absent-after-full-chain")
                if absent:
                    self._recompute()
                self.committed_any_chain = True
        if not self.enforce:
            return list(range(len(tools.items)))
        keep = []
        for i, v in enumerate(verdicts):
            if v is None or (decision is not None and v.name in decision.duplicates):
                continue
            item = state.lookup(self.states, "tool", v.name)
            if item.state == state.ALLOWED and item.sha256 == v.sha256:
                keep.append(i)
        return keep

    def _write_verdicts(self, verdicts: list, decision: PageDecision, era: dict | None) -> None:
        before = dict(self.states)
        phase = "refresh" if self.committed_any_chain else "initial"
        recorded = []
        for v in verdicts:
            if v is None:
                continue
            verdict = DUPLICATE_NAME if v.name in decision.duplicates else v.verdict
            ref = None
            if v.obj is not None:
                try:
                    ref = self.store.put_json(v.obj)
                except (StoreError, CanonicalizationError, OSError):
                    ref = None
            pin = v.pin if verdict in (PINNED_MATCH, ACCEPT_FLAG_NOT_ALLOWED) else None
            self._write("verdict", itemType="tool", name=v.name, sha256=v.sha256, verdict=verdict,
                        approvedBy=pin["approvedBy"] if pin else None,
                        approvedAt=pin["approvedAt"] if pin else None,
                        approvalMode=pin["approvalMode"] if pin else None, storeRef=ref)
            recorded.append((v, verdict))
        self._recompute()
        # The events report the verdict that was written, not v.verdict. A name
        # this page listed twice is recorded as duplicate-name whatever the pin
        # says, and an event that contradicted the line it reports on would be
        # the louder of the two.
        for v, verdict in recorded:
            self._verdict_events(v, verdict, era, before, phase)

    def _verdict_events(self, v: ItemVerdict, verdict: str, era: dict | None, before: dict, phase: str) -> None:
        pinned = era["tools"].get(v.name) if era is not None else None
        expected = pinned["sha256"] if pinned is not None else None
        after = state.lookup(self.states, "tool", v.name)
        self.events.emit("tool_listed", {"serverId": self.server_id, "tool": v.name, "sha256": v.sha256,
                                         "phase": phase})
        self.events.emit("lock_checked", {"serverId": self.server_id, "tool": v.name, "expectedSha256": expected,
                                          "actualSha256": v.sha256, "match": expected == v.sha256})
        prior = before.get(("tool", v.name))
        allowed = self.last_allowed.get(v.name)
        if prior is not None and prior.sha256 not in (None, v.sha256) and allowed is not None:
            # oldSha256 is the last allowed body's hash, not prior.sha256: on a
            # second swap inside one session the previous served body is
            # neither approved nor on either side of the diff, and a hash that
            # named it would describe a different object than the diff does.
            self._tool_swapped(v, allowed[0], allowed[1])
        elif prior is None and verdict == CHANGED and v.obj is not None and expected is not None:
            # A swap that landed between sessions has no in-session
            # predecessor: this process started with empty state and an empty
            # last_allowed, so a first listing that misses the pin would
            # otherwise say only that two hashes differ. The approved body is
            # still recoverable, so recover it and say what changed. prior is
            # None only until the first commit writes this item's state line.
            #
            # The gate is the recorded verdict rather than expected != v.sha256
            # because that comparison is looser than the refusal it reports on:
            # tool_verdict never compares against a pin whose capabilities do
            # not match this client's, and a name listed twice is refused as
            # duplicate-name. In both cases nothing was swapped, so no swap may
            # be announced. expected is still checked for None because an
            # ignored leaf that fails benign-value checking reads changed even
            # on a tool no era pins. v.obj already follows from that verdict,
            # since both of tool_verdict's changed returns carry the wire
            # object, and the check stays anyway because this arm prints the
            # served text: a None right-hand side would read as the description
            # having been deleted, which is what the in-session arm does and
            # what this arm refuses to do.
            approved, why = self._approved_obj(expected)
            if approved is not None:
                self._tool_swapped(v, expected, approved)
            else:
                # The lookup missed: an ignoreFields era pinning a stripped
                # object the store never held, a state dir that did not survive
                # the restart (spec 5), or a store object that no longer hashes
                # to its own name. Either way the verdict above already blocks
                # and the operator otherwise has nothing beyond two differing
                # hashes in lock_checked. Say so once, rather than leaving the
                # miss silent.
                self._diagnostic(f"cold pin mismatch on {v.name}: {why}, no diff shown")
        if after.state == state.ALLOWED:
            self.last_allowed[v.name] = (v.sha256, v.obj)
        if after.state == state.ALLOWED:
            decision = "allow"
        else:
            decision = "block" if self.enforce else "would-block"
        self.events.emit("gate_decision", {"serverId": self.server_id, "tool": v.name, "decision": decision,
                                           "reason": after.cause})

    def _tool_swapped(self, v: ItemVerdict, old_sha: str, old_obj: object) -> None:
        self.events.emit("tool_swapped", {"serverId": self.server_id, "tool": v.name, "oldSha256": old_sha,
                                          "newSha256": v.sha256,
                                          "descriptionDiff": description_change(old_obj, v.obj)})

    def _approved_obj(self, sha: str) -> tuple[object | None, str]:
        """(approved wire object, "") behind a pin hash, or (None, why) when the store cannot produce it.

        A pin hash is the store key for the approved body only because
        canonical.tool_sha256 over an empty ignore list is object_sha256,
        which is what Store.put_json keys on. Two things break that: an era
        with ignoreFields, where the pin covers a stripped object the store
        never held, and a state directory that did not survive the restart
        (spec 5). Either way the caller emits no event rather than a diff it
        cannot substantiate.

        The reason travels back with the miss because Store.get_json's three
        messages are not interchangeable: a missing object means this machine
        never received the store, while an object that does not hash to its own
        name means something rewrote one. Collapsing store tampering into
        benign absence would throw away the one signal a hash-checked store
        exists to raise.
        """
        try:
            return self.store.get_json(sha), ""
        except StoreError as e:
            return None, str(e)


HOLD_TIMEOUT_S = 10.0
MAX_CHAIN_PAGES = 100
MCP_META_PREFIX = "io.modelcontextprotocol/"


def _protocol_only_meta(meta: dict) -> dict:
    """Keep only the namespaced protocol keys from a client's _meta.

    A proxy-originated request must never carry a client's progressToken or
    any other application-specific _meta key. Those are scoped to the one
    client request-response pair that named them, and copying one into a
    request the proxy originates on its own would misdirect a server's
    progress notifications or leak a client-chosen value into a request the
    client never made.
    """
    return {k: v for k, v in meta.items() if k.startswith(MCP_META_PREFIX)}


@dataclass
class HeldCall:
    msg: Message
    pending: Pending
    out: bytes
    name: str
    after_chain: int
    since: float


@dataclass
class HeldList:
    p: Pending
    msg: Message
    since: float


class ProxyCore(InterceptCore):
    """InterceptCore plus the proxy's own requests (spec 8.2, 8.4, 8.5).

    - A tools/call for a not-listed or unverified tool is held while the
      proxy runs its own full listing chain, then forwarded or blocked.
      Holding always starts a fresh chain, never joins one already in
      flight. The call is released once its own chain or any later chain
      completes (completed_latest >= after_chain), since every such chain
      started after the call arrived.
    - notifications/tools/list_changed makes the proxy re-list with its own
      ids. Only items whose hash changed leave allowed. A further
      notification while a re-list is unanswered is coalesced into a single
      follow-up chain rather than starting one per notification. The
      re-list settles once any chain started at or after it completes, and
      a re-list with no progress for HOLD_TIMEOUT_S is abandoned for a
      fresh one, so neither a superseding chain nor a silent server can
      wedge re-listing. A failed superseding chain restarts the re-list at
      once, and a failed re-list retries once after HOLD_TIMEOUT_S.
    - A modern client that lists without discovering first gets a proxy
      server/discover in front of its list, so a server line always precedes
      the first list result (state.py obligation).
    - A held call or a held list is bounded: HOLD_TIMEOUT_S measured on the
      injected clock blocks a stale call and answers a stale list rather
      than waiting on a silent server forever. A chain is bounded too:
      MAX_CHAIN_PAGES caps its page count, and a cursor it has already seen
      fails it, so a malicious or buggy nextCursor loop cannot run forever.

    Proxy requests use cxbom-<proxySessionId>-<n> ids and copy the
    io.modelcontextprotocol/* keys of the client's latest _meta of any
    method, after capability stripping. caps_ok is computed from the
    declared (unstripped) capabilities of the same accepted, modern-shaped
    request that _meta came from, the same value the client path itself
    checked, so the two paths never disagree. Proxy responses
    never reach the client.
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self.held_calls: list[HeldCall] = []
        self.held_lists: list[HeldList] = []
        self.own_discover: Pending | None = None
        self._chain_pages: dict[int, int] = {}
        self._chain_cursors: dict[int, set[str]] = {}
        self._relist_chain: int | None = None
        self._relist_queued: bool = False
        self._relist_progress_at: float = 0.0
        # (due time, failed relist chain) for the one retry a failed relist
        # schedules, or None.
        self._relist_retry: tuple[float, int] | None = None

    # ----- the proxy's own requests -------------------------------------------------

    def _own_request(self, method: str, params: dict, chain: int | None = None, cursor: str | None = None) -> Pending:
        rid = self.ids.next()
        meta = self.last_meta.get(method, self.last_meta.get("*"))
        if self.era != LEGACY and isinstance(meta, dict):
            params = dict(params, _meta=_protocol_only_meta(meta))
        p = Pending(C2S, ("string", rid), method, own=True, chain=chain, cursor=cursor,
                    meta=params.get("_meta"), context={"id_raw": json_bytes(rid)})
        if isinstance(params.get("_meta"), dict):
            p.context["version"] = params["_meta"].get(META_PROTOCOL_VERSION)
            # The client path checks caps_ok against declared capabilities
            # before stripping (see _client_request below). Reusing the
            # stripped meta here instead would let a client's disallowed
            # capability (sampling, say) pass caps_ok on the proxy's own
            # requests while the client path itself still refuses it.
            declared = self.last_declared_caps.get(method, self.last_declared_caps.get("*", {}))
            p.context["caps_ok"] = caps_sha256(declared) == self.entry["clientCapabilitiesSha256"]
        self.pending.add(p)
        self.to_server(json_bytes({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
        self._message_event("proxy", "server", method, rid, f"proxy sends its own {method}")
        return p

    def _maybe_own_discover(self, version: object) -> None:
        if self.server_line_written or self.own_discover is not None or self.era == LEGACY:
            return
        if isinstance(version, str):
            self.own_discover = self._own_request("server/discover", {})

    def _start_own_chain(self) -> int:
        meta = self.last_meta.get("tools/list", self.last_meta.get("*"))
        self._maybe_own_discover(meta.get(META_PROTOCOL_VERSION) if isinstance(meta, dict) else None)
        cid = self.chains.start()
        self._chain_pages = {k: v for k, v in self._chain_pages.items() if k >= cid - 1}
        self._chain_cursors = {k: v for k, v in self._chain_cursors.items() if k >= cid - 1}
        self._chain_pages[cid] = 1
        self._own_request("tools/list", {}, chain=cid)
        return cid

    def _start_relist(self) -> None:
        self._relist_queued = False
        self._relist_retry = None
        self._relist_chain = self._start_own_chain()
        self._relist_progress_at = self.clock()

    def _relist_settled(self, failed: int | None = None) -> None:
        """Settle the list_changed relist once it is answered or failed.

        The relist is answered when any chain that started at or after it
        has completed (completed_latest >= _relist_chain). A later chain
        (one started for a held call, say) supersedes the relist chain, so
        the relist chain itself can never complete, but the later chain
        re-read the whole list after the notification, which is what the
        relist was for. Requiring the exact chain would wedge re-listing
        forever and let a later rug-pull through.

        Coalescing means at most one relist chain is ever in flight from
        notifications alone: a notification that arrives while one is
        already unanswered only sets a flag, and this starts the one
        follow-up chain the flag asked for once the current one is done.

        Failures (failed is the chain id that failed):
        - The relist chain itself failed with nothing queued: one retry is
          scheduled for tick() after HOLD_TIMEOUT_S, so a server that keeps
          erroring gets at most one relist per HOLD_TIMEOUT_S, never a
          tight error loop.
        - A newer chain that superseded the relist failed and no chain is
          newer still: nothing left in flight can settle the relist, so a
          fresh relist starts now instead of waiting for tick() to notice.
        """
        if failed is None and self._relist_retry is not None \
                and self.chains.completed_latest >= self._relist_retry[1]:
            # A chain started at or after the failed relist has completed,
            # so it re-read the whole list and the retry is moot.
            self._relist_retry = None
        relist = self._relist_chain
        if relist is None:
            return
        if failed == relist:
            self._relist_chain = None
            if self._relist_queued:
                self._start_relist()
            else:
                self._relist_retry = (self.clock() + HOLD_TIMEOUT_S, relist)
            return
        if failed is not None:
            if failed > relist and failed == self.chains.latest:
                self._start_relist()
            return
        if self.chains.completed_latest < relist:
            return
        self._relist_chain = None
        if self._relist_queued:
            self._start_relist()

    # ----- held calls ---------------------------------------------------------------

    def _unlisted_call(self, msg: Message, pending: Pending, out: bytes, name: str, item) -> None:
        # Always a fresh chain, never a join onto one already in flight: a
        # joined chain can be superseded before it ever completes (a later
        # chain starts while this one waits on a later page), which would
        # leave the call bound to a chain that started before it arrived.
        # This chain, or any later one, releases it.
        cid = self._start_own_chain()
        self.held_calls.append(HeldCall(msg, pending, out, name, cid, self.clock()))

    def _resolve_held_calls(self, completed: int) -> None:
        # Any chain started at or after the call's own chain also started
        # after the call arrived, so its completion satisfies spec 8.5. This
        # also releases calls whose own chain was superseded by a newer one
        # and so can never complete.
        ready = [h for h in self.held_calls if h.after_chain <= completed]
        self.held_calls = [h for h in self.held_calls if h.after_chain > completed]
        for h in ready:
            item = state.lookup(self.states, "tool", h.name)
            if item.state == state.ALLOWED and not self.attestation_down:
                self._forward_call(h.msg, h.pending, h.out, h.name)
            else:
                self._block_call(h.msg, h.name, item.cause)

    def _fail_held_calls(self, reason: str) -> None:
        held, self.held_calls = self.held_calls, []
        for h in held:
            self._block_call(h.msg, h.name, reason)

    def _fail_chain_calls(self, cid: int, reason: str) -> None:
        """Fail only the held calls bound to this one chain, not every held call."""
        failing = [h for h in self.held_calls if h.after_chain == cid]
        self.held_calls = [h for h in self.held_calls if h.after_chain != cid]
        for h in failing:
            self._block_call(h.msg, h.name, reason)
        self._relist_settled(failed=cid)

    # ----- overrides ----------------------------------------------------------------

    def _in_flight(self) -> int:
        return len(self.pending) + len(self.held_calls) + len(self.held_lists)

    def _in_flight_bytes(self) -> int:
        total = super()._in_flight_bytes()
        for h in self.held_calls:
            total += len(h.msg.raw) + len(h.out)
        for h in self.held_lists:
            total += len(h.msg.raw)
        return total

    def _attestation_failed(self) -> None:
        # The base sweep only reaches the pending table. Held calls and
        # held lists are ProxyCore's own, and they are just as stuck: a
        # held call is waiting on a chain that will never complete now, and
        # a held list on a discover that will not either. Empty both here
        # rather than leaving them for tick()'s HOLD_TIMEOUT_S, which would
        # answer them eventually but not at the moment the client is
        # actually entitled to know its request was blocked.
        super()._attestation_failed()
        if not self.enforce:
            return
        # Nothing re-lists after the break. A relist left in flight would
        # otherwise make tick() write a diagnostic, which raises
        # _AttestationDown out of tick() and ends the session early.
        self._relist_chain = None
        self._relist_retry = None
        self._relist_queued = False
        held_calls, self.held_calls = self.held_calls, []
        for h in held_calls:
            self._fail_client(h.pending, _BLOCK_ALL)
        held_lists, self.held_lists = self.held_lists, []
        for h in held_lists:
            self._fail_client(h.p, _BLOCK_ALL)

    def tick(self) -> None:
        super().tick()
        now = self.clock()
        timed_out_calls = [h for h in self.held_calls if now - h.since >= HOLD_TIMEOUT_S]
        if timed_out_calls:
            self.held_calls = [h for h in self.held_calls if now - h.since < HOLD_TIMEOUT_S]
            for h in timed_out_calls:
                self._block_call(h.msg, h.name, "relist-timeout")
        timed_out_lists = [h for h in self.held_lists if now - h.since >= HOLD_TIMEOUT_S]
        if timed_out_lists:
            self.held_lists = [h for h in self.held_lists if now - h.since < HOLD_TIMEOUT_S]
            for h in timed_out_lists:
                self._fail_client(h.p, "cxbom: the proxy's own discovery did not complete in time")
        if self._relist_chain is not None and now - self._relist_progress_at >= HOLD_TIMEOUT_S:
            # A server that never answers the relist must not wedge
            # re-listing: every later list_changed would only queue behind
            # it. Abandon it and start a fresh relist, which also covers any
            # notification queued behind the abandoned one.
            self._diagnostic("the proxy's own relist made no progress in time. Starting a fresh relist")
            # Drop the abandoned chain's unanswered requests so repeated
            # abandonment against a silent server does not accumulate them.
            # A late answer to a dropped id finds nothing pending and is
            # discarded by _server_response.
            abandoned = self._relist_chain
            for p in self.pending.outstanding(C2S):
                if p.own and p.chain == abandoned:
                    self.pending.discard(p)
            self._start_relist()
        elif self._relist_chain is None and self._relist_retry is not None and now >= self._relist_retry[0]:
            self._start_relist()

    def _client_request(self, msg: Message) -> None:
        # A held call or a held client list has left the pending table but
        # still owes the client its one response, so its id is still in use.
        if any(h.msg.id_key == msg.id_key for h in self.held_calls) \
                or any(not h.p.own and h.p.id_key == msg.id_key for h in self.held_lists):
            self._reply_client(msg, -32600, "cxbom: this request id is already pending")
            return
        super()._client_request(msg)

    def _client_tools_list(self, msg: Message, pending: Pending) -> bool:
        if not super()._client_tools_list(msg, pending):
            return False
        # The list is accepted, so its _meta is recorded now rather than
        # after this returns: the own discovery below copies it.
        self._remember_meta(msg, pending)
        self._maybe_own_discover(pending.context.get("version"))
        return True

    def _client_notification(self, msg: Message) -> None:
        if msg.method == "notifications/cancelled":
            key = id_key_from(msg.param("requestId"))
            for h in self.held_calls:
                if h.msg.id_key == key:
                    # The server never saw the held call, so the cancel stops here (spec 8.2).
                    self.held_calls.remove(h)
                    return
            # A held list's request already reached and was answered by the
            # server, so the cancel notification still passes through below.
            # Only the withheld answer must never be delivered later.
            self.held_lists = [h for h in self.held_lists if h.p.id_key != key]
        super()._client_notification(msg)

    def _server_notification(self, msg: Message) -> None:
        super()._server_notification(msg)
        if msg.method == "notifications/tools/list_changed" and self.server_line_written \
                and not self.attestation_down:
            if self._relist_chain is not None:
                self._relist_queued = True
            else:
                self._start_relist()

    def _server_response(self, msg: Message) -> None:
        kind, value = msg.id_key
        if kind == "string" and value.startswith(PROXY_ID_PREFIX) and self.pending.get(C2S, msg.id_key) is None:
            # Nothing is pending under a proxy-owned id here, so this is a
            # duplicate or unsolicited answer to a discovery or listing
            # request the proxy already resolved (or never sent). Observe
            # mode's unmatched-response path would otherwise stamp and
            # forward it. A proxy request's response must never reach the
            # client, in either mode (review minor 9 from Task 7).
            self._diagnostic("server sent an extra response to a proxy request id. Dropped")
            return
        super()._server_response(msg)

    def _server_unparseable(self, reason: str, raw: bytes | None) -> None:
        try:
            super()._server_unparseable(reason, raw)
        finally:
            if self.enforce:
                held, self.held_lists = self.held_lists, []
                for h in held:
                    self._fail_client(h.p, "cxbom: the server sent an unparseable message")
                self.own_discover = None
                self._relist_chain = None
                self._relist_queued = False
                self._relist_retry = None
                self._fail_held_calls("attestation-io" if self.attestation_down else "strict-parse")

    def _discover_result(self, p: Pending, msg: Message) -> None:
        super()._discover_result(p, msg)
        if p is self.own_discover:
            self.own_discover = None
            held, self.held_lists = self.held_lists, []
            for h in held:
                self._tools_list_result(h.p, h.msg)

    def _tools_list_result(self, p: Pending, msg: Message) -> None:
        if self._relist_chain is not None and p.chain is not None and p.chain >= self._relist_chain:
            # A page of the relist chain or of a chain that supersedes it is
            # progress, so a relist paging through a large listing is not
            # abandoned by tick() as silent.
            self._relist_progress_at = self.clock()
        if msg.kind != "error" and not self.server_line_written and self.own_discover is not None:
            self.held_lists.append(HeldList(p, msg, self.clock()))
            return
        super()._tools_list_result(p, msg)

    def _list_failed(self, p: Pending, message: str | None, raw: bytes | None) -> None:
        super()._list_failed(p, message, raw)
        if p.own:
            self._fail_chain_calls(p.chain, "relist-failed")
        elif p.chain is not None:
            # A client listing chain can supersede the relist too.
            self._relist_settled(failed=p.chain)

    def _commit_tools(self, p: Pending, msg: Message, result: Node, tools: Node) -> list[int]:
        completed = self.chains.completed_latest
        keep = super()._commit_tools(p, msg, result, tools)
        if self.chains.completed_latest != completed:
            self._resolve_held_calls(self.chains.completed_latest)
            self._relist_settled()
        return keep

    def _forward_list(self, p: Pending, msg: Message, result: Node, tools: Node, keep: list) -> None:
        if not p.own:
            super()._forward_list(p, msg, result, tools, keep)
            return
        nxt = result.get("nextCursor")
        if nxt is None or nxt.kind != "string" or p.chain != self.chains.latest:
            return
        cursor = nxt.value
        seen = self._chain_cursors.setdefault(p.chain, set())
        if cursor in seen or self._chain_pages.get(p.chain, 1) >= MAX_CHAIN_PAGES:
            # A repeated cursor is a loop, and a page count at the cap is
            # either a loop this check has not caught yet or a listing too
            # large to trust. Either way the chain fails rather than
            # continuing to page forever.
            self._fail_chain_calls(p.chain, "relist-failed")
            return
        seen.add(cursor)
        self._chain_pages[p.chain] = self._chain_pages.get(p.chain, 1) + 1
        self._own_request("tools/list", {"cursor": cursor}, chain=p.chain, cursor=cursor)


_REDACT_TOKENS = (re.compile(r"[A-Za-z0-9_\-+/=.~:@]+"), re.compile(r"[A-Za-z0-9_\-]+"))
CANARY = "<canary>"


def _shape_windows(value: str) -> Iterator[str]:
    """The SHAPE_LEN characters starting at every occurrence of the canary's prefix.

    Every canary of the J2 shape starts with SHAPE_PREFIX, so the set of places
    a canary can start is the set of places the prefix occurs, whatever sits on
    either side. A maximal token run cannot say that: a canary glued to a
    letter, a digit, `-` or `_` is one longer run whose hash is not the
    canary's, and that run is what this closes. The search steps one character
    at a time, so no occurrence is skipped even where two prefixes overlap. The
    prefix's first character occurs in it only at index 0, so two occurrences
    never overlap anyway (see canary.SHAPE_PREFIX), and the one-character step
    needs no proof to be complete. The cost is one SHA-256 over SHAPE_LEN bytes
    per occurrence of the prefix, so it stays linear.
    """
    at = value.find(SHAPE_PREFIX)
    while at >= 0:
        yield value[at:at + SHAPE_LEN]
        at = value.find(SHAPE_PREFIX, at + 1)


def redact(value: object, hashes: frozenset) -> object:
    """Replace any string that is, or contains, a redacted SHA-256 preimage.

    Hashing every substring is quadratic, so containment is checked over three
    candidate sets. The shape windows find a canary of the J2 shape at any
    offset, glued to anything. The whole string and its maximal runs of token
    characters find any other preimage a caller keyed, in a URL, a path, or a
    query string, where it stands as its own run.
    """
    if not hashes:
        return value
    if isinstance(value, str):
        candidates = {value}
        candidates.update(_shape_windows(value))
        for pattern in _REDACT_TOKENS:
            candidates.update(pattern.findall(value))
        if any(sha256_hex(c.encode("utf-8")) in hashes for c in candidates):
            return CANARY
        return value
    if isinstance(value, dict):
        return {redact(k, hashes): redact(v, hashes) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, hashes) for v in value]
    return value


# The free-text fields of a sidecar event's data, the only ones scrubbed.
# Identifier fields (serverId, tool, method, rpcId, item, the hashes) are
# matched against other records, so a scrub rewrite would break the match.
_FREE_TEXT_FIELDS = frozenset({"summary", "reason", "descriptionDiff"})
# Schema maxLength per (event type, field), applied last.
_FIELD_CAPS = {("mcp_message", "summary"): 200, ("launch_refused", "reason"): 512}
# Display bounds per (event type, field) for a value emitted as a finished
# string, applied after scrubbing and before the cap, for the same reason the
# cap waits: redaction and the scrubber have to see the text whole. The core
# emits descriptionDiff as a DescriptionChange, rendered above instead.
_FIELD_DISPLAY = {("tool_swapped", "descriptionDiff"): bound_diff_for_display}
# Stands in for a whole identifier that carries a home path, the user, the
# host, or an IP (a client can send any string as a tool name or an id).
# Nothing an event writes may carry those (spec 3), and a partial rewrite
# would leave a value that looks like a real identifier but matches nothing.
WITHHELD = "<withheld>"


def _event_data(type_: str, data: dict, hashes: frozenset, scrub) -> dict:
    """data as written to the sidecar: redact, then scrub free text, then bound for display, then cap.

    Redaction sees the whole text, so a canary that straddles a cap is still
    matched whole, and the cap runs after scrubbing, so a scrub rewrite
    cannot push a field past its schema maxLength. The display bound sits
    between them for the first reason: a line it cuts or escapes has already
    been redacted and scrubbed whole. A DescriptionChange is rendered by
    render_description_diff, which runs the same order on the two raw
    descriptions before any line exists. An identifier is never rewritten in
    part. One the scrubber would change is withheld whole.
    """
    out = dict(redact(data, hashes))
    for key, value in out.items():
        if isinstance(value, DescriptionChange):
            # Redacts and scrubs both descriptions before it splits or marks a line.
            out[key] = render_description_diff(value, hashes, scrub)
            continue
        if isinstance(value, str) and scrub is not None:
            if key in _FREE_TEXT_FIELDS:
                value = scrub(value)
            elif scrub(value) != value:
                value = WITHHELD
        display = _FIELD_DISPLAY.get((type_, key))
        if display is not None and isinstance(value, str):
            value = display(value)
        cap = _FIELD_CAPS.get((type_, key))
        out[key] = value if cap is None or not isinstance(value, str) else value[:cap]
    return out


class EventSinkError(RuntimeError):
    """The --events sidecar path is not a plain file this process can safely append to."""


class EventSink:
    """C2 1.2.0 sidecar writer for --events (spec 8.7).

    emit() never blocks: the queue is bounded, and a full queue drops the
    event. Attestation lines never pass through here. localSeq is assigned
    when a line is written, so dropped events leave no gap.

    dropped is accepted minus delivered, by construction. accepted counts
    every event handed to emit() or emit_pre_session(). delivered counts
    only lines confirmed on disk whole, closing newline included. No drop
    path counts itself, so a new or forgotten path cannot leave a loss
    uncounted: a full queue, an emit after close, a failed, short, or
    unserializable write, the backlog at close, and the event the writer
    holds when close stops waiting for it are all simply never delivered.
    close() waits at most CLOSE_BUDGET_S for the writer, then abandons it:
    after that the writer starts no write and confirms no delivery, so the
    count close() leaves is final. It can be high by the one line a stalled
    write lands after that, never low. An emit() after close() still raises
    the in-memory count, but no path in this module emits once a session's
    count is logged. Only integers are kept, never an event.

    Opening is O_NONBLOCK | O_NOFOLLOW so a FIFO with no reader or a symlink
    at the path fails fast instead of blocking __init__ forever or writing
    through a link an attacker controls. Once fstat confirms a regular file,
    the descriptor is put back into blocking mode for normal writes.
    """

    # The MCP SDK's stdio_client closes the server's stdin, waits 2.0 s, then
    # sends SIGTERM (then SIGKILL 2.0 s later). One second leaves the count
    # line and end that follow close() a full second of margin inside that.
    CLOSE_BUDGET_S = 1.0

    def __init__(self, path: Path, proxy_session_id: str, redact_sha256: Iterable[str] = (),
                 maxsize: int = 1024, clock=time.monotonic, scrub=None):
        name = Path(path).name
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC |
                         os.O_NONBLOCK | os.O_NOFOLLOW, 0o600)
        except OSError as e:
            raise EventSinkError(f"cxbom: cannot open sidecar {name}: {e.strerror or e}") from None
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise EventSinkError(f"cxbom: sidecar {name} is not a regular file")
        os.set_blocking(fd, True)
        self._fd = fd
        self._q: queue.Queue = queue.Queue(maxsize)
        self._psid = proxy_session_id
        self._hashes = frozenset(redact_sha256)
        self._scrub = scrub
        self._clock = clock
        self._t0 = clock()
        self._seq = 0
        # True while the sidecar's last bytes are a fragment a short write
        # left, its newline not yet written. _torn_whole is True when that
        # fragment is the whole JSON object, so the newline that closes it
        # delivers the event instead of ending a refused line.
        self._torn = False
        self._torn_whole = False
        # Emitters and the writer thread both touch the counts, and += on an
        # attribute is a read then a write, so they share one lock. The lock
        # also orders a delivery against close() abandoning the writer.
        self._count_lock = threading.Lock()
        self._accepted = 0
        self._delivered = 0
        self._abandoned = False
        self._started = False
        self._closing = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cxbom-events", daemon=True)

    @property
    def dropped(self) -> int:
        with self._count_lock:
            return self._accepted - self._delivered

    def bind(self, proxy_session_id: str) -> None:
        """Set the session id before start().

        run() opens the sidecar before the attestation log exists, so a bad
        --events path is refused without leaving a session log behind, and
        only then learns the proxySessionId the log assigns.
        """
        if self._started:
            raise RuntimeError("bind() must come before start()")
        self._psid = proxy_session_id

    def set_scrubber(self, scrub) -> None:
        """Replace the scrubber before start().

        The sink opens before the lock directory is known, so run() hands it
        the scrubber rebuilt with the lock directory once startup succeeds.
        """
        if self._started:
            raise RuntimeError("set_scrubber() must come before start()")
        self._scrub = scrub

    def start(self) -> None:
        self._started = True
        self._thread.start()

    def _accept(self) -> None:
        with self._count_lock:
            self._accepted += 1

    def emit(self, type_: str, data: dict) -> None:
        self._accept()
        if self._closing.is_set():
            return
        item = (type_, data, now_rfc3339(), round(max(0.0, self._clock() - self._t0), 6))
        try:
            self._q.put_nowait(item)
        except queue.Full:
            return  # never delivered, so dropped already counts it

    def emit_pre_session(self, type_: str, data: dict) -> None:
        """Write one line for a refusal before any proxy session opens (C2 1.2.0).

        proxySessionId is null and localSeq is 0, the envelope contracts.py
        requires for a pre-session line. Written synchronously, the same way
        _drain writes a line, because the writer thread never starts for a
        startup refusal: the proxy exits right after. Must be the only call
        this instance ever makes, and only before start().

        A line that is not delivered counts in dropped, but a startup refusal
        opens no attestation log, so that count is recorded nowhere. The
        refusal itself still reaches stderr and the exit code (2), so the only
        loss is the dashboard's copy of it.

        _event_data redacts the untruncated data first, so a canary is
        matched whole even when it sits past where the 512-character cap on a
        launch_refused reason would otherwise fall.
        """
        if self._started:
            raise RuntimeError("emit_pre_session() must come before start()")
        self._accept()
        processed = _event_data(type_, data, self._hashes, self._scrub)
        line = {"v": 1, "at": now_rfc3339(), "mono": round(max(0.0, self._clock() - self._t0), 6),
                "proxySessionId": None, "localSeq": 0, "type": type_, "data": processed}
        self._put_line(json_bytes(line) + b"\n")

    def close(self, timeout: float = CLOSE_BUDGET_S) -> None:
        """Stop the writer, waiting at most timeout seconds, then leave dropped final.

        The writer thread owns the descriptor: it is the only thing that
        calls os.close, in its own finally block, so a slow writer never
        races this method's caller over the same fd. Setting _closing first
        means a concurrent emit() never queues behind the shutdown sentinel.
        A second call waits out whatever budget an interrupted first call
        did not, so dropped is final after any close() that returns.
        """
        first = not self._closing.is_set()
        self._closing.set()
        if not self._started:
            # _run() never got to own the descriptor, so nothing else will
            # close it.
            if first:
                os.close(self._fd)
            return
        if first:
            try:
                self._q.put_nowait(None)
            except queue.Full:
                pass  # _drain() stops on its own once _closing is set and the queue is empty
        with self._count_lock:
            if self._abandoned:
                return
        self._thread.join(timeout)
        with self._count_lock:
            # Past this point the writer confirms nothing more, so what it
            # holds and what is still queued stay counted as dropped.
            self._abandoned = self._thread.is_alive()

    def _run(self) -> None:
        try:
            self._drain()
        finally:
            os.close(self._fd)

    def _drain(self) -> None:
        while not self._abandoned:
            try:
                # Once closing, take only what is already queued: waiting on
                # an empty queue would spend close()'s budget on nothing.
                item = self._q.get_nowait() if self._closing.is_set() else self._q.get(timeout=0.2)
            except queue.Empty:
                if self._closing.is_set():
                    break
                continue
            if item is None:
                break
            type_, data, at, mono = item
            # Any failure costs this one event, which stays undelivered, and
            # never the writer thread: a writer that died here would leave
            # every later event unwritten.
            try:
                # A line written after an unclosed fragment would glue onto
                # it, so an event that meets one stays undelivered.
                if not self._close_fragment():
                    continue
                line = {"v": 1, "at": at, "mono": mono, "proxySessionId": self._psid, "localSeq": self._seq,
                        "type": type_, "data": _event_data(type_, data, self._hashes, self._scrub)}
                self._put_line(json_bytes(line) + b"\n")
            except Exception:  # noqa: BLE001 - see the comment above
                continue
        self._close_fragment()

    def _put_line(self, raw: bytes) -> None:
        """Write one line in one os.write. Confirm it only when every byte, newline included, landed.

        A short write is never resent. The only follow-up write is the lone
        newline that closes the fragment, so every event ends as exactly one
        of three things on disk: a whole line, one refused fragment line, or
        nothing. A resent remainder could itself land short and leave a
        fragment that is neither.
        """
        if self._abandoned:
            return
        try:
            written = os.write(self._fd, raw)
        except OSError:
            return  # a write that raised put nothing on disk
        if written == len(raw):
            self._confirm()
        elif written > 0:
            self._torn = True
            self._torn_whole = written == len(raw) - 1
            self._close_fragment()

    def _close_fragment(self) -> bool:
        """Write the one newline a short write left off. True once the sidecar ends on a line boundary.

        A fragment holding the whole object becomes a whole line here, and
        its event is delivered once, now. Any shorter fragment becomes a
        refused line, and its event stays undelivered.
        """
        if not self._torn:
            return True
        if self._abandoned:
            return False
        try:
            if os.write(self._fd, b"\n") != 1:
                return False
        except OSError:
            return False
        self._torn = False
        if self._torn_whole:
            self._confirm()
        return True

    def _confirm(self) -> None:
        # localSeq advances with every line that landed whole, so the next
        # line continues it without a gap or a repeat. An abandoned writer
        # confirms nothing: close() has already handed its count over.
        self._seq += 1
        with self._count_lock:
            if not self._abandoned:
                self._delivered += 1


# ----- process: startup, relay threads, shutdown (spec 8.1, 8.8) ---------------------

EXIT_REFUSED = 2
EXIT_INTERNAL = 70
# Bytes a LineWriter may hold unwritten. Two maximum-size lines fit, so one
# oversized result never trips it on an idle stream, but a peer that stops
# reading while the other side keeps talking ends the session (exit 70)
# instead of growing the queue without limit.
WRITER_BUDGET = 2 * 64 * 1024 * 1024
_TICK_S = 0.2
_STDERR_MAX_LINE = 64 * 1024
_SERVER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DOCKER_DESKTOP_FS = frozenset({"fakeowner", "grpcfuse", "fuse.grpcfuse", "virtiofs", "osxfs", "9p"})
_IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\.?[0-9])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
                   r"|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)"
                   r"(?![0-9A-Za-z:])")


class StartupRefused(RuntimeError):
    """A spec 8.1 startup check failed. The proxy exits 2 without spawning anything."""


def os_message(e: OSError) -> str:
    """An OSError as file name plus reason, never an absolute path (anonymity)."""
    name = Path(e.filename).name if e.filename else "file"
    return f"{name}: {e.strerror or type(e).__name__}"


@dataclass(frozen=True)
class ProxyOptions:
    server_id: str
    command: list
    lock: str | None = None
    mode: str = "enforce"
    state_dir: str | None = None
    events: str | None = None
    redact_sha256: tuple = ()


def docker_desktop_shared(path: Path, mountinfo: str | None = None) -> bool:
    """True when path sits on a Docker Desktop host share (spec 8.1 step 3)."""
    if mountinfo is None:
        if not sys.platform.startswith("linux"):
            return False
        try:
            mountinfo = Path("/proc/self/mountinfo").read_text()
        except OSError:
            return False
    target = os.path.realpath(path)
    best, fstype = "", None
    for line in mountinfo.splitlines():
        left, sep, right = line.partition(" - ")
        fields = left.split()
        if not sep or len(fields) < 5 or not right.split():
            continue
        mount_point = fields[4].replace("\\040", " ")
        inside = target == mount_point or target.startswith(mount_point.rstrip("/") + "/")
        if inside and len(mount_point) >= len(best):
            best, fstype = mount_point, right.split()[0]
    return fstype in _DOCKER_DESKTOP_FS


def _word(text: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(text) + r"(?![A-Za-z0-9])", re.IGNORECASE)


class Scrubber:
    """Rewrites absolute paths, the user, the host, and IP addresses in text the proxy prints (spec 3).

    Paths go first, longest first, so a lock directory under the home
    directory becomes "." rather than "~/...". The word rules run after,
    so the user name inside a temp path such as pytest-of-<user> is still
    caught. The word rules can over-match (a user named "dev" turns every
    standalone "dev" into "<user>"), which costs readability on stderr and
    never anonymity.
    """

    def __init__(self, lock_dir: Path | None, cwd: Path):
        pairs = [(str(paths.pw_dir()), "~"), (str(cwd), "."), (tempfile.gettempdir(), "<tmp>")]
        if lock_dir is not None:
            pairs.append((str(lock_dir), "."))
        for p, label in list(pairs):
            real = os.path.realpath(p)
            if real != p:
                pairs.append((real, label))
        self._pairs = sorted(((p, label) for p, label in pairs if p not in ("", "/")), key=lambda x: -len(x[0]))
        words: list[tuple[re.Pattern, str]] = []
        try:
            host = socket.gethostname()
        except OSError:
            host = ""
        for name in sorted({host, host.split(".")[0]}, key=len, reverse=True):
            if name and name.lower() != "localhost":
                words.append((_word(name), "<host>"))
        try:
            pw = pwd.getpwuid(os.getuid())
        except KeyError:
            pw = None
        if pw is not None:
            full = pw.pw_gecos.split(",")[0].strip()
            if len(full) >= 4:
                words.append((_word(full), "<user>"))
            if pw.pw_name:
                words.append((_word(pw.pw_name), "<user>"))
        self._words = words

    def __call__(self, text: str) -> str:
        for p, label in self._pairs:
            text = text.replace(p, label)
        for pattern, label in self._words:
            text = pattern.sub(label, text)
        text = _IPV6.sub("<ip>", text)
        return _IPV4.sub("<ip>", text)


@dataclass
class _Started:
    verified: object
    plan: launch.LaunchPlan
    writer: attestation.AttestationWriter
    store: Store
    events: EventSink | None


def _open_events(opts: ProxyOptions, scrub) -> EventSink | None:
    if opts.events is None:
        return None
    try:
        # The session id is bound once the attestation log assigns it.
        return EventSink(Path(opts.events), "", opts.redact_sha256, scrub=scrub)
    except EventSinkError as e:
        text = str(e)
        raise StartupRefused(text[len("cxbom: "):] if text.startswith("cxbom: ") else text) from None


def _refuse_launch(events: EventSink | None, server_id: str, item: str, reason: str) -> None:
    """Write the one launch_refused sidecar line for a pre-session startup refusal (C2 1.2.0).

    Called from inside _startup, right before it re-raises the LockError or
    LaunchError that caused the refusal, so the caller's usual conversion to
    StartupRefused and its events.close() still run unchanged. A no-op when
    --events was never given. reason is passed through raw: emit_pre_session
    does its own redact-then-scrub-then-cap, in that order, on the full text.
    """
    if events is None:
        return
    events.emit_pre_session("launch_refused", {"serverId": server_id, "item": item, "reason": reason, "exitCode": 2})


def _startup(opts: ProxyOptions, config_dir: Path | None, environ: dict, cwd: Path, scrub) -> _Started:
    events = None
    try:
        paths.check_home_env(environ)
        if not _SERVER_ID.match(opts.server_id):
            raise StartupRefused("--server-id must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
        if opts.mode not in ("enforce", "observe"):
            raise StartupRefused("--mode must be enforce or observe")
        if not opts.command:
            raise StartupRefused("no server command after --")
        bad = [h for h in opts.redact_sha256 if not _HEX64.match(h)]
        if bad:
            raise StartupRefused("--redact-sha256 takes 64 lowercase hex characters")
        config = config_dir if config_dir is not None else paths.config_dir()
        if not os.path.lexists(config) or not os.path.lexists(config / signing.MANIFEST_FILE):
            raise StartupRefused("no signing key or trust manifest. Run cxbom keygen first")
        trusted = signing.load_trusted(config)
        if opts.state_dir is not None:
            state_root = Path(opts.state_dir)
            if paths.inside_git_worktree(state_root):
                raise StartupRefused("--state-dir is inside a git worktree")
        else:
            state_root = paths.state_dir()
        paths.ensure_private_dir(state_root)
        if docker_desktop_shared(state_root):
            raise StartupRefused("the state directory is a Docker Desktop host share")
        lock_path = lockfile.find_lock(cwd, Path(opts.lock) if opts.lock else None, environ)
        lock = lockfile.read_lock(lock_path)
        # The sidecar opens here, before the entry and launch checks that can
        # name a launch item, so a refusal from either can log one
        # launch_refused line to it before the proxy exits (C2 1.2.0). It
        # still opens before the attestation log, so a bad --events path (a
        # FIFO, a symlink, a directory) is refused with no session log left
        # behind, the same as every other startup refusal, and with no
        # launch_refused line either: events is None on that path.
        events = _open_events(opts, scrub)
        try:
            verified = lockfile.verified_entry(lock, opts.server_id, trusted, state_root,
                                               datetime.now(timezone.utc), update_highwater=True)
        except lockfile.LockError as e:
            _refuse_launch(events, opts.server_id, "entry", str(e))
            raise
        if opts.mode == "observe" and not verified.entry["allowObserve"]:
            raise StartupRefused("--mode observe requires allowObserve in the signed entry")
        try:
            plan = launch.check_launch(verified.entry, opts.command, lock_path.resolve().parent, environ,
                                       opts.server_id)
        except launch.LaunchError as e:
            # item is None only when a LaunchError reaches here from
            # somewhere check_launch does not itself instrument: a bug, not a
            # launch refusal. There is no item to report, so this is left to
            # fall through as an internal error (exit 70) below, rather than
            # mislabeled with a guessed item such as "policy".
            if e.item is not None:
                _refuse_launch(events, opts.server_id, e.item, str(e))
            raise
        store = Store(state_root / "store")
        writer = attestation.AttestationWriter(state_root / "attest", opts.server_id, {
            "contract": {"name": "cxbom-attestation", "version": "2.0.0"}, "serverId": opts.server_id,
            "mode": opts.mode, "startedAt": now_rfc3339(), "pid": os.getpid(),
            "envelopeSha256": verified.envelope_sha256, "keyFingerprint": verified.fingerprint,
            "launchSha256": plan.launch_sha256})
    except BaseException as e:
        if events is not None:
            events.close()
        if isinstance(e, OSError):
            raise StartupRefused(os_message(e)) from None
        if isinstance(e, launch.LaunchError) and e.item is None:
            # Not a launch refusal check_launch itself raised (see above): an
            # internal error, so it propagates unconverted. run() reports it
            # as exit 70, the same as any other unexpected exception here.
            raise
        if isinstance(e, (paths.PathSecurityError, signing.SigningError, lockfile.LockError, launch.LaunchError,
                          StoreError, attestation.AttestationIOError)):
            raise StartupRefused(str(e)) from None
        raise
    if events is not None:
        events.bind(writer.proxy_session_id)
    return _Started(verified, plan, writer, store, events)


# The attestation diagnostic that carries a session's final sidecar drop
# count. Only this fixed text and an integer are ever written, never an
# event, so nothing a peer sent can reach the log through it.
DROPPED_DIAGNOSTIC = "sidecar events dropped: "


class _StopSignalsHeld:
    """Hold off SIGTERM and SIGINT while a session's last lines are written.

    The MCP SDK's stdio_client sends SIGTERM to the whole process group 2.0 s
    after it closes the proxy's stdin. Under the default action that signal
    would kill the proxy between the sidecar's close and end, leaving a log
    with neither the count nor end. The handler here swaps the process-wide
    disposition, not a thread mask: a process-directed signal goes to any
    thread that does not block it, so blocking it in the main thread alone
    would still let the relay or writer threads take the default action.
    A signal that arrives is dropped, not replayed afterwards, because it asks
    the proxy to stop and the proxy already is stopping: every caller of
    _end_session goes straight on to stop the child and exit. The hold lasts
    as long as close() (at most EventSink.CLOSE_BUDGET_S) plus two log
    writes, so SIGKILL, which no handler can catch, still ends a proxy that
    hangs past that. Signal handlers can be set only from the main thread,
    so on any other thread this holds nothing, and every caller in this
    module runs on the main thread.
    """

    _SIGNALS = (signal.SIGTERM, signal.SIGINT)

    def __enter__(self):
        self._previous = {}
        if threading.current_thread() is threading.main_thread():
            self._previous = {s: signal.signal(s, lambda signum, frame: None) for s in self._SIGNALS}
        return self

    def __exit__(self, *exc) -> None:
        for s, h in self._previous.items():
            signal.signal(s, h)


def _end_session(writer: attestation.AttestationWriter, events: EventSink | None, reason: str) -> None:
    """Close the sidecar, log its drop count, then write end (C3 2.0.0 has no field for it on end).

    close() runs first so the count is final: close() gives the writer at
    most EventSink.CLOSE_BUDGET_S and then counts whatever it has not
    confirmed. A session with a sidecar always gets the line, 0 included, so
    for such a session a log with neither the line nor end was cut short, a
    killed proxy for one. Stop signals are held for the whole of it (see
    _StopSignalsHeld). The caller must make sure nothing emits once this
    starts: _serve holds the relay lock with done set, and _serve's own
    exception path stops the pumps before run() gets here. A log that is
    already ended (the core's attestation-io, or a second call from run()'s
    exception paths) makes the append raise AttestationIOError, and the
    caller treats that as it treats any other failed write. Raises
    AttestationIOError when either write fails. A failed diagnostic write
    still ends the log with attestation-io.
    """
    with _StopSignalsHeld():
        if events is not None:
            events.close()
            try:
                writer.append("diagnostic", message=f"{DROPPED_DIAGNOSTIC}{events.dropped}")
            except attestation.AttestationIOError:
                writer.end("attestation-io")
                raise
        writer.end(reason)


def exit_code(reason: str, child_status: int) -> int:
    if reason in ("internal-error", "attestation-io"):
        return EXIT_INTERNAL
    return launch.exit_status(child_status)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def run(opts: ProxyOptions, *, config_dir: Path | None = None, environ: dict | None = None,
        cwd: Path | None = None, stdin_fd: int = 0, stdout_fd: int = 1, stderr_fd: int = 2) -> int:
    environ = dict(os.environ) if environ is None else environ
    cwd = Path.cwd() if cwd is None else cwd
    scrub = Scrubber(None, cwd)

    def say(message: str) -> None:
        try:
            _write_all(stderr_fd, (scrub(f"cxbom proxy: {message}") + "\n").encode("utf-8", "replace"))
        except OSError:
            pass

    try:
        started = _startup(opts, config_dir, environ, cwd, scrub)
    except StartupRefused as e:
        say(str(e))
        return EXIT_REFUSED
    except Exception as e:
        # Only the exception type: its text could carry a path or a value
        # the proxy has not vetted.
        say(f"internal error during startup ({type(e).__name__})")
        return EXIT_INTERNAL
    scrub = Scrubber(started.plan.lock_dir, cwd)
    if started.events is not None:
        started.events.set_scrubber(scrub)
    writer = started.writer
    # The watchdog and the child start here, from the main thread, before any
    # other thread exists (spec 8.1 step 4). EventSink's thread is created
    # but not started, so it does not count.
    try:
        child = launch.spawn(started.plan)
    except launch.LaunchError as e:
        try:
            _end_session(writer, started.events, "internal-error")
        except attestation.AttestationIOError:
            pass
        writer.close()
        say(str(e))
        # The log already says internal-error, so the exit code agrees with
        # it (spec 8.8): the launch checks passed, and the spawn itself failed.
        return EXIT_INTERNAL
    try:
        reason, status = _serve(opts, started, child, scrub, stdin_fd, stdout_fd, stderr_fd)
    except KeyboardInterrupt:
        # _serve installs its own SIGINT handler (spec 8.8's signal path),
        # but only once it starts relaying. A SIGINT in the narrow window
        # between spawn and that point, or delivered to a thread that has
        # not yet swapped Python's default handler in, still raises here
        # instead. Treated the same as a caught signal: write end, stop the
        # child. If attestation already ended (down before the interrupt),
        # end("signal") itself raises and the reason falls back to that.
        try:
            _end_session(writer, started.events, "signal")
            reason = "signal"
        except attestation.AttestationIOError:
            reason = "attestation-io"
        status = child.stop()
    except Exception as e:
        say(f"internal error ({type(e).__name__})")
        try:
            _end_session(writer, started.events, "internal-error")
        except attestation.AttestationIOError:
            pass
        reason, status = "internal-error", child.stop()
    finally:
        if started.events is not None:
            started.events.close()
        writer.close()
    return exit_code(reason, status)


def _serve(opts: ProxyOptions, started: _Started, child: launch.Child, scrub, stdin_fd: int, stdout_fd: int,
           stderr_fd: int) -> tuple[str, int]:
    """Relay until EOF, child exit, a signal, or a fatal error. Returns (end reason, child status)."""
    writer = started.writer
    lock = threading.Lock()
    done = threading.Event()
    reasons: list[str] = []

    def shutdown(reason: str) -> None:
        # The first reason wins. A signal handler can land here while a relay
        # thread is mid-call, so nothing in here takes the relay lock.
        if not reasons:
            reasons.append(reason)
        done.set()

    to_client = LineWriter(stdout_fd, "client", max_queued_bytes=WRITER_BUDGET)
    to_server = LineWriter(child.proc.stdin.fileno(), "server", max_queued_bytes=WRITER_BUDGET)
    if started.events is not None:
        started.events.start()
    core = ProxyCore(server_id=opts.server_id, mode=opts.mode, entry=started.verified.entry, log=writer,
                     store=started.store, to_client=to_client.send, to_server=to_server.send,
                     proxy_session_id=writer.proxy_session_id, events=started.events, on_fatal=shutdown,
                     scrub=scrub)

    def pump(fd: int, feed, eof_reason: str, writer_name: str) -> None:
        # Any exception here, a WriterOverflow from a peer that stopped
        # reading included, is an internal error: the session ends with
        # "internal-error" and the proxy exits 70.
        try:
            for line in read_lines(fd):
                with lock:
                    if done.is_set():
                        return
                    feed(line)
        except WriterOverflow as e:
            # Distinct from the generic internal-error case below: this one
            # has a known, sayable cause, so it goes to stderr and the
            # attestation log gets a record of why the session ended, not
            # just that it did.
            message = f"the {writer_name} writer overflowed: {e}"
            try:
                _write_all(stderr_fd, (scrub(f"cxbom proxy: {message}") + "\n").encode("utf-8", "replace"))
            except OSError:
                pass
            with lock:
                try:
                    core._diagnostic(message)
                except _AttestationDown:
                    pass
            shutdown("internal-error")
            return
        except Exception:
            shutdown("internal-error")
            return
        shutdown(eof_reason)

    def relay_stderr() -> None:
        try:
            for line in read_lines(child.proc.stderr.fileno(), max_line=_STDERR_MAX_LINE):
                if line is OVERSIZE:
                    continue
                _write_all(stderr_fd, scrub(line.decode("utf-8", "replace")).encode("utf-8") + b"\n")
        except (OSError, RelayError):
            return

    threads = [threading.Thread(target=pump, args=(stdin_fd, core.from_client, "eof", "server"), daemon=True),
               threading.Thread(target=pump,
                                args=(child.proc.stdout.fileno(), core.from_server, "child-exit", "client"),
                                daemon=True)]
    stderr_thread = threading.Thread(target=relay_stderr, daemon=True)
    previous = {s: signal.signal(s, lambda signum, frame: shutdown("signal")) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        for t in threads + [stderr_thread]:
            t.start()
        # tick() drives hold timeouts, re-list abandonment, and the pending
        # table's cancel retention, all on the core's own clock.
        while not done.wait(_TICK_S):
            with lock:
                try:
                    core.tick()
                except Exception:
                    shutdown("internal-error")
    except BaseException:
        # run() ends the session on this path, outside the relay lock. With
        # done set, a pump that takes the lock after this returns without
        # feeding the core, so nothing emits once the sidecar's count is
        # taken and the logged count cannot come out low.
        shutdown("internal-error")
        with lock:
            pass
        raise
    finally:
        for s, h in previous.items():
            signal.signal(s, h)
    reason = reasons[0]
    with lock:
        if core.attestation_down:
            # The core already ended the log with attestation-io. Enforce kept
            # running with everything blocked until now, observe stopped at
            # once. Either way the exit code matches the log's end line.
            reason = "attestation-io"
        else:
            # Under the relay lock with done set, no pump feeds the core
            # again, so nothing emits once the sidecar closes here.
            try:
                _end_session(writer, started.events, reason)
            except attestation.AttestationIOError:
                reason = "attestation-io"
    # Spec 8.8: end is written, then the child's stdin closes. The server
    # writer holds a dup of that pipe, so it must finish before Child.stop()
    # closes the original, or the child never sees EOF.
    to_server.stop(launch.WATCHDOG_GRACE_S)
    status = child.stop()
    stderr_thread.join(launch.WATCHDOG_GRACE_S)
    to_client.stop()
    return reason, status
