"""Byte-level relay for one MCP stdio session: framing, shapes, ids, writers.

Owner: ATACE Working Group.

The proxy decides on exactly the bytes the other side will parse, so every
line goes through jsonstrict and must be exactly one JSON-RPC shape (spec 3).
Nothing here re-serializes a message. A line the proxy does not rewrite
leaves as the same bytes it arrived as.

Each output stream has one LineWriter, and every line bound for that stream,
relayed or proxy-originated, goes through it (spec 8.2). The writer owns a
queue and a thread, so a handler holding the proxy's lock never blocks on a
full pipe. Blocking there would deadlock against a server that is itself
blocked writing to a pipe the proxy is not reading.

Pending requests are keyed by direction plus the exact JSON type and lexeme
of the id. The number 1 and the string "1" never match each other, and 1.0
does not match 1 (spec 8.2).
"""
from __future__ import annotations

import os
import queue
import threading
from dataclasses import dataclass, field
from typing import Iterator

from . import jsonstrict

MAX_LINE = 64 * 1024 * 1024
# An id this large buys almost nothing for a legitimate caller but lets one
# message pin an outsized share of the in-flight byte budget into the
# pending table or a held entry (spec 8.2). Refused at classify() so an
# oversized id never reaches a Pending at all.
MAX_ID_RAW = 1024
# Wire names from MCP 2026-07-28 (basic/versioning, server/discover,
# basic/transports/stdio). Modern requests carry these in params._meta.
LEGACY_VERSION = "2025-11-25"
MODERN_VERSION = "2026-07-28"
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
META_LOG_LEVEL = "io.modelcontextprotocol/logLevel"
UNSUPPORTED_PROTOCOL_VERSION = -32022
MISSING_CLIENT_CAPABILITY = -32021
SESSION_META_KEY = "org.cxbom/proxySessionId"
PROXY_ID_PREFIX = "cxbom-"
CANCEL_RETENTION_S = 30.0

C2S = "c2s"      # a request the client (or the proxy, on the client's side) sent to the server
S2C = "s2c"      # a request the server sent to the client

_REQUEST_KEYS = frozenset({"jsonrpc", "id", "method", "params"})
_NOTIFICATION_KEYS = frozenset({"jsonrpc", "method", "params"})
_RESULT_KEYS = frozenset({"jsonrpc", "id", "result"})
_ERROR_KEYS = frozenset({"jsonrpc", "id", "error"})


class Oversize:
    """Marker for a line longer than the limit. Its bytes were discarded."""

    def __repr__(self) -> str:
        return "OVERSIZE"


OVERSIZE = Oversize()


class RelayError(ValueError):
    """Base error for cxbom.relay (spec 8.2).

    Catch this alone to cover every failure the module raises directly, or
    catch a specific subclass such as ShapeError or DuplicateId.
    """


class ShapeError(RelayError):
    """The line is strict JSON but not exactly one JSON-RPC 2.0 message."""


# A lone \r is legal JSON whitespace between tokens, and U+2028, U+2029, and
# U+0085 are legal, unescaped bytes inside a JSON string, so jsonstrict
# accepts a message that carries any of them. A universal-newline reader
# (Python's TextIOWrapper in text mode, Popen(text=True), str.splitlines())
# treats each of these, not only \n, as a line break. A server that places
# one of them before a second, JSON-RPC-shaped payload can hide that payload
# from the proxy's \n-only framing while a downstream text-mode reader still
# splits it out as its own line.
_LINE_TERMINATOR_SEQS = (
    b"\xe2\x80\xa8",   # U+2028 LINE SEPARATOR
    b"\xe2\x80\xa9",   # U+2029 PARAGRAPH SEPARATOR
    b"\xc2\x85",       # U+0085 NEXT LINE
)


def _refuse_smuggled_line_terminators(raw: bytes) -> None:
    """Raise ShapeError if raw hides a line break a text-mode reader would act on.

    A trailing \\r is allowed, matching a server that frames its lines with
    CRLF. Any other \\r, and any occurrence of a Unicode line terminator, is
    refused.
    """
    if b"\r" in raw[:-1]:
        raise ShapeError("line contains a carriage return that is not the final byte")
    for seq in _LINE_TERMINATOR_SEQS:
        if seq in raw:
            raise ShapeError("line contains a Unicode line-terminator character")


def _is_blank(line: bytes) -> bool:
    """A line is blank only if it is empty, or empty once a trailing \\r is removed.

    A line made only of other whitespace, such as a bare space or tab, is
    not blank. It is handed on so the caller's JSON parser reports the
    failure, the same way it reports any other unparseable line.
    """
    if line.endswith(b"\r"):
        line = line[:-1]
    return line == b""


def read_lines(fd: int, max_line: int = MAX_LINE, chunk: int = 65536) -> Iterator[bytes | Oversize]:
    buf = bytearray()
    discarding = False
    while True:
        try:
            data = os.read(fd, chunk)
        except OSError as e:
            raise RelayError(f"read failed: {e.strerror or e}") from None
        if not data:
            break
        start = 0
        while True:
            nl = data.find(b"\n", start)
            if nl < 0:
                if not discarding:
                    buf += data[start:]
                    if len(buf) > max_line:
                        buf.clear()
                        discarding = True
                break
            if discarding:
                discarding = False
                yield OVERSIZE
            else:
                buf += data[start:nl]
                if len(buf) > max_line:
                    yield OVERSIZE
                elif not _is_blank(buf):
                    yield bytes(buf)
                buf.clear()
            start = nl + 1
    if discarding:
        yield OVERSIZE
    elif not _is_blank(buf):
        yield bytes(buf)


class WriterOverflow(RelayError):
    """A LineWriter's queue would exceed its byte budget. The caller drops the connection."""


class LineWriter:
    """The single writer for one output stream. send() never blocks on I/O.

    __init__ dups fd and writes only to the dup, forced into blocking mode.
    The dup keeps working after the caller closes its own fd, and it stays
    immune to that fd number's later reuse. Without the dup, a writer
    thread still blocked in os.write() when stop() times out could resume
    after the caller closed and reopened that fd number for an unrelated
    file, and write a stale queued line into it. Forcing the dup blocking
    matters when the caller's own fd is non-blocking: the writer thread
    wants to block until a line is fully written, not raise on EAGAIN and
    drop the rest of the queue.

    With max_queued_bytes set, send() raises WriterOverflow instead of
    queuing a line that would push the unwritten bytes over the budget.
    Blocking there instead would stall the proxy's lock holder, which is
    the deadlock the queue exists to avoid.
    """

    def __init__(self, fd: int, name: str, max_queued_bytes: int | None = None):
        self._dup = os.dup(fd)
        os.set_blocking(self._dup, True)
        self._q: queue.SimpleQueue = queue.SimpleQueue()
        self.error: OSError | None = None
        self._stopped = False
        # None keeps the queue unbounded (tests and short-lived tools). The
        # proxy passes a budget so a peer that stops reading cannot make the
        # queue grow until the process runs out of memory.
        self._budget = max_queued_bytes
        self._queued = 0
        self._count_lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name=f"cxbom-writer-{name}", daemon=True)
        self._thread.start()

    def send(self, line: bytes) -> None:
        if self._stopped:
            raise RelayError("LineWriter.send() called after stop()")
        if b"\n" in line:
            raise RelayError("a relayed line must not contain a newline")
        data = bytes(line)
        with self._count_lock:
            if self._budget is not None and self._queued + len(data) > self._budget:
                raise WriterOverflow("the peer is not reading. The output queue is over its byte budget")
            self._queued += len(data)
        self._q.put(data)

    def stop(self, timeout: float = 5.0) -> bool:
        """Write every queued line, then stop. The caller owns and closes its fd.

        Returns True if the queue drained and the writer thread ended
        within timeout, False if the thread is still running, for example
        still blocked writing to a full pipe nobody reads.
        """
        self._stopped = True
        self._q.put(None)
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def _run(self) -> None:
        try:
            while True:
                item = self._q.get()
                if item is None:
                    return
                if self.error is None:
                    view = memoryview(item + b"\n")
                    try:
                        while view:
                            n = os.write(self._dup, view)
                            view = view[n:]
                    except OSError as e:
                        self.error = e
                # Written, or dropped because the peer is gone: either way the
                # line no longer counts against the budget.
                with self._count_lock:
                    self._queued -= len(item)
        finally:
            os.close(self._dup)


@dataclass(frozen=True)
class Message:
    raw: bytes
    node: jsonstrict.Node
    kind: str                      # request, notification, result, error
    method: str | None
    id_key: tuple | None
    id_raw: bytes | None

    @property
    def params(self) -> jsonstrict.Node | None:
        p = self.node.get("params")
        return p if p is not None and p.kind == "object" else None

    def param(self, key: str) -> jsonstrict.Node | None:
        p = self.params
        return p.get(key) if p is not None else None

    def meta(self) -> object:
        m = self.param("_meta")
        return jsonstrict.to_python(m) if m is not None and m.kind == "object" else None

    def id_python(self) -> object:
        return jsonstrict.to_python(self.node.get("id")) if self.id_key is not None else None


def id_key_of(node: jsonstrict.Node) -> tuple:
    if node.kind == "string":
        return ("string", node.value)
    if node.kind == "number":
        return ("number", node.value)
    if node.kind == "null":
        return ("null",)
    raise ShapeError("id must be a string, a number, or null")


def classify(raw: bytes) -> Message:
    _refuse_smuggled_line_terminators(raw)
    node = jsonstrict.parse(raw)
    if node.kind != "object":
        raise ShapeError("batch" if node.kind == "array" else "message is not a JSON object")
    keys = frozenset(k for k, _kn, _vn in node.items)
    version = node.get("jsonrpc")
    if version is None or version.kind != "string" or version.value != "2.0":
        raise ShapeError("jsonrpc must be \"2.0\"")
    method = node.get("method")
    params = node.get("params")
    if params is not None and params.kind != "object":
        raise ShapeError("params must be an object")
    if method is not None:
        if method.kind != "string":
            raise ShapeError("method must be a string")
        if "id" in keys:
            if not keys <= _REQUEST_KEYS:
                raise ShapeError("unexpected member in a request")
            idn = node.get("id")
            if idn.kind not in ("string", "number"):
                raise ShapeError("request id must be a string or a number")
            id_raw = raw[idn.start:idn.end]
            if len(id_raw) > MAX_ID_RAW:
                raise ShapeError(f"request id must not exceed {MAX_ID_RAW} bytes")
            return Message(raw, node, "request", method.value, id_key_of(idn), id_raw)
        if not keys <= _NOTIFICATION_KEYS:
            raise ShapeError("unexpected member in a notification")
        return Message(raw, node, "notification", method.value, None, None)
    if "id" not in keys:
        raise ShapeError("message has neither a method nor an id")
    idn = node.get("id")
    if keys == _RESULT_KEYS:
        if idn.kind not in ("string", "number"):
            raise ShapeError("result id must be a string or a number")
        id_raw = raw[idn.start:idn.end]
        if len(id_raw) > MAX_ID_RAW:
            raise ShapeError(f"result id must not exceed {MAX_ID_RAW} bytes")
        return Message(raw, node, "result", None, id_key_of(idn), id_raw)
    if keys == _ERROR_KEYS:
        err = node.get("error")
        code = err.get("code") if err.kind == "object" else None
        text = err.get("message") if err.kind == "object" else None
        if code is None or code.kind != "number" or any(c in code.value for c in ".eE"):
            raise ShapeError("error.code must be an integer")
        if text is None or text.kind != "string":
            raise ShapeError("error.message must be a string")
        id_raw = raw[idn.start:idn.end]
        if len(id_raw) > MAX_ID_RAW:
            raise ShapeError(f"error id must not exceed {MAX_ID_RAW} bytes")
        return Message(raw, node, "error", None, id_key_of(idn), id_raw)
    raise ShapeError("a response must carry exactly one of result or error")


@dataclass
class Pending:
    direction: str
    id_key: tuple
    method: str
    own: bool = False
    chain: int | None = None
    cursor: str | None = None
    meta: object = None
    context: dict = field(default_factory=dict)
    cancelled_at: float | None = None


class DuplicateId(RelayError):
    """A request reused an id that is still pending in the same direction."""


class PendingTable:
    def __init__(self, retention: float = CANCEL_RETENTION_S):
        self._t: dict[tuple, Pending] = {}
        self._retention = retention

    def add(self, p: Pending) -> None:
        key = (p.direction, p.id_key)
        if key in self._t:
            raise DuplicateId(f"id {p.id_key!r} is already pending")
        self._t[key] = p

    def __len__(self) -> int:
        """Every entry, cancelled ones still in their retention window included."""
        return len(self._t)

    def values(self) -> Iterator[Pending]:
        """Every entry, cancelled ones still in their retention window included.

        Used for the in-flight byte total (spec 8.2): those entries still
        hold their id_raw in memory until expire() or take() removes them.
        """
        return iter(self._t.values())

    def get(self, direction: str, id_key: tuple) -> Pending | None:
        return self._t.get((direction, id_key))

    def take(self, direction: str, id_key: tuple) -> Pending | None:
        """Remove and return the entry a response answers. The caller drops it if cancelled."""
        return self._t.pop((direction, id_key), None)

    def cancel(self, direction: str, id_key: tuple, now: float) -> Pending | None:
        p = self._t.get((direction, id_key))
        if p is not None and p.cancelled_at is None:
            p.cancelled_at = now
        return p

    def expire(self, now: float) -> None:
        for key, p in list(self._t.items()):
            if p.cancelled_at is not None and now - p.cancelled_at >= self._retention:
                del self._t[key]

    def outstanding(self, direction: str) -> list[Pending]:
        return [p for p in self._t.values() if p.direction == direction and p.cancelled_at is None]

    def discard(self, p: Pending) -> None:
        self._t.pop((p.direction, p.id_key), None)


class ProxyIds:
    """Ids for proxy-originated requests: cxbom-<proxySessionId>-<n> (spec 8.2)."""

    def __init__(self, proxy_session_id: str):
        self._prefix = f"{PROXY_ID_PREFIX}{proxy_session_id}-"
        self._n = 0

    def next(self) -> str:
        self._n += 1
        return f"{self._prefix}{self._n}"
