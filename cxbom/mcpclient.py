"""Minimal dual-era MCP stdio client for approve and check-drift.

Owner: ATACE Working Group.

It only reads listings. It never calls a tool, reads a resource, or gets a
prompt (spec 7 step 4). Every line from the server goes through jsonstrict
and the relay's shape check, because approve pins what it parses and a
parser differential here would pin something the proxy later sees
differently (premortem A3).
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass

from . import jsonstrict, launch
from .proxy import is_modern_error, json_bytes
from .relay import (LEGACY_VERSION, META_CLIENT_CAPABILITIES, META_CLIENT_INFO, META_PROTOCOL_VERSION,
                    META_SERVER_INFO, MODERN_VERSION, OVERSIZE, RelayError, ShapeError, classify, read_lines)

PROBE_TIMEOUT_S = 10.0
MAX_PAGES = 1000
CLIENT_INFO = {"name": "cxbom-approve", "version": "0.3.0"}


class McpClientError(RuntimeError):
    """The server broke the protocol, answered with an error, or timed out."""


class McpTimeout(McpClientError):
    """No answer arrived in time."""


class McpRpcError(McpClientError):
    def __init__(self, method: str, error: dict):
        self.code = error.get("code")
        self.error = error
        # error.message is server-controlled and lands in this exception's
        # str(), which a CLI prints to a terminal. Every character outside
        # printable ASCII is escaped, so a C0 or C1 control, a bidi override,
        # or a zero-width character cannot reach the operator's terminal.
        message = launch.escape_for_display(str(error.get("message"))[:200])
        super().__init__(f"{method}: server error {self.code}: {message}")


@dataclass(frozen=True)
class EraSnapshot:
    era_key: str                 # "legacy" or a modern protocol version
    negotiated_version: str
    instructions: str
    server_info: dict
    tools: list


class StdioClient:
    """Requests with integer ids over a spawned child's stdio, one at a time."""

    def __init__(self, child: launch.Child, startup_timeout: float, probe_timeout: float = PROBE_TIMEOUT_S,
                 clock=time.monotonic):
        self.child = child
        self._clock = clock
        self._started = clock()
        self._startup_timeout = startup_timeout
        self._probe_timeout = probe_timeout
        self._first_byte: float | None = None
        self._q: queue.Queue = queue.Queue()
        self._next_id = 1
        # method -> callback for server-initiated notifications (JSON-RPC
        # messages with a method and no id). A caller registers a hook so it
        # can react to, for example, notifications/tools/list_changed and
        # re-list. Handlers fire on the thread that is inside request(), which
        # is where the stream is drained, so they must stay lightweight and
        # must not issue another request on this client re-entrantly.
        self._notification_handlers: dict[str, object] = {}
        self._reader = threading.Thread(target=self._read, name="cxbom-approve-reader", daemon=True)
        self._reader.start()

    def join_reader(self, timeout: float = 5.0) -> None:
        """Wait for the reader to see EOF, so the next spawn forks with no extra thread alive."""
        self._reader.join(timeout)

    def on_notification(self, method: str, handler) -> None:
        """Register handler(params) for a server-initiated notification named method.

        params is the notification's params as a dict, or None when it carries
        none. Registering the same method again replaces the handler. The hook
        only sees a notification while a request() call is draining the stream,
        so a notification that arrives with no request in flight fires on the
        next request. This keeps the single-reader/single-consumer model the
        deadline math relies on: no extra dispatch thread is introduced.
        """
        self._notification_handlers[method] = handler

    def _read(self) -> None:
        # read_lines wraps a genuine OSError from the fd as a RelayError, not
        # a bare OSError, so that is what a read failure here actually raises.
        try:
            for line in read_lines(self.child.proc.stdout.fileno()):
                if self._first_byte is None:
                    self._first_byte = self._clock()
                self._q.put(line)
        except (OSError, RelayError):
            pass
        self._q.put(None)

    def _deadline(self, sent_at: float) -> float:
        # Spec 7 step 3: a slow first start gets the startup timeout, and that
        # timeout bounds only the wait for the *first* byte. Every answer
        # after that gets its own probe timeout measured from when the server
        # last spoke (or this request was sent, if that is later), not from
        # a min() against the startup deadline: a long-running session whose
        # --startup-timeout is generous must not have every later request
        # silently capped by how long ago the process started.
        if self._first_byte is None:
            return self._started + self._startup_timeout
        return max(self._first_byte, sent_at) + self._probe_timeout

    def _send(self, obj: dict) -> None:
        try:
            self.child.proc.stdin.write(json_bytes(obj) + b"\n")
            self.child.proc.stdin.flush()
        except (OSError, ValueError):
            # A closed stdin raises ValueError ("I/O operation on closed
            # file"), not OSError, once Python's io layer notices the file
            # object itself is closed rather than the underlying fd failing.
            raise McpClientError("the server closed its input") from None

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def request(self, method: str, params: dict) -> dict:
        rid = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        sent_at = self._clock()
        while True:
            remaining = self._deadline(sent_at) - self._clock()
            if remaining <= 0:
                raise McpTimeout(f"{method}: no answer before the timeout")
            try:
                line = self._q.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                continue
            if line is None:
                raise McpClientError(f"{method}: the server exited")
            if line is OVERSIZE:
                raise McpClientError(f"{method}: the server sent a line over the size limit")
            try:
                msg = classify(line)
            except (jsonstrict.StrictJSONError, ShapeError) as e:
                raise McpClientError(f"{method}: the server sent a malformed line ({e})") from None
            if msg.kind == "request":
                self._answer_server_request(msg)
                continue
            if msg.kind == "notification":
                self._dispatch_notification(msg)
                continue
            if msg.id_key != ("number", str(rid)):
                continue
            body = jsonstrict.to_python(msg.node)
            if msg.kind == "error":
                raise McpRpcError(method, body["error"])
            result = body["result"]
            if not isinstance(result, dict):
                raise McpClientError(f"{method}: result is not an object")
            return result

    def _dispatch_notification(self, msg) -> None:
        # A notification with no registered handler is dropped, not an error:
        # the server is allowed to emit notifications this client does not act
        # on, and the request/response path must carry on regardless.
        handler = self._notification_handlers.get(msg.method)
        if handler is None:
            return
        params = jsonstrict.to_python(msg.params) if msg.params is not None else None
        handler(params)

    def _answer_server_request(self, msg) -> None:
        rid = msg.id_python()
        if msg.method == "ping":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {}})
        else:
            self._send({"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32601, "message": "cxbom approve does not serve this method"}})


def modern_meta(version: str, caps: dict) -> dict:
    return {META_PROTOCOL_VERSION: version, META_CLIENT_INFO: CLIENT_INFO, META_CLIENT_CAPABILITIES: caps}


def discover(client: StdioClient, caps: dict, version: str = MODERN_VERSION) -> dict:
    return client.request("server/discover", {"_meta": modern_meta(version, caps)})


def initialize(client: StdioClient, caps: dict, client_info: dict | None = None) -> dict:
    # client_info lets the caller identify itself to the server. The default
    # stays CLIENT_INFO so approve and check-drift keep announcing themselves
    # as cxbom-approve; an agent that is not approve passes its own name and
    # version so the server sees who is really calling.
    info = client_info if client_info is not None else CLIENT_INFO
    result = client.request("initialize", {"protocolVersion": LEGACY_VERSION, "capabilities": caps,
                                           "clientInfo": info})
    client.notify("notifications/initialized")
    return result


def list_tools(client: StdioClient, meta: dict | None) -> list:
    tools: list = []
    cursor = None
    seen: set = set()
    for _ in range(MAX_PAGES):
        params: dict = {} if cursor is None else {"cursor": cursor}
        if meta is not None:
            params["_meta"] = meta
        result = client.request("tools/list", params)
        page = result.get("tools")
        if not isinstance(page, list):
            raise McpClientError("tools/list: result has no tools array")
        if not all(isinstance(t, dict) for t in page):
            raise McpClientError("tools/list: a tool entry is not an object")
        tools.extend(page)
        cursor = result.get("nextCursor")
        if cursor is None:
            return tools
        if not isinstance(cursor, str) or cursor in seen:
            raise McpClientError("tools/list: the server repeated or malformed a cursor")
        seen.add(cursor)
    raise McpClientError(f"tools/list: more than {MAX_PAGES} pages")


def _text(value: object, what: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise McpClientError(f"{what} is not a string")
    return value


def snapshot_legacy(client: StdioClient, caps: dict, client_info: dict | None = None) -> EraSnapshot:
    result = initialize(client, caps, client_info)
    info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
    version = result.get("protocolVersion")
    return EraSnapshot("legacy", version if isinstance(version, str) else "unknown",
                       _text(result.get("instructions"), "instructions"), info, list_tools(client, None))


def _snapshot_from_discover_result(client: StdioClient, caps: dict, version: str, result: dict) -> EraSnapshot:
    offered = result.get("supportedVersions")
    if not isinstance(offered, list) or version not in offered:
        raise McpClientError(f"server/discover: the server does not offer {version}")
    meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
    info = meta.get(META_SERVER_INFO) if isinstance(meta.get(META_SERVER_INFO), dict) else {}
    return EraSnapshot(version, version, _text(result.get("instructions"), "instructions"), info,
                       list_tools(client, modern_meta(version, caps)))


def snapshot_modern(client: StdioClient, caps: dict, version: str = MODERN_VERSION) -> EraSnapshot:
    result = discover(client, caps, version)
    return _snapshot_from_discover_result(client, caps, version, result)


def probe(client: StdioClient, caps: dict) -> str | EraSnapshot:
    """Spec 7 step 3. Returns a modern snapshot, "legacy" when initialize should follow, or "ambiguous".

    Only discover() itself is ambiguous about the era: no answer at all, or an
    error that says nothing about whether the server is modern. Once a real
    DiscoverResult comes back, the server has already proven it is modern, so
    anything that goes wrong after that (a broken tools/list, say) is a
    protocol error, not a reason to fall back to legacy or call the era
    unknown.
    """
    try:
        result = discover(client, caps)
    except McpTimeout:
        return "ambiguous"
    except McpRpcError as e:
        err = jsonstrict.parse(json_bytes(e.error))
        if is_modern_error(err):
            raise McpClientError(f"the server is modern but does not offer {MODERN_VERSION}") from None
        return "legacy"
    return _snapshot_from_discover_result(client, caps, MODERN_VERSION, result)
