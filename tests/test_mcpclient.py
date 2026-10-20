"""The dual-era approve client against the fake server (spec 7 steps 3 and 4). Owner: ATACE Working Group."""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_mcp_server as fake  # noqa: E402
from proxy_helpers import server_layout  # noqa: E402

from cxbom import launch, mcpclient  # noqa: E402


class FakeClock:
    """A manually-advanced clock for testing StdioClient's deadline math.

    Starts at 0.0 and only moves when the test calls advance(). It never
    reflects real wall-clock time, so a test can put "now" arbitrarily far
    past a startup timeout without actually waiting.
    """

    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


@pytest.fixture
def start(tmp_path):
    children = []

    def _start(script=None, startup_timeout=10.0, probe_timeout=2.0, clock=time.monotonic):
        lock_dir = tmp_path / f"proj{len(children)}"
        argv, environ = server_layout(lock_dir, script)
        pins = launch.compute_launch_pins(argv, lock_dir, environ)
        child = launch.spawn(launch.check_launch(pins, argv, lock_dir, environ, "fetch"))
        children.append(child)
        return mcpclient.StdioClient(child, startup_timeout, probe_timeout, clock=clock)

    yield _start
    for child in children:
        child.stop(grace=0.2)


def test_probe_falls_back_to_legacy_and_reads_every_page(start):
    tools = [dict(fake.FETCH, name=f"t{i}") for i in range(5)]
    client = start({"tools": tools, "pageSize": 2, "instructions": "hello"})
    assert mcpclient.probe(client, {}) == "legacy"
    snap = mcpclient.snapshot_legacy(client, {})
    assert (snap.era_key, snap.negotiated_version, snap.instructions) == ("legacy", "2025-11-25", "hello")
    assert [t["name"] for t in snap.tools] == [f"t{i}" for i in range(5)]
    assert snap.server_info == {"name": "fake-mcp", "version": "1.0.0"}


def test_probe_finds_a_modern_server(start):
    client = start({"eras": ["modern"]})
    snap = mcpclient.probe(client, {})
    assert snap.era_key == "2026-07-28" and snap.tools == [fake.FETCH]
    assert snap.server_info == {"name": "fake-mcp", "version": "1.0.0"}


def test_probe_with_no_answer_is_ambiguous(start):
    client = start({"silent": ["server/discover"]}, probe_timeout=0.3)
    client.request("ping", {})
    assert mcpclient.probe(client, {}) == "ambiguous"


def test_modern_server_without_our_version_is_an_error(start):
    client = start({"eras": ["modern"], "modernVersions": ["2027-01-01"]})
    with pytest.raises(mcpclient.McpClientError, match="does not offer 2026-07-28"):
        mcpclient.probe(client, {})


def test_malformed_server_line_is_an_error(start):
    client = start({"rawResponses": {"initialize": [b'{"jsonrpc":"2.0","id":__ID__,"result":{"a":1,"a":2}}'.hex()]}})
    with pytest.raises(mcpclient.McpClientError, match="malformed"):
        mcpclient.snapshot_legacy(client, {})


def test_repeated_cursor_is_an_error(start):
    loop_page = b'{"jsonrpc":"2.0","id":__ID__,"result":{"tools":[],"nextCursor":"same"}}'.hex()
    client = start({"rawResponses": {"tools/list": [loop_page, loop_page]}})
    mcpclient.initialize(client, {})
    with pytest.raises(mcpclient.McpClientError, match="repeated"):
        mcpclient.list_tools(client, None)


def test_server_requests_are_answered_and_skipped(start):
    ping = b'{"jsonrpc":"2.0","id":"srv-ping","method":"ping"}\n{"jsonrpc":"2.0","id":__ID__,"result":{}}'
    client = start({"rawResponses": {"ping": [ping.hex()]}})
    assert client.request("ping", {}) == {}


def test_startup_timeout_bounds_a_silent_server(start):
    client = start({"silent": ["server/discover"]}, startup_timeout=0.3)
    with pytest.raises(mcpclient.McpTimeout):
        client.request("server/discover", {})


def test_probe_timeout_applies_after_first_byte_not_the_startup_deadline(start):
    """Fix round 1, Important 1: the startup timeout must bound only the wait
    for the server's first byte, not every later request via a min() against
    it. A short --startup-timeout with a long-running session must not make a
    request sent long after startup time out immediately."""
    clock = FakeClock()
    client = start({}, startup_timeout=1.0, probe_timeout=5.0, clock=clock)
    assert client.request("ping", {}) == {}          # establishes first_byte at fake time 0.0
    clock.advance(100.0)                              # far past startup_timeout, real process still alive
    assert client.request("ping", {}) == {}            # bounded by probe_timeout from now, not from start


def test_probe_after_modern_discover_lets_a_broken_tools_list_raise(start):
    """Fix round 1, Important 2: once discover() returns a real DiscoverResult
    the server has already proven it is modern, so a tools/list failure after
    that must not be reclassified as "legacy" or "ambiguous"."""
    err = b'{"jsonrpc":"2.0","id":__ID__,"error":{"code":-32000,"message":"boom"}}'.hex()
    client = start({"eras": ["modern"], "rawResponses": {"tools/list": [err]}})
    with pytest.raises(mcpclient.McpClientError, match="boom"):
        mcpclient.probe(client, {})


def test_rpc_error_message_escapes_control_characters():
    """Fix round 1 minor: error.message is server-controlled and must not be
    able to smuggle a raw ESC or other control byte into an exception's str()
    that a caller might print straight to a terminal."""
    err = {"code": -32000, "message": "boom\x1b[31mred\x1b[0m\x07bell"}
    text = str(mcpclient.McpRpcError("m", err))
    assert "\x1b" not in text and "\x07" not in text
    assert "\\u{001B}" in text and "\\u{0007}" in text


def test_send_after_stdin_closed_raises_client_error(start):
    """Fix round 1 minor: a closed stdin raises ValueError, not OSError, once
    Python's io layer notices the file object is closed."""
    client = start({})
    client.child.proc.stdin.close()
    with pytest.raises(mcpclient.McpClientError, match="closed its input"):
        client.request("ping", {})


def test_list_tools_rejects_a_non_object_tool_entry(start):
    raw = b'{"jsonrpc":"2.0","id":__ID__,"result":{"tools":["not-an-object"]}}'.hex()
    client = start({"rawResponses": {"tools/list": [raw]}})
    mcpclient.initialize(client, {})
    with pytest.raises(mcpclient.McpClientError, match="not an object"):
        mcpclient.list_tools(client, None)


def test_a_server_error_message_is_escaped_beyond_c0():
    """Final review A6: C1, bidi, and zero-width characters are escaped too."""
    err = mcpclient.McpRpcError("tools/list", {"code": -1, "message": "a\x1b[2J\u009b31m\u202eb\u200bc"})
    text = str(err)
    assert not any(ch in text for ch in "\x1b\u009b\u202e\u200b")
    assert "\\u{001B}" in text and "\\u{009B}" in text and "\\u{202E}" in text and "\\u{200B}" in text


def test_on_notification_fires_for_its_method_and_leaves_the_response(start):
    """M-1 item 1: a server-initiated notification (no id) reaches the handler
    registered for its method, its params come through, and the request whose
    stream carried it still returns its own result. The handler for a different
    method must not fire, or the routing is not by method."""
    raw = (b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"tag":"swap"}}\n'
           b'{"jsonrpc":"2.0","id":__ID__,"result":{"ok":true}}')
    client = start({"rawResponses": {"ping": [raw.hex()]}})
    fired = []
    other = []
    client.on_notification("notifications/tools/list_changed", lambda p: fired.append(p))
    client.on_notification("notifications/message", lambda p: other.append(p))
    assert client.request("ping", {}) == {"ok": True}     # request/response path intact
    assert fired == [{"tag": "swap"}]                       # fired once, routed by method, params delivered
    assert other == []                                      # a handler for another method did not fire


def test_notification_without_a_handler_is_ignored(start):
    """M-1 item 1: a notification whose method has no registered handler is
    dropped cleanly. A handler is registered for a different method, so this
    also proves the None-handler lookup, not a blanket skip, is what spares it."""
    raw = (b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n'
           b'{"jsonrpc":"2.0","id":__ID__,"result":{}}')
    client = start({"rawResponses": {"ping": [raw.hex()]}})
    seen = []
    client.on_notification("notifications/message", lambda p: seen.append(p))
    assert client.request("ping", {}) == {}
    assert seen == []


def test_initialize_sends_the_given_client_info(start):
    """M-1 item 2: an agent passes its own clientInfo and that is what reaches
    the server, not the hardcoded cxbom-approve default."""
    client = start({"echoClientInfo": True})
    result = mcpclient.initialize(client, {}, client_info={"name": "agent-loop", "version": "9.9.9"})
    assert result["clientInfoEcho"] == {"name": "agent-loop", "version": "9.9.9"}


def test_initialize_default_client_info_is_cxbom_approve(start):
    """M-1 item 2: with no clientInfo argument the legacy default is preserved,
    so approve and check-drift still identify as cxbom-approve 0.3.0."""
    client = start({"echoClientInfo": True})
    result = mcpclient.initialize(client, {})
    assert result["clientInfoEcho"] == {"name": "cxbom-approve", "version": "0.3.0"}
