"""The --events sidecar: C2 1.1.0 lines, a droppable queue, canary redaction (spec 8.7).

Owner: ATACE Working Group.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "contracts"))
import checks  # noqa: E402

from proxy_helpers import ProxyProcess, init, note, rpc, signed_setup  # noqa: E402

from cxbom import attestation, proxy  # noqa: E402

PSID = "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11"
CANARY = "CANARY-7f3a91c2d4e5b6a7"
CANARY_SHA = hashlib.sha256(CANARY.encode()).hexdigest()


def read(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_lines_pass_the_sidecar_contract(tmp_path):
    ticks = iter([100.0, 100.5, 101.25])
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID, clock=lambda: next(ticks))
    sink.start()
    sink.emit("tool_listed", {"serverId": "fetch", "tool": "fetch", "sha256": "a" * 64, "phase": "initial"})
    sink.emit("gate_decision", {"serverId": "fetch", "tool": "fetch", "decision": "allow", "reason": "pinned-match"})
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert checks.check_sidecar_events(events) == []
    assert [(e["localSeq"], e["mono"]) for e in events] == [(0, 0.5), (1, 1.25)]
    assert all(e["proxySessionId"] == PSID and e["at"].endswith("Z") for e in events)
    assert stat.S_IMODE(os.stat(tmp_path / "e.jsonl").st_mode) == 0o600


def test_full_queue_drops_without_blocking_and_leaves_no_seq_gap(tmp_path):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID, maxsize=2)
    for i in range(5):
        sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping", "rpcId": i, "summary": "x"})
    sink.start()
    sink.close()
    # dropped is accepted minus delivered, so it is final only once close()
    # returns. Before that it also counts what is queued and not yet written.
    assert sink.dropped == 3
    events = read(tmp_path / "e.jsonl")
    assert [e["localSeq"] for e in events] == [0, 1]
    assert checks.check_sidecar_events(events) == []


def test_redaction_whole_string_and_embedded_token():
    hashes = frozenset({CANARY_SHA})
    assert proxy.redact(CANARY, hashes) == "<canary>"
    assert proxy.redact(f"https://x.example/?k={CANARY}&z=1", hashes) == "<canary>"
    assert proxy.redact({"a": [f"see {CANARY}.", "clean"], "n": 3}, hashes) == {"a": ["<canary>", "clean"], "n": 3}
    assert proxy.redact("CANARY-7f3a91c2", hashes) == "CANARY-7f3a91c2"
    assert proxy.redact(CANARY, frozenset()) == CANARY


def test_sink_redacts_before_writing(tmp_path):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID, redact_sha256=[CANARY_SHA])
    sink.start()
    sink.emit("tool_swapped", {"serverId": "fetch", "tool": "fetch", "oldSha256": "a" * 64, "newSha256": "b" * 64,
                               "descriptionDiff": f"+append ?k={CANARY}"})
    sink.close()
    text = (tmp_path / "e.jsonl").read_text()
    assert CANARY not in text and "<canary>" in text


def test_close_without_start_only_closes_the_file(tmp_path):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping", "rpcId": 1, "summary": "x"})
    sink.close()
    assert (tmp_path / "e.jsonl").read_text() == ""


def test_opening_a_fifo_with_no_reader_returns_promptly(tmp_path):
    fifo = tmp_path / "f.fifo"
    os.mkfifo(fifo)
    outcome = {}

    def attempt():
        try:
            proxy.EventSink(fifo, PSID)
        except Exception as e:  # noqa: BLE001 - captured across the thread boundary
            outcome["error"] = e

    t = threading.Thread(target=attempt, daemon=True)
    t.start()
    t.join(3.0)
    assert not t.is_alive(), "EventSink construction blocked on a FIFO with no reader"
    assert isinstance(outcome.get("error"), proxy.EventSinkError)
    assert str(fifo) not in str(outcome["error"])


def test_symlink_path_is_refused(tmp_path):
    target = tmp_path / "real.jsonl"
    target.write_text("")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(proxy.EventSinkError):
        proxy.EventSink(link, PSID)


def test_redaction_redacts_dict_keys_too():
    hashes = frozenset({CANARY_SHA})
    assert proxy.redact({CANARY: "clean", "n": 3}, hashes) == {"<canary>": "clean", "n": 3}


def test_close_drops_events_that_arrive_after_close_without_writing_or_raising(tmp_path):
    path = tmp_path / "e.jsonl"
    sink = proxy.EventSink(path, PSID)
    sink.start()
    sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping", "rpcId": 1, "summary": "x"})
    sink.close()
    before = path.read_bytes()

    # A single post-close emit is dropped immediately, not queued for a
    # writer thread that has already exited and will never read it.
    sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping", "rpcId": 2, "summary": "y"})
    assert sink.dropped == 1
    assert path.read_bytes() == before

    # Hammering emit() concurrently after close must never raise and must
    # never grow the file, whatever the drop count ends up being.
    errors = []
    stop = threading.Event()

    def hammer():
        while not stop.is_set():
            try:
                sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping",
                                          "rpcId": 3, "summary": "z"})
            except Exception as e:  # noqa: BLE001 - captured across the thread boundary
                errors.append(e)

    threads = [threading.Thread(target=hammer, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.05)
    stop.set()
    for t in threads:
        t.join(3.0)

    assert errors == []
    assert all(not t.is_alive() for t in threads)
    assert path.read_bytes() == before


def _mcp_message(summary):
    return {"from": "agent", "to": "server", "method": "tools/call", "rpcId": 1, "summary": summary}


def test_a_canary_straddling_the_summary_cap_is_redacted_whole(tmp_path):
    """Final review B4: the summary was cut to 200 characters before
    redaction, so a canary across position 200 survived half cut."""
    summary = "a " * 96 + CANARY + " tail"
    assert summary.index(CANARY) < 200 < summary.index(CANARY) + len(CANARY)
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID, redact_sha256=[CANARY_SHA])
    sink.start()
    sink.emit("mcp_message", _mcp_message(summary))
    sink.close()
    (event,) = read(tmp_path / "e.jsonl")
    assert event["data"]["summary"] == "<canary>"
    assert CANARY[:9] not in (tmp_path / "e.jsonl").read_text()


def test_the_summary_is_cut_after_scrubbing_and_identifiers_are_never_rewritten_in_part(tmp_path):
    """Final review B4: a scrub rewrite that grows the text cannot push the
    summary past the schema's maxLength, and an identifier (serverId, tool,
    method, rpcId) is never partly rewritten. One that would leak is
    withheld whole, since nothing an event writes may carry a user name."""
    def scrub(text):
        return text.replace("H", "<host>").replace("alice", "<user>")

    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID, scrub=scrub)
    sink.start()
    sink.emit("mcp_message", _mcp_message("H" * 200))
    sink.emit("gate_decision", {"serverId": "fetch", "tool": "alice-tool", "decision": "block",
                                "reason": "alice H"})
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert checks.check_sidecar_events(events) == []
    assert events[0]["data"]["summary"] == ("<host>" * 34)[:200] and events[0]["data"]["method"] == "tools/call"
    assert events[1]["data"] == {"serverId": "fetch", "tool": proxy.WITHHELD, "decision": "block",
                                 "reason": "<user> <host>"}


# ----- the dropped counter: every path that loses an event counts it ----------------

def _ping(i):
    return {"from": "agent", "to": "server", "method": "ping", "rpcId": i, "summary": "x"}


def _patch_sink_write(monkeypatch, sink, fake):
    """Route os.write for the sink's own descriptor through fake(real, fd, data), and leave every other fd alone."""
    real = os.write
    monkeypatch.setattr(proxy.os, "write",
                        lambda fd, data: fake(real, fd, data) if fd == sink._fd else real(fd, data))


def test_a_session_with_no_drops_counts_zero(tmp_path):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    sink.start()
    for i in range(3):
        sink.emit("mcp_message", _ping(i))
    sink.close()
    assert sink.dropped == 0
    assert [e["localSeq"] for e in read(tmp_path / "e.jsonl")] == [0, 1, 2]


def test_a_failed_writer_write_is_counted_and_the_next_event_still_lands(tmp_path, monkeypatch):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    calls = []

    def fake(real, fd, data):
        calls.append(data)
        if len(calls) == 1:
            raise OSError(28, "No space left on device")
        return real(fd, data)

    _patch_sink_write(monkeypatch, sink, fake)
    sink.emit("mcp_message", _ping(1))
    sink.emit("mcp_message", _ping(2))
    sink.start()
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert sink.dropped == 1
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in events] == [(0, 2)]


def _short_writes(plan):
    """A fake os.write that, for call i, puts plan[i] bytes of the line on disk and reports that many.

    None in the plan, or a call past its end, writes the whole line.
    """
    calls = []

    def fake(real, fd, data):
        calls.append(data)
        n = plan[len(calls) - 1] if len(calls) <= len(plan) else None
        if n is None:
            return real(fd, data)
        return real(fd, data[:n]) if n else 0

    return fake, calls


def test_a_short_writer_write_is_counted_takes_no_seq_and_stays_its_own_line(tmp_path, monkeypatch):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    fake, calls = _short_writes([10])
    _patch_sink_write(monkeypatch, sink, fake)
    for i in range(1, 4):
        sink.emit("mcp_message", _ping(i))
    sink.start()
    sink.close()
    assert sink.dropped == 1
    fragment, *whole, tail = (tmp_path / "e.jsonl").read_bytes().split(b"\n")
    # The torn line is exactly the bytes the short write put down, closed by
    # the next line's leading newline, so every line after it parses, and
    # only the one line right after the fragment carries a lead.
    assert fragment == calls[0][:10]
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in map(json.loads, whole)] == [(0, 2), (1, 3)]
    assert tail == b""
    with pytest.raises(ValueError):
        json.loads(fragment)


def test_a_short_write_that_put_nothing_down_adds_no_newline(tmp_path, monkeypatch):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    fake, _ = _short_writes([0])
    _patch_sink_write(monkeypatch, sink, fake)
    sink.emit("mcp_message", _ping(1))
    sink.emit("mcp_message", _ping(2))
    sink.start()
    sink.close()
    assert sink.dropped == 1
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in read(tmp_path / "e.jsonl")] == [(0, 2)]
    assert (tmp_path / "e.jsonl").read_bytes().count(b"\n") == 1


def test_an_event_the_writer_cannot_serialize_is_counted_and_the_writer_survives(tmp_path):
    # A set is not JSON. Before the fix the TypeError killed the writer
    # thread, and every later event stayed queued, unwritten and uncounted.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    sink.start()
    sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping", "rpcId": {1}, "summary": "x"})
    sink.emit("mcp_message", _ping(2))
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert sink.dropped == 1
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in events] == [(0, 2)]


def test_events_queued_behind_the_shutdown_sentinel_are_counted(tmp_path):
    # Stands in for the race where an emit() passes its _closing check, then
    # close() sets _closing and queues its sentinel first: the writer stops
    # at the sentinel and never reads what sits behind it.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    sink.start()
    sink._q.put(None)
    sink._thread.join(5.0)
    assert not sink._thread.is_alive()
    sink.emit("mcp_message", _ping(1))
    sink.emit("mcp_message", _ping(2))
    sink.close()
    assert sink.dropped == 2
    assert (tmp_path / "e.jsonl").read_text() == ""


def test_events_queued_on_a_sink_that_never_started_are_counted(tmp_path):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    for i in range(3):
        sink.emit("mcp_message", _ping(i))
    sink.close()
    assert sink.dropped == 3


def test_a_backlog_a_stalled_writer_cannot_reach_by_the_close_timeout_is_counted(tmp_path, monkeypatch):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    entered, release = threading.Event(), threading.Event()

    def fake(real, fd, data):
        entered.set()
        release.wait(10.0)
        return real(fd, data)

    _patch_sink_write(monkeypatch, sink, fake)
    for i in range(3):
        sink.emit("mcp_message", _ping(i))
    sink.start()
    assert entered.wait(5.0)
    sink.close(timeout=0.2)
    # The writer holds event 0 mid-write and events 1 and 2 are still
    # queued. None is confirmed on disk, so all three count.
    assert sink.dropped == 3
    release.set()
    sink._thread.join(5.0)
    # The held write lands late. The abandoned writer confirms nothing and
    # starts nothing more, so the count stays one high and never goes low.
    assert [e["data"]["rpcId"] for e in read(tmp_path / "e.jsonl")] == [0]
    assert sink.dropped == 3


@pytest.mark.parametrize("outcome", ["raise", "short"])
def test_a_pre_session_line_that_is_not_written_whole_is_counted(tmp_path, monkeypatch, outcome):
    sink = proxy.EventSink(tmp_path / "e.jsonl", "")

    def fake(real, fd, data):
        if outcome == "raise":
            raise OSError(28, "No space left on device")
        return len(data) - 1

    _patch_sink_write(monkeypatch, sink, fake)
    sink.emit_pre_session("launch_refused", {"serverId": "fetch", "item": "entry", "reason": "r", "exitCode": 2})
    assert sink.dropped == 1
    sink.close()
    assert sink.dropped == 1


# ----- the session's final drop count in the attestation log --------------------------


def _count_lines(log):
    return [line for line in attestation.read_log(log)
            if line["kind"] == "diagnostic" and line["message"].startswith(proxy.DROPPED_DIAGNOSTIC)]


def _session(tmp_path, env=None):
    setup = signed_setup(tmp_path)
    events = tmp_path / "events.jsonl"
    p = ProxyProcess(setup, events=str(events), env=env)
    p.send(init(0))
    p.recv()
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/list"))
    p.recv()
    assert p.close() == 0
    return attestation.read_log(p.log_path()), events


def test_a_session_with_no_drops_logs_a_count_of_zero_right_before_end(tmp_path):
    lines, events = _session(tmp_path)
    assert attestation.check_log(lines) == []
    assert [line["kind"] for line in lines[-2:]] == ["diagnostic", "end"]
    assert lines[-2]["message"] == "sidecar events dropped: 0"
    assert lines[-1]["reason"] == "eof"
    assert checks.check_sidecar_events(read(events)) == []


def test_a_session_with_forced_drops_logs_the_exact_count(tmp_path):
    lines, events = _session(tmp_path, env={"CXBOM_TEST_DROP_FIRST_EVENTS": "3"})
    written = read(events)
    assert [line["kind"] for line in lines[-2:]] == ["diagnostic", "end"]
    assert lines[-2]["message"] == "sidecar events dropped: 3"
    # The session emitted more than three, so the rest still landed, gapless.
    assert written and [e["localSeq"] for e in written] == list(range(len(written)))


def test_end_is_written_only_after_the_sidecar_closes(tmp_path):
    setup = signed_setup(tmp_path)
    code, lines, order = _run_patched(setup, tmp_path, _SPY_ORDER)
    assert code == 0
    assert order[:3] == ["close", "count", "end"]
    assert "end" not in order[3:]
    assert lines[-1]["reason"] == "eof"


def test_a_session_without_a_sidecar_logs_no_count(tmp_path):
    setup = signed_setup(tmp_path)
    p = ProxyProcess(setup)
    p.send(rpc(1, "ping"))
    p.recv()
    assert p.close() == 0
    assert _count_lines(p.log_path()) == []
    assert attestation.read_log(p.log_path())[-1]["kind"] == "end"


def test_a_killed_proxy_leaves_no_count_and_no_end(tmp_path):
    setup = signed_setup(tmp_path)
    p = ProxyProcess(setup, events=str(tmp_path / "events.jsonl"))
    p.send(init(0))
    p.recv()
    p.proc.kill()
    p.proc.wait(timeout=15)
    lines = attestation.read_log(p.log_path())
    assert lines and lines[0]["kind"] == "session"
    assert _count_lines(p.log_path()) == []
    assert [line for line in lines if line["kind"] == "end"] == []


# proxy.run in a fresh interpreter with a test patch applied first. A run that
# fails part way through _serve leaves relay threads behind, and launch.spawn
# refuses to start once any other thread exists, so running these in the
# pytest process would break every later in-process spawn.
_RUN_PATCHED = (
    "import json, os, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from pathlib import Path\n"
    "from cxbom import attestation, launch, proxy\n"
    "args = json.loads(sys.argv[2])\n"
    "order = []\n"
    "stdin_fd = os.open(os.devnull, os.O_RDONLY)\n"
    "exec(args['patch'])\n"
    "opts = proxy.ProxyOptions(server_id='fetch', command=args['argv'], state_dir=args['state'], events=args['events'])\n"
    "code = proxy.run(opts, config_dir=Path(args['config']), environ=dict(os.environ, **args['environ']),\n"
    "                 cwd=Path(args['cwd']), stdin_fd=stdin_fd)\n"
    "Path(args['out']).write_text(json.dumps({'code': code, 'order': order}))\n")

_SPY_ORDER = """
real_close, real_append, real_end = proxy.EventSink.close, attestation.AttestationWriter.append, attestation.AttestationWriter.end
def close(self, *a, **k):
    order.append('close')
    return real_close(self, *a, **k)
def append(self, kind, /, **fields):
    if kind == 'diagnostic' and fields['message'].startswith(proxy.DROPPED_DIAGNOSTIC):
        order.append('count')
    return real_append(self, kind, **fields)
def end(self, reason):
    order.append('end')
    return real_end(self, reason)
proxy.EventSink.close, attestation.AttestationWriter.append, attestation.AttestationWriter.end = close, append, end
"""


def _run_patched(setup, tmp_path, patch):
    out = tmp_path / "run.json"
    args = {"patch": patch, "argv": list(setup.argv), "state": str(setup.state), "events": str(tmp_path / "events.jsonl"),
            "config": str(setup.config), "environ": setup.environ, "cwd": str(setup.lock_dir), "out": str(out)}
    done = subprocess.run([sys.executable, "-c", _RUN_PATCHED, str(ROOT), json.dumps(args)], cwd=setup.lock_dir,
                          capture_output=True, timeout=60, check=False)
    # A child that died before writing its result would otherwise surface as
    # a bare FileNotFoundError that hides why.
    assert out.exists(), f"the patched run died (rc {done.returncode}): {done.stderr.decode('utf-8', 'replace')[-2000:]}"
    result = json.loads(out.read_text())
    (log,) = (setup.state / "attest").glob("fetch-*.jsonl")
    return result["code"], attestation.read_log(log), result["order"]


@pytest.mark.parametrize("exc, reason", [("RuntimeError", "internal-error"), ("KeyboardInterrupt", "signal")])
def test_a_session_that_fails_mid_serve_still_logs_its_count_before_end(tmp_path, exc, reason):
    setup = signed_setup(tmp_path)
    patch = f"def boom(*a, **k):\n    raise {exc}('test')\nproxy.ProxyCore = boom\n"
    code, lines, _ = _run_patched(setup, tmp_path, patch)
    assert [(line["kind"], line.get("message"), line.get("reason")) for line in lines[-2:]] == [
        ("diagnostic", "sidecar events dropped: 0", None), ("end", None, reason)]
    if reason == "internal-error":
        assert code == proxy.EXIT_INTERNAL


def test_a_spawn_failure_still_logs_its_count_before_end(tmp_path):
    setup = signed_setup(tmp_path)
    patch = ("def fail(plan, grace=None):\n    raise launch.LaunchError('python3: cannot start the server')\n"
             "launch.spawn = fail\n")
    code, lines, _ = _run_patched(setup, tmp_path, patch)
    assert code == proxy.EXIT_INTERNAL
    assert [(line["kind"], line.get("message"), line.get("reason")) for line in lines[-2:]] == [
        ("diagnostic", "sidecar events dropped: 0", None), ("end", None, "internal-error")]


def test_a_failed_count_write_still_ends_the_log_with_attestation_io(tmp_path):
    setup = signed_setup(tmp_path)
    patch = """
real_append = attestation.AttestationWriter.append
def append(self, kind, /, **fields):
    if kind == 'diagnostic' and fields['message'].startswith(proxy.DROPPED_DIAGNOSTIC):
        raise attestation.AttestationIOError('test: the count write failed')
    return real_append(self, kind, **fields)
attestation.AttestationWriter.append = append
"""
    code, lines, _ = _run_patched(setup, tmp_path, patch)
    assert code == proxy.EXIT_INTERNAL
    assert lines[-1]["kind"] == "end" and lines[-1]["reason"] == "attestation-io"
    assert [line for line in lines if line["kind"] == "diagnostic"] == []


# ----- fix round 1: dropped is accepted minus delivered, and close is bounded ----------

def _scheduled(plan):
    """A fake os.write whose call i follows plan[i]: None writes everything, "raise" raises
    ENOSPC, and an int k puts down data[:k] and reports k (a negative k counts from the end).
    A call past the plan's end writes everything. Covers line writes and newline repairs alike."""
    calls = []

    def fake(real, fd, data):
        calls.append(data)
        step = plan[len(calls) - 1] if len(calls) <= len(plan) else None
        if step is None:
            return real(fd, data)
        if step == "raise":
            raise OSError(28, "No space left on device")
        n = step % len(data) if step < 0 else min(step, len(data))
        return real(fd, data[:n]) if n else 0

    return fake, calls


def _valid_lines(path):
    """The sidecar's delivered lines: newline-terminated and parseable as a JSON object.

    A trailing segment with no newline is not a line yet, even when it parses.
    Callers run check_sidecar_events over the whole list, which checks each
    line's schema and localSeq contiguity across them.
    """
    *terminated, _tail = path.read_bytes().split(b"\n")
    out = []
    for raw in terminated:
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if isinstance(ev, dict):
            out.append(ev)
    return out


def test_a_short_write_that_loses_only_the_newline_delivers_the_event_once(tmp_path, monkeypatch):
    # I-1: the whole object landed and only its newline did not. The repair
    # writes that one newline, which makes the line whole, so the event is
    # delivered, counted once, and the next line takes the next localSeq.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    fake, calls = _scheduled([-1])
    _patch_sink_write(monkeypatch, sink, fake)
    for i in range(3):
        sink.emit("mcp_message", _ping(i))
    sink.start()
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert sink.dropped == 0
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in events] == [(0, 0), (1, 1), (2, 2)]
    assert checks.check_sidecar_events(events) == []
    # The repair is the lone newline, never a resend of the line.
    assert calls[1] == b"\n"
    assert (tmp_path / "e.jsonl").read_bytes() == calls[0] + b"".join(calls[2:])


def test_a_newline_repair_that_fails_holds_back_later_lines_until_it_lands(tmp_path, monkeypatch):
    # The repair right after the short write fails, and so does the retry
    # before event 1, so event 1 meets an unclosed fragment and is not written
    # (it would glue on). The retry before event 2 lands, which delivers
    # event 0 late, and event 2 continues at localSeq 1.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    fake, calls = _scheduled([-1, 0, "raise"])
    _patch_sink_write(monkeypatch, sink, fake)
    for i in range(3):
        sink.emit("mcp_message", _ping(i))
    sink.start()
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in events] == [(0, 0), (1, 2)]
    assert sink.dropped == 1
    assert checks.check_sidecar_events(events) == []


def test_the_writer_closes_a_last_fragment_before_it_stops(tmp_path, monkeypatch):
    # The last event loses its newline and the repair right after fails.
    # No later event comes to retry it, so the writer retries once as it
    # stops, and that newline delivers the event.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    fake, calls = _scheduled([None, -1, "raise"])
    _patch_sink_write(monkeypatch, sink, fake)
    sink.emit("mcp_message", _ping(0))
    sink.emit("mcp_message", _ping(1))
    sink.start()
    sink.close()
    events = read(tmp_path / "e.jsonl")
    assert [(e["localSeq"], e["data"]["rpcId"]) for e in events] == [(0, 0), (1, 1)]
    assert sink.dropped == 0
    assert (tmp_path / "e.jsonl").read_bytes().endswith(b"}\n")


def test_a_fragment_left_unclosed_at_close_is_not_delivered(tmp_path, monkeypatch):
    # The last event loses its newline and every repair fails. The object is
    # on disk without its newline, which is not a delivered line, so it counts.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    fake, _ = _scheduled([None, -1, "raise", "raise"])
    _patch_sink_write(monkeypatch, sink, fake)
    sink.emit("mcp_message", _ping(0))
    sink.emit("mcp_message", _ping(1))
    sink.start()
    sink.close()
    assert sink.dropped == 1
    assert [e["data"]["rpcId"] for e in _valid_lines(tmp_path / "e.jsonl")] == [0]


def test_a_close_after_an_interrupted_close_still_abandons_the_writer(tmp_path, monkeypatch):
    # M-2(a): the first close() is interrupted in its join. The second one
    # must still wait and abandon the writer. Returning early would leave a
    # live writer that lands the whole backlog after the count was taken.
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID)
    entered, release = threading.Event(), threading.Event()

    def fake(real, fd, data):
        entered.set()
        release.wait(10.0)
        return real(fd, data)

    _patch_sink_write(monkeypatch, sink, fake)
    for i in range(3):
        sink.emit("mcp_message", _ping(i))
    sink.start()
    assert entered.wait(5.0)
    real_join = sink._thread.join
    joins = []

    def interrupted_once(timeout=None):
        joins.append(timeout)
        if len(joins) == 1:
            raise KeyboardInterrupt
        return real_join(timeout)

    sink._thread.join = interrupted_once
    with pytest.raises(KeyboardInterrupt):
        sink.close(timeout=0.2)
    sink.close(timeout=0.2)
    assert sink.dropped == 3
    release.set()
    real_join(5.0)
    assert [e["data"]["rpcId"] for e in read(tmp_path / "e.jsonl")] == [0]
    assert sink.dropped == 3


def test_close_gives_a_stalled_writer_one_second_even_with_a_full_queue(tmp_path, monkeypatch):
    sink = proxy.EventSink(tmp_path / "e.jsonl", PSID, maxsize=2)
    entered, release = threading.Event(), threading.Event()

    def fake(real, fd, data):
        entered.set()
        release.wait(10.0)
        return real(fd, data)

    _patch_sink_write(monkeypatch, sink, fake)
    sink.emit("mcp_message", _ping(0))
    sink.start()
    assert entered.wait(5.0)
    sink.emit("mcp_message", _ping(1))
    sink.emit("mcp_message", _ping(2))
    assert sink._q.full()
    t0 = time.monotonic()
    sink.close()
    elapsed = time.monotonic() - t0
    release.set()
    # One budget for the whole close: the sentinel never waits for room in a
    # full queue, so it cannot add a second budget in front of the join.
    assert proxy.EventSink.CLOSE_BUDGET_S <= 1.0
    assert 0.9 <= elapsed < 1.6
    assert sink.dropped == 3


def test_the_count_is_emitted_minus_delivered_lines_for_any_failure_schedule(tmp_path, monkeypatch):
    # Property test over seeded random schedules: every os.write the writer
    # makes, line or newline repair, independently lands whole, lands short
    # (the newline-only loss weighted up), puts nothing down, or raises. Some
    # events cannot be serialized, some arrive after close. Whatever the
    # schedule, the count equals the events emitted minus the valid lines.
    import random

    for seed in range(250):
        rng = random.Random(seed)
        path = tmp_path / f"e{seed}.jsonl"
        sink = proxy.EventSink(path, PSID)
        real = os.write

        def fake(fd, data, rng=rng, sink=sink):
            if fd != sink._fd:
                return real(fd, data)
            roll = rng.random()
            if roll < 0.55 or len(data) == 1 and roll < 0.75:
                return real(fd, data)
            if roll < 0.65:
                raise OSError(28, "No space left on device")
            if roll < 0.72:
                return 0
            n = len(data) - 1 if roll < 0.85 or len(data) == 1 else rng.randrange(1, len(data))
            return real(fd, data[:n])

        monkeypatch.setattr(proxy.os, "write", fake)
        emitted = rng.randrange(1, 12)
        sink.start()
        for i in range(emitted):
            unserializable = rng.random() < 0.1
            sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "ping",
                                      "rpcId": {i} if unserializable else i, "summary": "x"})
        sink.close()
        late = rng.randrange(0, 3)
        for i in range(late):
            sink.emit("mcp_message", _ping(100 + i))
        monkeypatch.setattr(proxy.os, "write", real)
        valid = _valid_lines(path)
        assert sink.dropped == emitted + late - len(valid), f"seed {seed}"
        assert checks.check_sidecar_events(valid) == [], f"seed {seed}"


def _events_session(tmp_path, env):
    setup = signed_setup(tmp_path)
    events = tmp_path / "events.jsonl"
    p = ProxyProcess(setup, events=str(events), env=env)
    p.send(init(0))
    p.recv()
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/list"))
    p.recv()
    return p, events


def test_a_stalled_sidecar_still_gets_its_count_and_end_under_the_sdk_stdio_shutdown(tmp_path):
    # I-3, the MCP SDK's stdio_client shutdown: close stdin, wait 2.0 s, send
    # SIGTERM to the process group, wait 2.0 s more, then SIGKILL. The sidecar
    # stops answering after two lines, so every later event is held or queued.
    import signal

    p, events = _events_session(tmp_path, {"CXBOM_TEST_STALL_EVENT_WRITES_AFTER": "2"})
    p.proc.stdin.close()
    t0 = time.monotonic()
    for at, sig in ((2.0, signal.SIGTERM), (4.0, signal.SIGKILL)):
        try:
            p.proc.wait(max(0.0, t0 + at - time.monotonic()))
            break
        except subprocess.TimeoutExpired:
            os.killpg(p.proc.pid, sig)
    p.proc.wait(15)
    lines = attestation.read_log(p.log_path())
    assert [line["kind"] for line in lines[-2:]] == ["diagnostic", "end"]
    assert lines[-1]["reason"] == "eof"
    assert attestation.check_log(lines) == []
    written = _valid_lines(events)
    assert len(written) == 2
    dropped = int(lines[-2]["message"][len(proxy.DROPPED_DIAGNOSTIC):])
    assert dropped >= 1


_STALL_AND_SIGNAL_IN_CLOSE = """
import signal, threading, time
SIG = getattr(signal, {sig!r})
# A child started from a background shell inherits SIGINT ignored, and Python
# keeps an inherited ignore, which would let the SIGINT case pass vacuously.
signal.signal(signal.SIGINT, signal.default_int_handler)
held = []
real_start, real_close, real_write = proxy.EventSink.start, proxy.EventSink.close, os.write
def start(self):
    held.append(self._fd)
    real_start(self)
    self.emit("mcp_message", {{"from": "agent", "to": "server", "method": "ping", "rpcId": 1, "summary": "x"}})
def write(fd, data):
    if held and fd == held[0]:
        time.sleep(30)
    return real_write(fd, data)
def close(self, *a, **k):
    if not self._closing.is_set():
        threading.Timer(0.3, os.kill, (os.getpid(), SIG)).start()
    return real_close(self, *a, **k)
proxy.EventSink.start, proxy.EventSink.close, os.write = start, close, write
"""


@pytest.mark.parametrize("sig", ["SIGTERM", "SIGINT"])
def test_a_stop_signal_that_lands_during_close_does_not_cut_the_count_or_end(tmp_path, sig):
    # I-3's hold, pinned on its own: the signal lands 0.3 s into a close the
    # stalled writer keeps busy for the whole budget. Under the default
    # SIGTERM action the proxy would die with neither line, and SIGINT would
    # abandon the eof ending for a second one.
    setup = signed_setup(tmp_path)
    code, lines, _ = _run_patched(setup, tmp_path, _STALL_AND_SIGNAL_IN_CLOSE.format(sig=sig))
    assert [(line["kind"], line.get("message"), line.get("reason")) for line in lines[-2:]] == [
        ("diagnostic", "sidecar events dropped: 1", None), ("end", None, "eof")]
    assert attestation.check_log(lines) == []


_FLOOD_THEN_INTERRUPT = """
import time
sinks = []
real_start, real_read_lines, real_append, real_run = (proxy.EventSink.start, proxy.read_lines,
                                                      attestation.AttestationWriter.append, proxy.run)
def start(self):
    sinks.append(self)
    real_start(self)
def flood():
    i = 0
    while True:
        i += 1
        yield json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping"}).encode()
        time.sleep(0.001)
def read_lines(fd, *a, **k):
    return flood() if fd == stdin_fd else real_read_lines(fd, *a, **k)
ticks = []
def tick(self):
    ticks.append(1)
    if len(ticks) == 3:
        raise KeyboardInterrupt
def append(self, kind, /, **fields):
    if kind == 'diagnostic' and fields['message'].startswith(proxy.DROPPED_DIAGNOSTIC):
        order.append(sinks[0]._accepted)
    return real_append(self, kind, **fields)
def run(*a, **k):
    code = real_run(*a, **k)
    time.sleep(0.3)
    order.append(sinks[0]._accepted)
    return code
proxy.EventSink.start, proxy.read_lines, proxy.ProxyCore.tick = start, read_lines, tick
attestation.AttestationWriter.append, proxy.run = append, run
"""


def test_nothing_emits_after_the_count_when_serve_raises_with_live_pumps(tmp_path):
    # M-2: an exception out of _serve's relay loop reaches run(), which ends
    # the session outside the relay lock. The client pump is still feeding a
    # flood of pings, so unless _serve stops it first, events keep arriving
    # after the count is logged and the logged count comes out low.
    setup = signed_setup(tmp_path)
    _, lines, order = _run_patched(setup, tmp_path, _FLOOD_THEN_INTERRUPT)
    at_count, final = order
    assert at_count > 0
    assert final == at_count
    assert lines[-1]["kind"] == "end"
