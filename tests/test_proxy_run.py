"""cxbom proxy as a process: startup checks, relay threads, shutdown, exit codes (spec 8.1, 8.8, 13).

Owner: ATACE Working Group.
"""
import hashlib
import json
import os
import pwd
import signal
import socket
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_helpers import (Loop, ProxyProcess, entry, init, note, rpc, run_refused,  # noqa: E402
                           signed_setup)

from cxbom import attestation, launch, paths, proxy, relay, state  # noqa: E402

HOME = str(paths.pw_dir())


def test_end_to_end_legacy_session(tmp_path):
    setup = signed_setup(tmp_path)
    p = ProxyProcess(setup)
    p.send(init(0))
    first = p.recv()
    assert first["result"]["_meta"]["org.cxbom/proxySessionId"]
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/list"))
    assert [t["name"] for t in p.recv()["result"]["tools"]] == ["fetch"]
    p.send(rpc(2, "tools/call", {"name": "fetch", "arguments": {}}))
    assert p.recv()["result"]["content"][0]["text"] == "called fetch"
    assert p.close() == 0
    lines = attestation.read_log(p.log_path())
    assert attestation.check_log(lines) == []
    assert [line["kind"] for line in lines] == ["session", "protocol", "server", "verdict", "end"]
    assert lines[-1]["reason"] == "eof"
    assert lines[0]["mode"] == "enforce" and lines[0]["serverId"] == "fetch"
    assert state.lookup(state.compute(lines), "tool", "fetch").state == state.ALLOWED
    assert not attestation.is_live(p.log_path())


def test_child_exit_code_is_the_proxy_exit_code(tmp_path):
    p = ProxyProcess(signed_setup(tmp_path, script={"exitCodeOnEof": 5}))
    p.send(rpc(1, "ping"))
    assert p.recv() == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert p.close() == 5


def test_sigterm_writes_end_signal(tmp_path):
    p = ProxyProcess(signed_setup(tmp_path))
    p.send(rpc(1, "ping"))
    p.recv()
    p.proc.send_signal(signal.SIGTERM)
    assert p.proc.wait(timeout=15) == 0
    assert attestation.read_log(p.log_path())[-1]["reason"] == "signal"


def test_server_that_exits_ends_the_session_and_its_stderr_is_scrubbed(tmp_path):
    lock_dir = tmp_path / "proj"
    setup = signed_setup(tmp_path, script={"requireEnv": ["NOT_PASSED"],
                                           "stderrOnStart": f"loading {lock_dir}/script.json from {HOME}/x"})
    p = ProxyProcess(setup, env={"NOT_PASSED": "1"})
    code = p.proc.wait(timeout=15)
    err = p.stderr()
    assert code == 3
    assert "loading ./script.json from ~/x" in err
    assert HOME not in err and str(lock_dir) not in err
    assert attestation.read_log(p.log_path())[-1]["reason"] == "child-exit"


def refuse(tmp_path, setup, needle, **kw):
    code, err = run_refused(setup, **kw)
    assert code == 2, err
    assert needle in err
    assert HOME not in err and str(tmp_path) not in err
    return err


def test_home_redirect_is_refused(tmp_path):
    refuse(tmp_path, signed_setup(tmp_path), "HOME differs", env={"HOME": str(tmp_path)})


def test_missing_lock_is_refused(tmp_path):
    setup = signed_setup(tmp_path)
    (setup.lock_dir / "cxbom.lock").unlink()
    refuse(tmp_path, setup, "no cxbom.lock found")


def test_tampered_lock_is_refused(tmp_path):
    setup = signed_setup(tmp_path)
    lock_path = setup.lock_dir / "cxbom.lock"
    doc = json.loads(lock_path.read_text())
    doc["servers"]["fetch"]["envelope"]["entry"]["allowAcceptFlag"] = True
    lock_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    refuse(tmp_path, setup, "no trusted key verifies this entry")


def test_untrusted_signer_is_refused(tmp_path):
    setup = signed_setup(tmp_path)
    other = signed_setup(tmp_path / "other")
    setup.config = other.config
    refuse(tmp_path, setup, "no trusted key verifies this entry")


def test_rollback_below_the_high_water_mark_is_refused(tmp_path):
    newer = signed_setup(tmp_path, seq=5)
    p = ProxyProcess(newer)
    assert p.close() == 0
    older = signed_setup(tmp_path, seq=4)
    refuse(tmp_path, older, "rollback refused")


def test_launch_mismatch_is_refused_before_spawn(tmp_path):
    setup = signed_setup(tmp_path)
    (setup.lock_dir / "script.json").write_text('{"tools": []}')
    refuse(tmp_path, setup, "pinned file script.json differs")
    assert not (setup.state / "attest").exists() or not list((setup.state / "attest").iterdir())


def test_observe_needs_allow_observe(tmp_path):
    refuse(tmp_path, signed_setup(tmp_path), "requires allowObserve", mode="observe")


def test_expired_observe_entry_is_refused(tmp_path):
    setup = signed_setup(tmp_path, issued="2026-09-01T00:00:00Z", not_after="2026-09-01T12:00:00Z",
                         allowObserve=True)
    refuse(tmp_path, setup, "expired", mode="observe")


def test_observe_entry_with_no_not_after_starts_long_after_issue(tmp_path):
    # Owner decision 2026-10-05: an observe entry the owner signed with no
    # notAfter keeps working until the owner replaces it, here a year on.
    issued = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    setup = signed_setup(tmp_path, issued=issued, allowObserve=True)
    p = ProxyProcess(setup, mode="observe")
    p.send(init(0))
    assert "result" in p.recv()
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/list"))
    assert p.recv()["result"]["tools"]
    assert p.close() == 0


def test_state_dir_inside_a_git_worktree_is_refused(tmp_path):
    setup = signed_setup(tmp_path)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    refuse(tmp_path, setup, "inside a git worktree", state_dir=repo / "state")


def test_docker_desktop_share_detection():
    info = ("22 1 0:21 / / rw,relatime - overlay overlay rw\n"
            "40 22 0:35 / /work rw,relatime - fakeowner /run/host_mark rw\n"
            "41 22 0:36 / /work/local rw,relatime - ext4 /dev/vda1 rw\n")
    assert proxy.docker_desktop_shared(Path("/work/state"), info)
    assert not proxy.docker_desktop_shared(Path("/work/local/state"), info)
    assert not proxy.docker_desktop_shared(Path("/home/u/.local/state"), info)


def test_scrubber_rewrites_home_lock_and_cwd(tmp_path):
    lock_dir = tmp_path / "proj"
    s = proxy.Scrubber(lock_dir, tmp_path)
    assert s(f"{lock_dir}/a {tmp_path}/b {HOME}/c") == "./a ./b ~/c"


def test_os_errors_print_only_the_file_name(tmp_path):
    err = FileNotFoundError(2, "No such file or directory", str(tmp_path / "deep" / "cxbom.lock"))
    assert proxy.os_message(err) == "cxbom.lock: No such file or directory"


def test_exit_codes():
    assert proxy.exit_code("internal-error", 0) == 70
    assert proxy.exit_code("attestation-io", 0) == 70
    assert proxy.exit_code("eof", 3) == 3
    assert proxy.exit_code("signal", -9) == 137


# ----- adaptations beyond the brief --------------------------------------------------


def test_bad_events_path_is_refused_before_spawn_and_before_the_log(tmp_path):
    setup = signed_setup(tmp_path)
    target = tmp_path / "real.jsonl"
    target.write_text("")
    link = tmp_path / "events.jsonl"
    link.symlink_to(target)
    err = refuse(tmp_path, setup, "sidecar events.jsonl", events=str(link))
    assert "Traceback" not in err
    assert not (setup.state / "attest").exists() or not list((setup.state / "attest").iterdir())


def test_events_sidecar_is_written_and_scrubbed(tmp_path):
    setup = signed_setup(tmp_path)
    events = tmp_path / "events.jsonl"
    p = ProxyProcess(setup, events=str(events))
    p.send(init(0))
    p.recv()
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/call", {"name": f"{HOME}/secret", "arguments": {}}))
    reply = p.recv()
    while "id" not in reply:
        reply = p.recv()
    assert HOME not in json.dumps(reply) and "~/secret" in reply["error"]["message"]
    assert p.close() == 0
    lines = [json.loads(line) for line in events.read_text().splitlines()]
    assert lines and {line["proxySessionId"] for line in lines} == {p.log_path().stem.split("-", 1)[1]}
    assert HOME not in events.read_text()
    assert proxy.WITHHELD in [e["data"]["tool"] for e in lines if e["type"] == "gate_decision"]
    assert HOME not in p.log_path().read_text()


def test_scrubber_rewrites_user_host_and_ip(tmp_path):
    s = proxy.Scrubber(None, tmp_path)
    user = pwd.getpwuid(os.getuid()).pw_name
    host = socket.gethostname()
    out = s(f"user {user} on {host} at 192.168.1.20 and fe80::1ff:fe23:4567:890a")
    assert user not in out.split() and host not in out
    assert "<user>" in out and "<host>" in out
    assert "192.168.1.20" not in out and "fe80::1ff" not in out
    assert s("at 18:00:00 seq 3.14") == "at 18:00:00 seq 3.14"


def test_scrubber_rewrites_ipv4_with_a_trailing_or_leading_period(tmp_path):
    # A sentence-final period, or a period from surrounding text run
    # straight up against the address, must not save the digits: the old
    # lookarounds treated any adjacent period as proof the match was really
    # a longer number and skipped it entirely (the demo sidecar leak).
    s = proxy.Scrubber(None, tmp_path)
    assert s("reached 10.0.0.1.") == "reached <ip>."
    assert s("host.10.0.0.5 answered") == "host.<ip> answered"


def _held_loop(tmp_path):
    return Loop(tmp_path, entry(), proxy.ProxyCore)


def test_pending_table_cap_refuses_new_requests(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_IN_FLIGHT", 3)
    loop = _held_loop(tmp_path)
    for i in range(3):
        loop.send(rpc(10 + i, "ping"), hold=True)
    loop.send(rpc(99, "ping"), hold=True)
    (refused,) = loop.take()
    assert refused["id"] == 99 and refused["error"]["code"] == -32603
    assert len(loop.to_server) == 3
    loop.pump()
    assert sorted(m["id"] for m in loop.take()) == [10, 11, 12]
    loop.send(rpc(100, "ping"))
    assert loop.take() == [{"jsonrpc": "2.0", "id": 100, "result": {}}]


def test_pending_cap_refuses_server_requests(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_IN_FLIGHT", 1)
    loop = _held_loop(tmp_path)
    loop.send(rpc(1, "ping"), hold=True)
    sent = []
    loop.core.to_server = sent.append
    loop.core.from_server(rpc("s1", "roots/list"))
    (line,) = sent
    assert json.loads(line)["error"]["code"] == -32603
    assert loop.take() == []


def test_in_flight_byte_cap_refuses_new_requests(tmp_path, monkeypatch):
    # The count cap alone would let 3 requests this size through (default
    # 4096). Each string id is under MAX_ID_RAW but big enough that two of
    # them exhaust a small byte budget.
    monkeypatch.setattr(proxy, "MAX_IN_FLIGHT_BYTES", 2200)
    loop = _held_loop(tmp_path)
    big = "i" * 1000
    loop.send(rpc(big + "1", "ping"), hold=True)
    loop.send(rpc(big + "2", "ping"), hold=True)
    loop.send(rpc(big + "3", "ping"), hold=True)
    (refused,) = loop.take()
    assert refused["id"] == big + "3"
    assert refused["error"] == {"code": -32603, "message": "cxbom: too many bytes in flight"}
    assert len(loop.to_server) == 2
    loop.pump()
    assert sorted(m["id"] for m in loop.take()) == sorted([big + "1", big + "2"])
    # The two answered requests dropped out of the pending table, freeing
    # the budget for a new one.
    loop.send(rpc("small", "ping"))
    assert loop.take() == [{"jsonrpc": "2.0", "id": "small", "result": {}}]


def test_in_flight_byte_cap_counts_held_calls(tmp_path, monkeypatch):
    # A held call keeps the full request and its (possibly edited) outgoing
    # copy in memory until its re-list chain settles. The entry-count cap
    # alone does not see that: this is the gap it leaves open.
    monkeypatch.setattr(proxy, "MAX_IN_FLIGHT_BYTES", 4600)
    loop = _held_loop(tmp_path)
    pad = "x" * 900

    def call(rid):
        return rpc(rid, "tools/call", {"name": "fetch", "arguments": {"pad": pad}})

    loop.send(call(1), hold=True)
    loop.send(call(2), hold=True)
    loop.send(call(3), hold=True)
    (refused,) = [m for m in loop.take() if m.get("id") == 3]
    assert refused["error"] == {"code": -32603, "message": "cxbom: too many bytes in flight"}
    assert len(loop.core.held_calls) == 2


def test_own_relist_requests_are_exempt_from_the_byte_cap(tmp_path, monkeypatch):
    # The proxy's own tools/list and server/discover requests never pass
    # through _client_request or _server_request, so they are exempt from
    # the byte cap the same way they are exempt from the count cap: not by
    # a special case in the check, but because _own_request never reaches
    # either gate. 210 fits exactly one held call (80 bytes in, 80 out,
    # plus its own re-list request's small id_raw): no room is left for
    # the second call's own admission check, but the first call's own
    # re-list request still goes out.
    monkeypatch.setattr(proxy, "MAX_IN_FLIGHT_BYTES", 210)
    loop = _held_loop(tmp_path)
    loop.send(rpc(1, "tools/call", {"name": "fetch"}), hold=True)
    assert len(loop.core.held_calls) == 1
    assert len(loop.to_server) == 1
    assert json.loads(loop.to_server[0])["method"] == "tools/list"
    # The budget the own request quietly used up is real: an ordinary
    # second call, sized the same as the first, no longer fits.
    loop.send(rpc(2, "tools/call", {"name": "fetch"}), hold=True)
    (refused,) = loop.take()
    assert refused["id"] == 2
    assert refused["error"] == {"code": -32603, "message": "cxbom: too many bytes in flight"}


def test_line_writer_over_budget_raises_instead_of_growing(tmp_path):
    r, w = os.pipe()
    writer = relay.LineWriter(w, "t", max_queued_bytes=256 * 1024)
    os.close(w)
    chunk = b"x" * (32 * 1024)
    with pytest.raises(relay.WriterOverflow):
        for _ in range(64):              # 2 MiB against a 64 KiB pipe nobody reads
            writer.send(chunk)
    os.set_blocking(r, False)
    try:
        while os.read(r, 1 << 16):
            pass
    except BlockingIOError:
        pass
    os.close(r)
    writer.stop(1.0)


def test_line_writer_budget_is_released_as_lines_drain(tmp_path):
    r, w = os.pipe()
    writer = relay.LineWriter(w, "t", max_queued_bytes=4096)
    os.close(w)
    for _ in range(200):
        writer.send(b"y" * 1000)
        assert os.read(r, 1001) == b"y" * 1000 + b"\n"
    assert writer.stop(1.0)
    os.close(r)


# ----- fix round 1: attestation-down blocking, in-flight byte bound, writer overflow --


def test_writer_overflow_in_a_real_subprocess_exits_70(tmp_path):
    # The child never reads its stdin, so the proxy's write queue toward it
    # backs up deterministically once the OS pipe fills, instead of racing
    # against how fast a real child happens to drain it.
    setup = signed_setup(tmp_path, script={"neverReadStdin": True})
    p = ProxyProcess(setup)
    pad = "x" * (8 * 1024 * 1024)  # ~17 of these clear the 128 MiB writer budget

    def flood():
        try:
            for i in range(40):
                p.send(rpc(i, "ping", {"pad": pad}))
        except OSError:
            pass  # the proxy stopped reading once it hit the overflow

    threading.Thread(target=flood, daemon=True).start()
    assert p.proc.wait(timeout=60) == 70
    err = p.stderr()
    assert "writer overflowed" in err
    lines = attestation.read_log(p.wait_for_log())
    assert lines[-1]["reason"] == "internal-error"
    assert any(line["kind"] == "diagnostic" and "writer overflowed" in line["message"] for line in lines)


def test_attestation_io_in_observe_exits_70(tmp_path):
    not_after = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    setup = signed_setup(tmp_path, allowObserve=True, not_after=not_after)
    p = ProxyProcess(setup, mode="observe", env={"CXBOM_TEST_BREAK_ATTESTATION_AFTER": "4"})
    p.send(init(0))
    p.recv()
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/list"))
    p.recv()
    # The second listing's own verdict write is the 5th attestation write,
    # the one CXBOM_TEST_BREAK_ATTESTATION_AFTER=4 breaks.
    p.send(rpc(2, "tools/list"))
    blocked = p.recv()
    assert blocked["error"] == {"code": -32603,
                                "message": "cxbom: attestation is unavailable. Everything is blocked"}
    assert p.proc.wait(timeout=15) == 70


def test_attestation_io_in_enforce_blocks_everything_and_exits_70_at_shutdown(tmp_path):
    # swapAfterList=2 makes the server's answer to the second listing carry
    # a notifications/tools/list_changed line in the same batch: a server
    # line that arrives the instant attestation_down is set.
    setup = signed_setup(tmp_path, script={"swapAfterList": 2})
    p = ProxyProcess(setup, env={"CXBOM_TEST_BREAK_ATTESTATION_AFTER": "4"})
    p.send(init(0))
    p.recv()
    p.send(note("notifications/initialized"))
    p.send(rpc(1, "tools/list"))
    listed = p.recv()
    assert [t["name"] for t in listed["result"]["tools"]] == ["fetch"]
    # Fix round 2, the regression the round-1 fix introduced: pipeline a
    # ping right behind the listing that triggers the break, both without
    # waiting for a reply. By the time the break is detected mid-listing,
    # this ping is already forwarded and sitting in the pending table.
    # _attestation_failed's proactive sweep must fail it there and then,
    # not leave it for a server answer that _blocked_server_line now drops.
    p.send(rpc(2, "tools/list"))
    p.send(rpc(99, "ping"))
    block_all = {"code": -32603, "message": "cxbom: attestation is unavailable. Everything is blocked"}
    replies = {}
    while len(replies) < 2:
        msg = p.recv()
        replies[msg["id"]] = msg
    assert replies[2] == {"jsonrpc": "2.0", "id": 2, "error": block_all}
    assert replies[99] == {"jsonrpc": "2.0", "id": 99, "error": block_all}
    # Nothing is forwarded once enforce is blocked: not a new client
    # request (ping), and not the server's list_changed notification that
    # rode along with the answer above. If it had leaked through, it
    # would be sitting ahead of these replies in the queue.
    p.send(rpc(3, "ping"))
    refused = p.recv()
    assert refused == {"jsonrpc": "2.0", "id": 3,
                       "error": {"code": -32603,
                                 "message": "cxbom: attestation is unavailable. Everything is blocked"}}
    # Enforce blocks. It does not tear the session down on the spot the way
    # observe does (spec 8.6). Only the client's own EOF ends it.
    assert p.proc.poll() is None
    assert p.close(timeout=15) == 70


def test_an_entry_signed_under_older_env_rules_is_refused_at_launch(tmp_path):
    setup = signed_setup(tmp_path, pin_env=["PERL5OPT"],
                         extra_env={"PERL5OPT": "-Mevil"})
    refuse(tmp_path, setup, "--pin-env PERL5OPT loads code into the server")
    assert not (setup.state / "attest").exists() or not list((setup.state / "attest").iterdir())


# ----- Task 14b: launch_refused (C2 1.2.0) --------------------------------------------


def _no_attest(setup):
    assert not (setup.state / "attest").exists() or not list((setup.state / "attest").iterdir())


def _one_sidecar_event(path):
    lines = path.read_text().splitlines()
    assert len(lines) == 1, lines
    return json.loads(lines[0])


def test_argv_mismatch_writes_one_launch_refused_item_argv(tmp_path):
    setup = signed_setup(tmp_path)
    setup.argv = setup.argv + ["--extra"]
    events = tmp_path / "events.jsonl"
    code, err = run_refused(setup, events=str(events))
    assert code == 2
    ev = _one_sidecar_event(events)
    assert ev["type"] == "launch_refused" and ev["proxySessionId"] is None and ev["localSeq"] == 0
    assert ev["data"] == {"serverId": "fetch", "item": "argv", "exitCode": 2,
                          "reason": "the server command differs from the signed argv at argv[4]: --extra"}
    _no_attest(setup)


def test_changed_pinned_file_writes_one_launch_refused_item_files(tmp_path):
    setup = signed_setup(tmp_path)
    (setup.lock_dir / "script.json").write_text('{"tools": []}')
    events = tmp_path / "events.jsonl"
    code, err = run_refused(setup, events=str(events))
    assert code == 2
    ev = _one_sidecar_event(events)
    assert ev["data"] == {"serverId": "fetch", "item": "files", "exitCode": 2,
                          "reason": "pinned file script.json differs from the signed pin"}
    _no_attest(setup)


def test_pinned_env_mismatch_writes_one_launch_refused_item_env(tmp_path):
    setup = signed_setup(tmp_path, pin_env=["FOO"], extra_env={"FOO": "bar"})
    events = tmp_path / "events.jsonl"
    code, err = run_refused(setup, events=str(events), env={"FOO": "changed"})
    assert code == 2
    ev = _one_sidecar_event(events)
    assert ev["data"] == {"serverId": "fetch", "item": "env", "exitCode": 2,
                          "reason": "environment variable FOO differs from its pin"}
    _no_attest(setup)


def test_launchpolicy_refusal_writes_one_launch_refused_item_policy(tmp_path):
    setup = signed_setup(tmp_path, pin_env=["PERL5OPT"], extra_env={"PERL5OPT": "-Mevil"})
    events = tmp_path / "events.jsonl"
    code, err = run_refused(setup, events=str(events))
    assert code == 2
    ev = _one_sidecar_event(events)
    assert ev["data"]["item"] == "policy"
    assert "PERL5OPT loads code into the server" in ev["data"]["reason"]
    _no_attest(setup)


def test_rollback_refusal_writes_one_launch_refused_item_entry(tmp_path):
    newer = signed_setup(tmp_path, seq=5)
    assert ProxyProcess(newer).close() == 0
    # The successful run above already left its own attestation file, so the
    # no-spawn evidence here is that the refused run below adds none of its own.
    before = set((newer.state / "attest").iterdir())
    older = signed_setup(tmp_path, seq=4)
    events = tmp_path / "events.jsonl"
    code, err = run_refused(older, events=str(events))
    assert code == 2
    ev = _one_sidecar_event(events)
    assert ev["data"]["item"] == "entry"
    assert "rollback refused" in ev["data"]["reason"]
    assert set((older.state / "attest").iterdir()) == before


def test_check_launch_item_none_is_not_converted_to_a_startup_refusal(tmp_path, monkeypatch):
    """Fix round 1 ruling: a LaunchError with item=None (a bug in
    check_launch's own item coverage, not a real launch refusal) must not be
    reported as a launch_refused event or converted to exit 2. It propagates
    as a raw LaunchError, so run() reports it as an internal error (exit 70)
    the same as any other unexpected exception during startup."""
    setup = signed_setup(tmp_path)
    monkeypatch.setattr(launch, "check_launch",
                        lambda *a, **k: (_ for _ in ()).throw(launch.LaunchError("mystery failure")))
    environ = dict(os.environ, **setup.environ)
    scrub = proxy.Scrubber(None, setup.lock_dir)
    opts = proxy.ProxyOptions(server_id="fetch", command=list(setup.argv), state_dir=str(setup.state))
    with pytest.raises(launch.LaunchError, match="mystery failure"):
        proxy._startup(opts, setup.config, environ, setup.lock_dir, scrub)


def test_observe_refusal_without_allow_observe_writes_no_event(tmp_path):
    setup = signed_setup(tmp_path)
    events = tmp_path / "events.jsonl"
    code, err = run_refused(setup, mode="observe", events=str(events))
    assert code == 2
    assert events.exists() and events.read_text() == ""


def test_launch_refused_reason_is_scrubbed(tmp_path):
    # Exercises EventSink.emit_pre_session and proxy._refuse_launch directly:
    # every existing LaunchError message already names only basenames (spec
    # 3), so there is no live check_launch path that leaks a full path today.
    # This is the defense-in-depth net for the day one does.
    lock_dir = tmp_path / "proj"
    events_path = tmp_path / "events.jsonl"
    scrub = proxy.Scrubber(lock_dir, tmp_path)
    opts = proxy.ProxyOptions(server_id="fetch", command=["x"], events=str(events_path))
    sink = proxy._open_events(opts, scrub)
    proxy._refuse_launch(sink, "fetch", "files", f"{lock_dir}/secret.json differs from the signed pin")
    sink.close()
    ev = _one_sidecar_event(events_path)
    assert ev["data"]["reason"] == "./secret.json differs from the signed pin"
    assert str(lock_dir) not in ev["data"]["reason"]


def test_launch_refused_canary_straddling_512_is_fully_redacted(tmp_path):
    # Fix round 1, reviewer finding: cutting the reason to 512 characters
    # before redaction could split a canary token in two, leaving the
    # surviving half unmatched and unredacted. The canary here starts before
    # character 512 and ends after it.
    events_path = tmp_path / "events.jsonl"
    canary = "abcdefgh" * 5  # 40 characters, an isolated token (spaces on both sides)
    canary_hash = hashlib.sha256(canary.encode()).hexdigest()
    reason = ("x" * 500) + " " + canary + " " + ("y" * 40)
    assert 500 < reason.index(canary) + len(canary) < len(reason)  # confirm it straddles index 512
    sink = proxy.EventSink(events_path, "", redact_sha256=[canary_hash], scrub=None)
    proxy._refuse_launch(sink, "fetch", "files", reason)
    sink.close()
    ev = _one_sidecar_event(events_path)
    assert ev["data"]["reason"] == "<canary>"
    assert canary not in ev["data"]["reason"]


def test_bad_events_path_writes_no_launch_refused(tmp_path):
    setup = signed_setup(tmp_path)
    target = tmp_path / "real.jsonl"
    target.write_text("")
    link = tmp_path / "events.jsonl"
    link.symlink_to(target)
    code, err = run_refused(setup, events=str(link))
    assert code == 2
    assert target.read_text() == ""


def test_argv_mismatch_stderr_names_the_index_with_the_home_path_scrubbed(tmp_path):
    """Final review C8 (the J2 demo's S4): the operator sees where argv
    changed, and a home path in the changed value is shown as ~."""
    setup = signed_setup(tmp_path)
    setup.argv = [setup.argv[0], HOME + "/evil_server.py"] + setup.argv[2:]
    err = refuse(tmp_path, setup, "the server command differs from the signed argv at argv[1]: ~/evil_server.py")
    assert "evil_server.py" in err


def _run_in_process(setup, tmp_path, config_dir=None):
    """proxy.run in this process, with stderr captured through a pipe."""
    r, w = os.pipe()
    environ = dict(os.environ, **setup.environ)
    opts = proxy.ProxyOptions(server_id="fetch", command=list(setup.argv), state_dir=str(setup.state))
    try:
        code = proxy.run(opts, config_dir=config_dir or setup.config, environ=environ, cwd=setup.lock_dir,
                         stdin_fd=os.open(os.devnull, os.O_RDONLY), stderr_fd=w)
    finally:
        os.close(w)
    with os.fdopen(r, "rb") as f:
        return code, f.read().decode()


def test_a_spawn_failure_exits_70_to_match_its_internal_error_end_line(tmp_path, monkeypatch):
    """Final review B6: the log said internal-error while the exit code said startup refusal."""
    setup = signed_setup(tmp_path)

    def fail(plan, grace=launch.WATCHDOG_GRACE_S):
        raise launch.LaunchError("python3: cannot start the server")

    monkeypatch.setattr(launch, "spawn", fail)
    code, err = _run_in_process(setup, tmp_path)
    assert code == proxy.EXIT_INTERNAL == 70
    assert "cannot start the server" in err
    (log,) = (setup.state / "attest").glob("fetch-*.jsonl")
    assert attestation.read_log(log)[-1]["reason"] == "internal-error"


def test_a_missing_config_directory_says_to_run_keygen(tmp_path):
    """Final review C7."""
    setup = signed_setup(tmp_path)
    code, err = _run_in_process(setup, tmp_path, config_dir=tmp_path / "no-such-config")
    assert code == 2
    assert "Run cxbom keygen" in err and "does not exist" not in err


def test_sidecar_events_are_scrubbed_with_the_lock_directory_known(tmp_path):
    """Final review B3: the sidecar kept the scrubber built before the lock
    directory was known, so a lock directory outside the working directory
    showed up in events as a temp path rather than as "."."""
    setup = signed_setup(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    events = tmp_path / "events.jsonl"
    p = ProxyProcess(setup, events=str(events), cwd=elsewhere, lock=str(setup.lock_dir / "cxbom.lock"))
    p.send(init(0))
    p.recv()
    p.send(rpc(5, f"{setup.lock_dir}/custom"))
    p.recv()
    assert p.close() == 0
    summaries = [json.loads(line)["data"].get("summary") for line in events.read_text().splitlines()]
    assert "agent sends ./custom" in summaries, summaries
