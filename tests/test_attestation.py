"""Write-ahead attestation log (spec 8.6, premortem B1, C22). Owner: ATACE Working Group."""
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from cxbom import attestation as at

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import checks  # noqa: E402

SESSION = {"contract": {"name": "cxbom-attestation", "version": "2.0.0"}, "serverId": "fetch",
           "mode": "enforce", "startedAt": "2026-10-10T18:00:00Z", "pid": 1,
           "envelopeSha256": "a" * 64, "keyFingerprint": "b" * 64, "launchSha256": "c" * 64}


def test_write_read_and_seq(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    assert w.append("verdict", itemType="tool", name="fetch", sha256="d" * 64, verdict="pinned-match",
                    approvedBy="demo-operator", approvedAt="2026-10-10T18:00:00Z",
                    approvalMode="interactive", storeRef=None) == 1
    w.end("eof")
    w.close()
    lines = at.read_log(w.path)
    assert [l["kind"] for l in lines] == ["session", "verdict", "end"]
    assert at.check_log(lines) == []
    assert (os.stat(tmp_path / "attest").st_mode & 0o777) == 0o700
    uuid.UUID(lines[0]["proxySessionId"])


def test_partial_final_line_ignored(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    w.append("diagnostic", message="x")
    with open(w.path, "ab") as f:
        f.write(b'{"kind":"diag')
    assert [l["kind"] for l in at.read_log(w.path)] == ["session", "diagnostic"]
    w.close()


def test_seq_gap_detected():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:00Z", "message": "a"},
             {"kind": "diagnostic", "seq": 3, "at": "2026-10-10T18:00:00Z", "message": "b"}]
    assert any("seq" in e for e in at.check_log(lines))


def test_liveness_via_flock(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    assert at.is_live(w.path)
    w.close()
    assert not at.is_live(w.path)


def test_killed_writer_releases_lock(tmp_path):
    code = (
        "import sys, time\n"
        "sys.path.insert(0, %r)\n"
        "from cxbom import attestation as at\n"
        "w = at.AttestationWriter(__import__('pathlib').Path(%r), 'fetch', %r)\n"
        "print(w.path, flush=True)\n"
        "time.sleep(60)\n"
    ) % (str(Path(__file__).resolve().parents[1]), str(tmp_path / "attest"), SESSION)
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    path = __import__("pathlib").Path(p.stdout.readline().strip())
    assert at.is_live(path)
    p.kill()
    p.wait()
    deadline = time.time() + 1.0
    while at.is_live(path) and time.time() < deadline:
        time.sleep(0.02)
    assert not at.is_live(path)


# --- Controller rulings that extend the brief, closing defect classes earlier reviews found ---


def test_read_log_rejects_duplicate_key_on_middle_line(tmp_path):
    path = tmp_path / "attest.jsonl"
    session_line = json.dumps(dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
                              sort_keys=True, separators=(",", ":")) + "\n"
    bad_line = '{"kind":"diagnostic","seq":1,"at":"2026-10-10T18:00:00Z","message":"a","message":"b"}\n'
    end_line = json.dumps({"kind": "end", "seq": 2, "at": "2026-10-10T18:00:00Z", "reason": "eof"},
                          sort_keys=True, separators=(",", ":")) + "\n"
    path.write_bytes((session_line + bad_line + end_line).encode())
    with pytest.raises(at.AttestationFormatError, match="line 2"):
        at.read_log(path)


def test_read_log_rejects_nan_on_middle_line(tmp_path):
    path = tmp_path / "attest.jsonl"
    session_line = json.dumps(dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
                              sort_keys=True, separators=(",", ":")) + "\n"
    bad_line = '{"kind":"diagnostic","seq":1,"at":"2026-10-10T18:00:00Z","message":NaN}\n'
    end_line = json.dumps({"kind": "end", "seq": 2, "at": "2026-10-10T18:00:00Z", "reason": "eof"},
                          sort_keys=True, separators=(",", ":")) + "\n"
    path.write_bytes((session_line + bad_line + end_line).encode())
    with pytest.raises(at.AttestationFormatError, match="line 2"):
        at.read_log(path)


def test_check_log_flags_unknown_verdict():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "verdict", "seq": 1, "at": "2026-10-10T18:00:00Z", "itemType": "tool", "name": "fetch",
              "sha256": "d" * 64, "verdict": "looks-fine", "approvedBy": None, "approvedAt": None,
              "approvalMode": None, "storeRef": None}]
    errs = at.check_log(lines)
    assert errs
    assert any("looks-fine" in e for e in errs)


def test_check_log_empty():
    assert at.check_log([]) == ["attestation: log is empty"]


def test_append_schema_failure_does_not_write(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    with pytest.raises(at.AttestationFormatError):
        w.append("verdict", itemType="tool")  # missing required verdict fields
    w.close()
    assert [l["kind"] for l in at.read_log(w.path)] == ["session"]


def test_writer_init_failure_closes_descriptor(tmp_path):
    # serverId matches server_id so the pre-open checks pass, but the
    # session is still missing the rest of its required fields, so the
    # schema check inside __init__ (after os.open) is what fails here.
    bad_session = {"contract": {"name": "cxbom-attestation", "version": "2.0.0"}, "serverId": "fetch"}
    with pytest.raises(at.AttestationFormatError):
        at.AttestationWriter(tmp_path / "attest", "fetch", bad_session)
    files = list((tmp_path / "attest").glob("*.jsonl"))
    assert len(files) == 1
    # If __init__ had leaked the descriptor, the flock it took would still be
    # held and is_live would report the (aborted) session as live.
    assert not at.is_live(files[0])


def test_end_wraps_fsync_oserror(tmp_path, monkeypatch):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)

    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(at.os, "fsync", boom)
    with pytest.raises(at.AttestationIOError):
        w.end("eof")
    monkeypatch.undo()
    w.close()


# --- Fix round 1 ---


def test_check_log_rejects_second_session_line():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:00Z", "message": "a"},
             dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4()))]
    errs = at.check_log(lines)
    assert any("second session line" in e for e in errs), errs


@pytest.mark.parametrize("field", ["kind", "seq", "at"])
def test_append_rejects_reserved_fields(tmp_path, field):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    with pytest.raises(ValueError):
        w.append("diagnostic", message="x", **{field: "override"})
    w.close()


def test_append_after_end_raises(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    w.end("eof")
    with pytest.raises(at.AttestationIOError, match="already ended"):
        w.append("diagnostic", message="x")
    w.close()


def test_short_write_then_end_attestation_io_recovers(tmp_path, monkeypatch):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    real_write = os.write
    used = {"once": False}

    def flaky(fd, data):
        if not used["once"]:
            used["once"] = True
            return real_write(fd, data[: len(data) // 2])  # a genuine short write to disk
        return real_write(fd, data)

    monkeypatch.setattr(at.os, "write", flaky)
    with pytest.raises(at.AttestationIOError):
        w.append("diagnostic", message="x")
    # Once broken, every append is refused until the writer is closed.
    with pytest.raises(at.AttestationIOError):
        w.append("diagnostic", message="y")
    w.end("attestation-io")
    monkeypatch.undo()
    w.close()
    lines = at.read_log(w.path)
    assert [l["kind"] for l in lines] == ["session", "end"]
    assert lines[-1]["seq"] == 1
    assert lines[-1]["reason"] == "attestation-io"
    assert at.check_log(lines) == []


def test_a_short_write_that_loses_only_the_newline_keeps_seq_contiguous(tmp_path, monkeypatch):
    # The whole object landed without its newline. The newline end leads
    # with makes that a whole diagnostic line holding seq 1, so end takes 2.
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    real_write = os.write
    used = {"once": False}

    def newline_lost(fd, data):
        if not used["once"]:
            used["once"] = True
            return real_write(fd, data[:-1])
        return real_write(fd, data)

    monkeypatch.setattr(at.os, "write", newline_lost)
    with pytest.raises(at.AttestationIOError):
        w.append("diagnostic", message="x")
    w.end("attestation-io")
    monkeypatch.undo()
    w.close()
    lines = at.read_log(w.path)
    assert [(l["kind"], l["seq"]) for l in lines[1:]] == [("diagnostic", 1), ("end", 2)]
    assert at.check_log(lines) == []
    assert checks.check_attestation_text(w.path.read_text()) == []


def test_broken_writer_end_rejects_other_reasons(tmp_path, monkeypatch):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    real_write = os.write

    def flaky(fd, data):
        return real_write(fd, data[: len(data) // 2])

    monkeypatch.setattr(at.os, "write", flaky)
    with pytest.raises(at.AttestationIOError):
        w.append("diagnostic", message="x")
    with pytest.raises(at.AttestationIOError):
        w.end("eof")  # only end("attestation-io") can close a broken writer
    monkeypatch.undo()
    w.end("attestation-io")
    w.close()


def test_is_live_missing_file_returns_false(tmp_path):
    assert not at.is_live(tmp_path / "does-not-exist.jsonl")


def test_check_log_rejects_offset_time():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:00+00:00", "message": "a"}]
    errs = at.check_log(lines)
    assert errs


def test_check_log_rejects_backwards_time():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:05Z", "message": "a"},
             {"kind": "diagnostic", "seq": 2, "at": "2026-10-10T18:00:00Z", "message": "b"}]
    errs = at.check_log(lines)
    assert any("time" in e for e in errs), errs


def test_writer_rejects_path_traversal_server_id(tmp_path):
    with pytest.raises(ValueError):
        at.AttestationWriter(tmp_path / "attest", "../escape", SESSION)
    assert not (tmp_path / "attest").exists()


def test_writer_rejects_mismatched_server_id(tmp_path):
    with pytest.raises(ValueError):
        at.AttestationWriter(tmp_path / "attest", "other-server", SESSION)


def test_check_log_rejects_wrong_contract_version():
    bad = dict(SESSION, contract={"name": "cxbom-attestation", "version": "1.0.0"},
              kind="session", proxySessionId=str(uuid.uuid4()))
    errs = at.check_log([bad])
    assert errs


def test_check_log_rejects_float_seq():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 1.0, "at": "2026-10-10T18:00:00Z", "message": "a"}]
    errs = at.check_log(lines)
    assert any("seq" in e for e in errs), errs


def test_check_log_rejects_float_pid():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4()), pid=1.0)]
    errs = at.check_log(lines)
    assert any("pid" in e for e in errs), errs


def test_read_log_rejects_embedded_empty_line(tmp_path):
    path = tmp_path / "attest.jsonl"
    session_line = json.dumps(dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
                              sort_keys=True, separators=(",", ":")) + "\n"
    end_line = json.dumps({"kind": "end", "seq": 1, "at": "2026-10-10T18:00:00Z", "reason": "eof"},
                          sort_keys=True, separators=(",", ":")) + "\n"
    path.write_bytes(session_line.encode() + b"\n" + end_line.encode())
    with pytest.raises(at.AttestationFormatError):
        at.read_log(path)


def test_check_log_flags_lines_after_end():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "end", "seq": 1, "at": "2026-10-10T18:00:00Z", "reason": "eof"},
             {"kind": "diagnostic", "seq": 2, "at": "2026-10-10T18:00:01Z", "message": "late"}]
    errs = at.check_log(lines)
    assert any("lines after end" in e for e in errs), errs


def test_check_log_flags_reordered_lines():
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 2, "at": "2026-10-10T18:00:01Z", "message": "b"},
             {"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:00Z", "message": "a"}]
    assert at.check_log(lines)


def test_check_log_flags_missing_session_first_line():
    lines = [{"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:00Z", "message": "a"}]
    errs = at.check_log(lines)
    assert any("session" in e for e in errs), errs


def test_writer_file_mode_is_0600(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    assert (os.stat(w.path).st_mode & 0o777) == 0o600
    w.close()


# --- Final review A2, A3 ---


def test_failed_write_with_nothing_written_then_end_attestation_io(tmp_path, monkeypatch):
    import errno
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    real_write = os.write
    used = {"once": False}

    def enospc(fd, data):
        if not used["once"]:
            used["once"] = True
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(at.os, "write", enospc)
    with pytest.raises(at.AttestationIOError):
        w.append("diagnostic", message="x")
    w.end("attestation-io")
    monkeypatch.undo()
    w.close()
    lines = at.read_log(w.path)
    assert [l["kind"] for l in lines] == ["session", "end"]
    assert at.check_log(lines) == []


def test_append_refuses_end_kind(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    with pytest.raises(ValueError, match="end"):
        w.append("end", reason="eof")
    w.end("eof")
    w.close()
    assert [l["kind"] for l in at.read_log(w.path)] == ["session", "end"]


# --- Final review B4 ---


@pytest.mark.parametrize("session", [None, ["serverId", "fetch"], "fetch"])
def test_writer_non_dict_session_is_value_error(tmp_path, session):
    with pytest.raises(ValueError):
        at.AttestationWriter(tmp_path / "attest", "fetch", session)
    assert not (tmp_path / "attest").exists()


def test_check_log_turns_parse_time_failure_into_an_error(monkeypatch):
    from cxbom import state
    lines = [dict(SESSION, kind="session", proxySessionId=str(uuid.uuid4())),
             {"kind": "diagnostic", "seq": 1, "at": "2026-10-10T18:00:00Z", "message": "a"}]

    def refuse(s):
        raise ValueError("unparseable")

    monkeypatch.setattr(at, "parse_time", refuse)
    errs = at.check_log(lines)
    assert any("line 1" in e and "time" in e for e in errs), errs
    with pytest.raises(state.StateError):
        state.compute(lines)


def test_attestation_requires_format_checkers():
    from jsonschema import FormatChecker
    with pytest.raises(RuntimeError, match="date-time"):
        at._require_formats(FormatChecker(formats=["uuid"]))
    with pytest.raises(RuntimeError, match="uuid"):
        at._require_formats(FormatChecker(formats=["date-time"]))
    at._require_formats(FormatChecker())


# --- Final review F5 ---


def test_final_complete_garbage_line_is_a_format_error(tmp_path):
    w = at.AttestationWriter(tmp_path / "attest", "fetch", SESSION)
    w.append("diagnostic", message="x")
    w.close()
    with open(w.path, "ab") as f:
        f.write(b"garbage\n")
    with pytest.raises(at.AttestationFormatError, match="line 3"):
        at.read_log(w.path)
