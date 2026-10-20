"""Write-ahead attestation log for one proxy session.

Owner: ATACE Working Group.

The proxy writes each line in a single os.write on an O_APPEND | O_CLOEXEC
descriptor. It writes the line before it forwards the message that caused it,
so a record can never bind to a verdict the log does not hold yet (premortem
B1). The writer holds an exclusive flock for its whole life. A reader proves
the session is live by failing to take a shared lock, and the kernel drops the
lock when the process dies (C22). Because the descriptor is O_CLOEXEC, no
child process can inherit it and keep the lock alive.

Every line is checked against the C3 attestation-line schema before it leaves
the process (AttestationWriter.append) and again before it is trusted back
(check_log), so a malformed verdict can neither be written nor be believed
once read. read_log itself goes through jsonstrict, not the stdlib json
module, so a duplicate key or a non-finite number in a line is a read
failure, not a silently accepted parser differential (premortem A3, B3).

A failed os.write can leave a truncated JSON fragment as the log's last
bytes (spec 8.6). The writer latches into a broken state at that point and
refuses every append except end("attestation-io"), which closes the
fragment with a leading newline and its own single write so the log ends on
a real line a reader can trust. read_log tolerates exactly that one pattern:
an unparseable line immediately followed by that end record, nothing else.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import uuid
from datetime import datetime
from importlib import resources
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from . import jsonstrict
from .paths import ensure_private_dir
from .timeutil import now_rfc3339, parse_time

_SERVER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class AttestationIOError(RuntimeError):
    """An attestation line could not be written or read in full."""


class AttestationFormatError(ValueError):
    """An attestation line is not strict JSON, or fails the C3 schema."""


def _require_formats(checker: FormatChecker) -> None:
    # jsonschema skips "date-time" silently when its optional extra is not
    # installed, and every time in the C3 schemas would then pass unchecked.
    missing = [f for f in ("date-time", "uuid") if f not in checker.checkers]
    if missing:
        raise RuntimeError(
            f"jsonschema FormatChecker lacks {', '.join(missing)}. Install the pins in "
            "pyproject.toml: jsonschema[format-nongpl] and rfc3339-validator, which provides date-time")


def _load_schema() -> Draft202012Validator:
    text = resources.files("cxbom").joinpath("_data/attestation-line.schema.json").read_text()
    checker = FormatChecker()
    _require_formats(checker)
    return Draft202012Validator(json.loads(text), format_checker=checker)


_SCHEMA = _load_schema()


def _schema_errors(doc, where: str) -> list[str]:
    return [f"{where}{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
            for e in sorted(_SCHEMA.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))]


def _encode(obj: dict) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


class AttestationWriter:
    """One proxy session's append-only attestation log.

    Raises:
        ValueError: server_id is not a valid server id, session is not a
            dict, or session["serverId"] differs from server_id.
        AttestationFormatError: the session line fails the C3 schema.
        AttestationIOError: the log file cannot be created or written.
        PathSecurityError: the log directory is redirected or not private.
    """

    def __init__(self, directory: Path, server_id: str, session: dict):
        # Reject a bad server_id or a session that names a different server
        # before touching the filesystem at all: a path built from an
        # unchecked server_id is a path-traversal vector (the "../escape"
        # case), and a mismatched serverId would attest to the wrong server.
        if not isinstance(server_id, str) or not _SERVER_ID.fullmatch(server_id):
            raise ValueError(f"server_id {server_id!r} is not a valid server id")
        if not isinstance(session, dict):
            raise ValueError(f"session must be a dict, got {type(session).__name__}")
        if session.get("serverId") != server_id:
            raise ValueError(
                f"session serverId {session.get('serverId')!r} does not match server_id {server_id!r}")
        ensure_private_dir(directory)
        self.proxy_session_id = str(uuid.uuid4())
        self.path = directory / f"{server_id}-{self.proxy_session_id}.jsonl"
        try:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC, 0o600)
        except OSError as e:
            raise AttestationIOError(f"{self.path.name}: {e.strerror}") from None
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.seq = 0
            self._ended = False
            self._broken = False
            self._partial = False
            self._partial_whole = False
            self._write(dict(session, kind="session", proxySessionId=self.proxy_session_id))
        except BaseException:
            # A failure past this point must not leak the descriptor or hold
            # the flock past the object's lifetime, since nothing else will
            # ever call close() on a writer that never finished __init__.
            os.close(self.fd)
            raise

    def _raw_write(self, data: bytes) -> None:
        try:
            n = os.write(self.fd, data)
        except OSError as e:
            # A write that raised put no bytes on disk, so no fragment to close.
            self._broken = True
            self._partial = False
            self._partial_whole = False
            raise AttestationIOError(f"{self.path.name}: {e.strerror}") from None
        if n != len(data):
            self._broken = True
            self._partial = n > 0
            # Only the closing newline missing: the newline _end_broken
            # leads with turns this fragment into a whole, parseable line.
            self._partial_whole = n == len(data) - 1
            raise AttestationIOError(f"short attestation write ({n} of {len(data)} bytes)")

    def _write(self, obj: dict) -> None:
        errs = _schema_errors(obj, "attestation:")
        if errs:
            raise AttestationFormatError("; ".join(errs))
        self._raw_write(_encode(obj))

    def append(self, kind: str, /, **fields) -> int:
        # kind is positional-only so a caller cannot smuggle a second "kind"
        # into fields by keyword. The check below still catches it if they
        # try, alongside the "seq" and "at" fields append() itself assigns.
        reserved = fields.keys() & {"kind", "seq", "at"}
        if reserved:
            raise ValueError(f"append() fields must not include {sorted(reserved)}: they are assigned by append()")
        if kind == "end":
            # An end line written here would skip the ended latch and the
            # fsync, so every ending goes through end().
            raise ValueError("append() cannot write an end line. Call end(reason)")
        return self._append(kind, fields)

    def _append(self, kind: str, fields: dict) -> int:
        if self._ended:
            raise AttestationIOError("attestation log already ended")
        if self._broken:
            raise AttestationIOError("attestation log is broken after a failed write. Call end('attestation-io')")
        seq = self.seq + 1                 # commit only after a full write succeeds (below)
        self._write({"kind": kind, "seq": seq, "at": now_rfc3339(), **fields})
        self.seq = seq
        return seq

    def _end_broken(self, reason: str) -> None:
        # When a prior write failed partway through, the file's last bytes
        # are a truncated JSON fragment with no trailing newline. A leading
        # newline closes that fragment as its own (unparseable) line, and the
        # whole thing goes out in one os.write so the fragment and its
        # terminator never get split across two writes. A write that raised
        # left nothing behind, and a leading newline there would add an
        # empty line that read_log rejects. A fragment missing only its
        # newline becomes a whole line once that newline lands, and it holds
        # the seq the failed write took, so end takes the one after it.
        seq = self.seq + (2 if self._partial_whole else 1)
        obj = {"kind": "end", "seq": seq, "at": now_rfc3339(), "reason": reason}
        errs = _schema_errors(obj, "attestation:")
        if errs:
            raise AttestationFormatError("; ".join(errs))
        self._raw_write((b"\n" if self._partial else b"") + _encode(obj))
        self.seq = seq
        self._ended = True

    def end(self, reason: str) -> None:
        if self._ended:
            raise AttestationIOError("attestation log already ended")
        if self._broken:
            if reason != "attestation-io":
                raise AttestationIOError(
                    "attestation log is broken. Only end('attestation-io') can close it")
            self._end_broken(reason)
        else:
            self._append("end", {"reason": reason})
            self._ended = True
        try:
            os.fsync(self.fd)
        except OSError as e:
            raise AttestationIOError(f"{self.path.name}: {e.strerror}") from None

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _parse_as_end_attestation_io(raw: bytes) -> bool:
    try:
        obj = jsonstrict.to_python(jsonstrict.parse(raw))
    except jsonstrict.StrictJSONError:
        return False
    return isinstance(obj, dict) and obj.get("kind") == "end" and obj.get("reason") == "attestation-io"


def read_log(path: Path) -> list[dict]:
    try:
        data = path.read_bytes()
    except OSError as e:
        raise AttestationIOError(f"{path.name}: {e.strerror}") from None
    parts = data.split(b"\n")
    complete = parts[:-1]              # the final element is empty or a partial line
    n = len(complete)
    lines: list[dict] = []
    i = 0
    while i < n:
        raw = complete[i]
        line_no = i + 1
        if raw == b"":
            raise AttestationFormatError(f"line {line_no}: empty line")
        try:
            obj = jsonstrict.to_python(jsonstrict.parse(raw))
        except jsonstrict.StrictJSONError as e:
            # Tolerate exactly one unparseable line when it is immediately
            # followed by the log's final line and that line is the broken
            # writer's own termination record (end/attestation-io).
            if i == n - 2 and _parse_as_end_attestation_io(complete[i + 1]):
                i += 1
                continue
            raise AttestationFormatError(f"line {line_no}: {e}") from None
        lines.append(obj)
        i += 1
    return lines


def check_log(lines: list[dict]) -> list[str]:
    if not lines:
        return ["attestation: log is empty"]
    errs: list[str] = []
    for i, line in enumerate(lines):
        errs += _schema_errors(line, f"attestation[{i}]:")
    if errs:
        return errs
    if lines[0].get("kind") != "session":
        return ["attestation: first line must be the session line"]
    if type(lines[0].get("pid")) is not int:
        errs.append("attestation: line 0 pid must be an integer, not a float or bool")
    expected = 1
    prev_at: datetime | None = None
    for i, line in enumerate(lines[1:], start=1):
        if line["kind"] == "session":
            errs.append(f"attestation: line {i} is a second session line")
            break
        if type(line["seq"]) is not int:
            errs.append(f"attestation: line {i} seq must be an integer, not a float or bool")
            break
        if line["seq"] != expected:
            errs.append(f"attestation: line {i} seq {line['seq']} breaks contiguity (expected {expected})")
            break
        expected += 1
        try:
            cur_at = parse_time(line["at"])
        except ValueError:
            # The schema's pattern and format checks should make this
            # unreachable. If they ever disagree with parse_time, the log is
            # reported invalid rather than raising out of check_log.
            errs.append(f"attestation: line {i} time {line['at']!r} does not parse")
            break
        if prev_at is not None and cur_at < prev_at:
            errs.append(f"attestation: line {i} time {line['at']} is before the previous line's time")
        prev_at = cur_at
        if line["kind"] == "end" and i != len(lines) - 1:
            errs.append("attestation: lines after end")
    return errs


def is_live(path: Path) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)
