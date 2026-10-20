"""cxbom.lock discovery, canonical I/O, and signed-envelope verification.

Owner: ATACE Working Group.

The lock's location is not trusted. --lock, CXBOM_LOCK and walk-up discovery
only choose among envelopes that must still verify against the user's trust
manifest and pass the rollback high-water mark (premortem B2, C3).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Mapping

from jsonschema import Draft202012Validator, FormatChecker

from . import jsonstrict, signing
from .canonical import object_sha256

LOCK_NAME = "cxbom.lock"
MAX_LOCK_BYTES = 1024 * 1024
# I-JSON (RFC 7493) integers. A larger one reads differently in a consumer
# that parses numbers as doubles, and RFC 8785 cannot canonicalize it.
MAX_SAFE_INT = 2**53


class LockError(RuntimeError):
    """The lock is missing, malformed, unsigned, rolled back, or not for this server."""


def _require_formats(checker: FormatChecker) -> None:
    # jsonschema skips "date-time" silently when its optional extra is not
    # installed, and every time in the C3 schemas would then pass unchecked.
    missing = [f for f in ("date-time", "uuid") if f not in checker.checkers]
    if missing:
        raise RuntimeError(
            f"jsonschema FormatChecker lacks {', '.join(missing)}. Install the pins in "
            "pyproject.toml: jsonschema[format-nongpl] and rfc3339-validator, which provides date-time")


def _validator() -> Draft202012Validator:
    text = resources.files("cxbom").joinpath("_data/lockfile.schema.json").read_text()
    checker = FormatChecker()
    _require_formats(checker)
    return Draft202012Validator(json.loads(text), format_checker=checker)


_SCHEMA = _validator()


@dataclass(frozen=True)
class VerifiedEntry:
    server_id: str
    entry: dict
    envelope: dict
    envelope_sha256: str
    fingerprint: str
    entry_seq: int


def find_lock(start: Path, explicit: Path | None, environ: Mapping[str, str]) -> Path:
    if explicit is not None:
        return explicit
    if environ.get("CXBOM_LOCK"):
        return Path(environ["CXBOM_LOCK"])
    p = start.resolve()
    for candidate in (p, *p.parents):
        if (candidate / LOCK_NAME).is_file():
            return candidate / LOCK_NAME
    raise LockError("no cxbom.lock found")


def _unsafe_int(obj) -> bool:
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
        elif isinstance(cur, int) and not isinstance(cur, bool) and abs(cur) > MAX_SAFE_INT:
            return True
    return False


def read_lock(path: Path) -> dict:
    """Read, strictly parse, schema-check, and canonical-form-check a lock.

    Raises:
        LockError: the file cannot be read, is over 1 MiB, is not strict JSON
            (NaN, Infinity, duplicate keys, deep nesting, invalid UTF-8), holds
            an integer beyond 2**53, fails the C3 schema, or is not canonical.
    """
    try:
        data = path.read_bytes()
    except OSError as e:
        raise LockError(f"cannot read lock: {path.name}: {e.strerror}") from None
    try:
        doc = jsonstrict.to_python(jsonstrict.parse(data, max_bytes=MAX_LOCK_BYTES))
    except jsonstrict.StrictJSONError as e:
        raise LockError(f"lock is not strict JSON: {e}") from None
    if _unsafe_int(doc):
        raise LockError("lock holds an integer beyond 2**53")
    text = data.decode("utf-8")
    errs = [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}" for e in _SCHEMA.iter_errors(doc)]
    if errs:
        raise LockError("lock fails C3 2.0.0: " + "; ".join(errs[:5]))
    if text != json.dumps(doc, indent=2, sort_keys=True) + "\n":
        raise LockError("lock is not in canonical form")
    return doc


def write_lock(path: Path, lock: dict) -> None:
    data = (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode()
    try:
        signing._atomic_write(path, data, mode=0o644)
    except OSError as e:
        raise LockError(f"cannot write lock: {path.name}: {e.strerror}") from None


def new_lock(scope: str) -> dict:
    return {"contract": {"name": "cxbom-lock", "version": "2.0.0"},
            "canonicalization": "RFC 8785 JSON Canonicalization Scheme",
            "lockScope": scope, "servers": {}}


def verified_entry(lock: dict, server_id: str, trusted: dict, state: Path, now: datetime,
                   update_highwater: bool) -> VerifiedEntry:
    """Verify one server's signed envelope and check its high-water mark.

    Raises:
        LockError: now has no time zone, the lock fails the schema, the server
            has no entry, the envelope binding, signature, time window, or
            high-water check fails, or the state directory hits an OSError.
            The message carries only file names.
        PathSecurityError: the state directory is a symlink, is shared, or is
            not private. It propagates unwrapped on purpose, because a
            redirected state path is a different failure from a bad lock and
            callers report it differently.
    """
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise LockError("now must be a datetime with a time zone")
    errs = [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}" for e in _SCHEMA.iter_errors(lock)]
    if errs:
        raise LockError("lock fails C3 2.0.0: " + "; ".join(errs[:5]))
    srv = lock.get("servers", {}).get(server_id)
    if srv is None:
        raise LockError(f"not-approved: no signed entry for server {server_id!r}")
    env = srv["envelope"]
    sig = srv["signature"]
    if env["serverId"] != server_id:
        raise LockError("envelope serverId does not match")
    if env["lockScope"] != lock["lockScope"]:
        raise LockError("envelope lockScope does not match the lock")
    try:
        fp = signing.verify_envelope(env, sig, trusted, now)
        signing.check_highwater(state, env["lockScope"], server_id, env["entrySeq"], update=update_highwater)
    except signing.SigningError as e:
        raise LockError(str(e)) from None
    except OSError as e:
        name = Path(e.filename).name if e.filename else "state"
        raise LockError(f"{name}: {e.strerror}") from None
    return VerifiedEntry(server_id, env["entry"], env, object_sha256(env), fp, env["entrySeq"])
