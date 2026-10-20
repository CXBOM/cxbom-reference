"""Binding tool definitions and instructions to a live proxy session (spec 9.2 and 9.3).

Owner: ATACE Working Group.

At call time the emitter resolves a tool definition or server instructions
against the proxy's attestation log and the signed lock. Only an item that
state.compute reports allowed, whose hash equals the signed pin for the
latched era, and whose stored object renders back to that pin, gets its text
from the store. Anything else is unbound, and the caller must pass the exact
text the model receives.

At emit the captured binding is checked again (spec 9.3 checks 1 to 6). A
failure makes the component unverified. It never raises, except when the
named log is gone, which means the caller pointed at the wrong state
directory.

Causes are fixed codes, never exception text. Exception messages can carry
paths, and a cause lands in a record's finding evidence, which the anonymity
rule covers (spec 3). StateError, AttestationFormatError and
AttestationIOError from a malformed log all map to "log-invalid", which is the
forward obligation Plan 1 recorded for the emitter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import attestation, consistency, lockfile, signing, state
from .canonical import instructions_sha256
from .paths import PathSecurityError, check_private, inside_git_worktree
from .renderers import RendererError, check_rendered, render
from .store import Store, StoreError

SESSION_META_KEY = "org.cxbom/proxySessionId"
SERVER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_VERSION = re.compile(r"^[\x21-\x7e][\x20-\x7e]{0,63}$")


class BindingError(ValueError):
    """A proxy session id is malformed."""


class LogMissingError(BindingError):
    """The attestation log a proxy session names does not exist."""


class WorktreeStateError(BindingError):
    """The state directory sits inside a git worktree. Attestation state never shares a tree git tracks."""


@dataclass(frozen=True)
class ProxySession:
    proxy_session_id: str


@dataclass(frozen=True)
class Binding:
    kind: str                     # "tool" or "instructions"
    server_id: str
    name: str | None
    proxy_session_id: str
    log_path: Path
    seq: int
    sha256: str
    store_ref: str
    at: str
    approved_by: str | None
    approval_mode: str | None
    fingerprint: str
    envelope_sha256: str
    server_version: str | None


@dataclass(frozen=True)
class Resolved:
    text: str | None              # rendered store text, only when bound
    binding: Binding | None
    entry: dict | None            # the verified signed entry, when the lock verifies
    cause: str                    # "" when bound, else a fixed code
    verdict: str | None           # latest verdict for the item, for change findings
    mode: str | None              # proxy mode from the session line


def session_from_meta(result) -> ProxySession | None:
    """Read a ProxySession id from a list, initialize or discover result's _meta.

    Spec 9.2: the proxy stamps org.cxbom/proxySessionId only on those three
    result kinds. A tools/call result passes through byte for byte, so a
    malicious server can put any well-formed UUID under this same key in its
    own _meta there. This function cannot tell which kind of result the caller
    handed it, since a dict carries no record of the MCP method that produced
    it, so that check is a caller obligation, not something session_from_meta
    can enforce: never call it on a tools/call result. The safety net that
    still holds even when a caller forgets lives in Verifier.resolve and
    Verifier.recheck, which decide binding from the attestation log's own
    header, never from a caller-supplied session id alone (see
    test_forged_tools_call_session_meta_cannot_bind in test_assembly_tools.py).
    """
    meta = result.get("_meta") if isinstance(result, dict) else None
    if not isinstance(meta, dict) or SESSION_META_KEY not in meta:
        return None
    sid = meta[SESSION_META_KEY]
    if not isinstance(sid, str) or not _UUID4.fullmatch(sid):
        raise BindingError("proxySessionId is not a lowercase UUIDv4")
    return ProxySession(sid)


def _server_version(lines: list[dict]) -> str | None:
    servers = [line for line in lines if line.get("kind") == "server"]
    if not servers:
        return None
    version = servers[-1].get("serverInfo", {}).get("version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        return None
    # A server picks its own serverInfo.version, and a hostile or compromised
    # one can put a local path, a file: URI, an IP-literal host, or a
    # home-path pattern there. Recording it verbatim would make
    # consistency.anonymity refuse every record from that session,
    # permanently (Task 10 ruling important 2), so a version shaped like a
    # leak is treated the same as a server that reported no version at all:
    # the caller sees server_version None and the component declines it
    # through notCollected instead of inventing or leaking one.
    if consistency.leaks_location(version) or consistency.looks_like_home_path(version):
        return None
    return version


def _era(entry: dict, lines: list[dict]) -> dict | None:
    protocols = [line for line in lines if line.get("kind") == "protocol"]
    if not protocols:
        return None
    last = protocols[-1]
    key = "legacy" if last["era"] == "legacy" else last["protocolVersion"]
    return entry["eras"].get(key)


class Verifier:
    def __init__(self, *, lock: Path | None, state_dir: Path, config_dir: Path):
        if inside_git_worktree(state_dir):
            # A state dir git tracks could be committed, checked out from under a
            # live flock, or shared across worktrees that disagree about which
            # session is live. No path in the message: this is a setup refusal,
            # not a finding, so it never needs the caller's directory layout.
            raise WorktreeStateError("state_dir must not live inside a git worktree")
        self.lock = lock
        self.state_dir = state_dir
        self.config_dir = config_dir
        self._entries: dict[str, tuple[lockfile.VerifiedEntry | None, str]] = {}

    def entry(self, server_id: str) -> tuple[lockfile.VerifiedEntry | None, str]:
        if server_id not in self._entries:
            self._entries[server_id] = self._verify(server_id)
        return self._entries[server_id]

    def _verify(self, server_id: str) -> tuple[lockfile.VerifiedEntry | None, str]:
        if self.lock is None:
            return None, "no-lock"
        try:
            lock = lockfile.read_lock(self.lock)
            trusted = signing.load_trusted(self.config_dir)
            ve = lockfile.verified_entry(lock, server_id, trusted, self.state_dir,
                                         datetime.now(timezone.utc), update_highwater=False)
        except (lockfile.LockError, signing.SigningError, PathSecurityError, OSError):
            return None, "lock-invalid"
        return ve, ""

    def log_path(self, server_id: str, session: ProxySession) -> Path:
        # Validated before any Path is built: an unchecked server_id (e.g. "../x")
        # folded into this join would walk the constructed path outside the
        # attest directory, and a caller could then be pointed at any file on
        # disk under the server_id-controlled name.
        if not SERVER_ID.fullmatch(server_id):
            raise BindingError("server_id is not a valid server id")
        return self.state_dir / "attest" / f"{server_id}-{session.proxy_session_id}.jsonl"

    def read_state(self, path: Path) -> tuple[list[dict] | None, dict | None]:
        if not path.exists():
            raise LogMissingError("the attestation log for this proxy session does not exist")
        try:
            lines = attestation.read_log(path)
            return lines, state.compute(lines)
        except (attestation.AttestationFormatError, attestation.AttestationIOError, state.StateError):
            return None, None

    def resolve(self, kind: str, server_id: str, name: str | None, session: ProxySession | None) -> Resolved:
        ve, lock_cause = self.entry(server_id)
        entry = ve.entry if ve is not None else None
        if session is None:
            return Resolved(None, None, entry, "no-session", None, None)
        try:
            path = self.log_path(server_id, session)
        except BindingError:
            return Resolved(None, None, entry, "server-mismatch", None, None)
        lines, states = self.read_state(path)
        if lines is None:
            return Resolved(None, None, entry, "log-invalid", None, None)
        head = lines[0]
        mode = head["mode"]
        # A dead proxy or an ended log enforces nothing: a fresh binding must
        # never form against a session no one is watching (spec 9.3).
        try:
            live = attestation.is_live(path)
        except OSError:
            return Resolved(None, None, entry, "proxy-not-live", None, mode)
        if not live:
            return Resolved(None, None, entry, "proxy-not-live", None, mode)
        if any(x.get("kind") == "end" for x in lines):
            return Resolved(None, None, entry, "log-ended", None, mode)
        # The file name is not proof of whose session this is: a same-user
        # hard link, or a swapped file under the expected name, can put a
        # different session's log where this name is looked up.
        if head["proxySessionId"] != session.proxy_session_id or head["serverId"] != server_id:
            return Resolved(None, None, entry, "session-mismatch", None, mode)
        servers = [line for line in lines if line.get("kind") == "server"]
        if kind == "tool":
            item = state.lookup(states, "tool", name)
            verdict = item.verdict
            if item.state != state.ALLOWED:
                return Resolved(None, None, entry, f"state-{item.state}", verdict, mode)
            line = next(x for x in lines if x.get("seq") == item.seq)
            sha, seq = item.sha256, item.seq
        else:
            if not servers:
                return Resolved(None, None, entry, "state-not-listed", None, mode)
            line = servers[-1]
            verdict = line["verdict"]
            if verdict != state.PINNED_MATCH:
                return Resolved(None, None, entry, f"state-{state.BLOCKED}", verdict, mode)
            sha, seq = line["instructionsSha256"], line["seq"]
        if ve is None:
            return Resolved(None, None, None, lock_cause, verdict, mode)
        if head["envelopeSha256"] != ve.envelope_sha256:
            return Resolved(None, None, entry, "envelope-mismatch", verdict, mode)
        era = _era(ve.entry, lines)
        if era is None:
            return Resolved(None, None, entry, "era-not-pinned", verdict, mode)
        ref = line["storeRef"]
        if ref is None:
            return Resolved(None, None, entry, "store", verdict, mode)
        try:
            store = Store(self.state_dir / "store")
            if kind == "tool":
                pin = era["tools"].get(name)
                if pin is None or pin["sha256"] != sha:
                    return Resolved(None, None, entry, "pin-mismatch", verdict, mode)
                obj = store.get_json(ref)
                text = render(ve.entry["renderer"], obj)
                check_rendered(text, obj, [f["pointer"] for f in era["ignoreFields"]], sha)
            else:
                if era["instructionsSha256"] != sha:
                    return Resolved(None, None, entry, "pin-mismatch", verdict, mode)
                text = store.get_text(ref)
                if instructions_sha256(text) != sha:
                    return Resolved(None, None, entry, "store", verdict, mode)
        except (StoreError, PathSecurityError):
            return Resolved(None, None, entry, "store", verdict, mode)
        except RendererError:
            return Resolved(None, None, entry, "renderer", verdict, mode)
        binding = Binding(kind, server_id, name, session.proxy_session_id, path, seq, sha, ref, line["at"],
                          line.get("approvedBy"), line.get("approvalMode"), ve.fingerprint, ve.envelope_sha256,
                          _server_version(lines))
        return Resolved(text, binding, entry, "", verdict, mode)

    def recheck(self, b: Binding) -> str:
        attest_dir = self.state_dir / "attest"
        try:
            exists = b.log_path.exists()
            if b.log_path.resolve().parent != attest_dir.resolve():
                return "outside-state-dir"
            check_private(attest_dir)
            if exists:
                check_private(b.log_path)
        except (PathSecurityError, OSError):
            return "outside-state-dir"
        if not exists:
            raise LogMissingError("the attestation log for this proxy session does not exist")
        # os.open inside is_live raises PermissionError (a chmod'd-away log) or
        # another OSError (EMFILE) for anything beyond a missing file. Neither
        # may escape: an unreadable log means the same as an unwatched one.
        try:
            live = attestation.is_live(b.log_path)
        except OSError:
            return "proxy-not-live"
        if not live:
            return "proxy-not-live"
        lines, states = self.read_state(b.log_path)
        if lines is None:
            return "log-invalid"
        if any(line.get("kind") == "end" for line in lines):
            return "log-ended"
        if lines[0]["proxySessionId"] != b.proxy_session_id or lines[0]["serverId"] != b.server_id:
            return "session-mismatch"
        if lines[0]["envelopeSha256"] != b.envelope_sha256:
            return "envelope-mismatch"
        if b.kind == "tool":
            item = state.lookup(states, "tool", b.name)
            if item.state != state.ALLOWED or item.sha256 != b.sha256:
                return "state-changed"
        else:
            servers = [line for line in lines if line.get("kind") == "server"]
            if not servers or servers[-1]["verdict"] != state.PINNED_MATCH or \
                    servers[-1]["instructionsSha256"] != b.sha256:
                return "state-changed"
        return ""
