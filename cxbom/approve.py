"""cxbom approve, slice 1: accept-flag review, per-era pinning, and signing.

Owner: ATACE Working Group.

Slice 1 has no interactive review. Every new or changed hash must be named
with --accept SHA256 --reason TEXT, and each accepted pin records
approvalMode "accept-flag" (spec 7 step 6). The entry then sets
allowAcceptFlag, and the summary says so before the user types the server id.

The server is launched exactly as the proxy launches it (spec 7 step 2), so
the binary, interpreter, files, trees, and environment pinned here are the
ones the proxy will check.

Values that end up in the published lock are checked for identifying
content before anything is hashed (spec 3, 7 step 1). Pinned environment
values are checked too: a hash of a low-entropy value such as a hostname can
be confirmed by guessing.

A registry runner (uvx, uv, pipx, npx, npm, bunx, bun, pnpm, yarn, docker,
podman, or an interpreter starting one) fetches a package or image at launch
time. Unless the argv pins it exactly, the same signed argv can fetch a
different build on every launch, and the signature would describe a lookup
instead of a binary (spec 6, "Registry runners must pin every package"). This
is checked before argv is used to compute launch pins, so a moving target is
refused before anything is hashed or spawned.

Each runner is parsed with an allowlist grammar and fails closed: an unknown
flag before the package, or a flag before the subcommand, is refused rather
than skipped, and nothing after the package is inspected. Container runners
are parsed with the vendored docker and podman flag tables, so the image is
found by arity, never by guessing. Every earlier scanner that skipped a token
it did not understand was bypassed by hiding the real subcommand or package
right past it (Task 12 fix rounds 1 to 3).

A tool name is protocol data the server controls and this module prints
verbatim in the review summary. A name carrying a C0 control character or
DEL is treated the same as an unusable name and refused outright rather than
displayed. Every other server-controlled string this module shows the
operator, including a tool name that clears that gate, goes through the same
escaping review_text uses, so a C1 control byte, a bidi override, or a
zero-width character cannot ride along into the terminal either.

serverInfo is likewise server-controlled and goes into the signed, published
lock verbatim otherwise. It is stripped of forged org.cxbom/* keys at every
depth, capped in size, and checked for identifying content the same way an
argv token or an --accept reason is, before it is ever pinned (fix round 1
controller ruling 5, depth fixed in fix round 2 ruling D).
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence, TextIO

from . import launch, launchpolicy, lockfile, mcpclient, paths, signing
from .canonical import CanonicalizationError, canonical, instructions_sha256, object_sha256, tool_sha256
from .proxy import CXBOM_META_PREFIX, Scrubber, os_message
from .store import Store, StoreError
from .timeutil import parse_time

ROLE = re.compile(r"[A-Za-z0-9 _.-]{1,64}")
SERVER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
HEX64 = re.compile(r"[0-9a-f]{64}")
CREDENTIAL_PREFIXES = ("sk-", "ghp_", "github_pat_", "xox", "AKIA", "glpat-")
PUBLIC_REGISTRY_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
                                   "ghcr.io", "docker.io", "registry-1.docker.io", "index.docker.io"})
# RFC 2606 and RFC 6761 reserve exactly these three domains under .com,
# .net, and .org for documentation and testing, so a demo pinning
# example.com is not flagged the way a real hostname is (task 14b, J2 demo
# scenario S4). This must stay an exact-domain allowlist, never a TLD
# pattern: _HOSTNAME's alternation is matched greedily against the shortest
# suffix that fits it, so a TLD-shaped entry for "test", "example",
# "invalid", or "localhost" would let a real hostname through by appending
# one of those words, for example evil.com.test matching "evil.com" widened
# to swallow the whole string instead (fix round 1, reviewer finding).
# inbox.test, x.example, a.invalid, and foo.localhost need no allowlist
# entry at all: none of those four words is a TLD _HOSTNAME recognizes, so
# it never matches them in the first place.
RESERVED_EXAMPLE_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_HOME_PATH = re.compile(r"(?i)(^|[^A-Za-z0-9_.-])(/home/|/Users/|/root(/|$)|~/)")
_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s@]+@")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"\[[0-9A-Fa-f:.]+\]|(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}(?![0-9A-Za-z:])")
_HOSTNAME = re.compile(
    r"(?i)(?<![A-Za-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|ai|app|cloud|local|lan|internal|home|corp|edu|gov|co|us|uk|de|localdomain))(?![A-Za-z0-9-])")
_AUTH = re.compile(r"(?i)authorization\s*[:=]|\bbearer\s+\S")
_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")
WARNING = ("Approval is the only defense against a definition that was malicious when it was approved. "
           "A signed pin proves it did not change, not that it is benign.")

_CONTROL_NAME = re.compile(r"[\x00-\x1f\x7f]")
SERVER_INFO_MAX_BYTES = 4096


class ApproveError(RuntimeError):
    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


@dataclass
class ApproveOptions:
    server_id: str
    approver: str
    command: list
    lock: str | None = None
    era: str | None = None
    client_capabilities: dict = field(default_factory=dict)
    accept: dict = field(default_factory=dict)
    pin_env: list = field(default_factory=list)
    secret_env: list = field(default_factory=list)
    pin_trees: list = field(default_factory=list)
    startup_timeout: float = 60.0
    allow_observe: bool = False
    not_after: str | None = None


def _entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def identifying_content(value: str, home: str) -> str | None:
    """The first kind of identifying content in value, or None (spec 7 step 1)."""
    # Case-insensitive, because APFS resolves /users/NAME to /Users/NAME.
    if (home and home != "/" and home.casefold() in value.casefold()) or _HOME_PATH.search(value):
        return "a home path"
    if _USERINFO.search(value):
        return "URL userinfo"
    if _IPV4.search(value) or _IPV6.search(value):
        return "an IP literal"
    for m in _HOSTNAME.finditer(value):
        host = m.group(1).lower()
        if host in PUBLIC_REGISTRY_HOSTS or host in RESERVED_EXAMPLE_DOMAINS:
            continue
        return "a hostname"
    if any(p in value for p in CREDENTIAL_PREFIXES):
        return "a credential prefix"
    if _AUTH.search(value):
        return "an Authorization header"
    if any(_entropy(t) > 4.0 for t in _TOKEN.findall(value)):
        return "a high-entropy token"
    return None


def _escape_for_display(text: str) -> str:
    """Every character outside printable ASCII becomes a \\u{XXXX} escape.

    Used for every server-controlled string this module ever prints, so a
    C1 control byte (U+0080-U+009F, e.g. U+009B, the 8-bit CSI), a bidi
    override, or a zero-width character cannot ride along into the
    operator's terminal, even one that already cleared the C0/DEL gate a
    tool name is refused outright for (fix round 1, controller ruling 4).
    """
    return launch.escape_for_display(text)


def review_text(obj: object) -> tuple[str, int]:
    """First 200 characters of the canonical form, escaped, and the count of nonprintable characters.

    Newline and tab are ordinary formatting in descriptions, so they are
    escaped for display but not counted. Every other control, bidi,
    zero-width, tag, or non-ASCII character is counted.
    """
    text = canonical(obj).decode("utf-8")
    shown = _escape_for_display(text[:200])
    count = 0

    def walk(v: object) -> None:
        nonlocal count
        if isinstance(v, str):
            count += sum(1 for ch in v if not (0x20 <= ord(ch) < 0x7f or ch in "\n\t"))
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(k)
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(obj)
    return shown, count


@dataclass
class _EraResult:
    key: str
    pins: dict
    lines: list
    unaccepted_instructions: str | None


def _strip_cxbom_keys(v: object) -> object:
    """v with every org.cxbom/* key removed, at any nesting depth.

    A server could nest a forged org.cxbom/* key inside a sub-object of
    serverInfo instead of at the top level. A top-level-only strip would
    still publish it (fix round 2, controller ruling D).
    """
    if isinstance(v, dict):
        return {k: _strip_cxbom_keys(x) for k, x in v.items()
                if not (isinstance(k, str) and k.startswith(CXBOM_META_PREFIX))}
    if isinstance(v, list):
        return [_strip_cxbom_keys(x) for x in v]
    return v


def _clean_server_info(info: dict, home: str) -> dict:
    """serverInfo, stripped of forged org.cxbom/* keys at every depth,
    size-capped, and checked for identifying content before it is pinned
    into the signed, published lock (fix round 1 ruling 5, depth fixed in
    fix round 2 ruling D).

    serverInfo is server-controlled and would otherwise be published
    verbatim: a hostile server could plant an org.cxbom/* key to imitate
    cxbom's own provenance metadata, stuff the object to bloat the lock, or
    embed a hostname, IP, or credential where anonymity and secret-handling
    rules require none to appear.

    Raises:
        ApproveError: info cannot be canonicalized, is over
            SERVER_INFO_MAX_BYTES once canonicalized, or one of its string
            values contains identifying content.
    """
    cleaned = _strip_cxbom_keys(info)
    try:
        size = len(canonical(cleaned))
    except CanonicalizationError as e:
        raise ApproveError(f"serverInfo cannot be canonicalized ({e}). It cannot be pinned") from None
    if size > SERVER_INFO_MAX_BYTES:
        raise ApproveError(f"serverInfo is {size} bytes, over the {SERVER_INFO_MAX_BYTES}-byte cap. "
                           "It cannot be pinned")

    def walk(v: object) -> None:
        if isinstance(v, str):
            found = identifying_content(v, home)
            if found:
                raise ApproveError(f"serverInfo contains {found}. It cannot be pinned")
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(k)
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(cleaned)
    return cleaned


def _pin_era(snap: mcpclient.EraSnapshot, prev: dict | None, accept: dict, role: str, now_s: str,
             used: set, home: str) -> _EraResult:
    names = [t.get("name") if isinstance(t, dict) else None for t in snap.tools]
    for n in names:
        if not isinstance(n, str) or not n or n == "*" or _CONTROL_NAME.search(n):
            raise ApproveError("the server lists a tool without a usable name. It cannot be approved")
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        raise ApproveError(f"the server lists {_escape_for_display(dups[0])} more than once. "
                           "Duplicate names cannot be approved")
    lines = [f"  era {snap.era_key} (negotiated {snap.negotiated_version})"]
    tools: dict = {}
    for t in snap.tools:
        name = t["name"]
        shown_name = _escape_for_display(name)
        try:
            sha = tool_sha256(t)
        except CanonicalizationError:
            raise ApproveError(f"tool {shown_name} cannot be canonicalized and cannot be approved") from None
        shown, bad = review_text(t)
        prev_pin = prev["tools"].get(name) if prev is not None else None
        if prev_pin is not None and prev_pin["sha256"] == sha:
            tools[name] = prev_pin
            lines.append(f"    tool {shown_name} {sha} unchanged")
            continue
        if sha in accept:
            if bad:
                raise ApproveError(f"tool {shown_name} has {bad} nonprintable characters. Slice 1 cannot approve it")
            used.add(sha)
            tools[name] = {"sha256": sha, "approvedAt": now_s, "approvedBy": role, "approvalMode": "accept-flag",
                           "reason": accept[sha]}
            lines.append(f"    tool {shown_name} {sha} ACCEPTED (accept-flag)")
        else:
            lines.append(f"    tool {shown_name} {sha} left unpinned: pass --accept {sha} --reason TEXT")
        lines.append(f"      {shown}")
        if bad:
            lines.append(f"      {bad} nonprintable characters")
    isha = instructions_sha256(snap.instructions)
    unaccepted = None
    if prev is not None and prev["instructionsSha256"] == isha:
        lines.append(f"    instructions {isha} unchanged")
    elif isha in accept:
        shown, bad = review_text(snap.instructions)
        if bad:
            raise ApproveError(f"instructions have {bad} nonprintable characters. Slice 1 cannot approve them")
        used.add(isha)
        lines.append(f"    instructions {isha} ACCEPTED")
        lines.append(f"      {shown}")
    else:
        unaccepted = isha
        lines.append(f"    instructions {isha} NOT ACCEPTED: pass --accept {isha} --reason TEXT")
        lines.append(f"      {review_text(snap.instructions)[0]}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", snap.negotiated_version):
        raise ApproveError("the server negotiated a protocol version that is not a date. It cannot be pinned")
    server_info = _clean_server_info(snap.server_info, home)
    pins = {"negotiatedVersion": snap.negotiated_version, "instructionsSha256": isha, "serverInfo": server_info,
            "tools": tools, "prompts": {}, "resources": {}, "resourceTemplates": {}, "ignoreFields": []}
    return _EraResult(snap.era_key, pins, lines, unaccepted)


def _validate(opts: ApproveOptions, environ: dict, now: datetime) -> None:
    if not SERVER_ID.fullmatch(opts.server_id):
        raise ApproveError("--server-id must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    if not ROLE.fullmatch(opts.approver):
        raise ApproveError("--approver must match ^[A-Za-z0-9 _.-]{1,64}$")
    if opts.era not in (None, "legacy", "modern", "both"):
        raise ApproveError("--era must be legacy, modern, or both")
    if not opts.command:
        raise ApproveError("no server command after --")
    for sha, reason in opts.accept.items():
        if not HEX64.fullmatch(sha):
            raise ApproveError("--accept takes a 64-character lowercase hex SHA-256")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 500:
            raise ApproveError("every --accept needs a --reason of 1 to 500 characters")
    if not isinstance(opts.client_capabilities, dict):
        raise ApproveError("--client-capabilities must be a JSON object")
    # Hashed into the entry later. An integer past 2**53 has no RFC 8785
    # form, so it is refused here as a usage error instead of escaping _run.
    try:
        object_sha256(opts.client_capabilities)
    except CanonicalizationError as e:
        raise ApproveError(f"--client-capabilities cannot be canonicalized ({e})") from None
    # The same environment rules the proxy re-applies at every launch (spec 6).
    problem = launchpolicy.env_problem({n: environ[n] for n in opts.pin_env if n in environ}, opts.secret_env)
    if problem:
        raise ApproveError(problem)
    home = str(paths.pw_dir())
    checks = [("argv", a) for a in opts.command] + [("--reason", r) for r in opts.accept.values()]
    for name in opts.pin_env:
        if name not in environ:
            raise ApproveError(f"--pin-env {name}: variable is not set")
        checks.append((f"--pin-env {name}", environ[name]))
    for what, value in checks:
        found = identifying_content(value, home)
        if found:
            raise ApproveError(f"{what} contains {found}. Remove it, or pass the value with --secret-env")
    # --allow-observe takes no required --not-after, and --not-after has no
    # maximum (owner decision 2026-10-05). A recording-day lock must not
    # expire on its own. When the owner does set one, it is still checked.
    if opts.not_after is not None:
        try:
            not_after = parse_time(opts.not_after)
        except ValueError:
            raise ApproveError("--not-after must be an RFC 3339 time") from None
        if not opts.not_after.endswith("Z"):
            raise ApproveError("--not-after must be UTC with a Z suffix")
        if not now < not_after:
            raise ApproveError("--not-after must be in the future")


def _snapshots(opts: ApproveOptions, plan: launch.LaunchPlan) -> list:
    caps = opts.client_capabilities

    def with_child(fn):
        child = launch.spawn(plan)
        client = mcpclient.StdioClient(child, opts.startup_timeout)
        try:
            return fn(client)
        finally:
            child.stop()
            client.join_reader()

    def probed(client):
        found = mcpclient.probe(client, caps)
        if found == "legacy":
            return mcpclient.snapshot_legacy(client, caps)
        if found == "ambiguous":
            raise ApproveError("the era probe was ambiguous. Pass --era legacy, modern, or both")
        return found

    if opts.era is None:
        return [with_child(probed)]
    out = []
    if opts.era in ("legacy", "both"):
        out.append(with_child(lambda c: mcpclient.snapshot_legacy(c, caps)))
    if opts.era in ("modern", "both"):
        out.append(with_child(lambda c: mcpclient.snapshot_modern(c, caps)))
    return out


def run(opts: ApproveOptions, *, confirm: Callable[[str], str], passphrase: Callable[[], bytes], out: TextIO,
        config_dir: Path | None = None, state_dir: Path | None = None, environ: dict | None = None,
        cwd: Path | None = None, now: datetime | None = None) -> int:
    environ = dict(os.environ) if environ is None else environ
    cwd = Path.cwd() if cwd is None else cwd
    now = datetime.now(timezone.utc).replace(microsecond=0) if now is None else now
    scrub = Scrubber(None, cwd)
    try:
        return _run(opts, confirm, passphrase, out, config_dir, state_dir, environ, cwd, now)
    except ApproveError as e:
        out.write(scrub(f"cxbom approve: {e}") + "\n")
        return e.code
    except OSError as e:
        out.write(scrub(f"cxbom approve: {os_message(e)}") + "\n")
        return 2
    except (paths.PathSecurityError, signing.SigningError, lockfile.LockError, launch.LaunchError,
            mcpclient.McpClientError, StoreError) as e:
        out.write(scrub(f"cxbom approve: {e}") + "\n")
        return 2


def _run(opts, confirm, passphrase, out, config_dir, state_dir, environ, cwd, now) -> int:
    paths.check_home_env(environ)
    _validate(opts, environ, now)
    now_s = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    home = str(paths.pw_dir())
    config = config_dir if config_dir is not None else paths.config_dir()
    trusted = signing.load_trusted(config)
    state = state_dir if state_dir is not None else paths.state_dir()
    paths.ensure_private_dir(state)
    try:
        lock_path = lockfile.find_lock(cwd, Path(opts.lock) if opts.lock else None, environ)
    except lockfile.LockError:
        raise ApproveError("no cxbom.lock found. Run cxbom init in the project first") from None
    lock = lockfile.read_lock(lock_path)
    lock_dir = lock_path.resolve().parent
    # Signing rewrites the lock, so a tree that holds it changes hash the
    # moment approve writes the entry, and the proxy could never match it.
    lock_real = os.path.realpath(lock_path)
    for name in opts.pin_trees:
        tree_real = os.path.realpath(os.path.join(str(lock_dir), launch.normalize_tree(name)))
        if lock_real == tree_real or lock_real.startswith(tree_real.rstrip(os.sep) + os.sep):
            raise ApproveError("the lock file is inside this tree and changes when it is signed. "
                               "Pin a subdirectory")
    # After _validate's identifying-content checks, so the refusal, which
    # quotes the offending argument, never echoes a home path or a credential.
    # Here rather than in _validate, because a uv run target's inline
    # metadata is read from the lock directory. Still before anything is
    # hashed or launched.
    problem = launchpolicy.package_version_problem(opts.command, lock_dir, opts.pin_trees)
    if problem:
        raise ApproveError(problem)
    prev = None
    if opts.server_id in lock["servers"]:
        try:
            prev = lockfile.verified_entry(lock, opts.server_id, trusted, state, now, update_highwater=False)
        except lockfile.LockError as e:
            raise ApproveError(f"the existing entry does not verify ({e}). Refusing to extend it") from None
    launch_pins = launch.compute_launch_pins(opts.command, lock_dir, environ, opts.pin_env, opts.secret_env,
                                             opts.pin_trees)
    entry = dict(launch_pins, firstParty=False, allowObserve=opts.allow_observe, allowSampling=False,
                 allowAcceptFlag=False, renderer="jcs",
                 clientCapabilitiesSha256=object_sha256(opts.client_capabilities), eras={})
    plan = launch.check_launch(entry, opts.command, lock_dir, environ, opts.server_id)
    snaps = _snapshots(opts, plan)
    same_launch = prev is not None and all(prev.entry[k] == entry[k] for k in launch_pins) \
        and prev.entry["clientCapabilitiesSha256"] == entry["clientCapabilitiesSha256"]
    used: set = set()
    # A hash the user already approved stays approved whatever else changed.
    # Eras this run did not probe carry over only when the launch is identical.
    results = [_pin_era(s, prev.entry["eras"].get(s.era_key) if prev is not None else None, opts.accept,
                        opts.approver, now_s, used, home) for s in snaps]
    for r in results:
        entry["eras"][r.key] = r.pins
    carried = []
    if same_launch:
        for key, pins in prev.entry["eras"].items():
            if key not in entry["eras"]:
                entry["eras"][key] = pins
                carried.append(key)
    entry["allowAcceptFlag"] = any(p["approvalMode"] == "accept-flag"
                                   for e in entry["eras"].values() for p in e["tools"].values())
    unused = sorted(set(opts.accept) - used)
    shown_argv = " ".join(_escape_for_display(a) for a in opts.command)
    out.write(f"cxbom approve: server {opts.server_id}\n  argv: {shown_argv}\n")
    for r in results:
        out.write("\n".join(r.lines) + "\n")
    for key in carried:
        out.write(f"  era {key} carried over unchanged\n")
    old_flags = {k: prev.entry[k] for k in ("firstParty", "allowObserve", "allowSampling", "allowAcceptFlag")} \
        if prev is not None else {}
    for flag in ("firstParty", "allowObserve", "allowSampling", "allowAcceptFlag"):
        if old_flags.get(flag, False) != entry[flag]:
            out.write(f"  {flag}: {old_flags.get(flag, False)} -> {entry[flag]}\n")
    out.write(WARNING + "\n")
    if any(r.unaccepted_instructions for r in results):
        raise ApproveError("server instructions are new or changed and were not accepted. Nothing was signed", 1)
    if unused:
        raise ApproveError(f"--accept {unused[0]} matches no listed item or instructions")
    if confirm(f"Type the server id ({opts.server_id}) to sign: ").strip() != opts.server_id:
        raise ApproveError("confirmation did not match. Nothing was signed", 1)
    key = signing.load_private(passphrase(), config)
    envelope = {"serverId": opts.server_id, "lockScope": lock["lockScope"],
                "entrySeq": prev.entry_seq + 1 if prev is not None else 1,
                "issuedAt": now_s, "notAfter": opts.not_after, "entry": entry}
    lock["servers"][opts.server_id] = {"envelope": envelope, "signature": signing.sign_envelope(key, envelope)}
    # Verified before the write, so a bad signature never reaches disk, and
    # the high-water mark moves only after the write succeeds, so a failed
    # write cannot leave the mark ahead of the lock on disk and lock out the
    # entry that is still there.
    lockfile.verified_entry(lock, opts.server_id, trusted, state, now, update_highwater=False)
    lockfile.write_lock(lock_path, lock)
    lockfile.verified_entry(lock, opts.server_id, trusted, state, now, update_highwater=True)
    store = Store(state / "store")
    for s in snaps:
        store.put_json(s.instructions)
        for t in s.tools:
            store.put_json(t)
    out.write(f"signed entry {envelope['entrySeq']} for {opts.server_id}\n")
    return 0
