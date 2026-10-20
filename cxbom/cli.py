"""cxbom command line, slice 1: keygen, trust add, init, approve (--accept only), proxy.

Owner: ATACE Working Group.

Every usage error exits 2 (spec 11). keygen, trust add, and approve read
passphrases, and approve reads the typed server id, only from /dev/tty, so a
session with no controlling terminal cannot create keys or sign (spec 6,
7 step 8). main() takes the reader as a parameter only so tests can pass an
in-memory one. No flag, file, or environment variable supplies it.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import sys
import termios
from pathlib import Path

from . import approve, jsonstrict, lockfile, paths, proxy, signing
from .canonical import file_sha256
from .proxy import os_message
from .timeutil import now_rfc3339

# Verbatim from docs/design/tool.md section 2's "Not covered in this version"
# table (spec 2). tests/test_cli.py parses the doc's table and checks every
# row's first cell lands here, so the two cannot drift apart silently.
NOT_COVERED = """not covered in this version (spec 2):
  Tool results, resource bodies, prompt bodies
      Recorded by the emitter as unverified components
  Transitive dependencies of registry-runner packages, and code imported by a local server outside --pin-tree
      The runner binary, its interpreter, the exact top-level package version or image digest, pinned files, \
and the registry environment are enforced
  Registry runners approve does not recognize (any tool not in the section 6 runner table)
      Their argv is still pinned. Prefer a listed runner or a pinned local tree
  A runner started through a wrapper that approve does not recognize
      env, nice, timeout, nohup, stdbuf, and the common shells are recognized. A launch through one is refused \
when a shell carries -c, env carries -S, or a later word names a runner, an interpreter, or another wrapper. \
A shell handed a script file, and a wrapper handed a program cxbom does not recognize, are not inspected. \
Start the runner directly
  A container runner pointed at another daemon (-H, --context)
      The image digest is pinned. Where it runs is not
  A copy or hard link of a runner script under an unrecognized name
      Runner identity is by name. Keep runners on the trusted search path
  .pth files, sitecustomize, and imports resolved from a system interpreter's own site-packages
      Everything the interpreter loads from its own prefix carries the same trust as the trusted search path. \
For code you control, run from a pinned venv made with python -m venv --copies
  npx: the pin covers the npm shim script and node, not npm's library
      Prefer uvx or a pinned local tree
  Streamable HTTP servers
      stdio only
  A pinned file or tree swapped between the launch check and the exec by a process racing the proxy
      Pins are checked immediately before spawn. Keep the workspace free of untrusted writers while the proxy starts
  Revoked-key backdating: a stolen, revoked key signs entries with an issuedAt before its revocation
      entrySeq and the high-water mark bound rollback. Observe and sampling entries have no tool-set expiry, \
so this risk is accepted for them by owner decision 2026-10-05. A notAfter the owner sets still ends an entry
  prompts, resources, resource templates
      slice 1 verifies tools only and refuses the rest
  Hostnames under a TLD outside approve's fixed list
      The identifying-content check flags hostnames under a fixed TLD list only (section 7 step 1). \
Review argv and pinned values before approving"""


class UsageError(Exception):
    """The command line is malformed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        raise UsageError(message)


class _Ordered(argparse.Action):
    """Keeps --accept and --reason in command-line order, so each reason pairs with the accept before it."""

    def __call__(self, parser, namespace, values, option_string=None):
        items = list(getattr(namespace, "ordered", None) or [])
        items.append((self.dest, values))
        namespace.ordered = items


def split_command(argv: list) -> tuple:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def pair_accepts(ordered: list) -> dict:
    out: dict = {}
    pending = None
    for kind, value in ordered:
        if kind == "accept":
            if pending is not None:
                raise UsageError(f"--accept {pending} has no --reason")
            pending = value
        else:
            if pending is None:
                raise UsageError("--reason must follow an --accept")
            out[pending] = value
            pending = None
    if pending is not None:
        raise UsageError(f"--accept {pending} has no --reason")
    return out


def _startup_timeout(value: str) -> float:
    """--startup-timeout as a finite number in (0, 3600] (spec 11 usage errors).

    float() alone accepts "nan" and "inf", and a non-positive or huge timeout
    is not a usable startup budget. Raising ArgumentTypeError routes through
    argparse's own error() call, which _Parser turns into a UsageError, so
    every bad value here still exits 2 like any other usage error.
    """
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from None
    if not math.isfinite(parsed) or not (0 < parsed <= 3600):
        raise argparse.ArgumentTypeError("--startup-timeout must be finite, greater than 0, and at most 3600")
    return parsed


def tty_line(prompt: str) -> str:
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        raise signing.SigningError("no controlling terminal. cxbom approve signs only from a terminal") from None
    try:
        try:
            # Discard anything typed or pasted before this prompt was shown,
            # so a script or a fast-fingered paste cannot pre-answer the
            # server-id confirmation with leftover input.
            termios.tcflush(fd, termios.TCIFLUSH)
        except termios.error:
            pass
        os.write(fd, prompt.encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n") and len(buf) < 256:
            chunk = os.read(fd, 1)
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace").rstrip("\r\n")
    finally:
        os.close(fd)


def _parser() -> _Parser:
    # allow_abbrev=False everywhere: an abbreviated flag (--allow for
    # --allow-observe, --mo for --mode) is refused rather than silently
    # accepted, so a typo cannot land on the wrong flag as MCP tooling
    # evolves and adds new options that could turn today's unambiguous
    # abbreviation into an ambiguous one tomorrow.
    parser = _Parser(prog="cxbom", description="MCP pinning proxy and CxBOM tools.", epilog=NOT_COVERED,
                     formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="create your passphrase-protected Ed25519 signing key", allow_abbrev=False)
    t = sub.add_parser("trust", help="manage the signed trust manifest", allow_abbrev=False)
    tsub = t.add_subparsers(dest="trust_cmd", required=True)
    tsub.add_parser("add", help="trust another public key", allow_abbrev=False).add_argument("key_file")
    sub.add_parser("init", help="create cxbom.lock with a fresh lockScope", allow_abbrev=False)
    p = sub.add_parser("proxy", help="run an MCP server behind the pinning proxy", allow_abbrev=False)
    p.add_argument("--server-id", required=True)
    p.add_argument("--lock")
    p.add_argument("--mode", choices=("enforce", "observe"), default="enforce")
    p.add_argument("--state-dir")
    p.add_argument("--events")
    p.add_argument("--redact-sha256", action="append", default=[])
    a = sub.add_parser("approve", help="pin and sign an MCP server's listings", allow_abbrev=False)
    a.add_argument("--server-id", required=True)
    a.add_argument("--approver", required=True)
    a.add_argument("--lock")
    a.add_argument("--era", choices=("legacy", "modern", "both"))
    a.add_argument("--client-capabilities", default="{}")
    a.add_argument("--accept", action=_Ordered)
    a.add_argument("--reason", action=_Ordered)
    a.add_argument("--pin-env", action="append", default=[])
    a.add_argument("--secret-env", action="append", default=[])
    a.add_argument("--pin-tree", action="append", default=[])
    a.add_argument("--startup-timeout", type=_startup_timeout, default=60.0)
    a.add_argument("--allow-observe", action="store_true")
    a.add_argument("--not-after")
    return parser


def cmd_init(cwd: Path, config_dir: Path | None, entry_point: Path, out) -> int:
    """Write cxbom.lock, ignore .cxbom/, and record the wrapper's identity.

    The config directory is validated and prepared before anything is
    written to cwd, and the lock is written before .gitignore or
    wrapper.json, so a failure at any later step can roll the lock back
    and a failed init never leaves a stranded cxbom.lock behind (controller
    ruling, fix round 1).
    """
    lock_path = cwd / lockfile.LOCK_NAME
    if lock_path.exists():
        out.write("cxbom init: cxbom.lock already exists\n")
        return 2
    config = paths.ensure_private_dir(config_dir if config_dir is not None else paths.config_dir())
    try:
        lockfile.write_lock(lock_path, lockfile.new_lock(secrets.token_hex(16)))
        try:
            ignore = cwd / ".gitignore"
            text = ignore.read_text() if ignore.exists() else ""
            if ".cxbom/" not in text.splitlines():
                new_text = text + ("" if text == "" or text.endswith("\n") else "\n") + ".cxbom/\n"
                signing._atomic_write(ignore, new_text.encode("utf-8"), mode=0o644)
            real_entry = Path(os.path.realpath(entry_point))
            real_python = Path(os.path.realpath(sys.executable))
            wrapper = {"entryPoint": {"realpath": str(real_entry), "sha256": file_sha256(real_entry)},
                       "interpreter": {"realpath": str(real_python), "sha256": file_sha256(real_python)}}
            signing._atomic_write(config / "wrapper.json",
                                  (json.dumps(wrapper, indent=2, sort_keys=True) + "\n").encode(), mode=0o600)
        except BaseException:
            # The lock is the only state cmd_init itself created up to this
            # point (config was prepared, not created, by ensure_private_dir
            # above unless it was already there). Roll it back so a retry
            # after fixing the problem starts clean instead of being refused
            # by the "already exists" check above.
            lock_path.unlink(missing_ok=True)
            raise
    except lockfile.LockError as e:
        out.write(f"cxbom init: {e}\n")
        return 2
    except UnicodeDecodeError:
        out.write("cxbom init: .gitignore is not valid UTF-8\n")
        return 2
    except OSError as e:
        out.write(f"cxbom init: {os_message(e)}\n")
        return 2
    out.write("cxbom init: wrote cxbom.lock and ignored .cxbom/\n")
    return 0


def cmd_keygen(config: Path, read_secret, out) -> int:
    # Checked before the first passphrase prompt: asking twice for a
    # passphrase that generate_key will refuse anyway wastes the operator's
    # time and, worse, throws the typed passphrase away on a SigningError
    # instead of ever reaching a place that could report it.
    if (config / signing.KEY_FILE).exists() or (config / signing.PUB_FILE).exists():
        out.write("cxbom keygen: a signing key already exists\n")
        return 2
    first = read_secret("New passphrase: ")
    if read_secret("Repeat passphrase: ") != first:
        out.write("cxbom keygen: the passphrases differ\n")
        return 2
    fingerprint = signing.generate_key(first, config, now_rfc3339())
    out.write(f"cxbom keygen: key {fingerprint}\n")
    return 0


def cmd_trust_add(config: Path, key_file: Path, read_secret, out) -> int:
    try:
        text = key_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        out.write(f"cxbom trust add: cannot read {key_file.name}\n")
        return 2
    fingerprint = signing.trust_add(read_secret("Passphrase: "), config, text, now_rfc3339())
    out.write(f"cxbom trust add: trusted {fingerprint}\n")
    return 0


def main(argv: list | None = None, *, config_dir: Path | None = None, state_dir: Path | None = None,
         environ: dict | None = None, cwd: Path | None = None, out=None, entry_point: Path | None = None,
         read_secret=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    out = sys.stdout if out is None else out
    cwd = Path.cwd() if cwd is None else cwd
    read_secret = signing.read_passphrase if read_secret is None else read_secret
    head, command = split_command(argv)
    try:
        # A uid with no /etc/passwd entry (KeyError from pwd.getpwuid, for
        # example a container running as a raw uid) exits 2 like any other
        # startup refusal. Only this call is covered, so a KeyError from a
        # bug anywhere else is reported as the internal error it is.
        try:
            config = config_dir if config_dir is not None else paths.config_dir()
        except KeyError:
            sys.stderr.write("cxbom: no password database entry for this user id\n")
            return 2
        ns = _parser().parse_args(head)
        if ns.cmd in ("keygen", "trust") and command:
            raise UsageError(f"{ns.cmd} takes no server command")
        if ns.cmd == "keygen":
            paths.check_home_env(environ)
            return cmd_keygen(config, read_secret, out)
        if ns.cmd == "trust":
            paths.check_home_env(environ)
            return cmd_trust_add(config, cwd / ns.key_file, read_secret, out)
        if ns.cmd == "init":
            if command:
                raise UsageError("init takes no server command")
            return cmd_init(cwd, config, entry_point or Path(sys.argv[0]), out)
        if ns.cmd == "proxy":
            opts = proxy.ProxyOptions(server_id=ns.server_id, command=command, lock=ns.lock, mode=ns.mode,
                                      state_dir=ns.state_dir or (str(state_dir) if state_dir else None),
                                      events=ns.events, redact_sha256=tuple(ns.redact_sha256))
            return proxy.run(opts, config_dir=config_dir, environ=environ, cwd=cwd)
        try:
            caps = jsonstrict.to_python(jsonstrict.parse(ns.client_capabilities.encode("utf-8")))
        except jsonstrict.StrictJSONError as e:
            raise UsageError(f"--client-capabilities is not strict JSON ({e})") from None
        opts = approve.ApproveOptions(
            server_id=ns.server_id, approver=ns.approver, command=command, lock=ns.lock, era=ns.era,
            client_capabilities=caps, accept=pair_accepts(getattr(ns, "ordered", None) or []),
            pin_env=ns.pin_env, secret_env=ns.secret_env, pin_trees=ns.pin_tree,
            startup_timeout=ns.startup_timeout, allow_observe=ns.allow_observe, not_after=ns.not_after)
        return approve.run(opts, confirm=tty_line, passphrase=lambda: read_secret("Passphrase: "),
                           out=out, config_dir=config_dir, state_dir=state_dir, environ=environ, cwd=cwd)
    except UsageError as e:
        sys.stderr.write(f"cxbom: {e}\n")
        return 2
    except (signing.SigningError, paths.PathSecurityError) as e:
        # Same channel as a usage error (stderr), not out: neither exception
        # is a command's own reported outcome, they are cxbom refusing to
        # proceed at all (controller ruling, fix round 1).
        sys.stderr.write(f"cxbom: {e}\n")
        return 2
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except Exception as e:
        # Only the type name: the exception's text could carry a path or a
        # value cxbom has not vetted (spec 3, 11).
        sys.stderr.write(f"cxbom: internal error ({type(e).__name__})\n")
        return 70
