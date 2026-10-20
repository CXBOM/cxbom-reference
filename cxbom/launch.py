"""Launch pins, the child environment, the watchdog, and child spawning.

Owner: ATACE Working Group.

The proxy never inherits the environment it runs in. An attacker who can
write an MCP config controls that environment, so the proxy builds the
child's environment itself and checks every pinned value (spec 6, premortem
C1). The launcher binary is pinned by the hash of its realpath target, and a
script launcher's interpreter is pinned too, so a PATH redirect or a swapped
binary fails the check before anything runs.

Only the basename and hash of a binary are stored, never its path, because
locks are published and a path names the user (spec 3).

A bare argv[0] resolves only against the trusted search path, never the
caller's PATH. Actor (b) writes the launch env block, so a bare launcher
name found through it could be a byte-identical copy of the real binary
sitting next to a hostile sibling that redirects what it actually runs (a
hostile uv beside a copied uvx, a hostile pyvenv.cfg beside a copied
python), and the pin would still match. An argv[0] that names a path is
accepted only when it resolves inside a tree pinned with --pin-tree, and the
child's PATH is the trusted search path, preceded by that tree's directory
when the launcher came from one (spec 6, amended after a critical review
finding).

The watchdog is a separate process started with fork and exec from the main
thread before any other thread exists (spec 8.1). It holds only the read end
of a pipe. When the proxy dies, the kernel closes the write end, and the
watchdog kills the child's process group. On Linux the child also gets
PR_SET_PDEATHSIG as a second line. On macOS the watchdog is the only line.
"""
from __future__ import annotations

import ctypes
import fcntl
import functools
import os
import re
import stat
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import unquote
from pathlib import Path
from typing import Mapping, Sequence

from . import launchpolicy, paths
from .canonical import CanonicalizationError, file_sha256, launch_sha256, sha256_hex, tree_sha256

PASS_THROUGH = ("LANG", "LC_ALL", "TERM", "USER", "LOGNAME")
# The proxy sets these itself, so a lock can neither pin them nor mark them
# secret (spec 6). PYTHONNOUSERSITE is fixed at 1 as defense in depth: the
# user site loads ahead of a pinned module and is not pinned.
# PYTHONDONTWRITEBYTECODE is fixed at 1 because a Python server that imports
# a sibling module would otherwise write __pycache__ into its pinned tree on
# the first launch, approve's own probe included, and every later launch
# would then fail the tree pin.
RESERVED_ENV = frozenset({"HOME", "PATH", "TMPDIR", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"})
_SHIM_MARKERS = ("/.pyenv/shims/", "/.asdf/shims/", "/mise/shims/", "/.volta/bin/", "/.nodenv/shims/",
                 "/.rbenv/shims/")
_PIN_ONLY = re.compile(
    r"^(SSL_CERT_.*|.*_PROXY|NO_PROXY|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS|XDG_.*|UV_.*|PIP_.*|"
    r"NPM_CONFIG_.*|PYTHON.*|NODE_.*|LD_.*|DYLD_.*|DOCKER_.*|BUN_.*|COREPACK_.*|BASH_ENV|ENV|"
    r"VIRTUAL_ENV|CONDA_.*|GIT_.*|CURL_CA_BUNDLE|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|PERL5.*|RUBY.*|"
    r"GEM_.*|BUNDLE_.*)$", re.IGNORECASE)
TRUSTED_PATH = ["/usr/local/bin", "/usr/bin", "/bin"]
# The value half of a --flag=value or name=value argv element, pinned like a
# bare element (spec 6).
_LIST_SEPARATORS = re.compile(r"[,:]")
# An argument that yields more path candidates than this is refused rather
# than partly inspected.
_MAX_CANDIDATES = 4096


class LaunchError(RuntimeError):
    """The launch differs from the signed entry, or cannot be pinned or started.

    item names which part of check_launch's re-check a refusal came from
    (argv, binary, interpreter, files, trees, env, or policy for a
    launchpolicy refusal), so the proxy can report it in a launch_refused
    sidecar event (C2 1.2.0). None outside check_launch, where no single
    item applies.
    """

    def __init__(self, message: str, item: str | None = None):
        super().__init__(message)
        self.item = item


def escape_for_display(text: str) -> str:
    """Every character outside printable ASCII becomes a \\u{XXXX} escape, so a
    name taken from argv or the filesystem cannot carry a control sequence
    into the operator's terminal."""
    return "".join(ch if 0x20 <= ord(ch) < 0x7f else f"\\u{{{ord(ch):04X}}}" for ch in text)


def env_value_sha256(value: str) -> str:
    try:
        return sha256_hex(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise LaunchError("environment value is not valid UTF-8") from None


def is_pin_only(name: str) -> bool:
    return bool(_PIN_ONLY.match(name))


def trusted_search_path() -> list[str]:
    """Directories actor (b) cannot write, used to resolve a bare argv[0].

    The caller's PATH is never consulted for this: actor (b) writes the
    launch env block, so a name found through it could resolve to a
    byte-identical copy of the real launcher sitting next to a hostile
    sibling that redirects what it actually runs.
    """
    trusted = list(TRUSTED_PATH)
    if sys.platform == "darwin":
        trusted.append("/opt/homebrew/bin")
    trusted.append(str(paths.pw_dir() / ".local" / "bin"))
    return trusted


def child_path(argv0: str, found: str) -> str:
    """The child's PATH: the trusted search path, preceded by the directory
    holding argv[0] when it was resolved from a pinned tree rather than a
    bare name already on the trusted path."""
    trusted = trusted_search_path()
    if "/" in argv0:
        return ":".join([os.path.dirname(found), *trusted])
    return ":".join(trusted)


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _tree_containing(lock_dir: Path, p: Path, trees: Sequence[str]) -> str | None:
    """The pinned tree holding p both as named and after realpath, or None.

    Both must hold (spec 6). A path named outside the tree that symlinks into
    it is refused, because a Python interpreter reads the pyvenv.cfg beside
    the path it was started as, not beside its realpath. A path named inside
    the tree that symlinks out of it is refused, because the file that runs is
    not the one the tree hash covers.
    """
    named = os.path.normpath(str(p))
    real = os.path.realpath(p)
    for name in trees:
        tree_named = os.path.normpath(os.path.join(str(lock_dir), name))
        if _within(named, tree_named) and _within(real, os.path.realpath(tree_named)):
            return name
    return None


def resolve_argv0(argv0: str, lock_dir: Path, trees: Sequence[str] = ()) -> str:
    if "/" in argv0:
        p = Path(argv0) if argv0.startswith("/") else lock_dir / argv0
        if not p.is_file():
            raise LaunchError(f"{escape_for_display(os.path.basename(argv0))}: launcher not found")
        # The file and the directory it is named in both pass, so a symlinked
        # directory cannot stand in for the tree's own directory.
        if _tree_containing(lock_dir, p, trees) is None or _tree_containing(lock_dir, p.parent, trees) is None:
            raise LaunchError("put the binary on the standard PATH or pin its tree")
        return str(p)
    found = shutil.which(argv0, path=":".join(trusted_search_path()))
    if found is None:
        raise LaunchError(f"{escape_for_display(argv0)}: not found on PATH")
    return found


def _pin_real(real: str) -> dict:
    if any(m in real for m in _SHIM_MARKERS):
        raise LaunchError(f"{escape_for_display(os.path.basename(real))} is a version-manager shim. "
                          "Pass the real binary")
    try:
        return {"name": os.path.basename(real), "sha256": file_sha256(Path(real))}
    except (OSError, CanonicalizationError):
        raise LaunchError(f"{escape_for_display(os.path.basename(real))}: cannot hash the launcher") from None


def binary_pin(found: str) -> dict:
    return _pin_real(os.path.realpath(found))


def _dir_trusted(d: str, lock_dir: Path, trees: Sequence[str]) -> bool:
    """d passes the argv[0] test both as named and after realpath (spec 6).

    Each form must itself be a trusted search-path directory or lie inside a
    pinned tree. A trusted entry that is a symlink to a directory off the
    trusted path therefore fails on its realpath.
    """
    if not os.path.isabs(d):
        return False
    trusted = {os.path.normpath(t) for t in trusted_search_path()}
    tree_dirs = [os.path.normpath(os.path.join(str(lock_dir), name)) for name in trees]
    named, real = os.path.normpath(d), os.path.realpath(d)
    named_ok = named in trusted or any(_within(named, t) for t in tree_dirs)
    real_ok = real in trusted or any(_within(real, os.path.realpath(t)) for t in tree_dirs)
    return named_ok and real_ok


# The one env option allowed. Every other option (-u, -C, -P, and the rest)
# takes a value that would hide the real interpreter, and -i clears PATH so a
# different interpreter runs than the one pinned (spec 6).
_ENV_OPTIONS = frozenset({"-S"})


def interpreter_pin(found: str, search_path: str, lock_dir: Path, trees: Sequence[str]) -> dict | None:
    """The pin of a script launcher's interpreter, or None for a binary launcher.

    The interpreter's directory as named (the #! path, or the search result for
    #!/usr/bin/env NAME) must pass the same test as argv[0]: on the trusted
    search path or inside a pinned tree. A Python interpreter reads the
    pyvenv.cfg beside it, and an interpreter elsewhere sits in a directory
    actor (b) may write (spec 6). The env program itself is held to the same
    test, because it is what the kernel runs first. The realpath target is
    what gets hashed.
    """
    real = os.path.realpath(found)
    try:
        with open(real, "rb") as f:
            head = f.read(512)
    except OSError:
        raise LaunchError(f"{os.path.basename(real)}: cannot read the launcher") from None
    if not head.startswith(b"#!"):
        return None
    tokens = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").split()
    if not tokens:
        raise LaunchError(f"{os.path.basename(real)}: empty #! line")
    refusal = "put the interpreter on the standard PATH or pin its tree"
    if os.path.basename(tokens[0]) == "env":
        if not _dir_trusted(os.path.dirname(tokens[0]), lock_dir, trees):
            raise LaunchError(refusal)
        name = None
        for t in tokens[1:]:
            if t in _ENV_OPTIONS:
                continue
            # An assignment, an expansion, or an escape would change what env
            # runs or where it looks, so only a plain name is accepted.
            if t.startswith("-") or any(c in t for c in "=$\\"):
                raise LaunchError(f"{escape_for_display(os.path.basename(real))}: the #! line passes env "
                                  "something other than -S and an interpreter name")
            name = t
            break
        if name is None:
            raise LaunchError(f"{escape_for_display(os.path.basename(real))}: #! line names no interpreter")
        interp = shutil.which(name, path=search_path)
        if interp is None:
            raise LaunchError(f"{escape_for_display(name)}: interpreter not found on the child PATH")
    else:
        interp = tokens[0]
    if not _dir_trusted(os.path.dirname(interp), lock_dir, trees):
        raise LaunchError(refusal)
    return _pin_real(os.path.realpath(interp))


def _under(lock_dir: Path, rel: str) -> Path:
    if rel.startswith("/") or ".." in Path(rel).parts:
        raise LaunchError(f"{os.path.basename(rel)}: pinned paths must be relative to the lock directory")
    p = lock_dir / rel
    base = os.path.realpath(lock_dir)
    real = os.path.realpath(p)
    if real != base and not real.startswith(base + os.sep):
        raise LaunchError(f"{os.path.basename(rel)}: resolves outside the lock directory")
    return p


def _file_pin(lock_dir: Path, rel: str) -> str:
    try:
        return file_sha256(_under(lock_dir, rel))
    except (OSError, CanonicalizationError):
        raise LaunchError(f"{rel}: cannot hash the pinned file") from None


def _tree_pin(lock_dir: Path, rel: str) -> str:
    try:
        return tree_sha256(_under(lock_dir, rel))
    except (OSError, CanonicalizationError) as e:
        raise LaunchError(f"{os.path.basename(rel)}: cannot hash the pinned tree ({e})") from None


def normalize_tree(d: str) -> str:
    return os.path.normpath(d)


@functools.lru_cache(maxsize=64)
def _case_insensitive(path: str) -> bool:
    """True when the volume holding path matches names case-insensitively.

    Detected, not assumed: macOS answers pathconf(_PC_CASE_SENSITIVE), and
    elsewhere the same path with its case swapped is tested for being the
    same file. A path with no cased letters, or an error, counts as
    case-sensitive, which only narrows what matches.
    """
    try:
        if "PC_CASE_SENSITIVE" in os.pathconf_names:
            return os.pathconf(path, "PC_CASE_SENSITIVE") == 0
    except (OSError, ValueError):
        pass
    swapped = path.swapcase()
    if swapped == path:
        return False
    try:
        return os.path.samefile(path, swapped)
    except (OSError, ValueError):
        return False


def _rel_within(path: str, base: str, fold: bool) -> str | None:
    """path relative to base when path is base or below it, else None."""
    head, tail = path[:len(base)], path[len(base):]
    if (head.casefold() != base.casefold()) if fold else (head != base):
        return None
    if base.endswith(os.sep):
        return tail or "."
    if not tail:
        return "."
    return tail[1:] if tail.startswith(os.sep) else None


def _chain_match(path: str, lock_id: tuple) -> str | None:
    """path's name relative to the directory with device and inode lock_id,
    found by stat-ing each parent directory of path as written.

    os.stat follows the kernel's own resolution, so every spelling the kernel
    accepts for the lock directory matches: symlinks, case and Unicode
    normalization variants, the /System/Volumes/Data firmlink, and
    /.vol/<dev>/<ino>. The nearest matching parent wins. A remainder that
    climbs out with ".." is refused, because the kernel resolves it
    physically through whatever the components before it point to.
    """
    parent = path.rstrip("/") or "/"
    while True:
        up = os.path.dirname(parent)
        if up == parent:
            return None
        parent = up
        try:
            st = os.stat(parent)
        except (OSError, ValueError):
            continue
        if (st.st_dev, st.st_ino) != lock_id:
            continue
        rest = path[len(parent):].strip("/")
        rel = os.path.normpath(rest) if rest else "."
        if rel == ".." or rel.startswith("../") or "/../" in "/" + rest + "/":
            raise LaunchError(f"{escape_for_display(os.path.basename(path))}: resolves outside the lock directory")
        return rel


def _kernel_path(path: str) -> str | None:
    """The kernel's own path for an existing regular file or directory.

    A /.vol/<dev>/<ino> name addresses a file by inode, so no parent directory
    in its spelling is the lock directory. macOS F_GETPATH names it the way
    the kernel stores it. Only regular files and directories are opened, and
    without blocking, so a FIFO or a device is never touched.
    """
    get_path = getattr(fcntl, "F_GETPATH", None)
    try:
        st = os.lstat(path)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            return None
        if get_path is None:
            return os.path.realpath(path)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = fcntl.fcntl(fd, get_path, b"\0" * 1024)
        finally:
            os.close(fd)
        return raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
    except (OSError, ValueError):
        return None


def _lock_relative(lock_dir: Path, value: str) -> str | None:
    """value's path relative to the lock directory, or None when value names
    nothing inside it (spec 6).

    A value that exists is inside when one of its parent directories has the
    lock directory's device and inode (_chain_match), or when the kernel's own
    path for it does (a /.vol inode name). A value that does not exist uses
    the realpath of both sides, case-insensitively on a case-insensitive
    volume. The last component is kept as named, so an element that is itself
    a symlink maps to its own name and the caller refuses it.
    """
    if value.startswith("-"):
        return None
    base_named = os.path.normpath(str(lock_dir))
    named = value if os.path.isabs(value) else os.path.join(base_named, value)
    try:
        exists = os.path.lexists(named)
        lock_st = os.stat(base_named)
    except (OSError, ValueError):
        return None
    lock_id = (lock_st.st_dev, lock_st.st_ino)
    if exists:
        rel = _chain_match(named, lock_id)
        if rel is None:
            kernel = _kernel_path(named)
            if kernel is not None and kernel != named:
                rel = _chain_match(kernel, lock_id)
        return rel
    named = os.path.normpath(named)
    try:
        base_real = os.path.realpath(base_named)
        parent, leaf = os.path.split(named)
        real = os.path.join(os.path.realpath(parent), leaf) if leaf not in ("", ".") else os.path.realpath(named)
    except ValueError:
        return None
    fold = _case_insensitive(base_real)
    rel = _rel_within(real, base_real, fold)
    if rel is None:
        if _rel_within(named, base_named, fold) is not None:
            raise LaunchError(f"{escape_for_display(os.path.basename(named))}: resolves outside the lock directory")
        return None
    return rel


def within_trees(rel: str, trees: Sequence[str]) -> bool:
    """True when rel, a lock-relative path, is a pinned tree or lies in one."""
    return any(t == "." or rel == t or rel.startswith(t + "/") for t in trees)


def pinned_relative(lock_dir: Path, path: str) -> str | None:
    """path's lock-relative name when both path as named and its realpath lie
    in the lock directory by the device and inode test, else None.

    The named form is the one the file pins use. The realpath is where the
    code physically sits, so a symlink out of the lock directory fails here.
    Returns the realpath's name, which is what a tree hash covers.
    """
    try:
        if _lock_relative(lock_dir, path) is None:
            return None
        return _lock_relative(lock_dir, os.path.realpath(path))
    except (LaunchError, OSError, ValueError):
        return None


class _Cand(NamedTuple):
    """One path candidate inside an argv element.

    prefix + value + suffix is the element. strict says whether a missing
    path-shaped value is refused. rewrite says whether _exec_args may replace
    value with the absolute lock-directory path (a file:// URL keeps its own
    encoding and is already absolute).
    """
    prefix: str
    value: str
    suffix: str
    strict: bool
    rewrite: bool


def _wrap(prefix: str, suffix: str, inner: list) -> list:
    return [_Cand(prefix + c.prefix, c.value, c.suffix + suffix, c.strict, c.rewrite) for c in inner]


def _value_forms(text: str, budget: list) -> list:
    """Every path candidate in one argv element or value (spec 6).

    - --flag=value: the value.
    - -Xvalue, including clustered short flags (-ivHOST:CTR) and -v=value:
      the rest after every run of flag letters.
    - A bare element: itself, the value after its first "=" (any key), the
      rest after a leading "@", the path of a file:// URL, and each segment of
      a comma- or colon-separated list. A list's whole text is not strict,
      so ./data:/data is judged by ./data. In a file URL only the decoded
      path is strict.
    """
    budget[0] -= 1
    if budget[0] < 0:
        raise LaunchError("an argument holds too many path forms to check. Split it")
    if text.startswith("--"):
        key, eq, value = text.partition("=")
        return _wrap(key + eq, "", _value_forms(value, budget)) if eq else []
    if text.startswith("-") and len(text) > 1:
        out = []
        k = 2
        while k < len(text) and text[1:k].isalpha():
            out += _wrap(text[:k], "", _value_forms(text[k:], budget))
            k += 1
        return out
    listy = bool(_LIST_SEPARATORS.search(text))
    out = [_Cand("", text, "", not listy, True)]
    key, eq, value = text.partition("=")
    if eq:
        out += _wrap(key + eq, "", _value_forms(value, budget))
    if text.startswith("@"):
        out += _wrap("@", "", _value_forms(text[1:], budget))
    file_url = text[:7].casefold() == "file://"
    if file_url:
        host, slash, path = text[7:].partition("/")
        if slash and host.casefold() in ("", "localhost"):
            out.append(_Cand(text, unquote("/" + path), "", True, False))
    if listy:
        start = 0
        for m in [*_LIST_SEPARATORS.finditer(text), None]:
            end = m.start() if m else len(text)
            segment = text[start:end]
            if segment and not _LIST_SEPARATORS.search(segment):
                inner = _value_forms(segment, budget)
                if file_url:
                    # A file URL's raw segments still pin what they name, but
                    # only its decoded path is judged for existence.
                    inner = [c._replace(strict=False) for c in inner]
                out += _wrap(text[:start], text[end:], inner)
            start = m.end() if m else end
    return out


def _arg_forms(argv_rest: Sequence[str]) -> list:
    """The path candidates of every argv element, in order."""
    return [_value_forms(arg, [_MAX_CANDIDATES]) for arg in argv_rest]


def _must_exist(lock_dir: Path, value: str) -> bool:
    """True when a missing value is refused rather than left unpinned.

    Spec 6 calls a value path-shaped when it starts with "/", "./", "../", or
    "~", or contains "/" and its first segment exists in the lock directory,
    so @scope/pkg@1.2.3, mcp/fetch@sha256:..., and URLs are not paths.
    """
    if value.startswith(("/", "./", "../", "~")):
        return True
    if "/" in value:
        return os.path.lexists(os.path.join(str(lock_dir), value.split("/", 1)[0]))
    return False


def _pin_files(lock_dir: Path, argv_rest: Sequence[str]) -> dict:
    """Hashes of every argv path candidate naming a file under lock_dir.

    A symlink is refused. A path-shaped name under lock_dir that does not
    exist is refused, because a file created there after approval would run
    unpinned (spec 6).
    """
    files: dict = {}
    for forms in _arg_forms(argv_rest):
        for cand in forms:
            value, strict = cand.value, cand.strict
            rel = _lock_relative(lock_dir, value)
            if rel is None:
                continue
            target = lock_dir / rel
            name = escape_for_display(os.path.basename(rel))
            if target.is_symlink():
                raise LaunchError(f"{name}: a pinned argument cannot be a symlink")
            if not os.path.lexists(target):
                if strict and _must_exist(lock_dir, value):
                    raise LaunchError(f"{name} does not exist: create it before approve")
                continue
            if target.is_file():
                files[rel] = _file_pin(lock_dir, rel)
    return files


def compute_launch_pins(argv: Sequence[str], lock_dir: Path, environ: Mapping[str, str],
                        pin_env: Sequence[str] = (), secret_env: Sequence[str] = (),
                        pin_trees: Sequence[str] = ()) -> dict:
    """The launch half of a lock entry, computed exactly as check_launch will recompute it."""
    if not argv:
        raise LaunchError("empty server command")
    tree_names = [normalize_tree(d) for d in pin_trees]
    found = resolve_argv0(argv[0], lock_dir, tree_names)
    files = _pin_files(lock_dir, argv[1:])
    trees = {name: _tree_pin(lock_dir, name) for name in tree_names}
    env: dict = {}
    for name in pin_env:
        if name in RESERVED_ENV:
            raise LaunchError(f"{name} is set by the proxy and cannot be pinned")
        if name not in environ:
            raise LaunchError(f"--pin-env {name}: variable is not set")
        env[name] = {"sha256": env_value_sha256(environ[name])}
    for name in secret_env:
        if name in RESERVED_ENV:
            raise LaunchError(f"{name} is set by the proxy and cannot be a secret")
        if is_pin_only(name):
            raise LaunchError(f"{name} redirects trust or code. It can only be pinned with --pin-env")
        if name in env:
            raise LaunchError(f"{name} is both pinned and secret")
        env[name] = "secret"
    return {"argv": list(argv), "binary": binary_pin(found),
            "interpreter": interpreter_pin(found, child_path(argv[0], found), lock_dir, tree_names),
            "files": files, "trees": trees, "env": env}


@dataclass(frozen=True)
class LaunchPlan:
    argv: list
    exec_argv: list
    executable: str
    env: dict
    lock_dir: Path
    launch_sha256: str


def build_child_env(pins: Mapping, environ: Mapping[str, str], search_path: str) -> dict:
    env = {"HOME": str(paths.pw_dir()), "PATH": search_path, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    for name in PASS_THROUGH:
        if name in environ:
            env[name] = environ[name]
    for name in sorted(pins):
        pin = pins[name]
        if name in RESERVED_ENV:
            raise LaunchError(f"{name} is set by the proxy and cannot be pinned")
        if name not in environ:
            raise LaunchError(f"environment variable {name} is pinned but not set")
        if pin != "secret" and env_value_sha256(environ[name]) != pin["sha256"]:
            raise LaunchError(f"environment variable {name} differs from its pin")
        env[name] = environ[name]
    return env


def _exec_args(argv_rest: Sequence[str], entry: Mapping, lock_dir: Path) -> list:
    """argv_rest with each pinned path (a whole element, or the value inside
    one) made absolute under the lock directory, so the child in its temporary
    cwd opens the pinned file. Candidates come from the same _arg_forms the
    pins do, so approve and the proxy rewrite identically."""
    out = []
    for arg, forms in zip(argv_rest, _arg_forms(argv_rest)):
        new = arg
        for cand in forms:
            rel = _lock_relative(lock_dir, cand.value)
            if rel is None or not cand.rewrite:
                continue
            if rel in entry["files"] or within_trees(rel, entry["trees"]):
                new = cand.prefix + str(lock_dir / rel) + cand.suffix
                break
        out.append(new)
    return out


@contextmanager
def _item(item: str):
    """Wrap one check_launch step so any LaunchError it raises carries item.

    A step's own explicit raise has no item yet, and a lower helper it calls
    (resolve_argv0, interpreter_pin, _pin_files, _tree_pin, build_child_env,
    and the rest) never sets one either, since item only matters at the one
    place that reports a proxy startup refusal (spec 8.1, C2 1.2.0
    launch_refused). Reused only within check_launch, so item is always None
    going in.
    """
    try:
        yield
    except LaunchError as e:
        raise LaunchError(str(e), item=item) from None


def _argv_difference(argv: Sequence[str], signed: Sequence[str]) -> str:
    """Where argv first departs from the signed argv, for the refusal message.

    The value shown is the one being launched, escaped. The proxy scrubs
    home paths from everything it prints and from the launch_refused
    reason, so the operator sees ~ rather than the home directory.
    """
    i = next((k for k, (a, b) in enumerate(zip(argv, signed)) if a != b), min(len(argv), len(signed)))
    if i < len(argv):
        return f"at argv[{i}]: {escape_for_display(argv[i])}"
    return f"at argv[{i}]: the signed argv continues past the end of this one"


def check_launch(entry: Mapping, argv: Sequence[str], lock_dir: Path, environ: Mapping[str, str],
                 server_id: str) -> LaunchPlan:
    """The signed entry re-checked against this launch, and the plan to spawn it.

    server_id names the entry for the caller's own reporting. No refusal
    here names a command to run other than cxbom approve itself.
    """
    with _item("argv"):
        if list(argv) != entry["argv"]:
            where = _argv_difference(argv, entry["argv"])
            raise LaunchError(f"the server command differs from the signed argv {where}")
    trees = list(entry["trees"])
    # The rules approve applied before signing are re-applied to the signed
    # entry here, so an entry signed under older rules cannot escape a current
    # one (spec 6). A pinned value is checked as it is in the environment. A
    # value that differs from its pin is refused below by build_child_env.
    pinned = {n: environ[n] for n, pin in entry["env"].items() if pin != "secret" and n in environ}
    secret = [n for n, pin in entry["env"].items() if pin == "secret"]
    problem = launchpolicy.launch_problem(argv, lock_dir, trees, pinned, secret)
    if problem:
        raise LaunchError(problem, item="policy")
    with _item("binary"):
        found = resolve_argv0(argv[0], lock_dir, trees)
        binary = binary_pin(found)
        if binary != entry["binary"]:
            raise LaunchError(f"launcher binary {escape_for_display(binary['name'])} differs from the signed pin. "
                              "If only the binary was upgraded, re-run cxbom approve for this server")
    search_path = child_path(argv[0], found)
    with _item("interpreter"):
        if interpreter_pin(found, search_path, lock_dir, trees) != entry["interpreter"]:
            raise LaunchError(f"the interpreter of {escape_for_display(binary['name'])} differs from the signed "
                              "pin. If only the binary was upgraded, re-run cxbom approve for this server")
    # The file pins are recomputed from argv exactly as compute_launch_pins
    # computed them, so a file that appeared, vanished, or changed since
    # approval is refused, not only a change to a file the entry names.
    # A signed name that escapes the lock directory is refused on its own
    # terms first, whatever argv holds.
    with _item("files"):
        for rel in sorted(entry["files"]):
            _under(lock_dir, rel)
        files = _pin_files(lock_dir, argv[1:])
        for rel in sorted(set(files) | set(entry["files"])):
            if files.get(rel) != entry["files"].get(rel):
                raise LaunchError(f"pinned file {escape_for_display(rel)} differs from the signed pin")
    with _item("trees"):
        for rel, sha in sorted(entry["trees"].items()):
            if _tree_pin(lock_dir, rel) != sha:
                raise LaunchError(f"pinned tree {rel} differs from the signed pin")
    with _item("env"):
        env = build_child_env(entry["env"], environ, search_path)
    launch = {k: entry[k] for k in ("argv", "binary", "interpreter", "files", "trees", "env")}
    # _exec_args rewrites pinned paths through the same _lock_relative used by
    # _pin_files above, which can itself raise on an edge case (a named path
    # that nominally sits under the lock directory but whose parent resolves
    # elsewhere), so it gets the same item as the rest of the file checks.
    with _item("files"):
        exec_argv = [argv[0]] + _exec_args(argv[1:], entry, lock_dir)
    return LaunchPlan(list(argv), exec_argv, found, env, lock_dir, launch_sha256(launch))


WATCHDOG_GRACE_S = 1.0
WATCHDOG_SIGNALED_EXIT = 3  # distinct from 0, so a caller can tell which path the watchdog took
PR_SET_PDEATHSIG = 1
_LIBC = ctypes.CDLL(None, use_errno=True) if sys.platform.startswith("linux") else None
if _LIBC is not None:
    # Explicit types, so ctypes marshals the five prctl() arguments and its
    # return value the same way on every Linux architecture this runs on,
    # instead of falling back to its default (and narrower) int assumptions.
    _LIBC.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    _LIBC.prctl.restype = ctypes.c_int

WATCHDOG_CODE = rf"""
# cxbom-watchdog: kills the MCP server's process group when the proxy dies.
import os, signal, sys, time
fd = int(sys.argv[1])
data = b""
while len(data) < 4096:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    data += chunk
parts = data.split(b"\n")
if b"done" in parts:
    sys.exit(0)
try:
    pgid = int(parts[0])
except ValueError:
    sys.exit(0)
if pgid <= 1:
    sys.exit(0)
def kill(sig):
    try:
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False
if kill(signal.SIGTERM):
    time.sleep(float(sys.argv[2]))
    kill(signal.SIGKILL)
sys.exit({WATCHDOG_SIGNALED_EXIT})
"""


def _watchdog_preexec() -> None:
    # Ignored dispositions survive exec, so the watchdog is immune to terminal
    # signals from its first instruction, not only after Python starts.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)


def _pdeathsig(parent: int):
    def preexec() -> None:
        # Runs in the forked child before exec. The proxy spawns from its main
        # thread before starting any other thread, so this is safe. The death
        # signal fires when the forking thread exits, which is the main thread.
        if _LIBC.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(126)
        if os.getppid() != parent:
            os._exit(126)
    return preexec


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _killpg(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


class Child:
    """A spawned MCP server in its own process group, guarded by a watchdog."""

    def __init__(self, proc: subprocess.Popen, watchdog: subprocess.Popen, wd_fd: int, tmpdirs: list):
        self.proc = proc
        self.watchdog = watchdog
        self._wd_fd = wd_fd
        self._tmpdirs = tmpdirs
        self.pgid = proc.pid

    def close_stdin(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass

    def stop(self, grace: float = WATCHDOG_GRACE_S) -> int:
        """Spec 8.8: close stdin, wait, SIGTERM the group, wait, SIGKILL. Returns the exit status."""
        self.close_stdin()
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
        if _group_alive(self.pgid):
            _killpg(self.pgid, signal.SIGTERM)
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                self.proc.poll()            # reap the leader, or its zombie keeps the group alive
                if not _group_alive(self.pgid):
                    break
                time.sleep(0.02)
            else:
                # The loop ran out the clock without ever seeing the group
                # gone, so SIGTERM did not finish the job. A break above skips
                # this: the group was already empty and SIGKILL has nothing
                # left to do but risk recycled-pgid collateral damage.
                _killpg(self.pgid, signal.SIGKILL)
        rc = self.proc.wait()
        self.release_watchdog()
        return rc

    def release_watchdog(self) -> None:
        """Tell the watchdog the proxy cleaned up, so it exits without killing anything."""
        if self._wd_fd >= 0:
            try:
                os.write(self._wd_fd, b"done\n")
            except OSError:
                pass
            os.close(self._wd_fd)
            self._wd_fd = -1
        try:
            self.watchdog.wait(timeout=WATCHDOG_GRACE_S * 3)
        except subprocess.TimeoutExpired:
            pass
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def abandon_for_test(self) -> None:
        """Close the watchdog pipe without 'done', as the kernel does when the proxy dies."""
        os.close(self._wd_fd)
        self._wd_fd = -1


def exit_status(rc: int) -> int:
    return rc if rc >= 0 else 128 + (-rc)


def spawn(plan: LaunchPlan, grace: float = WATCHDOG_GRACE_S) -> Child:
    # PR_SET_PDEATHSIG ties the child's death to whichever thread called fork,
    # not to the process. A spawn from a worker thread would kill the child
    # the moment that thread (not the proxy) exits, so this refuses to run
    # anywhere but the main thread, with no other thread alive to race it.
    if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
        raise LaunchError("spawn must run on the main thread before any other thread starts")
    # os.pipe() descriptors are non-inheritable (PEP 446), so neither the
    # server nor any other child inherits the write end. The watchdog gets
    # the read end through pass_fds only.
    r, w = os.pipe()
    try:
        watchdog = subprocess.Popen([sys.executable, "-I", "-S", "-c", WATCHDOG_CODE, str(r), str(grace)],
                                    pass_fds=(r,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env={}, close_fds=True,
                                    start_new_session=True, preexec_fn=_watchdog_preexec)
    except OSError:
        os.close(r)
        os.close(w)
        raise LaunchError("cannot start the watchdog") from None
    os.close(r)
    # dir="/tmp" is a fixed root that never consults the environment. The
    # proxy's own TMPDIR is whatever it inherited at launch, and actor (b)
    # writes that launch env block, so tempfile.mkdtemp()'s default lookup
    # would let a hostile TMPDIR put the child's scratch space anywhere,
    # including inside the project tree.
    tmpdir = tempfile.mkdtemp(prefix="cxbom-tmp-", dir="/tmp")
    cwd = tempfile.mkdtemp(prefix="cxbom-cwd-", dir="/tmp")
    env = dict(plan.env, TMPDIR=tmpdir)
    preexec = _pdeathsig(os.getpid()) if _LIBC is not None else None
    try:
        proc = subprocess.Popen(plan.exec_argv, executable=plan.executable, env=env, cwd=cwd,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, preexec_fn=preexec, close_fds=True, bufsize=0)
    except OSError:
        os.close(w)
        watchdog.wait()
        shutil.rmtree(tmpdir, ignore_errors=True)
        shutil.rmtree(cwd, ignore_errors=True)
        raise LaunchError(f"{escape_for_display(os.path.basename(plan.argv[0]))}: cannot start the server") from None
    os.write(w, f"{proc.pid}\n".encode())
    return Child(proc, watchdog, w, [tmpdir, cwd])
