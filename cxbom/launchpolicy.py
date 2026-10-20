"""Launch policy: the pure argv and environment rules of spec 6.

Owner: ATACE Working Group.

approve applies these rules before it signs a lock entry, and the proxy's
launch.check_launch re-applies them to the signed entry at every launch, so
an entry signed under older rules is refused if it breaks a current one
(spec 6, fix round 5). Both call the same functions here, and nothing here
spawns a process or hashes a file.

A registry runner (uvx, uv, pipx, npx, npm, bunx, bun, pnpm, yarn, docker,
podman, or an interpreter starting one) fetches a package or image at launch
time. Unless the argv pins it exactly, the same signed argv can fetch a
different build on every launch. Each runner is parsed with an allowlist
grammar and fails closed. Container runners are parsed with the vendored
docker and podman flag tables. A python or node launch follows an allowlist
grammar, and its script or -m module must be pinned.

launch imports this module and this module imports launch. Every use of
launch here happens inside a function, at call time, so either module may
be imported first.
"""
from __future__ import annotations

import contextvars
import glob
import json
import os
import re
from importlib import resources
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from . import launch


def _escape_for_display(text: str) -> str:
    return launch.escape_for_display(text)


# ----- registry runners (spec 6, "Registry runners must pin every package") -------------
#
# Every parser below fails closed. A token it cannot place with certainty (an
# unknown flag, a flag whose value might be mistaken for a subcommand, an
# abbreviation npm would expand) is refused rather than skipped, because each
# earlier scanner that skipped what it did not understand was bypassed by
# putting the real subcommand or package right past the skipped token (Task 12
# fix rounds 1 and 2).

_REFUSED = "pin an exact package version"
# A range operator (^ ~ * < > =), a comma, a semicolon, or a space all fall
# outside this character class, so a leading digit followed by dotted
# alphanumerics rejects a moving target without a denylist of tag spellings.
# This is the PEP 440 side (uvx, uv, pipx). fullmatch, so a trailing newline
# cannot pass the way it passes a "$" anchor (fix round 3 ruling).
_VERSION_CHARS = re.compile(r"[0-9][0-9A-Za-z.+_-]*")
# npm resolves anything short of strict semver ("1", "1.2", "1.0.0rc1") as a
# range or a dist-tag lookup, not a pin.
_NPM_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?")
# PEP 508's project-name grammar with optional extras, and npm's own name
# grammar with an optional scope. A URL, a git or file reference, or a stray
# "@" fails both, even with a version-shaped suffix (fix round 2, ruling C).
_PIP_NAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?(\[[A-Za-z0-9,_.-]*\])?")
_NPM_NAME = re.compile(r"(@[a-z0-9._~-]+/)?[a-z0-9._~-]+")
_IMAGE_DIGEST = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
# An image reference that starts with a scheme word and ":" is a transport
# (a local path or store, not a registry digest) unless the ":" is a registry
# port ("host:5000/") or a tag right before the digest ("alpine:3.19@sha256:").
# The known transports of containers/image are refused even in a form that
# looks like a tag (spec 6).
_IMAGE_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_IMAGE_PORT = re.compile(r"[0-9]+/")
_IMAGE_TAG_DIGEST = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:")
_IMAGE_TRANSPORTS = frozenset({"docker", "docker-archive", "docker-daemon", "oci", "oci-archive", "dir",
                               "containers-storage", "ostree", "sif", "tarball", "atomic"})
# Installed runners realpath to a script whose name is not the runner's:
# npm and nvm ship npx-cli.js and npm-cli.js, corepack ships <runner>.js, and
# pnpm ships pnpm.cjs. Each maps back to the runner it is.
_LAUNCHER_ALIASES = {"npx-cli.js": "npx", "npm-cli.js": "npm", "npx.js": "npx", "npm.js": "npm",
                     "pnpm.cjs": "pnpm", "pnpm.js": "pnpm", "pnpx.cjs": "pnpx", "pnpx.js": "pnpx",
                     "yarn.js": "yarn", "yarn.cjs": "yarn", "yarnpkg": "yarn", "yarnpkg.js": "yarn",
                     "corepack.js": "corepack", "pipx.pyz": "pipx"}
# A script that is a runner only by where it sits: npm's own index.js, and the
# __main__.py of the pipx, uv, and uvx packages (spec 6).
_PACKAGE_SCRIPTS = {"index.js": frozenset({"npm"}), "__main__.py": frozenset({"pipx", "uv", "uvx"})}
# The package managers corepack starts: "corepack <pm> ..." is "<pm> ...".
_COREPACK_MANAGERS = frozenset({"npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg"})
_PYTHON_RUNNERS = frozenset({"pipx", "uv", "uvx"})
_NODE_RUNNERS = frozenset({"npx", "npm", "pnpm", "pnpx", "yarn", "corepack"})
# node and python launches follow an allowlist grammar (spec 6). An
# interpreter can load a runner through far more routes than a list of names
# covers (preloads, inline code, warning and -X hooks, env files), so only
# options that load no code are accepted before the script or -m module.
_PINNED_FILE = "put the code in a pinned file"
# CPython options that take no value and load no code. -O may repeat (-OO).
_PY_ALLOWED = frozenset("uBIEsSOqP")
# A -m module name python accepts: dotted identifiers (spec 6).
_PY_MODULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
# Module roots a copy in a pinned venv cannot stand in for. The standard
# library precedes site-packages on sys.path, and its builtin, frozen, and
# startup modules load before any path is searched (spec 6). The names are a
# static list for CPython 3.9 through 3.15, removed modules included, vendored
# in _data/python-stdlib-modules.json (its _source key names the sources),
# never read from the interpreter approve runs under. pip fetches and builds
# registry packages, which no pin form here covers (fix round 4 ruling).
_PY_UNPINNABLE_MODULES = frozenset(
    n.casefold() for n in json.loads(resources.files("cxbom").joinpath("_data/python-stdlib-modules.json")
                                     .read_text())["modules"]) | {"pip"}
_NODE_ALLOWED = frozenset({"--no-warnings", "--enable-source-maps", "--no-deprecation"})
_NODE_ALLOWED_VALUE = re.compile(r"--(?:max-old-space-size|stack-size)=[0-9]+")
# A pinned PYTHON* or NODE_* variable reaches the same load hooks the option
# allowlist closes (NODE_OPTIONS, NODE_PATH, PYTHONPATH, PYTHONHOME,
# PYTHONSTARTUP, PYTHONINSPECT, and more), so the environment is an allowlist
# too: only these may carry a value (spec 6). Matched case-insensitively,
# which only refuses more.
_INTERPRETER_ENV_PREFIXES = ("PYTHON", "NODE_")
_INTERPRETER_ENV_ALLOWED = frozenset({"PYTHONUNBUFFERED", "PYTHONIOENCODING", "PYTHONUTF8", "NODE_ENV",
                                      "NODE_NO_WARNINGS"})
# Variables that load code into the child whatever it runs: the dynamic
# loader's preloads and search paths, the shell startup files, the JVM's
# options and class path, Perl's options, library paths, and debugger, Ruby
# and Lua option and library hooks, OpenSSL's config and its engine and
# provider module directories, and glibc's gconv module path. Pinned only
# when empty, and never secret (spec 6).
_CODE_LOADING_ENV_PREFIXES = ("LD_", "DYLD_", "LUA_INIT")
_CODE_LOADING_ENV = frozenset({"BASH_ENV", "ENV", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
                               "CLASSPATH", "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB", "RUBYOPT", "RUBYLIB",
                               "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "GCONV_PATH"})
# npm's command list and alias table (npm 10, lib/utils/cmd-list.js). npm
# resolves a unique prefix of any of these words, then follows aliases.
_NPM_COMMANDS = frozenset({
    "access", "adduser", "audit", "bugs", "cache", "ci", "completion", "config", "dedupe", "deprecate", "diff",
    "dist-tag", "docs", "doctor", "edit", "exec", "explain", "explore", "find-dupes", "fund", "get", "help",
    "help-search", "hook", "init", "install", "install-ci-test", "install-test", "link", "ll", "login", "logout",
    "ls", "org", "outdated", "owner", "pack", "ping", "pkg", "prefix", "profile", "prune", "publish", "query",
    "rebuild", "repo", "restart", "root", "run-script", "sbom", "search", "set", "shrinkwrap", "star", "stars",
    "start", "stop", "team", "test", "token", "undeprecate", "uninstall", "unpublish", "unstar", "update",
    "version", "view", "whoami"})
_NPM_ALIASES = {
    "author": "owner", "home": "docs", "issues": "bugs", "info": "view", "show": "view", "find": "search",
    "add": "install", "unlink": "uninstall", "remove": "uninstall", "rm": "uninstall", "r": "uninstall",
    "un": "uninstall", "rb": "rebuild", "list": "ls", "ln": "link", "create": "init", "i": "install",
    "it": "install-test", "cit": "install-ci-test", "up": "update", "c": "config", "s": "search", "se": "search",
    "tst": "test", "t": "test", "ddp": "dedupe", "v": "view", "run": "run-script", "clean-install": "ci",
    "clean-install-test": "install-ci-test", "x": "exec", "why": "explain", "la": "ll", "verison": "version",
    "ic": "ci", "innit": "init", "in": "install", "ins": "install", "inst": "install", "insta": "install",
    "instal": "install", "isnt": "install", "isnta": "install", "isntal": "install", "isntall": "install",
    "install-clean": "ci", "isntall-clean": "ci", "hlep": "help", "dist-tags": "dist-tag", "upgrade": "update",
    "udpate": "update", "rum": "run-script", "sit": "install-ci-test", "urn": "run-script", "ogr": "org",
    "add-user": "adduser"}
_NPM_WORDS = _NPM_COMMANDS | frozenset(_NPM_ALIASES)
# Commands npm resolves a registry package for: exec (checked with the npx
# grammar), init and create (no pin form), and the install family with update
# and dedupe, which fetch and run registry lifecycle scripts (spec 6).
_NPM_REFUSED_TARGETS = frozenset({"exec", "init", "install", "ci", "install-test", "install-ci-test", "update",
                                  "dedupe"})


# The directory a relative argv path resolves against: the lock directory
# when approve knows it, so identity and inline-metadata checks read the file
# the proxy will run.
_BASE: contextvars.ContextVar[Path] = contextvars.ContextVar("_BASE", default=Path("."))
# The lock directory (None when approve has none), the normalized pinned
# trees, where a python or node script must lie, and argv[0], whose pinned
# venv an -m module must come from (spec 6).
_PINNED: contextvars.ContextVar[tuple] = contextvars.ContextVar("_PINNED", default=(None, (), ""))
# uv reads the whole script. A larger file is refused rather than read.
_INLINE_SCRIPT_MAX_BYTES = 16 * 1024 * 1024
_TOML_STR = r"""(?:"[^"\\\x00-\x1f\x7f]*"|'[^'\x00-\x1f\x7f]*')"""
_TOML_TAIL = r"[ \t]*(?:#[^\n]*)?\n"
_INLINE_BLANK = re.compile(_TOML_TAIL)
_INLINE_PYTHON = re.compile(r"[ \t]*requires-python[ \t]*=[ \t]*" + _TOML_STR + _TOML_TAIL)
_INLINE_DEPS = re.compile(r"[ \t]*dependencies[ \t]*=[ \t]*\[((?:\s|" + _TOML_STR + r"|,|#[^\n]*)*)\]"
                          + _TOML_TAIL)
_INLINE_TOKEN = re.compile(r"(" + _TOML_STR + r")|#[^\n]*|\s|,")
_INLINE_MARKER = re.compile(r"\s*#\s*///")


class _Refused(Exception):
    """A registry runner launch that approve refuses. Carries the message."""


def _refuse(arg: str) -> _Refused:
    return _Refused(f"{_REFUSED}: {_escape_for_display(arg)}")


def _unsupported_flag(flag: str) -> _Refused:
    return _Refused(f"unsupported container flag {_escape_for_display(flag)}: the image cannot be located")


def _is_exact_version(version: str) -> bool:
    if not version or version.lower() == "latest" or not _VERSION_CHARS.fullmatch(version):
        return False
    # "1.x" is otherwise made only of allowed characters, so an npm-style
    # wildcard segment needs its own check.
    return not any(seg.lower() == "x" for seg in version.split("."))


def _pip_exact(spec: str) -> bool:
    name, sep, version = spec.partition("==")
    return bool(sep) and bool(_PIP_NAME.fullmatch(name)) and _is_exact_version(version)


def _npm_exact(spec: str) -> bool:
    # A scoped package's leading "@" names the scope, so the version separator
    # is the first "@" after it.
    at = spec.find("@", 1 if spec.startswith("@") else 0)
    if at <= 0:
        return False
    return bool(_NPM_NAME.fullmatch(spec[:at])) and bool(_NPM_EXACT_VERSION.fullmatch(spec[at + 1:]))


def _match_flag(tok: str, flags: Sequence[tuple]) -> tuple | None:
    """(canonical, kind[, value]) for the first flag spec tok matches, or None.

    kind is "bare" for a switch, "value" when the value is the next token, or
    "inline" when tok carries it after "=".
    """
    for names, canonical, takes_value in flags:
        if tok in names:
            return (canonical, "value" if takes_value else "bare")
        if takes_value:
            hit = next((nm for nm in names if tok.startswith(nm + "=")), None)
            if hit is not None:
                return (canonical, "inline", tok[len(hit) + 1:])
    return None


def _scan(rest: Sequence[str], flags: Sequence[tuple], double_dash: bool = False) -> tuple[dict, int]:
    """(values per flag, index of the first positional) for rest.

    Only the allowlisted flags may appear before the positional (the package
    or command). Anything else starting with "-" is refused. A value flag
    whose separate value starts with "-" is refused too, so a flag cannot be
    hidden as another flag's value. Nothing past the positional is read, so a
    decoy positional cannot be paired with a pinned flag placed after it
    (fix round 1).
    """
    collected: dict[str, list] = {canonical: [] for _, canonical, _ in flags}
    i, n = 0, len(rest)
    while i < n:
        tok = rest[i]
        if double_dash and tok == "--":
            return collected, i + 1
        m = _match_flag(tok, flags)
        if m is None:
            if tok.startswith("-"):
                raise _refuse(tok)
            return collected, i
        if m[1] == "bare":
            i += 1
        elif m[1] == "value":
            if i + 1 >= n or rest[i + 1].startswith("-"):
                raise _refuse(tok)
            collected[m[0]].append(rest[i + 1])
            i += 2
        else:
            collected[m[0]].append(m[2])
            i += 1
    return collected, n


def _require(ok: bool, arg: str) -> None:
    if not ok:
        raise _refuse(arg)


def _positional(rest: Sequence[str], i: int, runner: str) -> str:
    if i >= len(rest):
        raise _refuse(runner)
    return rest[i]


_NPX_FLAGS = ((("-y", "--yes"), "yes", False), (("-p", "--package"), "package", True))
_DLX_FLAGS = ((("--package",), "package", True),)
_UVX_FLAGS = ((("--from",), "from", True), (("--with",), "with", True), (("--python",), "python", True))
_UV_RUN_FLAGS = ((("--with",), "with", True), (("--python",), "python", True),
                 (("--no-project",), "no-project", False), (("--script",), "script", False))
_PIPX_RUN_FLAGS = ((("--spec",), "spec", True),)


def _npm_style(rest: Sequence[str], flags: Sequence[tuple], runner: str, double_dash: bool = False) -> int:
    """npx, npm exec, bunx, pnpm dlx, yarn dlx: pkg@1.2.3, and every --package the same.

    With a --package, the positional names a binary from those packages, not
    a package, so it is not checked. Returns the index of the positional.
    """
    collected, i = _scan(rest, flags, double_dash)
    packages = collected.get("package", [])
    for p in packages:
        _require(_npm_exact(p), p)
    if not packages:
        target = _positional(rest, i, runner)
        _require(_npm_exact(target), target)
    return i


def _uvx(rest: Sequence[str]) -> None:
    collected, i = _scan(rest, _UVX_FLAGS)
    for spec in collected["with"] + collected["from"]:
        _require(_pip_exact(spec), spec)
    if not collected["from"]:
        target = _positional(rest, i, "uvx")
        _require(_pip_exact(target), target)


def _uv_run(rest: Sequence[str]) -> None:
    """uv run fetches from the registry only through --with. Without one it
    runs a local script or project. A URL command is refused, because uv run
    fetches and runs a remote script it names."""
    collected, i = _scan(rest, _UV_RUN_FLAGS)
    for spec in collected["with"]:
        _require(_pip_exact(spec), spec)
    if i < len(rest):
        _require("://" not in rest[i], rest[i])
        _inline_metadata(rest[i])


def _inline_block(text: str) -> str | None:
    """The content of the single PEP 723 script block in text, "" when there
    is none, or None when a block marker appears in any other shape.

    uv and the PEP differ in small ways about what a block looks like, so any
    line that looks like a marker must belong to exactly one well-formed
    "# /// script" block, or the file is refused.
    """
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]
    markers = [n for n, ln in enumerate(lines) if _INLINE_MARKER.match(ln)]
    if not markers:
        return ""
    if len(markers) != 2 or lines[markers[0]] != "# /// script" or lines[markers[1]] != "# ///":
        return None
    body = lines[markers[0] + 1:markers[1]]
    if any(not (ln == "#" or ln.startswith("# ")) for ln in body):
        return None
    return "".join(ln[2:] + "\n" for ln in body)


def _inline_metadata(target: str) -> None:
    """A uv run target file's PEP 723 dependencies must all be exact PyPI pins.

    uv fetches them from the registry at every launch (spec 6). Only
    requires-python and a dependencies array of plain strings are accepted.
    Every other key, table, or string form is refused, so nothing in the block
    can change where or what uv fetches without being read here.
    """
    try:
        path = target if os.path.isabs(target) else os.path.join(str(_BASE.get()), target)
        if not os.path.isfile(path):
            return
        with open(path, "rb") as f:
            data = f.read(_INLINE_SCRIPT_MAX_BYTES + 1)
        text = data.decode("utf-8-sig")
    except (OSError, ValueError):
        raise _refuse(target) from None
    if len(data) > _INLINE_SCRIPT_MAX_BYTES:
        raise _refuse(target)
    content = _inline_block(text)
    if content is None:
        raise _refuse(target)
    pos, seen = 0, set()
    while pos < len(content):
        for key, pattern in (("", _INLINE_BLANK), ("requires-python", _INLINE_PYTHON),
                             ("dependencies", _INLINE_DEPS)):
            m = pattern.match(content, pos)
            if m and m.end() > pos:
                break
        else:
            raise _refuse(target)
        if key:
            _require(key not in seen, target)
            seen.add(key)
        if key == "dependencies":
            # Tokenized in order, so a quote inside a comment is never read
            # as a dependency and a dependency is never read as a comment.
            for tok in _INLINE_TOKEN.finditer(m.group(1)):
                if tok.group(1):
                    _require(_pip_exact(tok.group(1)[1:-1]), tok.group(1)[1:-1])
        pos = m.end()


def _pipx_run(rest: Sequence[str]) -> None:
    collected, i = _scan(rest, _PIPX_RUN_FLAGS)
    for spec in collected["spec"]:
        _require(_pip_exact(spec), spec)
    if not collected["spec"]:
        target = _positional(rest, i, "pipx run")
        _require(_pip_exact(target), target)


def _subcommand(rest: Sequence[str], could_run: Callable[[str], bool], refusal: Callable[[str], _Refused]) -> int | None:
    """Index of the package-running subcommand at the head of rest, or None.

    A flag at the head is refused whenever any later token could be that
    subcommand. The flag's value is never skipped, because telling a value
    from a subcommand needs the runner's whole global flag grammar, and each
    earlier scanner that guessed was bypassed (fix round 3 ruling).
    """
    if not rest:
        return None
    if rest[0].startswith("-"):
        if any(not t.startswith("-") and could_run(t) for t in rest[1:]):
            raise refusal(rest[0])
        return None
    return 0 if could_run(rest[0]) else None


def _one_of(*words: str) -> Callable[[str], bool]:
    folded = frozenset(words)
    return lambda tok: tok.casefold() in folded


def _npm_deref(word: str) -> str:
    while word in _NPM_ALIASES:
        word = _NPM_ALIASES[word]
    return word


def _npm_could_run(tok: str) -> bool:
    """True when npm could resolve tok to exec, init, create, or the install family.

    npm expands a unique prefix of any command or alias and converts camelCase
    to dashes. This counts every word tok is a prefix of, unique or not, so an
    ambiguous prefix is refused rather than guessed at.
    """
    forms = {tok.casefold(), re.sub(r"[A-Z]", lambda m: "-" + m.group().lower(), tok)}
    for form in forms:
        words = [form] if form in _NPM_WORDS else [w for w in _NPM_WORDS if w.startswith(form)]
        if any(_npm_deref(w) in _NPM_REFUSED_TARGETS for w in words):
            return True
    return False


def _npm(rest: Sequence[str]) -> None:
    i = _subcommand(rest, _npm_could_run, _refuse)
    if i is None:
        return
    if rest[i] not in ("exec", "x"):
        # init, create, the install family, and every abbreviation or
        # misspelling npm expands to them or to exec. None has a pin form, and
        # an abbreviation is not a spelling the runner table lists.
        raise _refuse(rest[i])
    sub = rest[i + 1:]
    j = _npm_style(sub, _NPX_FLAGS, "npm exec", double_dash=True)
    # npm parses flags anywhere until "--", so a --package or --registry after
    # the package still applies. Unless "--" came before the package, any
    # later token starting with "-" is refused (spec 6). npx inserts that "--"
    # itself, so npx needs no such rule.
    if "--" not in sub[:j]:
        for tok in sub[j:]:
            if tok.startswith("-"):
                raise _refuse(tok)


def _uv(rest: Sequence[str]) -> None:
    i = _subcommand(rest, _one_of("run", "tool"), _refuse)
    if i is None:
        return
    if rest[i] == "run":
        _uv_run(rest[i + 1:])
        return
    _require(rest[i] == "tool", rest[i])
    tool = rest[i + 1:]
    j = _subcommand(tool, _one_of("run", "uvx"), _refuse)
    if j is None:
        return
    _require(tool[j] in ("run", "uvx"), tool[j])
    _uvx(tool[j + 1:])


def _pipx(rest: Sequence[str]) -> None:
    i = _subcommand(rest, _one_of("run"), _refuse)
    if i is None:
        return
    _require(rest[i] == "run", rest[i])
    _pipx_run(rest[i + 1:])


def _dlx_runner(name: str, sub: str) -> Callable[[Sequence[str]], None]:
    """bun x, pnpm dlx, yarn dlx. Their create subcommands run create-<x>
    from the registry the way npm create does and have no pin form either."""
    flags = () if name == "bun" else _DLX_FLAGS

    def check(rest: Sequence[str]) -> None:
        i = _subcommand(rest, _one_of(sub, "create"), _refuse)
        if i is None:
            return
        _require(rest[i] == sub, rest[i])
        _npm_style(rest[i + 1:], flags, f"{name} {sub}")
    return check


_FLAG_SECTIONS = ("docker_global", "docker", "podman")


def _load_flag_text() -> str:
    return resources.files("cxbom").joinpath("_data/container-run-flags.json").read_text()


def _str_map(value: object) -> bool:
    return isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())


def _flag_table() -> dict:
    """The vendored container flag tables, or a refusal when the file is
    unreadable or not the shape _container_flags indexes into, so a damaged
    install refuses a container launch instead of raising KeyError."""
    unreadable = "the container flag table cannot be read"
    try:
        table = json.loads(_load_flag_text())
    except (OSError, ValueError):
        raise _Refused(unreadable) from None
    if not isinstance(table, dict):
        raise _Refused(unreadable)
    for key in _FLAG_SECTIONS:
        section = table.get(key)
        if not (isinstance(section, dict) and _str_map(section.get("long")) and _str_map(section.get("short"))
                and _str_map(section.get("alias", {}))):
            raise _Refused(unreadable)
    return table


def _container_flags(rest: Sequence[str], i: int, table: dict, runner: str) -> int:
    """Index of the first token at or after i that is not a flag or a flag's value.

    Parses with each flag's arity from the vendored table: --flag=value and
    --flag value for value flags, only a bare flag or =true/=false for a
    boolean, combined short flags where a value flag takes the rest of the
    group or the next token, and "--" ending flags. A flag missing from the
    table is refused, because the image position cannot be found past it.
    """
    long, short, alias = table["long"], table["short"], table.get("alias", {})
    n = len(rest)
    while i < n:
        tok = rest[i]
        if tok == "--":
            return i + 1
        if tok.startswith("--"):
            name, eq, value = tok[2:].partition("=")
            canon = alias.get(name, name)
            kind = long.get(canon)
            if not name or kind is None:
                raise _unsupported_flag("--" + name)
            if runner == "podman" and canon == "rootfs":
                raise _Refused("podman --rootfs runs a host path, not a pinned image")
            if kind == "bool":
                if eq and value not in ("true", "false"):
                    raise _unsupported_flag(tok)
                i += 1
            elif eq:
                i += 1
            elif i + 1 < n:
                i += 2
            else:
                raise _refuse(tok)
        elif tok.startswith("-") and len(tok) > 1:
            letters, j, step = tok[1:], 0, 1
            while j < len(letters):
                canon = short.get(letters[j])
                if canon is None or canon not in long:
                    raise _unsupported_flag("-" + letters[j])
                if runner == "podman" and canon == "rootfs":
                    raise _Refused("podman --rootfs runs a host path, not a pinned image")
                after = letters[j + 1:]
                if long[canon] == "bool":
                    if after.startswith("="):
                        if after[1:] not in ("true", "false"):
                            raise _unsupported_flag(tok)
                        break
                    j += 1
                    continue
                # A value flag takes the rest of the group as its value, so it
                # is always the last flag in the group.
                if not after:
                    if i + 1 >= n:
                        raise _refuse(tok)
                    step = 2
                break
            i += step
        else:
            return i
    return n


def _container_image(rest: Sequence[str], table: dict, runner: str) -> None:
    i = _container_flags(rest, 0, table, runner)
    image = _positional(rest, i, f"{runner} run")
    scheme = _IMAGE_SCHEME.match(image)
    if scheme:
        after = image[scheme.end():]
        _require(scheme.group()[:-1].casefold() not in _IMAGE_TRANSPORTS
                 and bool(_IMAGE_PORT.match(after) or _IMAGE_TAG_DIGEST.match(after)), image)
    _require(bool(_IMAGE_DIGEST.fullmatch(image)), image)


def _container_subcommand(rest: Sequence[str], table: dict, runner: str) -> None:
    """run, or container run, with no flag between the words.

    compose, kube play, and play kube launch images named inside a file, where
    no digest pin in argv covers them, so they are refused (spec 6).
    """
    i = _subcommand(rest, _one_of("run", "container", "compose", "kube", "play"), _unsupported_flag)
    if i is None:
        return
    word, later = rest[i].casefold(), [t.casefold() for t in rest[i + 1:]]
    if word == "compose" or (word == "kube" and "play" in later) or (word == "play" and "kube" in later):
        raise _refuse(rest[i])
    if word in ("kube", "play"):
        return
    if rest[i] == "run":
        _container_image(rest[i + 1:], table, runner)
        return
    _require(rest[i] == "container", rest[i])
    sub = rest[i + 1:]
    j = _subcommand(sub, _one_of("run"), _unsupported_flag)
    if j is None:
        return
    _require(sub[j] == "run", sub[j])
    _container_image(sub[j + 1:], table, runner)


def _docker(rest: Sequence[str]) -> None:
    table = _flag_table()
    try:
        i = _container_flags(rest, 0, table["docker_global"], "docker")
    except _Refused:
        # An unknown global flag hides where the subcommand is. It matters
        # only when a later token could be run.
        if any(t.casefold() in ("run", "container", "mcp", "compose", "kube", "play") for t in rest):
            raise
        return
    if i > 0 and i <= len(rest) and rest[i - 1] == "--":
        raise _unsupported_flag("--")
    # The MCP gateway fetches servers from a catalog, with no digest in argv
    # (spec 6).
    if i < len(rest) and rest[i].casefold() == "mcp":
        raise _refuse(rest[i])
    _container_subcommand(rest[i:], table["docker"], "docker")


def _podman(rest: Sequence[str]) -> None:
    # Podman global flags before run are refused (spec 6), so no global
    # table is parsed.
    _container_subcommand(rest, _flag_table()["podman"], "podman")


def _path_identity(path: str) -> str:
    base = os.path.basename(path).casefold()
    parent = os.path.basename(os.path.dirname(path)).casefold()
    if parent in _PACKAGE_SCRIPTS.get(base, ()):
        return parent
    return _canonical_launcher_name(base)


_STANDARD_NAME = "run the runner by its standard name"
_NODE_PACKAGES = frozenset({"npm", "corepack"})
_PYTHON_PACKAGES = frozenset({"pipx", "uv", "uvx"})
# The standard entry points inside each runner package, by path from the
# package root, and the runner each one is. Anything else inside these
# packages is refused, because the installed runner's files under another
# spelling are the same runner (spec 6).
_STANDARD_ENTRIES = {
    ("npm", "bin/npm-cli.js"): "npm", ("npm", "bin/npx-cli.js"): "npx", ("npm", "index.js"): "npm",
    ("npm", "bin/npm"): "npm", ("npm", "bin/npx"): "npx",
    ("corepack", "dist/corepack.js"): "corepack",
    **{("corepack", f"dist/{pm}.js"): _LAUNCHER_ALIASES.get(f"{pm}.js", pm)
       for pm in ("npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg")},
    **{("corepack", f"shims/{pm}"): _LAUNCHER_ALIASES.get(pm, pm)
       for pm in ("corepack", "npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg")},
    ("pipx", "__main__.py"): "pipx", ("uv", "__main__.py"): "uv", ("uvx", "__main__.py"): "uvx",
}


def _package_json_name(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            data = json.loads(f.read(1024 * 1024))
    except (OSError, ValueError):
        return None
    name = data.get("name") if isinstance(data, dict) else None
    return name.casefold() if isinstance(name, str) else None


def _runner_package(real: str) -> tuple[str, str] | None:
    """(runner package, path inside it) when real lies in an installed npm,
    corepack, pipx, uv, or uvx package, else None.

    The package root is the nearest ancestor with a package.json (its name
    decides, so npm's own node_modules/<dep> is not npm), or a directory right
    under site-packages or dist-packages, or node_modules/npm and
    node_modules/corepack even without a readable package.json.
    """
    d = os.path.dirname(real)
    while True:
        base = os.path.basename(d).casefold()
        parent = os.path.basename(os.path.dirname(d)).casefold()
        inner = os.path.relpath(real, d).replace(os.sep, "/")
        if os.path.isfile(os.path.join(d, "package.json")):
            name = _package_json_name(os.path.join(d, "package.json"))
            if name is None and base in _NODE_PACKAGES:
                name = base
            return (name, inner) if name in _NODE_PACKAGES else None
        if parent in ("site-packages", "dist-packages"):
            return (base, inner) if base in _PYTHON_PACKAGES else None
        if parent == "node_modules" and base in _NODE_PACKAGES:
            return base, inner
        up = os.path.dirname(d)
        if up == d:
            return None
        d = up


def _node_resolve(path: str) -> str | None:
    """The file node runs for a script argument: the exact path, then with
    .js, .cjs, .mjs, or .json, then a directory's package.json main or its
    index file."""
    for cand in (path, path + ".js", path + ".cjs", path + ".mjs", path + ".json"):
        if os.path.isfile(cand):
            return cand
    if not os.path.isdir(path):
        return None
    try:
        with open(os.path.join(path, "package.json"), "rb") as f:
            main = json.loads(f.read(1024 * 1024)).get("main")
    except (OSError, ValueError, AttributeError):
        main = None
    if isinstance(main, str) and main:
        found = _node_resolve(os.path.join(path, main))
        if found is not None:
            return found
    for index in ("index.js", "index.cjs", "index.mjs", "index.json", "index.node"):
        if os.path.isfile(os.path.join(path, index)):
            return os.path.join(path, index)
    return None


def _python_resolve(path: str) -> str | None:
    """The source file python runs for a script argument: the file, a
    directory's __main__.py, and for bytecode the .py it was compiled from
    (__pycache__/NAME.cpython-312.pyc and NAME.pyc both name NAME.py)."""
    if os.path.isdir(path):
        path = os.path.join(path, "__main__.py")
    if not os.path.lexists(path):
        return None
    real = os.path.realpath(path)
    name = os.path.basename(real)
    if os.path.basename(os.path.dirname(real)) == "__pycache__":
        return os.path.join(os.path.dirname(os.path.dirname(real)), name.split(".", 1)[0] + ".py")
    if name.endswith(".pyc"):
        return real[:-1]
    return real


def _script_runners(tok: str, interpreter: str) -> set[str]:
    """The runners a node or python script argument is.

    By name (_identities), and by where its resolved realpath lies: a standard
    entry inside an installed runner package is that runner, and any other
    file there is refused with "run the runner by its standard name".
    """
    names = _identities(tok)
    path = tok if os.path.isabs(tok) else os.path.join(str(_BASE.get()), tok)
    try:
        found = _node_resolve(path) if interpreter == "node" else _python_resolve(path)
        real = os.path.realpath(found) if found is not None else None
    except (OSError, ValueError):
        real = None
    if real is None:
        return names
    return names | _package_identity(real)


def _package_identity(real: str) -> set[str]:
    """The runner names of a resolved file: its own name, and the runner a
    standard entry inside an installed runner package is. Any other file in
    such a package is refused with "run the runner by its standard name"."""
    names = {_path_identity(real)}
    package = _runner_package(real)
    if package is not None:
        entry = _STANDARD_ENTRIES.get(package)
        if entry is None:
            raise _Refused(_STANDARD_NAME)
        names.add(entry)
    return names


def _identities(tok: str) -> set[str]:
    """Runner names for tok as named and for its realpath target.

    A relative tok resolves against the lock directory, where the proxy
    resolves it.
    """
    names = {_path_identity(tok)}
    try:
        names.add(_path_identity(os.path.realpath(os.path.join(str(_BASE.get()), tok))))
    except (OSError, ValueError):
        pass
    return names


def _python(rest: Sequence[str]) -> None:
    """A python launch: allowlisted options, then a script or -m module.

    Only -u -B -I -E -s -S -O -q -P, alone or combined, may come first. Any
    other option, "-", "--", or no script at all is refused with "put the code
    in a pinned file". -m takes its module attached (-mpipx, -Imrunpy) or as
    the next token. A standard-library launcher module is refused. A runner
    module, or a script that is a runner, goes through that runner's grammar,
    and is refused after any interpreter option, as before (fix round 1).
    """
    for i, tok in enumerate(rest):
        if not tok.startswith("-") or tok == "-":
            if tok == "-":
                raise _Refused(_PINNED_FILE)
            runners = sorted(_script_runners(tok, "python") & _PYTHON_RUNNERS)
            if runners and i > 0:
                raise _refuse(rest[0])
            for runner in runners:
                _RUNNERS[runner](rest[i + 1:])
            if not runners:
                _pinned_script(tok, "python")
            return
        letters = tok[1:]
        for k, ch in enumerate(letters):
            if ch in _PY_ALLOWED:
                continue
            if ch != "m":
                raise _Refused(_PINNED_FILE)
            module, after = letters[k + 1:], i + 1
            if not module:
                if i + 1 >= len(rest):
                    raise _Refused(_PINNED_FILE)
                module, after = rest[i + 1], i + 2
            _python_module(module, rest[after:], rest[0] if (i > 0 or k > 0) else None)
            return
    raise _Refused(_PINNED_FILE)


def _python_module(module: str, rest: Sequence[str], first_option: str | None) -> None:
    """-m accepts a runner module, checked with the runner grammar, or a
    module whose top-level package or file lies in a pinned tree (spec 6).
    Anything else, the standard-library launchers included, is refused with
    "put the code in a pinned file"."""
    if not _PY_MODULE_NAME.fullmatch(module):
        raise _Refused(_PINNED_FILE)
    folded = module.casefold()
    root = folded.split(".")[0]
    if root not in _PYTHON_RUNNERS:
        _pinned_module(module.split(".")[0])
        return
    if first_option is not None:
        raise _refuse(first_option)
    # A runner submodule (pipx.main) has no pin form of its own.
    _require(folded in (root, root + ".__main__"), module)
    _RUNNERS[root](rest)


def _in_pinned_tree(path: str) -> bool:
    lock_dir, trees, _argv0 = _PINNED.get()
    if lock_dir is None:
        return False
    rel = launch.pinned_relative(lock_dir, path)
    return rel is not None and launch.within_trees(rel, trees)


def _pinned_script(tok: str, interpreter: str) -> None:
    """Refuse a python or node script that is not pinned (spec 6).

    A regular file named in the lock directory is pinned by its own hash,
    because compute_launch_pins hashes every argv file there. Anything else
    the interpreter runs (a directory, a zip, node's extension and index
    resolution) must lie in a pinned tree. Both use the device and inode
    test launch.py applies. A script elsewhere, the standard library
    included, can start any module, so it is refused.
    """
    lock_dir, _trees, _argv0 = _PINNED.get()
    if lock_dir is None:
        raise _Refused(_PINNED_FILE)
    path = tok if os.path.isabs(tok) else os.path.join(str(lock_dir), tok)
    try:
        if os.path.isfile(path) and not os.path.islink(path) and launch.pinned_relative(lock_dir, path) is not None:
            return
        if interpreter == "node":
            found = _node_resolve(path)
        else:
            found = path if os.path.exists(path) else None
    except (OSError, ValueError):
        found = None
    if found is None or not _in_pinned_tree(found):
        raise _Refused(_PINNED_FILE)


def _pinned_module(root: str) -> None:
    """Refuse an -m module that does not come from a pinned venv (spec 6).

    The child runs in an empty temporary directory and searches only the
    interpreter's own paths, never a pinned tree. So argv[0] must resolve
    into a pinned tree (launch.resolve_argv0 applies the tree test to a
    path-form argv[0] and to its directory), and the module's
    top-level package or <root>.py must lie in that interpreter's
    lib/python*/site-packages, inside a pinned tree. A bare python3 resolves
    on the trusted search path, whose site-packages nothing pins, so any
    non-runner module is refused. A standard-library name is refused even
    there, because the standard library loads first.
    """
    lock_dir, trees, argv0 = _PINNED.get()
    if lock_dir is None or root.casefold() in _PY_UNPINNABLE_MODULES:
        raise _Refused(_PINNED_FILE)
    try:
        found = launch.resolve_argv0(argv0, lock_dir, trees)
    except (launch.LaunchError, OSError, ValueError):
        raise _Refused(_PINNED_FILE) from None
    # The interpreter's own directory must lie in a pinned tree. The module
    # test below also refuses a system python3, because its site-packages
    # lies outside the lock directory. This check keeps the spec's rule when
    # a trusted search-path directory's prefix sits inside a pinned tree.
    if not _in_pinned_tree(os.path.dirname(found)):
        raise _Refused(_PINNED_FILE)
    prefix = os.path.dirname(os.path.dirname(found))
    for site in glob.glob(os.path.join(glob.escape(prefix), "lib", "python*", "site-packages")):
        for cand in (os.path.join(site, root), os.path.join(site, root + ".py")):
            if os.path.exists(cand) and _in_pinned_tree(cand):
                return
    raise _Refused(_PINNED_FILE)


def _node(rest: Sequence[str]) -> None:
    """A node launch: allowlisted options, then a script.

    Only --no-warnings, --enable-source-maps, --no-deprecation,
    --max-old-space-size=N, and --stack-size=N may come first. Any other
    option, in any form, is refused with "put the code in a pinned file", so a
    preload (--require=npx-cli.js) cannot start a runner before the script. A
    script that is a runner goes through that runner's grammar, and is refused
    after any node option, as before.
    """
    for i, tok in enumerate(rest):
        if tok.startswith("-"):
            if tok in _NODE_ALLOWED or _NODE_ALLOWED_VALUE.fullmatch(tok):
                continue
            raise _Refused(_PINNED_FILE)
        runners = sorted(_script_runners(tok, "node") & _NODE_RUNNERS)
        if runners and i > 0:
            raise _refuse(rest[0])
        for runner in runners:
            _RUNNERS[runner](rest[i + 1:])
        if not runners:
            _pinned_script(tok, "node")
        return
    raise _Refused(_PINNED_FILE)


def _corepack(rest: Sequence[str]) -> None:
    """corepack <pm>@X.Y.Z ... runs <pm> ..., so it is checked as that runner.

    The package manager itself must carry an exact version, because corepack
    resolves a bare name, a tag, or a range against the registry (spec 6).
    """
    def manager(tok: str) -> str:
        return _canonical_launcher_name(tok.split("@", 1)[0].casefold())

    i = _subcommand(rest, lambda t: manager(t) in _COREPACK_MANAGERS, _refuse)
    if i is None:
        return
    _name, at, version = rest[i].partition("@")
    _require(bool(at) and bool(_NPM_EXACT_VERSION.fullmatch(version)), rest[i])
    _RUNNERS[manager(rest[i])](rest[i + 1:])


_RUNNERS: dict[str, Callable[[Sequence[str]], None]] = {
    "npx": lambda rest: _npm_style(rest, _NPX_FLAGS, "npx"),
    "npm": _npm,
    "uvx": _uvx,
    "uv": _uv,
    "pipx": _pipx,
    "bunx": lambda rest: _npm_style(rest, (), "bunx"),
    "bun": _dlx_runner("bun", "x"),
    "pnpm": _dlx_runner("pnpm", "dlx"),
    "pnpx": lambda rest: _npm_style(rest, _DLX_FLAGS, "pnpx"),
    "yarn": _dlx_runner("yarn", "dlx"),
    "docker": _docker,
    "podman": _podman,
    "corepack": _corepack,
}
# The section 6 runner table as one set of launcher names. assembly's
# serverVersionPinned reads it, so a launcher this module treats as a
# registry runner is never reported version-pinned through its local files
# (spec 9.4).
REGISTRY_RUNNERS = frozenset(_RUNNERS)


def _canonical_launcher_name(basename: str) -> str:
    return _LAUNCHER_ALIASES.get(basename, basename)


def _launcher_basenames(argv0: str) -> set[str]:
    """Every casefolded, alias-mapped basename argv0 might really launch.

    argv0's own basename always counts, matched case-insensitively because
    APFS resolves a launcher name regardless of case. The realpath target's
    basename counts too, so a symlink under another name is matched by what
    it is. A bare name resolves through the trusted search path launch.py
    uses. A path-form name is realpath-resolved directly, because
    launch.resolve_argv0's path branch also runs a tree-containment check this
    pre-launch check has no lock directory or trees for (fix round 2).

    A resolution failure is ignored: launch.check_launch refuses a launcher it
    cannot resolve on its own. A realpath inside an installed runner package
    must be one of its standard entries.
    """
    if "/" in argv0:
        names = _identities(argv0)
        found = argv0 if os.path.isabs(argv0) else os.path.join(str(_BASE.get()), argv0)
    else:
        names = {_canonical_launcher_name(argv0.casefold())}
        try:
            found = launch.resolve_argv0(argv0, Path("/"), ())
        except (launch.LaunchError, OSError, ValueError):
            return names
    try:
        real = os.path.realpath(found)
    except (OSError, ValueError):
        return names
    # The same runner-package test a script argument gets (spec 6): a file
    # inside an installed runner package runs as that runner, so only its
    # standard entries are accepted.
    return names | _package_identity(real)


# Programs that run the program named later in their own argv (spec 6). A
# runner started through one would otherwise skip the runner grammar, which
# only looks at argv[0].
_EXEC_WRAPPERS = frozenset({"env", "nice", "timeout", "nohup", "stdbuf"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# A wrapper token is split into words at whitespace, quotes, and shell
# punctuation, so "npx evil" or 'npx' inside one element still names npx.
_WRAPPER_WORD_SPLIT = re.compile(r"[\s'\"`;|&()<>{}$=,]+")


def _is_short_option_with(tok: str, letter: str) -> bool:
    """True when tok is a cluster of single-dash (or shell "+") options that includes letter."""
    return len(tok) > 1 and tok[0] in "-+" and not tok.startswith("--") and letter in tok[1:]


def _word_names(word: str) -> set[str]:
    """The runner and interpreter names one word from a wrapper's argv could start."""
    names = _identities(word)
    path = word if os.path.isabs(word) else os.path.join(str(_BASE.get()), word)
    try:
        real = os.path.realpath(path) if "/" in word and os.path.isfile(path) else None
    except (OSError, ValueError):
        real = None
    if real is not None:
        names |= _package_identity(real)
    return names


def _starts_something(name: str) -> bool:
    return (name in _RUNNERS or name.startswith("python") or name in ("node", "nodejs")
            or name in _EXEC_WRAPPERS or name in _SHELLS)


def _wrapper(argv0: str, rest: Sequence[str]) -> None:
    """Refuse a runner, an interpreter, or another wrapper started through a
    wrapper (spec 6).

    A shell's -c and env's -S take a command string, which cannot be parsed
    safely, so either is refused outright with "put the code in a pinned
    file". Any other later word that names a registry runner, a runner's
    standard entry, a python or node interpreter, or another wrapper is
    refused, because the runner and interpreter grammars apply only to
    argv[0].
    """
    wrappers = sorted(_launcher_basenames(argv0) & (_EXEC_WRAPPERS | _SHELLS))
    if not wrappers:
        return
    if any(w in _SHELLS for w in wrappers) and any(_is_short_option_with(t, "c") for t in rest):
        raise _Refused(_PINNED_FILE)
    if "env" in wrappers and any(_is_short_option_with(t, "S") or t.startswith("--s") for t in rest):
        raise _Refused(_PINNED_FILE)
    for tok in rest:
        for word in _WRAPPER_WORD_SPLIT.split(tok):
            if word and any(_starts_something(n) for n in _word_names(word)):
                raise _Refused(f"run {_escape_for_display(word)} directly, not through {wrappers[0]}")


def package_version_problem(argv: Sequence[str], lock_dir: Path | None = None,
                            pin_trees: Sequence[str] = ()) -> str | None:
    """None, or the refusal for a registry runner launch that does not pin its package.

    A registry runner fetches a package or image at launch time, so the argv
    must pin it exactly: the section 6 runner table (uvx and uv tool run/uvx,
    uv run --with, pipx run, npx and npm exec/x, bunx and bun x, pnpm dlx and
    yarn dlx, docker and podman run). An interpreter starting a runner
    (python -m pipx, node npx-cli.js) is that runner, and corepack <pm> is
    <pm>. npm init/create and the install family, docker mcp, and the create
    subcommands of bun, pnpm, and yarn have no pin form and are refused. A uv
    run target file's inline dependencies must be exact pins. lock_dir is
    where a relative path in argv resolves, as it does for the proxy, and
    with pin_trees it is where a python or node script or -m module must lie.
    Without a lock directory no script or module counts as pinned. The refusal is "pin an exact package version" followed by the
    offending argument, escaped, or for a container runner a message naming
    the unsupported flag. There is no override.

    argv0 can match more than one runner (a symlink named uvx to uv, a docker
    that is podman). Every match is checked, and any refusal wins.
    """
    if not argv:
        return None
    rest = list(argv[1:])
    token = _BASE.set(lock_dir if lock_dir is not None else Path("."))
    pinned = _PINNED.set((lock_dir, tuple(launch.normalize_tree(d) for d in pin_trees), argv[0]))
    try:
        _wrapper(argv[0], rest)
        for name in sorted(_launcher_basenames(argv[0])):
            if name in _RUNNERS:
                _RUNNERS[name](rest)
            elif name.startswith("python"):
                _python(rest)
            elif name in ("node", "nodejs"):
                _node(rest)
    except _Refused as e:
        return str(e)
    finally:
        _PINNED.reset(pinned)
        _BASE.reset(token)
    return None


def env_problem(pinned: Mapping[str, str], secret: Iterable[str]) -> str | None:
    """None, or the refusal for a pinned or secret environment variable (spec 6).

    pinned maps each pinned name to its value. A PYTHON* or NODE_* name must
    be empty or on the allowlist, because the rest reach the interpreter's
    load hooks. A code-loading name must be empty. Neither kind may be a
    secret, because a secret's value comes from an untrusted source at
    launch. Names match case-insensitively, which only refuses more.
    """
    for name, value in pinned.items():
        upper = name.upper()
        if upper.startswith(_INTERPRETER_ENV_PREFIXES) and upper not in _INTERPRETER_ENV_ALLOWED and value != "":
            return (f"--pin-env {_escape_for_display(name)} reaches an interpreter hook. "
                    "Put the code in a pinned file, or pin it empty")
        if _code_loading(upper) and value != "":
            return f"--pin-env {_escape_for_display(name)} loads code into the server. Pin it empty"
    for name in secret:
        upper = name.upper()
        if upper.startswith(_INTERPRETER_ENV_PREFIXES) or _code_loading(upper):
            return (f"--secret-env {_escape_for_display(name)} loads code into the server, "
                    "and a secret's value is not pinned. Pin it with --pin-env instead")
    return None


def _code_loading(upper: str) -> bool:
    return upper.startswith(_CODE_LOADING_ENV_PREFIXES) or upper in _CODE_LOADING_ENV


def launch_problem(argv: Sequence[str], lock_dir: Path, pin_trees: Sequence[str],
                   pinned: Mapping[str, str], secret: Iterable[str]) -> str | None:
    """None, or the refusal for a launch under the current spec 6 rules: the
    environment rules, then the runner and interpreter grammar."""
    return env_problem(pinned, secret) or package_version_problem(argv, lock_dir, pin_trees)
