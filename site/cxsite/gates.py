"""Publication gates over a built site directory (design gates 1 to 5).

Owner: ATACE Working Group.

Every gate returns a list of error strings, and an empty list means pass. The
build runs all of them, and any error fails the build, so nothing reaches the
deploy step unless every gate passes. Gate 6 (axe-core) needs a browser, so it
is a separate CI job and not part of this module.

Fail-closed is the whole point, so these gates are written to three rules:

    A gate that cannot inspect its input refuses. Every file read goes through
    _text, which turns an unreadable file or one that is not UTF-8 into an
    error line rather than an exception that a caller might mistake for a pass.

    A gate that finds nothing to check refuses. An empty lock, a build with no
    schema, and a missing stylesheet are errors, not vacuous passes.

    An unexpected exception inside any gate becomes an error line naming that
    gate, in run_all. run_all can return an empty list only when every gate ran
    and every gate passed.

Gate 2 does not scan for identity strings itself. It invokes
scripts/anon_check.py, the project's own anonymity gate, as a subprocess and
takes its exit code as the verdict: 0 passes, 1 reports that script's findings,
and anything else is a refusal. Binding to the script by path rather than to its
internals means the version present at publish time is the version that runs.

Two rules make that verdict worth taking, and both are here because a measured
fail-open broke them:

    Nothing from that file runs in this process. The three helpers gate 2 shares
    with it are fetched through a probe subprocess (_anon_probe), so a SystemExit
    or an os._exit anywhere in it -- at its top level, in load_tokens, in
    require_tokens -- kills a child and costs a refusal, instead of ending the
    build at status 0 with no gate having run.

    A zero exit is not evidence on its own. A zero exit cannot tell "scanned and
    found nothing" from "returned without scanning", so before the checker's
    verdict on the build is trusted it has to report a planted token in one
    file of every type the build publishes (_canary_scan). A gate that has not
    shown it can detect anything has not earned a pass, and a checker that
    stopped reading one file type has not shown it can detect anything there.

Nothing in this module's own output names an absolute filesystem path. An
exception's str() can carry one -- OSError.args includes the filename, and a
traceback names every frame's file -- so a message interpolates an exception
type, e.strerror, or gate-authored text, never the exception itself. The same
rule is why the checker's exit-1 output is forwarded only where it carries that
script's own report prefix: a traceback does not, and a traceback is the one
output its withholding pass never saw.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from . import SITE_ORIGIN, links, palette

ROOT = Path(__file__).resolve().parents[2]
SITE_DIR = Path(__file__).resolve().parents[1]
ANON_SCRIPT = ROOT / "scripts" / "anon_check.py"
# A site scan reads every published file and unpacks fonts and archives, which
# is slow but bounded. The cap exists so a hung checker fails the gate instead
# of hanging the build. Measured, run_all over this build is 0.89 s and the scan
# is the bulk of it. The homepage film is a published binary the scan must
# read, and that read takes about a minute, so the cap is the test's 120 s
# ceiling rather than the old 60 s. The old 600 s meant a hung checker stalled a build for ten
# minutes before the gate refused, which is a worse failure than refusing early.
ANON_TIMEOUT = 120
# The probe only imports the checker and calls one helper, so it needs far less
# headroom than a scan.
ANON_PROBE_TIMEOUT = 30

ALLOWED_HOSTS = links.ALLOWED_HOSTS
ALLOWED_MAILTO = links.ALLOWED_MAILTO
# Only the viewer may carry inline script and style. _headers gives it the one
# path-scoped CSP that allows them. Anywhere else the site CSP would block them.
# An exact relative path, so a page that merely lives under viewer/ is not
# covered by the allowance.
INLINE_OK = frozenset({"viewer/index.html"})
URL_ATTRS = frozenset({"href", "src", "action", "formaction", "poster", "data", "xlink:href", "srcset", "cite"})
TEXT_SUFFIXES = frozenset({".html", ".css", ".json", ".txt", ".svg", ".xml"})

_SHA256 = re.compile(r"[0-9a-f]{64}")
# Text that crossed into this process from outside it, held to one printable
# ASCII line. A path separator, a control character or a non-ASCII byte means it
# is not the fixed text this module promises to print.
_SAFE_DETAIL = re.compile(r"[ -~]{1,200}")
# A denylist filename is one path component. The checker names it, and the
# checker is the untrusted file, so a "../" in that name must not become a write
# outside the scratch directory.
_SAFE_FILENAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
_CSS_URL = re.compile(r"""url\(\s*["']?([^"')]+)""")
# `@import "x";` carries a URL with no url() wrapper, so the pattern above misses
# it. CSP would block a cross-origin stylesheet, but this gate exists to keep an
# identifying host out of the published bytes, which CSP does nothing about.
_CSS_IMPORT = re.compile(r"""@import\s+["']([^"']+)["']""")
# A meta refresh navigates the reader somewhere without being a fetch, so no CSP
# directive covers it and the attribute scan below never sees the target.
_META_REFRESH_URL = re.compile(r"""^\s*[0-9.]*\s*;\s*url\s*=\s*["']?([^"']+)""", re.I)


class GateError(Exception):
    """A gate could not inspect an input, so it refuses rather than passing."""


def _text(path: Path, rel: str) -> str:
    """Read a built file as text, or raise GateError naming why it could not be read."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        raise GateError(f"{rel}: cannot be read ({e.strerror})") from e
    except UnicodeDecodeError:
        raise GateError(f"{rel}: is not valid UTF-8, so it cannot be checked") from None


def _safe_detail(text: object) -> str:
    """One line of text from outside this module, or fixed text saying it was withheld.

    Everything the probe child hands back crosses this, including the checker's
    own require_tokens message. A message may name a file's basename and an
    exception type. A path separator, a control character, a non-ASCII byte or
    more than 200 characters means it is not the fixed text this module promises,
    so it is replaced rather than forwarded. This is the structural half of the
    no-absolute-paths property: the gate cannot print one even if the untrusted
    file tries to hand it one.
    """
    if not isinstance(text, str) or not text.strip():
        return "no message"
    line = text.strip()
    if "/" in line or "\\" in line or not _SAFE_DETAIL.fullmatch(line):
        return "a message that is not fixed text, withheld"
    return line


def anon_module(script: Path | None = None):
    """Load scripts/anon_check.py as a module, for the helpers gate 2 shares with it.

    The denylist format and the fail-closed message belong to that script, so
    they are read from it rather than restated here.

    Callers in the gate path reach this only inside the probe child (see
    _probe_main). Running it in the process that has to survive to report is the
    fail-open this module removed: the checker is the untrusted file, and there
    is no handler for os._exit.
    """
    script = ANON_SCRIPT if script is None else script
    spec = importlib.util.spec_from_file_location("anon_check", script)
    if spec is None or spec.loader is None:
        raise GateError(f"{script.name} cannot be loaded as a module")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except (KeyboardInterrupt, MemoryError):
        # An interrupt is not a finding, and neither is running out of memory.
        raise
    except BaseException as e:
        # BaseException, because SystemExit is not an Exception: a module that
        # exits the interpreter while being imported has not loaded, and without
        # this a `raise SystemExit(0)` at its top level ended the build with
        # status 0 and no gate having run. Measured, not theorised. The type name
        # alone, because the exception's own str() can carry an absolute path.
        raise GateError(f"{script.name} failed while loading ({type(e).__name__})") from e
    return mod


# The child program, kept to four lines because everything it does is in
# _probe_main, in this file, where it is read and reviewed with the rest of the
# gate. argv is the site package directory, the request file and the response
# file.
_PROBE = """
import sys
sys.path.insert(0, sys.argv[1])
from cxsite.gates import _probe_main
_probe_main(sys.argv[2], sys.argv[3])
"""


def _probe_main(request_path: str, response_path: str) -> None:
    """The child half of _anon_probe: load the checker, answer one request, exit.

    Being a child is the point. A SystemExit or an os._exit from the checker's
    top level, from load_tokens or from require_tokens ends this process with the
    response file absent, and the parent reads an absent response as a refusal.

    The answer goes to a file rather than to stdout, so anything the checker
    prints on its way through its own module body cannot be mistaken for it.
    """
    req = json.loads(Path(request_path).read_text(encoding="utf-8"))
    try:
        mod = anon_module(Path(req["script"]))
        out: dict = {"ok": True, "denylist_name": mod.DENYLIST_NAME}
        # Uncoerced. Wrapping a helper's answer in list() here would turn a
        # string into a list of characters and hand the parent something that
        # passes its shape check, so the parent validates what the helper
        # actually returned.
        if req.get("require") is not None:
            out["missing"] = mod.require_tokens(list(req["require"]))
        if req.get("load") is not None:
            out["tokens"] = mod.load_tokens(Path(req["load"]))
        if req.get("load_under") is not None:
            out["tokens"] = mod.load_tokens(Path(req["load_under"]) / mod.DENYLIST_NAME)
    except GateError as e:
        out = {"ok": False, "detail": str(e)}
    except BaseException as e:
        # Same reasoning as anon_module's clause, one level out: a helper that
        # exits the interpreter has not answered. Named by type only, and the
        # parent puts it through _safe_detail anyway.
        out = {"ok": False, "detail": f"{type(e).__name__} escaped the probe"}
    Path(response_path).write_text(json.dumps(out, default=str), encoding="utf-8")


def _anon_probe(*, require: list[str] | None = None, load: Path | None = None,
                load_under: Path | None = None) -> dict:
    """Ask the checker for DENYLIST_NAME, require_tokens or load_tokens, out of process.

    Raises GateError with fixed text when the child did not answer. The child's
    exit status is deliberately not consulted: a hard _exit(0) sets it to 0, so
    the response file is the only evidence this accepts.
    """
    with tempfile.TemporaryDirectory(prefix="anon-probe-") as d:
        req, resp = Path(d) / "request.json", Path(d) / "response.json"
        req.write_text(json.dumps({
            "script": str(ANON_SCRIPT),
            "require": require,
            "load": None if load is None else str(load),
            "load_under": None if load_under is None else str(load_under),
        }), encoding="utf-8")
        try:
            subprocess.run([sys.executable, "-c", _PROBE, str(SITE_DIR), str(req), str(resp)],
                           capture_output=True, timeout=ANON_PROBE_TIMEOUT)
        except OSError as e:
            raise GateError(f"{ANON_SCRIPT.name} could not be run ({e.strerror})") from e
        except subprocess.TimeoutExpired:
            raise GateError(f"{ANON_SCRIPT.name} did not answer within "
                            f"{ANON_PROBE_TIMEOUT}s") from None
        try:
            answer = json.loads(resp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # No answer at all. This is what os._exit or SystemExit inside the
            # checker looks like from out here, and it is the whole import-time
            # fail-open class arriving as a refusal instead of a pass.
            raise GateError(f"{ANON_SCRIPT.name} cannot be loaded in a probe process "
                            f"(it answered nothing)") from None
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        detail = answer.get("detail") if isinstance(answer, dict) else None
        raise GateError(f"{ANON_SCRIPT.name} cannot be loaded in a probe process "
                        f"({_safe_detail(detail)})")
    return answer


def _probe_denylist_name(answer: dict) -> str:
    """The checker's denylist filename, held to one safe path component."""
    name = answer.get("denylist_name")
    if not isinstance(name, str) or name in (".", "..") or not _SAFE_FILENAME.fullmatch(name):
        raise GateError(f"{ANON_SCRIPT.name} did not name its denylist as a single filename")
    return name


def _probe_tokens(answer: dict) -> list[str]:
    """The token list the probe read, or a refusal if it is not one."""
    tokens = answer.get("tokens")
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        raise GateError(f"{ANON_SCRIPT.name} did not return a list of tokens")
    return tokens


def denylist_tokens(root: Path) -> list[str]:
    """The denylist tokens under `root`, read by the checker's own loader, out of process.

    The build path's one use of the checker's internals. The loader belongs to
    that script because the format does; the subprocess is because the file is
    untrusted and the build has to survive to report.
    """
    return _probe_tokens(_anon_probe(load_under=root))


class _Scan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.ids: set[str] = set()
        self.scripts: list[str | None] = []   # src, or None for an inline script
        self.inline_style = 0
        # A dict, not a list, so a page with two of the same handler reports it
        # once and a page with two different ones reports both. Reporting only
        # the first handler would let a fix for it hide the next one.
        self.handlers: dict[str, None] = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(a["id"])
        for k, v in attrs:
            if k in URL_ATTRS and v is not None:
                self.urls.append(v.strip())
            if k.startswith("on"):
                self.handlers[k] = None
            if k == "style":
                self.inline_style += 1
        if tag == "script":
            self.scripts.append(a.get("src"))
        if tag == "style":
            self.inline_style += 1
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
            m = _META_REFRESH_URL.match(a.get("content") or "")
            if m:
                self.urls.append(m.group(1).strip())

    # No handle_startendtag override: HTMLParser's own already dispatches a
    # self-closed tag to handle_starttag, measured on a self-closed <img>, an
    # <image xlink:href> and a self-closed <input onfocus>. An alias here read as
    # coverage it did not add.


def _scan(path: Path, rel: str) -> _Scan:
    s = _Scan()
    s.feed(_text(path, rel))
    s.close()
    return s


def html_files(dist: Path) -> list[Path]:
    return sorted(p for p in dist.rglob("*.html") if p.is_file())


def resolve(dist: Path, url_path: str) -> Path | None:
    """The file in `dist` a rooted, same-origin URL path names, or None.

    None covers every shape a browser would fetch from somewhere other than one
    file inside this build: a relative path, a protocol-relative "//host/x", a
    walk through "..", and a path that lands outside the build once symlinks are
    followed. Percent-escapes are deliberately not decoded: this build publishes
    no path that needs them, so a reference carrying one is refused rather than
    resolved, which is the safe side of that choice.
    """
    path = url_path.split("#", 1)[0].split("?", 1)[0]
    if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
        return None
    rel = path.lstrip("/")
    # No `or rel == ""` arm: path starts with "/" to reach this line, so an empty
    # rel means path is "/", which endswith("/") already covers.
    cand = dist / rel / "index.html" if path.endswith("/") else dist / rel
    try:
        if not cand.resolve().is_relative_to(dist.resolve()):
            return None
        return cand if cand.is_file() else None
    except (OSError, ValueError, RuntimeError):
        # A path with a NUL byte, a symlink loop, or a component that is not a
        # directory. None of them name a file in the build.
        return None


def _page_ids(dist: Path, target: Path) -> set[str]:
    return _scan(target, target.relative_to(dist).as_posix()).ids


def _check_internal(dist: Path, ids: set[str], url: str) -> str | None:
    if url.startswith("#"):
        return None if url[1:] in ids else f"fragment {url} has no target"
    target = resolve(dist, url)
    if target is None:
        return f"{url} does not resolve to a file in the build"
    frag = url.split("#", 1)[1] if "#" in url else ""
    if frag and target.suffix == ".html" and frag not in _page_ids(dist, target):
        return f"{url} names a fragment that {target.relative_to(dist).as_posix()} lacks"
    return None


def _same_origin_ref(parts) -> str:
    """The path, query and fragment of a self-referencing absolute URL, as one reference.

    The fragment has to come along: dropping it would let
    "https://cxbom.org/spec/#no-such-section" pass a check that the same link
    written "/spec/#no-such-section" fails.
    """
    ref = parts.path or "/"
    if parts.query:
        ref += "?" + parts.query
    if parts.fragment:
        ref += "#" + parts.fragment
    return ref


def check_link(dist: Path, ids: set[str], url: str) -> str | None:
    """Why this one reference is not publishable, or None.

    Host recognition is cxsite.links, the same matcher the content tests use, so
    an authority spelling it learns to read is read here too. Anything it finds
    that is not on the permitted-host list is refused whatever shape the
    reference takes, before any scheme or path check runs.
    """
    outside = links.unpermitted_authorities(url)
    if outside:
        return f"{url} names the authority {outside[0]}, which is not on the allowlist"
    if url in ALLOWED_MAILTO:
        return None
    try:
        parts = urlsplit(url)
        parts.port  # raises on a non-numeric port, which no allowlisted host has
    except ValueError as e:
        return f"{url} is not a URL this gate can read ({type(e).__name__})"
    if not parts.hostname:
        # No authority at all, so it has to be same-origin: a rooted path or a
        # fragment. A relative path, a "javascript:" or "data:" URL, and a
        # mailto other than the published one all land here and are refused.
        if url.startswith("#") or (url.startswith("/") and not url.startswith("//")):
            return _check_internal(dist, ids, url)
        return f"{url} is neither a same-origin reference nor an allowlisted link"
    if parts.scheme != "https":
        return f"{url} is not an https link"
    if parts.hostname.lower() == links.SITE_HOST:
        return _check_internal(dist, ids, _same_origin_ref(parts))
    return None


def check_links(dist: Path) -> list[str]:
    errs: list[str] = []
    for page in html_files(dist):
        rel = page.relative_to(dist).as_posix()
        try:
            scan = _scan(page, rel)
            for url in scan.urls:
                err = check_link(dist, scan.ids, url)
                if err:
                    errs.append(f"links: {rel}: {err}")
        except GateError as e:
            errs.append(f"links: {e}")
    for css in sorted(p for p in dist.rglob("*.css") if p.is_file()):
        rel = css.relative_to(dist).as_posix()
        try:
            text = _text(css, rel)
        except GateError as e:
            errs.append(f"links: {e}")
            continue
        for url in _CSS_URL.findall(text) + _CSS_IMPORT.findall(text):
            # A stylesheet fetches, it does not navigate, so every URL in one
            # must be a file this build serves. resolve rejects every other
            # shape, cross-origin and relative alike.
            if resolve(dist, url.strip()) is None:
                errs.append(f"links: {rel}: {url} is not a same-origin file in the build")
    return errs


def check_scripts(dist: Path) -> list[str]:
    errs: list[str] = []
    for page in html_files(dist):
        rel = page.relative_to(dist).as_posix()
        try:
            scripts = _scan(page, rel).scripts
        except GateError as e:
            errs.append(f"scripts: {e}")
            continue
        for src in scripts:
            # None is an inline script, which is check_inline's business.
            if src is not None and resolve(dist, src.strip()) is None:
                errs.append(f"scripts: {rel}: script {src} is not a same-origin file in the build")
    return errs


def check_inline(dist: Path) -> list[str]:
    errs: list[str] = []
    for page in html_files(dist):
        rel = page.relative_to(dist).as_posix()
        if rel in INLINE_OK:
            continue
        try:
            scan = _scan(page, rel)
        except GateError as e:
            errs.append(f"inline: {e}")
            continue
        if any(s is None for s in scan.scripts):
            errs.append(f"inline: {rel}: inline script, which the site CSP blocks")
        if scan.inline_style:
            errs.append(f"inline: {rel}: inline style, which the site CSP blocks")
        for attr in scan.handlers:
            errs.append(f"inline: {rel}: event handler attribute {attr}")
    return errs


def check_schema_ids(dist: Path) -> list[str]:
    schema_dir = dist / "schema"
    schemas = sorted(p for p in schema_dir.rglob("*.json") if p.is_file()) if schema_dir.is_dir() else []
    if not schemas:
        # A build that publishes no schema is not a build of this site, and
        # passing it would certify the $id agreement of nothing at all.
        return ["ids: the build publishes no schema"]
    errs: list[str] = []
    for p in schemas:
        rel = p.relative_to(dist).as_posix()
        try:
            doc = json.loads(_text(p, rel))
        except GateError as e:
            errs.append(f"ids: {e}")
            continue
        except ValueError:
            errs.append(f"ids: {rel}: is not valid JSON")
            continue
        if not isinstance(doc, dict):
            errs.append(f"ids: {rel}: is not a JSON object")
            continue
        want = f"{SITE_ORIGIN}/{rel}"
        got = doc.get("$id")
        if got != want:
            errs.append(f"ids: {rel}: $id {got!r} does not equal {want}")
    return errs


def check_site_urls(dist: Path) -> list[str]:
    """Every reference to the site's own origin anywhere in the build must resolve.

    Records included: this is what makes the $id a paper cites resolve to the
    schema it names. Host recognition is the shared matcher, so the reference is
    found however its scheme is spelled or its separators are encoded, and the
    authorities that are not this site's are check_links' business rather than
    silently skipped here.
    """
    errs: list[str] = []
    for p in sorted(dist.rglob("*")):
        if not (p.is_file() and p.suffix in TEXT_SUFFIXES):
            continue
        rel = p.relative_to(dist).as_posix()
        try:
            text = _text(p, rel)
        except GateError as e:
            errs.append(f"site-urls: {e}")
            continue
        seen: set[str] = set()
        for authority, rest in links.references(text):
            if authority != links.SITE_HOST or rest in seen:
                continue
            seen.add(rest)
            if resolve(dist, rest or "/") is None:
                errs.append(f"site-urls: {rel}: //{authority}{rest} is not served by the build")
    return errs


def check_freeze(dist: Path, lock: dict) -> list[str]:
    entries = [(n, e) for n, e in lock.items() if n != "vendored"]
    if not entries:
        # An empty lock would otherwise certify that every published artifact
        # matches its hash by having no published artifact.
        return ["freeze: the lock pins no published artifact, so nothing is frozen"]
    errs: list[str] = []
    for name, entry in entries:
        if not isinstance(entry, dict):
            errs.append(f"freeze: {name}: lock entry is not an object")
            continue
        served = entry.get("servedAt")
        if not isinstance(served, str) or not served.startswith(SITE_ORIGIN + "/"):
            errs.append(f"freeze: {name}: servedAt {served!r} is not on {SITE_ORIGIN}")
            continue
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            errs.append(f"freeze: {name}: sha256 {digest!r} is not a sha-256 digest")
            continue
        target = resolve(dist, served[len(SITE_ORIGIN):])
        if target is None:
            errs.append(f"freeze: {name}: {served} is missing from the build")
            continue
        try:
            got = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError as e:
            errs.append(f"freeze: {name}: {served} cannot be read ({e.strerror})")
            continue
        if got != digest:
            errs.append(f"freeze: {name}: {served} does not match its locked hash")
    return errs


@contextlib.contextmanager
def _denylist_root(tokens: list[str], name: str):
    """A throwaway git top level holding `tokens` as its denylist.

    anon_check.py reads its denylist from the git top level of the directory it
    runs in, so this is how a token list other than the repository's reaches it
    without editing the repository's own file. The directory is 0700 and the
    denylist 0600, and both are removed when the scan ends, because a denylist
    is an anonymity trust anchor and must not outlive one scan on disk. The
    publish path does not come through here at all: it passes the repository
    root as denylist_root, so the real denylist is never copied anywhere.

    The .git directory is written by hand rather than by `git init`, so no
    global init template runs and the layout is identical on every machine.
    """
    root = Path(tempfile.mkdtemp(prefix="anon-denylist-"))
    try:
        git = root / ".git"
        (git / "objects").mkdir(parents=True)
        (git / "refs").mkdir()
        (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (git / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
                                    encoding="utf-8")
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("".join(t + "\n" for t in tokens))
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


# The checker prefixes every line of its own report with this. A line without it
# did not come from that report, and on the exit-1 path that means a traceback:
# absolute paths in every frame, and the checker's withholding pass never ran
# because the crash happened before it.
ANON_PREFIX = "anon-check: "
# The exit-1 branch was the only one with no bound on how much it forwards. The
# other branch has always printed detail[:1].
ANON_MAX_FINDINGS = 50
# Planted in a one-file scratch scan to prove the checker can still find a token.
# Synthetic and namespaced, so it is not a denylist entry and matches nothing in
# the build. Never built from a real token.
CANARY_TOKEN = "zz-canary-planted-token"
# A suffix short enough to be named in a refusal. A published filename's suffix
# is text the gate did not write, and a longer one could hold a name, so a
# longer one is counted and not printed.
_NAMEABLE_SUFFIX = re.compile(r"\.[A-Za-z0-9]{1,5}")


def _anon_findings(stderr: str) -> tuple[list[str], int]:
    """The checker's report lines with its prefix removed, and how many lines had none.

    Report lines are taken verbatim otherwise. That script withholds any finding
    whose text matches the denylist, and re-deriving or reformatting a line here
    would be the one place a withheld token could come back.

    A line without the prefix is counted, never forwarded. It is not a finding,
    so forwarding it would print text no withholding pass has seen, which is
    exactly how a crash inside the checker used to put fifteen lines of absolute
    paths into the gate output.
    """
    lines = [ln for ln in stderr.splitlines() if ln.strip()]
    findings = [ln.removeprefix(ANON_PREFIX) for ln in lines if ln.startswith(ANON_PREFIX)]
    return findings, len(lines) - len(findings)


def _published_suffixes(dist: Path) -> list[str]:
    """Every file suffix under dist, "" for a file with none, read from the build itself.

    Derived rather than listed, so a file type the build starts publishing gets
    a canary without anyone remembering to add one. A build with no files still
    gets one canary, because a checker that cannot detect has earned nothing
    even on an empty site.
    """
    found = {Path(name).suffix for _, _, names in os.walk(dist) for name in names}
    return sorted(found) or [""]


def _canary_scan(denylist_name: str, dist: Path) -> list[str]:
    """Refuse unless the checker reports a planted token in one file of every published type.

    A zero exit is the only evidence _run_anon_site gets, and a zero exit cannot
    tell "scanned and found nothing" from "returned without scanning". This is
    what separates them, on an input whose answer is known: a site path that
    stops scanning, stops reporting, or exits before it reports fails here,
    before its verdict on the build is trusted.

    One file per suffix the build publishes, because a checker narrowed by file
    type fails open for that type alone: a single .html canary passed a checker
    that had stopped reading .json, which is what the example records and the
    schemas are. Each planted file has to be named by a finding of its own, so
    a report that names some of them, or none, or only prints a traceback, is
    a refusal. Measured cost is still one subprocess.

    The scratch root is the same machinery the scan itself uses, so the canary
    runs against a synthetic denylist and the repository's own is never read,
    copied, or needed.
    """
    suffixes = _published_suffixes(dist)
    what = f"{ANON_SCRIPT.name} site"
    with _denylist_root([CANARY_TOKEN], denylist_name) as root:
        site = root / "canary"
        site.mkdir()
        try:
            for suffix in suffixes:
                (site / f"canary{suffix}").write_text(f"<p>{CANARY_TOKEN}</p>\n", encoding="utf-8")
        except OSError as e:
            return [f"anonymity: the canary files could not be planted ({e.strerror}); "
                    f"refusing to certify anonymity"]
        try:
            done = subprocess.run([sys.executable, str(ANON_SCRIPT), "site", str(site)],
                                  cwd=root, capture_output=True, text=True, timeout=ANON_TIMEOUT)
        except OSError as e:
            return [f"anonymity: the canary scan could not be run ({e.strerror}); "
                    f"refusing to certify anonymity"]
        except subprocess.TimeoutExpired:
            return [f"anonymity: the canary scan did not finish within {ANON_TIMEOUT}s; "
                    f"refusing to certify anonymity"]
        findings, _ = _anon_findings(done.stderr)
        # The file a finding is about is its first chain element: "canary.json:
        # ..." for the file itself, "canary.json > member: ..." inside it.
        named = {f.split(": ", 1)[0].split(" > ", 1)[0] for f in findings}
        missed = [s for s in suffixes if f"canary{s}" not in named]
        # "Reported nothing" needs no clause of its own: with at least one file
        # planted, a report with no findings misses every one of them.
        if done.returncode != 1 or missed:
            shown = [s or "no suffix" for s in missed if not s or _NAMEABLE_SUFFIX.fullmatch(s)]
            hidden = len(missed) - len(shown)
            listed = ", ".join(shown + ([f"{hidden} other"] if hidden else [])) or "none"
            return [f"anonymity: {what} did not report a planted token in every published file "
                    f"type (exit {done.returncode}, {len(suffixes) - len(missed)} of "
                    f"{len(suffixes)} planted files reported, missed: {listed}), so it has not "
                    f"shown it can detect anything there; refusing to certify anonymity"]
        return []


def check_anonymity(dist: Path, tokens: list[str], denylist_root: Path | None = None) -> list[str]:
    """Run `scripts/anon_check.py site <dist>` and take its exit code as the verdict.

    The gate is that script, not a copy of it: it owns the denylist format, the
    folded and decoded views it scans, and the withholding of its own output.
    This function decides only what an exit code means, and only 0 means pass,
    and only after the canary has shown that a zero exit still means something.

    `denylist_root` names the directory whose `.anon-tokens` the checker should
    read. The publish path passes the repository root, so the real denylist stays
    where it is. With no root, `tokens` are materialized into a throwaway one,
    which is how a caller scans against a denylist other than the repository's.
    """
    try:
        answer = _anon_probe(require=tokens)
        name = _probe_denylist_name(answer)
    except GateError as e:
        return [f"anonymity: {e}; refusing to certify anonymity"]
    missing = answer.get("missing")
    if not isinstance(missing, list):
        return [f"anonymity: {ANON_SCRIPT.name} did not answer whether the denylist is usable; "
                f"refusing to certify anonymity"]
    if missing:
        return [f"anonymity: {_safe_detail(m)}" for m in missing]
    canary = _canary_scan(name, dist)
    if canary:
        return canary
    if denylist_root is not None:
        return _run_anon_site(dist, denylist_root)
    with _denylist_root(tokens, name) as root:
        # A token the denylist format cannot carry -- a comment marker, a blank,
        # anything that does not survive the round trip -- would vanish on
        # re-read and the scan would run against fewer tokens than the caller
        # asked for. Checked with the checker's own loader, not a copy of its
        # rules, because that is the loader the scan will use.
        want = [t.strip().lower() for t in tokens]
        try:
            got = _probe_tokens(_anon_probe(load=root / name))
        except GateError as e:
            return [f"anonymity: {e}; refusing to certify anonymity"]
        if got != want:
            return [f"anonymity: {len(want) - len(got)} of {len(want)} tokens do not survive the "
                    f"{name} format; refusing to certify anonymity"]
        return _run_anon_site(dist, root)


def _run_anon_site(dist: Path, cwd: Path) -> list[str]:
    what = f"{ANON_SCRIPT.name} site"
    try:
        done = subprocess.run([sys.executable, str(ANON_SCRIPT), "site", str(dist)],
                              cwd=cwd, capture_output=True, text=True, timeout=ANON_TIMEOUT)
    except OSError as e:
        return [f"anonymity: {what} could not be run ({e.strerror}); refusing to certify anonymity"]
    except subprocess.TimeoutExpired:
        return [f"anonymity: {what} did not finish within {ANON_TIMEOUT}s; "
                f"refusing to certify anonymity"]
    if done.returncode == 0:
        return []
    findings, stray = _anon_findings(done.stderr)
    if done.returncode == 1:
        if stray:
            # Exit 1 with a line that is not a finding is a crash report, not a
            # report. Naming the count and nothing else keeps a traceback's
            # absolute paths out of whatever log this failure gets pasted into.
            return [f"anonymity: {what} exited 1 with {stray} line(s) that are not findings, so "
                    f"its output is a crash report rather than a report; "
                    f"refusing to certify anonymity"]
        # Exit 1 is the checker reporting findings. An exit 1 with nothing on
        # stderr is still a refusal, never an empty pass.
        over = len(findings) - ANON_MAX_FINDINGS
        return ([f"anonymity: {d}" for d in findings[:ANON_MAX_FINDINGS]]
                + ([f"anonymity: and {over} further findings, not shown"] if over > 0 else [])
                or [f"anonymity: {what} reported a finding and printed no detail"])
    return [f"anonymity: {what} exited {done.returncode} without completing a scan; "
            f"refusing to certify anonymity"] + [f"anonymity: {d}" for d in findings[:1]]


def check_contrast(dist: Path) -> list[str]:
    rel = "assets/site.css"
    css = dist / rel
    if not css.is_file():
        return [f"contrast: {rel} is missing from the build"]
    try:
        return palette.check_contrast(_text(css, rel))
    except GateError as e:
        return [f"contrast: {e}"]


def run_all(dist: Path, lock: dict, tokens: list[str], denylist_root: Path | None = None) -> list[str]:
    ordered = (
        ("freeze", lambda: check_freeze(dist, lock)),
        ("anonymity", lambda: check_anonymity(dist, tokens, denylist_root)),
        ("links", lambda: check_links(dist)),
        ("scripts", lambda: check_scripts(dist)),
        ("inline", lambda: check_inline(dist)),
        ("ids", lambda: check_schema_ids(dist)),
        ("site-urls", lambda: check_site_urls(dist)),
        ("contrast", lambda: check_contrast(dist)),
    )
    errs: list[str] = []
    for name, run in ordered:
        try:
            errs += run()
        except KeyboardInterrupt:
            # An interrupt is not a finding, so it reaches the caller.
            raise
        except BaseException as e:
            # A gate that raised has not passed, whatever it raised. Reporting it
            # instead of letting it propagate keeps the other gates' findings
            # visible in the same run, and leaves no path on which an exception
            # yields an empty list.
            #
            # BaseException, not Exception: SystemExit is not an Exception, so a
            # gate that raised SystemExit(0) used to leave this loop and end the
            # process at status 0 with no error line and nothing on either
            # stream. This is the last net before the build reports.
            #
            # Type name only: an exception's str() can carry an absolute
            # filesystem path, and OSError.args includes the filename.
            errs.append(f"{name}: refused after an unexpected {type(e).__name__}")
    return errs
