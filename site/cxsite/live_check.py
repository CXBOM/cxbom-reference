"""Check a deployed copy of the site against the build that produced it.

Owner: ATACE Working Group.

Usage (from the repository root):
    python site/live_check.py https://cxbom.org
    python site/live_check.py https://<hash>.cxbom-spec.pages.dev --dist site/dist
    python site/live_check.py http://127.0.0.1:8788
Exit 0 when the deployment matches, 1 on any difference, 2 on a usage error.

Cloudflare can add content after a deploy: a dashboard toggle for email
obfuscation, Rocket Loader, or Web Analytics injects script or rewrites HTML.
This check fetches every file in the build and requires the served body to
equal the built bytes. It also refuses any Set-Cookie header, any /cdn-cgi/
reference, any redirect, any response header that differs from what
site/_headers declares, and any response header name that is neither declared
there nor on the documented list of what Pages sends.

This runs after a deploy, so it is the last place a difference can be noticed
before the public internet keeps it. That makes one property worth more than
every check in the file: **no failure to reach the deployment may read as a
pass.** A timeout, a refused connection, a DNS failure, a TLS error, a 5xx, a
redirect, a truncated body, a body larger than any built file, an empty build
directory, a site/_headers that declares nothing -- each yields an entry in the
returned list, never an empty one. `fetch` converts every network condition
into a `Response` carrying `problem`, the reason no usable response arrived,
and `check_live` reports `problem` before it looks at anything else. Nothing in
this module answers "no difference" when it means "I could not tell".

The module parses no host out of a response, by design rather than by
omission. A served body must equal a built file byte for byte, which no host
matcher can improve on; a redirect is refused with its Location reported
verbatim rather than resolved; and every checked header is compared as a
literal string against site/_headers. The one argument whose host is parsed is
`base`, which the operator types.

Exit 2 means the check could not run: a bad `base`, or a --dist that is not a
build. Exit 1 means it ran and found differences. An exception that escapes
`check_live` is not converted, so it exits 1 on a traceback, which a pipeline
that branches on the code alone cannot tell from "differences found". Branch on
the code and read the stderr.
"""
from __future__ import annotations

import argparse
import http.client
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
CHECKED_HEADERS = ("content-security-policy", "referrer-policy", "x-content-type-options",
                   "permissions-policy", "cross-origin-opener-policy")
MISSING_PATH = "/cxbom-live-check-missing-page/"
# Pages can answer a missing path differently inside a subtree that has its own
# rule block, and the top-level shape alone would not show it. The viewer's
# block is the one that detaches and replaces a header, so a miss under it is
# also the only end-to-end look at what detach-then-set serves.
MISSING_PATHS = (MISSING_PATH, "/viewer" + MISSING_PATH)
# The one file in the build that is never fetched as a served path, because
# Pages consumes it. Asked for by name so that a deployment publishing the
# site's own header policy is noticed.
HEADERS_PATH = "/_headers"
TIMEOUT_S = 20
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Response header names a faithful Pages response may carry. A name that is not
# here and not declared in site/_headers is the anonymity channel no pre-deploy
# scan can reach: a Transform Rule adding "Link: <https://some.host/>", a Server
# banner naming an origin, a Report-To endpoint. Every name below is documented
# by the HTTP specifications or by Cloudflare, so the set is written from
# documentation rather than from an observed deploy. Scanning header *values*
# against the anonymity denylist is the other half of this and is not here: it
# needs one calibration deploy to learn Cloudflare's own values, and an
# uncalibrated scanner that fires on the first real run is a gate that gets
# switched off. Set-Cookie and Location are deliberately absent. A faithful
# response carries neither, and each already has its own refusal below, so their
# arrival is named twice rather than permitted once.
PERMITTED_HEADERS = frozenset(CHECKED_HEADERS) | frozenset({
    # HTTP entity, caching and connection headers.
    "accept-ranges", "age", "cache-control", "connection", "content-encoding",
    "content-length", "content-type", "date", "etag", "expires",
    "last-modified", "transfer-encoding", "vary",
    # Cloudflare's own documented set.
    "alt-svc", "cf-cache-status", "cf-ray", "nel", "report-to", "server",
    # Pages adds this to every static asset, and site/_headers declares it under
    # /schema/* only. Permitting the name is what keeps this scan from firing on
    # every other path. The value is still required to match wherever _headers
    # asks for it.
    "access-control-allow-origin",
})
# Larger than any file the build writes by a wide margin, and small enough that
# a response claiming to be far larger cannot exhaust memory before it is
# refused. A body over the cap is a difference from the build in its own right.
MAX_BODY_BYTES = 32 * 1024 * 1024


class LiveCheckError(Exception):
    """The check could not run against the given build directory."""


@dataclass
class Response:
    """One response to one request. There is no list of redirect hops because
    `fetch` follows none, so a request never produces more than one response."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes
    # Why no usable response arrived, or None when one did. Every caller must
    # read this before it reads status, headers or body: those three carry
    # placeholder values whenever problem is set, and treating a placeholder as
    # an observation is how a network failure becomes a pass.
    problem: str | None = None

    def header(self, name: str) -> str | None:
        vals = [v for k, v in self.headers if k.lower() == name]
        return ", ".join(vals) if vals else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _read_capped(stream) -> bytes | None:
    """Read to end of stream, or None once the body passes MAX_BODY_BYTES.

    Reading in a loop until the stream is spent, rather than in one sized read,
    is what keeps a legitimate large body from being mistaken for a truncated
    one: a single read(n) is free to return fewer than n bytes on a socket that
    simply has not delivered the rest yet, and _length_problem would then call
    a whole font file truncated. The loop stops one byte past the cap, so a
    response that claims to be enormous is refused without being buffered.
    """
    body = b""
    while len(body) <= MAX_BODY_BYTES:
        chunk = stream.read(MAX_BODY_BYTES + 1 - len(body))
        if not chunk:
            return body
        body += chunk
    return None


def _length_problem(r: Response) -> str | None:
    """The reason the body length contradicts Content-Length, or None when it does not.

    Reading with a size bound means http.client is never asked to enforce
    Content-Length itself, so this comparison is the truncation detector rather
    than a second opinion on one. A truncated body that got as far as the byte
    comparison would be reported as a content difference, which sends the reader
    looking for a deploy fault that was a dropped connection.
    """
    declared = r.header("content-length")
    if declared is None:
        return None
    try:
        want = int(declared)
    except ValueError:
        # Includes the repeated-header case, which header() joins with ", ".
        return f"content-length is {declared!r}, which is not a length"
    if want != len(r.body):
        return f"body is {len(r.body)} bytes, content-length said {want}"
    return None


def fetch(url: str) -> Response:
    """GET url once, without following redirects, and never raise for a network condition.

    Redirects are not followed. The deployment serves every built path
    directly, so a redirect is a fault to report rather than a hop to chase,
    and not following one keeps this check from issuing a request to a location
    the deployment chose. The 3xx comes back as the response, so the status
    check, the cookie scan and the redirect report all see it, and nothing has
    to reason about which response in a chain a header came from.
    """
    # An empty ProxyHandler replaces the default one, which reads http_proxy and
    # https_proxy out of the environment. A proxy or a cache between this check
    # and the edge can serve a stale copy that matches the build, which would
    # certify bytes the public is not being served. Refusing to use a proxy
    # fails closed in a proxied network: the request cannot complete, and an
    # unreachable deployment is already a refusal. Cache-Control asks any
    # intermediary that is there anyway for the origin's answer.
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "cxbom-live-check",
                                              "Cache-Control": "no-cache"})
    try:
        try:
            with opener.open(req, timeout=TIMEOUT_S) as r:
                status, headers, body = r.status, list(r.headers.items()), _read_capped(r)
        except urllib.error.HTTPError as e:
            # A 3xx with redirects disabled, and every 4xx and 5xx, arrive here
            # as an exception carrying a real response. Those are observations,
            # not failures to observe, so they get a status and no problem.
            status, headers, body = e.code, list(e.headers.items()), _read_capped(e)
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
        # URLError covers DNS and connection failures. OSError covers ssl.SSLError,
        # TimeoutError and ConnectionResetError. HTTPException covers IncompleteRead
        # and a malformed status line. ValueError covers an unparseable URL or port.
        # All of them mean the same thing here: no usable response. Reporting that
        # as a problem rather than letting it escape keeps a caller that treats
        # check_live as returning a list from seeing an exception instead.
        return Response(0, [], b"", problem=f"{type(e).__name__}: {e}")
    if body is None:
        return Response(0, [], b"", problem=f"response body exceeds {MAX_BODY_BYTES} bytes")
    resp = Response(status, headers, body)
    problem = _length_problem(resp)
    if problem is not None:
        return Response(0, [], b"", problem=problem)
    return resp


def parse_headers_file(text: str) -> list[tuple[str, list[tuple[str, str]], list[str]]]:
    """Return (pattern, [(name, value)], [detached names]) rules in file order."""
    rules: list[tuple[str, list[tuple[str, str]], list[str]]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            rules.append((line.strip(), [], []))
            continue
        # An indented line before any pattern, or a header line with no colon,
        # is a file this check cannot read. Refusing beats guessing: a rule this
        # parser drops becomes a header it never compares, which is a pass it
        # did not earn.
        if not rules:
            raise LiveCheckError(f"_headers line {lineno}: header line before any path pattern")
        if line.strip().startswith("!"):
            rules[-1][2].append(line.strip()[1:].strip().lower())
        elif ":" in line:
            name, value = line.strip().split(":", 1)
            rules[-1][1].append((name.strip().lower(), value.strip()))
        else:
            raise LiveCheckError(f"_headers line {lineno}: {line.strip()!r} is not 'Name: value'")
    return rules


def _matches(pattern: str, path: str) -> bool:
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def expected_headers(rules, path: str) -> dict[str, str]:
    # Cloudflare Pages applies every matching rule. A repeated header joins with
    # ", ", and "! Name" removes a header that an earlier rule set.
    out: dict[str, str] = {}
    for pattern, headers, detached in rules:
        if not _matches(pattern, path):
            continue
        for name in detached:
            out.pop(name, None)
        for name, value in headers:
            out[name] = f"{out[name]}, {value}" if name in out else value
    return out


def url_paths(dist: Path) -> list[tuple[str, Path]]:
    pairs = []
    for p in sorted(dist.rglob("*")):
        rel = p.relative_to(dist).as_posix()
        if p.is_dir():
            continue
        if not p.is_file():
            # Neither a file nor a directory: a broken symlink, a device node, or
            # an entry this process cannot stat. Path.is_file() answers False for
            # all three, so skipping on a false answer would drop the entry from
            # the comparison silently. The build writes regular files only.
            raise LiveCheckError(f"{rel}: not a regular file; {dist} is not a site build")
        if rel in ("_headers", "404.html"):
            # Pages consumes _headers rather than serving it, and reaches 404.html
            # only through a missing path, which check_live requests by name.
            continue
        if rel == "index.html":
            path = "/"
        elif rel.endswith("/index.html"):
            path = "/" + rel[: -len("index.html")]
        else:
            path = "/" + rel
        pairs.append((path, p))
    return pairs


def check_live(base: str, dist: Path, get: Callable[[str], Response] = fetch) -> list[str]:
    """Compare the deployment at `base` with the build in `dist`. Empty list means every check matched.

    A non-empty list means "not certified", which covers both "the deployment
    differs" and "the deployment could not be read". The two are reported in
    the same channel on purpose: a caller that acts only on a difference would
    treat an unreachable site as a clean one.
    """
    # 404.html is a comparison input as well as a site page: the missing-path
    # request below is held against it. Requiring index.html too would be site-map
    # knowledge this module does not own, and would make the empty-inventory
    # refusal below unreachable, which is the same as not having it.
    if not (dist / "404.html").is_file():
        raise LiveCheckError(f"{dist} has no 404.html; it is not a site build")
    rules = parse_headers_file((dist / "_headers").read_text(encoding="utf-8"))
    errs: list[str] = []

    pairs = url_paths(dist)
    if not pairs:
        errs.append(f"{dist}: holds no served files; it cannot certify a deployment")

    # A site/_headers that declares nothing for a path parses cleanly into no
    # expectation for it, and the header comparison below then expects nothing
    # and is satisfied by a deployment that sends nothing. That is the fail-open
    # shape of this check. Checking the root alone leaves it one path wide: a
    # pattern retyped from /* to /, or a rule that detaches a header without
    # replacing it, keeps the root's expectation whole while every other path's
    # goes vacuous. Every path this run will request is checked instead, and
    # because that reads local files only, it happens before the first request.
    wants = {path: expected_headers(rules, path)
             for path in [p for p, _ in pairs] + list(MISSING_PATHS) + [HEADERS_PATH]}
    for path, want in wants.items():
        for name in CHECKED_HEADERS:
            if name not in want:
                errs.append(f"_headers: declares no {name} for {path}; it cannot certify a deployment")

    def common(path: str, r: Response) -> None:
        if any(k.lower() == "set-cookie" for k, _ in r.headers):
            errs.append(f"{path}: response sets a cookie")
        if b"/cdn-cgi/" in r.body:
            errs.append(f"{path}: body references /cdn-cgi/")
        arrived = {k.lower() for k, _ in r.headers} - PERMITTED_HEADERS - set(wants[path])
        if arrived:
            errs.append(f"{path}: unexpected response headers {sorted(arrived)}")

    def compare_headers(path: str, r: Response) -> None:
        want = wants[path]
        for name in CHECKED_HEADERS:
            got = r.header(name)
            if got != want.get(name):
                errs.append(f"{path}: {name} is {got!r}, expected {want.get(name)!r}")

    def unusable(path: str, r: Response) -> bool:
        """Report and return True when r carries no observation to compare against."""
        if r.problem is not None:
            errs.append(f"{path}: {r.problem}")
            return True
        return False

    def redirects(path: str, r: Response) -> None:
        # Every built path is served directly, so a redirect means something
        # between the build and the reader rewrote the route. The Location is
        # reported as it arrived, not resolved: this check never follows it, so
        # it has no reason to parse a host out of it either.
        where = ", ".join(v for k, v in r.headers if k.lower() == "location")
        if where:
            errs.append(f"{path}: redirects to {where!r}")
        elif r.status in REDIRECT_STATUSES:
            # A redirect status with nowhere to go is still a rewritten route,
            # and the status check alone would not say so.
            errs.append(f"{path}: status {r.status} redirect with no Location header")

    for path, local in pairs:
        r = get(base.rstrip("/") + path)
        if unusable(path, r):
            continue
        common(path, r)
        redirects(path, r)
        if r.status != 200:
            errs.append(f"{path}: status {r.status}")
            continue
        if not r.body:
            # Reported before the byte comparison so an empty 200 reads as what
            # it is rather than as a content difference. No built file is empty,
            # so this never fires on a faithful deployment.
            errs.append(f"{path}: empty response body")
        elif r.body != local.read_bytes():
            errs.append(f"{path}: served bytes differ from the build")
        compare_headers(path, r)
        want = wants[path]
        # Pages adds "Access-Control-Allow-Origin: *" to every static asset, which is
        # harmless for a public, credential-free site. Only require it where _headers asks.
        if "access-control-allow-origin" in want and r.header("access-control-allow-origin") != want["access-control-allow-origin"]:
            errs.append(f"{path}: access-control-allow-origin is {r.header('access-control-allow-origin')!r}, "
                        f"expected {want['access-control-allow-origin']!r}")
        if path.startswith("/schema/") and (r.header("content-type") or "").split(";")[0].strip() != "application/schema+json":
            errs.append(f"{path}: content-type is {r.header('content-type')!r}, expected application/schema+json")

    for path in MISSING_PATHS:
        r = get(base.rstrip("/") + path)
        if unusable(path, r):
            continue
        common(path, r)
        redirects(path, r)
        if r.status != 404:
            errs.append(f"{path}: status {r.status}, expected 404")
            continue
        # Pages answers a missing path with 404.html, so the not-found page is
        # a served body like any other and gets the same byte comparison. Without
        # it, script injected into the one page no build path reaches would be
        # invisible to everything here except the /cdn-cgi/ scan.
        if not r.body:
            errs.append(f"{path}: empty response body")
        elif r.body != (dist / "404.html").read_bytes():
            errs.append(f"{path}: served bytes differ from the build")
        compare_headers(path, r)

    r = get(base.rstrip("/") + HEADERS_PATH)
    if not unusable(HEADERS_PATH, r):
        common(HEADERS_PATH, r)
        redirects(HEADERS_PATH, r)
        if r.status != 404:
            # A 200 here means the deployment is serving the site's own header
            # policy as a document. The body is not compared against 404.html:
            # whether Pages answers a file it consumes with the custom not-found
            # page is not documented, and requiring it would turn this into a
            # gate that fires on a faithful deployment.
            errs.append(f"{HEADERS_PATH}: status {r.status}, expected 404")
    return errs


def _usage(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="site/live_check.py", description=__doc__.splitlines()[0])
    ap.add_argument("base", help="https://cxbom.org, a pages.dev preview URL, or http://127.0.0.1:<port>")
    ap.add_argument("--dist", type=Path, default=ROOT / "site" / "dist")
    args = ap.parse_args(argv)
    try:
        parts = urlsplit(args.base)
        host = parts.hostname
    except ValueError as e:
        return _usage(f"base is not a URL: {e}")
    local = parts.scheme == "http" and host in ("127.0.0.1", "localhost")
    if not (parts.scheme == "https" or local) or parts.path not in ("", "/"):
        return _usage("base must be an https origin or a local http origin, with no path")
    if parts.query or parts.fragment or parts.username or parts.password:
        # Every request below is built by concatenating a path onto base, so a
        # query or fragment here would land in the middle of a URL. Credentials
        # in a base are never right for a public, credential-free site.
        return _usage("base must be a bare origin, with no query, fragment or credentials")
    try:
        if not all((args.dist / n).is_file() for n in ("_headers", "index.html", "404.html")):
            return _usage("--dist does not hold a site build")
        # get=fetch passed rather than left to the default, so the transport is
        # resolved when main runs. The default in check_live's signature is bound
        # at import, which would make the module's one network call unreachable
        # from a test that has no network to offer it.
        errs = check_live(args.base, args.dist, get=fetch)
        checked = len(url_paths(args.dist))
    except LiveCheckError as e:
        return _usage(str(e))
    for e in errs:
        print(f"live-check: {e}", file=sys.stderr)
    if not errs:
        print(f"live-check: {checked} files match the build, {MISSING_PATH} is a faithful 404, "
              f"and {HEADERS_PATH} is not served")
    return 1 if errs else 0
