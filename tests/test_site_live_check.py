"""The live check passes a faithful deployment and catches what Cloudflare can add.

Owner: ATACE Working Group.

A local HTTP server plays the part of Cloudflare Pages: it serves the build and
applies site/_headers the way Pages does. Each fault flag plants one change a
dashboard toggle could make after a deploy.

Every request in this file goes to 127.0.0.1 on an ephemeral port. Nothing here
resolves a name, opens a socket off the loopback interface, or depends on
cxbom.org existing, so the suite is offline and deterministic. Loopback is
enough for more of the failure matrix than it first appears: a refused
connection is a closed port, a timeout is a sleeping handler against a lowered
TIMEOUT_S, and a TLS error is an https:// request to a port speaking plain
HTTP. The two conditions loopback cannot express -- a Response that already
carries `problem`, and a Content-Length that disagrees with a body the
transport did not object to -- go through the `get` seam that check_live
exposes for exactly this.

What this cannot see is recorded in the task report: a real certificate chain,
real DNS, and Cloudflare's own behaviour (whether Pages honours site/_headers
at all, its header casing over HTTP/2, chunked transfer, and the real shape of
a Rocket Loader rewrite).
"""
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import build, live_check  # noqa: E402


@pytest.fixture(scope="module")
def dist(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("live") / "dist"
    build.build(ROOT, out)
    return out


def _serve(dist: Path, faults: set[str]):
    """Start a Pages-shaped server over the build. Returns (base, shutdown)."""
    rules = live_check.parse_headers_file((dist / "_headers").read_text(encoding="utf-8"))

    class Pages(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = self.path
            rel = path.lstrip("/") + ("index.html" if path.endswith("/") else "")
            f = dist / rel
            served = f.is_file() and (rel != "_headers" or "serve-headers" in faults)
            status = 200 if served else 404
            body = f.read_bytes() if status == 200 else (dist / "404.html").read_bytes()
            if "slow" in faults:
                time.sleep(1.0)
            if "inject" in faults and path.endswith("/") and status == 200:
                body = body.replace(b"</body>", b'<script src="/cdn-cgi/scripts/x.js"></script></body>')
            if "inject-404" in faults and status == 404:
                body = body.replace(b"</body>", b"<script>1</script></body>")
            if "missing-200" in faults and status == 404:
                status = 200
            if "500" in faults:
                status, body = 500, b"upstream is unhappy"
            if "big" in faults:
                status, body = 200, b"x" * 4096
            if "empty" in faults:
                status, body = 200, b""
            self.send_response(status)
            headers = live_check.expected_headers(rules, path)
            if path.startswith("/schema/") and "wrong-type" in faults:
                headers["content-type"] = "application/json"
            if "content-type" not in headers:
                headers["content-type"] = "text/html" if rel.endswith(".html") else "application/octet-stream"
            if "no-cors" in faults:
                headers.pop("access-control-allow-origin", None)
            for fault in faults:
                if fault.startswith("drop:"):
                    headers.pop(fault[len("drop:"):], None)
            for k, v in headers.items():
                self.send_header(k, v)
            for fault in faults:
                # add:<Name>=<value> plants a header site/_headers never mentions,
                # which is the shape a Transform Rule or a dashboard toggle takes.
                if fault.startswith("add:"):
                    name, _, value = fault[len("add:"):].partition("=")
                    self.send_header(name, value)
            if "dup-csp" in faults:
                self.send_header("Content-Security-Policy", "default-src 'none'")
            if "cookie" in faults:
                self.send_header("Set-Cookie", "__cf_bm=x; Path=/")
            if "redirect" in faults:
                # Sent last so it rides on whatever status the flags above chose,
                # which is how a route rewrite reaches a response that was a 200.
                status = 301
            if status == 301 and "no-location" not in faults:
                self.send_header("Location", "https://cxbom.org.example/elsewhere/")
            self.send_header("Content-Length", str(len(body) + (1 if "short" in faults else 0)))
            self.end_headers()
            self.wfile.write(body)

        def send_response(self, code, message=None):
            # The redirect flag has to reach the status line too, and the handler
            # above only learns the final status after the header block is chosen.
            super().send_response(301 if "redirect" in faults else code, message)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Pages)
    # shutdown() blocks for one poll interval, and this fixture is torn down once
    # per test, so the default half second is most of the suite's runtime.
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv.shutdown


@pytest.fixture
def server(dist: Path):
    faults: set[str] = set()
    base, shutdown = _serve(dist, faults)
    yield base, faults
    shutdown()


# ---------------------------------------------------------------------------
# The contract: a faithful deployment passes, and each fault a dashboard toggle
# can introduce is caught.

def test_faithful_deployment_passes(server, dist):
    base, _ = server
    assert live_check.check_live(base, dist) == []


def test_cookie_is_caught(server, dist):
    base, faults = server
    faults.add("cookie")
    errs = live_check.check_live(base, dist)
    assert "/: response sets a cookie" in errs
    assert f"{live_check.MISSING_PATH}: response sets a cookie" in errs


def test_injected_script_is_caught(server, dist):
    base, faults = server
    faults.add("inject")
    errs = live_check.check_live(base, dist)
    assert "/: body references /cdn-cgi/" in errs
    assert "/: served bytes differ from the build" in errs


def test_schema_content_type_and_cors_are_checked(server, dist):
    base, faults = server
    faults.update({"wrong-type", "no-cors"})
    errs = live_check.check_live(base, dist)
    assert ("/schema/0.2.0/cxbom.schema.json: content-type is 'application/json', "
            "expected application/schema+json") in errs
    assert ("/schema/0.2.0/cxbom.schema.json: access-control-allow-origin is None, expected '*'") in errs


def test_expected_headers_follow_pages_rules():
    rules = live_check.parse_headers_file((ROOT / "site/_headers").read_text(encoding="utf-8"))
    viewer = live_check.expected_headers(rules, "/viewer/")
    assert "'unsafe-inline'" in viewer["content-security-policy"]
    assert "," not in viewer["content-security-policy"]
    spec = live_check.expected_headers(rules, "/spec/")
    assert spec["content-security-policy"].startswith("default-src 'self'; base-uri 'none'")
    assert "access-control-allow-origin" not in spec
    schema = live_check.expected_headers(rules, "/schema/0.2.0/cxbom.schema.json")
    assert schema["content-type"] == "application/schema+json" and schema["access-control-allow-origin"] == "*"


def test_two_rules_setting_one_header_join_the_way_pages_joins_them(dist, tmp_path):
    # The detach half of the merge model is pinned twice over, by the viewer CSP at
    # the unit level and by a miss under /viewer/ end to end. The join half was
    # pinned nowhere, because no path in today's site/_headers has two rules
    # setting the same header. The expected value here is written out rather than
    # taken from the code, so the model is the thing under test.
    out = _copy(dist, tmp_path)
    text = (out / "_headers").read_text(encoding="utf-8")
    (out / "_headers").write_text(text + "\n/spec/*\n  Referrer-Policy: same-origin\n", encoding="utf-8")
    rules = live_check.parse_headers_file((out / "_headers").read_text(encoding="utf-8"))
    assert live_check.expected_headers(rules, "/spec/")["referrer-policy"] == "no-referrer, same-origin"
    assert live_check.expected_headers(rules, "/")["referrer-policy"] == "no-referrer"


def test_cli_refuses_a_plain_http_remote_origin(dist):
    assert live_check.main(["http://cxbom.org", "--dist", str(dist)]) == 2
    assert live_check.main(["https://cxbom.org/spec/", "--dist", str(dist)]) == 2


# ---------------------------------------------------------------------------
# No failure to reach the deployment reads as a pass.
#
# Each test below plants one way the check can fail to observe the site and
# requires a non-empty result. The `== []` assertion in
# test_faithful_deployment_passes is the only place an empty list is correct,
# so every test here is written as "not empty, and it says why".

def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_a_refused_connection_is_a_refusal_not_a_pass(dist):
    base = f"http://127.0.0.1:{_closed_port()}"
    errs = live_check.check_live(base, dist)
    assert errs, "an unreachable deployment must never certify"
    assert any("/: URLError" in e for e in errs), errs
    assert f"{live_check.MISSING_PATH}: URLError" in "\n".join(errs)


def test_a_refused_connection_leaves_the_cli_nonzero(dist):
    assert live_check.main([f"http://127.0.0.1:{_closed_port()}", "--dist", str(dist)]) == 1


def test_the_request_timeout_is_finite():
    # The timeout test below monkeypatches TIMEOUT_S, so nothing else pins the
    # value the check ships with. None means urllib blocks until the socket gives
    # up, which hangs the deploy rather than refusing it. That is a liveness
    # failure rather than a fail-open, and it is one assertion to close.
    assert isinstance(live_check.TIMEOUT_S, (int, float)) and not isinstance(live_check.TIMEOUT_S, bool)
    assert 0 < live_check.TIMEOUT_S <= 60


def test_a_timeout_is_a_refusal_not_a_pass(dist, monkeypatch):
    monkeypatch.setattr(live_check, "TIMEOUT_S", 0.2)
    faults = {"slow"}
    base, shutdown = _serve(dist, faults)
    try:
        r = live_check.fetch(base + "/")
    finally:
        shutdown()
    assert r.problem is not None, "a timeout must carry a reason, not an empty body"
    assert r.status == 0 and r.body == b""
    assert "TimeoutError" in r.problem
    assert f"/: {r.problem}" in live_check.check_live(base, dist, get=lambda url: r)


def test_a_tls_error_is_a_refusal_not_a_pass(server, dist):
    # The server speaks plain HTTP, so an https:// request to it fails inside the
    # handshake. That is the same code path a real certificate problem takes.
    base, _ = server
    https = "https://" + base.removeprefix("http://")
    r = live_check.fetch(https + "/")
    assert r.problem is not None and r.status == 0, r
    errs = live_check.check_live(https, dist)
    assert errs and all(":" in e for e in errs)
    assert not any("served bytes differ" in e for e in errs), "a handshake failure is not a content difference"


def test_a_5xx_is_a_refusal(server, dist):
    base, faults = server
    faults.add("500")
    errs = live_check.check_live(base, dist)
    assert "/: status 500" in errs
    assert f"{live_check.MISSING_PATH}: status 500, expected 404" in errs
    assert not any("served bytes differ" in e for e in errs), "a 5xx body is not compared"


def test_a_304_is_a_refusal_named_as_its_status(dist):
    # Nothing here sends If-None-Match or If-Modified-Since, so a 304 is a server
    # fault rather than an answer, and a status the check treats as served would
    # take the empty body that comes with it as the deployment's content.
    r = live_check.Response(304, [], b"")
    errs = live_check.check_live("https://cxbom.org", dist, get=lambda url: r)
    assert "/: status 304" in errs, errs
    assert f"{live_check.MISSING_PATH}: status 304, expected 404" in errs


def test_a_redirect_is_a_refusal_and_is_not_followed(server, dist):
    base, faults = server
    faults.add("redirect")
    errs = live_check.check_live(base, dist)
    assert "/: redirects to 'https://cxbom.org.example/elsewhere/'" in errs
    assert "/: status 301" in errs
    assert f"{live_check.MISSING_PATH}: redirects to 'https://cxbom.org.example/elsewhere/'" in errs
    # Not followed: fetch hands back the 3xx itself, so nothing from the
    # redirect target can be mistaken for the deployment's own response, and
    # this check issues no request to a location the deployment chose.
    r = live_check.fetch(base + "/")
    assert r.status == 301 and r.problem is None
    assert r.header("location") == "https://cxbom.org.example/elsewhere/"


def test_a_redirect_with_no_location_is_still_named_a_redirect(server, dist):
    base, faults = server
    faults.update({"redirect", "no-location"})
    errs = live_check.check_live(base, dist)
    assert "/: status 301 redirect with no Location header" in errs


def test_a_cookie_on_a_redirect_is_caught(server, dist):
    base, faults = server
    faults.update({"redirect", "cookie"})
    errs = live_check.check_live(base, dist)
    assert "/: response sets a cookie" in errs


def test_an_empty_200_is_a_refusal(server, dist):
    base, faults = server
    faults.add("empty")
    errs = live_check.check_live(base, dist)
    assert "/: empty response body" in errs
    # Named as what it is. An empty body reported only as a content difference
    # sends the reader looking for a deploy fault instead of a dropped response.
    assert "/: served bytes differ from the build" not in errs


def test_a_truncated_transfer_is_a_refusal(server, dist):
    # The server declares one byte more than it writes. urllib is asked for a
    # bounded read, so it never enforces Content-Length itself and hands the
    # short body back without complaint: _length_problem is the only thing
    # between a dropped transfer and a "served bytes differ" verdict.
    base, faults = server
    faults.add("short")
    local = (dist / "index.html").stat().st_size
    errs = live_check.check_live(base, dist)
    assert f"/: body is {local} bytes, content-length said {local + 1}" in errs, errs
    assert not any("served bytes differ" in e for e in errs), "a truncated body is not a content difference"


def test_a_body_whose_length_contradicts_content_length_is_a_refusal(dist):
    short = live_check.Response(200, [("Content-Length", "99")], b"abc")
    assert live_check._length_problem(short) == "body is 3 bytes, content-length said 99"
    bad = live_check.Response(200, [("Content-Length", "12"), ("Content-Length", "12")], b"x" * 12)
    assert live_check._length_problem(bad) == "content-length is '12, 12', which is not a length"
    ok = live_check.Response(200, [("Content-Length", "3")], b"abc")
    assert live_check._length_problem(ok) is None


def test_a_body_over_the_cap_is_a_refusal(dist, monkeypatch):
    monkeypatch.setattr(live_check, "MAX_BODY_BYTES", 1024)
    faults = {"big"}
    base, shutdown = _serve(dist, faults)
    try:
        r = live_check.fetch(base + "/")
    finally:
        shutdown()
    assert r.problem == "response body exceeds 1024 bytes"
    assert r.status == 0 and r.body == b""


def test_a_problem_response_is_reported_before_anything_is_compared(dist):
    # The single predicate the whole fail-closed design rests on: a Response
    # carrying `problem` must produce exactly one entry naming the reason, and
    # must not be mined for a status, a header or a body comparison.
    r = live_check.Response(0, [], b"", problem="SSLCertVerificationError: hostname mismatch")
    errs = live_check.check_live("https://example.invalid", dist, get=lambda url: r)
    assert errs
    probed = [p for p, _ in live_check.url_paths(dist)] + list(live_check.MISSING_PATHS) + [
        live_check.HEADERS_PATH]
    assert set(errs) == {f"{p}: SSLCertVerificationError: hostname mismatch" for p in probed}


# ---------------------------------------------------------------------------
# The not-found page is a served body like any other.

def test_a_missing_path_answering_200_is_a_refusal(server, dist):
    base, faults = server
    faults.add("missing-200")
    errs = live_check.check_live(base, dist)
    assert f"{live_check.MISSING_PATH}: status 200, expected 404" in errs


def test_script_injected_into_the_404_page_is_caught(server, dist):
    base, faults = server
    faults.add("inject-404")
    errs = live_check.check_live(base, dist)
    assert f"{live_check.MISSING_PATH}: served bytes differ from the build" in errs


def test_the_404_page_is_held_to_the_declared_headers(server, dist):
    base, faults = server
    faults.add("drop:referrer-policy")
    errs = live_check.check_live(base, dist)
    assert f"{live_check.MISSING_PATH}: referrer-policy is None, expected 'no-referrer'" in errs


def test_a_miss_under_the_viewer_is_held_to_the_detached_policy(server, dist):
    # The viewer block is the only rule that detaches a header and sets another in
    # its place, and a miss under it is the one path where the value that semantics
    # produces is compared against a live response rather than only against
    # expected_headers. The declared value is read out of the file line by line.
    base, faults = server
    faults.add("drop:content-security-policy")
    errs = live_check.check_live(base, dist)
    declared = _declared_in_block(dist, "/viewer/*", "content-security-policy")
    assert "'unsafe-inline'" in declared and "," not in declared
    assert (f"/viewer{live_check.MISSING_PATH}: content-security-policy is None, "
            f"expected {declared!r}") in errs, errs


def test_the_headers_file_itself_must_not_be_served(server, dist):
    # _headers is the one file in the build no served path reaches, so without this
    # probe a deployment publishing the site's own header policy would certify.
    base, faults = server
    faults.add("serve-headers")
    errs = live_check.check_live(base, dist)
    assert f"{live_check.HEADERS_PATH}: status 200, expected 404" in errs, errs


# ---------------------------------------------------------------------------
# The header comparison discriminates.
#
# The faithful case cannot show this on its own: the fixture builds its response
# from expected_headers, the same function the check compares against, so a
# comparison that always agreed would still pass it. These drop one declared
# header at a time and require the check to name it.

def _declared_under_star(dist: Path, name: str) -> str:
    """The value site/_headers gives `name` in its /* block, read line by line.

    Deliberately not parse_headers_file: this is the independent reading the
    header tests compare the check's verdict against. The /* block is the first
    rule in the file and no later rule sets any of CHECKED_HEADERS except the
    viewer's Content-Security-Policy, which is detached first, so the first
    match in file order is the value that applies to /.
    """
    for line in (dist / "_headers").read_text(encoding="utf-8").splitlines():
        if line[:1].isspace() and line.strip().lower().startswith(name + ":"):
            return line.strip().split(":", 1)[1].strip()
    raise AssertionError(f"_headers declares no {name}")


def _declared_in_block(dist: Path, pattern: str, name: str) -> str:
    """The value site/_headers gives `name` inside its `pattern` block, read line by line.

    The companion to _declared_under_star for a block that is not the first one.
    Same reason for existing: neither reader calls parse_headers_file or
    expected_headers, so a verdict compared against one of them is compared
    against a second reading of the file rather than against itself. A "! Name"
    line does not match, so a detached-then-set header returns the value that is
    set.
    """
    inside = False
    for line in (dist / "_headers").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            inside = line.strip() == pattern
        elif inside and line.strip().lower().startswith(name + ":"):
            return line.strip().split(":", 1)[1].strip()
    raise AssertionError(f"_headers block {pattern} declares no {name}")


def test_headers_declares_every_checked_header_under_the_all_paths_pattern():
    """site/_headers must declare the checked headers under /*, the one pattern that matches every path.

    The live check cannot certify a path site/_headers says nothing about, and the
    fail-open shape it guards against is reachable by a one-character edit:
    retyping /* as / leaves the root declared and every other path bare. That edit
    changes no built byte and breaks no build assertion, so without this the
    repository suite stays green on it. site/_headers belongs to the build task,
    so the assertion lives here, next to the check whose certification rests on it.
    """
    pattern = ""
    covered: dict[str, str] = {}
    for line in (ROOT / "site/_headers").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            pattern = line.strip()
        elif ":" in line and not line.strip().startswith("!"):
            covered.setdefault(line.strip().split(":", 1)[0].strip().lower(), pattern)
    for name in live_check.CHECKED_HEADERS:
        assert covered.get(name) == "/*", f"_headers must declare {name} under /*, not {covered.get(name)!r}"


def test_an_unexpected_response_header_name_is_refused(server, dist):
    # The channel no pre-deploy scan can reach: a header arriving that site/_headers
    # never mentions. Link with a preconnect target is the shape a Cloudflare
    # Transform Rule takes, and it carries a host that the build never wrote.
    base, faults = server
    faults.add("add:Link=<https://cdn.example.test/>; rel=preconnect")
    errs = live_check.check_live(base, dist)
    assert "/: unexpected response headers ['link']" in errs, errs
    assert f"{live_check.MISSING_PATH}: unexpected response headers ['link']" in errs
    assert f"{live_check.HEADERS_PATH}: unexpected response headers ['link']" in errs


def test_a_header_site_headers_declares_for_itself_is_not_unexpected(dist, tmp_path):
    # The allowlist is documented names, so it cannot know what the site chooses to
    # declare. A rule added to site/_headers is an expectation in its own right,
    # which is what keeps this scan from firing on a deliberate addition.
    out = _copy(dist, tmp_path)
    text = (out / "_headers").read_text(encoding="utf-8")
    (out / "_headers").write_text(text + "\n/spec/*\n  X-Robots-Tag: noindex\n", encoding="utf-8")
    assert "x-robots-tag" not in live_check.PERMITTED_HEADERS
    base, shutdown = _serve(out, set())
    try:
        errs = live_check.check_live(base, out)
    finally:
        shutdown()
    assert errs == [], errs


def test_fetch_ignores_environment_proxies_and_asks_for_the_origin_copy(server):
    # A proxy or a cache between this check and the edge can answer with a stale
    # copy that matches the build, which would certify bytes the public is not
    # being served. The default ProxyHandler reads http_proxy out of the
    # environment, so it is replaced rather than inherited.
    base, _ = server
    handlers: list[object] = []
    requests: list[urllib.request.Request] = []
    real_opener, real_request = urllib.request.build_opener, urllib.request.Request

    def build_opener(*hs):
        handlers.extend(hs)
        return real_opener(*hs)

    def Request(url, **kw):
        req = real_request(url, **kw)
        requests.append(req)
        return req

    monkeypatched = pytest.MonkeyPatch()
    monkeypatched.setattr(live_check.urllib.request, "build_opener", build_opener)
    monkeypatched.setattr(live_check.urllib.request, "Request", Request)
    try:
        r = live_check.fetch(base + "/")
    finally:
        monkeypatched.undo()
    assert r.status == 200 and r.problem is None
    proxies = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert proxies, handlers
    assert all(h.proxies == {} for h in proxies), proxies
    assert requests[0].get_header("Cache-control") == "no-cache", requests[0].headers


def test_the_names_cloudflare_documents_are_not_refused(server, dist):
    # The other half of the allowlist's job. A set tight enough to fire on
    # Cloudflare's own headers is a gate that gets switched off after one run, so
    # the documented names must pass on a deployment that is otherwise faithful.
    base, faults = server
    for name in ("CF-Ray", "CF-Cache-Status", "NEL", "Report-To", "Alt-Svc", "Age", "Vary"):
        faults.add(f"add:{name}=x")
    errs = live_check.check_live(base, dist)
    assert not any("unexpected response headers" in e for e in errs), errs


@pytest.mark.parametrize("name", live_check.CHECKED_HEADERS)
def test_dropping_any_checked_header_is_caught(server, dist, name):
    base, faults = server
    faults.add(f"drop:{name}")
    errs = live_check.check_live(base, dist)
    # The declared value is lifted straight out of the file's /* block with a
    # one-line read, not through parse_headers_file and expected_headers. Taking
    # it from those would assert the check against the expression that produced
    # its own verdict, which is no assertion at all.
    declared = _declared_under_star(dist, name)
    assert f"/: {name} is None, expected {declared!r}" in errs, errs


def test_a_second_copy_of_a_declared_header_is_caught(server, dist):
    # Two Content-Security-Policy headers are two policies a browser intersects,
    # and the weaker one is not what site/_headers declares.
    base, faults = server
    faults.add("dup-csp")
    errs = live_check.check_live(base, dist)
    assert any("content-security-policy is" in e and "default-src 'none'" in e for e in errs), errs


# ---------------------------------------------------------------------------
# A build directory or a site/_headers that cannot certify anything.

def _copy(dist: Path, tmp_path: Path) -> Path:
    out = tmp_path / "dist"
    shutil.copytree(dist, out)
    return out


def test_a_build_with_no_served_files_cannot_certify(dist, tmp_path, server):
    base, _ = server
    out = _copy(dist, tmp_path)
    for path, p in live_check.url_paths(out):
        p.unlink()
    errs = live_check.check_live(base, out)
    assert any("holds no served files" in e for e in errs), errs


def test_a_headers_file_that_declares_nothing_cannot_certify(dist, tmp_path, server):
    base, _ = server
    out = _copy(dist, tmp_path)
    (out / "_headers").write_text("# nothing declared\n", encoding="utf-8")
    errs = live_check.check_live(base, out)
    for name in live_check.CHECKED_HEADERS:
        assert f"_headers: declares no {name} for /; it cannot certify a deployment" in errs
    # The server was started over the pristine build, so it still serves the real
    # policy while this copy of _headers expects nothing. The comparison therefore
    # has a value on one side and nothing on the other, and it has to say so rather
    # than take what arrived as the expectation.
    declared = _declared_under_star(dist, "referrer-policy")
    assert f"/: referrer-policy is {declared!r}, expected None" in errs, errs


def test_a_pattern_that_stops_matching_a_subtree_cannot_certify(dist, tmp_path, server):
    # The one-character edit: /* retyped /. Every served path but the root then
    # expects no header at all, and a comparison against nothing is satisfied by a
    # deployment that sends nothing. A guard that covers the root only calls this a
    # pass while 17 paths and the not-found page carry none of the five.
    base, _ = server
    out = _copy(dist, tmp_path)
    lines = (out / "_headers").read_text(encoding="utf-8").splitlines(keepends=True)
    lines[lines.index("/*\n")] = "/\n"
    (out / "_headers").write_text("".join(lines), encoding="utf-8")
    errs = live_check.check_live(base, out)
    for name in live_check.CHECKED_HEADERS:
        assert f"_headers: declares no {name} for /spec/; it cannot certify a deployment" in errs
        assert (f"_headers: declares no {name} for {live_check.MISSING_PATH}; "
                "it cannot certify a deployment") in errs
    assert f"_headers: declares no referrer-policy for {live_check.HEADERS_PATH}; " \
           "it cannot certify a deployment" in errs


def test_a_detached_header_with_no_replacement_cannot_certify(dist, tmp_path, server):
    # The authoring slip the /viewer/* block is one line away from: detach a header
    # and forget to set it again. The subtree then expects nothing, which the root
    # guard cannot see because the root still expects everything.
    base, _ = server
    out = _copy(dist, tmp_path)
    text = (out / "_headers").read_text(encoding="utf-8")
    (out / "_headers").write_text(text + "\n/spec/*\n  ! Content-Security-Policy\n", encoding="utf-8")
    errs = live_check.check_live(base, out)
    assert ("_headers: declares no content-security-policy for /spec/; "
            "it cannot certify a deployment") in errs, errs


@pytest.mark.parametrize("text,fragment", [
    ("  Referrer-Policy: no-referrer\n", "header line before any path pattern"),
    ("/*\n  Referrer-Policy\n", "is not 'Name: value'"),
])
def test_an_unreadable_headers_file_is_refused_not_guessed(dist, tmp_path, text, fragment):
    out = _copy(dist, tmp_path)
    (out / "_headers").write_text(text, encoding="utf-8")
    with pytest.raises(live_check.LiveCheckError) as e:
        live_check.check_live("https://cxbom.org", out, get=_unreachable)
    assert fragment in str(e.value)


def test_a_dist_missing_its_pages_is_refused(dist, tmp_path):
    out = _copy(dist, tmp_path)
    (out / "404.html").unlink()
    with pytest.raises(live_check.LiveCheckError):
        live_check.check_live("https://cxbom.org", out, get=_unreachable)


def test_an_entry_that_is_not_a_regular_file_is_refused_not_skipped(dist, tmp_path):
    out = _copy(dist, tmp_path)
    (out / "assets" / "dangling").symlink_to(out / "assets" / "gone.css")
    with pytest.raises(live_check.LiveCheckError) as e:
        live_check.url_paths(out)
    assert "not a regular file" in str(e.value)


class _Stop(Exception):
    """Raised by an injected transport to prove a request was built, and stop there."""


def _unreachable(url: str) -> live_check.Response:
    raise AssertionError(f"no request may be made before the build is validated: {url}")


def test_url_paths_excludes_what_pages_does_not_serve(dist):
    paths = dict(live_check.url_paths(dist))
    assert "/" in paths and paths["/"].name == "index.html"
    assert "/_headers" not in paths and "/404.html" not in paths
    assert "/spec/" in paths and "/schema/0.2.0/cxbom.schema.json" in paths
    assert all(p.startswith("/") for p in paths)


def test_url_paths_covers_every_file_the_build_writes(dist):
    # The byte comparison is a total check on the deployment only while the
    # inventory is total. This is what makes "the pre-deploy anonymity scan and
    # this check cover the same bytes" a property of the code rather than a fact
    # about today's build: url_paths narrowed to skip a directory would drop those
    # files from every comparison, and the assertion above would not notice
    # because it names three paths and derives the rest from url_paths itself.
    served = {p.relative_to(dist).as_posix() for _u, p in live_check.url_paths(dist)}
    every = {p.relative_to(dist).as_posix() for p in dist.rglob("*") if p.is_file()}
    assert {"_headers", "404.html"} <= every, every
    assert served == every - {"_headers", "404.html"}
    # Both exclusions are fetched by name instead, so no file in the build goes
    # unrequested: 404.html through a missing path, _headers as a required miss.
    assert live_check.MISSING_PATHS and live_check.HEADERS_PATH == "/_headers"


# ---------------------------------------------------------------------------
# The command line.

def test_cli_passes_a_faithful_deployment(server, dist, capsys):
    base, _ = server
    assert live_check.main([base, "--dist", str(dist)]) == 0
    out = capsys.readouterr().out
    assert f"{len(live_check.url_paths(dist))} files match the build" in out
    assert live_check.MISSING_PATH in out


def test_cli_reports_each_difference_and_exits_one(server, dist, capsys):
    base, faults = server
    faults.add("cookie")
    assert live_check.main([base, "--dist", str(dist)]) == 1
    err = capsys.readouterr().err
    assert "live-check: /: response sets a cookie" in err


@pytest.mark.parametrize("base", [
    "http://cxbom.org",                     # plain http to a remote origin
    "https://cxbom.org/spec/",              # a path, not an origin
    "https://cxbom.org?preview=1",          # a query would land mid-URL
    "https://cxbom.org#top",                # so would a fragment
    "https://user:pw@cxbom.org",            # credentials on a credential-free site
    "ftp://cxbom.org",                      # a scheme this check cannot speak
    "cxbom.org",                            # no scheme at all
])
def test_cli_refuses_a_base_that_is_not_a_bare_secure_origin(dist, base):
    assert live_check.main([base, "--dist", str(dist)]) == 2


def test_cli_accepts_a_local_http_origin_and_an_https_origin(dist, monkeypatch):
    # The transport is replaced before main runs, so "https://cxbom.org" here
    # gets no further than the first call. Nothing in this suite reaches a name
    # that has to be resolved.
    seen: list[str] = []

    def get(url):
        seen.append(url)
        raise _Stop

    monkeypatch.setattr(live_check, "fetch", get)
    # The trailing-slash forms are the most likely operator typo, and main accepts
    # them. Each request is built by concatenating a path onto base, so a base that
    # keeps its slash would send every request to a doubled //path.
    for base in ("http://127.0.0.1:8788", "http://localhost:8788", "https://cxbom.org",
                 "https://cxbom.org/", "http://127.0.0.1:8788/"):
        seen.clear()
        with pytest.raises(_Stop):
            live_check.main([base, "--dist", str(dist)])
        assert seen, f"{base} was refused before any request was built"
        assert all(urlsplit(u).netloc == urlsplit(base).netloc for u in seen), seen
        assert all(urlsplit(u).path.startswith("/") for u in seen), seen
        assert not any(urlsplit(u).path.startswith("//") for u in seen), seen


def test_the_documented_invocation_runs(server, dist):
    # site/live_check.py is the entry point the deploy runbook names, and it is
    # the only place the sys.path insertion that makes `cxsite` importable is
    # exercised. Importing cxsite.live_check.main directly, as every test above
    # does, would leave a broken wrapper green.
    # Run under PYTHONSAFEPATH, which stops Python adding the script's own
    # directory to sys.path. Without it the wrapper's sys.path insertion is
    # redundant and a test cannot tell whether it works, which was true of the
    # first version of this test.
    base, _ = server
    p = subprocess.run([sys.executable, "site/live_check.py", base, "--dist", str(dist)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120,
                       env={**os.environ, "PYTHONSAFEPATH": "1"})
    assert p.returncode == 0, p.stderr
    assert "files match the build" in p.stdout


def test_cli_refuses_a_dist_that_is_not_a_build(tmp_path):
    (tmp_path / "_headers").write_text("/*\n  Referrer-Policy: no-referrer\n", encoding="utf-8")
    assert live_check.main(["https://cxbom.org", "--dist", str(tmp_path)]) == 2


def test_cli_refuses_a_dist_with_both_pages_but_no_index(tmp_path, monkeypatch):
    # The only thing main's precheck uniquely requires is index.html, and a
    # directory holding the two pages without it reaches check_live's guards and
    # would come back as exit 1, a difference, rather than exit 2, a bad argument.
    # The transport is replaced so a missing precheck cannot reach the network.
    monkeypatch.setattr(live_check, "fetch", _unreachable)
    (tmp_path / "_headers").write_text("/*\n  Referrer-Policy: no-referrer\n", encoding="utf-8")
    (tmp_path / "404.html").write_text("<!doctype html><title>not found</title>\n", encoding="utf-8")
    assert live_check.main(["https://cxbom.org", "--dist", str(tmp_path)]) == 2


def test_cli_turns_an_unreadable_headers_file_into_a_usage_error(dist, tmp_path):
    out = _copy(dist, tmp_path)
    (out / "_headers").write_text("  Referrer-Policy: no-referrer\n", encoding="utf-8")
    assert live_check.main(["https://cxbom.org", "--dist", str(out)]) == 2
