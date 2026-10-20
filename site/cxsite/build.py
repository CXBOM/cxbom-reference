"""Build cxbom.org into a directory, then run every publication gate.

Owner: ATACE Working Group.

Usage (from the repository root):
    python site/build.py                 # build site/dist and run the gates
    python site/build.py --out DIR       # build somewhere else
    python site/build.py --lock          # add new schema versions to spec/published.lock.json
Exit 0 when every gate passes, 1 on any gate error, 2 on a refused build.

A gate error is a finding to fix at its source, never by editing a gate.

The build is deterministic: the same sources give the same bytes, with no
timestamps. Every file goes into a fresh scratch directory beside the target,
and that directory is renamed into place only after the last file is written,
so the served directory holds either the previous build or the complete new
one, never a partial tree.

What a killed build can leave behind is the scratch directory. Every exit path
inside the process removes it, KeyboardInterrupt and SystemExit included; a
SIGKILL runs no cleanup at all, so each build first reaps the `.dist-*`
siblings an earlier killed run left beside the target. `lock_new_schemas`
installs `spec/published.lock.json` the same way, through a temp sibling and a
rename, so a killed lock run leaves that committed file either untouched or
fully replaced, never truncated.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import html
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from . import SITE_ORIGIN, gates, reference, render, scope, strip

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
EXAMPLES = (
    ("cxbom_example_clean_baseline.json", "Clean baseline session"),
    ("cxbom_example_finance_assistant.json", "Finance assistant session with an open finding"),
    ("cxbom_example_multiturn_ring1derived.json", "Multi-turn session with ring-1-derived content"),
)
FONT_FILES = (
    "source-serif-4-latin-400-normal.woff2", "source-serif-4-latin-400-italic.woff2",
    "source-serif-4-latin-600-normal.woff2", "source-code-pro-latin-400-normal.woff2",
    "source-code-pro-latin-600-normal.woff2", "OFL.txt",
)
REFERENCE_SCHEMA = "cxbom-0.3.0.schema.json"
_SCHEMA_NAME = re.compile(r"^cxbom-(\d+\.\d+\.\d+)\.schema\.json$")
# Suffix on every temp file _atomic_write_text creates. .gitignore matches it as
# spec/published.lock.json.*.tmp so a killed run's leftover never gets committed.
_TMP_SUFFIX = ".tmp"


class BuildError(Exception):
    """The build refused to run or could not finish."""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(out: Path, rel: str, data: str | bytes) -> str:
    target = out / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    target.write_bytes(data)
    return rel


def _atomic_write_text(path: Path, text: str) -> None:
    """Install text at path: write a temp sibling, fsync it, then rename over path.

    The same pattern as cxbom.signing._atomic_write, written out again here
    rather than imported so the site build keeps its stdlib-only dependency set
    (the cxbom package pulls in cryptography for its own reasons).

    The temp file is a sibling of the target because os.replace is atomic only
    within one filesystem. The fsync is what extends the guarantee past a killed
    process to a host that loses power: a filesystem is free to commit the
    rename before the data blocks behind it, which would leave the target
    correctly named and truncated. published.lock.json is committed state that
    every later build reads unconditionally, so one fsync per lock run is the
    cheap side of that trade.
    """
    data = text.encode("utf-8")
    # mkstemp creates its file 0600; carry the target's own mode across so an
    # atomic install never silently narrows a committed file's permissions.
    keep_mode = path.stat().st_mode & 0o777 if path.exists() else None
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=_TMP_SUFFIX)
    try:
        try:
            if keep_mode is not None:
                os.fchmod(fd, keep_mode)
            n = os.write(fd, data)
            if n != len(data):
                # Renaming a short write into place would replace a good file
                # with a truncated one, the exact failure this helper prevents.
                raise OSError(errno.EIO, f"short write ({n} of {len(data)} bytes)")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        # BaseException, not Exception: a KeyboardInterrupt here must not leave
        # the temp sibling behind either.
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise


def _reap_temp_siblings(path: Path) -> None:
    """Remove temp files a killed earlier _atomic_write_text left beside path.

    Only a SIGKILL can leave one: every exit path inside the process removes its
    own temp file. Reaping keeps the committed spec/ directory from collecting
    one stray file per interrupted run. Two lock runs at once are not supported
    -- they would already race over whose lock wins -- so a reap that cannot
    tell a live temp file from an orphan costs nothing.
    """
    for p in sorted(path.parent.glob(f"{path.name}.*{_TMP_SUFFIX}")):
        p.unlink(missing_ok=True)


def _reap_scratch_dirs(out: Path) -> None:
    """Remove `.dist-*` scratch directories a killed earlier build left beside out.

    A build stopped by something Python never sees as an exception (SIGKILL, an
    OOM kill, a pulled plug) runs no cleanup, so its scratch tree survives.
    Reaping before the next build starts is the only place that collects it.
    Directories only, because a directory is the only thing this module ever
    creates under that name. Concurrent builds into the same output directory
    are not supported -- they would already race on the swap at the end of
    build() -- so a reap that cannot tell a live sibling from an orphan costs
    nothing.
    """
    for p in sorted(out.parent.glob(".dist-*")):
        # A caller is free to name the output directory .dist-anything.
        if p != out and p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)


def _film_html() -> str:
    """The homepage film, injected because the markdown renderer refuses raw HTML.

    Captions are burned into the picture. Sound stays off until the viewer unmutes.
    No autoplay, so a reduced-motion preference has nothing to stop.
    """
    return (
        '<figure class="film">'
        '<video controls muted playsinline preload="metadata" poster="/video/keeper-poster.jpg">'
        '<source src="/video/keeper.mp4" type="video/mp4">'
        '<track kind="captions" src="/video/keeper.vtt" srclang="en" label="English" default>'
        "</video>"
        "<figcaption>On this recording, for three attacks, a notes tool description that changed after "
        "it was signed sent the secret when the gate was off and the inbox showed that it arrived, and "
        "when the gate was on that tool was dropped from the listing, the secret did not arrive, and the "
        "model kept calling fetch until it hit its limit, and only on the third attack was that definition "
        "clean on the first listing and changed on a re-listing within the session.</figcaption>"
        "</figure>"
    )


def load_lock(root: Path) -> dict:
    return json.loads(_read(root / "spec" / "published.lock.json"))


def _examples_body(root: Path) -> str:
    parts = ['<h1 id="examples">Example records</h1>',
             "<p>Three hand-authored, illustrative records. Each one validates against the "
             '<a href="/schema/0.3.0/cxbom.schema.json">0.3.0 schema</a>. Open a downloaded file in the '
             '<a href="/viewer/">viewer</a> with its load button.</p>']
    for name, title in EXAMPLES:
        doc = json.loads(_read(root / "spec" / name))
        s = doc["sessionSummary"]
        facts = (f"{len(doc['contextComponents'])} components, {s['totalContextTokens']:,} component tokens, "
                 f"{s['templateOverheadTokens']:,} template overhead tokens, "
                 f"{s['findingsSummary']['totalOpen']} open finding{'' if s['findingsSummary']['totalOpen'] == 1 else 's'}. "
                 f"Session audit clean: {'yes' if s['sessionAuditClean'] else 'no'}.")
        parts.append(f'<h2 id="{render.slug(title)}">{html.escape(title)}</h2>')
        parts.append(f"<p>{html.escape(facts)}</p>")
        parts.append(f'<p><a href="/examples/{name}">{html.escape(name)}</a></p>')
    return "\n".join(parts)


def build(root: Path, out: Path) -> list[str]:
    """Build the site from `root` into `out`. Returns the written paths, relative to `out`."""
    if out.exists() and not ((out / "index.html").is_file() and (out / "_headers").is_file()):
        # The basename, not the path. main() prints this refusal, and an output
        # directory outside the repository would put an absolute filesystem path
        # into the build log.
        raise BuildError(f"the output directory {out.name!r} exists and is not a previous "
                         f"site build. Refusing to replace it.")
    lock = load_lock(root)
    record = json.loads(_read(root / "site" / "data" / "session_reference.json"))
    template = _read(root / "site" / "templates" / "page.html")
    strip_html = strip.strip_svg(record, "strip")
    note_html = strip.strip_note(record)

    out.parent.mkdir(parents=True, exist_ok=True)
    _reap_scratch_dirs(out)
    tmp = Path(tempfile.mkdtemp(prefix=".dist-", dir=out.parent))
    written: list[str] = []
    try:
        def page(rel: str, p: render.Page) -> None:
            written.append(_write(tmp, rel, render.render_page(template, p, strip_html, note_html)))

        landing = render.md_to_html(_read(root / "site" / "content" / "landing.md"))
        landing = landing.replace("</h1>", "</h1>\n" + _film_html(), 1) + strip.ledger_table(record)
        page("index.html", render.Page("/", "Context Bill of Materials", landing))
        page("spec/index.html", render.Page("/spec/", "Specification", render.md_to_html(_read(root / "spec" / "SPEC.md")), numbered=True))
        tool_md = _read(root / "docs" / "design" / "tool.md")
        page("scope/index.html", render.Page("/scope/", "Scope and threat model", render.md_to_html(scope.scope_markdown(tool_md))))
        page("changelog/index.html", render.Page("/changelog/", "Changelog", render.md_to_html(_read(root / "spec" / "CHANGELOG.md"))))
        page("examples/index.html", render.Page("/examples/", "Example records", _examples_body(root)))
        page("404.html", render.Page("/404", "Not found", '<h1 id="not-found">Not found</h1>\n<p>No page lives at this address. Start from the <a href="/">home page</a>.</p>'))

        served = [(n, e) for n, e in lock.items() if n != "vendored" and not e.get("local")]
        for name, entry in served:
            rel = entry["servedAt"][len(SITE_ORIGIN) + 1:]
            written.append(_write(tmp, rel, (root / "spec" / name).read_bytes()))
        schema = json.loads(_read(root / "spec" / REFERENCE_SCHEMA))
        served_path = lock[REFERENCE_SCHEMA]["servedAt"][len(SITE_ORIGIN):]
        page("reference/index.html", render.Page("/reference/", "Field reference", reference.schema_reference_html(schema, served_path)))

        for name, _ in EXAMPLES:
            written.append(_write(tmp, f"examples/{name}", (root / "spec" / name).read_bytes()))
        written.append(_write(tmp, "viewer/index.html", (root / "site" / "viewer" / "cxbom_view.html").read_bytes()))
        written.append(_write(tmp, "assets/site.css", (root / "site" / "templates" / "site.css").read_bytes()))
        written.append(_write(tmp, "video/keeper.mp4", (root / "site" / "video" / "keeper.mp4").read_bytes()))
        written.append(_write(tmp, "video/keeper-poster.jpg", (root / "site" / "video" / "keeper-poster.jpg").read_bytes()))
        written.append(_write(tmp, "video/keeper.vtt", (root / "site" / "video" / "keeper.vtt").read_bytes()))
        for f in FONT_FILES:
            written.append(_write(tmp, f"fonts/{f}", (root / "site" / "fonts" / f).read_bytes()))
        written.append(_write(tmp, "_headers", (root / "site" / "_headers").read_bytes()))
        # Pages ignores Range on a static mp4. The player cannot seek without a 206.
        written.append(_write(tmp, "_worker.js", (root / "site" / "video_range.js").read_bytes()))
        if out.exists():
            shutil.rmtree(out)
        tmp.rename(out)
    finally:
        # Only reached with tmp still on disk when the swap above did not happen.
        # A finally, not an `except Exception`: KeyboardInterrupt and SystemExit
        # are BaseException subclasses and would otherwise orphan the scratch
        # tree. A SIGKILL reaches no cleanup at all; _reap_scratch_dirs collects
        # that one on the next run.
        shutil.rmtree(tmp, ignore_errors=True)
    return sorted(set(written))


def lock_new_schemas(root: Path) -> list[str]:
    """Add every spec/cxbom-X.Y.Z.schema.json that is not yet locked. Never edits an existing entry.

    The lock file is installed atomically, so a run killed part way through
    leaves the committed file either untouched or fully replaced.
    """
    lock_path = root / "spec" / "published.lock.json"
    _reap_temp_siblings(lock_path)
    lock = load_lock(root)
    served = {e.get("servedAt") for n, e in lock.items() if n != "vendored"}
    added: list[str] = []
    for p in sorted((root / "spec").glob("cxbom-*.schema.json")):
        m = _SCHEMA_NAME.match(p.name)
        if not m or p.name in lock:
            continue
        url = f"{SITE_ORIGIN}/schema/{m.group(1)}/cxbom.schema.json"
        doc = json.loads(_read(p))
        if doc.get("$id") != url:
            raise BuildError(f"{p.name}: $id {doc.get('$id')!r} must be {url}")
        if url in served:
            raise BuildError(f"{p.name}: {url} is already served by another locked artifact")
        lock[p.name] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "servedAt": url,
                        "immutable": True, "lockedBy": "site/build.py --lock"}
        added.append(p.name)
    if added:
        vendored = lock.pop("vendored", None)
        if vendored is not None:
            lock["vendored"] = vendored
        _atomic_write_text(lock_path, json.dumps(lock, indent=2) + "\n")
    return added


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="site/build.py", description="Build cxbom.org and run the publication gates.")
    ap.add_argument("--out", type=Path, default=SITE / "dist")
    ap.add_argument("--lock", action="store_true", help="lock new schema versions, then exit")
    args = ap.parse_args(argv)
    out = args.out.resolve()
    try:
        if args.lock:
            added = lock_new_schemas(ROOT)
            print("locked: " + (", ".join(added) if added else "nothing new"))
            return 0
        written = build(ROOT, out)
    except (BuildError, scope.ScopeError, strip.StripError, render.RenderError) as e:
        print(f"build refused: {e}", file=sys.stderr)
        return 2
    try:
        # Out of process, so nothing in the checker can end this process while it
        # is being read. In-process this call was a fail-open: a SystemExit(0)
        # from load_tokens escaped the clause below and the build exited 0 with
        # no gate having run and nothing on either stream. GateError is the only
        # thing denylist_tokens raises; anything else propagates into a traceback
        # and a non-zero exit, which is the safe direction.
        tokens = gates.denylist_tokens(ROOT)
    except gates.GateError as e:
        # The anonymity checker is the one gate that cannot be skipped, so a
        # failure to load it fails the build rather than running the rest.
        print(f"gate: anonymity: {e}; refusing to certify anonymity", file=sys.stderr)
        return 1
    # denylist_root is the repository itself, so the real denylist is read where
    # it lives and never copied.
    errs = gates.run_all(out, load_lock(ROOT), tokens, denylist_root=ROOT)
    # Named `err`, not `e`: every `{e}` in this package is an exception value, and
    # the one rule these messages follow is that an exception value is never
    # rendered whole. A gate finding is already fixed text.
    for err in errs:
        print(f"gate: {err}", file=sys.stderr)
    if errs:
        return 1
    print(f"built {len(written)} files, all gates pass")
    return 0
