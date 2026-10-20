"""The restyled viewer keeps its data, loses the old look, and stays offline.

Owner: ATACE Working Group.

site/viewer/cxbom_view.html is CXBOM/ATACE viz/cxbom_view.html at 3e7f88f with the
ledger palette, self-hosted type, keyboard access, and corrected copy applied.
"""
import functools
import json
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import palette  # noqa: E402

VIEWER = (ROOT / "site/viewer/cxbom_view.html").read_text(encoding="utf-8")
CSS = (ROOT / "site/templates/site.css").read_text(encoding="utf-8")
PROBE = Path(__file__).resolve().parent / "viewer_dom_probe.js"
RECORD = json.loads((ROOT / "site/data/session_reference.json").read_text(encoding="utf-8"))

# The trust-ring designation a screen-reader user must hear. Stated here rather
# than read out of the viewer, so an edit that renames the words on the page
# fails instead of agreeing with itself. site/cxsite/strip.py writes the same
# three words into the ledger's accessible description.
RING_WORD = {0: "operator", 1: "agent", 2: "user"}

# HTML void elements, which never take an end tag.
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
         "meta", "param", "source", "track", "wbr"}
# Elements the parser leaves inside head. Anything else closes head and opens
# an implicit body, which is what a browser does with this file: it has no
# body start tag at all, so a parser that does not implement that one rule
# would nest the whole page inside head and hand the probe the wrong tree.
_HEAD_ONLY = {"meta", "title", "style", "link", "base", "script", "noscript", "template"}
# style and script text is not DOM content any assertion here reads, and
# leaving it out keeps the document's text content free of CSS and JS source.
_SKIP_SUBTREE = {"style", "script"}


class _StaticDom(HTMLParser):
    """Builds the pre-script element tree and pulls the inline script out of it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root: dict = {"tag": "html", "attrs": {}, "children": []}
        self._stack: list[dict] = [self.root]
        self._skipping: str | None = None
        self.scripts: list[str] = []

    def _open(self, tag: str, attrs: list) -> dict:
        node = {"tag": tag, "attrs": {k: ("" if v is None else v) for k, v in attrs}, "children": []}
        self._stack[-1]["children"].append(node)
        return node

    def handle_starttag(self, tag, attrs):
        if self._skipping:
            return
        if tag in _SKIP_SUBTREE:
            self._skipping = tag
            return
        if tag == "html":
            self.root["attrs"].update({k: ("" if v is None else v) for k, v in attrs})
            return
        if tag not in _HEAD_ONLY and any(n["tag"] == "head" for n in self._stack):
            while self._stack[-1]["tag"] != "html":
                self._stack.pop()
            self._stack.append(self._open("body", []))
        node = self._open(tag, attrs)
        if tag not in _VOID:
            self._stack.append(node)

    def handle_startendtag(self, tag, attrs):
        if not self._skipping:
            self._open(tag, attrs)

    def handle_endtag(self, tag):
        if self._skipping:
            self._skipping = None if tag == self._skipping else self._skipping
            return
        for depth in range(len(self._stack) - 1, 0, -1):
            if self._stack[depth]["tag"] == tag:
                del self._stack[depth:]
                return
        # An end tag with no start tag (this file closes a body it never opens).

    def handle_data(self, data):
        if self._skipping == "script":
            self.scripts.append(data)
        elif not self._skipping and data.strip():
            self._stack[-1]["children"].append({"text": data})


def _static_dom() -> tuple[dict, str]:
    parser = _StaticDom()
    parser.feed(VIEWER)
    parser.close()
    assert len(parser.scripts) == 1, f"expected one inline script, found {len(parser.scripts)}"
    return parser.root, parser.scripts[0]


@functools.lru_cache(maxsize=1)
def _rendered():
    """Run the viewer's own script over a minimal DOM and return what it built.

    Fails closed when no engine is present, in the same spirit as the CI
    anonymity job: a missing tool turns this red rather than passing blind,
    because a skip here would let the very mutation this test exists to catch
    through a green suite.
    """
    node = shutil.which("node")
    assert node, ("node is required to run the viewer's render path. It is not a "
                  "browser and not a pinned Python dependency; install node or "
                  "run this suite where one is on PATH.")
    tree, script = _static_dom()
    with tempfile.TemporaryDirectory() as work:
        payload = Path(work) / "input.json"
        payload.write_text(json.dumps({"document": tree, "script": script}), encoding="utf-8")
        done = subprocess.run([node, str(PROBE), str(payload)],
                              capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, f"the viewer's script failed to run:\n{done.stderr[-4000:]}"
    return json.loads(done.stdout)


def _segment_buttons():
    return _rendered()["segkeys"]


def _run(actions):
    """Run the viewer's own script over the minimal DOM, performing load actions.

    Mirrors _rendered(), but passes probe actions (loadText / loadExample /
    loadReference) that call the page's own entry points, and returns the full
    probe output including each action's validation-region snapshot. Not cached:
    every action list is its own run, since each one mutates the page.
    """
    node = shutil.which("node")
    assert node, "node is required to run the viewer's render path."
    tree, script = _static_dom()
    with tempfile.TemporaryDirectory() as work:
        payload = Path(work) / "input.json"
        payload.write_text(json.dumps({"document": tree, "script": script, "actions": actions}),
                           encoding="utf-8")
        done = subprocess.run([node, str(PROBE), str(payload)], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, f"the viewer's script failed to run:\n{done.stderr[-4000:]}"
    return json.loads(done.stdout)


# The three JS constants that carry frozen artifacts verbatim: the embedded
# reference record, the 0.2.0 schema, and the three bundled examples. The sync
# tests below pin each to its source file; the claims and attention bans are a
# statement about the page's own words, so they scan the source with these three
# data lines removed.
_DATA_CONSTANTS = ("const RAW = ", "const SCHEMA = ", "const EXAMPLES = ")


def _authored_source() -> str:
    kept = [ln for ln in VIEWER.splitlines() if not ln.startswith(_DATA_CONSTANTS)]
    return "\n".join(kept)


def _const(prefix: str):
    line = next(ln for ln in VIEWER.splitlines() if ln.startswith(prefix))
    return json.loads(line[len(prefix):].rstrip().rstrip(";"))


def test_viewer_palette_equals_site_palette():
    assert palette.parse_palette(VIEWER) == palette.parse_palette(CSS)


def test_old_navy_and_cyan_palette_is_gone():
    # \x23 is '#'. Written as an escape so a local source-scanning hook does not
    # mistake these hex literals for the start of a line comment.
    for old in ("\x230c1017", "\x2337c3d8", "\x23131a24", "\x234d86ff", "rgba(240,101,90"):
        assert old not in VIEWER, old


def test_embedded_record_is_the_reference_record():
    line = next(ln for ln in VIEWER.splitlines() if ln.startswith("const RAW = "))
    embedded = json.loads(line[len("const RAW = "):].rstrip().rstrip(";"))
    assert embedded == json.loads((ROOT / "site/viewer/reference.json").read_text(encoding="utf-8"))


def test_copy_makes_no_attention_claim():
    for claim in ("competes equally", "attention field", "actually sees", "share of the attention"):
        assert claim not in VIEWER, claim
    assert "It does not measure attention." in VIEWER


def test_viewer_loads_nothing_remote_and_stores_nothing():
    for banned in ("localStorage", "sessionStorage", "document.cookie", "indexedDB", "fetch(",
                   "XMLHttpRequest", "WebSocket", "<link", "@import", "<iframe"):
        assert banned not in VIEWER, banned
    assert not re.search(r'\ssrc="(?!/)', VIEWER)
    assert re.findall(r'url\("([^"]+)"\)', VIEWER) == [
        "/fonts/source-serif-4-latin-400-normal.woff2", "/fonts/source-serif-4-latin-600-normal.woff2",
        "/fonts/source-code-pro-latin-400-normal.woff2", "/fonts/source-code-pro-latin-600-normal.woff2"]


def test_keyboard_access_markup_is_present_in_source():
    """Source shape only, and named so no one mistakes it for the real check.

    Every string below survives a mutation that empties the segment loop, which
    is why the behavioural tests under it exist. This test is kept because the
    empty container and the load button are a static-markup contract in their
    own right: they must be in the shipped bytes before any script runs.
    """
    assert '<div class="segkeys" id="segkeys" role="group" aria-label="Trust ring components"></div>' in VIEWER
    assert "el.addEventListener('focus',show)" in VIEWER
    assert "if(e.key==='Escape')hideTip();" in VIEWER
    assert '<button class="btn" id="loadBtn" type="button">Load a CxBOM record (JSON file)</button>' in VIEWER


def test_keyboard_access_to_viz_details():
    """One focusable button per component, each naming that component's facts.

    Behavioural: the viewer's own script runs over a minimal DOM and this reads
    the nodes it appended. The facts come from site/data/session_reference.json,
    not from re-running the page's own name-building expression.
    """
    components = RECORD["contextComponents"]
    buttons = _segment_buttons()
    assert buttons is not None, "the segment container is missing from the rendered page"
    assert len(buttons) == len(components)
    assert [b["tag"] for b in buttons] == ["BUTTON"] * len(components)
    assert [b["type"] for b in buttons] == ["button"] * len(components)

    names = [b["text"] for b in buttons]
    assert len(set(names)) == len(names), names
    for component, name in zip(components, names):
        assert component["id"] in name, name
        assert RING_WORD[component["trustRing"]] in name, name
        # Digits only: the page groups thousands for readability, and the test
        # should not pin the grouping character.
        assert str(component["content"]["tokenCount"]) in name.replace(",", ""), name
        stated = re.search(r"([0-9]+\.[0-9]+)%", name)
        assert stated, name
        assert abs(float(stated.group(1)) - component["content"]["contextualSharePercent"]) < 0.005, name
        inverted = component.get("toolDefinitionTrustInversion", {}).get("detected", False)
        assert ("trust inversion" in name) is inverted, name


def test_segment_buttons_stand_in_record_order_inside_the_tab_order():
    order = _rendered()["tabOrder"]
    at = [i for i, item in enumerate(order) if "segkey" in item["className"].split()]
    assert at, "no segment button is in the tab order"
    assert at == list(range(at[0], at[0] + len(RECORD["contextComponents"]))), "the buttons are not contiguous"
    ahead = [(item["tag"], item["id"] or item["className"]) for item in order[:at[0]]]
    # The load controls and the one-click example buttons lead the tab order, in
    # DOM order, before the per-segment buttons. Everything ahead of the first
    # segment button is listed so a new focusable stop cannot slip in unseen.
    assert ahead == [("A", "skip"), ("A", "brand"), ("A", ""), ("A", ""), ("A", ""),
                     ("A", ""), ("A", ""), ("A", ""), ("A", "repo"),
                     ("BUTTON", "loadBtn"), ("BUTTON", "themeToggle"),
                     ("BUTTON", "ex-reference"), ("BUTTON", "ex-clean"),
                     ("BUTTON", "ex-finance"), ("BUTTON", "ex-multiturn")]
    reached = [order[i]["text"].split(" ")[0] for i in at]
    assert reached == [c["id"] for c in RECORD["contextComponents"]]
    assert len(order) > at[-1] + 1, "the tab order stops at the last segment button"


def test_focusing_a_segment_announces_its_detail_in_a_live_region():
    probes = _rendered()["focusProbes"]
    assert len(probes) == len(RECORD["contextComponents"])
    for component, probe in zip(RECORD["contextComponents"], probes):
        assert probe["writtenContainerCount"] == 1, component["id"]
        # The container is found by watching which pre-existing node the focus
        # handler wrote into, so this checks the node that actually speaks.
        assert probe["liveAttrs"]["aria-live"] == "polite", component["id"]
        assert "on" in probe["liveClassWhileOpen"].split(), component["id"]
        detail = probe["liveText"]
        assert component["type"] in detail, detail
        assert RING_WORD[component["trustRing"]] in detail, detail
        assert str(component["content"]["tokenCount"]) in detail.replace(",", ""), detail
        assert component["source"]["origin"] in detail, detail


def test_escape_closes_the_detail_without_moving_focus():
    for probe in _rendered()["focusProbes"]:
        assert "on" not in probe["liveClassAfterEscape"].split()
        assert probe["focusCallsDuringEscape"] == 0


def test_the_no_attention_disclaimer_reaches_the_rendered_page():
    # test_copy_makes_no_attention_claim only proves the sentence is in the
    # file. The page builds that paragraph at runtime, so the sentence could
    # sit in the source while no reader ever sees it.
    assert "It does not measure attention." in _rendered()["documentText"]


def test_landmarks_skip_link_and_one_h1():
    assert '<html lang="en">' in VIEWER
    assert '<a class="skip" href="\x23main">Skip to content</a>' in VIEWER
    assert '<main id="main">' in VIEWER and "</main>" in VIEWER
    assert VIEWER.count("<h1>") == 1
    assert "prefers-reduced-motion:reduce" in VIEWER


def test_loaded_records_render_as_text_only():
    # A record dropped into the viewer is untrusted. Every value goes through
    # createTextNode or setAttribute, never through an HTML parser.
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in VIEWER, sink


def test_no_attention_softmax_or_crowding_claim():
    """C4 / design-vs-spec ruling 4: rings are pre-inference labels, not attention.

    The ban is on the page's own words. softmax and crowding name mechanisms the
    page must never invoke, and the one place attention may be named is the
    disclaimer, which exists to deny the measurement rather than make it.

    The scan is the authored source, with the three embedded data constants
    (RAW, SCHEMA, EXAMPLES) removed. Those carry frozen artifacts verbatim: the
    0.2.0 schema documents its own field named attentionMechanism and the
    bundled example records describe real findings in their own words. Those are
    data the viewer displays, pinned to their sources by the sync tests, not
    claims this page makes, so they are out of scope here exactly as the field
    name was before the schema was embedded.
    """
    # Each data constant is one line, so removing them drops exactly three lines;
    # this guards the helper against a constant that was renamed or re-wrapped.
    copy = _authored_source()
    assert len(VIEWER.splitlines()) - len(copy.splitlines()) == 3
    for banned in ("softmax", "crowding"):
        assert banned not in copy.lower(), banned
    assert copy.count("It does not measure attention.") == 1
    assert "attention" not in copy.replace("It does not measure attention.", "").lower()


# ----------------------------------------------------------------------------
# In-browser schema validation, one-click examples, the educational layer, and
# the removal of the blocking alert() error path.
# ----------------------------------------------------------------------------

def test_embedded_schema_is_the_published_0_3_0_schema():
    # The validator runs against the same bytes the site serves at
    # /schema/0.3.0/cxbom.schema.json, embedded so it needs no network.
    assert _const("const SCHEMA = ") == json.loads(
        (ROOT / "spec/cxbom-0.3.0.schema.json").read_text(encoding="utf-8"))


def test_embedded_examples_are_the_shipped_examples():
    embedded = _const("const EXAMPLES = ")
    want = {
        "clean_baseline": "cxbom_example_clean_baseline.json",
        "finance_assistant": "cxbom_example_finance_assistant.json",
        "multiturn_ring1derived": "cxbom_example_multiturn_ring1derived.json",
    }
    assert set(embedded) == set(want)
    for key, name in want.items():
        assert embedded[key] == json.loads((ROOT / "spec" / name).read_text(encoding="utf-8")), key


def test_no_blocking_alert_path_remains():
    # The old readFile error path raised a modal alert(). It is gone: a malformed
    # or schema-invalid record is reported inline (see the behavioural tests
    # below), never in a dialog the DOM probe's sandbox would throw on.
    assert "alert(" not in VIEWER


def test_default_record_is_reported_valid_in_an_announced_region():
    v = _rendered()["validation"]
    assert v is not None, "the viewer has no validation status region"
    assert v["attrs"].get("role") == "status"
    assert v["attrs"].get("aria-live") == "polite"
    assert "valid" in v["className"].split()
    assert "Valid against CxBOM 0.3.0" in v["text"]


def test_each_bundled_example_is_one_click_and_validates():
    keys = ["clean_baseline", "finance_assistant", "multiturn_ring1derived"]
    out = _run([{"type": "loadExample", "key": k} for k in keys])
    results = out["actionResults"]
    assert [r["action"]["key"] for r in results] == keys
    for r in results:
        v = r["validation"]
        assert "valid" in v["className"].split(), (r["action"]["key"], v["className"])
        assert "invalid" not in v["className"].split(), r["action"]["key"]
        assert "Valid against CxBOM 0.3.0" in v["text"], r["action"]["key"]


def test_example_buttons_are_in_the_markup_with_stable_ids():
    for bid, label in (("ex-reference", "Reference session"), ("ex-clean", "Clean baseline"),
                       ("ex-finance", "Finance assistant"),
                       ("ex-multiturn", "Multi-turn (ring-1-derived)")):
        assert f'<button class="btn" id="{bid}" type="button" aria-pressed="false">{label}</button>' in VIEWER, bid


def test_malformed_json_shows_an_inline_error_not_an_alert():
    # alert() throws in the probe sandbox, so reaching the old path would fail
    # the run. A clean exit here is itself the evidence the modal path is gone.
    out = _run([{"type": "loadText", "text": "{ this is not json "}])
    v = out["actionResults"][0]["validation"]
    assert "parse" in v["className"].split(), v["className"]
    assert "valid" not in v["className"].split()
    assert "Not valid JSON" in v["text"]
    assert "could not be read as JSON" in v["text"]


def test_schema_invalid_record_shows_inline_errors_with_paths():
    # Valid JSON, but it violates the schema in several places at once.
    bad = json.dumps({"bomFormat": "not-cxbom"})
    out = _run([{"type": "loadText", "text": bad}])
    v = out["actionResults"][0]["validation"]
    assert "invalid" in v["className"].split(), v["className"]
    assert "against CxBOM 0.3.0" in v["text"]
    assert v["items"], "no per-error lines were listed"
    joined = "\n".join(v["items"])
    # Each error names what failed and where: a JSON-pointer path plus a reason.
    assert any(it.startswith("/bomFormat") and "must equal" in it for it in v["items"]), joined
    assert any(it.startswith("/specVersion") and "required" in it for it in v["items"]), joined


def test_a_valid_record_still_renders_after_an_invalid_one():
    # Loading garbage must not wedge the viewer: the reference record renders and
    # reports valid again afterwards.
    out = _run([{"type": "loadText", "text": "nonsense"},
                {"type": "loadReference"}])
    final = out["actionResults"][-1]["validation"]
    assert "valid" in final["className"].split()
    assert "Valid against CxBOM 0.3.0" in final["text"]


def test_educational_layer_is_present_and_uses_native_disclosures():
    # Native <details>/<summary> is keyboard-operable by the browser with no
    # script, and the cards ship open so the teaching is visible for the axe gate.
    assert '<section class="edu"' in VIEWER
    summaries = re.findall(r"<summary>([^<]+)</summary>", VIEWER)
    for heading in ("What a CxBOM is", "What the trust rings mean",
                    "The tool-definition inversion", "How to read the panels"):
        assert heading in summaries, heading
    assert VIEWER.count('<details class="educard" open>') == len(summaries)


def test_educational_text_reaches_the_rendered_page():
    text = _rendered()["documentText"]
    for phrase in ("Context Bill of Materials", "Token Democracy",
                   "tool-definition trust inversion",
                   "Ring 0, operator", "Ring 1, agent", "Ring 2, user",
                   "It does not block the tool, verify the server, or stop any particular attack"):
        assert phrase in text, phrase


def test_rendered_text_is_claims_and_attention_clean():
    # The task's claims bans, scanned over what a first-time reader actually sees
    # (the default render plus the authored teaching). The example records carry
    # their own finding prose and are data, not scanned here.
    text = _rendered()["documentText"]
    low = text.lower()
    assert "softmax" not in low
    assert "crowding" not in low
    assert "CVE-" not in text
    assert text.count("It does not measure attention.") == 1
    assert "attention" not in low.replace("it does not measure attention.", "")


def test_rendered_viewer_passes_anon_check_site():
    # The project's own anonymity gate, run over the shipped viewer bytes. This
    # is the same checker site/build.py runs over the whole dist; here it is
    # scoped to the viewer so a failure points straight at this file.
    script = ROOT / "scripts" / "anon_check.py"
    with tempfile.TemporaryDirectory() as work:
        site = Path(work) / "site"
        site.mkdir()
        shutil.copyfile(ROOT / "site/viewer/cxbom_view.html", site / "cxbom_view.html")
        done = subprocess.run([sys.executable, str(script), "site", str(site)],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, f"anon_check flagged the viewer:\n{done.stderr[-4000:]}"


# ----------------------------------------------------------------------------
# The concentric trust-ring visualization. It replaced the horizontal context
# stream canvas: an offline, hand-rolled inline SVG with Ring 0 (operator) at the
# core, Ring 1 (agent) the middle band, Ring 2 (user) outward. These read the
# nodes the viewer's own draw step built, via the DOM probe's viz snapshot.
# ----------------------------------------------------------------------------

def _viz():
    viz = _rendered()["viz"]
    assert viz is not None, "the viewer built no trust-ring diagram"
    return viz


def test_viz_is_a_labelled_inline_svg_not_a_canvas():
    # The stream canvas is gone; no 2d context is constructed anywhere.
    assert "<canvas" not in VIEWER
    assert ".getContext(" not in VIEWER
    viz = _viz()
    assert viz["tag"] == "SVG"
    assert viz["role"] == "img", viz["role"]
    assert viz["label"].strip(), "the svg needs an aria-label text equivalent"


def test_every_component_is_a_mark_on_its_own_trust_ring():
    # cc-001 -> ring 0, cc-002..cc-005 -> ring 1, cc-006 -> ring 2. Each component
    # is one arc, drawn on the band for the ring the record assigns it.
    comps = RECORD["contextComponents"]
    by_id = {m["id"]: m for m in _viz()["marks"]}
    assert set(by_id) == {c["id"] for c in comps}, by_id
    for c in comps:
        assert by_id[c["id"]]["ring"] == c["trustRing"], c["id"]


def test_all_three_trust_rings_are_drawn():
    rings = sorted({m["ring"] for m in _viz()["marks"]})
    assert rings == [0, 1, 2], rings


def test_the_tool_definition_inversion_is_marked_in_the_viz():
    # The whole point of CxBOM: the ring-1 tool definition wielding ring-0-equivalent
    # authority must be visible in the picture, not only in the table.
    viz = _viz()
    flagged = [c["id"] for c in RECORD["contextComponents"]
               if c.get("toolDefinitionTrustInversion", {}).get("detected")]
    assert flagged, "the reference record should carry the inversion"
    inverted = [m["id"] for m in viz["marks"] if m["inversion"]]
    assert inverted == flagged, (inverted, flagged)
    assert viz["inversionMarked"] is True, "a distinct inversion connector must be drawn"


def test_legend_is_present_and_names_all_three_rings():
    # Identity is never carried by colour alone: the legend is always present and
    # names every ring in words plus its number.
    items = _viz()["legend"]
    assert items, "the legend is missing"
    joined = " ".join(items)
    for word in ("operator", "agent", "user"):
        assert word in joined, word
    for n in ("0", "1", "2"):
        assert any(n in it for it in items), n
