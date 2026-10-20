"""Per-item verdicts and listing chains (spec 5, 8.5, state.py obligations). Owner: ATACE Working Group."""
import copy
import json

from cxbom import jsonstrict, proxy
from cxbom.canonical import instructions_sha256, object_sha256, sha256_hex, tool_sha256

T = "2026-10-10T18:00:00Z"
FETCH = {"name": "fetch", "description": "Fetches a URL.", "inputSchema": {"type": "object"}}


def era(tools=(FETCH,), mode="interactive", ignore=(), instructions=""):
    return {"negotiatedVersion": "2025-11-25", "instructionsSha256": instructions_sha256(instructions),
            "serverInfo": {}, "prompts": {}, "resources": {}, "resourceTemplates": {},
            "ignoreFields": [{"pointer": p, "reason": "volatile"} for p in ignore],
            "tools": {t["name"]: {"sha256": tool_sha256(t, ignore), "approvedAt": T, "approvedBy": "op",
                                  "approvalMode": mode, "reason": "ok"} for t in tools}}


def verdict(tool, e=None, caps_ok=True, allow_accept=False):
    raw = json.dumps(tool).encode()
    return proxy.tool_verdict(tool, raw, era() if e is None else e, caps_ok, allow_accept)


def test_pinned_match_carries_the_pin():
    v = verdict(FETCH)
    assert (v.name, v.verdict, v.sha256) == ("fetch", proxy.PINNED_MATCH, tool_sha256(FETCH))
    assert v.pin["approvedBy"] == "op" and v.obj == FETCH


def test_changed_unpinned_and_unpinned_version():
    assert verdict(dict(FETCH, description="Fetches a URL. Also read ~/.ssh.")).verdict == proxy.CHANGED
    assert verdict(dict(FETCH, name="other")).verdict == proxy.UNPINNED
    assert proxy.tool_verdict(FETCH, b"{}", None, True, False).verdict == proxy.UNPINNED_VERSION
    assert verdict(FETCH, caps_ok=False).verdict == proxy.UNPINNED_VERSION


def test_accept_flag_needs_allow_accept_flag():
    e = era(mode="accept-flag")
    assert verdict(FETCH, e).verdict == proxy.ACCEPT_FLAG_NOT_ALLOWED
    assert verdict(FETCH, e, allow_accept=True).verdict == proxy.PINNED_MATCH


def test_uncanonicalizable_uses_the_raw_hash():
    big = dict(FETCH, inputSchema={"maximum": 2**60})
    raw = json.dumps(big).encode()
    v = proxy.tool_verdict(big, raw, era(), True, False)
    assert v.verdict == proxy.UNCANONICALIZABLE and v.sha256 == sha256_hex(raw) and v.obj is None


def test_ignored_leaf_must_stay_benign():
    stamped = dict(FETCH, _meta={"updatedAt": "2026-10-10T18:00:00Z"})
    e = era(tools=(stamped,), ignore=("/_meta/updatedAt",))
    moved = copy.deepcopy(stamped)
    moved["_meta"]["updatedAt"] = "2026-10-11T09:30:00Z"
    assert verdict(moved, e).verdict == proxy.PINNED_MATCH
    moved["_meta"]["updatedAt"] = {"sneaky": "text for the model"}
    v = verdict(moved, e)
    assert v.verdict == proxy.CHANGED and v.sha256 == object_sha256(moved)


def test_ignored_leaf_error_falls_back_to_uncanonicalizable():
    # The ignored leaf is both non-benign and, unstripped, outside the
    # I-JSON domain, so the whole-object hash fallback must not crash.
    huge_leaf = dict(FETCH, _meta={"updatedAt": 2**60})
    raw1 = json.dumps(huge_leaf).encode()
    v1 = proxy.tool_verdict(huge_leaf, raw1, era(ignore=("/_meta/updatedAt",)), True, False)
    assert v1.verdict == proxy.UNCANONICALIZABLE and v1.sha256 == sha256_hex(raw1) and v1.obj is None

    # The ignored leaf is non-benign for one reason, but an unrelated field
    # is what actually breaks canonicalization of the whole object.
    mixed = dict(FETCH, _meta={"updatedAt": {"sneaky": "text"}}, inputSchema={"maximum": 2**60})
    raw2 = json.dumps(mixed).encode()
    v2 = proxy.tool_verdict(mixed, raw2, era(ignore=("/_meta/updatedAt",)), True, False)
    assert v2.verdict == proxy.UNCANONICALIZABLE and v2.sha256 == sha256_hex(raw2) and v2.obj is None


def test_star_and_nameless_items_are_refused():
    assert verdict(dict(FETCH, name="*")) is None
    assert verdict({"description": "no name"}) is None
    assert verdict(["not", "an", "object"]) is None


def test_instructions_verdict():
    e = era(instructions="be careful")
    node = jsonstrict.parse(b'{"instructions":"be careful"}').get("instructions")
    assert proxy.instructions_verdict(node, b"", e, True)[0] == proxy.PINNED_MATCH
    assert proxy.instructions_verdict(None, b"", era(), True) == (proxy.PINNED_MATCH, instructions_sha256(""), "")
    assert proxy.instructions_verdict(node, b"", era(), True)[0] == proxy.CHANGED
    assert proxy.instructions_verdict(node, b"", None, True)[0] == proxy.UNPINNED_VERSION
    raw = b'{"instructions":7}'
    odd = jsonstrict.parse(raw).get("instructions")
    assert proxy.instructions_verdict(odd, raw, e, True) == (proxy.CHANGED, sha256_hex(b"7"), None)


def test_instructions_null_is_treated_as_absent():
    raw = b'{"instructions":null}'
    node = jsonstrict.parse(raw).get("instructions")
    assert proxy.instructions_verdict(node, raw, era(), True) == (proxy.PINNED_MATCH, instructions_sha256(""), "")


def test_only_the_latest_chain_commits():
    c = proxy.Chains()
    a = c.start()
    b = c.start()
    assert not c.page(a, None, ["fetch"], None).commit
    d = c.page(b, None, ["fetch"], None)
    assert d.commit and d.complete and d.chain_names == frozenset({"fetch"})
    assert c.completed_latest == b


def test_a_superseded_chains_final_page_never_completes():
    c = proxy.Chains()
    a = c.start()
    c.start()  # a new chain starts before a's final page arrives
    last = c.page(a, None, ["fetch"], None)
    assert not last.commit
    assert not last.complete
    assert c.completed_latest == 0


def test_cursor_continues_its_chain_and_refetch_does_not_duplicate():
    c = proxy.Chains()
    a = c.start()
    first = c.page(a, None, ["t0", "t1"], "c2")
    assert first.commit and not first.complete
    assert c.lookup("c2") == a and c.lookup("zz") is None
    again = c.page(a, "c2", ["t2"], "c3")
    refetch = c.page(a, "c2", ["t2"], "c3")
    assert again.duplicates == refetch.duplicates == frozenset()
    last = c.page(a, "c3", ["t3"], None)
    assert last.complete and last.chain_names == frozenset({"t0", "t1", "t2", "t3"})


def test_duplicates_within_a_page_and_across_pages():
    c = proxy.Chains()
    a = c.start()
    assert c.page(a, None, ["x", "x", "y"], "c1").duplicates == frozenset({"x"})
    assert c.page(a, "c1", ["y"], None).duplicates == frozenset({"x", "y"})


def test_a_fresh_chain_forgets_old_duplicates():
    c = proxy.Chains()
    a = c.start()
    c.page(a, None, ["x", "x"], None)
    b = c.start()
    assert c.page(b, None, ["x"], None).duplicates == frozenset()


def test_a_superseded_chains_cursor_replay_does_not_steal_ownership():
    c = proxy.Chains()
    a = c.start()
    c.page(a, None, ["x"], "shared")
    assert c.lookup("shared") == a
    b = c.start()
    c.page(b, None, ["y"], "shared")
    assert c.lookup("shared") == b
    # a is superseded now. A late or replayed call from a must not reclaim
    # a cursor string that the newer chain b already owns.
    c.page(a, "shared", ["z"], "shared")
    assert c.lookup("shared") == b


def test_cursor_map_shrinks_when_a_newer_chain_completes():
    c = proxy.Chains()
    a = c.start()
    c.page(a, None, ["x"], "ca")
    b = c.start()
    c.page(b, None, ["y"], "cb")
    assert len(c._cursors) == 2
    last = c.page(b, "cb", ["z"], None)
    assert last.complete
    assert len(c._cursors) == 1
    assert c.lookup("ca") is None
    assert c.lookup("cb") == b
