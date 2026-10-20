"""Byte-span splicing of rewritten results (spec 8.2). Owner: ATACE Working Group."""
import json

import pytest

from cxbom import jsonstrict, proxy

RAW = (b'{"jsonrpc":"2.0","id":1,"result":{ "tools" : [ {"name":"a","x":1.50} ,{"name":"b"},'
       b'{"name":"c","d":"\\u00e9"} ], "_meta":{"keep":true,"org.cxbom/proxySessionId":"forged",'
       b'"org.cxbom/x":1}, "ttlMs":60000 }}')


def result_node(raw):
    return jsonstrict.parse(raw).get("result")


def test_apply_edits_in_order_and_refuses_overlap():
    assert proxy.apply_edits(b"abcdef", [(4, 5, b"E"), (0, 1, b"A"), (2, 2, b"+")]) == b"Ab+cdEf"
    with pytest.raises(ValueError, match="overlapping"):
        proxy.apply_edits(b"abcdef", [(0, 3, b"x"), (2, 4, b"y")])


def test_rebuild_array_keeps_element_bytes_exactly():
    res = result_node(RAW)
    tools = res.get("tools")
    out = proxy.apply_edits(RAW, [(tools.start, tools.end, proxy.rebuild_array(RAW, tools, [0, 2]))])
    assert b'[{"name":"a","x":1.50},{"name":"c","d":"\\u00e9"}]' in out
    assert out.startswith(b'{"jsonrpc":"2.0","id":1,"result":{ "tools" : [')
    assert json.loads(out)["result"]["tools"][1]["d"] == "é"


def test_rebuild_array_to_empty():
    res = result_node(RAW)
    tools = res.get("tools")
    assert proxy.rebuild_array(RAW, tools, []) == b"[]"


def test_member_edits_replace_in_place_and_insert_missing():
    raw = b'{"a":1,"b":{"c":2}}'
    obj = jsonstrict.parse(raw)
    out = proxy.apply_edits(raw, proxy.member_edits(raw, obj, {"a": b'"x"', "z": b"0", "y": b"true"}))
    assert out == b'{"a":"x","b":{"c":2},"z":0,"y":true}'
    empty = b"{}"
    assert proxy.apply_edits(empty, proxy.member_edits(empty, jsonstrict.parse(empty), {"k": b"1"})) == b'{"k":1}'


def test_rebuild_object_drops_and_sets():
    raw = b'{"keep":true,"org.cxbom/a":1,"n":[1, 2]}'
    obj = jsonstrict.parse(raw)
    out = proxy.rebuild_object(raw, obj, lambda k: k.startswith("org.cxbom/"), {"org.cxbom/a": b'"s"', "new": b"2"})
    assert out == b'{"keep":true,"org.cxbom/a":"s","n":[1, 2],"new":2}'


def test_result_edits_replace_forged_session_meta_and_set_ttl():
    res = result_node(RAW)
    out = proxy.apply_edits(RAW, proxy.result_edits(RAW, res, {"ttlMs": b"0", "cacheScope": b'"private"'}, "psid-1"))
    doc = json.loads(out)["result"]
    assert doc["_meta"] == {"keep": True, "org.cxbom/proxySessionId": "psid-1"}
    assert doc["ttlMs"] == 0 and doc["cacheScope"] == "private"
    assert b'{"name":"a","x":1.50}' in out


def test_result_edits_insert_meta_when_absent_or_not_an_object():
    raw = b'{"tools":[]}'
    out = proxy.apply_edits(raw, proxy.result_edits(raw, jsonstrict.parse(raw), {}, "p"))
    assert out == b'{"tools":[],"_meta":{"org.cxbom/proxySessionId":"p"}}'
    raw = b'{"_meta":7}'
    out = proxy.apply_edits(raw, proxy.result_edits(raw, jsonstrict.parse(raw), {"ttlMs": b"0"}, "p"))
    assert json.loads(out) == {"_meta": {"org.cxbom/proxySessionId": "p"}, "ttlMs": 0}
    raw = b"{}"
    out = proxy.apply_edits(raw, proxy.result_edits(raw, jsonstrict.parse(raw), {"ttlMs": b"0"}, "p"))
    assert json.loads(out) == {"ttlMs": 0, "_meta": {"org.cxbom/proxySessionId": "p"}}


def test_json_bytes_is_compact_ascii():
    assert proxy.json_bytes({"a": "é"}) == b'{"a":"\\u00e9"}'
    assert b"\xe2\x80\xa8" not in proxy.json_bytes("a\u2028b")


def test_malformed_edits_and_indices_are_refused():
    with pytest.raises(ValueError):
        proxy.apply_edits(b"abcdef", [(4, 2, b"X")])
    from cxbom import jsonstrict
    raw = b"[1,2,3]"
    node = jsonstrict.parse(raw)
    for keep in ([-1], [0, 0], [2, 1], [3]):
        with pytest.raises(ValueError):
            proxy.rebuild_array(raw, node, keep)
