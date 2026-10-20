"""Strict JSON parsing with byte spans (spec 5). Owner: ATACE Working Group."""
import pytest

from cxbom.jsonstrict import StrictJSONError, parse, to_python


def test_round_trip_and_spans():
    data = b'{"a": [1, 2.50, "x\\n\xc3\xa9"], "b": {"c": null, "d": true}}'
    node = parse(data)
    assert to_python(node) == {"a": [1, 2.5, "x\né"], "b": {"c": None, "d": True}}
    a = node.get("a")
    assert data[a.start:a.end] == b'[1, 2.50, "x\\n\xc3\xa9"]'
    assert a.items[1].value == "2.50"          # lexeme preserved


@pytest.mark.parametrize("bad", [
    b'{"d": "\xff"}',                        # invalid UTF-8
    b'{"d": 1, "d": 2}',                     # duplicate key
    b'{"d": "\\ud800"}',                     # lone surrogate escape
    b'{"d": 1e400}',                         # overflow to infinity
    b'{"d": NaN}',                           # non-standard literal
    b'{"d": 1,}',                            # trailing comma
    b'{"d": "a\x01b"}',                      # raw control character
    b'[1] x',                                # trailing data
    b'{"d": 01}',                            # leading zero
])
def test_rejects(bad):
    with pytest.raises(StrictJSONError):
        parse(bad)


def test_large_integer_kept_exact():
    node = parse(b'{"n": 9223372036854775807}')
    assert to_python(node)["n"] == 9223372036854775807


def test_max_bytes():
    with pytest.raises(StrictJSONError):
        parse(b'"' + b"a" * 100 + b'"', max_bytes=50)


def test_depth_limit():
    with pytest.raises(StrictJSONError):
        parse(b"[" * 600 + b"]" * 600)


def test_depth_limit_boundary():
    # 128 levels should parse fine
    node = parse(b"[" * 128 + b"]" * 128)
    assert node.kind == "array"

    # 129 levels should be rejected (exceeds MAX_DEPTH=128)
    with pytest.raises(StrictJSONError):
        parse(b"[" * 129 + b"]" * 129)


def test_number_length_limit():
    # 400-character number should parse fine
    node = parse(b'{"n": ' + b'9' * 400 + b'}')
    assert to_python(node)["n"] == int('9' * 400)

    # 401-character number should be rejected
    with pytest.raises(StrictJSONError):
        parse(b'{"n": ' + b'9' * 401 + b'}')


@pytest.mark.parametrize("not_bytes", ["{}", None, 42, bytearray(b"{}")])
def test_parse_non_bytes_is_strict_json_error(not_bytes):
    with pytest.raises(StrictJSONError):
        parse(not_bytes)
