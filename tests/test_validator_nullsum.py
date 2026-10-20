"""check_numeric (and its siblings in validator.py) must report on malformed
token-accounting input, not crash on it. `.get(key, default)` substitutes the
default only when the key is ABSENT; a component whose `content` is present
but JSON null, or whose `tokenCount` is present but null or the wrong type,
used to crash `check_numeric` with AttributeError or TypeError. Every test
here pins an independently-chosen expected error string (never the exact
expression the code under test produces) so a broken guard fails loudly
instead of tautologically passing.

Owner: ATACE Working Group.
"""
import copy
import decimal
import hashlib
import json
import math
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cxbom import validator

ROOT = Path(__file__).resolve().parents[1]
MINIMAL = json.loads((ROOT / "tests/fixtures/atace/valid-minimal.json").read_text(encoding="utf-8"))

# The widest integer any record can carry, and the one that broke round 2.
# json.loads refuses a 4301-digit literal and CPython refuses to render a
# 4301-digit integer (sys.get_int_max_str_digits() is 4300), so 4300 digits is
# simultaneously the reachable maximum and the last width that can be printed --
# and adding anything to it, which every token-accounting sum here does, carries
# past the limit. Built through json.loads rather than as 10 ** n so the comment
# above is a claim the construction itself checks.
BIGGEST_JSON_INTEGER = json.loads('{"n": ' + "9" * 4300 + "}")["n"]


def _doc():
    return copy.deepcopy(MINIMAL)


def _nested(depth, leaf):
    """{"a": {"a": ... leaf}} nested depth levels, built without recursion. It is
    the value json.loads('{"a":' * depth + json.dumps(leaf) + "}" * depth) returns
    where the parser follows that deep. CPython 3.14 follows past 100,000 levels.
    3.10 and 3.12, the versions CI and the Jetson run, raise RecursionError below
    2,000, so a test that parsed its deep record would fail there before reaching
    the walk it means to test. test_nested_is_what_json_loads_returns pins the
    equivalence at the deepest level each interpreter parses."""
    node = leaf
    for _ in range(depth):
        node = {"a": node}
    return node


def test_nested_is_what_json_loads_returns():
    """At the deepest nesting json.loads parses on this interpreter, its result
    has exactly _nested's shape, compared iteratively because == on it would
    recurse. One level deeper, the parser raises RecursionError. The depth is
    measured, so 3.10 and 3.12 check the equivalence near their limit too,
    rather than skipping a depth only 3.14 parses. Every parse runs from this
    frame, because 3.10 counts frames toward the parser's limit."""
    def text(d):
        return '{"a":' * d + '"leaf"' + "}" * d

    lo, hi = 0, 1024
    while True:
        try:
            json.loads(text(hi))
        except RecursionError:
            break
        lo, hi = hi, hi * 2
        assert hi <= 400_000
    while hi - lo > 1:
        mid = (lo + hi) // 2
        try:
            json.loads(text(mid))
            lo = mid
        except RecursionError:
            hi = mid
    assert lo > 1
    with pytest.raises(RecursionError):
        json.loads(text(lo + 1))
    parsed, built = json.loads(text(lo)), _nested(lo, "leaf")
    for _ in range(lo):
        assert type(parsed) is dict and list(parsed) == ["a"]
        assert type(built) is dict and list(built) == ["a"]
        parsed, built = parsed["a"], built["a"]
    assert parsed == built == "leaf"


# --- primary defect: cxbom/validator.py:107, content/tokenCount -----------


def test_baseline_fixture_is_unchanged():
    """Regression anchor: the well-formed fixture's full error list, from
    every check in check_all, must still be empty after the fix."""
    assert validator.check_all(_doc()) == []


def test_content_absent_still_contributes_zero_silently():
    """A component missing `content` entirely is validate_doc's job (required
    field); check_numeric must keep treating it as a zero contribution, not
    newly start reporting on it, or a previously-identical malformed-record
    error list would change shape."""
    doc = _doc()
    del doc["contextComponents"][0]["content"]
    errs = validator.check_numeric(doc)
    assert errs == ["totalContextTokens 100 != sum(component tokenCount) 40"]


def test_content_null_is_reported_not_crashed():
    doc = _doc()
    doc["contextComponents"][0]["content"] = None
    errs = validator.check_numeric(doc)
    assert "cc-001: content None is not an object" in errs


def test_content_not_a_dict_is_reported_not_crashed():
    doc = _doc()
    doc["contextComponents"][0]["content"] = ["unexpected", "list"]
    errs = validator.check_numeric(doc)
    assert "cc-001: content ['unexpected', 'list'] is not an object" in errs


def test_tokencount_absent_still_contributes_zero_silently():
    doc = _doc()
    del doc["contextComponents"][0]["content"]["tokenCount"]
    errs = validator.check_numeric(doc)
    assert errs == ["totalContextTokens 100 != sum(component tokenCount) 40"]


def test_tokencount_null_is_reported_not_crashed():
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = None
    errs = validator.check_numeric(doc)
    assert "cc-001: tokenCount None is not an integer" in errs


def test_tokencount_bool_is_reported_not_silently_summed():
    """isinstance(True, int) is True in Python: a naive `isinstance(tc, int)`
    guard would silently accept a boolean tokenCount and sum it as 1. This is
    the exact isinstance-vs-type trap called out for mutation testing."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = True
    errs = validator.check_numeric(doc)
    assert "cc-001: tokenCount True is not an integer" in errs
    # and it must not have been folded into the sum as 1
    assert "totalContextTokens 100 != sum(component tokenCount) 41" not in errs


def test_tokencount_numeric_string_is_reported_not_crashed():
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = "60"
    errs = validator.check_numeric(doc)
    assert "cc-001: tokenCount '60' is not an integer" in errs


def test_tokencount_integral_float_is_accepted_like_the_schema():
    """jsonschema's Draft7Validator accepts an integral float (60.0) as type
    "integer" (verified directly against the library, not assumed). A record
    with content.tokenCount == 60.0 is therefore schema-valid; check_numeric
    must not gain a new error for a value the schema already accepts, or a
    currently-passing record's error list would move."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = 60.0
    assert validator.check_numeric(doc) == []
    assert validator.check_all(doc) == []


def test_tokencount_non_integral_float_is_reported_not_crashed():
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = 60.5
    errs = validator.check_numeric(doc)
    assert "cc-001: tokenCount 60.5 is not an integer" in errs


def test_one_malformed_component_does_not_suppress_the_other_findings():
    """A malformed cc-001 must not crash the whole check and must not hide
    that cc-002 is otherwise fine: the malformed-component error and the
    resulting total mismatch both appear, nothing else."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = None
    errs = validator.check_numeric(doc)
    assert "cc-001: tokenCount None is not an integer" in errs
    assert "totalContextTokens 100 != sum(component tokenCount) 40" in errs
    # cc-002's own share is still checked and still passes (40/40, no error)
    assert not any("cc-002" in e for e in errs)


# --- sweep: same shape elsewhere in check_numeric --------------------------


def test_contextcomponents_null_does_not_crash_check_numeric():
    doc = _doc()
    doc["contextComponents"] = None
    errs = validator.check_numeric(doc)
    assert "totalContextTokens 100 != sum(component tokenCount) 0" in errs


def test_sessionsummary_null_does_not_crash_check_numeric():
    doc = _doc()
    doc["sessionSummary"] = None
    errs = validator.check_numeric(doc)
    assert "totalContextTokens None != sum(component tokenCount) 100" in errs


def test_metadata_session_contextwindowtokensused_chain_nulls_do_not_crash():
    for bad in ({"session": {"contextWindowTokensUsed": None}}, {"session": None}, None):
        doc = _doc()
        doc["metadata"] = bad
        # must not raise; the mismatch is reported by validate_doc separately
        validator.check_numeric(doc)


def test_component_breakdown_null_chain_does_not_crash():
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"] = None
    errs = validator.check_numeric(doc)
    assert "sum(byTrustRing) 0 != totalContextTokens 100" in errs
    assert "sum(byType) 0 != totalContextTokens 100" in errs


def test_byTrustRing_and_byType_entry_null_does_not_crash():
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byTrustRing"]["ring0"] = None
    doc["sessionSummary"]["componentBreakdown"]["byType"]["systemPrompt"] = None
    errs = validator.check_numeric(doc)
    # ring0's 60 tokens are gone from the sum: 40 (ring1) != 100
    assert "sum(byTrustRing) 40 != totalContextTokens 100" in errs
    assert "sum(byType) 40 != totalContextTokens 100" in errs


# --- sweep: sibling validators in the same module --------------------------


def test_check_honesty_survives_top_level_nulls():
    doc = _doc()
    doc["findings"] = None
    doc["sessionSummary"] = None
    doc["contextComponents"] = [
        {"id": "c1", "notCollected": None, "sanitization": None, "source": None},
        {
            "id": "c2",
            "notCollected": ["source.serverChecksumVerified"],
            "sanitization": None,
            "source": None,
        },
    ]
    errs = validator.check_honesty(doc)
    assert "c2: security field 'source.serverChecksumVerified' not-collected but no missingControls entry" in errs


def test_check_honesty_audit_clean_blockers_null_is_treated_as_empty():
    """sessionSummary present, but auditCleanBlockers itself is null: this is
    the specific chain link `set(doc.get('sessionSummary', {}).get(
    'auditCleanBlockers', []))` used to crash on (set(None) raises)."""
    doc = _doc()
    doc["sessionSummary"]["auditCleanBlockers"] = None
    doc["sessionSummary"]["sessionAuditClean"] = True
    doc["contextComponents"] = [
        {"id": "c1", "notCollected": ["serverChecksumVerified"], "sanitization": {}, "source": {}},
    ]
    errs = validator.check_honesty(doc)
    assert "not-collected security field did not register an auditCleanBlocker" in errs


def test_check_crosswalk_survives_top_level_nulls():
    doc = _doc()
    doc["controlLayers"] = [{"layerId": "l1", "owaspCoverage": None, "agenticCoverage": None}]
    doc["findings"] = [{"id": "f1", "owaspRefs": None, "agenticRefs": None}]
    doc["metadata"] = None
    doc["schema"] = None
    errs = validator.check_crosswalk(doc)
    assert isinstance(errs, list)  # no crash; content is exercised elsewhere


def test_check_crosswalk_controllayers_and_findings_null_do_not_crash():
    doc = _doc()
    doc["controlLayers"] = None
    doc["findings"] = None
    validator.check_crosswalk(doc)


def test_check_crosswalk_catalogversions_and_entry_null_do_not_crash():
    doc = _doc()
    doc["catalogVersions"] = None
    validator.check_crosswalk(doc)
    doc2 = _doc()
    doc2["catalogVersions"]["owaspLlm"] = None
    validator.check_crosswalk(doc2)


def test_check_trust_tier_ring_survives_source_null():
    doc = _doc()
    doc["contextComponents"] = [
        {
            "id": "c1",
            "trustTier": "ring-1-derived",
            "trustRing": 1,
            "assembledAtTurn": 1,
            "source": None,
        }
    ]
    errs = validator.check_trust_tier_ring(doc)
    assert "c1: ring-1-derived requires a model-generated source.origin, got ''" in errs


def test_check_trust_tier_ring_survives_contextcomponents_null():
    """A null contextComponents is a wrong type, not an empty array: the
    contract reports it by name and checks nothing further, where the earlier
    `or []` guard read it as empty and said nothing at all."""
    doc = _doc()
    doc["contextComponents"] = None
    assert validator.check_trust_tier_ring(doc) == ["contextComponents None is not an array"]


def test_check_boundary_survives_metadata_session_turncount_null():
    for bad in (None, {"session": None}, {"session": {"turnCount": None}}):
        doc = _doc()
        doc["illustrative"] = True
        doc["metadata"] = bad
        # must not raise regardless of which link in the chain is null
        validator.check_boundary(doc)


def test_check_hash_binding_survives_contextcomponents_and_content_null(tmp_path):
    # check_hash_binding only reaches the content.sha256 chain when a content
    # file exists on disk for the component id, so the file must actually be
    # there or this test would pass without ever exercising the guard.
    (tmp_path / "c1.txt").write_bytes(b"payload")
    doc = _doc()
    doc["contextComponents"] = [{"id": "c1", "content": None}]
    # Two findings, not one: the null content is named as a wrong type, and the
    # binding it made impossible is still reported. Before, the null was read as
    # an empty object and only the second finding came back.
    assert validator.check_hash_binding(doc, tmp_path) == [
        "c1: content None is not an object",
        "c1: content.sha256 does not bind to " + str(tmp_path / "c1.txt"),
    ]
    doc2 = _doc()
    doc2["contextComponents"] = None
    assert validator.check_hash_binding(doc2, tmp_path) == ["contextComponents None is not an array"]


def test_count_verified_hash_bindings_survives_contextcomponents_and_content_null(tmp_path):
    doc = _doc()
    doc["contextComponents"] = [{"id": "c1", "content": None}]
    assert validator.count_verified_hash_bindings(doc, tmp_path) == 0
    doc2 = _doc()
    doc2["contextComponents"] = None
    assert validator.count_verified_hash_bindings(doc2, tmp_path) == 0


# --- check_all: a crash in an earlier check must not hide a later one ------


def test_check_all_survives_a_document_null_almost_everywhere():
    """Before the fix, check_honesty alone (which check_all runs before
    check_numeric) would crash on a null sessionSummary, so check_numeric's
    own findings never came back. This constructs a document where several
    top-level sections are null simultaneously and asserts check_all still
    returns a normal list of the resulting schema/accounting errors."""
    doc = _doc()
    doc["sessionSummary"] = None
    doc["findings"] = None
    doc["controlLayers"] = None
    doc["catalogVersions"] = None
    doc["contextComponents"][0]["content"] = None
    errs = validator.check_all(doc)
    assert isinstance(errs, list)
    assert any("cc-001: content None is not an object" in e for e in errs)


# ==========================================================================
# The malformed-input contract, in one place.
#
# Round 1 of this fix hand-copied `x.get(k) or {}` about twenty times. `or`
# catches only None, so every one of those sites still crashed on a truthy
# wrong-typed value, and the blind spot had to be fixed twenty times over.
# Round 2 routes every read through cxbom.validator._Reader's typed accessors,
# so the tests below pin the accessors' contract once and then drive the public
# entry point over the whole type matrix to prove nothing reads around them.
# ==========================================================================

# The values every field in the matrix below is driven to. Nine, not the twenty
# round 2 shipped, and the count is measured rather than argued:
#
#   - Seven of the twenty (None, True, 7, "x", [], [1], {}) carry the whole
#     shape story -- null, a bool, a number, a string, an empty array, an array
#     of the wrong element type, an object -- and killed all but one of the
#     mutants the twenty killed. Adding 10 ** 400 back, which is the only value
#     that reaches the unbounded-number arithmetic, made the two identical. The
#     other twelve bought no additional mutant kill at all, so they were volume,
#     not coverage. Round 3 cut them and re-measured; the count is in the
#     round 3 report.
#   - BIGGEST_JSON_INTEGER is the ninth and the opposite case. It is the one
#     value the twenty were MISSING: 10 ** 400 is 401 digits, one order of
#     magnitude short of the 4300-digit ceiling, so the matrix passed while a
#     4300-digit record crashed check_all. A matrix whose largest value sits
#     just under a limit is how a defect survives a sweep, so the value that
#     sits exactly ON the limit is now permanent.
#
# NaN, Infinity, the integral and non-integral floats, the numeric strings, the
# bool False and the zero are each covered by a named test of their own rather
# than by a cross-product cell; see test_number_rejects_nan_and_infinity_by_name,
# the _is_schema_integer parity probes, and the tokenCount tests above.
ALL_TYPES = [None, True, 7, "x", [], [1], {}, 10 ** 400, BIGGEST_JSON_INTEGER]


def _type_id(value):
    """A short parametrize id. repr() of a wide integer would put hundreds or
    thousands of characters into every test name it appears in."""
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 10 ** 20:
        return f"int-{len(str(abs(value)))}-digits"
    return repr(value)

ACCESSOR_EXPECTATIONS = [
    ("obj", "an object"),
    ("objs", "an array"),
    ("texts", "an array"),
    ("text", "a string"),
    ("integer", "an integer"),
    ("number", "a finite number"),
    ("flag", "a boolean"),
]


def _reader():
    errs = []
    return validator._Reader(errs), errs


def test_every_accessor_is_silent_on_an_absent_key():
    """An absent key is validate_doc's business (required-field enforcement).
    A sibling check that reported it too would put a second copy of every
    missing-field error in the list."""
    read, errs = _reader()
    assert read.obj({}, "k") == {}
    assert read.objs({}, "k") == []
    assert read.texts({}, "k") == []
    assert read.text({}, "k") is None
    assert read.integer({}, "k") is None
    assert read.number({}, "k") is None
    assert read.flag({}, "k") is None
    assert errs == []


@pytest.mark.parametrize("method,expected", ACCESSOR_EXPECTATIONS)
def test_every_accessor_reports_a_present_null(method, expected):
    """The original defect: a default covers an absent key, never a present
    null. Here null is a wrong type like any other and is named as one."""
    read, errs = _reader()
    getattr(read, method)({"k": None}, "k")
    assert errs == [f"k None is not {expected}"]


@pytest.mark.parametrize("method,expected", ACCESSOR_EXPECTATIONS)
@pytest.mark.parametrize("container", [None, 0, 7, "x", ["k"], True, float("nan")])
def test_every_accessor_reports_a_container_that_is_not_an_object(method, expected, container):
    """The systemic gap in `x.get(k) or {}`: a truthy container of the wrong
    type reached the next `.get` and raised AttributeError there."""
    read, errs = _reader()
    getattr(read, method)(container, "k")
    assert errs == [f"k is unreadable: {container!r} is not an object"]


@pytest.mark.parametrize("method,expected", ACCESSOR_EXPECTATIONS)
def test_every_accessor_names_the_label_it_was_given(method, expected):
    """A finding has to say which field it is about: the label the call site
    passes is what puts a component id or a nested path in the message."""
    bad = 9 if method == "text" else "wrong"
    read, errs = _reader()
    getattr(read, method)({"k": bad}, "k", "cc-009: deep.k")
    assert errs == [f"cc-009: deep.k {bad!r} is not {expected}"]


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_obj_returns_a_dict_for_every_json_type(value):
    read, errs = _reader()
    got = read.obj({"k": value}, "k")
    assert isinstance(got, dict)
    assert (got is value) == isinstance(value, dict)
    assert bool(errs) == (not isinstance(value, dict))


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_objs_returns_a_list_of_dicts_for_every_json_type(value):
    read, errs = _reader()
    got = read.objs({"k": value}, "k")
    assert isinstance(got, list)
    assert all(isinstance(x, tuple) and isinstance(x[0], int) and isinstance(x[1], dict) for x in got)
    assert bool(errs) == (not (isinstance(value, list) and all(isinstance(x, dict) for x in value)))


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_texts_returns_a_list_of_strings_for_every_json_type(value):
    read, errs = _reader()
    got = read.texts({"k": value}, "k")
    assert isinstance(got, list) and all(isinstance(x, str) for x in got)
    assert bool(errs) == (not (isinstance(value, list) and all(isinstance(x, str) for x in value)))


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_text_returns_a_string_or_none_for_every_json_type(value):
    read, errs = _reader()
    got = read.text({"k": value}, "k")
    assert got is None or isinstance(got, str)
    assert bool(errs) == (not isinstance(value, str))


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_flag_returns_a_bool_or_none_for_every_json_type(value):
    read, errs = _reader()
    got = read.flag({"k": value}, "k")
    assert got is None or isinstance(got, bool)
    assert bool(errs) == (not isinstance(value, bool))


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_integer_returns_something_arithmetic_accepts_for_every_json_type(value):
    """The point of the accessor: whatever comes back can be added, compared
    and summed. A bool must not come back, because True + 1 is 2."""
    read, errs = _reader()
    got = read.integer({"k": value}, "k")
    assert got is None or (isinstance(got, (int, float)) and not isinstance(got, bool))
    if got is not None:
        assert got + 1 > got  # arithmetic, the operation the site downstream performs


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_number_returns_something_decimal_can_round_for_every_json_type(value):
    read, errs = _reader()
    got = read.number({"k": value}, "k")
    assert got is None or (isinstance(got, (int, float)) and not isinstance(got, bool))
    if got is not None and abs(got) < 10 ** 20:
        assert validator._round2(got) is not None


def test_number_rejects_nan_and_infinity_by_name():
    """json.loads parses NaN and Infinity even though JSON has no literal for
    them, and decimal raises InvalidOperation rounding either."""
    read, errs = _reader()
    assert read.number({"k": float("nan")}, "k") is None
    assert read.number({"k": float("-inf")}, "k") is None
    assert errs == ["k nan is not a finite number", "k -inf is not a finite number"]


def test_text_accepts_null_only_where_the_schema_declares_it_nullable():
    """catalogVersions.<key>.releaseTag is typed ["string", "null"] by the
    schema, so a null there is a value the submission gate acts on, not a type
    fault. Every other string field must still report a null."""
    read, errs = _reader()
    assert read.text({"k": None}, "k", nullable=True) is None
    assert errs == []
    assert read.text({"k": 5}, "k", nullable=True) is None
    assert errs == ["k 5 is not a string"]


def test_objs_and_texts_report_the_offending_element_by_index_and_drop_it():
    read, errs = _reader()
    assert read.objs({"k": [{"a": 1}, 5, None]}, "k") == [(0, {"a": 1})]
    assert read.texts({"k": ["ok", [], None]}, "k") == ["ok"]
    assert errs == [
        "k[1] 5 is not an object",
        "k[2] None is not an object",
        "k[1] [] is not a string",
        "k[2] None is not a string",
    ]


def test_a_reader_writes_into_the_findings_list_it_was_given():
    """The accessors report into the same list the check function returns, so a
    shape fault and an invariant failure come back together rather than one
    hiding the other."""
    errs = ["pre-existing"]
    read = validator._Reader(errs)
    read.obj({"k": "no"}, "k")
    assert errs == ["pre-existing", "k 'no' is not an object"]


# --- _is_schema_integer / _is_schema_number against the live schema library --


JSONSCHEMA_PROBES = [
    60, 60.0, 60.5, -1, -1.0, 0, 0.0, True, False, "60", "60.0", None, [], {}, [60],
    float("nan"), float("inf"), 1e300, 2 ** 63, 2 ** 63 + 0.0,
]


@pytest.mark.parametrize("probe", JSONSCHEMA_PROBES, ids=_type_id)
def test_is_schema_integer_matches_jsonschema_itself(probe):
    """Not assumed: compared against a live Draft7Validator. This is round 1's
    verified behaviour and must survive round 2 -- 60.0 accepted because the
    schema accepts it, True rejected because the schema rejects it even though
    isinstance(True, int) is True."""
    from jsonschema import Draft7Validator

    schema_says = Draft7Validator({"type": "integer"}).is_valid(probe)
    assert validator._is_schema_integer(probe) is schema_says, probe


@pytest.mark.parametrize("probe", JSONSCHEMA_PROBES, ids=_type_id)
def test_is_schema_number_matches_jsonschema_except_for_the_non_finite(probe):
    """_is_schema_number is jsonschema's "number" minus NaN and Infinity, which
    the library accepts as floats and decimal cannot round. Any other
    divergence would mean this module is stricter than the schema it enforces,
    and a schema-valid record would gain an error it must not have."""
    from jsonschema import Draft7Validator

    schema_says = Draft7Validator({"type": "number"}).is_valid(probe)
    non_finite = isinstance(probe, float) and not math.isfinite(probe)
    assert validator._is_schema_number(probe) is (schema_says and not non_finite), probe


# ==========================================================================
# Driven from the public entry point.
#
# check_all is the function cxbom/assembly.py calls in production and the CLI's
# main() calls on a file. Closing a function is not closing a contract, so the
# matrix below mutates every field these checks read, to every JSON type, and
# requires check_all to come back with a list of strings each time.
# ==========================================================================

# Every field cxbom/validator.py reads, addressed as it sits in the fixture.
MATRIX_PATHS = [
    "specVersion",
    "illustrative",
    "metadata",
    "metadata.session",
    "metadata.session.turnCount",
    "metadata.session.contextWindowTokensUsed",
    "metadata.generatedBy",
    "metadata.generatedBy.schema",
    "contextComponents",
    "contextComponents[0]",
    "contextComponents[0].id",
    "contextComponents[0].trustTier",
    "contextComponents[0].trustRing",
    "contextComponents[0].assembledAtTurn",
    "contextComponents[0].content",
    "contextComponents[0].content.sha256",
    "contextComponents[0].content.tokenCount",
    "contextComponents[0].content.contextualSharePercent",
    "contextComponents[0].sanitization",
    "contextComponents[0].source",
    "contextComponents[0].source.origin",
    "contextComponents[0].source.serverChecksumVerified",
    "contextComponents[0].source.serverOperatorIdentityVerified",
    "contextComponents[1].notCollected",
    "contextComponents[1].notCollected[0]",
    "contextComponents[1].sanitization.missingControls",
    "contextComponents[1].sanitization.missingControls[0]",
    "controlLayers",
    "controlLayers[0]",
    "controlLayers[0].layerId",
    "controlLayers[0].owaspCoverage",
    "controlLayers[0].owaspCoverage[0]",
    "controlLayers[0].agenticCoverage",
    "controlLayers[0].agenticCoverage[0]",
    "findings",
    "findings[0]",
    "findings[0].id",
    "findings[0].status",
    "findings[0].owaspRefs",
    "findings[0].owaspRefs[0]",
    "findings[0].agenticRefs",
    "findings[0].cweRef",
    "findings[0].formalRef",
    "sessionSummary",
    "sessionSummary.totalContextTokens",
    "sessionSummary.templateOverheadTokens",
    "sessionSummary.sessionAuditClean",
    "sessionSummary.auditCleanBlockers",
    "sessionSummary.auditCleanBlockers[0]",
    "sessionSummary.componentBreakdown",
    "sessionSummary.componentBreakdown.byTrustRing",
    "sessionSummary.componentBreakdown.byTrustRing.ring0",
    "sessionSummary.componentBreakdown.byTrustRing.ring0.tokens",
    "sessionSummary.componentBreakdown.byType",
    "sessionSummary.componentBreakdown.byType.systemPrompt",
    "sessionSummary.componentBreakdown.byType.systemPrompt.tokens",
    "schema",
    "schema.cxbomVersion",
    "catalogVersions",
    "catalogVersions.owaspLlm",
    "catalogVersions.owaspLlm.contentHash",
    "catalogVersions.owaspLlm.releaseTag",
    "catalogVersions.owaspLlm.released",
]

# Two fields the validator reads that the minimal fixture legitimately omits;
# every other path above must already resolve in it, or the matrix would be
# silently testing a key nothing reads.
PATHS_ABSENT_FROM_THE_FIXTURE = {
    "contextComponents[0].source.serverChecksumVerified",
    "contextComponents[0].source.serverOperatorIdentityVerified",
}


def _tokens(path):
    out = []
    for part in path.split("."):
        name, _, rest = part.partition("[")
        out.append(name)
        out.extend(int(i) for i in re.findall(r"(\d+)\]", rest))
    return out


def _set(doc, path, value):
    """Set the fixture path to value. The parent chain must already exist, so a
    typo in MATRIX_PATHS raises here instead of quietly testing nothing."""
    node = doc
    tokens = _tokens(path)
    for tok in tokens[:-1]:
        node = node[tok]
    node[tokens[-1]] = value


def _delete(doc, path):
    node = doc
    tokens = _tokens(path)
    for tok in tokens[:-1]:
        node = node[tok]
    del node[tokens[-1]]


def _get(doc, path):
    node = doc
    for tok in _tokens(path):
        node = node[tok]
    return node


def test_every_matrix_path_resolves_in_the_fixture():
    """Anti-vacuity guard for the matrix below: a path that does not resolve
    would make every one of its cases pass without exercising anything."""
    for path in MATRIX_PATHS:
        doc = _doc()
        if path in PATHS_ABSENT_FROM_THE_FIXTURE:
            _set(doc, path, "canary")  # parent chain must still resolve
        assert _get(doc, path) is not None or path in PATHS_ABSENT_FROM_THE_FIXTURE
        _set(doc, path, "canary-value")
        assert _get(doc, path) == "canary-value"


@pytest.mark.parametrize("path", MATRIX_PATHS)
@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_check_all_never_raises_for_any_wrong_type_at_any_field(path, value):
    """Named for what it checks. It asserts that check_all RETURNED -- a list of
    strings -- not that the fault was reported, and the distinction matters: the
    old name ("reports every wrong type") promised a reader more than the body
    delivers. Non-raising is the module's stated contract and this is the widest
    proof of it; the messages themselves are pinned one field at a time by the
    named tests further down."""
    doc = _doc()
    _set(doc, path, value)
    errs = validator.check_all(doc)
    assert isinstance(errs, list) and all(isinstance(e, str) for e in errs)


@pytest.mark.parametrize("path", MATRIX_PATHS)
def test_check_all_survives_every_field_being_absent(path):
    doc = _doc()
    if path in PATHS_ABSENT_FROM_THE_FIXTURE:
        return
    _delete(doc, path)
    errs = validator.check_all(doc)
    assert isinstance(errs, list) and all(isinstance(e, str) for e in errs)


@pytest.mark.parametrize("path", [p for p in MATRIX_PATHS if p.startswith("catalogVersions")])
@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_submission_mode_reports_every_wrong_type_in_a_catalog_pin(path, value):
    """The submission gate reads releaseTag and released, which nothing else
    reads, so the matrix has to drive it with submission_mode=True as well."""
    doc = _doc()
    _set(doc, path, value)
    errs = validator.check_all(doc, submission_mode=True)
    assert isinstance(errs, list) and all(isinstance(e, str) for e in errs)


@pytest.mark.parametrize("doc", [None, [], [1, 2], "a record", 7, True, {}], ids=_type_id)
def test_check_all_returns_findings_for_a_document_that_is_not_an_object(doc):
    """check_all's annotation says dict; main() hands it whatever the file
    parsed to. A list or a string at the top level is malformed input to
    report, not an AttributeError to raise out of the CLI."""
    errs = validator.check_all(doc)
    assert isinstance(errs, list) and errs and all(isinstance(e, str) for e in errs)


@pytest.mark.parametrize("value", ALL_TYPES, ids=_type_id)
def test_hash_binding_entry_points_survive_every_wrong_type(value, tmp_path):
    """check_hash_binding and count_verified_hash_bindings take a content_dir
    and so sit outside check_all, but they are public and they read the same
    components."""
    (tmp_path / "cc-001.txt").write_bytes(b"payload")
    for path in ("contextComponents", "contextComponents[0]", "contextComponents[0].id",
                 "contextComponents[0].content", "contextComponents[0].content.sha256"):
        doc = _doc()
        _set(doc, path, value)
        errs = validator.check_hash_binding(doc, tmp_path)
        assert isinstance(errs, list) and all(isinstance(e, str) for e in errs)
        assert isinstance(validator.count_verified_hash_bindings(doc, tmp_path), int)


def test_check_all_survives_a_record_nested_deeper_than_the_recursion_limit():
    """_iter_strings and _iter_keys used to recurse once per level, so a record
    nested a thousand deep raised RecursionError out of check_numeric and
    check_boundary -- reachable through check_all, and a crash rather than a
    report. json.loads on CPython 3.14 parses such a record happily, so the walks
    must survive it. Built with _nested so 3.10 and 3.12 test the walks too."""
    deep = _nested(4000, "leaf")
    doc = _doc()
    doc["metadata"]["session"]["turnCount"] = 5
    doc["sessionSummary"]["riskRationale"] = deep  # an object where a string belongs, 4000 levels of it
    errs = validator.check_all(doc)
    assert isinstance(errs, list) and all(isinstance(e, str) for e in errs)


def test_the_boundary_walks_still_report_in_document_order():
    """Both walks became iterative; an iterative walk that reversed the order
    would reorder every boundary finding. The paths pin the order."""
    doc = _doc()
    doc["illustrative"] = True
    doc["metadata"]["session"]["turnCount"] = 5
    doc["trustModel"]["description"] = "attention shifts across turns"
    doc["sessionSummary"]["riskRationale"] = "share grows over turns"
    errs = validator.check_boundary(doc)
    assert [e.split()[2] for e in errs] == ["$.trustModel.description", "$.sessionSummary.riskRationale"]


def test_the_key_walk_still_finds_a_share_trend_key_in_document_order():
    """Ordered, not a membership test. The two keys are deliberately nested --
    sharePerTurn sits inside shareDelta -- which is exactly the relationship a
    post-order walk reverses, and a membership assertion cannot tell the two
    apart. Round 2's report claimed this walk's order was pinned by tests; it
    was not, and a mutant that yielded each key after its own value survived the
    whole suite."""
    doc = _doc()
    doc["illustrative"] = True
    doc["metadata"]["session"]["turnCount"] = 5
    doc["contextComponents"][0]["content"]["shareDelta"] = {"nested": {"sharePerTurn": 1}}
    errs = validator.check_boundary(doc)
    assert errs == [
        "boundary violation: forbidden per-turn share-trend structure key 'shareDelta'",
        "boundary violation: forbidden per-turn share-trend structure key 'sharePerTurn'",
    ]


# ==========================================================================
# Each finding the round-1 review reproduced, pinned with the message it must
# now produce. Every expected string here is authored from the fixture's known
# values, never copied from the code's own expression.
# ==========================================================================


def test_non_numeric_total_is_reported_instead_of_crashing_the_arithmetic():
    """`total + overhead` and `tc / total` ran on a value no guard had looked
    at: a string totalContextTokens raised TypeError out of check_all."""
    doc = _doc()
    doc["sessionSummary"]["totalContextTokens"] = "100"
    errs = validator.check_numeric(doc)
    assert "totalContextTokens '100' is not an integer" in errs
    assert "totalContextTokens None != sum(component tokenCount) 100" in errs


def test_non_numeric_overhead_is_reported_instead_of_crashing_the_arithmetic():
    doc = _doc()
    doc["sessionSummary"]["templateOverheadTokens"] = [10]
    errs = validator.check_numeric(doc)
    assert "templateOverheadTokens [10] is not an integer" in errs
    # the sum invariant that does not need overhead still ran
    assert not any("!= sum(component tokenCount)" in e for e in errs)


def test_non_numeric_share_is_reported_instead_of_raising_from_decimal():
    """contextualSharePercent went straight into decimal.Decimal(str(x)),
    which raises decimal.InvalidOperation on a non-numeric string."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["contextualSharePercent"] = "sixty"
    errs = validator.check_numeric(doc)
    assert "cc-001: contextualSharePercent 'sixty' is not a finite number" in errs


def test_a_share_too_large_to_round_is_reported_not_raised():
    """A JSON integer has no upper bound and jsonschema calls 10**400 an
    integer, so the share arithmetic must survive one: float division raises
    OverflowError and decimal.quantize raises InvalidOperation."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = 10 ** 400
    errs = validator.check_numeric(doc)
    assert any("too large to compare" in e for e in errs)
    assert any("!= sum(component tokenCount)" in e for e in errs)


def test_breakdown_tokens_null_is_reported_not_summed():
    """The original defect shape one level down: `.get("tokens", 0)` covers an
    absent key, so a present-but-null tokens reached sum() as None."""
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byTrustRing"]["ring0"]["tokens"] = None
    errs = validator.check_numeric(doc)
    assert "componentBreakdown.byTrustRing.ring0: tokens None is not an integer" in errs
    assert "sum(byTrustRing) 40 != totalContextTokens 100" in errs


def test_breakdown_tokens_string_is_reported_not_summed():
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byType"]["systemPrompt"]["tokens"] = "60"
    errs = validator.check_numeric(doc)
    assert "componentBreakdown.byType.systemPrompt: tokens '60' is not an integer" in errs
    assert "sum(byType) 40 != totalContextTokens 100" in errs


def test_byTrustRing_null_alone_is_reported_and_does_not_touch_byType():
    """Round 1's mutation testing found this guard unverified: no test nulled
    byTrustRing on its own, so reverting the guard kept every test passing."""
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byTrustRing"] = None
    errs = validator.check_numeric(doc)
    assert "componentBreakdown.byTrustRing None is not an object" in errs
    assert "sum(byTrustRing) 0 != totalContextTokens 100" in errs
    assert not any("byType" in e for e in errs)


def test_byType_null_alone_is_reported_and_does_not_touch_byTrustRing():
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byType"] = None
    errs = validator.check_numeric(doc)
    assert "componentBreakdown.byType None is not an object" in errs
    assert "sum(byType) 0 != totalContextTokens 100" in errs
    assert not any("byTrustRing" in e for e in errs)


def test_a_bucket_that_is_not_an_object_is_reported_by_name():
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byTrustRing"]["ring1"] = 40
    errs = validator.check_numeric(doc)
    assert "componentBreakdown.byTrustRing.ring1 40 is not an object" in errs
    assert "sum(byTrustRing) 60 != totalContextTokens 100" in errs


def test_a_finding_without_an_id_does_not_raise_through_check_all():
    """check_honesty built a set of open findings' ids with a raw f["id"]
    subscript, so an open finding with no id raised KeyError and lost every
    other finding in the record. The set was never read by anything."""
    doc = _doc()
    del doc["findings"][0]["id"]
    errs = validator.check_all(doc)
    assert isinstance(errs, list)
    assert any("'id' is a required property" in e for e in errs)


def test_a_component_without_an_id_does_not_raise_from_the_hash_binding_checks(tmp_path):
    """Both functions built a filename from a raw c['id'] subscript. A
    component with no id names no file: in particular it must not be bound to a
    file called None.txt, which is what interpolating the missing id into the
    filename would reach for."""
    (tmp_path / "cc-001.txt").write_bytes(b"payload")
    (tmp_path / "None.txt").write_bytes(b"payload")
    # Two documents, because the two functions fail the other way round: a
    # binding check would report a MISMATCH against None.txt, and a verification
    # count would count a MATCH against it.
    mismatch = _doc()
    del mismatch["contextComponents"][0]["id"]
    assert validator.check_hash_binding(mismatch, tmp_path) == []
    match = _doc()
    del match["contextComponents"][0]["id"]
    match["contextComponents"][0]["content"]["sha256"] = hashlib.sha256(b"payload").hexdigest()
    assert validator.count_verified_hash_bindings(match, tmp_path) == 0


def test_a_component_with_an_unusable_id_is_named_by_its_position():
    """A finding has to be traceable to a component. When the id is the wrong
    type there is no name to use, so the position in the array is the name."""
    doc = _doc()
    doc["contextComponents"][0]["id"] = ["cc-001"]
    doc["contextComponents"][0]["content"]["tokenCount"] = None
    errs = validator.check_numeric(doc)
    assert "contextComponents[0]: id ['cc-001'] is not a string" in errs
    assert "contextComponents[0]: tokenCount None is not an integer" in errs


def test_an_unhashable_trust_tier_is_reported_not_raised():
    """`tier in _TIER_RING` on a list raises TypeError: unhashable type."""
    doc = _doc()
    doc["contextComponents"][0]["trustTier"] = ["operator"]
    errs = validator.check_trust_tier_ring(doc)
    assert errs == ["cc-001: trustTier ['operator'] is not a string"]


def test_a_non_numeric_turn_count_is_reported_not_compared():
    """`turn_count <= 1` on a numeric string raises TypeError; `or 1` never
    caught it because "5" is truthy."""
    doc = _doc()
    doc["illustrative"] = True
    doc["metadata"]["session"]["turnCount"] = "5"
    errs = validator.check_boundary(doc)
    assert errs == ["metadata.session.turnCount '5' is not an integer"]


def test_assembled_at_turn_true_no_longer_passes_as_turn_one():
    """isinstance(True, int) is True in Python, so `isinstance(atn, int) and
    atn > 0` read assembledAtTurn: true as a valid turn 1 and let a malformed
    record validate as clean. This is the trap _is_schema_integer exists to
    avoid, three functions from where round 1 applied it."""
    doc = _doc()
    doc["contextComponents"] = [{
        "id": "cc-009", "trustTier": "ring-1-derived", "trustRing": 1,
        "assembledAtTurn": True, "source": {"origin": "model"},
    }]
    errs = validator.check_trust_tier_ring(doc)
    assert "cc-009: assembledAtTurn True is not an integer" in errs
    assert "cc-009: ring-1-derived requires assembledAtTurn > 0 (re-entrant model content)" in errs


def test_a_non_string_content_hash_is_reported_not_sliced():
    """ch[:12] in the error message crashed on a non-string contentHash: the
    reporter of a malformed record raising inside its own report."""
    doc = _doc()
    doc["catalogVersions"]["owaspLlm"]["contentHash"] = 12345
    errs = validator.check_crosswalk(doc)
    assert errs == ["catalogVersions.owaspLlm.contentHash 12345 is not a string"]


def test_a_mismatched_content_hash_still_reports_its_first_twelve_characters():
    """The other half of the slice: a string hash that does not match must
    still be reported the way it always was."""
    doc = _doc()
    doc["catalogVersions"]["owaspLlm"]["contentHash"] = "0" * 64
    errs = validator.check_crosswalk(doc)
    assert any(e.startswith("catalogVersions.owaspLlm.contentHash 000000000000 != snapshot ") for e in errs)


def test_not_collected_wrong_types_are_reported_not_iterated():
    doc = _doc()
    doc["contextComponents"][1]["notCollected"] = 5
    assert "cc-002: notCollected 5 is not an array" in validator.check_honesty(doc)
    doc2 = _doc()
    doc2["contextComponents"][1]["notCollected"] = [5, None]
    errs = validator.check_honesty(doc2)
    assert "cc-002: notCollected[0] 5 is not a string" in errs
    assert "cc-002: notCollected[1] None is not a string" in errs


def test_audit_clean_blockers_wrong_type_is_reported_not_set():
    doc = _doc()
    doc["sessionSummary"]["auditCleanBlockers"] = 5
    assert "auditCleanBlockers 5 is not an array" in validator.check_honesty(doc)


def test_an_unhashable_coverage_code_is_reported_not_looked_up():
    """`code not in llm` on a dict raises TypeError: unhashable type. The
    round-1 review's inventory did not name this one; the accessor closes it
    with the rest of the class."""
    doc = _doc()
    doc["controlLayers"][0]["owaspCoverage"] = [{"code": "LLM01"}]
    errs = validator.check_crosswalk(doc)
    assert "controlLayer tool-execution: owaspCoverage[0] {'code': 'LLM01'} is not a string" in errs


def test_an_unhashable_cwe_ref_is_reported_not_looked_up():
    doc = _doc()
    doc["findings"][0]["cweRef"] = {"id": "CWE-345"}
    errs = validator.check_crosswalk(doc)
    assert "finding finding-001: cweRef {'id': 'CWE-345'} is not a string" in errs


@pytest.mark.parametrize("wrong", ["oops", 5, [1], True], ids=_type_id)
def test_a_wrong_typed_container_is_reported_where_or_only_caught_null(wrong):
    """The systemic finding: `x.get(k) or {}` caught None and nothing else, so
    a truthy wrong-typed container crashed at the next .get with
    AttributeError. Session summary is one of nine such containers."""
    doc = _doc()
    doc["sessionSummary"] = wrong
    errs = validator.check_numeric(doc)
    assert f"sessionSummary {wrong!r} is not an object" in errs
    doc2 = _doc()
    doc2["metadata"]["session"] = wrong
    errs2 = validator.check_numeric(doc2)
    assert f"metadata.session {wrong!r} is not an object" in errs2


def test_a_non_object_component_is_reported_by_index_and_skipped():
    doc = _doc()
    doc["contextComponents"][1] = 40
    errs = validator.check_numeric(doc)
    assert "contextComponents[1] 40 is not an object" in errs
    assert "totalContextTokens 100 != sum(component tokenCount) 60" in errs


def test_a_non_boolean_illustrative_is_reported_and_stops_the_boundary_check():
    """A truthy non-boolean used to enable the boundary scan. The record cannot
    say whether it is illustrative, so the scan does not run and the type is
    reported instead."""
    doc = _doc()
    doc["illustrative"] = "yes"
    assert validator.check_boundary(doc) == ["illustrative 'yes' is not a boolean"]


def test_submission_mode_still_gates_on_a_schema_nullable_release_tag():
    """releaseTag is typed ["string", "null"]: a null is schema-valid and must
    reach the gate as a value, not be reported as a wrong type."""
    doc = _doc()
    doc["catalogVersions"]["owaspLlm"]["releaseTag"] = None
    errs = validator.check_crosswalk(doc, submission_mode=True)
    assert errs == ["submission-mode: catalogVersions.owaspLlm is not an official release (releaseTag=None)"]
    assert validator.check_all(_doc(), submission_mode=True) == []


def test_a_component_id_that_names_a_directory_does_not_raise(tmp_path):
    """Instance N+1, found by hunting after the accessor fix landed: the
    accessors guarantee the id is a string, and a string id still made
    read_bytes() raise IsADirectoryError when the content dir held a directory
    of that name. exists() was the wrong question; is_file() is the right one."""
    (tmp_path / "cc-001.txt").mkdir()
    doc = _doc()
    assert validator.check_hash_binding(doc, tmp_path) == []
    assert validator.count_verified_hash_bindings(doc, tmp_path) == 0


# ==========================================================================
# Round 3. Reporting a value is as much a part of the contract as reading one:
# round 1 fixed the reported line and left the class, round 2 fixed the values
# and then the walk, and left the FORMATTING of the values. Everything below
# pins the third level.
# ==========================================================================


def test_show_is_repr_for_every_value_repr_can_render():
    """_show sits in every finding message, so it must not move any of them: it
    is repr, exactly, up to the width at which repr stops working."""
    for value in (None, True, False, 0, 7, -3, 7.0, 7.5, "", "x", [], [1], [None],
                  {}, {"a": 1}, float("nan"), float("inf"), 10 ** 400,
                  BIGGEST_JSON_INTEGER):
        assert validator._show(value) == repr(value), value


def test_show_describes_an_integer_too_wide_for_the_interpreter_to_render():
    """4300 digits renders; 4301 raises ValueError out of repr itself. The digit
    count comes from bit_length, so it is approximate by one and the message
    says so."""
    assert validator._show(10 ** 4299) == repr(10 ** 4299)          # 4300 digits
    assert validator._show(10 ** 4300) == "<an integer of about 4301 digits>"
    assert validator._show(-(10 ** 4300)) == "<a negative integer of about 4301 digits>"
    with pytest.raises(ValueError):
        repr(10 ** 4300)                                            # the thing being absorbed


def test_a_4300_digit_token_count_is_reported_through_check_all_not_raised():
    """Instance N+5. int.__str__ is not an ArithmeticError, so the guards round 2
    put on the arithmetic did not cover the f-string that reports the result.
    A 4300-digit tokenCount is schema-valid, parses, passes validate_doc, and
    summed to 4301 digits -- one digit past what repr will render."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = BIGGEST_JSON_INTEGER
    errs = validator.check_all(doc)
    # 4301 because the fixture's other component carries 40 tokens and the carry
    # takes 4300 nines to 4301 digits. Counted from the fixture, not from _show.
    assert ("totalContextTokens 100 != sum(component tokenCount)"
            " <an integer of about 4301 digits>") in errs


def test_a_4300_digit_ring_bucket_is_reported_not_raised():
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byTrustRing"]["ring0"]["tokens"] = BIGGEST_JSON_INTEGER
    errs = validator.check_numeric(doc)
    assert ("sum(byTrustRing) <an integer of about 4301 digits>"
            " != totalContextTokens 100") in errs


def test_a_4300_digit_type_bucket_is_reported_not_raised():
    """The third site. The review named two lines; byType's sum formats the same
    way byTrustRing's does and crashed identically."""
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byType"]["systemPrompt"]["tokens"] = BIGGEST_JSON_INTEGER
    errs = validator.check_numeric(doc)
    assert ("sum(byType) <an integer of about 4301 digits>"
            " != totalContextTokens 100") in errs


def test_a_4300_digit_token_count_is_reported_by_the_cli_not_raised(tmp_path):
    """The same record through the CLI, which is the path an operator and
    cxbom/assembly.py both take. Round 2 exited 1 with a traceback on stderr,
    which is a crash reported as a failure, not a finding."""
    doc = _doc()
    doc["contextComponents"][0]["content"]["tokenCount"] = BIGGEST_JSON_INTEGER
    path = tmp_path / "bigint.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "cxbom.validator", str(path)],
                          capture_output=True, text=True, timeout=300, cwd=str(ROOT))
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr, proc.stderr
    assert "ValueError" not in proc.stderr, proc.stderr
    assert "<an integer of about 4301 digits>" in proc.stdout


@pytest.mark.parametrize("doc, expected", [
    ({"sessionSummary": [10 ** 5000]}, "sessionSummary [<an integer of about 5001 digits>] is not an object"),
    ({"contextComponents": {"a": 10 ** 5000}},
     "contextComponents {'a': <an integer of about 5001 digits>} is not an array"),
    ([10 ** 5000], "is unreadable: [<an integer of about 5001 digits>] is not an object"),
])
def test_a_container_holding_an_unprintable_integer_is_reported(doc, expected):
    """repr() of a container raises the same ValueError as the integer inside
    it, and _show used to treat the container as the integer and call
    .bit_length() on it. It now renders every element by its type."""
    errs = validator.check_all(doc)
    assert any(expected in e for e in errs), errs


class _HostileInt(int):
    def __repr__(self):
        raise KeyError("repr")

    def __format__(self, spec):
        raise KeyError("format")


class _HostileStr(str):
    def __repr__(self):
        raise KeyError("repr")

    __hash__ = str.__hash__


class _HostileList(list):
    def __iter__(self):
        raise KeyError("iter")

    def __len__(self):
        raise KeyError("len")


class _HostileDict(dict):
    def items(self):
        raise KeyError("items")

    def __iter__(self):
        raise KeyError("iter")


class _HostileRepr:
    def __repr__(self):
        raise RuntimeError("no")


HOSTILE = [_HostileInt(5), _HostileStr("x"), _HostileList([1]), _HostileDict(a=1), _HostileRepr()]


@pytest.mark.parametrize("value", HOSTILE, ids=lambda v: type(v).__name__)
def test_show_renders_by_exact_type_and_runs_no_code_the_value_supplies(value):
    """isinstance admitted a subclass, whose __repr__, __iter__ or items() is
    arbitrary code. _show now matches exact builtin types and gives every other
    type a fixed placeholder, alone, inside a container, and as a dict key."""
    other = validator._SHOW_OTHER
    assert validator._show(value) == other
    assert validator._show([1, value]) == f"[1, {other}]"
    assert validator._show({"k": value}) == f"{{'k': {other}}}"
    assert validator._show({_HostileStr("k"): 1}) == f"{{{other}: 1}}"


@pytest.mark.parametrize("value", HOSTILE, ids=lambda v: type(v).__name__)
def test_check_all_refuses_a_constructed_record_holding_a_hostile_subclass(value):
    """jsonschema interpolates a value with repr() and the checks format,
    iterate and compare values, so a subclass that raises there raised out of
    check_all. A document holding any type json.loads cannot produce is now
    refused, with its path, before any check runs."""
    doc = _doc()
    doc["sessionSummary"]["totalContextTokens"] = value
    assert validator.check_all(doc) == [
        "the document holds a value of a type JSON cannot produce, at $.sessionSummary.totalContextTokens,"
        " so no other check ran on it"]


def test_check_all_refuses_a_hostile_key_and_a_hostile_top_level():
    doc = _doc()
    doc["metadata"][_HostileStr("k")] = 1
    assert validator.check_all(doc) == [
        "the document holds a value of a type JSON cannot produce, at $.metadata (a key), so no other check ran on it"]
    assert validator.check_all(_HostileDict(a=1)) == [
        "the document holds a value of a type JSON cannot produce, at $, so no other check ran on it"]


def test_the_json_type_check_passes_every_parsed_record_and_a_shared_subtree():
    """json.loads only produces the allowed types, so a record from disk never
    trips the refusal. A subtree reached twice is checked once and not refused.
    The deep case is built with _nested, the value 3.14's json.loads returns."""
    assert validator._foreign_value(_doc()) is None
    shared = {"a": [1, 2]}
    assert validator._foreign_value({"x": shared, "y": shared}) is None
    assert validator._foreign_value(_nested(100_000, 1)) is None


def test_show_renders_a_self_referential_container_as_repr_does():
    loop = [1]
    loop.append(loop)
    ring = {"a": 1}
    ring["self"] = ring
    assert validator._show(loop) == repr(loop) == "[1, [...]]"
    assert validator._show(((1,), ())) == repr(((1,), ())) == "((1,), ())"
    assert validator._show(ring) == repr(ring)


def test_show_caps_a_long_value_and_keeps_a_4300_digit_one_whole():
    assert validator._show("y" * 1_000_000) == "'" + "y" * 9_999 + " ... (truncated)"
    assert validator._show([BIGGEST_JSON_INTEGER]) == "[" + "9" * 4300 + "]"


def test_round2_returns_none_for_a_number_too_wide_to_stringify():
    """_round2 converts through str() on purpose (Decimal(0.1) would carry the
    whole binary expansion), and str() of a wide integer raises ValueError, not
    an ArithmeticError, so the existing guard did not cover it."""
    assert validator._round2(10 ** 5000) is None
    assert validator._round2(60.0) == decimal.Decimal("60.00")


def test_validate_doc_reports_a_value_jsonschema_itself_cannot_render():
    """Instance N+6, found by hunting the same class one layer out. jsonschema
    builds every error message eagerly and interpolates the offending value with
    repr(), so a wide integer raises ValueError inside the library before any
    error object reaches this module -- which means guarding this module's own
    f-strings does not close it. json.loads caps a literal at 4300 digits, so
    only a constructed document gets there, and cxbom/assembly.py hands
    check_all a document it constructed."""
    doc = _doc()
    doc["specVersion"] = 10 ** 5000
    errs = validator.validate_doc(doc)
    assert len(errs) == 1 and errs[0].startswith("the document cannot be schema-checked: ")
    assert isinstance(validator.check_all(doc), list)


# --- the walks are bounded, and bounded the right way ----------------------


def test_a_self_referential_document_is_reported_inside_a_bound():
    """Round 2 traded a bounded crash for an unbounded hang: round 1's recursive
    walks raised RecursionError on a cycle, the iterative ones spun past two
    million strings. json.loads cannot build a cycle, but check_all is public and
    cxbom/assembly.py hands it a dict that module constructed, and a hang inside
    a build is the worse of the two failures."""
    cycle = {"a": "leaf"}
    cycle["self"] = cycle
    doc = _doc()
    doc["illustrative"] = True
    doc["metadata"]["session"]["turnCount"] = 5
    doc["sessionSummary"]["riskRationale"] = cycle
    started = time.monotonic()
    errs = validator.check_all(doc)
    # The real assertion is the two findings below: an unbounded walk never
    # returns, so it hangs here rather than failing. The clock is a loose
    # backstop deliberately -- a tight one would flake on a loaded machine while
    # adding nothing, since the bounded walk returns in milliseconds.
    assert time.monotonic() - started < 120
    assert ("the document refers back into itself at $.sessionSummary.riskRationale.self:"
            " the string walk stopped there instead of looping") in errs
    assert ("the document refers back into itself:"
            " the key walk stopped there instead of looping") in errs


def test_a_cycle_is_caught_by_ancestry_and_not_by_having_been_seen_before():
    """The bound is a set of the containers on the path to the current node, not
    a set of every container already visited. The difference is observable: two
    parents may legitimately share one child, and a global seen-set would walk
    that subtree once and silently stop looking the second time -- a fail-open
    boundary scan, which is the opposite of what this check is for."""
    shared = {"description": "attention shifts across turns"}
    doc = _doc()
    doc["illustrative"] = True
    doc["metadata"]["session"]["turnCount"] = 5
    doc["trustModel"]["first"] = shared
    doc["trustModel"]["second"] = shared
    errs = validator.check_boundary(doc)
    assert [e.split()[2] for e in errs] == ["$.trustModel.first.description",
                                            "$.trustModel.second.description"]


def test_a_walk_that_reaches_the_node_ceiling_says_so():
    """The second bound, for the shape cycle detection does not cover: an acyclic
    document whose shared subtrees multiply the number of PATHS exponentially.
    Forty levels of two-way sharing is 2**40 paths over 41 distinct nodes, so no
    node is ever its own ancestor and only the ceiling stops it."""
    node = {"s": "x"}
    for _ in range(40):
        node = {"p": node, "q": node}
    errs = []
    walked = sum(1 for _ in validator._iter_strings(node, errs))
    assert walked < validator._WALK_BUDGET
    assert errs == [validator._WALK_TRUNCATED]


def test_the_widest_documents_the_round_2_sweep_probed_still_walk_in_full():
    """Anti-regression on the ceiling. A bound added to stop a hang must not
    newly truncate a document that used to be walked, and the widest one the
    round 2 crash sweep drove through clean held 200,000 keys."""
    wide = {f"k{i}": "v" for i in range(200000)}
    errs = []
    assert sum(1 for _ in validator._iter_strings(wide, errs)) == 200000
    assert errs == []
    key_errs = []
    assert sum(1 for _ in validator._iter_keys(wide, key_errs)) == 200000
    assert key_errs == []


def test_a_truncated_walk_reports_into_the_callers_own_findings_list():
    """The walks take the caller's list because a generator has no other way to
    say it stopped early, and a check that quietly stopped looking is fail-open."""
    node = {"s": "x"}
    for _ in range(40):
        node = {"p": node, "q": node}
    doc = _doc()
    doc["sessionSummary"]["riskRationale"] = node
    assert validator._WALK_TRUNCATED in validator.check_numeric(doc)


# --- a dropped element must not renumber the ones after it -----------------


def test_objs_returns_the_index_each_element_has_in_the_record():
    read, errs = _reader()
    assert read.objs({"k": [5, {"a": 1}, None, {"b": 2}]}, "k") == [(1, {"a": 1}), (3, {"b": 2})]
    assert errs == ["k[0] 5 is not an object", "k[2] None is not an object"]


def test_a_dropped_non_object_element_does_not_renumber_the_ones_after_it():
    """objs() filtered the array and every caller enumerate()d the survivors, so
    with contextComponents: [5, {...}] the dropped scalar and the object AFTER it
    were both labelled contextComponents[0]. A fail-closed validator whose report
    names the wrong array element sends its reader to the wrong place. New in
    round 2, because round 1 crashed here instead of reporting."""
    doc = _doc()
    doc["contextComponents"] = [5, {"id": 123}]
    errs = validator.check_all(doc)
    assert "contextComponents[0] 5 is not an object" in errs
    assert "contextComponents[1]: id 123 is not a string" in errs
    assert not any("contextComponents[0]: id" in e for e in errs)


def test_the_index_label_survives_two_dropped_elements_in_a_row():
    doc = _doc()
    doc["contextComponents"] = [5, "x", {"id": 123}]
    errs = validator.check_trust_tier_ring(doc)
    assert errs == [
        "contextComponents[0] 5 is not an object",
        "contextComponents[1] 'x' is not an object",
        "contextComponents[2]: id 123 is not a string",
    ]


def test_a_dropped_control_layer_does_not_renumber_the_findings_after_it():
    """controlLayers and findings run through the same accessor, so the label
    had the same defect there."""
    doc = _doc()
    doc["controlLayers"] = [7, {"layerId": 5}]
    errs = validator.check_crosswalk(doc)
    assert "controlLayers[0] 7 is not an object" in errs
    assert "controlLayers[1]: layerId 5 is not a string" in errs


# --- one bad field, one finding -------------------------------------------


def test_one_bad_field_yields_one_finding_through_check_all():
    """check_numeric, check_honesty and check_trust_tier_ring each read
    contextComponents through their own _Reader, so a wrong type there arrived at
    check_all three times over. The module docstring reasons carefully about not
    putting a second copy of a missing-field error in an error list and then
    shipped triplicated type faults."""
    doc = _doc()
    doc["contextComponents"] = "oops"
    errs = validator.check_all(doc)
    assert errs.count("contextComponents 'oops' is not an array") == 1
    # Collapsing happens at check_all. Each check on its own still reports
    # everything it read, which is what makes it independently usable.
    assert "contextComponents 'oops' is not an array" in validator.check_numeric(doc)
    assert "contextComponents 'oops' is not an array" in validator.check_honesty(doc)
    assert "contextComponents 'oops' is not an array" in validator.check_trust_tier_ring(doc)


def test_a_badly_typed_component_id_is_named_once_through_check_all():
    doc = _doc()
    doc["contextComponents"][0]["id"] = 123
    errs = validator.check_all(doc)
    assert errs.count("contextComponents[0]: id 123 is not a string") == 1


def test_collapsing_repeats_keeps_the_first_seen_order():
    """Order is what an operator reads and what the CLI prints, so the collapse
    has to keep it: validate_doc's schema errors, then each check in turn."""
    doc = _doc()
    doc["contextComponents"] = "oops"
    errs = validator.check_all(doc)
    assert errs[0] == "['contextComponents']: 'oops' is not of type 'array'"
    assert errs.index("contextComponents 'oops' is not an array") < \
        errs.index("totalContextTokens 100 != sum(component tokenCount) 0")


# --- the three guards the round 2 mutation run left unverified -------------


def test_a_zero_token_bucket_recorded_as_a_float_is_read_as_present():
    """The accumulator tests `tokens is not None` rather than truthiness, and the
    difference is observable because the schema admits 0.0 as an integer
    (_is_schema_integer(0.0) is True) while 0.0 is falsy. `total += tokens or 0`
    substitutes an int zero and the reported sum loses its float-ness. The
    fixture's own zero bucket is an int, which is what hid this: a fixture that
    uses the integer form of a value the schema also admits as a float hides
    every mutant that turns on falsiness."""
    doc = _doc()
    doc["sessionSummary"]["componentBreakdown"]["byTrustRing"] = {
        "ring0": {"tokens": 40}, "ring1": {"tokens": 0.0},
    }
    errs = validator.check_numeric(doc)
    assert "sum(byTrustRing) 40.0 != totalContextTokens 100" in errs


def test_a_catalog_snapshot_that_is_a_directory_does_not_raise(tmp_path, monkeypatch):
    """The third is_file() guard, the one with no record-shaped distinguishing
    input: the offending path is package data. atlas.json is the only catalog
    check_crosswalk hashes but never loads, so pointing the catalog directory at
    a copy where atlas.json is a DIRECTORY exercises the validator's own read
    and not crosswalk.load_catalog, which would trip first on any other name."""
    for src in (validator.crosswalk._CAT).iterdir():
        if src.is_file():
            (tmp_path / src.name).write_bytes(src.read_bytes())
    (tmp_path / "atlas.json").unlink()
    (tmp_path / "atlas.json").mkdir()
    monkeypatch.setattr(validator.crosswalk, "_CAT", tmp_path)
    doc = _doc()
    doc["catalogVersions"]["atlas"]["contentHash"] = "0" * 64
    errs = validator.check_crosswalk(doc)
    # exists() would reach read_bytes() and raise IsADirectoryError; is_file()
    # reads the same way it reads a catalog with no snapshot at all.
    assert not any("atlas" in e for e in errs), errs


def test_an_absent_window_total_does_not_invent_a_mismatch():
    """Found by round 3's own mutation run, not by the review. The contract says
    an ABSENT key is validate_doc's business and stays silent in these checks, so
    the window-total invariant has to SKIP when a field it needs is missing --
    not substitute zero for it. `(total or 0) + (overhead or 0) != cwtu` reports a
    mismatch against a figure the record never carried, which is a fabricated
    finding rather than a crash, and nothing caught it."""
    for missing in (("metadata", "session", "contextWindowTokensUsed"),
                    ("sessionSummary", "templateOverheadTokens"),
                    ("sessionSummary", "totalContextTokens")):
        doc = _doc()
        node = doc
        for key in missing[:-1]:
            node = node[key]
        del node[missing[-1]]
        errs = validator.check_numeric(doc)
        assert not any("contextWindowTokensUsed" in e for e in errs), (missing, errs)


def test_the_key_walk_carries_the_same_node_ceiling():
    """Both walks need the ceiling and both need it pinned. The string walk's is
    covered above; nothing covered this one, because cycle detection alone stops
    the cyclic document and the exponential-sharing document only went through
    _iter_strings."""
    node = {"s": "x"}
    for _ in range(40):
        node = {"p": node, "q": node}
    errs = []
    walked = sum(1 for _ in validator._iter_keys(node, errs))
    assert walked < validator._WALK_BUDGET
    assert errs == [validator._WALK_TRUNCATED]


def test_a_deeply_nested_record_does_not_hold_one_path_per_level():
    """A regression round 3 introduced and closed inside the same round, caught
    by the crash sweep rather than by reading. The closing entry that takes a
    container back off the ancestor set carries the container's ID, not the
    container: an earlier draft carried the container, so its PATH string stayed
    alive for as long as its whole subtree was being walked, which is one string
    per nesting level and quadratic memory in the depth. A 100,000-level record
    peaked at 48 GB of resident memory that way and at 0.1 GB after.

    The assertion is the wall clock because memory is what makes the bad version
    slow: it swaps long before it finishes, and there is no finding to check
    instead. The bound is very loose on purpose -- the good version walks this in
    under a second and the bad one takes minutes, so anything in between is a
    loaded machine rather than a regression."""
    node = "leaf"
    for _ in range(100000):
        node = {"a": node}
    errs = []
    started = time.monotonic()
    assert sum(1 for _ in validator._iter_strings(node, errs)) == 1
    assert time.monotonic() - started < 180
    assert errs == []


def test_a_record_nested_past_the_repr_limit_is_reported_not_raised():
    """The second trigger for instance N+6, and unlike the wide integer this one
    is reachable from a record on disk wherever json.loads parses 100,000 levels
    (CPython 3.14 does it in a hundredth of a second), and jsonschema's eager message building calls repr()
    on the offending value, which recurses once per level. It raises inside the
    library, at the same line the wide integer does. Round 2 made this module's
    own walks iterative and left the library's recursion, which is why the
    round 2 sweep called a 100,000-level record clean when check_all raised
    RecursionError on it. Built with _nested so 3.10 and 3.12, whose parser
    stops below 2,000 levels, still test the library-side guard."""
    deep = _nested(100_000, "leaf")
    doc = _doc()
    doc["sessionSummary"]["riskRationale"] = deep
    errs = validator.check_all(doc)
    assert isinstance(errs, list) and all(isinstance(e, str) for e in errs)
    assert any(e.startswith("the document cannot be schema-checked: RecursionError") for e in errs)
    # and the walks this module owns still cover the same record without help
    assert validator._iter_strings(deep, []) is not None
    walk_errs = []
    assert sum(1 for _ in validator._iter_strings(deep, walk_errs)) == 1
    assert walk_errs == []


def test_show_stops_walking_once_the_text_passes_the_cap(monkeypatch):
    """The cap bounds time, not only the text returned. A walk that rendered the
    whole value and then cut the text would spend as long as the value is
    large, which is how a 100,000-level record once took 12 s at the CLI.
    _show only walks exact lists, so the count comes from the leaf renderer."""
    calls = []
    real = validator._show_leaf

    def counting(value):
        calls.append(1)
        return real(value)

    monkeypatch.setattr(validator, "_show_leaf", counting)
    shown = validator._show(list(range(1_000_000)))
    assert shown.endswith(" ... (truncated)")
    assert len(calls) < 5_000
