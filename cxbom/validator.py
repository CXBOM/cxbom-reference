"""CxBOM validator: conformance + honesty + numeric invariants + crosswalk.

Fail-closed. Every check returns a list of human-readable error strings; the CLI
exits non-zero if any check on any document produces an error.

Malformed-input contract. A record arrives here unvalidated -- validating it is
what this module is for -- so every value in it can be any shape the JSON
grammar allows, whatever the schema says it must be. This module reports such a
record. It never raises on one.

  - Every read of a record goes through one of _Reader's typed accessors. A
    present value whose type the schema does not allow -- null included, bar the
    one field the schema itself declares nullable -- becomes a finding in the
    same list the check returns, named by its own path, and the invariant that
    needed it does not run. A bad value is never replaced by one that could let
    malformed accounting balance.
  - An ABSENT key is validate_doc's business (required-field enforcement) and
    stays silent in the sibling checks, so an error list never carries a second
    copy of a missing-field error.
  - Reporting a value is as much a part of the contract as reading it. A number
    the interpreter refuses to render -- an integer wider than
    sys.get_int_max_str_digits(), which a record can carry and the accounting
    sums can exceed -- is described by magnitude through _show rather than
    interpolated, because a report that raises while being written is still a
    crash. _show walks a value iteratively and renders each element by its
    type, so a container holding such an integer, a container nested past the
    C stack, or a constructed object whose repr raises is rendered too, and
    every rendering is capped at _SHOW_LIMIT characters.
  - The walks over every string and every key (_iter_strings, _iter_keys) are
    iterative for the same reason: a record nests as deep as its author chose,
    and a RecursionError out of check_boundary is a crash, not a report. They
    are also bounded (_WALK_BUDGET), because a dict that reaches itself -- which
    a parsed record cannot be but a constructed one can -- would otherwise
    replace that crash with a hang.
  - Consequently check_all returns a list for any JSON value handed to it,
    including a list, a string, or null at the top level, and that list carries
    each distinct finding once however many checks read the offending field.
    A constructed document holding a type json.loads cannot produce (a subclass
    of a builtin, whose methods are arbitrary code) is refused with its path
    before any check runs, so no code a record supplies ever executes here.
  - The CLI (main) extends the contract to the file: a file that cannot be read,
    is not a regular file, is not UTF-8, is not JSON, holds an integer
    json.loads refuses, or nests deeper than json.loads can follow is refused
    with one line on stderr and exit status 1, never a traceback. Every line it
    writes names the file by position, never by path, and is exactly one
    physical line: a character that is not printable is written as an escape,
    so a record cannot forge a line or drive the terminal.

tests/test_validator_nullsum.py holds that contract in one place: every
accessor over the full type matrix, and check_all over the same matrix at every
field these checks read. tests/test_validator_main.py holds the CLI's half.

The schema is loaded from a local file and its internal $refs resolve within the
document, so no `$id` dereference occurs. The offline test suite (sockets
disabled) proves no external fetch happens.

Owner: ATACE Working Group.
"""
from __future__ import annotations

import decimal
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys

from jsonschema import Draft7Validator

from . import crosswalk

_SPEC = pathlib.Path(str(__import__("importlib.resources", fromlist=["files"]).files("cxbom"))) / "_data"
_SCHEMA_PATH = _SPEC / "cxbom-0.2.0.schema.json"
SCHEMA_VERSION = "0.2.0"

# Fields the assembler/tokenizer structurally computes: never legitimately
# "not-collected" (declining to record them would hide a computable fact).
STRUCTURAL_FIELDS = frozenset({
    "tokenCount", "contextualSharePercent", "positionInContext", "trustRing",
    "trustTier", "type", "subtype", "controlLayer", "assembledAtTurn", "sha256",
})
# Security-relevant fields: a not-collected/not-assessed here must be recorded as
# a missing control and block a clean audit.
SECURITY_FIELDS = frozenset({
    "sanitization.status", "serverChecksumVerified", "serverOperatorIdentityVerified",
    "operatorControlled", "containsPII", "containsCredentials", "containsSecretsOrKeys",
    "injectionRiskRating", "toolDefinitionTrustInversion.detected",
})
# Trust-elevating integrity booleans that must bind to a recomputable artifact.
INTEGRITY_BOOLEANS = ("serverChecksumVerified", "serverOperatorIdentityVerified", "operatorControlled")

# formalRef must reference one of the paper's formal anchors. Anything else fails
# closed, so the shipped validator never certifies a result the paper does not state.
KNOWN_ANCHORS = ("Finding 1", "Lemma 1", "Proposition 1", "Proposition 2", "Framework 1", "Observation 1")

# A bare quantitative risk threshold (no citation) is a fabricated-number smell.
_BARE_THRESHOLD = re.compile(r"~?\s*\d+\s*%\s*(utilization|context|ring|window)", re.I)

# Pre-inference boundary regex: a subject that is presented as CHANGING across
# turns/steps. Scoped, NOT a bare-word ban: "attention" or a static "share" figure
# alone is legit schema and paper prose (the CxBOM records a model's
# attentionMechanism string and a per-component contextualSharePercent; the paper
# says controls fail "inside attention"). Only a trend-over-turns co-occurrence
# within a short window trips it, because a token-share change across turns is an
# attention-dynamics result, not a pre-inference CxBOM fact. The subject alternation
# covers bare "share" (so "contextual share"/"contextualSharePercent"/"token-share"
# all match) in addition to "attention"/"decay".
_BOUNDARY = re.compile(
    r"(?:attention|decay|share)"                 # subject (bare "share" covers all share variants)
    r".{0,60}?"                                    # short window
    r"(?:(?:chang|shift|grow|rise|drop|fall|trend|across|over).{0,20}?(?:turn|step)"
    r"|(?:turn|step).{0,20}?(?:chang|shift|grow|rise|drop|fall|trend|across|over))",
    re.I,
)
# A per-turn share-trend STRUCTURE key (e.g. sharePerTurn / shareDelta / shareTrend)
# encodes the same forbidden claim as data rather than prose.
_SHARE_TREND_KEY = re.compile(r"share.*(perturn|delta|trend|byturn)", re.I)
# Schema-glossary / annotation paths whose legitimate "attention mechanism" prose must
# not false-positive the boundary scan (they are excluded from the walk).
_BOUNDARY_EXCLUDE_SEGMENTS = ("fieldglossary", "glossary", "$comment", "_comment", "_ref")

# trustTier <-> trustRing map + the model-generated origins a ring-1-derived
# component must carry. ring-1-derived marks model-generated content (assistant turns
# that re-enter the context) which inherits Ring 1 provenance (trustRing 1).
_TIER_RING = {"operator": 0, "agent": 1, "ring-1-derived": 1, "user": 2}
_MODEL_ORIGINS = ("model", "assistant", "agent", "generated")

# A key that is not in the record at all, which is distinct from a key whose
# value is null: the first is a missing required field (validate_doc's job), the
# second is a value of the wrong type (reported here, by name).
_ABSENT = object()

# Two independent bounds on either document walk (_iter_strings, _iter_keys).
#
# json.loads cannot build a cycle, but check_all is public and cxbom/assembly.py
# hands it a dict that module constructed, and a dict that reaches itself makes
# an iterative walk run forever. Round 1's recursive walk at least stopped with
# RecursionError; trading a bounded crash for an unbounded hang is the worse
# failure for a validator a build waits on.
#
# A cycle is caught exactly, by holding the ids of the containers on the current
# path and refusing to descend into one of them a second time. Exactly, because
# the alternative -- one global set of every container already seen -- would also
# skip a subtree that two parents legitimately share, and a walk that silently
# stops looking is a fail-open check. Ids are safe to compare here: every node in
# the set is reachable from the document and so cannot be collected and reused
# while the walk runs.
#
# The node ceiling is the second bound, for the shape a cycle check does not
# cover: an acyclic document whose shared subtrees multiply the number of PATHS
# exponentially. 500,000 nodes is three orders of magnitude above any real record
# and still covers in full the widest document the round 2 review probed (200,000
# keys, 400,001 nodes through _iter_keys).
#
# Either bound reports. A truncated walk that said nothing would be a check that
# quietly stopped looking.
_WALK_BUDGET = 500_000
_WALK_TRUNCATED = (
    f"the document could not be walked in full: stopped after {_WALK_BUDGET} nodes "
    "(it is larger, or shares more structure, than any record should)"
)


# The longest text _show returns, beyond a short truncation marker. It is wider
# than the widest integer a parsed record can carry (4300 digits), so every
# value a record on disk can hold in one field is still quoted in full up to
# that width, and a finding stays a readable line instead of a megabyte.
_SHOW_LIMIT = 10_000
_SHOW_TRUNCATED = " ... (truncated)"


def _show_int(value: int) -> str:
    """An int as repr gives it, or its magnitude when repr refuses.

    Rendering an integer wider than sys.get_int_max_str_digits() (4300 by
    default) raises ValueError. That is not an ArithmeticError, so none of the
    arithmetic guards below catch it, and json.loads accepts an integer literal
    of exactly 4300 digits -- so the widest number a record can carry is one
    whose own report used to crash, and adding two of them, which the accounting
    checks do, carries past the limit from operands that were each printable.
    Describing the magnitude keeps both the finding readable and the record
    reportable. Raising the interpreter's limit instead would reintroduce the
    quadratic conversion cost the limit exists to bound.
    """
    try:
        return repr(value)
    except ValueError:
        # bit_length is O(1) and needs no decimal conversion at all; log10(2)
        # turns bits into decimal digits to within one, which is why the
        # message says "about" rather than quoting a figure it cannot verify.
        digits = int(value.bit_length() * math.log10(2)) + 1
        return f"<{'a negative' if value < 0 else 'an'} integer of about {digits} digits>"


# What _show writes for a value of any type it does not render itself. Fixed
# text: naming the type would read type(value).__name__, and a metaclass can
# make even that raise.
_SHOW_OTHER = "<a value of another type>"


def _show_leaf(value) -> str:
    """A value that is not a list, tuple or dict, rendered by its EXACT type.

    type(value) is ..., never isinstance: a subclass of int, str or float can
    override __repr__ or __format__ with code that raises, and a constructed
    record (cxbom/assembly hands check_all one) can hold one. For the exact
    builtin types repr cannot raise, bar the int width that _show_int handles.
    Every other type gets a fixed placeholder, and no foreign code runs.
    """
    kind = type(value)
    if kind is int:
        return _show_int(value)
    if value is None or kind is bool or kind is float or kind is str:
        return repr(value)
    return _SHOW_OTHER


def _show(value) -> str:
    """value as it reads inside a finding: repr, exactly, for anything repr can
    render in _SHOW_LIMIT characters, and never an exception.

    repr() itself fails in three ways a record reaches. An integer wider than
    the interpreter renders raises ValueError, whether it stands alone or sits
    anywhere inside a container -- so a guard around repr() of the container
    cannot know which element to describe. A container nested past the C stack
    raises RecursionError, and json.loads parses more than 100,000 levels, so a
    record on disk reaches that one. And a constructed record (cxbom/assembly
    hands check_all one) can hold an object whose repr raises anything at all,
    including a subclass of a builtin whose __repr__ or __iter__ raises.

    So this walks the value itself, iteratively, and renders by EXACT type:
    int, bool, float, str and None as repr gives them, list, tuple and dict by
    walking them, and every other type, subclasses of those included, as a fixed
    placeholder. No code the record supplies ever runs here, which is what makes
    "never an exception" true by construction rather than by guard. It stops once the text passes _SHOW_LIMIT, which also bounds the time
    spent on a record as deep or wide as its author chose, and it renders a
    container that reaches itself the way repr does, as [...] or {...}.
    """
    parts: list[str] = []
    size = 0
    ancestors: set[int] = set()
    # Each frame: [iterator, closing text, is a dict, first element pending,
    # container id, is a one-element tuple].
    stack: list[list] = []
    todo, pending = value, True
    while size <= _SHOW_LIMIT:
        if pending:
            pending = False
            v = todo
            kind = type(v)
            if kind is list or kind is tuple or kind is dict:
                # Exact types only, for the same reason as _show_leaf: iter(),
                # items() and len() on a subclass run its own code, and they
                # cannot raise on the builtins, since nothing here mutates them.
                if id(v) in ancestors:
                    text = "{...}" if kind is dict else "[...]" if kind is list else "(...)"
                else:
                    ancestors.add(id(v))
                    if kind is dict:
                        opener, closer, items = "{", "}", iter(dict.items(v))
                    elif kind is list:
                        opener, closer, items = "[", "]", iter(v)
                    else:
                        opener, closer, items = "(", ")", iter(v)
                    stack.append([items, closer, kind is dict, True, id(v), kind is tuple and len(v) == 1])
                    parts.append(opener)
                    size += 1
                    continue
            else:
                text = _show_leaf(v)
            parts.append(text)
            size += len(text)
            continue
        if not stack:
            break
        frame = stack[-1]
        item = next(frame[0], _ABSENT)
        if item is _ABSENT:
            closer = ",)" if frame[5] else frame[1]
            parts.append(closer)
            size += len(closer)
            ancestors.discard(frame[4])
            stack.pop()
            continue
        if not frame[3]:
            parts.append(", ")
            size += 2
        frame[3] = False
        if frame[2]:
            key, todo = item
            key_text = (_show(key) if type(key) is tuple else _show_leaf(key)) + ": "
            parts.append(key_text)
            size += len(key_text)
        else:
            todo = item
        pending = True
    text = "".join(parts)
    if size > _SHOW_LIMIT:
        return text[:_SHOW_LIMIT] + _SHOW_TRUNCATED
    return text


class _Reader:
    """The one place a read of an unvalidated record turns a wrong shape into a
    reported finding instead of an exception.

    Each accessor names the JSON type the schema declares for the field and
    returns a value of the matching Python type, or the type's empty value when
    there is nothing usable. So no caller can hand a string to arithmetic, a
    list to a dict subscript, a bool to an integer comparison, or an unhashable
    value to a membership test, and no caller needs a guard of its own to get
    wrong. A wrong type is appended to the caller's own findings list -- the
    same list the check function returns -- because a validator that raises on
    malformed input instead of reporting it loses every other finding in the
    same record.

    This replaces about twenty hand-copied `x.get(k) or {}` guards. `or` catches
    only None, so every one of them passed a truthy wrong-typed value (a string,
    a list, a number) straight through to the next subscript and crashed there.
    Centralising the reads means that blind spot, and the next one found, is
    closed once for every caller rather than once per site.
    """

    def __init__(self, errs: list[str]) -> None:
        self.errs = errs

    def _fault(self, what: str, value, expected: str) -> None:
        self.errs.append(f"{what} {_show(value)} is not {expected}")

    def _read(self, container, key: str, what: str):
        """container[key], or _ABSENT when the key is not there.

        A container that is not an object is reported under the field's own
        name. Every parent in this module is itself read through obj()/objs()
        and so is already a dict, which makes this the backstop for a container
        acquired some other way -- above all the document handed to check_all,
        which is a dict only by convention.
        """
        if not isinstance(container, dict):
            self.errs.append(f"{what} is unreadable: {_show(container)} is not an object")
            return _ABSENT
        return container.get(key, _ABSENT)

    def obj(self, container, key: str, what: str | None = None) -> dict:
        """The object at container[key], or {} when there is no usable one. A
        caller reading further fields out of the result then reads them out of
        an empty dict, which reports or skips, rather than crashing."""
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT:
            return {}
        if not isinstance(value, dict):
            self._fault(what, value, "an object")
            return {}
        return value

    def objs(self, container, key: str, what: str | None = None) -> list[tuple[int, dict]]:
        """The array of objects at container[key] as (index, object) pairs, or []
        when there is no usable one. An element that is not itself an object is
        reported by index and dropped, so a caller's loop body only ever sees a
        dict -- the shape that made `contextComponents: [1, 2, 3]` crash every
        loop over it.

        The index is the element's position in the RECORD, not in the list this
        returns, and every caller labels its findings with it. Handing back a
        bare list and letting the caller enumerate() it numbered the survivors
        instead: with `contextComponents: [5, {...}]` the dropped scalar and the
        object that follows it were both reported as contextComponents[0], which
        sends a reader of the report to the wrong array element.
        """
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT:
            return []
        if not isinstance(value, list):
            self._fault(what, value, "an array")
            return []
        out = []
        for i, item in enumerate(value):
            if isinstance(item, dict):
                out.append((i, item))
            else:
                self._fault(f"{what}[{i}]", item, "an object")
        return out

    def texts(self, container, key: str, what: str | None = None) -> list[str]:
        """The array of strings at container[key], or [] when there is no usable
        one. A non-string element is reported by index and dropped: the callers
        split these on ".", put them in a set, and test them for catalog
        membership, all of which need a real string."""
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT:
            return []
        if not isinstance(value, list):
            self._fault(what, value, "an array")
            return []
        out = []
        for i, item in enumerate(value):
            if isinstance(item, str):
                out.append(item)
            else:
                self._fault(f"{what}[{i}]", item, "a string")
        return out

    def text(self, container, key: str, what: str | None = None, nullable: bool = False) -> str | None:
        """The string at container[key], or None when there is no usable one.

        nullable=True is for a field the schema itself declares as
        ["string", "null"], where a null is a value to act on rather than a type
        to report. Only catalogVersions.<key>.releaseTag is read that way here.
        """
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT or (nullable and value is None):
            return None
        if not isinstance(value, str):
            self._fault(what, value, "a string")
            return None
        return value

    def integer(self, container, key: str, what: str | None = None) -> int | float | None:
        """The integer at container[key], or None when there is no usable one.
        Integer means what the schema means by it (see _is_schema_integer): an
        integral float counts, a bool does not."""
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT:
            return None
        if not _is_schema_integer(value):
            self._fault(what, value, "an integer")
            return None
        return value

    def number(self, container, key: str, what: str | None = None) -> int | float | None:
        """The number at container[key], or None when there is no usable one
        (see _is_schema_number)."""
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT:
            return None
        if not _is_schema_number(value):
            self._fault(what, value, "a finite number")
            return None
        return value

    def flag(self, container, key: str, what: str | None = None) -> bool | None:
        """The boolean at container[key], or None when there is no usable one.
        The callers compare with `is True`/`is False`, which a wrong-typed value
        cannot crash but can quietly satisfy the wrong way, so the type is
        checked here rather than trusted to the comparison."""
        what = key if what is None else what
        value = self._read(container, key, what)
        if value is _ABSENT:
            return None
        if not isinstance(value, bool):
            self._fault(what, value, "a boolean")
            return None
        return value


def load_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def make_validator() -> Draft7Validator:
    # Internal-only $refs + FORMAT_CHECKER means format assertions are enforced
    # and no network fetch occurs.
    return Draft7Validator(load_schema(), format_checker=Draft7Validator.FORMAT_CHECKER)


def validate_doc(doc: dict) -> list[str]:
    v = make_validator()
    try:
        errors = list(v.iter_errors(doc))
    except (ValueError, RecursionError) as exc:
        # jsonschema builds each error's message eagerly and interpolates the
        # offending value with repr(), which is where both of these come from,
        # inside the library, before there is an error object here to report.
        #
        # ValueError: the value is an integer wider than
        # sys.get_int_max_str_digits() and the interpreter refuses to render it.
        # json.loads caps an integer literal at exactly that width, so only a
        # caller that builds its own dict (cxbom/assembly does) reaches this.
        #
        # RecursionError: repr of a nested container recurses once per level,
        # and json.loads parses 100,000 levels without complaint, so THIS one is
        # reachable from a record on disk. It is the same defect round 2 fixed
        # in this module's own walks, one layer out in the library, where it
        # cannot be fixed by making a walk iterative.
        #
        # Fail closed with a finding either way. The one module whose contract
        # is that it reports malformed input must not raise on it.
        return [f"the document cannot be schema-checked: {type(exc).__name__}: {exc}"]
    # The sort key compares path elements, which are property names and array
    # indices, so a str-against-int comparison would raise TypeError. It cannot
    # happen for one document: two error paths only compare element-wise where
    # they share a prefix, and the node at the end of that prefix is either an
    # array (int indices) or an object (str names), never both. Coercing to str
    # would make the comparison total at the price of ordering index 10 before
    # index 2, so this is left as is deliberately.
    return [f"{list(e.path)}: {e.message}" for e in sorted(errors, key=lambda e: list(e.path))]


def _round2(x) -> decimal.Decimal | None:
    """x rounded to 2 decimal places, or None when x cannot be rounded.

    decimal raises InvalidOperation when quantizing a value with more integer
    digits than the context's precision, and a JSON number has no upper bound:
    a schema-valid tokenCount of 10**400 is enough. Returning None leaves the
    decision with the caller, which reports the record rather than raising on
    it.
    """
    try:
        return decimal.Decimal(str(x)).quantize(decimal.Decimal("0.01"), rounding=decimal.ROUND_HALF_EVEN)
    except ArithmeticError:  # decimal.InvalidOperation and friends are all ArithmeticError
        return None
    except ValueError:
        # str(x) raises this, not an ArithmeticError, on an integer wider than
        # the interpreter's digit limit. str() is deliberate here (Decimal(0.1)
        # would carry the whole binary expansion), so the limit is this
        # function's to absorb.
        return None


def _share_percent(token_count, total) -> decimal.Decimal | None:
    """token_count as a percentage of total, rounded to 2 decimal places, or
    None when the record's own magnitudes put the answer out of reach: an
    unbounded JSON integer overflows float division (OverflowError, an
    ArithmeticError) before _round2 ever sees the product."""
    try:
        return _round2(token_count / total * 100)
    except ArithmeticError:
        return None


def _is_schema_integer(v) -> bool:
    """True if v is an integer-valued JSON number under the schema's own
    "integer" semantics: Draft7Validator accepts an integral float (40.0) as
    type integer and rejects bool even though Python's isinstance(True, int)
    is True (confirmed against jsonschema directly, not assumed). Matching
    that definition here means this check is never stricter than the schema
    (a schema-valid record never gains a spurious error) and never looser
    (a bool, string, or null is never silently summed as if it were zero)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return v.is_integer()
    return False


def _is_schema_number(v) -> bool:
    """True if v is a JSON number this module's arithmetic can use: bool is
    excluded for the same reason as in _is_schema_integer, and a non-finite
    float is excluded because json.loads accepts NaN and Infinity as an
    extension even though JSON has no literal for them, every comparison
    against NaN is meaningless, and decimal raises InvalidOperation rounding
    either one."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and math.isfinite(v)


def _label(read: _Reader, component: dict, index: int) -> str:
    """How a context component names itself in a finding: its own id when it
    has a usable one, its position in the array otherwise, so a component whose
    id is missing or wrongly typed is still identifiable in the report."""
    return read.text(component, "id", f"contextComponents[{index}]: id") or f"contextComponents[{index}]"


def _partition_tokens(read: _Reader, breakdown: dict, key: str) -> tuple[dict, int | float]:
    """One componentBreakdown partition and its token sum.

    Each bucket is read as an object and its tokens as an integer, so a bucket
    that is null or a scalar, and a tokens value that is null or a string, are
    reported by name instead of crashing sum(). This is the original defect
    shape one level down: `.get("tokens", 0)`'s default covers an absent key
    only, so a present-but-null tokens reached sum() as None. An absent tokens
    still contributes 0, as that default did.
    """
    buckets = read.obj(breakdown, key, f"componentBreakdown.{key}")
    total = 0
    for name in buckets:
        bucket = read.obj(buckets, name, f"componentBreakdown.{key}.{name}")
        tokens = read.integer(bucket, "tokens", f"componentBreakdown.{key}.{name}: tokens")
        if tokens is not None:
            total += tokens
    return buckets, total


def check_numeric(doc: dict) -> list[str]:
    """Token-accounting invariants."""
    errs: list[str] = []
    read = _Reader(errs)
    comps = read.objs(doc, "contextComponents")
    ss = read.obj(doc, "sessionSummary")
    total = read.integer(ss, "totalContextTokens")

    # Resolve each component's content/tokenCount once, up front, instead of
    # re-deriving it separately in the sum below and the per-component share
    # loop. A content or tokenCount that is PRESENT and the wrong type (null
    # included) is reported by name by the accessor and contributes nothing:
    # substituting 0 for a value that is present but bad would let malformed
    # accounting pass as clean. One that is simply ABSENT is validate_doc's job
    # (required-field enforcement) and keeps contributing 0, unchanged.
    resolved = []  # (label, content, tokenCount-or-None)
    for i, c in comps:
        label = _label(read, c, i)
        content = read.obj(c, "content", f"{label}: content")
        resolved.append((label, content, read.integer(content, "tokenCount", f"{label}: tokenCount")))

    comp_sum = sum(tc for _, _, tc in resolved if tc is not None)
    if total != comp_sum:
        # total is None when totalContextTokens is absent or was just reported
        # as the wrong type; the mismatch still stands, and the type fault
        # ahead of it names the value the record actually held.
        errs.append(f"totalContextTokens {_show(total)} != sum(component tokenCount) {_show(comp_sum)}")
    session = read.obj(read.obj(doc, "metadata"), "session", "metadata.session")
    cwtu = read.integer(session, "contextWindowTokensUsed", "metadata.session.contextWindowTokensUsed")
    overhead = read.integer(ss, "templateOverheadTokens")
    if total is not None and overhead is not None and cwtu is not None:
        if total + overhead != cwtu:
            errs.append(f"totalContextTokens {_show(total)} + templateOverheadTokens {_show(overhead)}"
                        f" != contextWindowTokensUsed {_show(cwtu)}")
    # per-component share
    for label, content, tc in resolved:
        share = read.number(content, "contextualSharePercent", f"{label}: contextualSharePercent")
        if tc is not None and share is not None and total:
            expected = _share_percent(tc, total)
            actual = _round2(share)
            if expected is None or actual is None:
                errs.append(f"{label}: contextualSharePercent {_show(share)} and tokenCount"
                            f" {_show(tc)}/{_show(total)} are too large to compare")
            elif actual != expected:
                errs.append(f"{label}: contextualSharePercent {_show(share)} != {expected}"
                            f" (tokenCount {_show(tc)}/{_show(total)})")
    # ring + type partitions
    breakdown = read.obj(ss, "componentBreakdown")
    _, ring_sum = _partition_tokens(read, breakdown, "byTrustRing")
    if total is not None and ring_sum != total:
        errs.append(f"sum(byTrustRing) {_show(ring_sum)} != totalContextTokens {_show(total)}")
    by_type, type_sum = _partition_tokens(read, breakdown, "byType")
    if "other" in by_type:
        errs.append("byType contains a forbidden catch-all 'other' bucket")
    if total is not None and type_sum != total:
        errs.append(f"sum(byType) {_show(type_sum)} != totalContextTokens {_show(total)}")
    # numeric-threshold honesty
    for path, val in _iter_strings(doc, errs):
        if _BARE_THRESHOLD.search(val):
            errs.append(f"{path}: bare numeric risk threshold without a citation: {val!r}")
    return errs


def _iter_strings(node, errs, path="$"):
    """Every string in the document, with its path, in document order.

    An explicit stack rather than recursion: a record nests as deep as its
    author chose, this walk is reached from check_numeric and check_boundary
    (so from check_all), and a thousand-level record used to raise
    RecursionError here -- a crash instead of a report, which is the failure
    mode this module exists to avoid. Children are pushed reversed so the walk
    order still matches the depth-first one the paths describe.

    errs is the caller's own findings list, for the two things this walk has to
    say for itself: that the document reaches back into itself, and that it
    stopped early. See _WALK_BUDGET.
    """
    budget = _WALK_BUDGET
    # The containers on the path from the root to the node being visited. A
    # closing entry is pushed under each container's children so the id comes
    # back off the set at the moment the walk leaves that container, which keeps
    # the test "is this node one of my own ancestors" and not "have I ever seen
    # this node".
    on_path: set[int] = set()
    reported_cycle = False
    stack = [(node, path, False)]
    while stack:
        if not budget:
            errs.append(_WALK_TRUNCATED)
            return
        budget -= 1
        current, at, leaving = stack.pop()
        if leaving:
            # On a closing entry `current` is the container's id, not the
            # container, and `at` is None. Deliberate: a closing entry sits on
            # the stack for as long as its whole subtree is being walked, so
            # holding the container's PATH string in it would keep one string
            # per nesting level alive at once -- quadratic memory in the depth,
            # which is tens of gigabytes for a 100,000-level record.
            on_path.discard(current)
        elif isinstance(current, (dict, list)):
            if id(current) in on_path:
                if not reported_cycle:  # one finding, not one per path into the cycle
                    errs.append(f"the document refers back into itself at {at}:"
                                " the string walk stopped there instead of looping")
                    reported_cycle = True
                continue
            on_path.add(id(current))
            stack.append((id(current), None, True))
            if isinstance(current, dict):
                stack.extend(reversed([(v, f"{at}.{k}", False) for k, v in current.items()]))
            else:
                stack.extend(reversed([(v, f"{at}[{i}]", False) for i, v in enumerate(current)]))
        elif isinstance(current, str):
            yield at, current


def _iter_keys(node, errs):
    """Every object key in the document, in document order. Iterative, and
    bounded, for the same reasons as _iter_strings. The stack carries
    (state, payload) pairs: a KEY entry is yielded at the moment the walk
    reaches it, ahead of its own value's keys, which is the order a recursive
    walk produced, and a LEAVING entry takes a container back off on_path -- see
    _iter_strings for why it holds the container's id rather than the
    container."""
    KEY, NODE, LEAVING = 0, 1, 2
    budget = _WALK_BUDGET
    on_path: set[int] = set()
    reported_cycle = False
    stack = [(NODE, node)]
    while stack:
        if not budget:
            errs.append(_WALK_TRUNCATED)
            return
        budget -= 1
        state, payload = stack.pop()
        if state == KEY:
            yield payload
        elif state == LEAVING:
            on_path.discard(payload)     # payload is the id, see _iter_strings
        elif isinstance(payload, (dict, list)):
            if id(payload) in on_path:
                if not reported_cycle:
                    errs.append("the document refers back into itself:"
                                " the key walk stopped there instead of looping")
                    reported_cycle = True
                continue
            on_path.add(id(payload))
            stack.append((LEAVING, id(payload)))
            if isinstance(payload, dict):
                for k, v in reversed(list(payload.items())):
                    stack.append((NODE, v))
                    stack.append((KEY, k))
            else:
                stack.extend((NODE, v) for v in reversed(payload))


def check_honesty(doc: dict) -> list[str]:
    """not-collected discipline + integrity binding."""
    errs: list[str] = []
    read = _Reader(errs)
    session_summary = read.obj(doc, "sessionSummary")
    blockers = set(read.texts(session_summary, "auditCleanBlockers"))
    clean = read.flag(session_summary, "sessionAuditClean")
    any_sec_not_collected = False
    for i, c in read.objs(doc, "contextComponents"):
        label = _label(read, c, i)
        # Read once per component, ahead of the field loop: a second read of the
        # same malformed sanitization would report the same fault twice.
        missing_controls = read.texts(
            read.obj(c, "sanitization", f"{label}: sanitization"),
            "missingControls", f"{label}: sanitization.missingControls")
        for field in read.texts(c, "notCollected", f"{label}: notCollected"):
            leaf = field.split(".")[-1]
            if leaf in STRUCTURAL_FIELDS:
                errs.append(f"{label}: notCollected names structurally-observable field {field!r}")
            if field in SECURITY_FIELDS or leaf in {f.split('.')[-1] for f in SECURITY_FIELDS}:
                any_sec_not_collected = True
                if not missing_controls:
                    errs.append(f"{label}: security field {field!r} not-collected but no missingControls entry")
        # integrity-boolean binding
        src = read.obj(c, "source", f"{label}: source")
        if read.flag(src, "serverChecksumVerified", f"{label}: source.serverChecksumVerified") is True \
                and "serverChecksum" not in src:
            errs.append(f"{label}: serverChecksumVerified true but no serverChecksum to recompute")
        if read.flag(src, "serverOperatorIdentityVerified", f"{label}: source.serverOperatorIdentityVerified") is True \
                and "contentSignature" not in src:
            errs.append(f"{label}: serverOperatorIdentityVerified true but no contentSignature binding")
    if clean is True and any_sec_not_collected:
        errs.append("sessionAuditClean true while a security field is not-collected")
    # a not-collected security field must also block a clean audit
    if any_sec_not_collected and clean is True and not blockers:
        errs.append("not-collected security field did not register an auditCleanBlocker")
    return errs


def _recompute_hash(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_crosswalk(doc: dict, submission_mode: bool = False) -> list[str]:
    """Catalog resolution, content-hash integrity, version lockstep, formalRef
    allowlist, and submission-mode release gate."""
    errs: list[str] = []
    read = _Reader(errs)
    cat_dir = crosswalk._CAT
    llm = crosswalk.load_catalog("owasp-llm-2026")
    asi = crosswalk.load_catalog("owasp-asi-2026")
    cwe = crosswalk.load_catalog("cwe")
    # Every code below is read as a string before it is tested for catalog
    # membership: `code not in llm` on a list or a dict raises TypeError
    # (unhashable), so an unhashable coverage entry crashed this check outright.
    for i, layer in read.objs(doc, "controlLayers"):
        layer_id = read.text(layer, "layerId", f"controlLayers[{i}]: layerId")
        for code in read.texts(layer, "owaspCoverage", f"controlLayer {layer_id}: owaspCoverage"):
            if code not in llm:
                errs.append(f"controlLayer {layer_id}: owaspCoverage {code} unresolved in owasp-llm-2026")
        for code in read.texts(layer, "agenticCoverage", f"controlLayer {layer_id}: agenticCoverage"):
            if code not in asi:
                errs.append(f"controlLayer {layer_id}: agenticCoverage {code} unresolved in owasp-asi-2026")
    for i, f in read.objs(doc, "findings"):
        fid = read.text(f, "id", f"findings[{i}]: id")
        for code in read.texts(f, "owaspRefs", f"finding {fid}: owaspRefs"):
            if code not in llm:
                errs.append(f"finding {fid}: owaspRefs {code} unresolved in owasp-llm-2026")
        for code in read.texts(f, "agenticRefs", f"finding {fid}: agenticRefs"):
            if code not in asi:
                errs.append(f"finding {fid}: agenticRefs {code} unresolved in owasp-asi-2026")
        cwe_ref = read.text(f, "cweRef", f"finding {fid}: cweRef")
        if cwe_ref and cwe_ref not in cwe:
            errs.append(f"finding {fid}: cweRef {cwe_ref} unresolved in cwe catalog")
        fr = read.text(f, "formalRef", f"finding {fid}: formalRef")
        if fr and not any(a in fr for a in KNOWN_ANCHORS):
            errs.append(f"finding {fid}: formalRef {fr!r} references no known anchor {KNOWN_ANCHORS}")
    # version lockstep
    spec_version = read.text(doc, "specVersion")
    if spec_version != SCHEMA_VERSION:
        errs.append(f"specVersion {spec_version} != {SCHEMA_VERSION}")
    gb = read.text(read.obj(read.obj(doc, "metadata"), "generatedBy", "metadata.generatedBy"),
                   "schema", "metadata.generatedBy.schema")
    if gb and f"/{SCHEMA_VERSION}/" not in gb:
        errs.append(f"generatedBy.schema {gb} not on {SCHEMA_VERSION}")
    cv = read.obj(doc, "catalogVersions")
    cxbom_version = read.text(read.obj(doc, "schema"), "cxbomVersion", "schema.cxbomVersion")
    if cxbom_version not in (None, SCHEMA_VERSION):
        errs.append(f"schema.cxbomVersion {cxbom_version} != {SCHEMA_VERSION}")
    # catalogVersions content-hash recompute (only for hashed taxonomy catalogs)
    hashed = {"owaspLlm": "owasp-llm-2026", "owaspAgentic": "owasp-asi-2026", "cwe": "cwe", "atlas": "atlas"}
    for key, fname in hashed.items():
        entry = read.obj(cv, key, f"catalogVersions.{key}")
        ch = read.text(entry, "contentHash", f"catalogVersions.{key}.contentHash")
        snap = cat_dir / f"{fname}.json"
        if ch and snap.is_file():  # is_file: a directory of that name would raise out of _recompute_hash
            actual = _recompute_hash(snap)
            if ch != actual:
                # ch[:12] slices a str because the accessor guarantees one: a
                # non-string contentHash used to crash this very error message.
                errs.append(f"catalogVersions.{key}.contentHash {ch[:12]} != snapshot {actual[:12]}")
        # submission-mode release gate
        if submission_mode:
            # nullable=True: releaseTag is the one field this module reads that
            # the schema declares as ["string", "null"], where null means "not
            # an official release" -- a value this gate acts on, not a type
            # fault to report.
            tag = read.text(entry, "releaseTag", f"catalogVersions.{key}.releaseTag", nullable=True)
            if not tag or re.search(r"(?i)(rc|candidate|draft|sprint|preview|-pre)", tag):
                errs.append(f"submission-mode: catalogVersions.{key} is not an official release (releaseTag={tag!r})")
            if read.flag(entry, "released", f"catalogVersions.{key}.released") is False:
                errs.append(f"submission-mode: catalogVersions.{key} marked released=false")
    return errs


def check_hash_binding(doc: dict, content_dir) -> list[str]:
    """For records with stored content, recompute sha256 over the content
    file and confirm it binds to the recorded content.sha256."""
    errs: list[str] = []
    read = _Reader(errs)
    cd = pathlib.Path(content_dir)
    for i, c in read.objs(doc, "contextComponents"):
        cid = read.text(c, "id", f"contextComponents[{i}]: id")
        if cid is None:
            continue  # no usable id names no content file; the missing required field is validate_doc's
        # is_file(), not exists(): a record whose id names a DIRECTORY in the
        # content dir made read_bytes() raise IsADirectoryError. A directory is
        # not a content file, so this reads as "no stored content", which is the
        # case this check already skips.
        f = cd / f"{cid}.txt"
        if f.is_file():
            actual = hashlib.sha256(f.read_bytes()).hexdigest()
            if actual != read.text(read.obj(c, "content", f"{cid}: content"), "sha256", f"{cid}: content.sha256"):
                errs.append(f"{cid}: content.sha256 does not bind to {f}")
    return errs


def count_verified_hash_bindings(doc: dict, content_dir) -> int:
    """Number of components whose recorded content.sha256 is present AND binds to
    an existing content file with a matching digest. Distinct from check_hash_binding
    (which silently skips a missing file); this counts REAL verifications so a test can
    assert coverage is non-empty and complete rather than vacuously skipped."""
    cd = pathlib.Path(content_dir)
    # This function returns a count, not findings, so its reader's faults go
    # nowhere: a malformed component cannot be verified and so is not counted,
    # which is the whole answer this function owes its caller.
    read = _Reader([])
    n = 0
    for i, c in read.objs(doc, "contextComponents"):
        cid = read.text(c, "id", f"contextComponents[{i}]: id")
        if cid is None:
            continue  # no usable id names no content file, so nothing to verify
        recorded = read.text(read.obj(c, "content", f"{cid}: content"), "sha256", f"{cid}: content.sha256")
        if not recorded:
            continue
        f = cd / f"{cid}.txt"
        if f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest() == recorded:  # is_file: see check_hash_binding
            n += 1
    return n


def check_boundary(doc: dict) -> list[str]:
    """A multi-turn illustrative record records PRE-INFERENCE token composition
    ONLY. It must never imply attention, decay, or a token-share trend across turns
    (that is an attention-dynamics result, not a CxBOM fact). Walk EVERY
    string recursively (not a fixed field list) so findings/trustModel/sessionSummary
    prose is covered, excluding schema glossary/annotation metadata, and match only the
    scoped trend-over-turns regex (bare 'attention'/'decay' stay legal)."""
    errs: list[str] = []
    read = _Reader(errs)
    if read.flag(doc, "illustrative") is not True:
        return errs
    # An absent or null turnCount means "assume single-turn, this check does not
    # apply", the same as the `.get("turnCount", 1)` default did. A present
    # turnCount of the wrong type is reported by the accessor and lands here as
    # None, so the `<=` comparison can no longer be handed a string or a list.
    session = read.obj(read.obj(doc, "metadata"), "session", "metadata.session")
    turn_count = read.integer(session, "turnCount", "metadata.session.turnCount")
    if turn_count is None or turn_count <= 1:
        return errs
    for path, s in _iter_strings(doc, errs):
        low = path.lower()
        if any(seg in low for seg in _BOUNDARY_EXCLUDE_SEGMENTS):
            continue
        if _BOUNDARY.search(s):
            errs.append(f"boundary violation: {path} implies cross-turn attention/share dynamics: {s!r}")
    for key in _iter_keys(doc, errs):
        if _SHARE_TREND_KEY.search(key):
            errs.append(f"boundary violation: forbidden per-turn share-trend structure key {key!r}")
    return errs


def check_trust_tier_ring(doc: dict) -> list[str]:
    """trustTier must agree with trustRing (operator->0, agent->1,
    ring-1-derived->1, user->2). ring-1-derived marks model-generated re-entrant
    content, so it needs a positive assembly turn (it re-enters AFTER an earlier turn)
    and a model-generated source.origin (never a user-turn / operator-vault origin)."""
    errs: list[str] = []
    read = _Reader(errs)
    for i, c in read.objs(doc, "contextComponents"):
        label = _label(read, c, i)
        # tier is read as a string before it indexes _TIER_RING: an unhashable
        # trustTier (a list, a dict) raised TypeError on the membership test.
        tier = read.text(c, "trustTier", f"{label}: trustTier")
        ring = read.integer(c, "trustRing", f"{label}: trustRing")
        if tier in _TIER_RING and _TIER_RING[tier] != ring:
            errs.append(f"{label}: trustTier {tier!r} implies trustRing {_TIER_RING[tier]} != {_show(ring)}")
        if tier == "ring-1-derived":
            # The accessor applies the schema's own integer semantics, which
            # exclude bool: isinstance(True, int) is True in Python, so a plain
            # isinstance guard read assembledAtTurn: true as turn 1 and let a
            # malformed record validate as clean.
            atn = read.integer(c, "assembledAtTurn", f"{label}: assembledAtTurn")
            if atn is None or atn <= 0:
                errs.append(f"{label}: ring-1-derived requires assembledAtTurn > 0 (re-entrant model content)")
            origin = read.text(read.obj(c, "source", f"{label}: source"), "origin", f"{label}: source.origin") or ""
            if not any(m in origin.lower() for m in _MODEL_ORIGINS):
                errs.append(f"{label}: ring-1-derived requires a model-generated source.origin, got {origin.lower()!r}")
    return errs


def _foreign_value(doc) -> str | None:
    """The path of the first value in doc whose EXACT type json.loads cannot
    produce, or None when every value is a dict with str keys, a list, a str, an
    int, a float, a bool or None.

    A parsed record always passes. A constructed one (cxbom/assembly hands
    check_all the record it built) can hold a subclass of a builtin whose
    __repr__, __format__, __iter__ or comparison raises, and jsonschema and
    every check below would run that code. Refusing such a document before any
    of them sees it makes "check_all never raises" hold by construction: past
    this point every value is a builtin whose methods cannot raise on it.

    Iterative, with each container visited once (a node's type is the same
    however it is reached, so skipping a shared subtree cannot miss anything),
    and the path kept as parent links rather than strings, so a deep document
    costs linear memory. Only the offending path is ever built.
    """
    parents: list[tuple[int, str]] = [(-1, "$")]
    seen: set[int] = set()
    stack: list[tuple[object, int]] = [(doc, 0)]

    def path_of(index: int) -> str:
        segments = []
        while index >= 0:
            index, segment = parents[index]
            segments.append(segment)
        text = "".join(reversed(segments))
        return text if len(text) <= _SHOW_LIMIT else text[:_SHOW_LIMIT] + _SHOW_TRUNCATED

    while stack:
        node, here = stack.pop()
        kind = type(node)
        if kind is dict or kind is list:
            if id(node) in seen:
                continue
            seen.add(id(node))
            pairs = dict.items(node) if kind is dict else enumerate(node)
            for key, child in pairs:
                if kind is dict and type(key) is not str:
                    return path_of(here) + " (a key)"
                parents.append((here, f".{key}" if kind is dict else f"[{key}]"))
                stack.append((child, len(parents) - 1))
        elif not (node is None or kind is str or kind is int or kind is float or kind is bool):
            return path_of(here)
    return None


def check_all(doc: dict, submission_mode: bool = False) -> list[str]:
    # Each check reads the record through its own _Reader, so a fault in a field
    # that three of them read -- contextComponents, a component's id -- used to
    # arrive here three times. dict.fromkeys drops the repeats and keeps
    # first-seen order, which is the standard the module docstring already sets
    # for an error list. Two different faults can collide into one only when
    # their text is identical. A finding names the path and value it is about,
    # but check_crosswalk labels a finding or control layer by its own id, so two
    # entries that share an id and the same unresolved code print one line. The
    # record still fails on that line. Collapsing is done here rather than in the
    # accessors because the checks hold separate lists by design: each one is
    # independently useful and reports everything it read.
    foreign = _foreign_value(doc)
    if foreign is not None:
        return [f"the document holds a value of a type JSON cannot produce, at {foreign}, "
                "so no other check ran on it"]
    return list(dict.fromkeys(
        validate_doc(doc)
        + check_honesty(doc)
        + check_numeric(doc)
        + check_boundary(doc)
        + check_trust_tier_ring(doc)
        + check_crosswalk(doc, submission_mode=submission_mode)
    ))


def _escape_unprintable(ch: str) -> str:
    o = ord(ch)
    return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}"


def _emit(stream, line: str) -> None:
    """Write exactly one physical line of CLI output, whatever the text carries.

    A finding quotes record values, and the FAIL and OK lines used to quote the
    path the caller typed, so the record's author chooses some of these bytes.
    A newline in them forged a line of its own (an "OK" under a FAIL), and an
    escape sequence drove the terminal (erase the line above, recolour). The
    bound is an allowlist: every character str.isprintable() rejects -- the C0
    and C1 controls, DEL, the line and paragraph separators, format characters
    such as the bidirectional overrides, and lone surrogates -- is written as a
    visible \\xNN, \\uNNNN or \\UNNNNNNNN escape. Then backslashreplace covers a
    printable character the stream's encoding lacks, so writing cannot raise.
    """
    if not line.isprintable():
        line = "".join(ch if ch.isprintable() else _escape_unprintable(ch) for ch in line)
    enc = getattr(stream, "encoding", None) or "utf-8"
    stream.write(line.encode(enc, "backslashreplace").decode(enc) + "\n")


def _load(p: str):
    """(document, None) for a file that holds JSON, else (None, reason).

    A reason is fixed text plus figures the reader or parser computed (a byte
    offset, a line and a column). It is never an exception's own str(): an
    OSError's str() carries the path, which may be absolute, and nothing a
    refusal needs to say requires echoing the file or its contents.
    """
    try:
        # O_NONBLOCK: opening a FIFO that has no writer blocks forever, before
        # any check could see what the path names. On a regular file it
        # changes nothing. O_NOCTTY: a terminal device must not become ours.
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
    except (OSError, ValueError) as exc:
        # OSError: missing, unreadable, a socket. ValueError: a path holding a
        # NUL byte, which no shell passes but main(argv=[...]) can.
        return None, f"the file cannot be read ({getattr(exc, 'strerror', None) or type(exc).__name__})"
    try:
        # fstat the object that was opened, not the path, so nothing can swap
        # the path between the check and the read. A FIFO, a device such as
        # /dev/zero (which reads until memory runs out) and a directory are
        # all refused here.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "the file is not a regular file (a directory, FIFO, device or socket)"
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read()
    except OSError as exc:
        return None, f"the file cannot be read ({exc.strerror or type(exc).__name__})"
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, f"the file is not UTF-8 (invalid byte at offset {exc.start})"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:  # before ValueError: it subclasses ValueError
        return None, f"the file is not JSON ({exc.msg} at line {exc.lineno} column {exc.colno})"
    except ValueError:
        # The one bare ValueError json.loads raises: an integer literal wider
        # than sys.get_int_max_str_digits(), which int() refuses to convert.
        return None, f"the file holds an integer wider than {sys.get_int_max_str_digits()} digits"
    except RecursionError:
        # json.loads recurses once per nesting level. Where it gives up depends
        # on the interpreter: about 116,000 levels on this project's CPython 3.14.
        return None, "the file nests deeper than the JSON parser can follow"


def main(argv=None) -> int:
    """Validate each file named on the command line. Exit status 1 if any file
    fails a check or is refused, else 0.

    Owner ruling 2 (2026-09-27) reversed the earlier instruction to leave this
    function upstream-identical: a traceback on a bad file is worse than a
    smaller upstream-identical region. The edit is declared as its own hunk,
    with its reason, in spec/published.lock.json.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    submission = "--submission" in argv
    paths = [a for a in argv if not a.startswith("-")]
    rc = 0
    for n, p in enumerate(paths, 1):
        # Every line names the file by position, never by path: the path is
        # whatever the caller typed, often absolute and possibly holding a
        # newline, and a label generated here is the only output bounded by
        # construction (fix round 1, controller ruling on m2).
        label = f"file {n} of {len(paths)}"
        doc, reason = _load(p)
        if reason is not None:
            rc = 1  # the next file still runs
            _emit(sys.stderr, f"REFUSED {label}: {reason}")
            continue
        errs = check_all(doc, submission_mode=submission)
        if errs:
            rc = 1
            _emit(sys.stdout, f"FAIL {label}")
            for e in errs:
                _emit(sys.stdout, f"  - {e}")
        else:
            _emit(sys.stdout, f"OK   {label}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
