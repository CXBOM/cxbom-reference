"""The validator CLI refuses a bad file cleanly (owner ruling 2, 2026-09-27).

Owner: ATACE Working Group.

cxbom/validator.py's main() used to call json.loads on the file's text with no
guard, so every way a file can be bad ended in a traceback. The ruling: a
malformed file gets exit status 1, one line of stderr, no traceback, and no
absolute path in the message. Each way a file can be bad has its own test here,
because one input exercising two guards pins neither.

The in-process tests hold the exact output. The subprocess tests hold the
process-level half (the exit status SystemExit carries and the absence of a
traceback), which an in-process call cannot observe.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cxbom import validator

ROOT = Path(__file__).resolve().parents[1]
MINIMAL = (ROOT / "tests/fixtures/atace/valid-minimal.json").read_text(encoding="utf-8")

# Past every limit measured below (CPython 3.14.7 parses 116,200 levels), so the
# fixed-depth refusal tests refuse on every interpreter. The tests that need a
# depth near a limit measure it on the running interpreter instead.
UNPARSEABLE_DEPTH = 200_000
# The ceiling for measured limits. It exceeds every limit measured, and the
# probes fail rather than report it as a limit.
SEARCH_CEILING = 400_000
TOO_DEEP = "the file nests deeper than the JSON parser can follow"


NOT_REGULAR = "the file is not a regular file (a directory, FIFO, device or socket)"


def _write(tmp_path, name, data):
    path = tmp_path / name
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


def _run(capsys, *argv):
    rc = validator.main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return rc, out, err


def _assert_refused(capsys, tmp_path, path, reason):
    rc, out, err = _run(capsys, path)
    assert rc == 1
    assert out == ""
    assert err == f"REFUSED file 1 of 1: {reason}\n"
    assert str(tmp_path) not in err
    return err


# --------------------------------------------------------------------------
# One test per way the file can be bad.
# --------------------------------------------------------------------------

def test_a_missing_file_is_refused(capsys, tmp_path):
    _assert_refused(capsys, tmp_path, tmp_path / "absent.json",
                    "the file cannot be read (No such file or directory)")


def test_a_directory_is_refused(capsys, tmp_path):
    """A directory opens on POSIX. It is refused by the regular-file check, not
    by an OSError."""
    _assert_refused(capsys, tmp_path, tmp_path, NOT_REGULAR)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_unreadable_file_is_refused(capsys, tmp_path):
    path = _write(tmp_path, "locked.json", MINIMAL)
    path.chmod(0)
    try:
        _assert_refused(capsys, tmp_path, path, "the file cannot be read (Permission denied)")
    finally:
        path.chmod(0o600)


def test_a_path_holding_a_nul_byte_is_refused(capsys, tmp_path):
    """No shell passes a NUL byte, but main(argv=[...]) can, and open() raises
    ValueError on it rather than OSError."""
    _assert_refused(capsys, tmp_path, f"{tmp_path}/a\0b.json", "the file cannot be read (ValueError)")


def test_a_file_that_is_not_utf8_is_refused(capsys, tmp_path):
    path = _write(tmp_path, "latin1.json", b'{"a": "\xff"}')
    _assert_refused(capsys, tmp_path, path, "the file is not UTF-8 (invalid byte at offset 7)")


def test_a_file_that_is_not_json_is_refused(capsys, tmp_path):
    path = _write(tmp_path, "broken.json", '{"a": 1,\n  oops}')
    _assert_refused(capsys, tmp_path, path,
                    "the file is not JSON (Expecting property name enclosed in double quotes"
                    " at line 2 column 3)")


def test_a_file_nested_deeper_than_the_parser_follows_is_refused(capsys, tmp_path):
    path = _write(tmp_path, "deep.json", "[" * UNPARSEABLE_DEPTH + "]" * UNPARSEABLE_DEPTH)
    _assert_refused(capsys, tmp_path, path, "the file nests deeper than the JSON parser can follow")


def test_a_file_holding_an_integer_json_loads_refuses_is_refused(capsys, tmp_path):
    """4301 digits: json.loads accepts 4300 and raises a bare ValueError one past
    it, which is not a JSONDecodeError and so needs its own guard. The figure is
    written out rather than read from the interpreter, so the test checks it."""
    path = _write(tmp_path, "wide.json", '{"n": ' + "9" * 4301 + "}")
    _assert_refused(capsys, tmp_path, path, "the file holds an integer wider than 4300 digits")


def test_the_integer_refusal_reports_the_limit_in_force(capsys, tmp_path):
    """The message reports the interpreter's limit, not the default. Under a
    raised limit a hard-coded 4300 would be wrong."""
    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(5000)
    try:
        path = _write(tmp_path, "wider.json", '{"n": ' + "9" * 5001 + "}")
        _assert_refused(capsys, tmp_path, path, "the file holds an integer wider than 5000 digits")
    finally:
        sys.set_int_max_str_digits(old)


def test_a_fifo_is_refused_without_blocking(tmp_path):
    """A FIFO with no writer used to block the CLI forever inside open(). Run
    in a subprocess so a regression fails on the timeout instead of hanging
    the suite."""
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    proc = subprocess.run([sys.executable, "-m", "cxbom.validator", str(fifo)],
                          capture_output=True, text=True, timeout=60, cwd=str(ROOT))
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert proc.stderr == f"REFUSED file 1 of 1: {NOT_REGULAR}\n"


def test_a_character_device_is_refused(capsys, tmp_path):
    """/dev/null is empty, so without the regular-file check it read as "not
    JSON". /dev/zero, the dangerous one, would read until memory ran out."""
    rc, out, err = _run(capsys, "/dev/null")
    assert (rc, out, err) == (1, "", f"REFUSED file 1 of 1: {NOT_REGULAR}\n")


# --------------------------------------------------------------------------
# Files that parse but used to crash the report.
# --------------------------------------------------------------------------

def _deep_list(depth):
    """A list nested depth levels, built without recursion, so it exists on every
    interpreter whether or not that interpreter's json.loads follows it."""
    outer = node = []
    for _ in range(depth - 1):
        node.append([])
        node = node[0]
    return outer


def _deep_text(depth):
    return "[" * depth + "]" * depth


def _depth_of(doc):
    """Levels of single-element nesting, counted iteratively. The empty list at
    the bottom counts as one level, as the text's first "[" does."""
    depth = 0
    while isinstance(doc, list):
        depth += 1
        assert len(doc) <= 1
        doc = doc[0] if doc else None
    return depth


def _deepest(succeeds):
    """The largest depth for which succeeds(depth) is True, where succeeds is True
    up to some limit and False past it. Doubling first keeps the probe cheap on
    3.10, whose limit is near 1,000. A limit past SEARCH_CEILING fails here
    instead of being reported as the ceiling."""
    lo, hi = 0, 1024
    while succeeds(hi):
        lo, hi = hi, hi * 2
        assert hi <= SEARCH_CEILING
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if succeeds(mid):
            lo = mid
        else:
            hi = mid
    return lo


def _no_recursion_error(fn):
    """True when fn() returns, False when it raises RecursionError. Any other
    exception propagates, so a third outcome cannot hide inside False."""
    try:
        fn()
    except RecursionError:
        return False
    return True


def _parse_limit():
    """The deepest list json.loads parses at this call depth."""
    return _deepest(lambda d: _no_recursion_error(lambda: json.loads(_deep_text(d))))


def _main_boundary(capsys, tmp_path):
    """The deepest list file validator.main reads past its parser, with main's
    result at that depth and one level deeper. 3.10 counts Python frames toward
    the parser's limit, so every call to main here runs from this one frame: a
    boundary measured a frame deeper than it is checked moves by that frame."""
    refused = f"REFUSED file 1 of 1: {TOO_DEEP}\n"
    path = tmp_path / "deep.json"
    lo, hi = 0, 1024
    while True:
        path.write_text(_deep_text(hi), encoding="utf-8")
        if _run(capsys, path)[2] == refused:
            break
        lo, hi = hi, hi * 2
        assert hi <= SEARCH_CEILING
    while hi - lo > 1:
        mid = (lo + hi) // 2
        path.write_text(_deep_text(mid), encoding="utf-8")
        if _run(capsys, path)[2] == refused:
            hi = mid
        else:
            lo = mid
    path.write_text(_deep_text(lo), encoding="utf-8")
    at = _run(capsys, path)
    path.write_text(_deep_text(lo + 1), encoding="utf-8")
    past = _run(capsys, path)
    return lo, at, past


def test_the_deep_record_premise_holds():
    """The window the next test relies on is a depth json.loads parses and repr()
    cannot render. Whether it exists depends on the interpreter. Measured at the
    same call depth, CPython 3.14.7 parses 116,200 levels and renders about
    69,700, while 3.10.18 parses 989 and renders 992 and 3.12.2 parses and
    renders 1,497. So on 3.10 and 3.12, the versions CI and the Jetson run, repr
    renders the deepest record the parser accepts and the window cannot be
    reached from a file. This pins that per version, so an interpreter that
    moves either limit fails here and says so. 3.13 was not measured and is not
    pinned."""
    parse = _parse_limit()
    doc = json.loads(_deep_text(parse))
    assert _depth_of(doc) == parse
    if sys.version_info >= (3, 14):
        with pytest.raises(RecursionError):
            repr(doc)
    elif sys.version_info < (3, 13):
        assert repr(doc) == _deep_text(parse)


def test_a_record_that_parses_but_nests_too_deeply_to_print_is_reported(capsys, tmp_path):
    """A document json.loads parses and repr() cannot render. validate_doc already
    caught jsonschema's RecursionError, but every _Reader fault rendered the
    document with repr() and raised the same error one layer in.

    The depth is a tenth below the parse limit this interpreter measures, which
    on 3.14 sits about 35,000 levels past the repr limit. Where repr renders that
    depth (3.10 and 3.12, pinned by the premise test), the property cannot be
    reached from a file, and the test instead reports the deepest file main
    parses, exactly, rendered whole or truncated as _show gives it. Whether
    jsonschema's own repr overflows at that last level depends on how far below
    main it runs (3.12.2 overflows there, 3.10.18 does not), so this asserts
    nothing about it. The same library-side guard is exercised on every
    interpreter by test_validator_nullsum.py on a constructed record."""
    parse = _parse_limit()
    depth = parse - parse // 10
    if not _no_recursion_error(lambda: repr(_deep_list(depth))):
        path = _write(tmp_path, "deep.json", _deep_text(depth))
        rc, out, err = _run(capsys, path)
        assert rc == 1
        assert err == ""
        assert "  - the document cannot be schema-checked: RecursionError" in out
        shown = "[" * 10_000 + " ... (truncated)"
        assert f"  - contextComponents is unreadable: {shown} is not an object\n" in out
        return
    depth, (rc, out, err), _ = _main_boundary(capsys, tmp_path)
    assert depth > 1
    assert rc == 1
    assert err == ""
    text = _deep_text(depth)
    shown = text if len(text) <= 10_000 else text[:10_000] + " ... (truncated)"
    assert f"  - contextComponents is unreadable: {shown} is not an object\n" in out


def test_a_file_one_level_past_the_deepest_main_parses_is_refused(capsys, tmp_path):
    """The refusal at the boundary this interpreter draws, not at a depth chosen
    for one interpreter. main parses the deepest depth and refuses one more."""
    depth, at, past = _main_boundary(capsys, tmp_path)
    assert depth > 1
    assert at[2] == ""
    assert past == (1, "", f"REFUSED file 1 of 1: {TOO_DEEP}\n")


def test_show_bounds_a_container_repr_cannot_render():
    """_show walks iteratively and stops at _SHOW_LIMIT characters, so depth
    costs neither a RecursionError nor time."""
    deep_list, deep_dict = [], {}
    node_l, node_d = deep_list, deep_dict
    for _ in range(1_000_000):
        node_l.append([])
        node_l = node_l[0]
        node_d["a"] = {}
        node_d = node_d["a"]
    assert validator._show(deep_list) == "[" * 10_000 + " ... (truncated)"
    assert validator._show(deep_dict) == ("{'a': " * 1700)[:10_000] + " ... (truncated)"


def test_a_finding_quoting_a_lone_surrogate_prints(capsys, tmp_path):
    """\\ud800 is valid JSON and check_crosswalk quotes an unresolved code
    verbatim. print() raised UnicodeEncodeError on it after the FAIL line,
    which is a traceback halfway through a report."""
    doc = json.loads(MINIMAL)
    doc["findings"][0]["owaspRefs"][0] = "LLM\ud800"
    path = _write(tmp_path, "surrogate.json", json.dumps(doc))
    rc, out, err = _run(capsys, path)
    assert rc == 1
    assert err == ""
    assert "  - finding finding-001: owaspRefs LLM\\ud800 unresolved in owasp-llm-2026\n" in out


# --------------------------------------------------------------------------
# Several files: a refusal does not stop the run and does not hide a pass.
# --------------------------------------------------------------------------

def test_a_refused_file_does_not_stop_the_next_one(capsys, tmp_path):
    good = _write(tmp_path, "good.json", MINIMAL)
    bad = _write(tmp_path, "bad.json", "{")
    rc, out, err = _run(capsys, bad, good)
    assert rc == 1
    assert out == "OK   file 2 of 2\n"
    assert err == "REFUSED file 1 of 2: the file is not JSON (Expecting property name enclosed" \
                  " in double quotes at line 1 column 2)\n"


def test_a_clean_file_still_passes(capsys, tmp_path):
    good = _write(tmp_path, "good.json", MINIMAL)
    assert _run(capsys, good) == (0, "OK   file 1 of 1\n", "")


# --------------------------------------------------------------------------
# The process: exit status and no traceback, through python -m.
# --------------------------------------------------------------------------

BAD_FILES = {
    "missing": None,
    "not-utf8": b'{"a": "\xff"}',
    "not-json": "{",
    "too-deep": "[" * UNPARSEABLE_DEPTH + "]" * UNPARSEABLE_DEPTH,
    "wide-int": '{"n": ' + "9" * 4301 + "}",
}


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_the_cli_process_exits_1_without_a_traceback(tmp_path, case):
    path = tmp_path / f"{case}.json"
    if BAD_FILES[case] is not None:
        _write(tmp_path, path.name, BAD_FILES[case])
    proc = subprocess.run([sys.executable, "-m", "cxbom.validator", str(path)],
                          capture_output=True, text=True, timeout=300, cwd=str(ROOT))
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr, proc.stderr
    # Exactly one line, counted over all of stderr. runpy used to add a
    # RuntimeWarning line on every `python -m cxbom.validator`, because
    # cxbom/__init__.py imported the validator eagerly before runpy ran it.
    lines = proc.stderr.splitlines()
    assert len(lines) == 1 and lines[0].startswith("REFUSED file 1 of 1: "), proc.stderr
    assert str(tmp_path) not in lines[0]


def test_the_cli_process_prints_a_character_its_stream_cannot_encode(tmp_path):
    """A finding quotes the record. Under an ASCII stream it used to raise
    UnicodeEncodeError. The FAIL and OK lines name the files by position, so
    the non-ASCII file names never reach the stream."""
    doc = json.loads(MINIMAL)
    doc["findings"][0]["owaspRefs"][0] = "LLMé"
    bad = _write(tmp_path, "accént.json", json.dumps(doc))
    good = _write(tmp_path, "clean-é.json", MINIMAL)
    env = dict(os.environ, PYTHONIOENCODING="ascii")
    proc = subprocess.run([sys.executable, "-m", "cxbom.validator", str(bad), str(good)],
                          capture_output=True, text=True, timeout=300, cwd=str(ROOT), env=env)
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0] == "FAIL file 1 of 2"
    assert "  - finding finding-001: owaspRefs LLM\\xe9 unresolved in owasp-llm-2026" in lines
    assert lines[-1] == "OK   file 2 of 2"


def test_the_cli_fails_closed_when_jsonschema_cannot_check_a_date_time(tmp_path):
    """Without jsonschema's date-time checker, "date-time" is skipped silently. The
    CLI then printed OK for a record whose timestamp is not a date-time, once
    the package stopped importing its API eagerly. The package import refuses
    first now, so the run fails and no OK line appears."""
    doc = json.loads(MINIMAL)
    doc["metadata"]["timestamp"] = "not-a-time"
    path = _write(tmp_path, "badtime.json", json.dumps(doc))
    code = ("import runpy, sys\n"
            "sys.modules['rfc3339_validator'] = None\n"
            "sys.argv = ['cxbom.validator', sys.argv[1]]\n"
            "runpy._run_module_as_main('cxbom.validator')\n")  # what python -m calls
    proc = subprocess.run([sys.executable, "-c", code, str(path)],
                          capture_output=True, text=True, timeout=300, cwd=str(ROOT))
    assert proc.returncode != 0
    assert proc.stdout == ""
    lines = proc.stderr.splitlines()
    assert len(lines) == 1 and "jsonschema FormatChecker lacks date-time" in lines[0], proc.stderr
    assert "jsonschema[format-nongpl] and rfc3339-validator" in lines[0]


# --------------------------------------------------------------------------
# Output is bounded: one emitted line is one physical line (fix round 1, I1).
# --------------------------------------------------------------------------

FORGED = "LLM\n  - x\nOK   forged.json\x1b[31mRED\x1b[0m"


def test_a_record_cannot_forge_an_ok_line(capsys, tmp_path):
    """The reviewer's payload. check_crosswalk quotes an unresolved code
    verbatim, so the record chose these bytes, and before the bound they
    printed an OK line of their own and raw escape sequences."""
    doc = json.loads(MINIMAL)
    doc["findings"][0]["owaspRefs"][0] = FORGED
    path = _write(tmp_path, "forged.json", json.dumps(doc))
    rc, out, err = _run(capsys, path)
    assert (rc, err) == (1, "")
    assert not [line for line in out.splitlines() if line.startswith("OK")]
    assert "\x1b" not in out
    assert ("  - finding finding-001: owaspRefs LLM\\x0a  - x\\x0aOK   forged.json\\x1b[31mRED\\x1b[0m"
            " unresolved in owasp-llm-2026\n") in out


def test_a_file_name_holding_a_newline_cannot_forge_an_ok_line(capsys, tmp_path):
    doc = json.loads(MINIMAL)
    doc["findings"][0]["owaspRefs"][0] = "LLM99"
    path = _write(tmp_path, "x\nOK   good.json", json.dumps(doc))
    rc, out, err = _run(capsys, path)
    assert (rc, err) == (1, "")
    lines = out.splitlines()
    assert lines[0] == "FAIL file 1 of 1"
    assert all(line.startswith("  - ") for line in lines[1:])


# Every class str.splitlines() breaks on, the terminal escape, and a
# bidirectional override that reorders what follows it on screen.
@pytest.mark.parametrize("ch, shown", [
    ("\n", "\\x0a"), ("\r", "\\x0d"), ("\x0b", "\\x0b"), ("\x0c", "\\x0c"), ("\x1c", "\\x1c"),
    ("\x1d", "\\x1d"), ("\x1e", "\\x1e"), ("\x85", "\\x85"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029"),
    ("\x1b", "\\x1b"), ("\x7f", "\\x7f"), ("\x9b", "\\x9b"), ("\x00", "\\x00"), ("\t", "\\x09"),
    ("\u202e", "\\u202e"), ("\ud800", "\\ud800"), ("\U000e0001", "\\U000e0001"),
])
def test_emit_writes_one_physical_line_whatever_the_text_holds(ch, shown):
    import io
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    validator._emit(stream, f"a{ch}b")
    stream.flush()
    written = stream.buffer.getvalue().decode("utf-8")
    assert written == f"a{shown}b\n"
    assert len(written.splitlines()) == 1


def test_emit_leaves_printable_text_alone():
    import io
    stream = io.StringIO()
    validator._emit(stream, "OK   é ü 漢 \\ ' \" plain")
    assert stream.getvalue() == "OK   é ü 漢 \\ ' \" plain\n"
