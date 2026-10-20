"""RFC 3339 helpers. Owner: ATACE Working Group."""
from datetime import timezone

import pytest

from cxbom.timeutil import now_rfc3339, parse_time


def test_now_is_utc_z():
    s = now_rfc3339()
    assert s.endswith("Z") and "T" in s
    assert parse_time(s).tzinfo is not None


def test_parse_accepts_z_and_offset_on_310():
    assert parse_time("2026-10-10T18:00:00Z").utcoffset().total_seconds() == 0
    assert parse_time("2026-10-10T20:00:00+02:00") == parse_time("2026-10-10T18:00:00Z")


def test_parse_rejects_naive():
    with pytest.raises(ValueError):
        parse_time("2026-10-10T18:00:00")


# --- Final review C1: one RFC 3339 grammar on every Python version ---


@pytest.mark.parametrize("frac, micro", [
    (".5", 500000), (".123", 123000), (".12345", 123450), (".123456", 123456), (".123456789", 123456),
])
def test_fractions_of_any_length_parse_and_truncate(frac, micro):
    t = parse_time(f"2026-10-10T18:00:00{frac}Z")
    assert t.microsecond == micro
    assert t.utcoffset().total_seconds() == 0


def test_result_is_utc():
    t = parse_time("2026-10-10T20:30:00.25+02:30")
    assert t.tzinfo == timezone.utc
    assert (t.hour, t.minute, t.microsecond) == (18, 0, 250000)


@pytest.mark.parametrize("bad", [
    "2026-02-30T00:00:00Z",          # calendar-invalid
    "2026-10-10T24:00:00Z",
    "2026-10-10T18:00:60Z",
    "2026-10-10 18:00:00Z",          # space separator (3.11+ fromisoformat accepts it)
    "20261010T180000Z",              # basic format
    "2026-10-10T18:00Z",             # no seconds
    "2026-10-10T18:00:00+0200",      # offset without a colon
    "2026-10-10T18:00:00+24:00",     # offset out of range
    "2026-10-10T18:00:00+05:60",
    "2026-10-10t18:00:00z",          # lowercase designators
    "2026-10-10T18:00:00.Z",
    "2026-10-10T18:00:00",           # naive
    "2026-10-10T18:00:00Z\n",
    "",
])
def test_rejects_everything_outside_the_grammar(bad):
    with pytest.raises(ValueError):
        parse_time(bad)


@pytest.mark.parametrize("not_str", [None, 20261010, b"2026-10-10T18:00:00Z"])
def test_non_str_is_value_error(not_str):
    with pytest.raises(ValueError):
        parse_time(not_str)
