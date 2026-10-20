"""RFC 3339 time helpers. Owner: ATACE Working Group.

datetime.fromisoformat accepts a different grammar on every Python version:
3.10 rejects a trailing "Z" and any fraction that is not 3 or 6 digits, and
3.11+ accepts a space separator, basic format, and offsets without a colon.
A verdict that depends on the interpreter is a parser differential, so every
parse goes through one regex here and builds the datetime by hand.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s: str) -> datetime:
    """Parse an RFC 3339 date-time into an aware UTC datetime.

    Fractions of any length are truncated to microseconds.

    Raises:
        ValueError: s is not a str, does not match the grammar, names a
            calendar-invalid date or time, or has an out-of-range offset.
    """
    # A str \d also matches non-ASCII digits, so the input must be ASCII.
    # fullmatch refuses the trailing newline that "$" alone would allow.
    if not isinstance(s, str) or not s.isascii():
        raise ValueError(f"not an RFC 3339 time: {s!r}")
    m = RFC3339.fullmatch(s)
    if m is None:
        raise ValueError(f"not an RFC 3339 time: {s!r}")
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    frac, zone = m.group(7), m.group(8)
    micro = int((frac[1:] + "00000")[:6]) if frac else 0
    if zone == "Z":
        offset = timedelta(0)
    else:
        oh, om = int(zone[1:3]), int(zone[4:6])
        if oh > 23 or om > 59:
            raise ValueError(f"time offset out of range: {s!r}")
        offset = timedelta(hours=oh, minutes=om)
        if zone[0] == "-":
            offset = -offset
    # datetime() raises ValueError for Feb 30, hour 24, second 60, and so on.
    value = datetime(year, month, day, hour, minute, second, micro, tzinfo=timezone(offset))
    try:
        return value.astimezone(timezone.utc)
    except OverflowError:
        # An offset can push year 1 or year 9999 past datetime's range.
        raise ValueError(f"time out of range: {s!r}") from None
