"""Edge cases from the Plan 1 final re-review. Owner: ATACE Working Group."""
import json
from pathlib import Path

import pytest

from cxbom import attestation as at
from cxbom import timeutil
from cxbom.canonical import IgnoredFieldError, tool_sha256

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("s", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_parse_time_range_overflow_is_value_error(s):
    with pytest.raises(ValueError):
        timeutil.parse_time(s)


def test_ignored_meta_time_overflow_stays_in_canonical_errors():
    tool = {"name": "t", "inputSchema": {"type": "object"}, "_meta": {"ts": "0001-01-01T00:00:00+01:00"}}
    with pytest.raises(IgnoredFieldError):
        tool_sha256(tool, ["/_meta/ts"])


def test_schema_patterns_refuse_trailing_newline():
    lines = at.read_log(ROOT / "contracts/proxy/example.attestation.jsonl")
    assert at.check_log(lines) == []
    bad = [dict(l) for l in lines]
    for line in bad:
        if line["kind"] == "verdict":
            line["sha256"] = line["sha256"] + "\n"
    assert at.check_log(bad)
