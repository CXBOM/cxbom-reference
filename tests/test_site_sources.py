"""The records the site serves are the vendored ATACE records, and they validate.

Owner: ATACE Working Group.

Their bytes are pinned under "vendored" in spec/published.lock.json and checked
by tests/test_vendored_atace.py. This file checks what the site relies on.
"""
import json
from pathlib import Path

import pytest

from cxbom import conformance

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ID = "https://cxbom.org/schema/0.2.0/cxbom.schema.json"
EXAMPLES = sorted(ROOT.glob("spec/cxbom_example_*.json"))
REFERENCE = ROOT / "site/data/session_reference.json"


def test_three_examples_are_present():
    assert [p.name for p in EXAMPLES] == [
        "cxbom_example_clean_baseline.json",
        "cxbom_example_finance_assistant.json",
        "cxbom_example_multiturn_ring1derived.json",
    ]


@pytest.mark.parametrize("path", EXAMPLES + [REFERENCE], ids=lambda p: p.name)
def test_record_validates_and_names_the_published_schema(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert conformance.check_all(doc) == []
    expected = f"https://cxbom.org/schema/{doc['specVersion']}/cxbom.schema.json"
    assert doc["metadata"]["generatedBy"]["schema"] == expected


def test_reference_session_token_accounting():
    doc = json.loads(REFERENCE.read_text(encoding="utf-8"))
    summary = doc["sessionSummary"]
    rings = summary["componentBreakdown"]["byTrustRing"]
    assert [rings[k]["tokens"] for k in ("ring0", "ring1", "ring2")] == [45, 46131, 16]
    assert summary["totalContextTokens"] == 46192
    assert summary["templateOverheadTokens"] == 13
    assert doc["metadata"]["session"]["contextWindowTokensUsed"] == 46205
