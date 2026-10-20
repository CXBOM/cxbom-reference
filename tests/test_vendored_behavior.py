"""The vendored validator, crosswalk and detector run from package data, offline.

Owner: ATACE Working Group.
"""
import copy
import json
import socket
from pathlib import Path

import pytest

from cxbom import crosswalk, detectors, validator

ROOT = Path(__file__).resolve().parents[1]
MINIMAL = json.loads((ROOT / "tests/fixtures/atace/valid-minimal.json").read_text(encoding="utf-8"))


def test_data_paths_resolve_inside_the_package():
    pkg = (ROOT / "cxbom").resolve()
    assert validator._SCHEMA_PATH.resolve() == pkg / "_data" / "cxbom-0.2.0.schema.json"
    assert crosswalk._CAT.resolve() == pkg / "_data" / "catalogs"


def test_minimal_record_passes_offline(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("the validator opened a socket")
    monkeypatch.setattr(socket, "socket", refuse)
    assert validator.check_all(MINIMAL) == []


def test_timestamp_yesterday_fails():
    doc = copy.deepcopy(MINIMAL)
    doc["metadata"]["timestamp"] = "yesterday"
    assert any("date-time" in e for e in validator.check_all(doc))


@pytest.mark.parametrize("name", ["owasp-llm-2025", "owasp-llm-2026", "owasp-asi-2026", "cwe", "atlas"])
def test_catalogs_load_with_hash_guard(name):
    assert crosswalk.load_catalog(name)
    with pytest.raises(crosswalk.CatalogIntegrityError):
        crosswalk.load_catalog(name, _force_hash="0" * 64)


def test_detector_flags_third_party_schema_block_only_without_label():
    comp = {"type": "tool-definition", "source": {"thirdParty": True},
            "content": {"positionInContext": "tool-schema-block"}, "sanitization": {}}
    assert detectors.detect_trust_inversion(comp)["detected"] is True
    comp["sanitization"]["trustLabel"] = "cxbom-untrusted-tool"
    assert detectors.detect_trust_inversion(comp)["detected"] is False
