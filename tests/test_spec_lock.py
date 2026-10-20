"""Immutable published artifacts keep their exact bytes.

Owner: ATACE Working Group.

The 0.2.0 schema is printed as the `$id` in a paper under review, so the file
served at that URL must never change. A new schema version gets a new path.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"


def test_locked_artifacts_match_their_hashes():
    lock = json.loads((SPEC / "published.lock.json").read_text())
    for name, entry in lock.items():
        if name == "vendored":           # vendored files are checked in test_vendored_atace.py
            continue
        path = ROOT / name if (ROOT / name).is_file() else SPEC / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"{name} changed after publication"


def test_schema_id_matches_served_path():
    lock = json.loads((SPEC / "published.lock.json").read_text())
    for name, entry in lock.items():
        if name.endswith(".schema.json"):
            assert json.loads((SPEC / name).read_text())["$id"] == entry["servedAt"]
