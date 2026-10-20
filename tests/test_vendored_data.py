"""Package data copies must equal their contract sources. Owner: ATACE Working Group."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = [("contracts/proxy/lockfile.schema.json", "cxbom/_data/lockfile.schema.json"),
         ("contracts/proxy/attestation-line.schema.json", "cxbom/_data/attestation-line.schema.json")]


def test_package_data_matches_contracts():
    for src, dst in PAIRS:
        assert (ROOT / src).read_bytes() == (ROOT / dst).read_bytes(), f"{dst} drifted from {src}"
