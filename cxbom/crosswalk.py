"""OWASP LLM 2025->2026 crosswalk with content-hashed catalog integrity.

The migration is a RENUMBERING, not a relabel: the same code means a different
category between years. We migrate by category NAME and then verify name
stability, so a well-formed find-replace corruption (which resolves fine against
an id-shape regex) is caught. Catalog snapshots are content-hashed; a silent edit
to a vendored snapshot fails the loader.

Owner: ATACE Working Group.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re

_CAT = pathlib.Path(str(__import__("importlib.resources", fromlist=["files"]).files("cxbom"))) / "_data" / "catalogs"


class CatalogIntegrityError(Exception):
    """A vendored catalog snapshot does not match its recorded content hash."""


class UnknownCatalogId(Exception):
    """A code does not resolve in the named catalog."""


class RenumberingCorruption(Exception):
    """A 2025->2026 mapping changes the category name outside a declared rename."""


# 2025 -> 2026 by category NAME (see fixtures/catalogs/SOURCES.md).
LLM_2025_TO_2026: dict[str, str] = {
    "LLM01": "LLM01",  # Prompt Injection
    "LLM02": "LLM02",  # Sensitive Information Disclosure
    "LLM03": "LLM04",  # Supply Chain
    "LLM04": "LLM05",  # Data and Model Poisoning
    "LLM05": "LLM10",  # Improper Output Handling
    "LLM06": "LLM03",  # Excessive Agency
    "LLM07": "LLM08",  # System Prompt Leakage -> Hidden Context Exposure (rename)
    "LLM08": "LLM09",  # Vector and Embedding Weaknesses
    "LLM09": "LLM07",  # Misinformation
    "LLM10": "LLM06",  # Unbounded Consumption
}

# Codes whose category was renamed (not merely renumbered). Name-stability is
# not asserted for these; each carries a written justification.
RENAME_EXCEPTIONS: dict[str, str] = {"LLM07": "LLM08"}
RENAME_JUSTIFICATIONS: dict[str, str] = {
    "LLM07": (
        "2025 'System Prompt Leakage' has no same-name 2026 entry. It was reworked "
        "into the broader 2026 LLM08 'Hidden Context Exposure' (verified against the "
        "pinned 2026/final source)."
    )
}

_STOPWORDS = {"and", "the", "of", "for", "a", "an"}


def _normalize(title: str) -> str:
    """Normalize a category title for name-stability comparison (robust to
    punctuation, case, and stopword rewording)."""
    t = title.lower().replace("&", "and")
    t = re.sub(r"[^a-z0-9\s]", " ", t)
    tokens = [w for w in t.split() if w not in _STOPWORDS]
    return " ".join(tokens)


def _expected_hash(name: str) -> str:
    sources = json.loads((_CAT / "SOURCES.json").read_text(encoding="utf-8"))
    for e in sources:
        if e["file"] == f"{name}.json":
            return e["sha256"]
    raise CatalogIntegrityError(f"no SOURCES.json entry for {name}")


def load_catalog(name: str, _force_hash: str | None = None) -> dict[str, str]:
    """Load a vendored catalog, verifying its content hash. `_force_hash` is a
    test seam to inject a wrong expected hash and prove the guard fires."""
    path = _CAT / f"{name}.json"
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    expected = _force_hash if _force_hash is not None else _expected_hash(name)
    if actual != expected:
        raise CatalogIntegrityError(
            f"{name}.json hash {actual[:12]} != expected {expected[:12]}"
        )
    return json.loads(raw.decode("utf-8"))


def resolve(code: str, catalog: str) -> str:
    """Return the canonical title for `code` in `catalog`, or raise."""
    cat = load_catalog(catalog)
    if code not in cat:
        raise UnknownCatalogId(f"{code} not in {catalog}")
    return cat[code]


def assert_name_stability(
    map_2025_2026: dict[str, str],
    cat25: dict[str, str],
    cat26: dict[str, str],
    exceptions: dict[str, str],
) -> None:
    """Raise RenumberingCorruption if any non-exception mapping changes the
    (normalized) category name between 2025 and 2026."""
    for code25, code26 in map_2025_2026.items():
        if code25 in exceptions:
            continue
        name25 = cat25.get(code25)
        name26 = cat26.get(code26)
        if name25 is None or name26 is None:
            raise RenumberingCorruption(
                f"missing title for {code25}->{code26} ({name25!r}->{name26!r})"
            )
        if _normalize(name25) != _normalize(name26):
            raise RenumberingCorruption(
                f"{code25} '{name25}' -> {code26} '{name26}' changes category name"
            )
