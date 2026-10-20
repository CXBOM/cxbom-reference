"""Version-aware conformance for CxBOM records.

Owner: ATACE Working Group.

The vendored validator in `cxbom/validator.py` is the ATACE 0.2.0 validator,
kept byte-identical to its upstream except for the declared packaging patches.
This module is the local seam that lets the current release write 0.3.0 records
while the 0.2.0 file stays readable for the recorded takes and the ATACE copy.

It does not copy a single check. It points the vendored module at the schema the
record names, briefly, and calls the same `check_all`. The swap is process-wide,
so this module is not thread-safe; every caller in this package emits on one
thread, and a caller that needs concurrency should serialize around it.
"""
from __future__ import annotations

from contextlib import contextmanager

from . import validator

SCHEMA_VERSION = "0.3.0"
SCHEMA_VERSIONS = ("0.2.0", "0.3.0")


def record_version(doc) -> str:
    """The version a record names, or the write version when it names none."""
    if isinstance(doc, dict) and doc.get("specVersion") in SCHEMA_VERSIONS:
        return doc["specVersion"]
    return SCHEMA_VERSION


@contextmanager
def _at(version: str):
    if version not in SCHEMA_VERSIONS:
        raise ValueError(f"unknown schema version {version!r}")
    old_path, old_version = validator._SCHEMA_PATH, validator.SCHEMA_VERSION
    validator._SCHEMA_PATH = validator._SPEC / f"cxbom-{version}.schema.json"
    validator.SCHEMA_VERSION = version
    try:
        yield
    finally:
        validator._SCHEMA_PATH, validator.SCHEMA_VERSION = old_path, old_version


def load_schema(version: str | None = None) -> dict:
    with _at(SCHEMA_VERSION if version is None else version):
        return validator.load_schema()


def make_validator(version: str | None = None):
    with _at(SCHEMA_VERSION if version is None else version):
        return validator.make_validator()


def validate_doc(doc: dict) -> list[str]:
    with _at(record_version(doc)):
        return validator.validate_doc(doc)


def check_all(doc: dict, submission_mode: bool = False) -> list[str]:
    with _at(record_version(doc)):
        return validator.check_all(doc, submission_mode=submission_mode)
