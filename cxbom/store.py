"""Content-addressed store for wire definitions and rendered texts.

Owner: ATACE Working Group.

Readers recompute the hash before returning anything, so a modified store file
can't pass as approved content. Files are 0600 in 0700 directories. Changed
definitions are kept unredacted here and never go into bundles (spec 5).
"""
from __future__ import annotations

import re
from pathlib import Path

from .canonical import CanonicalizationError, canonical, object_sha256, sha256_hex
from .jsonstrict import StrictJSONError, parse as parse_json, to_python
from .paths import ensure_private_dir
from . import signing


class StoreError(RuntimeError):
    """A store object is missing or does not match its hash."""


class Store:
    def __init__(self, root: Path):
        self.root = ensure_private_dir(root)
        self._defs = ensure_private_dir(root / "defs")
        self._text = ensure_private_dir(root / "text")

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        try:
            signing._atomic_write(path, data)
        except OSError as e:
            raise StoreError(f"{path.name}: {e.strerror}") from None

    def put_json(self, obj) -> str:
        """Store obj under its RFC 8785 hash and return the hash.

        Raises:
            StoreError: obj is outside the I-JSON domain, or the write failed.
        """
        try:
            data = canonical(obj)
        except CanonicalizationError as e:
            raise StoreError(f"object cannot be canonicalized: {e}") from None
        h = sha256_hex(data)
        self._write(self._defs / f"{h}.json", data)
        return h

    def get_json(self, sha: str):
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise StoreError("invalid store hash")
        path = self._defs / f"{sha}.json"
        try:
            data = path.read_bytes()
        except OSError:
            raise StoreError(f"missing store object {sha[:16]}") from None
        try:
            node = parse_json(data)
            obj = to_python(node)
            if object_sha256(obj) != sha:
                raise StoreError(f"store object {sha[:16]} does not match its hash")
        except (StrictJSONError, CanonicalizationError, ValueError):
            raise StoreError(f"store object {sha[:16]} is not valid") from None
        return obj

    def put_text(self, text: str) -> str:
        data = text.encode("utf-8")
        h = sha256_hex(data)
        self._write(self._text / f"{h}.txt", data)
        return h

    def get_text(self, sha: str) -> str:
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise StoreError("invalid store hash")
        path = self._text / f"{sha}.txt"
        try:
            data = path.read_bytes()
        except OSError:
            raise StoreError(f"missing store text {sha[:16]}") from None
        if sha256_hex(data) != sha:
            raise StoreError(f"store text {sha[:16]} does not match its hash")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise StoreError(f"store text {sha[:16]} is not valid UTF-8") from None
