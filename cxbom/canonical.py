"""RFC 8785 canonical hashing for tools, instructions, launches and trees.

Owner: ATACE Working Group.

The whole wire object is hashed so that any field change is a change. The only
exception is approved ignore pointers: exact leaves under /_meta. Their values
must stay benign at every verdict, because renderers and clients still see
them (premortem C6).
"""
from __future__ import annotations

import copy
import hashlib
import math
import os
import stat
from pathlib import Path
from typing import Sequence

import rfc8785

from . import timeutil

class CanonicalizationError(ValueError):
    """Value is outside the I-JSON domain RFC 8785 requires, or a tree is unsafe."""


class IgnoredFieldError(ValueError):
    """An ignore pointer is malformed, or the value at it is no longer benign."""


def canonical(obj) -> bytes:
    try:
        return rfc8785.dumps(obj)
    except rfc8785.CanonicalizationError as e:
        raise CanonicalizationError(str(e)) from None


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def object_sha256(obj) -> str:
    return sha256_hex(canonical(obj))


def _tokens(ptr: str) -> list[str]:
    return [t.replace("~1", "/").replace("~0", "~") for t in ptr.split("/")[1:]]


def validate_ignore_pointer(ptr: str) -> None:
    if not ptr.startswith("/_meta/"):
        raise IgnoredFieldError(f"ignore pointer must be under /_meta: {ptr!r}")
    toks = _tokens(ptr)
    if len(toks) < 2 or any(t == "" for t in toks):
        raise IgnoredFieldError(f"ignore pointer must name an exact leaf: {ptr!r}")


def ignored_value_ok(v) -> bool:
    if v is None:
        return True
    if isinstance(v, bool):
        return True
    if isinstance(v, int):
        return math.isfinite(v) and abs(v) <= 2**53
    if isinstance(v, float):
        return math.isfinite(v) and abs(v) <= 2**53
    if isinstance(v, str) and len(v.encode("utf-8")) <= 40:
        # timeutil.parse_time owns the one RFC 3339 grammar, so this verdict
        # does not change with the Python version.
        try:
            timeutil.parse_time(v)
            return True
        except ValueError:
            return False
    return False


def _strip(obj: dict, ptr: str) -> None:
    toks = _tokens(ptr)
    cur = obj
    for t in toks[:-1]:
        if not isinstance(cur, dict) or t not in cur:
            return
        cur = cur[t]
    if isinstance(cur, dict) and toks[-1] in cur:
        value = cur[toks[-1]]
        if not ignored_value_ok(value):
            raise IgnoredFieldError(f"value at {ptr} is no longer a benign leaf")
        del cur[toks[-1]]


def tool_sha256(tool: dict, ignore: Sequence[str] = ()) -> str:
    stripped = copy.deepcopy(tool)
    for ptr in ignore:
        validate_ignore_pointer(ptr)
        _strip(stripped, ptr)
    return object_sha256(stripped)


def instructions_sha256(s: str) -> str:
    return object_sha256(s)


def launch_sha256(launch: dict) -> str:
    return object_sha256(launch)


def file_sha256(path: Path) -> str:
    """SHA-256 of a regular file's bytes.

    Raises:
        CanonicalizationError: the path is missing, unreadable, a symlink, or
            not a regular file. The message names only the file, never its
            absolute path.
    """
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise CanonicalizationError(f"{path.name}: not a regular file")
        return sha256_hex(path.read_bytes())
    except OSError as e:
        raise CanonicalizationError(f"{path.name}: {e.strerror}") from None


def _walk_error(e: OSError) -> None:
    # os.walk skips a directory it cannot list unless onerror raises, and a
    # skipped directory would hash as if its files were not there.
    name = Path(e.filename).name if e.filename else "tree"
    raise CanonicalizationError(f"{name}: {e.strerror}")


def tree_sha256(root: Path) -> str:
    """SHA-256 over the sorted (relative path, file hash) pairs of a tree.

    Raises:
        CanonicalizationError: the root is missing or not a real directory,
            the tree holds a symlink, or any directory or file is unreadable.
    """
    try:
        st = os.lstat(root)
    except OSError as e:
        raise CanonicalizationError(f"{root.name}: {e.strerror}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise CanonicalizationError(f"{root.name}: pinned tree root must be a real directory")
    pairs = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=_walk_error, followlinks=False):
        for name in dirnames + filenames:
            if os.path.islink(os.path.join(dirpath, name)):
                raise CanonicalizationError(f"symlink in pinned tree: {name}")
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            pairs.append([full.relative_to(root).as_posix(), file_sha256(full)])
    return object_sha256(sorted(pairs))
