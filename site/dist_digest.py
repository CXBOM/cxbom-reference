"""One sha256 over a built site directory, so deploy ships only what build made.

Owner: ATACE Working Group.

Usage (from the repository root):
    python site/dist_digest.py site/dist              prints sha256=<hex>
    python site/dist_digest.py site/dist --expect HEX  exits 0 only on a match
Exit 0 on success, 1 on a mismatch or a tree it refuses, 2 on a usage error.

The build job prints the digest into its job outputs right before it uploads
site/dist. The deploy job recomputes it over the artifact it downloaded and
stops before wrangler if the two differ. Any job in the run can replace an
artifact, but no job can change another job's outputs, so the check does not
depend on how artifact downloads behave.

The digest is sha256 over a manifest with one line per regular file, sorted by
the file's path relative to the root, as bytes: the file's own sha256 in hex,
two spaces, the path, a newline. Paths are part of the digest, so a renamed,
added or removed file changes it as surely as a changed byte.

The tree is refused, not digested, when it holds something the artifact would
not carry faithfully: a symlink, anything that is neither a directory nor a
regular file, a name starting with "." (upload-artifact drops hidden files, so
the digest would cover files the artifact lacks), or a newline in a name (it
would make the manifest ambiguous). An empty tree is refused too, because it
digests to a constant that proves nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import sys
from pathlib import Path

HEX64 = re.compile(r"[0-9a-f]{64}")


class RefusedTree(Exception):
    """The directory holds something the digest cannot vouch for."""


def _files(root: Path, rel: str = "") -> list[tuple[bytes, Path]]:
    out: list[tuple[bytes, Path]] = []
    with os.scandir(root / rel if rel else root) as entries:
        for entry in entries:
            name = entry.name
            path = f"{rel}/{name}" if rel else name
            if name.startswith(".") or "\n" in name:
                raise RefusedTree(f"hidden or unsafe name: {path!r}")
            # Neither test follows a link, so a symlink matches neither and
            # lands in the refusal below with every other special file.
            if entry.is_dir(follow_symlinks=False):
                out.extend(_files(root, path))
            elif entry.is_file(follow_symlinks=False):
                out.append((os.fsencode(path), Path(entry.path)))
            else:
                raise RefusedTree(f"symlink or other non-regular file: {path!r}")
    return out


def digest(root: Path) -> str:
    """Return the hex sha256 of the manifest of every file under root."""
    if root.is_symlink() or not root.is_dir():
        raise RefusedTree(f"not a directory: {root}")
    files = sorted(_files(root))
    if not files:
        raise RefusedTree(f"no files under {root}")
    manifest = hashlib.sha256()
    for rel, path in files:
        body = hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii")
        manifest.update(body + b"  " + rel + b"\n")
    return manifest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", type=Path)
    ap.add_argument("--expect", help="the 64-hex digest the build job recorded")
    args = ap.parse_args(argv)
    # An empty or malformed expectation means the build output never arrived.
    # Refuse it rather than compare against it.
    if args.expect is not None and not HEX64.fullmatch(args.expect):
        print(f"dist_digest: expected digest is not 64 lowercase hex: {args.expect!r}", file=sys.stderr)
        return 2
    try:
        got = digest(args.root)
    except (RefusedTree, OSError) as exc:
        print(f"dist_digest: refused {args.root}: {exc}", file=sys.stderr)
        return 1
    if args.expect is None:
        print(f"sha256={got}")
        return 0
    if not hmac.compare_digest(got, args.expect):
        print(f"dist_digest: {args.root} digests to {got}, the build recorded {args.expect}", file=sys.stderr)
        return 1
    print(f"dist_digest: {args.root} matches the build: {got}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
