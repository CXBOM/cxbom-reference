"""Build the cxbom wheel reproducibly (spec 12).

Owner: ATACE Working Group.

Usage:
    python scripts/build_wheel.py --out DIR

Builds only from committed sources: it refuses when cxbom/, pyproject.toml,
LICENSE or NOTICE differ from HEAD, because a wheel must equal what a commit
says. SOURCE_DATE_EPOCH is the time of the last commit that touched those
files, so the Mac and the Jetson build byte-identical wheels from any commit
with the same package sources, and a STATUS-only commit changes nothing.
It writes every package file from the HEAD commit's blobs into a temporary
directory and builds that, never the working tree. Building the working tree
would let hatchling apply .gitignore and drop committed files, follow a
committed symlink out of the repo, or ship an edit hidden from git status
with --assume-unchanged. It refuses symlinks and submodules, and it keeps each
file's git mode (100755 or 100644). git archive is not used because it honors
export-ignore.
The interpreter needs hatchling from requirements/build.txt (install_cxbom.py
build sets that up) or requirements-dev.txt. The build runs offline with no
build isolation, so pip fetches nothing. Because pip does not verify build
requirements without isolation, the script checks that the interpreter has
hatchling exactly HATCHLING and passes --check-build-dependencies. The pip
child gets an allowlisted environment, so an inherited PYTHONPATH or PIP_*
setting cannot swap the backend.
The build interpreter needs pip MIN_PIP or newer, because --check-build-dependencies
arrived in pip 22.1 and only a current pip is tested against this build. Ubuntu
22.04's pip 22.0.2 is the floor for installing a built wheel, never for building
one, so the install job builds in a venv with a modern pip and installs on 22.0.2.

Prints "<sha256>  <wheel name>". Exit 0 on success, 2 on refusal.
"""
from __future__ import annotations

import argparse
import re
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("cxbom", "pyproject.toml", "LICENSE", "NOTICE")
HATCHLING = "1.32.4"
MIN_PIP = (24, 0)
_PIP_VERSION = re.compile(r"^pip (\d+)\.(\d+)")
# Git modes a wheel may carry. 120000 (symlink) and 160000 (submodule) are refused by name.
_FILE_MODES = {"100644": 0o644, "100755": 0o755}
_REFUSED_MODES = {"120000": "symlink", "160000": "submodule"}
_ABS_PATH = re.compile(r"(?:file://)?/[^\s'\"]+")


class BuildError(RuntimeError):
    """The wheel cannot be built from this tree."""


def _git_bytes(root: Path, *args: str) -> bytes:
    r = subprocess.run(["git", *args], cwd=root, capture_output=True)
    if r.returncode != 0:
        raise BuildError(f"git {args[0]} failed: {_one_line(r.stderr.decode('utf-8', 'replace'))}")
    return r.stdout


def _git(root: Path, *args: str) -> str:
    return _git_bytes(root, *args).decode("utf-8")


def _one_line(text: str) -> str:
    """Return the last error line with absolute paths removed, so no home or temp path leaks."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = [line for line in lines if line.startswith("ERROR")]
    last = (errors or lines or ["no output"])[-1]
    return _ABS_PATH.sub("<path>", last)


def source_epoch(root: Path, rev: str = "HEAD") -> int:
    stamp = _git(root, "log", "-1", "--format=%ct", rev, "--", *SOURCES).strip()
    if not stamp:
        raise BuildError("no commit touches the package sources")
    return int(stamp)


def check_clean(root: Path) -> None:
    if _git(root, "status", "--porcelain", "--untracked-files=all", "--", *SOURCES).strip():
        raise BuildError("the package sources have uncommitted changes. Commit them first")


def stage_sources(root: Path, dst: Path, rev: str = "HEAD") -> Path:
    """Write the package files of commit rev into dst from git's blobs, with their git modes."""
    commit = _git(root, "rev-parse", "--verify", f"{rev}^{{commit}}").strip()
    listing = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *SOURCES)
    entries = [e for e in listing.split("\0") if e]
    if not entries:
        raise BuildError("the commit holds no package files")
    for entry in entries:
        meta, name = entry.split("\t", 1)
        mode, _, blob = meta.split(" ")
        if mode in _REFUSED_MODES:
            raise BuildError(f"{name} is a {_REFUSED_MODES[mode]}. The wheel ships only regular files")
        if mode not in _FILE_MODES:
            raise BuildError(f"{name} has git mode {mode}. The wheel ships only regular files")
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_git_bytes(root, "cat-file", "blob", blob))
        target.chmod(_FILE_MODES[mode])
    return dst


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_pip(python: str, env: dict[str, str]) -> None:
    """Refuse a build interpreter whose pip predates MIN_PIP."""
    needed = ".".join(str(n) for n in MIN_PIP)
    r = subprocess.run([python, "-m", "pip", "--version"], env=env, capture_output=True, text=True)
    m = _PIP_VERSION.match(r.stdout.strip()) if r.returncode == 0 else None
    if m is None:
        raise BuildError(f"the build interpreter has no usable pip, and the build needs pip {needed} or newer")
    if (int(m.group(1)), int(m.group(2))) < MIN_PIP:
        raise BuildError(f"the build interpreter has pip {m.group(1)}.{m.group(2)}, and the build needs "
                         f"pip {needed} or newer")


def build_wheel(src: Path, out: Path, epoch: int, python: str = sys.executable) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    if any(out.glob("cxbom-*.whl")):
        raise BuildError("the output directory already holds a cxbom wheel")
    env = {"PATH": os.environ.get("PATH", os.defpath), "SOURCE_DATE_EPOCH": str(epoch),
           "PIP_NO_INPUT": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    probe = subprocess.run([python, "-c", "import importlib.metadata as m; print(m.version('hatchling'))"],
                           env=env, capture_output=True, text=True)
    found = probe.stdout.strip() if probe.returncode == 0 else "missing"
    if found != HATCHLING:
        raise BuildError(f"the build interpreter has hatchling {found}, and the build needs exactly {HATCHLING} "
                         "from requirements/build.txt")
    check_pip(python, env)
    r = subprocess.run([python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--no-index",
                        "--check-build-dependencies", "--wheel-dir", str(out), str(src)],
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise BuildError("pip wheel failed: " + _one_line(r.stdout + "\n" + r.stderr))
    wheels = sorted(out.glob("cxbom-*.whl"))
    if len(wheels) != 1:
        raise BuildError(f"expected one cxbom wheel, found {len(wheels)}")
    return wheels[0]


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(prog="build_wheel.py", description="Build the cxbom wheel reproducibly.")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        check_clean(root)
        # Resolve HEAD once, so the files and the epoch come from the same commit even if HEAD moves.
        commit = _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip()
        with tempfile.TemporaryDirectory(prefix="cxbom-build-") as tmp:
            src = stage_sources(root, Path(tmp) / "src", commit)
            wheel = build_wheel(src, args.out, source_epoch(root, commit))
    except BuildError as e:
        print(f"build_wheel: {e}", file=sys.stderr)
        return 2
    print(f"{sha256_file(wheel)}  {wheel.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
