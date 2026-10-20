"""Check an installed cxbom environment after a --no-deps install (spec 12).

Owner: ATACE Working Group.

Usage, with the environment's own interpreter:
    VENV/bin/python scripts/verify_env.py [--emit]

Runs pip check and accepts exactly two outcomes: exit 0 that prints only
"No broken requirements found.", or, with --emit, exit 1 whose every line is in
requirements/pip-check-allow.txt. Anything else fails, so a pip that is
missing or crashes (exit 1 with empty output) can never pass. It also refuses when huggingface_hub is
importable (the emit lock installs tokenizers without it), when cxbom is not
imported from this environment's site-packages, or, with --emit, when
tokenizers is missing. Exit 0 when the environment is complete, 1 otherwise.
"""
from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW = ROOT / "requirements" / "pip-check-allow.txt"
CLEAN = "No broken requirements found."


def load_allowed(path: Path) -> set[str]:
    return {ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")}


def unexpected(output: str, allowed: set[str]) -> list[str]:
    return [ln.strip() for ln in output.splitlines()
            if ln.strip() and ln.strip() != CLEAN and ln.strip() not in allowed]


def pip_check_errors(returncode: int, stdout: str, stderr: str, allowed: set[str]) -> list[str]:
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if returncode == 0 and lines == [CLEAN]:
        return []
    # pip reports broken requirements with exit 1. Requiring at least one line,
    # all allowed, rejects the empty exit 1 that "No module named pip" produces.
    if returncode == 1 and lines and all(ln in allowed for ln in lines):
        return []
    errs = [f"pip check: {ln}" for ln in lines if ln != CLEAN and ln not in allowed]
    detail = " ".join(ln.strip() for ln in stderr.splitlines() if ln.strip()) or "no stderr"
    errs.append(f"pip check did not pass (exit {returncode}, {len(lines)} stdout lines, stderr: {detail})")
    return errs


def problems(emit: bool) -> list[str]:
    r = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True)
    errs = pip_check_errors(r.returncode, r.stdout, r.stderr, load_allowed(ALLOW) if emit else set())
    if importlib.util.find_spec("huggingface_hub") is not None:
        errs.append("huggingface_hub is installed. The emit lock installs tokenizers without it")
    spec = importlib.util.find_spec("cxbom")
    purelib = Path(sysconfig.get_paths()["purelib"]).resolve()
    if spec is None or spec.origin is None or not Path(spec.origin).resolve().is_relative_to(purelib):
        errs.append("cxbom is not installed in this environment's site-packages")
    if emit and importlib.util.find_spec("tokenizers") is None:
        errs.append("tokenizers is missing. Install requirements/emit.txt")
    return errs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_env.py", description="Check an installed cxbom environment.")
    parser.add_argument("--emit", action="store_true", help="the environment includes the emit lock")
    args = parser.parse_args(argv)
    errs = problems(args.emit)
    for e in errs:
        print(f"verify_env: {e}", file=sys.stderr)
    print("verify_env: FAILED" if errs else "verify_env: ok")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
