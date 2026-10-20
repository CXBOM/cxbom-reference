"""Refuse to deploy a commit whose site content main has since changed.

Owner: ATACE Working Group.

Usage, in the deploy job, from the repository root:
    GH_TOKEN=<the job's read-only token> python site/deploy_freshness.py
It reads GITHUB_REPOSITORY and GITHUB_SHA from the environment. Exit 0 allows
the deploy. Exit 1 refuses it, with the reason on stderr.

A run may deploy its commit only when both hold:
  1. The commit is main's current head or an ancestor of it.
  2. No path in the site workflow's push trigger list changed between the
     commit and that head.
So re-running an old run cannot ship stale content over a newer site. A later
commit that touches only paths outside the site (paper/, cxbom/) starts no site
run, and it does not block this one.

Both facts come from one call to the compare API, GET
repos/{repo}/compare/{sha}...main, made through `gh api` with the job token,
because the repository is private and an unauthenticated read fails. The
response lists at most 300 changed files, so a list of 300 or more is treated
as truncated and refused. Every error, whether gh missing, a failed call,
malformed JSON, or an unexpected shape, refuses. Nothing here reads the
repository without the token.

SITE_PATHS must equal on.push.paths in .github/workflows/site.yml. A test
compares them, since this script runs where no YAML parser is installed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

SITE_PATHS = ("spec/**", "site/**", "docs/design/tool.md", "scripts/anon_check.py",
              "requirements-dev.txt", ".github/workflows/site.yml")
# The compare API's documented cap on the changed-file list.
FILE_CAP = 300
SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class Refused(Exception):
    """The deploy must not proceed."""


def touches_site(path: str) -> bool:
    for pattern in SITE_PATHS:
        if pattern.endswith("/**"):
            if path.startswith(pattern[:-2]):
                return True
        elif path == pattern:
            return True
    return False


def compare(repo: str, sha: str) -> dict:
    cmd = ["gh", "api", f"repos/{repo}/compare/{sha}...main"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused(f"could not run gh: {exc}") from exc
    if out.returncode != 0:
        raise Refused(f"gh api failed with exit {out.returncode}: {out.stderr.strip()}")
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError as exc:
        raise Refused(f"gh api returned something other than JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise Refused("gh api returned JSON that is not an object")
    return data


def verdict(data: dict) -> None:
    """Raise Refused unless the compare response allows the deploy."""
    status = data.get("status")
    # base...head with base = this commit: "identical" or "ahead" means main
    # descends from it. "behind" and "diverged" mean it is not on main.
    if status not in ("identical", "ahead"):
        raise Refused(f"this commit is not main's head or an ancestor of it (status {status!r})")
    files = data.get("files")
    if not isinstance(files, list):
        raise Refused("the compare response carries no file list")
    if len(files) >= FILE_CAP:
        raise Refused(f"{len(files)} changed files, at or over the API's {FILE_CAP}-file cap, so the list may be cut")
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
            raise Refused(f"malformed file entry: {entry!r}")
        # A rename touches the site if either end of it is a site path.
        for key in ("filename", "previous_filename"):
            name = entry.get(key)
            if isinstance(name, str) and touches_site(name):
                raise Refused(f"main has changed {name} since this commit, so this run's site is stale")


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    try:
        # Both values go into an API path, so bound them before use.
        if not REPO.fullmatch(repo):
            raise Refused(f"GITHUB_REPOSITORY is not owner/name: {repo!r}")
        if not SHA.fullmatch(sha):
            raise Refused(f"GITHUB_SHA is not a 40-hex commit: {sha!r}")
        verdict(compare(repo, sha))
    except Refused as exc:
        print(f"deploy_freshness: refused: {exc}", file=sys.stderr)
        return 1
    print(f"deploy_freshness: {sha} carries main's current site")
    return 0


if __name__ == "__main__":
    sys.exit(main())
