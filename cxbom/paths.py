"""User-level cxbom paths, resolved from the OS user database only.

Owner: ATACE Working Group.

HOME and XDG_* come from the process environment, and an attacker who can write
an MCP config's env block controls them (premortem C1). Every cxbom path
resolves from pwd, and a process whose HOME disagrees with the account home
refuses to run.
"""
from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path
from typing import Mapping


class PathSecurityError(RuntimeError):
    """A cxbom path is redirected, shared, or writable by someone else."""


def pw_dir() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def config_dir() -> Path:
    return pw_dir() / ".config" / "cxbom"


def state_dir() -> Path:
    return pw_dir() / ".local" / "state" / "cxbom"


def check_home_env(environ: Mapping[str, str] | None = None) -> None:
    env = os.environ if environ is None else environ
    home = env.get("HOME")
    if home is not None and Path(home).resolve() != pw_dir().resolve():
        raise PathSecurityError(
            "HOME differs from the account home directory; refusing to run")


def check_private(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise PathSecurityError(f"{path.name}: does not exist")
    if stat.S_ISLNK(st.st_mode):
        raise PathSecurityError(f"{path.name}: symlinks are not allowed for cxbom state")
    if st.st_uid != os.getuid():
        raise PathSecurityError(f"{path.name}: not owned by the current user")
    if st.st_mode & 0o077:
        raise PathSecurityError(f"{path.name}: accessible by group or others")


def ensure_private_dir(path: Path) -> Path:
    """Create path and any missing parents at 0700, then check each one.

    Path.mkdir(parents=True) creates parents with the umask default (often
    0755), so a later ensure_private_dir on a parent would fail. This walks
    down from the first existing ancestor and creates each component itself.

    Raises:
        PathSecurityError: a component is not a directory, cannot be
            created, or fails check_private.
    """
    missing: list[Path] = []
    cur = path
    while True:
        try:
            os.lstat(cur)
            break
        except FileNotFoundError:
            missing.append(cur)
        except OSError as e:
            raise PathSecurityError(f"{cur.name}: {e.strerror}") from None
        if cur.parent == cur:
            break
        cur = cur.parent
    created: list[Path] = []
    for component in reversed(missing):
        try:
            os.mkdir(component, 0o700)
        except OSError as e:
            # FileExistsError here means something raced this call, and
            # NotADirectoryError means an ancestor is a file. Both refuse.
            raise PathSecurityError(f"{component.name}: {e.strerror}") from None
        created.append(component)
    try:
        st = os.lstat(path)
    except OSError as e:
        raise PathSecurityError(f"{path.name}: {e.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise PathSecurityError(f"{path.name}: symlinks are not allowed for cxbom state")
    if not stat.S_ISDIR(st.st_mode):
        raise PathSecurityError(f"{path.name}: exists and is not a directory")
    for component in created:
        check_private(component)
    check_private(path)
    return path


def inside_git_worktree(path: Path) -> bool:
    p = path.resolve()
    for candidate in (p, *p.parents):
        if (candidate / ".git").exists():
            return True
    return False
