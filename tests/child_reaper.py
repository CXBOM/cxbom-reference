"""Reap every child process a test spawns, on every path: pass, fail, error or timeout.

Owner: ATACE Working Group. Version 0.1.0.

A test module opts in by importing the fixture by name:

    from child_reaper import reap_spawned_children  # noqa: F401  (autouse)

Why: the fake browsers and relays these tests start can ignore SIGTERM on
purpose, which is what a bounded close() is tested against. A test that fails
before its own cleanup runs, as every mutant that breaks close() makes it do,
used to leave such a child reparented to launchd for good, one per run.

The fixture wraps os.posix_spawn and subprocess.Popen for the test's length and
records each child's pid, and whether the child leads a process group of its
own (setsid, setpgroup=0, start_new_session or process_group=0), taken from the
spawn call's arguments, never from a later lookup that a zombie would fail.

At teardown, for each recorded child that the code under test did not reap:
SIGKILL its group when it leads one (so helpers it started die with it), then
SIGKILL the child and reap it. The pid is still this process's unreaped child
at that point, so neither it nor the group it leads can have been reused. A
child the code under test already reaped is left alone: its pid may be anyone's
by now. The group of a child that does not lead one is pytest's own group, and
is never signalled.

A test that left a child running fails at teardown after the kill, so a leak
is an error in the run, not a quiet survivor on the machine.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time

import pytest

REAP_SECONDS = 10.0             # after SIGKILL, the wait for the child to be reapable
POLL_SECONDS = 0.02


def _still_ours(pid: int) -> bool:
    """True while pid is this process's child and unreaped, running or a zombie. Reaps nothing."""
    try:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return False
    return True


def _running(pid: int) -> bool:
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None


def _kill_and_reap(pid: int, leads_group: bool) -> bool:
    """SIGKILL an unreaped child (and its group if it leads one) and reap it. True if it was still running."""
    if not _still_ours(pid):
        return False
    was_running = _running(pid)
    if leads_group:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass            # macOS answers EPERM for a group whose only member is the zombie leader
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + REAP_SECONDS
    while True:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return was_running
        if done:
            return was_running
        if time.monotonic() >= deadline:
            raise RuntimeError(f"child {pid} survived SIGKILL for {REAP_SECONDS} s")
        time.sleep(POLL_SECONDS)


@pytest.fixture(autouse=True)
def reap_spawned_children():
    spawned: list[tuple[int, bool]] = []
    # A test's own monkeypatch can be undone after this fixture's undo and put an earlier test's wrapper back.
    # Unwrap it, so wrappers never nest and one spawn is never recorded by two of them.
    real_spawn = getattr(os.posix_spawn, "_reaper_real", os.posix_spawn)
    real_init = getattr(subprocess.Popen.__init__, "_reaper_real", subprocess.Popen.__init__)
    live = True                 # cleared at teardown: a wrapper restored later by someone else records nothing

    def record(pid: int, leads: bool) -> None:
        # One record per pid while it is unreaped (its number cannot have been reused), however many paths ran.
        if live and not any(p == pid and _still_ours(pid) for p, _ in spawned):
            spawned.append((pid, leads))

    def posix_spawn(path, argv, env, **kwargs):
        if not live:
            return real_spawn(path, argv, env, **kwargs)
        try:
            pid = real_spawn(path, argv, env, **kwargs)
        except NotImplementedError:
            # A libc without POSIX_SPAWN_SETSID refuses the flag. Same fallback as demo/recording/browser.py:
            # a Popen with start_new_session=True. The Popen wrapper records that child, so it is not
            # recorded twice here. Only plain setsid=True spawns are replaceable this way.
            if not kwargs.get("setsid") or set(kwargs) - {"setsid"}:
                raise
            proc = subprocess.Popen(argv, executable=path, env=env, start_new_session=True)
            # The caller reaps this pid itself, as it would a posix_spawn child.
            proc.returncode = 0
            return proc.pid
        record(pid, bool(kwargs.get("setsid")) or kwargs.get("setpgroup") == 0)
        return pid

    def popen_init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        record(self.pid, bool(kwargs.get("start_new_session")) or kwargs.get("process_group") == 0)

    posix_spawn._reaper_real = real_spawn
    popen_init._reaper_real = real_init

    # A MonkeyPatch of its own: undoing it must not undo the test's patches before their own teardown.
    patch = pytest.MonkeyPatch()
    patch.setattr(os, "posix_spawn", posix_spawn)
    patch.setattr(subprocess.Popen, "__init__", popen_init)
    try:
        yield spawned           # (pid, leads its own group) per child, in spawn order
    finally:
        # The wrappers go first, so nothing this teardown does is recorded.
        live = False
        patch.undo()
    left = [pid for pid, leads in spawned if _kill_and_reap(pid, leads)]
    if left:
        pytest.fail(f"the test left {len(left)} child process{'es' if len(left) != 1 else ''} running; "
                    "killed and reaped at teardown", pytrace=False)
