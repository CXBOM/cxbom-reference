"""Child spawning, the watchdog, and shutdown (spec 8.1 step 4, 8.8). Owner: ATACE Working Group.

The watchdog and group kill are POSIX and run on Linux and macOS.
PR_SET_PDEATHSIG exists only on Linux, so that one test is skipped on
darwin and runs in CI on ubuntu.
"""
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_helpers import ROOT, server_layout  # noqa: E402

from cxbom import launch  # noqa: E402


def plan_for(tmp_path, script):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir, script)
    pins = launch.compute_launch_pins(argv, lock_dir, environ)
    return launch.check_launch(pins, argv, lock_dir, environ, "fetch")


def gone(pid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False


def wait_for(path, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not path.exists() or not path.read_text():
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        time.sleep(0.02)
    return json.loads(path.read_text())


def test_child_gets_the_built_environment_a_fresh_cwd_and_its_own_group(tmp_path):
    out = tmp_path / "env.json"
    child = launch.spawn(plan_for(tmp_path, {"envFile": str(out)}))
    seen = wait_for(out)
    env, cwd = seen["env"], seen["cwd"]
    assert set(env) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"} == {"HOME", "PATH", "LANG", "TMPDIR",
                                                                      "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"}
    assert env["PYTHONNOUSERSITE"] == "1" and env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert stat.S_IMODE(os.stat(env["TMPDIR"]).st_mode) == 0o700
    assert Path(cwd).resolve() != Path.cwd().resolve() and "cxbom-cwd-" in cwd
    assert os.getpgid(child.proc.pid) == child.proc.pid != os.getpgid(0)
    assert child.stop() == 0
    assert not os.path.exists(env["TMPDIR"]) and not os.path.exists(cwd)


def test_child_tmpdir_and_cwd_ignore_the_proxys_own_tmpdir(tmp_path, monkeypatch):
    """A probe put the child's TMPDIR and cwd inside the git worktree by setting
    the proxy's own TMPDIR: actor (b) writes the launch env block the proxy
    runs under, and tempfile.mkdtemp()'s default lookup follows that. Both
    scratch dirs must come from a fixed root instead, regardless of it.
    """
    hostile = tmp_path / "hostile-tmp"
    hostile.mkdir()
    monkeypatch.setenv("TMPDIR", str(hostile))
    out = tmp_path / "env.json"
    child = launch.spawn(plan_for(tmp_path, {"envFile": str(out)}))
    seen = wait_for(out)
    env, cwd = seen["env"], seen["cwd"]
    real_tmp = os.path.realpath("/tmp") + os.sep
    assert os.path.realpath(env["TMPDIR"]).startswith(real_tmp)
    assert os.path.realpath(cwd).startswith(real_tmp)
    assert str(hostile) not in env["TMPDIR"] and str(hostile) not in cwd
    assert child.stop() == 0


def test_spawn_refuses_to_run_off_the_main_thread(tmp_path):
    plan = plan_for(tmp_path, {})
    errors = []

    def worker():
        try:
            launch.spawn(plan)
        except launch.LaunchError as e:
            errors.append(e)

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert len(errors) == 1
    assert "main thread" in str(errors[0])


def test_stop_returns_the_child_exit_code(tmp_path):
    child = launch.spawn(plan_for(tmp_path, {"exitCodeOnEof": 5}))
    assert launch.exit_status(child.stop()) == 5


def test_stop_kills_a_stubborn_child_and_its_grandchild(tmp_path):
    pids_file = tmp_path / "pids.json"
    child = launch.spawn(plan_for(tmp_path, {"ignoreSigterm": True, "hangOnEof": True, "spawnGrandchild": True,
                                             "pidFile": str(pids_file)}))
    pids = wait_for(pids_file)
    assert child.stop(grace=0.3) == -signal.SIGKILL
    assert gone(pids["grandchild"], 3.0)


def test_watchdog_kills_the_group_when_the_proxy_dies(tmp_path):
    pids_file = tmp_path / "pids.json"
    child = launch.spawn(plan_for(tmp_path, {"ignoreSigterm": True, "hangOnEof": True, "spawnGrandchild": True,
                                             "pidFile": str(pids_file)}), grace=0.3)
    pids = wait_for(pids_file)
    child.abandon_for_test()
    assert child.proc.wait(timeout=5) == -signal.SIGKILL
    assert gone(pids["grandchild"], 3.0)
    child.watchdog.wait(timeout=5)


def test_watchdog_ignores_terminal_signals(tmp_path):
    child = launch.spawn(plan_for(tmp_path, {}))
    assert os.getsid(child.watchdog.pid) == child.watchdog.pid != os.getsid(0)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        os.kill(child.watchdog.pid, sig)
    time.sleep(0.2)
    assert child.watchdog.poll() is None
    # Abandon rather than stop(), so the watchdog takes the group-kill path
    # instead of the done path, and its distinct exit code proves it: staying
    # alive through the signals above and then actually killing on abandonment
    # are two different claims, and asserting 0 here (the done code) would
    # have proven neither.
    child.abandon_for_test()
    child.proc.wait(timeout=5)
    assert child.watchdog.wait(timeout=5) == launch.WATCHDOG_SIGNALED_EXIT


def test_watchdog_exits_quietly_after_done(tmp_path):
    child = launch.spawn(plan_for(tmp_path, {}))
    child.stop()
    assert child.watchdog.returncode == 0


def test_spawn_failure_is_a_launch_error(tmp_path):
    plan = plan_for(tmp_path, {})
    broken = launch.LaunchPlan(plan.argv, plan.exec_argv, str(tmp_path / "missing-binary"), plan.env,
                               plan.lock_dir, plan.launch_sha256)
    with pytest.raises(launch.LaunchError, match="cannot start the server"):
        launch.spawn(broken)


def test_a_spawn_failure_names_only_the_escaped_launcher_basename(tmp_path):
    """Final review A6: the message carried the whole argv[0], path included, unescaped."""
    plan = plan_for(tmp_path, {})
    argv = [str(tmp_path / "bin" / "py\u202e\u009bthon")] + plan.argv[1:]
    broken = launch.LaunchPlan(argv, plan.exec_argv, str(tmp_path / "missing-binary"), plan.env,
                               plan.lock_dir, plan.launch_sha256)
    with pytest.raises(launch.LaunchError) as ei:
        launch.spawn(broken)
    assert str(ei.value) == "py\\u{202E}\\u{009B}thon: cannot start the server"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux only")
def test_linux_pdeathsig_kills_the_child_even_without_the_watchdog(tmp_path):
    pids_file = tmp_path / "pids.json"
    plan = plan_for(tmp_path, {"ignoreSigterm": True, "pidFile": str(pids_file)})
    code = (
        "import sys, time, json\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from cxbom import launch\n"
        f"plan = launch.LaunchPlan(*json.loads({json.dumps(json.dumps([plan.argv, plan.exec_argv, plan.executable, plan.env, str(plan.lock_dir), plan.launch_sha256]))}))\n"
        "child = launch.spawn(plan)\n"
        "print(child.proc.pid, child.watchdog.pid, flush=True)\n"
        "time.sleep(60)\n")
    helper = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    server_pid, watchdog_pid = map(int, helper.stdout.readline().split())
    wait_for(pids_file)
    os.kill(watchdog_pid, signal.SIGKILL)
    helper.kill()
    helper.wait()
    assert gone(server_pid, 1.0)


def test_a_python_server_that_imports_a_sibling_leaves_its_pinned_tree_unchanged(tmp_path):
    """Final review A1: the first launch, approve's probe included, must not
    write __pycache__ into a pinned tree, or the proxy then refuses the very
    entry approve just signed."""
    lock_dir = tmp_path / "proj"
    tree = lock_dir / "srv"
    tree.mkdir(parents=True)
    (tree / "helper.py").write_text("VALUE = 1\n")
    (tree / "server.py").write_text("import helper\nassert helper.VALUE == 1\n")
    argv = ["python3", "srv/server.py"]
    environ = {"LANG": "C.UTF-8", "HOME": str(Path.home())}
    pins = launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=["srv"])
    child = launch.spawn(launch.check_launch(pins, argv, lock_dir, environ, "fetch"))
    assert child.proc.wait(timeout=30) == 0
    assert child.stop() == 0
    assert not any(p.name == "__pycache__" for p in tree.rglob("*"))
    launch.check_launch(pins, argv, lock_dir, environ, "fetch")
