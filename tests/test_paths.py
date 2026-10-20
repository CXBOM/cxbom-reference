"""Account-home path resolution (premortem C1). Owner: ATACE Working Group."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cxbom import paths

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(paths, "pw_dir", lambda: home)
    return home


def test_dirs_come_from_pw_dir_not_env(fake_home, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/attacker")
    monkeypatch.setenv("XDG_STATE_HOME", "/tmp/attacker")
    assert paths.config_dir() == fake_home / ".config" / "cxbom"
    assert paths.state_dir() == fake_home / ".local" / "state" / "cxbom"


def test_home_mismatch_refused(fake_home):
    with pytest.raises(paths.PathSecurityError):
        paths.check_home_env({"HOME": "/tmp/attacker-workspace/.x"})
    paths.check_home_env({"HOME": str(fake_home)})
    paths.check_home_env({})


def test_the_ambient_environment_passes_the_home_check():
    """The suite must run where HOME is not the passwd home.

    lab/tools/integrate runs the root suite with HOME=/tmp/home. Without the
    hermetic_home fixture in conftest, every test that reaches check_home_env
    with the ambient environment fails there on the tool's own defense.
    """
    assert os.environ["HOME"] == str(paths.pw_dir())
    paths.check_home_env()


def test_a_subprocess_inherits_a_home_the_cli_accepts():
    """Most CLI tests spawn a subprocess that inherits os.environ.

    Pinning HOME in-process is only half the fix; it has to reach the child,
    which is what this asserts.
    """
    code = (f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
            "from cxbom import paths\npaths.check_home_env()\n")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=60)
    assert done.returncode == 0, done.stderr


def test_private_dir_created_0700(fake_home):
    d = paths.ensure_private_dir(fake_home / "a" / "b")
    assert (d.stat().st_mode & 0o777) == 0o700


def test_group_writable_refused(fake_home):
    d = fake_home / "open"
    d.mkdir()
    os.chmod(d, 0o770)
    with pytest.raises(paths.PathSecurityError):
        paths.check_private(d)


def test_symlink_refused(fake_home, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    link = fake_home / "link"
    link.symlink_to(target)
    with pytest.raises(paths.PathSecurityError):
        paths.check_private(link)


def test_group_readable_refused(fake_home):
    d = fake_home / "readable"
    d.mkdir()
    os.chmod(d, 0o755)
    with pytest.raises(paths.PathSecurityError):
        paths.check_private(d)


def test_nonexistent_path_refused(fake_home):
    d = fake_home / "nonexistent"
    with pytest.raises(paths.PathSecurityError):
        paths.check_private(d)


def test_file_exists_not_directory(fake_home):
    f = fake_home / "file"
    f.touch()
    with pytest.raises(paths.PathSecurityError):
        paths.ensure_private_dir(f)


def test_inside_git_worktree(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "sub").mkdir()
    assert paths.inside_git_worktree(repo / "sub")
    assert not paths.inside_git_worktree(tmp_path / "other")


# --- Final review A1: every component this call creates is private ---


def test_ensure_private_dir_creates_every_missing_component_0700(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    leaf = paths.ensure_private_dir(root / "state" / "store")
    assert (os.stat(root / "state").st_mode & 0o777) == 0o700
    assert (os.stat(leaf).st_mode & 0o777) == 0o700
    # The intermediate directory must itself pass check_private later.
    assert paths.ensure_private_dir(root / "state") == root / "state"


def test_ensure_private_dir_under_a_file_is_a_path_security_error(tmp_path):
    f = tmp_path / "file"
    f.touch()
    with pytest.raises(paths.PathSecurityError):
        paths.ensure_private_dir(f / "sub" / "leaf")
