"""cxbom command line, slice 1 (spec 7, 8, 11). Owner: ATACE Working Group."""
import io
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_helpers import ACCEPT_FETCH, ROOT, project  # noqa: E402

from cxbom import cli, lockfile  # noqa: E402
from cxbom.canonical import file_sha256  # noqa: E402


def _spec_not_covered_rows() -> list:
    """Both cells of every row in tool.md section 2's "Not covered" table.

    Backticks are stripped, matching how NOT_COVERED renders the same rows
    for a terminal (fix round 1, Important 1): the doc's markdown code-span
    syntax is not terminal output.
    """
    text = (ROOT / "docs" / "design" / "tool.md").read_text()
    marker = text.index("Not covered in this version.")
    start = text.index("| Channel | Instead |", marker)
    lines = text[start:].splitlines()
    rows = []
    for line in lines[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip().replace("`", "") for c in line.strip().strip("|").split("|")]
        rows.append((cells[0], cells[1]))
    return rows


def _spec_not_covered_channels() -> list:
    return [channel for channel, _instead in _spec_not_covered_rows()]


def _help_not_covered_rows(out: str) -> list:
    """Both cells of every row cxbom --help prints, read from the help text.

    Reading the rendered help rather than cli.NOT_COVERED proves what a user
    sees: argparse could re-wrap the epilog and split a cell across lines,
    which this parse would show as a row whose reason ends early.
    """
    tail = out[out.index("not covered in this version"):]
    rows = []
    for line in tail.splitlines()[1:]:
        if line.startswith("      "):
            assert rows, f"a reason line before any channel line: {line!r}"
            rows[-1][1].append(line.strip())
        elif line.startswith("  "):
            rows.append([line.strip(), []])
        elif line.strip():
            break
    return [(channel, " ".join(reason)) for channel, reason in rows]


def test_split_command_at_the_first_double_dash():
    assert cli.split_command(["proxy", "--server-id", "x", "--", "uvx", "--", "y"]) == \
        (["proxy", "--server-id", "x"], ["uvx", "--", "y"])
    assert cli.split_command(["init"]) == (["init"], [])


def test_accepts_pair_with_the_following_reason():
    ordered = [("accept", "a" * 64), ("reason", "one"), ("accept", "b" * 64), ("reason", "two")]
    assert cli.pair_accepts(ordered) == {"a" * 64: "one", "b" * 64: "two"}
    with pytest.raises(cli.UsageError, match="has no --reason"):
        cli.pair_accepts([("accept", "a" * 64), ("accept", "b" * 64), ("reason", "x")])
    with pytest.raises(cli.UsageError, match="must follow"):
        cli.pair_accepts([("reason", "x")])
    with pytest.raises(cli.UsageError, match="has no --reason"):
        cli.pair_accepts([("accept", "a" * 64)])


def test_init_writes_a_fresh_scope_gitignore_and_wrapper(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / ".gitignore").write_text("build/")
    out = io.StringIO()
    entry = ROOT / "cxbom" / "__main__.py"
    assert cli.main(["init"], cwd=work, config_dir=tmp_path / "config", out=out, entry_point=entry) == 0
    lock = lockfile.read_lock(work / "cxbom.lock")
    assert len(lock["lockScope"]) == 32 and lock["servers"] == {}
    assert (work / ".gitignore").read_text() == "build/\n.cxbom/\n"
    wrapper = tmp_path / "config" / "wrapper.json"
    assert stat.S_IMODE(os.stat(wrapper).st_mode) == 0o600
    assert json.loads(wrapper.read_text())["entryPoint"]["sha256"] == file_sha256(entry)
    assert cli.main(["init"], cwd=work, config_dir=tmp_path / "config", out=out, entry_point=entry) == 2
    other = tmp_path / "other"
    other.mkdir()
    cli.main(["init"], cwd=other, config_dir=tmp_path / "config", out=out, entry_point=entry)
    assert lockfile.read_lock(other / "cxbom.lock")["lockScope"] != lock["lockScope"]


@pytest.mark.parametrize("argv, needle", [
    (["proxy", "--", "x"], "--server-id"),
    (["proxy", "--server-id", "x", "--mode", "loud", "--", "x"], "invalid choice"),
    (["approve", "--server-id", "x", "--", "x"], "--approver"),
    (["approve", "--server-id", "x", "--approver", "op", "--accept", "a" * 64, "--", "x"], "has no --reason"),
    (["approve", "--server-id", "x", "--approver", "op", "--client-capabilities", "{\"a\":1,\"a\":2}", "--", "x"],
     "strict JSON"),
    (["frobnicate"], "invalid choice"),
])
def test_usage_errors_exit_2(argv, needle, capsys):
    assert cli.main(argv) == 2
    assert needle in capsys.readouterr().err


def test_help_names_what_is_not_covered(capsys):
    assert cli.main(["--help"]) == 0
    assert "not covered in this version" in capsys.readouterr().out


def test_approve_without_a_terminal_signs_nothing(tmp_path):
    setup = project(tmp_path)
    args = ["approve", "--server-id", "fetch", "--approver", "demo-operator"]
    for sha, reason in ACCEPT_FETCH.items():
        args += ["--accept", sha, "--reason", reason]
    args += ["--"] + setup.argv
    code = ("import sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from pathlib import Path\n"
            "from cxbom import cli\n"
            f"sys.exit(cli.main({args!r}, config_dir=Path({str(setup.config)!r}), "
            f"state_dir=Path({str(setup.state)!r})))\n")
    env = dict(os.environ)
    env.update(setup.environ)
    done = subprocess.run([sys.executable, "-c", code], cwd=setup.lock_dir, env=env, capture_output=True,
                          start_new_session=True, stdin=subprocess.DEVNULL, timeout=60)
    assert done.returncode == 2, done.stdout + done.stderr
    assert b"no controlling terminal" in done.stdout
    assert json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"] == {}


def test_keygen_and_trust_add_with_an_in_memory_reader(tmp_path):
    out = io.StringIO()
    secrets_ = iter([b"pw", b"pw"])
    config = tmp_path / "config"
    assert cli.main(["keygen"], config_dir=config, out=out, read_secret=lambda prompt: next(secrets_)) == 0
    own = out.getvalue().split()[-1]
    assert len(own) == 64
    other = project(tmp_path / "other")
    pub = (other.config / "signing-key.pub").read_text()
    (tmp_path / "demo.pub").write_text(pub)
    out = io.StringIO()
    assert cli.main(["trust", "add", "demo.pub"], cwd=tmp_path, config_dir=config, out=out,
                    read_secret=lambda prompt: b"pw") == 0
    from cxbom import signing
    assert set(signing.load_trusted(config)) == {own, out.getvalue().split()[-1]}


def test_keygen_refuses_mismatched_passphrases_and_a_second_key(tmp_path):
    out = io.StringIO()
    answers = iter([b"a", b"b"])
    assert cli.main(["keygen"], config_dir=tmp_path / "c", out=out, read_secret=lambda p: next(answers)) == 2
    assert "differ" in out.getvalue()
    assert cli.main(["keygen"], config_dir=tmp_path / "c", out=out, read_secret=lambda p: b"x") == 0
    assert cli.main(["keygen"], config_dir=tmp_path / "c", out=out, read_secret=lambda p: b"x") == 2
    assert "already exists" in out.getvalue()


def test_keygen_without_a_terminal_exits_2(tmp_path):
    code = ("import sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from pathlib import Path\n"
            "from cxbom import cli\n"
            f"sys.exit(cli.main(['keygen'], config_dir=Path({str(tmp_path / 'c')!r})))\n")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, start_new_session=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    assert done.returncode == 2 and b"no controlling terminal" in done.stderr, done.stdout + done.stderr
    assert not (tmp_path / "c" / "signing-key.pem").exists()


# ----- fix round 1 (controller ruling) ------------------------------------------------


def test_help_lists_every_not_covered_row_from_the_spec(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    channels = _spec_not_covered_channels()
    assert len(channels) >= 10, "the spec table parse found suspiciously few rows"
    for channel in channels:
        assert channel in out, f"docs/design/tool.md row missing from --help: {channel!r}"
    # This slice's own scope note. It is in the design doc's table too
    # (docs/design/tool.md:78), and the loop above already covers it; asserted
    # again here by name because it is the row most likely to be dropped from
    # --help without anyone noticing the coverage claim went with it.
    assert "prompts, resources, resource templates" in out


# ----- task 12 --------------------------------------------------------------------------


def test_help_gives_the_same_reason_as_the_spec_for_every_not_covered_row(capsys):
    """NOT_COVERED says it is verbatim from tool.md's table, so both cells must agree.

    The channel-only check above passed while the wrapper row's reason in
    NOT_COVERED still claimed the shells are "recognized and refused", after
    the spec had narrowed that to the cases the code actually refuses. A
    reason that overstates coverage is the half of the row a reader acts on.
    """
    assert cli.main(["--help"]) == 0
    rows = _help_not_covered_rows(capsys.readouterr().out)
    spec = _spec_not_covered_rows()
    assert len(spec) >= 10, "the spec table parse found suspiciously few rows"
    assert rows == spec


def test_init_refuses_cleanly_when_the_directory_is_read_only(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    out = io.StringIO()
    entry = ROOT / "cxbom" / "__main__.py"
    os.chmod(work, 0o500)
    try:
        code = cli.main(["init"], cwd=work, config_dir=tmp_path / "config", out=out, entry_point=entry)
    finally:
        os.chmod(work, 0o700)
    assert code == 2
    assert not (work / "cxbom.lock").exists()


def test_init_refuses_a_non_utf8_gitignore_and_leaves_no_lock(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / ".gitignore").write_bytes(b"\xff\xfe not valid utf-8")
    out = io.StringIO()
    entry = ROOT / "cxbom" / "__main__.py"
    assert cli.main(["init"], cwd=work, config_dir=tmp_path / "config", out=out, entry_point=entry) == 2
    assert not (work / "cxbom.lock").exists()


def test_init_refuses_a_group_writable_config_dir_and_leaves_no_lock(tmp_path, capsys):
    work = tmp_path / "work"
    work.mkdir()
    config = tmp_path / "config"
    config.mkdir()
    os.chmod(config, 0o750)
    out = io.StringIO()
    entry = ROOT / "cxbom" / "__main__.py"
    assert cli.main(["init"], cwd=work, config_dir=config, out=out, entry_point=entry) == 2
    assert not (work / "cxbom.lock").exists()
    assert "cxbom:" in capsys.readouterr().err


def test_init_gitignore_write_does_not_follow_a_symlink(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside-gitignore"
    outside.write_text("do not touch\n")
    (work / ".gitignore").symlink_to(outside)
    out = io.StringIO()
    entry = ROOT / "cxbom" / "__main__.py"
    assert cli.main(["init"], cwd=work, config_dir=tmp_path / "config", out=out, entry_point=entry) == 0
    assert outside.read_text() == "do not touch\n"
    assert not (work / ".gitignore").is_symlink()
    assert (work / ".gitignore").read_text() == "do not touch\n.cxbom/\n"


def test_proxy_flag_wiring_reaches_proxy_options(monkeypatch, tmp_path):
    captured = {}

    def fake_run(opts, **kw):
        captured["opts"] = opts
        captured["kw"] = kw
        return 0

    monkeypatch.setattr(cli.proxy, "run", fake_run)
    argv = ["proxy", "--server-id", "srv-1", "--lock", "custom.lock", "--mode", "observe",
            "--state-dir", "/tmp/some-state", "--events", "/tmp/events.sock",
            "--redact-sha256", "a" * 64, "--redact-sha256", "b" * 64,
            "--", "python3", "server.py", "--flag"]
    config = tmp_path / "config"
    state = tmp_path / "state"
    environ = {"HOME": str(Path.home())}
    assert cli.main(argv, config_dir=config, state_dir=state, environ=environ, cwd=tmp_path) == 0
    opts = captured["opts"]
    # Every ProxyOptions field: deleting any one kwarg in cli.py's construction
    # drops one of these assertions (fix round 1, Important 3).
    assert opts.server_id == "srv-1"
    assert opts.command == ["python3", "server.py", "--flag"]
    assert opts.lock == "custom.lock"
    assert opts.mode == "observe"
    assert opts.state_dir == "/tmp/some-state"
    assert opts.events == "/tmp/events.sock"
    assert opts.redact_sha256 == ("a" * 64, "b" * 64)
    kw = captured["kw"]
    assert kw["config_dir"] == config
    assert kw["environ"] == environ
    assert kw["cwd"] == tmp_path


def test_proxy_state_dir_falls_back_to_the_main_kwarg(monkeypatch, tmp_path):
    captured = {}

    def fake_run(opts, **kw):
        captured["opts"] = opts
        return 0

    monkeypatch.setattr(cli.proxy, "run", fake_run)
    state = tmp_path / "state"
    assert cli.main(["proxy", "--server-id", "s", "--", "python3", "x.py"], state_dir=state) == 0
    assert captured["opts"].state_dir == str(state)


def test_approve_flag_wiring_reaches_approve_options(monkeypatch, tmp_path):
    captured = {}

    def fake_run(opts, **kw):
        captured["opts"] = opts
        captured["kw"] = kw
        return 0

    monkeypatch.setattr(cli.approve, "run", fake_run)
    sha_a, sha_b = "a" * 64, "b" * 64
    argv = ["approve", "--server-id", "srv-2", "--approver", "demo op", "--lock", "custom.lock",
            "--era", "both", "--client-capabilities", '{"sampling":{}}',
            "--accept", sha_a, "--reason", "reason one",
            "--accept", sha_b, "--reason", "reason two",
            "--pin-env", "FOO", "--pin-env", "BAR", "--secret-env", "TOKEN",
            "--pin-tree", "vendor/lib", "--startup-timeout", "12.5", "--allow-observe",
            "--not-after", "2026-09-27T00:00:00Z",
            "--", "python3", "server.py"]
    config = tmp_path / "config"
    state = tmp_path / "state"
    environ = {"HOME": str(Path.home())}
    assert cli.main(argv, config_dir=config, state_dir=state, environ=environ, cwd=tmp_path) == 0
    opts = captured["opts"]
    # Every ApproveOptions field: deleting any one kwarg in cli.py's
    # construction drops one of these assertions (fix round 1, Important 3).
    assert opts.server_id == "srv-2"
    assert opts.approver == "demo op"
    assert opts.command == ["python3", "server.py"]
    assert opts.lock == "custom.lock"
    assert opts.era == "both"
    assert opts.client_capabilities == {"sampling": {}}
    assert opts.accept == {sha_a: "reason one", sha_b: "reason two"}
    assert opts.pin_env == ["FOO", "BAR"]
    assert opts.secret_env == ["TOKEN"]
    assert opts.pin_trees == ["vendor/lib"]
    assert opts.startup_timeout == 12.5
    assert opts.allow_observe is True
    assert opts.not_after == "2026-09-27T00:00:00Z"
    kw = captured["kw"]
    assert kw["config_dir"] == config
    assert kw["state_dir"] == state
    assert kw["environ"] == environ
    assert kw["cwd"] == tmp_path
    assert callable(kw["confirm"]) and callable(kw["passphrase"])


def test_allow_abbrev_is_disabled():
    assert cli.main(["proxy", "--server-id", "x", "--mo", "observe", "--", "python3", "x.py"]) == 2
    assert cli.main(["approve", "--server-id", "x", "--approver", "op", "--allow",
                     "--", "python3", "x.py"]) == 2


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-5", "3601", "not-a-number"])
def test_startup_timeout_rejects_out_of_range_values(value):
    argv = ["approve", "--server-id", "x", "--approver", "op", "--startup-timeout", value,
            "--", "python3", "x.py"]
    assert cli.main(argv) == 2


def test_startup_timeout_accepts_the_boundary_values(monkeypatch):
    captured = {}

    def fake_run(opts, **kw):
        captured["v"] = opts.startup_timeout
        return 0

    monkeypatch.setattr(cli.approve, "run", fake_run)
    for value in ("0.001", "3600"):
        argv = ["approve", "--server-id", "x", "--approver", "op", "--startup-timeout", value,
                "--", "python3", "x.py"]
        assert cli.main(argv) == 0
        assert captured["v"] == float(value)


def test_tty_line_flushes_typed_ahead_input(monkeypatch):
    import pty
    controller, follower = pty.openpty()
    real_open = os.open

    def fake_open(path, flags, *a, **kw):
        if path == "/dev/tty":
            return os.dup(follower)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(cli.os, "open", fake_open)
    try:
        os.write(controller, b"typed-ahead-junk")
        result = {}
        t = threading.Thread(target=lambda: result.update(value=cli.tty_line("prompt: ")))
        t.start()
        time.sleep(0.1)
        os.write(controller, b"answer\n")
        t.join(timeout=5)
        assert not t.is_alive()
        assert result["value"] == "answer"
    finally:
        os.close(controller)
        os.close(follower)


def test_signing_and_path_security_errors_go_to_stderr_not_out(tmp_path, capsys):
    out = io.StringIO()
    environ = {"HOME": "/nonexistent-does-not-match-the-account-home"}
    assert cli.main(["keygen"], config_dir=tmp_path / "c", out=out, environ=environ,
                    read_secret=lambda p: b"x") == 2
    assert out.getvalue() == ""
    assert "cxbom:" in capsys.readouterr().err


def test_config_dir_with_no_passwd_entry_exits_2(monkeypatch, capsys):
    def boom():
        raise KeyError("getpwuid(): uid not found")

    monkeypatch.setattr(cli.paths, "config_dir", boom)
    out = io.StringIO()
    assert cli.main(["keygen"], out=out, read_secret=lambda p: b"x") == 2
    assert out.getvalue() == ""
    assert capsys.readouterr().err == "cxbom: no password database entry for this user id\n"


@pytest.mark.parametrize("error", [KeyError("/Users/someone/.config/cxbom"), RuntimeError("/home/someone/x")])
def test_an_unexpected_exception_is_an_internal_error_with_no_path(tmp_path, monkeypatch, capsys, error):
    """Final review C2: a KeyError from anywhere but the config_dir lookup is
    a bug, not a missing passwd entry, and any other exception exits 70
    rather than escaping as a traceback."""
    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "cmd_keygen", boom)
    out = io.StringIO()
    assert cli.main(["keygen"], config_dir=tmp_path / "c", out=out, read_secret=lambda p: b"x") == 70
    assert out.getvalue() == ""
    assert capsys.readouterr().err == f"cxbom: internal error ({type(error).__name__})\n"


def test_keygen_checks_for_an_existing_key_before_prompting(tmp_path):
    config = tmp_path / "c"
    out = io.StringIO()
    assert cli.main(["keygen"], config_dir=config, out=out, read_secret=lambda p: b"x") == 0
    calls = []
    out2 = io.StringIO()
    assert cli.main(["keygen"], config_dir=config, out=out2,
                    read_secret=lambda p: calls.append(p) or b"x") == 2
    assert calls == []
    assert "already exists" in out2.getvalue()
