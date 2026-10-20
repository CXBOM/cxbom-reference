"""Launch pins and the child environment (spec 6, 8.1 step 2). Owner: ATACE Working Group."""
import copy
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_helpers import server_layout  # noqa: E402

from cxbom import launch, launchpolicy, paths  # noqa: E402
from cxbom.canonical import file_sha256  # noqa: E402

# Captured before the autouse fixture below ever patches the attribute, so
# this always calls the real implementation regardless of test order.
_REAL_TRUSTED_SEARCH_PATH = launch.trusted_search_path


@pytest.fixture(autouse=True)
def _trusted_interpreter_dir(monkeypatch):
    """Most fixtures here launch the test interpreter itself as a stand-in
    MCP server. It normally lives off the trusted search path (a project
    venv), so this treats its directory as trusted too, the way a real
    deployment's /usr/local/bin entry would. Tests that probe the trust
    boundary itself override trusted_search_path explicitly.
    """
    real_trusted = launch.trusted_search_path
    monkeypatch.setattr(launch, "trusted_search_path", lambda: [os.path.dirname(sys.executable), *real_trusted()])


def pinned(tmp_path, **kw):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    environ.update(kw.pop("extra_env", {}))
    pins = launch.compute_launch_pins(argv, lock_dir, environ, **kw)
    return lock_dir, argv, environ, pins


def test_trusted_search_path_ignores_home_and_gates_homebrew_on_darwin(monkeypatch):
    """The .local/bin entry must come from the account's passwd record, not a
    caller-controlled HOME (premortem C1: actor (b) writes the launch env
    block, HOME included). /opt/homebrew/bin is trusted only on darwin.
    """
    monkeypatch.setenv("HOME", "/tmp/not-the-real-home")
    expected_local_bin = str(paths.pw_dir() / ".local" / "bin")

    monkeypatch.setattr(sys, "platform", "darwin")
    darwin_path = _REAL_TRUSTED_SEARCH_PATH()
    assert darwin_path[-1] == expected_local_bin
    assert "/opt/homebrew/bin" in darwin_path

    monkeypatch.setattr(sys, "platform", "linux")
    linux_path = _REAL_TRUSTED_SEARCH_PATH()
    assert linux_path[-1] == expected_local_bin
    assert "/opt/homebrew/bin" not in linux_path


def test_pins_hash_the_realpath_target_and_relative_files(tmp_path):
    lock_dir, argv, _env, pins = pinned(tmp_path)
    real = os.path.realpath(sys.executable)
    assert pins["argv"] == argv
    assert pins["binary"] == {"name": os.path.basename(real), "sha256": file_sha256(Path(real))}
    assert pins["interpreter"] is None
    assert pins["files"] == {"fake_mcp_server.py": file_sha256(lock_dir / "fake_mcp_server.py"),
                             "script.json": file_sha256(lock_dir / "script.json")}
    assert pins["trees"] == {} and pins["env"] == {}
    assert "/" not in pins["binary"]["name"]


def test_check_launch_builds_the_plan(tmp_path):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    plan = launch.check_launch(pins, argv, lock_dir, dict(environ, FOO="leak"), "fetch")
    assert plan.exec_argv == [argv[0], str(lock_dir / "fake_mcp_server.py"), "--script",
                              str(lock_dir / "script.json")]
    assert plan.env["HOME"] == str(paths.pw_dir())
    assert plan.env["PATH"].startswith(os.path.dirname(sys.executable) + ":/usr/local/bin:/usr/bin:/bin")
    assert plan.env["LANG"] == "C.UTF-8"
    assert "FOO" not in plan.env
    assert len(plan.launch_sha256) == 64


def test_argv_mismatch_refused(tmp_path):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    with pytest.raises(launch.LaunchError, match="signed argv"):
        launch.check_launch(pins, argv + ["--extra"], lock_dir, environ, "fetch")


@pytest.mark.parametrize("item", ["binary", "interpreter"])
def test_binary_or_interpreter_mismatch_says_to_re_run_approve(tmp_path, item):
    """Final review C1: --rebind-binary is a next-plan feature, so the
    message must not name it."""
    lock_dir, argv, environ, pins = pinned(tmp_path)
    bad = copy.deepcopy(pins)
    bad[item] = {"name": "python3", "sha256": "0" * 64}
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(bad, argv, lock_dir, environ, "fetch")
    assert "re-run cxbom approve for this server" in str(ei.value) and "rebind" not in str(ei.value)
    assert ei.value.item == item


@pytest.mark.parametrize("change, where", [
    (lambda a: a + ["--extra"], "at argv[4]: --extra"),
    (lambda a: [a[0], "evil\u202e.py"] + a[2:], "at argv[1]: evil\\u{202E}.py"),
    (lambda a: a[:2], "at argv[2]: the signed argv continues past the end of this one")])
def test_argv_mismatch_names_the_first_differing_index(tmp_path, change, where):
    """Final review C8."""
    lock_dir, argv, environ, pins = pinned(tmp_path)
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(pins, change(argv), lock_dir, environ, "fetch")
    assert str(ei.value) == f"the server command differs from the signed argv {where}"


def test_hostile_caller_path_never_consulted_for_bare_argv0(tmp_path, monkeypatch):
    """The reviewer's probe: actor (b) writes the launch env block, so a bare
    argv[0] must resolve only on the proxy's own trusted search path. A
    directory on the caller's PATH holding a byte-identical copy of the real
    launcher, plus a hostile sibling that would redirect its behavior (a
    hostile pyvenv.cfg beside a copied python, a hostile uv beside a copied
    uvx), must have no effect on resolution or on the child PATH.
    """
    lock_dir, argv, environ, pins = pinned(tmp_path)
    real_dir = os.path.dirname(sys.executable)
    monkeypatch.setattr(launch, "trusted_search_path", lambda: [real_dir])
    evil = tmp_path / "evil"
    evil.mkdir()
    shutil.copyfile(sys.executable, evil / argv[0])
    (evil / argv[0]).chmod(0o755)
    (evil / "pyvenv.cfg").write_text("home = /nowhere\n")
    plan = launch.check_launch(pins, argv, lock_dir, dict(environ, PATH=str(evil)), "fetch")
    assert plan.env["PATH"] == real_dir
    assert str(evil) not in plan.env["PATH"]
    assert plan.executable != str(evil / argv[0])


def test_relative_argv0_outside_pinned_tree_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    bindir = lock_dir / "bin"
    bindir.mkdir(parents=True)
    server = bindir / "server"
    server.write_text("#!/bin/sh\nexit 0\n")
    server.chmod(0o755)
    with pytest.raises(launch.LaunchError, match="put the binary on the standard PATH or pin its tree"):
        launch.compute_launch_pins(["bin/server"], lock_dir, {})


def test_relative_argv0_inside_pinned_tree_is_accepted(tmp_path):
    lock_dir = tmp_path / "proj"
    bindir = lock_dir / "bin"
    bindir.mkdir(parents=True)
    server = bindir / "server"
    server.write_text("#!/bin/sh\nexit 0\n")
    server.chmod(0o755)
    pins = launch.compute_launch_pins(["bin/server"], lock_dir, {}, pin_trees=["bin"])
    plan = launch.check_launch(pins, ["bin/server"], lock_dir, {}, "srv")
    assert plan.env["PATH"].startswith(str(bindir) + ":")
    assert plan.executable == str(server)


def test_changed_pinned_file_refused(tmp_path):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    (lock_dir / "script.json").write_text('{"tools": []}')
    with pytest.raises(launch.LaunchError, match="pinned file script.json"):
        launch.check_launch(pins, argv, lock_dir, environ, "fetch")


def test_pinned_file_outside_lock_dir_refused(tmp_path):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    (tmp_path / "outside.py").write_text("x")
    (lock_dir / "link.py").symlink_to(tmp_path / "outside.py")
    bad = copy.deepcopy(pins)
    bad["files"]["link.py"] = "0" * 64
    with pytest.raises(launch.LaunchError, match="outside the lock directory"):
        launch.check_launch(bad, argv, lock_dir, environ, "fetch")
    bad["files"] = {"../outside.py": "0" * 64}
    with pytest.raises(launch.LaunchError, match="relative to the lock directory"):
        launch.check_launch(bad, argv, lock_dir, environ, "fetch")


def test_pinned_arg_file_absolute_and_relative_map_to_the_same_key(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    extra = lock_dir / "extra.json"
    extra.write_text("{}")
    argv_abs = argv + [str(extra)]
    pins_abs = launch.compute_launch_pins(argv_abs, lock_dir, environ)
    assert pins_abs["files"]["extra.json"] == file_sha256(extra)
    plan = launch.check_launch(pins_abs, argv_abs, lock_dir, environ, "fetch")
    assert plan.exec_argv[-1] == str(extra)
    argv_rel = argv + ["extra.json"]
    pins_rel = launch.compute_launch_pins(argv_rel, lock_dir, environ)
    assert pins_rel["files"] == pins_abs["files"]


def test_pinned_arg_symlink_is_refused_relative_and_absolute(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    (tmp_path / "outside.py").write_text("x")
    link = lock_dir / "link.py"
    link.symlink_to(tmp_path / "outside.py")
    with pytest.raises(launch.LaunchError, match="symlink"):
        launch.compute_launch_pins(argv + ["link.py"], lock_dir, environ)
    with pytest.raises(launch.LaunchError, match="symlink"):
        launch.compute_launch_pins(argv + [str(link)], lock_dir, environ)


def test_tree_pin_and_symlink_refusal(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    (lock_dir / "srv").mkdir()
    (lock_dir / "srv" / "a.py").write_text("print(1)")
    pins = launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=["srv/"])
    assert list(pins["trees"]) == ["srv"]
    launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    (lock_dir / "srv" / "a.py").write_text("print(2)")
    with pytest.raises(launch.LaunchError, match="pinned tree srv"):
        launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    (lock_dir / "srv" / "b.py").symlink_to(lock_dir / "srv" / "a.py")
    with pytest.raises(launch.LaunchError, match="symlink"):
        launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=["srv"])


def test_pin_tree_dot_pins_the_lock_directory_itself(tmp_path):
    lock_dir, argv, environ, _pins = pinned(tmp_path)
    pins = launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=["."])
    assert list(pins["trees"]) == ["."]
    launch.check_launch(pins, argv, lock_dir, environ, "fetch")


def test_pin_tree_dot_slash_prefix_normalizes(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    (lock_dir / "srv").mkdir()
    (lock_dir / "srv" / "a.py").write_text("print(1)")
    pins = launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=["./srv"])
    assert list(pins["trees"]) == ["srv"]


def test_env_value_sha256_rejects_lone_surrogate(tmp_path):
    bad = "value-\udcff-tail"
    with pytest.raises(launch.LaunchError) as ei:
        launch.env_value_sha256(bad)
    msg = str(ei.value)
    assert "value-" not in msg and "tail" not in msg and "\udcff" not in msg


def test_pin_tree_absolute_path_error_shows_basename_only(tmp_path):
    lock_dir, argv, environ, _pins = pinned(tmp_path)
    secret_dir = str(tmp_path / "secret-tree")
    with pytest.raises(launch.LaunchError) as ei:
        launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=[secret_dir])
    msg = str(ei.value)
    assert str(tmp_path) not in msg
    assert msg.startswith("secret-tree:")


def test_env_pins_and_secrets(tmp_path):
    lock_dir, argv, environ, pins = pinned(tmp_path, extra_env={"UV_INDEX_URL": "https://pypi.org/simple",
                                                                "API_TOKEN": "t0k"},
                                           pin_env=["UV_INDEX_URL"], secret_env=["API_TOKEN"])
    assert pins["env"] == {"UV_INDEX_URL": {"sha256": launch.env_value_sha256("https://pypi.org/simple")},
                           "API_TOKEN": "secret"}
    plan = launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    assert plan.env["UV_INDEX_URL"] == "https://pypi.org/simple" and plan.env["API_TOKEN"] == "t0k"
    with pytest.raises(launch.LaunchError, match="UV_INDEX_URL differs"):
        launch.check_launch(pins, argv, lock_dir, dict(environ, UV_INDEX_URL="https://evil.example/simple"),
                            "fetch")
    no_secret = {k: v for k, v in environ.items() if k != "API_TOKEN"}
    with pytest.raises(launch.LaunchError, match="API_TOKEN is pinned but not set"):
        launch.check_launch(pins, argv, lock_dir, no_secret, "fetch")


@pytest.mark.parametrize("name", ["UV_INDEX_URL", "http_proxy", "HTTPS_PROXY", "SSL_CERT_FILE", "PYTHONPATH",
                                  "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "npm_config_registry", "XDG_CONFIG_HOME",
                                  "NODE_OPTIONS", "DOCKER_HOST", "BUN_INSTALL", "COREPACK_HOME", "PIP_INDEX_URL",
                                  "NO_PROXY", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "BASH_ENV", "ENV",
                                  "VIRTUAL_ENV", "CONDA_PREFIX", "GIT_SSH_COMMAND", "CURL_CA_BUNDLE",
                                  "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "PERL5LIB", "RUBYOPT", "GEM_HOME",
                                  "BUNDLE_GEMFILE"])
def test_trust_redirecting_names_cannot_be_secret(tmp_path, name):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    environ[name] = "x"
    with pytest.raises(launch.LaunchError, match="can only be pinned"):
        launch.compute_launch_pins(argv, lock_dir, environ, secret_env=[name])


@pytest.mark.parametrize("name", ["HOME", "PATH", "TMPDIR"])
def test_reserved_names_cannot_be_pinned(tmp_path, name):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    environ[name] = environ.get(name, "/tmp")
    with pytest.raises(launch.LaunchError, match="set by the proxy"):
        launch.compute_launch_pins(argv, lock_dir, environ, pin_env=[name])


def test_script_launcher_pins_its_interpreter(tmp_path, monkeypatch):
    lock_dir = tmp_path / "proj"
    bindir = lock_dir / "bin"
    bindir.mkdir(parents=True)
    interp = bindir / "fakeinterp"
    interp.write_bytes(b"\x7fELF not really")
    interp.chmod(0o755)
    tool = bindir / "tool"
    tool.write_text("#!/usr/bin/env -S fakeinterp --flag\n")
    tool.chmod(0o755)
    # /usr/bin holds the env program the #! line runs, which is held to the
    # same trusted-directory test as the interpreter.
    monkeypatch.setattr(launch, "trusted_search_path", lambda: [str(bindir), "/usr/bin"])
    pins = launch.compute_launch_pins(["tool"], lock_dir, {})
    assert pins["interpreter"] == {"name": "fakeinterp", "sha256": file_sha256(interp)}
    interp.write_bytes(b"\x7fELF swapped")
    with pytest.raises(launch.LaunchError, match="interpreter of tool"):
        launch.check_launch(pins, ["tool"], lock_dir, {}, "srv")


def test_version_manager_shims_are_refused(tmp_path, monkeypatch):
    shims = tmp_path / ".pyenv" / "shims"
    shims.mkdir(parents=True)
    shim = shims / "python"
    shim.write_text("#!/bin/sh\nexec python \"$@\"\n")
    shim.chmod(0o755)
    monkeypatch.setattr(launch, "trusted_search_path", lambda: [str(shims)])
    with pytest.raises(launch.LaunchError, match="Pass the real binary"):
        launch.compute_launch_pins(["python"], tmp_path, {})


def test_launch_errors_carry_no_absolute_path(tmp_path):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    (lock_dir / "script.json").unlink()
    cases = [lambda: launch.check_launch(pins, argv, lock_dir, environ, "fetch"),
             lambda: launch.compute_launch_pins([str(tmp_path / "nope" / "server")], lock_dir, environ),
             lambda: launch.compute_launch_pins(argv, lock_dir, environ, pin_trees=["missing-tree"])]
    for case in cases:
        with pytest.raises(launch.LaunchError) as ei:
            case()
        assert str(tmp_path) not in str(ei.value) and str(paths.pw_dir()) not in str(ei.value)


def test_missing_launcher_is_a_launch_error(tmp_path):
    with pytest.raises(launch.LaunchError, match="not found on PATH"):
        launch.compute_launch_pins(["no-such-launcher-xyz"], tmp_path, {"PATH": str(tmp_path)})


# ----- Task 12b: flag values, missing files, and the interpreter's directory -------------

def test_flag_value_file_is_pinned_rewritten_and_checked(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    conf = lock_dir / "conf.json"
    conf.write_text("{}")
    argv = argv + ["--config=./conf.json", "--verbose"]
    pins = launch.compute_launch_pins(argv, lock_dir, environ)
    assert pins["files"]["conf.json"] == file_sha256(conf)
    assert set(pins["files"]) == {"fake_mcp_server.py", "script.json", "conf.json"}
    plan = launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    assert plan.exec_argv[-2:] == ["--config=" + str(lock_dir / "conf.json"), "--verbose"]
    conf.write_text('{"changed": true}')
    with pytest.raises(launch.LaunchError, match="pinned file conf.json differs"):
        launch.check_launch(pins, argv, lock_dir, environ, "fetch")


def test_flag_value_symlink_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    (tmp_path / "outside.json").write_text("{}")
    (lock_dir / "link.json").symlink_to(tmp_path / "outside.json")
    with pytest.raises(launch.LaunchError, match="symlink"):
        launch.compute_launch_pins(argv + ["--config=link.json"], lock_dir, environ)


@pytest.mark.parametrize("arg, name", [
    ("--config=./missing.json", "missing.json"),
    ("./missing.py", "missing.py"),
    ("sub/missing.py", "missing.py"),
    ("--config=sub/missing.json", "missing.json"),
    ("~missing", "~missing"),
])
def test_missing_path_shaped_file_under_the_lock_dir_is_refused(tmp_path, arg, name):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    (lock_dir / "sub").mkdir()
    with pytest.raises(launch.LaunchError) as ei:
        launch.compute_launch_pins(argv + [arg], lock_dir, environ)
    assert str(ei.value) == f"{name} does not exist: create it before approve"


def test_missing_absolute_path_under_the_lock_dir_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    with pytest.raises(launch.LaunchError, match="missing.py does not exist: create it before approve"):
        launch.compute_launch_pins(argv + [str(lock_dir / "missing.py")], lock_dir, environ)


@pytest.mark.parametrize("arg", [
    "OUTSIDE",
    "../elsewhere/x.py",
    "--out=../elsewhere/x.json",
    "@scope/pkg@1.2.3",
    "mcp/fetch@sha256:" + "0" * 64,
    "https://example.com/a/b",
    "--url=https://example.com/a/b",
    "missing-bare-name.json",
])
def test_values_that_are_not_missing_lock_dir_files_are_left_alone(tmp_path, arg):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    arg = str(tmp_path / "elsewhere" / "x.py") if arg == "OUTSIDE" else arg
    pins = launch.compute_launch_pins(argv + [arg], lock_dir, environ)
    assert set(pins["files"]) == {"fake_mcp_server.py", "script.json"}


def test_file_created_after_approval_at_an_argv_position_is_refused(tmp_path):
    """check_launch recomputes the file pins from argv, so a file that did not
    exist at approval cannot appear later and be passed unpinned."""
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    argv = argv + ["later.json"]
    pins = launch.compute_launch_pins(argv, lock_dir, environ)
    launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    (lock_dir / "later.json").write_text("{}")
    with pytest.raises(launch.LaunchError, match="pinned file later.json differs"):
        launch.check_launch(pins, argv, lock_dir, environ, "fetch")


def _script_server(lock_dir, shebang):
    srv = lock_dir / "srv"
    srv.mkdir(parents=True)
    tool = srv / "tool"
    tool.write_text(f"#!{shebang}\n")
    tool.chmod(0o755)
    return ["srv/tool"]


def _fake_venv(lock_dir):
    bindir = lock_dir / "venv" / "bin"
    bindir.mkdir(parents=True)
    interp = bindir / "python"
    interp.write_bytes(b"\x7fELF not really")
    interp.chmod(0o755)
    (lock_dir / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    return interp


def test_interpreter_outside_trusted_path_and_pinned_trees_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    interp = _fake_venv(lock_dir)
    argv = _script_server(lock_dir, str(interp))
    with pytest.raises(launch.LaunchError) as ei:
        launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])
    assert str(ei.value) == "put the interpreter on the standard PATH or pin its tree"
    pins = launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv", "venv"])
    assert pins["interpreter"] == {"name": "python", "sha256": file_sha256(interp)}
    launch.check_launch(pins, argv, lock_dir, {}, "srv")
    # The proxy applies the same test: an entry whose trees no longer cover
    # the interpreter's directory is refused at launch.
    bad = copy.deepcopy(pins)
    del bad["trees"]["venv"]
    with pytest.raises(launch.LaunchError, match="put the interpreter on the standard PATH or pin its tree"):
        launch.check_launch(bad, argv, lock_dir, {}, "srv")


def test_env_program_outside_trusted_path_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    evil = lock_dir / "evilbin"
    evil.mkdir(parents=True)
    (evil / "env").write_text("#!/bin/sh\n")
    argv = _script_server(lock_dir, f"{evil / 'env'} python3")
    with pytest.raises(launch.LaunchError, match="put the interpreter on the standard PATH or pin its tree"):
        launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])


def test_env_shebang_on_the_trusted_path_is_still_accepted(tmp_path):
    lock_dir = tmp_path / "proj"
    argv = _script_server(lock_dir, "/usr/bin/env python3")
    pins = launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])
    assert pins["interpreter"] is not None and pins["interpreter"]["name"].startswith("python")
    launch.check_launch(pins, argv, lock_dir, {}, "srv")


def test_the_registry_runner_set_is_the_runner_table():
    assert launchpolicy.REGISTRY_RUNNERS == {"bun", "bunx", "npm", "pnpm", "pnpx", "yarn", "uv", "npx", "uvx",
                                             "pipx", "docker", "podman", "corepack"}



# ----- Task 12b fix round 1: aliases, value forms, volumes, env options, dir symlinks ----

def _evil(tmp_path):
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir)
    (lock_dir / "evil.py").write_text("print(1)\n")
    return lock_dir, argv, environ


def _var_alias(path):
    """path through the host's own /var -> /private/var symlink, or None."""
    s = str(path)
    if s.startswith("/private/var/") and os.path.islink("/var") and os.path.realpath("/var") == "/private/var":
        return "/var" + s[len("/private/var"):]
    return None


def test_host_symlink_alias_of_the_lock_dir_is_pinned(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    alias = _var_alias(lock_dir)
    if alias is None:
        pytest.skip("this host has no /var -> /private/var symlink")
    argv = argv + [alias + "/evil.py"]
    pins = launch.compute_launch_pins(argv, lock_dir, environ)
    assert "evil.py" in pins["files"]
    plan = launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    assert plan.exec_argv[-1] == str(lock_dir / "evil.py")


def test_created_symlink_alias_of_the_lock_dir_is_pinned(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    (tmp_path / "alias").symlink_to(lock_dir)
    argv = argv + [str(tmp_path / "alias" / "evil.py")]
    pins = launch.compute_launch_pins(argv, lock_dir, environ)
    assert "evil.py" in pins["files"]
    (lock_dir / "evil.py").write_text("print(2)\n")
    with pytest.raises(launch.LaunchError, match="pinned file evil.py differs"):
        launch.check_launch(pins, argv, lock_dir, environ, "fetch")


def test_case_variant_of_the_lock_dir_is_pinned_on_a_case_insensitive_volume(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    variant = str(lock_dir).swapcase()
    if not launch._case_insensitive(os.path.realpath(lock_dir)):
        with pytest.raises(OSError):
            os.stat(variant)
        pytest.skip("case-sensitive volume")
    pins = launch.compute_launch_pins(argv + [variant + "/evil.py"], lock_dir, environ)
    assert "evil.py" in pins["files"]


def test_case_insensitivity_is_detected_not_assumed(tmp_path):
    real = os.path.realpath(tmp_path)
    swapped = real.swapcase()
    expected = os.path.exists(swapped) and os.path.samefile(real, swapped)
    assert launch._case_insensitive(real) is expected


@pytest.mark.parametrize("form", ["-c{}", "cfg={}", "--cfg={}", "-Dx={}"])
def test_short_attached_and_name_value_forms_are_pinned_and_rewritten(tmp_path, form):
    lock_dir, argv, environ = _evil(tmp_path)
    arg = form.format(lock_dir / "evil.py")
    pins = launch.compute_launch_pins(argv + [arg], lock_dir, environ)
    assert "evil.py" in pins["files"]
    plan = launch.check_launch(pins, argv + [arg], lock_dir, environ, "fetch")
    assert plan.exec_argv[-1] == arg
    rel = form.format("./evil.py")
    pins = launch.compute_launch_pins(argv + [rel], lock_dir, environ)
    plan = launch.check_launch(pins, argv + [rel], lock_dir, environ, "fetch")
    assert plan.exec_argv[-1] == form.format(lock_dir / "evil.py")
    with pytest.raises(launch.LaunchError, match="missing.py does not exist"):
        launch.compute_launch_pins(argv + [form.format("./missing.py")], lock_dir, environ)


def test_path_inside_as_written_but_resolving_outside_is_refused(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "x.py").write_text("x")
    (lock_dir / "linkdir").symlink_to(tmp_path / "outside")
    with pytest.raises(launch.LaunchError, match="resolves outside the lock directory"):
        launch.compute_launch_pins(argv + ["linkdir/x.py"], lock_dir, environ)


@pytest.mark.parametrize("vol", [["-v", "./data:/data"], ["--volume", "./data:/data:ro"], ["--volume=./data:/data"],
                                 ["-v./data:/data"]])
def test_container_volume_tests_only_the_host_part(tmp_path, vol):
    lock_dir = tmp_path / "proj"
    lock_dir.mkdir()
    argv = ["python3"] + vol
    with pytest.raises(launch.LaunchError, match="data does not exist"):
        launch._pin_files(lock_dir, vol)
    (lock_dir / "data").mkdir()
    assert launch._pin_files(lock_dir, vol) == {}
    (lock_dir / "data").rmdir()
    (lock_dir / "data").write_text("{}")
    assert list(launch._pin_files(lock_dir, vol)) == ["data"]
    entry = {"files": launch._pin_files(lock_dir, vol), "trees": {}}
    rewritten = launch._exec_args(argv[1:], entry, lock_dir)
    assert rewritten[-1].startswith((str(lock_dir / "data") + ":", "-v" + str(lock_dir / "data") + ":",
                                     "--volume=" + str(lock_dir / "data") + ":"))


def test_interpreter_dir_symlinked_into_a_pinned_tree_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    interp = _fake_venv(lock_dir)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "bin").symlink_to(interp.parent)
    (outside / "pyvenv.cfg").write_text("home = /attacker\n")
    argv = _script_server(lock_dir, str(outside / "bin" / "python"))
    with pytest.raises(launch.LaunchError, match="put the interpreter on the standard PATH or pin its tree"):
        launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv", "venv"])


def test_path_form_argv0_dir_symlinked_into_a_pinned_tree_is_refused(tmp_path):
    lock_dir = tmp_path / "proj"
    srv = lock_dir / "srv"
    srv.mkdir(parents=True)
    tool = srv / "tool"
    tool.write_bytes(b"\x7fELF not really")
    tool.chmod(0o755)
    (tmp_path / "outside").symlink_to(srv)
    with pytest.raises(launch.LaunchError, match="put the binary on the standard PATH or pin its tree"):
        launch.compute_launch_pins([str(tmp_path / "outside" / "tool")], lock_dir, {}, pin_trees=["srv"])
    pins = launch.compute_launch_pins(["srv/tool"], lock_dir, {}, pin_trees=["srv"])
    assert pins["binary"]["name"] == "tool"


@pytest.mark.parametrize("line", ["/usr/bin/env -u ls {evil}", "/usr/bin/env -C /tmp python3",
                                  "/usr/bin/env -P {evildir} python3", "/usr/bin/env FOO=1 python3",
                                  "/usr/bin/env --ignore-environment python3", "/usr/bin/env -S -u X python3",
                                  "/usr/bin/env -S ${{PY}}", "/usr/bin/env -i python3",
                                  "/usr/bin/env -S -i python3"])
def test_env_options_other_than_s_and_i_are_refused(tmp_path, line):
    lock_dir = tmp_path / "proj"
    interp = _fake_venv(lock_dir)
    argv = _script_server(lock_dir, line.format(evil=interp, evildir=interp.parent))
    with pytest.raises(launch.LaunchError, match="the #! line passes env something other than"):
        launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])


@pytest.mark.parametrize("line", ["/usr/bin/env -S python3 -u", "/usr/bin/env python3"])
def test_env_s_is_accepted(tmp_path, line):
    lock_dir = tmp_path / "proj"
    argv = _script_server(lock_dir, line)
    pins = launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])
    assert pins["interpreter"]["name"].startswith("python")




def test_trusted_dir_that_symlinks_off_the_trusted_path_is_refused(tmp_path, monkeypatch):
    """The realpath half of the directory test is reachable only through a
    trusted entry that is itself a symlink, so this sets the trusted list."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    interp = elsewhere / "fakeinterp"
    interp.write_bytes(b"\x7fELF not really")
    interp.chmod(0o755)
    (tmp_path / "tbin").symlink_to(elsewhere)
    lock_dir = tmp_path / "proj"
    argv = _script_server(lock_dir, str(tmp_path / "tbin" / "fakeinterp"))
    monkeypatch.setattr(launch, "trusted_search_path", lambda: [str(tmp_path / "tbin")])
    with pytest.raises(launch.LaunchError, match="put the interpreter on the standard PATH or pin its tree"):
        launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])
    monkeypatch.setattr(launch, "trusted_search_path", lambda: [str(tmp_path / "tbin"), str(elsewhere)])
    assert launch.compute_launch_pins(argv, lock_dir, {}, pin_trees=["srv"])["interpreter"]["name"] == "fakeinterp"


def test_path_form_argv0_through_a_symlinked_dir_in_the_tree_is_refused_as_untrusted(tmp_path):
    """srv/link points outside the tree and the file there points back in, so
    the file's realpath is in the tree but its directory's is not. The launch
    is refused for the directory, before the tree hash sees the symlink."""
    lock_dir = tmp_path / "proj"
    srv = lock_dir / "srv"
    srv.mkdir(parents=True)
    real_tool = srv / "real_tool"
    real_tool.write_bytes(b"\x7fELF not really")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "tool").symlink_to(real_tool)
    (srv / "link").symlink_to(outside)
    with pytest.raises(launch.LaunchError) as ei:
        launch.compute_launch_pins(["srv/link/tool"], lock_dir, {}, pin_trees=["srv"])
    assert str(ei.value) == "put the binary on the standard PATH or pin its tree"


# ----- Task 12b fix round 2: device-and-inode containment and more value forms -----------

def test_firmlink_spelling_of_the_lock_dir_is_pinned(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    data = "/System/Volumes/Data"
    if not os.path.isdir(data):
        pytest.skip("no /System/Volumes/Data firmlink on this host")
    alias = data + str(lock_dir) + "/evil.py"
    if not os.path.exists(alias):
        pytest.skip("the lock directory is not on the data volume")
    pins = launch.compute_launch_pins(argv + [alias], lock_dir, environ)
    assert "evil.py" in pins["files"]
    (lock_dir / "evil.py").write_text("print(2)\n")
    with pytest.raises(launch.LaunchError, match="pinned file evil.py differs"):
        launch.check_launch(pins, argv + [alias], lock_dir, environ, "fetch")


def test_volfs_spelling_of_the_lock_dir_and_of_the_file_is_pinned(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    if not os.path.isdir("/.vol"):
        pytest.skip("no /.vol on this host")
    st = os.stat(lock_dir)
    fst = os.stat(lock_dir / "evil.py")
    by_dir = f"/.vol/{st.st_dev}/{st.st_ino}/evil.py"
    by_file = f"/.vol/{fst.st_dev}/{fst.st_ino}"
    if not os.path.exists(by_dir) or not os.path.exists(by_file):
        pytest.skip("volfs does not resolve on this volume")
    for alias in (by_dir, by_file):
        pins = launch.compute_launch_pins(argv + [alias], lock_dir, environ)
        assert "evil.py" in pins["files"], alias
        plan = launch.check_launch(pins, argv + [alias], lock_dir, environ, "fetch")
        assert plan.exec_argv[-1] == str(lock_dir / "evil.py")


def test_unicode_normalization_variant_of_the_lock_dir_is_pinned(tmp_path):
    import unicodedata
    lock_dir = tmp_path / unicodedata.normalize("NFC", "caf\u00e9")
    argv, environ = server_layout(lock_dir)
    (lock_dir / "evil.py").write_text("print(1)\n")
    variant = str(tmp_path / unicodedata.normalize("NFD", "caf\u00e9") / "evil.py")
    assert variant != str(lock_dir / "evil.py")
    if not os.path.exists(variant):
        pytest.skip("this volume does not match Unicode normalization variants")
    pins = launch.compute_launch_pins(argv + [variant], lock_dir, environ)
    assert "evil.py" in pins["files"]


def test_chain_match_refuses_a_climb_through_a_symlink(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    (tmp_path / "elsewhere" / "deep").mkdir(parents=True)
    (tmp_path / "elsewhere" / "x.py").write_text("x")
    (lock_dir / "hop").symlink_to(tmp_path / "elsewhere" / "deep")
    with pytest.raises(launch.LaunchError, match="resolves outside the lock directory"):
        launch.compute_launch_pins(argv + [str(lock_dir) + "/hop/../x.py"], lock_dir, environ)


@pytest.mark.parametrize("form", [
    "--import=file://{}",
    "--import=file://localhost{}",
    "@{}",
    "--x=a,{}",
    "--x={}:b",
    "a:b={}",
    "-iv{}:/ctr",
    "-v={}:/ctr",
    "--mount=type=bind,source={},target=/ctr",
    "type=bind,src={},dst=/ctr",
])
def test_round_2_value_forms_are_pinned(tmp_path, form):
    lock_dir, argv, environ = _evil(tmp_path)
    arg = form.format(lock_dir / "evil.py")
    pins = launch.compute_launch_pins(argv + [arg], lock_dir, environ)
    assert "evil.py" in pins["files"], arg
    (lock_dir / "evil.py").write_text("print(2)\n")
    with pytest.raises(launch.LaunchError, match="pinned file evil.py differs"):
        launch.check_launch(pins, argv + [arg], lock_dir, environ, "fetch")


def test_file_url_percent_encoding_is_decoded_and_not_rewritten(tmp_path):
    lock_dir, argv, environ = _evil(tmp_path)
    arg = "--import=file://" + str(lock_dir) + "/evil%2Epy"
    pins = launch.compute_launch_pins(argv + [arg], lock_dir, environ)
    assert "evil.py" in pins["files"]
    assert launch.check_launch(pins, argv + [arg], lock_dir, environ, "fetch").exec_argv[-1] == arg


@pytest.mark.parametrize("form", ["-iv./data:/ctr", "-v=./data:/ctr", "type=bind,source=./data,target=/ctr",
                                  "--mount=type=bind,src=./data,dst=/ctr"])
def test_round_2_mount_sources_are_rewritten_and_refused_when_missing(tmp_path, form):
    lock_dir = tmp_path / "proj"
    lock_dir.mkdir()
    with pytest.raises(launch.LaunchError, match="data does not exist"):
        launch._pin_files(lock_dir, [form])
    (lock_dir / "data").write_text("{}")
    files = launch._pin_files(lock_dir, [form])
    assert list(files) == ["data"]
    rewritten = launch._exec_args([form], {"files": files, "trees": {}}, lock_dir)[0]
    assert str(lock_dir / "data") in rewritten and "/ctr" in rewritten


def test_an_argument_with_too_many_path_forms_is_refused(tmp_path):
    with pytest.raises(launch.LaunchError, match="too many path forms"):
        launch._pin_files(tmp_path, ["-" + "a" * 5000 + "x"])



@pytest.mark.parametrize("name", ["PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"])
def test_child_env_always_sets_the_proxy_fixed_python_variables(tmp_path, name):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    plan = launch.check_launch(pins, argv, lock_dir, dict(environ, **{name: ""}), "fetch")
    assert plan.env[name] == "1"
    assert launch.build_child_env({}, {}, "/usr/bin")[name] == "1"


def test_pythonnousersite_is_not_part_of_the_launch_pins(tmp_path):
    from cxbom.canonical import launch_sha256
    lock_dir, argv, environ, pins = pinned(tmp_path)
    assert pins["env"] == {}
    plan = launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    assert plan.launch_sha256 == launch_sha256({k: pins[k] for k in
                                                ("argv", "binary", "interpreter", "files", "trees", "env")})


@pytest.mark.parametrize("name", ["PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"])
@pytest.mark.parametrize("kind", ["pin_env", "secret_env"])
def test_a_proxy_fixed_python_variable_cannot_be_pinned_or_secret(tmp_path, kind, name):
    with pytest.raises(launch.LaunchError, match=f"{name} is set by the proxy"):
        pinned(tmp_path, extra_env={name: "0"}, **{kind: [name]})
    with pytest.raises(launch.LaunchError, match=f"{name} is set by the proxy"):
        launch.build_child_env({name: "secret"}, {name: ""}, "/usr/bin")


def test_a_user_site_module_is_not_imported_by_the_child(tmp_path):
    import subprocess
    # A venv interpreter never reads the user site, so the probe uses the base
    # interpreter. PYTHONUSERBASE moves the user site under tmp_path, because
    # build_child_env fixes HOME to the real home directory.
    python = getattr(sys, "_base_executable", sys.executable)
    base = str(tmp_path / "userbase")
    probe = {"PYTHONUSERBASE": base, "PATH": "/usr/bin:/bin"}
    site_dir = subprocess.run([python, "-c", "import site; print(site.getusersitepackages())"], env=probe,
                              capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    Path(site_dir).mkdir(parents=True)
    (Path(site_dir) / "usersite_probe.py").write_text("")
    code = ["-c", "import usersite_probe"]
    control = subprocess.run([python, *code], env=probe, capture_output=True, timeout=60)
    if control.returncode != 0:
        pytest.skip("this interpreter does not read the user site")
    env = launch.build_child_env({"PYTHONUSERBASE": {"sha256": launch.env_value_sha256(base)}},
                                 {"PYTHONUSERBASE": base}, "/usr/bin:/bin")
    child = subprocess.run([python, *code], env=env, capture_output=True, text=True, timeout=60)
    assert child.returncode != 0 and "No module named 'usersite_probe'" in child.stderr


def _signed_like(pins, argv):
    return dict(pins, argv=list(argv))


@pytest.mark.parametrize("argv, needle", [
    (["npx", "evilpkg"], "pin an exact package version"),
    ([sys.executable, "-m", "cProfile", "-m", "pipx", "run", "evil"], "put the code in a pinned file"),
    ([sys.executable, "-m", "mymodule"], "put the code in a pinned file"),
    ([sys.executable, "-c", "import pipx"], "put the code in a pinned file"),
    ([sys.executable, __import__("sysconfig").get_paths()["stdlib"] + "/code.py"], "put the code in a pinned file"),
])
def test_check_launch_reapplies_the_argv_rules_to_a_signed_entry(tmp_path, argv, needle):
    lock_dir, _argv, environ, pins = pinned(tmp_path)
    with pytest.raises(launch.LaunchError, match=re.escape(needle)):
        launch.check_launch(_signed_like(pins, argv), argv, lock_dir, environ, "fetch")


@pytest.mark.parametrize("name, pin, value, needle", [
    ("LD_PRELOAD", "pinned", "/x/evil.so", "--pin-env LD_PRELOAD loads code into the server"),
    ("OPENSSL_CONF", "pinned", "/x/evil.cnf", "--pin-env OPENSSL_CONF loads code into the server"),
    ("PYTHONPATH", "pinned", "/x", "--pin-env PYTHONPATH reaches an interpreter hook"),
    ("NODE_OPTIONS", "secret", "--require=/x", "--secret-env NODE_OPTIONS loads code into the server"),
    ("lua_init", "secret", "x", "--secret-env lua_init loads code into the server"),
])
def test_check_launch_reapplies_the_env_rules_to_a_signed_entry(tmp_path, name, pin, value, needle):
    lock_dir, argv, environ, pins = pinned(tmp_path)
    entry = copy.deepcopy(pins)
    entry["env"][name] = "secret" if pin == "secret" else {"sha256": launch.env_value_sha256(value)}
    with pytest.raises(launch.LaunchError, match=re.escape(needle)):
        launch.check_launch(entry, argv, lock_dir, dict(environ, **{name: value}), "fetch")
    if pin != "secret":
        empty = copy.deepcopy(pins)
        empty["env"][name] = {"sha256": launch.env_value_sha256("")}
        launch.check_launch(empty, argv, lock_dir, dict(environ, **{name: ""}), "fetch")


# --- Task 14b fix round 1: LaunchError.item covers every check_launch stage ---


def test_check_launch_wraps_exec_args_failure_as_item_files(tmp_path, monkeypatch):
    """Fix round 1, reviewer finding: the final _exec_args call was the one
    check_launch step left outside an _item() wrapper, so a LaunchError from
    it (a narrow _lock_relative edge case: a named path that nominally sits
    under the lock directory but whose parent resolves elsewhere) reached the
    proxy with item=None instead of "files"."""
    lock_dir, argv, environ, pins = pinned(tmp_path)
    monkeypatch.setattr(launch, "_exec_args", lambda *a, **k: (_ for _ in ()).throw(launch.LaunchError("boom")))
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(pins, argv, lock_dir, environ, "fetch")
    assert ei.value.item == "files"


def test_check_launch_every_stage_sets_a_concrete_item(tmp_path):
    """Every LaunchError check_launch can raise on ordinary input carries a
    non-None item, so the proxy never falls back to guessing "policy" (or,
    after this fix round, treating it as an internal error) for a launch
    that really did name argv, binary, interpreter, files, trees, or env."""
    lock_dir, argv, environ, pins = pinned(tmp_path)
    bad_argv = copy.deepcopy(pins)
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(bad_argv, argv + ["--extra"], lock_dir, environ, "fetch")
    assert ei.value.item == "argv"

    bad_binary = copy.deepcopy(pins)
    bad_binary["binary"]["sha256"] = "0" * 64
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(bad_binary, argv, lock_dir, environ, "fetch")
    assert ei.value.item == "binary"

    bad_env = copy.deepcopy(pins)
    bad_env["env"]["MISSING"] = {"sha256": launch.env_value_sha256("x")}
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(bad_env, argv, lock_dir, environ, "fetch")
    assert ei.value.item == "env"
